"""Throw malformed bytes at the structure parsers and the validators.

What this is
------------
A targeted, reproducible fuzz pass over the two layers that read
attacker-controlled bytes: :data:`core.carve.structure.PARSERS`, which walk a
format's own length fields to derive an object's end, and
:data:`core.carve.validate.VALIDATORS`, which hand bytes to real decoders.
Those are the code paths a seized disk reaches, so they are the ones that have
to survive a disk somebody filled deliberately.

What counts as a failure
------------------------
Exactly three things:

* **a crash** - any exception that is not the parser's own refusal. A parser
  returning ``None`` is correct behaviour; a parser raising ``struct.error``
  is a bug reachable from evidence.
* **a timeout** - a single input taking longer than :data:`CASE_TIMEOUT_S`.
  An unbounded loop over a hostile size field is a denial of service on the
  process that holds the ledger.
* **a memory failure** - ``MemoryError``, or an allocation the harness's own
  bound refuses. A 4-byte length field that says four gigabytes is the classic
  shape.

**Rejecting malformed data is not a failure.** It is the whole point. The
counts below separate "refused" from "crashed" for that reason.

What this is not
----------------
It is not coverage-guided, it does not run for hours, and it does not persist
a corpus between runs. It is a bounded pass with a fixed seed, which makes it
reproducible and makes its results quotable, and it establishes nothing about
inputs it did not generate. See ``docs/validation/fuzz.md`` for the honest
statement of what a run does and does not prove.

Run it with::

    python -m testkit.fuzz --iterations 2000 --seed 0
"""

from __future__ import annotations

import argparse
import io
import json
import random
import struct
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.carve.structure import PARSERS
from core.carve.validate import VALIDATORS, validate_bytes

__all__ = [
    "CASE_TIMEOUT_S",
    "MAX_CASE_BYTES",
    "FuzzFinding",
    "ParserResult",
    "FuzzReport",
    "mutate",
    "seed_inputs",
    "fuzz_parsers",
    "fuzz_validators",
    "run",
    "main",
]

#: A single input may not take longer than this. A parser that walks a format's
#: own length fields has to terminate on bytes that lie about them, and "it
#: finished eventually" is not the property being tested.
CASE_TIMEOUT_S = 2.0

#: The largest input the harness generates. Parsers are given a ``max_size``
#: bound by their caller in production; this keeps the harness itself honest
#: about how much memory it is willing to hand over.
MAX_CASE_BYTES = 512 * 1024

#: Values chosen to be hostile to a length field: zero, one, the signed and
#: unsigned boundaries at 16, 32 and 64 bits, and one past each.
_HOSTILE_INTS = (
    0,
    1,
    0x7F,
    0x80,
    0xFF,
    0x7FFF,
    0x8000,
    0xFFFF,
    0x7FFFFFFF,
    0x80000000,
    0xFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
)

#: Real headers for every format with a parser, so a mutation starts from
#: something the scanner would actually have matched rather than from noise.
#: A fuzz pass that only ever produced inputs the parser rejects at byte 0
#: would exercise one branch and report a clean run.
_HEADERS: dict[str, bytes] = {
    "ZIP": b"PK\x03\x04",
    "PDF": b"%PDF-1.7\n",
    "JPEG": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00",
    "SQLite": b"SQLite format 3\x00",
    "PNG": b"\x89PNG\r\n\x1a\n",
    "MP4": b"\x00\x00\x00\x18ftypisom",
    "TIFF-LE": b"II*\x00\x08\x00\x00\x00",
    "TIFF-BE": b"MM\x00*\x00\x00\x00\x08",
    "BMP": b"BM" + struct.pack("<I", 1024) + b"\x00\x00\x00\x00\x36\x00\x00\x00",
    "WebP": b"RIFF" + struct.pack("<I", 512) + b"WEBP",
    "WAV": b"RIFF" + struct.pack("<I", 512) + b"WAVE",
    "GZIP": b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03",
    "TAR": b"fuzz.txt" + b"\x00" * 92 + b"ustar\x0000",
    "RTF": b"{\\rtf1\\ansi ",
    "HTML": b"<!DOCTYPE html>\n",
    "HTML-tag": b"<html>\n",
}

#: Headers keyed by the extension the validators use, for the decoder pass.
_VALIDATOR_HEADERS: dict[str, bytes] = {
    "jpg": _HEADERS["JPEG"],
    "jpeg": _HEADERS["JPEG"],
    "png": _HEADERS["PNG"],
    "gif": b"GIF89a",
    "bmp": _HEADERS["BMP"],
    "tiff": _HEADERS["TIFF-LE"],
    "webp": _HEADERS["WebP"],
    "pdf": _HEADERS["PDF"],
    "zip": _HEADERS["ZIP"],
    "docx": _HEADERS["ZIP"],
    "xlsx": _HEADERS["ZIP"],
    "pptx": _HEADERS["ZIP"],
    "sqlite": _HEADERS["SQLite"],
    "db": _HEADERS["SQLite"],
    "mp4": _HEADERS["MP4"],
    "wav": _HEADERS["WAV"],
    "gz": _HEADERS["GZIP"],
    "tar": _HEADERS["TAR"],
    "doc": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    "xls": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
}


@dataclass(frozen=True)
class FuzzFinding:
    """One input that crashed, hung or ran out of memory."""

    target: str
    kind: str
    category: str
    detail: str
    #: Enough to reproduce: the seed and the iteration index regenerate it.
    seed: int
    iteration: int
    input_bytes: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "kind": self.kind,
            "category": self.category,
            "detail": self.detail,
            "seed": self.seed,
            "iteration": self.iteration,
            "input_bytes": self.input_bytes,
        }


@dataclass
class ParserResult:
    """Counts for one target across a run."""

    target: str
    cases: int = 0
    #: The parser or validator returned a refusal. Correct behaviour.
    refused: int = 0
    #: It returned a result. Also correct: a mutation can be valid.
    accepted: int = 0
    crashes: int = 0
    timeouts: int = 0
    memory_failures: int = 0
    slowest_seconds: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "cases": self.cases,
            "refused": self.refused,
            "accepted": self.accepted,
            "crashes": self.crashes,
            "timeouts": self.timeouts,
            "memory_failures": self.memory_failures,
            "slowest_seconds": round(self.slowest_seconds, 4),
        }


@dataclass
class FuzzReport:
    """Everything one run produced."""

    seed: int
    iterations: int
    results: list[ParserResult] = field(default_factory=list)
    findings: list[FuzzFinding] = field(default_factory=list)
    elapsed_seconds: float = 0.0

    @property
    def clean(self) -> bool:
        return not self.findings

    def as_dict(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "iterations": self.iterations,
            "case_timeout_seconds": CASE_TIMEOUT_S,
            "max_case_bytes": MAX_CASE_BYTES,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "total_cases": sum(item.cases for item in self.results),
            "clean": self.clean,
            "results": [item.as_dict() for item in self.results],
            "findings": [item.as_dict() for item in self.findings],
        }


# --------------------------------------------------------------------------
# Input generation
# --------------------------------------------------------------------------


def _corrupt_bytes(rng: random.Random, data: bytearray) -> str:
    """Flip, swap or truncate. The generic mutations."""
    choice = rng.randrange(4)
    if choice == 0 and data:
        index = rng.randrange(len(data))
        data[index] ^= 1 << rng.randrange(8)
        return "bit flip"
    if choice == 1 and data:
        index = rng.randrange(len(data))
        data[index] = rng.randrange(256)
        return "byte replacement"
    if choice == 2 and len(data) > 8:
        cut = rng.randrange(1, len(data))
        del data[cut:]
        return "truncation"
    data.extend(rng.randbytes(rng.randrange(1, 4096)))
    return "appended garbage"


def _hostile_size_field(rng: random.Random, data: bytearray) -> str:
    """Overwrite a field with a value chosen to break a length calculation.

    The category the parsers exist to survive. A format's length field is the
    one number a parser trusts, and an image off a seized disk is exactly where
    an untrustworthy one arrives from.
    """
    if len(data) < 16:
        data.extend(b"\x00" * 16)
    value = rng.choice(_HOSTILE_INTS)
    width = rng.choice((2, 4, 8))
    order = rng.choice(("<", ">"))
    try:
        code = {2: "H", 4: "I", 8: "Q"}[width]
        packed = struct.pack(f"{order}{code}", value & ((1 << (width * 8)) - 1))
    except struct.error:  # pragma: no cover - width is from a fixed tuple
        return "hostile size field (skipped)"
    index = rng.randrange(0, max(len(data) - width, 1))
    data[index : index + width] = packed
    return f"hostile size field ({value:#x}, {width * 8}-bit {order})"


def _invalid_offset(rng: random.Random, data: bytearray) -> str:
    """Point an internal offset outside the object."""
    if len(data) < 8:
        data.extend(b"\x00" * 8)
    index = rng.randrange(0, max(len(data) - 4, 1))
    data[index : index + 4] = struct.pack(
        "<I", rng.choice((len(data) + 1, len(data) * 16, 0xFFFFFFFF, 0))
    )
    return "invalid internal offset"


def _recursive_structure(rng: random.Random, data: bytearray, header: bytes) -> str:
    """Nest the format's own header inside itself, repeatedly.

    A container that recurses on a header it finds inside itself recurses
    forever on this.
    """
    depth = rng.randrange(8, 64)
    data.extend(header * depth)
    return f"self-nested header x{depth}"


def _compression_bomb(rng: random.Random, data: bytearray) -> str:
    """A small input that expands enormously, in a real container.

    Built with the standard library rather than hand-rolled, so the container
    is genuinely well-formed and the parser has no structural excuse to
    decline. What is being tested is whether the *size* is bounded, not
    whether the header parses.
    """
    import gzip
    import zipfile

    if rng.randrange(2):
        data.clear()
        data.extend(gzip.compress(b"\x00" * (32 * 1024 * 1024)))
        return "gzip bomb (32 MiB of zeros)"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("bomb", b"\x00" * (32 * 1024 * 1024))
    data.clear()
    data.extend(buffer.getvalue())
    return "zip bomb (32 MiB of zeros)"


#: Every mutation category, named so the report can be read by category.
CATEGORIES = (
    "generic corruption",
    "hostile size field",
    "invalid offset",
    "recursive structure",
    "compression bomb",
    "header only",
    "random noise",
)


def mutate(rng: random.Random, header: bytes) -> tuple[bytes, str]:
    """Produce one malformed input and the category it belongs to."""
    category = rng.choice(CATEGORIES)
    data = bytearray(header)

    if category == "header only":
        return bytes(data), category
    if category == "random noise":
        data.extend(rng.randbytes(rng.randrange(0, 8192)))
        return bytes(data), category
    if category == "recursive structure":
        _recursive_structure(rng, data, header)
        return bytes(data), category
    if category == "compression bomb":
        _compression_bomb(rng, data)
        return bytes(data), category

    # Start from a plausible body so the mutation lands inside structure
    # rather than after the end of it.
    data.extend(rng.randbytes(rng.randrange(64, 4096)))
    if category == "hostile size field":
        _hostile_size_field(rng, data)
    elif category == "invalid offset":
        _invalid_offset(rng, data)
    else:
        for _ in range(rng.randrange(1, 6)):
            _corrupt_bytes(rng, data)
    return bytes(data[:MAX_CASE_BYTES]), category


def seed_inputs() -> dict[str, bytes]:
    """The starting header for each parser target."""
    return dict(_HEADERS)


# --------------------------------------------------------------------------
# A read-only handle over bytes, so a parser can be driven without an image
# --------------------------------------------------------------------------


class _BytesHandle:
    """The read-only surface :data:`PARSERS` need, over an in-memory buffer.

    Deliberately read-only and deliberately minimal: it declares ``read`` and
    ``size`` and no write method at all, which is the same property
    :class:`core.carve.evidence.EvidenceHandle` has and the reason the carving
    path cannot modify evidence even by mistake.
    """

    def __init__(self, data: bytes) -> None:
        self._data = data
        self.size = len(data)

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise ValueError("negative read")
        return self._data[offset : offset + length]


# --------------------------------------------------------------------------
# The passes
# --------------------------------------------------------------------------


def _run_case(
    call: Callable[[], Any],
    *,
    target: str,
    category: str,
    seed: int,
    iteration: int,
    size: int,
    result: ParserResult,
) -> FuzzFinding | None:
    """Run one input, classify the outcome, and time it."""
    result.cases += 1
    started = time.monotonic()
    try:
        answer = call()
    except MemoryError as exc:
        result.memory_failures += 1
        return FuzzFinding(
            target=target,
            kind="memory",
            category=category,
            detail=f"MemoryError: {exc}",
            seed=seed,
            iteration=iteration,
            input_bytes=size,
        )
    except Exception as exc:  # noqa: BLE001 - classifying, that is the job
        result.crashes += 1
        return FuzzFinding(
            target=target,
            kind="crash",
            category=category,
            detail=f"{type(exc).__name__}: {exc}",
            seed=seed,
            iteration=iteration,
            input_bytes=size,
        )
    finally:
        elapsed = time.monotonic() - started
        result.slowest_seconds = max(result.slowest_seconds, elapsed)

    if elapsed > CASE_TIMEOUT_S:
        result.timeouts += 1
        return FuzzFinding(
            target=target,
            kind="timeout",
            category=category,
            detail=f"took {elapsed:.2f}s, above the {CASE_TIMEOUT_S}s bound",
            seed=seed,
            iteration=iteration,
            input_bytes=size,
        )

    if answer is None:
        result.refused += 1
    else:
        result.accepted += 1
    return None


def fuzz_parsers(
    *, iterations: int, seed: int = 0
) -> Iterator[tuple[ParserResult, list[FuzzFinding]]]:
    """Fuzz every registered structure parser."""
    headers = seed_inputs()
    for name, parser in PARSERS.items():
        rng = random.Random(f"{seed}:{name}")
        result = ParserResult(target=f"structure.{name}")
        findings: list[FuzzFinding] = []
        header = headers.get(name, b"")
        for iteration in range(iterations):
            data, category = mutate(rng, header)
            handle = _BytesHandle(data)
            finding = _run_case(
                lambda: parser(handle, 0, max_size=len(data)),  # noqa: B023
                target=result.target,
                category=category,
                seed=seed,
                iteration=iteration,
                size=len(data),
                result=result,
            )
            if finding is not None:
                findings.append(finding)
        yield result, findings


def fuzz_validators(
    *, iterations: int, seed: int = 0
) -> Iterator[tuple[ParserResult, list[FuzzFinding]]]:
    """Fuzz every registered validator, which is every real decoder."""
    for ext in sorted(VALIDATORS):
        rng = random.Random(f"{seed}:validate:{ext}")
        result = ParserResult(target=f"validate.{ext}")
        findings: list[FuzzFinding] = []
        header = _VALIDATOR_HEADERS.get(ext, b"")
        for iteration in range(iterations):
            data, category = mutate(rng, header)
            finding = _run_case(
                lambda: validate_bytes(data, ext),  # noqa: B023
                target=result.target,
                category=category,
                seed=seed,
                iteration=iteration,
                size=len(data),
                result=result,
            )
            if finding is not None:
                findings.append(finding)
        yield result, findings


def run(*, iterations: int = 500, seed: int = 0) -> FuzzReport:
    """Run both passes and collect the report."""
    started = time.monotonic()
    report = FuzzReport(seed=seed, iterations=iterations)
    for pass_ in (fuzz_parsers, fuzz_validators):
        for result, findings in pass_(iterations=iterations, seed=seed):
            report.results.append(result)
            report.findings.extend(findings)
    report.elapsed_seconds = time.monotonic() - started
    return report


def format_report(report: FuzzReport) -> str:
    """Fixed-width summary, for a terminal and for a document."""
    header = (
        f"{'target':<26}{'cases':>7}{'refused':>9}{'accepted':>10}"
        f"{'crash':>7}{'timeout':>9}{'oom':>5}{'slowest':>10}"
    )
    lines = [header, "-" * len(header)]
    for item in sorted(report.results, key=lambda row: row.target):
        lines.append(
            f"{item.target:<26}{item.cases:>7}{item.refused:>9}{item.accepted:>10}"
            f"{item.crashes:>7}{item.timeouts:>9}{item.memory_failures:>5}"
            f"{item.slowest_seconds:>9.3f}s"
        )
    lines.append("")
    if report.clean:
        lines.append(
            f"No crashes, timeouts or memory failures in "
            f"{sum(item.cases for item in report.results)} cases."
        )
    else:
        lines.append(f"{len(report.findings)} finding(s):")
        for finding in report.findings[:40]:
            lines.append(
                f"  {finding.target} [{finding.kind}] {finding.category}: "
                f"{finding.detail}"
            )
    return "\n".join(lines)


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description=(
            "Fuzz the structure parsers and validators with malformed inputs."
        )
    )
    parser.add_argument("--iterations", type=int, default=500)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument(
        "--json",
        type=Path,
        default=None,
        help="write the raw report here, so the document can quote it",
    )
    args = parser.parse_args()

    report = run(iterations=args.iterations, seed=args.seed)
    print(format_report(report))  # noqa: T201 - a CLI, not a core layer
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(report.as_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"\nwrote {args.json}")  # noqa: T201
    raise SystemExit(0 if report.clean else 1)


if __name__ == "__main__":  # pragma: no cover
    main()
