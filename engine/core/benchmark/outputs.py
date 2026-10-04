"""Recovered outputs, and which planted object each one is a recovery of.

This is the attribution step every benchmark score is built on, moved here from
``testkit/benchmark.py`` so that the synthetic benchmark and the first-class
scorer in :mod:`core.benchmark.score` run **the same code**. The registered
recall baseline was produced by this algorithm; a physical run scored by a
different one would compare two different measurements.

The rules, unchanged from the testkit scorer:

* An output whose SHA-256 equals a planted object's is a byte-identical
  recovery of every planted object with that content.
* Otherwise, an output whose leading bytes agree with one planted object longer
  than with any other (at least :data:`MIN_AGREEMENT` bytes, over the first
  :data:`HEAD_BYTES`) is a corrupt recovery of it. Agreeing equally with two
  different planted contents is *ambiguous*; the best match being a decoy is a
  *decoy* false positive.
* Anything else is a false positive: a *fragment* when its head lies inside a
  planted file, otherwise *unrelated*.
* A second output for a planted object already recovered is a duplicate.

Nothing here opens a device. Output files are read, never written.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

__all__ = [
    "HEAD_BYTES",
    "MIN_AGREEMENT",
    "OUTPUT_INDEX",
    "REPORT_FILES",
    "OutputKind",
    "OutputRecord",
    "OutputAttribution",
    "Attribution",
    "TruthLike",
    "common_prefix",
    "index_outputs",
    "load_outputs",
    "select_outputs",
    "attribute_outputs",
]

KIB = 1024
MIB = 1024 * KIB

#: Leading bytes compared when attributing a non-identical output.
HEAD_BYTES = 64 * KIB
#: Agreement shorter than this attributes nothing: every JPEG shares its SOI.
MIN_AGREEMENT = 64
#: Files a tool writes about its run rather than recovered objects.
REPORT_FILES = frozenset({"photorec.log", "report.xml", "audit.txt"})
#: Per-run record of every output: name, size, SHA-256 and first 64 KiB.
OUTPUT_INDEX = "outputs.json"

OutputKind = Literal[
    "exact", "corrupt", "fp_fragment", "fp_decoy", "fp_ambiguous", "fp_unrelated"
]


class TruthLike(Protocol):
    """What attribution needs from a planted object. Read-only."""

    @property
    def name(self) -> str: ...

    @property
    def sha256(self) -> str: ...

    @property
    def role(self) -> str: ...


@dataclass(frozen=True)
class OutputRecord:
    """One recovered output, as the scorer sees it."""

    #: Path relative to the output directory. Sorting key: deterministic order.
    path: str
    name: str
    size: int
    sha256: str
    #: The first :data:`HEAD_BYTES` bytes.
    head: bytes
    #: The file itself, when the outputs were read from a directory. ``None``
    #: when only an index survives, in which case only ``head`` can be compared.
    source: Path | None = None


@dataclass(frozen=True)
class OutputAttribution:
    """What one output was judged to be."""

    output: OutputRecord
    kind: OutputKind
    #: Planted objects this output recovers (``exact``/``corrupt``) or is
    #: attributed to (``fp_decoy``). Empty for the other false-positive kinds.
    targets: tuple[str, ...] = ()
    #: A second output for a planted object that was already recovered.
    duplicate: bool = False
    #: Leading bytes agreeing with the best-matching planted object.
    prefix_agreement: int = 0


@dataclass
class Attribution:
    """Every output's attribution, and the planted objects recovered."""

    outputs: list[OutputAttribution] = field(default_factory=list)
    exact: set[str] = field(default_factory=set)
    corrupt: set[str] = field(default_factory=set)
    duplicate_outputs: int = 0

    def count(self, kind: OutputKind) -> int:
        """Outputs attributed as ``kind``."""
        return sum(1 for item in self.outputs if item.kind == kind)


def common_prefix(left: bytes, right: bytes) -> int:
    """Length of the common prefix, found by halving rather than byte by byte."""
    limit = min(len(left), len(right))
    if left[:limit] == right[:limit]:
        return limit
    low, high = 0, limit
    while high - low > 1:
        middle = (low + high) // 2
        if left[:middle] == right[:middle]:
            low = middle
        else:
            high = middle
    return low


def index_outputs(files: Path) -> list[dict[str, Any]]:
    """What the scorer needs from each output file, without keeping the file.

    Sanctum writes a candidate that no parser could bound as the span to the end
    of the image, so one run over a 255 MiB volume wrote 2.8 GiB. The scorer
    reads only an output's digest and its first :data:`HEAD_BYTES`, so those
    are recorded and the files can go.
    """
    entries: list[dict[str, Any]] = []
    for path in sorted(item for item in files.rglob("*") if item.is_file()):
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            head = handle.read(HEAD_BYTES)
            digest.update(head)
            size = len(head)
            for chunk in iter(lambda: handle.read(MIB), b""):
                digest.update(chunk)
                size += len(chunk)
        entries.append(
            {
                "path": path.relative_to(files).as_posix(),
                "name": path.name,
                "size": size,
                "sha256": digest.hexdigest(),
                "head": base64.b64encode(head).decode("ascii"),
            }
        )
    return entries


def load_outputs(source: Path) -> list[OutputRecord]:
    """Outputs from a directory of files, or from an :data:`OUTPUT_INDEX` file."""
    if source.is_dir():
        return [
            OutputRecord(
                path=str(entry["path"]),
                name=str(entry["name"]),
                size=int(entry["size"]),
                sha256=str(entry["sha256"]),
                head=base64.b64decode(entry["head"]),
                source=source / str(entry["path"]),
            )
            for entry in index_outputs(source)
        ]
    entries = json.loads(source.read_text(encoding="utf-8"))
    return [
        OutputRecord(
            path=str(entry["path"]),
            name=str(entry["name"]),
            size=int(entry["size"]),
            sha256=str(entry["sha256"]),
            head=base64.b64decode(entry["head"]),
        )
        for entry in entries
    ]


def select_outputs(
    records: Sequence[OutputRecord], only: Collection[str] | None = None
) -> list[OutputRecord]:
    """Drop a tool's own report files, keep ``only`` names if given, sort by path."""
    return sorted(
        (
            record
            for record in records
            if record.name not in REPORT_FILES and (only is None or record.name in only)
        ),
        key=lambda record: record.path,
    )


def attribute_outputs(
    objects: Sequence[TruthLike],
    references: Mapping[str, bytes],
    outputs: Sequence[OutputRecord],
) -> Attribution:
    """Attribute every output to planted objects, in the order given.

    ``references`` maps each planted object's name to its bytes as planted (or
    as surviving on the medium when the planted bytes are unknown). The order of
    ``outputs`` decides which of two identical outputs is the duplicate, so
    callers pass :func:`select_outputs`' sorted list.
    """
    by_digest: dict[str, list[TruthLike]] = {}
    for obj in objects:
        if obj.sha256:
            by_digest.setdefault(obj.sha256, []).append(obj)
    heads: dict[bytes, list[TruthLike]] = {}
    for obj in objects:
        if obj.role in ("file", "decoy") and len(references[obj.name]) >= 8:
            heads.setdefault(references[obj.name][:8], []).append(obj)

    result = Attribution()
    for record in outputs:
        data = record.head
        matched = by_digest.get(record.sha256)
        if matched:
            names = {obj.name for obj in matched}
            duplicate = names <= result.exact
            if duplicate:
                result.duplicate_outputs += 1
            result.exact |= names
            result.outputs.append(
                OutputAttribution(
                    output=record,
                    kind="exact",
                    targets=tuple(sorted(names)),
                    duplicate=duplicate,
                    prefix_agreement=record.size,
                )
            )
            continue
        scored = sorted(
            (
                (
                    common_prefix(
                        data[:HEAD_BYTES], references[obj.name][:HEAD_BYTES]
                    ),
                    obj,
                )
                for obj in heads.get(data[:8], [])
            ),
            key=lambda pair: -pair[0],
        )
        if scored and scored[0][0] >= MIN_AGREEMENT:
            best, winner = scored[0]
            rivals = [
                obj
                for agreement, obj in scored[1:]
                if agreement == best
                and references[obj.name][:best] != b""
                and (obj.sha256 != winner.sha256 or not obj.sha256)
            ]
            if rivals:
                result.outputs.append(
                    OutputAttribution(
                        output=record,
                        kind="fp_ambiguous",
                        targets=tuple(sorted({winner.name, *(o.name for o in rivals)})),
                        prefix_agreement=best,
                    )
                )
            elif winner.role == "decoy":
                result.outputs.append(
                    OutputAttribution(
                        output=record,
                        kind="fp_decoy",
                        targets=(winner.name,),
                        prefix_agreement=best,
                    )
                )
            else:
                duplicate = winner.name in result.corrupt or winner.name in result.exact
                if duplicate:
                    result.duplicate_outputs += 1
                result.corrupt.add(winner.name)
                result.outputs.append(
                    OutputAttribution(
                        output=record,
                        kind="corrupt",
                        targets=(winner.name,),
                        duplicate=duplicate,
                        prefix_agreement=best,
                    )
                )
            continue
        probe = data[:256]
        inside = len(probe) >= 32 and any(
            references[obj.name].find(probe, 1) != -1
            for obj in objects
            if obj.role == "file"
        )
        result.outputs.append(
            OutputAttribution(
                output=record, kind="fp_fragment" if inside else "fp_unrelated"
            )
        )
    return result
