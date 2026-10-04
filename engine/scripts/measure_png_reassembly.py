"""Measure PNG bifragment reassembly: reach, refusals and false accepts.

Deterministic (fixed seeds), host storage only, no device access. Writes one
JSON document with every population's counts and the worst-case time, so the
figures in ``docs/validation/png-reassembly.md`` can be regenerated:

    .venv/bin/python scripts/measure_png_reassembly.py \
        docs/validation/png-reassembly.json

Populations:

* reach - noise-filled gaps from 64 KiB to 7 MiB, on 512- and 4096-byte grids,
  half noisy images and half gradient-with-noise images;
* gap fill - text and zero gaps, which put the most and fewest candidate chunk
  types in front of the search;
* adversarial - chimeras of two PNGs with identical dimensions, a tail whose
  first cluster was overwritten, a tail missing its first 512 bytes, and a tail
  with 512 bytes substituted. Every accept in these is wrong by construction.
"""

from __future__ import annotations

import io
import json
import platform
import random
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:  # pragma: no cover - import bootstrap
    sys.path.insert(0, str(ROOT))

from core.carve.evidence import BytesEvidence  # noqa: E402
from core.carve.fragmentation import reassemble_bifragmented_png_runs  # noqa: E402
from PIL import Image  # noqa: E402

KIB = 1024
MIB = 1024 * KIB
CLUSTER = 4096


def make_png(seed: int, *, smooth: bool = False) -> bytes:
    """A noisy 192 px image, or a 384 px gradient with low-amplitude noise."""
    rng = random.Random(seed)
    size = 384 if smooth else 192
    image = Image.new("RGB", (size, size))
    if smooth:
        image.putdata(
            [
                (
                    min(255, x * 255 // size + rng.randrange(9)),
                    min(255, y * 255 // size + rng.randrange(9)),
                    (seed * 37 + rng.randrange(9)) & 255,
                )
                for y in range(size)
                for x in range(size)
            ]
        )
    else:
        image.putdata(
            [
                (rng.randrange(256), rng.randrange(256), rng.randrange(256))
                for _ in range(size * size)
            ]
        )
    buffer = io.BytesIO()
    image.save(buffer, "PNG")
    return buffer.getvalue()


def attempt(laid: bytes, grid: int) -> tuple[bytes | None, float]:
    evidence = BytesEvidence(laid + bytes(8 * KIB))
    started = time.perf_counter()
    found = reassemble_bifragmented_png_runs(
        evidence, 0, max_size=16 * MIB, cluster_size=grid
    )
    return (None if found is None else found.payload), time.perf_counter() - started


def tally(rows: list[tuple[bytes | None, bytes | None, float]]) -> dict[str, Any]:
    """rows: (recovered payload, expected payload or None if any accept is wrong)."""
    recovered = wrong = refused = 0
    worst = 0.0
    for payload, expected, seconds in rows:
        worst = max(worst, seconds)
        if payload is None:
            refused += 1
        elif expected is not None and payload == expected:
            recovered += 1
        else:
            wrong += 1
    return {
        "cases": len(rows),
        "recovered": recovered,
        "wrong": wrong,
        "refused": refused,
        "worst_seconds": round(worst, 3),
    }


def measure() -> dict[str, Any]:
    rng = random.Random(2026)
    out: dict[str, Any] = {
        "host": {"python": platform.python_version(), "machine": platform.machine()},
        "reach": [],
        "gap_fill": [],
        "adversarial": {},
    }
    for grid in (512, CLUSTER):
        for gap in (64 * KIB, 256 * KIB, MIB, 2 * MIB, 4 * MIB, 7 * MIB):
            rows = []
            for index in range(10):
                original = make_png(1000 + index, smooth=index % 2 == 1)
                head = rng.randrange(1, (len(original) - 1) // grid) * grid
                laid = original[:head] + rng.randbytes(gap) + original[head:]
                payload, seconds = attempt(laid, grid)
                rows.append((payload, original, seconds))
            out["reach"].append({"grid": grid, "gap": gap, **tally(rows)})

    text = b"GET /index.html HTTP/1.1 Host example Accept text html keep-alive\n"
    fills = {"text": text * (8 * MIB // len(text) + 1), "zeros": bytes(8 * MIB)}
    for label, fill in fills.items():
        for grid in (512, CLUSTER):
            for gap in (MIB, 7 * MIB):
                rows = []
                for index in range(5):
                    original = make_png(1000 + index)
                    head = (3 + index) * grid
                    laid = original[:head] + fill[:gap] + original[head:]
                    payload, seconds = attempt(laid, grid)
                    rows.append((payload, original, seconds))
                out["gap_fill"].append(
                    {"fill": label, "grid": grid, "gap": gap, **tally(rows)}
                )

    def population(name: str, build: Any) -> None:
        rows = []
        for index in range(200):
            laid = build(index)
            payload, seconds = attempt(laid, CLUSTER)
            rows.append((payload, None, seconds))
        out["adversarial"][name] = tally(rows)

    def head_of(index: int) -> int:
        return (1 + index % 20) * CLUSTER

    def chimera(index: int) -> bytes:
        first, second = make_png(5000 + index), make_png(9000 + index)
        head = head_of(index)
        return first[:head] + rng.randbytes(16 * CLUSTER) + second[head:]

    def overwritten(index: int) -> bytes:
        original = make_png(7000 + index)
        head = head_of(index)
        laid = bytearray(original[:head] + rng.randbytes(8 * CLUSTER) + original[head:])
        tail = head + 8 * CLUSTER
        laid[tail : tail + CLUSTER] = rng.randbytes(CLUSTER)
        return bytes(laid)

    def lost(index: int) -> bytes:
        original = make_png(8000 + index)
        head = head_of(index)
        return original[:head] + rng.randbytes(8 * CLUSTER) + original[head + 512 :]

    def substituted(index: int) -> bytes:
        original = make_png(6000 + index)
        head = head_of(index)
        tail = bytearray(original[head:])
        at = 700 + index * 13 % 2000
        tail[at : at + 512] = rng.randbytes(512)
        return original[:head] + rng.randbytes(8 * CLUSTER) + bytes(tail)

    population("chimera_same_dimensions", chimera)
    population("tail_first_cluster_overwritten", overwritten)
    population("tail_missing_first_512_bytes", lost)
    population("tail_with_512_bytes_substituted", substituted)
    return out


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        sys.stderr.write("usage: measure_png_reassembly.py OUT.json\n")
        return 2
    result = measure()
    Path(args[0]).write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":  # pragma: no cover - process entry point
    raise SystemExit(main())
