"""Carve a multi-gigabyte image with known contents, and measure the run.

Why this exists
---------------
Every other measurement in ``docs/performance`` is taken on images of tens of
megabytes. That establishes correctness and says nothing about scale: whether a
7 GiB image finishes, how long it takes, how much memory the process holds at
its peak, and whether the false-positive rate on high-entropy filler stays
where the small corpora put it. This harness answers those four questions and
nothing else.

What it builds
--------------
An image of ``--size-gib`` gibibytes of seeded pseudo-random filler, with the
objects of ``--seeds`` independent :func:`testkit.generate_corpus._plants`
corpora written into it at 4 KiB-aligned offsets spaced evenly across the whole
image. Every planted object's SHA-256 and recoverability are recorded in a
manifest beside the image, so the scoring needs no judgement: a candidate is a
true positive when its digest matches a recoverable plant, and a false positive
when it matches nothing that was planted.

Random filler is the realistic hard case for a signature carver, not an easy
one. A three-byte JPEG magic occurs in uniform noise about once every 16 MiB,
so a 7 GiB image contains a few hundred headers that were never files. Whether
they reach HIGH is the question.

What it measures
----------------
The carve runs in a **child process**, so ``ru_maxrss`` is that run's peak
resident set and not this harness's. Wall-clock time is measured around the
child. Throughput is image bytes over carve wall-clock. Nothing is estimated.

Run it with::

    python -m testkit.largeimage --work-dir ~/.cache/sanctum-large \\
        --size-gib 7 --seeds 40 --json docs/validation/large-image.json

The image is several gigabytes; put ``--work-dir`` on a real disk, not tmpfs.
Pass ``--keep`` to leave it behind; by default it is deleted after the run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import random
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = ["build_image", "carve_in_child", "score", "main"]

GIB = 1024**3
MIB = 1024**2
ALIGN = 4096
#: Filler is written in chunks this size, so building the image never holds
#: more than one chunk of it.
CHUNK = 8 * MIB


@dataclass(frozen=True)
class Plant:
    offset: int
    length: int
    sha256: str
    ext: str
    kind: str
    recoverable: bool


def build_image(path: Path, *, size_gib: float, seeds: int) -> list[Plant]:
    """Write the image and return what was planted in it."""
    from testkit.generate_corpus import _plants

    size = int(size_gib * GIB)
    payloads: list[tuple[bytes, str, str, bool]] = []
    for seed in range(seeds):
        for plant in _plants(random.Random(seed)):
            recoverable = plant.kind in {"intact", "duplicate"}
            payloads.append((plant.data, plant.ext, plant.kind, recoverable))

    # Evenly spaced, 4 KiB-aligned, leaving the first and last slot free so no
    # object touches either end of the image.
    slot = (size // (len(payloads) + 2)) // ALIGN * ALIGN
    placed: list[tuple[int, bytes]] = []
    plants: list[Plant] = []
    for index, (data, ext, kind, recoverable) in enumerate(payloads, start=1):
        offset = index * slot
        if len(data) >= slot:
            raise ValueError("objects do not fit their slots; lower --seeds")
        placed.append((offset, data))
        plants.append(
            Plant(
                offset=offset,
                length=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
                ext=ext,
                kind=kind,
                recoverable=recoverable,
            )
        )

    rng = random.Random(0xD15C)
    path.parent.mkdir(parents=True, exist_ok=True)
    cursor = 0
    pending = iter(placed)
    upcoming = next(pending, None)
    with path.open("wb") as handle:
        while cursor < size:
            end = min(cursor + CHUNK, size)
            chunk = bytearray(rng.randbytes(end - cursor))
            # Every object that starts inside this chunk is written into it;
            # one that runs past the chunk's end is completed in the next.
            while upcoming is not None and upcoming[0] < end:
                offset, data = upcoming
                start = offset - cursor
                head = data[: end - offset]
                chunk[start : start + len(head)] = head
                if len(head) < len(data):
                    # Carry the tail into the next chunk.
                    upcoming = (end, data[len(head) :])
                    break
                upcoming = next(pending, None)
            handle.write(chunk)
            cursor = end
    return plants


_CHILD = r"""
import json, resource, sys, time
from pathlib import Path
from api.carve_job import carve_generator

image, out_dir, work_dir, answer = (Path(item) for item in sys.argv[1:5])
started = time.monotonic()
generator = carve_generator(
    image, undelete=True, carve_signatures=True, pii_triage=True,
    out_dir=out_dir, job_id="large-image", work_dir=work_dir,
)
phases = []
try:
    while True:
        progress = next(generator)
        phases.append([progress.phase, round(time.monotonic() - started, 2)])
except StopIteration as stop:
    result = stop.value
elapsed = time.monotonic() - started
usage = resource.getrusage(resource.RUSAGE_SELF)
json.dump({
    "elapsed_seconds": elapsed,
    "peak_rss_kib": usage.ru_maxrss,
    "phases": phases,
    "candidates": [
        {k: c[k] for k in ("offset", "length", "ext", "source", "bucket",
                           "confidence_bp", "sha256", "validation")}
        for c in result["candidates"]
    ],
    "written": len(result["written"]),
    "limitations": result["limitations"],
}, answer.open("w"))
"""


def carve_in_child(image: Path, out_dir: Path, work_dir: Path) -> dict[str, Any]:
    """Run the product's carve pipeline in a child and return its measurements."""
    root = Path(__file__).resolve().parents[1]
    # The answer goes to a file, not stdout: structlog writes to stdout, and a
    # measurement that had to be fished out of a log stream is one parse
    # error away from a wrong number.
    answer = image.with_suffix(".result.json")
    started = time.monotonic()
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            _CHILD,
            str(image),
            str(out_dir),
            str(work_dir),
            str(answer),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    wall = time.monotonic() - started
    if completed.returncode != 0:
        return {
            "failed": True,
            "returncode": completed.returncode,
            "stderr_tail": completed.stderr[-4000:],
            "wall_seconds": wall,
        }
    measured: dict[str, Any] = json.loads(answer.read_text(encoding="utf-8"))
    measured["wall_seconds"] = wall
    measured["failed"] = False
    return measured


def score(plants: list[Plant], candidates: list[dict[str, Any]]) -> dict[str, Any]:
    """Precision and recall against the manifest, by bucket."""
    recoverable = {plant.sha256 for plant in plants if plant.recoverable}
    planted = {plant.sha256 for plant in plants}
    buckets: dict[str, dict[str, int]] = {}
    found: set[str] = set()
    for candidate in candidates:
        row = buckets.setdefault(
            candidate["bucket"], {"n": 0, "tp": 0, "fp_unplanted": 0}
        )
        row["n"] += 1
        if candidate["sha256"] in recoverable:
            row["tp"] += 1
            found.add(candidate["sha256"])
        elif candidate["sha256"] not in planted:
            row["fp_unplanted"] += 1
    return {
        "recoverable_objects": len(recoverable),
        "recovered_distinct": len(found),
        "recall_bp": round(len(found) * 10_000 / len(recoverable))
        if recoverable
        else 0,
        "by_bucket": buckets,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--size-gib", type=float, default=7.0)
    parser.add_argument("--seeds", type=int, default=40)
    parser.add_argument("--json", type=Path, default=None)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()

    work = args.work_dir.expanduser()
    image = work / "large.dd"
    out_dir = work / "recovered"
    spill = work / "spill"
    if out_dir.exists():
        shutil.rmtree(out_dir)

    built_at = time.monotonic()
    plants = build_image(image, size_gib=args.size_gib, seeds=args.seeds)
    build_seconds = time.monotonic() - built_at

    measured = carve_in_child(image, out_dir, spill)
    size = image.stat().st_size
    record: dict[str, Any] = {
        "image_bytes": size,
        "image_gib": round(size / GIB, 3),
        "planted_objects": len(plants),
        "seeds": args.seeds,
        "build_seconds": round(build_seconds, 1),
        "host": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "cpu_count": __import__("os").cpu_count(),
        },
        "carve": {
            key: value for key, value in measured.items() if key != "candidates"
        },
    }
    if not measured["failed"]:
        record["carve"]["throughput_mib_per_s"] = round(
            size / MIB / measured["elapsed_seconds"], 2
        )
        record["carve"]["peak_rss_mib"] = round(measured["peak_rss_kib"] / 1024, 1)
        record["candidate_count"] = len(measured["candidates"])
        record["score"] = score(plants, measured["candidates"])
        record["spill_left_behind"] = (
            sum(1 for _ in spill.rglob("*")) if spill.exists() else 0
        )

    text = json.dumps(record, indent=2, sort_keys=True)
    print(text)  # noqa: T201 - a CLI
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(text + "\n", encoding="utf-8")
    if not args.keep:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":  # pragma: no cover
    main()
