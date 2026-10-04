"""Measure E01 acquisition throughput, and what compression selection costs.

Run with:

    .venv/bin/python scripts/measure-e01-throughput.py [--ewfacquire PATH]

Two measurements, because Sanctum and ewfacquire do not have the same choices
available to them:

* **Sanctum**, through ``core.carve.acquire.acquire(fmt="e01")``. pyewf binds
  no compression setter, so this is one number at libewf's default and
  ``AcquireOptions.compression`` has no effect on it. Both hashes are computed
  in the same pass, so the figure is end-to-end acquisition, not raw codec
  speed.
* **ewfacquire**, if a path to one is given, at ``-c fast`` and ``-c best``.
  That is the comparison Sanctum cannot make itself, and it says what would be
  gained by binding the setter.

The source is not random bytes. A disk image is mostly unused space, and
measuring deflate against incompressible noise would report a throughput no
real acquisition ever sees. The synthetic source is 60% zero fill, 25%
text-like records and 15% incompressible - a partly-used disk - and the
composition is printed with the result so the number can be read honestly.
"""

from __future__ import annotations

import argparse
import os
import random
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from core.carve.acquire import AcquireOptions, acquire, e01_write_supported

MIB = 1024 * 1024

#: Shares of the synthetic source, in percent. Sums to 100.
ZERO_PCT = 60
TEXT_PCT = 25
NOISE_PCT = 15

_TEXT = (
    b"2026-09-04T11:22:33Z INFO  session=%d user=examiner action=open "
    b"target=/evidence/case-0001 result=ok bytes=4096\n"
)


def build_source(path: Path, size: int, *, seed: int = 0) -> None:
    """Write a source whose compressibility resembles a partly-used disk."""
    rng = random.Random(seed)
    block = MIB
    zero_blocks = size // block * ZERO_PCT // 100
    text_blocks = size // block * TEXT_PCT // 100
    total_blocks = size // block

    with open(path, "wb") as handle:
        for index in range(total_blocks):
            if index < zero_blocks:
                handle.write(b"\x00" * block)
            elif index < zero_blocks + text_blocks:
                line = _TEXT % index
                handle.write((line * (block // len(line) + 1))[:block])
            else:
                handle.write(rng.randbytes(block))


def _drop_page_cache_hint() -> None:
    """Best effort only. Dropping the cache needs root; this run does not."""
    os.sync()


def measure_sanctum(source: Path, dest: Path, fmt: str) -> tuple[float, int]:
    """Return ``(seconds, bytes on disk)`` for one acquisition."""
    _drop_page_cache_hint()
    start = time.monotonic()
    generator = acquire(
        source, dest, fmt=fmt, options=AcquireOptions(compression="fast")
    )
    while True:
        try:
            next(generator)
        except StopIteration:
            break
    elapsed = time.monotonic() - start

    produced = dest if dest.exists() else dest.with_name(f"{dest.stem}.E01")
    written = sum(
        item.stat().st_size
        for item in produced.parent.iterdir()
        if item.name.startswith(produced.stem)
    )
    return elapsed, written


def measure_ewfacquire(
    tool: Path, source: Path, out_dir: Path, level: str
) -> tuple[float, int] | None:
    """Return ``(seconds, bytes on disk)`` for ewfacquire at one level."""
    target = out_dir / f"ewf-{level}"
    _drop_page_cache_hint()
    start = time.monotonic()
    completed = subprocess.run(
        [
            str(tool),
            "-u",                      # unattended: take every default
            "-t", str(target),
            "-c", level,
            "-d", "sha1",
            "-f", "encase6",
            str(source),
        ],
        capture_output=True,
        text=True,
    )
    elapsed = time.monotonic() - start
    if completed.returncode != 0:
        print(f"  ewfacquire -c {level} failed: {completed.stderr.strip()[:300]}")
        return None
    written = sum(
        item.stat().st_size
        for item in out_dir.iterdir()
        if item.name.startswith(target.name)
    )
    return elapsed, written


def _report(label: str, size: int, elapsed: float, written: int) -> None:
    rate = size / elapsed / MIB
    ratio = 100 * written / size
    print(
        f"  {label:<28} {elapsed:7.2f} s   {rate:7.1f} MiB/s   "
        f"{written / MIB:8.1f} MiB on disk ({ratio:5.1f}% of source)"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size-mib", type=int, default=512)
    parser.add_argument(
        "--ewfacquire",
        type=Path,
        default=None,
        help="path to an ewfacquire binary, for the fast-vs-best comparison",
    )
    args = parser.parse_args()

    size = args.size_mib * MIB
    print(
        f"source: {args.size_mib} MiB, {ZERO_PCT}% zero fill / {TEXT_PCT}% text "
        f"/ {NOISE_PCT}% incompressible"
    )
    print(f"e01_write_supported(): {e01_write_supported()}\n")

    with tempfile.TemporaryDirectory(prefix="sanctum-e01-bench-") as directory:
        work = Path(directory)
        source = work / "source.dd"
        build_source(source, size)

        print("Sanctum core.carve.acquire (sha256 + blake3 in the read pass):")
        elapsed, written = measure_sanctum(source, work / "raw.dd", "raw")
        _report("raw baseline", size, elapsed, written)

        if e01_write_supported():
            elapsed, written = measure_sanctum(source, work / "case.E01", "e01")
            _report("e01 (libewf default)", size, elapsed, written)
        else:
            print("  e01 unavailable on this build")

        tool = args.ewfacquire or (
            Path(shutil.which("ewfacquire")) if shutil.which("ewfacquire") else None
        )
        if tool is None:
            print("\nno ewfacquire on PATH; skipping the fast-vs-best comparison")
            return

        print(f"\newfacquire {tool} (no hashing in Sanctum's sense; sha1 only):")
        for level in ("none", "fast", "best"):
            result = measure_ewfacquire(tool, source, work, level)
            if result is not None:
                _report(f"-c {level}", size, *result)


if __name__ == "__main__":
    main()
