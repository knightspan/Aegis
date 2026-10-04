"""Fixtures for the M2 suite. Real filesystem only; no OS-layer mocking.

One thing here needs explaining. Several tests need a file on a **real
block-backed filesystem**, not on ``tmp_path``: pytest's temporary directory is
usually ``/tmp``, which on most Linux hosts is a tmpfs, and tmpfs answers no
FIEMAP, has no block device and reports no meaningful cluster size. A test for
extent capture that ran there would pass by measuring nothing.

:func:`real_fs_dir` therefore places its files beside the repository, which is
on the host's real filesystem, and cleans up after itself. Where even that is
not block-backed the test skips with the filesystem named.
"""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from core.erase._platform import backend
from core.models import FileEraseOptions, Progress

#: Windows-only behaviour: alternate data streams, resident MFT data, VSS.
ntfs_only = pytest.mark.skipif(
    sys.platform != "win32",
    reason=(
        "NTFS-specific behaviour (ADS, resident data, VSS); this host is not "
        "Windows"
    ),
)

posix_only = pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX-specific behaviour; this host is Windows",
)


def real_erase(**overrides: Any) -> FileEraseOptions:
    """Options with the destructive gate deliberately opened."""
    base: dict[str, Any] = {"confirm": True}
    base.update(overrides)
    return FileEraseOptions.model_validate(base)


def drain(generator: Any) -> tuple[list[Progress], Any]:
    """Run a Progress generator to completion, returning (progress, return value)."""
    records: list[Progress] = []
    try:
        while True:
            records.append(next(generator))
    except StopIteration as stop:
        return records, stop.value


@pytest.fixture
def real_fs_dir(request: pytest.FixtureRequest) -> Iterator[Path]:
    """A scratch directory on a real block-backed filesystem.

    Beside the repository rather than in ``tmp_path``, because tmpfs cannot
    answer the questions these tests ask. Skips, naming the filesystem, when
    even this location is not block-backed.
    """
    root = Path(__file__).resolve().parents[3]
    scratch = root / f".m2-scratch-{os.getpid()}-{abs(hash(request.node.name)) % 10**6}"
    scratch.mkdir(parents=True, exist_ok=True)

    probe = scratch / ".probe"
    probe.write_bytes(b"probe")
    device, _ = backend().block_device_for(probe)
    fs_type, _ = backend().fs_type(probe)
    probe.unlink()
    if device is None:
        shutil.rmtree(scratch, ignore_errors=True)
        pytest.skip(
            f"{scratch} is on {fs_type or 'an unidentified filesystem'}, which "
            "is not block-backed, so extents and slack cannot be measured here"
        )
    try:
        yield scratch
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


@pytest.fixture
def sparse_file(real_fs_dir: Path) -> Path:
    """A file with a real hole in it, created without any external tool."""
    target = real_fs_dir / "sparse.bin"
    with open(target, "wb") as handle:
        handle.seek(4 << 20)
        handle.write(b"tail")
    stat = os.stat(target)
    if not hasattr(stat, "st_blocks"):
        pytest.skip(
            "st_blocks is POSIX-only; NTFS sparseness is covered by "
            "tests/platform/test_windows_filesystem.py"
        )
    if stat.st_blocks * 512 >= stat.st_size:
        pytest.skip(f"{target} was not allocated sparsely on this filesystem")
    return target
