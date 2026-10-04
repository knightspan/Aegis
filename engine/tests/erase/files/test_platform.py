"""The platform seam: honest unknowns, and a real backend where one exists."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from core.erase._platform import backend
from core.erase._platform.base import Flags, PortableBackend

from .conftest import posix_only


def test_portable_backend_never_raises_and_explains_every_unknown(
    tmp_path: Path,
) -> None:
    """The contract that lets every caller skip try/except.

    A backend that raised would push error handling into every call site and
    tempt someone into swallowing the exception and reporting False - which is
    the tool claiming a guarantee it does not have.
    """
    target = tmp_path / "f.bin"
    target.write_bytes(b"x" * 64)
    portable = PortableBackend()

    resident, limits = portable.is_resident(target)
    assert resident is None
    assert limits and "resident" in limits[0].lower()

    extents, limits = portable.extents(target)
    assert extents == []
    assert limits and "verif" in limits[0].lower()

    snapshots, limits = portable.cow_snapshots(target)
    assert snapshots is None, "unknown must be None, never an empty list"
    assert limits

    device, limits = portable.block_device_for(target)
    assert device is None
    assert limits

    flags, limits = portable.flags(target)
    assert flags == Flags()
    assert limits


def test_the_portable_backend_answers_every_protocol_method(tmp_path: Path) -> None:
    """It is the base class, so a new method must never break another OS."""
    from core.erase._platform.base import PlatformBackend

    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    required = {
        name
        for name in dir(PlatformBackend)
        if not name.startswith("_") and callable(getattr(PlatformBackend, name, None))
    }
    for name in required:
        assert hasattr(PortableBackend, name), f"PortableBackend lacks {name}"


def test_backend_is_selected_once_for_this_host() -> None:
    chosen = backend()
    assert chosen.name in {"windows", "posix", "portable"}
    assert backend() is chosen, "the backend must be memoised"
    if sys.platform in {"linux", "darwin"}:
        assert chosen.name == "posix"


@posix_only
def test_the_posix_backend_reads_the_filesystem_type(tmp_path: Path) -> None:
    target = tmp_path / "f.bin"
    target.write_bytes(b"x" * 128)
    fs_type, limits = backend().fs_type(target)
    assert fs_type, f"no filesystem type was determined: {limits}"


@posix_only
def test_the_posix_backend_reads_a_cluster_size(tmp_path: Path) -> None:
    target = tmp_path / "f.bin"
    target.write_bytes(b"x" * 128)
    cluster, limits = backend().cluster_bytes(target)
    assert cluster > 0, f"no cluster size was determined: {limits}"


@posix_only
def test_the_posix_backend_round_trips_an_extended_attribute(
    tmp_path: Path,
) -> None:
    target = tmp_path / "f.bin"
    target.write_bytes(b"x" * 128)
    setter = getattr(__import__("os"), "setxattr", None)
    if setter is None:
        pytest.skip("this platform has no setxattr")
    try:
        setter(target, "user.sanctum", b"secret")
    except OSError as exc:
        pytest.skip(f"extended attributes are unavailable here: {exc}")

    names, _ = backend().xattrs(target)
    assert "user.sanctum" in names


@posix_only
def test_the_posix_backend_detects_a_sparse_file(tmp_path: Path) -> None:
    target = tmp_path / "sparse.bin"
    with open(target, "wb") as handle:
        handle.seek(4 << 20)
        handle.write(b"tail")
    import os

    if os.stat(target).st_blocks * 512 >= os.stat(target).st_size:
        pytest.skip("this filesystem did not allocate the file sparsely")
    flags, _ = backend().flags(target)
    assert flags.sparse is True


@posix_only
def test_fsync_dir_succeeds_on_posix(tmp_path: Path) -> None:
    ok, why = backend().fsync_dir(tmp_path)
    assert ok is True, why


def test_extents_come_back_empty_with_a_reason_on_a_filesystem_without_them(
    tmp_path: Path,
) -> None:
    """tmpfs answers no FIEMAP. Degrading is correct; degrading silently is not."""
    target = tmp_path / "f.bin"
    target.write_bytes(b"x" * 4096)
    extents, limits = backend().extents(target)
    if extents:
        pytest.skip(f"{tmp_path} does support extent mapping")
    assert limits, "an empty extent map must always carry its reason"
    assert any("verif" in item.lower() or "fiemap" in item.lower() for item in limits)
