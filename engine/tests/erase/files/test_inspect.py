"""Inspection runs before anything is written, and never writes."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from core.erase.inspect import SYNC_DIR_MARKERS, in_sync_directory, inspect_path


def test_inspection_reports_size_and_link_count(real_fs_dir: Path) -> None:
    target = real_fs_dir / "f.bin"
    target.write_bytes(b"x" * 4096)
    inspection = inspect_path(target)
    assert inspection.size_bytes == 4096
    assert inspection.hardlink_count == 1
    assert inspection.is_reparse_point is False


def test_hardlinks_are_counted(real_fs_dir: Path) -> None:
    original = real_fs_dir / "a.bin"
    original.write_bytes(b"payload")
    os.link(original, real_fs_dir / "b.bin")
    assert inspect_path(original).hardlink_count == 2


def test_slack_is_derived_from_the_cluster_size(real_fs_dir: Path) -> None:
    target = real_fs_dir / "small.bin"
    target.write_bytes(b"x" * 100)
    inspection = inspect_path(target)
    if inspection.cluster_bytes == 0:
        pytest.skip("cluster size unavailable on this filesystem")
    assert inspection.slack_bytes == inspection.cluster_bytes - 100


def test_inspection_does_not_modify_the_file(real_fs_dir: Path) -> None:
    """Read-only, including the timestamps.

    An inspection that bumped st_atime would alter the evidence it is meant to
    record - and MAC timestamps are exactly what an examiner reads.
    """
    target = real_fs_dir / "f.bin"
    target.write_bytes(b"original")
    before = target.stat()

    inspect_path(target)

    after = target.stat()
    assert target.read_bytes() == b"original"
    assert after.st_mtime_ns == before.st_mtime_ns
    assert after.st_size == before.st_size


def test_a_symlink_is_flagged_and_not_followed(real_fs_dir: Path) -> None:
    """The target must not be inspected, let alone erased."""
    target = real_fs_dir / "real.bin"
    target.write_bytes(b"real")
    link = real_fs_dir / "link.bin"
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable to this user: {exc}")

    inspection = inspect_path(link)

    assert inspection.is_reparse_point is True
    assert inspection.extents == [], "a link's target must not be mapped"
    assert any("not be erased" in item for item in inspection.limitations)
    assert target.read_bytes() == b"real"


def test_a_real_extent_map_is_captured_on_a_block_backed_filesystem(
    real_fs_dir: Path,
) -> None:
    """Without this the erase cannot be verified at all, so it is worth asserting.

    The physical offset has to be a real volume address, not a logical one: a
    backend that returned the logical offset would look right in every field
    and address the wrong blocks.
    """
    target = real_fs_dir / "mapped.bin"
    target.write_bytes(b"x" * (256 * 1024))

    inspection = inspect_path(target)

    if not inspection.extents:
        pytest.skip(
            f"{inspection.fs_type or 'this filesystem'} returned no extent map: "
            + "; ".join(inspection.limitations)[:200]
        )
    assert sum(extent.length for extent in inspection.extents) >= 256 * 1024
    assert inspection.extents[0].physical_offset > 0
    assert inspection.extents[0].physical_offset != inspection.extents[0].logical_offset


def test_a_missing_file_yields_a_limitation_rather_than_raising(
    real_fs_dir: Path,
) -> None:
    inspection = inspect_path(real_fs_dir / "never-existed.bin")
    assert inspection.size_bytes == 0
    assert inspection.limitations


def test_sync_directories_are_recognised_case_insensitively() -> None:
    assert in_sync_directory(Path("/home/x/OneDrive/secret.txt"))
    assert in_sync_directory(Path("/home/x/dropbox/y/secret.txt"))
    assert not in_sync_directory(Path("/home/x/Documents/secret.txt"))
    assert SYNC_DIR_MARKERS, "the marker list must not be empty"


def test_an_unknown_capability_is_none_and_carries_a_reason(
    real_fs_dir: Path,
) -> None:
    """Every unknown must be explained, or the report is just a shrug."""
    target = real_fs_dir / "f.bin"
    target.write_bytes(b"x" * 64)

    inspection = inspect_path(target)

    unknowns = {
        "is_resident": inspection.is_resident,
        "trim_likely": inspection.trim_likely,
        "cow_snapshots": inspection.cow_snapshots,
    }
    for name, value in unknowns.items():
        if value is None:
            assert inspection.limitations, (
                f"{name} is unknown but no reason was recorded"
            )
