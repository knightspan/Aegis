"""Free-space wipe gates, without mounting anything and without writing a fill.

Nothing here fills a filesystem. ``tmp_path`` is usually on a tmpfs under a
per-user quota, and filling it would stop the suite - which is exactly the
failure the system-volume gate exists to prevent. The fill itself is exercised
on loop volumes in ``test_free_space_wipe_carve.py``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from core.device.guard import (
    SYSTEM_PATHS,
    assert_volume_confirmed,
    assert_volume_wipeable,
)
from core.errors import ConfirmationMismatch, SystemDiskRefused, UnsupportedCapability
from core.models import FreeSpaceWipeOptions, VolumeInfo

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="the volume is resolved from /proc/mounts"
)


def volume(**overrides: object) -> VolumeInfo:
    base: dict[str, object] = {
        "mount_point": "/run/media/op/STICK",
        "fs_type": "vfat",
        "source": "/dev/sdz1",
        "fs_uuid": "7BD6-024B",
        "identifier": "7BD6-024B",
        "st_dev": 4242,
        "frsize": 4096,
        "trim_likely": True,
    }
    base.update(overrides)
    return VolumeInfo.model_validate(base)


# --------------------------------------------------------------------------
# resolve_volume
# --------------------------------------------------------------------------


def test_a_folder_inside_a_volume_is_refused_and_the_mount_is_named(
    tmp_path: Path,
) -> None:
    from core.erase.freespace import resolve_volume

    inner = tmp_path / "folder"
    inner.mkdir()
    mounts = f"/dev/sdz1 {tmp_path} vfat rw 0 0\n"
    with pytest.raises(UnsupportedCapability) as excinfo:
        resolve_volume(inner, mounts_text=mounts, by_uuid=tmp_path / "none")
    assert str(tmp_path) in excinfo.value.message
    assert "not a mount point" in excinfo.value.message


@pytest.mark.parametrize(
    "fs_type", ["btrfs", "ntfs", "ntfs3", "fuseblk", "fuse.ext4", "tmpfs", "xfs"]
)
def test_filesystems_whose_fill_was_not_measured_are_refused(
    tmp_path: Path, fs_type: str
) -> None:
    from core.erase.freespace import resolve_volume

    mounts = f"/dev/sdz1 {tmp_path} {fs_type} rw 0 0\n"
    with pytest.raises(UnsupportedCapability) as excinfo:
        resolve_volume(tmp_path, mounts_text=mounts, by_uuid=tmp_path / "none")
    assert fs_type in excinfo.value.message


@pytest.mark.parametrize("fs_type", ["vfat", "exfat", "ext4"])
def test_a_supported_volume_resolves_with_the_mount_point_as_identifier(
    tmp_path: Path, fs_type: str
) -> None:
    from core.erase.freespace import resolve_volume

    mounts = f"/dev/sdz1 {tmp_path} {fs_type} rw 0 0\n"
    found = resolve_volume(tmp_path, mounts_text=mounts, by_uuid=tmp_path / "none")
    assert found.mount_point == str(tmp_path)
    assert found.identifier == str(tmp_path)
    assert found.fs_uuid is None
    assert found.st_dev == os.stat(tmp_path).st_dev


def test_the_uuid_is_the_identifier_when_one_links_to_the_source(
    tmp_path: Path,
) -> None:
    from core.erase.freespace import resolve_volume

    source = tmp_path / "fake-device"
    source.write_bytes(b"")
    by_uuid = tmp_path / "by-uuid"
    by_uuid.mkdir()
    (by_uuid / "7BD6-024B").symlink_to(source)
    point = tmp_path / "mnt"
    point.mkdir()
    # resolve_volume only reads a UUID for a /dev source; a symlink under /dev
    # cannot be made here, so the source is recorded as the link's target path
    # and the lookup is exercised directly.
    from core.erase import freespace

    assert freespace._uuid_for(str(source), by_uuid) == "7BD6-024B"
    mounts = f"{source} {point} exfat rw 0 0\n"
    found = resolve_volume(point, mounts_text=mounts, by_uuid=by_uuid)
    assert found.fs_uuid is None, "a non-/dev source must not borrow a UUID"


# --------------------------------------------------------------------------
# assert_volume_wipeable
# --------------------------------------------------------------------------


@pytest.mark.parametrize("system_path", SYSTEM_PATHS)
def test_the_volume_holding_any_system_path_is_refused(system_path: str) -> None:
    def stat_dev(path: Path) -> int | None:
        return 4242 if str(path) == system_path else 1

    with pytest.raises(SystemDiskRefused) as excinfo:
        assert_volume_wipeable(volume(), stat_dev=stat_dev, swap_files=list)
    assert system_path in excinfo.value.message


def test_the_volume_holding_an_active_swap_file_is_refused() -> None:
    swap = Path("/run/media/op/STICK/swapfile")

    def stat_dev(path: Path) -> int | None:
        return 4242 if path == swap else 1

    with pytest.raises(SystemDiskRefused) as excinfo:
        assert_volume_wipeable(volume(), stat_dev=stat_dev, swap_files=lambda: [swap])
    assert "swap" in excinfo.value.message


def test_the_volume_holding_this_deployments_state_is_refused() -> None:
    state = Path("/run/media/op/STICK/sanctum-state")

    def stat_dev(path: Path) -> int | None:
        return 4242 if path == state else 1

    with pytest.raises(SystemDiskRefused) as excinfo:
        assert_volume_wipeable(
            volume(), protected=[state], stat_dev=stat_dev, swap_files=list
        )
    assert "this deployment's own state" in excinfo.value.message


def test_a_separate_data_volume_passes() -> None:
    assert_volume_wipeable(volume(), stat_dev=lambda path: 1, swap_files=list)


def test_the_real_root_filesystem_is_refused_whatever_its_type() -> None:
    root = VolumeInfo.model_validate(
        volume(mount_point="/", st_dev=os.stat("/").st_dev).model_dump()
    )
    with pytest.raises(SystemDiskRefused):
        assert_volume_wipeable(root)


# --------------------------------------------------------------------------
# assert_volume_confirmed
# --------------------------------------------------------------------------


@pytest.mark.parametrize("typed", ["", "   ", "7BD6-024C", "/run/media/op/STICK"])
def test_anything_but_the_identifier_is_refused(typed: str) -> None:
    with pytest.raises(ConfirmationMismatch) as excinfo:
        assert_volume_confirmed(volume(), typed)
    assert "7BD6-024B" in excinfo.value.remediation


def test_the_identifier_confirms_case_insensitively() -> None:
    assert_volume_confirmed(volume(), " 7bd6-024b ")


# --------------------------------------------------------------------------
# wipe_free_space: the gates run before anything is created
# --------------------------------------------------------------------------


def _unreal_volume(point: Path) -> VolumeInfo:
    # st_dev -1 matches no real path, so the system-volume gate passes without
    # this test depending on which filesystem tmp_path is on.
    return volume(mount_point=str(point), identifier=str(point), st_dev=-1)


def _drain(generator: object) -> object:
    try:
        while True:
            next(generator)  # type: ignore[call-overload]
    except StopIteration as finished:
        return finished.value


def test_the_read_only_plan_creates_nothing_and_names_the_identifier(
    tmp_path: Path,
) -> None:
    from core.erase.freespace import NOT_REACHED, plan_volume

    point = tmp_path / "volume"
    point.mkdir()
    volume = _unreal_volume(point)
    plan = plan_volume(point, volume=volume)
    assert list(point.iterdir()) == []
    assert plan["identifier"] == volume.identifier
    assert plan["not_reached"] == list(NOT_REACHED)
    assert plan["free_bytes"] >= 0


def test_the_wipe_has_no_rehearsal_mode() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        FreeSpaceWipeOptions.model_validate({"dry_run": True})


def test_a_run_without_the_identifier_writes_nothing(tmp_path: Path) -> None:
    from core.erase.freespace import wipe_free_space

    point = tmp_path / "volume"
    point.mkdir()
    generator = wipe_free_space(
        point,
        FreeSpaceWipeOptions(typed_identifier="wrong"),
        job_id="job-refused",
        ledger=None,
        volume=_unreal_volume(point),
    )
    with pytest.raises(ConfirmationMismatch):
        next(generator)
    assert list(point.iterdir()) == []


def test_flash_and_reserved_blocks_are_named_before_the_fill(tmp_path: Path) -> None:
    from core.erase.freespace import plan_volume

    point = tmp_path / "volume"
    point.mkdir()
    plan = plan_volume(point, volume=_unreal_volume(point))
    blob = " ".join(plan["limitations"])
    assert "flash" in blob
    assert list(point.iterdir()) == []
