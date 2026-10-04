"""Raw acquisition on Windows and macOS, through the native-adapter doubles.

The readers are exercised end to end by :func:`core.carve.acquire.acquire`:
hashes, bad-sector salvage, identity binding and a device that disappears.
Nothing opens a real device, and nothing here writes to a source.
"""

from __future__ import annotations

import hashlib
import sys
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
from core.carve import acquire as acquire_mod
from core.carve.acquire import AcquireOptions, acquire
from core.carve.mac_source import MacDiskReader, open_macos_source
from core.carve.win_source import (
    WindowsDiskReader,
    WindowsVolumeReader,
    open_windows_source,
)
from core.errors import (
    ConfirmationMismatch,
    DeviceVanished,
    EvidenceIntegrityError,
    UnsupportedCapability,
)
from core.models import AcquisitionRecord
from testkit.fake_macos import FakeMacDisk, FakeMacIo
from testkit.fake_windows import FakeDisk, FakeWindowsApi

MIB = 1 << 20
SIZE = 2 * MIB


def _run(gen: Generator[Any, None, AcquisitionRecord]) -> AcquisitionRecord:
    while True:
        try:
            next(gen)
        except StopIteration as stop:
            return stop.value


def _win(**over: Any) -> tuple[FakeWindowsApi, FakeDisk]:
    base: dict[str, Any] = {"number": 3, "size_bytes": SIZE, "serial": "EVID01"}
    base.update(over)
    disk = FakeDisk(**base)
    return FakeWindowsApi([disk]), disk


def test_windows_disk_acquisition_hashes_every_byte(tmp_path: Path) -> None:
    api, disk = _win()
    reader = WindowsDiskReader(
        api, "PhysicalDrive3", expected_serial="EVID01", expected_size=SIZE
    )
    record = _run(acquire(reader, tmp_path / "image.raw"))
    assert record.source.size_bytes == SIZE
    image = (tmp_path / "image.raw").read_bytes()
    assert image == bytes(disk.data)
    assert record.sha256 == hashlib.sha256(bytes(disk.data)).hexdigest()
    assert disk.opened_for_write == 0
    assert all(
        write is False
        for kind, (path, write) in [(k, v) for k, v in api.calls if k == "open"]
    )


def test_the_reader_is_bound_to_the_selected_disk() -> None:
    api, _ = _win(serial="SOMEONE-ELSE")
    with pytest.raises(ConfirmationMismatch):
        WindowsDiskReader(
            api, "PhysicalDrive3", expected_serial="EVID01", expected_size=SIZE
        )
    with pytest.raises(EvidenceIntegrityError, match="serial and size"):
        open_windows_source("\\\\.\\PhysicalDrive3", api=api)


def test_a_drive_letter_is_never_taken_for_the_disk() -> None:
    with pytest.raises(UnsupportedCapability):
        WindowsDiskReader(
            FakeWindowsApi([]), "E:", expected_serial="x", expected_size=1
        )


def test_windows_bad_sectors_are_salvaged_and_recorded(tmp_path: Path) -> None:
    api, disk = _win(unreadable_sectors={10})
    reader = WindowsDiskReader(
        api, "PhysicalDrive3", expected_serial="EVID01", expected_size=SIZE
    )
    record = _run(acquire(reader, tmp_path / "image.raw"))
    assert [(r.first_lba, r.last_lba) for r in record.bad_sectors] == [(10, 10)]
    image = (tmp_path / "image.raw").read_bytes()
    assert image[10 * 512 : 11 * 512] == bytes(512)
    assert image[: 10 * 512] == bytes(disk.data[: 10 * 512])


def test_a_disk_that_disappears_aborts_rather_than_fills(tmp_path: Path) -> None:
    api, disk = _win()
    reader = WindowsDiskReader(
        api, "PhysicalDrive3", expected_serial="EVID01", expected_size=SIZE
    )
    gen = acquire(reader, tmp_path / "image.raw")
    next(gen)
    disk.present = False
    with pytest.raises(DeviceVanished):
        _run(gen)


def test_4kn_disk_serves_512_byte_salvage_reads() -> None:
    api, disk = _win(sector=4096, physical_sector=4096)
    reader = WindowsDiskReader(
        api, "PhysicalDrive3", expected_serial="EVID01", expected_size=SIZE
    )
    assert reader.read_at(512, 512) == bytes(disk.data[512:1024])


def test_logical_volume_acquisition(tmp_path: Path) -> None:
    api, disk = _win(letters={"E": (MIB, 512 * 1024)})
    reader = WindowsVolumeReader(api, "\\\\.\\E:")
    record = _run(acquire(reader, tmp_path / "vol.raw"))
    assert record.source.size_bytes == 512 * 1024
    assert (tmp_path / "vol.raw").read_bytes() == bytes(
        disk.data[MIB : MIB + 512 * 1024]
    )


def test_a_win32_path_on_windows_goes_to_the_createfile_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    api, disk = _win()
    monkeypatch.setattr(acquire_mod.sys, "platform", "win32")
    monkeypatch.setattr("core.device.win.native.default_api", lambda: api)
    options = AcquireOptions(expected_serial="EVID01", expected_size=SIZE)
    record = _run(acquire("\\\\.\\PhysicalDrive3", tmp_path / "d.raw", options=options))
    assert record.sha256 == hashlib.sha256(bytes(disk.data)).hexdigest()
    assert any("NO_SOFTWARE_WRITE_BLOCK" in item for item in record.limitations)


def test_a_win32_path_off_windows_is_refused_by_name(tmp_path: Path) -> None:
    # On Windows the same path is a real device path; without the selected
    # disk's serial and size the handle cannot be bound, and nothing is opened.
    expected = "needs the serial and size" if sys.platform == "win32" else "not Windows"
    with pytest.raises(EvidenceIntegrityError, match=expected):
        _run(acquire("\\\\.\\PhysicalDrive3", tmp_path / "d.raw"))


# -- macOS --------------------------------------------------------------------------


def test_macos_raw_acquisition_reads_the_raw_device(tmp_path: Path) -> None:
    disk = FakeMacDisk(name="disk4", size_bytes=SIZE)
    io = FakeMacIo([disk])
    reader = MacDiskReader("/dev/disk4", expected_size=SIZE, io=io)
    record = _run(acquire(reader, tmp_path / "m.raw"))
    assert (tmp_path / "m.raw").read_bytes() == bytes(disk.data)
    assert record.sha256 == hashlib.sha256(bytes(disk.data)).hexdigest()
    assert io.opened == [("/dev/rdisk4", False)]


def test_macos_reader_refuses_a_size_mismatch_and_needs_root() -> None:
    io = FakeMacIo([FakeMacDisk(name="disk4", size_bytes=SIZE)])
    with pytest.raises(ConfirmationMismatch):
        MacDiskReader("disk4", expected_size=SIZE * 2, io=io)
    with pytest.raises(UnsupportedCapability, match="root"):
        MacDiskReader(
            "disk4",
            expected_size=SIZE,
            io=FakeMacIo([FakeMacDisk(name="disk4", size_bytes=SIZE)], root=False),
        )
    with pytest.raises(EvidenceIntegrityError):
        open_macos_source("disk4", io=io)


def test_macos_bad_blocks_are_salvaged(tmp_path: Path) -> None:
    disk = FakeMacDisk(name="disk4", size_bytes=SIZE, bad_blocks={7})
    reader = MacDiskReader("disk4", expected_size=SIZE, io=FakeMacIo([disk]))
    record = _run(acquire(reader, tmp_path / "m.raw"))
    assert [(r.first_lba, r.last_lba) for r in record.bad_sectors] == [(7, 7)]
