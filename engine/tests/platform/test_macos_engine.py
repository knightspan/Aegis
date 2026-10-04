"""macOS external-disk clear and preparation, end to end, through doubles.

``diskutil`` and ``system_profiler`` answer from fixtures; ``/dev/rdiskN``
answers from :class:`testkit.fake_macos.FakeMacIo`. No device is touched.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
from core.errors import (
    ConfirmationMismatch,
    MountedRefused,
    SystemDiskRefused,
    UnsupportedCapability,
)
from core.platform.macos import MacOSAdapter
from core.platform.model import Capability, CapabilityState, PrivilegeState
from testkit.fake_macos import FakeMacDisk, FakeMacIo

from .conftest import mac_listing, mac_profiler, mac_runner

T7_SIZE = 1000204886016
ROOT = PrivilegeState(level="root", elevated=True, basis="os.geteuid() returned 0")


@pytest.fixture(autouse=True)
def _no_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "record.json"
    path.write_text(json.dumps({"physical_validations": []}), encoding="utf-8")
    monkeypatch.setattr("core.platform.validation.RECORD_PATH", path)


def _unmounted() -> dict[str, Any]:
    listing = copy.deepcopy(mac_listing())
    for entry in listing["AllDisksAndPartitions"]:
        if entry["DeviceIdentifier"] == "disk4":
            for part in entry["Partitions"]:
                part.pop("MountPoint", None)
    return listing


def _adapter(
    *,
    listing: dict[str, Any] | None = None,
    profiler: dict[str, Any] | None = None,
    io: FakeMacIo | None = None,
) -> MacOSAdapter:
    return MacOSAdapter(
        runner=mac_runner(listing=listing, profiler=profiler),
        mac_io=io,
        privilege=ROOT,
    )


def _small_setup(size: int = 1 << 20) -> tuple[MacOSAdapter, FakeMacDisk]:
    """An unmounted external disk4 whose diskutil size matches a small fake."""
    listing = _unmounted()
    from . import conftest

    infos = conftest.mac_infos()
    infos["disk4"]["TotalSize"] = size
    disk = FakeMacDisk(name="disk4", size_bytes=size)

    runner = mac_runner(listing=listing)
    base_answer = runner.answer

    import plistlib

    from core.device._sysio import CommandResult

    def answer(argv: list[str]) -> CommandResult:
        if argv[1:4] == ["info", "-plist", "disk4"]:
            return CommandResult(argv, 0, plistlib.dumps(infos["disk4"]).decode(), "")
        return base_answer(argv)

    runner.answer = answer
    adapter = MacOSAdapter(runner=runner, mac_io=FakeMacIo([disk]), privilege=ROOT)
    return adapter, disk


def _params(tmp_path: Path, **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "path": "disk4",
        "level": "CLEAR",
        "typed_serial": "S5T7NS0R123456",
        "ledger_root": str(tmp_path / "ledger"),
        "job_id": "job-m1",
    }
    base.update(over)
    return base


def _drain(gen: Generator[dict[str, Any], None, dict[str, Any]]) -> dict[str, Any]:
    while True:
        try:
            next(gen)
        except StopIteration as stop:
            return stop.value


def test_the_external_ssd_offers_clear_and_refuses_purge_by_platform() -> None:
    adapter = _adapter(listing=_unmounted())
    t7 = adapter.inspect_device("disk4")
    assessment = adapter.assess_device(t7)
    assert assessment.headline == "READY"
    assert assessment.device_class == "usb-ssd"
    assert assessment.recommended is not None
    assert assessment.recommended.level == "CLEAR"
    assert "/dev/rdisk" in assessment.recommended.mechanism
    rows = {row.capability: row for row in assessment.capabilities}
    assert (
        rows[Capability.ATA_SANITIZE].state is CapabilityState.UNSUPPORTED_BY_PLATFORM
    )
    assert (
        rows[Capability.NVME_SANITIZE].state is CapabilityState.UNSUPPORTED_BY_PLATFORM
    )
    raw = rows[Capability.RAW_ACQUISITION]
    assert raw.state is CapabilityState.IMPLEMENTED_NOT_PHYSICALLY_VALIDATED


def test_a_real_clear_of_an_external_disk(tmp_path: Path) -> None:
    adapter, disk = _small_setup()
    result = _drain(adapter.execute_drive_sanitization(_params(tmp_path)))["result"]
    assert bytes(disk.data) == b"\xa5" * len(disk.data)
    assert result["verification"]["passed"] is True
    assert result["achieved_level"] == "CLEAR"
    assert any("system_profiler" in text for text in result["limitations"])


@pytest.mark.parametrize("key", ["dry_run", "simulation", "simulate"])
def test_a_simulation_switch_is_refused_and_opens_nothing(
    tmp_path: Path, key: str
) -> None:
    from core.errors import WorkflowGateRefused

    adapter, disk = _small_setup()
    before = bytes(disk.data)
    with pytest.raises(WorkflowGateRefused, match=key):
        _drain(adapter.execute_drive_sanitization(_params(tmp_path, **{key: True})))
    assert bytes(disk.data) == before
    assert disk.writes == 0

def test_a_mounted_external_disk_is_refused(tmp_path: Path) -> None:
    adapter = _adapter(io=FakeMacIo([]))
    with pytest.raises(MountedRefused):
        _drain(adapter.execute_drive_sanitization(_params(tmp_path)))


def test_internal_storage_is_refused_even_when_asked(tmp_path: Path) -> None:
    adapter = _adapter(io=FakeMacIo([]))
    with pytest.raises(SystemDiskRefused):
        _drain(adapter.execute_drive_sanitization(_params(tmp_path, path="disk0")))


def test_purge_is_refused_never_downgraded(tmp_path: Path) -> None:
    adapter, disk = _small_setup()
    with pytest.raises(UnsupportedCapability, match="never replaced"):
        _drain(adapter.execute_drive_sanitization(_params(tmp_path, level="PURGE")))
    assert disk.writes == 0


def test_a_serial_that_changes_before_the_seam_is_refused(tmp_path: Path) -> None:
    adapter, disk = _small_setup()
    changed = copy.deepcopy(mac_profiler())
    changed["SPUSBDataType"][0]["_items"][0]["serial_num"] = "OTHERSERIAL"
    original = adapter.serials

    calls = {"n": 0}

    def serials() -> dict[str, str]:
        calls["n"] += 1
        if calls["n"] > 1:
            from core.platform.macos import serial_map

            return serial_map(changed)
        return original()

    adapter.serials = serials  # type: ignore[method-assign]
    with pytest.raises(ConfirmationMismatch, match="now reports serial"):
        _drain(adapter.execute_drive_sanitization(_params(tmp_path)))
    assert disk.writes == 0


def test_unmount_is_its_own_explicit_step() -> None:
    adapter = _adapter()
    with pytest.raises(ConfirmationMismatch):
        adapter.prepare_device({"path": "disk4"})
    done = adapter.prepare_device(
        {"path": "disk4", "typed_serial": "S5T7NS0R123456"}
    )
    assert done["performed"] is True
    assert done["unmounts"] == ["/Volumes/BACKUP"]
    with pytest.raises(SystemDiskRefused):
        adapter.prepare_device({"path": "disk0"})


def test_resume_finishes_an_interrupted_external_clear(tmp_path: Path) -> None:
    adapter, disk = _small_setup(size=1 << 20)
    params = _params(tmp_path)
    gen = adapter.execute_drive_sanitization(params)
    next(gen)
    next(gen)
    gen.close()
    result = _drain(adapter.resume_drive_sanitization(params))
    assert "result" in result
