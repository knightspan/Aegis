"""Windows whole-drive clear, device sanitize and preparation, end to end.

Discovery answers from a PowerShell inventory built here; the disk answers
from :class:`testkit.fake_windows.FakeWindowsApi`. The adapter under test is
the real :class:`core.platform.windows.WindowsAdapter`: revalidation, the
resolver, handle binding, the engines and the ledger all run for real. No
device is touched.
"""

from __future__ import annotations

import json
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
from core.errors import (
    ConfirmationMismatch,
    DeviceVanished,
    MountedRefused,
    SystemDiskRefused,
    UnsupportedCapability,
)
from core.platform.model import Capability, CapabilityState, PrivilegeState
from core.platform.windows import WindowsAdapter
from testkit.fake_windows import FakeAta, FakeDisk, FakeNvme, FakeWindowsApi

from .conftest import FakeRunner, ok

MIB = 1 << 20
SIZE = 2 * MIB
ADMIN = PrivilegeState(
    level="administrator", elevated=True, basis="IsUserAnAdmin() returned 1"
)
USER = PrivilegeState(
    level="standard", elevated=False, basis="IsUserAnAdmin() returned 0"
)
EMPTY_RECORD: dict[str, Any] = {"physical_validations": []}


@pytest.fixture(autouse=True)
def _no_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "record.json"
    path.write_text(json.dumps(EMPTY_RECORD), encoding="utf-8")
    monkeypatch.setattr("core.platform.validation.RECORD_PATH", path)


def _disk_row(
    number: int, serial: str, bus: str, *, boot: bool = False, size: int = SIZE
) -> dict[str, Any]:
    return {
        "Number": number,
        "FriendlyName": f"Disk {number}",
        "SerialNumber": serial,
        "Size": size,
        "BusType": bus,
        "IsBoot": boot,
        "IsSystem": boot,
        "IsOffline": False,
        "IsReadOnly": False,
        "PartitionStyle": "MBR",
        "UniqueId": f"UID{number}",
        "Manufacturer": "FAKE",
        "Model": f"Model {number}",
    }


def _inventory(
    rows: list[dict[str, Any]],
    media: dict[int, str],
    letters: dict[int, str] | None = None,
) -> dict[str, Any]:
    partitions = [
        {
            "DiskNumber": number,
            "PartitionNumber": 1,
            "DriveLetter": letter,
            "Size": MIB,
            "Type": "IFS",
            "IsBoot": False,
            "IsSystem": False,
            "AccessPaths": [f"{letter}:\\"],
        }
        for number, letter in (letters or {}).items()
    ]
    return {
        "disks": rows,
        "physical": [
            {
                "DeviceId": str(row["Number"]),
                "MediaType": media.get(row["Number"], "Unspecified"),
                "BusType": row["BusType"],
                "SerialNumber": row["SerialNumber"],
            }
            for row in rows
        ],
        "partitions": partitions,
        "volumes": [
            {
                "DriveLetter": letter,
                "FileSystem": "FAT32",
                "FileSystemLabel": "X",
                "DriveType": "Removable",
                "Path": "",
            }
            for letter in (letters or {}).values()
        ],
        "pagefiles": [],
        "system_drive": "C:",
        "hiberfil": False,
    }


def _adapter(
    inventory: dict[str, Any], api: FakeWindowsApi, privilege: PrivilegeState = ADMIN
) -> WindowsAdapter:
    runner = FakeRunner(lambda argv: ok(argv, json.dumps(inventory)))
    return WindowsAdapter(
        runner=runner, native=api, privilege=privilege, os_build=26100, poll_s=0.0
    )


def _stick(**over: Any) -> FakeDisk:
    base: dict[str, Any] = {"number": 2, "size_bytes": SIZE, "serial": "STICK01"}
    base.update(over)
    return FakeDisk(**base)


def _usb_setup(**over: Any) -> tuple[WindowsAdapter, FakeWindowsApi]:
    api = FakeWindowsApi([_stick(**over)])
    inventory = _inventory([_disk_row(2, "STICK01", "USB")], {})
    return _adapter(inventory, api), api


def _params(tmp_path: Path, **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "path": "PhysicalDrive2",
        "level": "CLEAR",
        "typed_serial": "STICK01",
        "ledger_root": str(tmp_path / "ledger"),
        "job_id": "job-w1",
    }
    base.update(over)
    return base


def _drain(gen: Generator[dict[str, Any], None, dict[str, Any]]) -> dict[str, Any]:
    while True:
        try:
            next(gen)
        except StopIteration as stop:
            return stop.value


# -- assessment ----------------------------------------------------------------


def test_a_usb_stick_offers_clear_and_explains_why_not_purge() -> None:
    adapter, _ = _usb_setup(bridge_blocks_ata=True)
    device = adapter.inspect_device("PhysicalDrive2")
    assessment = adapter.assess_device(device)
    assert assessment.headline == "READY"
    assert assessment.device_class == "usb-flash"
    assert assessment.recommended is not None
    assert assessment.recommended.level == "CLEAR"
    assert (
        assessment.recommended.state
        is CapabilityState.IMPLEMENTED_NOT_PHYSICALLY_VALIDATED
    )
    purge = next(o for o in assessment.unavailable if o.level == "PURGE")
    assert purge.state is CapabilityState.UNSUPPORTED_BY_DEVICE
    assert "bridge" in purge.why
    states = {row.capability: row.state for row in assessment.capabilities}
    assert (
        states[Capability.RAW_ACQUISITION]
        is CapabilityState.IMPLEMENTED_NOT_PHYSICALLY_VALIDATED
    )
    assert states[Capability.NVME_FORMAT] is CapabilityState.UNSUPPORTED_BY_PLATFORM


def test_an_nvme_drive_reporting_sanitize_is_offered_purge_first() -> None:
    api = FakeWindowsApi(
        [
            FakeDisk(
                number=1,
                size_bytes=SIZE,
                serial="NVME01",
                bus_type=17,
                removable=False,
                nvme=FakeNvme(model="N", serial="NVME01", block_erase=True),
            )
        ]
    )
    adapter = _adapter(_inventory([_disk_row(1, "NVME01", "NVMe")], {1: "SSD"}), api)
    assessment = adapter.assess_device(adapter.inspect_device("PhysicalDrive1"))
    assert assessment.recommended is not None
    assert assessment.recommended.level == "PURGE"
    assert assessment.recommended.method == "NVME_SANITIZE_BLOCK"
    assert "REINITIALIZE_MEDIA" in assessment.recommended.mechanism
    rows = {row.capability: row for row in assessment.capabilities}
    assert rows[Capability.CRYPTO_ERASE].state is CapabilityState.UNSUPPORTED_BY_DEVICE
    assert "SANICAP crypto erase: no" in rows[Capability.CRYPTO_ERASE].reason


def test_unelevated_is_not_authorized_and_says_the_probe_did_not_run() -> None:
    api = FakeWindowsApi([_stick()], elevated=False)
    adapter = _adapter(_inventory([_disk_row(2, "STICK01", "USB")], {}), api, USER)
    assessment = adapter.assess_device(adapter.inspect_device("PhysicalDrive2"))
    assert assessment.headline == "NOT AUTHORIZED"
    assert "Run as administrator" in assessment.recommended_action
    rows = {row.capability: row for row in assessment.capabilities}
    assert (
        rows[Capability.WHOLE_DRIVE_CLEAR].state
        is CapabilityState.AVAILABLE_BUT_REQUIRES_PRIVILEGE
    )


def test_the_platform_matrix_no_longer_says_unsupported_for_whole_drive() -> None:
    adapter, _ = _usb_setup()
    rows = {row.operation.value: row for row in adapter.operation_capabilities()}
    clear = rows["whole_drive_clear"]
    assert clear.state is CapabilityState.IMPLEMENTED_NOT_PHYSICALLY_VALIDATED
    assert "PhysicalDrive" in clear.mechanism
    assert rows["free_space_wipe"].state is CapabilityState.NOT_IMPLEMENTED
    assert (
        rows["whole_drive_purge"].state is CapabilityState.IMPLEMENTED_DEVICE_DEPENDENT
    )


def test_authorization_probe_has_the_workflow_shape() -> None:
    adapter, _ = _usb_setup(bridge_blocks_ata=True)
    probe = adapter.authorization_probe("PhysicalDrive2")
    assert probe["device"]["serial"] == "STICK01"
    assert probe["device"]["size_bytes"] == SIZE
    assert probe["device"]["is_system_disk"] is False
    assert probe["capabilities"]["achievable_levels"] == ["CLEAR"]


# -- execution ------------------------------------------------------------------


def test_a_real_clear_writes_every_byte_through_the_bound_handle(
    tmp_path: Path,
) -> None:
    adapter, api = _usb_setup()
    answer = _drain(adapter.execute_drive_sanitization(_params(tmp_path)))
    result = answer["result"]
    assert bytes(api.disks[2].data) == b"\xa5" * SIZE
    assert result["verification"]["passed"] is True
    assert result["achieved_level"] == "CLEAR"
    assert result["level"] == "CLEAR"


@pytest.mark.parametrize("key", ["dry_run", "simulation", "simulate"])
def test_a_simulation_switch_is_refused_and_writes_nothing(
    tmp_path: Path, key: str
) -> None:
    """Neither honoured nor ignored: refused before the disk is opened."""
    from core.errors import WorkflowGateRefused

    adapter, api = _usb_setup()
    before = bytes(api.disks[2].data)
    with pytest.raises(WorkflowGateRefused, match=key):
        _drain(adapter.execute_drive_sanitization(_params(tmp_path, **{key: True})))
    assert bytes(api.disks[2].data) == before
    assert api.disks[2].writes == 0

def test_a_mistyped_serial_writes_nothing(tmp_path: Path) -> None:
    adapter, api = _usb_setup()
    with pytest.raises(ConfirmationMismatch):
        _drain(
            adapter.execute_drive_sanitization(_params(tmp_path, typed_serial="NOPE"))
        )
    assert api.disks[2].writes == 0


def test_mounted_and_system_disks_are_refused(tmp_path: Path) -> None:
    api = FakeWindowsApi([_stick()])
    mounted = _adapter(_inventory([_disk_row(2, "STICK01", "USB")], {}, {2: "E"}), api)
    with pytest.raises(MountedRefused):
        _drain(mounted.execute_drive_sanitization(_params(tmp_path)))
    boot = _adapter(_inventory([_disk_row(2, "STICK01", "USB", boot=True)], {}), api)
    with pytest.raises(SystemDiskRefused):
        _drain(boot.execute_drive_sanitization(_params(tmp_path)))
    assert api.disks[2].writes == 0


def test_a_disk_swapped_after_discovery_is_refused_at_the_seam(tmp_path: Path) -> None:
    adapter, api = _usb_setup(serial="SWAPPED9")
    with pytest.raises(ConfirmationMismatch, match="not the disk that was planned"):
        _drain(adapter.execute_drive_sanitization(_params(tmp_path)))
    assert api.disks[2].writes == 0


def test_a_volume_mounted_after_discovery_is_refused_at_the_seam(
    tmp_path: Path,
) -> None:
    adapter, api = _usb_setup(volumes={"\\\\?\\Volume{late}\\": ["F:\\"]})
    with pytest.raises(MountedRefused, match="write seam"):
        _drain(adapter.execute_drive_sanitization(_params(tmp_path)))
    assert api.disks[2].writes == 0


def test_a_letterless_volume_still_blocks_until_the_disk_is_offline(
    tmp_path: Path,
) -> None:
    adapter, api = _usb_setup(volumes={"\\\\?\\Volume{hidden}\\": []})
    with pytest.raises(MountedRefused, match="still exposes volume"):
        _drain(adapter.execute_drive_sanitization(_params(tmp_path)))
    assert api.disks[2].writes == 0
    adapter.prepare_device(
        {"path": "PhysicalDrive2", "typed_serial": "STICK01"}
    )
    result = _drain(adapter.execute_drive_sanitization(_params(tmp_path)))["result"]
    assert result["verification"]["passed"] is True


def test_an_ambiguous_serial_is_refused(tmp_path: Path) -> None:
    api = FakeWindowsApi([_stick(), _stick(number=3)])
    inventory = _inventory(
        [_disk_row(2, "STICK01", "USB"), _disk_row(3, "STICK01", "USB")], {}
    )
    adapter = _adapter(inventory, api)
    adapter.enumerate_devices()
    with pytest.raises(ConfirmationMismatch, match="ambiguous"):
        _drain(adapter.execute_drive_sanitization(_params(tmp_path)))


def test_a_device_that_vanishes_mid_clear_stops(tmp_path: Path) -> None:
    adapter, api = _usb_setup(vanish_after_writes=0)
    with pytest.raises(DeviceVanished):
        _drain(adapter.execute_drive_sanitization(_params(tmp_path)))


def test_purge_on_a_usb_stick_is_refused_never_downgraded(tmp_path: Path) -> None:
    adapter, api = _usb_setup(bridge_blocks_ata=True)
    with pytest.raises(UnsupportedCapability, match="never replaced by an overwrite"):
        _drain(adapter.execute_drive_sanitization(_params(tmp_path, level="PURGE")))
    assert api.disks[2].writes == 0


def test_nvme_block_sanitize_is_issued_and_read_back(tmp_path: Path) -> None:
    disk = FakeDisk(
        number=1,
        size_bytes=SIZE,
        serial="NVME01",
        bus_type=17,
        removable=False,
        nvme=FakeNvme(model="N", serial="NVME01", block_erase=True),
    )
    api = FakeWindowsApi([disk])
    adapter = _adapter(_inventory([_disk_row(1, "NVME01", "NVMe")], {1: "SSD"}), api)
    params = _params(
        tmp_path, path="PhysicalDrive1", typed_serial="NVME01", level="PURGE"
    )
    result = _drain(adapter.execute_drive_sanitization(params))["result"]
    assert result["method"] == "NVME_SANITIZE_BLOCK"
    assert result["achieved_level"] == "PURGE"
    assert result["hw_attested"] is False
    assert result["verification"]["strategy"] == "hw_attested"
    assert disk.nvme is not None and len(disk.nvme.reinitialize_calls) == 1
    assert disk.writes == 0


def test_ata_crypto_scramble_is_checked_by_change_not_pattern(tmp_path: Path) -> None:
    ata = FakeAta(
        model="SSD",
        serial="SATA01",
        native_max_lba=SIZE // 512 - 1,
        accessible_max_lba=SIZE // 512 - 1,
        sanitize=True,
        crypto=True,
    )
    disk = FakeDisk(
        number=4,
        size_bytes=SIZE,
        serial="SATA01",
        bus_type=11,
        removable=False,
        ata=ata,
    )
    api = FakeWindowsApi([disk])
    adapter = _adapter(_inventory([_disk_row(4, "SATA01", "SATA")], {4: "SSD"}), api)
    params = _params(
        tmp_path, path="PhysicalDrive4", typed_serial="SATA01", level="PURGE"
    )
    result = _drain(adapter.execute_drive_sanitization(params))["result"]
    assert result["method"] == "ATA_SANITIZE_CRYPTO_SCRAMBLE"
    assert result["hw_attested"] is True
    assert result["verification"]["passed"] is True
    assert "cannot show the old key" in result["verification"]["probability_note"]
    assert (0xB4, 0x0011) in ata.commands


def test_resume_finishes_an_interrupted_clear(tmp_path: Path) -> None:
    adapter, api = _usb_setup()
    params = _params(tmp_path)
    gen = adapter.execute_drive_sanitization(params)
    for _ in range(4):
        next(gen)
    gen.close()
    result = _drain(adapter.resume_drive_sanitization(params))["result"]
    assert result["verification"]["passed"] is True
    assert bytes(api.disks[2].data) == b"\xa5" * SIZE


def test_resume_without_a_checkpoint_is_refused(tmp_path: Path) -> None:
    adapter, _ = _usb_setup()
    with pytest.raises(UnsupportedCapability, match="checkpoint"):
        _drain(adapter.resume_drive_sanitization(_params(tmp_path, job_id="never-ran")))


# -- preparation ---------------------------------------------------------------------


def test_taking_a_disk_offline_is_explicit_and_bound() -> None:
    api = FakeWindowsApi([_stick(volumes={"\\\\?\\Volume{v}\\": ["E:\\"]})])
    adapter = _adapter(_inventory([_disk_row(2, "STICK01", "USB")], {}, {2: "E"}), api)
    with pytest.raises(ConfirmationMismatch):
        adapter.prepare_device({"path": "PhysicalDrive2"})
    assert api.disks[2].offline is False
    done = adapter.prepare_device(
        {"path": "PhysicalDrive2", "typed_serial": "STICK01"}
    )
    assert done["performed"] is True and api.disks[2].offline is True
    assert api.disks[2].writes == 0
