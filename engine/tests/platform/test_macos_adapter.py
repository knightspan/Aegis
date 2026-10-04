"""macOS adapter, from captured diskutil plists, on any host.

The case that matters most is APFS: the booted volume is on a synthesized
container disk, and the physical SSD behind it has nothing mounted on its own
partitions. The adapter must still call that SSD the boot disk.
"""

from __future__ import annotations

import pytest
from core.device._sysio import CommandResult
from core.errors import PlatformUnsupported
from core.platform.macos import DISKUTIL, SYSTEM_PROFILER, MacOSAdapter, parse_inventory
from core.platform.model import Capability, CapabilityState

from .conftest import FakeRunner, mac_apfs, mac_infos, mac_listing, mac_root, mac_runner


def _devices() -> dict[str, object]:
    found = parse_inventory(mac_listing(), mac_apfs(), mac_infos(), mac_root())
    return {device.id: device for device in found}


def test_the_internal_ssd_behind_the_boot_container_is_protected() -> None:
    internal = _devices()["disk0"]

    assert internal.system_device is True  # type: ignore[attr-defined]
    reasons = " ".join(internal.system_reasons)  # type: ignore[attr-defined]
    assert "boots from an APFS container" in reasons
    assert "System" in reasons and "VM" in reasons and "Data" in reasons
    assert internal.mounted is True  # type: ignore[attr-defined]
    assert "/" in internal.mount_points  # type: ignore[attr-defined]
    assert internal.media_type == "ssd"  # type: ignore[attr-defined]
    assert internal.interface == "nvme"  # type: ignore[attr-defined]
    assert internal.filesystems == ["APFS"]  # type: ignore[attr-defined]


def test_the_synthesized_container_is_not_listed_as_a_device() -> None:
    assert "disk3" not in _devices()


def test_a_mounted_external_is_mounted_but_not_a_system_device() -> None:
    external = _devices()["disk4"]

    assert external.system_device is False  # type: ignore[attr-defined]
    assert external.mounted is True  # type: ignore[attr-defined]
    assert external.mount_points == ["/Volumes/BACKUP"]  # type: ignore[attr-defined]
    assert external.interface == "usb"  # type: ignore[attr-defined]
    assert external.media_type == "ssd"  # type: ignore[attr-defined]
    assert external.stable_id == "T7-UUID"  # type: ignore[attr-defined]


def test_an_sd_card_is_flash_and_removable() -> None:
    card = _devices()["disk5"]

    assert card.interface == "mmc"  # type: ignore[attr-defined]
    assert card.media_type == "flash"  # type: ignore[attr-defined]
    assert card.removable is True  # type: ignore[attr-defined]
    assert card.mounted is False  # type: ignore[attr-defined]
    assert any("serial" in item for item in card.limitations)  # type: ignore[attr-defined]


def test_diskutil_is_called_by_absolute_path_and_only_with_bsd_names() -> None:
    runner = mac_runner()
    adapter = MacOSAdapter(runner=runner)

    devices = adapter.enumerate_devices()

    assert {d.id for d in devices} == {"disk0", "disk4", "disk5"}, "disk images hidden"
    assert DISKUTIL == "/usr/sbin/diskutil"
    assert all(call[0] in {DISKUTIL, SYSTEM_PROFILER} for call in runner.calls)
    assert SYSTEM_PROFILER == "/usr/sbin/system_profiler"
    info_targets = [
        call[3]
        for call in runner.calls
        if call[0] == DISKUTIL and call[1:3] == ["info", "-plist"]
    ]
    assert "/" in info_targets
    assert all(t == "/" or t.startswith("disk") for t in info_targets)


def test_a_hostile_whole_disk_name_is_never_passed_to_diskutil() -> None:
    """``WholeDisks`` comes from diskutil, but it is still never trusted as argv."""
    listing = mac_listing()
    listing["WholeDisks"].append("disk9; rm -rf /")
    base = mac_runner()
    import plistlib

    def answer(argv: list[str]) -> CommandResult:
        if argv[1:] == ["list", "-plist"]:
            return CommandResult(argv, 0, plistlib.dumps(listing).decode(), "")
        return base.answer(argv)

    runner = FakeRunner(answer)
    MacOSAdapter(runner=runner).enumerate_devices()

    assert not any("rm -rf" in " ".join(call) for call in runner.calls)


def test_internal_storage_is_never_raw_written_and_names_apples_own_path() -> None:
    adapter = MacOSAdapter(runner=mac_runner())
    internal = next(d for d in adapter.enumerate_devices() if d.id == "disk0")

    assessment = adapter.assess_device(internal)

    assert assessment.headline == "NOT AVAILABLE"
    assert assessment.device_class == "apple-internal"
    assert "Erase All Content and Settings" in assessment.recommended_action
    rows = {row.capability: row for row in assessment.capabilities}
    assert (
        rows[Capability.WHOLE_DRIVE_CLEAR].state
        is CapabilityState.BLOCKED_BY_SAFETY_POLICY
    )
    assert "Secure Enclave" in rows[Capability.WHOLE_DRIVE_CLEAR].reason


def test_a_disk_with_no_serial_cannot_be_bound() -> None:
    adapter = MacOSAdapter(runner=mac_runner())
    card = next(d for d in adapter.enumerate_devices() if d.id == "disk5")
    assert card.serial == ""

    assessment = adapter.assess_device(card)

    assert assessment.headline == "NOT AVAILABLE"
    rows = {row.capability: row for row in assessment.capabilities}
    clear = rows[Capability.WHOLE_DRIVE_CLEAR]
    assert clear.state is CapabilityState.BLOCKED_BY_SAFETY_POLICY
    assert "no serial number" in clear.reason


def test_the_external_ssd_gets_its_serial_from_system_profiler() -> None:
    adapter = MacOSAdapter(runner=mac_runner())
    t7 = next(d for d in adapter.enumerate_devices() if d.id == "disk4")
    assert t7.serial == "S5T7NS0R123456"
    assert t7.internal is False


def test_a_failed_listing_raises_rather_than_returning_no_disks() -> None:
    runner = FakeRunner(lambda argv: CommandResult(argv, 1, "", "diskutil: busy"))

    with pytest.raises(PlatformUnsupported, match="busy"):
        MacOSAdapter(runner=runner).enumerate_devices()
