"""The Windows raw-disk layer, driven through the native-adapter double.

Runs on every host. :class:`testkit.fake_windows.FakeWindowsApi` decodes the
structures :mod:`core.device.win.ioctl` packs, so a layout error fails here.
Nothing opens a real device.
"""

from __future__ import annotations

import struct

import pytest
from core.device.win import ata, ioctl, nvme
from core.device.win.disk import (
    WindowsDisk,
    disk_path,
    parse_disk_number,
    volumes_on_disk,
)
from core.errors import (
    ConfirmationMismatch,
    DeviceFrozen,
    DeviceVanished,
    UnsupportedCapability,
)
from testkit.fake_windows import (
    FakeAta,
    FakeDisk,
    FakeNvme,
    FakeWindowsApi,
    build_identify,
)

MIB = 1 << 20


def _disk(**over: object) -> FakeDisk:
    base: dict[str, object] = {"number": 2, "size_bytes": 4 * MIB}
    base.update(over)
    return FakeDisk(**base)  # type: ignore[arg-type]


# -- control codes and layouts --------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (ioctl.IOCTL_DISK_GET_LENGTH_INFO, 0x0007405C),
        (ioctl.IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, 0x000700A0),
        (ioctl.IOCTL_DISK_UPDATE_PROPERTIES, 0x00070140),
        (ioctl.IOCTL_STORAGE_GET_DEVICE_NUMBER, 0x002D1080),
        (ioctl.IOCTL_STORAGE_QUERY_PROPERTY, 0x002D1400),
        (ioctl.IOCTL_STORAGE_REINITIALIZE_MEDIA, 0x002D9640),
        (ioctl.IOCTL_ATA_PASS_THROUGH, 0x0004D02C),
        (ioctl.FSCTL_LOCK_VOLUME, 0x00090018),
        (ioctl.FSCTL_DISMOUNT_VOLUME, 0x00090020),
        (ioctl.IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, 0x00560000),
    ],
)
def test_control_codes_match_winioctl(value: int, expected: int) -> None:
    assert value == expected


def test_ata_pass_through_ex_is_the_64_bit_layout() -> None:
    assert ioctl.ATA_PASS_THROUGH_EX_SIZE == 48
    packed = ioctl.pack_ata_pass_through(
        command=0x37, count=1, lba=0x0000_1234_5678_9A, ext=True
    )
    assert struct.unpack_from("<H", packed, 0)[0] == 48
    flags = struct.unpack_from("<H", packed, 2)[0]
    assert flags & ioctl.ATA_FLAGS_48BIT_COMMAND
    assert struct.unpack_from("<Q", packed, 24)[0] == 48
    current = packed[40:48]
    previous = packed[32:40]
    assert current[6] == 0x37
    assert current[2:5] == bytes([0x9A, 0x78, 0x56])
    assert previous[2:5] == bytes([0x34, 0x12, 0x00])


def test_reinitialize_media_sets_method_and_forbids_quiet_exit() -> None:
    packed = ioctl.pack_reinitialize_media(ioctl.STORAGE_SANITIZE_CRYPTO_ERASE, 600)
    version, size, timeout, option = struct.unpack("<IIII", packed)
    assert (version, size, timeout) == (16, 16, 600)
    assert option & 0xF == 2
    assert option & 0x10
    with pytest.raises(ValueError):
        ioctl.pack_reinitialize_media(0, 600)


def test_device_descriptor_and_extents_parse() -> None:
    api = FakeWindowsApi([_disk(serial="ABC 123", vendor="Kingston", product="DT")])
    with WindowsDisk(api, 2) as disk:
        identity = disk.read_identity()
    assert identity.serial == "ABC 123"
    assert identity.model == "Kingston DT"
    assert identity.bus == "USB"
    assert identity.removable is True
    raw = (
        struct.pack("<I4x", 2)
        + struct.pack("<I4xqq", 3, 1, 2)
        + struct.pack("<I4xqq", 5, 3, 4)
    )
    assert ioctl.parse_volume_disk_extents(raw) == [(3, 1, 2), (5, 3, 4)]
    with pytest.raises(ValueError):
        ioctl.parse_volume_disk_extents(struct.pack("<I4x", 9))


# -- identity binding -----------------------------------------------------------


@pytest.mark.parametrize(
    "text", ["E:", "E:\\", "\\\\.\\E:", "\\\\?\\Volume{x}", "disk2"]
)
def test_a_drive_letter_is_never_a_physical_disk(text: str) -> None:
    with pytest.raises(UnsupportedCapability, match="not a physical disk"):
        parse_disk_number(text)


def test_physical_drive_numbers_parse() -> None:
    assert parse_disk_number("PhysicalDrive3") == 3
    assert parse_disk_number("\\\\.\\PhysicalDrive12") == 12
    assert disk_path(3) == "\\\\.\\PhysicalDrive3"


def test_bind_accepts_the_planned_disk() -> None:
    api = FakeWindowsApi([_disk(serial="SER1")])
    disk = WindowsDisk(api, 2, write=True).open()
    identity = disk.bind(serial=" ser1 ", size_bytes=4 * MIB)
    assert identity.number == 2
    assert disk.size_bytes == 4 * MIB
    disk.close()


@pytest.mark.parametrize(
    ("serial", "size", "word"),
    [
        ("OTHER", 4 * MIB, "serial"),
        ("SER1", 8 * MIB, "bytes"),
        ("", 4 * MIB, "no serial"),
    ],
)
def test_bind_refuses_any_difference(serial: str, size: int, word: str) -> None:
    api = FakeWindowsApi([_disk(serial="SER1")])
    disk = WindowsDisk(api, 2, write=True).open()
    with pytest.raises(ConfirmationMismatch, match=word):
        disk.bind(serial=serial, size_bytes=size)


def test_an_unelevated_open_is_refused_with_the_reason() -> None:
    api = FakeWindowsApi([_disk()], elevated=False)
    with pytest.raises(UnsupportedCapability, match="Administrator"):
        WindowsDisk(api, 2).open()


def test_a_native_error_keeps_its_win32_code() -> None:
    """On Windows OSError owns a ``winerror`` slot; the code must survive it.

    Set before ``OSError.__init__``, the slot was reset to None on Windows, so
    no refusal (access denied, device gone, bridge) was ever translated there.
    Off Windows the attribute is an ordinary one and this always held.
    """
    from core.device.win.native import NativeError

    error = NativeError(ioctl.ERROR_ACCESS_DENIED, "CreateFileW", r"\\.\PhysicalDrive2")
    assert error.winerror == ioctl.ERROR_ACCESS_DENIED
    assert error.call == "CreateFileW"
    assert "Win32 error 5" in str(error)


def test_a_missing_disk_is_vanished() -> None:
    api = FakeWindowsApi([_disk()])
    with pytest.raises(DeviceVanished):
        WindowsDisk(api, 7).open()


def test_unaligned_io_is_refused_before_the_os_sees_it() -> None:
    api = FakeWindowsApi([_disk(serial="S")])
    disk = WindowsDisk(api, 2, write=True).open()
    disk.bind(serial="S", size_bytes=4 * MIB)
    with pytest.raises(ValueError, match="sector"):
        disk.read_at(100, 512)
    with pytest.raises(ValueError, match="past the end"):
        disk.write_at(4 * MIB, b"\0" * 512)


def test_a_read_only_handle_cannot_write() -> None:
    api = FakeWindowsApi([_disk(serial="S")])
    disk = WindowsDisk(api, 2).open()
    disk.bind(serial="S", size_bytes=4 * MIB)
    with pytest.raises(PermissionError):
        disk.write_at(0, b"\0" * 512)


def test_volumes_on_disk_names_mounted_volumes() -> None:
    target = _disk(volumes={"\\\\?\\Volume{aaa}\\": ["E:\\"]})
    other = FakeDisk(
        number=0, size_bytes=MIB, volumes={"\\\\?\\Volume{sys}\\": ["C:\\"]}
    )
    api = FakeWindowsApi([target, other])
    assert volumes_on_disk(api, 2) == [("\\\\?\\Volume{aaa}\\", ["E:\\"])]


# -- ATA ------------------------------------------------------------------------------


def _ata_disk(**ata_over: object) -> FakeDisk:
    base: dict[str, object] = {
        "model": "Samsung SSD 870",
        "serial": "S5Y1NX0",
        "native_max_lba": 8191,
        "accessible_max_lba": 8191,
    }
    base.update(ata_over)
    return _disk(bus_type=11, removable=False, ata=FakeAta(**base))  # type: ignore[arg-type]


def test_identify_decodes_capabilities_and_checksum() -> None:
    data = build_identify(
        model="M",
        serial="S",
        max_lba=1000,
        sanitize=True,
        block_erase=True,
        crypto=True,
    )
    parsed = ata.parse_identify(data)
    assert parsed.checksum_valid is True
    assert parsed.sanitize_supported and parsed.block_erase and parsed.crypto_scramble
    assert parsed.addressable_sectors == 1000
    assert parsed.model == "M"
    bad = ata.parse_identify(
        build_identify(model="M", serial="S", max_lba=1000, corrupt_checksum=True)
    )
    assert bad.checksum_valid is False
    assert not bad.trustworthy


def test_identify_through_the_pass_through() -> None:
    api = FakeWindowsApi([_ata_disk(sanitize=True, block_erase=True)])
    with WindowsDisk(api, 2, write=True) as disk:
        identity = ata.identify(disk)
    assert identity.serial == "S5Y1NX0"
    assert identity.sanitize_supported


def test_a_usb_bridge_refusal_is_reported_not_guessed() -> None:
    api = FakeWindowsApi([_ata_disk()])
    api.disks[2].bridge_blocks_ata = True
    with WindowsDisk(api, 2, write=True) as disk:
        with pytest.raises(UnsupportedCapability, match="did not pass ATA"):
            ata.identify(disk)


def test_hpa_discovery_and_volatile_set_max() -> None:
    api = FakeWindowsApi([_ata_disk(native_max_lba=9999, accessible_max_lba=8191)])
    with WindowsDisk(api, 2, write=True) as disk:
        assert ata.read_native_max(disk) == 9999
        assert ata.dco_identify(disk) == 9999
        ata.set_max_address(disk, 9999, volatile=True)
    fake = api.disks[2].ata
    assert fake is not None
    assert fake.set_max_calls == [(9999, True)]
    assert fake.accessible_max_lba == 9999


def test_set_max_beyond_native_is_aborted() -> None:
    api = FakeWindowsApi([_ata_disk(native_max_lba=9999, accessible_max_lba=8191)])
    with WindowsDisk(api, 2, write=True) as disk:
        with pytest.raises(UnsupportedCapability, match="aborted SET MAX"):
            ata.set_max_address(disk, 20000, volatile=True)


def test_sanitize_block_erase_polls_to_completion() -> None:
    api = FakeWindowsApi([_ata_disk(sanitize=True, block_erase=True)])
    with WindowsDisk(api, 2, write=True) as disk:
        run = ata.sanitize(disk, ata.SANITIZE_BLOCK_ERASE, sleep=lambda _: None)
        seen = []
        while True:
            try:
                seen.append(next(run))
            except StopIteration as stop:
                final = stop.value
                break
    assert final.completed_ok and not final.in_progress
    assert any(item.in_progress for item in seen)
    assert bytes(api.disks[2].data[:4096]) == bytes(4096)
    fake = api.disks[2].ata
    assert fake is not None
    assert (0xB4, 0x0012) in fake.commands


def test_sanitize_on_an_unsupporting_drive_is_aborted_not_downgraded() -> None:
    api = FakeWindowsApi([_ata_disk(sanitize=False)])
    before = bytes(api.disks[2].data[:4096])
    with WindowsDisk(api, 2, write=True) as disk:
        with pytest.raises(UnsupportedCapability, match="aborted SANITIZE"):
            list(ata.sanitize(disk, ata.SANITIZE_BLOCK_ERASE, sleep=lambda _: None))
    assert bytes(api.disks[2].data[:4096]) == before


def test_a_sanitize_frozen_drive_is_refused() -> None:
    api = FakeWindowsApi(
        [_ata_disk(sanitize=True, block_erase=True, sanitize_frozen=True)]
    )
    with WindowsDisk(api, 2, write=True) as disk:
        with pytest.raises(DeviceFrozen):
            list(ata.sanitize(disk, ata.SANITIZE_BLOCK_ERASE, sleep=lambda _: None))


def test_the_overwrite_action_is_never_issued() -> None:
    api = FakeWindowsApi([_ata_disk(sanitize=True)])
    with WindowsDisk(api, 2, write=True) as disk:
        with pytest.raises(UnsupportedCapability):
            list(ata.sanitize(disk, ata.SANITIZE_OVERWRITE, sleep=lambda _: None))


# -- NVMe ------------------------------------------------------------------


def _nvme_disk(**over: object) -> FakeDisk:
    base: dict[str, object] = {"model": "Samsung 980", "serial": "S64ANS0"}
    base.update(over)
    return _disk(bus_type=17, removable=False, nvme=FakeNvme(**base))  # type: ignore[arg-type]


def test_nvme_identify_controller_through_the_property_query() -> None:
    api = FakeWindowsApi([_nvme_disk(block_erase=True, crypto_erase=True)])
    with WindowsDisk(api, 2) as disk:
        identity = nvme.identify_controller(disk)
    assert identity.block_erase and identity.crypto_erase
    assert identity.format_supported and identity.format_crypto
    assert identity.serial == "S64ANS0"


def test_nvme_identify_on_a_non_nvme_disk_says_why() -> None:
    api = FakeWindowsApi([_disk()])
    with WindowsDisk(api, 2) as disk:
        with pytest.raises(UnsupportedCapability, match="Identify Controller"):
            nvme.identify_controller(disk)


def test_reinitialize_media_requests_the_method_on_a_new_build() -> None:
    api = FakeWindowsApi([_nvme_disk(block_erase=True)])
    with WindowsDisk(api, 2, write=True) as disk:
        record = nvme.reinitialize_media(
            disk, ioctl.STORAGE_SANITIZE_BLOCK_ERASE, timeout_s=60, os_build=26100
        )
    assert record["method_honoured"] is True
    fake = api.disks[2].nvme
    assert fake is not None
    assert len(fake.reinitialize_calls[0]) == 16
    assert bytes(api.disks[2].data[:4096]) == bytes(4096)


def test_reinitialize_media_on_an_old_build_says_the_method_was_not_honoured() -> None:
    api = FakeWindowsApi([_nvme_disk(block_erase=True)])
    with WindowsDisk(api, 2, write=True) as disk:
        record = nvme.reinitialize_media(
            disk, ioctl.STORAGE_SANITIZE_BLOCK_ERASE, timeout_s=60, os_build=19045
        )
    assert record["method_honoured"] is False
    assert "ignores the requested method" in str(record["note"])


def test_a_refused_reinitialize_is_reported() -> None:
    api = FakeWindowsApi([_nvme_disk(block_erase=True, refuse_reinitialize=True)])
    with WindowsDisk(api, 2, write=True) as disk:
        with pytest.raises(UnsupportedCapability, match="REINITIALIZE_MEDIA"):
            nvme.reinitialize_media(
                disk, ioctl.STORAGE_SANITIZE_BLOCK_ERASE, timeout_s=60, os_build=26100
            )
