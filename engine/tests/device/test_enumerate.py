"""Device enumeration: lsblk primary path, sysfs fallback, system-disk marking."""

from __future__ import annotations

from pathlib import Path

import pytest
from core.device._sysio import SystemProbe
from core.device.enumerate import (
    _transport_from_syspath,
    enumerate_devices,
    get_device,
)
from core.errors import DeviceVanished

from .conftest import (
    BY_ID_MAP,
    FINDMNT_ROOT,
    LSBLK_JSON,
    LSBLK_JSON_LEGACY_MOUNTPOINT,
    MISSING,
    SWAPS_NONE,
    SWAPS_ON_SDB,
    FakeRunner,
    ok,
)

LSBLK = ("lsblk",)
FINDMNT = ("findmnt",)


def make_probe(
    tmp_path: Path,
    *,
    lsblk: str | None = LSBLK_JSON,
    swaps: str = SWAPS_NONE,
    sysfs: dict[str, dict[str, str]] | None = None,
    syspaths: dict[str, str] | None = None,
) -> SystemProbe:
    responses = {FINDMNT: ok(FINDMNT_ROOT)}
    responses[LSBLK] = ok(lsblk) if lsblk is not None else MISSING
    proc = tmp_path / "proc"
    proc.mkdir(exist_ok=True)
    (proc / "swaps").write_text(swaps, encoding="utf-8")
    sys_root = tmp_path / "sys"
    for name, files in (sysfs or {}).items():
        for rel, content in files.items():
            target = sys_root / "block" / name / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
    return SystemProbe(
        runner=FakeRunner(responses),
        sysfs_root=sys_root,
        proc_root=proc,
        dev_root=tmp_path / "dev",
        by_id_map=BY_ID_MAP,
        block_syspath_map=syspaths,
    )


# --------------------------------------------------------------------------
# lsblk path
# --------------------------------------------------------------------------


def test_enumerates_disks_and_rom_but_not_loop(tmp_path: Path) -> None:
    devices = enumerate_devices(make_probe(tmp_path))
    assert [d.path for d in devices] == [
        "/dev/nvme0n1",
        "/dev/sda",
        "/dev/sdb",
        "/dev/sr0",
    ]


def test_include_virtual_adds_loop_devices(tmp_path: Path) -> None:
    devices = enumerate_devices(make_probe(tmp_path), include_virtual=True)
    assert "/dev/loop0" in [d.path for d in devices]


def test_parses_identity_and_geometry(tmp_path: Path) -> None:
    devices = {d.path: d for d in enumerate_devices(make_probe(tmp_path))}
    nvme = devices["/dev/nvme0n1"]
    assert nvme.model == "Samsung SSD 980 PRO 1TB"
    assert nvme.serial == "S5GXNX0R123456"
    assert nvme.size_bytes == 1000204886016
    assert nvme.rotational is False
    assert nvme.pt_type == "gpt"


def test_maps_ata_transport_to_sata(tmp_path: Path) -> None:
    devices = {d.path: d for d in enumerate_devices(make_probe(tmp_path))}
    assert devices["/dev/sdb"].transport == "sata"
    assert devices["/dev/nvme0n1"].transport == "nvme"
    assert devices["/dev/sda"].transport == "usb"


def test_unknown_transport_when_lsblk_reports_none(tmp_path: Path) -> None:
    devices = {
        d.path: d for d in enumerate_devices(make_probe(tmp_path), include_virtual=True)
    }
    assert devices["/dev/loop0"].transport == "unknown"


def test_mounted_at_aggregates_device_and_partitions(tmp_path: Path) -> None:
    devices = {d.path: d for d in enumerate_devices(make_probe(tmp_path))}
    assert sorted(devices["/dev/nvme0n1"].mounted_at) == ["/", "/boot/efi"]
    assert devices["/dev/sda"].mounted_at == ["/media/usb"]
    assert devices["/dev/sdb"].mounted_at == []


def test_reads_legacy_scalar_mountpoint_field(tmp_path: Path) -> None:
    probe = make_probe(tmp_path, lsblk=LSBLK_JSON_LEGACY_MOUNTPOINT)
    devices = enumerate_devices(probe)
    assert devices[0].mounted_at == ["/data"]


def test_marks_root_disk_as_system_disk(tmp_path: Path) -> None:
    devices = {d.path: d for d in enumerate_devices(make_probe(tmp_path))}
    assert devices["/dev/nvme0n1"].is_system_disk is True
    assert devices["/dev/sdb"].is_system_disk is False


def test_marks_disk_holding_active_swap_as_system_disk(tmp_path: Path) -> None:
    probe = make_probe(tmp_path, swaps=SWAPS_ON_SDB)
    devices = {d.path: d for d in enumerate_devices(probe)}
    assert devices["/dev/sdb"].is_system_disk is True


def test_resolves_stable_by_id_path_preferring_model_serial_link(
    tmp_path: Path,
) -> None:
    devices = {d.path: d for d in enumerate_devices(make_probe(tmp_path))}
    assert (
        devices["/dev/sdb"].by_id_path
        == "/dev/disk/by-id/ata-ST2000DM008-2FR102_ZFL2ABCD"
    )
    assert (
        devices["/dev/nvme0n1"].by_id_path
        == "/dev/disk/by-id/nvme-Samsung_SSD_980_PRO_1TB_S5GXNX0R123456"
    )


def test_by_id_path_is_none_when_no_link_exists(tmp_path: Path) -> None:
    devices = {d.path: d for d in enumerate_devices(make_probe(tmp_path))}
    assert devices["/dev/sr0"].by_id_path is None


# --------------------------------------------------------------------------
# sysfs fallback
# --------------------------------------------------------------------------

SYSFS_TREE = {
    "sdb": {
        "size": "3907029168\n",
        "queue/rotational": "1\n",
        "device/model": "ST2000DM008-2FR102\n",
        "device/serial": "ZFL2ABCD\n",
        "device/vendor": "ATA\n",
    },
    "sda": {
        "size": "30464000\n",
        "queue/rotational": "1\n",
        "device/model": "Cruzer Blade\n",
    },
}


def test_falls_back_to_sysfs_when_lsblk_missing(tmp_path: Path) -> None:
    probe = make_probe(
        tmp_path,
        lsblk=None,
        sysfs=SYSFS_TREE,
        syspaths={
            "sdb": "/sys/devices/pci0000:00/0000:00:17.0/ata3/host2/block/sdb",
            "sda": "/sys/devices/pci0000:00/0000:00:14.0/usb2/2-1/host6/block/sda",
        },
    )
    devices = {d.path: d for d in enumerate_devices(probe)}
    assert set(devices) == {"/dev/sda", "/dev/sdb"}
    sdb = devices["/dev/sdb"]
    assert sdb.model == "ST2000DM008-2FR102"
    assert sdb.serial == "ZFL2ABCD"
    assert sdb.rotational is True
    assert sdb.transport == "sata"


def test_sysfs_fallback_multiplies_sector_count_by_512(tmp_path: Path) -> None:
    probe = make_probe(tmp_path, lsblk=None, sysfs=SYSFS_TREE, syspaths={})
    devices = {d.path: d for d in enumerate_devices(probe)}
    assert devices["/dev/sdb"].size_bytes == 3907029168 * 512


def test_sysfs_fallback_degrades_on_missing_attributes(tmp_path: Path) -> None:
    probe = make_probe(tmp_path, lsblk=None, sysfs=SYSFS_TREE, syspaths={})
    devices = {d.path: d for d in enumerate_devices(probe)}
    sda = devices["/dev/sda"]
    assert sda.serial == ""
    assert sda.transport == "unknown"


@pytest.mark.parametrize(
    ("syspath", "expected"),
    [
        ("/sys/devices/pci0000:00/0000:00:14.0/usb2/2-1/block/sda", "usb"),
        ("/sys/devices/pci0000:00/0000:00:01.0/nvme/nvme0/nvme0n1", "nvme"),
        ("/sys/devices/platform/soc/fe340000.mmc/mmc_host/mmc0/block/mmcblk0", "mmc"),
        ("/sys/devices/pci0000:00/0000:00:17.0/ata3/host2/block/sdb", "sata"),
        ("/sys/devices/virtual/block/loop0", "unknown"),
    ],
)
def test_transport_derived_from_subsystem_chain(syspath: str, expected: str) -> None:
    assert _transport_from_syspath(syspath) == expected


def test_usb_wins_over_ata_when_both_appear_in_chain() -> None:
    # A USB-SATA bridge exposes an ata node beneath the usb node; the bridge is
    # what limits capability, so usb must win.
    chain = "/sys/devices/pci0000:00/usb2/2-1/2-1:1.0/host6/ata9/block/sda"
    assert _transport_from_syspath(chain) == "usb"


# --------------------------------------------------------------------------
# get_device
# --------------------------------------------------------------------------


def test_get_device_by_kernel_path(tmp_path: Path) -> None:
    device = get_device("/dev/sdb", make_probe(tmp_path))
    assert device.serial == "ZFL2ABCD"


def test_get_device_by_bare_name(tmp_path: Path) -> None:
    assert get_device("sdb", make_probe(tmp_path)).path == "/dev/sdb"


def test_get_device_by_serial(tmp_path: Path) -> None:
    assert get_device("ZFL2ABCD", make_probe(tmp_path)).path == "/dev/sdb"


def test_get_device_by_by_id_path(tmp_path: Path) -> None:
    device = get_device(
        "/dev/disk/by-id/ata-ST2000DM008-2FR102_ZFL2ABCD", make_probe(tmp_path)
    )
    assert device.path == "/dev/sdb"


def test_get_device_raises_device_vanished(tmp_path: Path) -> None:
    with pytest.raises(DeviceVanished) as excinfo:
        get_device("/dev/sdz", make_probe(tmp_path))
    assert excinfo.value.remediation
