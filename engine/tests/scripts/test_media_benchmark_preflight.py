"""The gates in front of the one command that writes to a physical device.

These run without a device: ``_lsblk`` and ``_root_disk`` are the only two
things that touch the host, and both are replaced. That matters more here than
usual - a safety gate nobody can test until they have the hardware in their
hand is a safety gate that gets tested for the first time by the run it was
supposed to protect.

Every test asserts a **refusal**. The one test that asserts success states the
full configuration it needed, so a future change that loosens a gate has to
delete an assertion rather than quietly widen a condition.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
from scripts.media_benchmark import MEDIA_SIZE, Refused, _kernel_serial, preflight

SERIAL = "B103B9C19DE1CCC1BD535ACB"
SYSFS_SERIAL = "/sys/devices/pci0000:00/usb8/8-1/serial"

# The sysfs fixtures below mirror real kernel names ("8-1:1.0", "0:0:0:0"),
# which NTFS rejects, and link them with a symlink, which NT gates behind a
# privilege. sysfs itself exists only on Linux, so that is the only host the
# reader has anything to read on.
linux_sysfs = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="sysfs exists only on Linux"
)


def _disk(**overrides: Any) -> dict[str, Any]:
    """A healthy, unmounted, removable test stick."""
    node: dict[str, Any] = {
        "name": "sdb",
        "path": "/dev/sdb",
        "type": "disk",
        "size": 7759462400,
        "tran": "usb",
        "rm": True,
        "ro": False,
        "serial": SERIAL,
        "model": "TransMemory",
        "mountpoints": [None],
        "children": [],
    }
    node.update(overrides)
    return node


@pytest.fixture
def host(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Point the two host probes at values a test controls."""

    def install(
        node: dict[str, Any],
        root: str = "nvme0n1",
        *,
        kernel: tuple[str | None, str | None] = (SERIAL, SYSFS_SERIAL),
    ) -> None:
        monkeypatch.setattr(
            "scripts.media_benchmark._lsblk", lambda device: node
        )
        monkeypatch.setattr(
            "scripts.media_benchmark._kernel_serial", lambda name, tran: kernel
        )
        monkeypatch.setattr("scripts.media_benchmark._root_disk", lambda: root)
        monkeypatch.setattr(Path, "exists", lambda self: True)
        monkeypatch.setattr(Path, "is_block_device", lambda self: True)

    return install


def test_a_healthy_unmounted_removable_stick_passes(host: Any) -> None:
    host(_disk())
    result = preflight("/dev/sdb", expect_serial=SERIAL)
    assert result["verdict"] == "SAFE"
    assert result["serial"] == SERIAL
    assert result["mountpoints"] == []
    assert result["removable"] is True


def test_a_mounted_device_is_refused(host: Any) -> None:
    host(_disk(mountpoints=["/run/media/someone/STICK"]))
    with pytest.raises(Refused, match="mounted filesystems"):
        preflight("/dev/sdb", expect_serial=SERIAL)


def test_a_mounted_partition_is_refused_even_when_the_disk_is_not(host: Any) -> None:
    """The mount is usually on the partition, which is the case that matters."""
    host(
        _disk(
            mountpoints=[None],
            children=[{"name": "sdb1", "mountpoints": ["/run/media/x/S"]}],
        )
    )
    with pytest.raises(Refused, match="mounted filesystems"):
        preflight("/dev/sdb", expect_serial=SERIAL)


def test_the_root_disk_is_refused(host: Any) -> None:
    host(_disk(name="nvme0n1", rm=False), root="nvme0n1")
    with pytest.raises(Refused, match="root filesystem"):
        preflight("/dev/nvme0n1", expect_serial=SERIAL, allow_fixed=True)


def test_a_partition_given_where_a_disk_is_meant_is_refused(host: Any) -> None:
    host(_disk(type="part"))
    with pytest.raises(Refused, match="not a whole disk"):
        preflight("/dev/sdb1", expect_serial=SERIAL)


def test_a_serial_mismatch_is_refused_rather_than_prompted(host: Any) -> None:
    host(_disk())
    with pytest.raises(Refused, match="declared test"):
        preflight("/dev/sdb", expect_serial="SOMEOTHERSERIAL")


def test_a_device_reporting_no_serial_is_refused(host: Any) -> None:
    """An unidentifiable device must never be written to."""
    host(_disk(serial=""))
    with pytest.raises(Refused, match="no serial"):
        preflight("/dev/sdb", expect_serial=SERIAL)


def test_an_unexpectedly_read_only_device_is_refused(host: Any) -> None:
    host(_disk(ro=True))
    with pytest.raises(Refused, match="read-only"):
        preflight("/dev/sdb", expect_serial=SERIAL)


def test_a_fixed_disk_needs_an_explicit_override(host: Any) -> None:
    host(_disk(rm=False))
    with pytest.raises(Refused, match="not removable"):
        preflight("/dev/sdb", expect_serial=SERIAL)
    # And with the override it is allowed through, which is the whole point of
    # the flag being explicit rather than a default.
    assert preflight("/dev/sdb", expect_serial=SERIAL, allow_fixed=True)["verdict"]


def test_a_device_too_small_for_the_corpus_is_refused(host: Any) -> None:
    host(_disk(size=MEDIA_SIZE - 1))
    with pytest.raises(Refused, match="smaller than"):
        preflight("/dev/sdb", expect_serial=SERIAL)


def test_an_implausibly_large_device_is_refused(host: Any) -> None:
    """A 2 TB target is not a test stick, and is not read into memory either."""
    host(_disk(size=2 * 1024**4))
    with pytest.raises(Refused, match="sanity limit"):
        preflight("/dev/sdb", expect_serial=SERIAL)


# ------------------------------------------------ the independent serial


def test_agreeing_serial_sources_are_reported_as_agreement(host: Any) -> None:
    host(_disk())
    result = preflight("/dev/sdb", expect_serial=SERIAL)
    check = result["serial_check"]
    assert check["status"] == "AGREE"
    assert check["source_a"]["value"] == SERIAL
    assert check["source_b"] == {"name": SYSFS_SERIAL, "value": SERIAL}


def test_disagreeing_serial_sources_are_refused(host: Any) -> None:
    """lsblk matches the declaration, the kernel does not: neither is believed."""
    host(_disk(), kernel=("B103B9C19DE1CCC1BD535ACC", SYSFS_SERIAL))
    with pytest.raises(Refused, match="disagree"):
        preflight("/dev/sdb", expect_serial=SERIAL)


def test_an_unreadable_independent_serial_is_unverified_not_agreed(
    host: Any,
) -> None:
    host(_disk(), kernel=(None, None))
    result = preflight("/dev/sdb", expect_serial=SERIAL)
    assert result["serial_check"]["status"] == "UNVERIFIED"
    assert result["serial_check"]["source_b"]["value"] is None


def _sysfs(root: Path, device_dir: Path) -> None:
    (root / "sdb").mkdir(parents=True)
    device_dir.mkdir(parents=True)
    (root / "sdb" / "device").symlink_to(device_dir)


@linux_sysfs
def test_the_kernel_serial_of_a_usb_disk_is_its_usb_device_serial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    usb = tmp_path / "devices" / "usb8" / "8-1"
    scsi = usb / "8-1:1.0" / "host0" / "target0:0:0" / "0:0:0:0"
    _sysfs(tmp_path / "block", scsi)
    (usb / "idVendor").write_text("0930\n")
    (usb / "serial").write_text(SERIAL + "\n")
    # A host controller further up also has a serial; it must not be taken.
    (usb.parent / "idVendor").write_text("1d6b\n")
    (usb.parent / "serial").write_text("0000:76:00.4\n")
    monkeypatch.setattr("scripts.media_benchmark.SYSFS_BLOCK", tmp_path / "block")
    assert _kernel_serial("sdb", "usb") == (SERIAL, str(usb / "serial"))


@linux_sysfs
def test_the_kernel_serial_of_a_scsi_disk_comes_from_its_vpd_page(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scsi = tmp_path / "devices" / "0:0:0:0"
    _sysfs(tmp_path / "block", scsi)
    payload = b"  WD-ABC123 "
    header = b"\x00\x80" + len(payload).to_bytes(2, "big")
    (scsi / "vpd_pg80").write_bytes(header + payload)
    monkeypatch.setattr("scripts.media_benchmark.SYSFS_BLOCK", tmp_path / "block")
    assert _kernel_serial("sdb", "sata") == ("WD-ABC123", str(scsi / "vpd_pg80"))


@linux_sysfs
def test_a_missing_kernel_serial_is_not_invented(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _sysfs(tmp_path / "block", tmp_path / "devices" / "0:0:0:0")
    monkeypatch.setattr("scripts.media_benchmark.SYSFS_BLOCK", tmp_path / "block")
    assert _kernel_serial("sdb", "usb") == (None, None)
    assert _kernel_serial("sdb", "sata") == (None, None)
    assert _kernel_serial("sdz", "usb") == (None, None)
