"""The device list carries the engine's flash determination and erase preview.

The Sanitize screen renders these instead of deciding for itself (audit F5,
F6). If the helper stopped sending them, the screen would have nothing true to
show, so their presence and their agreement with the engine are pinned here.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest
from core.errors import UnsupportedCapability
from core.models import Device, DeviceCapabilities, HiddenAreaReport, SanitizationLevel

if sys.platform != "linux":  # pragma: no cover - platform gate
    pytest.skip("core.erase.drive is Linux-only", allow_module_level=True)

from helper.daemon import _op_enumerate_devices  # noqa: E402

STICK = Device(
    path="/dev/sdq",
    model="TransMemory",
    serial="STICK-1",
    size_bytes=8 * 1024**3,
    rotational=True,
    transport="usb",
    is_system_disk=False,
    mounted_at=[],
    pt_type=None,
    by_id_path=None,
)

SSD = STICK.model_copy(
    update={
        "path": "/dev/sdr",
        "serial": "SSD-1",
        "transport": "sata",
        "rotational": False,
    }
)


def _caps(**over: Any) -> DeviceCapabilities:
    base: dict[str, Any] = {
        "ata_security_erase": False,
        "ata_enhanced_erase": False,
        "ata_sanitize_ops": [],
        "nvme_sanicap": {},
        "is_sed_opal": False,
        "security_frozen": False,
        "est_erase_seconds": 0,
        "achievable_levels": {SanitizationLevel.CLEAR},
        "limitations": [],
    }
    base.update(over)
    return DeviceCapabilities.model_validate(base)


def _patch(monkeypatch: pytest.MonkeyPatch, probe: Any) -> None:
    monkeypatch.setattr(
        "core.device.enumerate.enumerate_devices",
        lambda include_virtual=False: [STICK, SSD],
    )
    monkeypatch.setattr("core.device.capabilities.probe", probe)
    # The adapter reads partitions from a second lsblk call; the devices here
    # are fixtures, so there is nothing on the host to read them from.
    monkeypatch.setattr(
        "core.platform.linux.LinuxAdapter._partitions", lambda self, probe: {}
    )
    monkeypatch.setattr(
        "core.platform.linux.LinuxAdapter._removable", lambda self, probe, device: None
    )
    monkeypatch.setattr(
        "core.device.hidden_areas.detect_hidden_areas",
        lambda device: HiddenAreaReport(
            hpa_present=False,
            dco_present=False,
            native_max_sectors=1,
            accessible_sectors=1,
            hidden_bytes=0,
        ),
    )


def test_each_row_carries_the_flash_determination_and_the_preview(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def probe(device: Device) -> DeviceCapabilities:
        if device is SSD:
            return _caps(
                ata_sanitize_ops=["BLOCK_ERASE_EXT"],
                achievable_levels={SanitizationLevel.CLEAR, SanitizationLevel.PURGE},
            )
        return _caps()

    _patch(monkeypatch, probe)
    rows = {row["device"]["path"]: row for row in _op_enumerate_devices({})["devices"]}

    stick = rows["/dev/sdq"]
    assert stick["device"]["rotational"] is True
    assert stick["media"]["flash"] is True
    purge = next(p for p in stick["erase_preview"]["plans"] if p["level"] == "PURGE")
    assert purge["reachable"] is False

    ssd = rows["/dev/sdr"]
    purge = next(p for p in ssd["erase_preview"]["plans"] if p["level"] == "PURGE")
    assert purge["method"] == "ATA_SANITIZE_BLOCK_ERASE"
    clear = next(p for p in ssd["erase_preview"]["plans"] if p["level"] == "CLEAR")
    assert clear["method"] == "SINGLE_PASS_OVERWRITE"


def test_a_failed_probe_still_reports_flash_and_sends_no_preview(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def probe(device: Device) -> DeviceCapabilities:
        raise UnsupportedCapability("probe needs root")

    _patch(monkeypatch, probe)
    row = _op_enumerate_devices({})["devices"][0]
    assert row["media"]["flash"] is True
    assert row["erase_preview"] is None
    assert row["capability_error"] == "probe needs root"
