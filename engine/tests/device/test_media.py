"""Is this device flash, and how do we know.

``flash = not device.rotational`` was the test everywhere, and a USB bridge does
not clear ``queue/rotational``. The Toshiba TransMemory stick used for hardware
validation reports ``rotational: True``; ``lsblk`` agrees, so it was not even a
disagreement to report. Every flash caveat in the erase path was gated on that
negation and none of them reached the report for a USB flash stick.
"""

from __future__ import annotations

import pytest
from core.device.media import FLASH_TRANSPORTS, is_flash
from core.models import Device


def device(**overrides: object) -> Device:
    base: dict[str, object] = {
        "path": "/dev/sda",
        "model": "TransMemory",
        "serial": "B103B9C19DE1CCC1BD535ACB",
        "size_bytes": 7759462400,
        "rotational": True,
        "transport": "usb",
        "is_system_disk": False,
        "mounted_at": [],
        "pt_type": None,
    }
    base.update(overrides)
    return Device.model_validate(base)


def test_the_validation_stick_is_flash_despite_the_rotational_flag() -> None:
    """The exact device and the exact flag that produced the defect."""
    flash, reason = is_flash(device())

    assert flash is True
    assert "usb bus" in reason
    assert "rotational=True" in reason, (
        "the reason must admit the flag disagrees, or a reader cannot check it"
    )


@pytest.mark.parametrize("transport", sorted(FLASH_TRANSPORTS))
def test_every_flash_transport_wins_over_the_flag(transport: str) -> None:
    flash, _ = is_flash(device(transport=transport, rotational=True))

    assert flash is True


def test_a_cleared_rotational_flag_is_trusted_when_it_is_set() -> None:
    """A kernel that bothered to clear it is telling us something."""
    flash, reason = is_flash(
        device(transport="sata", rotational=False, model="Samsung SSD 870")
    )

    assert flash is True
    assert "queue/rotational=0" in reason


def test_a_spinning_disk_is_not_flash() -> None:
    flash, reason = is_flash(
        device(transport="sata", rotational=True, model="ST2000DM008")
    )

    assert flash is False
    assert "no flash signal" in reason


def test_the_model_string_catches_flash_on_a_sata_bus() -> None:
    flash, reason = is_flash(
        device(transport="sata", rotational=True, model="SanDisk SSD PLUS 1TB")
    )

    assert flash is True
    assert "model string" in reason


def test_a_measured_elision_settles_it_whatever_the_bus_says() -> None:
    """Only a flash translation layer can acknowledge a write it did not perform."""
    flash, reason = is_flash(
        device(transport="sata", rotational=True, model="ST2000DM008"),
        elision_detected=True,
    )

    assert flash is True
    assert "calibration" in reason


def test_a_negative_calibration_does_not_override_the_other_signals() -> None:
    """No elision measured is not evidence of a spinning disk."""
    flash, reason = is_flash(device(), elision_detected=False)

    assert flash is True
    assert "usb bus" in reason
