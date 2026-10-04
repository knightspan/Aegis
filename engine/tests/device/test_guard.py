"""The safety gate. Every destructive path must pass through these two checks."""

from __future__ import annotations

import pytest
from core.device.guard import assert_erasable, assert_serial_confirmed
from core.errors import (
    ConfirmationMismatch,
    MountedRefused,
    SystemDiskRefused,
)
from core.models import Device


def device(**overrides: object) -> Device:
    base: dict[str, object] = {
        "path": "/dev/sdb",
        "model": "ST2000DM008",
        "serial": "ZFL2ABCD",
        "size_bytes": 2000398934016,
        "rotational": True,
        "transport": "sata",
        "is_system_disk": False,
        "mounted_at": [],
        "pt_type": "gpt",
        "by_id_path": "/dev/disk/by-id/ata-ST2000DM008_ZFL2ABCD",
    }
    base.update(overrides)
    return Device.model_validate(base)


# --------------------------------------------------------------------------
# assert_erasable
# --------------------------------------------------------------------------


def test_clean_unmounted_non_system_device_passes() -> None:
    assert assert_erasable(device()) is None


def test_refuses_the_system_disk() -> None:
    with pytest.raises(SystemDiskRefused) as excinfo:
        assert_erasable(device(is_system_disk=True))
    assert excinfo.value.remediation


def test_refuses_a_mounted_device_and_names_the_mountpoints() -> None:
    with pytest.raises(MountedRefused) as excinfo:
        assert_erasable(device(mounted_at=["/media/usb", "/mnt/data"]))
    assert "/media/usb" in str(excinfo.value)
    assert "/mnt/data" in str(excinfo.value)


def test_system_disk_refusal_takes_precedence_over_mounted() -> None:
    with pytest.raises(SystemDiskRefused):
        assert_erasable(device(is_system_disk=True, mounted_at=["/"]))


# --------------------------------------------------------------------------
# assert_serial_confirmed
# --------------------------------------------------------------------------


def test_matching_serial_confirms() -> None:
    assert assert_serial_confirmed(device(), "ZFL2ABCD") is None


def test_tolerates_surrounding_whitespace_and_case() -> None:
    assert assert_serial_confirmed(device(), "  zfl2abcd \n") is None


def test_wrong_serial_is_refused() -> None:
    with pytest.raises(ConfirmationMismatch) as excinfo:
        assert_serial_confirmed(device(), "ZFL2ABCE")
    assert excinfo.value.remediation


def test_empty_confirmation_is_refused() -> None:
    with pytest.raises(ConfirmationMismatch):
        assert_serial_confirmed(device(), "   ")


def test_model_number_is_not_accepted_as_confirmation() -> None:
    with pytest.raises(ConfirmationMismatch):
        assert_serial_confirmed(device(), "ST2000DM008")


def test_device_without_serial_accepts_its_stable_by_id_path() -> None:
    target = device(serial="")
    assert (
        assert_serial_confirmed(target, "/dev/disk/by-id/ata-ST2000DM008_ZFL2ABCD")
        is None
    )


def test_device_without_serial_refuses_an_unrelated_token() -> None:
    with pytest.raises(ConfirmationMismatch) as excinfo:
        assert_serial_confirmed(device(serial=""), "sdb")
    assert "by-id" in excinfo.value.remediation
