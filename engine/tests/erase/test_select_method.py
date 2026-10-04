"""Method selection policy. Linux-only because core.erase.drive is.

The rule these tests exist to protect: a Purge that cannot be delivered raises.
It is never quietly turned into a Clear.
"""

from __future__ import annotations

import sys

import pytest
from core.errors import DeviceFrozen, UnsupportedCapability
from core.models import EraseMethod, SanitizationLevel

from .conftest import make_caps, make_device

if sys.platform != "linux":  # pragma: no cover - platform gate
    pytest.skip("core.erase.drive is Linux-only", allow_module_level=True)

from core.erase.drive import select_method  # noqa: E402


def test_delegates_to_recommend_method_for_clear() -> None:
    method, limits = select_method(
        make_device(), make_caps(), SanitizationLevel.CLEAR
    )
    assert method == EraseMethod.SINGLE_PASS_OVERWRITE
    assert limits == []


def test_delegates_to_recommend_method_for_purge() -> None:
    caps = make_caps(
        ata_sanitize_ops=["BLOCK_ERASE_EXT"],
        achievable_levels={SanitizationLevel.CLEAR, SanitizationLevel.PURGE},
    )
    method, _ = select_method(make_device(), caps, SanitizationLevel.PURGE)
    assert method == EraseMethod.ATA_SANITIZE_BLOCK_ERASE


def test_frozen_device_blocking_the_only_purge_path_raises(
) -> None:
    caps = make_caps(
        ata_security_erase=True,
        ata_enhanced_erase=True,
        security_frozen=True,
        achievable_levels={SanitizationLevel.CLEAR},
    )
    with pytest.raises(DeviceFrozen) as excinfo:
        select_method(make_device(), caps, SanitizationLevel.PURGE)
    assert "suspend" in excinfo.value.remediation.lower() or (
        "power-cycle" in excinfo.value.remediation.lower()
    )


def test_frozen_device_never_downgrades_to_clear() -> None:
    caps = make_caps(
        ata_security_erase=True,
        ata_enhanced_erase=True,
        security_frozen=True,
        achievable_levels={SanitizationLevel.CLEAR},
    )
    with pytest.raises(DeviceFrozen):
        select_method(make_device(), caps, SanitizationLevel.PURGE)


def test_unreachable_purge_raises_rather_than_downgrading() -> None:
    caps = make_caps(achievable_levels={SanitizationLevel.CLEAR})
    with pytest.raises(UnsupportedCapability):
        select_method(make_device(), caps, SanitizationLevel.PURGE)


def test_requested_dod_is_honoured_with_a_legacy_warning() -> None:
    method, limits = select_method(
        make_device(),
        make_caps(),
        SanitizationLevel.CLEAR,
        requested=EraseMethod.DOD_5220_22_M_3PASS,
    )
    assert method == EraseMethod.DOD_5220_22_M_3PASS
    blob = " ".join(limits)
    assert "legacy" in blob.lower()
    assert "800-88" in blob
    assert "no measurable benefit" in blob or "no benefit" in blob


def test_requested_dod_on_flash_warns_about_program_erase_cycles() -> None:
    _, limits = select_method(
        make_device(rotational=False),
        make_caps(),
        SanitizationLevel.CLEAR,
        requested=EraseMethod.DOD_5220_22_M_3PASS,
    )
    assert any("program/erase" in item for item in limits)


def test_requested_single_pass_carries_no_warning() -> None:
    method, limits = select_method(
        make_device(),
        make_caps(),
        SanitizationLevel.CLEAR,
        requested=EraseMethod.SINGLE_PASS_OVERWRITE,
    )
    assert method == EraseMethod.SINGLE_PASS_OVERWRITE
    assert limits == []


@pytest.mark.parametrize(
    "method",
    [
        EraseMethod.ATA_SANITIZE_BLOCK_ERASE,
        EraseMethod.NVME_SANITIZE_BLOCK,
        EraseMethod.SED_CRYPTO_ERASE,
        EraseMethod.ATA_SECURITY_ERASE_ENHANCED,
    ],
)
def test_firmware_methods_cannot_be_requested_directly(
    method: EraseMethod,
) -> None:
    with pytest.raises(UnsupportedCapability):
        select_method(
            make_device(), make_caps(), SanitizationLevel.PURGE, requested=method
        )


def test_capability_limitations_are_carried_into_the_plan() -> None:
    caps = make_caps(limitations=["USB bridge blocks ATA pass-through"])
    _, limits = select_method(make_device(), caps, SanitizationLevel.CLEAR)
    assert "USB bridge blocks ATA pass-through" in limits


@pytest.mark.parametrize(
    "method", [EraseMethod.SINGLE_PASS_OVERWRITE, EraseMethod.DOD_5220_22_M_3PASS]
)
@pytest.mark.parametrize(
    "level", [SanitizationLevel.PURGE, SanitizationLevel.DESTROY]
)
def test_a_host_overwrite_is_refused_for_anything_but_clear_at_planning(
    method: EraseMethod, level: SanitizationLevel
) -> None:
    # STANDARDS_REPORT F18: this pairing used to be planned and run, and only
    # the level written to the report caught it.
    caps = make_caps(
        ata_sanitize_ops=["BLOCK_ERASE_EXT"],
        achievable_levels={SanitizationLevel.CLEAR, SanitizationLevel.PURGE},
    )
    with pytest.raises(UnsupportedCapability) as excinfo:
        select_method(make_device(), caps, level, requested=method)
    assert "Clear at most" in excinfo.value.message


def test_the_write_time_check_still_refuses_a_host_overwrite_purge() -> None:
    # Defence in depth: whatever reaches the report, a host overwrite is never
    # recorded as a Purge.
    from core.erase.drive import _achieved_level
    from core.models import VerificationResult

    from .conftest import make_job

    verification = VerificationResult.model_validate(
        {
            "passed": True,
            "strategy": "full_read",
            "bytes_checked": 1,
            "sample_count": 0,
            "confidence_bp": 10_000,
            "failed_offsets": [],
            "hw_attested": False,
            "probability_note": "",
        }
    )
    job = make_job(make_device(), level=SanitizationLevel.PURGE)
    caps = make_caps(ata_sanitize_ops=["BLOCK_ERASE_EXT"])
    achieved = _achieved_level(
        job, EraseMethod.SINGLE_PASS_OVERWRITE, caps, verification
    )
    assert achieved is SanitizationLevel.CLEAR
