"""ATA enhanced SECURITY ERASE on flash is a Clear, at every point a claim is made.

No SATA SSD has been available to this project, so these tests are the only
evidence for this path. The authority is NIST SP 800-88r1 Table A-8 (ATA SSDs);
see tests/device/test_purge_by_device_class.py and docs/compliance.md.
Linux-only because core.erase.drive is.
"""

from __future__ import annotations

import sys

import pytest
from core.erase.verify import assess_residual_risk
from core.errors import DeviceFrozen, UnsupportedCapability
from core.models import (
    DeviceCapabilities,
    EraseMethod,
    SanitizationLevel,
    VerificationResult,
)

from .conftest import make_caps, make_device, make_job

if sys.platform != "linux":  # pragma: no cover - platform gate
    pytest.skip("core.erase.drive is Linux-only", allow_module_level=True)

from core.erase.drive import _achieved_level, select_method  # noqa: E402

SSD = {"rotational": False, "model": "Samsung SSD 870 EVO"}
HDD = {"rotational": True, "model": "ST2000DM008-2FR102"}


def enhanced_caps(**overrides: object) -> DeviceCapabilities:
    base: dict[str, object] = {
        "ata_security_erase": True,
        "ata_enhanced_erase": True,
    }
    base.update(overrides)
    return make_caps(**base)


def verification(passed: bool = True) -> VerificationResult:
    return VerificationResult.model_validate(
        {
            "passed": passed,
            "strategy": "hw_attested",
            "bytes_checked": 1 << 20,
            "sample_count": 0,
            "confidence_bp": 10_000,
            "failed_offsets": [],
            "hw_attested": True,
            "probability_note": "",
        }
    )


# --------------------------------------------------------------------------
# select_method
# --------------------------------------------------------------------------


def test_frozen_enhanced_erase_on_flash_is_not_reported_as_the_freeze() -> None:
    caps = enhanced_caps(security_frozen=True)
    with pytest.raises(UnsupportedCapability) as excinfo:
        select_method(make_device(**SSD), caps, SanitizationLevel.PURGE)
    assert not isinstance(excinfo.value, DeviceFrozen)


def test_frozen_enhanced_erase_on_magnetic_still_raises_device_frozen() -> None:
    caps = enhanced_caps(security_frozen=True)
    with pytest.raises(DeviceFrozen):
        select_method(make_device(**HDD), caps, SanitizationLevel.PURGE)


def test_purge_on_flash_with_enhanced_erase_only_raises() -> None:
    # A capability record claiming PURGE, as one probed before this rule would.
    caps = enhanced_caps(
        achievable_levels={SanitizationLevel.CLEAR, SanitizationLevel.PURGE}
    )
    with pytest.raises(UnsupportedCapability):
        select_method(make_device(**SSD), caps, SanitizationLevel.PURGE)


def test_purge_on_magnetic_with_enhanced_erase_only_selects_it() -> None:
    caps = enhanced_caps(
        achievable_levels={SanitizationLevel.CLEAR, SanitizationLevel.PURGE}
    )
    method, _ = select_method(make_device(**HDD), caps, SanitizationLevel.PURGE)
    assert method is EraseMethod.ATA_SECURITY_ERASE_ENHANCED


# --------------------------------------------------------------------------
# The level written to the report
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("device", "method", "expected"),
    [
        pytest.param(
            HDD,
            EraseMethod.ATA_SECURITY_ERASE_ENHANCED,
            SanitizationLevel.PURGE,
            id="magnetic-enhanced",
        ),
        pytest.param(
            SSD,
            EraseMethod.ATA_SECURITY_ERASE_ENHANCED,
            SanitizationLevel.CLEAR,
            id="flash-enhanced",
        ),
        pytest.param(
            HDD,
            EraseMethod.SINGLE_PASS_OVERWRITE,
            SanitizationLevel.CLEAR,
            id="magnetic-host-overwrite",
        ),
        pytest.param(
            SSD,
            EraseMethod.ATA_SANITIZE_BLOCK_ERASE,
            SanitizationLevel.PURGE,
            id="flash-sanitize-block",
        ),
    ],
)
def test_purge_is_claimed_only_for_a_purge_mechanism_of_this_device(
    device: dict[str, object],
    method: EraseMethod,
    expected: SanitizationLevel,
) -> None:
    caps = enhanced_caps(ata_sanitize_ops=["BLOCK_ERASE_EXT"])
    job = make_job(make_device(**device), level=SanitizationLevel.PURGE)
    assert _achieved_level(job, method, caps, verification()) is expected


def test_failed_verification_is_clear_whatever_the_method() -> None:
    job = make_job(make_device(**HDD), level=SanitizationLevel.PURGE)
    achieved = _achieved_level(
        job,
        EraseMethod.ATA_SECURITY_ERASE_ENHANCED,
        enhanced_caps(),
        verification(False),
    )
    assert achieved is SanitizationLevel.CLEAR


def test_clear_job_stays_clear() -> None:
    job = make_job(make_device(**SSD), level=SanitizationLevel.CLEAR)
    achieved = _achieved_level(
        job, EraseMethod.SINGLE_PASS_OVERWRITE, make_caps(), verification()
    )
    assert achieved is SanitizationLevel.CLEAR


# --------------------------------------------------------------------------
# Residual risk
# --------------------------------------------------------------------------


def assess(device: dict[str, object], requested: SanitizationLevel) -> object:
    return assess_residual_risk(
        device=make_device(**device),
        capabilities=enhanced_caps(),
        method=EraseMethod.ATA_SECURITY_ERASE_ENHANCED,
        requested_level=requested,
        achieved_level=SanitizationLevel.CLEAR,
        verification=verification(),
    )


def test_enhanced_erase_on_flash_names_its_clear_only_basis() -> None:
    risk = assess(SSD, SanitizationLevel.CLEAR)
    blob = " ".join(risk.factors)  # type: ignore[attr-defined]
    assert "Clear only" in blob
    assert "Table A-8" in blob
    assert "IEEE 2883" in blob
    assert risk.purge_achieved is False  # type: ignore[attr-defined]
    assert risk.level == "medium"  # type: ignore[attr-defined]
    assert "is a Clear" in risk.notes  # type: ignore[attr-defined]


def test_enhanced_erase_on_flash_after_a_purge_request_is_high() -> None:
    risk = assess(SSD, SanitizationLevel.PURGE)
    assert risk.level == "high"  # type: ignore[attr-defined]
    assert any("Table A-8" in f for f in risk.factors)  # type: ignore[attr-defined]


def test_enhanced_erase_on_magnetic_carries_no_flash_factor() -> None:
    risk = assess_residual_risk(
        device=make_device(**HDD),
        capabilities=enhanced_caps(),
        method=EraseMethod.ATA_SECURITY_ERASE_ENHANCED,
        requested_level=SanitizationLevel.PURGE,
        achieved_level=SanitizationLevel.PURGE,
        verification=verification(),
    )
    assert not any("Table A-8" in f for f in risk.factors)
    assert risk.level == "low"
