"""Residual risk is always emitted and never quietly optimistic."""

from __future__ import annotations

from core.erase.verify import assess_residual_risk
from core.models import (
    Device,
    DeviceCapabilities,
    EraseMethod,
    HiddenAreaReport,
    SanitizationLevel,
    UnwritableRange,
    VerificationResult,
)


def device(**overrides: object) -> Device:
    base: dict[str, object] = {
        "path": "/dev/sdb",
        "model": "SYNTHETIC",
        "serial": "SYN-1",
        "size_bytes": 1 << 30,
        "rotational": True,
        "transport": "sata",
        "is_system_disk": False,
        "mounted_at": [],
        "pt_type": None,
    }
    base.update(overrides)
    return Device.model_validate(base)


def caps(**overrides: object) -> DeviceCapabilities:
    base: dict[str, object] = {
        "ata_security_erase": False,
        "ata_enhanced_erase": False,
        "ata_sanitize_ops": [],
        "nvme_sanicap": {},
        "is_sed_opal": False,
        "security_frozen": False,
        "est_erase_seconds": 60,
        "achievable_levels": {SanitizationLevel.CLEAR},
        "limitations": [],
    }
    base.update(overrides)
    return DeviceCapabilities.model_validate(base)


def verification(**overrides: object) -> VerificationResult:
    base: dict[str, object] = {
        "passed": True,
        "strategy": "full_read",
        "bytes_checked": 1 << 30,
        "sample_count": 0,
        "confidence_bp": 10_000,
        "failed_offsets": [],
        "hw_attested": False,
        "probability_note": "",
    }
    base.update(overrides)
    return VerificationResult.model_validate(base)


def assess(**overrides: object) -> object:
    kwargs: dict[str, object] = {
        "device": device(),
        "capabilities": caps(),
        "method": EraseMethod.SINGLE_PASS_OVERWRITE,
        "requested_level": SanitizationLevel.CLEAR,
        "achieved_level": SanitizationLevel.CLEAR,
        "verification": verification(),
    }
    kwargs.update(overrides)
    return assess_residual_risk(**kwargs)  # type: ignore[arg-type]


def test_purge_requested_but_only_clear_achieved_is_high() -> None:
    risk = assess(
        requested_level=SanitizationLevel.PURGE,
        achieved_level=SanitizationLevel.CLEAR,
    )
    assert risk.level == "high"  # type: ignore[attr-defined]
    assert risk.purge_achieved is False  # type: ignore[attr-defined]


def test_overwrite_only_on_flash_is_medium_and_names_over_provisioning() -> None:
    risk = assess(device=device(rotational=False))
    assert risk.level == "medium"  # type: ignore[attr-defined]
    assert any(  # type: ignore[attr-defined]
        "over-provisioned" in factor for factor in risk.factors  # type: ignore[attr-defined]
    )


def test_hardware_attested_purge_with_clean_verification_is_low() -> None:
    risk = assess(
        method=EraseMethod.ATA_SANITIZE_BLOCK_ERASE,
        requested_level=SanitizationLevel.PURGE,
        achieved_level=SanitizationLevel.PURGE,
        verification=verification(strategy="hw_attested", hw_attested=True),
    )
    assert risk.level == "low"  # type: ignore[attr-defined]


def test_failed_verification_is_high_whatever_else_happened() -> None:
    risk = assess(
        method=EraseMethod.ATA_SANITIZE_BLOCK_ERASE,
        requested_level=SanitizationLevel.PURGE,
        achieved_level=SanitizationLevel.PURGE,
        verification=verification(passed=False, failed_offsets=[4096]),
    )
    assert risk.level == "high"  # type: ignore[attr-defined]


def test_unwritable_ranges_raise_the_level_and_are_counted() -> None:
    risk = assess(
        unwritable_ranges=[UnwritableRange(offset=8192, length=512, errno=5)],
    )
    assert risk.level == "high"  # type: ignore[attr-defined]
    assert any("512 bytes" in factor for factor in risk.factors)  # type: ignore[attr-defined]


def test_uncovered_hidden_area_is_named_explicitly() -> None:
    risk = assess(
        hidden=HiddenAreaReport(
            hpa_present=True,
            dco_present=False,
            native_max_sectors=100,
            accessible_sectors=90,
            hidden_bytes=5120,
        ),
        hidden_covered=False,
    )
    assert risk.level == "high"  # type: ignore[attr-defined]
    assert any("NOT covered" in factor for factor in risk.factors)  # type: ignore[attr-defined]


def test_usb_bridge_is_always_a_factor() -> None:
    risk = assess(device=device(transport="usb"))
    assert any("bridge" in factor for factor in risk.factors)  # type: ignore[attr-defined]


def test_sed_not_crypto_erased_is_a_factor() -> None:
    risk = assess(capabilities=caps(is_sed_opal=True))
    assert any(  # type: ignore[attr-defined]
        "media encryption key" in factor for factor in risk.factors  # type: ignore[attr-defined]
    )


def test_sampled_verification_carries_its_probability_note() -> None:
    risk = assess(
        verification=verification(
            strategy="sampled", sample_count=4096, probability_note="P = formula here"
        )
    )
    assert any("P = formula here" in factor for factor in risk.factors)  # type: ignore[attr-defined]


def test_capability_limitations_are_carried_through() -> None:
    risk = assess(capabilities=caps(limitations=["bridge blocks pass-through"]))
    assert "bridge blocks pass-through" in risk.factors  # type: ignore[attr-defined]


def test_factors_are_never_empty_for_a_plain_clear() -> None:
    risk = assess(limitations=["O_DIRECT unavailable; fell back to O_DSYNC"])
    assert risk.factors  # type: ignore[attr-defined]
    assert risk.notes  # type: ignore[attr-defined]
