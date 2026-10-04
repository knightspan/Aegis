"""The Sanitize screen shows what the engine will run. Prove the two agree.

Audit F6: the screen offered DoD 5220.22-M, the request carried only a level,
and the certificate said single pass. The screen now renders
:func:`core.erase.drive.preview`, and these tests pin that the preview names
the method :func:`core.erase.drive.execute` runs, for every device class the
selection distinguishes, including the two Purge methods the old UI list
omitted (F7).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from core.models import EraseMethod, ErasePreview, PlannedErase, SanitizationLevel

from .conftest import make_caps, make_device, make_job

if sys.platform != "linux":  # pragma: no cover - platform gate
    pytest.skip("core.erase.drive is Linux-only", allow_module_level=True)

from core.erase import drive  # noqa: E402

BOTH = {SanitizationLevel.CLEAR, SanitizationLevel.PURGE}

#: (name, device overrides, capability overrides, expected Purge method or None)
CASES: list[tuple[str, dict[str, object], dict[str, object], EraseMethod | None]] = [
    (
        "usb-stick-behind-a-bridge",
        {"transport": "usb", "rotational": True, "model": "TransMemory"},
        {},
        None,
    ),
    (
        "sata-ssd-block-erase",
        {"rotational": False},
        {"ata_sanitize_ops": ["BLOCK_ERASE_EXT"], "achievable_levels": BOTH},
        EraseMethod.ATA_SANITIZE_BLOCK_ERASE,
    ),
    (
        "magnetic-sanitize-overwrite-only",
        {},
        {"ata_sanitize_ops": ["OVERWRITE_EXT"], "achievable_levels": BOTH},
        EraseMethod.ATA_SANITIZE_OVERWRITE,
    ),
    (
        "nvme-format-crypto-only",
        {"transport": "nvme", "rotational": False},
        {"nvme_sanicap": {"fna_crypto_format": True}, "achievable_levels": BOTH},
        EraseMethod.NVME_FORMAT_SES1,
    ),
    (
        "nvme-sanitize",
        {"transport": "nvme", "rotational": False},
        {"nvme_sanicap": {"block_erase": True}, "achievable_levels": BOTH},
        EraseMethod.NVME_SANITIZE_BLOCK,
    ),
    (
        "magnetic-enhanced-erase",
        {},
        {"ata_enhanced_erase": True, "achievable_levels": BOTH},
        EraseMethod.ATA_SECURITY_ERASE_ENHANCED,
    ),
    (
        "flash-with-enhanced-erase-only",
        {"rotational": False},
        {"ata_enhanced_erase": True},
        None,
    ),
    (
        "magnetic-frozen",
        {},
        {"ata_enhanced_erase": True, "security_frozen": True},
        None,
    ),
    (
        "opal-only",
        {"rotational": False},
        {"is_sed_opal": True, "achievable_levels": BOTH},
        EraseMethod.SED_CRYPTO_ERASE,
    ),
]


def _plan(preview: ErasePreview, level: SanitizationLevel) -> PlannedErase:
    return next(plan for plan in preview.plans if plan.level is level)


@pytest.mark.parametrize(
    ("device_over", "caps_over", "expected"),
    [case[1:] for case in CASES],
    ids=[case[0] for case in CASES],
)
def test_the_preview_names_the_method_the_engine_selects(
    device_over: dict[str, object],
    caps_over: dict[str, object],
    expected: EraseMethod | None,
) -> None:
    device = make_device(**device_over)
    caps = make_caps(**caps_over)
    shown = drive.preview(device, caps)

    clear = _plan(shown, SanitizationLevel.CLEAR)
    assert clear.reachable
    assert clear.method is EraseMethod.SINGLE_PASS_OVERWRITE
    assert clear.method == drive.select_method(device, caps, SanitizationLevel.CLEAR)[0]

    purge = _plan(shown, SanitizationLevel.PURGE)
    if expected is None:
        assert not purge.reachable
        assert purge.method is None
        assert purge.refusal and purge.remediation
        assert shown.purge_requires
        with pytest.raises(Exception, match=r".") as raised:
            drive.select_method(device, caps, SanitizationLevel.PURGE)
        assert raised.value.message == purge.refusal  # type: ignore[attr-defined]
    else:
        assert purge.reachable
        assert purge.method is expected
        assert purge.evidence
        method, limits = drive.select_method(device, caps, SanitizationLevel.PURGE)
        assert purge.method is method
        assert purge.limitations == limits
        assert shown.purge_mechanisms[0] is expected


def test_an_opal_only_drive_is_shown_as_chosen_but_not_executable() -> None:
    shown = drive.preview(
        make_device(rotational=False),
        make_caps(is_sed_opal=True, achievable_levels=BOTH),
    )
    purge = _plan(shown, SanitizationLevel.PURGE)
    assert purge.method is EraseMethod.SED_CRYPTO_ERASE
    assert not purge.executable
    assert "PSID" in purge.not_executable_reason


def test_a_usb_stick_is_flash_whatever_the_rotational_flag_says() -> None:
    """F5: the flag the old UI tested is True on the validation stick."""
    shown = drive.preview(
        make_device(transport="usb", rotational=True, model="TransMemory"),
        make_caps(),
    )
    assert shown.flash
    assert "usb" in shown.flash_reason
    clear = _plan(shown, SanitizationLevel.CLEAR)
    assert any("flash translation layer" in note for note in clear.evidence)
    assert "bridge" in shown.purge_requires


def test_the_capability_limitations_reach_the_preview() -> None:
    note = "The drive supports ATA enhanced SECURITY ERASE, but ..."
    shown = drive.preview(
        make_device(rotational=False),
        make_caps(ata_enhanced_erase=True, limitations=[note]),
    )
    for plan in shown.plans:
        assert note in plan.limitations


@pytest.mark.parametrize(
    ("device_over", "caps_over", "expected"),
    [
        case[1:]
        for case in CASES
        if case[3] is not None and case[3] is not EraseMethod.SED_CRYPTO_ERASE
    ],
    ids=[
        case[0]
        for case in CASES
        if case[3] is not None and case[3] is not EraseMethod.SED_CRYPTO_ERASE
    ],
)
def test_a_real_run_plans_the_method_the_preview_showed(
    device_over: dict[str, object],
    caps_over: dict[str, object],
    expected: EraseMethod,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End to end through ``execute``: the planned method equals the shown one."""
    from core.erase.sink import LedgerSink

    device = make_device(**device_over)
    caps = make_caps(**caps_over)
    shown = _plan(drive.preview(device, caps), SanitizationLevel.PURGE)

    class _Sink(LedgerSink):
        def record(self, phase: object, event: str, detail: dict[str, object]) -> None:
            return None

    monkeypatch.setattr(drive.guard, "assert_erasable", lambda d: None)
    monkeypatch.setattr(drive, "_reread_serial", lambda d, p: None)
    monkeypatch.setattr(
        drive,
        "device_geometry",
        lambda path, probe=None: drive.Geometry(64 * 1024 * 1024, 512, 512),
    )
    monkeypatch.setattr(
        drive.hidden_areas, "detect_hidden_areas", lambda d, io=None: None
    )

    # execute always dispatches; the write and the read-back are faked so the
    # method it selects can be compared without touching a device.
    def fake_dispatch(*_a: object, **_k: object) -> object:
        yield from ()
        return (0, 1, [], [], True)

    def fake_verify(*_a: object, **_k: object) -> object:
        return drive.VerificationResult(
            passed=True,
            strategy="hw_attested",
            bytes_checked=0,
            sample_count=0,
            confidence_bp=10_000,
            failed_offsets=[],
            hw_attested=True,
        )

    def no_calibration(*_a: object, **_k: object) -> object:
        raise AssertionError("a firmware method must not calibrate")

    monkeypatch.setattr(drive, "_dispatch", fake_dispatch)
    monkeypatch.setattr(drive.verify_mod, "verify", fake_verify)
    monkeypatch.setattr(drive.calibrate_mod, "calibrate_write", no_calibration)

    job = make_job(device, level=SanitizationLevel.PURGE)
    generator = drive.execute(job, caps, ledger=_Sink())
    while True:
        try:
            next(generator)
        except StopIteration as stop:
            result = stop.value
            break
    assert result.method is shown.method is expected
