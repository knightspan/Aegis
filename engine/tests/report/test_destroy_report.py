"""The Destroy record's report and certificate say it was attested, not observed."""

from __future__ import annotations

from typing import Any

from core.report.render import build_destroy_report, render_pdf

from .test_module_reports import COMMON

RECORD: dict[str, Any] = {
    "serial": "WD-WX41A12345",
    "model": "WDC WD10EZEX",
    "capacity_bytes": 1_000_204_886_016,
    "media_type": "HDD",
    "technique": "SHRED",
    "technique_detail": "",
    "particle_size_mm": 20,
    "reason": "Heads failed; the drive cannot be purged.",
    "performed_by": "A. Rao",
    "witnessed_by": "S. Iyer",
    "performed_at": "2026-09-24T10:00:00Z",
    "location": "Evidence room 2",
    "vendor_certificate": "",
    "notes": "",
}


def report(**overrides: Any) -> dict[str, Any]:
    fields = dict(COMMON) | {
        "record": RECORD,
        "recorded_at": "2026-09-25T12:00:00+00:00",
        "limitations": ["ATTESTED, NOT OBSERVED: ..."],
    }
    fields.update(overrides)
    return build_destroy_report(**fields)


def test_the_record_keeps_the_attested_and_the_recorded_dates_apart() -> None:
    sections = report()["sections"]
    assert sections["destruction"]["performed_at"] == "2026-09-24T10:00:00Z"
    assert sections["attestation"]["recorded_at"] == "2026-09-25T12:00:00+00:00"
    assert sections["attestation"]["observed_by_tool"] is False
    assert sections["destruction"]["sanitization_outcome"].startswith("DESTROY")


def test_the_shape_ends_like_every_other_report() -> None:
    names = list(report()["sections"])
    assert names[0] == "case_identity"
    assert names[-3:] == ["limitations", "audit_trail", "signature"]


def test_the_certificate_headline_never_claims_the_tool_saw_it() -> None:
    blob = render_pdf(report())
    assert b"Record of Destruction" in blob
    assert b"Destruction attested, not observed" in blob
    assert b"witnessed by S. Iyer" in blob


def test_no_witness_is_said_on_the_certificate() -> None:
    blob = render_pdf(report(record=RECORD | {"witnessed_by": ""}))
    assert b"no witness recorded" in blob
