"""Models construct, round-trip through JSON, and export via ``import *``."""

from __future__ import annotations

import core.models as models
import pytest
from core.ledger.canon import canonical_bytes
from core.models import (
    CarveCandidate,
    Device,
    DeviceCapabilities,
    EraseJob,
    ErasePlan,
    ForensicReport,
    LedgerEntry,
    Progress,
    VerificationResult,
)
from pydantic import ValidationError


def test_star_export_matches_all() -> None:
    exported = {name for name in dir(models) if not name.startswith("_")}
    assert set(models.__all__).issubset(exported)


def test_device_round_trip(sample_device: Device) -> None:
    assert Device.model_validate_json(sample_device.model_dump_json()) == sample_device


def test_an_erase_job_has_no_dry_run_and_needs_its_serial(
    sample_erase_job: EraseJob,
) -> None:
    assert "dry_run" not in EraseJob.model_fields
    assert sample_erase_job.confirmed_serial is None


def test_candidate_round_trip(sample_candidate: CarveCandidate) -> None:
    dumped = sample_candidate.model_dump_json()
    assert CarveCandidate.model_validate_json(dumped) == sample_candidate


def test_verification_round_trip(sample_verification: VerificationResult) -> None:
    dumped = sample_verification.model_dump_json()
    assert VerificationResult.model_validate_json(dumped) == sample_verification


def test_ledger_entry_round_trip(sample_ledger_entry: LedgerEntry) -> None:
    dumped = sample_ledger_entry.model_dump_json()
    assert LedgerEntry.model_validate_json(dumped) == sample_ledger_entry


def test_report_round_trip(sample_report: ForensicReport) -> None:
    dumped = sample_report.model_dump_json()
    assert ForensicReport.model_validate_json(dumped) == sample_report


def _progress(**overrides: object) -> Progress:
    fields: dict[str, object] = {
        "job_id": "job-1",
        "phase": "ERASE",
        "pct_bp": 9940,
        "bytes_done": 512,
        "bytes_total": 1024,
        "throughput_bytes_per_sec": 1_048_576,
        "eta_seconds": 143,
        "message": "pass 1 of 1",
    }
    fields.update(overrides)
    return Progress.model_validate(fields)


def test_progress_reaches_canon_without_a_transform() -> None:
    """Every Progress field is an integer, so canon accepts the payload as-is.

    This is the whole reason the fields are integers. ``canonical_bytes``
    raises on any float, so if this passes, no boundary rewrite is needed and
    a verifier reads the same units the operation measured.
    """
    canonical_bytes(_progress().model_dump(mode="json"))


def test_progress_rejects_percentage_outside_basis_point_range() -> None:
    with pytest.raises(ValidationError):
        _progress(pct_bp=10_001)


def test_no_ledgered_model_carries_a_float(
    sample_capabilities: DeviceCapabilities,
    sample_verification: VerificationResult,
    sample_candidate: CarveCandidate,
    sample_plan: ErasePlan,
) -> None:
    """Every model that reaches a ledger entry canonicalises as written.

    These four are recorded by ``core.erase.drive`` and, from M3, by the
    acquisition path. ``canonical_bytes`` raises on a float and names the key,
    so a single float anywhere in them fails this test. Passing is what lets
    the boundary rewrite be deleted rather than merely narrowed.
    """
    for model in (
        sample_capabilities,
        sample_verification,
        sample_candidate,
        sample_plan,
    ):
        canonical_bytes(model.model_dump(mode="json"))


def test_confidence_fields_are_bounded_basis_points(
    sample_verification: VerificationResult, sample_candidate: CarveCandidate
) -> None:
    for model, field in (
        (sample_verification, "confidence_bp"),
        (sample_candidate, "confidence_bp"),
    ):
        with pytest.raises(ValidationError):
            type(model).model_validate({**model.model_dump(), field: 10_001})
