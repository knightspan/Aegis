"""M2 models: tri-state unknowns and two independent destructive gates."""

from __future__ import annotations

from core.models import (
    FileEraseOptions,
    FileInspection,
    FileVerificationResult,
    ResidualFinding,
    ResidualKind,
    Severity,
)


def test_unknown_capabilities_are_none_not_false() -> None:
    """``None`` means "could not determine". Reporting it as False would lie.

    "This volume has no snapshots" and "nobody could enumerate the snapshots"
    lead an operator to opposite decisions, so they cannot share a value.
    """
    inspection = FileInspection(path="/x/y.txt", size_bytes=10)
    assert inspection.is_resident is None
    assert inspection.vss_present is None
    assert inspection.trim_likely is None
    assert inspection.cow_snapshots is None
    assert inspection.is_sparse is None
    assert inspection.is_encrypted is None
    assert inspection.extents == []
    assert inspection.limitations == []


def test_the_confirmation_gate_defaults_closed_and_there_is_no_dry_run() -> None:
    options = FileEraseOptions()
    assert "dry_run" not in FileEraseOptions.model_fields
    assert options.confirm is False
    assert options.break_hardlinks is False
    assert options.rename_rounds == 8


def test_finding_carries_addressability_and_explanation() -> None:
    finding = ResidualFinding(
        kind=ResidualKind.HARDLINK_SURVIVES,
        severity=Severity.HIGH,
        explanation="st_nlink was 2; the data is alive under another name.",
        addressable=True,
        detail={"nlink": 2},
    )
    assert finding.addressable is True
    assert finding.severity is Severity.HIGH


def test_file_verification_passed_is_tri_state() -> None:
    result = FileVerificationResult(
        passed=None,
        strategy="not_possible",
        reason="No extent map was captured before the erase.",
    )
    assert result.passed is None
    assert result.passed is not True
    assert result.passed is not False


def test_slack_is_zero_when_the_cluster_size_is_unknown() -> None:
    """0 means "no slack" *and* "unmeasurable", which is safe only here.

    The residual scanner reports FILE_SLACK on a positive value only, so an
    unknown produces no finding rather than a false reassurance - and the
    unknown itself already travels as a limitation.
    """
    assert FileInspection(path="x", size_bytes=100, cluster_bytes=0).slack_bytes == 0
    sized = FileInspection(path="x", size_bytes=100, cluster_bytes=4096)
    assert sized.slack_bytes == 3996
    aligned = FileInspection(path="x", size_bytes=8192, cluster_bytes=4096)
    assert aligned.slack_bytes == 0


def test_highest_severity_is_the_worst_not_the_first() -> None:
    from core.models import FileEraseRecord

    record = FileEraseRecord(
        path="x",
        ok=True,
        inspection=FileInspection(path="x", size_bytes=1),
        findings=[
            ResidualFinding(
                kind=ResidualKind.FILE_SLACK,
                severity=Severity.MEDIUM,
                explanation="e",
                addressable=False,
            ),
            ResidualFinding(
                kind=ResidualKind.HARDLINK_SURVIVES,
                severity=Severity.HIGH,
                explanation="e",
                addressable=True,
            ),
        ],
    )
    assert record.highest_severity is Severity.HIGH
