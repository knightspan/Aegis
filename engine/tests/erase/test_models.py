"""Erase-lifecycle models: phases, checkpoints, plan and result."""

from __future__ import annotations

from datetime import UTC, datetime

from core.models import (
    EraseCheckpoint,
    EraseMethod,
    ErasePhase,
    ErasePlan,
    EraseResult,
    ResidualRiskAssessment,
    SanitizationLevel,
    UnwritableRange,
)


def test_phases_are_declared_in_execution_order() -> None:
    assert list(ErasePhase) == [
        ErasePhase.PREFLIGHT,
        ErasePhase.HIDDEN_AREA_UNLOCK,
        ErasePhase.ERASE,
        ErasePhase.HIDDEN_AREA_RESTORE,
        ErasePhase.VERIFY,
        ErasePhase.REPORT,
    ]


def test_unwritable_range_records_the_errno() -> None:
    bad = UnwritableRange(offset=4096, length=512, errno=5)
    assert bad.end == 4608


def test_checkpoint_round_trips() -> None:
    point = EraseCheckpoint(
        job_id="j1",
        pass_index=0,
        offset=268435456,
        bytes_written=268435456,
        ts_utc=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert EraseCheckpoint.model_validate_json(point.model_dump_json()) == point


def plan() -> ErasePlan:
    return ErasePlan(
        method=EraseMethod.SINGLE_PASS_OVERWRITE,
        level=SanitizationLevel.CLEAR,
        justification="No firmware sanitize was observed on this bridge.",
        est_seconds=750,
        limitations=[],
        hidden_bytes=0,
    )


def test_result_defaults_to_no_hardware_attestation() -> None:
    result = EraseResult(
        job_id="j1",
        method=EraseMethod.SINGLE_PASS_OVERWRITE,
        level=SanitizationLevel.CLEAR,
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        finished_at=datetime(2026, 1, 1, tzinfo=UTC),
        bytes_written=0,
        passes=1,
        plan=plan(),
        residual_risk=ResidualRiskAssessment(
            level="medium", factors=[], purge_achieved=False, notes=""
        ),
    )
    assert result.hw_attested is False
    assert result.unwritable_ranges == []
    assert result.limitations == []
