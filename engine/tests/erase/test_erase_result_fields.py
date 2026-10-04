"""An erase result carries what its certificate has to state.

The drive report is built from the job's result. Until 2026-09-25 the engine's
``EraseResult`` held the plan, the residual risk and the byte counts, but not
the device it wrote to, the read-back verdict, the hidden-area record or the
level it achieved - so a report built through the API named no device, no
verification and no achieved level. The API tests did not see it because their
helper fixture invented those fields. These run the real ``execute``.
"""

from __future__ import annotations

from pathlib import Path

from core.models import SanitizationLevel
from core.report.render import drive_report_inputs

from .test_hidden_area_phases import SECTOR, honest, run_with_calibration


def test_a_real_run_records_device_verification_hidden_areas_and_level(
    tmp_path: Path,
) -> None:
    result, _, _, _, _ = run_with_calibration(tmp_path, calibration=honest())
    assert result is not None
    assert result.device is not None and result.device.serial == "SYN-0001"
    assert result.logical_block_size == SECTOR
    assert result.verification is not None and result.verification.passed is True
    assert result.hidden_areas is not None
    assert result.achieved_level is SanitizationLevel.CLEAR


def test_a_result_has_no_rehearsal_flag(tmp_path: Path) -> None:
    """Every result is of a real run; there is no field that could say otherwise."""
    result, _, _, _, _ = run_with_calibration(tmp_path, calibration=honest())
    assert result is not None
    assert "dry_run" not in result.model_dump()


def test_the_report_inputs_name_the_levels_and_the_device(tmp_path: Path) -> None:
    result, _, _, _, _ = run_with_calibration(tmp_path, calibration=honest())
    assert result is not None
    inputs = drive_report_inputs(result.model_dump(mode="json"))
    assert inputs["method"]["level_requested"] == "CLEAR"
    assert inputs["method"]["level_achieved"] == "CLEAR"
    assert inputs["device"]["serial"] == "SYN-0001"
    assert inputs["device"]["logical_block_size"] == SECTOR
    assert inputs["verification"]["passed"] is True
    assert "covered" in inputs["hidden_areas"]


def test_a_legacy_dry_run_flag_in_a_result_is_not_honoured_as_a_claim() -> None:
    """New reports never print "NONE (dry run"; a legacy flag claims nothing either.

    A result recorded by an earlier build with ``dry_run`` set carried no
    verification and no achieved level. Built into a new report, the achieved
    level is simply not recorded - never a level, never a rehearsal wording.
    """
    inputs = drive_report_inputs(
        {"dry_run": True, "plan": {"level": "CLEAR"}, "achieved_level": None}
    )
    assert inputs["method"]["level_achieved"] == ""
    assert inputs["verification"] == {}


def test_a_result_with_nothing_in_it_yields_empty_sections() -> None:
    """A failed job has no result; the report prints the sections as empty."""
    inputs = drive_report_inputs({})
    assert all(section == {} for section in inputs.values())
