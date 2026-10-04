"""The graded verdict: one word that never claims more than the checks do.

``Result: PASS`` says every applicable check passed. It does not say whether
every check *could* run, or whether the report itself declares limits on what it
proves. The verdict says both, and every downgrade carries a reason.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from core.report.verify_report import (
    ChainExcerptStatus,
    CheckName,
    ReportCheck,
    ReportVerdict,
    grade_report,
    verify_report_file,
)

from tests.report.test_verify_report import case, tamper  # noqa: F401


def _checks(
    *,
    failed: set[CheckName] = frozenset(),  # type: ignore[assignment]
    skipped: set[CheckName] = frozenset(),  # type: ignore[assignment]
    excerpt: ChainExcerptStatus = ChainExcerptStatus.VERIFIED_COMPLETE,
) -> list[ReportCheck]:
    out = []
    for name in CheckName:
        status = excerpt.value if name is CheckName.CHAIN_INTEGRITY else ""
        out.append(
            ReportCheck(
                name=name,
                passed=name not in failed,
                detail="detail",
                applicable=name not in skipped,
                status=status,
            )
        )
    return out


def _report(
    *,
    limitations: list[str] | None = None,
    level: str = "low",
    factors: list[str] | None = None,
    passed: bool | None = True,
) -> dict[str, Any]:
    sections: dict[str, Any] = {
        "limitations": {"items": limitations or ["none recorded"]},
        "residual_risk": {"level": level, "factors": factors or ["none recorded"]},
    }
    if passed is not None:
        sections["verification"] = {"passed": passed}
    return {"sections": sections}


def test_everything_clean_is_verified() -> None:
    verdict, reasons = grade_report(_report(), _checks())
    assert verdict is ReportVerdict.VERIFIED
    assert reasons == []


def test_any_failed_check_is_failed_verification() -> None:
    verdict, reasons = grade_report(_report(), _checks(failed={CheckName.SIGNATURE}))
    assert verdict is ReportVerdict.FAILED_VERIFICATION
    assert any("signature" in reason for reason in reasons)


def test_failure_outranks_a_skipped_check() -> None:
    verdict, _ = grade_report(
        _report(),
        _checks(failed={CheckName.SIGNATURE}, skipped={CheckName.CHAIN_STORE}),
    )
    assert verdict is ReportVerdict.FAILED_VERIFICATION


def test_a_check_that_could_not_run_is_partial_not_verified() -> None:
    verdict, reasons = grade_report(
        _report(),
        _checks(skipped={CheckName.CHAIN_STORE, CheckName.BLOBS_AVAILABLE}),
    )
    assert verdict is ReportVerdict.PARTIAL
    assert any("chain_store" in reason for reason in reasons)
    assert any("blobs_available" in reason for reason in reasons)


def test_declared_limitations_downgrade_to_with_limitations() -> None:
    verdict, reasons = grade_report(
        _report(limitations=["Overwrite cannot reach remapped flash blocks"]),
        _checks(),
    )
    assert verdict is ReportVerdict.VERIFIED_WITH_LIMITATIONS
    assert any("remapped" in reason for reason in reasons)


def test_a_partial_excerpt_is_a_limitation() -> None:
    verdict, reasons = grade_report(
        _report(), _checks(excerpt=ChainExcerptStatus.VERIFIED_PARTIAL)
    )
    assert verdict is ReportVerdict.VERIFIED_WITH_LIMITATIONS
    assert any("excerpt" in reason for reason in reasons)


def test_residual_risk_above_low_is_a_limitation() -> None:
    verdict, reasons = grade_report(
        _report(level="high", factors=["CONTROLLER_WRITE_ELISION"]), _checks()
    )
    assert verdict is ReportVerdict.VERIFIED_WITH_LIMITATIONS
    assert any("residual risk high (1 factor" in reason for reason in reasons)


def test_a_report_recording_its_own_failed_verification_is_not_verified() -> None:
    """Authentic bytes that say the erase did not verify are not a clean pass."""
    verdict, reasons = grade_report(_report(passed=False), _checks())
    assert verdict is ReportVerdict.VERIFIED_WITH_LIMITATIONS
    assert any("did not pass" in reason for reason in reasons)


def test_an_empty_verification_block_is_not_a_failed_verification() -> None:
    """An acquisition never reads back; its defaulted block is absence, not failure."""
    report = _report(passed=False)
    report["sections"]["verification"] = {
        "passed": False,
        "strategy": "",
        "bytes_checked": 0,
    }
    verdict, reasons = grade_report(report, _checks())
    assert verdict is ReportVerdict.VERIFIED
    assert not any("did not pass" in reason for reason in reasons)


def test_a_report_without_a_verification_section_is_not_penalised() -> None:
    verdict, _ = grade_report(_report(passed=None), _checks())
    assert verdict is ReportVerdict.VERIFIED


def test_skipped_outranks_limitations() -> None:
    verdict, _ = grade_report(
        _report(limitations=["x"]), _checks(skipped={CheckName.CHAIN_STORE})
    )
    assert verdict is ReportVerdict.PARTIAL


def test_malformed_sections_do_not_crash_and_do_not_upgrade() -> None:
    verdict, _ = grade_report({"sections": "nonsense"}, _checks())
    assert verdict is ReportVerdict.VERIFIED
    verdict, _ = grade_report(
        {"sections": {"limitations": {"items": "not a list"}}}, _checks()
    )
    assert verdict is ReportVerdict.VERIFIED


def test_the_verification_carries_the_verdict(case: dict[str, Any]) -> None:  # noqa: F811
    result = verify_report_file(case["path"], ledger_root=case["ledger_root"])
    assert result.verdict is ReportVerdict.VERIFIED
    assert result.verdict_reasons == []


def test_without_a_ledger_root_the_verdict_is_partial(
    case: dict[str, Any],  # noqa: F811
) -> None:
    result = verify_report_file(case["path"])
    assert result.ok is True
    assert result.verdict is ReportVerdict.PARTIAL


def test_a_tampered_report_is_failed_verification(case: dict[str, Any]) -> None:  # noqa: F811
    tamper(case["path"], lambda d: d["sections"]["device_identity"].update(serial="X"))
    result = verify_report_file(case["path"], ledger_root=case["ledger_root"])
    assert result.verdict is ReportVerdict.FAILED_VERIFICATION


def _cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "core.report.cli", "verify-report", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_prints_the_verdict_after_the_result(case: dict[str, Any]) -> None:  # noqa: F811
    done = _cli(str(case["path"]), "--ledger-root", str(case["ledger_root"]))
    assert done.returncode == 0
    lines = done.stdout.splitlines()
    result_at = lines.index("Result: PASS")
    assert lines[result_at + 1] == "Verdict: VERIFIED"


def test_cli_prints_why_the_verdict_is_partial(case: dict[str, Any]) -> None:  # noqa: F811
    done = _cli(str(case["path"]))
    assert done.returncode == 0, "exit code still follows Result, not the verdict"
    assert "Verdict: PARTIAL" in done.stdout
    assert "  - " in done.stdout


def test_cli_verdict_on_a_tampered_report(case: dict[str, Any]) -> None:  # noqa: F811
    raw = json.loads(Path(case["path"]).read_bytes())
    raw["case_id"] = "CASE-9999"
    Path(case["path"]).write_bytes(json.dumps(raw).encode())
    done = _cli(str(case["path"]), "--ledger-root", str(case["ledger_root"]))
    assert done.returncode == 1
    assert "Verdict: FAILED_VERIFICATION" in done.stdout


def test_verdict_words_are_the_four_documented_ones() -> None:
    assert {v.value for v in ReportVerdict} == {
        "VERIFIED",
        "VERIFIED_WITH_LIMITATIONS",
        "PARTIAL",
        "FAILED_VERIFICATION",
    }
