"""The restore report: method, source, target, scope, verification, limitations."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from core.backup import BackupRecord
from core.ledger.chain import Ledger
from core.report.render import build_restore_report, render_json, render_pdf
from core.restore import (
    FileBlockTarget,
    execute_restore,
    file_target_identity,
    plan_restore,
)

from .conftest import IMAGE_SIZE, TARGET_SIZE, drain


def test_a_restore_report_carries_every_section(
    record: BackupRecord, tmp_path: Path, ledger: Ledger
) -> None:
    target_path = tmp_path / "t.img"
    FileBlockTarget.create(target_path, TARGET_SIZE).close()
    plan = plan_restore(record, file_target_identity(target_path))
    target = FileBlockTarget(target_path)
    _, result = drain(
        execute_restore(record, plan, target, job_id="r", ledger=ledger)
    )
    target.close()
    report = build_restore_report(
        case_id="case-restore",
        operator="tester",
        generated_at=datetime(2026, 9, 28, tzinfo=UTC),
        tool_version="test",
        result=result.model_dump(mode="json"),
        ledger_excerpt=[],
        chain_verification=ledger.verify(),
        pubkey_fingerprint="",
    )
    sections = report["sections"]
    assert sections["restore_method"]["result"] == "RESTORED_VERIFIED"
    assert "not a NIST SP 800-88" in sections["restore_method"]["note"]
    assert sections["restore_source"]["image_sha256"] == record.image_sha256
    assert sections["restore_target"]["path"] == str(target_path)
    assert sections["restore_scope"]["bytes_written"] == IMAGE_SIZE
    assert sections["restore_scope"]["unwritable"] == ["none recorded"]
    assert sections["restore_verification"]["passed"] is True
    assert any("READ_BACK_THROUGH_OS" in i for i in sections["limitations"]["items"])
    assert render_json(report)
    assert render_pdf(report).startswith(b"%PDF")
