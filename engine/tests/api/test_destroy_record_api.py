"""POST /jobs/record-destroy chains an attestation and can be certified."""

from __future__ import annotations

import time
from typing import Any

from fastapi.testclient import TestClient

BODY: dict[str, Any] = {
    "serial": "WD-WX41A12345",
    "model": "WDC WD10EZEX",
    "media_type": "HDD",
    "technique": "DISINTEGRATE",
    "particle_size_mm": 6,
    "reason": "Controller failed; Purge cannot be issued.",
    "performed_by": "A. Rao",
    "witnessed_by": "S. Iyer",
    "performed_at": "2026-09-24T10:00:00Z",
}


def _finish(client: TestClient, body: dict[str, Any]) -> dict[str, Any]:
    answer = client.post("/jobs/record-destroy", json=body)
    assert answer.status_code == 200, answer.text
    job_id = answer.json()["job_id"]
    for _ in range(300):
        status: dict[str, Any] = client.get(f"/jobs/{job_id}").json()
        if status["state"] in {"complete", "failed"}:
            break
        time.sleep(0.02)
    assert status["state"] == "complete", status.get("error")
    return status


def test_a_destruction_is_chained_and_its_report_says_attested(
    client: TestClient,
) -> None:
    status = _finish(client, BODY)
    assert status["kind"] == "destroy-record"
    assert status["result"]["observed_by_tool"] is False
    operations = [entry["operation"] for entry in status["ledger_entries"]]
    assert "destroy.recorded" in operations

    report = client.post(
        f"/reports/{status['job_id']}", json={"case_id": "", "operator": ""}
    )
    assert report.status_code == 200, report.text
    signed = client.get(report.json()["json_url"]).json()
    assert signed["sections"]["media"]["serial"] == "WD-WX41A12345"
    assert signed["sections"]["attestation"]["observed_by_tool"] is False
    items = signed["sections"]["limitations"]["items"]
    assert any(str(item).startswith("ATTESTED, NOT OBSERVED") for item in items)
    verified = client.get(f"/reports/{status['job_id']}/verify").json()
    assert verified["passed"] is True


def test_a_future_date_is_refused_and_nothing_is_submitted(
    client: TestClient,
) -> None:
    answer = client.post(
        "/jobs/record-destroy", json=BODY | {"performed_at": "2099-01-01T00:00:00Z"}
    )
    assert answer.status_code == 422
    assert answer.json()["detail"]["kind"] == "DestructionDateInFuture"


def test_an_incomplete_attestation_is_a_422(client: TestClient) -> None:
    answer = client.post("/jobs/record-destroy", json=BODY | {"performed_by": ""})
    assert answer.status_code == 422
