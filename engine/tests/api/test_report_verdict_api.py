"""The report verification endpoint carries the graded verdict and its reasons.

A file-erase report declares limitations (journals, snapshots, what a file-level
overwrite cannot reach), so an honest verdict for one is never a bare VERIFIED.
"""

from __future__ import annotations

import time
from pathlib import Path

from fastapi.testclient import TestClient

VERDICTS = {"VERIFIED", "VERIFIED_WITH_LIMITATIONS", "PARTIAL", "FAILED_VERIFICATION"}

def _confirmed(target: Path) -> dict[str, object]:
    """A confirmed erase of one scratch file; every erase is real."""
    return {"paths": [str(target)], "confirm": True, "sweep_traces": False}



def _finished_erase(client: TestClient, tmp_path: Path) -> str:
    target = tmp_path / "f.bin"
    target.write_bytes(b"x" * 64)
    job_id = client.post("/jobs/erase-files", json=_confirmed(target)).json()[
        "job_id"
    ]
    for _ in range(300):
        status = client.get(f"/jobs/{job_id}").json()
        if status["state"] in {"complete", "failed"}:
            break
        time.sleep(0.02)
    assert status["state"] == "complete", status.get("error")
    report = client.post(f"/reports/{job_id}", json={"case_id": "", "operator": ""})
    assert report.status_code == 200, report.text
    return str(job_id)


def test_verify_returns_a_verdict_and_reasons(
    client: TestClient, tmp_path: Path
) -> None:
    job_id = _finished_erase(client, tmp_path)
    body = client.get(f"/reports/{job_id}/verify").json()
    assert body["verdict"] in VERDICTS
    assert isinstance(body["verdict_reasons"], list)
    if body["verdict"] != "VERIFIED":
        assert body["verdict_reasons"], "a downgrade must say why"


def test_a_passing_report_is_never_failed_and_a_failing_one_never_verified(
    client: TestClient, tmp_path: Path
) -> None:
    job_id = _finished_erase(client, tmp_path)
    body = client.get(f"/reports/{job_id}/verify").json()
    if body["passed"]:
        assert body["verdict"] != "FAILED_VERIFICATION"
    else:
        assert body["verdict"] == "FAILED_VERIFICATION"
