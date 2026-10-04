"""A report says what state its job was in, and refuses when that is no state.

MANUAL_REPORT FINDING 1. ``POST /reports/{job_id}`` read the registry and fell
back to ``{"state": "unknown", "result": None}`` on a miss, and nothing refused a
job still in ``running``. A report generated seconds into a carve was signed,
carried ``recovery: {}`` and ``objects_written: 0``, and passed every check. It
was not false; it invited one reading and supported another.

Two fixes, answering two different questions:

* **Refusal** stops the misleading artifact from existing. A running job has no
  result yet, and a job this process has forgotten has no result here at all.
  Those are different situations with different remedies, so they are refused
  with different kinds.
* **``job_state`` in ``case_identity``** means an artifact that does exist -
  for a failed or a cancelled job, both legitimate things to document - still
  says what it documents, inside the signed bytes.

FINDING 5 rides along: a failed or cancelled job has no result, so the report's
limitations used to collapse to the deployment's own. The one report most in
need of a caveat now carries one that names the state.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any

from api.deps import AppServices
from api.jobs import JobRegistry
from api.routes.audit import REPORT_GENERATED
from core.ledger.chain import Ledger
from core.models import Progress
from fastapi.testclient import TestClient


def _progress(job_id: str, step: int) -> Progress:
    return Progress(
        job_id=job_id,
        phase="signatures",
        pct_bp=min(step, 10_000),
        bytes_done=step,
        bytes_total=10_000,
        throughput_bytes_per_sec=0,
        eta_seconds=0,
        message=f"step {step}",
    )


def _report_entries(services: AppServices) -> list[Any]:
    chain = Ledger(services.ledger_root, tool_version="t", pubkey_fingerprint="")
    return [e for e in chain.entries() if e.operation == REPORT_GENERATED]


def _reports_on_disk(services: AppServices) -> list[Path]:
    return sorted(services.reports_dir.rglob("*.forensic.*"))


def _generate(client: TestClient, job_id: str) -> Any:
    return client.post(
        f"/reports/{job_id}", json={"case_id": f"CASE-{job_id}", "operator": "tester"}
    )


def _document(answer: Any) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(Path(answer.json()["json_path"]).read_text())
    return loaded


def _acquire_job(client: TestClient, tmp_path: Path, name: str) -> str:
    source = tmp_path / f"{name}.dd"
    source.write_bytes(name.encode() * 512)
    accepted = client.post(
        "/jobs/acquire", json={"source": str(source), "dest": f"{name}.dd"}
    )
    assert accepted.status_code == 200, accepted.text
    job_id: str = accepted.json()["job_id"]
    deadline = time.monotonic() + 30
    # `settled`, not `state`: the outcome entry these tests read is appended
    # after the state flips. See JobRecord.settled.
    while not client.get(f"/jobs/{job_id}").json()["settled"]:
        assert time.monotonic() < deadline, "the job never settled"
        time.sleep(0.01)
    return job_id


# --------------------------------------------------------------------------
# Refused: running
# --------------------------------------------------------------------------


def test_a_report_for_a_running_job_is_refused_and_nothing_is_written(
    client: TestClient, services: AppServices
) -> None:
    started = threading.Event()
    release = threading.Event()

    def factory() -> Generator[Progress, None, dict[str, Any]]:
        started.set()
        release.wait(timeout=10)
        yield _progress("carve-running", 1)
        return {}

    job_id = services.registry.submit("carve", {}, factory, job_id="carve-running")
    assert started.wait(timeout=5)
    try:
        answer = _generate(client, job_id)
    finally:
        release.set()
        services.registry.wait(job_id)

    assert answer.status_code == 409, answer.text
    detail = answer.json()["detail"]
    assert detail["kind"] == "JobNotFinished"
    assert "running" in detail["error"]
    assert f"GET /jobs/{job_id}" in detail["remediation"]
    assert _report_entries(services) == []
    assert _reports_on_disk(services) == []


# --------------------------------------------------------------------------
# Refused: unknown, in two distinguishable ways
# --------------------------------------------------------------------------


def test_a_report_for_a_job_nobody_has_seen_is_refused_as_unknown(
    client: TestClient, services: AppServices
) -> None:
    answer = _generate(client, "carve-never-submitted")

    assert answer.status_code == 404, answer.text
    detail = answer.json()["detail"]
    assert detail["kind"] == "JobNotKnown"
    assert "no entries" in detail["error"]
    assert detail["remediation"]
    assert _report_entries(services) == []
    assert _reports_on_disk(services) == []


def test_a_job_forgotten_by_a_restart_is_rebuilt_from_the_chain(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    """A restart no longer destroys report accessibility.

    This is the behaviour that changed. It used to be a 404: the result lived
    in the process that ran the job and the report could not be assembled
    without it. The result is now written into the chain when the job finishes
    (``job.outcome``), stored in the same content-addressed blob store every
    other result goes to, so a process that never saw the job can read the
    identical object back by digest and build the identical report.

    The artifact says where its inputs came from, in its own limitations, so
    "rebuilt after a restart" is a property of the document and not a detail
    only the server knows.
    """
    job_id = _acquire_job(client, tmp_path, "restart")
    services.registry = JobRegistry()  # what a process restart leaves behind
    services.prepare()  # ... and what the next process's startup does

    answer = _generate(client, job_id)

    assert answer.status_code == 200, answer.text
    document = _document(answer)
    limitations = " ".join(document["sections"]["limitations"]["items"])
    assert "REBUILT FROM THE LEDGER" in limitations
    # One report.generated entry: the rebuild is a normal generation, not a
    # second mechanism with its own bookkeeping.
    assert len(_report_entries(services)) == 1


def test_a_report_rebuilt_after_a_restart_still_verifies(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    """The acceptance test for durability, end to end.

    Run the operation, restart, generate, verify. A signature over a rebuilt
    document has to verify for the same reason one over a live document does -
    it covers the canonical bytes that were actually written - and this holds
    that the rebuild did not quietly produce something the verifier rejects.
    """
    job_id = _acquire_job(client, tmp_path, "restart-verify")
    services.registry = JobRegistry()
    services.prepare()

    assert _generate(client, job_id).status_code == 200

    verification = client.get(f"/reports/{job_id}/verify")
    assert verification.status_code == 200, verification.text
    body = verification.json()
    assert body["passed"] is True, body
    assert body["ledger_digest_matches"] is True
    signature = [c for c in body["checks"] if c["name"] == "signature"]
    assert signature and signature[0]["passed"] is True


def test_a_job_with_chain_entries_but_no_outcome_is_still_unknown(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    """The refusal path survives, for the case it was written for.

    A job whose engine wrote entries but which never reached a terminal state -
    the process was killed mid-run - has no ``job.outcome`` and therefore no
    result to rebuild from. That is still a 404, and it still names what the
    chain holds, because "killed mid-run" and "never submitted" are different
    situations with different remedies.
    """
    job_id = _acquire_job(client, tmp_path, "no-outcome")
    services.registry = JobRegistry()
    services.prepare()

    # Drop the outcome entry's blob, which is what an interrupted process would
    # never have written in the first place. The chain still carries the
    # engine's own acquire entries.
    from api.durable import JOB_OUTCOME

    chain = Ledger(services.ledger_root, tool_version="t", pubkey_fingerprint="")
    outcome = [e for e in chain.entries() if e.operation == JOB_OUTCOME]
    assert outcome, "the job should have recorded an outcome to begin with"
    for entry in outcome:
        chain.blobs._path_for(entry.result_hash).unlink()

    answer = _generate(client, job_id)

    assert answer.status_code == 404, answer.text
    detail = answer.json()["detail"]
    assert detail["kind"] == "JobNotKnown"
    # Names what the chain still holds, so "killed mid-run" reads differently
    # from "never submitted".
    assert "the chain holds" in detail["error"]
    assert "entr" in detail["error"]


# --------------------------------------------------------------------------
# Generated, and marked: failed and cancelled
# --------------------------------------------------------------------------


def test_a_report_for_a_failed_job_carries_its_state_and_a_caveat(
    client: TestClient, services: AppServices
) -> None:
    def factory() -> Generator[Progress, None, dict[str, Any]]:
        yield _progress("carve-failed", 1)
        raise OSError("the image went away")

    job_id = services.registry.submit("carve", {}, factory, job_id="carve-failed")
    assert services.registry.wait(job_id).state == "failed"

    answer = _generate(client, job_id)

    assert answer.status_code == 200, answer.text
    document = _document(answer)
    assert document["sections"]["case_identity"]["job_state"] == "failed"
    items = document["sections"]["limitations"]["items"]
    caveat = items[0]
    assert "failed" in caveat
    assert "the image went away" in caveat
    assert len(_report_entries(services)) == 1


def test_a_report_for_a_cancelled_job_carries_its_state_and_a_caveat(
    client: TestClient, services: AppServices
) -> None:
    def factory() -> Generator[Progress, None, dict[str, Any]]:
        step = 0
        while True:
            step += 1
            yield _progress("carve-cancelled", step)
            time.sleep(0.005)

    job_id = services.registry.submit(
        "carve", {}, factory, job_id="carve-cancelled"
    )
    services.registry.cancel(job_id)
    assert services.registry.wait(job_id).state == "cancelled"

    answer = _generate(client, job_id)

    assert answer.status_code == 200, answer.text
    document = _document(answer)
    assert document["sections"]["case_identity"]["job_state"] == "cancelled"
    assert "cancelled" in document["sections"]["limitations"]["items"][0]


# --------------------------------------------------------------------------
# Unaffected: complete
# --------------------------------------------------------------------------


def test_a_report_for_a_completed_job_is_unaffected_apart_from_naming_its_state(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    job_id = _acquire_job(client, tmp_path, "whole")

    answer = _generate(client, job_id)

    assert answer.status_code == 200, answer.text
    document = _document(answer)
    assert document["sections"]["case_identity"]["job_state"] == "complete"
    for item in document["sections"]["limitations"]["items"]:
        assert "JOB " not in item
    verified = client.get(f"/reports/{job_id}/verify").json()
    assert verified["passed"] is True
