"""``/reports/{job_id}/verify`` resolves through the chain, or answers 404.

Audit item C8. The endpoint used to glob ``*{job_id}*.forensic.json`` and, when
that missed, fall back to *any* report in the directory and return the
alphabetically last one - with ``passed: true`` and the wrong job's document. On
a demo machine with several reports staged, asking about job A returned a green
tick for job B.

The glob could not have worked anyway. A report is named
``<case_id>.forensic.json``, and the case id is whatever the operator typed, so
on the normal path the job id is not in the filename at all. Batch 1 found this
and correctly stopped rather than deleting a fallback two happy-path tests were
silently depending on.

What replaced it: generating a report appends a ``report.generated`` entry
carrying the job id, both artifact paths and the SHA-256 of the JSON. Resolution
reads that entry. No filename is ever guessed, and a job with no report gets a
404 that names the job rather than somebody else's document.
"""

from __future__ import annotations

import json
from pathlib import Path

from api.deps import AppServices
from api.routes.audit import REPORT_GENERATED
from fastapi.testclient import TestClient

from .conftest import settle


def acquire_job(
    client: TestClient, services: AppServices, tmp_path: Path, name: str
) -> str:
    """Run one real acquisition to completion and return its job id."""
    source = tmp_path / f"{name}.dd"
    source.write_bytes(name.encode() * 512)
    accepted = client.post(
        "/jobs/acquire", json={"source": str(source), "dest": f"{name}.dd"}
    )
    assert accepted.status_code == 200, accepted.text
    job_id: str = accepted.json()["job_id"]
    assert settle(services, job_id) == "complete"
    return job_id


def generate(client: TestClient, job_id: str, case_id: str) -> dict:
    answer = client.post(
        f"/reports/{job_id}", json={"case_id": case_id, "operator": "tester"}
    )
    assert answer.status_code == 200, answer.text
    result: dict = answer.json()
    return result


# --------------------------------------------------------------------------
# Generation is an audited event
# --------------------------------------------------------------------------


def test_generating_a_report_appends_a_chain_entry_naming_the_artifact(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    """The entry binds job to file to digest, and it is hash-chained like the rest.

    A forensic tool that records what it did to a device but not what it
    published about that device has a gap in its own account of itself.
    """
    from core.ledger.chain import Ledger

    job_id = acquire_job(client, services, tmp_path, "alpha")
    report = generate(client, job_id, "CASE-ALPHA")

    chain = Ledger(
        services.ledger_root, tool_version="t", pubkey_fingerprint=""
    )
    entries = [e for e in chain.entries() if e.operation == REPORT_GENERATED]
    assert len(entries) == 1

    params = chain.params_of(entries[0])
    result = chain.result_of(entries[0])
    assert params["job_id"] == job_id
    assert params["case_id"] == "CASE-ALPHA"
    assert params["json_path"] == report["json_path"]
    assert params["pdf_path"] == report["pdf_path"]
    assert result["sha256"] == report["sha256"]

    # The digest is of the bytes actually on disk, not of something rebuilt.
    import hashlib

    on_disk = hashlib.sha256(Path(report["json_path"]).read_bytes()).hexdigest()
    assert result["sha256"] == on_disk


def test_the_chain_still_verifies_after_a_report_entry(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    """A new entry kind must not be a new way to break the chain."""
    job_id = acquire_job(client, services, tmp_path, "beta")
    generate(client, job_id, "CASE-BETA")

    chain = client.get("/ledger/verify").json()
    assert chain["status"] == "VALID", chain["explanation"]


# --------------------------------------------------------------------------
# Resolution
# --------------------------------------------------------------------------


def test_verify_resolves_the_report_belonging_to_the_job(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    """The case id is in the filename and the job id is not; resolution still works."""
    job_id = acquire_job(client, services, tmp_path, "gamma")
    report = generate(client, job_id, "CASE-GAMMA")

    answer = client.get(f"/reports/{job_id}/verify")

    assert answer.status_code == 200, answer.text
    body = answer.json()
    assert body["report"] == report["json_path"]
    assert job_id not in Path(report["json_path"]).name, (
        "this test is only meaningful while the filename does NOT contain the "
        "job id - that is what the old glob was trying and failing to match"
    )


def test_a_directory_of_other_reports_never_answers_for_this_job(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    """The C8 defect itself, in one assertion.

    Three jobs, three reports, one directory. Each job must resolve to its own
    document - and critically, the job with no report of its own must not be
    handed one of the other two.
    """
    first = acquire_job(client, services, tmp_path, "one")
    second = acquire_job(client, services, tmp_path, "two")
    third = acquire_job(client, services, tmp_path, "three")

    first_report = generate(client, first, "AAA-CASE")
    second_report = generate(client, second, "ZZZ-CASE")

    assert client.get(f"/reports/{first}/verify").json()["report"] == (
        first_report["json_path"]
    )
    assert client.get(f"/reports/{second}/verify").json()["report"] == (
        second_report["json_path"]
    )

    # The old code sorted the directory and returned the last entry, so this
    # job would have been answered with ZZZ-CASE and a green tick.
    orphan = client.get(f"/reports/{third}/verify")
    assert orphan.status_code == 404, orphan.text
    assert third in orphan.json()["detail"]["error"]


def test_a_job_with_no_report_is_a_404_naming_the_job(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    """Not a failed verification, and not somebody else's report."""
    job_id = acquire_job(client, services, tmp_path, "delta")

    answer = client.get(f"/reports/{job_id}/verify")

    assert answer.status_code == 404
    detail = answer.json()["detail"]
    assert detail["kind"] == "ReportNotFound"
    assert job_id in detail["error"]
    assert f"POST /reports/{job_id}" in detail["remediation"]


def test_an_unknown_job_is_a_404_not_a_report(client: TestClient) -> None:
    """A job this process never heard of resolves to nothing at all."""
    answer = client.get("/reports/erase-drive-neverexisted/verify")

    assert answer.status_code == 404
    assert answer.json()["detail"]["kind"] == "ReportNotFound"


def test_regenerating_a_report_resolves_to_the_newest_one(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    """Regenerating is legitimate; the latest entry is the one that counts."""
    job_id = acquire_job(client, services, tmp_path, "epsilon")
    generate(client, job_id, "FIRST-CASE")
    second = generate(client, job_id, "SECOND-CASE")

    body = client.get(f"/reports/{job_id}/verify").json()

    assert body["report"] == second["json_path"]


def test_a_report_deleted_after_generation_is_a_404_naming_the_path(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    """The chain says it existed; the disk says otherwise. Say both."""
    job_id = acquire_job(client, services, tmp_path, "zeta")
    report = generate(client, job_id, "CASE-ZETA")
    Path(report["json_path"]).unlink()

    answer = client.get(f"/reports/{job_id}/verify")

    assert answer.status_code == 404
    assert report["json_path"] in answer.json()["detail"]["error"]


# --------------------------------------------------------------------------
# The digest the chain recorded
# --------------------------------------------------------------------------


def test_verify_reports_whether_the_file_is_still_the_recorded_bytes(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    job_id = acquire_job(client, services, tmp_path, "eta")
    report = generate(client, job_id, "CASE-ETA")

    body = client.get(f"/reports/{job_id}/verify").json()
    assert body["ledger_digest"] == report["sha256"]
    assert body["ledger_digest_matches"] is True

    document = json.loads(Path(report["json_path"]).read_bytes())
    document["sections"]["case_identity"]["operator"] = "somebody else"
    Path(report["json_path"]).write_bytes(json.dumps(document).encode())

    tampered = client.get(f"/reports/{job_id}/verify").json()
    assert tampered["ledger_digest_matches"] is False
    assert tampered["passed"] is False
    # Still five checks: the digest is reported alongside them, not folded in.
    assert len(tampered["checks"]) == 5


def test_no_glob_fallback_remains_in_the_source(  # noqa: D401
) -> None:
    """A guard against the fallback being reintroduced by a well-meaning patch.

    In the style of ``tests/test_stubs_raise.py``: the defect was a two-line
    convenience, and it will look like a two-line convenience again next time.
    """
    import api.routes.audit as audit_module

    source = Path(audit_module.__file__).read_text(encoding="utf-8")

    assert 'glob(f"*{job_id}*' not in source
    assert 'glob("*.forensic.json")' not in source
