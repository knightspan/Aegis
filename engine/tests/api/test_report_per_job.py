"""Two reports in one case never share a file, and the report entry's actor is trusted.

Found in the 2026-09-21 black-box UI run. Reports are named by case id, and
every job in a case now inherits the case id, so the second report of a case
overwrote the first. ``GET /reports/{first job}/verify`` then checked the
second job's file and the Audit screen showed 5 of 5 passed for a report the
first job never produced - the same class of error as audit item C8.

The same run found the ``report.generated`` entry's actor taken verbatim from
the request body, so the entry that binds a report to its job carried
whatever the browser typed.
"""

from __future__ import annotations

from pathlib import Path

from api.deps import AppServices
from api.identity import resolve
from api.routes.audit import REPORT_GENERATED
from core.ledger.chain import Ledger
from fastapi.testclient import TestClient

from .conftest import settle


def _job(client: TestClient, services: AppServices, tmp_path: Path, name: str) -> str:
    source = tmp_path / f"{name}.bin"
    source.write_bytes(name.encode() * 512)
    job_id: str = client.post(
        "/jobs/acquire", json={"source": str(source), "dest": f"{name}.dd"}
    ).json()["job_id"]
    assert settle(services, job_id) == "complete"
    return job_id


def test_two_reports_in_one_case_do_not_overwrite_each_other(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    first = _job(client, services, tmp_path, "first")
    second = _job(client, services, tmp_path, "second")
    a = client.post(f"/reports/{first}", json={"case_id": "SAME-CASE"}).json()
    b = client.post(f"/reports/{second}", json={"case_id": "SAME-CASE"}).json()

    assert a["json_path"] != b["json_path"]
    assert Path(a["json_path"]).is_file() and Path(b["json_path"]).is_file()
    for job in (first, second):
        verdict = client.get(f"/reports/{job}/verify").json()
        assert verdict["passed"] is True
        # The decisive assertion: each job's report is still its own bytes.
        assert verdict["ledger_digest_matches"] is True


def test_report_urls_resolve_through_the_artifact_endpoint(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    job = _job(client, services, tmp_path, "urls")
    made = client.post(f"/reports/{job}", json={"case_id": "C"}).json()
    verdict = client.get(f"/reports/{job}/verify").json()

    urls = (made["json_url"], made["pdf_url"], verdict["json_url"], verdict["pdf_url"])
    for url in urls:
        assert client.get(url).status_code == 200, url


def test_the_report_entry_actor_is_the_trusted_identity(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    job = _job(client, services, tmp_path, "actor")
    client.post(f"/reports/{job}", json={"case_id": "C", "operator": "Chief Examiner"})

    chain = Ledger(services.ledger_root, tool_version="t", pubkey_fingerprint="")
    actors = [e.actor for e in chain.entries() if e.operation == REPORT_GENERATED]

    assert actors == [f"{resolve(services).actor} [label: Chief Examiner]"]


def test_a_job_id_that_is_not_a_name_is_refused(client: TestClient) -> None:
    answer = client.post("/reports/..%2F..%2Fetc", json={})

    assert answer.status_code in {404, 405}
