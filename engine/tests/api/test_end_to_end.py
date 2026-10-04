"""One run through the whole product, entirely over HTTP.

Acquire a test image, stream the job to completion, generate the signed report,
verify it. Nothing here reaches into a core module: if the API cannot do it,
neither can the UI, and neither can an operator at the venue.

This is the test that would have caught a stub left behind anywhere along that
chain, which is why it exercises the real acquisition, the real ledger, the
real signing key and the real report verification rather than any of them
in fixture form.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from api.deps import AppServices
from fastapi.testclient import TestClient

from .test_streaming import parse_events


def _await_job(client: TestClient, job_id: str, timeout: float = 60.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = client.get(f"/jobs/{job_id}").json()
        if status["state"] in {"complete", "failed", "cancelled"}:
            return status
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} did not finish within {timeout}s")


def test_acquire_stream_report_and_verify_through_the_api_only(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    # -- a test image, with content whose hash we know ---------------------
    source = tmp_path / "evidence.dd"
    payload = bytes(range(256)) * 4096  # 1 MiB, non-repeating within a block
    source.write_bytes(payload)
    expected = hashlib.sha256(payload).hexdigest()
    # Relative, and therefore inside the deployment's evidence directory. An
    # absolute path outside it is refused before anything is opened; see
    # test_an_acquisition_outside_the_evidence_directory_is_refused.
    dest = services.evidence_dir / "acquired.dd"

    # -- acquire -----------------------------------------------------------
    accepted = client.post(
        "/jobs/acquire",
        json={"source": str(source), "dest": "acquired.dd", "fmt": "raw"},
    )
    assert accepted.status_code == 200, accepted.text
    job_id = accepted.json()["job_id"]

    # -- stream it to completion ------------------------------------------
    with client.stream("GET", f"/jobs/{job_id}/stream") as response:
        assert response.status_code == 200
        body = "".join(response.iter_text())

    events = parse_events(body)
    progress = [data for name, data in events if name == "progress"]
    assert progress, "the acquisition produced no progress"
    assert events[-1][0] == "state"
    assert events[-1][1]["state"] == "complete", events[-1][1].get("error")

    # The image really was written, and it really is the source's bytes.
    assert dest.exists()
    assert hashlib.sha256(dest.read_bytes()).hexdigest() == expected

    status = _await_job(client, job_id)
    assert status["result"]["sha256"] == expected, (
        "the acquisition record must carry the hash computed during the read pass"
    )

    # -- the chain recorded it --------------------------------------------
    chain = client.get("/ledger/verify").json()
    assert chain["status"] == "VALID", chain["explanation"]
    assert chain["entry_count"] >= 2  # genesis, plus the acquisition

    assert status["ledger_entries"], (
        "the job's own entries must be findable by job_id, or a report cannot "
        "be joined to the run that produced it"
    )

    # -- generate the signed report ---------------------------------------
    generated = client.post(
        f"/reports/{job_id}", json={"case_id": "CASE-E2E", "operator": "tester"}
    )
    assert generated.status_code == 200, generated.text
    report = generated.json()

    json_path = Path(report["json_path"])
    pdf_path = Path(report["pdf_path"])
    assert json_path.is_file() and pdf_path.is_file()
    assert pdf_path.read_bytes().startswith(b"%PDF-")
    assert report["pubkey_fingerprint"]

    document = json.loads(json_path.read_bytes())
    assert document["signature"]["pubkey_fingerprint"] == report["pubkey_fingerprint"]

    # -- verify it, every check independently -----------------------------
    verified = client.get(f"/reports/{job_id}/verify")
    assert verified.status_code == 200, verified.text
    result = verified.json()

    names = {check["name"] for check in result["checks"]}
    assert len(result["checks"]) == 5, result["checks"]
    assert names == {
        "signature",
        "fingerprint_matches_genesis",
        "chain_integrity",
        # The store re-verified independently of the excerpt, and of the
        # chain_status the report prints about itself.
        "chain_store",
        "blobs_available",
    }, names
    # Each reported independently: they fail for different reasons and a reader
    # needs to know which. An unverifiable fingerprint means only that the key
    # was not published anywhere this host can reach, which is not a defect in
    # the report at all.
    assert all("detail" in check for check in result["checks"])
    assert result["caveat"], "the identity caveat must travel with the result"

    signature_check = next(
        check for check in result["checks"] if check["name"] == "signature"
    )
    assert signature_check["passed"] is True, signature_check["detail"]
    assert result["passed"] is True, result["checks"]


def test_a_tampered_report_fails_its_signature_check(
    client: TestClient, tmp_path: Path
) -> None:
    """The check has to have teeth, or the whole audit trail is decoration."""
    source = tmp_path / "small.dd"
    source.write_bytes(b"S" * 4096)
    accepted = client.post(
        "/jobs/acquire",
        json={"source": str(source), "dest": "out.dd"},
    ).json()
    _await_job(client, accepted["job_id"])

    report = client.post(
        f"/reports/{accepted['job_id']}",
        json={"case_id": "CASE-TAMPER", "operator": "tester"},
    ).json()

    json_path = Path(report["json_path"])
    document = json.loads(json_path.read_bytes())
    document["sections"]["case_identity"]["operator"] = "somebody else"
    json_path.write_bytes(json.dumps(document).encode())

    result = client.get(f"/reports/{accepted['job_id']}/verify").json()
    signature_check = next(
        check for check in result["checks"] if check["name"] == "signature"
    )
    assert signature_check["passed"] is False
    assert result["passed"] is False
