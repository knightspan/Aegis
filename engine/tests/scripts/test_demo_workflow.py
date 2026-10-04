"""The judge demo, end to end, on the state ``scripts/demo_setup.py`` builds.

Every beat of the six-minute flow is driven here through the real routes, the
real job registry and the real carve pipeline, against the staged image, so
"the demo works" is a test result and not a rehearsal note:

case → evidence with its hash → recovery → gallery artifact served →
reconstructed JPEG with its runs → signed report → verification → tamper
simulation → restart → report still resolves and verifies.

No device is opened. The only erasure-capable thing the script creates is a
directory of throwaway files, and this test does not erase it.
"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest
from api.deps import AppServices
from api.jobs import JobRegistry
from api.main import create_app
from fastapi.testclient import TestClient
from helper.daemon import InProcessHelper

from tests._loopback import LOOPBACK_BASE_URL

ROOT = Path(__file__).resolve().parents[2]


def _load_setup() -> Any:
    spec = importlib.util.spec_from_file_location(
        "demo_setup", ROOT / "scripts" / "demo_setup.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def staged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("SANCTUM_KEY_PASSPHRASE", "demo-test-passphrase")
    monkeypatch.setattr(sys, "argv", ["demo_setup", "--state-dir", str(tmp_path / "s")])
    assert _load_setup().main() == 0
    return tmp_path / "s"


def _services(state: Path) -> AppServices:
    built = AppServices(
        registry=JobRegistry(),
        helper=InProcessHelper(),
        state_dir=state,
        key_dir=state / "keys",
    )
    built.prepare()
    return built


def _wait(client: TestClient, job_id: str) -> dict[str, Any]:
    status: dict[str, Any] = {}
    for _ in range(3000):
        status = client.get(f"/jobs/{job_id}").json()
        if status["state"] not in {"pending", "running"}:
            return status
    raise AssertionError(f"job {job_id} did not finish: {status}")


def test_setup_refuses_a_directory_that_is_not_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A demo must never share a ledger or evidence tree with real casework."""
    (tmp_path / "busy").mkdir()
    (tmp_path / "busy" / "chain.jsonl").write_text("real work", encoding="utf-8")
    monkeypatch.setenv("SANCTUM_KEY_PASSPHRASE", "x")
    monkeypatch.setattr(
        sys, "argv", ["demo_setup", "--state-dir", str(tmp_path / "busy")]
    )

    assert _load_setup().main() == 2
    assert (tmp_path / "busy" / "chain.jsonl").read_text() == "real work"


def test_the_six_minute_flow_runs_on_real_data(staged: Path) -> None:
    services = _services(staged)
    notes = (staged / "DEMO.md").read_text(encoding="utf-8")
    jpeg_digest = notes.split("Bifragmented JPEG SHA-256 (whole file): `")[1][:64]

    with TestClient(
        create_app(services=services, serve_ui=False), base_url=LOOPBACK_BASE_URL
    ) as client:
        # 00:00 - 00:40  case, evidence, source hash
        detail = client.get("/cases/DEMO-CASE-001").json()
        exhibit = detail["evidence"][0]
        image = Path(exhibit["source"])
        assert exhibit["source_hash"] == hashlib.sha256(image.read_bytes()).hexdigest()
        assert detail["case"]["integrity"] == "VALID"

        # 01:10  recovery, filed against the case
        accepted = client.post(
            "/jobs/carve",
            json={
                "image": str(image),
                "out_dir": "demo-run",
                "case_id": "DEMO-CASE-001",
                "operator": "Examiner A",
            },
        )
        assert accepted.status_code == 200, accepted.text
        job_id = accepted.json()["job_id"]
        status = _wait(client, job_id)
        assert status["state"] == "complete", status.get("error")

        # 01:50  gallery: real recovered files are served
        listing = client.get("/artifacts/recovered").json()["artifacts"]
        images = [item for item in listing if item["content_type"] == "image/jpeg"]
        assert images, (
            "the gallery would have nothing to show; the carve reported: "
            f"written={len(status['result']['written'])} "
            f"limitations={status['result']['limitations']}"
        )
        served = client.get(images[0]["url"])
        assert served.status_code == 200
        assert served.content[:2] == b"\xff\xd8"

        # 02:20 - 03:00  the reconstructed JPEG, its runs, and its confidence
        rebuilt = [
            item
            for item in status["result"]["candidates"]
            if item["fragments"] and item["sha256"] == jpeg_digest
        ]
        assert len(rebuilt) == 1, "the staged bifragment JPEG was not reassembled"
        candidate = rebuilt[0]
        assert len(candidate["fragments"]) == 2
        assert candidate["score_components"]["reassembly"] != 0
        assert candidate["confidence_bp"] < 8000  # held under HIGH, by design

        # 03:20 - 03:40  signed report, verified
        report = client.post(
            f"/reports/{job_id}", json={"case_id": "DEMO-CASE-001"}
        ).json()
        assert client.get(report["pdf_url"]).status_code == 200
        verification = client.get(f"/reports/{job_id}/verify").json()
        assert verification["passed"] is True
        genesis = [
            c for c in verification["checks"]
            if c["name"] == "fingerprint_matches_genesis"
        ]
        assert genesis and genesis[0]["passed"] and genesis[0]["applicable"]

        # 04:00 - 04:20  tamper simulation breaks a copy at the exact sequence
        demo = client.post("/ledger/tamper-demo", json={}).json()
        assert demo["after"]["status"] == "BROKEN"
        assert demo["after"]["first_broken_seq"] == demo["tampered_seq"]
        assert client.get("/ledger/verify").json()["status"] == "VALID"

        # The case now accounts for all of it.
        detail = client.get("/cases/DEMO-CASE-001").json()
        assert detail["operations"][0]["operation_id"] == job_id
        assert detail["reports"], "the report should be filed against the case"

    # 04:40  restart: a new process still resolves and verifies the report.
    restarted = _services(staged)
    with TestClient(
        create_app(services=restarted, serve_ui=False), base_url=LOOPBACK_BASE_URL
    ) as client:
        assert client.get(f"/jobs/{job_id}").json()["reconstructed"] is True
        assert client.get(f"/reports/{job_id}/verify").json()["passed"] is True
