"""Every certificate says which OS, app build and privilege it was issued under.

A Windows file erase and a Linux one make different claims (resident MFT data,
no directory flush; journals, FIEMAP read-back), so the report must carry the
platform rather than leave the reader to infer it.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from fastapi.testclient import TestClient


def _confirmed(target: Path) -> dict[str, object]:
    """A confirmed erase of one scratch file; every erase is real."""
    return {"paths": [str(target)], "confirm": True, "sweep_traces": False}



def test_a_file_erase_report_records_the_platform(
    client: TestClient, tmp_path: Path
) -> None:
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
    recorded = status["params"]["platform"]
    assert recorded["os"]
    assert recorded["privilege"] in {"root", "administrator", "standard", "unknown"}
    assert recorded["privilege_basis"]

    report = client.post(f"/reports/{job_id}", json={"case_id": "", "operator": ""})
    assert report.status_code == 200, report.text
    body = client.get(f"/reports/{job_id}/verify").json()
    assert body  # the signed artifact still verifies with the new field

    json_path = Path(report.json()["json_path"])
    import json

    identity = json.loads(json_path.read_text())["sections"]["case_identity"]
    expected = {"linux": "linux", "win32": "windows", "darwin": "macos"}.get(
        sys.platform, "other"
    )
    assert identity["platform"]["family"] == expected
    assert identity["platform"]["app_version"]


def test_the_desktop_app_can_sign_with_a_typed_passphrase(
    client: TestClient, tmp_path: Path, monkeypatch: object
) -> None:
    """A double-clicked app has no environment and no terminal to prompt on."""
    import pytest

    mp: pytest.MonkeyPatch = monkeypatch  # type: ignore[assignment]
    mp.delenv("SANCTUM_KEY_PASSPHRASE", raising=False)
    mp.setattr("core.report.sign._prompt_passphrase", lambda path: "")
    target = tmp_path / "g.bin"
    target.write_bytes(b"y" * 64)
    job_id = client.post("/jobs/erase-files", json=_confirmed(target)).json()[
        "job_id"
    ]
    for _ in range(300):
        if client.get(f"/jobs/{job_id}").json()["state"] != "running":
            break
        time.sleep(0.02)

    missing = client.post(f"/reports/{job_id}", json={"case_id": "", "operator": ""})
    assert missing.status_code == 503
    assert missing.json()["detail"]["kind"] == "KeyPassphraseMissing"

    short = client.post(
        f"/reports/{job_id}",
        json={"case_id": "", "operator": "", "key_passphrase": "short"},
    )
    assert short.json()["detail"]["kind"] == "KeyPassphraseMissing"

    good = "correct horse battery staple"
    made = client.post(
        f"/reports/{job_id}",
        json={"case_id": "", "operator": "", "key_passphrase": good},
    )
    assert made.status_code == 200, made.text
    assert good not in Path(made.json()["json_path"]).read_text()

    wrong = client.post(
        f"/reports/{job_id}",
        json={
            "case_id": "",
            "operator": "",
            "key_passphrase": "not the passphrase at all",
        },
    )
    assert wrong.status_code == 503
    assert "does not open" in wrong.json()["detail"]["error"]
