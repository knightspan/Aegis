"""The file-erase endpoint sweeps traces by default, and the report says so.

The home the sweep searches is built under ``tmp_path`` here; the suite-wide
fixture in tests/conftest.py already keeps every other test off the real one.
"""

from __future__ import annotations

import hashlib
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from core.erase import traces
from fastapi.testclient import TestClient

from tests.erase.files.test_trace_sweep import png


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    if sys.platform == "win32":
        pytest.skip("freedesktop places name POSIX paths; this host is Windows")
    made = tmp_path / "home"
    made.mkdir()
    locations = traces.locations_for("linux", {}, made)
    monkeypatch.setattr(traces, "default_locations", lambda: locations)
    return made


def _thumbnail(home: Path, target: Path) -> Path:
    uri = traces.file_uris(str(target))[0]
    folder = home / ".cache" / "thumbnails" / "normal"
    folder.mkdir(parents=True, exist_ok=True)
    cached = (
        folder / f"{hashlib.md5(uri.encode(), usedforsecurity=False).hexdigest()}.png"
    )
    cached.write_bytes(png(uri))
    return cached


def _finish(client: TestClient, body: dict[str, Any]) -> dict[str, Any]:
    answer = client.post("/jobs/erase-files", json=body)
    assert answer.status_code == 200, answer.text
    job_id = answer.json()["job_id"]
    for _ in range(300):
        status: dict[str, Any] = client.get(f"/jobs/{job_id}").json()
        if status["state"] in {"complete", "failed"}:
            break
        time.sleep(0.02)
    assert status["state"] == "complete", status.get("error")
    return status


def test_an_unconfirmed_request_is_refused_and_removes_nothing(
    client: TestClient, home: Path, tmp_path: Path
) -> None:
    """There is no preview sweep: without confirm, nothing is searched or removed."""
    target = tmp_path / "plan.jpg"
    target.write_bytes(b"\xff\xd8" + b"p" * 200)
    cached = _thumbnail(home, target)

    answer = client.post("/jobs/erase-files", json={"paths": [str(target)]})

    assert answer.status_code == 409
    assert answer.json()["detail"]["kind"] == "ConfirmationMismatch"
    assert cached.exists() and target.exists()


def test_a_real_erase_removes_the_trace_and_the_report_lists_it(
    client: TestClient, home: Path, tmp_path: Path
) -> None:
    target = tmp_path / "plan.jpg"
    target.write_bytes(b"\xff\xd8" + b"p" * 200)
    cached = _thumbnail(home, target)

    status = _finish(
        client, {"paths": [str(target)], "confirm": True}
    )

    (trace,) = status["result"]["trace_sweep"]["traces"]
    assert trace["removed"] is True and trace["action"] == "erased"
    assert not cached.exists()
    report = client.post(
        f"/reports/{status['job_id']}", json={"case_id": "", "operator": ""}
    )
    assert report.status_code == 200, report.text
    signed = client.get(report.json()["json_url"]).json()
    section = signed["sections"]["traces"]
    assert section["swept"] is True and section["removed"] == 1
    assert section["items"][0]["path"] == str(cached)
    operations = [entry["operation"] for entry in status["ledger_entries"]]
    assert "erase.file.trace" in operations and "erase.file.traces" in operations


def test_the_sweep_can_be_turned_off(
    client: TestClient, home: Path, tmp_path: Path
) -> None:
    target = tmp_path / "plan.jpg"
    target.write_bytes(b"x" * 10)
    cached = _thumbnail(home, target)

    status = _finish(
        client,
        {
            "paths": [str(target)],
            "confirm": True,
            "sweep_traces": False,
        },
    )

    assert status["result"]["trace_sweep"] is None
    assert cached.exists()
