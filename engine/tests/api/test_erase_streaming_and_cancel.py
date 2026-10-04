"""A drive wipe, seen from the API while it is still running.

Two defects this covers, both of which the demo would have shown a judge:

**The progress bar was a replay.** The helper call was one blocking
request/response, so every phase record arrived at the instant the wipe
finished. ``GET /jobs/{id}`` reported zero progress for the whole run and then
all of it at once, and the SSE stream did the same.

**Cancel did nothing.** ``api/jobs.py`` tests ``cancel_requested`` between
yields; with no yields until the end there was no point at which it could act.
``POST /jobs/{id}/cancel`` returned 200, set a flag nobody read, and the wipe
continued to completion.

The helper here is a double, and it has to be: a test suite must not open a
device. What it reproduces faithfully is the *shape* of the real transport - a
generator that yields records over time and can be closed - because that shape
is the whole of what changed.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Generator, Iterator
from pathlib import Path
from typing import Any

import pytest
from api.deps import AppServices
from api.jobs import JobRegistry
from api.main import create_app
from fastapi.testclient import TestClient

from tests._loopback import LOOPBACK_BASE_URL

from .conftest import FAKE_DEVICES, approve_workflow, open_workflow

PHASES = ("PREFLIGHT", "HIDDEN_AREA_UNLOCK", "ERASE", "VERIFY", "REPORT")


class SlowHelper:
    """A helper whose ``run_erase`` takes measurable time and can be stopped.

    ``records_before_close`` is how far the engine got when it was closed, which
    is what distinguishes a cancellation that reached the device from one that
    only set a flag in the web process.
    """

    def __init__(self, *, records: int = 200, step: float = 0.005) -> None:
        self.records = records
        self.step = step
        self.closed = threading.Event()
        self.first_record_seen = threading.Event()
        self.records_before_close = 0

    def call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "probe_capabilities":
            row = FAKE_DEVICES[0]
            return {"device": row["device"], "capabilities": row["capabilities"]}
        raise KeyError(method)

    def call_stream(
        self, method: str, params: dict[str, Any]
    ) -> Generator[dict[str, Any], None, dict[str, Any]]:
        job_id = str(params.get("job_id", "erase"))
        try:
            for index in range(self.records):
                time.sleep(self.step)
                self.records_before_close = index + 1
                self.first_record_seen.set()
                yield {
                    "job_id": job_id,
                    "phase": PHASES[min(index, len(PHASES) - 1)],
                    "pct_bp": min(10_000, index * 10_000 // self.records),
                    "bytes_done": index * 4096,
                    "bytes_total": self.records * 4096,
                    "throughput_bytes_per_sec": 4096,
                    "eta_seconds": 1,
                    "message": f"record {index}",
                }
            return {"result": {"job_id": job_id}}
        except GeneratorExit:
            self.closed.set()
            raise


@pytest.fixture
def slow_helper() -> SlowHelper:
    return SlowHelper()


@pytest.fixture
def slow_services(slow_helper: SlowHelper, tmp_path: Path) -> AppServices:
    services = AppServices(
        registry=JobRegistry(),
        helper=slow_helper,
        state_dir=tmp_path / "state",
        key_dir=tmp_path / "keys",
    )
    services.prepare()
    return services


@pytest.fixture
def slow_client(slow_services: AppServices) -> Iterator[TestClient]:
    with TestClient(
        create_app(services=slow_services, serve_ui=False),
        base_url=LOOPBACK_BASE_URL,
    ) as client:
        # Every erase is real and gated, so each test's client carries the
        # services it needs to open and approve one.
        client.sanctum_services = slow_services  # type: ignore[attr-defined]
        yield client


def start_erase(client: TestClient) -> str:
    services: AppServices = client.sanctum_services  # type: ignore[attr-defined]
    auth_id = open_workflow(client, services)
    approve_workflow(client, auth_id)
    device = FAKE_DEVICES[0]["device"]
    accepted = client.post(
        "/jobs/erase-drive",
        json={
            "path": device["path"],
            "typed_serial": device["serial"],
            "authorization_id": auth_id,
        },
    )
    assert accepted.status_code == 200, accepted.text
    job_id: str = accepted.json()["job_id"]
    return job_id


def test_progress_is_visible_while_the_wipe_is_still_running(
    slow_client: TestClient, slow_helper: SlowHelper
) -> None:
    """The assertion that separates a live bar from a replay.

    The job is observed in the ``running`` state with progress already counted.
    Under the batched transport this was impossible by construction: the count
    went from zero to final at the moment the state went from running to
    complete.
    """
    job_id = start_erase(slow_client)
    assert slow_helper.first_record_seen.wait(timeout=5.0)

    seen_running_with_progress = False
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        status = slow_client.get(f"/jobs/{job_id}").json()
        if status["state"] == "running" and status["progress_count"] > 0:
            seen_running_with_progress = True
            break
        if status["state"] != "running":
            break
        time.sleep(0.01)

    slow_client.post(f"/jobs/{job_id}/cancel")
    assert seen_running_with_progress, (
        "the job never reported progress while it was running, which is the "
        "batched behaviour: all of it arrives at the end or none of it does"
    )


def test_cancel_stops_the_engine_rather_than_setting_a_flag(
    slow_client: TestClient, slow_helper: SlowHelper
) -> None:
    """Cancel reaches the helper's generator, and the job ends cancelled."""
    job_id = start_erase(slow_client)
    assert slow_helper.first_record_seen.wait(timeout=5.0)

    cancelled = slow_client.post(f"/jobs/{job_id}/cancel")
    assert cancelled.status_code == 200, cancelled.text

    assert slow_helper.closed.wait(timeout=5.0), (
        "the helper's operation was never closed, so a real erase would have "
        "continued to completion with the UI showing it cancelled"
    )
    assert slow_helper.records_before_close < slow_helper.records, (
        "the operation ran to the end anyway"
    )

    deadline = time.monotonic() + 5.0
    state = ""
    while time.monotonic() < deadline:
        state = slow_client.get(f"/jobs/{job_id}").json()["state"]
        if state in {"cancelled", "complete", "failed"}:
            break
        time.sleep(0.01)
    assert state == "cancelled", state


def test_the_stream_reports_the_cancellation_as_its_terminal_state(
    slow_client: TestClient, slow_helper: SlowHelper
) -> None:
    """A consumer must learn *how* a job ended, not watch the socket close."""
    from .test_streaming import parse_events

    job_id = start_erase(slow_client)
    assert slow_helper.first_record_seen.wait(timeout=5.0)

    def cancel_shortly() -> None:
        time.sleep(0.2)
        slow_client.post(f"/jobs/{job_id}/cancel")

    canceller = threading.Thread(target=cancel_shortly, daemon=True)
    canceller.start()
    with slow_client.stream("GET", f"/jobs/{job_id}/stream") as response:
        body = "".join(response.iter_text())
    canceller.join(timeout=5.0)

    events = parse_events(body)
    assert events[-1][0] == "state"
    assert events[-1][1]["state"] == "cancelled", events[-1][1]
    assert [name for name, _ in events].count("progress") > 0
