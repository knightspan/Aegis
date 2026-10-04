"""SSE: the stream yields Progress, terminates, and survives a reconnect.

The reconnect test is the one that matters. A page reload during a four-hour
wipe must not leave the operator staring at an empty progress bar wondering
whether the job is still running, and the only way to be sure it does not is to
disconnect mid-stream and reattach.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from api.jobs import JobRegistry
from api.sse import format_event
from core.models import Progress
from fastapi.testclient import TestClient
from helper.rpc import RpcError


def _confirmed(target: Path) -> dict[str, object]:
    """A confirmed erase of one scratch file; every erase is real."""
    return {"paths": [str(target)], "confirm": True, "sweep_traces": False}



def parse_events(payload: str) -> list[tuple[str, dict[str, Any]]]:
    """Parse an SSE body into ``(event, data)`` pairs."""
    events: list[tuple[str, dict[str, Any]]] = []
    for block in payload.split("\n\n"):
        name = ""
        data = ""
        for line in block.splitlines():
            if line.startswith("event: "):
                name = line[len("event: ") :]
            elif line.startswith("data: "):
                data = line[len("data: ") :]
        if name and data:
            events.append((name, json.loads(data)))
    return events


def _progress(job_id: str, index: int, total: int) -> Progress:
    return Progress(
        job_id=job_id,
        phase="ERASE",
        pct_bp=10_000 * index // total,
        bytes_done=index * 1024,
        bytes_total=total * 1024,
        throughput_bytes_per_sec=1024,
        eta_seconds=total - index,
        message=f"record {index}",
    )


# --------------------------------------------------------------------------
# The registry's fan-out
# --------------------------------------------------------------------------


def test_a_subscriber_replays_the_backlog_then_follows_live() -> None:
    """What makes a page reload survivable, tested without a browser."""
    registry = JobRegistry()
    released = False

    def factory() -> Any:
        def generator() -> Any:
            for index in range(1, 4):
                yield _progress("j", index, 6)
            while not released:
                time.sleep(0.01)
            for index in range(4, 7):
                yield _progress("j", index, 6)
            return {"done": True}

        return generator()

    job_id = registry.submit("test", {}, factory)

    # Wait for the first three to be buffered, then subscribe late.
    for _ in range(200):
        if len(registry.record(job_id).progress) >= 3:
            break
        time.sleep(0.01)

    stream = registry.subscribe(job_id)
    backlog = [next(stream) for _ in range(3)]
    assert [item.message for item in backlog] == [
        "record 1",
        "record 2",
        "record 3",
    ], "a late subscriber must be replayed the run from its beginning"

    released = True
    rest = list(stream)
    assert [item.message for item in rest][-3:] == [
        "record 4",
        "record 5",
        "record 6",
    ]


def test_a_subscriber_to_a_finished_job_still_gets_the_whole_history() -> None:
    """Reconnecting after the job ended must not yield an empty stream."""
    registry = JobRegistry()

    def factory() -> Any:
        def generator() -> Any:
            for index in range(1, 4):
                yield _progress("j", index, 3)
            return {"done": True}

        return generator()

    job_id = registry.submit("test", {}, factory)
    record = registry.wait(job_id, timeout=5)
    assert record.state == "complete"

    replayed = list(registry.subscribe(job_id))
    assert [item.message for item in replayed] == [
        "record 1",
        "record 2",
        "record 3",
    ]


def test_a_failing_job_is_recorded_rather_than_lost() -> None:
    """An exception at the top of a worker thread would otherwise vanish."""
    registry = JobRegistry()

    def factory() -> Any:
        def generator() -> Any:
            yield _progress("j", 1, 2)
            raise RuntimeError("the drive went away")

        return generator()

    job_id = registry.submit("test", {}, factory)
    record = registry.wait(job_id, timeout=5)

    assert record.state == "failed"
    assert record.error == "the drive went away"
    assert record.error_kind == "RuntimeError"


def test_a_helper_error_keeps_the_kind_it_was_raised_as() -> None:
    """Not "RpcError": the transport wrapper says nothing a caller can act on.

    A write-seam refusal and a failed erase both arrive as RpcError, and the
    Sanitize screen tells them apart by this field.
    """
    registry = JobRegistry()
    kinds = {}
    for kind in ("WorkflowGateRefused", ""):

        def factory(kind: str = kind) -> Any:
            def generator() -> Any:
                yield _progress("j", 1, 2)
                raise RpcError("refused", remediation="open a new one", kind=kind)

            return generator()

        record = registry.wait(registry.submit("test", {}, factory), timeout=5)
        assert record.state == "failed"
        assert record.remediation == "open a new one"
        kinds[kind] = record.error_kind
    assert kinds == {"WorkflowGateRefused": "WorkflowGateRefused", "": "RpcError"}


def test_the_progress_buffer_is_bounded_and_says_when_it_truncated() -> None:
    """An unbounded buffer on a 4 TB wipe is a memory leak with a progress bar."""
    registry = JobRegistry(max_buffered=10)

    def factory() -> Any:
        def generator() -> Any:
            for index in range(1, 51):
                yield _progress("j", index, 50)
            return None

        return generator()

    job_id = registry.submit("test", {}, factory)
    record = registry.wait(job_id, timeout=5)

    assert len(record.progress) == 10
    assert record.dropped == 40
    assert record.as_dict()["dropped_progress"] == 40


def test_cancellation_is_cooperative_not_a_kill() -> None:
    registry = JobRegistry()
    entered = False

    def factory() -> Any:
        def generator() -> Any:
            nonlocal entered
            entered = True
            for index in range(1, 1000):
                yield _progress("j", index, 1000)
                time.sleep(0.005)
            return None

        return generator()

    job_id = registry.submit("test", {}, factory)
    for _ in range(200):
        if entered and registry.record(job_id).progress:
            break
        time.sleep(0.01)

    registry.cancel(job_id)
    record = registry.wait(job_id, timeout=5)
    assert record.state == "cancelled"


# --------------------------------------------------------------------------
# The wire format
# --------------------------------------------------------------------------


def test_an_event_is_one_data_line_so_a_client_never_has_to_reassemble() -> None:
    framed = format_event("progress", {"message": "line one\nline two"})
    body = framed.decode()

    assert body.startswith("event: progress\ndata: ")
    assert body.endswith("\n\n")
    assert body.count("data:") == 1, (
        "json.dumps escapes newlines, so a payload is always one data line"
    )


# --------------------------------------------------------------------------
# Over HTTP
# --------------------------------------------------------------------------


def test_the_stream_yields_progress_and_terminates_with_a_state_event(
    client: TestClient, tmp_path: Path
) -> None:
    target = tmp_path / "f.bin"
    target.write_bytes(b"x" * 4096)
    accepted = client.post("/jobs/erase-files", json=_confirmed(target)).json()

    with client.stream("GET", f"/jobs/{accepted['job_id']}/stream") as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        body = "".join(response.iter_text())

    events = parse_events(body)
    assert events, "the stream produced nothing"
    assert any(name == "progress" for name, _ in events)

    # Every stream ends with a state event, so a consumer always learns *how* a
    # job finished rather than watching the socket close and having to guess.
    assert events[-1][0] == "state"
    assert events[-1][1]["state"] in {"complete", "failed", "cancelled"}


def test_reconnecting_after_a_disconnect_replays_the_whole_run(
    client: TestClient, tmp_path: Path
) -> None:
    """The page-reload case, simulated by closing the stream and reopening it."""
    target = tmp_path / "f.bin"
    target.write_bytes(b"y" * 8192)
    accepted = client.post("/jobs/erase-files", json=_confirmed(target)).json()
    job_id = accepted["job_id"]

    # First connection: read one chunk, then abandon it mid-stream.
    with client.stream("GET", f"/jobs/{job_id}/stream") as response:
        for _ in response.iter_text():
            break

    for _ in range(300):
        if client.get(f"/jobs/{job_id}").json()["state"] == "complete":
            break
        time.sleep(0.02)

    # Second connection: the browser reloaded and reattached by job_id.
    with client.stream("GET", f"/jobs/{job_id}/stream") as response:
        body = "".join(response.iter_text())

    events = parse_events(body)
    progress = [data for name, data in events if name == "progress"]
    assert progress, "the reconnect saw none of the run it missed"
    assert events[-1][0] == "state"
    assert events[-1][1]["state"] == "complete"


def test_streaming_an_unknown_job_is_refused_cleanly(client: TestClient) -> None:
    answer = client.get("/jobs/nope/stream")
    assert answer.status_code in {409, 410}
    assert "remediation" in answer.json()["detail"]
