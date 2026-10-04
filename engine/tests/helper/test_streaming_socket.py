"""The helper socket under a long operation: liveness, streaming, cancellation.

Three properties, all of them things the product got wrong before:

**A long operation is not a failed one.** The client used to apply
``READ_TIMEOUT_SECONDS`` - thirty seconds - to the *completion* of a request,
while the helper did not reply until the whole erase had finished. Every real
wipe therefore raised ``TimeoutError`` in the client, the API marked the job
failed, and the root helper carried on erasing the device. The tool said the
operation failed and it had not. The deadline is now on silence.

**Progress arrives while the operation runs**, one frame per record, so a
progress bar is a live view rather than a replay.

**Cancellation reaches the engine.** Closing the client generator sends a
cancel frame on the connection the operation is running on; the daemon notices
it between records and closes the engine's generator, which stops at its next
yield and never mid-write.

The timing constants are scaled down by monkeypatch rather than waited out. The
old deadline was thirty seconds and the assertion that matters is *ran longer
than the deadline and still succeeded*, which is the same statement at 0.3 s as
at 30 s and does not cost the suite half a minute to make.
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from helper.daemon import (
    OPERATIONS,
    STREAMING_OPERATIONS,
    HelperClient,
    HelperDaemon,
    InProcessHelper,
)

from helper import rpc

# How long the fake engine runs, and how often it speaks. Every test below is
# bounded by these, so the whole module costs a few seconds.
STEP_SECONDS = 0.02
FAST_DEADLINE = 0.3


pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason=(
        "the helper daemon serves a Unix socket and authenticates every peer "
        "with SO_PEERCRED, which is Linux-only; helper/__main__.py refuses to "
        "start elsewhere rather than serve unauthenticated. The in-process "
        "helper is covered on every platform."
    ),
)


@contextmanager
def running_daemon(socket_path: Path) -> Iterator[HelperDaemon]:
    """A daemon serving on ``socket_path`` for the body of the block."""
    daemon = HelperDaemon(operator_uid=os.getuid(), socket_path=str(socket_path))
    daemon.bind()
    thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    thread.start()
    try:
        yield daemon
    finally:
        daemon.stop()
        daemon.close()
        # Nudge the accept() the daemon is parked in, so the thread can see the
        # stop flag rather than being left behind for the whole session.
        thread.join(timeout=1.0)


class FakeEngine:
    """A streaming operation whose duration and chattiness the test picks."""

    def __init__(self) -> None:
        self.started = threading.Event()
        self.closed = threading.Event()
        self.records_emitted = 0

    def handler(
        self, params: dict[str, Any]
    ) -> Generator[dict[str, Any], None, dict[str, Any]]:
        records = int(params.get("records", 1))
        step = float(params.get("step", STEP_SECONDS))
        quiet_first = float(params.get("quiet_first", 0.0))
        self.started.set()
        try:
            time.sleep(quiet_first)
            for index in range(records):
                time.sleep(step)
                self.records_emitted = index + 1
                yield {"index": index, "message": f"record {index}"}
            return {"finished": True, "records": records}
        except GeneratorExit:
            # What ``core.erase.drive.execute`` uses to record that the device
            # is partially sanitized. Here it only has to prove the close
            # reached the engine at all.
            self.closed.set()
            raise


@pytest.fixture
def engine(monkeypatch: pytest.MonkeyPatch) -> FakeEngine:
    """Register a fake streaming operation in both allowlists.

    Both, because the tables are one allowlist expressed twice and a name in
    ``STREAMING_OPERATIONS`` that is not in ``OPERATIONS`` would be a method the
    socket serves and the batch path does not know about.
    """
    fake = FakeEngine()
    monkeypatch.setitem(STREAMING_OPERATIONS, "fake_engine", fake.handler)
    monkeypatch.setitem(OPERATIONS, "fake_engine", lambda params: {"batched": True})
    return fake


# --------------------------------------------------------------------------
# The thirty-second bug
# --------------------------------------------------------------------------


def test_an_operation_longer_than_the_old_deadline_completes_and_says_so(
    short_socket_dir: Path, engine: FakeEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The single most important assertion in this file.

    An operation that runs for many multiples of the old wall-clock deadline
    now returns its result, and the result says it finished. Before, the client
    raised ``TimeoutError`` at the deadline, ``api/jobs.py`` recorded the job as
    **failed**, and the helper kept erasing the device - the tool reporting a
    failure that had not happened, about a drive it was still wiping.
    """
    monkeypatch.setattr("helper.daemon.READ_TIMEOUT_SECONDS", FAST_DEADLINE)
    socket_path = short_socket_dir / "h.sock"

    with running_daemon(socket_path):
        client = HelperClient(str(socket_path), idle_timeout=FAST_DEADLINE)
        started = time.monotonic()
        stream = client.call_stream("fake_engine", {"records": 60, "step": 0.02})
        records, result = _drain(stream)
        elapsed = time.monotonic() - started

    assert elapsed > FAST_DEADLINE, (
        f"the operation finished in {elapsed:.2f}s, which is inside the old "
        f"{FAST_DEADLINE}s deadline; this test proves nothing unless it runs "
        "past it"
    )
    assert len(records) == 60
    assert result == {"finished": True, "records": 60}


def test_progress_arrives_while_the_operation_is_still_running(
    short_socket_dir: Path, engine: FakeEngine
) -> None:
    """A live bar, not a replay. The engine is still going when we see record 1."""
    socket_path = short_socket_dir / "h.sock"

    with running_daemon(socket_path):
        client = HelperClient(str(socket_path), idle_timeout=5.0)
        stream = client.call_stream("fake_engine", {"records": 40, "step": 0.02})
        first = next(stream)
        emitted_when_first_seen = engine.records_emitted
        stream.close()

    assert first["index"] == 0
    assert emitted_when_first_seen < 40, (
        "the first progress record only reached the client after the engine had "
        "produced all forty, which is the batched behaviour this replaced"
    )


def test_a_quiet_phase_is_kept_alive_by_heartbeats_not_failed(
    short_socket_dir: Path, engine: FakeEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Whole phases yield nothing, and none of them is a hung helper.

    A sampled verify of a multi-terabyte disk is quiet for minutes. If silence
    from the *engine* failed the call, the fix for the thirty-second bug would
    be the thirty-second bug with a larger number.
    """
    monkeypatch.setattr("helper.daemon.HEARTBEAT_SECONDS", 0.05)
    socket_path = short_socket_dir / "h.sock"

    with running_daemon(socket_path):
        client = HelperClient(str(socket_path), idle_timeout=FAST_DEADLINE)
        stream = client.call_stream(
            # Silent for four times the client's whole deadline, then finishes.
            "fake_engine",
            {"records": 1, "step": 0.01, "quiet_first": FAST_DEADLINE * 4},
        )
        records, result = _drain(stream)

    assert records == [{"index": 0, "message": "record 0"}]
    assert result["finished"] is True


def test_a_helper_that_stops_speaking_is_still_detected(short_socket_dir: Path) -> None:
    """The deadline removal must not make a dead helper look like a slow one.

    Nothing is served here at all: a socket that accepts and then says nothing
    is exactly what a wedged daemon looks like from the client's side, and the
    client has to give up on it rather than wait for a wipe that is not running.
    """
    socket_path = short_socket_dir / "h.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    server.listen(1)
    accepted: list[socket.socket] = []

    def swallow() -> None:
        conn, _ = server.accept()
        accepted.append(conn)  # held open, never answered

    thread = threading.Thread(target=swallow, daemon=True)
    thread.start()
    try:
        client = HelperClient(str(socket_path), idle_timeout=0.2)
        with pytest.raises(TimeoutError) as raised:
            list(client.call_stream("fake_engine", {}))
        assert "stopped speaking" in str(raised.value)
        assert "may still be running" in str(raised.value), (
            "the message must not let an operator conclude the device is idle"
        )
    finally:
        for conn in accepted:
            conn.close()
        server.close()
        thread.join(timeout=1.0)


# --------------------------------------------------------------------------
# Cancellation
# --------------------------------------------------------------------------


def test_closing_the_client_stream_stops_the_engine(
    short_socket_dir: Path, engine: FakeEngine
) -> None:
    """Cancel reaches across the socket, or the button on the screen lies."""
    socket_path = short_socket_dir / "h.sock"

    with running_daemon(socket_path):
        client = HelperClient(str(socket_path), idle_timeout=5.0)
        stream = client.call_stream("fake_engine", {"records": 500, "step": 0.01})
        next(stream)
        stream.close()
        stopped = engine.closed.wait(timeout=5.0)

    assert stopped, "the engine kept running after the client cancelled"
    assert engine.records_emitted < 500


def test_a_client_that_disappears_stops_the_engine_too(
    short_socket_dir: Path, engine: FakeEngine
) -> None:
    """A caller that will never read the answer is not a reason to keep wiping."""
    socket_path = short_socket_dir / "h.sock"

    with running_daemon(socket_path):
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(5.0)
        conn.connect(str(socket_path))
        conn.sendall(
            rpc.encode_request("fake_engine", {"records": 500, "step": 0.01}, req_id=1)
        )
        assert engine.started.wait(timeout=5.0)
        conn.recv(65536)  # let at least one frame be written before leaving
        conn.close()
        stopped = engine.closed.wait(timeout=5.0)

    assert stopped, "the engine kept running for a client that had gone away"


# --------------------------------------------------------------------------
# The batch path still exists, and still agrees
# --------------------------------------------------------------------------


def test_a_non_streaming_call_still_gets_one_answer(
    short_socket_dir: Path, engine: FakeEngine
) -> None:
    """``call`` discards progress and returns the result, as it always did."""
    socket_path = short_socket_dir / "h.sock"

    with running_daemon(socket_path):
        client = HelperClient(str(socket_path), idle_timeout=5.0)
        answer = client.call("fake_engine", {"records": 3, "step": 0.01})

    assert answer == {"finished": True, "records": 3}


def test_the_in_process_helper_streams_and_stops_the_engine_too(
    engine: FakeEngine,
) -> None:
    """The transport with no socket has to behave the same, or the demo lies.

    ``InProcessHelper`` is what a box with no ``SANCTUM_HELPER_SOCKET`` gets -
    the developer default and the container - so if cancellation only worked
    over the socket, the Cancel button would be real in one configuration and
    decorative in the other, with nothing on screen to tell them apart.
    """
    helper = InProcessHelper()
    stream = helper.call_stream("fake_engine", {"records": 500, "step": 0.001})

    first = next(stream)
    stream.close()

    assert first["index"] == 0
    assert engine.closed.is_set(), "closing the stream did not reach the engine"
    assert engine.records_emitted < 500


def _drain(
    stream: Generator[dict[str, Any], None, dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run a client stream to completion: every record, then its result."""
    records: list[dict[str, Any]] = []
    while True:
        try:
            records.append(next(stream))
        except StopIteration as stop:
            return records, stop.value
