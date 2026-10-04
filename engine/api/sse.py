"""Server-sent events: stream job progress to the UI without blocking.

SSE rather than a WebSocket because the traffic is one-directional and SSE
reconnects on its own: a browser that loses the connection reissues the request
without any client code, which is exactly the page-reload behaviour the UI
needs. A WebSocket would need reconnection logic written by hand and would buy
nothing, since the browser never sends anything back on this channel.

The wire format is the SSE default with named events:

* ``event: progress`` - one :class:`~core.models.Progress` as JSON.
* ``event: state`` - the job's terminal state and its result or error.
* ``event: ping`` - a keepalive, so a proxy or a browser does not time out a
  quiet stream during a long sequential read that yields infrequently.

Every stream ends with a ``state`` event, so a consumer always learns *how* a
job finished rather than watching the socket close and having to guess.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:  # pragma: no cover - import cycle only matters to the checker
    from api.jobs import JobRegistry

__all__ = ["progress_events", "format_event", "SSE_HEADERS", "PING_SECONDS"]

logger = structlog.get_logger(__name__)

#: Sent when a job produces nothing for this long. A sequential read of a slow
#: disk can be quiet for minutes, and an idle connection is one a proxy will
#: close.
PING_SECONDS = 15.0

#: Headers every SSE response carries. ``X-Accel-Buffering`` disables buffering
#: in nginx, which would otherwise hold events until its buffer filled and make
#: a live progress bar arrive in bursts.
SSE_HEADERS = {
    "Cache-Control": "no-cache, no-transform",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no",
}


def format_event(event: str, data: dict[str, Any]) -> bytes:
    """Frame one SSE event.

    ``json.dumps`` cannot emit a raw newline inside a string, so the single
    ``data:`` line is always well formed. A multi-line payload would need one
    ``data:`` prefix per line and is deliberately not produced.
    """
    payload = json.dumps(data, separators=(",", ":"))
    return f"event: {event}\ndata: {payload}\n\n".encode()


async def progress_events(
    registry: JobRegistry, job_id: str
) -> AsyncIterator[bytes]:
    """Yield SSE-framed progress for ``job_id`` until the job ends.

    The registry's iterator is synchronous and blocking, so it is drained on a
    worker thread and handed over a queue. Iterating it directly would block
    the event loop and stall every other request for the duration of a wipe.
    """
    import asyncio
    import queue as queue_mod
    import threading

    loop = asyncio.get_running_loop()
    handoff: queue_mod.SimpleQueue[Any] = queue_mod.SimpleQueue()
    _SENTINEL = object()

    def pump() -> None:
        try:
            for progress in registry.subscribe(job_id):
                handoff.put(progress)
        except KeyError:
            handoff.put(KeyError(job_id))
        except Exception as exc:  # noqa: BLE001 - forwarded, never swallowed
            handoff.put(exc)
        finally:
            handoff.put(_SENTINEL)

    thread = threading.Thread(target=pump, name=f"sse-{job_id}", daemon=True)
    thread.start()

    try:
        while True:
            try:
                item = await loop.run_in_executor(
                    None, lambda: handoff.get(timeout=PING_SECONDS)
                )
            except queue_mod.Empty:
                yield format_event("ping", {"job_id": job_id})
                continue
            if item is _SENTINEL:
                break
            if isinstance(item, BaseException):
                yield format_event(
                    "state",
                    {"job_id": job_id, "state": "failed", "error": str(item)},
                )
                return
            yield format_event("progress", item.model_dump(mode="json"))
    finally:
        # The terminal event is emitted even when the client disconnected, so
        # the code path is identical either way; the write simply goes nowhere.
        try:
            status = registry.status(job_id)
        except KeyError:
            status = {"job_id": job_id, "state": "unknown"}
        yield format_event("state", status)
