"""In-process registry of background jobs.

A job wraps a core generator - erase, file erase, acquire, carve - and fans its
:class:`~core.models.Progress` records out to SSE consumers. **No blocking call
ever runs in request context**: the generator is driven on a worker thread and
the request handler only ever reads from a queue.

Two properties the UI depends on, and how they are obtained:

**A job survives a page reload.** Progress is appended to a per-job buffer as
it is produced, and a subscriber that arrives late is replayed the whole buffer
before it starts receiving live records. So a browser that reconnects to
``/jobs/{id}/stream`` after a refresh sees the run from its beginning, not from
whenever it happened to reconnect. The buffer is bounded; past the bound the
replay is truncated and says so, because an unbounded buffer on a
multi-terabyte wipe is a memory leak with a progress bar.

**The authoritative record is the ledger, not this registry.** The buffer is a
convenience for a live view. :meth:`JobRegistry.status` reports what the
registry knows; a caller that needs to prove what happened reads the
hash-chained ledger, which is written by the core layers themselves and
survives this process exiting. That separation is why a reload can be answered
from memory while an audit cannot.

Cancellation is cooperative. A generator is asked to stop at its next yield by
closing it; nothing here kills a thread mid-write, because a wipe interrupted
between an lseek and a write is exactly the state the checkpoint machinery
exists to avoid.
"""

from __future__ import annotations

import queue
import threading
import traceback
import uuid
from collections.abc import Callable, Generator, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

import structlog
from core.models import Progress
from helper.rpc import RpcError

__all__ = ["JobRegistry", "JobRecord", "JobState", "MAX_BUFFERED_PROGRESS"]

logger = structlog.get_logger(__name__)

#: Progress records kept per job for replay after a reconnect. A 4 TB wipe
#: yields one record per megabyte written, so an unbounded buffer would be a
#: memory leak. Past this the replay is truncated and the truncation is
#: reported rather than hidden.
MAX_BUFFERED_PROGRESS = 4096

JobState = Literal["pending", "running", "complete", "failed", "cancelled"]

#: What a job's generator yields and finally returns.
JobFactory = Callable[[], Generator[Progress, None, Any]]


@dataclass
class JobRecord:
    """Everything the registry knows about one job."""

    job_id: str
    kind: str
    state: JobState = "pending"
    params: dict[str, Any] = field(default_factory=dict)
    progress: list[Progress] = field(default_factory=list)
    #: Records dropped from the head of the buffer, so a replay can say so.
    dropped: int = 0
    result: Any = None
    error: str | None = None
    error_kind: str | None = None
    remediation: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    #: Set when a caller asked for cancellation. The generator stops at its
    #: next yield rather than being killed mid-operation.
    cancel_requested: bool = False
    #: The trusted actor string, resolved server-side from the privileged
    #: helper (:mod:`api.identity`). Never taken from a request body.
    actor: str = "sanctum"
    #: How that actor was established, as a sentence.
    actor_basis: str = ""
    #: Set once the job is terminal **and** its outcome has been handed to
    #: :attr:`JobRegistry.on_finish`. ``state`` becomes terminal a moment
    #: earlier, inside the worker loop; a caller that reads the ledger as soon
    #: as it sees ``complete`` would otherwise race the ``job.outcome`` append.
    settled: threading.Event = field(default_factory=threading.Event)

    @property
    def terminal(self) -> bool:
        return self.state in {"complete", "failed", "cancelled"}

    def as_dict(self) -> dict[str, Any]:
        """The JSON shape the API returns for ``GET /jobs/{id}``."""
        return {
            "job_id": self.job_id,
            "kind": self.kind,
            "state": self.state,
            # Terminal *and* written to the chain. `state` flips a moment
            # earlier, inside the worker loop, so a client that asked for a
            # report the instant it saw "complete" could beat the job.outcome
            # append and be told the job is unknown. Seen on the Windows CI
            # runner, where that window is wide enough to lose.
            "settled": self.settled.is_set(),
            "params": _redact(self.params),
            "progress_count": len(self.progress),
            "dropped_progress": self.dropped,
            "latest": (
                self.progress[-1].model_dump(mode="json") if self.progress else None
            ),
            "result": _jsonable(self.result),
            "error": self.error,
            "error_kind": self.error_kind,
            "remediation": self.remediation,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "cancel_requested": self.cancel_requested,
            "actor": self.actor,
            "actor_basis": self.actor_basis,
        }


#: Parameters never echoed to a client. The authorization binding repeats the
#: device serial and names the backup image and state directory; it exists for
#: the helper, not for a screen.
_REDACTED_PARAMS = frozenset({"typed_serial", "authorization", "authorization_dir"})


def _redact(params: dict[str, Any]) -> dict[str, Any]:
    """Drop the typed serial from an echoed parameter set.

    It is a confirmation token, not a fact worth repeating. Echoing it back
    into a UI that may be screen-shared, or into a browser cache, spreads the
    one string that authorises a destructive operation.
    """
    return {
        key: ("<redacted>" if key in _REDACTED_PARAMS else value)
        for key, value in params.items()
    }


def _jsonable(value: Any) -> Any:
    """Best-effort JSON shape for a pydantic model or a plain value."""
    if value is None:
        return None
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        return dump(mode="json")
    if isinstance(value, (str, int, float, bool, list, dict)):
        return value
    return str(value)


class _Subscriber:
    """One SSE consumer's queue, fed by the job thread."""

    def __init__(self) -> None:
        self.queue: queue.SimpleQueue[Progress | None] = queue.SimpleQueue()


class JobRegistry:
    """Tracks running jobs and fans their progress out to subscribers."""

    def __init__(self, *, max_buffered: int = MAX_BUFFERED_PROGRESS) -> None:
        self._jobs: dict[str, JobRecord] = {}
        self._subscribers: dict[str, list[_Subscriber]] = {}
        self._generators: dict[str, Generator[Progress, None, Any]] = {}
        self._lock = threading.RLock()
        self._max_buffered = max_buffered
        #: Called with the record once a job reaches a terminal state, on the
        #: worker thread. :func:`api.deps.AppServices.prepare` sets it to the
        #: durable-outcome writer, which is what lets a report survive a
        #: restart; a registry with none simply keeps everything in memory, as
        #: this class always did. A raising callback never fails the job - see
        #: :meth:`_run`.
        self.on_finish: Callable[[JobRecord], None] | None = None

    # -- submission --------------------------------------------------------

    def submit(
        self,
        kind: str,
        params: dict[str, Any],
        factory: JobFactory,
        *,
        job_id: str | None = None,
        actor: str = "sanctum",
        actor_basis: str = "",
    ) -> str:
        """Start a job of ``kind`` on a worker thread and return its id.

        Returns as soon as the thread is started. The caller is a request
        handler and must not wait for a wipe.
        """
        identifier = job_id or f"{kind}-{uuid.uuid4().hex[:12]}"
        with self._lock:
            if identifier in self._jobs:
                raise KeyError(f"job {identifier} already exists")
            record = JobRecord(
                job_id=identifier,
                kind=kind,
                params=dict(params),
                actor=actor,
                actor_basis=actor_basis,
            )
            self._jobs[identifier] = record
            self._subscribers[identifier] = []

        thread = threading.Thread(
            target=self._run,
            args=(identifier, factory),
            name=f"sanctum-job-{identifier}",
            daemon=True,
        )
        thread.start()
        logger.info("job_submitted", job_id=identifier, kind=kind)
        return identifier

    def _run(self, job_id: str, factory: JobFactory) -> None:
        """Drive one job's generator to completion on a worker thread."""
        record = self._jobs[job_id]
        record.state = "running"
        try:
            generator = factory()
            with self._lock:
                self._generators[job_id] = generator
            while True:
                if record.cancel_requested:
                    generator.close()
                    record.state = "cancelled"
                    break
                try:
                    progress = next(generator)
                except StopIteration as stop:
                    record.result = stop.value
                    record.state = "complete"
                    break
                self._publish(job_id, progress)
        except BaseException as exc:  # noqa: BLE001 - recorded, never swallowed
            # Deliberately broad, and deliberately not re-raised: this is the
            # top of a worker thread, so an exception that escaped would be
            # printed to stderr by the threading module and lost. The record is
            # the only place a caller can learn the job failed.
            record.state = "failed"
            record.error = str(exc)
            # A helper error crosses the boundary as RpcError; its ``kind`` is
            # the core exception it was raised as, which is what a caller
            # branches on (a write-seam refusal is not a failed erase).
            record.error_kind = (
                exc.kind
                if isinstance(exc, RpcError) and exc.kind
                else type(exc).__name__
            )
            record.remediation = str(getattr(exc, "remediation", "") or "")
            logger.warning(
                "job_failed",
                job_id=job_id,
                kind=record.kind,
                error=str(exc),
                traceback=traceback.format_exc(limit=4),
            )
        finally:
            record.finished_at = datetime.now(UTC)
            with self._lock:
                self._generators.pop(job_id, None)
                for subscriber in self._subscribers.get(job_id, []):
                    subscriber.queue.put(None)
            logger.info("job_finished", job_id=job_id, state=record.state)
            # After the subscribers are released, so a slow durable write never
            # holds an SSE stream open past the end of the run, and inside the
            # finally so a failed job is recorded exactly like a complete one.
            callback = self.on_finish
            if callback is not None:
                try:
                    callback(record)
                except Exception as exc:  # noqa: BLE001 - never fail a job
                    logger.warning(
                        "job_on_finish_failed",
                        job_id=job_id,
                        error=str(exc),
                        kind=type(exc).__name__,
                    )
            record.settled.set()

    def _publish(self, job_id: str, progress: Progress) -> None:
        """Buffer one record and hand it to every live subscriber."""
        with self._lock:
            record = self._jobs[job_id]
            record.progress.append(progress)
            if len(record.progress) > self._max_buffered:
                overflow = len(record.progress) - self._max_buffered
                del record.progress[:overflow]
                record.dropped += overflow
            for subscriber in self._subscribers.get(job_id, []):
                subscriber.queue.put(progress)

    # -- inspection --------------------------------------------------------

    def status(self, job_id: str) -> dict[str, Any]:
        """Return the current status record for ``job_id``.

        Raises:
            KeyError: no such job.
        """
        with self._lock:
            record = self._jobs.get(job_id)
        if record is None:
            raise KeyError(job_id)
        return record.as_dict()

    def record(self, job_id: str) -> JobRecord:
        with self._lock:
            record = self._jobs.get(job_id)
        if record is None:
            raise KeyError(job_id)
        return record

    def ids(self) -> list[str]:
        with self._lock:
            return list(self._jobs)

    def wait(self, job_id: str, timeout: float = 30.0) -> JobRecord:
        """Block until a job reaches a terminal state. For tests and the CLI.

        Never called from a request handler; the API streams instead.
        """
        record = self.record(job_id)
        # Waits for the outcome to be recorded, not only for the state to
        # flip: see JobRecord.settled.
        record.settled.wait(timeout)
        return record

    # -- streaming ---------------------------------------------------------

    def subscribe(self, job_id: str) -> Iterator[Progress]:
        """Replay this job's buffered progress, then follow it live.

        The replay is what makes a page reload survivable: a browser that
        reconnects sees the run from its beginning rather than from the moment
        it happened to reattach. A job that has already finished yields its
        whole buffer and then stops, so a late subscriber still gets the full
        history instead of an empty stream.
        """
        with self._lock:
            record = self._jobs.get(job_id)
            if record is None:
                raise KeyError(job_id)
            backlog = list(record.progress)
            subscriber = _Subscriber()
            if not record.terminal:
                self._subscribers[job_id].append(subscriber)
            already_finished = record.terminal

        try:
            yield from backlog
            if already_finished:
                return
            while True:
                item = subscriber.queue.get()
                if item is None:
                    return
                # Records produced between the backlog snapshot and the
                # subscription would otherwise be sent twice. Progress is
                # monotonic in bytes_done, so a record no further along than
                # the last replayed one is a duplicate.
                if backlog and item.bytes_done < backlog[-1].bytes_done:
                    continue
                yield item
        finally:
            with self._lock:
                subscribers = self._subscribers.get(job_id, [])
                if subscriber in subscribers:
                    subscribers.remove(subscriber)

    # -- cancellation ------------------------------------------------------

    def cancel(self, job_id: str) -> dict[str, Any]:
        """Request cancellation of ``job_id``.

        Cooperative: the generator is asked to stop at its next yield. Nothing
        here kills a thread mid-write, because a wipe interrupted between an
        lseek and a write is the state the checkpoint machinery exists to
        recover from, not one to create deliberately.
        """
        with self._lock:
            record = self._jobs.get(job_id)
        if record is None:
            raise KeyError(job_id)
        if record.terminal:
            return record.as_dict()
        record.cancel_requested = True
        logger.info("job_cancel_requested", job_id=job_id)
        return record.as_dict()
