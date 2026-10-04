"""Durable job outcomes, so a report survives the process that produced it.

The problem this solves
-----------------------
:class:`api.jobs.JobRegistry` is an in-memory map. It is the right place for a
live progress buffer and the wrong place for the only copy of a result: a
restart used to take every finished job's result with it, and
``POST /reports/{job_id}`` then had nothing to build a report from even though
the chain still held every entry the run wrote. The refusal was honest - a
report assembled from nothing would have been signed and empty - but the
information was not actually gone, only unreachable.

What is added
-------------
One more kind of ledger entry, :data:`JOB_OUTCOME`, appended when a job reaches
a terminal state. Its params carry the job's identity and final state and its
result carries the job's own result object, which the chain stores in the
content-addressed blob store exactly as it stores every other result. So the
authoritative record is still the ledger - there is no second database, no
sidecar file and no competing source of truth - and a restarted process can
rebuild the same status dict the registry would have returned.

Precedence is deliberate and stated in one place, :func:`status_for`: if the
registry has the job, the registry wins. It is the live object and it is a
superset - it holds progress records the chain never carries. The chain is the
fallback, and it is also the thing an examiner is asked to trust, which is why
the fallback is not a cache of the registry but a read of the same file the
report's own ledger excerpt is drawn from.

What a reconstructed status cannot have
---------------------------------------
Progress records. The registry buffers them for replay to a browser and the
chain does not carry them, because a 4 TB wipe yields one per megabyte and a
hash chain is not a log shipper. A reconstructed status therefore reports
``progress_count`` 0 and a null ``latest``, and says so through
``reconstructed``. A caller that renders a progress bar from it will correctly
render nothing; a caller that builds a report from it gets the same result the
original process had.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:  # pragma: no cover - import cycle avoidance only
    from core.ledger.chain import Ledger

    from api.deps import AppServices
    from api.jobs import JobRecord

__all__ = [
    "JOB_OUTCOME",
    "record_outcome",
    "reconstruct_status",
    "status_for",
    "durable_job_ids",
]

logger = structlog.get_logger(__name__)

#: The ledger operation that carries a finished job's result.
#:
#: A new kind rather than a reuse, for the same reason ``report.generated`` is:
#: the engines' own entries describe *what they did to the medium*, one per
#: phase, and none of them carries the assembled result object the report
#: builders take. ``carve.complete`` comes closest and deliberately carries only
#: a digest of the candidate list, not the list.
JOB_OUTCOME = "job.outcome"


def record_outcome(ledger: Ledger, record: JobRecord) -> None:
    """Append the entry that makes ``record``'s result outlive this process.

    Called from the registry's worker thread once the job is terminal. A
    failure here is logged and swallowed: the job itself already happened, its
    engine already wrote its own chain entries, and turning a bookkeeping
    failure into a lost job would be the larger harm. The consequence of a
    swallowed failure is exactly the behaviour that existed before this module -
    the result does not survive a restart - which is a degradation and not a
    corruption.
    """
    from api.jobs import _jsonable, _redact

    try:
        ledger.append(
            actor=record.actor,
            operation=JOB_OUTCOME,
            params={
                "job_id": record.job_id,
                "kind": record.kind,
                "state": record.state,
                # Redacted for the same reason the status route redacts it: the
                # typed serial is a confirmation token, not a fact worth
                # keeping, and the chain is the last place to put one.
                "job_params": _redact(record.params),
                "started_at": record.started_at.isoformat(),
                "finished_at": (
                    record.finished_at.isoformat() if record.finished_at else None
                ),
                "error": record.error,
                "error_kind": record.error_kind,
                "remediation": record.remediation,
                "cancel_requested": record.cancel_requested,
                "actor": record.actor,
                "actor_basis": record.actor_basis,
            },
            result={"result": _jsonable(record.result)},
        )
    except Exception as exc:  # noqa: BLE001 - degradation, never a lost job
        logger.warning(
            "job_outcome_not_recorded",
            job_id=record.job_id,
            error=str(exc),
            kind=type(exc).__name__,
        )


def reconstruct_status(services: AppServices, job_id: str) -> dict[str, Any] | None:
    """Rebuild ``GET /jobs/{id}``'s shape for ``job_id`` from the chain.

    Returns ``None`` when the chain holds no :data:`JOB_OUTCOME` entry for the
    job, which is the honest answer for a job that never finished, never ran
    here, or whose id is simply wrong. The newest entry wins: re-running a job
    under the same id is not a thing this API does, but a chain merged from two
    hosts could carry two, and the later one is the later truth.
    """
    from core.ledger.chain import Ledger

    try:
        ledger = Ledger(
            services.ledger_root,
            tool_version=services.tool_version,
            pubkey_fingerprint="",  # read-only: this never appends
        )
        found = [
            entry
            for entry in ledger.entries()
            if entry.operation == JOB_OUTCOME
            and ledger.params_of(entry).get("job_id") == job_id
        ]
    except (OSError, ValueError, FileNotFoundError):
        return None
    if not found:
        return None

    entry = found[-1]
    try:
        params = ledger.params_of(entry)
        result = ledger.result_of(entry).get("result")
    except (OSError, ValueError, FileNotFoundError):
        # The entry names a blob the store no longer holds. That is a
        # MISSING_BLOB finding for the chain verifier, not something to paper
        # over with an empty result here.
        return None

    return {
        "job_id": job_id,
        "kind": params.get("kind", ""),
        "state": params.get("state", ""),
        "params": params.get("job_params") or {},
        # The chain carries no progress records; see the module docstring.
        "progress_count": 0,
        "dropped_progress": 0,
        "latest": None,
        "result": result,
        "error": params.get("error"),
        "error_kind": params.get("error_kind"),
        "remediation": params.get("remediation") or "",
        "started_at": params.get("started_at"),
        "finished_at": params.get("finished_at"),
        "cancel_requested": bool(params.get("cancel_requested")),
        "actor": params.get("actor") or "",
        "actor_basis": params.get("actor_basis") or "",
        #: True whenever this dict came from the chain rather than the registry.
        #: A consumer that draws a progress bar needs to know the difference,
        #: and a report needs to say where its inputs came from.
        "reconstructed": True,
        "reconstructed_from_seq": entry.seq,
    }


def status_for(services: AppServices, job_id: str) -> dict[str, Any] | None:
    """The job's status: the registry's if it has one, the chain's otherwise.

    The one place the precedence between the two is decided. The registry wins
    when it has the job because it is the live object and a strict superset -
    it carries the progress buffer as well as the result.
    """
    try:
        status = services.registry.status(job_id)
    except KeyError:
        return reconstruct_status(services, job_id)
    status.setdefault("reconstructed", False)
    return status


def durable_job_ids(services: AppServices) -> list[str]:
    """Every job id the chain carries a finished outcome for, oldest first."""
    from core.ledger.chain import Ledger

    try:
        ledger = Ledger(
            services.ledger_root,
            tool_version=services.tool_version,
            pubkey_fingerprint="",
        )
        seen: list[str] = []
        for entry in ledger.entries():
            if entry.operation != JOB_OUTCOME:
                continue
            identifier = str(ledger.params_of(entry).get("job_id") or "")
            if identifier and identifier not in seen:
                seen.append(identifier)
        return seen
    except (OSError, ValueError, FileNotFoundError):
        return []


def entries_as_json(ledger: Ledger, job_id: str) -> list[dict[str, Any]]:
    """Chain entries belonging to ``job_id``, as plain dicts, in file order."""
    found: list[dict[str, Any]] = []
    for entry in ledger.entries():
        if ledger.params_of(entry).get("job_id") == job_id:
            found.append(json.loads(entry.model_dump_json()))
    return found
