"""``/cases`` - the entity everything else is grouped by.

A case is created here, evidence and operations are attached to it as they
happen, and :func:`case_detail` assembles the one screen that accounts for an
investigation: what was seized, what was done to it, what came out, and what
the chain says about all of it.

**The case document is an index and the ledger is the record.** Every count on
this screen is derived from one or the other and the docstrings say which. The
integrity verdict is always the chain's, never the document's: a case file is
ordinary mutable JSON and proves nothing, which is exactly why it is allowed to
be convenient.
"""

from __future__ import annotations

from typing import Any

from core.cases import (
    CaseError,
    attach_evidence,
    case_summary,
    close_case,
    create_case,
    list_cases,
    load_case,
    update_operation,
)
from fastapi import APIRouter, Depends

from api.deps import AppServices
from api.durable import JOB_OUTCOME, status_for
from api.identity import resolve as resolve_identity
from api.routes.common import get_services, sanctum_error_response
from api.routes.models import CaseCreateRequest, EvidenceAttachRequest

__all__ = ["router"]

router = APIRouter(tags=["cases"])

#: The ledger operation recorded when a case is opened.
CASE_OPENED = "case.opened"
#: The ledger operation recorded when a case is closed.
CASE_CLOSED = "case.closed"
#: The ledger operation recorded when an exhibit is registered against a case.
EVIDENCE_REGISTERED = "case.evidence.registered"


def _case_error(exc: CaseError) -> Exception:
    kind = "CaseNotFound" if "No case" in exc.message else "CaseRefused"
    return sanctum_error_response(kind, exc.message, exc.remediation)


@router.get("/cases")
def index(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    """Every case, newest first, as dashboard rows."""
    return {"cases": list_cases(services.cases_dir)}


@router.post("/cases")
def create(
    body: CaseCreateRequest,
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    """Open a case.

    ``created_by`` is the trusted local identity, not anything in the body. A
    case whose author is a text field the browser filled in would reintroduce
    at the case level exactly the problem :mod:`api.identity` fixed at the
    operation level.
    """
    identity = resolve_identity(services)
    try:
        case = create_case(
            services.cases_dir,
            case_id=body.case_id,
            title=body.title,
            description=body.description,
            created_by=identity.actor,
        )
    except CaseError as exc:
        raise _case_error(exc) from exc

    # Opening a case is an auditable act: it is the first thing in the custody
    # story and the one every later entry refers back to.
    try:
        services.ledger().append(
            actor=identity.actor,
            operation=CASE_OPENED,
            params={
                "case_id": case.case_id,
                "title": case.title,
                "description": case.description,
                "created_by": identity.actor,
                "actor_basis": identity.basis,
            },
            result={},
        )
    except Exception as exc:  # noqa: BLE001 - the case exists either way
        # Not fatal, and said out loud. The case document is an index; losing
        # its chain entry costs the audit trail one line and costs the case
        # nothing. Failing the request would leave a created case behind a 500.
        return {"case": case_summary(case), "ledger_warning": str(exc)}
    return {"case": case_summary(case)}


@router.post("/cases/{case_id}/close")
def close(
    case_id: str,
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    """Close a case. The closing is chained like the opening was."""
    identity = resolve_identity(services)
    try:
        case = close_case(
            services.cases_dir, case_id=case_id, closed_by=identity.actor
        )
    except CaseError as exc:
        raise _case_error(exc) from exc

    try:
        services.ledger().append(
            actor=identity.actor,
            operation=CASE_CLOSED,
            params={
                "case_id": case.case_id,
                "closed_by": identity.actor,
                "actor_basis": identity.basis,
                "evidence_count": len(case.evidence),
                "operation_count": len(case.operations),
                "report_count": len(case.reports),
            },
            result={},
        )
    except Exception as exc:  # noqa: BLE001 - see create()
        return {"case": case_summary(case), "ledger_warning": str(exc)}
    return {"case": case_summary(case)}


@router.post("/cases/{case_id}/evidence")
def register_evidence(
    case_id: str,
    body: EvidenceAttachRequest,
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    """Register an exhibit against a case.

    This records *that an exhibit exists and what its hashes are*. It does not
    acquire it, does not open it and does not hash it: acquisition is a job
    with its own read-only path and its own chain entries, and a registration
    endpoint that quietly read a device would be a privileged operation wearing
    a bookkeeping name.
    """
    identity = resolve_identity(services)
    try:
        record = attach_evidence(
            services.cases_dir,
            case_id=case_id,
            evidence_id=body.evidence_id,
            source=body.source,
            media_type=body.media_type,
            acquired_at=body.acquired_at,
            source_hash=body.source_hash,
            verification_hash=body.verification_hash,
            state=body.state,
            detail={"registered_by": identity.actor},
        )
    except CaseError as exc:
        raise _case_error(exc) from exc

    try:
        services.ledger().append(
            actor=identity.actor,
            operation=EVIDENCE_REGISTERED,
            params={"case_id": case_id, **record},
            result={},
        )
    except Exception as exc:  # noqa: BLE001 - see create()
        return {"evidence": record, "ledger_warning": str(exc)}
    return {"evidence": record}


@router.get("/cases/{case_id}")
def case_detail(
    case_id: str, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    """One case, with its operations reconciled against the chain.

    Each operation's status is refreshed from :func:`api.durable.status_for`
    before the case is rendered, so a case opened after a restart shows what
    actually happened rather than what the document last happened to be told.
    The refresh writes back, which keeps the index honest without ever making
    it authoritative.
    """
    try:
        case = load_case(services.cases_dir, case_id)
    except CaseError as exc:
        raise _case_error(exc) from exc

    for operation in case.operations:
        identifier = str(operation.get("operation_id") or "")
        if not identifier or operation.get("status") not in {"running", "pending"}:
            continue
        status = status_for(services, identifier)
        if status is None or str(status.get("state")) in {"pending", "running"}:
            continue
        result = status.get("result") or {}
        written = result.get("written") if isinstance(result, dict) else None
        verification = result.get("verification") if isinstance(result, dict) else None
        passed = verification.get("passed") if isinstance(verification, dict) else None
        update_operation(
            services.cases_dir,
            case_id=case_id,
            operation_id=identifier,
            status=str(status.get("state")),
            result_ref=f"{JOB_OUTCOME}:{identifier}",
            recovered_artifacts=len(written) if isinstance(written, list) else 0,
            completed_at=str(status.get("finished_at") or ""),
            error_kind=str(status.get("error_kind") or ""),
            verification_passed=passed if isinstance(passed, bool) else None,
        )
    case = load_case(services.cases_dir, case_id)

    chain = _chain_state(services)
    events = _audit_events_for_case(services, case_id)
    summary = case_summary(case)
    summary["audit_event_count"] = len(events)
    summary["integrity"] = chain["status"]
    return {
        "case": summary,
        "evidence": case.evidence,
        "operations": case.operations,
        "reports": case.reports,
        "audit": {
            "chain_status": chain["status"],
            "chain_explanation": chain["explanation"],
            "first_broken_seq": chain["first_broken_seq"],
            "entry_count": chain["entry_count"],
            "events": events,
        },
    }


def _chain_state(services: AppServices) -> dict[str, Any]:
    """This host's chain verdict, or an EMPTY verdict when there is none."""
    try:
        verification = services.ledger().verify(check_blobs=True)
    except Exception as exc:  # noqa: BLE001 - reported, never raised at a screen
        return {
            "status": "UNREADABLE",
            "explanation": f"The chain could not be read: {type(exc).__name__}",
            "first_broken_seq": None,
            "entry_count": 0,
        }
    return {
        "status": verification.status.value,
        "explanation": verification.explanation,
        "first_broken_seq": verification.first_bad_seq,
        "entry_count": verification.entry_count,
    }


def _audit_events_for_case(
    services: AppServices, case_id: str, *, limit: int = 500
) -> list[dict[str, Any]]:
    """Chain entries naming this case, newest first.

    An entry belongs to this case when the chain says so, in one of two ways:
    it carries the ``case_id`` its writer stamped, or it carries a ``job_id``
    that this case's document lists as one of its operations. Both are needed
    and neither is a guess. The engines below the API - the erase pipeline, the
    acquisition - write their phase entries with the ``job_id`` the route
    handed them and know nothing about cases, so matching on ``case_id`` alone
    would show a case its recoveries and none of its wipes. Matching through
    the job id is a lookup, not an inference: the operation id came back from
    the route that started the job.
    """
    try:
        ledger = services.ledger()
        entries = ledger.entries()
    except Exception:  # noqa: BLE001 - an unreadable chain is an empty timeline
        return []

    try:
        case = load_case(services.cases_dir, case_id)
        job_ids = {
            str(item.get("operation_id") or "") for item in case.operations
        } - {""}
    except CaseError:
        job_ids = set()

    found: list[dict[str, Any]] = []
    for entry in entries:
        try:
            params = ledger.params_of(entry)
        except (OSError, ValueError, FileNotFoundError):
            continue
        job_id = str(params.get("job_id") or "")
        if params.get("case_id") != case_id and job_id not in job_ids:
            continue
        found.append(
            {
                "seq": entry.seq,
                "case_id": case_id,
                "operation_id": job_id,
                "sequence": entry.seq,
                "actor": entry.actor,
                "event": entry.operation,
                "timestamp": entry.ts_utc.isoformat(),
                "previous_hash": entry.prev_entry_hash,
                "current_hash": entry.entry_hash,
            }
        )
    return list(reversed(found))[:limit]
