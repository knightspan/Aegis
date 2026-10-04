"""Backup records, backup verification, and the restore workflow.

Backups
-------
``POST /workflow/backup`` records an image under the evidence directory as a
backup of a device whose identity the helper re-reads. Hashing is a job: the
route returns at once and the record is the job's result. ``POST
/workflow/backup/{id}/verify`` re-hashes the image as a job and names the first
chunk that stopped matching. Neither writes to an image or a device.

Restore
-------
A restore overwrites its target, so it is authorized exactly like an erase, in
calls no request can collapse into one:

1. ``POST /workflow/restore`` re-reads the target, plans the restore (size,
   system/mounted refusal, same or different device, exact byte range, time
   estimate) and opens a ``restore`` authorization. Nothing is written.
2. ``POST /workflow/restore/{id}/approve`` records a human approval, with the
   target serial typed by hand and an explicit acknowledgement.
3. ``POST /workflow/restore/{id}/execute`` runs the real restore. With the
   typed serial it passes the API gate, spends the authorization, and hands the
   helper a ``run_restore``; the helper re-checks everything at the write seam
   (:func:`helper.authorization.revalidate_restore`). There is no dry-run mode.
4. ``GET /workflow/restore/{id}`` reports the state from a fresh read.

An erase authorization can never be spent as a restore, nor a restore one as an
erase: every step checks the record's ``kind``.
"""

from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Any

import structlog
from core.authorization import (
    device_identity,
    identity_drift,
    image_drift,
    kind_mismatch,
    stat_fingerprint,
)
from core.backup import (
    BackupRecord,
    create_backup_record,
    load_backup_record,
    record_from_acquisition,
    save_backup_record,
    source_identity_from_probe,
    verify_backup,
)
from core.errors import EvidenceIntegrityError
from core.models import AcquisitionRecord, Progress
from core.restore import (
    RestorePlan,
    confirmation_token,
    plan_restore,
    restore_plan_drift,
    target_identity_from_probe,
)
from core.workflow import WorkflowState
from fastapi import APIRouter, Depends, HTTPException

from api.authorization import (
    AuthorizationStore,
    GateRefused,
    _now,
    _Record,
    new_id,
)
from api.deps import AppServices
from api.identity import resolve as resolve_identity
from api.routes.common import (
    get_services,
    resolve_output_path,
    sanctum_error_response,
)
from api.routes.jobs import _helper_job, _submit
from api.routes.models import (
    ApproveRestoreRequest,
    CreateBackupRequest,
    ExecuteRestoreRequest,
    JobAccepted,
    OpenRestoreRequest,
)
from api.routes.workflow import _probe

__all__ = ["router", "authorize_restore"]

router = APIRouter(tags=["restore"])
logger = structlog.get_logger(__name__)

_BACKUP_ID = re.compile(r"^bk-[0-9a-f]{16}$")
_OPEN_HINT = (
    "Open a restore with POST /workflow/restore, record a human approval with "
    "POST /workflow/restore/{id}/approve, then execute it."
)


# --------------------------------------------------------------------------
# Backup records
# --------------------------------------------------------------------------


def _backup_path(services: AppServices, backup_id: str) -> Path:
    if not _BACKUP_ID.match(backup_id):
        raise sanctum_error_response(
            "JobNotKnown", f"No backup {backup_id!r}.", "Record a backup first."
        )
    return services.state_dir / "backups" / f"{backup_id}.json"


def _load_backup(services: AppServices, backup_id: str) -> BackupRecord:
    path = _backup_path(services, backup_id)
    if not path.exists():
        raise sanctum_error_response(
            "JobNotKnown", f"No backup {backup_id!r}.", "Record a backup first."
        )
    try:
        return load_backup_record(path)
    except EvidenceIntegrityError as exc:
        raise sanctum_error_response(
            "EvidenceIntegrityError", exc.message, exc.remediation
        ) from exc


def _ledger(
    services: AppServices,
    actor: str,
    operation: str,
    params: dict[str, Any],
    result: dict[str, Any] | None = None,
) -> None:
    services.ledger().append(
        actor=actor, operation=operation, params=params, result=result or {}
    )


def _acquisition(services: AppServices, job_id: str) -> AcquisitionRecord | None:
    """The chain's ``acquire.complete`` record for ``job_id``, if any."""
    ledger = services.ledger()
    for entry in reversed(ledger.entries()):
        if entry.operation != "acquire.complete":
            continue
        params = ledger.params_of(entry)
        if params.get("job_id") == job_id:
            return AcquisitionRecord.model_validate(params)
    return None


@router.post("/workflow/backup", response_model=JobAccepted)
def create_backup(
    body: CreateBackupRequest, services: AppServices = Depends(get_services)
) -> JobAccepted:
    """Record an image as a backup of a device. Read-only; a job, not a wait."""
    image = resolve_output_path(
        services.evidence_dir, body.backup_image, field="backup_image"
    )
    if not image.is_file():
        raise sanctum_error_response(
            "EvidenceIntegrityError",
            f"Backup image {image} is not a regular file.",
            "Name an image file under the evidence directory.",
        )
    source = source_identity_from_probe(_probe(services, body.source_path))
    actor = resolve_identity(services).actor
    job_id = f"backup-{uuid.uuid4().hex[:12]}"
    store_dir = services.state_dir / "backups"

    acquired: BackupRecord | None = None
    if body.acquisition_job_id:
        acquisition = _acquisition(services, body.acquisition_job_id)
        if acquisition is None:
            raise sanctum_error_response(
                "JobNotKnown",
                "The chain holds no completed acquisition "
                f"{body.acquisition_job_id!r}.",
                "Name the job id POST /jobs/acquire returned, once it completed.",
            )
        if Path(acquisition.dest_path).resolve() != image:
            raise sanctum_error_response(
                "EvidenceIntegrityError",
                f"Acquisition {body.acquisition_job_id} wrote "
                f"{acquisition.dest_path}, not {image}.",
                "Name the image that acquisition produced.",
            )
        try:
            acquired = record_from_acquisition(acquisition, source)
        except EvidenceIntegrityError as exc:
            raise sanctum_error_response(
                "EvidenceIntegrityError", exc.message, exc.remediation
            ) from exc

    def persist(record: BackupRecord) -> dict[str, Any]:
        save_backup_record(record, store_dir / f"{record.backup_id}.json")
        payload = record.model_dump(mode="json")
        _ledger(
            services, actor, "backup.record", {"job_id": job_id, **payload},
            {"record_digest": record.record_digest},
        )
        return payload

    def factory() -> Any:
        if acquired is not None:
            yield Progress(
                job_id=job_id, phase="RECORD", pct_bp=10_000,
                bytes_done=acquired.image_size_bytes,
                bytes_total=acquired.image_size_bytes,
                throughput_bytes_per_sec=0, eta_seconds=0,
                message="reusing the acquisition's hashes",
            )
            return persist(acquired)
        record = yield from create_backup_record(image, source, job_id=job_id)
        return persist(record)

    params = {
        "backup_image": str(image),
        "source_path": body.source_path,
        "acquisition_job_id": body.acquisition_job_id,
    }
    _submit(
        services, "backup-record", params, factory,
        job_id=job_id, label=body.operator, case_id=body.case_id,
    )
    return JobAccepted(
        job_id=job_id, kind="backup-record", state="running",
        stream_url=f"/jobs/{job_id}/stream",
    )


@router.get("/workflow/backup/{backup_id}")
def backup_state(
    backup_id: str, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    """The record, refused with 422 if it was altered after it was made."""
    record = _load_backup(services, backup_id)
    return {"backup": record.model_dump(mode="json")}


@router.post("/workflow/backup/{backup_id}/verify", response_model=JobAccepted)
def verify_backup_job(
    backup_id: str, services: AppServices = Depends(get_services)
) -> JobAccepted:
    """Re-hash the image against its record, chunk by chunk. A job."""
    record = _load_backup(services, backup_id)
    actor = resolve_identity(services).actor
    job_id = f"backup-verify-{uuid.uuid4().hex[:12]}"

    def factory() -> Any:
        verification = yield from verify_backup(record, job_id=job_id)
        payload = verification.model_dump(mode="json")
        _ledger(
            services, actor, "backup.verify",
            {"job_id": job_id, "backup_id": backup_id, **payload},
            {"passed": verification.passed},
        )
        return payload

    _submit(services, "backup-verify", {"backup_id": backup_id}, factory, job_id=job_id)
    return JobAccepted(
        job_id=job_id, kind="backup-verify", state="running",
        stream_url=f"/jobs/{job_id}/stream",
    )


# --------------------------------------------------------------------------
# Restore
# --------------------------------------------------------------------------


def _store(services: AppServices) -> AuthorizationStore:
    return AuthorizationStore(services.state_dir / "authorizations")


def _load_restore(store: AuthorizationStore, auth_id: str) -> _Record:
    record = store.load(auth_id)
    if record is None or record.kind != "restore":
        raise sanctum_error_response(
            "JobNotKnown",
            f"No restore authorization {auth_id!r}."
            + (f" It is a {record.kind} authorization." if record else ""),
            "Open a restore first.",
        )
    return record


def _refusal(
    services: AppServices,
    *,
    actor: str,
    path: str,
    state: WorkflowState,
    reasons: list[str],
    remediation: str = _OPEN_HINT,
) -> HTTPException:
    """A 409 in the erase gate's shape, ledgered best-effort."""
    try:
        _ledger(
            services, actor, "restore.refused",
            {"path": path, "workflow_state": state.value},
            {"verdict": "REFUSED", "why_blocked": reasons},
        )
    except Exception as exc:  # noqa: BLE001 - the refusal matters more
        logger.warning("restore_refusal_not_recorded", path=path, error=str(exc))
    refusal = GateRefused(
        f"REFUSED: a restore onto {path} needs the workflow gates satisfied; the "
        f"workflow is at {state.value}. Nothing was written.",
        state=state,
        why_blocked=reasons,
        remediation=remediation,
    )
    return HTTPException(status_code=409, detail=refusal.detail())


def _drift(
    record: _Record, probe: dict[str, Any]
) -> tuple[RestorePlan | None, list[str]]:
    """The plan re-derived from a fresh read, and every way it differs.

    ``None`` and a reason when the stored backup record or plan no longer
    parses or its digest does not hold: nothing can be re-planned from it.
    """
    try:
        backup = BackupRecord.model_validate(record.backup["record"])
        approved = RestorePlan.model_validate(record.plan)
        fresh = plan_restore(backup, target_identity_from_probe(probe))
    except (KeyError, TypeError, ValueError, EvidenceIntegrityError):
        return None, ["the recorded backup or plan is unreadable or was altered"]
    reasons = identity_drift(record.device, device_identity(probe))
    reasons.extend(restore_plan_drift(approved, fresh))
    reasons.extend(image_drift(record.backup))
    return fresh, list(dict.fromkeys(reasons))


def _binding(record: _Record) -> dict[str, Any]:
    return {
        "auth_id": record.auth_id,
        "kind": record.kind,
        "path": record.path,
        "device": dict(record.device),
        "backup": dict(record.backup),
        "plan": dict(record.plan),
    }


def _view(services: AppServices, record: _Record) -> dict[str, Any]:
    store = _store(services)
    probe = _probe(services, record.path)
    _, reasons = _drift(record, probe)
    spent = store.is_spent(record.auth_id)
    executed = (store.root / f"{record.auth_id}.executed").exists()
    if executed or spent:
        state = WorkflowState.EXECUTING
        next_action = (
            "follow the restore job; read its verification before relying on it"
        )
    elif reasons:
        state = WorkflowState.BLOCKED
        next_action = "resolve every reason by hand and open a new restore"
    elif not record.approved_by:
        state = WorkflowState.HUMAN_APPROVAL_REQUIRED
        next_action = (
            "a person reviews the plan and approves it with the target serial typed"
        )
    else:
        state = WorkflowState.PLAN_READY
        next_action = "execute on the real target, typing its serial again"
    plan = record.plan
    return {
        "authorization_id": record.auth_id,
        "kind": record.kind,
        "path": record.path,
        "approved": bool(record.approved_by),
        "approved_by": record.approved_by,
        "spent": spent,
        "executed": executed,
        "workflow": {
            "state": state.value,
            "why_blocked": [] if (executed or spent) else reasons,
            "next_action": next_action,
        },
        "backup": {
            key: record.backup[key]
            for key in ("backup_id", "path", "sha256", "size_bytes")
        },
        "plan": plan,
        "identity_statement": plan.get("identity_statement", ""),
        "backup_limitation": (
            "The image is checked chunk by chunk against its record as it is "
            "written, and a mismatch stops the restore before that chunk is "
            "written. The record's hashes do not prove where the image came from."
        ),
    }


@router.post("/workflow/restore")
def open_restore(
    body: OpenRestoreRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    """Plan a restore from a fresh read of the target and open its authorization."""
    backup = _load_backup(services, body.backup_id)
    image = Path(backup.image_path)
    actor = resolve_identity(services).actor
    try:
        size = image.stat().st_size
    except OSError:
        size = -1
    if size != backup.image_size_bytes:
        raise sanctum_error_response(
            "EvidenceIntegrityError",
            f"Backup image {image} is {size} bytes; its record says "
            f"{backup.image_size_bytes}.",
            "Verify the backup; do not restore from a changed image.",
        )
    probe = _probe(services, body.target_path)
    plan = plan_restore(backup, target_identity_from_probe(probe))
    if plan.blocking:
        raise _refusal(
            services, actor=actor, path=body.target_path,
            state=WorkflowState.BLOCKED, reasons=list(plan.blocking),
            remediation="Resolve every reason by hand, then open the restore again.",
        )
    record = _Record(
        auth_id=new_id(),
        path=body.target_path,
        level="RESTORE",
        device=device_identity(probe),
        backup={
            "backup_id": backup.backup_id,
            "record": backup.model_dump(mode="json"),
            "path": str(image),
            "sha256": backup.image_sha256,
            "size_bytes": size,
            "mtime_ns": image.stat().st_mtime_ns,
            **stat_fingerprint(image),
        },
        plan=plan.model_dump(mode="json"),
        opened_by=actor,
        opened_at=_now(),
        kind="restore",
    )
    _store(services).create(record)
    _ledger(
        services, actor, "restore.plan",
        {
            "authorization_id": record.auth_id,
            "backup_id": backup.backup_id,
            "plan_digest": plan.plan_digest,
            "target": plan.target.model_dump(mode="json"),
            "identity_relation": plan.identity_relation,
            "write_offset": plan.write_offset,
            "write_length": plan.write_length,
        },
    )
    return _view(services, record)


@router.get("/workflow/restore/{auth_id}")
def restore_state(
    auth_id: str, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    return _view(services, _load_restore(_store(services), auth_id))


@router.post("/workflow/restore/{auth_id}/approve")
def approve_restore(
    auth_id: str,
    body: ApproveRestoreRequest,
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    """Record a human approval of the restore plan. The only place it is written."""
    store = _store(services)
    record = _load_restore(store, auth_id)
    if store.is_spent(auth_id) or record.approved_by:
        raise sanctum_error_response(
            "ConfirmationMismatch",
            f"Approval refused: restore authorization {auth_id} is already "
            + ("used." if store.is_spent(auth_id) else "approved."),
            "Open a new restore if another is intended.",
        )
    probe = _probe(services, record.path)
    fresh, reasons = _drift(record, probe)
    token = confirmation_token(fresh.target) if fresh else ""
    if (
        not body.acknowledge_data_overwrite
        or not token
        or body.typed_serial.strip().casefold() != token.strip().casefold()
    ):
        raise sanctum_error_response(
            "ConfirmationMismatch",
            f"Approval refused for {record.path}: it needs "
            "acknowledge_data_overwrite=true and the exact target serial.",
            "Re-read the target serial from the device list and type it exactly.",
        )
    if reasons:
        raise sanctum_error_response(
            "ConfirmationMismatch",
            "Approval refused: " + "; ".join(reasons),
            "Open a new restore against the target as it is now.",
        )
    record.approved_by = resolve_identity(services).actor
    record.approved_at = _now()
    store.save(record)
    try:
        _ledger(
            services, record.approved_by, "restore.authorize",
            {
                "authorization_id": auth_id,
                "path": record.path,
                "device": record.device,
                "backup_id": record.backup["backup_id"],
                "backup_sha256": record.backup["sha256"],
                "plan_digest": record.plan.get("plan_digest", ""),
            },
            {"approved": True},
        )
    except Exception as exc:  # noqa: BLE001 - an unrecorded approval is refused
        record.approved_by = ""
        record.approved_at = ""
        store.save(record)
        raise sanctum_error_response(
            "LedgerBusy",
            f"The approval was NOT recorded: {exc}",
            "Retry once the ledger is available.",
        ) from exc
    return _view(services, record)


def authorize_restore(
    services: AppServices,
    *,
    auth_id: str,
    probe: dict[str, Any],
    typed_serial: str,
    actor: str,
) -> dict[str, Any]:
    """Pass the API gate for a real restore and spend the record, or 409.

    The helper does not trust this verdict; it re-reads the target and image
    at the write seam. Refusal spends nothing and writes nothing.
    """
    store = _store(services)
    record = store.load(auth_id)
    if record is None:
        raise _refusal(
            services, actor=actor, path="", state=WorkflowState.BLOCKED,
            reasons=[f"authorization {auth_id!r} does not exist"],
        )
    kind_reasons = kind_mismatch({"auth_id": auth_id, "kind": record.kind}, "restore")
    if kind_reasons:
        raise _refusal(
            services, actor=actor, path=record.path,
            state=WorkflowState.BLOCKED, reasons=kind_reasons,
        )
    if store.is_spent(auth_id):
        raise _refusal(
            services, actor=actor, path=record.path, state=WorkflowState.BLOCKED,
            reasons=[
                f"authorization {auth_id} was already used; it authorizes one "
                "execution"
            ],
        )
    reasons: list[str] = []
    if not record.approved_by:
        reasons.append("no person has approved this restore")
    fresh, drift = _drift(record, probe)
    reasons.extend(drift)
    token = confirmation_token(fresh.target) if fresh else ""
    if not token or typed_serial.strip().casefold() != token.strip().casefold():
        reasons.append(
            f"the typed serial does not match the target {record.path} as re-read "
            "now"
        )
    if reasons:
        state = (
            WorkflowState.HUMAN_APPROVAL_REQUIRED
            if not record.approved_by
            else WorkflowState.BLOCKED
        )
        raise _refusal(
            services, actor=actor, path=record.path, state=state, reasons=reasons
        )
    if not store.spend(auth_id):
        raise _refusal(
            services, actor=actor, path=record.path, state=WorkflowState.BLOCKED,
            reasons=[
                f"authorization {auth_id} was already used; it authorizes one "
                "execution"
            ],
        )
    return _binding(record)


@router.post("/workflow/restore/{auth_id}/execute", response_model=JobAccepted)
def execute_restore_job(
    auth_id: str,
    body: ExecuteRestoreRequest,
    services: AppServices = Depends(get_services),
) -> JobAccepted:
    """Run the real restore through the helper. Refused without the typed serial."""
    store = _store(services)
    actor = resolve_identity(services).actor
    record = store.load(auth_id)
    if record is None or record.kind != "restore":
        raise _refusal(
            services, actor=actor, path=record.path if record else "",
            state=WorkflowState.BLOCKED,
            reasons=(
                kind_mismatch({"auth_id": auth_id, "kind": record.kind}, "restore")
                if record
                else [f"authorization {auth_id!r} does not exist"]
            ),
        )
    if not body.typed_serial:
        raise _refusal(
            services, actor=actor, path=record.path,
            state=WorkflowState.HUMAN_APPROVAL_REQUIRED,
            reasons=["no serial was typed; a restore is opt-in twice"],
        )
    probe = _probe(services, record.path)
    binding = authorize_restore(
        services, auth_id=auth_id, probe=probe,
        typed_serial=body.typed_serial, actor=actor,
    )
    params: dict[str, Any] = {
        "path": record.path,
        "typed_serial": body.typed_serial,
        "authorization": binding,
        "authorization_dir": str(store.root),
        "ledger_root": str(services.ledger_root),
        "tool_version": services.tool_version,
        "actor": actor,
    }
    job_id = f"restore-{uuid.uuid4().hex[:12]}"

    def factory() -> Any:
        return _helper_job(services, "run_restore", params, job_id=job_id)

    _submit(
        services, "restore", params, factory,
        job_id=job_id, label=body.operator, case_id=body.case_id,
    )
    return JobAccepted(
        job_id=job_id, kind="restore", state="running",
        stream_url=f"/jobs/{job_id}/stream",
    )
