"""The guarded HPA/DCO workflow over the API.

An ordinary erase never changes a drive's Host Protected Area; it erases the
accessible range and reports the hidden bytes it could not reach. Exposing
them is this separate workflow, authorized exactly like an erase or a restore,
in calls no request can collapse into one:

1. ``POST /workflow/hidden-area`` has the helper read the drive's native and
   accessible maxima (read-only), checks the reading for plausibility, and
   plans one change - SET MAX ADDRESS to the native maximum, volatile unless a
   permanent change is asked for - and opens an ``hpa`` authorization. Nothing
   is sent to the drive.
2. ``POST /workflow/hidden-area/{id}/approve`` records a human approval, with
   the device serial typed by hand and an explicit acknowledgement (a second
   one for a permanent change). It is refused until a backup of at least the
   accessible range has been recorded and verified.
3. ``POST /workflow/hidden-area/{id}/execute`` runs the real change. With the
   typed serial it passes the API gate, spends the authorization, and hands the
   helper a ``run_hpa_change``; the helper re-checks everything at the write
   seam and the engine re-reads the drive immediately before the command,
   refusing a stale plan. There is no dry-run mode.
4. ``GET /workflow/hidden-area/{id}`` reports the state from a fresh read.

An ``hpa`` authorization is never spendable as an erase or a restore, and an
erase or restore authorization never as an HPA change: every step checks the
record's ``kind``. DCO RESTORE and DCO SET are never issued.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import replace
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
from core.backup import BackupRecord, BackupVerification, load_backup_record
from core.device.hidden_area_workflow import (
    HiddenAreaState,
    HpaFacts,
    HpaPlan,
    HpaState,
    IllegalTransition,
    advance,
    backup_problems,
    derive,
    plan_drift,
    plan_hpa_change,
)
from core.errors import EvidenceIntegrityError
from core.models import Device
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
from api.routes.common import get_services, sanctum_error_response
from api.routes.jobs import _helper_job, _submit
from api.routes.models import (
    ApproveHiddenAreaRequest,
    ExecuteHiddenAreaRequest,
    JobAccepted,
    OpenHiddenAreaRequest,
)

__all__ = ["router", "authorize_hpa"]

router = APIRouter(tags=["hidden-area"])
logger = structlog.get_logger(__name__)

_BACKUP_ID = re.compile(r"^bk-[0-9a-f]{16}$")
_OPEN_HINT = (
    "Open an HPA/DCO workflow with POST /workflow/hidden-area, record and "
    "verify a backup, approve it with POST /workflow/hidden-area/{id}/approve, "
    "then execute it."
)
_NOTICE = (
    "An ordinary erase never changes the HPA or the DCO. This workflow changes "
    "only the HPA (SET MAX ADDRESS to the native maximum); DCO RESTORE and DCO "
    "SET are never issued. It erases nothing: erase the whole device afterwards."
)


# --------------------------------------------------------------------------
# Reads
# --------------------------------------------------------------------------


def _store(services: AppServices) -> AuthorizationStore:
    return AuthorizationStore(services.state_dir / "authorizations")


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


def _discover(services: AppServices, path: str) -> dict[str, Any]:
    """The helper's read-only reading of the drive: device, maxima, or why not."""
    from helper.rpc import RpcError

    try:
        return services.helper.call("discover_hidden_area", {"path": path})
    except RpcError as exc:
        raise sanctum_error_response(
            exc.kind or "DeviceVanished", exc.message, exc.remediation
        ) from exc
    except OSError as exc:
        raise sanctum_error_response(
            "PlatformUnsupported",
            f"The privileged helper could not be reached: {exc}",
            "Start the helper daemon and set SANCTUM_HELPER_SOCKET.",
        ) from exc


def _parse(
    answer: dict[str, Any],
) -> tuple[Device, HiddenAreaState | None, str, str]:
    device = Device.model_validate(answer["device"])
    raw = answer.get("state")
    state = HiddenAreaState.model_validate(raw) if raw else None
    return (
        device,
        state,
        str(answer.get("unavailable") or ""),
        str(answer.get("platform") or ""),
    )


def _device_refusal(device: Device) -> str:
    if device.is_system_disk:
        return f"{device.path} holds the running system"
    if device.mounted_at:
        return f"{device.path} has mounted filesystems: " + ", ".join(
            sorted(device.mounted_at)
        )
    return ""


def _verification(
    services: AppServices, backup_id: str
) -> BackupVerification | None:
    """The chain's most recent ``backup.verify`` of ``backup_id``, if any."""
    ledger = services.ledger()
    for entry in reversed(ledger.entries()):
        if entry.operation != "backup.verify":
            continue
        params = ledger.params_of(entry)
        if params.get("backup_id") == backup_id:
            try:
                return BackupVerification.model_validate(params)
            except ValueError:
                return None
    return None


def _backup_record(
    services: AppServices, backup_id: str
) -> tuple[BackupRecord | None, list[str]]:
    if not _BACKUP_ID.match(backup_id):
        return None, [f"no backup {backup_id!r} is recorded"]
    path = services.state_dir / "backups" / f"{backup_id}.json"
    if not path.exists():
        return None, [f"no backup {backup_id!r} is recorded"]
    try:
        return load_backup_record(path), []
    except EvidenceIntegrityError as exc:
        return None, [exc.message]


def _backup_gate(
    services: AppServices, binding: dict[str, Any], device: Device,
    state: HiddenAreaState,
) -> list[str]:
    """Why the backup gate is not met now, or an empty list."""
    backup_id = str(binding.get("backup_id") or "")
    if not backup_id:
        return [
            "no backup was named when this workflow was opened; record and "
            "verify a backup of the device, then open a new HPA workflow with "
            "its backup_id"
        ]
    record, reasons = _backup_record(services, backup_id)
    if record is None:
        return reasons
    verification = _verification(services, backup_id)
    reasons = backup_problems(record, verification, device=device, state=state)
    if verification is not None and verification.passed:
        try:
            changed = Path(record.image_path).stat().st_ctime_ns
        except OSError:
            changed = -1
        verified = int(verification.verified_at.timestamp() * 1_000_000_000)
        if changed < 0:
            reasons.append("the backup image is no longer readable")
        elif changed > verified:
            reasons.append(
                "the backup image changed after it was verified; verify it again"
            )
    reasons.extend(image_drift(binding))
    return list(dict.fromkeys(reasons))


def _outcome(services: AppServices, auth_id: str) -> tuple[str, str]:
    """``("complete"|"failed"|"", reason)`` from the chain, for this authorization."""
    ledger = services.ledger()
    for entry in reversed(ledger.entries()):
        if entry.operation not in {"hpa.complete", "hpa.failed"}:
            continue
        params = ledger.params_of(entry)
        if params.get("authorization_id") != auth_id:
            continue
        if entry.operation == "hpa.complete":
            return "complete", ""
        try:
            result = ledger.result_of(entry)
        except FileNotFoundError:
            result = {}
        return "failed", str(result.get("reason") or "the HPA change failed")
    return "", ""


def _facts(
    services: AppServices, record: _Record, answer: dict[str, Any]
) -> tuple[HpaFacts, Device, HiddenAreaState | None]:
    """:class:`HpaFacts` from a *fresh* reading and the stored record."""
    device, state, unavailable, _ = _parse(answer)
    try:
        plan = HpaPlan.model_validate(record.plan)
    except ValueError:
        return (
            HpaFacts(
                device_present=True,
                discovery_refusal="the recorded HPA plan is unreadable",
            ),
            device,
            state,
        )
    blocking = list(plan.blocking)
    blocking.extend(
        identity_drift(
            record.device, device_identity({"device": device.model_dump()})
        )
    )
    problems: list[str] = []
    if state is not None:
        blocking.extend(plan_drift(plan, device, state))
        problems = _backup_gate(services, record.backup, device, state)
    facts = HpaFacts(
        device_present=True,
        device_refusal=_device_refusal(device),
        discovery_refusal=unavailable,
        discovered=state is not None,
        plausible=bool(state and state.plausible),
        plausibility_reason=state.plausibility_reason if state else "",
        # The plan's own hidden-byte count: after a completed change the drive
        # reads as having no HPA, which is the point rather than a refusal.
        hidden_area_present=plan.hidden_bytes > 0,
        backup_verified=not problems,
        backup_problems=tuple(problems),
        plan_generated=True,
        plan_blocking=tuple(dict.fromkeys(blocking)),
        human_approved=bool(record.approved_by),
    )
    return facts, device, state


def _view(
    services: AppServices, record: _Record, answer: dict[str, Any] | None = None
) -> dict[str, Any]:
    store = _store(services)
    answer = answer if answer is not None else _discover(services, record.path)
    facts, device, state = _facts(services, record, answer)
    spent = store.is_spent(record.auth_id)
    executed = (store.root / f"{record.auth_id}.executed").exists()
    outcome, reason = _outcome(services, record.auth_id)
    if outcome == "complete":
        facts = replace(facts, complete=True)
    elif outcome == "failed":
        facts = replace(facts, failed=reason)
    elif spent or executed:
        facts = replace(facts, modifying=True)
    status = derive(facts)
    return {
        "authorization_id": record.auth_id,
        "kind": record.kind,
        "path": record.path,
        "approved": bool(record.approved_by),
        "approved_by": record.approved_by,
        "spent": spent,
        "executed": executed,
        "workflow": status.as_dict(),
        "device": device.model_dump(mode="json"),
        "hidden_area_state": state.model_dump(mode="json") if state else None,
        "plan": record.plan,
        "backup": {
            key: record.backup.get(key)
            for key in ("backup_id", "path", "sha256", "size_bytes")
        },
        "notice": _NOTICE,
    }


def _refusal(
    services: AppServices,
    *,
    actor: str,
    path: str,
    state: HpaState,
    reasons: list[str],
    remediation: str = _OPEN_HINT,
    extra: dict[str, Any] | None = None,
) -> HTTPException:
    """A 409 in the erase gate's shape, ledgered best-effort."""
    try:
        _ledger(
            services, actor, "hpa.refused",
            {"path": path, "workflow_state": state.value},
            {"verdict": "REFUSED", "why_blocked": reasons},
        )
    except Exception as exc:  # noqa: BLE001 - the refusal matters more than its record
        logger.warning("hpa_refusal_not_recorded", path=path, error=str(exc))
    detail = GateRefused(
        f"REFUSED: an HPA change on {path or 'this device'} needs the workflow "
        f"gates satisfied; the workflow is at {state.value}. Nothing was sent to "
        "the drive.",
        state=_as_workflow_state(state),
        why_blocked=reasons,
        remediation=remediation,
    ).detail()
    detail["workflow_state"] = state.value
    detail.update(extra or {})
    return HTTPException(status_code=409, detail=detail)


def _as_workflow_state(state: HpaState) -> Any:
    """:class:`GateRefused` carries an erase-workflow state; map the nearest."""
    from core.workflow import WorkflowState

    return {
        HpaState.APPROVAL_REQUIRED: WorkflowState.HUMAN_APPROVAL_REQUIRED,
        HpaState.PLAN_READY: WorkflowState.PLAN_READY,
        HpaState.ANALYZED: WorkflowState.BACKUP_REQUIRED,
        HpaState.BACKUP_VERIFIED: WorkflowState.BACKUP_VERIFIED,
        HpaState.DISCOVERED: WorkflowState.DISCOVERED,
    }.get(state, WorkflowState.BLOCKED)


def _load_hpa(store: AuthorizationStore, auth_id: str) -> _Record:
    record = store.load(auth_id)
    if record is None or record.kind != "hpa":
        raise sanctum_error_response(
            "JobNotKnown",
            f"No HPA authorization {auth_id!r}."
            + (f" It is a {record.kind} authorization." if record else ""),
            "Open an HPA/DCO workflow first.",
        )
    return record


def _binding(record: _Record) -> dict[str, Any]:
    return {
        "auth_id": record.auth_id,
        "kind": record.kind,
        "path": record.path,
        "device": dict(record.device),
        "backup": dict(record.backup),
        "plan": dict(record.plan),
    }


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------


@router.post("/workflow/hidden-area")
def open_hidden_area(
    body: OpenHiddenAreaRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    """Discover and analyze the drive, plan the change, open the authorization."""
    actor = resolve_identity(services).actor
    answer = _discover(services, body.path)
    device, state, unavailable, platform = _parse(answer)
    shown = {"hidden_area_state": state.model_dump(mode="json") if state else None}
    refusal = _device_refusal(device)
    if refusal or unavailable or state is None or platform not in {"linux", "windows"}:
        raise _refusal(
            services, actor=actor, path=body.path, state=HpaState.BLOCKED,
            reasons=[
                refusal
                or unavailable
                or "the drive's maxima could not be read on this platform"
            ],
            remediation="Resolve the reason by hand, then open the workflow again.",
            extra=shown,
        )
    plan = plan_hpa_change(
        device,
        state,
        platform="linux" if platform == "linux" else "windows",
        volatile=body.volatile,
    )
    if plan.blocking:
        raise _refusal(
            services, actor=actor, path=body.path, state=HpaState.BLOCKED,
            reasons=list(plan.blocking),
            remediation="Nothing can be changed on this drive as it is now.",
            extra={**shown, "plan": plan.model_dump(mode="json")},
        )
    backup: dict[str, Any] = {}
    if body.backup_id:
        record_, reasons = _backup_record(services, body.backup_id)
        if record_ is None:
            raise sanctum_error_response(
                "EvidenceIntegrityError",
                "; ".join(reasons),
                "Record the backup with POST /workflow/backup first.",
            )
        image = Path(record_.image_path)
        try:
            stat = image.stat()
        except OSError as exc:
            raise sanctum_error_response(
                "EvidenceIntegrityError",
                f"Backup image {image} is not readable.",
                "Verify the backup; do not rely on a missing image.",
            ) from exc
        backup = {
            "backup_id": record_.backup_id,
            "path": str(image),
            "sha256": record_.image_sha256,
            "size_bytes": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
            **stat_fingerprint(image),
        }
    record = _Record(
        auth_id=new_id(),
        path=body.path,
        level="HPA",
        device=device_identity({"device": device.model_dump()}),
        backup=backup,
        plan=plan.model_dump(mode="json"),
        opened_by=actor,
        opened_at=_now(),
        kind="hpa",
    )
    _store(services).create(record)
    _ledger(
        services, actor, "hpa.open",
        {
            "authorization_id": record.auth_id,
            "path": record.path,
            "plan_digest": plan.plan_digest,
            "operation": plan.operation,
            "volatile": plan.volatile,
            "state": state.model_dump(mode="json"),
            "backup_id": backup.get("backup_id", ""),
        },
    )
    return _view(services, record, answer)


@router.get("/workflow/hidden-area/{auth_id}")
def hidden_area_state_route(
    auth_id: str, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    """The workflow's state, derived from a fresh read of the drive."""
    return _view(services, _load_hpa(_store(services), auth_id))


@router.post("/workflow/hidden-area/{auth_id}/approve")
def approve_hidden_area(
    auth_id: str,
    body: ApproveHiddenAreaRequest,
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    """Record a human approval of the HPA plan. The only place it is written."""
    store = _store(services)
    record = _load_hpa(store, auth_id)
    if store.is_spent(auth_id) or record.approved_by:
        raise sanctum_error_response(
            "ConfirmationMismatch",
            f"Approval refused: HPA authorization {auth_id} is already "
            + ("used." if store.is_spent(auth_id) else "approved."),
            "Open a new HPA workflow if another change is intended.",
        )
    answer = _discover(services, record.path)
    facts, device, _ = _facts(services, record, answer)
    status = derive(facts)
    serial = device.serial.strip()
    if (
        not body.acknowledge_configuration_change
        or not serial
        or body.typed_serial.strip().casefold() != serial.casefold()
    ):
        raise sanctum_error_response(
            "ConfirmationMismatch",
            f"Approval refused for {record.path}: it needs "
            "acknowledge_configuration_change=true and the exact device serial.",
            "Re-read the device serial from the capability report and type it "
            "exactly.",
        )
    if record.plan.get("volatile") is False and not body.acknowledge_permanent:
        raise sanctum_error_response(
            "ConfirmationMismatch",
            "Approval refused: this plan makes a PERMANENT change that survives "
            "power cycles; it needs acknowledge_permanent=true as well.",
            "Acknowledge the permanent change, or open a volatile workflow.",
        )
    if status.state is not HpaState.APPROVAL_REQUIRED:
        raise sanctum_error_response(
            "ConfirmationMismatch",
            f"Approval refused: the workflow is at {status.state.value}: "
            + "; ".join(status.why_blocked),
            status.next_action,
        )
    record.approved_by = resolve_identity(services).actor
    record.approved_at = _now()
    store.save(record)
    try:
        _ledger(
            services, record.approved_by, "hpa.approved",
            {
                "authorization_id": auth_id,
                "path": record.path,
                "device": record.device,
                "backup_id": record.backup.get("backup_id", ""),
                "plan_digest": record.plan.get("plan_digest", ""),
                "operation": record.plan.get("operation", ""),
                "volatile": record.plan.get("volatile", True),
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
    return _view(services, record, answer)


def authorize_hpa(
    services: AppServices,
    *,
    auth_id: str,
    typed_serial: str,
    actor: str,
) -> dict[str, Any]:
    """Pass the API gate for a real HPA change and spend the record, or 409.

    Rebuilds every :class:`HpaFacts` field from a fresh read of the drive,
    requires ``derive`` to answer ``PLAN_READY`` and ``advance`` to accept
    ``MODIFYING``. The helper does not trust this verdict; it re-reads the
    device at the write seam, and the engine re-reads the drive's maxima
    immediately before the command. Refusal spends nothing and sends nothing.
    """
    store = _store(services)
    record = store.load(auth_id)
    if record is None:
        raise _refusal(
            services, actor=actor, path="", state=HpaState.BLOCKED,
            reasons=[f"authorization {auth_id!r} does not exist"],
        )
    kind_reasons = kind_mismatch({"auth_id": auth_id, "kind": record.kind}, "hpa")
    if kind_reasons:
        raise _refusal(
            services, actor=actor, path=record.path, state=HpaState.BLOCKED,
            reasons=kind_reasons,
        )
    used = [f"authorization {auth_id} was already used; it authorizes one execution"]
    if store.is_spent(auth_id):
        raise _refusal(
            services, actor=actor, path=record.path, state=HpaState.BLOCKED,
            reasons=used,
        )
    facts, device, _ = _facts(services, record, _discover(services, record.path))
    status = derive(facts)
    try:
        advance(HpaState.PLAN_READY, HpaState.MODIFYING, facts)
    except IllegalTransition:
        raise _refusal(
            services, actor=actor, path=record.path, state=status.state,
            reasons=list(status.why_blocked) or ["the workflow is not at PLAN_READY"],
            remediation=status.next_action,
        ) from None
    serial = device.serial.strip()
    if not serial or typed_serial.strip().casefold() != serial.casefold():
        raise _refusal(
            services, actor=actor, path=record.path, state=HpaState.PLAN_READY,
            reasons=[
                f"the typed serial does not match {record.path} as re-read now"
            ],
        )
    if not store.spend(auth_id):
        raise _refusal(
            services, actor=actor, path=record.path, state=HpaState.BLOCKED,
            reasons=used,
        )
    return _binding(record)


@router.post("/workflow/hidden-area/{auth_id}/execute", response_model=JobAccepted)
def execute_hidden_area(
    auth_id: str,
    body: ExecuteHiddenAreaRequest,
    services: AppServices = Depends(get_services),
) -> JobAccepted:
    """Run the real change through the helper. Refused without the typed serial."""
    store = _store(services)
    actor = resolve_identity(services).actor
    record = store.load(auth_id)
    if record is None or record.kind != "hpa":
        raise _refusal(
            services, actor=actor, path=record.path if record else "",
            state=HpaState.BLOCKED,
            reasons=(
                kind_mismatch({"auth_id": auth_id, "kind": record.kind}, "hpa")
                if record
                else [f"authorization {auth_id!r} does not exist"]
            ),
        )
    if not body.typed_serial:
        raise _refusal(
            services, actor=actor, path=record.path,
            state=HpaState.APPROVAL_REQUIRED,
            reasons=["no serial was typed; an HPA change is opt-in twice"],
        )
    binding = authorize_hpa(
        services, auth_id=auth_id, typed_serial=body.typed_serial, actor=actor
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
    job_id = f"hpa-{uuid.uuid4().hex[:12]}"

    def factory() -> Any:
        return _helper_job(services, "run_hpa_change", params, job_id=job_id)

    _submit(
        services, "hpa-change", params, factory,
        job_id=job_id, label=body.operator, case_id=body.case_id,
    )
    return JobAccepted(
        job_id=job_id, kind="hpa-change", state="running",
        stream_url=f"/jobs/{job_id}/stream",
    )
