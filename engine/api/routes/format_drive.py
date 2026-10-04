"""Make an erased device usable again, over the API.

A sanitization leaves a device with nothing on it, which an operating system
reads as unformatted. This workflow writes one partition table and one
filesystem onto a device that Sanctum has just erased, authorized exactly like
an erase, a restore or an HPA change, in calls no request can collapse into one:

1. ``POST /workflow/format`` reads the device (through the helper), checks the
   ledger for a completed erase of this very device that nothing has followed,
   plans one format and opens a ``format`` authorization. Nothing is written.
2. ``POST /workflow/format/{id}/approve`` records a human approval, with the
   device serial typed by hand and an explicit acknowledgement.
3. ``POST /workflow/format/{id}/execute`` passes the API gate, spends the
   authorization and hands the helper a ``run_format``; the helper re-checks
   everything at the write seam. There is no dry-run mode.

A ``format`` authorization is never spendable as an erase, restore or HPA change
and none of those is spendable as a format: every step checks the record's
``kind``. Only Linux has a format backend; another host is refused by the
helper with the platform's reason.
"""

from __future__ import annotations

import uuid
from typing import Any

import structlog
from core.authorization import device_identity, identity_drift, kind_mismatch
from core.format import plan_format
from core.models import Device
from fastapi import APIRouter, Depends, HTTPException

from api.authorization import AuthorizationStore, _now, _Record, new_id
from api.deps import AppServices
from api.durable import JOB_OUTCOME
from api.identity import resolve as resolve_identity
from api.routes.common import get_services, sanctum_error_response
from api.routes.jobs import _helper_job, _submit
from api.routes.models import (
    ApproveFormatRequest,
    ExecuteFormatRequest,
    JobAccepted,
    OpenFormatRequest,
)

__all__ = ["router"]

router = APIRouter(tags=["format"])
logger = structlog.get_logger(__name__)

_OPEN_HINT = (
    "Erase the device with the drive eraser first. A format is only offered on "
    "a device Sanctum has just erased."
)
_NOTICE = (
    "This writes a partition table and one filesystem to a few sectors. It does "
    "not sanitize anything; the sanitization certificate describes the device at "
    "the end of the erase, before this step."
)
#: Job kinds whose outcome says what a device holds now: an erase, a resumed
#: erase, a restore, a format. The newest one for a device decides.
_DRIVE_KINDS = ("erase-drive", "restore", "format")


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


def _probe(services: AppServices, path: str) -> Device:
    """The helper's fresh reading of the device. Read-only."""
    from helper.rpc import RpcError

    try:
        answer = services.helper.call("probe_capabilities", {"path": path})
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
    return Device.model_validate(answer["device"])


def _is_drive_kind(kind: str) -> bool:
    return kind in _DRIVE_KINDS or kind.startswith("resume-")


def _last_outcome(services: AppServices, path: str) -> dict[str, Any] | None:
    """The newest recorded job outcome that changed what ``path`` holds."""
    from core.ledger.chain import Ledger

    try:
        ledger = Ledger(
            services.ledger_root,
            tool_version=services.tool_version,
            pubkey_fingerprint="",
        )
        found: dict[str, Any] | None = None
        for entry in ledger.entries():
            if entry.operation != JOB_OUTCOME:
                continue
            params = ledger.params_of(entry)
            kind = str(params.get("kind", ""))
            job_params = params.get("job_params") or {}
            if _is_drive_kind(kind) and job_params.get("path") == path:
                found = {
                    "job_id": str(params.get("job_id", "")),
                    "kind": kind,
                    "state": str(params.get("state", "")),
                    "result": ledger.result_of(entry).get("result") or {},
                }
        return found
    except (OSError, ValueError):
        return None


def _follows_erase(services: AppServices, device: Device) -> tuple[str, list[str]]:
    """The erase job a format may follow, or why there is none."""
    outcome = _last_outcome(services, device.path)
    if outcome is None:
        return "", [
            f"no completed erase of {device.path} is on record; a format is only "
            "offered on a device Sanctum has just erased"
        ]
    kind = outcome["kind"]
    if not (kind == "erase-drive" or kind.startswith("resume-")):
        return "", [
            f"the last job on {device.path} was a {kind}, not an erase; a format "
            "is only offered right after an erase"
        ]
    if outcome["state"] != "complete":
        return "", [
            f"the last erase of {device.path} ended {outcome['state']}, not complete"
        ]
    erased = str((outcome["result"].get("device") or {}).get("serial", ""))
    if not erased or erased.casefold() != device.serial.casefold():
        return "", [
            f"the device at {device.path} is not the one that was erased: the erase "
            f"recorded serial {erased!r}, this one reports {device.serial!r}"
        ]
    return outcome["job_id"], []


def _refusal(
    services: AppServices,
    *,
    actor: str,
    path: str,
    reasons: list[str],
    remediation: str = _OPEN_HINT,
) -> HTTPException:
    """A 409 in the erase gate's shape, ledgered best-effort."""
    try:
        _ledger(
            services,
            actor,
            "format.refused",
            {"path": path},
            {"verdict": "REFUSED", "why_blocked": reasons},
        )
    except Exception as exc:  # noqa: BLE001 - the refusal matters more than its record
        logger.warning("format_refusal_not_recorded", path=path, error=str(exc))
    error = sanctum_error_response(
        "WorkflowGateRefused",
        f"REFUSED: a format of {path or 'this device'} is not allowed: "
        + "; ".join(reasons)
        + ". Nothing was written.",
        remediation,
    )
    error.detail["why_blocked"] = reasons  # type: ignore[index]
    return error


def _load(store: AuthorizationStore, auth_id: str) -> _Record:
    record = store.load(auth_id)
    if record is None or record.kind != "format":
        raise sanctum_error_response(
            "JobNotKnown",
            f"No format authorization {auth_id!r}."
            + (f" It is a {record.kind} authorization." if record else ""),
            "Open a format workflow first.",
        )
    return record


def _view(record: _Record, store: AuthorizationStore) -> dict[str, Any]:
    return {
        "authorization_id": record.auth_id,
        "kind": record.kind,
        "path": record.path,
        "approved": bool(record.approved_by),
        "approved_by": record.approved_by,
        "spent": store.is_spent(record.auth_id),
        "plan": record.plan,
        "notice": _NOTICE,
    }


def _binding(record: _Record) -> dict[str, Any]:
    return {
        "auth_id": record.auth_id,
        "kind": record.kind,
        "path": record.path,
        "device": dict(record.device),
        "backup": dict(record.backup),
        "plan": dict(record.plan),
    }


def _recheck(
    services: AppServices, record: _Record, typed_serial: str
) -> tuple[Device, list[str]]:
    """Every fact re-read now: identity, mounts, the erase, the typed serial."""
    device = _probe(services, record.path)
    reasons = identity_drift(
        record.device, device_identity({"device": device.model_dump()})
    )
    if device.is_system_disk:
        reasons.append(f"{device.path} holds the running system")
    if device.mounted_at:
        reasons.append(
            f"{device.path} has mounted filesystems: "
            + ", ".join(sorted(device.mounted_at))
        )
    _job, why = _follows_erase(services, device)
    reasons.extend(why)
    serial = device.serial.strip()
    if not serial or typed_serial.strip().casefold() != serial.casefold():
        reasons.append(f"the typed serial does not match {record.path} as read now")
    return device, list(dict.fromkeys(reasons))


@router.get("/workflow/format/eligibility")
def format_eligibility(
    path: str, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    """Whether Make usable is offered for ``path`` now. Reads only.

    Answered from the ledger and a fresh read of the device, so it holds across a
    restart: an erase run in an earlier session still counts.
    """
    try:
        device = _probe(services, path)
    except HTTPException as exc:
        detail = exc.detail
        message = (
            str(detail.get("error", "")) if isinstance(detail, dict) else str(detail)
        )
        return {
            "eligible": False,
            "follows_job": "",
            "reasons": [message or "the device could not be read"],
        }
    erase_job, reasons = _follows_erase(services, device)
    reasons = reasons + list(plan_format(device, "exfat", "USB").blocking)
    return {
        "eligible": not reasons,
        "follows_job": erase_job if not reasons else "",
        "reasons": list(dict.fromkeys(reasons)),
    }


@router.post("/workflow/format")
def open_format(
    body: OpenFormatRequest, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    """Read the device, check it was just erased, plan the format."""
    actor = resolve_identity(services).actor
    device = _probe(services, body.path)
    erase_job, reasons = _follows_erase(services, device)
    plan = plan_format(device, body.filesystem, body.label, follows_job=erase_job)
    reasons = reasons + list(plan.blocking)
    if reasons:
        raise _refusal(
            services, actor=actor, path=body.path, reasons=list(dict.fromkeys(reasons))
        )
    record = _Record(
        auth_id=new_id(),
        path=body.path,
        level="FORMAT",
        device=device_identity({"device": device.model_dump()}),
        backup={},
        plan=plan.model_dump(mode="json"),
        opened_by=actor,
        opened_at=_now(),
        kind="format",
    )
    store = _store(services)
    store.create(record)
    _ledger(
        services,
        actor,
        "format.open",
        {
            "authorization_id": record.auth_id,
            "path": record.path,
            "plan_digest": plan.plan_digest,
            "filesystem": plan.filesystem,
            "label": plan.label,
            "follows_job": erase_job,
        },
    )
    return _view(record, store)


@router.post("/workflow/format/{auth_id}/approve")
def approve_format(
    auth_id: str,
    body: ApproveFormatRequest,
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    """Record a human approval of the plan. The only place it is written."""
    store = _store(services)
    record = _load(store, auth_id)
    actor = resolve_identity(services).actor
    if store.is_spent(auth_id) or record.approved_by:
        raise _refusal(
            services,
            actor=actor,
            path=record.path,
            reasons=[
                f"authorization {auth_id} is already "
                + ("used" if store.is_spent(auth_id) else "approved")
            ],
            remediation="Open a new format workflow if another format is intended.",
        )
    _device, reasons = _recheck(services, record, body.typed_serial)
    if not body.acknowledge_format:
        reasons.append("acknowledge_format=true is required")
    if reasons:
        raise _refusal(
            services,
            actor=actor,
            path=record.path,
            reasons=reasons,
            remediation="Re-read the serial from the device list and type it exactly.",
        )
    record.approved_by = actor
    record.approved_at = _now()
    store.save(record)
    try:
        _ledger(
            services,
            actor,
            "format.approved",
            {
                "authorization_id": auth_id,
                "path": record.path,
                "device": record.device,
                "plan_digest": record.plan.get("plan_digest", ""),
                "filesystem": record.plan.get("filesystem", ""),
                "label": record.plan.get("label", ""),
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
    return _view(record, store)


@router.post("/workflow/format/{auth_id}/execute", response_model=JobAccepted)
def execute_format(
    auth_id: str,
    body: ExecuteFormatRequest,
    services: AppServices = Depends(get_services),
) -> JobAccepted:
    """Pass the API gate, spend the authorization and run the real format."""
    store = _store(services)
    actor = resolve_identity(services).actor
    record = store.load(auth_id)
    if record is None:
        raise _refusal(
            services,
            actor=actor,
            path="",
            reasons=[f"authorization {auth_id!r} does not exist"],
        )
    reasons = kind_mismatch({"auth_id": auth_id, "kind": record.kind}, "format")
    if not reasons and not record.approved_by:
        reasons.append("no person has approved this format")
    if not reasons and store.is_spent(auth_id):
        reasons.append(
            f"authorization {auth_id} was already used; it authorizes one execution"
        )
    if not reasons and not body.typed_serial.strip():
        reasons.append("no serial was typed; a format is opt-in twice")
    if not reasons:
        _device, reasons = _recheck(services, record, body.typed_serial)
    if reasons:
        raise _refusal(services, actor=actor, path=record.path, reasons=reasons)
    if not store.spend(auth_id):
        raise _refusal(
            services,
            actor=actor,
            path=record.path,
            reasons=[f"authorization {auth_id} was already used"],
        )
    params: dict[str, Any] = {
        "path": record.path,
        "typed_serial": body.typed_serial,
        "authorization": _binding(record),
        "authorization_dir": str(store.root),
        "ledger_root": str(services.ledger_root),
        "tool_version": services.tool_version,
        "actor": actor,
    }
    job_id = f"format-{uuid.uuid4().hex[:12]}"

    def factory() -> Any:
        return _helper_job(services, "run_format", params, job_id=job_id)

    _submit(
        services,
        "format",
        params,
        factory,
        job_id=job_id,
        label=body.operator,
        case_id=body.case_id,
    )
    return JobAccepted(
        job_id=job_id,
        kind="format",
        state="running",
        stream_url=f"/jobs/{job_id}/stream",
    )
