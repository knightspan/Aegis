"""The workflow that authorizes a real drive erase.

Three calls, in order, none of which writes to a device: open the record with a
verified backup, record a human approval, read the state. ``POST
/jobs/erase-drive`` then spends the record. See :mod:`api.authorization` for
the invariant and what it does not claim.
"""

from __future__ import annotations

from typing import Any

from core.authorization import build_plan, device_identity, stat_fingerprint
from core.workflow import derive
from fastapi import APIRouter, Depends

from api.authorization import (
    AuthorizationStore,
    _now,
    _Record,
    facts_for,
    new_id,
    sha256_of,
)
from api.deps import AppServices
from api.identity import resolve as resolve_identity
from api.routes.common import (
    get_services,
    resolve_output_path,
    sanctum_error_response,
)
from api.routes.models import ApproveEraseRequest, OpenEraseWorkflowRequest

__all__ = ["router"]

router = APIRouter(tags=["workflow"])


def _probe(services: AppServices, path: str) -> dict[str, Any]:
    from helper.rpc import RpcError

    try:
        return services.helper.call("probe_capabilities", {"path": path})
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


def _view(record: _Record, probe: dict[str, Any]) -> dict[str, Any]:
    status = derive(facts_for(record, probe, level=record.level))
    return {
        "authorization_id": record.auth_id,
        "path": record.path,
        "level": record.level,
        "workflow": status.as_dict(),
        "approved": bool(record.approved_by),
        "approved_by": record.approved_by,
        "backup": {key: record.backup[key] for key in ("path", "sha256", "size_bytes")},
        "backup_limitation": (
            "The image was hashed and sized read-only. This does not prove it "
            "is a copy of this device."
        ),
        "plan": record.plan,
    }


def _store(services: AppServices) -> AuthorizationStore:
    return AuthorizationStore(services.state_dir / "authorizations")


def _load_erase(store: AuthorizationStore, auth_id: str) -> _Record:
    """An erase authorization record, or 404. A restore record is not one."""
    record = store.load(auth_id)
    if record is None or record.kind != "erase":
        raise sanctum_error_response(
            "JobNotKnown",
            f"No erase authorization {auth_id!r}."
            + (f" It is a {record.kind} authorization." if record else ""),
            "Open a workflow first.",
        )
    return record


def _present(services: AppServices, record: _Record) -> dict[str, Any]:
    probe = _probe(services, record.path)
    view = _view(record, probe)
    view["spent"] = _store(services).is_spent(record.auth_id)
    return view


@router.post("/workflow/erase-drive")
def open_erase_workflow(
    body: OpenEraseWorkflowRequest,
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    """Open an authorization: probe the device, verify the backup image read-only."""
    probe = _probe(services, body.path)
    device = probe.get("device", {})
    if device.get("is_system_disk") or device.get("mounted_at"):
        raise sanctum_error_response(
            "MountedRefused" if device.get("mounted_at") else "SystemDiskRefused",
            f"Refusing to open an erase workflow for {body.path}: the device is "
            "mounted or hosts the running system.",
            "Unmount by hand or choose another device. Nothing here unmounts.",
        )
    if probe.get("capabilities") is None:
        raise sanctum_error_response(
            "UnsupportedCapability",
            f"Capabilities of {body.path} could not be probed.",
            "Resolve the probe failure and try again.",
        )
    image = resolve_output_path(
        services.evidence_dir, body.backup_image, field="backup_image"
    )
    if not image.is_file():
        raise sanctum_error_response(
            "EvidenceIntegrityError",
            f"Backup image {image} is not a regular file.",
            "Take a backup image onto a different disk under the evidence directory.",
        )
    before = stat_fingerprint(image)
    digest, size, mtime_ns = sha256_of(image)
    if stat_fingerprint(image) != before:
        raise sanctum_error_response(
            "EvidenceIntegrityError",
            f"Backup image {image} changed while it was being verified.",
            "Wait for whatever is writing the image to finish, then open the "
            "workflow again.",
        )
    identity = device_identity(probe)
    if size < identity["size_bytes"] or identity["size_bytes"] <= 0:
        raise sanctum_error_response(
            "EvidenceIntegrityError",
            f"Backup image is {size} bytes; the device is "
            f"{identity['size_bytes']} bytes. The backup does not cover the device.",
            "Take a complete backup image, then open the workflow again.",
        )
    who = resolve_identity(services)
    record = _Record(
        auth_id=new_id(),
        path=body.path,
        level=body.level,
        device=identity,
        backup={
            "path": str(image),
            "sha256": digest,
            "size_bytes": size,
            "mtime_ns": mtime_ns,
            **stat_fingerprint(image),
        },
        plan=build_plan(probe, body.level),
        opened_by=who.actor,
        opened_at=_now(),
    )
    _store(services).create(record)
    return _present(services, record)


@router.get("/workflow/erase-drive/{auth_id}")
def erase_workflow_state(
    auth_id: str, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    record = _load_erase(_store(services), auth_id)
    return _present(services, record)


@router.post("/workflow/erase-drive/{auth_id}/approve")
def approve_erase(
    auth_id: str,
    body: ApproveEraseRequest,
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    """Record a human approval of the plan. The only place approval is written."""
    store = _store(services)
    record = _load_erase(store, auth_id)
    if store.is_spent(auth_id) or record.approved_by:
        # An approval is written once. Overwriting it would let a later caller
        # replace the recorded approver, and approving a spent record would put
        # an approval in the chain after the execution it supposedly preceded.
        raise sanctum_error_response(
            "ConfirmationMismatch",
            f"Approval refused: authorization {auth_id} is already "
            + ("used." if store.is_spent(auth_id) else "approved."),
            "Open a new workflow if another erase is intended.",
        )
    probe = _probe(services, record.path)
    facts = facts_for(record, probe, level=record.level)
    status = derive(facts)
    serial = str(probe.get("device", {}).get("serial", ""))
    if not body.acknowledge_data_destruction or body.typed_serial != serial:
        raise sanctum_error_response(
            "ConfirmationMismatch",
            f"Approval refused for {record.path}: it needs "
            "acknowledge_data_destruction=true and the exact device serial.",
            "Re-read the device serial from the capability report and type it "
            "exactly.",
        )
    if status.state.value in {"BLOCKED", "BACKUP_REQUIRED", "DISCOVERED"}:
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
        services.ledger().append(
            actor=record.approved_by,
            operation="erase.approved",
            params={
                "authorization_id": record.auth_id,
                "path": record.path,
                "level": record.level,
                "device": record.device,
                "backup_sha256": record.backup["sha256"],
            },
            result={"approved": True},
        )
    except Exception as exc:  # noqa: BLE001 - see below
        # An approval with no chain entry is refused rather than half-recorded.
        record.approved_by = ""
        record.approved_at = ""
        store.save(record)
        raise sanctum_error_response(
            "LedgerBusy",
            f"The approval was NOT recorded: {exc}",
            "Retry once the ledger is available.",
        ) from exc
    return _present(services, record)
