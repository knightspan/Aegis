"""Job endpoints: submit, stream, inspect, cancel.

Every submission returns a ``job_id`` immediately and runs the work on a worker
thread. No handler here waits for a wipe, an acquisition or a carve to finish -
a 4 TB overwrite is hours long and an HTTP request that lived that long would
be dead well before the work was.

**Every destructive endpoint runs the real operation.** There is no dry-run or
simulation switch, and a body that still sends one is refused with 422 (see
:mod:`api.routes.models`). What stands between a request and the device is the
set of gates: a typed serial or identifier, and for a device a server-issued,
human-approved, single-use authorization. The serial is re-checked inside the
helper against the serial that process reads from the host, so a stale browser
cannot authorise a wipe of a device that was swapped since the page loaded.
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path
from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from api.authorization import GateRefused, authorize_execution
from api.deps import AppServices
from api.identity import resolve as resolve_identity
from api.identity import sanitise_label
from api.routes.common import (
    get_services,
    resolve_output_path,
    sanctum_error_response,
)
from api.routes.models import (
    AcquireRequest,
    CarveRequest,
    DestroyRecordRequest,
    EraseDriveRequest,
    EraseFilesRequest,
    JobAccepted,
    PlanFreeSpaceRequest,
    ResumeEraseRequest,
    WipeFreeSpaceRequest,
)
from api.sse import SSE_HEADERS, progress_events

__all__ = ["router"]

router = APIRouter(tags=["jobs"])


def _signing_fingerprint(services: AppServices) -> str:
    """This deployment's signing-key fingerprint, or ``""`` if it has none yet.

    Recorded in the ledger's genesis entry so a report signed later can be
    checked against the key the chain was started with. The lookup never
    creates a key: accepting a job must not have the side effect of minting one,
    and a deployment with no key still has to be able to start a chain.
    """
    from core.report.sign import fingerprint_of_existing_key

    return fingerprint_of_existing_key(
        services.key_dir or (services.state_dir / "keys")
    )


def _accepted(job_id: str, kind: str) -> JobAccepted:
    return JobAccepted(
        job_id=job_id,
        kind=kind,
        state="running",
        stream_url=f"/jobs/{job_id}/stream",
    )


def _refuse_confirmation(message: str, remediation: str) -> HTTPException:
    """A confirmation refusal in the same shape as a workflow-gate refusal.

    Raised before anything is submitted, so nothing was erased. The extra
    fields let a client render "BLOCKED / WHY BLOCKED" from the server's own
    words instead of a generic failure. ``kind`` stays ConfirmationMismatch.
    """
    refusal = sanctum_error_response("ConfirmationMismatch", message, remediation)
    detail = {**cast("dict[str, Any]", refusal.detail)}
    detail.update(
        {
            "verdict": "REFUSED",
            "workflow_state": "HUMAN_APPROVAL_REQUIRED",
            "WHY BLOCKED": [message],
            "physical_device_modified": False,
        }
    )
    return HTTPException(status_code=refusal.status_code, detail=detail)


def _gate_real_erase(
    services: AppServices,
    *,
    authorization_id: str,
    path: str,
    level: str,
    probe: dict[str, Any],
) -> dict[str, Any]:
    """Refuse a real drive erase unless the workflow gates are satisfied.

    One call, shared by the erase and the resume, so neither can skip it.
    Runs after the helper probe and before anything is submitted.
    """
    try:
        return authorize_execution(
            services,
            auth_id=authorization_id,
            path=path,
            level=level,
            probe=probe,
            actor=resolve_identity(services).actor,
        )
    except GateRefused as refusal:
        raise HTTPException(status_code=409, detail=refusal.detail()) from refusal


def _submit(
    services: AppServices,
    kind: str,
    params: dict[str, Any],
    factory: Any,
    *,
    job_id: str,
    label: str = "",
    case_id: str = "",
) -> None:
    """Submit a job under the *trusted* actor, whatever the body said.

    Every route goes through here so there is one place the identity is
    attached. The client's ``operator`` field never becomes the actor: it is
    sanitised into a label, recorded in the job parameters beside the identity
    that was actually established, and the two are never merged into one
    unmarked string. See :mod:`api.identity`.
    """
    identity = resolve_identity(services)
    cleaned = sanitise_label(label)
    enriched = dict(params)
    enriched["case_id"] = case_id
    enriched["operator_label"] = cleaned
    enriched["actor"] = identity.actor
    enriched["platform"] = services.platform_snapshot()
    services.registry.submit(
        kind,
        enriched,
        factory,
        job_id=job_id,
        actor=identity.labelled_actor(cleaned),
        actor_basis=identity.basis,
    )
    if case_id:
        from core.cases import attach_operation

        attach_operation(
            services.cases_dir,
            case_id=case_id,
            operation_id=job_id,
            kind=kind,
            actor=identity.actor,
            params=enriched,
        )


# --------------------------------------------------------------------------
# Erase a drive
# --------------------------------------------------------------------------


@router.post("/jobs/erase-drive", response_model=JobAccepted)
def erase_drive(
    body: EraseDriveRequest,
    services: AppServices = Depends(get_services),
) -> JobAccepted:
    """Start a real drive sanitization of the selected device.

    Refused before anything is submitted unless the typed serial matches a
    fresh probe and the authorization passes the workflow gate. The helper
    then re-checks both against the device it re-reads itself, so a mismatch
    there comes back with the core's own remediation text.
    """
    from helper.rpc import RpcError

    if not body.typed_serial:
        raise _refuse_confirmation(
            f"Refusing to erase {body.path}: no serial was typed. Destructive "
            "erasure is opt-in twice: an approved authorization and the typed "
            "serial.",
            "Re-read the device serial from the capability report and type it "
            "exactly.",
        )

    params: dict[str, Any] = {
        "path": body.path,
        "level": body.level,
        "typed_serial": body.typed_serial,
        "ledger_root": str(services.ledger_root),
        "tool_version": services.tool_version,
    }

    # Validated before the job is accepted, so a mismatch is a 409 the operator
    # sees immediately rather than a job that starts and fails a second later.
    try:
        probe = services.helper.call("probe_capabilities", {"path": body.path})
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

    serial = str(probe.get("device", {}).get("serial", ""))
    if body.typed_serial != serial:
        raise _refuse_confirmation(
            f"The typed serial {body.typed_serial!r} does not match "
            f"{body.path}, whose serial is {serial!r}. Nothing was erased.",
            "Re-read the device serial from the capability report and type it "
            "exactly.",
        )

    # The workflow gate. The typed serial above is a confirmation token, not an
    # approval; a real erase also needs the recorded approval and verified
    # backup, re-derived from a fresh read of the device.
    binding = _gate_real_erase(
        services,
        authorization_id=body.authorization_id,
        path=body.path,
        level=body.level,
        probe=probe,
    )
    # The helper re-checks this against the host at the write seam.
    params["authorization"] = binding
    params["authorization_dir"] = str(services.state_dir / "authorizations")

    # Minted here rather than by the registry, for the same reason the carve
    # route mints its own: the ledger entries this run writes are keyed by the
    # job id the helper is given, and GET /jobs/{id} and the report excerpt
    # both look them up by the id this endpoint returned. Sending a placeholder
    # instead wrote all six phases under an id no consumer ever queries, so a
    # wipe's audit trail could not be found again and the erasure certificate
    # carried nothing but the genesis entry.
    job_id = f"erase-drive-{uuid.uuid4().hex[:12]}"

    def factory() -> Any:
        return _helper_job(services, "run_erase", params, job_id=job_id)

    _submit(
        services, "erase-drive", params, factory,
        job_id=job_id, label=body.operator, case_id=body.case_id,
    )
    return _accepted(job_id, "erase-drive")


def _linux_block_identity(source: str) -> Any:
    """The serial and size to bind a Linux block-device read to.

    A whole disk answers with its own serial and capacity. A partition has no
    serial of its own, so it is bound to the disk that holds it, and to its own
    size: an image of ``/dev/sda1`` must come from the disk the operator chose,
    and must be as long as that partition.

    Raises:
        DeviceVanished: no enumerated disk or partition is ``source``.
    """
    from types import SimpleNamespace

    from core.errors import DeviceVanished
    from core.platform import current_adapter

    for device in current_adapter().enumerate_devices(include_virtual=True):
        if source in {device.path, device.id}:
            return device
        for partition in device.partitions:
            if source == partition.id:
                return SimpleNamespace(
                    serial=device.serial, capacity_bytes=partition.size_bytes
                )
    raise DeviceVanished(
        f"No storage device or partition matches {source!r}.",
        remediation="Re-enumerate devices and confirm the target is still connected.",
    )


def _is_block_device(path: str) -> bool:
    """True when ``path`` names a block device node on this host."""
    import stat

    try:
        return stat.S_ISBLK(os.stat(path).st_mode)
    except OSError:
        return False


def _helper_job(
    services: AppServices, method: str, params: dict[str, Any], *, job_id: str
) -> Any:
    """Drive a helper call as a generator so the registry can stream it.

    The helper streams: one progress frame per record the engine yields, over
    the same connection the request went out on. This used to be one blocking
    request/response that returned the whole progress list at the end, which
    made the UI's progress bar a replay of an operation that had already
    finished and left ``POST /jobs/{id}/cancel`` with no yield point to act on.

    Two consequences follow from ``yield from``, and both are the point:

    * the registry sees records as the device is written, so the bar moves
      while the wipe runs;
    * the registry's cancellation - ``generator.close()`` between yields -
      propagates into the helper transport, which tells the helper, which stops
      the engine at *its* next yield. Nothing is killed mid-write.

    ``job_id`` is the id the caller was handed and the registry filed the job
    under. It has to be the one the helper receives, because the helper is what
    passes it to the engine that writes the ledger.
    """
    from core.models import Progress

    stream = services.helper.call_stream(method, {**params, "job_id": job_id})
    try:
        while True:
            try:
                record = next(stream)
            except StopIteration as stop:
                answer: dict[str, Any] = stop.value
                break
            yield Progress.model_validate(record)
    finally:
        # Explicit, not left to the collector. On cancellation this is the call
        # that reaches the helper, and "when the frame happens to be freed" is
        # not a schedule to run a drive erase on.
        stream.close()
    return answer.get("result") or answer.get("record")


# --------------------------------------------------------------------------
# Erase files
# --------------------------------------------------------------------------


@router.post("/jobs/erase-files", response_model=JobAccepted)
def erase_files(
    body: EraseFilesRequest,
    services: AppServices = Depends(get_services),
) -> JobAccepted:
    """Start a real file or folder erase. Refused unless ``confirm`` is true.

    File erasure is unprivileged - it writes through ordinary file handles - so
    it runs in this process rather than through the helper. There is nothing
    for the privilege boundary to protect here: the API can already open any
    file the operator can.
    """
    from core.erase.files import erase_paths
    from core.erase.sink import ChainLedgerSink
    from core.ledger.chain import Ledger
    from core.models import FileEraseOptions

    if not body.confirm:
        raise sanctum_error_response(
            "ConfirmationMismatch",
            "Refusing to erase: confirm was not set. Destructive file erasure "
            "needs an explicit confirmation. Nothing was touched.",
            "Review the selected paths, then send confirm=true to erase them.",
        )

    options = FileEraseOptions(
        confirm=body.confirm,
        cleanse_metadata=body.cleanse_metadata,
        break_hardlinks=body.break_hardlinks,
        recursive=body.recursive,
        sweep_traces=body.sweep_traces,
    )
    params = {
        "paths": body.paths,
        "confirm": body.confirm,
        "break_hardlinks": body.break_hardlinks,
        "sweep_traces": body.sweep_traces,
    }
    # The id is minted here rather than by the registry, so the same string
    # reaches erase_paths and therefore the ledger. Letting the registry
    # allocate it would leave the chain entries keyed to an id the job endpoint
    # never learned, and GET /jobs/{id} could not find them again.
    job_id = f"erase-files-{uuid.uuid4().hex[:12]}"
    ledger = Ledger(
        services.ledger_root,
        tool_version=services.tool_version,
        # The key this deployment signs reports with, when it has one. A chain
        # whose genesis records no fingerprint can never satisfy the report
        # check that compares the two. Looked up rather than created: starting a
        # job must not mint a signing key as a side effect.
        pubkey_fingerprint=_signing_fingerprint(services),
    )

    def factory() -> Any:
        return erase_paths(
            [Path(item) for item in body.paths],
            options,
            job_id=job_id,
            ledger=ChainLedgerSink(ledger),
        )

    _submit(
        services, "erase-files", params, factory,
        job_id=job_id, label=body.operator, case_id=body.case_id,
    )
    return _accepted(job_id, "erase-files")


# --------------------------------------------------------------------------
# Record a physical destruction
# --------------------------------------------------------------------------


@router.post("/jobs/record-destroy", response_model=JobAccepted)
def record_destroy(
    body: DestroyRecordRequest,
    services: AppServices = Depends(get_services),
) -> JobAccepted:
    """Chain and file a physical destruction, as the people who did it attest.

    Destroy is the NIST SP 800-88 Rev. 2 outcome no software performs. Nothing
    here opens a device: the job writes one ``destroy.recorded`` entry, and its
    report says in the signed bytes that the tool observed nothing.
    """
    from core.destroy import record_destruction, refuse_a_future_date
    from core.errors import SanctumError
    from core.ledger.chain import Ledger
    from core.models import DestructionRecord

    record = DestructionRecord.model_validate(
        body.model_dump(exclude={"case_id", "operator"})
    )
    try:
        refuse_a_future_date(record)
    except SanctumError as exc:
        raise sanctum_error_response(
            "DestructionDateInFuture", exc.message, exc.remediation
        ) from exc

    job_id = f"destroy-{uuid.uuid4().hex[:12]}"
    ledger = Ledger(
        services.ledger_root,
        tool_version=services.tool_version,
        pubkey_fingerprint=_signing_fingerprint(services),
    )
    actor = resolve_identity(services).labelled_actor(body.operator)
    params = {
        "serial": record.serial,
        "technique": record.technique.value,
        "media_type": record.media_type,
        "observed_by_tool": False,
    }

    def factory() -> Any:
        return record_destruction(
            record, ledger=ledger, job_id=job_id, actor=actor, case_id=body.case_id
        )

    _submit(
        services, "destroy-record", params, factory,
        job_id=job_id, label=body.operator, case_id=body.case_id,
    )
    return _accepted(job_id, "destroy-record")


def _protected_paths(services: AppServices) -> list[Path]:
    """This deployment's own state: a volume holding any of it is never filled."""
    return [
        services.state_dir,
        services.ledger_root,
        services.reports_dir,
        services.key_dir or (services.state_dir / "keys"),
    ]


@router.post("/workflow/wipe-free-space")
def plan_free_space_wipe(
    body: PlanFreeSpaceRequest,
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    """Resolve a volume for a free-space wipe and report it. Writes nothing.

    The plan step: the filesystem, the identifier the operator must type to
    confirm, the free space the fill will cover and what it cannot reach. Every
    refusal the wipe applies runs here too, so a refused volume is refused
    before anyone is asked to confirm it. No job is created.
    """
    from core.erase.freespace import plan_volume
    from core.errors import SanctumError

    try:
        return plan_volume(body.mount_point, protected=_protected_paths(services))
    except SanctumError as exc:
        raise sanctum_error_response(
            type(exc).__name__, exc.message, exc.remediation
        ) from exc


@router.post("/jobs/wipe-free-space", response_model=JobAccepted)
def wipe_free_space(
    body: WipeFreeSpaceRequest,
    services: AppServices = Depends(get_services),
) -> JobAccepted:
    """Fill a mounted volume's free space and release it. Always a real fill.

    Unprivileged, like file erasure, so it runs in this process. Every gate runs
    here, before a job exists: the volume must be a supported filesystem at
    exactly its mount point, must not be the system volume or hold this
    deployment's state, and the typed identifier must be the one
    ``POST /workflow/wipe-free-space`` reports. A refusal is an HTTP error, not
    a failed job.
    """
    from core.device import guard
    from core.erase.freespace import resolve_volume
    from core.erase.freespace import wipe_free_space as run_wipe
    from core.errors import SanctumError
    from core.ledger.chain import Ledger
    from core.models import FreeSpaceWipeOptions

    protected = _protected_paths(services)
    try:
        volume = resolve_volume(body.mount_point)
        guard.assert_volume_wipeable(volume, protected=protected)
        guard.assert_volume_confirmed(volume, body.typed_identifier)
    except SanctumError as exc:
        raise sanctum_error_response(
            type(exc).__name__, exc.message, exc.remediation
        ) from exc

    options = FreeSpaceWipeOptions(typed_identifier=body.typed_identifier)
    job_id = f"wipe-free-space-{uuid.uuid4().hex[:12]}"
    ledger = Ledger(
        services.ledger_root,
        tool_version=services.tool_version,
        pubkey_fingerprint=_signing_fingerprint(services),
    )

    def factory() -> Any:
        return run_wipe(
            volume.mount_point,
            options,
            job_id=job_id,
            ledger=ledger,
            operator=body.operator,
            protected=protected,
            volume=volume,
        )

    params = {
        "mount_point": volume.mount_point,
        "identifier": volume.identifier,
        "fs_type": volume.fs_type,
    }
    _submit(
        services, "wipe-free-space", params, factory,
        job_id=job_id, label=body.operator,
    )
    return _accepted(job_id, "wipe-free-space")


# --------------------------------------------------------------------------
# Acquire
# --------------------------------------------------------------------------


@router.post("/jobs/acquire", response_model=JobAccepted)
def acquire_image(
    body: AcquireRequest,
    services: AppServices = Depends(get_services),
) -> JobAccepted:
    """Image a device or file read-only. Nothing is destroyed.

    The source is opened ``O_RDONLY`` and, on Linux against a block device, set
    read-only at the block layer first. See :mod:`core.carve.acquire`.

    **The destination is confined to this deployment's evidence directory.** It
    used to be passed through verbatim, and the API has no authentication of any
    kind, so any local process that could open the port could name any path this
    process can write and have an image written over it. Under the runbook's
    former ``sudo python -m api.main`` that process was root, which made it an
    arbitrary-file-write-as-root primitive; the runbook is corrected separately,
    but a path check that only holds when the deployment is configured correctly
    is not a check. A path outside the configured directory is now refused with
    a 400 before anything is opened.

    An image file is read in *this* process: an ``O_RDONLY`` read needs no
    privilege the operator does not already have. A Linux block device is
    ``root:disk 0660``, which the operator cannot open, so it goes through the
    helper's ``acquire_image`` operation, bound to the serial the operator chose.
    """
    from core.carve.acquire import AcquireOptions, acquire, is_win32_device_path
    from core.errors import SanctumError
    from core.ledger.chain import Ledger
    from core.platform.base import normalized_serial

    # A Linux block device is root:disk 0660, so this unprivileged process
    # cannot open it. It is read through the helper, which is the one place
    # that already holds that privilege; the serial binding below applies to it
    # exactly as it does to a raw disk on the other platforms.
    linux_block = sys.platform.startswith("linux") and _is_block_device(body.source)
    raw_device = (
        is_win32_device_path(body.source)
        or linux_block
        or (
            sys.platform == "darwin"
            and body.source.startswith(("/dev/disk", "/dev/rdisk"))
        )
    )
    expected_size = 0
    if is_win32_device_path(body.source) and sys.platform != "win32":
        raise sanctum_error_response(
            "EvidenceIntegrityError",
            f"{body.source} is a Win32 device path, and this host is not Windows",
            "Acquire the device on the Windows machine it is attached to. "
            "Nothing was opened.",
        )
    if raw_device:
        # The device is re-read from the OS here; the size and serial the reader
        # binds to come from that read, and the operator's serial must agree.
        from core.platform import current_adapter

        try:
            device = (
                _linux_block_identity(body.source)
                if linux_block
                else current_adapter().inspect_device(body.source)
            )
        except SanctumError as exc:
            raise sanctum_error_response(
                type(exc).__name__, exc.message, exc.remediation
            ) from exc
        expected = normalized_serial(body.expected_serial)
        if not expected or expected != normalized_serial(device.serial):
            raise sanctum_error_response(
                "EvidenceIntegrityError",
                f"raw acquisition of {body.source} needs the serial of the selected "
                f"disk, and it must match what the disk reports now "
                f"({device.serial or 'no serial'}). Nothing was opened.",
                "Start the acquisition from the Devices screen.",
            )
        expected_size = device.capacity_bytes
        source: Path | str = body.source
    else:
        source = Path(body.source)
        if not source.exists():
            raise sanctum_error_response(
                "EvidenceIntegrityError",
                f"acquisition source not found: {source}",
                "Check the path. Nothing was created.",
            )

    dest = resolve_output_path(services.evidence_dir, body.dest, field="dest")
    dest.parent.mkdir(parents=True, exist_ok=True)

    params = {
        "source": str(source),
        "dest": str(dest),
        "fmt": body.fmt,
        "compression": body.compression,
    }
    ledger = Ledger(
        services.ledger_root,
        tool_version=services.tool_version,
        # The key this deployment signs reports with, when it has one. A chain
        # whose genesis records no fingerprint can never satisfy the report
        # check that compares the two. Looked up rather than created: starting a
        # job must not mint a signing key as a side effect.
        pubkey_fingerprint=_signing_fingerprint(services),
    )

    job_id = f"acquire-{uuid.uuid4().hex[:12]}"

    if linux_block:
        helper_params: dict[str, Any] = {
            "source": str(source),
            "dest": str(dest),
            "fmt": body.fmt,
            "compression": body.compression,
            "expected_serial": body.expected_serial,
            "expected_size": expected_size,
            "operator": resolve_identity(services).labelled_actor(body.operator),
            "ledger_root": str(services.ledger_root),
            "tool_version": services.tool_version,
            "pubkey_fingerprint": _signing_fingerprint(services),
        }

        def helper_factory() -> Any:
            return _helper_job(
                services, "acquire_image", helper_params, job_id=job_id
            )

        _submit(
            services, "acquire", params, helper_factory,
            job_id=job_id, label=body.operator, case_id=body.case_id,
        )
        return _accepted(job_id, "acquire")

    def factory() -> Any:
        return acquire(
            source,
            dest,
            fmt=body.fmt,
            options=AcquireOptions(
                expected_serial=body.expected_serial,
                expected_size=expected_size,
                compression=body.compression,
                # The trusted actor, not body.operator. The engine writes this
                # into the chain, so it has to be the identity the helper
                # resolved rather than the string the browser sent.
                operator=resolve_identity(services).labelled_actor(body.operator),
            ),
            ledger=ledger,
            job_id=job_id,
        )

    _submit(
        services, "acquire", params, factory,
        job_id=job_id, label=body.operator, case_id=body.case_id,
    )
    return _accepted(job_id, "acquire")


# --------------------------------------------------------------------------
# Carve
# --------------------------------------------------------------------------


@router.post("/jobs/carve", response_model=JobAccepted)
def carve_image(
    body: CarveRequest,
    services: AppServices = Depends(get_services),
) -> JobAccepted:
    """Recover objects from an image. Read-only by construction.

    Nothing in the carving path opens the evidence ``O_RDWR``; see
    :mod:`core.carve.evidence`, which declares no write method at all.
    """
    from api.carve_job import carve_generator

    image = Path(body.image)
    if not image.exists():
        raise sanctum_error_response(
            "EvidenceIntegrityError",
            f"evidence not found: {image}",
            "Check the path; nothing was opened.",
        )

    from core.ledger.chain import Ledger

    # Same treatment as the acquisition destination, for the same reason: the
    # API has no authentication, so an unchecked output path is a
    # write-anywhere primitive for any local process that can open the port.
    # Confined to the *recovered* directory rather than the evidence one -
    # recovered objects are derived output and evidence is read-only input, and
    # a recovery that wrote into the tree holding the image it is reading is
    # the one thing this path must never do.
    out_dir = (
        resolve_output_path(services.recovered_dir, body.out_dir, field="out_dir")
        if body.out_dir
        else None
    )

    params = {
        "image": str(image),
        "undelete": body.undelete,
        "carve_signatures": body.carve_signatures,
        "pii_triage": body.pii_triage,
        "media_map": body.media_map,
        "out_dir": str(out_dir) if out_dir else None,
    }

    # Minted here for the same reason the erase routes mint theirs: the ledger
    # entries this run writes have to be keyed to an id GET /jobs/{id} and the
    # report excerpt can find again.
    job_id = f"carve-{uuid.uuid4().hex[:12]}"
    ledger = Ledger(
        services.ledger_root,
        tool_version=services.tool_version,
        pubkey_fingerprint=_signing_fingerprint(services),
    )

    def factory() -> Any:
        return carve_generator(
            image,
            undelete=body.undelete,
            carve_signatures=body.carve_signatures,
            pii_triage=body.pii_triage,
            out_dir=out_dir,
            job_id=job_id,
            ledger=ledger,
            operator=resolve_identity(services).labelled_actor(body.operator),
            case_id=body.case_id,
            work_dir=services.work_dir,
            media_map=body.media_map,
        )

    _submit(
        services, "carve", params, factory,
        job_id=job_id, label=body.operator, case_id=body.case_id,
    )
    return _accepted(job_id, "carve")


# --------------------------------------------------------------------------
# Resume
# --------------------------------------------------------------------------


#: Ledger operation carrying the plan an erase ran under. Read to tell a
#: resumable overwrite from a firmware sanitize.
_PLAN_OPERATION = "erase.preflight.plan"
#: Ledger operation an overwrite appends every checkpoint interval.
_CHECKPOINT_SUFFIX = ".checkpoint"


def _erase_facts(services: AppServices, job_id: str) -> dict[str, Any]:
    """What the chain says about one erase job: its plan and its last checkpoint."""
    from core.ledger.chain import Ledger

    facts: dict[str, Any] = {
        "found": False,
        "method": "",
        "level": "",
        "path": "",
        "serial": "",
        "checkpoint": None,
    }
    try:
        ledger = Ledger(
            services.ledger_root,
            tool_version=services.tool_version,
            pubkey_fingerprint="",
        )
        entries = ledger.entries()
    except (OSError, ValueError):
        return facts

    for entry in entries:
        try:
            params = ledger.params_of(entry)
        except (OSError, ValueError, FileNotFoundError):
            continue
        if params.get("job_id") != job_id:
            continue
        if entry.operation == _PLAN_OPERATION:
            plan = params.get("plan") or {}
            facts["found"] = True
            facts["method"] = str(plan.get("method") or "")
            facts["level"] = str(plan.get("level_requested") or plan.get("level") or "")
            facts["path"] = str(params.get("path") or "")
            facts["serial"] = str(params.get("serial") or "")
        elif entry.operation.endswith(_CHECKPOINT_SUFFIX):
            facts["found"] = True
            facts["checkpoint"] = {
                "offset": int(params.get("offset") or 0),
                "pass_index": int(params.get("pass_index") or 0),
                "seq": entry.seq,
            }
    return facts


def _resume_state(services: AppServices, job_id: str) -> dict[str, Any]:
    """Whether this job can be resumed, and the honest reason when it cannot.

    Resumability is read from the chain, not guessed from the job kind. Three
    outcomes, and the middle one is the one this endpoint exists to state
    plainly rather than hide behind a disabled button:

    * **available** - the chain holds a checkpoint. An overwrite records one
      every :data:`core.erase.drive.CHECKPOINT_INTERVAL_BYTES`, so there is a
      byte offset and a pass index to continue from.
    * **firmware** - the chain holds a plan naming a firmware method and no
      checkpoint. A firmware sanitize is one command the drive executes on its
      own: there is no offset to continue from and no way to ask how far it
      got. Resuming one means running it again from the beginning, and calling
      that "resume" would be a lie about what the device did.
    * **no checkpoint** - an overwrite that stopped before its first
      checkpoint, or a job that is not an erase at all.
    """
    from core.erase import patterns as pattern_mod

    facts = _erase_facts(services, job_id)
    software = {item.value for item in pattern_mod.SOFTWARE_METHODS}

    if facts["checkpoint"] is not None:
        point = facts["checkpoint"]
        return {
            **facts,
            "resumable": True,
            "reason": (
                f"An overwrite checkpoint was recorded at byte {point['offset']} "
                f"of pass {point['pass_index']} (ledger entry {point['seq']}). "
                "The overwrite continues from there rather than restarting."
            ),
        }
    if facts["method"] and facts["method"] not in software:
        return {
            **facts,
            "resumable": False,
            "reason": (
                f"RESUME NOT AVAILABLE: {facts['method']} is a firmware "
                "operation. The drive executes it on its own and reports no "
                "progress, so there is no offset to continue from. Running it "
                "again would start it from the beginning, which is not a "
                "resume and is not offered as one."
            ),
        }
    if not facts["found"]:
        return {
            **facts,
            "resumable": False,
            "reason": (
                f"RESUME NOT AVAILABLE: the chain holds no erase entries for "
                f"job {job_id!r}. There is nothing recorded to continue."
            ),
        }
    return {
        **facts,
        "resumable": False,
        "reason": (
            "RESUME NOT AVAILABLE: this job recorded a plan but never reached "
            "its first checkpoint, so there is no recorded offset to continue "
            "from. Start the erase again."
        ),
    }


@router.get("/jobs/{job_id}/resume")
def resume_state(
    job_id: str, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    """Whether an interrupted erase can be continued, and why or why not."""
    return _resume_state(services, job_id)


@router.post("/jobs/{job_id}/resume", response_model=JobAccepted)
def resume_erase(
    job_id: str,
    body: ResumeEraseRequest,
    services: AppServices = Depends(get_services),
) -> JobAccepted:
    """Continue an interrupted overwrite from its last recorded checkpoint.

    A resume writes to the medium, so it keeps **every** gate of the run it
    continues: the typed serial, which the helper re-checks against the device
    it reads itself, and an approved, unspent authorization. A resume is not a
    lesser operation than the erase it finishes and is not confirmed like one.
    """
    from helper.rpc import RpcError

    state = _resume_state(services, job_id)
    if not state["resumable"]:
        raise sanctum_error_response(
            "ResumeNotAvailable", state["reason"],
            "Start the erase again from the Sanitize screen. Nothing was "
            "written.",
        )
    if not body.typed_serial:
        raise sanctum_error_response(
            "ConfirmationMismatch",
            f"Refusing to resume the erase of {state['path']}: no serial was "
            "typed. A resume writes to the medium and is opt-in twice, like "
            "the run it continues.",
            "Re-read the device serial from the capability report and type it "
            "exactly.",
        )

    params: dict[str, Any] = {
        "path": state["path"],
        "level": state["level"] or "CLEAR",
        "typed_serial": body.typed_serial,
        "ledger_root": str(services.ledger_root),
        "tool_version": services.tool_version,
    }
    try:
        probe = services.helper.call("probe_capabilities", {"path": state["path"]})
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

    if body.typed_serial != str(probe.get("device", {}).get("serial", "")):
        raise sanctum_error_response(
            "ConfirmationMismatch",
            f"The typed serial does not match {state['path']}. Nothing was "
            "erased.",
            "Re-read the device serial from the capability report and type "
            "it exactly.",
        )
    params["authorization"] = _gate_real_erase(
        services,
        authorization_id=body.authorization_id,
        path=state["path"],
        level=params["level"],
        probe=probe,
    )
    params["authorization_dir"] = str(services.state_dir / "authorizations")

    # The *same* job id, deliberately. A resume continues one erasure, and
    # giving it a new id would split one device's account of itself across two
    # ids that nothing links. core.erase.drive.resume looks the checkpoint up
    # by this id.
    def factory() -> Any:
        return _helper_job(services, "resume_erase", params, job_id=job_id)

    services.registry.submit(
        f"resume-{job_id}",
        params,
        factory,
        job_id=f"resume-{job_id}",
        actor=resolve_identity(services).labelled_actor(body.operator),
        actor_basis=resolve_identity(services).basis,
    )
    return _accepted(f"resume-{job_id}", "erase-drive-resume")


# --------------------------------------------------------------------------
# Inspect, stream, cancel
# --------------------------------------------------------------------------


@router.get("/jobs/{job_id}")
def job_status(
    job_id: str, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    """Current state of one job, resumable from the ledger.

    ``ledger_entries`` is what makes a reload survivable beyond this process:
    the registry's buffer lives in memory and dies with the API, while the
    chain is on disk and is what a report is built from.
    """
    from api.durable import status_for

    status = status_for(services, job_id)
    if status is None:
        raise sanctum_error_response(
            "DeviceVanished",
            f"no job {job_id!r} is known to this process, and the chain holds "
            "no finished outcome for it",
            "The id is wrong, or the job never reached a terminal state in any "
            "process. A finished job's result is written into the ledger and "
            "survives a restart; see GET /ledger/verify.",
        )
    status["ledger_entries"] = _ledger_entries_for(services, job_id)
    return status


def _ledger_entries_for(services: AppServices, job_id: str) -> list[dict[str, Any]]:
    """Chain entries belonging to ``job_id``, as plain dicts."""
    import json

    from core.ledger.chain import Ledger

    try:
        ledger = Ledger(
            services.ledger_root,
            tool_version=services.tool_version,
            pubkey_fingerprint="",  # read-only: this never appends
        )
        found: list[dict[str, Any]] = []
        for entry in ledger.entries():
            params = ledger.params_of(entry)
            if params.get("job_id") == job_id:
                found.append(json.loads(entry.model_dump_json()))
        return found
    except (OSError, ValueError):
        return []


@router.get("/jobs/{job_id}/stream")
def job_stream(
    job_id: str, services: AppServices = Depends(get_services)
) -> StreamingResponse:
    """Server-sent events for one job.

    Reconnecting replays the whole buffered run before following it live, so a
    browser that reloaded mid-wipe sees the progress it missed rather than
    picking up blind from wherever it reattached.
    """
    try:
        services.registry.status(job_id)
    except KeyError:
        raise sanctum_error_response(
            "DeviceVanished",
            f"no job {job_id!r} is known to this process",
            "The API was restarted, or the id is wrong.",
        ) from None

    return StreamingResponse(
        progress_events(services.registry, job_id),
        media_type="text/event-stream",
        headers=SSE_HEADERS,
    )


@router.post("/jobs/{job_id}/cancel")
def job_cancel(
    job_id: str, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    """Ask a job to stop at its next yield.

    Cooperative, never a kill. A wipe interrupted between an lseek and a write
    is the state the checkpoint machinery exists to recover from, and creating
    it deliberately would be perverse.
    """
    try:
        return services.registry.cancel(job_id)
    except KeyError:
        raise sanctum_error_response(
            "DeviceVanished",
            f"no job {job_id!r} is known to this process",
            "The API was restarted, or the id is wrong.",
        ) from None
