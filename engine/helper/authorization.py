"""The write seam's own check of an erase, restore or HPA authorization.

Each authorization has a ``kind``. :func:`revalidate_execution` accepts only an
erase authorization (a record with no kind was written before kinds existed and
is an erase one); :func:`revalidate_restore` accepts only a restore one;
:func:`revalidate_hpa` only an ``hpa`` one. An approval of one kind is never
spendable as another.

The API opens, approves and spends an authorization, then hands the helper a
real erase. The helper is the process that would write, so it does not take the
API's word: immediately before the engine starts it re-reads the device and the
backup image from the host and refuses on any difference from what was approved.

What is re-checked, each from a fresh read in *this* process:

* an authorization record exists, is approved, was spent by the API, and says
  exactly what the request says (path, level, identity, plan, backup);
* the device at the path still has the recorded serial, model and size, is not
  the system disk and has no mounted filesystem;
* the capability plan derived now equals the approved plan;
* the backup image still has the recorded size, mtime, ctime and inode and still
  covers the device;
* the authorization has not already been executed: an exclusive-create marker
  ``<id>.executed`` is taken last, so two concurrent attempts cannot both pass.

What this does **not** establish, and the report must not claim: the record and
its markers are files in the API's state directory, so a process able to write
that directory as the operator could forge a consistent set (the helper socket
is what keeps other users out, not this check); the backup is not re-hashed; and
between this check and the first write the engine's own guards (system-disk,
mount, serial re-read) are the only checks left. The window is narrowed, not
removed.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.authorization import (
    AUTH_ID,
    backup_drift,
    build_plan,
    device_identity,
    identity_drift,
    image_drift,
    kind_mismatch,
    plan_drift,
)
from core.backup import BackupRecord, check_record_digest
from core.device.guard import refuse_removed_mode_keys
from core.device.hidden_area_workflow import HpaPlan
from core.device.hidden_area_workflow import plan_digest_of as hpa_plan_digest_of
from core.errors import EvidenceIntegrityError, WorkflowGateRefused
from core.format import FormatPlan
from core.format import plan_digest_of as format_plan_digest_of
from core.models import Device
from core.restore import (
    RestorePlan,
    confirmation_token,
    plan_digest_of,
    plan_restore,
    restore_plan_drift,
    target_identity_from_probe,
)

__all__ = [
    "FormatAuthorized",
    "HpaAuthorized",
    "RestoreAuthorized",
    "revalidate_execution",
    "revalidate_format",
    "revalidate_hpa",
    "revalidate_restore",
]

_HINT = (
    "Open a workflow (POST /workflow/erase-drive), approve it, and execute with "
    "the authorization it returns. Nothing was erased."
)


def _refuse(reasons: list[str]) -> WorkflowGateRefused:
    return WorkflowGateRefused(
        "REFUSED at the write seam: " + "; ".join(reasons) + ". Nothing was erased.",
        why_blocked=reasons,
        remediation=_HINT,
    )


def _fresh_probe(path: str) -> dict[str, Any]:
    """Re-read the device and its capabilities from the host, now.

    Through this host's platform adapter: ``lsblk`` and the hdparm/nvme probe
    on Linux, the Storage module and the controller's IDENTIFY on Windows,
    ``diskutil`` and ``system_profiler`` on macOS.
    """
    from core.platform import current_adapter

    return current_adapter().authorization_probe(path)


def revalidate_execution(
    params: dict[str, Any],
    *,
    probe: Callable[[str], dict[str, Any]] | None = None,
) -> None:
    """Refuse an erase unless its authorization holds up, or return.

    Applies to every erase and resume request: there is no non-writing mode to
    exempt, and a request that still carries a simulation switch is refused
    outright. Raises :class:`~core.errors.WorkflowGateRefused` and does nothing
    else on refusal. On success it has taken the ``.executed`` marker, so a
    second call with the same authorization refuses.
    """
    refuse_removed_mode_keys(params)
    binding = params.get("authorization")
    root_raw = params.get("authorization_dir")
    if not isinstance(binding, dict) or not root_raw:
        raise _refuse(["the request carries no authorization"])
    auth_id = str(binding.get("auth_id", ""))
    if not AUTH_ID.match(auth_id):
        raise _refuse(["the authorization id is malformed"])
    root = Path(str(root_raw))

    try:
        record = json.loads((root / f"{auth_id}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise _refuse([f"authorization {auth_id} does not exist"]) from None
    if not isinstance(record, dict):
        raise _refuse([f"authorization {auth_id} is unreadable"])

    # An erase is authorized only by an erase authorization. Records written
    # before kinds existed carry none and read as erase.
    kind_reasons = kind_mismatch({**record, "auth_id": auth_id}, "erase")
    if kind_reasons:
        raise _refuse(kind_reasons)

    reasons: list[str] = []
    if not record.get("approved_by"):
        reasons.append("no person has approved this authorization")
    if not (root / f"{auth_id}.spent").exists():
        reasons.append("the authorization was not consumed by the API gate")
    path = str(params.get("path", ""))
    level = str(params.get("level", ""))
    for label, asked, held in (
        ("path", path, record.get("path")),
        ("level", level, record.get("level")),
    ):
        if asked != held:
            reasons.append(
                f"the request's {label} {asked!r} is not the approved {held!r}"
            )
    for key in ("device", "backup", "plan"):
        if binding.get(key) != record.get(key):
            reasons.append(f"the request's {key} does not match the recorded approval")
    if reasons:
        raise _refuse(reasons)

    # From here every fact is read from the host, not from either party.
    try:
        fresh = (probe or _fresh_probe)(path)
    except Exception as exc:  # noqa: BLE001 - any failure to re-read is a refusal
        raise _refuse(
            [
                "the device could not be re-read at the write seam "
                f"({type(exc).__name__})"
            ]
        ) from None
    device = fresh.get("device", {})
    now = device_identity(fresh)
    reasons.extend(identity_drift(record["device"], now))
    if device.get("is_system_disk"):
        reasons.append("the device hosts the running root filesystem")
    if device.get("mounted_at"):
        reasons.append(
            "the device has mounted filesystems: " + ", ".join(device["mounted_at"])
        )
    if fresh.get("capabilities") is None:
        reasons.append("the device's capabilities could not be probed")
    reasons.extend(plan_drift(record["plan"], build_plan(fresh, level)))
    if level not in build_plan(fresh, level)["achievable_levels"]:
        reasons.append(f"level {level} is not achievable on the device now")
    reasons.extend(backup_drift(record["backup"], now["size_bytes"]))
    if reasons:
        raise _refuse(reasons)

    # Last, so a refusal above never burns the marker and two racers cannot both
    # pass: exclusive create is atomic on a local filesystem.
    _take_marker(root, auth_id, _refuse)


def _take_marker(
    root: Path, auth_id: str, refuse: Callable[[list[str]], WorkflowGateRefused]
) -> None:
    """Take ``<id>.executed`` by exclusive create, or refuse: one execution each."""
    try:
        fd = os.open(
            root / f"{auth_id}.executed", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
    except FileExistsError:
        raise refuse(
            [
                f"authorization {auth_id} was already executed; it authorizes "
                "one execution"
            ]
        ) from None
    except OSError as exc:
        raise refuse(
            [f"the execution marker could not be taken ({type(exc).__name__})"]
        ) from None
    os.close(fd)


# --------------------------------------------------------------------------
# Restore
# --------------------------------------------------------------------------

_RESTORE_HINT = (
    "Open a restore workflow (POST /workflow/restore), approve it, and execute "
    "with the authorization it returns. Nothing was written."
)


def _refuse_restore(reasons: list[str]) -> WorkflowGateRefused:
    return WorkflowGateRefused(
        "REFUSED at the restore write seam: "
        + "; ".join(reasons)
        + ". Nothing was written.",
        why_blocked=reasons,
        remediation=_RESTORE_HINT,
    )


def _fresh_restore_probe(path: str) -> dict[str, Any]:
    """Re-read the restore target's identity from the host, now.

    Through the platform adapter, so Windows and macOS targets are re-read by
    their own discovery (identity, system disk, mounts), exactly as an erase's.
    """
    from core.platform import current_adapter

    probe = current_adapter().authorization_probe(path)
    return {"device": probe["device"]}


@dataclass(frozen=True)
class RestoreAuthorized:
    """What passed the restore write seam.

    The backup record, the approved plan, and the plan re-derived from this
    process's own read of the target.
    """

    auth_id: str
    record: BackupRecord
    plan: RestorePlan
    fresh: RestorePlan


def revalidate_restore(
    params: dict[str, Any],
    *,
    probe: Callable[[str], dict[str, Any]] | None = None,
) -> RestoreAuthorized:
    """Refuse a restore unless its authorization holds up here, now.

    The restore mirror of :func:`revalidate_execution`. Every restore needs an
    opened record of kind ``restore``, a target that re-plans without drift, a
    recorded approval, the API's ``.spent`` marker, and a typed serial equal to
    the one this process just read; it takes the ``.executed`` marker last. A
    request that still carries a simulation switch is refused outright.

    Every fact about the target and the image is read from the host here. The
    request's binding is compared with the stored record, never trusted.
    """
    refuse_removed_mode_keys(params)
    binding = params.get("authorization")
    root_raw = params.get("authorization_dir")
    if not isinstance(binding, dict) or not root_raw:
        raise _refuse_restore(["the request carries no restore authorization"])
    auth_id = str(binding.get("auth_id", ""))
    if not AUTH_ID.match(auth_id):
        raise _refuse_restore(["the authorization id is malformed"])
    root = Path(str(root_raw))
    try:
        record = json.loads((root / f"{auth_id}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise _refuse_restore([f"authorization {auth_id} does not exist"]) from None
    if not isinstance(record, dict):
        raise _refuse_restore([f"authorization {auth_id} is unreadable"])
    kind_reasons = kind_mismatch({**record, "auth_id": auth_id}, "restore")
    if kind_reasons:
        raise _refuse_restore(kind_reasons)

    reasons: list[str] = []
    if not record.get("approved_by"):
        reasons.append("no person has approved this restore")
    if not (root / f"{auth_id}.spent").exists():
        reasons.append("the authorization was not consumed by the API gate")
    path = str(params.get("path", ""))
    if path != record.get("path"):
        reasons.append(
            f"the request's target {path!r} is not the approved "
            f"{record.get('path')!r}"
        )
    for key in ("device", "backup", "plan"):
        if binding.get(key) != record.get(key):
            reasons.append(f"the request's {key} does not match the recorded approval")
    if reasons:
        raise _refuse_restore(reasons)

    try:
        backup = BackupRecord.model_validate(record["backup"]["record"])
        check_record_digest(backup)
        approved = RestorePlan.model_validate(record["plan"])
    except (KeyError, TypeError, ValueError, EvidenceIntegrityError):
        raise _refuse_restore(
            ["the recorded backup or plan is unreadable or was altered"]
        ) from None
    if approved.plan_digest != plan_digest_of(approved):
        reasons.append("the approved restore plan was altered after it was made")
    if approved.backup_record_digest != backup.record_digest:
        reasons.append("the approved plan names a different backup record")

    # From here every fact is read from the host, not from either party.
    try:
        fresh_probe = (probe or _fresh_restore_probe)(path)
        fresh = plan_restore(backup, target_identity_from_probe(fresh_probe))
    except Exception as exc:  # noqa: BLE001 - any failure to re-read is a refusal
        raise _refuse_restore(
            [
                "the target could not be re-read at the write seam "
                f"({type(exc).__name__})"
            ]
        ) from None
    reasons.extend(identity_drift(record["device"], device_identity(fresh_probe)))
    reasons.extend(restore_plan_drift(approved, fresh))
    reasons.extend(image_drift(record["backup"]))
    typed = str(params.get("typed_serial") or "").strip()
    token = confirmation_token(fresh.target).strip()
    if not typed:
        reasons.append("no serial was typed; a restore is opt-in twice")
    elif typed.casefold() != token.casefold():
        reasons.append(
            "the typed serial does not match the target re-read at the write seam"
        )
    if reasons:
        # De-duplicated, order kept: identity and plan drift can name one change.
        raise _refuse_restore(list(dict.fromkeys(reasons)))

    _take_marker(root, auth_id, _refuse_restore)
    return RestoreAuthorized(auth_id=auth_id, record=backup, plan=approved, fresh=fresh)


# --------------------------------------------------------------------------
# HPA change
# --------------------------------------------------------------------------

_HPA_HINT = (
    "Open an HPA/DCO workflow (POST /workflow/hidden-area), approve it, and "
    "execute with the authorization it returns. Nothing was sent to the drive."
)


def _refuse_hpa(reasons: list[str]) -> WorkflowGateRefused:
    return WorkflowGateRefused(
        "REFUSED at the HPA write seam: "
        + "; ".join(reasons)
        + ". Nothing was sent to the drive.",
        why_blocked=reasons,
        remediation=_HPA_HINT,
    )


def _fresh_hpa_probe(path: str) -> dict[str, Any]:
    """Re-read the device's identity, system-disk and mount state, now."""
    from core.platform import current_adapter

    probe = current_adapter().authorization_probe(path)
    return {"device": probe["device"]}


@dataclass(frozen=True)
class HpaAuthorized:
    """What passed the HPA write seam: the approved plan and a fresh device read."""

    auth_id: str
    plan: HpaPlan
    device: Device


def revalidate_hpa(
    params: dict[str, Any],
    *,
    probe: Callable[[str], dict[str, Any]] | None = None,
) -> HpaAuthorized:
    """Refuse an HPA change unless its authorization holds up here, now.

    Only a record of kind ``hpa`` is accepted: an erase or restore approval is
    never spendable as a change to the drive's configuration, nor an HPA one as
    either of those. Every change needs an opened record whose plan still
    matches the device, a recorded approval, the API's ``.spent`` marker, a
    backup image unchanged since the approval, and a typed serial equal to the
    one this process just read; it takes the single-use ``.executed`` marker
    last. A request that still carries a simulation switch is refused outright.

    The drive's maxima are *not* re-read here: the engine
    (:func:`core.device.hidden_area_workflow.execute`) re-discovers them through
    the platform backend immediately before the command and refuses a stale
    plan.
    """
    refuse_removed_mode_keys(params)
    binding = params.get("authorization")
    root_raw = params.get("authorization_dir")
    if not isinstance(binding, dict) or not root_raw:
        raise _refuse_hpa(["the request carries no HPA authorization"])
    auth_id = str(binding.get("auth_id", ""))
    if not AUTH_ID.match(auth_id):
        raise _refuse_hpa(["the authorization id is malformed"])
    root = Path(str(root_raw))
    try:
        record = json.loads((root / f"{auth_id}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise _refuse_hpa([f"authorization {auth_id} does not exist"]) from None
    if not isinstance(record, dict):
        raise _refuse_hpa([f"authorization {auth_id} is unreadable"])
    kind_reasons = kind_mismatch({**record, "auth_id": auth_id}, "hpa")
    if kind_reasons:
        raise _refuse_hpa(kind_reasons)

    reasons: list[str] = []
    backup = record.get("backup") or {}
    if not record.get("approved_by"):
        reasons.append("no person has approved this HPA change")
    if not (root / f"{auth_id}.spent").exists():
        reasons.append("the authorization was not consumed by the API gate")
    if not backup.get("backup_id"):
        reasons.append("no verified backup is bound to this authorization")
    path = str(params.get("path", ""))
    if path != record.get("path"):
        reasons.append(
            f"the request's device {path!r} is not the approved "
            f"{record.get('path')!r}"
        )
    for key in ("device", "backup", "plan"):
        if binding.get(key) != record.get(key):
            reasons.append(f"the request's {key} does not match the recorded approval")
    if reasons:
        raise _refuse_hpa(reasons)

    try:
        plan = HpaPlan.model_validate(record["plan"])
    except (KeyError, TypeError, ValueError):
        raise _refuse_hpa(["the recorded HPA plan is unreadable"]) from None
    if plan.plan_digest != hpa_plan_digest_of(plan):
        reasons.append("the approved HPA plan was altered after it was made")
    reasons.extend(plan.blocking)

    # From here every fact is read from the host, not from either party.
    try:
        fresh = (probe or _fresh_hpa_probe)(path)
        device = Device.model_validate(fresh["device"])
    except Exception as exc:  # noqa: BLE001 - any failure to re-read is a refusal
        raise _refuse_hpa(
            [
                "the device could not be re-read at the write seam "
                f"({type(exc).__name__})"
            ]
        ) from None
    reasons.extend(identity_drift(record["device"], device_identity(fresh)))
    if device.is_system_disk:
        reasons.append("the device hosts the running system")
    if device.mounted_at:
        reasons.append(
            "the device has mounted filesystems: " + ", ".join(device.mounted_at)
        )
    if backup.get("backup_id"):
        reasons.extend(image_drift(backup))
    typed = str(params.get("typed_serial") or "").strip()
    serial = device.serial.strip()
    if not typed:
        reasons.append("no serial was typed; an HPA change is opt-in twice")
    elif not serial or typed.casefold() != serial.casefold():
        reasons.append(
            "the typed serial does not match the device re-read at the write seam"
        )
    if reasons:
        raise _refuse_hpa(list(dict.fromkeys(reasons)))

    _take_marker(root, auth_id, _refuse_hpa)
    return HpaAuthorized(auth_id=auth_id, plan=plan, device=device)


# --------------------------------------------------------------------------
# Format
# --------------------------------------------------------------------------

_FORMAT_HINT = (
    "Open a format workflow (POST /workflow/format), approve it, and execute "
    "with the authorization it returns. Nothing was written to the device."
)


def _refuse_format(reasons: list[str]) -> WorkflowGateRefused:
    return WorkflowGateRefused(
        "REFUSED at the format write seam: "
        + "; ".join(reasons)
        + ". Nothing was written to the device.",
        why_blocked=reasons,
        remediation=_FORMAT_HINT,
    )


@dataclass(frozen=True)
class FormatAuthorized:
    """What passed the format write seam: the approved plan and a fresh device read."""

    auth_id: str
    plan: FormatPlan
    device: Device


def revalidate_format(
    params: dict[str, Any],
    *,
    probe: Callable[[str], dict[str, Any]] | None = None,
) -> FormatAuthorized:
    """Refuse a format unless its authorization holds up here, now.

    Only a record of kind ``format`` is accepted, and a format record is never
    spendable as any other kind. The record must be approved by a person and
    consumed by the API gate, name the device and plan the request names, carry
    a plan whose digest still matches, and describe a device that a fresh read
    in this process still shows with the same identity, unmounted and not the
    system disk. The typed serial must equal the serial this process just read.
    The single-use ``.executed`` marker is taken last. A request that still
    carries a simulation switch is refused outright.

    No backup is bound: the device holds nothing from before its erase. That the
    erase happened is checked at the API gate, from the ledger; the helper does
    not read the ledger.
    """
    refuse_removed_mode_keys(params)
    binding = params.get("authorization")
    root_raw = params.get("authorization_dir")
    if not isinstance(binding, dict) or not root_raw:
        raise _refuse_format(["the request carries no format authorization"])
    auth_id = str(binding.get("auth_id", ""))
    if not AUTH_ID.match(auth_id):
        raise _refuse_format(["the authorization id is malformed"])
    root = Path(str(root_raw))
    try:
        record = json.loads((root / f"{auth_id}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise _refuse_format([f"authorization {auth_id} does not exist"]) from None
    if not isinstance(record, dict):
        raise _refuse_format([f"authorization {auth_id} is unreadable"])
    kind_reasons = kind_mismatch({**record, "auth_id": auth_id}, "format")
    if kind_reasons:
        raise _refuse_format(kind_reasons)

    reasons: list[str] = []
    if not record.get("approved_by"):
        reasons.append("no person has approved this format")
    if not (root / f"{auth_id}.spent").exists():
        reasons.append("the authorization was not consumed by the API gate")
    path = str(params.get("path", ""))
    if path != record.get("path"):
        reasons.append(
            f"the request's device {path!r} is not the approved {record.get('path')!r}"
        )
    for key in ("device", "plan"):
        if binding.get(key) != record.get(key):
            reasons.append(f"the request's {key} does not match the recorded approval")
    if reasons:
        raise _refuse_format(reasons)

    try:
        plan = FormatPlan.model_validate(record["plan"])
    except (KeyError, TypeError, ValueError):
        raise _refuse_format(["the recorded format plan is unreadable"]) from None
    if plan.plan_digest != format_plan_digest_of(plan):
        reasons.append("the approved format plan was altered after it was made")
    reasons.extend(plan.blocking)

    try:
        fresh = (probe or _fresh_probe)(path)
        device = Device.model_validate(fresh["device"])
    except Exception as exc:  # noqa: BLE001 - any failure to re-read is a refusal
        raise _refuse_format(
            [
                "the device could not be re-read at the write seam "
                f"({type(exc).__name__})"
            ]
        ) from None
    reasons.extend(identity_drift(record["device"], device_identity(fresh)))
    if device.is_system_disk:
        reasons.append("the device hosts the running system")
    if device.mounted_at:
        reasons.append(
            "the device has mounted filesystems: " + ", ".join(device.mounted_at)
        )
    typed = str(params.get("typed_serial") or "").strip()
    serial = device.serial.strip()
    if not typed:
        reasons.append("no serial was typed; a format is opt-in twice")
    elif not serial or typed.casefold() != serial.casefold():
        reasons.append(
            "the typed serial does not match the device re-read at the write seam"
        )
    if reasons:
        raise _refuse_format(list(dict.fromkeys(reasons)))

    _take_marker(root, auth_id, _refuse_format)
    return FormatAuthorized(auth_id=auth_id, plan=plan, device=device)
