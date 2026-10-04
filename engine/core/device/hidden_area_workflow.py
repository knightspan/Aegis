"""The guarded HPA/DCO workflow. The only code that changes a drive's HPA.

An ordinary erase never unlocks or modifies a Host Protected Area or a Device
Configuration Overlay: it erases the accessible range, reports the hidden bytes
it could not reach, and points here. This module is the explicit, separately
authorized path that widens the accessible maximum to the native maximum, so a
later erase can reach the sectors an HPA was hiding.

What it does
------------
* **Discovers** the native and accessible maxima through a platform backend:
  ``hdparm -N`` and ``hdparm --dco-identify`` on Linux; IDENTIFY DEVICE, READ
  NATIVE MAX ADDRESS EXT and DEVICE CONFIGURATION IDENTIFY through
  ``IOCTL_ATA_PASS_THROUGH`` on Windows. A reading that fails the plausibility
  checks is rejected, never acted on.
* **Plans** one change: SET MAX ADDRESS to the native maximum. The plan names
  the exact command, the original values, and whether the change is volatile.
  **Volatile is the default**: the drive forgets it at the next power cycle and
  returns to its original accessible maximum. A permanent change is made only
  when it was explicitly requested and approved.
* **Executes** the plan behind two opt-ins (a recorded human approval, and the
  device serial typed by hand), after re-discovering the drive immediately
  before the command and refusing if anything drifted from the plan. The drive is read
  again afterwards and the change is verified, not assumed.

What it never does
------------------
* It never issues DCO RESTORE or DCO SET. The DCO is *discovered* (DEVICE
  CONFIGURATION IDENTIFY) and reported; sectors a DCO hides beyond the native
  maximum stay hidden, and the result says so.
* It never erases. Widening the accessible range exposes whatever the hidden
  sectors hold; sanitizing them is a separate erase.
* It never acts through a USB or MMC bridge, or on an NVMe device (HPA and DCO
  are ATA features). The refusal is reported, not guessed around.

The state machine at the top is pure, like :mod:`core.workflow`: a model of
where a change is and why it cannot move on, never an actor.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Generator
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol

import structlog
from pydantic import BaseModel, ConfigDict

from core.device import guard
from core.device._sysio import SystemProbe
from core.errors import (
    ConfirmationMismatch,
    MountedRefused,
    PlatformUnsupported,
    SanctumError,
    UnsupportedCapability,
    WorkflowGateRefused,
)
from core.ledger.canon import canonical_bytes
from core.models import Device, Progress

if TYPE_CHECKING:  # pragma: no cover - typing only
    from core.backup import BackupRecord, BackupVerification
    from core.device.win.disk import WindowsDisk
    from core.device.win.native import NativeApi

__all__ = [
    "DCO_NEVER_MODIFIED",
    "HPA_PLAN_SCHEMA",
    "TRANSITIONS",
    "HiddenAreaBackend",
    "HiddenAreaState",
    "HpaDeviceIdentity",
    "HpaFacts",
    "HpaLedger",
    "HpaPlan",
    "HpaResult",
    "HpaState",
    "HpaStatus",
    "IllegalTransition",
    "LinuxHpaBackend",
    "WindowsHpaBackend",
    "advance",
    "backup_problems",
    "derive",
    "execute",
    "hidden_area_state",
    "operation_text",
    "plan_digest_of",
    "plan_drift",
    "plan_hpa_change",
    "platform_backend",
    "plausibility_problem",
]

logger = structlog.get_logger(__name__)

HPA_PLAN_SCHEMA = "sanctum.hpa-plan/1"

#: How far a reading may sit from the OS-reported capacity before it is
#: rejected. The same factor :mod:`core.device.hidden_areas` applies: an HPA
#: hides a slice of a drive, not 90% of it.
SANITY_FACTOR = 10

#: Transports where a SET MAX command is never sent. A bridge may answer,
#: refuse or invent a reply, and nothing distinguishes those cases.
_BRIDGED = frozenset({"usb", "mmc"})

DCO_NEVER_MODIFIED = (
    "The DCO was discovered only (DEVICE CONFIGURATION IDENTIFY). DCO RESTORE "
    "and DCO SET are never issued by this build: a DCO change can make a drive "
    "report a different geometry and cannot be undone by a power cycle. Sectors "
    "a DCO hides beyond the native maximum stay hidden."
)

_NOT_AN_ERASE = (
    "This workflow does not erase anything. The sectors the HPA was hiding are "
    "now addressable and still hold whatever they held; sanitize them with an "
    "ordinary erase of the whole, now wider, device."
)


# ==========================================================================
# State machine. Pure: no I/O, no device, no approval recorded here.
# ==========================================================================


class HpaState(StrEnum):
    """Where an HPA change is. Declaration order is the happy path."""

    DISCOVERED = "DISCOVERED"
    ANALYZED = "ANALYZED"
    BACKUP_VERIFIED = "BACKUP_VERIFIED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    PLAN_READY = "PLAN_READY"
    MODIFYING = "MODIFYING"
    VERIFYING = "VERIFYING"
    COMPLETE = "COMPLETE"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


_S = HpaState

#: The states before anything is sent to the drive, in order.
_PRE_EXECUTION = (
    _S.DISCOVERED,
    _S.ANALYZED,
    _S.BACKUP_VERIFIED,
    _S.APPROVAL_REQUIRED,
    _S.PLAN_READY,
)

#: Every legal edge. Anything absent is refused by :func:`advance`. ``BLOCKED``
#: is reachable from every pre-execution state; ``FAILED`` only from the two
#: states in which the drive is being changed or read back.
TRANSITIONS: dict[HpaState, frozenset[HpaState]] = {
    _S.DISCOVERED: frozenset({_S.ANALYZED, _S.BLOCKED}),
    _S.ANALYZED: frozenset({_S.BACKUP_VERIFIED, _S.BLOCKED}),
    _S.BACKUP_VERIFIED: frozenset({_S.APPROVAL_REQUIRED, _S.BLOCKED, _S.ANALYZED}),
    _S.APPROVAL_REQUIRED: frozenset({_S.PLAN_READY, _S.BLOCKED, _S.ANALYZED}),
    _S.PLAN_READY: frozenset({_S.MODIFYING, _S.BLOCKED, _S.ANALYZED}),
    _S.MODIFYING: frozenset({_S.VERIFYING, _S.FAILED}),
    _S.VERIFYING: frozenset({_S.COMPLETE, _S.FAILED}),
    _S.BLOCKED: frozenset({_S.DISCOVERED}),
    _S.COMPLETE: frozenset(),
    _S.FAILED: frozenset(),
}

_NEXT_ACTION: dict[HpaState, str] = {
    _S.DISCOVERED: (
        "read the drive's native and accessible maxima (read-only) and check "
        "them for plausibility"
    ),
    _S.ANALYZED: (
        "record a backup of at least the accessible range and verify it "
        "(POST /workflow/backup, then /workflow/backup/{id}/verify)"
    ),
    _S.BACKUP_VERIFIED: "generate the HPA plan for review",
    _S.APPROVAL_REQUIRED: (
        "a person reviews the plan - the exact command, the original values, "
        "volatile or permanent - and records an explicit approval with the "
        "device serial typed; this software cannot approve on anyone's behalf"
    ),
    _S.PLAN_READY: (
        "run the change on the real drive; it needs the device serial typed by "
        "hand"
    ),
    _S.MODIFYING: "wait for SET MAX ADDRESS to return; do not disconnect the device",
    _S.VERIFYING: "wait for the drive to be read back",
    _S.COMPLETE: (
        "read the result and its limitations, then erase the whole device; a "
        "volatile change is lost at the next power cycle"
    ),
    _S.BLOCKED: (
        "resolve every reason listed, by hand, then discover the drive again; "
        "nothing here unmounts, elevates or retries on its own"
    ),
    _S.FAILED: (
        "read the failure; re-discover the drive before relying on its "
        "accessible maximum, which is unknown until it is read again"
    ),
}


class IllegalTransition(ValueError):
    """A transition that is not an edge, or that the facts do not support."""


@dataclass(frozen=True)
class HpaFacts:
    """What the gates have established. Every field defaults to "not yet"."""

    device_present: bool = False
    #: A system-disk or mounted-filesystem refusal, verbatim, or empty.
    device_refusal: str = ""
    #: Why the drive could not be interrogated (a bridge, NVMe, no privilege).
    discovery_refusal: str = ""
    discovered: bool = False
    plausible: bool = False
    plausibility_reason: str = ""
    hidden_area_present: bool = False
    backup_verified: bool = False
    #: Why the backup gate is not met, verbatim.
    backup_problems: tuple[str, ...] = ()
    plan_generated: bool = False
    #: The plan's own blocking list, plus any drift found since, verbatim.
    plan_blocking: tuple[str, ...] = ()
    #: Recorded by a caller after a person approved. Never inferred.
    human_approved: bool = False
    modifying: bool = False
    verifying: bool = False
    complete: bool = False
    #: A failure description, or empty.
    failed: str = ""


@dataclass(frozen=True)
class HpaStatus:
    """The derived state, why it cannot move on, and what a person does next."""

    state: HpaState
    why_blocked: tuple[str, ...]
    next_action: str

    @property
    def allowed_next(self) -> frozenset[HpaState]:
        return TRANSITIONS[self.state]

    def as_dict(self) -> dict[str, Any]:
        """Plain JSON-able form for reports, plans and screens."""
        return {
            "state": self.state.value,
            "why_blocked": list(self.why_blocked),
            "next_action": self.next_action,
            "allowed_next": sorted(state.value for state in self.allowed_next),
        }


def _status(state: HpaState, *reasons: str) -> HpaStatus:
    return HpaStatus(
        state=state,
        why_blocked=tuple(reason for reason in reasons if reason),
        next_action=_NEXT_ACTION[state],
    )


def derive(facts: HpaFacts) -> HpaStatus:
    """The state these facts put an HPA change in. Pure; earliest unmet gate wins."""
    if facts.failed:
        return _status(_S.FAILED, facts.failed)
    if facts.complete:
        return _status(_S.COMPLETE)
    if facts.verifying:
        return _status(_S.VERIFYING)
    if facts.modifying:
        return _status(_S.MODIFYING)

    if not facts.device_present:
        return _status(_S.BLOCKED, "the device is not present at the path given")
    if facts.device_refusal:
        return _status(_S.BLOCKED, facts.device_refusal)
    if facts.discovery_refusal:
        return _status(_S.BLOCKED, facts.discovery_refusal)
    if not facts.discovered:
        return _status(_S.DISCOVERED)
    if not facts.plausible:
        return _status(
            _S.BLOCKED,
            facts.plausibility_reason
            or "the drive's native maximum reading did not pass the plausibility "
            "checks",
        )
    if not facts.hidden_area_present:
        return _status(
            _S.BLOCKED,
            "the accessible maximum already equals the native maximum: there is "
            "no HPA to remove and nothing to change",
        )
    if not facts.backup_verified:
        return _status(
            _S.ANALYZED,
            *(
                facts.backup_problems
                or ("no verified backup covers the accessible range",)
            ),
        )
    if not facts.plan_generated:
        return _status(_S.BACKUP_VERIFIED)
    if facts.plan_blocking:
        return _status(_S.BLOCKED, *facts.plan_blocking)
    if not facts.human_approved:
        return _status(
            _S.APPROVAL_REQUIRED,
            "no person has approved this plan; approval is required before the "
            "drive's configuration is changed",
        )
    return _status(_S.PLAN_READY)


def _permits(target: HpaState, derived: HpaState) -> bool:
    if target in {_S.BLOCKED, _S.FAILED}:
        return True  # moving to a safer or a truthful state is always allowed
    if target is _S.MODIFYING:
        return derived is _S.PLAN_READY
    if target in _PRE_EXECUTION and derived in _PRE_EXECUTION:
        # The facts must support at least the target. Being further along than
        # the step being named is fine; being short of it is not.
        return _PRE_EXECUTION.index(target) <= _PRE_EXECUTION.index(derived)
    return derived is target


def advance(current: HpaState, target: HpaState, facts: HpaFacts) -> HpaState:
    """Move from ``current`` to ``target``, or raise :class:`IllegalTransition`.

    The edge must exist and the facts must support it. There is no edge into
    ``MODIFYING`` except from ``PLAN_READY``, and it is refused unless the
    facts derive ``PLAN_READY``. Returns ``target``.
    """
    if target not in TRANSITIONS[current]:
        raise IllegalTransition(
            f"{current.value} -> {target.value} is not a legal transition; "
            f"from {current.value} the next states are "
            f"{sorted(state.value for state in TRANSITIONS[current]) or 'none'}"
        )
    status = derive(facts)
    if not _permits(target, status.state):
        reasons = "; ".join(status.why_blocked) or "no reason recorded"
        raise IllegalTransition(
            f"{current.value} -> {target.value} refused: the facts put this "
            f"change in {status.state.value} ({reasons})"
        )
    return target


# ==========================================================================
# Models
# ==========================================================================


class HiddenAreaState(BaseModel):
    """One reading of a drive's maxima, and whether it may be believed.

    LBAs are *maximum addresses* (the highest addressable LBA), not counts:
    a drive whose accessible max LBA is 99 exposes 100 sectors.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    native_max_lba: int
    accessible_max_lba: int
    sector_bytes: int
    #: What the operating system says the device's length is, in bytes.
    reported_capacity_bytes: int
    hpa_supported: bool
    dco_supported: bool
    #: The factory maximum DEVICE CONFIGURATION IDENTIFY reported, if read.
    dco_max_lba: int | None = None
    #: Bytes between the accessible and the native maximum. Zero when the
    #: reading is implausible: an unbelievable number measures nothing.
    hidden_bytes: int
    #: Bytes a DCO hides beyond the native maximum, which this build never
    #: exposes.
    dco_hidden_bytes: int = 0
    #: The commands the reading came from, verbatim.
    source_commands: tuple[str, ...]
    plausible: bool
    plausibility_reason: str = ""
    limitations: tuple[str, ...] = ()

    @property
    def accessible_bytes(self) -> int:
        return (self.accessible_max_lba + 1) * self.sector_bytes


def plausibility_problem(
    *,
    native_max_lba: int,
    accessible_max_lba: int,
    reported_capacity_bytes: int,
    sector_bytes: int,
) -> str | None:
    """Why this reading must not be believed, or ``None`` if it may be.

    A native maximum *smaller* than the accessible one is impossible on a
    working drive; one more than :data:`SANITY_FACTOR` times the size the
    operating system reports is a bridge's invention or a parse fault, not an
    HPA. The same rule rejects an accessible maximum an order of magnitude
    away from the OS size. A native maximum *equal* to the accessible one is a
    believable reading of a drive with no HPA; the plan refuses it separately.
    """
    if sector_bytes <= 0 or native_max_lba <= 0 or accessible_max_lba <= 0:
        return (
            f"the drive reported native max LBA {native_max_lba} and accessible "
            f"max LBA {accessible_max_lba} with {sector_bytes}-byte sectors; a "
            "zero is not a measurement, so no HPA determination was made"
        )
    if native_max_lba < accessible_max_lba:
        return (
            f"the native max LBA {native_max_lba} is not larger than the "
            f"accessible max LBA {accessible_max_lba}; a drive cannot address "
            "more than its native maximum, so the reading was rejected"
        )
    if reported_capacity_bytes <= 0:
        return (
            "the operating system reported no capacity for the device, so the "
            "reading could not be checked and was rejected"
        )
    native_bytes = (native_max_lba + 1) * sector_bytes
    accessible_bytes = (accessible_max_lba + 1) * sector_bytes
    if native_bytes > reported_capacity_bytes * SANITY_FACTOR:
        return (
            f"the native maximum ({native_bytes} bytes) is more than "
            f"{SANITY_FACTOR}x the {reported_capacity_bytes} bytes the operating "
            "system reports; the reading was rejected as implausible"
        )
    if not (
        reported_capacity_bytes // SANITY_FACTOR
        <= accessible_bytes
        <= reported_capacity_bytes * SANITY_FACTOR
    ):
        return (
            f"the accessible maximum ({accessible_bytes} bytes) is more than "
            f"{SANITY_FACTOR}x away from the {reported_capacity_bytes} bytes the "
            "operating system reports; the reading was rejected as implausible"
        )
    return None


def hidden_area_state(
    *,
    path: str,
    native_max_lba: int,
    accessible_max_lba: int,
    sector_bytes: int,
    reported_capacity_bytes: int,
    hpa_supported: bool,
    dco_supported: bool,
    dco_max_lba: int | None,
    source_commands: tuple[str, ...],
    limitations: tuple[str, ...] = (),
) -> HiddenAreaState:
    """Build a :class:`HiddenAreaState`, computing hidden bytes and plausibility."""
    problem = plausibility_problem(
        native_max_lba=native_max_lba,
        accessible_max_lba=accessible_max_lba,
        reported_capacity_bytes=reported_capacity_bytes,
        sector_bytes=sector_bytes,
    )
    plausible = problem is None
    hidden = (
        (native_max_lba - accessible_max_lba) * sector_bytes if plausible else 0
    )
    dco_hidden = 0
    notes = list(limitations)
    if dco_max_lba is not None and plausible:
        if dco_max_lba > native_max_lba:
            dco_hidden = (dco_max_lba - native_max_lba) * sector_bytes
            notes.append(
                f"The DCO reports a factory maximum of LBA {dco_max_lba}, "
                f"{dco_hidden} bytes beyond the native maximum. "
                + DCO_NEVER_MODIFIED
            )
    return HiddenAreaState(
        path=path,
        native_max_lba=native_max_lba,
        accessible_max_lba=accessible_max_lba,
        sector_bytes=sector_bytes,
        reported_capacity_bytes=reported_capacity_bytes,
        hpa_supported=hpa_supported,
        dco_supported=dco_supported,
        dco_max_lba=dco_max_lba,
        hidden_bytes=hidden,
        dco_hidden_bytes=dco_hidden,
        source_commands=source_commands,
        plausible=plausible,
        plausibility_reason=problem or "",
        limitations=tuple(notes),
    )


class HpaDeviceIdentity(BaseModel):
    """The device a plan is bound to. Any difference at execution refuses."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    serial: str
    model: str
    size_bytes: int


class HpaPlan(BaseModel):
    """The one change a person approves. Sealed by :func:`plan_digest_of`."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = HPA_PLAN_SCHEMA
    platform: Literal["linux", "windows"]
    device: HpaDeviceIdentity
    original_native_max_lba: int
    original_accessible_max_lba: int
    original_dco_max_lba: int | None
    sector_bytes: int
    hidden_bytes: int
    #: Always the native maximum: the plan exposes the HPA, never more.
    requested_accessible_max_lba: int
    #: True: SET MAX lasts until the next power cycle. False only when a
    #: permanent change was explicitly requested.
    volatile: bool = True
    #: The exact command that would be sent.
    operation: str
    dco_action: str = (
        "none: DEVICE CONFIGURATION IDENTIFY only; DCO RESTORE and DCO SET are "
        "never issued"
    )
    blocking: tuple[str, ...]
    limitations: tuple[str, ...]
    created_at: datetime
    #: SHA-256 over the canonical JSON of every other field.
    plan_digest: str = ""


class HpaResult(BaseModel):
    """What an execution did, and whether the drive confirmed it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    job_id: str
    plan_digest: str
    outcome: Literal["COMPLETE", "FAILED"]
    operation: str
    volatile: bool
    original_native_max_lba: int
    original_accessible_max_lba: int
    original_dco_max_lba: int | None
    requested_accessible_max_lba: int
    #: The reading taken immediately before the command.
    pre_state: HiddenAreaState
    #: The reading taken after it. ``None`` when the drive could not be read
    #: back.
    post_state: HiddenAreaState | None
    #: True only when the re-read accessible maximum equals the requested one
    #: and the native maximum is unchanged.
    verification_passed: bool
    verification_notes: tuple[str, ...]
    #: ``unknown`` when the command was sent and the drive was not read back.
    device_modified: Literal["no", "yes", "unknown"]
    started_at: datetime
    finished_at: datetime
    limitations: tuple[str, ...]


def plan_digest_of(plan: HpaPlan) -> str:
    """SHA-256 of the canonical bytes of every field but the digest itself."""
    body = plan.model_dump(mode="json", exclude={"plan_digest"})
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def operation_text(
    platform: Literal["linux", "windows"], path: str, lba: int, *, volatile: bool
) -> str:
    """The exact command a plan would send, as a person reads it.

    ``hdparm -N`` takes a sector *count*, so it is given ``lba + 1``; a ``p``
    prefix makes the setting permanent. SET MAX ADDRESS EXT takes the maximum
    LBA itself, with the volatile bit (VV) in the Count field.
    """
    if platform == "linux":
        count = lba + 1
        return f"hdparm -N {'' if volatile else 'p'}{count} {path}"
    return (
        f"SET MAX ADDRESS EXT (37h) LBA={lba} VV={1 if volatile else 0} through "
        f"IOCTL_ATA_PASS_THROUGH on {path}, immediately after READ NATIVE MAX "
        "ADDRESS EXT (27h)"
    )


def _plan_limitations(
    platform: Literal["linux", "windows"], state: HiddenAreaState, volatile: bool
) -> list[str]:
    notes = list(state.limitations)
    if volatile:
        notes.append(
            "VOLATILE: the new accessible maximum lasts until the drive is next "
            "power-cycled. The drive then returns to accessible max LBA "
            f"{state.accessible_max_lba} and the formerly hidden sectors are "
            "hidden again. Erase them before the drive loses power."
        )
    else:
        notes.append(
            "PERMANENT: the new accessible maximum survives power cycles. The "
            "HPA is gone until someone sets it again; to restore it, issue SET "
            f"MAX ADDRESS with LBA {state.accessible_max_lba} (non-volatile)."
        )
    if not any(DCO_NEVER_MODIFIED in note for note in notes):
        notes.append(DCO_NEVER_MODIFIED)
    notes.append(_NOT_AN_ERASE)
    if platform == "linux":
        notes.append(
            "The Linux kernel keeps the device size it read at attach time. "
            "Rescan or re-attach the device, and re-enumerate it, before an "
            "erase, or the erase still covers only the old accessible range."
        )
    return notes


def plan_hpa_change(
    device: Device,
    state: HiddenAreaState,
    *,
    platform: Literal["linux", "windows"],
    volatile: bool = True,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> HpaPlan:
    """The plan to expose the HPA of ``device``: accessible max := native max.

    Pure. Always returns a plan; one that must not run carries ``blocking``
    reasons, which :func:`execute` refuses on. ``volatile`` defaults to True;
    a permanent change is planned only when the caller asks for it.
    """
    blocking: list[str] = []
    if device.is_system_disk:
        blocking.append(f"{device.path} holds the running system")
    if device.mounted_at:
        blocking.append(
            f"{device.path} has mounted filesystems: "
            + ", ".join(sorted(device.mounted_at))
        )
    if device.transport in _BRIDGED:
        blocking.append(
            f"{device.path} is behind a {device.transport} bridge; SET MAX "
            "ADDRESS is never sent through one"
        )
    if not device.serial.strip():
        blocking.append(
            f"{device.path} reports no serial, so the change cannot be confirmed "
            "by typing it"
        )
    if state.path != device.path:
        blocking.append(
            f"the reading is of {state.path}, not of {device.path}"
        )
    if not state.plausible:
        blocking.append(state.plausibility_reason or "the reading is implausible")
    elif state.native_max_lba <= state.accessible_max_lba:
        blocking.append(
            f"the native max LBA {state.native_max_lba} is not larger than the "
            f"accessible max LBA {state.accessible_max_lba}: there is no HPA to "
            "remove"
        )
    if not state.hpa_supported:
        blocking.append("the drive does not report the HPA feature set")
    draft = HpaPlan(
        platform=platform,
        device=HpaDeviceIdentity(
            path=device.path,
            serial=device.serial,
            model=device.model,
            size_bytes=device.size_bytes,
        ),
        original_native_max_lba=state.native_max_lba,
        original_accessible_max_lba=state.accessible_max_lba,
        original_dco_max_lba=state.dco_max_lba,
        sector_bytes=state.sector_bytes,
        hidden_bytes=state.hidden_bytes,
        requested_accessible_max_lba=state.native_max_lba,
        volatile=volatile,
        operation=operation_text(
            platform, device.path, state.native_max_lba, volatile=volatile
        ),
        blocking=tuple(blocking),
        limitations=tuple(_plan_limitations(platform, state, volatile)),
        created_at=clock(),
    )
    return draft.model_copy(update={"plan_digest": plan_digest_of(draft)})


def plan_drift(plan: HpaPlan, device: Device, state: HiddenAreaState) -> list[str]:
    """Every way the drive now differs from what the plan recorded.

    An empty list means the plan is current. Anything else means it is stale:
    the identity or the original values it was approved against are gone.
    """
    reasons: list[str] = []
    if plan.plan_digest != plan_digest_of(plan):
        reasons.append("the plan was altered after it was made")
    recorded = plan.device
    for label, was, now in (
        ("path", recorded.path, device.path),
        ("serial", recorded.serial, device.serial),
        ("model", recorded.model, device.model),
        ("size_bytes", recorded.size_bytes, device.size_bytes),
    ):
        if was != now:
            reasons.append(
                f"the device {label} changed since the plan: recorded {was!r}, "
                f"now {now!r}"
            )
    readings: tuple[tuple[str, int | None, int | None], ...] = (
        ("native max LBA", plan.original_native_max_lba, state.native_max_lba),
        (
            "accessible max LBA",
            plan.original_accessible_max_lba,
            state.accessible_max_lba,
        ),
        ("DCO max LBA", plan.original_dco_max_lba, state.dco_max_lba),
        ("sector size", plan.sector_bytes, state.sector_bytes),
    )
    for label, before, after in readings:
        if before != after:
            reasons.append(
                f"the drive's {label} changed since the plan: recorded {before}, "
                f"now {after}"
            )
    if not state.plausible:
        reasons.append(state.plausibility_reason or "the reading is implausible")
    return reasons


def backup_problems(
    record: BackupRecord | None,
    verification: BackupVerification | None,
    *,
    device: Device,
    state: HiddenAreaState,
) -> list[str]:
    """Why the backup gate is not met, or an empty list if it is.

    The gate is a :class:`core.backup.BackupRecord` whose own digest holds,
    a passing :class:`core.backup.BackupVerification` of that very record,
    recorded against this device's serial, whose image covers at least the
    accessible range. It proves the image is unchanged since it was hashed;
    it does not prove where the image came from (the record's own limitations
    say so).
    """
    from core.backup import record_digest_of

    if record is None:
        return ["no backup record was named for this device"]
    reasons: list[str] = []
    if record.record_digest != record_digest_of(record):
        reasons.append(
            f"backup record {record.backup_id} was altered after it was made"
        )
    if verification is None:
        reasons.append(
            f"backup {record.backup_id} has not been verified; run "
            "/workflow/backup/{id}/verify"
        )
    else:
        if verification.backup_id != record.backup_id:
            reasons.append("the verification is of a different backup record")
        elif not verification.passed:
            reasons.append(
                f"backup {record.backup_id} failed verification: "
                f"{verification.message}"
            )
    recorded_serial = "".join(record.source.serial.split()).casefold()
    device_serial = "".join(device.serial.split()).casefold()
    if not recorded_serial or recorded_serial != device_serial:
        reasons.append(
            f"backup {record.backup_id} was recorded against serial "
            f"{record.source.serial!r}, not this device's {device.serial!r}"
        )
    if record.image_size_bytes < state.accessible_bytes:
        reasons.append(
            f"backup {record.backup_id} is {record.image_size_bytes} bytes and "
            f"does not cover the {state.accessible_bytes}-byte accessible range"
        )
    return reasons


# ==========================================================================
# Backends
# ==========================================================================


class HiddenAreaBackend(Protocol):
    """Reads and sets one drive's maxima. One implementation per platform."""

    platform: Literal["linux", "windows"]

    def discover(
        self, device: Device, *, after_change: bool = False
    ) -> HiddenAreaState:
        """Read the maxima. Read-only. Raises when the drive cannot be asked.

        ``after_change`` is set for the read-back after SET MAX: the device's
        length is then expected to differ from the plan, so only its identity
        (serial) binds the read.
        """
        ...

    def set_max(self, device: Device, lba: int, *, volatile: bool) -> None:
        """Set the accessible maximum to ``lba``. The only mutating call."""
        ...


def _refuse_transport(device: Device) -> None:
    """Raise for a device whose transport never carries an HPA command."""
    if device.transport in _BRIDGED:
        raise UnsupportedCapability(
            f"{device.path} is behind a {device.transport} bridge, where ATA "
            "pass-through is not dependable: a bridge may answer, refuse or "
            "invent a reply to READ NATIVE MAX and SET MAX. The HPA was not "
            "read and will not be changed; nothing was sent to the drive.",
            remediation="Attach the drive directly to a SATA port and discover "
            "it again.",
        )
    if device.transport == "nvme":
        raise UnsupportedCapability(
            f"{device.path} is an NVMe device. HPA and DCO are ATA features; an "
            "NVMe namespace has neither, so there is nothing to change.",
            remediation="No HPA workflow applies to NVMe.",
        )


_MAX_SECTORS = re.compile(r"max sectors\s*=\s*(\d+)\s*/\s*(\d+)", re.IGNORECASE)
_DCO_REAL_MAX = re.compile(r"Real max sectors:\s*(\d+)", re.IGNORECASE)
_INVALID_HPA = re.compile(r"HPA setting seems invalid", re.IGNORECASE)


class LinuxHpaBackend:
    """hdparm, through the :class:`core.device._sysio.SystemProbe` seam.

    ``hdparm -N`` reports and takes sector *counts*; this backend converts to
    and from maximum LBAs at the boundary. Without a ``p`` prefix the setting
    is volatile.
    """

    platform: Literal["linux", "windows"] = "linux"

    def __init__(self, io: SystemProbe | None = None) -> None:
        self.io = io or SystemProbe()

    def _sector_bytes(self, device: Device) -> tuple[int, list[str]]:
        name = Path(device.path).name
        raw = self.io.read_text(
            self.io.sysfs_root / "block" / name / "queue" / "logical_block_size"
        )
        try:
            value = int((raw or "").strip())
        except ValueError:
            value = 0
        if value > 0:
            return value, []
        return 512, [
            f"The logical sector size of {device.path} could not be read from "
            "sysfs; 512 bytes was assumed for the byte counts. The LBAs are "
            "the drive's own and are unaffected."
        ]

    def _require_privilege(self, device: Device, tool: str, denied: bool) -> None:
        if denied:
            raise UnsupportedCapability(
                f"{tool} could not read {device.path}: permission denied.",
                remediation="Run the privileged helper as root. A permission "
                "failure is never read as 'no hidden area'.",
            )

    def discover(
        self, device: Device, *, after_change: bool = False
    ) -> HiddenAreaState:
        """``hdparm -N`` and ``hdparm --dco-identify``. Read-only."""
        _refuse_transport(device)
        result = self.io.run("hdparm", "-N", device.path)
        self._require_privilege(device, "hdparm -N", result.permission_denied)
        if not result.ok:
            raise UnsupportedCapability(
                f"hdparm -N exited {result.returncode} for {device.path}; the "
                "native maximum could not be read and nothing was changed."
            )
        if _INVALID_HPA.search(result.stdout):
            raise UnsupportedCapability(
                f"hdparm -N reported the HPA setting of {device.path} as invalid "
                "and still exited 0; the reading was discarded, not believed."
            )
        match = _MAX_SECTORS.search(result.stdout)
        if match is None:
            raise UnsupportedCapability(
                f"hdparm -N printed no 'max sectors' line for {device.path}; the "
                "drive did not answer READ NATIVE MAX."
            )
        accessible_count, native_count = int(match.group(1)), int(match.group(2))
        sector, notes = self._sector_bytes(device)

        dco_max: int | None = None
        dco_supported = False
        dco = self.io.run("hdparm", "--dco-identify", device.path)
        self._require_privilege(device, "hdparm --dco-identify", dco.permission_denied)
        if dco.ok and (dco_match := _DCO_REAL_MAX.search(dco.stdout)):
            dco_supported = True
            dco_max = int(dco_match.group(1)) - 1
        else:
            notes.append(
                f"hdparm --dco-identify gave no reading for {device.path}; "
                "whether a DCO hides further sectors is unknown."
            )
        return hidden_area_state(
            path=device.path,
            native_max_lba=native_count - 1,
            accessible_max_lba=accessible_count - 1,
            sector_bytes=sector,
            reported_capacity_bytes=device.size_bytes,
            hpa_supported=True,
            dco_supported=dco_supported,
            dco_max_lba=dco_max,
            source_commands=(
                f"hdparm -N {device.path}",
                f"hdparm --dco-identify {device.path}",
            ),
            limitations=tuple(notes),
        )

    def set_max(self, device: Device, lba: int, *, volatile: bool) -> None:
        """``hdparm -N <count>`` (volatile) or ``hdparm -N p<count>`` (permanent)."""
        _refuse_transport(device)
        count = lba + 1
        argument = f"{'' if volatile else 'p'}{count}"
        result = self.io.run("hdparm", "-N", argument, device.path)
        self._require_privilege(device, "hdparm -N", result.permission_denied)
        if not result.ok:
            raise UnsupportedCapability(
                f"hdparm -N {argument} {device.path} exited {result.returncode}: "
                f"{(result.stderr or result.stdout).strip()[:200]}. The drive's "
                "accessible maximum is unknown until it is read again."
            )


class WindowsHpaBackend:
    """ATA commands through ``IOCTL_ATA_PASS_THROUGH`` on a bound disk handle.

    Every call opens ``\\\\.\\PhysicalDriveN`` and binds it to the planned
    serial (and, before a change, the planned size) before any ATA command is
    sent: the identity is read from the handle, never trusted from the path.
    Pass-through needs a read/write handle; discovery sends only IDENTIFY,
    READ NATIVE MAX and DCO IDENTIFY, none of which changes the drive.
    """

    platform: Literal["linux", "windows"] = "windows"

    def __init__(self, api: NativeApi) -> None:
        self.api = api

    def _open(self, device: Device, *, check_size: bool) -> WindowsDisk:
        from core.device.win.disk import WindowsDisk, parse_disk_number

        number = parse_disk_number(device.path)
        disk = WindowsDisk(self.api, number, write=True).open()
        if check_size:
            disk.bind(serial=device.serial, size_bytes=device.size_bytes)
            return disk
        identity = disk.read_identity()
        wanted = "".join(device.serial.split()).upper()
        got = "".join(identity.serial.split()).upper()
        if identity.number != number or not wanted or wanted != got:
            disk.close()
            raise ConfirmationMismatch(
                f"{disk.path} now reports serial {identity.serial!r}, not the "
                f"planned {device.serial!r}; it was not read back.",
                remediation="Re-discover the drive; its HPA state is unknown.",
            )
        return disk

    def discover(
        self, device: Device, *, after_change: bool = False
    ) -> HiddenAreaState:
        """IDENTIFY DEVICE, READ NATIVE MAX ADDRESS EXT, DCO IDENTIFY. Read-only."""
        from core.device.win import ata

        _refuse_transport(device)
        disk = self._open(device, check_size=not after_change)
        try:
            ident = ata.identify(disk)
            if not ident.trustworthy:
                raise UnsupportedCapability(
                    f"{disk.path} answered IDENTIFY DEVICE with a buffer whose "
                    "checksum does not hold: it was not the drive's. Nothing was "
                    "inferred from it and nothing was changed.",
                    remediation="Attach the drive directly to a SATA port.",
                )
            accessible = ident.addressable_sectors - 1
            notes: list[str] = []
            commands = ["IDENTIFY DEVICE (ECh)"]
            if ident.hpa_supported:
                native = ata.read_native_max(disk)
                commands.append("READ NATIVE MAX ADDRESS EXT (27h)")
            else:
                native = accessible
                notes.append(
                    "The drive does not report the HPA feature set; READ NATIVE "
                    "MAX ADDRESS was not sent."
                )
            dco_max: int | None = None
            if ident.dco_supported:
                try:
                    dco_max = ata.dco_identify(disk)
                    commands.append("DEVICE CONFIGURATION IDENTIFY (B1h/C2h)")
                except UnsupportedCapability as exc:
                    notes.append(
                        f"DEVICE CONFIGURATION IDENTIFY was refused ({exc.message}); "
                        "whether a DCO hides further sectors is unknown."
                    )
            identity = disk.identity
            capacity = identity.size_bytes if identity is not None else 0
            sector = identity.logical_sector if identity is not None else 512
        finally:
            disk.close()
        return hidden_area_state(
            path=device.path,
            native_max_lba=native,
            accessible_max_lba=accessible,
            sector_bytes=sector,
            reported_capacity_bytes=capacity,
            hpa_supported=ident.hpa_supported,
            dco_supported=ident.dco_supported,
            dco_max_lba=dco_max,
            source_commands=tuple(commands),
            limitations=tuple(notes),
        )

    def set_max(self, device: Device, lba: int, *, volatile: bool) -> None:
        """READ NATIVE MAX ADDRESS EXT, then at once SET MAX ADDRESS EXT."""
        from core.device.win import ata
        from core.device.win.disk import volumes_on_disk

        _refuse_transport(device)
        disk = self._open(device, check_size=True)
        try:
            mounted = [
                path
                for _, paths in volumes_on_disk(self.api, disk.number)
                for path in paths
            ]
            if mounted:
                raise MountedRefused(
                    f"{disk.path} has mounted volumes: {', '.join(mounted)}. "
                    "SET MAX ADDRESS was not sent."
                )
            # ATA: SET MAX ADDRESS EXT is aborted unless the command immediately
            # before it was READ NATIVE MAX ADDRESS EXT. Nothing goes between.
            native = ata.read_native_max(disk)
            if lba > native:
                raise UnsupportedCapability(
                    f"The requested max LBA {lba} is beyond the drive's native "
                    f"max LBA {native}; SET MAX ADDRESS was not sent."
                )
            ata.set_max_address(disk, lba, volatile=volatile)
            disk.update_properties()
        finally:
            disk.close()


def platform_backend(
    family: str, *, io: SystemProbe | None = None, api: NativeApi | None = None
) -> HiddenAreaBackend:
    """The backend for this host's platform family, or :class:`PlatformUnsupported`.

    macOS has no public ATA pass-through, which the capability resolver
    already records as UNSUPPORTED_BY_PLATFORM; this raises with that reason.
    """
    if family == "linux":
        return LinuxHpaBackend(io)
    if family == "windows":
        if api is None:
            from core.device.win.native import default_api

            api = default_api()
        return WindowsHpaBackend(api)
    from core.platform.capability import Capability, implementation

    entry = implementation(
        family,  # type: ignore[arg-type]
        Capability.HPA_DCO_MODIFY,
    )
    raise PlatformUnsupported(
        (entry.reason or f"No HPA backend exists for the {family!r} platform.")
        + " Nothing was sent to the drive.",
        remediation="Run the HPA/DCO workflow on Linux or Windows with the "
        "drive attached directly to a SATA port.",
    )


# ==========================================================================
# Execution
# ==========================================================================


class HpaLedger(Protocol):
    """The hash-chained ledger: :class:`core.ledger.chain.Ledger` satisfies it."""

    def append(
        self,
        *,
        actor: str,
        operation: str,
        params: dict[str, Any],
        result: dict[str, Any],
    ) -> object:
        """Append one entry that carries the SHA-256 of the one before it."""
        ...


def _progress(job_id: str, phase: str, pct_bp: int, message: str) -> dict[str, Any]:
    return Progress(
        job_id=job_id,
        phase=phase,
        pct_bp=pct_bp,
        bytes_done=0,
        bytes_total=0,
        throughput_bytes_per_sec=0,
        eta_seconds=0,
        message=message,
    ).model_dump(mode="json")


def _values(plan: HpaPlan) -> dict[str, Any]:
    return {
        "original_native_max_lba": plan.original_native_max_lba,
        "original_accessible_max_lba": plan.original_accessible_max_lba,
        "original_dco_max_lba": plan.original_dco_max_lba,
        "requested_accessible_max_lba": plan.requested_accessible_max_lba,
        "volatile": plan.volatile,
        "operation": plan.operation,
    }


def execute(
    plan: HpaPlan,
    backend: HiddenAreaBackend,
    *,
    device: Device,
    typed_serial: str,
    ledger: HpaLedger,
    actor: str = "sanctum",
    job_id: str = "hpa",
    authorization_id: str = "",
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> Generator[dict[str, Any], None, HpaResult]:
    """Run one approved HPA plan on the real drive; yields progress dicts.

    ``device`` is the caller's *fresh* read of the device (identity, system
    disk, mounts). Immediately before the command the drive's maxima are read
    again through ``backend`` and compared with the plan: any drift in
    identity or in the original values refuses the plan as stale. Every run
    needs ``typed_serial`` equal to the device's serial. There is no
    non-writing mode: a run that passes the checks sends the command.

    Every step is ledgered: ``hpa.plan``, then ``hpa.blocked`` (a refusal),
    or ``hpa.modify`` (written *before* the command, with the
    original values to restore to), ``hpa.verify``, and ``hpa.complete`` or
    ``hpa.failed``.

    Raises:
        SystemDiskRefused, MountedRefused: the device must not be touched.
        ConfirmationMismatch: the exact serial was not typed.
        WorkflowGateRefused: the plan is blocked, stale, or for another platform.
        UnsupportedCapability: the drive could not be re-read before the change.
    """
    started = clock()
    base: dict[str, Any] = {
        "job_id": job_id,
        "authorization_id": authorization_id,
        "path": plan.device.path,
        "serial": plan.device.serial,
        "plan_digest": plan.plan_digest,
    }

    def record(operation: str, params: dict[str, Any], result: dict[str, Any]) -> None:
        ledger.append(
            actor=actor, operation=operation, params={**base, **params}, result=result
        )

    def refuse(exc: SanctumError, reasons: list[str]) -> SanctumError:
        record(
            "hpa.blocked",
            {},
            {"verdict": "REFUSED", "why_blocked": reasons, "device_modified": "no"},
        )
        logger.warning("hpa_refused", path=plan.device.path, reasons=reasons)
        return exc

    record(
        "hpa.plan",
        {"plan": plan.model_dump(mode="json")},
        {"state": HpaState.PLAN_READY.value},
    )
    yield _progress(job_id, HpaState.PLAN_READY.value, 0, f"plan: {plan.operation}")

    if plan.blocking:
        reasons = list(plan.blocking)
        raise refuse(_gate(reasons), reasons)
    if backend.platform != plan.platform:
        reasons = [
            f"the plan is for {plan.platform}, this backend is {backend.platform}"
        ]
        raise refuse(_gate(reasons), reasons)
    try:
        guard.assert_erasable(device)
    except SanctumError as exc:
        raise refuse(exc, [exc.message]) from None
    typed = typed_serial.strip().casefold()
    serial = device.serial.strip().casefold()
    if not typed or not serial or typed != serial:
        reasons = [
            "an HPA change needs the device serial typed by hand, and the "
            "typed value does not match the serial read from the device"
        ]
        raise refuse(
            ConfirmationMismatch(
                f"Typed value does not match the serial of {device.path}. "
                "Nothing was sent to the drive."
            ),
            reasons,
        )

    # Re-read immediately before the command. A plan approved against values
    # the drive no longer reports is not the plan that was approved.
    try:
        pre = backend.discover(device)
    except SanctumError as exc:
        raise refuse(exc, [exc.message]) from None
    stale = plan_drift(plan, device, pre)
    if stale:
        stale = ["the plan is stale", *stale]
        raise refuse(_gate(stale), stale)

    limitations = list(plan.limitations)

    # ---------------- MODIFYING ----------------
    yield _progress(job_id, HpaState.MODIFYING.value, 0, f"sending {plan.operation}")
    record(
        "hpa.modify",
        {
            **_values(plan),
            "pre_state": pre.model_dump(mode="json"),
            "note": (
                "Written before the command. If this job is interrupted, the "
                "drive's accessible maximum is unknown until it is read again; "
                f"the original accessible max LBA was "
                f"{plan.original_accessible_max_lba}."
            ),
        },
        {"state": HpaState.MODIFYING.value},
    )
    try:
        backend.set_max(
            device, plan.requested_accessible_max_lba, volatile=plan.volatile
        )
    except (SanctumError, OSError) as exc:
        text = exc.message if isinstance(exc, SanctumError) else str(exc)
        return _failed(
            plan, pre, None, job_id, started, clock, limitations, record,
            phase=HpaState.MODIFYING, reason=f"SET MAX ADDRESS failed: {text}",
            modified="unknown",
        )

    # ---------------- VERIFYING ----------------
    try:
        yield _progress(
            job_id, HpaState.VERIFYING.value, 5_000, "reading the drive back"
        )
    except GeneratorExit:
        record(
            "hpa.failed",
            {**_values(plan), "phase": HpaState.VERIFYING.value},
            {
                "state": HpaState.FAILED.value,
                "device_modified": "unknown",
                "reason": "Cancelled after SET MAX ADDRESS was sent and before "
                "the drive was read back. The accessible maximum is unknown "
                "until the drive is discovered again.",
            },
        )
        raise
    try:
        post = backend.discover(device, after_change=True)
    except (SanctumError, OSError) as exc:
        text = exc.message if isinstance(exc, SanctumError) else str(exc)
        return _failed(
            plan, pre, None, job_id, started, clock, limitations, record,
            phase=HpaState.VERIFYING,
            reason=f"The drive could not be read back after SET MAX: {text}",
            modified="unknown",
        )
    notes: list[str] = []
    if post.accessible_max_lba != plan.requested_accessible_max_lba:
        notes.append(
            f"the drive now reports accessible max LBA {post.accessible_max_lba}, "
            f"not the requested {plan.requested_accessible_max_lba}"
        )
    if post.native_max_lba != plan.original_native_max_lba:
        notes.append(
            f"the drive now reports native max LBA {post.native_max_lba}, not the "
            f"original {plan.original_native_max_lba}"
        )
    if plan.original_dco_max_lba is not None and post.dco_max_lba != (
        plan.original_dco_max_lba
    ):
        notes.append(
            f"the DCO maximum changed from {plan.original_dco_max_lba} to "
            f"{post.dco_max_lba}, which this workflow never asks for"
        )
    passed = not notes
    modified: Literal["no", "yes", "unknown"] = (
        "yes" if post.accessible_max_lba != pre.accessible_max_lba else "no"
    )
    record(
        "hpa.verify",
        {"post_state": post.model_dump(mode="json")},
        {"passed": passed, "notes": notes},
    )
    if not passed:
        return _failed(
            plan, pre, post, job_id, started, clock, limitations, record,
            phase=HpaState.VERIFYING,
            reason="Verification failed: " + "; ".join(notes),
            modified=modified,
        )
    record(
        "hpa.complete",
        _values(plan),
        {
            "state": HpaState.COMPLETE.value,
            "device_modified": modified,
            "accessible_max_lba": post.accessible_max_lba,
            "exposed_bytes": pre.hidden_bytes,
        },
    )
    yield _progress(
        job_id,
        HpaState.COMPLETE.value,
        10_000,
        f"accessible max LBA is now {post.accessible_max_lba}; "
        f"{pre.hidden_bytes} bytes exposed"
        + (" until the next power cycle" if plan.volatile else " permanently"),
    )
    return HpaResult(
        job_id=job_id,
        plan_digest=plan.plan_digest,
        outcome="COMPLETE",
        operation=plan.operation,
        volatile=plan.volatile,
        original_native_max_lba=plan.original_native_max_lba,
        original_accessible_max_lba=plan.original_accessible_max_lba,
        original_dco_max_lba=plan.original_dco_max_lba,
        requested_accessible_max_lba=plan.requested_accessible_max_lba,
        pre_state=pre,
        post_state=post,
        verification_passed=True,
        verification_notes=(
            "The drive was read again: the accessible maximum equals the "
            "requested value and the native maximum is unchanged.",
        ),
        device_modified=modified,
        started_at=started,
        finished_at=clock(),
        limitations=tuple(limitations),
    )


def _gate(reasons: list[str]) -> WorkflowGateRefused:
    return WorkflowGateRefused(
        "REFUSED: the HPA plan cannot run: " + "; ".join(reasons)
        + ". Nothing was sent to the drive.",
        why_blocked=reasons,
        remediation="Discover the drive again and open a new HPA/DCO workflow "
        "against it as it is now.",
    )


def _failed(
    plan: HpaPlan,
    pre: HiddenAreaState,
    post: HiddenAreaState | None,
    job_id: str,
    started: datetime,
    clock: Callable[[], datetime],
    limitations: list[str],
    record: Callable[[str, dict[str, Any], dict[str, Any]], None],
    *,
    phase: HpaState,
    reason: str,
    modified: Literal["no", "yes", "unknown"],
) -> HpaResult:
    record(
        "hpa.failed",
        {**_values(plan), "phase": phase.value},
        {"state": HpaState.FAILED.value, "device_modified": modified, "reason": reason},
    )
    logger.warning("hpa_failed", path=plan.device.path, reason=reason)
    return HpaResult(
        job_id=job_id,
        plan_digest=plan.plan_digest,
        outcome="FAILED",
        operation=plan.operation,
        volatile=plan.volatile,
        original_native_max_lba=plan.original_native_max_lba,
        original_accessible_max_lba=plan.original_accessible_max_lba,
        original_dco_max_lba=plan.original_dco_max_lba,
        requested_accessible_max_lba=plan.requested_accessible_max_lba,
        pre_state=pre,
        post_state=post,
        verification_passed=False,
        verification_notes=(reason,),
        device_modified=modified,
        started_at=started,
        finished_at=clock(),
        limitations=(
            *limitations,
            "The change did not verify. Discover the drive again before "
            "relying on its accessible maximum or erasing it.",
        ),
    )
