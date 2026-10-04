"""The destructive-workflow state machine. A model, never an actor.

Every destructive path in this project already re-checks its own gates at the
moment of writing: ``write_image`` in ``scripts/media_benchmark.py`` re-runs the
preflight and the whole backup verification itself, and the drive engine does
the same for its own gates. Those checks are the protection. This module does
not replace or bypass any of them.

What it adds is a *name* for where a job is, and the reason it cannot move on,
in the words an operator or a judge reads:

    DISCOVERED -> PREFLIGHT -> BACKUP_REQUIRED -> BACKUP_VERIFIED
      -> HUMAN_APPROVAL_REQUIRED -> PLAN_READY -> EXECUTING -> VERIFYING
      -> COMPLETE

with ``BLOCKED`` reachable from every state before execution and ``FAILED`` from
execution and verification. :func:`derive` computes the state from facts that
the gates established; it never infers a fact. :func:`advance` refuses any
transition that is not an edge of :data:`TRANSITIONS`, or that the facts do not
support - there is no edge into ``EXECUTING`` except from ``PLAN_READY``, and
``PLAN_READY`` is only derived when a human approval is recorded against a plan
with nothing blocking.

Nothing here performs I/O, opens a device, or records an approval. Approval is
a fact a caller supplies after a person gave it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

__all__ = [
    "TRANSITIONS",
    "IllegalTransition",
    "WorkflowFacts",
    "WorkflowState",
    "WorkflowStatus",
    "advance",
    "derive",
]


class WorkflowState(StrEnum):
    """Where a destructive job is. Declaration order is the happy path."""

    DISCOVERED = "DISCOVERED"
    PREFLIGHT = "PREFLIGHT"
    BLOCKED = "BLOCKED"
    BACKUP_REQUIRED = "BACKUP_REQUIRED"
    BACKUP_VERIFIED = "BACKUP_VERIFIED"
    PLAN_READY = "PLAN_READY"
    HUMAN_APPROVAL_REQUIRED = "HUMAN_APPROVAL_REQUIRED"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


_S = WorkflowState

#: Every legal edge. Anything absent is refused by :func:`advance`.
TRANSITIONS: dict[WorkflowState, frozenset[WorkflowState]] = {
    _S.DISCOVERED: frozenset({_S.PREFLIGHT, _S.BLOCKED}),
    _S.PREFLIGHT: frozenset({_S.BLOCKED, _S.BACKUP_REQUIRED, _S.BACKUP_VERIFIED}),
    _S.BLOCKED: frozenset({_S.DISCOVERED, _S.PREFLIGHT}),
    _S.BACKUP_REQUIRED: frozenset({_S.BACKUP_VERIFIED, _S.BLOCKED, _S.PREFLIGHT}),
    _S.BACKUP_VERIFIED: frozenset(
        {_S.HUMAN_APPROVAL_REQUIRED, _S.BLOCKED, _S.BACKUP_REQUIRED}
    ),
    _S.HUMAN_APPROVAL_REQUIRED: frozenset(
        {_S.PLAN_READY, _S.BLOCKED, _S.BACKUP_REQUIRED}
    ),
    _S.PLAN_READY: frozenset({_S.EXECUTING, _S.BLOCKED, _S.BACKUP_REQUIRED}),
    _S.EXECUTING: frozenset({_S.VERIFYING, _S.FAILED}),
    _S.VERIFYING: frozenset({_S.COMPLETE, _S.FAILED}),
    _S.COMPLETE: frozenset(),
    _S.FAILED: frozenset(),
}

_NEXT_ACTION: dict[WorkflowState, str] = {
    _S.DISCOVERED: "run the read-only preflight against the persistent device path",
    _S.PREFLIGHT: "read the preflight result",
    _S.BLOCKED: (
        "resolve every reason listed, by hand, then run the preflight again; "
        "nothing here unmounts, elevates or retries on its own"
    ),
    _S.BACKUP_REQUIRED: (
        "take a backup of the write extent onto a different physical disk, "
        "then run verify-backup"
    ),
    _S.BACKUP_VERIFIED: "generate the read-only plan for review",
    _S.HUMAN_APPROVAL_REQUIRED: (
        "a person reviews the plan and records an explicit approval; "
        "this software cannot approve on anyone's behalf"
    ),
    _S.PLAN_READY: (
        "the approved operator runs the destructive command, typing the "
        "device serial by hand"
    ),
    _S.EXECUTING: "wait for the operation to finish; do not disconnect the device",
    _S.VERIFYING: "wait for read-back verification to finish",
    _S.COMPLETE: "read the report and its limitations before relying on it",
    _S.FAILED: "read the failure; the device is in an unknown state until checked",
}


class IllegalTransition(ValueError):
    """A transition that is not an edge, or that the facts do not support."""


@dataclass(frozen=True)
class WorkflowFacts:
    """What the gates have established. Every field defaults to "not yet"."""

    device_present: bool = False
    preflight_ran: bool = False
    preflight_safe: bool = False
    preflight_refusal: str = ""
    serial_sources_agree: bool = False
    backup_sufficient: bool = False
    plan_generated: bool = False
    #: The plan's own blocking list, verbatim.
    plan_blocking: tuple[str, ...] = ()
    #: Recorded by a caller after a person approved. Never inferred.
    human_approved: bool = False
    executing: bool = False
    verifying: bool = False
    complete: bool = False
    #: A failure description, or empty.
    failed: str = ""


@dataclass(frozen=True)
class WorkflowStatus:
    """The derived state, why it cannot move on, and what a person does next."""

    state: WorkflowState
    why_blocked: tuple[str, ...]
    next_action: str

    @property
    def allowed_next(self) -> frozenset[WorkflowState]:
        return TRANSITIONS[self.state]

    def as_dict(self) -> dict[str, Any]:
        """Plain JSON-able form for reports, plans and screens."""
        return {
            "state": self.state.value,
            "why_blocked": list(self.why_blocked),
            "next_action": self.next_action,
            "allowed_next": sorted(state.value for state in self.allowed_next),
        }


def _status(state: WorkflowState, *reasons: str) -> WorkflowStatus:
    return WorkflowStatus(
        state=state,
        why_blocked=tuple(reason for reason in reasons if reason),
        next_action=_NEXT_ACTION[state],
    )


def derive(facts: WorkflowFacts) -> WorkflowStatus:
    """The state these facts put a job in. Pure; the earliest unmet gate wins."""
    if facts.failed:
        return _status(_S.FAILED, facts.failed)
    if facts.complete:
        return _status(_S.COMPLETE)
    if facts.verifying:
        return _status(_S.VERIFYING)
    if facts.executing:
        return _status(_S.EXECUTING)

    if not facts.device_present:
        return _status(
            _S.BLOCKED, "the device is not present at the persistent path given"
        )
    if not facts.preflight_ran:
        return _status(_S.DISCOVERED)
    if not facts.preflight_safe:
        return _status(
            _S.BLOCKED,
            f"preflight refused: {facts.preflight_refusal}"
            if facts.preflight_refusal
            else "preflight did not return SAFE",
        )
    if not facts.serial_sources_agree:
        return _status(
            _S.BLOCKED,
            "the serial is not confirmed by two independent machine sources",
        )
    if not facts.backup_sufficient:
        return _status(
            _S.BACKUP_REQUIRED,
            *(facts.plan_blocking or ("no verified backup covers the write extent",)),
        )
    if not facts.plan_generated:
        return _status(_S.BACKUP_VERIFIED)
    if facts.plan_blocking:
        return _status(_S.BLOCKED, *facts.plan_blocking)
    if not facts.human_approved:
        return _status(
            _S.HUMAN_APPROVAL_REQUIRED,
            "no person has approved this plan; approval is required before any write",
        )
    return _status(_S.PLAN_READY)


def _permits(target: WorkflowState, derived: WorkflowState) -> bool:
    if target is _S.BLOCKED:
        return True  # moving to a safer state is always allowed
    if target is _S.EXECUTING:
        return derived is _S.PLAN_READY
    if target is _S.FAILED:
        return True
    return derived is target


def advance(
    current: WorkflowState, target: WorkflowState, facts: WorkflowFacts
) -> WorkflowState:
    """Move from ``current`` to ``target``, or raise :class:`IllegalTransition`.

    The edge must exist, and the facts must derive a state that supports it.
    Returns ``target`` on success so a caller can assign it directly.
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
            f"{current.value} -> {target.value} refused: the facts put this job in "
            f"{status.state.value} ({reasons})"
        )
    return target
