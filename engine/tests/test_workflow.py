"""The destructive-workflow state machine: where a job is, and why it stops.

The gates themselves live in the code that writes (``write_image`` re-runs every
check). This model names the current state, says WHY BLOCKED in words, and
refuses any transition that would skip a gate. It never performs an operation.
"""

from __future__ import annotations

import pytest
from core.workflow import (
    TRANSITIONS,
    IllegalTransition,
    WorkflowFacts,
    WorkflowState,
    advance,
    derive,
)

S = WorkflowState


def ready(**overrides: object) -> WorkflowFacts:
    """Every precondition met except approval, which is the human's."""
    base: dict[str, object] = {
        "device_present": True,
        "preflight_ran": True,
        "preflight_safe": True,
        "serial_sources_agree": True,
        "backup_sufficient": True,
        "plan_generated": True,
        "plan_blocking": (),
        "human_approved": False,
    }
    base.update(overrides)
    return WorkflowFacts(**base)  # type: ignore[arg-type]


def test_the_eleven_states_are_the_documented_ones() -> None:
    assert [s.value for s in WorkflowState] == [
        "DISCOVERED",
        "PREFLIGHT",
        "BLOCKED",
        "BACKUP_REQUIRED",
        "BACKUP_VERIFIED",
        "PLAN_READY",
        "HUMAN_APPROVAL_REQUIRED",
        "EXECUTING",
        "VERIFYING",
        "COMPLETE",
        "FAILED",
    ]


def test_an_absent_device_is_blocked_with_a_reason() -> None:
    status = derive(WorkflowFacts(device_present=False))
    assert status.state is S.BLOCKED
    assert any("not present" in reason for reason in status.why_blocked)


def test_a_present_device_without_preflight_is_discovered() -> None:
    status = derive(WorkflowFacts(device_present=True))
    assert status.state is S.DISCOVERED
    assert status.why_blocked == ()


def test_a_preflight_refusal_blocks_and_carries_the_refusal_text() -> None:
    status = derive(
        WorkflowFacts(
            device_present=True,
            preflight_ran=True,
            preflight_safe=False,
            preflight_refusal="has mounted filesystems: /run/media/x/STICK",
        )
    )
    assert status.state is S.BLOCKED
    assert any("mounted filesystems" in reason for reason in status.why_blocked)


def test_disagreeing_serial_sources_block_even_after_a_safe_preflight() -> None:
    status = derive(ready(serial_sources_agree=False))
    assert status.state is S.BLOCKED
    assert any("serial" in reason for reason in status.why_blocked)


def test_no_backup_means_backup_required() -> None:
    status = derive(
        ready(
            backup_sufficient=False,
            plan_generated=False,
            plan_blocking=("backup does not exist",),
        )
    )
    assert status.state is S.BACKUP_REQUIRED
    assert "backup does not exist" in status.why_blocked


def test_a_sufficient_backup_without_a_plan_is_backup_verified() -> None:
    status = derive(ready(plan_generated=False))
    assert status.state is S.BACKUP_VERIFIED


def test_a_clean_plan_without_approval_requires_a_human() -> None:
    status = derive(ready())
    assert status.state is S.HUMAN_APPROVAL_REQUIRED
    assert any("approve" in reason for reason in status.why_blocked)


def test_a_plan_with_any_blocking_reason_is_blocked_not_ready() -> None:
    status = derive(ready(plan_blocking=("image hash changed",), human_approved=True))
    assert status.state is S.BLOCKED
    assert "image hash changed" in status.why_blocked


def test_approval_on_a_clean_plan_is_plan_ready() -> None:
    status = derive(ready(human_approved=True))
    assert status.state is S.PLAN_READY
    assert status.why_blocked == ()


def test_approval_cannot_rescue_a_missing_backup() -> None:
    status = derive(ready(backup_sufficient=False, human_approved=True))
    assert status.state is S.BACKUP_REQUIRED


def test_runtime_states_follow_the_operation() -> None:
    assert derive(ready(human_approved=True, executing=True)).state is S.EXECUTING
    assert derive(ready(human_approved=True, verifying=True)).state is S.VERIFYING
    assert derive(ready(human_approved=True, complete=True)).state is S.COMPLETE
    failed = derive(ready(human_approved=True, failed="short write at 4096"))
    assert failed.state is S.FAILED
    assert "short write at 4096" in failed.why_blocked


def test_failure_outranks_every_other_fact() -> None:
    status = derive(
        ready(human_approved=True, executing=True, complete=True, failed="x")
    )
    assert status.state is S.FAILED


def test_every_state_names_a_next_action() -> None:
    samples = [
        WorkflowFacts(device_present=False),
        WorkflowFacts(device_present=True),
        ready(backup_sufficient=False),
        ready(plan_generated=False),
        ready(),
        ready(human_approved=True),
        ready(human_approved=True, complete=True),
    ]
    for facts in samples:
        assert derive(facts).next_action


def test_no_edge_reaches_executing_except_from_plan_ready() -> None:
    sources = {src for src, targets in TRANSITIONS.items() if S.EXECUTING in targets}
    assert sources == {S.PLAN_READY}


def test_complete_is_reached_only_through_verifying() -> None:
    sources = {src for src, targets in TRANSITIONS.items() if S.COMPLETE in targets}
    assert sources == {S.VERIFYING}


def test_terminal_states_have_no_exits() -> None:
    assert TRANSITIONS[S.COMPLETE] == frozenset()
    assert TRANSITIONS[S.FAILED] == frozenset()


def test_advance_refuses_skipping_the_backup() -> None:
    with pytest.raises(IllegalTransition, match="BACKUP_REQUIRED"):
        advance(S.BACKUP_REQUIRED, S.EXECUTING, ready(backup_sufficient=False))


def test_advance_refuses_executing_without_approval() -> None:
    with pytest.raises(IllegalTransition, match="HUMAN_APPROVAL_REQUIRED"):
        advance(S.HUMAN_APPROVAL_REQUIRED, S.EXECUTING, ready())


def test_advance_refuses_an_edge_the_facts_do_not_support() -> None:
    """PLAN_READY -> EXECUTING is an edge, but not when the facts say blocked."""
    with pytest.raises(IllegalTransition):
        advance(S.PLAN_READY, S.EXECUTING, ready(human_approved=False))


def test_advance_allows_the_legal_path() -> None:
    facts = ready(human_approved=True)
    assert advance(S.PLAN_READY, S.EXECUTING, facts) is S.EXECUTING


def test_advance_out_of_a_terminal_state_is_refused() -> None:
    with pytest.raises(IllegalTransition):
        advance(S.COMPLETE, S.EXECUTING, ready(human_approved=True))


def test_status_serialises_for_reports_and_screens() -> None:
    body = derive(ready()).as_dict()
    assert body["state"] == "HUMAN_APPROVAL_REQUIRED"
    assert isinstance(body["why_blocked"], list)
    assert body["next_action"]
    assert "EXECUTING" not in body["allowed_next"]
