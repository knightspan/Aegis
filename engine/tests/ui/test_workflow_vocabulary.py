"""The Sanitize screen names its workflow states with core/workflow.py's words.

``ui/src/lib/workflowState.ts`` derives the state the strip on the Sanitize
screen shows. The names are duplicated there because the UI has no Python at
runtime, and a duplicated vocabulary drifts. This reads the TypeScript union and
fails if it names a state the state machine does not define, or drops one it
does, so "BLOCKED" on the screen and in a plan's JSON stay the same word.
"""

from __future__ import annotations

import re
from pathlib import Path

from core.workflow import TRANSITIONS, WorkflowState

SOURCE = Path(__file__).resolve().parents[2] / "ui" / "src" / "lib" / "workflowState.ts"


def test_the_ui_state_names_are_exactly_the_state_machine_names() -> None:
    text = SOURCE.read_text(encoding="utf-8")
    union = re.search(r"export type WorkflowStateName =(.*?)\n\n", text, re.S)
    assert union, "WorkflowStateName union not found"
    names = set(re.findall(r"'([A-Z_]+)'", union.group(1)))
    assert names == {state.value for state in WorkflowState}


def _path(name: str) -> list[str]:
    text = SOURCE.read_text(encoding="utf-8")
    block = re.search(rf"export const {name}\b.*?= \[(.*?)\]", text, re.S)
    assert block, f"{name} not found"
    return re.findall(r"'([A-Z_]+)'", block.group(1))


def test_every_drawn_path_uses_only_state_machine_names() -> None:
    known = {state.value for state in WorkflowState}
    assert set(_path("REAL_ERASE_PATH")) <= known


def test_the_ui_draws_one_path_and_it_is_real() -> None:
    """The rehearsal path (SANITIZE_PATH, no backup and no approval) is gone."""
    text = SOURCE.read_text(encoding="utf-8")
    assert "SANITIZE_PATH" not in text
    assert not re.search(r"DRY RUN|dryRun|simulation", text)


def test_the_real_erase_path_is_a_walk_of_the_state_machine_edges() -> None:
    """The strip a real erase draws follows TRANSITIONS, edge for edge."""
    path = [WorkflowState(name) for name in _path("REAL_ERASE_PATH")]
    for here, there in zip(path, path[1:], strict=False):
        assert there in TRANSITIONS[here], f"{here} -> {there} is not an edge"
    assert path[-1] is WorkflowState.COMPLETE


def test_the_screen_recognises_exactly_the_states_the_server_can_send() -> None:
    text = SOURCE.read_text(encoding="utf-8")
    block = re.search(r"const STATE_NAMES.*?\(\[(.*?)\]\)", text, re.S)
    assert block, "STATE_NAMES not found"
    assert set(re.findall(r"'([A-Z_]+)'", block.group(1))) == {
        state.value for state in WorkflowState
    }
