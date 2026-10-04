#!/usr/bin/env python3
# ruff: noqa: E501, B905, E402
"""Exhaustive workflow state-machine check. SYNTHETIC (pure functions, no I/O).

    .venv/bin/python scripts/validation_workflow_matrix.py [OUT.json]

For every (current, target) pair and for every combination of the gate facts,
records whether ``advance`` allowed it, then asserts the two safety properties:
EXECUTING is reachable only from PLAN_READY with every gate satisfied, and no
edge leaves COMPLETE or FAILED.
"""

from __future__ import annotations

import itertools
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.workflow import (  # noqa: E402
    TRANSITIONS,
    IllegalTransition,
    WorkflowFacts,
    advance,
    derive,
)
from core.workflow import (
    WorkflowState as S,
)

GATES = (
    "device_present",
    "preflight_ran",
    "preflight_safe",
    "serial_sources_agree",
    "backup_sufficient",
    "plan_generated",
    "human_approved",
)


def main() -> int:
    edges = allowed = refused_no_edge = refused_facts = 0
    executing_ok: set[tuple[str, ...]] = set()
    violations: list[str] = []
    states = list(S)
    for bits in itertools.product((False, True), repeat=len(GATES)):
        facts = WorkflowFacts(**dict(zip(GATES, bits)))
        status = derive(facts)
        for cur, tgt in itertools.product(states, states):
            try:
                advance(cur, tgt, facts)
                ok = True
            except IllegalTransition as exc:
                ok = False
                if tgt not in TRANSITIONS[cur]:
                    refused_no_edge += 1
                else:
                    refused_facts += 1
                    if not str(exc):
                        violations.append(f"empty refusal {cur}->{tgt}")
            edges += 1
            if ok:
                allowed += 1
                if tgt is S.EXECUTING:
                    executing_ok.add(bits)
                    if (
                        cur is not S.PLAN_READY
                        or not all(bits)
                        or status.state is not S.PLAN_READY
                    ):
                        violations.append(
                            f"EXECUTING allowed from {cur} with {dict(zip(GATES, bits))}"
                        )
                if cur in (S.COMPLETE, S.FAILED):
                    violations.append(f"edge left terminal state {cur}->{tgt}")
        if status.state is S.BLOCKED and not status.why_blocked:
            violations.append(f"BLOCKED without reason for {bits}")
        if (
            status.state in (S.BACKUP_REQUIRED, S.HUMAN_APPROVAL_REQUIRED)
            and not status.why_blocked
        ):
            violations.append(f"{status.state} without reason for {bits}")
    # human_approved False must never yield PLAN_READY
    no_approval = [
        derive(WorkflowFacts(**dict(zip(GATES, b)))).state
        for b in itertools.product((False, True), repeat=len(GATES))
        if not b[-1]
    ]
    if S.PLAN_READY in no_approval:
        violations.append("PLAN_READY derived without approval")
    doc = {
        "population": "SYNTHETIC",
        "states": [s.value for s in states],
        "fact_combinations": 2 ** len(GATES),
        "pairs_checked": edges,
        "allowed": allowed,
        "refused_no_edge": refused_no_edge,
        "refused_by_facts": refused_facts,
        "executing_reachable_only_with_fact_vectors": sorted(map(list, executing_ok)),
        "violations": violations,
        "result": "PASS" if not violations else "FAIL",
    }
    print(json.dumps(doc, indent=1))
    if len(sys.argv) > 1:
        Path(sys.argv[1]).write_text(json.dumps(doc, indent=2) + "\n")
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
