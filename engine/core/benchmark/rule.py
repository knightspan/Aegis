"""The registered pass/fail rule for the physical recovery benchmark.

Registered in ``scripts/media_benchmark.py`` before any physical run, and
recorded in ``docs/validation/methodology-open-decision.md``:

* ``PASS_WITHIN_POINTS = 5.0``
* ``FAIL_BELOW_POINTS = 10.0``

It compares byte-identical recall on the physical medium with the synthetic
baseline row ``media-fat32-255m.img`` / ``sanctum-carve`` in
``docs/performance/benchmark.csv``. It covers recall only.

How the two numbers are applied here, stated so it can be checked:

* ``delta`` is physical recall minus baseline recall, in percentage points,
  computed exactly (as a fraction, never a float).
* **PASS** when physical recall is no more than 5 points below the baseline
  (``delta >= -5``). A physical recall above the baseline is within it.
* **FAIL** when it is more than 10 points below (``delta < -10``).
* Between the two the registered rule states no verdict. That is reported as
  ``BETWEEN_THRESHOLDS`` for a person to judge, never rounded to either side.

What is *not* registered: a HIGH false-positive condition. No decision on it is
recorded (checklist gate 1), so per that document the run is judged by the
5/10 rule alone and HIGH false positives are listed as an observation. This
module does not decide the open question and does not read the checklist; if
the experiment owner records Option A, this module and :data:`RULE_VERSION`
must change, and results under the old version say which rule they used.

The rule judges a PHYSICAL run. For a SYNTHETIC result the delta is still
computed, for information, and the outcome is ``NOT_APPLICABLE``.
"""

from __future__ import annotations

import csv
import math
from enum import StrEnum
from fractions import Fraction
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from core.benchmark.manifest import BenchmarkKind

__all__ = [
    "RULE_VERSION",
    "PASS_WITHIN_POINTS",
    "FAIL_BELOW_POINTS",
    "BASELINE_IMAGE",
    "BASELINE_TOOL",
    "RuleOutcome",
    "Baseline",
    "RuleEvaluation",
    "read_baseline",
    "evaluate_rule",
]

RULE_VERSION = "registered-5-10-recall-rule/1"
#: The registered constants, as exact fractions of a percentage point.
PASS_WITHIN_POINTS = Fraction(5)
FAIL_BELOW_POINTS = Fraction(10)
#: The registered baseline row.
BASELINE_IMAGE = "media-fat32-255m.img"
BASELINE_TOOL = "sanctum-carve"

METHODOLOGY_NOTE = (
    "Judged by the registered 5/10 recall rule alone. No HIGH false-positive "
    "condition is registered and no methodology decision (checklist gate 1) "
    "was known to this rule version; HIGH false positives are an observation, "
    "not a pass/fail condition (docs/validation/methodology-open-decision.md)."
)


class RuleOutcome(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    BETWEEN_THRESHOLDS = "BETWEEN_THRESHOLDS"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_EVALUATED = "NOT_EVALUATED"


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Baseline(_Frozen):
    """The pre-registered synthetic reference row."""

    image: str
    tool: str
    full: int
    exact: int
    source: str


class RuleEvaluation(_Frozen):
    """The registered rule applied to one result. Integers and strings only."""

    rule_version: str
    pass_within_points: int
    fail_below_points: int
    outcome: RuleOutcome
    #: True only for a PHYSICAL result with a usable baseline.
    binding: bool
    baseline: Baseline | None
    measured_exact: int
    measured_full: int
    #: Recall in basis points, rounded down. For display; the outcome is
    #: decided on the exact fractions.
    measured_recall_bp: int | None
    baseline_recall_bp: int | None
    #: ``delta`` in points as an exact fraction ``"p/q"``, and rounded to basis
    #: points of a percentage point (1 point = 100).
    delta_points_exact: str | None
    delta_points_bp: int | None
    methodology: str
    reason: str


def read_baseline(
    csv_path: Path, *, image: str = BASELINE_IMAGE, tool: str = BASELINE_TOOL
) -> Baseline:
    """The registered baseline row from the checked-in CSV.

    Raises:
        LookupError: the CSV has no such row.
        OSError: the CSV cannot be read.
    """
    with open(csv_path, encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if row["image"] == image and row["tool"] == tool:
                return Baseline(
                    image=image,
                    tool=tool,
                    full=int(row["full"]),
                    exact=int(row["exact"]),
                    source=str(csv_path),
                )
    raise LookupError(f"no baseline row for {image}/{tool} in {csv_path}")


def _bp(value: Fraction) -> int:
    """A fraction of one, in basis points, rounded toward negative infinity."""
    return math.floor(value * 10000)


def evaluate_rule(
    kind: BenchmarkKind,
    *,
    exact: int,
    full: int,
    baseline: Baseline | None,
    image_name: str,
    baseline_problem: str = "",
) -> RuleEvaluation:
    """Apply the registered 5/10 recall rule. See the module docstring."""
    common: dict[str, Any] = {
        "rule_version": RULE_VERSION,
        "pass_within_points": int(PASS_WITHIN_POINTS),
        "fail_below_points": int(FAIL_BELOW_POINTS),
        "baseline": baseline,
        "measured_exact": exact,
        "measured_full": full,
        "measured_recall_bp": _bp(Fraction(exact, full)) if full else None,
        "methodology": METHODOLOGY_NOTE,
    }
    if baseline is None or not baseline.full or not full:
        return RuleEvaluation(
            **common,
            outcome=RuleOutcome.NOT_EVALUATED,
            binding=False,
            baseline_recall_bp=None,
            delta_points_exact=None,
            delta_points_bp=None,
            reason=(
                baseline_problem
                or ("no FULL files to measure recall on" if not full else "")
                or "no registered baseline is available"
            ),
        )
    recall = Fraction(exact, full)
    base = Fraction(baseline.exact, baseline.full)
    delta = (recall - base) * 100
    shared: dict[str, Any] = {
        **common,
        "baseline_recall_bp": _bp(base),
        "delta_points_exact": f"{delta.numerator}/{delta.denominator}",
        "delta_points_bp": math.floor(delta * 100),
    }
    if kind is not BenchmarkKind.PHYSICAL:
        return RuleEvaluation(
            **shared,
            outcome=RuleOutcome.NOT_APPLICABLE,
            binding=False,
            reason=(
                "the registered rule judges a PHYSICAL run against the synthetic "
                "baseline; this result is SYNTHETIC, so the delta is information "
                "only"
            ),
        )
    if image_name != baseline.image:
        return RuleEvaluation(
            **shared,
            outcome=RuleOutcome.NOT_EVALUATED,
            binding=False,
            reason=(
                f"the registered baseline is for {baseline.image}; this manifest "
                f"describes {image_name}, a different experiment"
            ),
        )
    if delta >= -PASS_WITHIN_POINTS:
        outcome, reason = RuleOutcome.PASS, (
            f"physical recall is within {PASS_WITHIN_POINTS} points of the baseline"
        )
    elif delta < -FAIL_BELOW_POINTS:
        outcome, reason = RuleOutcome.FAIL, (
            f"physical recall is more than {FAIL_BELOW_POINTS} points below the "
            "baseline"
        )
    else:
        outcome, reason = RuleOutcome.BETWEEN_THRESHOLDS, (
            f"physical recall is between {PASS_WITHIN_POINTS} and "
            f"{FAIL_BELOW_POINTS} points below the baseline; the registered rule "
            "states no verdict here and a person must judge it"
        )
    return RuleEvaluation(**shared, outcome=outcome, binding=True, reason=reason)
