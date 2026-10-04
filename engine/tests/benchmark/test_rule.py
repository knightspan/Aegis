"""The registered 5/10 recall rule, exactly as registered, and nothing more."""

from __future__ import annotations

from fractions import Fraction
from pathlib import Path

import pytest
from core.benchmark import rule
from core.benchmark.manifest import BenchmarkKind
from core.benchmark.rule import (
    Baseline,
    RuleOutcome,
    evaluate_rule,
    read_baseline,
)

REPO = Path(__file__).resolve().parents[2]
HUNDRED = Baseline(image=rule.BASELINE_IMAGE, tool="sanctum-carve", full=100, exact=100,
                   source="test")


def test_the_constants_are_the_registered_ones() -> None:
    import scripts.media_benchmark as harness

    assert Fraction(harness.PASS_WITHIN_POINTS) == rule.PASS_WITHIN_POINTS == 5
    assert Fraction(harness.FAIL_BELOW_POINTS) == rule.FAIL_BELOW_POINTS == 10
    assert harness.BASELINE_IMAGE == rule.BASELINE_IMAGE
    assert harness.BASELINE_TOOL == rule.BASELINE_TOOL
    decision = (REPO / "docs/validation/methodology-open-decision.md").read_text()
    assert "`PASS_WITHIN_POINTS = 5.0`" in decision
    assert "`FAIL_BELOW_POINTS = 10.0`" in decision


def test_the_baseline_is_the_checked_in_row() -> None:
    baseline = read_baseline(REPO / "docs/performance/benchmark.csv")
    assert (baseline.full, baseline.exact) == (22, 21)


@pytest.mark.parametrize(
    ("exact", "outcome"),
    [
        (100, RuleOutcome.PASS),
        (95, RuleOutcome.PASS),  # exactly 5 points below: within
        (94, RuleOutcome.BETWEEN_THRESHOLDS),
        (90, RuleOutcome.BETWEEN_THRESHOLDS),  # exactly 10 below: not more than 10
        (89, RuleOutcome.FAIL),
        (0, RuleOutcome.FAIL),
    ],
)
def test_the_rule_on_a_physical_run(exact: int, outcome: RuleOutcome) -> None:
    result = evaluate_rule(
        BenchmarkKind.PHYSICAL,
        exact=exact,
        full=100,
        baseline=HUNDRED,
        image_name=rule.BASELINE_IMAGE,
    )
    assert result.outcome is outcome
    assert result.binding is True
    assert result.delta_points_bp == (exact - 100) * 100


def test_the_decision_uses_exact_fractions_not_rounded_recall() -> None:
    # The harness prints recall rounded to two places: 142/157 shows as 90.45
    # against the baseline's 95.45, which reads as exactly 5 points. The exact
    # gap is 5.0087 points, which is not within 5.
    baseline = Baseline(
        image=rule.BASELINE_IMAGE, tool="t", full=22, exact=21, source="test"
    )
    assert round(100 * 142 / 157, 2) - round(100 * 21 / 22, 2) == pytest.approx(-5)
    near = evaluate_rule(
        BenchmarkKind.PHYSICAL,
        exact=142,
        full=157,
        baseline=baseline,
        image_name=rule.BASELINE_IMAGE,
    )
    assert near.outcome is RuleOutcome.BETWEEN_THRESHOLDS
    # Exactly 5 points below is within: 199/220 against 21/22.
    edge = evaluate_rule(
        BenchmarkKind.PHYSICAL,
        exact=199,
        full=220,
        baseline=baseline,
        image_name=rule.BASELINE_IMAGE,
    )
    assert edge.outcome is RuleOutcome.PASS
    assert edge.delta_points_exact == "-5/1"


def test_a_synthetic_result_is_never_judged_by_the_physical_rule() -> None:
    result = evaluate_rule(BenchmarkKind.SYNTHETIC, exact=50, full=100,
                           baseline=HUNDRED, image_name=rule.BASELINE_IMAGE)
    assert result.outcome is RuleOutcome.NOT_APPLICABLE
    assert result.binding is False
    assert result.delta_points_bp == -5000


def test_a_different_image_is_a_different_experiment() -> None:
    result = evaluate_rule(BenchmarkKind.PHYSICAL, exact=100, full=100,
                           baseline=HUNDRED, image_name="media-exfat-255m.img")
    assert result.outcome is RuleOutcome.NOT_EVALUATED
    assert result.binding is False


def test_without_a_baseline_nothing_is_decided() -> None:
    result = evaluate_rule(BenchmarkKind.PHYSICAL, exact=100, full=100, baseline=None,
                           image_name=rule.BASELINE_IMAGE, baseline_problem="gone")
    assert result.outcome is RuleOutcome.NOT_EVALUATED
    assert result.reason == "gone"


def test_high_false_positives_are_not_part_of_the_rule() -> None:
    result = evaluate_rule(BenchmarkKind.PHYSICAL, exact=100, full=100,
                           baseline=HUNDRED, image_name=rule.BASELINE_IMAGE)
    assert "observation" in result.methodology
    assert "5/10 recall rule alone" in result.methodology
    assert not any("high" in name.lower() for name in type(result).model_fields)
