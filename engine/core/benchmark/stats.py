"""Aggregate results without ever blending synthetic and physical evidence.

A recall figure measured on image files and one measured on a real device
answer different questions; averaging them produces a number that answers
neither. :func:`aggregate` therefore refuses a mix of kinds outright, and a
caller that wants both gets two aggregates.

:func:`physical_validation_status` is the only place that may say PHYSICALLY
VALIDATED, and it says so only for a PHYSICAL result whose manifest records a
source device and an acquisition of it (:func:`physical_identity_problems`)
and whose registered-rule outcome is PASS. Anything less is reported as what
it is.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from pydantic import BaseModel, ConfigDict

from core.benchmark.manifest import (
    BenchmarkKind,
    GroundTruthManifest,
    physical_identity_problems,
)
from core.benchmark.result import BenchmarkResult
from core.benchmark.rule import RuleOutcome
from core.errors import SanctumError

__all__ = [
    "PHYSICALLY_VALIDATED",
    "PHYSICALLY_RUN_NOT_VALIDATED",
    "PHYSICAL_VALIDATION_REQUIRED",
    "MixedBenchmarkKinds",
    "Aggregate",
    "PhysicalStatus",
    "aggregate",
    "aggregate_by_kind",
    "physical_validation_status",
]

PHYSICALLY_VALIDATED = "PHYSICALLY VALIDATED"
PHYSICALLY_RUN_NOT_VALIDATED = "PHYSICALLY RUN, NOT VALIDATED"
#: The repository's existing label for a claim with no physical evidence yet.
PHYSICAL_VALIDATION_REQUIRED = "PHYSICAL VALIDATION REQUIRED"

_SUMMED = (
    "full",
    "exact",
    "corrupt",
    "missed",
    "partial",
    "partial_returned",
    "gone",
    "gone_returned",
    "outputs",
    "duplicate_outputs",
    "fp_total",
)


class MixedBenchmarkKinds(SanctumError):
    """SYNTHETIC and PHYSICAL results were given to one aggregate."""

    default_remediation = (
        "Aggregate each kind separately (aggregate_by_kind) and report them "
        "side by side. They are never merged into one figure."
    )


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Aggregate(_Frozen):
    """Totals over results of one kind."""

    kind: BenchmarkKind
    results: int
    result_digests: list[str]
    scorer_versions: list[str]
    totals: dict[str, int]
    fragmented_full: int
    fragmented_exact: int
    recall_bp: int | None
    rule_outcomes: dict[str, int]


class PhysicalStatus(_Frozen):
    """Whether the registered physical benchmark has validated recovery."""

    status: str
    qualifying_results: list[str]
    reasons: list[str]


def aggregate(results: Sequence[BenchmarkResult]) -> Aggregate:
    """Sum results of **one** kind.

    Raises:
        MixedBenchmarkKinds: the results are not all the same kind.
        ValueError: no results were given.
    """
    if not results:
        raise ValueError("nothing to aggregate")
    kinds = {result.kind for result in results}
    if len(kinds) != 1:
        raise MixedBenchmarkKinds(
            "refusing to merge "
            + " and ".join(sorted(str(kind) for kind in kinds))
            + " results into one figure"
        )
    totals = {
        key: sum(int(getattr(result.score.counts, key)) for result in results)
        for key in _SUMMED
    }
    outcomes: dict[str, int] = {}
    for result in results:
        label = str(result.rule.outcome)
        outcomes[label] = outcomes.get(label, 0) + 1
    return Aggregate(
        kind=next(iter(kinds)),
        results=len(results),
        result_digests=[result.result_digest for result in results],
        scorer_versions=sorted({result.scorer_version for result in results}),
        totals=totals,
        fragmented_full=sum(r.score.fragmented.full for r in results),
        fragmented_exact=sum(r.score.fragmented.exact for r in results),
        recall_bp=(
            totals["exact"] * 10000 // totals["full"] if totals["full"] else None
        ),
        rule_outcomes=outcomes,
    )


def aggregate_by_kind(
    results: Iterable[BenchmarkResult],
) -> dict[str, Aggregate]:
    """One aggregate per kind present, never one across kinds."""
    grouped: dict[BenchmarkKind, list[BenchmarkResult]] = {}
    for result in results:
        grouped.setdefault(result.kind, []).append(result)
    return {str(kind): aggregate(items) for kind, items in sorted(grouped.items())}


def physical_validation_status(
    results: Iterable[BenchmarkResult],
    manifests: Iterable[GroundTruthManifest],
) -> PhysicalStatus:
    """PHYSICALLY VALIDATED only with a qualifying PHYSICAL result that passed.

    ``results`` and ``manifests`` must already have been loaded through
    :func:`core.benchmark.result.load_result` and
    :func:`core.benchmark.manifest.load_manifest`, which verify their digests.
    A result is matched to its manifest by digest; a PHYSICAL result whose
    manifest is not given cannot qualify.
    """
    by_digest = {manifest.manifest_digest: manifest for manifest in manifests}
    reasons: list[str] = []
    qualifying: list[str] = []
    ran: list[str] = []
    physical = [result for result in results if result.kind is BenchmarkKind.PHYSICAL]
    if not physical:
        return PhysicalStatus(
            status=PHYSICAL_VALIDATION_REQUIRED,
            qualifying_results=[],
            reasons=["no PHYSICAL benchmark result exists"],
        )
    for result in physical:
        label = f"{result.benchmark_id} ({result.result_digest[:12]})"
        manifest = by_digest.get(result.manifest_digest)
        if manifest is None:
            reasons.append(f"{label}: its manifest was not provided")
            continue
        problems = physical_identity_problems(manifest)
        if problems:
            reasons.append(f"{label}: " + "; ".join(problems))
            continue
        ran.append(label)
        if result.rule.outcome is not RuleOutcome.PASS or not result.rule.binding:
            reasons.append(
                f"{label}: registered rule outcome {result.rule.outcome} "
                f"({result.rule.reason})"
            )
            continue
        qualifying.append(result.result_digest)
    if qualifying:
        status = PHYSICALLY_VALIDATED
    elif ran:
        status = PHYSICALLY_RUN_NOT_VALIDATED
    else:
        status = PHYSICAL_VALIDATION_REQUIRED
    return PhysicalStatus(status=status, qualifying_results=qualifying, reasons=reasons)
