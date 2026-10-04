"""Score recovered outputs against a sealed ground-truth manifest.

Attribution is :func:`core.benchmark.outputs.attribute_outputs`, the same code
the synthetic benchmark's ``score_run`` runs, so the totals here equal that
scorer's totals on the same inputs (``tests/benchmark`` checks it). What this
module adds is the per-file table: for every planted object, whether it came
back byte-identical, corrupt (with how much of it agrees), or not at all, and
which outputs were false positives or duplicates. Fragmented files are totalled
separately, because recovering a file in two runs is a different problem from
recovering one in one.

Counting rules, all inherited from the synthetic benchmark:

* Planted objects with the same content form one group and count once. The
  group's status is its least-damaged member's.
* Only FULL ``file`` groups are in the recall denominator. PARTIAL and GONE
  groups are reported as returned / not returned; ``unformatted`` content is
  reported apart; decoys are never recovery targets.

The agreement ratio of a corrupt recovery is the share of byte positions at
which the output equals the planted object, over the longer of the two, in
integer basis points. When only an output index survives (not the file), just
its first 64 KiB is known, and the ratio is a lower bound, labelled as such.

Nothing here opens a device. Output files and image files are read only.
"""

from __future__ import annotations

import hashlib
import operator
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Literal

import structlog
from pydantic import BaseModel, ConfigDict

from core.benchmark.manifest import ExpectedFile, GroundTruthManifest
from core.benchmark.outputs import (
    Attribution,
    OutputAttribution,
    OutputRecord,
    attribute_outputs,
    load_outputs,
    select_outputs,
)
from core.errors import EvidenceIntegrityError

__all__ = [
    "SCORER_VERSION",
    "Outcome",
    "FileResult",
    "OutputFinding",
    "ScoreCounts",
    "FragmentedCounts",
    "HighBucketObservation",
    "ScoreReport",
    "load_references",
    "score_outputs",
    "score_manifest",
    "agreement_bp",
]

logger = structlog.get_logger(__name__)

#: Bumped whenever a counting rule changes. Recorded in every result, so two
#: results from different scorer versions are never silently compared.
SCORER_VERSION = "sanctum-benchmark-scorer/1"

Outcome = Literal[
    "EXACT", "CORRUPT", "MISSED", "RETURNED", "NOT_RETURNED", "NOT_A_TARGET"
]

_SEVERITY = {"FULL": 0, "PARTIAL": 1, "GONE": 2}
_CHUNK = 1024 * 1024


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class FileResult(_Frozen):
    """One planted object's outcome."""

    name: str
    format: str
    role: str
    status: str
    fragmented: bool
    size: int
    sha256: str
    outcome: Outcome
    #: Whether this object's group is in the recall denominator.
    counted_in_recall: bool
    exact_outputs: list[str]
    corrupt_outputs: list[str]
    #: Best agreement among corrupt outputs, in basis points (10000 = all).
    best_agreement_bp: int | None
    agreement_basis: Literal["full", "head_lower_bound"] | None


class OutputFinding(_Frozen):
    """An output that is a false positive or a duplicate."""

    path: str
    size: int
    sha256: str
    kind: str
    targets: list[str]
    #: The tool's own confidence bucket for this output, when it reported one.
    bucket: str | None


class ScoreCounts(_Frozen):
    """Totals, counted per distinct planted content."""

    full: int
    exact: int
    corrupt: int
    missed: int
    partial: int
    partial_returned: int
    partial_exact: int
    gone: int
    gone_returned: int
    unformatted_full: int
    unformatted_exact: int
    outputs: int
    duplicate_outputs: int
    fp_total: int
    fp_fragment: int
    fp_decoy: int
    fp_ambiguous: int
    fp_unrelated: int
    #: ``exact * 10000 // full``, or ``None`` with no FULL files.
    recall_bp: int | None


class FragmentedCounts(_Frozen):
    """The same outcomes, for FULL files stored in more than one run."""

    full: int
    exact: int
    corrupt: int
    missed: int
    names: list[str]


class HighBucketObservation(_Frozen):
    """HIGH-confidence outputs that were not byte-identical recoveries.

    An observation, not a pass/fail condition: no HIGH false-positive condition
    is registered (``docs/validation/methodology-open-decision.md``), and
    whether a corrupt HIGH recovery counts as a HIGH false positive is an open
    question for the experiment owner. Both lists are therefore reported apart,
    and neither is classified.
    """

    available: bool
    reason: str
    high_false_positives: list[str]
    high_corrupt_recoveries: list[str]


class ScoreReport(_Frozen):
    """Everything the scorer found, per file and in total."""

    scorer_version: str
    counts: ScoreCounts
    fragmented: FragmentedCounts
    files: list[FileResult]
    false_positives: list[OutputFinding]
    duplicates: list[OutputFinding]
    high_bucket: HighBucketObservation


def _reference(item: ExpectedFile, payloads: Path | None, medium: Path | None) -> bytes:
    if item.sha256 and payloads is not None and (payloads / item.sha256).is_file():
        return (payloads / item.sha256).read_bytes()
    if medium is None:
        return b""
    parts: list[bytes] = []
    with open(medium, "rb") as handle:
        for run in item.fragments:
            handle.seek(run.offset)
            parts.append(handle.read(run.length))
    return b"".join(parts)


def load_references(
    manifest: GroundTruthManifest,
    *,
    payloads: Path | None = None,
    image: Path | None = None,
) -> dict[str, bytes]:
    """Every expected file's bytes: from the payload store, else from the image.

    A payload whose SHA-256 differs from the manifest is refused: the answer key
    would be wrong without anyone noticing. The image is opened read-only and
    must be a regular file; the scorer never opens a device.
    """
    if image is not None and not image.is_file():
        raise EvidenceIntegrityError(
            f"{image} is not a regular file; the scorer reads image files only"
        )
    references: dict[str, bytes] = {}
    for item in manifest.files:
        data = _reference(item, payloads, image)
        if (
            item.sha256
            and payloads is not None
            and (payloads / item.sha256).is_file()
            and hashlib.sha256(data).hexdigest() != item.sha256
        ):
            raise EvidenceIntegrityError(
                f"payload for {item.name} does not hash to the manifest's "
                f"{item.sha256}"
            )
        references[item.name] = data
    return references


def _equal_bytes(left: bytes, right: bytes) -> int:
    """Positions below the shorter length at which the two agree."""
    equal = 0
    common = min(len(left), len(right))
    for start in range(0, common, _CHUNK):
        a = left[start : min(start + _CHUNK, common)]
        b = right[start : min(start + _CHUNK, common)]
        equal += len(a) if a == b else sum(map(operator.eq, a, b))
    return equal


def agreement_bp(output: bytes, reference: bytes) -> int:
    """Positions where ``output`` equals ``reference``, per 10000 of the longer."""
    longest = max(len(output), len(reference))
    if longest == 0:
        return 10000
    return _equal_bytes(output, reference) * 10000 // longest


def _output_agreement(
    record: OutputRecord, reference: bytes
) -> tuple[int, Literal["full", "head_lower_bound"]]:
    """Agreement of one output with its planted object, over the longer of the two.

    Every byte of the output past the planted object's end is a disagreement,
    so only ``len(reference)`` bytes of the output are ever read.
    """
    longest = max(record.size, len(reference))
    if longest == 0:
        return 10000, "full"
    if record.source is not None and record.source.is_file():
        with open(record.source, "rb") as handle:
            seen = handle.read(len(reference))
        return _equal_bytes(seen, reference) * 10000 // longest, "full"
    equal = _equal_bytes(record.head, reference)
    return equal * 10000 // longest, "head_lower_bound"


def _finding(item: OutputAttribution, buckets: Mapping[str, str]) -> OutputFinding:
    return OutputFinding(
        path=item.output.path,
        size=item.output.size,
        sha256=item.output.sha256,
        kind=item.kind,
        targets=list(item.targets),
        bucket=buckets.get(item.output.name),
    )


def score_outputs(
    manifest: GroundTruthManifest,
    references: Mapping[str, bytes],
    outputs: Sequence[OutputRecord],
    *,
    buckets: Mapping[str, str] | None = None,
) -> ScoreReport:
    """Score ``outputs`` against ``manifest``, given every expected file's bytes.

    ``buckets`` maps an output's file name to the confidence bucket the tool
    reported for it (Sanctum's ``sanctum-result.json``). Without it, the HIGH
    observation is reported as unavailable rather than as zero.
    """
    selected = select_outputs(outputs)
    attribution: Attribution = attribute_outputs(manifest.files, references, selected)
    bucket_of = dict(buckets or {})

    exact_by: dict[str, list[str]] = {}
    corrupt_by: dict[str, list[OutputAttribution]] = {}
    for item in attribution.outputs:
        if item.kind == "exact":
            for name in item.targets:
                exact_by.setdefault(name, []).append(item.output.path)
        elif item.kind == "corrupt":
            corrupt_by.setdefault(item.targets[0], []).append(item)

    groups: dict[str, list[ExpectedFile]] = {}
    for obj in manifest.files:
        if obj.role != "decoy":
            groups.setdefault(obj.sha256 or obj.name, []).append(obj)

    tally = {
        key: 0
        for key in (
            "full",
            "exact",
            "corrupt",
            "missed",
            "partial",
            "partial_returned",
            "partial_exact",
            "gone",
            "gone_returned",
            "unformatted_full",
            "unformatted_exact",
        )
    }
    frag = {"full": 0, "exact": 0, "corrupt": 0, "missed": 0}
    frag_names: list[str] = []
    outcome_of: dict[str, tuple[Outcome, bool]] = {}
    for members in groups.values():
        lead = min(members, key=lambda obj: _SEVERITY[obj.status])
        names = {obj.name for obj in members}
        hit_exact = bool(names & attribution.exact)
        hit_any = hit_exact or bool(names & attribution.corrupt)
        outcome: Outcome
        counted = False
        if lead.role == "unformatted":
            if lead.status == "FULL":
                tally["unformatted_full"] += 1
                tally["unformatted_exact"] += int(hit_exact)
            outcome = "EXACT" if hit_exact else "CORRUPT" if hit_any else "MISSED"
        elif lead.status == "FULL":
            counted = True
            tally["full"] += 1
            outcome = "EXACT" if hit_exact else "CORRUPT" if hit_any else "MISSED"
            tally[outcome.lower()] += 1
            if lead.fragmented:
                frag["full"] += 1
                frag[outcome.lower()] += 1
                frag_names.extend(sorted(names))
        elif lead.status == "PARTIAL":
            tally["partial"] += 1
            tally["partial_returned"] += int(hit_any)
            tally["partial_exact"] += int(hit_exact)
            outcome = "RETURNED" if hit_any else "NOT_RETURNED"
        else:
            tally["gone"] += 1
            tally["gone_returned"] += int(hit_any)
            outcome = "RETURNED" if hit_any else "NOT_RETURNED"
        for name in names:
            outcome_of[name] = (outcome, counted)

    files: list[FileResult] = []
    for obj in manifest.files:
        best: int | None = None
        basis: Literal["full", "head_lower_bound"] | None = None
        for item in corrupt_by.get(obj.name, []):
            ratio, how = _output_agreement(item.output, references[obj.name])
            if best is None or ratio > best:
                best, basis = ratio, how
        outcome, counted = outcome_of.get(obj.name, ("NOT_A_TARGET", False))
        files.append(
            FileResult(
                name=obj.name,
                format=obj.format,
                role=obj.role,
                status=obj.status,
                fragmented=obj.fragmented,
                size=obj.size,
                sha256=obj.sha256,
                outcome=outcome,
                counted_in_recall=counted,
                exact_outputs=sorted(exact_by.get(obj.name, [])),
                corrupt_outputs=sorted(
                    item.output.path for item in corrupt_by.get(obj.name, [])
                ),
                best_agreement_bp=best,
                agreement_basis=basis,
            )
        )

    false_positives = [
        _finding(item, bucket_of)
        for item in attribution.outputs
        if item.kind.startswith("fp_")
    ]
    duplicates = [
        _finding(item, bucket_of) for item in attribution.outputs if item.duplicate
    ]
    fp = {kind: attribution.count(kind) for kind in (
        "fp_fragment", "fp_decoy", "fp_ambiguous", "fp_unrelated"
    )}
    counts = ScoreCounts(
        **tally,
        outputs=len(selected),
        duplicate_outputs=attribution.duplicate_outputs,
        fp_total=sum(fp.values()),
        fp_fragment=fp["fp_fragment"],
        fp_decoy=fp["fp_decoy"],
        fp_ambiguous=fp["fp_ambiguous"],
        fp_unrelated=fp["fp_unrelated"],
        recall_bp=(tally["exact"] * 10000 // tally["full"]) if tally["full"] else None,
    )
    if buckets is None:
        high = HighBucketObservation(
            available=False,
            reason="the tool reported no confidence buckets for its outputs",
            high_false_positives=[],
            high_corrupt_recoveries=[],
        )
    else:
        high = HighBucketObservation(
            available=True,
            reason=(
                "observation only: no HIGH false-positive condition is "
                "registered, and whether a corrupt HIGH recovery is a HIGH "
                "false positive is undecided (methodology-open-decision.md)"
            ),
            high_false_positives=sorted(
                item.output.path
                for item in attribution.outputs
                if item.kind.startswith("fp_")
                and bucket_of.get(item.output.name) == "HIGH"
            ),
            high_corrupt_recoveries=sorted(
                item.output.path
                for item in attribution.outputs
                if item.kind == "corrupt" and bucket_of.get(item.output.name) == "HIGH"
            ),
        )
    report = ScoreReport(
        scorer_version=SCORER_VERSION,
        counts=counts,
        fragmented=FragmentedCounts(**frag, names=sorted(frag_names)),
        files=files,
        false_positives=false_positives,
        duplicates=duplicates,
        high_bucket=high,
    )
    logger.info(
        "benchmark_scored",
        benchmark_id=manifest.benchmark_id,
        full=counts.full,
        exact=counts.exact,
        fp_total=counts.fp_total,
    )
    return report


def score_manifest(
    manifest: GroundTruthManifest,
    outputs: Path,
    *,
    payloads: Path | None = None,
    image: Path | None = None,
    buckets: Mapping[str, str] | None = None,
) -> ScoreReport:
    """Score a directory of outputs, or an output index, against ``manifest``."""
    references = load_references(manifest, payloads=payloads, image=image)
    return score_outputs(manifest, references, load_outputs(outputs), buckets=buckets)
