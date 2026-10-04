"""Measure what the confidence buckets actually mean, and write the evidence down.

An uncalibrated score is a number somebody made up. This harness turns it into
a measurement: build a corpus whose contents are known byte for byte, run the
whole carving pipeline over it, and count how often each bucket was right.

A candidate is a **true positive** when its SHA-256 matches a planted object
the manifest marks recoverable. Nothing softer counts - not "starts at the
right offset", not "is the right type" - because a recovered file that differs
from the original by one byte is a file that does not open.

Three tables come out, and each answers a different question an examiner asks:

* **by bucket** - does HIGH mean what it claims? Precision here is what the
  word "high confidence" is worth in a report.
* **by format** - which decoders are carrying the score, and which formats are
  being scored on structure alone.
* **by source** - whether filesystem metadata, structure parsing or a raw
  signature match found the file.

Results land in ``docs/performance/calibration.csv`` with a matplotlib chart
beside them. The reasoning, and every weight that moved because of a run, is
recorded in ``docs/performance/calibration.md``.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from core.carve.classify import classify_candidate, dedupe
from core.carve.evidence import open_evidence
from core.carve.score import WEIGHTS, ScoreWeights, resolve_overlaps, score_candidate
from core.carve.structure import carve_structures
from core.carve.validate import validate_candidate
from core.models import CarveCandidate

from testkit.generate_corpus import (
    CorpusManifest,
    FilesystemCorpus,
    generate_corpus,
    generate_filesystem_corpus,
    load_filesystem_manifest,
    load_manifest,
)

__all__ = [
    "BucketRow",
    "CalibrationResult",
    "CSV_COLUMNS",
    "run_pipeline",
    "measure",
    "write_csv",
    "write_chart",
    "calibrate",
    "PooledCalibration",
    "measure_pooled",
    "calibrate_pooled",
    "format_per_seed",
    "FilesystemRow",
    "WeightTrial",
    "FilesystemCalibration",
    "FS_CSV_COLUMNS",
    "FS_WEIGHT_SWEEP",
    "score_filesystem_candidates",
    "measure_filesystems",
    "sweep_fs_metadata_weight",
    "calibrate_filesystems",
    "format_filesystem_table",
    "format_weight_sweep",
    "main",
]

#: Where a run writes by default. Committed, so a reader of the report can
#: check the numbers rather than take them on trust.
DEFAULT_OUT_DIR = Path(__file__).resolve().parents[1] / "docs" / "performance"

CSV_COLUMNS = (
    "dimension",
    "key",
    "count",
    "true_positives",
    "precision_bp",
    "recall_bp",
)

BUCKETS = ("HIGH", "MEDIUM", "LOW")


@dataclass(frozen=True)
class BucketRow:
    """One measured row: a slice of the candidates, and how it performed."""

    dimension: str
    key: str
    count: int
    true_positives: int
    #: Share of candidates in this slice that matched a planted object, in
    #: basis points. Integer for the same reason every other rate in this
    #: codebase is one: it ends up in a report a third party reads.
    precision_bp: int
    #: Share of the corpus's recoverable objects this slice recovered, in
    #: basis points.
    recall_bp: int

    def as_row(self) -> dict[str, str | int]:
        return {
            "dimension": self.dimension,
            "key": self.key,
            "count": self.count,
            "true_positives": self.true_positives,
            "precision_bp": self.precision_bp,
            "recall_bp": self.recall_bp,
        }


@dataclass(frozen=True)
class CalibrationResult:
    """Everything one calibration run produced."""

    weights: ScoreWeights
    manifest: CorpusManifest
    candidates: list[CarveCandidate]
    rows: list[BucketRow]
    csv_path: Path
    chart_path: Path | None

    def bucket(self, name: str) -> BucketRow:
        """The row for one confidence bucket."""
        for row in self.rows:
            if row.dimension == "bucket" and row.key == name:
                return row
        raise KeyError(name)


def run_pipeline(
    corpus_dir: Path, manifest: CorpusManifest, *, weights: ScoreWeights = WEIGHTS
) -> list[CarveCandidate]:
    """Carve, validate, classify, score, resolve overlaps, dedupe.

    The same order the product runs in. Scoring comes after validation because
    the decoder verdict is a score component, and overlap resolution comes
    after scoring because the winner of an overlap is the higher score.
    """
    image_path = Path(corpus_dir) / manifest.image
    with open_evidence(image_path) as image:
        carved = list(carve_structures(image))
        judged = [
            score_candidate(
                classify_candidate(
                    validate_candidate(candidate, image), image=image
                ),
                image=image,
                weights=weights,
            )
            for candidate in carved
        ]
    return dedupe(resolve_overlaps(judged, weights=weights))


def _rate_bp(part: int, whole: int) -> int:
    return int(round(part * 10_000 / whole)) if whole else 0


def _row(
    dimension: str,
    key: str,
    slice_: Sequence[CarveCandidate],
    truth: set[str],
    total_recoverable: int,
) -> BucketRow:
    hits = [item for item in slice_ if item.sha256 in truth]
    found = {item.sha256 for item in hits}
    return BucketRow(
        dimension=dimension,
        key=key,
        count=len(slice_),
        true_positives=len(hits),
        precision_bp=_rate_bp(len(hits), len(slice_)),
        recall_bp=_rate_bp(len(found), total_recoverable),
    )


def measure(
    candidates: Sequence[CarveCandidate], manifest: CorpusManifest
) -> list[BucketRow]:
    """Score the run against the manifest, by bucket, by format and by source."""
    truth = manifest.recoverable_digests
    total = len(truth)

    rows = [
        _row(
            "bucket",
            bucket,
            [item for item in candidates if item.bucket == bucket],
            truth,
            total,
        )
        for bucket in BUCKETS
    ]
    rows.append(_row("bucket", "ALL", list(candidates), truth, total))

    for ext in sorted({item.ext for item in candidates}):
        rows.append(
            _row(
                "format",
                ext,
                [item for item in candidates if item.ext == ext],
                truth,
                total,
            )
        )
    for source in sorted({item.source for item in candidates}):
        rows.append(
            _row(
                "source",
                source,
                [item for item in candidates if item.source == source],
                truth,
                total,
            )
        )
    for verdict in sorted({item.validation for item in candidates}):
        rows.append(
            _row(
                "validation",
                verdict,
                [item for item in candidates if item.validation == verdict],
                truth,
                total,
            )
        )
    return rows


def write_csv(rows: Iterable[BucketRow], path: Path) -> Path:
    """Write the measured table. One file, every dimension, no summarising."""
    path.parent.mkdir(parents=True, exist_ok=True)
    # newline="" is the csv module's requirement; lineterminator is what stops
    # it writing CRLF into a repository that is eol=lf everywhere else, which
    # rewrites every line of the file on every regeneration.
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=list(CSV_COLUMNS), lineterminator="\n"
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row.as_row())
    return path


def write_chart(rows: Sequence[BucketRow], path: Path) -> Path | None:
    """Plot precision and recall per bucket. Returns None if matplotlib is absent."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return None

    buckets = [row for row in rows if row.dimension == "bucket" and row.key != "ALL"]
    labels = [f"{row.key}\n(n={row.count})" for row in buckets]
    precision = [row.precision_bp / 100 for row in buckets]
    recall = [row.recall_bp / 100 for row in buckets]
    positions = range(len(buckets))
    width = 0.38

    figure, axes = plt.subplots(figsize=(7.5, 4.5))
    axes.bar(
        [pos - width / 2 for pos in positions],
        precision,
        width,
        label="precision %",
        color="#2f6f4f",
    )
    axes.bar(
        [pos + width / 2 for pos in positions],
        recall,
        width,
        label="recall %",
        color="#7a4f8f",
    )
    axes.axhline(95, linestyle="--", linewidth=1, color="#444444")
    axes.text(len(buckets) - 0.5, 95.6, "HIGH target 95%", fontsize=8, ha="right")
    axes.axhline(70, linestyle=":", linewidth=1, color="#444444")
    axes.text(len(buckets) - 0.5, 70.6, "MEDIUM target 70%", fontsize=8, ha="right")
    axes.set_xticks(list(positions))
    axes.set_xticklabels(labels)
    axes.set_ylim(0, 105)
    axes.set_ylabel("percent")
    axes.set_title("Carve confidence buckets: measured precision and recall")
    axes.legend(loc="lower left")
    figure.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(path, dpi=140)
    plt.close(figure)
    return path


def calibrate(
    corpus_dir: Path,
    out_dir: Path = DEFAULT_OUT_DIR,
    *,
    seed: int = 0,
    regenerate: bool = True,
    chart: bool = True,
    weights: ScoreWeights = WEIGHTS,
) -> CalibrationResult:
    """Build the corpus, run the pipeline over it, and write the measurement."""
    corpus_dir = Path(corpus_dir)
    manifest = (
        generate_corpus(corpus_dir, seed=seed)
        if regenerate
        else load_manifest(corpus_dir)
    )
    candidates = run_pipeline(corpus_dir, manifest, weights=weights)
    rows = measure(candidates, manifest)
    csv_path = write_csv(rows, Path(out_dir) / "calibration.csv")
    chart_path = write_chart(rows, Path(out_dir) / "calibration.png") if chart else None
    return CalibrationResult(
        weights=weights,
        manifest=manifest,
        candidates=candidates,
        rows=rows,
        csv_path=csv_path,
        chart_path=chart_path,
    )


@dataclass(frozen=True)
class PooledCalibration:
    """Several seeds' runs, measured as one population.

    Why pooling rather than averaging: precision is a ratio of counts, and the
    mean of per-seed ratios is not the ratio of the pooled counts unless every
    seed produced the same number of candidates - which they do not, because a
    different seed plants different objects. Pooling the candidates and
    measuring once gives the figure an examiner would compute from the raw
    data, which is the figure the document has to carry.
    """

    seeds: tuple[int, ...]
    #: Per-seed rows, kept so a reader can see the spread and not only the
    #: pooled number. A single outlying seed is a fact about the measurement.
    per_seed: dict[int, list[BucketRow]]
    rows: list[BucketRow]
    candidate_count: int
    recoverable_count: int
    csv_path: Path
    chart_path: Path | None

    def bucket(self, name: str) -> BucketRow:
        for row in self.rows:
            if row.dimension == "bucket" and row.key == name:
                return row
        raise KeyError(name)


def measure_pooled(
    runs: Sequence[tuple[Sequence[CarveCandidate], CorpusManifest]],
) -> list[BucketRow]:
    """Measure several corpus runs as one population.

    Each run has its own manifest, so the truth set is the union of every run's
    recoverable digests and the recall denominator is the total across runs. A
    digest is globally unique - it is the SHA-256 of the planted bytes - so the
    union is well defined and a file planted by two seeds is counted once.
    """
    truth: set[str] = set()
    for _, manifest in runs:
        truth |= manifest.recoverable_digests
    candidates: list[CarveCandidate] = []
    for run_candidates, _ in runs:
        candidates.extend(run_candidates)

    total = len(truth)
    rows = [
        _row(
            "bucket",
            bucket,
            [c for c in candidates if c.bucket == bucket],
            truth,
            total,
        )
        for bucket in BUCKETS
    ]
    rows.append(_row("bucket", "ALL", candidates, truth, total))
    for dimension, attribute in (
        ("format", "ext"),
        ("source", "source"),
        ("validation", "validation"),
    ):
        for key in sorted({str(getattr(item, attribute)) for item in candidates}):
            rows.append(
                _row(
                    dimension,
                    key,
                    [c for c in candidates if str(getattr(c, attribute)) == key],
                    truth,
                    total,
                )
            )
    return rows


def calibrate_pooled(
    corpus_dir: Path,
    out_dir: Path = DEFAULT_OUT_DIR,
    *,
    seeds: Sequence[int],
    chart: bool = True,
    weights: ScoreWeights = WEIGHTS,
) -> PooledCalibration:
    """Run the sweep over several seeds and measure them as one population.

    The single-seed :func:`calibrate` measured 24 planted objects, which is
    enough to show the buckets are ordered and too few to say what HIGH is
    worth: one decoy landing in the wrong bucket moves precision by four
    points. Each seed plants a different set at different offsets, so N seeds
    is N times the population over the same pipeline, with no change to the
    scoring code and nothing hand-picked.

    Each seed gets its own corpus directory, so a run is reproducible from the
    seed list alone and two seeds cannot overwrite each other's image.
    """
    runs: list[tuple[list[CarveCandidate], CorpusManifest]] = []
    per_seed: dict[int, list[BucketRow]] = {}
    for seed in seeds:
        seed_dir = Path(corpus_dir) / f"seed-{seed}"
        manifest = generate_corpus(seed_dir, seed=seed)
        candidates = run_pipeline(seed_dir, manifest, weights=weights)
        runs.append((candidates, manifest))
        per_seed[seed] = measure(candidates, manifest)

    rows = measure_pooled(runs)
    csv_path = write_csv(rows, Path(out_dir) / "calibration-pooled.csv")
    chart_path = (
        write_chart(rows, Path(out_dir) / "calibration-pooled.png") if chart else None
    )
    truth: set[str] = set()
    for _, manifest in runs:
        truth |= manifest.recoverable_digests
    return PooledCalibration(
        seeds=tuple(seeds),
        per_seed=per_seed,
        rows=rows,
        candidate_count=sum(len(candidates) for candidates, _ in runs),
        recoverable_count=len(truth),
        csv_path=csv_path,
        chart_path=chart_path,
    )


def format_per_seed(pooled: PooledCalibration) -> str:
    """Per-seed HIGH-bucket precision and recall, so the spread is visible.

    A pooled number with no spread beside it invites the reader to assume the
    seeds agreed. Sometimes they do not, and that is a measurement too.
    """
    header = f"{'seed':>6}{'n':>6}{'TP':>5}{'HIGH prec':>12}{'ALL recall':>12}"
    lines = [header, "-" * len(header)]
    for seed in pooled.seeds:
        rows = pooled.per_seed[seed]
        high = next(r for r in rows if r.dimension == "bucket" and r.key == "HIGH")
        every = next(r for r in rows if r.dimension == "bucket" and r.key == "ALL")
        lines.append(
            f"{seed:>6}{every.count:>6}{every.true_positives:>5}"
            f"{high.precision_bp / 100:>11.1f}%{every.recall_bp / 100:>11.1f}%"
        )
    return "\n".join(lines)


def format_table(rows: Sequence[BucketRow]) -> str:
    """Render the measured rows as fixed-width text, for a commit message."""
    header = (
        f"{'dimension':<11}{'key':<22}{'n':>5}{'TP':>5}"
        f"{'precision':>11}{'recall':>9}"
    )
    lines = [header, "-" * len(header)]
    for row in rows:
        lines.append(
            f"{row.dimension:<11}{row.key:<22}{row.count:>5}{row.true_positives:>5}"
            f"{row.precision_bp / 100:>10.1f}%{row.recall_bp / 100:>8.1f}%"
        )
    return "\n".join(lines)


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Calibrate carve confidence buckets against a known corpus."
    )
    parser.add_argument(
        "--corpus-dir",
        type=Path,
        required=True,
        help="directory the corpus is written to and carved from",
    )
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument(
        "--reuse-corpus",
        action="store_true",
        help="carve an existing corpus instead of regenerating it",
    )
    parser.add_argument("--no-chart", action="store_true")
    parser.add_argument(
        "--seeds",
        type=str,
        default="",
        help=(
            "comma-separated seeds to pool into one population, e.g. "
            "0,1,2,3,4,5,6,7. Each seed plants a different corpus, and the "
            "candidates are measured together: a larger population over the "
            "same pipeline, with nothing hand-picked. Writes "
            "calibration-pooled.csv beside the single-seed table."
        ),
    )
    parser.add_argument(
        "--filesystems",
        action="store_true",
        help=(
            "build the real filesystem images instead of the flat corpus, and "
            "measure per-filesystem recall plus the fs_metadata weight sweep"
        ),
    )
    args = parser.parse_args()

    if args.filesystems:
        filesystems = calibrate_filesystems(
            args.corpus_dir,
            args.out_dir,
            seed=args.seed,
            regenerate=not args.reuse_corpus,
        )
        print(format_filesystem_table(filesystems.rows))  # noqa: T201 - a CLI
        print()  # noqa: T201
        print(format_weight_sweep(filesystems.sweep))  # noqa: T201
        print(f"\nwrote {filesystems.csv_path}")  # noqa: T201
        return

    if args.seeds:
        seeds = [int(part) for part in args.seeds.split(",") if part.strip()]
        pooled = calibrate_pooled(
            args.corpus_dir,
            args.out_dir,
            seeds=seeds,
            chart=not args.no_chart,
        )
        print(format_per_seed(pooled))  # noqa: T201 - a CLI
        print()  # noqa: T201
        print(format_table(pooled.rows))  # noqa: T201
        print(  # noqa: T201
            f"\npooled {pooled.candidate_count} candidates over "
            f"{len(pooled.seeds)} seeds against {pooled.recoverable_count} "
            "recoverable objects"
        )
        print(f"wrote {pooled.csv_path}")  # noqa: T201
        if pooled.chart_path is not None:
            print(f"wrote {pooled.chart_path}")  # noqa: T201
        return

    result = calibrate(
        args.corpus_dir,
        args.out_dir,
        seed=args.seed,
        regenerate=not args.reuse_corpus,
        chart=not args.no_chart,
    )
    print(format_table(result.rows))  # noqa: T201 - this is a CLI, not a core layer
    print(f"\nwrote {result.csv_path}")  # noqa: T201
    if result.chart_path is not None:
        print(f"wrote {result.chart_path}")  # noqa: T201



# --------------------------------------------------------------------------
# Filesystem-aware recovery
# --------------------------------------------------------------------------
#
# The corpus above is a flat image, so it exercises the signature and structure
# carvers and never produces an fs_metadata candidate. That is why the
# fs_metadata weight went uncalibrated through the first run and kept its
# invented value. This section measures it against real filesystem images, and
# reports recall per filesystem rather than one averaged number - because the
# average of NTFS and ext4 describes neither.

#: Weights to try for the fs_metadata component. 0 asks what the component is
#: worth at all; 3000 is past the point where it could carry a candidate into
#: HIGH on its own.
FS_WEIGHT_SWEEP = (0, 500, 1000, 1500, 2000, 2500, 3000, 3500, 4000, 5000)

FS_CSV_COLUMNS = (
    "filesystem",
    "damage",
    "pipeline",
    "deleted",
    "candidates",
    "named",
    "exact",
    "recall_bp",
    "precision_bp",
)

#: How the files in the corpus were made unreachable. The corpus deletes them;
#: nothing in ``testkit/`` quick-formats a volume. Recorded in the CSV because
#: a baseline row is only a baseline for the damage model that produced it, and
#: scoring a quick-format run against a delete row compares two experiments.
FS_DAMAGE = "delete"

#: Which halves of the recovery pipeline produced the numbers in the row.
#: :func:`score_filesystem_candidates` calls ``undelete_report()`` and nothing
#: else, so the signature carver contributes no candidate here and no false
#: positive either. A real run that carves signatures as well is measuring a
#: different pipeline, and its precision is not comparable to this one under
#: the same column name.
FS_PIPELINE = "undelete"


@dataclass(frozen=True)
class FilesystemRow:
    """What recovery achieved on one filesystem, measured against the manifest."""

    filesystem: str
    #: Damage model that made the files unreachable. See :data:`FS_DAMAGE`.
    damage: str
    #: Pipeline halves that produced the row. See :data:`FS_PIPELINE`.
    pipeline: str
    #: Deleted files planted, counted by distinct SHA-256.
    deleted: int
    #: ``source="fs_metadata"`` candidates the pass emitted.
    candidates: int
    #: Candidates carrying an original filename.
    named: int
    #: Deleted files reproduced byte for byte.
    exact: int
    #: ``exact / deleted``, in basis points. The honest answer to "how well
    #: does it work" - the denominator is every deleted file, not only the ones
    #: the manifest expects to be recoverable, because using the latter would
    #: be marking one's own homework.
    recall_bp: int
    #: ``exact / candidates``, in basis points.
    precision_bp: int

    def as_row(self) -> dict[str, str | int]:
        return {
            "filesystem": self.filesystem,
            "damage": self.damage,
            "pipeline": self.pipeline,
            "deleted": self.deleted,
            "candidates": self.candidates,
            "named": self.named,
            "exact": self.exact,
            "recall_bp": self.recall_bp,
            "precision_bp": self.precision_bp,
        }


@dataclass(frozen=True)
class WeightTrial:
    """What one candidate value of the fs_metadata weight produced."""

    high_count: int
    #: Share of HIGH candidates that reproduced a planted file exactly.
    high_precision_bp: int
    #: Share of deleted files recovered exactly *and* scored HIGH.
    high_recall_bp: int
    #: Candidates at MEDIUM or above that recovered **no bytes at all**. These
    #: are the name-only recoveries: a filename from index slack with nothing
    #: behind it. Any number above zero here means the weight is telling an
    #: examiner to give weight to a candidate that recovered nothing.
    contentless_at_medium_or_above: int
    #: Candidates at HIGH that no decoder confirmed. The fs_metadata component
    #: must never be large enough to put one of these in HIGH on its own:
    #: "a filesystem record agrees a file lived here" says nothing about
    #: whether the bytes now at that location are that file.
    unconfirmed_at_high: int


@dataclass(frozen=True)
class FilesystemCalibration:
    """One sweep of the fs_metadata weight over the filesystem corpus."""

    rows: list[FilesystemRow]
    #: ``{weight: WeightTrial}``.
    sweep: dict[int, WeightTrial]
    #: Every scored candidate from the run at the weight in force.
    candidates: list[CarveCandidate]
    csv_path: Path | None = None


def score_filesystem_candidates(
    corpus_dir: Path,
    corpus: FilesystemCorpus,
    *,
    weights: ScoreWeights = WEIGHTS,
) -> list[tuple[str, CarveCandidate, bytes]]:
    """Run undelete, then the rest of the pipeline, over every corpus image.

    Returns ``(image, scored candidate, recovered bytes)``. The bytes travel
    with the candidate because they have to: a candidate whose file lived in
    several runs cannot be re-read from ``offset`` and ``length``, so the
    decoder, the classifier and the scorer are all handed the reassembled
    content rather than left to fetch a contiguous range that was never a file.
    """
    from core.carve.fsaware import read_recovered, undelete_report

    out: list[tuple[str, CarveCandidate, bytes]] = []
    for image in corpus.images:
        path = Path(corpus_dir) / image
        if not path.exists():
            continue
        with open_evidence(path) as handle:
            report = undelete_report(handle)
            scored: list[CarveCandidate] = []
            payloads: list[bytes] = []
            for item in report.files:
                payload = read_recovered(handle, item)
                candidate = validate_candidate(item.candidate, data=payload)
                candidate = classify_candidate(candidate, data=payload)
                candidate = score_candidate(candidate, data=payload, weights=weights)
                scored.append(candidate)
                payloads.append(payload)
        # Overlaps are resolved per image: two candidates in different images
        # cannot claim the same bytes, and pooling them would invent conflicts.
        resolved = resolve_overlaps(scored, weights=weights)
        by_offset = {(item.offset, item.length): item for item in resolved}
        for candidate, payload in zip(scored, payloads, strict=True):
            final = by_offset.get((candidate.offset, candidate.length), candidate)
            out.append((image, final, payload))
    return out


def measure_filesystems(
    corpus_dir: Path, corpus: FilesystemCorpus, *, weights: ScoreWeights = WEIGHTS
) -> list[FilesystemRow]:
    """Recall and precision per filesystem, counted on byte-identical recovery."""
    scored = score_filesystem_candidates(corpus_dir, corpus, weights=weights)

    # Counted per image and then summed, never pooled by digest across images.
    # The same NTFS file is planted in ntfs.img, ntfs-reused.img and
    # two-partitions.img; pooling would put it in the denominator once and in
    # the numerator once while three separate recoveries of it sat in the
    # candidate count, and NTFS precision would come out at a third of the
    # truth for an arithmetic reason rather than a forensic one.
    # Keyed by (image, filesystem), not by image. two-partitions.img holds an
    # NTFS volume and a FAT32 one; keying by image alone would file every FAT32
    # candidate under NTFS and report NTFS precision at a sixth of the truth.
    deleted: dict[tuple[str, str], set[str]] = {}
    for planted in corpus.files:
        if planted.deleted:
            key = (planted.image, planted.filesystem)
            deleted.setdefault(key, set()).add(planted.sha256)

    per_image_hits: dict[tuple[str, str], set[str]] = {}
    counted: dict[tuple[str, str], int] = {}
    named: dict[tuple[str, str], int] = {}
    for image, candidate, payload in scored:
        key = (image, candidate.fs_type or "unknown")
        counted[key] = counted.get(key, 0) + 1
        if candidate.original_name:
            named[key] = named.get(key, 0) + 1
        if payload:
            digest = hashlib.sha256(payload).hexdigest()
            if digest in deleted.get(key, set()):
                per_image_hits.setdefault(key, set()).add(digest)

    totals: dict[str, list[int]] = {}
    for key in set(deleted) | set(counted):
        bucket = totals.setdefault(key[1], [0, 0, 0, 0])
        bucket[0] += len(deleted.get(key, set()))
        bucket[1] += counted.get(key, 0)
        bucket[2] += named.get(key, 0)
        bucket[3] += len(per_image_hits.get(key, set()))

    return [
        FilesystemRow(
            filesystem=filesystem,
            damage=FS_DAMAGE,
            pipeline=FS_PIPELINE,
            deleted=want,
            candidates=candidates,
            named=with_names,
            exact=hits,
            recall_bp=_rate_bp(hits, want),
            precision_bp=_rate_bp(hits, candidates),
        )
        for filesystem, (want, candidates, with_names, hits) in sorted(totals.items())
    ]


def sweep_fs_metadata_weight(
    corpus_dir: Path,
    corpus: FilesystemCorpus,
    *,
    weights: Sequence[int] = FS_WEIGHT_SWEEP,
) -> dict[int, WeightTrial]:
    """Measure HIGH precision and recall at each candidate fs_metadata weight.

    HIGH is the bucket the report tells an examiner to trust, so it is the one
    the weight has to be chosen for. Recall here is over every deleted file in
    the corpus, across all five filesystems, which means the ext4 rows drag it
    down - correctly. A weight tuned on NTFS alone would be a weight tuned on
    the easiest case.
    """
    per_image_truth: dict[tuple[str, str], set[str]] = {}
    for planted in corpus.files:
        if planted.deleted:
            key = (planted.image, planted.filesystem)
            per_image_truth.setdefault(key, set()).add(planted.sha256)
    total_deleted = sum(len(items) for items in per_image_truth.values())

    results: dict[int, tuple[int, int, int]] = {}
    for weight in weights:
        trial = replace(WEIGHTS, fs_metadata=weight)
        scored = score_filesystem_candidates(corpus_dir, corpus, weights=trial)
        high = [
            ((image, candidate.fs_type or "unknown"), payload)
            for image, candidate, payload in scored
            if candidate.bucket == "HIGH"
        ]
        correct = 0
        hits: dict[tuple[str, str], set[str]] = {}
        for key, payload in high:
            if not payload:
                continue
            digest = hashlib.sha256(payload).hexdigest()
            if digest in per_image_truth.get(key, set()):
                correct += 1
                hits.setdefault(key, set()).add(digest)
        contentless = sum(
            1
            for _image, candidate, payload in scored
            if candidate.bucket in {"HIGH", "MEDIUM"} and not payload
        )
        unconfirmed = sum(
            1
            for _image, candidate, _payload in scored
            if candidate.bucket == "HIGH" and candidate.validation != "valid"
        )
        results[weight] = WeightTrial(
            high_count=len(high),
            high_precision_bp=_rate_bp(correct, len(high)),
            high_recall_bp=_rate_bp(
                sum(len(items) for items in hits.values()), total_deleted
            ),
            contentless_at_medium_or_above=contentless,
            unconfirmed_at_high=unconfirmed,
        )
    return results


def calibrate_filesystems(
    corpus_dir: Path,
    out_dir: Path = DEFAULT_OUT_DIR,
    *,
    seed: int = 0,
    regenerate: bool = True,
    weights: ScoreWeights = WEIGHTS,
) -> FilesystemCalibration:
    """Build the filesystem corpus, measure it, and sweep the fs_metadata weight."""
    corpus_dir = Path(corpus_dir)
    corpus = (
        generate_filesystem_corpus(corpus_dir, seed=seed)
        if regenerate
        else load_filesystem_manifest(corpus_dir)
    )
    rows = measure_filesystems(corpus_dir, corpus, weights=weights)
    sweep = sweep_fs_metadata_weight(corpus_dir, corpus)
    scored = score_filesystem_candidates(corpus_dir, corpus, weights=weights)

    path = Path(out_dir) / "calibration-filesystems.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=list(FS_CSV_COLUMNS), lineterminator="\n"
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row.as_row())

    return FilesystemCalibration(
        rows=rows,
        sweep=sweep,
        candidates=[candidate for _image, candidate, _payload in scored],
        csv_path=path,
    )


def format_filesystem_table(rows: Sequence[FilesystemRow]) -> str:
    """Render the per-filesystem measurement for a commit message."""
    header = (
        f"{'filesystem':<12}{'deleted':>8}{'cands':>7}{'named':>7}"
        f"{'exact':>7}{'recall':>9}{'precision':>11}"
    )
    lines = [header, "-" * len(header)]
    for row in rows:
        lines.append(
            f"{row.filesystem:<12}{row.deleted:>8}{row.candidates:>7}"
            f"{row.named:>7}{row.exact:>7}"
            f"{row.recall_bp / 100:>8.1f}%{row.precision_bp / 100:>10.1f}%"
        )
    return "\n".join(lines)


def format_weight_sweep(sweep: dict[int, WeightTrial]) -> str:
    """Render the fs_metadata sweep for a commit message.

    The last two columns are the ones that decide the weight. Precision and
    recall can both be improved by raising it, because this corpus contains
    hundreds of correctly recovered filler files - and the same rise puts
    candidates in HIGH that no decoder ever confirmed, including one the corpus
    knows is wrong. An aggregate that improves while those columns go non-zero
    is an aggregate to distrust.
    """
    header = (
        f"{'fs_metadata':<13}{'HIGH n':>8}{'precision':>11}{'recall':>9}"
        f"{'empty>=MED':>12}{'unconfirmed@HIGH':>18}"
    )
    lines = [header, "-" * len(header)]
    for weight in sorted(sweep):
        trial = sweep[weight]
        lines.append(
            f"{weight:<13}{trial.high_count:>8}"
            f"{trial.high_precision_bp / 100:>10.1f}%"
            f"{trial.high_recall_bp / 100:>8.1f}%"
            f"{trial.contentless_at_medium_or_above:>12}"
            f"{trial.unconfirmed_at_high:>18}"
        )
    return "\n".join(lines)

if __name__ == "__main__":
    main()
