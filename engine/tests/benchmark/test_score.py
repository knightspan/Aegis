"""The first-class scorer: per-file outcomes, totals, and agreement with testkit.

Every output in the fixture was put there by hand, so each count is known before
the scorer runs (see ``conftest.fill_outputs``).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from core.benchmark.manifest import GroundTruthManifest
from core.benchmark.outputs import OUTPUT_INDEX, index_outputs
from core.benchmark.score import ScoreReport, agreement_bp, score_manifest
from core.benchmark.sources import synthetic_manifest
from core.errors import EvidenceIntegrityError

from tests.benchmark.conftest import Corpus


def _manifest(corpus: Corpus) -> GroundTruthManifest:
    return synthetic_manifest(
        truth_path=corpus.truth, image_path=corpus.image, benchmark_id="t", seed=0
    )


def _score(corpus: Corpus, **kwargs: object) -> ScoreReport:
    return score_manifest(
        _manifest(corpus),
        corpus.outputs,
        payloads=corpus.payloads,
        image=corpus.image,
        **kwargs,  # type: ignore[arg-type]
    )


def _row(report: ScoreReport, name: str) -> dict[str, object]:
    for item in report.files:
        if item.name == name:
            return item.model_dump()
    raise KeyError(name)


def test_every_outcome_is_counted_once(filled: Corpus) -> None:
    report = _score(filled)
    counts = report.counts
    assert (counts.full, counts.exact, counts.corrupt, counts.missed) == (5, 2, 1, 2)
    assert counts.recall_bp == 4000
    assert (counts.partial, counts.partial_returned, counts.partial_exact) == (1, 1, 0)
    assert (counts.unformatted_full, counts.unformatted_exact) == (1, 1)
    assert counts.outputs == 9  # audit.txt is a tool report and is never scored
    assert counts.duplicate_outputs == 1
    assert (counts.fp_fragment, counts.fp_decoy, counts.fp_unrelated) == (1, 1, 1)
    assert counts.fp_ambiguous == 0
    assert counts.fp_total == 3


def test_the_per_file_table_names_each_outcome(filled: Corpus) -> None:
    report = _score(filled)
    assert _row(report, "exact.jpg")["outcome"] == "EXACT"
    assert _row(report, "exact.jpg")["exact_outputs"] == [
        "a/exact.jpg",
        "b/exact-again.jpg",
    ]
    assert _row(report, "corrupt.pdf")["outcome"] == "CORRUPT"
    assert _row(report, "missed.zip")["outcome"] == "MISSED"
    assert _row(report, "partial.tif")["outcome"] == "RETURNED"
    assert _row(report, "partial.tif")["counted_in_recall"] is False
    assert _row(report, "decoy.txt")["outcome"] == "NOT_A_TARGET"
    assert _row(report, "fill.pad")["counted_in_recall"] is False
    assert [item.path for item in report.duplicates] == ["b/exact-again.jpg"]
    assert sorted((f.path, f.kind) for f in report.false_positives) == [
        ("f/inner.bin", "fp_fragment"),
        ("g/noise.bin", "fp_unrelated"),
        ("h/decoy.jpg", "fp_decoy"),
    ]


def test_a_corrupt_recovery_reports_its_byte_agreement(filled: Corpus) -> None:
    row = _row(_score(filled), "corrupt.pdf")
    size = len(filled.data("corrupt.pdf"))
    # 3000 bytes agree, every later byte was inverted, and the lengths match.
    assert row["best_agreement_bp"] == 3000 * 10000 // size
    assert row["agreement_basis"] == "full"
    assert row["corrupt_outputs"] == ["c/corrupt.pdf"]


def test_with_only_an_index_the_agreement_is_a_labelled_lower_bound(
    filled: Corpus,
) -> None:
    index = filled.root / OUTPUT_INDEX
    index.write_text(json.dumps(index_outputs(filled.outputs)))
    report = score_manifest(
        _manifest(filled), index, payloads=filled.payloads, image=filled.image
    )
    row = _row(report, "corrupt.pdf")
    assert row["agreement_basis"] == "head_lower_bound"
    assert row["best_agreement_bp"] == 3000 * 10000 // len(filled.data("corrupt.pdf"))
    assert report.counts == _score(filled).counts


def test_fragmented_files_are_broken_out(filled: Corpus) -> None:
    fragmented = _score(filled).fragmented
    outcome = (fragmented.full, fragmented.exact, fragmented.corrupt, fragmented.missed)
    assert outcome == (2, 1, 0, 1)
    assert fragmented.names == ["frag.gif", "frag.png"]


def test_a_head_only_recovery_of_a_fragmented_file_is_corrupt(corpus: Corpus) -> None:
    # What a carver without reassembly returns: the first run, then whatever
    # follows it on the medium.
    first_run = corpus.image.read_bytes()[24 * 1024 : 24 * 1024 + 6008]
    corpus.put("frag-head.png", first_run)
    report = _score(corpus)
    assert _row(report, "frag.png")["outcome"] == "CORRUPT"
    assert report.fragmented.corrupt == 1
    agreement = _row(report, "frag.png")["best_agreement_bp"]
    assert isinstance(agreement, int) and 4000 <= agreement < 10000


def test_no_outputs_means_every_file_is_missed(corpus: Corpus) -> None:
    report = _score(corpus)
    assert (report.counts.exact, report.counts.missed) == (0, 5)
    assert report.counts.fp_total == 0 and report.counts.outputs == 0


def test_the_high_observation_is_unavailable_without_buckets(filled: Corpus) -> None:
    high = _score(filled).high_bucket
    assert high.available is False
    assert high.high_false_positives == [] and high.high_corrupt_recoveries == []


def test_high_bucket_outputs_are_listed_as_an_observation(filled: Corpus) -> None:
    buckets = {"noise.bin": "HIGH", "corrupt.pdf": "HIGH", "inner.bin": "LOW"}
    high = _score(filled, buckets=buckets).high_bucket
    assert high.available is True
    assert high.high_false_positives == ["g/noise.bin"]
    # Reported apart and not classified: the question is open.
    assert high.high_corrupt_recoveries == ["c/corrupt.pdf"]
    assert "undecided" in high.reason


def test_the_totals_equal_the_synthetic_benchmarks_scorer(filled: Corpus) -> None:
    """One attribution for both scorers: the registered baseline stays comparable."""
    from testkit.benchmark import score_run
    from testkit.damage import load_truth

    legacy = score_run(
        load_truth(filled.truth),
        filled.outputs,
        filled.payloads,
        tool="t",
        image_path=filled.image,
    )
    counts = _score(filled).counts
    for name in (
        "full",
        "exact",
        "corrupt",
        "missed",
        "partial",
        "partial_returned",
        "partial_exact",
        "unformatted_full",
        "unformatted_exact",
        "outputs",
        "duplicate_outputs",
        "fp_fragment",
        "fp_decoy",
        "fp_ambiguous",
        "fp_unrelated",
        "fp_total",
    ):
        assert getattr(counts, name) == getattr(legacy, name), name


def test_a_payload_that_does_not_match_the_manifest_is_refused(corpus: Corpus) -> None:
    manifest = _manifest(corpus)
    target = corpus.payloads / manifest.by_name("exact.jpg").sha256
    target.write_bytes(b"not the planted bytes")
    with pytest.raises(EvidenceIntegrityError):
        _score(corpus)


def test_the_scorer_reads_image_files_only(corpus: Corpus, tmp_path: Path) -> None:
    with pytest.raises(EvidenceIntegrityError):
        score_manifest(_manifest(corpus), corpus.outputs, image=tmp_path)


def test_agreement_is_positional_over_the_longer_input() -> None:
    assert agreement_bp(b"abcd", b"abcd") == 10000
    assert agreement_bp(b"abXd", b"abcd") == 7500
    assert agreement_bp(b"ab", b"abcd") == 5000
    assert agreement_bp(b"", b"") == 10000
