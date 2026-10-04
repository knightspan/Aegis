"""Every component of the score is testable on its own, and so is the total.

A composite score nobody can take apart is a number that has to be believed.
These tests construct a candidate that hits exactly one component at a time
and assert the basis points it is worth, so the arithmetic behind a HIGH label
can be checked line by line.
"""

from __future__ import annotations

import pytest
from core.carve.evidence import BytesEvidence
from core.carve.score import (
    CALIBRATED_WEIGHTS,
    HIGH_BUCKET_FLOOR_BP,
    MEDIUM_BUCKET_FLOOR_BP,
    ScoreEvidence,
    bucket_for,
    gather_evidence,
    measure_entropy,
    resolve_overlaps,
    score_candidate,
    score_from_evidence,
)
from core.carve.validate import validate_candidate

from tests.carve.score.conftest import candidate

WEIGHTS = CALIBRATED_WEIGHTS


# --------------------------------------------------------------------------
# One component at a time
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("evidence", "component", "expected"),
    [
        (ScoreEvidence(header_match=True), "header", WEIGHTS.header),
        (ScoreEvidence(exact_length=True), "exact_length", WEIGHTS.exact_length),
        (ScoreEvidence(decoder="valid"), "decoder", WEIGHTS.decoder_valid),
        (ScoreEvidence(decoder="truncated"), "decoder", WEIGHTS.decoder_truncated),
        (ScoreEvidence(decoder="corrupt"), "decoder", 0),
        (
            ScoreEvidence(decoder="decoder_unavailable"),
            "decoder",
            WEIGHTS.decoder_unavailable,
        ),
        (ScoreEvidence(entropy_matches=True), "entropy", WEIGHTS.entropy),
        (ScoreEvidence(fs_corroborated=True), "fs_metadata", WEIGHTS.fs_metadata),
        (ScoreEvidence(overlapped=False), "no_overlap", WEIGHTS.no_overlap),
        (ScoreEvidence(overlapped=True), "no_overlap", 0),
    ],
)
def test_each_component_is_worth_exactly_its_weight(
    evidence: ScoreEvidence, component: str, expected: int
) -> None:
    components = score_from_evidence(evidence, weights=WEIGHTS)
    assert components[component] == expected


def test_components_that_were_not_established_are_reported_as_zero() -> None:
    """A missing key would leave a reader guessing whether the check ran."""
    components = score_from_evidence(ScoreEvidence(), weights=WEIGHTS)
    assert set(components) == {
        "header",
        "exact_length",
        "decoder",
        "entropy",
        "fs_metadata",
        "no_overlap",
        "reassembly",
    }
    assert components["header"] == 0


def test_every_component_at_once_clamps_to_ten_thousand() -> None:
    components = score_from_evidence(
        ScoreEvidence(
            header_match=True,
            exact_length=True,
            decoder="valid",
            entropy_matches=True,
            fs_corroborated=True,
            overlapped=False,
        ),
        weights=WEIGHTS,
    )
    assert min(10_000, sum(components.values())) == 10_000


def test_no_decoder_verdict_can_reach_the_high_bucket() -> None:
    """``decoder_unavailable`` is capped below HIGH by construction."""
    best_possible = score_from_evidence(
        ScoreEvidence(
            header_match=True,
            exact_length=True,
            decoder="decoder_unavailable",
            entropy_matches=True,
            fs_corroborated=True,
        ),
        weights=WEIGHTS,
    )
    assert sum(best_possible.values()) < HIGH_BUCKET_FLOOR_BP


@pytest.mark.parametrize(
    ("confidence_bp", "bucket"),
    [
        (10_000, "HIGH"),
        (8000, "HIGH"),
        (7999, "MEDIUM"),
        (5000, "MEDIUM"),
        (4999, "LOW"),
    ],
)
def test_bucket_boundaries(confidence_bp: int, bucket: str) -> None:
    assert bucket_for(confidence_bp) == bucket


# --------------------------------------------------------------------------
# Entropy
# --------------------------------------------------------------------------


def test_entropy_separates_compressed_data_from_prose(
    jpeg_bytes: bytes, jpeg_header_over_text: bytes
) -> None:
    compressed, compressed_share = measure_entropy(jpeg_bytes)
    prose, prose_share = measure_entropy(jpeg_header_over_text)

    assert compressed > 7500
    assert compressed_share > 9000
    assert prose < 5000
    assert prose_share == 0


def test_jpeg_header_over_prose_scores_low(jpeg_header_over_text: bytes) -> None:
    """The classic false positive: a real header on 100 KB of English text."""
    image = BytesEvidence(jpeg_header_over_text)
    subject = candidate(
        jpeg_header_over_text, ext="jpg", mime="image/jpeg", possibly_fragmented=True
    )

    scored = score_candidate(validate_candidate(subject, image), image=image)

    assert scored.validation == "corrupt"
    assert scored.confidence_bp < MEDIUM_BUCKET_FLOOR_BP
    assert scored.bucket == "LOW"
    assert scored.entropy_millibits_per_byte is not None
    assert scored.entropy_millibits_per_byte < 5000


def test_measured_entropy_is_recorded_on_the_candidate(jpeg_bytes: bytes) -> None:
    """The report shows the number, not just the conclusion drawn from it."""
    image = BytesEvidence(jpeg_bytes)
    scored = score_candidate(candidate(jpeg_bytes, ext="jpg"), image=image)

    assert scored.entropy_millibits_per_byte is not None
    assert 7000 <= scored.entropy_millibits_per_byte <= 8000
    assert scored.high_entropy_windows_bp == 10_000
    assert scored.score_components["entropy"] == WEIGHTS.entropy


# --------------------------------------------------------------------------
# Whole-candidate scoring
# --------------------------------------------------------------------------


def test_whole_jpeg_scores_high(jpeg_bytes: bytes) -> None:
    image = BytesEvidence(jpeg_bytes)
    scored = score_candidate(
        validate_candidate(candidate(jpeg_bytes, ext="jpg"), image), image=image
    )

    assert scored.validation == "valid"
    assert scored.bucket == "HIGH"


def test_truncated_jpeg_never_scores_high(truncated_jpeg: bytes) -> None:
    """A file that does not open must not carry a HIGH label into a report."""
    image = BytesEvidence(truncated_jpeg)
    subject = candidate(truncated_jpeg, ext="jpg", possibly_fragmented=True)

    scored = score_candidate(validate_candidate(subject, image), image=image)

    assert scored.validation == "truncated"
    assert scored.bucket in {"LOW", "MEDIUM"}
    assert scored.confidence_bp < HIGH_BUCKET_FLOOR_BP


def test_unmeasured_components_are_not_assumed(jpeg_bytes: bytes) -> None:
    """With no bytes to look at, header and entropy score zero rather than pass."""
    evidence = gather_evidence(candidate(jpeg_bytes, ext="jpg"))
    assert evidence.header_match is False
    assert evidence.entropy_matches is False


def test_filesystem_metadata_corroborates(jpeg_bytes: bytes) -> None:
    image = BytesEvidence(jpeg_bytes)
    subject = candidate(
        jpeg_bytes, ext="jpg", source="fs_metadata", original_name="holiday.jpg"
    )

    scored = score_candidate(validate_candidate(subject, image), image=image)

    assert scored.score_components["fs_metadata"] == WEIGHTS.fs_metadata
    assert scored.confidence_bp == 10_000


# --------------------------------------------------------------------------
# Overlap
# --------------------------------------------------------------------------


def test_overlapping_loser_is_marked_not_deleted(jpeg_bytes: bytes) -> None:
    winner = candidate(jpeg_bytes, offset=1000, ext="jpg", confidence_bp=9000)
    winner = winner.model_copy(
        update={"score_components": {"decoder": 8500, "no_overlap": 500}}
    )
    loser = candidate(
        jpeg_bytes[:400], offset=1200, ext="jpg", confidence_bp=6000
    ).model_copy(update={"score_components": {"decoder": 5500, "no_overlap": 500}})

    resolved = resolve_overlaps([winner, loser])

    assert len(resolved) == 2  # nothing was dropped
    kept = next(item for item in resolved if item.offset == 1000)
    suppressed = next(item for item in resolved if item.offset == 1200)
    assert kept.overlapped is False
    assert suppressed.overlapped is True
    assert suppressed.overlaps_with == 1000  # a pointer to what displaced it
    assert suppressed.confidence_bp == 5500  # lost the no_overlap component
    assert suppressed.bucket == "MEDIUM"


def test_non_overlapping_candidates_keep_their_score(jpeg_bytes: bytes) -> None:
    first = candidate(jpeg_bytes, offset=0, ext="jpg", confidence_bp=8500)
    second = candidate(
        jpeg_bytes, offset=len(jpeg_bytes), ext="jpg", confidence_bp=8500
    )

    resolved = resolve_overlaps([first, second])

    assert [item.overlapped for item in resolved] == [False, False]
    assert [item.confidence_bp for item in resolved] == [8500, 8500]
