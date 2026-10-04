"""A reassembled object is held below HIGH, and the record says so (Batch 7 Task 4).

For a contiguous candidate every component is measured on bytes that sit on the
medium as one run. For a reassembled one the gap between the runs is an
inference: exact MCU accounting shows the joined bytes are one well-formed scan,
not that the medium laid them out that way, and on a real case there is no
manifest to check the layout against. The measured residual - a join that loses
or replaces 512 to 1,536 bytes of the object's own scan, passing about one time
in twenty on noise-like JPEGs when the true tail start is gone - exists only for
reassembled objects.

So a candidate with ``fragments`` carries a ``reassembly`` component that holds
its total at ``HIGH_BUCKET_FLOOR_BP - 1`` at most, whatever the other
components add up to. It is a component rather than a clamp so that the six
numbers and the total still reconcile, and so that the reason is on the record
where an examiner reads the score.
"""

from __future__ import annotations

import hashlib

import pytest
from core.carve.score import (
    CALIBRATED_WEIGHTS,
    HIGH_BUCKET_FLOOR_BP,
    ScoreEvidence,
    bucket_for,
    resolve_overlaps,
    score_candidate,
    score_from_evidence,
)
from core.models import CarveCandidate, CarveFragment

CEILING = HIGH_BUCKET_FLOOR_BP - 1


def _candidate(payload: bytes, fragments: list[CarveFragment]) -> CarveCandidate:
    return CarveCandidate(
        offset=0,
        length=len(payload),
        ext="jpg",
        mime="image/jpeg",
        source="structure",
        validation="valid",
        confidence_bp=0,
        bucket="LOW",
        sha256=hashlib.sha256(payload).hexdigest(),
        original_name=None,
        possibly_fragmented=bool(fragments),
        fragments=fragments,
    )


def _runs(payload: bytes) -> list[CarveFragment]:
    return [
        CarveFragment(offset=0, length=4096),
        CarveFragment(offset=40960, length=len(payload) - 4096),
    ]


def test_every_candidate_reports_the_reassembly_component() -> None:
    """Zero for a contiguous object, present regardless: the check ran."""
    components = score_from_evidence(ScoreEvidence(), weights=CALIBRATED_WEIGHTS)

    assert components["reassembly"] == 0


def test_the_same_bytes_score_high_contiguous_and_medium_reassembled(
    jpeg_bytes: bytes,
) -> None:
    contiguous = score_candidate(_candidate(jpeg_bytes, []), data=jpeg_bytes)
    rebuilt = score_candidate(
        _candidate(jpeg_bytes, _runs(jpeg_bytes)), data=jpeg_bytes
    )

    assert contiguous.bucket == "HIGH", contiguous.score_components
    assert rebuilt.bucket == "MEDIUM", rebuilt.score_components
    assert sum(rebuilt.score_components.values()) == rebuilt.confidence_bp
    assert rebuilt.confidence_bp == CEILING
    assert rebuilt.score_components["reassembly"] < 0
    others = {k: v for k, v in rebuilt.score_components.items() if k != "reassembly"}
    assert others == {
        k: v for k, v in contiguous.score_components.items() if k != "reassembly"
    }, "the ceiling must not change what any other component measured"


@pytest.mark.parametrize("fs_corroborated", [False, True])
def test_no_combination_of_components_lifts_a_reassembled_object_into_high(
    fs_corroborated: bool,
) -> None:
    """Every component awarded - including one a structure candidate never gets."""
    components = score_from_evidence(
        ScoreEvidence(
            header_match=True,
            exact_length=True,
            decoder="valid",
            entropy_matches=True,
            fs_corroborated=fs_corroborated,
            overlapped=False,
            reassembled=True,
        ),
        weights=CALIBRATED_WEIGHTS,
    )

    assert sum(components.values()) == CEILING
    assert bucket_for(sum(components.values())) == "MEDIUM"


def test_a_reassembled_object_below_the_ceiling_is_not_marked_down(
    jpeg_bytes: bytes,
) -> None:
    """The component holds the total at the ceiling; it is not a penalty."""
    components = score_from_evidence(
        ScoreEvidence(header_match=True, decoder="truncated", reassembled=True),
        weights=CALIBRATED_WEIGHTS,
    )

    assert components["reassembly"] == 0


def test_losing_an_overlap_keeps_the_arithmetic_honest(jpeg_bytes: bytes) -> None:
    rebuilt = score_candidate(
        _candidate(jpeg_bytes, _runs(jpeg_bytes)), data=jpeg_bytes
    )
    winner = rebuilt.model_copy(
        update={
            "offset": 0,
            "fragments": [],
            "confidence_bp": 9500,
            "score_components": {"decoder": 9000, "no_overlap": 500},
        }
    )

    resolved = resolve_overlaps([rebuilt, winner])
    loser = next(item for item in resolved if item.fragments)

    assert loser.overlapped is True
    assert loser.score_components["no_overlap"] == 0
    assert sum(loser.score_components.values()) == loser.confidence_bp
    others = sum(
        value for name, value in loser.score_components.items() if name != "reassembly"
    )
    # Losing no_overlap lowers what the others add up to; the ceiling is
    # recomputed against that, so it never marks the object down further than
    # the ceiling requires.
    assert loser.confidence_bp == min(others, CEILING)
    assert loser.score_components["reassembly"] == min(0, CEILING - others)
    before = rebuilt.score_components["reassembly"]
    assert loser.score_components["reassembly"] >= before
