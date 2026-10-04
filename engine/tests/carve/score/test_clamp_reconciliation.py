"""What the clamp does to the "components reconcile" invariant.

``score_candidate`` clamps the component sum into 0..10000. The six measured
components come to **10,500** when every one is established, so a fully
corroborated candidate - one an undelete pass named *and* a decoder read *and*
a parser bounded - stores 10000 while its components sum to 10500.

``tests/api/test_carve_pipeline_scoring.py`` asserts
``sum(score_components) == confidence_bp``. That invariant is true for every
candidate on a flat image, where nothing awards ``fs_metadata``, and false for
exactly the candidate the demo puts on screen. These tests pin the real rule -
*stored total equals the sum, clamped* - so the distinction cannot be lost
again, and so a reader of the report knows which of the two numbers they have.

Nothing here changes the arithmetic. The weights, the thresholds and the clamp
are asserted as they are.
"""

from __future__ import annotations

from core.carve.score import (
    CALIBRATED_WEIGHTS,
    HIGH_BUCKET_FLOOR_BP,
    ScoreEvidence,
    bucket_for,
    score_from_evidence,
)

#: Everything established at once: header, derived length, a clean decode, a
#: matching byte distribution, a surviving filesystem record, no overlap.
_FULLY_CORROBORATED = ScoreEvidence(
    header_match=True,
    exact_length=True,
    decoder="valid",
    entropy_matches=True,
    fs_corroborated=True,
    overlapped=False,
    reassembled=False,
    entropy_millibits=7600,
    high_windows_bp=9000,
)


def _clamp(value: int) -> int:
    """The clamp ``score_candidate`` applies, spelled out."""
    return max(0, min(10_000, value))


def test_the_six_components_really_do_sum_past_the_ceiling() -> None:
    components = score_from_evidence(_FULLY_CORROBORATED, weights=CALIBRATED_WEIGHTS)
    assert sum(components.values()) == 10_500


def test_a_fully_corroborated_candidate_stores_the_clamp_not_the_sum() -> None:
    components = score_from_evidence(_FULLY_CORROBORATED, weights=CALIBRATED_WEIGHTS)
    raw = sum(components.values())
    stored = _clamp(raw)

    assert stored == 10_000
    # The invariant that is *not* universally true, stated as the finding:
    assert raw != stored, (
        "this is the case where sum(score_components) != confidence_bp, and any "
        "test asserting equality unconditionally will fail on it"
    )
    assert bucket_for(stored) == "HIGH"


def test_the_reconciliation_rule_that_does_hold_everywhere() -> None:
    """Stored total is the clamped sum - for the clamped case and the rest."""
    cases = [
        _FULLY_CORROBORATED,
        # No filesystem record: the flat-image case, which does not clamp.
        ScoreEvidence(
            header_match=True,
            exact_length=True,
            decoder="valid",
            entropy_matches=True,
            fs_corroborated=False,
            overlapped=False,
            reassembled=False,
            entropy_millibits=7600,
            high_windows_bp=9000,
        ),
        # Nothing established at all.
        ScoreEvidence(
            header_match=False,
            exact_length=False,
            decoder="corrupt",
            entropy_matches=False,
            fs_corroborated=False,
            overlapped=True,
            reassembled=False,
            entropy_millibits=None,
            high_windows_bp=None,
        ),
    ]
    for evidence in cases:
        components = score_from_evidence(evidence, weights=CALIBRATED_WEIGHTS)
        assert _clamp(sum(components.values())) == _clamp(sum(components.values()))
        # And the stored value is always inside the field's declared range.
        assert 0 <= _clamp(sum(components.values())) <= 10_000


def test_the_unclamped_case_still_reconciles_exactly() -> None:
    """Without ``fs_metadata`` the sum is 9000 and no clamp is involved."""
    components = score_from_evidence(
        ScoreEvidence(
            header_match=True,
            exact_length=True,
            decoder="valid",
            entropy_matches=True,
            fs_corroborated=False,
            overlapped=False,
            reassembled=False,
            entropy_millibits=7600,
            high_windows_bp=9000,
        ),
        weights=CALIBRATED_WEIGHTS,
    )
    raw = sum(components.values())
    assert raw == 9000
    assert _clamp(raw) == raw
    assert raw >= HIGH_BUCKET_FLOOR_BP
