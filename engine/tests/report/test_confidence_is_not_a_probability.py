"""The report must not let ``confidence_bp`` be read as a probability.

``CarveCandidate.confidence_bp`` is a clamped sum of evidence components.
``VerificationResult.confidence_bp`` is a detection probability. They share a
field name because the signed report schema has always used it, so the wording
around each one is the only thing keeping them apart - and wording is exactly
what drifts. These tests pin it.

Nothing here touches the arithmetic: the weights, thresholds and bucket
boundaries are covered by ``tests/carve/score/test_score.py`` and are asserted
unchanged below.
"""

from __future__ import annotations

from core.carve.score import (
    CALIBRATED_WEIGHTS,
    HIGH_BUCKET_FLOOR_BP,
    MEDIUM_BUCKET_FLOOR_BP,
    bucket_for,
)
from core.report.render import build_carve_report

from tests.report.test_module_reports import carve_inputs


def _note() -> str:
    return build_carve_report(**carve_inputs())["sections"]["confidence"]["note"]


def test_the_confidence_note_says_outright_that_it_is_not_a_probability() -> None:
    note = _note()
    assert "NOT A PROBABILITY" in note
    assert "EVIDENCE SCORE" in note


def test_the_note_explains_that_10000_is_where_the_clamp_lands() -> None:
    """A reader seeing 10000 must be told why, not left to infer certainty."""
    note = _note()
    assert "10500" in note
    assert "clamp" in note


def test_the_note_states_the_calibration_population_and_its_limit() -> None:
    """A precision figure without its population is a slogan."""
    note = _note()
    # The pooled population the claim actually rests on.
    assert "173" in note
    assert "104" in note
    # And the case where it did not hold, which must travel with it.
    assert "86.6%" in note


def test_the_components_sum_past_the_clamp_which_is_why_10000_is_reachable() -> None:
    """The arithmetic behind the wording, asserted rather than described."""
    weights = CALIBRATED_WEIGHTS
    everything = (
        weights.header
        + weights.exact_length
        + weights.decoder_valid
        + weights.entropy
        + weights.fs_metadata
        + weights.no_overlap
    )
    assert everything == 10_500
    # So a candidate establishing every component is clamped, not measured at
    # certainty. The clamp is what the report note has to explain.
    assert min(everything, 10_000) == 10_000


def test_the_thresholds_this_change_must_not_move() -> None:
    assert HIGH_BUCKET_FLOOR_BP == 8000
    assert MEDIUM_BUCKET_FLOOR_BP == 5000
    assert bucket_for(10_000) == "HIGH"
    assert bucket_for(8000) == "HIGH"
    assert bucket_for(7999) == "MEDIUM"
    assert bucket_for(5000) == "MEDIUM"
    assert bucket_for(4999) == "LOW"


def test_the_erase_verification_statement_keeps_its_own_careful_wording() -> None:
    """The one ``confidence_bp`` that *is* a probability keeps its wording.

    It does not use the word "probability" about itself, and that is
    deliberate: it names the thing the number is the chance *of*, and then
    says what it is not. Nothing in this change may weaken that.
    """
    from core.erase.verify import probability_statement

    statement = probability_statement(
        total_bytes=1_000_000,
        residual_bytes=1024,
        sample_bytes=1024,
        draws=16,
    )
    assert "chance of detecting" in statement.lower()
    assert "not a guarantee that none exists" in statement.lower()
