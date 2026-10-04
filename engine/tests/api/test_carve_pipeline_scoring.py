"""No candidate leaves the pipeline carrying a confidence nobody computed.

``core.carve.structure.carve_structures`` assigns ``confidence_bp`` itself -
7500 for a reassembled fragment, 9500 for a clean parse, 4000 otherwise - and
sets a bucket to match. Those are placeholders for a library caller, and they
are wrong: they are not derived from any evidence about the object, they cannot
be decomposed, and 9500 would put a candidate in HIGH on the strength of a
parser having read it.

The pipeline is required to overwrite every one of them by running
:func:`core.carve.score.score_candidate`, which recomputes the total from six
named components and records them on the candidate. Before this batch the
question was moot because ``carve_structures`` was never called. Now that it is,
these tests are what stands between the product and a shipped fake score.

The invariant asserted here is deliberately *structural* rather than a list of
forbidden numbers: a real score decomposes and a hardcoded one does not, so
``sum(score_components.values()) == confidence_bp`` over a non-empty component
map is the property that cannot be satisfied by accident. Checking only that
``confidence_bp not in {7500, 9500, 4000}`` would pass the day a placeholder
changed value.

The interaction that makes this worth a file of its own is in
:func:`core.carve.score.resolve_overlaps`: when a candidate has no
``score_components`` it falls back to ``confidence_bp - weights.no_overlap``.
An unscored candidate therefore does not fail loudly - it silently becomes
7500 - 500 = 7000 and reads exactly like a scored one.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest
from api.carve_job import carve_generator

from tests.carve.signature.conftest import (
    Embedded,
    lay_out,
    make_noisy_jpeg,
    make_noisy_png,
)

#: The values core/carve/structure.py assigns without evidence.
PLACEHOLDER_CONFIDENCE = {7500, 9500, 4000}

#: The seven components core.carve.score always emits - six measured, and the
#: reassembly ceiling, which is zero unless the object was rebuilt from runs. A
#: candidate carrying a different key set did not come from score_from_evidence.
EXPECTED_COMPONENTS = {
    "header",
    "exact_length",
    "decoder",
    "entropy",
    "fs_metadata",
    "no_overlap",
    "reassembly",
}


def _carve(image: Path) -> dict[str, Any]:
    generator = carve_generator(
        image, undelete=True, carve_signatures=True, job_id="scoring", ledger=None
    )
    try:
        while True:
            next(generator)
    except StopIteration as stop:
        result: dict[str, Any] = stop.value
        return result


@pytest.fixture(scope="module")
def carved(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """An image with objects every parser in the table will engage with."""
    directory = tmp_path_factory.mktemp("scoring")
    jpeg = make_noisy_jpeg(seed=7)
    png = make_noisy_png()

    items: list[Embedded] = []
    cursor = 65536
    for ext, blob in (("jpg", jpeg), ("png", png)):
        items.append(Embedded(ext=ext, offset=cursor, data=blob))
        cursor += len(blob) + 65536

    image = directory / "case.dd"
    image.write_bytes(lay_out(items, cursor + 65536))
    return _carve(image)


def test_the_pipeline_produced_structure_derived_candidates(
    carved: dict[str, Any],
) -> None:
    """Guard the guard: these assertions are vacuous on an empty result.

    They are also vacuous if the pipeline reverted to the signature carver, in
    which case nothing below is testing what it claims to test.
    """
    candidates = carved["candidates"]
    assert candidates, "the fixture produced no candidates to score"
    assert any(item["source"] == "structure" for item in candidates), (
        "no candidate came from carve_structures; the pipeline is not routed "
        "through it and these scoring assertions prove nothing"
    )


def test_every_candidate_carries_a_decomposed_score(carved: dict[str, Any]) -> None:
    """The property a hardcoded number cannot satisfy."""
    offenders = [
        (item["offset"], item["ext"], item["confidence_bp"])
        for item in carved["candidates"]
        if not item.get("score_components")
    ]
    assert not offenders, (
        "candidates reached the output without score_components, so their "
        f"confidence was never computed from evidence: {offenders}"
    )


def test_every_confidence_equals_the_clamped_sum_of_its_components(
    carved: dict[str, Any],
) -> None:
    """A total that does not reconcile is a total from somewhere else.

    Reconciliation is against the **clamped** sum, which is what
    ``score_candidate`` stores. Asserting plain equality passes on this image -
    it is flat, so nothing awards ``fs_metadata`` and no candidate exceeds
    9000 - and is false for the candidate the demo puts on screen: with a
    surviving filesystem record the six components come to 10,500 and the
    stored total is 10000. See
    ``tests/carve/score/test_clamp_reconciliation.py``.
    """
    offenders = [
        {
            "offset": item["offset"],
            "ext": item["ext"],
            "confidence_bp": item["confidence_bp"],
            "components": item["score_components"],
            "component_sum": sum(item["score_components"].values()),
        }
        for item in carved["candidates"]
        if max(0, min(10_000, sum(item["score_components"].values())))
        != item["confidence_bp"]
    ]
    assert not offenders, f"confidence does not reconcile with components: {offenders}"


def test_every_candidate_carries_the_full_component_set(
    carved: dict[str, Any],
) -> None:
    """Components are always present, including the ones worth zero.

    ``score_from_evidence`` emits all six so a report can say "entropy: 0, the
    check ran and failed" rather than leaving a reader to guess whether it ran.
    A partial map means something other than that function wrote it.
    """
    offenders = [
        (item["offset"], sorted(item["score_components"]))
        for item in carved["candidates"]
        if set(item["score_components"]) != EXPECTED_COMPONENTS
    ]
    assert not offenders, f"unexpected component key set: {offenders}"


def test_no_candidate_carries_a_structure_placeholder_confidence(
    carved: dict[str, Any],
) -> None:
    """Weaker than the reconciliation tests, and worth keeping anyway.

    If a placeholder ever survives scoring, this names it in the failure
    message instead of leaving the reader to work out which number was wrong.
    A scored candidate may legitimately land on one of these values, so this
    only fires when the components do not also reconcile.
    """
    offenders = [
        (item["offset"], item["ext"], item["confidence_bp"])
        for item in carved["candidates"]
        if item["confidence_bp"] in PLACEHOLDER_CONFIDENCE
        and sum(item.get("score_components", {}).values()) != item["confidence_bp"]
    ]
    assert not offenders, (
        f"structure.py placeholder confidence reached the output: {offenders}"
    )


def test_the_bucket_matches_the_scored_confidence(carved: dict[str, Any]) -> None:
    """structure.py sets a bucket directly too; it must be recomputed as well."""
    from core.carve.score import bucket_for

    offenders = [
        (item["offset"], item["confidence_bp"], item["bucket"])
        for item in carved["candidates"]
        if item["bucket"] != bucket_for(item["confidence_bp"])
    ]
    assert not offenders, f"bucket does not match confidence: {offenders}"


def test_entropy_was_measured_on_every_candidate(carved: dict[str, Any]) -> None:
    """``score_candidate`` records the measurement, not only the verdict.

    ``entropy_millibits_per_byte`` is populated by ``gather_evidence`` and by
    nothing else, so its presence is a second independent witness that the
    candidate went through the scorer.
    """
    offenders = [
        item["offset"]
        for item in carved["candidates"]
        if item.get("entropy_millibits_per_byte") is None
    ]
    assert not offenders, (
        f"candidates with no entropy measurement, so unscored: {offenders}"
    )


def test_the_recovered_bytes_hash_to_what_the_candidate_claims(
    carved: dict[str, Any], tmp_path: Path
) -> None:
    """A candidate's sha256 must describe bytes that are actually on the medium.

    ``carve_structures`` rewrites both the length and the digest when a parser
    resolves an object. If those two ever disagree, every downstream artifact -
    the ledger digest, the report, the written file - describes something that
    was never on the medium.

    **Where those bytes are depends on the candidate, and the candidate says
    which.** A contiguous one is ``offset``..``offset + length``. A bifragmented
    one that reassembly recovered is the concatenation of its ``fragments``,
    because head + gap + tail is not the object and hashing that span would be
    the tool describing the gap as part of the file. Batch 3 made that case
    reachable, so this test now covers both shapes rather than only the one that
    existed when it was written. It is not weakened: every candidate is still
    required to account for its digest, and a candidate that flattened a
    fragmented object into a span - the exact bug this was written to catch -
    still fails, now with the fragment list in the failure message.
    """
    jpeg = make_noisy_jpeg(seed=7)
    # A second, bifragmented object so the fragment branch below is not dead:
    # split on a cluster boundary with 32 KiB of unrelated filler in the gap,
    # which is what reassembly recovers and what no single span describes.
    other = make_noisy_jpeg(seed=99)
    filler = bytes((index * 7 + 3) & 0xFF for index in range(32 * 1024))
    split = other[:4096] + filler + other[4096:]

    image = tmp_path / "hashcheck.dd"
    image.write_bytes(
        lay_out(
            [
                Embedded(ext="jpg", offset=4096, data=jpeg),
                Embedded(ext="jpg", offset=4096 + len(jpeg) + 4096, data=split),
            ],
            262144 + len(jpeg) + len(split),
        )
    )

    raw = image.read_bytes()
    offenders = []
    reassembled = 0
    for item in _carve(image)["candidates"]:
        if item["source"] == "fs_metadata":
            continue  # multi-extent; its bytes do not live at offset..+length
        runs = item["fragments"]
        if runs:
            reassembled += 1
            payload = b"".join(
                raw[run["offset"] : run["offset"] + run["length"]] for run in runs
            )
            if item["length"] != sum(run["length"] for run in runs):
                offenders.append((item["offset"], "length disagrees with runs", runs))
                continue
            if item["offset"] != runs[0]["offset"]:
                offenders.append((item["offset"], "offset is not the first run", runs))
                continue
        else:
            payload = raw[item["offset"] : item["offset"] + item["length"]]
        if hashlib.sha256(payload).hexdigest() != item["sha256"]:
            offenders.append((item["offset"], item["length"], item["source"], runs))

    assert not offenders, (
        f"candidate digest does not match the bytes it points at: {offenders}"
    )
    assert reassembled == 1, (
        "the fragmented object was not reassembled, so the fragment branch "
        "above proved nothing"
    )


def test_the_pipeline_calls_carve_structures_and_not_both_carvers() -> None:
    """Static guard, in the shape ``tests/test_stubs_raise.py`` uses.

    ``carve_structures`` runs the signature scan internally and yields every
    hit, refined or unchanged. Calling ``carve_signatures`` as well would find
    every object twice and leave dedupe to hide it, so the two must not both
    appear.
    """
    import api.carve_job as carve_job

    source = Path(carve_job.__file__).read_text(encoding="utf-8")
    # Whitespace-normalised, so wrapping the call across lines to stay inside
    # the line-length limit does not read as removing it. The guard is about
    # which carver is called, not about how the call is formatted.
    flattened = " ".join(source.split())

    assert "from core.carve.structure import carve_structures" in source
    # Batch 7 passes the undelete pass's cluster sizes as a keyword argument.
    assert "carve_structures( handle, cluster_bytes_at=" in flattened
    assert "import carve_signatures" not in source, (
        "both carvers are wired in; carve_structures already runs the scan"
    )
