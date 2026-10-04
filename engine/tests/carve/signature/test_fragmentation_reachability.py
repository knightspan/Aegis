"""Bifragment reassembly, from the header match to the candidate record.

Batch 2 routed ``api/carve_job.py`` through
:func:`core.carve.structure.carve_structures` and proved the reassembler works
when called directly, while the trigger above it never fired: ``carve_structures``
attempted reassembly only when ``parse_jpeg`` reported something other than
``valid``, and for a bifragmented JPEG whose tail is still on the medium -
the entire case the technique exists for - ``parse_jpeg`` reports ``valid``. Its
entropy scan steps over the gap, finds the real EOI on the far side and returns
a length spanning head + gap + tail. This file was a strict xfail pinning that.

The trigger now runs off a decode oracle instead, and the xfail is gone. What
took its place is the thing that made the fix non-trivial:

**Pillow on its own is not the oracle the search needs.** Measured here:
``Image.load`` accepts ``jpeg[:4096] + FFD9`` and reports a fully decoded
256x256 image. libjpeg stops at EOI and returns what it has, so "it decoded" is
not evidence that the bytes between SOS and EOI were this object's. Driving
reassembly off ``decodes_cleanly`` alone made the pipeline ship *fabricated*
objects at HIGH confidence - a head joined to a stray EOI in unrelated filler,
decoding fine, hashing to nothing that was ever a file. That is worse than the
gap it closed. :func:`core.carve.fragmentation.is_whole_jpeg` adds the check
Pillow does not do - reserved marker codes inside the scan, and an EOI anywhere
but the end - and that is what both the trigger and the search now use.

**And the first accepted join is not necessarily the right one.** The search
tries short heads first, so a JPEG split 8192 bytes in was reassembled as
head 4096 + the correct tail: a real, decodable, structurally clean JPEG that is
4096 bytes short and hashes to something else. Both halves are the object's own
scan data, so no test of the bytes can see it. The medium's layout can: the gap
is where somebody else's bytes are, so the true head is the longest one that
still reassembles, which is what ``_extend_head`` finds.

**Stated limit.** Fragments are sought on cluster boundaries, 4096 bytes by
default, because that is where a filesystem puts them. A split 1024 or 2048
bytes into an object is not something a 4 KiB-cluster volume can produce and the
search does not enumerate it; those objects are reported as low-confidence
candidates over the span the parser derived, never as recoveries. The last test
below shows the same objects recovering exactly when the cluster size matches
the split, so this is the alignment assumption and not a defect in the search.
"""

from __future__ import annotations

import hashlib

import pytest
from core.carve.evidence import BytesEvidence
from core.carve.fragmentation import (
    decodes_cleanly,
    is_whole_jpeg,
    reassemble_bifragmented_jpeg,
    reassemble_bifragmented_jpeg_runs,
)
from core.carve.structure import carve_structures

from tests.carve.signature.conftest import Embedded, lay_out, make_noisy_jpeg

CLUSTER = 4096
GAP_BYTES = 32 * 1024
MIB = 1024 * 1024

#: Split points a 4 KiB-cluster volume can actually produce.
ALIGNED_SPLITS = [4096, 8192]

#: Split points it cannot. Kept because Batch 2 measured all four.
UNALIGNED_SPLITS = [1024, 2048]


def _split_across_gap(payload: bytes, *, head_bytes: int, gap: int) -> bytes:
    """Lay a payload down as two runs separated by unrelated filler."""
    assert head_bytes < len(payload), (
        "head_bytes >= payload puts the whole object in the first fragment"
    )
    filler = bytes((index * 7 + 3) & 0xFF for index in range(gap))
    return payload[:head_bytes] + filler + payload[head_bytes:]


def _fragmented_image(payload: bytes, head_bytes: int) -> bytes:
    laid = _split_across_gap(payload, head_bytes=head_bytes, gap=GAP_BYTES)
    return lay_out([Embedded(ext="jpg", offset=0, data=laid)], len(laid) + 8192)


@pytest.fixture(scope="module")
def original() -> bytes:
    return make_noisy_jpeg(seed=99)


@pytest.fixture(scope="module")
def fragmented_image(original: bytes) -> bytes:
    return _fragmented_image(original, CLUSTER)


# --------------------------------------------------------------------------
# The oracle
# --------------------------------------------------------------------------


def test_pillow_alone_accepts_a_truncated_jpeg_closed_with_an_eoi(
    original: bytes,
) -> None:
    """The measurement the whole fix turns on, pinned so it cannot be forgotten.

    A 4096-byte prefix of a 77,458-byte JPEG, closed with a bare ``FFD9``,
    loads as a fully decoded 256x256 image. Anything that treats
    ``decodes_cleanly`` as proof that a gap was guessed right is accepting a
    5%-complete object as a whole one.

    **``is_whole_jpeg`` does not catch this one either, and says so.** Its job
    is foreign bytes spliced into a scan, and there are none here - the prefix
    is this object's own legal scan data and the EOI ends the stream. What
    stops the search from producing this is the one-cluster floor on the second
    fragment: a stray ``FFD9`` two bytes past a cluster boundary is not a run
    of the medium. Layered deliberately, and recorded here so a reader does not
    assume the oracle covers more than it does.
    """
    stump = original[:CLUSTER] + b"\xff\xd9"

    assert decodes_cleanly(stump) is True, (
        "Pillow used to accept this; if it no longer does, update the "
        "fragmentation module docstring, which says it does"
    )
    assert is_whole_jpeg(stump) is True, (
        "structure alone cannot see a truncation that ends on a real EOI; if "
        "it now can, the cluster floor in the search may be retireable"
    )
    assert is_whole_jpeg(original[:CLUSTER]) is False, (
        "with no EOI at all it is plainly not whole"
    )


def test_the_span_the_parser_derived_is_not_a_whole_jpeg(
    fragmented_image: bytes, original: bytes
) -> None:
    """head + gap + tail is rejected without a decode being needed."""
    span = BytesEvidence(fragmented_image).read(0, len(original) + GAP_BYTES)

    assert is_whole_jpeg(span) is False
    assert is_whole_jpeg(original) is True


def test_the_parser_still_reports_valid_for_a_bifragmented_span(
    original: bytes, fragmented_image: bytes
) -> None:
    """The root cause is still in ``parse_jpeg``; the fix is above it.

    ``parse_jpeg`` remains a pure structural walk with no decoder behind it -
    that is what lets it run on formats Pillow cannot open, and what keeps the
    parser table uniform. ``carve_structures`` is where the verdict is checked
    against a decoder before it becomes a candidate's ``validation``. Pinned so
    that a future change inside the parser shows up here, naming the cause.
    """
    from core.carve.structure import parse_jpeg

    parsed = parse_jpeg(BytesEvidence(fragmented_image), 0, max_size=20 * MIB)

    assert parsed is not None
    assert parsed.validation == "valid"
    assert parsed.length == len(original) + GAP_BYTES


# --------------------------------------------------------------------------
# The mechanism
# --------------------------------------------------------------------------


def test_the_reassembler_recovers_the_object_byte_for_byte(
    original: bytes, fragmented_image: bytes
) -> None:
    rebuilt = reassemble_bifragmented_jpeg(
        BytesEvidence(fragmented_image), 0, max_size=20 * MIB
    )

    assert rebuilt is not None
    assert hashlib.sha256(rebuilt).hexdigest() == hashlib.sha256(original).hexdigest()


def test_the_runs_say_where_on_the_medium_each_byte_was(
    original: bytes, fragmented_image: bytes
) -> None:
    """A digest with no locatable bytes behind it is not evidence."""
    found = reassemble_bifragmented_jpeg_runs(
        BytesEvidence(fragmented_image), 0, max_size=20 * MIB
    )

    assert found is not None
    assert found.fragmented is True
    assert [(run.offset, run.length) for run in found.runs] == [
        (0, CLUSTER),
        (CLUSTER + GAP_BYTES, len(original) - CLUSTER),
    ]
    rejoined = b"".join(
        fragmented_image[run.offset : run.end] for run in found.runs
    )
    assert rejoined == found.payload == original


def test_the_head_is_extended_to_the_edge_of_the_gap(original: bytes) -> None:
    """The regression that first-accepted-join produced, pinned directly.

    Split 8192 bytes in, the enumeration reaches head 4096 + the correct tail
    before it reaches head 8192. Both decode. Only the longer one is the file.
    """
    found = reassemble_bifragmented_jpeg_runs(
        BytesEvidence(_fragmented_image(original, 8192)), 0, max_size=20 * MIB
    )

    assert found is not None
    assert found.runs[0].length == 8192, (
        "the head stopped short of the gap, so the object is missing the "
        f"clusters between {found.runs[0].length} and 8192"
    )
    assert hashlib.sha256(found.payload).hexdigest() == (
        hashlib.sha256(original).hexdigest()
    )


# --------------------------------------------------------------------------
# Alignment, not capability
# --------------------------------------------------------------------------


@pytest.mark.parametrize("head_bytes", UNALIGNED_SPLITS + ALIGNED_SPLITS)
def test_the_split_points_recover_when_the_cluster_size_matches(
    original: bytes, head_bytes: int
) -> None:
    """Alignment, not capability: the search finds all four when told the size."""
    found = reassemble_bifragmented_jpeg_runs(
        BytesEvidence(_fragmented_image(original, head_bytes)),
        0,
        max_size=20 * MIB,
        cluster_size=1024,
    )

    assert found is not None
    assert hashlib.sha256(found.payload).hexdigest() == (
        hashlib.sha256(original).hexdigest()
    )
    assert found.runs[0].length == head_bytes


@pytest.mark.parametrize("head_bytes", UNALIGNED_SPLITS)
def test_a_known_cluster_size_refuses_a_split_it_cannot_produce(
    original: bytes, head_bytes: int
) -> None:
    """On a 4096-byte-cluster volume a head of 1024 or 2048 bytes is impossible.

    No allocator produced it, so no join is enumerated for it - including the
    right one. The object is refused, not guessed at.
    """
    found = reassemble_bifragmented_jpeg_runs(
        BytesEvidence(_fragmented_image(original, head_bytes)),
        0,
        max_size=20 * MIB,
        cluster_size=CLUSTER,
    )

    assert found is None


def test_two_tails_the_medium_cannot_tell_apart_are_refused(original: bytes) -> None:
    """The same tail lies on the medium twice, each after a gap of foreign bytes.

    Both joins account for every MCU and hash to the original, but only one set
    of runs is where the file was, and nothing on the medium says which. Emitting
    either would put a layout on the record that the evidence does not support,
    so the search refuses when a second join passes at the level the first did.
    This is the only layout that reaches that check in practice - a substituted
    or shifted scan never passed it in 7,200 measured attempts - so without it
    removing the check would go unnoticed.
    """
    filler = bytes((index * 7 + 3) & 0xFF for index in range(GAP_BYTES))
    tail = original[CLUSTER:]
    # The first copy's last cluster is padded with slack, as a filesystem would
    # leave it, so the second copy starts on a cluster boundary too.
    slack = bytes(-len(tail) % CLUSTER)
    laid = original[:CLUSTER] + filler + tail + slack + filler + tail
    image = lay_out([Embedded(ext="jpg", offset=0, data=laid)], len(laid) + 8192)

    found = reassemble_bifragmented_jpeg_runs(
        BytesEvidence(image), 0, max_size=20 * MIB, cluster_size=CLUSTER
    )

    assert found is None, (
        "reassembled a duplicated tail as if the medium said which copy was the "
        f"file's: runs {[(run.offset, run.length) for run in found.runs]}"
    )


# --------------------------------------------------------------------------
# What must never happen
# --------------------------------------------------------------------------


def test_no_candidate_ever_claims_a_digest_it_cannot_account_for(
    original: bytes,
) -> None:
    """Over every split point, aligned or not, and the intact object.

    Each candidate is either a span - ``offset``..``offset + length`` - or a set
    of runs. Whichever it is, reading those bytes back off the medium must
    reproduce its ``sha256``. This is the invariant the fragments field exists
    to make expressible.
    """
    from core.carve.fragmentation import read_fragments

    layouts = {"intact": lay_out(
        [Embedded(ext="jpg", offset=0, data=original)], len(original) + 8192
    )}
    for head in UNALIGNED_SPLITS + ALIGNED_SPLITS:
        layouts[f"split@{head}"] = _fragmented_image(original, head)
    layouts["head only"] = lay_out(
        [Embedded(ext="jpg", offset=0, data=original[:8192])], 262144
    )

    for name, blob in layouts.items():
        handle = BytesEvidence(blob)
        for item in carve_structures(handle):
            if item.fragments:
                payload = read_fragments(handle, item.fragments)
                assert item.length == sum(run.length for run in item.fragments)
                assert item.offset == item.fragments[0].offset
            else:
                payload = blob[item.offset : item.offset + item.length]
            assert hashlib.sha256(payload).hexdigest() == item.sha256, (
                f"{name}: candidate at {item.offset} claims a digest for bytes "
                "that are not where it says they are"
            )
