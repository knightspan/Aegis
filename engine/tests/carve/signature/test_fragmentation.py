"""Bifragment gap carving, and the honest limit around it.

Only JPEG and PNG get reconstruction. Everything else is flagged
possibly_fragmented and left alone. General fragment reassembly is an open
research problem, and a tool that claims to solve it is a tool a panel will take
apart.
"""

from __future__ import annotations

import hashlib
import time

from core.carve.evidence import BytesEvidence
from core.carve.fragmentation import (
    MAX_GAP_CANDIDATES,
    MAX_SEARCH_WINDOW,
    reassemble_bifragmented_jpeg,
)
from core.carve.structure import carve_structures

from tests.carve.signature.conftest import (
    Embedded,
    lay_out,
    make_noisy_jpeg,
    make_noisy_png,
)

CLUSTER = 4096


def _split_across_gap(payload: bytes, *, head_bytes: int, gap: int) -> bytes:
    """Lay a payload down in two fragments separated by unrelated filler."""
    assert head_bytes < len(payload), (
        f"head_bytes {head_bytes} >= payload {len(payload)}: this would put the "
        "whole object in the first fragment and fragment nothing"
    )
    head, tail = payload[:head_bytes], payload[head_bytes:]
    filler = bytes((index * 7 + 3) & 0xFF for index in range(gap))
    return head + filler + tail


def test_the_fixture_really_spans_several_clusters() -> None:
    """Guards the trap this file fell into: a payload shorter than a cluster
    cannot be split at a cluster boundary, so any test built on one passes
    without ever exercising reassembly."""
    assert len(make_noisy_jpeg()) > 3 * CLUSTER
    assert len(make_noisy_png()) > 3 * CLUSTER


def test_bifragmented_jpeg_is_reassembled_and_hash_matches_the_original() -> None:
    original = make_noisy_jpeg()
    gap = 32 * 1024
    laid = _split_across_gap(original, head_bytes=CLUSTER, gap=gap)
    image = lay_out([Embedded(ext="jpg", offset=0, data=laid)], len(laid) + 8192)

    recovered = reassemble_bifragmented_jpeg(
        BytesEvidence(image), 0, max_size=1 << 20, cluster_size=CLUSTER
    )

    assert recovered is not None, "bifragmented JPEG was not reassembled"
    assert hashlib.sha256(recovered).hexdigest() == (
        hashlib.sha256(original).hexdigest()
    )


def test_a_truncated_head_alone_does_not_decode() -> None:
    """Proves the previous test needed reassembly rather than getting it free."""
    original = make_noisy_jpeg()
    from core.carve.fragmentation import decodes_cleanly

    assert not decodes_cleanly(original[:CLUSTER])


def test_contiguous_jpeg_needs_no_reassembly() -> None:
    original = make_noisy_jpeg()
    image = lay_out(
        [Embedded(ext="jpg", offset=0, data=original)], len(original) + 4096
    )
    recovered = reassemble_bifragmented_jpeg(
        BytesEvidence(image), 0, max_size=1 << 20, cluster_size=CLUSTER
    )
    assert recovered is not None
    assert hashlib.sha256(recovered).hexdigest() == (
        hashlib.sha256(original).hexdigest()
    )


def test_search_is_bounded_and_gives_up_rather_than_grinding() -> None:
    """An unrecoverable object must cost a bounded search, not the whole image."""
    original = make_noisy_jpeg()
    # A gap far larger than the search window: reassembly must fail, not hang.
    laid = _split_across_gap(
        original, head_bytes=CLUSTER, gap=MAX_SEARCH_WINDOW + 64 * 1024
    )
    image = lay_out([Embedded(ext="jpg", offset=0, data=laid)], len(laid) + 4096)

    started = time.perf_counter()
    recovered = reassemble_bifragmented_jpeg(
        BytesEvidence(image), 0, max_size=1 << 26, cluster_size=CLUSTER
    )
    elapsed = time.perf_counter() - started

    assert recovered is None
    assert elapsed < 15.0, f"bounded search took {elapsed:.1f}s"
    assert MAX_GAP_CANDIDATES <= 64


def test_formats_without_a_reassembler_are_flagged_never_reconstructed() -> None:
    """A split PNG whose tail is not on the medium: flagged, never rebuilt.

    PNG gained a reassembler with an exact oracle (see test_png_fragmentation);
    what must still hold is that an object nothing can account for is left as
    the span that is really there, marked possibly_fragmented, and not valid.
    """
    png = make_noisy_png()
    laid = png[:CLUSTER] + bytes((index * 7 + 3) & 0xFF for index in range(8192))
    image = lay_out([Embedded(ext="png", offset=0, data=laid)], len(laid) + 4096)

    candidates = [c for c in carve_structures(BytesEvidence(image)) if c.ext == "png"]

    assert candidates, "the PNG header should still be reported"
    assert all(c.validation != "valid" for c in candidates), (
        "a fragmented PNG must never be reported valid"
    )
    assert any(c.possibly_fragmented for c in candidates)
    assert all(not c.fragments for c in candidates)
