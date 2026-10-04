"""Bifragment reassembly for PNG, and every way it must refuse.

A PNG carries its own oracle. Every chunk ends in a CRC-32 over its type and
data, and the image data is one zlib stream whose Adler-32 and exact inflated
length are fixed by the IHDR. A join that drops, adds or substitutes bytes has
to reproduce a 32-bit CRC and a valid deflate stream of exactly the right
length at once. These tests check the join is found, that its runs point at
the medium, and that the search refuses rather than guesses when the medium
does not say which bytes are the file.
"""

from __future__ import annotations

import hashlib
import io
import random
import time

from core.carve.evidence import BytesEvidence
from core.carve.fragmentation import (
    MAX_SEARCH_WINDOW,
    reassemble_bifragmented_png_runs,
)
from core.carve.score import REASSEMBLED_CEILING_BP
from core.carve.structure import carve_structures, parse_png
from PIL import Image

from tests.carve.signature.conftest import Embedded, lay_out, make_noisy_png

CLUSTER = 4096


def _filler(size: int, seed: int = 3) -> bytes:
    return bytes((index * 7 + seed) & 0xFF for index in range(size))


def _split(payload: bytes, *, head_bytes: int, gap: int) -> bytes:
    assert 0 < head_bytes < len(payload)
    return payload[:head_bytes] + _filler(gap) + payload[head_bytes:]


def _interlaced_png(size: int = 160, seed: int = 3) -> bytes:
    rng = random.Random(seed)
    image = Image.new("RGB", (size, size))
    image.putdata(
        [
            (rng.randrange(256), rng.randrange(256), rng.randrange(256))
            for _ in range(size * size)
        ]
    )
    buffer = io.BytesIO()
    image.save(buffer, "PNG", interlace=1)
    return buffer.getvalue()


def _image(laid: bytes) -> BytesEvidence:
    return BytesEvidence(
        lay_out([Embedded(ext="png", offset=0, data=laid)], len(laid) + 8192)
    )


def test_the_fixture_is_long_enough_to_fragment() -> None:
    assert len(make_noisy_png()) > 8 * CLUSTER


def test_a_head_alone_fails_its_crc() -> None:
    """Proves reassembly is needed: the split object is not valid as laid."""
    original = make_noisy_png()
    image = _image(_split(original, head_bytes=3 * CLUSTER, gap=32 * 1024))
    parsed = parse_png(image, 0, max_size=1 << 22)
    assert parsed is not None
    assert parsed.validation != "valid"


def test_bifragmented_png_is_reassembled_byte_for_byte() -> None:
    original = make_noisy_png()
    head, gap = 3 * CLUSTER, 32 * 1024
    image = _image(_split(original, head_bytes=head, gap=gap))

    found = reassemble_bifragmented_png_runs(
        image, 0, max_size=1 << 22, cluster_size=CLUSTER
    )

    assert found is not None, "bifragmented PNG was not reassembled"
    assert hashlib.sha256(found.payload).digest() == hashlib.sha256(original).digest()
    assert found.fragmented
    assert [(run.offset, run.length) for run in found.runs] == [
        (0, head),
        (head + gap, len(original) - head),
    ]


def test_the_runs_read_back_to_the_same_digest() -> None:
    """The runs are provenance: reading them again must give the same bytes."""
    from core.carve.fragmentation import read_fragments

    original = make_noisy_png()
    image = _image(_split(original, head_bytes=5 * CLUSTER, gap=16 * 1024))
    found = reassemble_bifragmented_png_runs(
        image, 0, max_size=1 << 22, cluster_size=CLUSTER
    )
    assert found is not None
    assert read_fragments(image, found.runs) == found.payload


def test_unknown_cluster_size_searches_the_sector_grid() -> None:
    original = make_noisy_png()
    image = _image(_split(original, head_bytes=7 * 512, gap=9 * 512))
    found = reassemble_bifragmented_png_runs(image, 0, max_size=1 << 22)
    assert found is not None
    assert found.payload == original


def test_a_join_in_the_second_idat_chunk_is_found() -> None:
    """The break can fall in any chunk, not only the first IDAT."""
    original = make_noisy_png()
    head = 18 * CLUSTER  # past the first 64 KiB IDAT, inside the second
    assert 65581 < head < 110936
    image = _image(_split(original, head_bytes=head, gap=12 * 1024))
    found = reassemble_bifragmented_png_runs(
        image, 0, max_size=1 << 22, cluster_size=CLUSTER
    )
    assert found is not None
    assert found.payload == original


def test_interlaced_png_is_reassembled() -> None:
    original = _interlaced_png()
    image = _image(_split(original, head_bytes=4 * CLUSTER, gap=20 * 1024))
    found = reassemble_bifragmented_png_runs(
        image, 0, max_size=1 << 22, cluster_size=CLUSTER
    )
    assert found is not None
    assert found.payload == original


def test_contiguous_png_is_one_run() -> None:
    original = make_noisy_png()
    image = _image(original)
    found = reassemble_bifragmented_png_runs(
        image, 0, max_size=1 << 22, cluster_size=CLUSTER
    )
    assert found is not None
    assert not found.fragmented
    assert found.payload == original


def test_an_overwritten_tail_is_refused() -> None:
    """The tail's first cluster was reused: no join accounts for the object."""
    original = make_noisy_png()
    head, gap = 3 * CLUSTER, 16 * 1024
    laid = bytearray(_split(original, head_bytes=head, gap=gap))
    laid[head + gap : head + gap + CLUSTER] = bytes(CLUSTER)
    found = reassemble_bifragmented_png_runs(
        _image(bytes(laid)), 0, max_size=1 << 22, cluster_size=CLUSTER
    )
    assert found is None


def test_a_chimera_of_two_same_size_pngs_is_refused() -> None:
    """Head of one PNG, tail of another with identical dimensions and type."""
    first = make_noisy_png(seed=11)
    second = make_noisy_png(seed=12)
    head = 3 * CLUSTER
    laid = first[:head] + _filler(16 * 1024) + second[head:]
    found = reassemble_bifragmented_png_runs(
        _image(laid), 0, max_size=1 << 22, cluster_size=CLUSTER
    )
    assert found is None


def test_two_copies_of_the_tail_make_the_join_ambiguous() -> None:
    """The medium holds two places the tail could be. Refuse, do not pick."""
    original = make_noisy_png()
    head = 3 * CLUSTER
    tail = original[head:]
    pad = (-len(tail)) % CLUSTER
    laid = (
        original[:head]
        + _filler(8 * 1024)
        + tail
        + _filler(pad + 8 * 1024, seed=5)
        + tail
    )
    found = reassemble_bifragmented_png_runs(
        _image(laid), 0, max_size=1 << 22, cluster_size=CLUSTER
    )
    assert found is None


def test_a_gap_beyond_the_window_is_refused_quickly() -> None:
    original = make_noisy_png()
    laid = _split(original, head_bytes=3 * CLUSTER, gap=MAX_SEARCH_WINDOW + CLUSTER)
    started = time.perf_counter()
    found = reassemble_bifragmented_png_runs(
        _image(laid), 0, max_size=1 << 26, cluster_size=CLUSTER
    )
    assert found is None
    assert time.perf_counter() - started < 15.0


def test_not_a_png_returns_none() -> None:
    image = BytesEvidence(b"\x00" * 65536)
    found = reassemble_bifragmented_png_runs(
        image, 0, max_size=1 << 20, cluster_size=CLUSTER
    )
    assert found is None


def test_a_truncated_png_with_no_tail_on_the_medium_is_refused() -> None:
    original = make_noisy_png()
    head = 3 * CLUSTER
    image = _image(original[:head] + _filler(64 * 1024))
    found = reassemble_bifragmented_png_runs(
        image, 0, max_size=1 << 22, cluster_size=CLUSTER
    )
    assert found is None


def test_a_bad_cluster_size_is_a_caller_error() -> None:
    import pytest

    with pytest.raises(ValueError):
        reassemble_bifragmented_png_runs(
            _image(make_noisy_png()), 0, max_size=1 << 22, cluster_size=1000
        )


def test_carve_reports_a_reassembled_png_below_high_with_its_runs() -> None:
    original = make_noisy_png()
    head, gap = 3 * CLUSTER, 32 * 1024
    image = _image(_split(original, head_bytes=head, gap=gap))

    candidates = [
        c
        for c in carve_structures(image, cluster_bytes_at=lambda _offset: CLUSTER)
        if c.ext == "png" and c.offset == 0
    ]

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.validation == "valid"
    assert candidate.bucket != "HIGH"
    assert candidate.confidence_bp <= REASSEMBLED_CEILING_BP
    assert candidate.sha256 == hashlib.sha256(original).hexdigest()
    assert [(run.offset, run.length) for run in candidate.fragments] == [
        (0, head),
        (head + gap, len(original) - head),
    ]


def test_carve_leaves_an_unrecoverable_png_flagged_and_not_valid() -> None:
    original = make_noisy_png()
    head = 3 * CLUSTER
    image = _image(original[:head] + _filler(64 * 1024))
    candidates = [
        c for c in carve_structures(image) if c.ext == "png" and c.offset == 0
    ]
    assert candidates
    assert all(c.validation != "valid" for c in candidates)
    assert all(c.possibly_fragmented for c in candidates)
    assert all(not c.fragments for c in candidates)
