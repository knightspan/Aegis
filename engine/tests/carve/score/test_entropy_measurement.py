"""The entropy figure must not move when the way it is computed does.

``measure_entropy`` was a pure-Python per-byte histogram, and it was 236.5 s of
a 249.9 s profiled carve. Tallying with :class:`collections.Counter` does the
same arithmetic in C. Whether it does *exactly* the same arithmetic is not
something to assume: the weights in :mod:`core.carve.score` were calibrated
against these numbers, so a value that moved by one millibit would quietly
invalidate the calibration rather than fail anything.

This file pins the output against an independent implementation of the
definition, not against recorded constants.
"""

from __future__ import annotations

import math
import random

import pytest
from core.carve.score import (
    ENTROPY_WINDOW_BYTES,
    HIGH_ENTROPY_MILLIBITS,
    measure_entropy,
)


def _reference(data: bytes, window: int = ENTROPY_WINDOW_BYTES) -> tuple[int, int]:
    """Shannon entropy per window, written out the long way.

    This is the implementation ``measure_entropy`` had when the weights were
    calibrated, kept here as the thing to agree with.
    """
    if not data:
        return 0, 0
    totals = 0.0
    windows = 0
    high = 0
    for start in range(0, len(data), window):
        chunk = data[start : start + window]
        if not chunk:
            break
        counts = [0] * 256
        for byte in chunk:
            counts[byte] += 1
        size = len(chunk)
        entropy = 0.0
        for count in counts:
            if count:
                share = count / size
                entropy -= share * math.log2(share)
        millibits = int(round(entropy * 1000))
        totals += millibits
        windows += 1
        if millibits >= HIGH_ENTROPY_MILLIBITS:
            high += 1
    if windows == 0:
        return 0, 0
    return int(round(totals / windows)), int(round(high * 10_000 / windows))


def _samples() -> list[tuple[str, bytes]]:
    rng = random.Random(20260916)
    prose = (
        b"The examiner mounted the image read-only and started the carve. "
        b"Nothing in this file is a photograph, and every byte of it is text. "
    )
    return [
        ("empty", b""),
        ("one byte", b"\x00"),
        ("all zeros", bytes(8192)),
        ("one repeated byte", b"\x41" * 5000),
        ("random", rng.randbytes(40_000)),
        ("prose", (prose * 200)[:40_000]),
        ("prose then random", (prose * 40)[:8192] + rng.randbytes(8192)),
        ("shorter than one window", rng.randbytes(1000)),
        ("exactly one window", rng.randbytes(ENTROPY_WINDOW_BYTES)),
        ("one window and one byte", rng.randbytes(ENTROPY_WINDOW_BYTES + 1)),
        ("every byte value once", bytes(range(256))),
    ]


@pytest.mark.parametrize("name,data", _samples(), ids=[n for n, _ in _samples()])
def test_measured_entropy_equals_the_calibrated_definition(
    name: str, data: bytes
) -> None:
    assert measure_entropy(data) == _reference(data), (
        f"{name}: the entropy figure moved, which invalidates the calibration"
    )


def test_a_window_of_one_repeated_byte_is_zero_bits() -> None:
    """The definition's anchor: no uncertainty at all is zero, not near zero."""
    assert measure_entropy(b"\x00" * ENTROPY_WINDOW_BYTES) == (0, 0)


def test_a_window_of_every_byte_value_is_eight_bits() -> None:
    mean, high = measure_entropy(bytes(range(256)) * 16)
    assert mean == 8000
    assert high == 10_000
