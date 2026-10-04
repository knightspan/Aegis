"""Malformed evidence is rejected, never raised out of the pipeline.

A validator reads bytes off a seized disk. Every one of them must turn a
malformed object into a *verdict* - ``corrupt``, ``truncated`` or
``decoder_unavailable`` - because an exception escaping into
``carve_generator`` fails the whole recovery job over one bad file, and the one
bad file is exactly what somebody who did not want their disk carved would
leave behind.

The WAV case here is a regression, found by ``testkit/fuzz.py`` at seed 0 and
fixed in ``core/carve/validate.py``: CPython's ``wave`` module raises a **bare**
``RuntimeError`` - no message, not a ``wave.Error`` - from its internal
``Chunk.seek`` when a chunk header declares more bytes than the file holds.
"""

from __future__ import annotations

import struct

import pytest
from core.carve.validate import VALIDATORS, validate_bytes

#: A RIFF/WAVE header whose chunk size field is a lie. This is the shape that
#: reached ``Chunk.seek`` and raised.
WAV_LYING_CHUNK = (
    b"RIFF"
    + struct.pack("<I", 0xFFFFFFFF)
    + b"WAVE"
    + b"LIST"
    + struct.pack("<I", 0x7FFFFFFF)
    + b"\x00" * 32
)


def test_a_wav_whose_chunk_header_lies_is_corrupt_not_an_exception() -> None:
    """The regression. A bare RuntimeError used to escape into the carve job."""
    report = validate_bytes(WAV_LYING_CHUNK, "wav")

    assert report.verdict in {"corrupt", "truncated", "decoder_unavailable"}
    assert report.decoder == "wave"
    assert "declares more bytes" in report.detail or report.detail


def test_a_wav_with_no_chunks_at_all_is_corrupt() -> None:
    report = validate_bytes(b"RIFF" + struct.pack("<I", 512) + b"WAVE", "wav")

    assert report.verdict == "corrupt"


@pytest.mark.parametrize("ext", sorted(VALIDATORS))
def test_no_validator_raises_on_a_truncated_header(ext: str) -> None:
    """Four bytes and nothing else. Every decoder has to have an opinion."""
    report = validate_bytes(b"\xff\xd8\xff\xe0", ext)

    assert report.verdict in {
        "valid",
        "truncated",
        "corrupt",
        "decoder_unavailable",
    }


@pytest.mark.parametrize("ext", sorted(VALIDATORS))
def test_no_validator_raises_on_pure_noise(ext: str) -> None:
    report = validate_bytes(bytes(range(256)) * 4, ext)

    assert report.verdict in {
        "valid",
        "truncated",
        "corrupt",
        "decoder_unavailable",
    }


@pytest.mark.parametrize("ext", sorted(VALIDATORS))
def test_no_validator_raises_on_all_zeros(ext: str) -> None:
    """Fill, which is what most of an erased disk is."""
    report = validate_bytes(b"\x00" * 4096, ext)

    assert report.verdict in {
        "valid",
        "truncated",
        "corrupt",
        "decoder_unavailable",
    }


def test_an_empty_candidate_is_truncated_and_not_an_error() -> None:
    assert validate_bytes(b"", "jpg").verdict == "truncated"


def test_an_unregistered_format_is_unavailable_and_not_an_error() -> None:
    report = validate_bytes(b"whatever", "no-such-format")

    assert report.verdict == "decoder_unavailable"
    assert "no decoder is registered" in report.detail
