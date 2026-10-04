"""Decoders for the formats added in Batch 8, and the TIFF trailing-data guard.

The guard is the one to read first. Pillow reads a TIFF's IFD chain and ignores
whatever follows it, so a candidate holding a 49 KB image plus 61 MB of the rest
of the medium decoded as cleanly as the image alone and was reported ``valid``.
That is how a span covering most of a volume reached MEDIUM confidence in the
benchmark (finding B4): an examiner was told to look at a 61 MB file that holds
4 KB of evidence. The same reasoning as the exact scan accounting for JPEG - the
decoder's verdict covers the bytes it read, and the object is only as long as
its own structure says.
"""

from __future__ import annotations

import gzip
import io
import random
import tarfile
import wave

import pytest
from core.carve.validate import validate_bytes
from PIL import Image


@pytest.fixture(scope="module")
def rng() -> random.Random:
    return random.Random(20260916)


@pytest.fixture(scope="module")
def tiff_bytes(rng: random.Random) -> bytes:
    image = Image.new("RGB", (64, 64))
    image.frombytes(rng.randbytes(64 * 64 * 3))
    buffer = io.BytesIO()
    image.save(buffer, "TIFF")
    return buffer.getvalue()


@pytest.fixture(scope="module")
def wav_bytes(rng: random.Random) -> bytes:
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as out:
        out.setnchannels(1)
        out.setsampwidth(2)
        out.setframerate(8000)
        out.writeframes(rng.randbytes(8000 * 2))
    return buffer.getvalue()


@pytest.fixture(scope="module")
def tar_bytes() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as out:
        for index in range(3):
            body = (f"member {index} " * 100).encode()
            info = tarfile.TarInfo(f"notes{index}.txt")
            info.size = len(body)
            info.mtime = 1_700_000_000
            out.addfile(info, io.BytesIO(body))
    return buffer.getvalue()


# --------------------------------------------------------------------------
# B4: a TIFF plus the rest of the medium is not a valid TIFF
# --------------------------------------------------------------------------


def test_tiff_alone_is_valid(tiff_bytes: bytes) -> None:
    report = validate_bytes(tiff_bytes, "tiff")
    assert report.verdict == "valid"


def test_tiff_followed_by_the_rest_of_the_medium_is_not_valid(
    tiff_bytes: bytes, rng: random.Random
) -> None:
    """Pillow decodes this exactly as happily as the image on its own."""
    span = tiff_bytes + rng.randbytes(4 * 1024 * 1024)

    with Image.open(io.BytesIO(span)) as opened:
        opened.load()  # the decoder has no objection at all

    report = validate_bytes(span, "tiff")

    assert report.verdict == "corrupt"
    assert str(len(tiff_bytes)) in report.detail
    assert "not part of the image" in report.detail


# --------------------------------------------------------------------------
# WAV
# --------------------------------------------------------------------------


def test_whole_wav_is_valid(wav_bytes: bytes) -> None:
    report = validate_bytes(wav_bytes, "wav")
    assert report.verdict == "valid"
    assert "8000 Hz" in report.detail


def test_wav_missing_its_samples_is_truncated(wav_bytes: bytes) -> None:
    """The ``fmt`` chunk survives a cut, so opening alone still succeeds."""
    report = validate_bytes(wav_bytes[: len(wav_bytes) // 2], "wav")
    assert report.verdict == "truncated"


# --------------------------------------------------------------------------
# GZIP
# --------------------------------------------------------------------------


def test_whole_gzip_member_is_valid() -> None:
    """zlib checks the CRC and the length trailer, so this is a real verdict."""
    member = gzip.compress(("case notes " * 2000).encode(), mtime=0)
    report = validate_bytes(member, "gz")
    assert report.verdict == "valid"
    assert "CRC" in report.detail


def test_gzip_cut_short_is_truncated() -> None:
    member = gzip.compress(("case notes " * 2000).encode(), mtime=0)
    report = validate_bytes(member[: len(member) // 2], "gz")
    assert report.verdict == "truncated"


def test_gzip_with_a_corrupted_byte_is_corrupt() -> None:
    member = bytearray(gzip.compress(("case notes " * 2000).encode(), mtime=0))
    member[len(member) // 2] ^= 0xFF
    report = validate_bytes(bytes(member), "gz")
    assert report.verdict in {"corrupt", "truncated"}
    assert report.verdict != "valid"


# --------------------------------------------------------------------------
# TAR
# --------------------------------------------------------------------------


def test_whole_tar_is_valid(tar_bytes: bytes) -> None:
    report = validate_bytes(tar_bytes, "tar")
    assert report.verdict == "valid"
    assert "3 member(s)" in report.detail


def test_tar_cut_inside_a_member_is_not_valid(tar_bytes: bytes) -> None:
    report = validate_bytes(tar_bytes[: len(tar_bytes) // 3], "tar")
    assert report.verdict != "valid"
