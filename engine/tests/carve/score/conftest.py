"""Fixtures for the validate/score/classify tests.

Every object here is produced by a real encoder, through the same generators
:mod:`testkit.generate_corpus` plants in the calibration corpus. A test that
builds its own fake JPEG proves the test's idea of a JPEG, not the decoder's.
"""

from __future__ import annotations

import hashlib
import io
import random
import zipfile

import pytest
from core.models import CarveCandidate
from testkit.generate_corpus import (
    make_docx,
    make_encrypted_zip,
    make_jpeg,
    make_png,
    make_png_bomb,
)

KIB = 1024


@pytest.fixture(scope="session")
def rng() -> random.Random:
    return random.Random(20260904)


@pytest.fixture(scope="session")
def jpeg_bytes(rng: random.Random) -> bytes:
    return make_jpeg(rng, 128)


@pytest.fixture(scope="session")
def jpeg_with_gps(rng: random.Random) -> bytes:
    return make_jpeg(rng, 96, gps=True)


@pytest.fixture(scope="session")
def png_bytes(rng: random.Random) -> bytes:
    return make_png(rng, 96)


@pytest.fixture(scope="session")
def truncated_jpeg(jpeg_bytes: bytes) -> bytes:
    """A real JPEG with its end-of-image marker and the last scan rows removed."""
    return jpeg_bytes[: len(jpeg_bytes) // 2]


@pytest.fixture(scope="session")
def png_bomb() -> bytes:
    return make_png_bomb()


@pytest.fixture(scope="session")
def docm_bytes() -> bytes:
    return make_docx(macros=True)


@pytest.fixture(scope="session")
def docx_bytes() -> bytes:
    return make_docx()


@pytest.fixture(scope="session")
def encrypted_zip(rng: random.Random) -> bytes:
    return make_encrypted_zip(rng)


@pytest.fixture(scope="session")
def jpeg_header_over_text() -> bytes:
    """100 KB of English prose behind a genuine ``FFD8FF`` header."""
    prose = (
        "The examiner mounted the image read-only and started the carve. "
        "Nothing in this file is a photograph, and every byte of it is text. "
    )
    body = (prose * (100 * KIB // len(prose) + 1))[: 100 * KIB]
    return b"\xff\xd8\xff\xe0" + body.encode("ascii")


def make_zip_with(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


def candidate(data: bytes, **overrides: object) -> CarveCandidate:
    """A candidate describing ``data`` at offset 0, with sane defaults."""
    fields: dict[str, object] = {
        "offset": 0,
        "length": len(data),
        "ext": "bin",
        "mime": "application/octet-stream",
        "source": "structure",
        "validation": "valid",
        "confidence_bp": 0,
        "bucket": "LOW",
        "sha256": hashlib.sha256(data).hexdigest(),
        "original_name": None,
        "possibly_fragmented": False,
    }
    fields.update(overrides)
    return CarveCandidate.model_validate(fields)
