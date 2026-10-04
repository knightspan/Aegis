"""Decoders decide, and they decide within a bound.

The two failures these tests exist to prevent are a truncated file reported as
valid - which puts an unopenable file in front of an examiner with a HIGH
label on it - and a crafted header taking the process down before it can
report anything at all.
"""

from __future__ import annotations

import io
import time

import pytest
from core.carve.evidence import BytesEvidence
from core.carve.validate import (
    DEADLINE_S,
    MAX_IMAGE_PIXELS,
    validate_bytes,
    validate_candidate,
)
from PIL import Image, ImageFile

from tests.carve.score.conftest import candidate, make_zip_with


def test_whole_jpeg_validates_valid(jpeg_bytes: bytes) -> None:
    report = validate_bytes(jpeg_bytes, "jpg")
    assert report.verdict == "valid"
    assert "128x128" in report.detail


def test_truncated_jpeg_validates_truncated(truncated_jpeg: bytes) -> None:
    """``Image.open`` alone accepts this file. ``.load()`` is what catches it."""
    with Image.open(io.BytesIO(truncated_jpeg)) as opened:
        assert opened.format == "JPEG"  # open() lies about truncated files

    report = validate_bytes(truncated_jpeg, "jpg")
    assert report.verdict == "truncated"
    assert "truncated" in report.detail.lower()


def test_load_truncated_images_stays_disabled() -> None:
    """Pillow's forgiving mode would turn every truncated file into a valid one."""
    assert ImageFile.LOAD_TRUNCATED_IMAGES is False


def test_declared_bomb_is_corrupt_and_bounded(png_bomb: bytes) -> None:
    """A 40000x40000 PNG header asks for 4.8 GB. It gets a verdict instead."""
    before = Image.MAX_IMAGE_PIXELS
    started = time.monotonic()
    report = validate_bytes(png_bomb, "png")
    elapsed = time.monotonic() - started

    assert report.verdict == "corrupt"
    assert str(MAX_IMAGE_PIXELS) in report.detail
    assert elapsed < DEADLINE_S
    # The ceiling is global state in Pillow. Leaving it moved would silently
    # change every later decode in the process.
    assert Image.MAX_IMAGE_PIXELS == before


def test_password_protected_zip_does_not_attempt_decryption(
    encrypted_zip: bytes,
) -> None:
    """No verdict about content nobody can read, and no time spent trying."""
    started = time.monotonic()
    report = validate_bytes(encrypted_zip, "zip")
    elapsed = time.monotonic() - started

    assert report.verdict == "decoder_unavailable"
    assert "encrypted" in report.detail
    assert elapsed < 2.0


def test_ooxml_needs_its_document_part(docx_bytes: bytes) -> None:
    report = validate_bytes(docx_bytes, "zip")
    assert report.verdict == "valid"
    assert "WordprocessingML" in report.detail


def test_ooxml_with_unparseable_document_part_is_corrupt() -> None:
    broken = make_zip_with(
        {
            "[Content_Types].xml": b'<?xml version="1.0"?><Types/>',
            "word/document.xml": b"<w:document><w:body>",
        }
    )
    report = validate_bytes(broken, "zip")
    assert report.verdict == "corrupt"
    assert "word/document.xml" in report.detail


def test_unregistered_format_is_decoder_unavailable() -> None:
    """A missing decoder is not evidence about the file."""
    report = validate_bytes(b"\x7fELF" + b"\x00" * 64, "elf")
    assert report.verdict == "decoder_unavailable"
    assert "no decoder" in report.detail


def test_mp4_without_ffprobe_is_not_claimed_valid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.carve import validate
    from testkit.generate_corpus import make_mp4

    monkeypatch.setattr(validate, "_ffprobe_path", lambda: None)
    report = validate_bytes(make_mp4(), "mp4")
    assert report.verdict == "decoder_unavailable"
    assert "ffprobe" in report.detail


def test_ffprobe_asks_for_a_hidden_console_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ffprobe is a console-subsystem tool; this packaged (console=False)
    app has no console of its own to give it. Same defect, same fix as
    core.device._sysio.SubprocessRunner - found in the same audit,
    2026-09-27."""
    import subprocess
    import sys
    from unittest.mock import patch

    from core.carve import validate
    from testkit.generate_corpus import make_mp4

    monkeypatch.setattr(validate, "_ffprobe_path", lambda: "ffprobe")
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0, b'{"format": {}, "streams": []}', b""
        )
        validate_bytes(make_mp4(), "mp4")

    assert mock_run.call_args.kwargs["creationflags"] == 0x08000000


def test_validate_candidate_reads_through_the_evidence(jpeg_bytes: bytes) -> None:
    image = BytesEvidence(b"\x00" * 512 + jpeg_bytes)
    subject = candidate(jpeg_bytes, offset=512, ext="jpg")

    judged = validate_candidate(subject, image)

    assert judged.validation == "valid"
    assert judged.validation_detail
    assert judged.offset == 512  # nothing else about the candidate moved


def test_sqlite_integrity_check_runs_in_memory() -> None:
    from testkit.generate_corpus import make_sqlite

    report = validate_bytes(make_sqlite(rows=20), "sqlite")
    assert report.verdict == "valid"
    assert "integrity_check ok" in report.detail


def test_truncated_sqlite_is_reported_truncated() -> None:
    from testkit.generate_corpus import make_sqlite

    report = validate_bytes(make_sqlite(rows=20)[: 4 * 1024], "sqlite")
    assert report.verdict == "truncated"
    assert "declares" in report.detail
