"""Type from content, flags an investigator filters on, and one row per file.

GPS coordinates in a recovered photograph and a macro-bearing document are the
two highest-value hits in a real case, so those two flags get the most
attention here.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from core.carve.classify import (
    classify_bytes,
    classify_candidate,
    dedupe,
    output_filename,
    write_recovered,
)
from core.carve.evidence import BytesEvidence

from tests.carve.score.conftest import candidate

# --------------------------------------------------------------------------
# Type from the parse, not the extension
# --------------------------------------------------------------------------


def test_ooxml_is_named_from_its_parts_not_its_signature(docx_bytes: bytes) -> None:
    """The signature table calls every PK archive a ZIP. The parse knows better."""
    subject = candidate(docx_bytes, ext="zip", mime="application/zip")

    classified = classify_candidate(subject, data=docx_bytes)

    assert classified.ext == "docx"
    assert classified.mime.endswith("wordprocessingml.document")
    assert classified.category == "document"


def test_plain_archive_stays_an_archive(png_bytes: bytes) -> None:
    from tests.carve.score.conftest import make_zip_with

    archive = make_zip_with({"holiday.png": png_bytes})
    facts = classify_bytes(archive, "zip")

    assert facts.ext == "zip"
    assert facts.category == "archive"


def test_undecodable_content_reports_that_nobody_looked() -> None:
    facts = classify_bytes(b"\x7fELF" + b"\x00" * 32, "elf")

    assert facts.category == "executable"
    assert facts.flags.inspected is False
    assert facts.flags.contains_macros is False  # not observed, not "observed absent"


# --------------------------------------------------------------------------
# Flags
# --------------------------------------------------------------------------


def test_gps_flag_is_set_only_when_the_photo_carries_coordinates(
    jpeg_with_gps: bytes, jpeg_bytes: bytes
) -> None:
    with_gps = classify_bytes(jpeg_with_gps, "jpg")
    without_gps = classify_bytes(jpeg_bytes, "jpg")

    assert with_gps.flags.has_exif_gps is True
    assert without_gps.flags.has_exif_gps is False
    assert without_gps.flags.inspected is True  # the decoder did look


def test_macro_flag_is_set_from_the_vba_part(
    docm_bytes: bytes, docx_bytes: bytes
) -> None:
    with_macros = classify_bytes(docm_bytes, "zip")
    without_macros = classify_bytes(docx_bytes, "zip")

    assert with_macros.flags.contains_macros is True
    assert with_macros.ext == "docm"  # the macro part is what makes it a .docm
    assert without_macros.flags.contains_macros is False
    assert without_macros.ext == "docx"


def test_password_protected_archive_is_flagged_without_decrypting(
    encrypted_zip: bytes,
) -> None:
    started = time.monotonic()
    facts = classify_bytes(encrypted_zip, "zip")
    elapsed = time.monotonic() - started

    assert facts.flags.is_password_protected is True
    assert facts.flags.is_encrypted is True
    assert elapsed < 2.0


# --------------------------------------------------------------------------
# Dedupe
# --------------------------------------------------------------------------


def test_identical_content_is_reported_once_with_every_offset(
    jpeg_bytes: bytes,
) -> None:
    copies = [
        candidate(jpeg_bytes, offset=offset, ext="jpg", confidence_bp=8500)
        for offset in (4096, 65536, 1048576)
    ]

    kept = dedupe(copies)

    assert len(kept) == 1
    assert kept[0].offset == 4096
    assert kept[0].duplicate_offsets == [65536, 1048576]


def test_different_content_is_not_folded_together(
    jpeg_bytes: bytes, png_bytes: bytes
) -> None:
    kept = dedupe(
        [
            candidate(jpeg_bytes, offset=0, ext="jpg"),
            candidate(png_bytes, offset=8192, ext="png"),
        ]
    )
    assert len(kept) == 2
    assert all(item.duplicate_offsets == [] for item in kept)


def test_dedupe_keeps_the_highest_scoring_copy(jpeg_bytes: bytes) -> None:
    weak = candidate(jpeg_bytes, offset=0, ext="jpg", confidence_bp=4000, bucket="LOW")
    strong = candidate(
        jpeg_bytes, offset=8192, ext="jpg", confidence_bp=9000, bucket="HIGH"
    )

    kept = dedupe([weak, strong])

    assert len(kept) == 1
    assert kept[0].offset == 8192
    assert kept[0].duplicate_offsets == [0]


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


def test_filename_sorts_by_offset_and_carries_its_provenance(
    jpeg_bytes: bytes,
) -> None:
    named = candidate(
        jpeg_bytes,
        offset=1337,
        ext="jpg",
        confidence_bp=8500,
        original_name="holiday photo.jpg",
    )
    generated = candidate(jpeg_bytes, offset=99, ext="jpg", confidence_bp=500)

    assert output_filename(named) == "000000001337_08500_holiday_photo.jpg"
    assert output_filename(generated) == "000000000099_00500_carved-000000000099.jpg"
    assert output_filename(generated) < output_filename(named)  # sortable by offset


def test_recovered_bytes_are_written_to_the_output_directory(
    tmp_path: Path, jpeg_bytes: bytes
) -> None:
    image = BytesEvidence(b"\x00" * 512 + jpeg_bytes)
    subject = candidate(jpeg_bytes, offset=512, ext="jpg", confidence_bp=9000)

    progress = list(write_recovered([subject], image, tmp_path))

    assert len(progress) == 1
    assert progress[0]["phase"] == "WRITE"
    assert progress[0]["bytes_written"] == len(jpeg_bytes)
    written = tmp_path / output_filename(subject)
    assert written.read_bytes() == jpeg_bytes


def test_writing_into_the_evidence_path_is_refused(
    tmp_path: Path, jpeg_bytes: bytes
) -> None:
    """The evidence path is read-only. Recovered files never go back into it."""
    evidence_path = tmp_path / "case" / "image.dd"
    evidence_path.parent.mkdir()
    evidence_path.write_bytes(jpeg_bytes)

    from core.carve.evidence import open_evidence

    with open_evidence(evidence_path) as image:
        with pytest.raises(ValueError, match="refusing to write"):
            list(
                write_recovered(
                    [candidate(jpeg_bytes, ext="jpg")], image, evidence_path
                )
            )
