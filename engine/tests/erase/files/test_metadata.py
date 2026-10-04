"""Metadata cleansing: strip the fields, keep the file, never claim a false clean."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest
from core.erase.metadata import cleanse_only, detect_format

_CORE_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties
  xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
  xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:creator>an operator</dc:creator>
  <cp:lastModifiedBy>another operator</cp:lastModifiedBy>
  <dc:title>Operation Notes</dc:title>
</cp:coreProperties>"""

_APP_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties
  xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  <Company>NTRO</Company><Manager>a manager</Manager>
</Properties>"""

_DOCUMENT_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>keep this text</w:t></w:r></w:p></w:body>
</w:document>"""

_CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/xml"/>
</Types>"""


@pytest.fixture
def jpeg_with_gps(tmp_path: Path) -> Path:
    import piexif
    from PIL import Image

    target = tmp_path / "photo.jpg"
    Image.new("RGB", (64, 48), (120, 30, 200)).save(target, "JPEG", quality=90)
    exif = {
        "0th": {
            piexif.ImageIFD.Make: b"SanctumCam",
            piexif.ImageIFD.Model: b"X-1",
            piexif.ImageIFD.Software: b"secret-pipeline-v3",
        },
        "Exif": {piexif.ExifIFD.DateTimeOriginal: b"2026:01:02 03:04:05"},
        "GPS": {
            piexif.GPSIFD.GPSLatitudeRef: b"N",
            piexif.GPSIFD.GPSLatitude: ((12, 1), (58, 1), (0, 1)),
            piexif.GPSIFD.GPSLongitudeRef: b"E",
            piexif.GPSIFD.GPSLongitude: ((77, 1), (35, 1), (0, 1)),
        },
        "1st": {},
        "thumbnail": None,
    }
    piexif.insert(piexif.dump(exif), str(target))
    return target


def test_every_exif_tag_including_gps_is_removed(jpeg_with_gps: Path) -> None:
    """GPS above all: it places a person somewhere at a time."""
    import piexif

    result = cleanse_only(jpeg_with_gps)

    assert result.parsed is True
    assert result.format == "JPEG"
    names = {field.name for field in result.fields}
    assert {"Make", "Model", "Software", "GPSLatitude", "GPSLatitudeRef"} <= names
    assert all(field.removed for field in result.fields)

    after = piexif.load(str(jpeg_with_gps))
    assert after["0th"] == {}
    assert after["GPS"] == {}


def test_the_cleansed_image_still_decodes(jpeg_with_gps: Path) -> None:
    """Stripping metadata must not corrupt the file it is stripping."""
    from PIL import Image

    cleanse_only(jpeg_with_gps)

    with Image.open(jpeg_with_gps) as image:
        image.load()
        assert image.size == (64, 48)


def test_docx_properties_go_and_the_document_survives(tmp_path: Path) -> None:
    target = tmp_path / "notes.docx"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", _CONTENT_TYPES)
        archive.writestr("docProps/core.xml", _CORE_XML)
        archive.writestr("docProps/app.xml", _APP_XML)
        archive.writestr("word/document.xml", _DOCUMENT_XML)

    result = cleanse_only(target)

    assert result.parsed is True
    assert result.format == "OOXML"
    names = {field.name for field in result.fields}
    assert {"dc:creator", "cp:lastModifiedBy", "dc:title", "Company"} <= names

    with zipfile.ZipFile(target) as archive:
        remaining = set(archive.namelist())
        assert "docProps/core.xml" not in remaining
        assert "docProps/app.xml" not in remaining
        assert b"keep this text" in archive.read("word/document.xml")


def test_png_text_chunks_are_removed_and_the_image_survives(tmp_path: Path) -> None:
    from PIL import Image, PngImagePlugin

    target = tmp_path / "shot.png"
    info = PngImagePlugin.PngInfo()
    info.add_text("Author", "an operator")
    info.add_text("Comment", "a secret")
    Image.new("RGB", (32, 32), (5, 5, 5)).save(target, "PNG", pnginfo=info)

    result = cleanse_only(target)

    assert result.parsed is True
    assert {"Author", "Comment"} <= {field.name for field in result.fields}
    with Image.open(target) as image:
        image.load()
        assert "Author" not in image.info
        assert image.size == (32, 32)


def test_pdf_info_and_xmp_are_both_cleared(tmp_path: Path) -> None:
    """Two separate stores that usually disagree; clearing one is not enough."""
    pikepdf = pytest.importorskip("pikepdf")

    target = tmp_path / "doc.pdf"
    with pikepdf.new() as document:
        document.add_blank_page()
        with document.open_metadata() as meta:
            meta["dc:creator"] = ["an operator"]
            meta["dc:title"] = "Operation Notes"
        document.docinfo["/Author"] = "an operator"
        document.docinfo["/Producer"] = "secret-pipeline-v3"
        document.save(target)

    result = cleanse_only(target)

    assert result.parsed is True
    containers = {field.container for field in result.fields}
    assert "Info" in containers
    with pikepdf.open(target) as document:
        assert "/Info" not in document.trailer
        with document.open_metadata() as meta:
            assert "dc:creator" not in meta


def test_an_unparsable_file_is_never_reported_as_clean(tmp_path: Path) -> None:
    """The rule that makes the whole module trustworthy.

    ``parsed=False`` with a reason reads very differently from a clean file with
    no metadata, and collapsing them would let a corrupt document be reported
    as sanitised.
    """
    target = tmp_path / "broken.jpg"
    target.write_bytes(b"\xff\xd8\xff" + b"not really a jpeg" * 10)

    result = cleanse_only(target)

    assert result.parsed is False
    assert result.fields == []
    assert result.limitations
    assert result.removed_count == 0


def test_a_format_with_no_handler_says_so_rather_than_claiming_success(
    tmp_path: Path,
) -> None:
    target = tmp_path / "data.bin"
    target.write_bytes(b"\x00\x01\x02\x03" * 64)

    result = cleanse_only(target)

    assert result.parsed is False
    assert result.limitations
    assert "no metadata handler" in result.limitations[0]


def test_format_detection_is_by_content_not_by_extension(tmp_path: Path) -> None:
    """A JPEG named .txt is exactly the file whose EXIF someone hoped nobody read."""
    from PIL import Image

    disguised = tmp_path / "notes.txt"
    Image.new("RGB", (16, 16), (1, 2, 3)).save(disguised, "JPEG")

    assert detect_format(disguised) == "JPEG"


def test_ole_streams_are_named_but_honestly_not_removed(tmp_path: Path) -> None:
    """Reporting what was found without claiming to have removed it."""
    olefile = pytest.importorskip("olefile")

    target = tmp_path / "legacy.doc"
    target.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 4096)

    result = cleanse_only(target)

    assert result.format == "OLE"
    if result.parsed:
        assert all(not field.removed for field in result.fields)
    else:
        assert result.limitations
    assert olefile is not None
