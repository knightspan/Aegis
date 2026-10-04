"""A footer search never runs past the next object of the same format.

Found by the 7 GiB validation run (``docs/validation/large-image.md``), and not
by any of the small corpora, because there every object sat 512 KiB from its
neighbour. On the large image a truncated PDF - header present, ``%%EOF`` gone
- was bounded by the *next* PDF's ``%%EOF`` 11.7 MB away. The PDF decoder
repairs from any trailer it can reach, so it called that span valid and the
candidate scored HIGH: 39 HIGH candidates matched no planted file. The
oversized span then overlapped small intact archives and demoted them to LOW.

The rule: a second header of the same, non-nesting format means a new object
has begun, so a footer beyond it belongs to that object.
"""

from __future__ import annotations

from core.carve.evidence import BytesEvidence
from core.carve.signature import load_signatures, scan

from tests.carve.signature.conftest import Embedded, lay_out, make_jpeg

TRUNCATED_PDF = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n" + b"x" * 100
WHOLE_PDF = (
    b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
    b"trailer\n<< /Root 1 0 R >>\n%%EOF"
)


def _pdfs(image: bytes) -> list[tuple[int, int]]:
    report = scan(BytesEvidence(image), signatures=load_signatures())
    return [(c.offset, c.length) for c in report.candidates if c.ext == "pdf"]


def test_a_truncated_pdf_does_not_borrow_the_next_pdfs_trailer() -> None:
    image = lay_out(
        [
            Embedded(ext="pdf", offset=4096, data=TRUNCATED_PDF),
            Embedded(ext="pdf", offset=4096 + 2 * 1024 * 1024, data=WHOLE_PDF),
        ],
        4 * 1024 * 1024,
    )

    spans = dict(_pdfs(image))

    # The truncated one ends no later than where the second one begins...
    assert spans[4096] <= 2 * 1024 * 1024
    # ...and the whole one still reaches its own footer exactly.
    assert spans[4096 + 2 * 1024 * 1024] == len(WHOLE_PDF)


def test_a_truncated_pdf_is_reported_as_truncated_not_valid() -> None:
    image = lay_out(
        [
            Embedded(ext="pdf", offset=4096, data=TRUNCATED_PDF),
            Embedded(ext="pdf", offset=1024 * 1024, data=WHOLE_PDF),
        ],
        2 * 1024 * 1024,
    )
    report = scan(BytesEvidence(image), signatures=load_signatures())
    first = next(c for c in report.candidates if c.offset == 4096)

    assert first.validation == "truncated"
    assert first.bucket == "LOW"


def test_a_jpeg_thumbnail_does_not_cut_its_parent_short() -> None:
    """JPEG nests: an EXIF thumbnail carries its own SOI.

    The same-format bound must not apply to a format whose objects contain
    headers of their own kind, or every JPEG with a thumbnail would end at it.
    """
    parent = make_jpeg(64)
    thumb = make_jpeg(16, (10, 200, 10))
    nested = parent[:20] + thumb + parent[20:]
    image = lay_out([Embedded(ext="jpg", offset=8192, data=nested)], 256 * 1024)

    report = scan(BytesEvidence(image), signatures=load_signatures())
    outer = next(c for c in report.candidates if c.offset == 8192)

    # Bounded by the first FFD9 as before, which is the thumbnail's: the point
    # is only that the new rule did not shorten it further.
    assert outer.length >= 20 + len(thumb)


# --------------------------------------------------------------------------
# The structure parser: an incremental update never contains a new document
# --------------------------------------------------------------------------


def _xref_pdf() -> bytes:
    """A small PDF whose startxref really points at its xref table."""
    body = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
    xref_at = len(body)
    body += b"xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n"
    body += b"trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n"
    body += str(xref_at).encode() + b"\n%%EOF"
    return body


def test_a_pdf_does_not_absorb_an_identical_pdf_further_along() -> None:
    """Found on the 1 GiB validation image.

    Two byte-identical PDFs: the second one's ``startxref``, measured from the
    first one's start, lands on the first one's xref, so it corroborates. The
    filler after the first ``%%EOF`` begins with ``%``, which the revision
    prefix test accepts. Only the second ``%PDF-`` header in between says this
    is a new document.
    """
    from core.carve.structure import parse_pdf

    pdf = _xref_pdf()
    gap = b"% not an update\n" + bytes((i * 7 + 3) & 0xFF for i in range(8192))
    image = pdf + gap + pdf + b"\x00" * 4096

    parsed = parse_pdf(BytesEvidence(image), 0, max_size=len(image))

    assert parsed is not None
    assert parsed.length <= len(pdf) + 2


def test_a_genuine_incremental_update_is_still_followed() -> None:
    from core.carve.structure import parse_pdf

    pdf = _xref_pdf()
    update_at = len(pdf) + 1
    update = b"\n2 0 obj\n<< /Producer (edit) >>\nendobj\n"
    xref_at = update_at + len(update)
    update += b"xref\n2 1\n0000000000 00000 n \ntrailer\n<< /Size 3 >>\nstartxref\n"
    update += str(xref_at - 1).encode() + b"\n%%EOF"
    image = pdf + update + b"\x00" * 4096

    parsed = parse_pdf(BytesEvidence(image), 0, max_size=len(image))

    assert parsed is not None
    assert parsed.length > len(pdf) + 2
