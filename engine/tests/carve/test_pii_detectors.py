"""Detectors: published checksum vectors, boundaries, and the window seam.

The values used here are synthetic. Each Aadhaar-shaped and card-shaped string
is built by computing its own check digit, so none is a real identifier.
"""

from __future__ import annotations

import io
import zipfile

import pytest
from core.carve import pii


def _verhoeff_complete(stem: str) -> str:
    for digit in "0123456789":
        if pii.verhoeff_valid(stem + digit):
            return stem + digit
    raise AssertionError("Verhoeff always has exactly one check digit")


def _luhn_complete(stem: str) -> str:
    for digit in "0123456789":
        if pii.luhn_valid(stem + digit):
            return stem + digit
    raise AssertionError("Luhn always has exactly one check digit")


AADHAAR = _verhoeff_complete("49731862054")
CARD = _luhn_complete("401288888888188")


def test_verhoeff_published_vectors() -> None:
    # Wikipedia's worked example: 236 has check digit 3; 12345 has check digit 1.
    assert pii.verhoeff_valid("2363")
    assert pii.verhoeff_valid("123451")
    assert not pii.verhoeff_valid("2364")
    # Verhoeff catches every single-digit error and every adjacent transposition.
    for index in range(len(AADHAAR)):
        for digit in "0123456789":
            if digit != AADHAAR[index]:
                wrong = AADHAAR[:index] + digit + AADHAAR[index + 1 :]
                assert not pii.verhoeff_valid(wrong)
    for index in range(len(AADHAAR) - 1):
        a, b = AADHAAR[index], AADHAAR[index + 1]
        if a != b:
            swapped = AADHAAR[:index] + b + a + AADHAAR[index + 2 :]
            assert not pii.verhoeff_valid(swapped)


def test_luhn_published_vectors() -> None:
    assert pii.luhn_valid("79927398713")
    assert pii.luhn_valid("4111111111111111")
    assert not pii.luhn_valid("4111111111111112")


@pytest.mark.parametrize(
    ("text", "kind", "expected"),
    [
        (f"UID {AADHAAR} end", "aadhaar", 1),
        (f"UID {AADHAAR[:4]} {AADHAAR[4:8]} {AADHAAR[8:]}.", "aadhaar", 1),
        (f"UID {AADHAAR[:4]}-{AADHAAR[4:8]}-{AADHAAR[8:]}.", "aadhaar", 1),
        (f"mixed {AADHAAR[:4]} {AADHAAR[4:8]}-{AADHAAR[8:]}.", "aadhaar", 0),
        (f"bad {AADHAAR[:-1]}{(int(AADHAAR[-1]) + 1) % 10}", "aadhaar", 0),
        (f"longer 9{AADHAAR}", "aadhaar", 0),
        ("starts 1 " + _verhoeff_complete("19731862054"), "aadhaar", 0),
        ("PAN ABCPE1234F.", "pan", 1),
        ("PAN ABCXE1234F.", "pan", 0),
        ("xABCPE1234F", "pan", 0),
        ("IFSC SBIN0001234,", "ifsc", 1),
        ("IFSC SBIN1001234,", "ifsc", 0),
        ("call 9876543210 now", "indian_mobile", 1),
        ("call +919876543210 now", "indian_mobile", 1),
        ("call +91 9876543210 now", "indian_mobile", 1),
        ("call 0091-9876543210 now", "indian_mobile", 1),
        ("call 5876543210 now", "indian_mobile", 0),
        ("call 98765432101 now", "indian_mobile", 0),
        (f"card {CARD} ok", "payment_card", 1),
        (f"card {CARD[:4]} {CARD[4:8]} {CARD[8:12]} {CARD[12:]} ok", "payment_card", 1),
        (f"card {CARD[:-1]}{(int(CARD[-1]) + 1) % 10} ok", "payment_card", 0),
        ("mail examiner.one@case-unit.example.in, thanks", "email", 1),
        ("mail not@an-email", "email", 0),
    ],
)
def test_detector_shapes(text: str, kind: str, expected: int) -> None:
    assert pii.count_bytes(text.encode()).get(kind, 0) == expected


def test_a_value_is_counted_once_however_the_window_seam_cuts_it() -> None:
    """Every position of the seam relative to the value, including inside it."""
    values = {
        "aadhaar": f"{AADHAAR[:4]} {AADHAAR[4:8]} {AADHAAR[8:]}".encode(),
        "payment_card": CARD.encode(),
        "email": b"a.very.long.local.part@sub.domain.example.co.in",
        "indian_mobile": b"+91 9876543210",
    }
    for kind, value in values.items():
        for shift in range(-len(value) - 2, 3):
            at = pii.WINDOW_BYTES + shift
            blob = bytearray(b"\x00" * (2 * pii.WINDOW_BYTES + 100))
            blob[at : at + len(value)] = value
            counts = pii.count_bytes(bytes(blob))
            assert counts.get(kind, 0) == 1, (kind, shift, counts)


def _naive(data: bytes) -> dict[str, int]:
    """Every precise pattern over the whole buffer: the prefilter's reference."""
    counts: dict[str, int] = {}
    for kind, pattern, checksum in pii.DETECTORS:
        for match in pattern.finditer(data):
            digits = "".join(ch for ch in match.group().decode() if ch.isdigit())
            if checksum is None or checksum(digits):
                counts[kind] = counts.get(kind, 0) + 1
    return counts


def test_the_prefilter_changes_no_count() -> None:
    """Randomised: text-like noise dense in digits, capitals, separators and @."""
    import random

    rng = random.Random(26149)
    alphabet = (
        b"0123456789" * 6
        + b"ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 2
        + b" -+@._" * 3
        + b"abcxyz\n\x00"
    )
    plants = [
        AADHAAR.encode(),
        f"{AADHAAR[:4]} {AADHAAR[4:8]} {AADHAAR[8:]}".encode(),
        CARD.encode(),
        b"+91-9876543210",
        b"ABCPE1234F",
        b"SBIN0001234",
        b"first.last@mail.example.in",
    ]
    for _ in range(40):
        buffer = bytearray(rng.choice(alphabet) for _ in range(20_000))
        for plant in plants:
            at = rng.randrange(0, len(buffer) - len(plant))
            buffer[at : at + len(plant)] = plant
        data = bytes(buffer)
        assert pii.count_bytes(data) == _naive(data)


def test_streamed_text_counts_equal_the_in_memory_scan_however_it_is_cut() -> None:
    """The OOXML path feeds text in pieces; the seams must not change a count."""
    import random

    rng = random.Random(149)
    value = f"{AADHAAR[:4]} {AADHAAR[4:8]} {AADHAAR[8:]} +91 9876543210 {CARD}".encode()
    # Filler must be a boundary character: an alphanumeric neighbour would stop
    # every planted value from matching, and the test would compare zero to zero.
    blob = bytearray(b"." * (3 * pii.WINDOW_BYTES + 777))
    for at in (0, pii.WINDOW_BYTES - 20, 2 * pii.WINDOW_BYTES - 40, len(blob) - 60):
        blob[at : at + len(value)] = value
    data = bytes(blob)
    expected = pii.count_bytes(data)
    assert expected["aadhaar"] == 4
    for _ in range(6):
        counts: dict[str, int] = {}
        stream = pii._StreamCounter(counts)
        at = 0
        while at < len(data):
            step = rng.choice(
                [1, 7, 511, 4096, pii.WINDOW_BYTES + 3, 2 * pii.WINDOW_BYTES]
            )
            stream.feed(data[at : at + step])
            at += step
        stream.finish()
        assert counts == expected


def test_a_tag_or_entity_split_by_an_inflate_chunk_is_carried_whole() -> None:
    """Chunk the XML so tags and ``&amp;`` land on the seam at every offset."""
    xml = (
        b"<w:document><w:body>"
        + b"<w:p><w:r><w:t>R&amp;D pad</w:t></w:r></w:p>" * 9000
        + f"<w:p><w:r><w:t>{AADHAAR[:5]}</w:t></w:r><w:r><w:t>{AADHAAR[5:]}"
        f"</w:t></w:r></w:p>".encode()
        + b"</w:body></w:document>"
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("word/document.xml", xml)
    original = pii._XML_CHUNK_BYTES
    try:
        for chunk in (37, 41, 64, 97, 4096):
            pii._XML_CHUNK_BYTES = chunk
            counts: dict[str, int] = {}
            assert pii._count_ooxml(buffer.getvalue(), counts) == 1
            assert counts == {"aadhaar": 1}, (chunk, counts)
    finally:
        pii._XML_CHUNK_BYTES = original


def test_a_large_ooxml_part_is_never_held_whole() -> None:
    """32 MiB of inflated XML scans in a few MiB of Python allocation."""
    import tracemalloc

    paragraph = b"<w:p><w:r><w:t>case note 12345 witness</w:t></w:r></w:p>"
    xml = b"<w:document><w:body>" + paragraph * (32 * 1024 * 1024 // len(paragraph))
    xml += b"</w:body></w:document>"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("word/document.xml", xml)
    package = buffer.getvalue()
    del xml, buffer
    tracemalloc.start()
    try:
        scan = pii.scan_content(
            package, ext="docx", category="document", length=len(package)
        )
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert scan.inspected
    # Before streaming, the same package peaked at 207.9 MiB.
    assert peak < 8 * 1024 * 1024, f"peak {peak / 2**20:.1f} MiB"


def test_the_seam_does_not_invent_a_boundary() -> None:
    """A 13-digit run cut at the seam must not yield a 12-digit Aadhaar."""
    stem = "7" + AADHAAR
    at = pii.WINDOW_BYTES - 1
    blob = bytearray(b"\x00" * (2 * pii.WINDOW_BYTES))
    blob[at : at + len(stem)] = stem.encode()
    assert pii.count_bytes(bytes(blob)).get("aadhaar", 0) == 0


def test_the_reader_holds_one_window_at_a_time() -> None:
    data = b"\x00" * (5 * pii.WINDOW_BYTES) + b" 9876543210 "
    largest = 0

    def read(offset: int, size: int) -> bytes:
        nonlocal largest
        largest = max(largest, size)
        return data[offset : offset + size]

    assert pii.count_reader(read, len(data)) == {"indian_mobile": 1}
    assert largest <= pii.WINDOW_BYTES + 2 * pii.CONTEXT_BYTES


def test_ooxml_runs_are_joined_and_paragraphs_are_not() -> None:
    xml = (
        "<w:document><w:body>"
        f"<w:p><w:r><w:t>{AADHAAR[:6]}</w:t></w:r><w:r><w:t>{AADHAAR[6:]}</w:t></w:r></w:p>"
        "<w:p><w:r><w:t>1234</w:t></w:r></w:p><w:p><w:r><w:t>98765432</w:t></w:r></w:p>"
        "</w:body></w:document>"
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("word/document.xml", xml)
    scan = pii.scan_content(
        buffer.getvalue(),
        ext="docx",
        category="document",
        length=len(buffer.getvalue()),
    )
    assert scan.inspected
    assert scan.counts == {"aadhaar": 1}


def test_images_are_not_scanned_and_say_why() -> None:
    scan = pii.scan_content(b" 9876543210 ", ext="jpg", category="image", length=12)
    assert not scan.inspected
    assert scan.counts == {}
    assert "false-positive" in scan.basis


def test_the_scan_result_carries_no_matched_text() -> None:
    text = f"{AADHAAR} ABCPE1234F SBIN0001234 9876543210 {CARD} x@y.example.in".encode()
    scan = pii.scan_content(text, ext="txt", category="document", length=len(text))
    blob = repr(scan).encode()
    for value in (
        AADHAAR,
        "ABCPE1234F",
        "SBIN0001234",
        "9876543210",
        CARD,
        "x@y.example.in",
    ):
        assert value.encode() not in blob
    assert sum(scan.counts.values()) == 6
