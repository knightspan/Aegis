"""Structure parsers: exact lengths, detected truncation, bounded malformed input.

A signature carver guesses a length. A structure parser derives one. These
tests hold the parsers to the derived answer being *exactly* right, because a
length that is close is a file that does not open.
"""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

from core.carve.evidence import BytesEvidence
from core.carve.structure import (
    MAX_ITERATIONS,
    carve_structures,
    parse_jpeg,
    parse_mp4,
    parse_png,
    parse_sqlite,
    parse_zip,
)

from tests.carve.signature.conftest import (
    Embedded,
    lay_out,
    make_docx,
    make_jpeg,
    make_mp4,
    make_png,
    make_sqlite,
)

# --------------------------------------------------------------------------
# 5. ZIP / docx
# --------------------------------------------------------------------------


def test_zip_parse_returns_the_exact_length_of_a_real_docx(tmp_path: Path) -> None:
    docx = make_docx()
    on_disk = tmp_path / "real.docx"
    on_disk.write_bytes(docx)

    image = lay_out([Embedded(ext="zip", offset=2048, data=docx)], 256 * 1024)
    parsed = parse_zip(BytesEvidence(image), 2048, max_size=1 << 30)

    assert parsed is not None
    assert parsed.length == on_disk.stat().st_size
    recovered = image[2048 : 2048 + parsed.length]
    assert hashlib.sha256(recovered).hexdigest() == hashlib.sha256(docx).hexdigest()
    # And the recovered bytes really are a readable archive.
    carved = tmp_path / "carved.docx"
    carved.write_bytes(recovered)
    with zipfile.ZipFile(carved) as archive:
        assert "word/document.xml" in archive.namelist()
        assert archive.testzip() is None


# --------------------------------------------------------------------------
# 6. SQLite
# --------------------------------------------------------------------------


def test_sqlite_length_is_page_size_times_page_count() -> None:
    database = make_sqlite()
    image = lay_out([Embedded(ext="sqlite", offset=512, data=database)], 512 * 1024)

    parsed = parse_sqlite(BytesEvidence(image), 512, max_size=1 << 30)

    assert parsed is not None
    assert parsed.length == len(database)
    page_size = int.from_bytes(database[16:18], "big")
    page_count = int.from_bytes(database[28:32], "big")
    expected = (65536 if page_size == 1 else page_size) * page_count
    assert parsed.length == expected


def test_sqlite_page_size_of_one_means_65536() -> None:
    """The format's escape for a 64 KiB page. Reading it as 1 gives a 1-byte file."""
    header = bytearray(b"SQLite format 3\x00")
    header += (1).to_bytes(2, "big")  # page_size == 1 -> 65536
    header += bytes(28 - len(header))
    header += (2).to_bytes(4, "big")  # page_count
    body = bytes(header) + b"\x00" * (2 * 65536 - len(header))

    parsed = parse_sqlite(BytesEvidence(body), 0, max_size=1 << 30)
    assert parsed is not None
    assert parsed.length == 2 * 65536


# --------------------------------------------------------------------------
# 7. Truncated JPEG
# --------------------------------------------------------------------------


def test_jpeg_without_its_end_marker_is_reported_truncated() -> None:
    jpeg = make_jpeg()
    assert jpeg.endswith(bytes.fromhex("FFD9"))
    chopped = jpeg[:-2]

    parsed = parse_jpeg(BytesEvidence(chopped), 0, max_size=1 << 20)

    assert parsed is not None
    assert parsed.validation == "truncated"


def test_intact_jpeg_is_reported_valid_with_its_exact_length() -> None:
    jpeg = make_jpeg()
    image = lay_out([Embedded(ext="jpg", offset=100, data=jpeg)], 64 * 1024)

    parsed = parse_jpeg(BytesEvidence(image), 100, max_size=1 << 20)

    assert parsed is not None
    assert parsed.validation == "valid"
    assert parsed.length == len(jpeg)


# --------------------------------------------------------------------------
# 8. Malformed MP4
# --------------------------------------------------------------------------


def test_malformed_mp4_box_size_neither_hangs_nor_reads_past_max_size() -> None:
    """A hostile length field must not turn into a multi-gigabyte read."""
    body = bytearray(make_mp4())
    body[0:4] = (0xFFFFFFFF).to_bytes(4, "big")
    handle = _CountingEvidence(bytes(body))

    import time as _time

    started = _time.perf_counter()
    parsed = parse_mp4(handle, 0, max_size=64 * 1024)
    elapsed = _time.perf_counter() - started

    assert elapsed < 5.0, f"parser took {elapsed:.1f}s on a malformed box"
    assert handle.bytes_read <= 64 * 1024 * 4, "parser read far past max_size"
    if parsed is not None:
        assert parsed.length <= 64 * 1024


def test_mp4_box_loop_is_iteration_capped() -> None:
    """A zero-size box would otherwise spin forever without advancing."""
    zero_box = (0).to_bytes(4, "big") + b"free"
    body = b"\x00\x00\x00\x18ftyp" + b"isom" + b"\x00" * 12 + zero_box * 4096

    import time as _time

    started = _time.perf_counter()
    parse_mp4(BytesEvidence(body), 0, max_size=1 << 20)
    assert _time.perf_counter() - started < 5.0
    assert MAX_ITERATIONS > 0


class _CountingEvidence(BytesEvidence):
    """Counts bytes handed out, so 'did not read past the cap' is measurable."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.bytes_read = 0

    def read(self, offset: int, length: int) -> bytes:
        out = super().read(offset, length)
        self.bytes_read += len(out)
        return out


# --------------------------------------------------------------------------
# 10. PNG CRC
# --------------------------------------------------------------------------


def test_png_with_a_corrupted_chunk_crc_is_reported_corrupt() -> None:
    png = bytearray(make_png())
    # The IHDR CRC sits at bytes 29-33: 8 magic + 4 length + 4 type + 13 data.
    png[29] ^= 0xFF

    parsed = parse_png(BytesEvidence(bytes(png)), 0, max_size=1 << 20)

    assert parsed is not None
    assert parsed.validation == "corrupt"


def test_intact_png_is_valid_and_exactly_sized() -> None:
    png = make_png()
    image = lay_out([Embedded(ext="png", offset=777, data=png)], 128 * 1024)

    parsed = parse_png(BytesEvidence(image), 777, max_size=1 << 20)

    assert parsed is not None
    assert parsed.validation == "valid"
    assert parsed.length == len(png)


# --------------------------------------------------------------------------
# Structure carving end to end
# --------------------------------------------------------------------------


def test_structure_carving_marks_its_source_as_structure(
    corpus_image: bytes,
) -> None:
    candidates = list(carve_structures(BytesEvidence(corpus_image)))
    assert candidates
    parsed = [c for c in candidates if c.source == "structure"]
    assert parsed, "no candidate was resolved by a parser"
    for candidate in parsed:
        assert candidate.length > 0


def test_structure_lengths_beat_signature_guesses(corpus: list[Embedded]) -> None:
    """The whole point: a parser gets the exact length, a footer search guesses."""
    from tests.carve.signature.conftest import lay_out as build

    zip_item = next(item for item in corpus if item.ext == "zip")
    image = build([Embedded(ext="zip", offset=4096, data=zip_item.data)], 1 << 20)
    parsed = parse_zip(BytesEvidence(image), 4096, max_size=1 << 30)
    assert parsed is not None
    assert parsed.length == zip_item.length
