"""Real files of real formats, embedded at known offsets. No mocked parsers.

A carver tested against synthetic byte patterns proves nothing: the whole
difficulty is that real containers have padding, embedded thumbnails and
nested copies of their own magic. Every fixture here is produced by a real
encoder and can be opened by the format's real reader.
"""

from __future__ import annotations

import io
import sqlite3
import zipfile
from dataclasses import dataclass
from pathlib import Path

import pytest
from PIL import Image

MIB = 1024 * 1024


@dataclass(frozen=True)
class Embedded:
    """One known object placed at a known offset in a synthetic image."""

    ext: str
    offset: int
    data: bytes

    @property
    def length(self) -> int:
        return len(self.data)


def make_jpeg(size: int = 64, colour: tuple[int, int, int] = (200, 30, 30)) -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", (size, size), colour).save(buffer, "JPEG", quality=90)
    return buffer.getvalue()


def make_noisy_jpeg(size: int = 256, seed: int = 7) -> bytes:
    """A JPEG that is genuinely several clusters long.

    A flat-colour JPEG compresses to a few hundred bytes, which is *shorter
    than one cluster*. Splitting one at a 4096-byte boundary puts the whole
    file in the first fragment and leaves the second empty, so a reassembly
    test built on it passes by never fragmenting anything. Noise defeats the
    entropy coder and gives a file worth splitting.
    """
    import random

    rng = random.Random(seed)
    image = Image.new("RGB", (size, size))
    image.putdata(
        [
            (rng.randrange(256), rng.randrange(256), rng.randrange(256))
            for _ in range(size * size)
        ]
    )
    buffer = io.BytesIO()
    image.save(buffer, "JPEG", quality=95)
    return buffer.getvalue()


def make_noisy_png(size: int = 192, seed: int = 11) -> bytes:
    """A PNG several clusters long, for the same reason as the JPEG above."""
    import random

    rng = random.Random(seed)
    image = Image.new("RGB", (size, size))
    image.putdata(
        [
            (rng.randrange(256), rng.randrange(256), rng.randrange(256))
            for _ in range(size * size)
        ]
    )
    buffer = io.BytesIO()
    image.save(buffer, "PNG")
    return buffer.getvalue()


def make_png(size: int = 64) -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", (size, size), (20, 120, 200)).save(buffer, "PNG")
    return buffer.getvalue()


def make_gif(size: int = 32) -> bytes:
    buffer = io.BytesIO()
    Image.new("P", (size, size)).save(buffer, "GIF")
    return buffer.getvalue()


def make_zip(entries: int = 3) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for index in range(entries):
            archive.writestr(f"file{index}.txt", f"payload {index}\n" * 40)
    return buffer.getvalue()


def make_docx() -> bytes:
    """A minimal but structurally real OOXML package."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org'
            '/package/2006/content-types"><Default Extension="xml" '
            'ContentType="application/xml"/></Types>',
        )
        archive.writestr(
            "word/document.xml",
            '<?xml version="1.0"?><w:document xmlns:w="http://schemas.'
            'openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r>'
            "<w:t>sanctum</w:t></w:r></w:p></w:body></w:document>",
        )
        archive.writestr("docProps/core.xml", "<coreProperties/>")
    return buffer.getvalue()


def make_pdf() -> bytes:
    """A hand-built PDF with a correct xref table and startxref offset."""
    objects = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] "
        b"/Contents 4 0 R >>\nendobj\n",
        b"4 0 obj\n<< /Length 44 >>\nstream\nBT /F1 12 Tf 20 100 Td "
        b"(sanctum) Tj ET\nendstream\nendobj\n",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets: list[int] = []
    for obj in objects:
        offsets.append(len(out))
        out += obj
    xref_at = len(out)
    out += b"xref\n0 %d\n" % (len(objects) + 1)
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += b"%010d 00000 n \n" % offset
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\n" % (len(objects) + 1)
    out += b"startxref\n%d\n" % xref_at
    out += b"%%EOF\n"
    return bytes(out)


def make_sqlite(rows: int = 50) -> bytes:
    """A real SQLite database, so page_size x page_count is genuinely testable."""
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "db.sqlite"
        connection = sqlite3.connect(path)
        connection.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, body TEXT)")
        connection.executemany(
            "INSERT INTO t (body) VALUES (?)",
            [(f"row {index} " * 8,) for index in range(rows)],
        )
        connection.commit()
        connection.close()
        return path.read_bytes()


def make_mp4() -> bytes:
    """Top-level boxes only: ftyp then a sized mdat. Enough to walk."""

    def box(kind: bytes, payload: bytes) -> bytes:
        return (len(payload) + 8).to_bytes(4, "big") + kind + payload

    ftyp = box(b"ftyp", b"isom" + (512).to_bytes(4, "big") + b"isomiso2mp41")
    mdat = box(b"mdat", bytes(range(256)) * 4)
    return ftyp + mdat


#: Twelve objects across six formats, in the order they are embedded.
def build_corpus() -> list[Embedded]:
    payloads: list[tuple[str, bytes]] = [
        ("jpg", make_jpeg(64, (200, 30, 30))),
        ("png", make_png(64)),
        ("pdf", make_pdf()),
        ("zip", make_zip()),
        ("sqlite", make_sqlite()),
        ("gif", make_gif()),
        ("jpg", make_jpeg(96, (30, 200, 90))),
        ("png", make_png(32)),
        ("zip", make_docx()),
        ("mp4", make_mp4()),
        ("pdf", make_pdf()),
        ("jpg", make_jpeg(48, (10, 10, 220))),
    ]
    # Spread them across the image on 4 MiB centres, offset off any power of two
    # so an off-by-one in chunk arithmetic cannot pass by luck.
    stride = 4 * MIB
    return [
        Embedded(ext=ext, offset=index * stride + 1337, data=data)
        for index, (ext, data) in enumerate(payloads)
    ]


def lay_out(corpus: list[Embedded], total: int) -> bytes:
    """Place the corpus into a filler image of ``total`` bytes."""
    canvas = bytearray()
    seed = 0x12345678
    while len(canvas) < total:
        seed = (seed * 1103515245 + 12345) & 0xFFFFFFFF
        canvas += seed.to_bytes(4, "little")
    canvas = canvas[:total]
    for item in corpus:
        canvas[item.offset : item.offset + item.length] = item.data
    return bytes(canvas)


@pytest.fixture(scope="session")
def corpus() -> list[Embedded]:
    return build_corpus()


@pytest.fixture(scope="session")
def corpus_image(corpus: list[Embedded]) -> bytes:
    return lay_out(corpus, 64 * MIB)


@pytest.fixture(scope="session")
def corpus_file(tmp_path_factory: pytest.TempPathFactory, corpus_image: bytes) -> Path:
    path = tmp_path_factory.mktemp("corpus") / "corpus.dd"
    path.write_bytes(corpus_image)
    return path
