"""Build a synthetic disk-image corpus for evaluating the carving pipeline.

Every object planted here is produced by a real encoder and can be opened by
the format's real reader, because a corpus of synthetic byte patterns measures
nothing: the difficulty in carving is that real containers carry padding,
embedded thumbnails and nested copies of their own magic.

The manifest records four kinds of planted object, and the difference between
them is what makes precision measurable at all:

``intact``
    A whole file. The carver is expected to recover exactly these bytes, so
    the SHA-256 here is what a true positive matches against.
``duplicate``
    Byte-identical content planted at another offset. Recovering it is not a
    second find; the dedupe pass folds it into the first.
``truncated``
    A real file with its tail removed. Recoverable as an object, but never
    byte-identical to anything - a candidate matching one of these is a
    genuine finding that must not be scored HIGH.
``decoy``
    A valid header attached to bytes that are not that format at all: the
    ``FFD8FF`` inside a text file that every naive signature carver reports.
    Every candidate covering a decoy is a false positive.

Never touches a real device. The images are ordinary files in ``out_dir``.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import random
import sqlite3
import struct
import tempfile
import zipfile
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from PIL import Image
from PIL.TiffImagePlugin import IFDRational

__all__ = [
    "PlantedObject",
    "CorpusManifest",
    "MANIFEST_NAME",
    "generate_corpus",
    "load_manifest",
    "FilesystemFile",
    "FilesystemCorpus",
    "FS_MANIFEST_NAME",
    "generate_filesystem_corpus",
    "load_filesystem_manifest",
    "main",
]

KIB = 1024
MIB = 1024 * KIB

MANIFEST_NAME = "ground_truth.json"

#: Distance between planted objects. Wide enough that the signature scanner's
#: "bounded by the next header" rule never truncates an intact object, small
#: enough that the whole corpus fits in a few megabytes.
STRIDE_BYTES = 512 * KIB

#: Offset of the first object. Deliberately not a power of two, so an off-by-one
#: in chunk arithmetic cannot pass by luck.
FIRST_OFFSET = 1337

PlantKind = Literal["intact", "duplicate", "truncated", "decoy"]


@dataclass(frozen=True)
class PlantedObject:
    """One object at one offset in one image, with its ground truth."""

    offset: int
    length: int
    sha256: str
    ext: str
    name: str
    kind: PlantKind
    #: True when a correct carve reproduces these bytes exactly. Only ``intact``
    #: and ``duplicate`` objects are recoverable; the rest exist to be scored
    #: against, not to be found.
    recoverable: bool


@dataclass(frozen=True)
class CorpusManifest:
    """Everything planted in one image."""

    image: str
    size_bytes: int
    seed: int
    objects: list[PlantedObject]

    @property
    def recoverable_digests(self) -> set[str]:
        """SHA-256 of every object a correct carve reproduces."""
        return {item.sha256 for item in self.objects if item.recoverable}


# --------------------------------------------------------------------------
# Content generators - real encoders only
# --------------------------------------------------------------------------


def _noisy_image(size: int, rng: random.Random) -> Image.Image:
    """An image the entropy coder cannot flatten, so the file is worth carving."""
    image = Image.new("RGB", (size, size))
    image.putdata(
        [
            (rng.randrange(256), rng.randrange(256), rng.randrange(256))
            for _ in range(size * size)
        ]
    )
    return image


def make_jpeg(rng: random.Random, size: int = 128, *, gps: bool = False) -> bytes:
    buffer = io.BytesIO()
    image = _noisy_image(size, rng)
    if gps:
        exif = Image.Exif()
        # 28.6139 N, 77.2090 E - degrees/minutes/seconds as EXIF rationals.
        exif[0x8825] = {
            1: "N",
            2: (IFDRational(28), IFDRational(36), IFDRational(50)),
            3: "E",
            4: (IFDRational(77), IFDRational(12), IFDRational(32)),
        }
        image.save(buffer, "JPEG", quality=95, exif=exif)
    else:
        image.save(buffer, "JPEG", quality=95)
    return buffer.getvalue()


def make_png(rng: random.Random, size: int = 96) -> bytes:
    buffer = io.BytesIO()
    _noisy_image(size, rng).save(buffer, "PNG")
    return buffer.getvalue()


def make_gif(size: int = 48) -> bytes:
    buffer = io.BytesIO()
    Image.new("P", (size, size)).save(buffer, "GIF")
    return buffer.getvalue()


#: Every archive member is stamped with this time instead of "now".
#: ``ZipFile.writestr`` records the current local time in each header, so the
#: same seed produced a different ZIP, DOCX and XLSX digest on every run, and
#: members identical across seeds (the OOXML packages carry no seeded content)
#: coincided or not depending on the wall clock. The pooled calibration's
#: recoverable total moved between 70 and 73 across two runs of the same seeds
#: for exactly that reason. The DOS epoch is the earliest time the format holds.
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def _member(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def make_zip(rng: random.Random, entries: int = 4) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for index in range(entries):
            archive.writestr(
                _member(f"file{index}.txt"), f"payload {index} {rng.random()}\n" * 60
            )
    return buffer.getvalue()


def make_docx(*, macros: bool = False) -> bytes:
    """A structurally real OOXML package, optionally carrying a VBA project."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            _member("[Content_Types].xml"),
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org'
            '/package/2006/content-types"><Default Extension="xml" '
            'ContentType="application/xml"/></Types>',
        )
        archive.writestr(
            _member("word/document.xml"),
            '<?xml version="1.0"?><w:document xmlns:w="http://schemas.'
            'openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r>'
            "<w:t>sanctum</w:t></w:r></w:p></w:body></w:document>",
        )
        archive.writestr(_member("docProps/core.xml"), "<coreProperties/>")
        if macros:
            # Bytes, not a real VBA project: the flag is set from the part's
            # presence, and nothing in this codebase ever executes it.
            archive.writestr(
                _member("word/vbaProject.bin"), b"\xd0\xcf\x11\xe0" + b"\x00" * 512
            )
    return buffer.getvalue()


def make_xlsx() -> bytes:
    """A SpreadsheetML package: the same OPC rules, a different required part."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            _member("[Content_Types].xml"),
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org'
            '/package/2006/content-types"><Default Extension="xml" '
            'ContentType="application/xml"/></Types>',
        )
        archive.writestr(
            _member("xl/workbook.xml"),
            '<?xml version="1.0"?><workbook xmlns="http://schemas.'
            'openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet '
            'name="Sheet1" sheetId="1"/></sheets></workbook>',
        )
        archive.writestr(_member("docProps/core.xml"), "<coreProperties/>")
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


def make_sqlite(rows: int = 200) -> bytes:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "corpus.sqlite"
        connection = sqlite3.connect(path)
        connection.execute("CREATE TABLE contacts (id INTEGER PRIMARY KEY, body TEXT)")
        connection.executemany(
            "INSERT INTO contacts (body) VALUES (?)",
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
    mdat = box(b"mdat", bytes(range(256)) * 16)
    return ftyp + mdat


_DECOY_PROSE = (
    "The examiner opened the drive image and began the recovery run. "
    "Every candidate was recorded with the offset it was found at. "
)


def make_jpeg_decoy(length: int = 100 * KIB) -> bytes:
    """A JPEG header glued to English text: the classic signature false positive."""
    body = (_DECOY_PROSE * (length // len(_DECOY_PROSE) + 1))[:length]
    return b"\xff\xd8\xff\xe0" + body.encode("ascii")


def make_png_bomb() -> bytes:
    """A PNG header declaring 40000x40000 pixels over a few hundred bytes of data.

    Decoding it honestly would ask for 4.8 GB. It is planted so a corpus run
    exercises the decompression-bomb guard on the real pipeline rather than
    only in a unit test.
    """

    def chunk(kind: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + kind
            + payload
            + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
        )

    header = struct.pack(">IIBBBBB", 40000, 40000, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(b"\x00" * 256))
        + chunk(b"IEND", b"")
    )


def make_encrypted_zip(rng: random.Random) -> bytes:
    """An archive whose members are marked encrypted in their headers.

    Built by setting the encryption bit on a plain archive rather than by
    actually encrypting it: what has to be exercised is that the validator
    *declines* to decrypt and moves on, and that path is reached from the flag
    bits alone. No decryption is ever attempted, so the payload behind the flag
    never matters.
    """
    plain = make_zip(rng, entries=2)
    with zipfile.ZipFile(io.BytesIO(plain)) as archive:
        local_offsets = [item.header_offset for item in archive.infolist()]
    out = bytearray(plain)
    for offset in local_offsets:
        out[offset + 6] |= 0x01
    cursor = out.find(b"PK\x01\x02")
    while cursor != -1:
        out[cursor + 8] |= 0x01
        cursor = out.find(b"PK\x01\x02", cursor + 4)
    return bytes(out)


# --------------------------------------------------------------------------
# Layout
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class _Plant:
    ext: str
    name: str
    data: bytes
    kind: PlantKind


def _plants(rng: random.Random) -> list[_Plant]:
    """The corpus contents, in the order they are planted."""
    photo = make_jpeg(rng, 128, gps=True)
    duplicated = make_png(rng, 96)
    intact: list[_Plant] = [
        _Plant("jpg", "photo-with-gps.jpg", photo, "intact"),
        _Plant("png", "screenshot.png", duplicated, "intact"),
        _Plant("pdf", "statement.pdf", make_pdf(), "intact"),
        _Plant("zip", "archive.zip", make_zip(rng), "intact"),
        _Plant("zip", "letter.docx", make_docx(), "intact"),
        _Plant("zip", "budget-macros.docm", make_docx(macros=True), "intact"),
        _Plant("sqlite", "contacts.sqlite", make_sqlite(), "intact"),
        _Plant("gif", "sticker.gif", make_gif(), "intact"),
        _Plant("mp4", "clip.mp4", make_mp4(), "intact"),
        _Plant("jpg", "second-photo.jpg", make_jpeg(rng, 160), "intact"),
        _Plant("jpg", "third-photo.jpg", make_jpeg(rng, 96, gps=True), "intact"),
        _Plant("png", "chart.png", make_png(rng, 128), "intact"),
        _Plant("pdf", "invoice.pdf", make_pdf(), "intact"),
        _Plant("zip", "sheet.xlsx", make_xlsx(), "intact"),
        _Plant("sqlite", "messages.sqlite", make_sqlite(rows=400), "intact"),
    ]
    truncated_jpeg = make_jpeg(rng, 128)[: 3 * KIB]
    extras: list[_Plant] = [
        # The same PNG at two more offsets: dedupe has to fold three into one.
        _Plant("png", "screenshot.png", duplicated, "duplicate"),
        _Plant("png", "screenshot.png", duplicated, "duplicate"),
        _Plant("jpg", "half-written.jpg", truncated_jpeg, "truncated"),
        _Plant("pdf", "half-written.pdf", make_pdf()[:180], "truncated"),
        _Plant("png", "half-written.png", make_png(rng, 96)[: 2 * KIB], "truncated"),
        _Plant("jpg", "prose-with-jpeg-header.txt", make_jpeg_decoy(), "decoy"),
        _Plant(
            "jpg",
            "source-code-with-jpeg-header.txt",
            make_jpeg_decoy(40 * KIB),
            "decoy",
        ),
        _Plant("png", "declared-40000x40000.png", make_png_bomb(), "decoy"),
        _Plant("zip", "locked.zip", make_encrypted_zip(rng), "intact"),
    ]
    return intact + extras


def _filler(size: int, rng: random.Random) -> bytearray:
    """Pseudo-random filler. Not zeros: zeros make every carve look easy."""
    return bytearray(rng.randbytes(size))


def generate_corpus(
    out_dir: Path, *, seed: int = 0, first_offset: int = FIRST_OFFSET
) -> CorpusManifest:
    """Write a synthetic image plus ``ground_truth.json`` into ``out_dir``.

    ``first_offset`` moves every object by the same amount. The default puts
    objects off every sector boundary, which no filesystem does; the benchmark
    also carves a copy with ``first_offset=4096`` because a carver that looks
    for headers only at block starts, as PhotoRec does, finds nothing in the
    default layout for a reason that has nothing to do with real media.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)

    plants = _plants(rng)
    size = first_offset + STRIDE_BYTES * (len(plants) + 1)
    canvas = _filler(size, rng)

    objects: list[PlantedObject] = []
    for index, plant in enumerate(plants):
        offset = first_offset + index * STRIDE_BYTES
        canvas[offset : offset + len(plant.data)] = plant.data
        objects.append(
            PlantedObject(
                offset=offset,
                length=len(plant.data),
                sha256=hashlib.sha256(plant.data).hexdigest(),
                ext=plant.ext,
                name=plant.name,
                kind=plant.kind,
                recoverable=plant.kind in {"intact", "duplicate"},
            )
        )

    image_path = out_dir / "corpus.dd"
    image_path.write_bytes(bytes(canvas))
    manifest = CorpusManifest(
        image=image_path.name, size_bytes=size, seed=seed, objects=objects
    )
    (out_dir / MANIFEST_NAME).write_text(
        json.dumps(
            {
                "version": 1,
                "image": manifest.image,
                "size_bytes": manifest.size_bytes,
                "seed": manifest.seed,
                "objects": [asdict(item) for item in manifest.objects],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest


def load_manifest(corpus_dir: Path) -> CorpusManifest:
    """Read a manifest written by :func:`generate_corpus`."""
    raw = json.loads((Path(corpus_dir) / MANIFEST_NAME).read_text(encoding="utf-8"))
    return CorpusManifest(
        image=raw["image"],
        size_bytes=raw["size_bytes"],
        seed=raw["seed"],
        objects=[PlantedObject(**item) for item in raw["objects"]],
    )


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Generate a synthetic carving corpus.")
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()
    manifest = generate_corpus(args.out_dir, seed=args.seed)
    print(  # noqa: T201 - this is a CLI, not a core layer
        f"wrote {manifest.image} ({manifest.size_bytes} bytes) with "
        f"{len(manifest.objects)} planted objects"
    )


if __name__ == "__main__":
    main()


# --------------------------------------------------------------------------
# Filesystem corpus
# --------------------------------------------------------------------------
#
# The image above is a flat canvas with objects planted in it, which measures
# the signature and structure carvers and nothing else. Filesystem-aware
# recovery needs real volumes: real mkfs output, real directory entries, real
# deletion. Those are built here, on top of testkit.fsimage, and the manifest
# records per file what filesystem it was on, whether it was deleted, whether
# it was fragmented, and its SHA-256 - which is what makes a per-filesystem
# recall table possible rather than one averaged number that hides ext4 behind
# NTFS.

FS_MANIFEST_NAME = "filesystem_truth.json"

#: NTFS needs room for its metadata files before it will accept any content.
NTFS_IMAGE_BYTES = 24 * MIB

#: The smallest volume ``mkfs.vfat -F 32`` will still format as FAT32 with
#: room to spare. This image is filled to capacity to force fragmentation, so
#: unlike the others it occupies its full size on disk.
FAT_IMAGE_BYTES = 40 * MIB

#: Filler size, and therefore the size of every hole the fragmented file is
#: threaded through.
FAT_FILLER_BYTES = 256 * KIB

#: The fragmented file, sized to span several holes and so be fragmented
#: several times over rather than merely split in two.
FAT_FRAGMENT_BYTES = 5 * FAT_FILLER_BYTES

#: exFAT and ext hold a handful of small files and need nothing more.
SMALL_IMAGE_BYTES = 12 * MIB


@dataclass(frozen=True)
class FilesystemFile:
    """One file planted in one filesystem image, with its ground truth."""

    image: str
    filesystem: str
    name: str
    sha256: str
    size: int
    deleted: bool
    fragmented: bool
    #: True when a correct undelete reproduces these bytes exactly. Deleted
    #: files on ext4 are deliberately **not** recoverable: the extent tree is
    #: gone, and a corpus that claimed otherwise would be measuring a
    #: filesystem nobody runs.
    recoverable: bool
    #: Why this row is what it is, for a reader of the manifest.
    note: str = ""


@dataclass(frozen=True)
class FilesystemCorpus:
    """Every filesystem image built, and everything planted in them."""

    images: list[str]
    files: list[FilesystemFile]
    #: Images built to be damaged, and what was done to each.
    damaged: dict[str, str]
    #: Image-absolute byte offset of each partition in the multi-partition
    #: image, so a test can check a recovered offset against a known plant.
    partition_offsets: list[int]

    def for_filesystem(self, filesystem: str) -> list[FilesystemFile]:
        return [item for item in self.files if item.filesystem == filesystem]

    def recoverable_digests(self, filesystem: str | None = None) -> set[str]:
        return {
            item.sha256
            for item in self.files
            if item.recoverable
            and (filesystem is None or item.filesystem == filesystem)
        }


def _fs_objects(rng: random.Random) -> list[tuple[str, bytes]]:
    """Real files, produced by real encoders, for planting in a volume."""
    return [
        ("photo.jpg", make_jpeg(rng, 128, gps=True)),
        ("screenshot.png", make_png(rng, 96)),
        ("statement.pdf", make_pdf()),
        ("archive.zip", make_zip(rng)),
        ("letter.docx", make_docx()),
        ("budget.xlsx", make_xlsx()),
        ("contacts.sqlite", make_sqlite()),
        ("sticker.gif", make_gif()),
        ("clip.mp4", make_mp4()),
        ("second.jpg", make_jpeg(rng, 160)),
    ]


def _ntfs_objects(rng: random.Random) -> list[tuple[str, bytes]]:
    """Twenty distinct files for the NTFS image.

    Distinct is the requirement, not merely twenty. Several of the generators
    above take no randomness - ``make_pdf`` and ``make_gif`` produce the same
    bytes every call - so planting one list twice yields duplicate content, and
    a recall counted over SHA-256 would report eight recovered files as six. So
    every object here is parameterised by something that actually varies.
    """
    objects: list[tuple[str, bytes]] = []
    for index in range(10):
        photo = make_jpeg(rng, 96 + index * 8, gps=index % 2 == 0)
        objects.append((f"photo{index:02d}.jpg", photo))
    for index in range(5):
        objects.append((f"shot{index:02d}.png", make_png(rng, 64 + index * 16)))
    for index in range(3):
        objects.append((f"arch{index:02d}.zip", make_zip(rng, entries=2 + index)))
    objects.append(("contacts.sqlite", make_sqlite(rows=120)))
    objects.append(("messages.sqlite", make_sqlite(rows=260)))
    return objects


def generate_filesystem_corpus(  # noqa: C901 - one pass per filesystem, read top to bottom
    out_dir: Path, *, seed: int = 0, payload_dir: Path | None = None
) -> FilesystemCorpus:
    """Build one image per filesystem, plus the damaged and multi-partition ones.

    Needs no root. Every builder in :mod:`testkit.fsimage` writes the on-disk
    structures directly or drives a tool that does, because a corpus that only
    builds under ``sudo`` stops being built and nobody finds out until it
    matters.

    ``payload_dir``, when given, receives every planted file's bytes named by
    their SHA-256. The manifest records digests only; the benchmark needs the
    bytes to find each file on the medium and to tell a corrupt recovery of a
    planted file from an object that was never planted.
    """
    # Image sizes are kept small on purpose. The corpus is built into pytest's
    # tmp_path, which on most Linux hosts is a tmpfs - so every megabyte here
    # is a megabyte of RAM, held for the session and for the two previous
    # sessions pytest keeps. Filling a FAT32 volume to capacity to force
    # fragmentation materialises the whole image, so that one dominates: it is
    # sized to the smallest volume mkfs.vfat will still format as FAT32.
    from testkit.fsimage import (
        PlantedFile,
        build_exfat,
        build_ext,
        build_fat32,
        build_ntfs,
        build_two_partition_image,
        damage_boot_sector,
        damage_partition_table,
        ntfs_reuse_record,
        quick_format,
        sparse_copy,
    )

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    objects = _fs_objects(rng)
    rows: list[FilesystemFile] = []
    images: list[str] = []

    def record(
        image: str,
        filesystem: str,
        planted: PlantedFile,
        *,
        recoverable: bool,
        note: str = "",
    ) -> None:
        if payload_dir is not None:
            digest = hashlib.sha256(planted.data).hexdigest()
            stored = Path(payload_dir) / digest
            if not stored.exists():
                stored.parent.mkdir(parents=True, exist_ok=True)
                stored.write_bytes(planted.data)
        rows.append(
            FilesystemFile(
                image=image,
                filesystem=filesystem,
                name=planted.name,
                sha256=hashlib.sha256(planted.data).hexdigest(),
                size=len(planted.data),
                deleted=planted.deleted,
                fragmented=planted.fragmented,
                recoverable=recoverable,
                note=note,
            )
        )

    # -- NTFS: the demo filesystem. 20 files, 8 deleted, all recoverable. ----
    # Twenty *distinct* objects, not ten planted twice. Identical content would
    # collapse to ten digests, and a recall figure counted over digests would
    # then report ten recoveries as five and be wrong in the flattering
    # direction only by accident.
    ntfs_objects = _ntfs_objects(random.Random(seed + 1))
    ntfs_files = [
        PlantedFile(f"{index:02d}-{name}", data, deleted=index % 5 in (0, 3))
        for index, (name, data) in enumerate(ntfs_objects)
    ]
    build_ntfs(out_dir / "ntfs.img", ntfs_files, size=NTFS_IMAGE_BYTES)
    images.append("ntfs.img")
    for planted in ntfs_files:
        record(
            "ntfs.img",
            "ntfs",
            planted,
            recoverable=planted.deleted,
            note="MFT record and $DATA run list both survive deletion",
        )

    # -- NTFS with a reused record: a name in $I30 slack and no content. -----
    # The file whose record gets reused has to be the *last* entry in the
    # directory's index. NTFS removes an entry by shifting the ones after it
    # down, so a middle entry's bytes are overwritten by its successors and
    # nothing of it survives. Only the last entry has nothing after it to
    # shift: the end marker lands on its 16-byte header and leaves its
    # $FILE_NAME key sitting in slack, which is the state being modelled. The
    # names are index-prefixed, so the last entry is simply the highest index.
    reuse_files = [
        PlantedFile(
            f"{index:02d}-{name}",
            data,
            deleted=index % 5 in (0, 3) or index == len(ntfs_objects) - 1,
        )
        for index, (name, data) in enumerate(ntfs_objects)
    ]
    records = build_ntfs(
        out_dir / "ntfs-reused.img", reuse_files, size=NTFS_IMAGE_BYTES
    )
    images.append("ntfs-reused.img")
    reused_name = reuse_files[-1].name
    ntfs_reuse_record(
        out_dir / "ntfs-reused.img", records[reused_name], "X" * len(reused_name)
    )
    for planted in reuse_files:
        record(
            "ntfs-reused.img",
            "ntfs",
            planted,
            recoverable=planted.deleted and planted.name != reused_name,
            note=(
                "MFT record reused by another file: the name survives in $I30 "
                "slack and no content does"
                if planted.name == reused_name
                else ""
            ),
        )

    # -- FAT32, twice: once with live neighbours, once without. -------------
    fragment_payload = rng.randbytes(FAT_FRAGMENT_BYTES)
    for image_name, keep in (("fat32.img", False), ("fat32-neighbours.img", True)):
        fat_files = [
            PlantedFile("keep.jpg", objects[0][1]),
            PlantedFile("gone.png", objects[1][1], deleted=True),
            PlantedFile("gone.pdf", objects[2][1], deleted=True),
            PlantedFile(
                "split.bin", fragment_payload, deleted=True, fragmented=True
            ),
        ]
        fillers = build_fat32(
            out_dir / image_name,
            fat_files,
            size=FAT_IMAGE_BYTES,
            filler_bytes=FAT_FILLER_BYTES,
            keep_fillers=keep,
        )
        images.append(image_name)
        # The fillers are ordinary files that were written and, for half of
        # them, deleted. Recovery finds them, so leaving them out of the
        # manifest would score several hundred correct recoveries as false
        # positives and report FAT precision near zero for a reason that has
        # nothing to do with FAT.
        for planted in fillers:
            record(
                image_name,
                "fat32",
                planted,
                recoverable=planted.deleted,
                note="filler written to force fragmentation of split.bin",
            )
        for planted in fat_files:
            recoverable = planted.deleted and not (planted.fragmented and not keep)
            record(
                image_name,
                "fat32",
                planted,
                recoverable=recoverable,
                note=(
                    "fragmented; the neighbouring fillers still exist, so the "
                    "reconstruction can route around them and happens to be exact"
                    if planted.fragmented and keep
                    else "fragmented and its neighbours were deleted too, so the "
                    "reconstruction pulls in their bytes and is wrong"
                    if planted.fragmented
                    else "cluster chain destroyed; recovered on the free-cluster "
                    "assumption"
                    if planted.deleted
                    else ""
                ),
            )

    # -- exFAT: one file with NoFatChain set, one without. -------------------
    exfat_files = [
        PlantedFile("contiguous.jpg", objects[9][1], deleted=True),
        PlantedFile("chained.png", objects[1][1], deleted=True),
        PlantedFile("neighbour.pdf", objects[2][1]),
    ]
    flags = build_exfat(
        out_dir / "exfat.img",
        exfat_files,
        size=SMALL_IMAGE_BYTES,
        contiguous=["contiguous.jpg"],
    )
    images.append("exfat.img")
    for planted in exfat_files:
        no_chain = flags.get(planted.name, False)
        record(
            "exfat.img",
            "exfat",
            planted,
            recoverable=planted.deleted and no_chain,
            note=(
                "NoFatChain set: exFAT stored this as one run and recorded that "
                "it had, so the contiguous read is a fact"
                if no_chain
                else "NoFatChain clear: it used a chain, deletion destroyed it, "
                "and the file was laid out non-contiguously on purpose"
            ),
        )

    # -- ext2, ext3, ext4 ----------------------------------------------------
    for kind in ("ext2", "ext3", "ext4"):
        ext_files = [
            PlantedFile("report.pdf", objects[2][1], deleted=True),
            PlantedFile("photo.jpg", objects[0][1], deleted=True),
            PlantedFile("kept.zip", objects[3][1]),
        ]
        build_ext(
            out_dir / f"{kind}.img", ext_files, kind=kind, size=SMALL_IMAGE_BYTES
        )
        images.append(f"{kind}.img")
        for planted in ext_files:
            record(
                f"{kind}.img",
                kind,
                planted,
                # ext4 zeroes the extent tree on unlink. Nothing points at the
                # blocks any more, so nothing is recoverable from the inode.
                recoverable=planted.deleted and kind != "ext4",
                note=(
                    "ext4 zeroes the inode's extent tree on unlink; recovery "
                    "from metadata is not possible and this row is expected to "
                    "be a miss"
                    if kind == "ext4" and planted.deleted
                    else "block pointers survive the unlink"
                    if planted.deleted
                    else ""
                ),
            )

    # -- A plain FAT32 volume: no fillers, no fragmentation, so it stays
    # sparse. Used for the partition-offset image and the quick-format one,
    # neither of which needs the packed volume.
    plain_fat_files = [
        PlantedFile("holiday.jpg", objects[0][1], deleted=True),
        PlantedFile("notes.pdf", objects[2][1], deleted=True),
        PlantedFile("kept.gif", objects[7][1]),
    ]
    build_fat32(
        out_dir / "fat32-plain.img", plain_fat_files, size=FAT_IMAGE_BYTES
    )
    images.append("fat32-plain.img")
    for planted in plain_fat_files:
        record(
            "fat32-plain.img",
            "fat32",
            planted,
            recoverable=planted.deleted,
            note="unfragmented; the free-cluster reconstruction is exact here",
        )

    # -- Two partitions, so offsets can be checked against a known plant. ----
    offsets = build_two_partition_image(
        out_dir / "two-partitions.img",
        [(out_dir / "ntfs.img", "ntfs"), (out_dir / "fat32-plain.img", "fat32")],
    )
    images.append("two-partitions.img")
    for planted in ntfs_files:
        record(
            "two-partitions.img",
            "ntfs",
            planted,
            recoverable=planted.deleted,
            note=f"partition 1 at image offset {offsets[0]}",
        )
    # The second partition is a byte-for-byte copy of fat32.img, so everything
    # planted there is planted here too. Recording only the NTFS half would
    # leave a hundred and ninety FAT32 recoveries with no manifest row to match
    # against, and they would be counted as false positives.
    for planted in plain_fat_files:
        record(
            "two-partitions.img",
            "fat32",
            planted,
            recoverable=planted.deleted,
            note=f"partition 2 at image offset {offsets[1]}",
        )

    # -- Damaged variants ----------------------------------------------------
    damaged: dict[str, str] = {}

    sparse_copy(out_dir / "ntfs.img", out_dir / "damaged-boot.img")
    damage_boot_sector(out_dir / "damaged-boot.img")
    damaged["damaged-boot.img"] = "NTFS volume with its boot sector zeroed"

    sparse_copy(
        out_dir / "two-partitions.img", out_dir / "damaged-parttable.img"
    )
    damage_partition_table(out_dir / "damaged-parttable.img")
    damaged["damaged-parttable.img"] = (
        "two-partition image whose MBR entries are garbage but whose 55 AA "
        "signature is intact, so a volume system tries and fails to parse it"
    )

    # Copied from the *unfilled* FAT32 volume, not the one deliberately packed
    # to capacity: this variant is about what a quick format leaves behind, and
    # a hundred filler files would only make it bigger, not more instructive.
    sparse_copy(out_dir / "fat32-plain.img", out_dir / "quick-formatted.img")
    quick_format(out_dir / "quick-formatted.img", kind="fat32")
    damaged["quick-formatted.img"] = (
        "FAT32 volume re-created over its own contents: every record gone, "
        "every data block still there"
    )
    images.extend(sorted(damaged))

    corpus = FilesystemCorpus(
        images=images,
        files=rows,
        damaged=damaged,
        partition_offsets=offsets,
    )
    (out_dir / FS_MANIFEST_NAME).write_text(
        json.dumps(
            {
                "version": 1,
                "seed": seed,
                "images": corpus.images,
                "damaged": corpus.damaged,
                "partition_offsets": corpus.partition_offsets,
                "files": [asdict(item) for item in corpus.files],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return corpus


def load_filesystem_manifest(corpus_dir: Path) -> FilesystemCorpus:
    """Read a manifest written by :func:`generate_filesystem_corpus`."""
    raw = json.loads(
        (Path(corpus_dir) / FS_MANIFEST_NAME).read_text(encoding="utf-8")
    )
    return FilesystemCorpus(
        images=raw["images"],
        files=[FilesystemFile(**item) for item in raw["files"]],
        damaged=raw["damaged"],
        partition_offsets=raw["partition_offsets"],
    )
