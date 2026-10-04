"""Head-to-head recovery benchmark: Sanctum, PhotoRec and Foremost on identical images.

The question it answers is narrow on purpose: given the same image and the same
ground truth, which tool returns the planted files **byte for byte**, how many
files does it return that are corrupt, how many objects does it return that
were never planted, and how long does it take.

Fairness rules, which decide whether the output is evidence:

* **Like with like.** PhotoRec and Foremost carve; they do not read filesystem
  metadata. Sanctum's comparable row is ``sanctum-carve`` (``undelete=False``).
  ``sanctum-full`` (undelete, then carve) is reported as a separate row and is
  never the row compared against the carvers.
* **Default settings for all three.** Sanctum runs ``carve_generator`` with its
  defaults (PII triage on). Foremost runs with no configuration file, which is
  its built-in type set. PhotoRec runs with its default file-type selection;
  the one option given is scope - ``partition_none,wholespace`` - so it scans
  the whole image as the other two do, rather than one partition or free space
  only.
* **One scorer.** Every tool writes files into a directory, and the same code
  hashes and attributes every file. No tool's own report, log or claimed offset
  is read. See :func:`score_run`.

Scoring, per image:

* A planted object whose SHA-256 matches an output file is **byte-identical**.
* Otherwise, an output whose leading bytes agree with one planted object longer
  than with any other (at least 64 bytes) is a **corrupt** recovery of it.
* An output attributed to nothing planted is a **false positive**, split into
  *fragment* (its head lies inside a planted file, such as a ZIP member or an
  embedded thumbnail), *decoy* (a planted fake header), *ambiguous* (agrees
  equally with two different planted objects) and *unrelated*.
* Recall denominators hold only **FULL** formatted objects
  (:mod:`testkit.damage`). PARTIAL objects are reported apart, GONE objects are
  not counted, and unformatted content (fillers, random bytes) is reported apart
  because no signature carver can find it.

Never touches a device. Every image is an ordinary file.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import random
import shutil
import struct
import subprocess
import sys
import tarfile
import time
import wave
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from core.benchmark.outputs import (
    HEAD_BYTES,
    MIN_AGREEMENT,
    OUTPUT_INDEX,
    REPORT_FILES,
    attribute_outputs,
    common_prefix,
    index_outputs,
    load_outputs,
    select_outputs,
)
from PIL import Image

from testkit.damage import (
    TRUTH_SUFFIX,
    Overwrite,
    Truth,
    TruthObject,
    apply_interleaved_overwrite,
    apply_metadata_destruction,
    apply_truncation,
    apply_zeroed_regions,
    load_truth,
    locate,
    status_of,
    write_truth,
)

__all__ = [
    "TOOLS",
    "COMPARABLE",
    "RunScore",
    "score_run",
    "build",
    "run",
    "score",
    "main",
]

KIB = 1024
MIB = 1024 * KIB
REPO = Path(__file__).resolve().parents[1]

#: Every row the benchmark produces. ``sanctum-full`` is not a carver's peer.
TOOLS = ("sanctum-carve", "photorec", "foremost", "sanctum-full")
#: The rows that are compared with each other.
COMPARABLE = ("sanctum-carve", "photorec", "foremost")

#: Files a tool writes about its run rather than recovered objects, and the
#: attribution thresholds. They live in :mod:`core.benchmark.outputs`, which is
#: the one attribution both this benchmark and the first-class scorer run.
_REPORT_FILES = REPORT_FILES
_HEAD_BYTES = HEAD_BYTES
_MIN_AGREEMENT = MIN_AGREEMENT

PHOTOREC_OPTIONS = "partition_none,wholespace,search"


# --------------------------------------------------------------------------
# Planted content
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Plant:
    name: str
    format: str
    data: bytes
    deleted: bool = False


def _noise_image(rng: random.Random, size: int, mode: str = "RGB") -> Image.Image:
    image = Image.new(mode, (size, size))
    image.frombytes(rng.randbytes(size * size * len(mode)))
    return image


def _encode(image: Image.Image, fmt: str, **options: Any) -> bytes:
    buffer = io.BytesIO()
    image.save(buffer, fmt, **options)
    return buffer.getvalue()


def _pdf(text: str) -> bytes:
    """A PDF with a correct xref, like ``generate_corpus.make_pdf`` but distinct."""
    content = f"BT /F1 12 Tf 20 100 Td ({text}) Tj ET".encode()
    objects = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] "
        b"/Contents 4 0 R >>\nendobj\n",
        b"4 0 obj\n<< /Length %d >>\nstream\n" % len(content)
        + content
        + b"\nendstream\nendobj\n",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for obj in objects:
        offsets.append(len(out))
        out += obj
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % offset for offset in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        xref,
    )
    return bytes(out)


def _prose(rng: random.Random, words: int) -> str:
    vocabulary = (
        "examiner image sector cluster record volume recovered deleted file "
        "header footer offset evidence ledger report chain signature carve"
    ).split()
    return " ".join(rng.choice(vocabulary) for _ in range(words))


def _wav(rng: random.Random, seconds: float = 1.0, rate: int = 8000) -> bytes:
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as out:
        out.setnchannels(1)
        out.setsampwidth(2)
        out.setframerate(rate)
        out.writeframes(rng.randbytes(int(seconds * rate) * 2))
    return buffer.getvalue()


def _tar(rng: random.Random) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as out:
        for index in range(2):
            body = (_prose(rng, 400) + "\n").encode()
            info = tarfile.TarInfo(f"notes{index}.txt")
            info.size = len(body)
            info.mtime = 1_700_000_000
            out.addfile(info, io.BytesIO(body))
    return buffer.getvalue()


def media_plants(rng: random.Random) -> list[Plant]:
    """What every benchmark volume holds. Real encoders only.

    Two groups on purpose. JPEG, PNG, GIF, PDF, ZIP, DOCX, XLSX, SQLite, MP4 and
    TIFF have a header in Sanctum's signature table. BMP, WebP, WAV, GZIP, TAR,
    HTML and RTF do not, and PhotoRec knows all of them: a benchmark with only
    the first group would hide exactly where Sanctum should lose.
    """
    from testkit.generate_corpus import (
        make_docx,
        make_gif,
        make_jpeg,
        make_mp4,
        make_png,
        make_sqlite,
        make_xlsx,
        make_zip,
    )

    html = (
        "<!DOCTYPE html>\n<html><head><title>case notes</title></head><body>"
        f"<p>{_prose(rng, 600)}</p></body></html>\n"
    ).encode()
    rtf = "{\\rtf1\\ansi\\deff0 {\\fonttbl {\\f0 Times;}}\\f0 " + _prose(rng, 600) + "}"
    return [
        Plant("photo-small.jpg", "JPEG", make_jpeg(rng, 128, gps=True), True),
        Plant("photo-mid.jpg", "JPEG", make_jpeg(rng, 384), True),
        Plant("photo-large.jpg", "JPEG", make_jpeg(rng, 768), False),
        Plant("shot.png", "PNG", make_png(rng, 192), True),
        Plant("chart.png", "PNG", make_png(rng, 96), False),
        Plant("sticker.gif", "GIF", make_gif(64), True),
        Plant("statement.pdf", "PDF", _pdf("statement " + _prose(rng, 20)), True),
        Plant("invoice.pdf", "PDF", _pdf("invoice " + _prose(rng, 20)), False),
        Plant("archive.zip", "ZIP", make_zip(rng, 6), True),
        Plant("letter.docx", "DOCX", make_docx(), True),
        Plant("budget.xlsx", "XLSX", make_xlsx(), False),
        Plant("contacts.sqlite", "SQLite", make_sqlite(rows=2000), True),
        Plant("clip.mp4", "MP4", make_mp4(), True),
        Plant("scan.tiff", "TIFF", _encode(_noise_image(rng, 128), "TIFF"), True),
        Plant("icon.bmp", "BMP", _encode(_noise_image(rng, 128), "BMP"), True),
        Plant(
            "photo.webp",
            "WebP",
            _encode(_noise_image(rng, 256), "WEBP", quality=90),
            True,
        ),
        Plant("voice.wav", "WAV", _wav(rng), True),
        Plant(
            "notes.gz",
            "GZIP",
            gzip.compress((_prose(rng, 3000) + "\n").encode(), mtime=0),
            True,
        ),
        Plant("backup.tar", "TAR", _tar(rng), True),
        Plant("page.html", "HTML", html, True),
        Plant("memo.rtf", "RTF", rtf.encode(), True),
    ]


def interleave_overwrites(rng: random.Random) -> list[Overwrite]:
    """The two later files of the interleaved-overwrite model."""
    from testkit.generate_corpus import make_jpeg, make_png

    return [
        Overwrite(
            "contacts.sqlite", "later-head.jpg", "JPEG", make_jpeg(rng, 160), 0.0
        ),
        Overwrite("photo-large.jpg", "later-tail.png", "PNG", make_png(rng, 128), 0.5),
    ]


# --------------------------------------------------------------------------
# Building the images
# --------------------------------------------------------------------------


def _store(payloads: Path, data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    target = payloads / digest
    if not target.exists():
        payloads.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return digest


def _cluster_bytes(path: Path, filesystem: str) -> int:
    """The volume's cluster size from its boot record, or 512 if unreadable.

    A damaged or multi-volume image has no single boot record to read; every
    layout is still on the 512-byte sector grid, so that is the fallback.
    """
    with open(path, "rb") as handle:
        boot = handle.read(4096)
    value = 0
    if filesystem in ("fat32", "ntfs"):
        value = int(struct.unpack_from("<H", boot, 0x0B)[0]) * boot[0x0D]
    elif filesystem == "exfat" and boot[0x6C] < 16 and boot[0x6D] < 26:
        value = (1 << boot[0x6C]) << boot[0x6D]
    elif filesystem.startswith("ext"):
        shift = int(struct.unpack_from("<I", boot, 1024 + 0x18)[0])
        value = 1024 << shift if shift < 8 else 0
    if value < 512 or value & (value - 1):
        return 512
    return value


def _near(medium: bytes, data: bytes) -> tuple[int, int] | None:
    """Where a small object sits with a few bytes changed: (offset, bytes equal).

    Only objects of at most 64 KiB whose first 64 bytes are intact are tried,
    and at least 90% of the bytes must agree. Anything looser would be a guess.
    """
    if len(data) > 64 * KIB or len(data) < 64:
        return None
    best: tuple[int, int] | None = None
    at = medium.find(data[:64])
    tries = 0
    while at != -1 and tries < 64:
        tries += 1
        window = medium[at : at + len(data)]
        equal = sum(
            1 for left, right in zip(window, data, strict=False) if left == right
        )
        if best is None or equal > best[1]:
            best = (at, equal)
        at = medium.find(data[:64], at + 1)
    if best is None or best[1] * 10 < len(data) * 9:
        return None
    return best


def _truth_from_plants(
    image: Path,
    *,
    corpus: str,
    model: str,
    description: str,
    filesystem: str,
    plants: Sequence[Plant],
    payloads: Path,
    unformatted: frozenset[str] = frozenset(),
    notes: dict[str, str] | None = None,
    require: bool = True,
) -> Truth:
    cluster = _cluster_bytes(image, filesystem)
    size = image.stat().st_size
    objects: list[TruthObject] = []
    with open(image, "rb") as handle:
        medium = handle.read()
    for plant in plants:
        digest = _store(payloads, plant.data)
        extents = locate(medium, plant.data, grid=cluster, holes=True)
        note = (notes or {}).get(plant.name, "")
        holes = 0
        near = _near(medium, plant.data) if extents is None else None
        if extents is None and near is not None:
            at, alive = near
            extents, status = ((at, len(plant.data)),), "PARTIAL"
            differ = len(plant.data) - alive
            note = (note + "; " if note else "") + (
                f"on the medium with {differ} of {len(plant.data)} bytes differing"
                " (for NTFS, a file resident in its MFT record, whose update-"
                "sequence fixups replace the last two bytes of each sector)"
            )
        elif extents is None:
            if require and plant.name not in unformatted:
                raise RuntimeError(f"{plant.name} is not on {image.name}")
            extents, status, alive = (), "GONE", 0
            note = note or "not found on the medium"
        else:
            holes = len(plant.data) - sum(length for _at, length in extents)
            status, alive = status_of(extents, len(plant.data) - holes, [])
            if holes:
                note = (note + "; " if note else "") + (
                    f"sparse: {holes} bytes of zero blocks were stored as holes"
                )
            if len(extents) > 1:
                note = (note + "; " if note else "") + (
                    f"fragmented, {len(extents)} runs"
                )
        objects.append(
            TruthObject(
                name=plant.name,
                format=plant.format,
                role="unformatted" if plant.name in unformatted else "file",
                sha256=digest,
                size=len(plant.data),
                extents=tuple(extents),
                status=status,  # type: ignore[arg-type]
                surviving_bytes=alive,
                deleted=plant.deleted,
                note=note,
                hole_bytes=holes if extents else 0,
            )
        )
    return Truth(
        image=image.name,
        corpus=corpus,
        model=model,
        description=description,
        size_bytes=size,
        filesystem=filesystem,
        cluster_bytes=cluster,
        objects=tuple(objects),
    )


def _mtools(image: Path, *command: str) -> None:
    subprocess.run(
        [command[0], "-i", str(image), *command[1:]],
        check=True,
        capture_output=True,
        env={"MTOOLS_SKIP_CHECK": "1", "PATH": "/usr/bin:/bin"},
    )


def _build_fat32_media(
    path: Path, size: int, plants: Sequence[Plant], rng: random.Random, stage: Path
) -> tuple[list[Plant], dict[str, str]]:
    """A FAT32 volume with every plant, and one JPEG in exactly two runs.

    The split is made the way a real volume makes one: two 64 KiB pad files are
    written, the first is deleted, and the JPEG - larger than the hole - is
    written with the free-cluster hint cleared, so FAT puts its head in the hole
    and its tail after the live second pad. That is the case Sanctum's bifragment
    reassembly exists for, and the manifest checks it is exactly two runs.
    """
    from testkit.fsimage import _fat32_forget_free_hint
    from testkit.generate_corpus import make_jpeg

    with open(path, "wb") as handle:
        handle.truncate(size)
    subprocess.run(
        ["mkfs.vfat", "-F", "32", "-n", "SANCTUM", str(path)],
        check=True,
        capture_output=True,
    )
    stage.mkdir(parents=True, exist_ok=True)
    pad = 64 * KIB
    frag = b""
    for side in range(96, 400, 8):
        frag = make_jpeg(random.Random(side), side)
        if pad + _cluster_bytes(path, "fat32") < len(frag) < 2 * pad:
            break
    extras = [
        Plant("pad-a.bin", "random", rng.randbytes(pad), True),
        Plant("pad-b.bin", "random", rng.randbytes(pad), False),
        Plant("frag.jpg", "JPEG", frag, True),
    ]

    def put(plant: Plant) -> None:
        staged = stage / plant.name
        staged.write_bytes(plant.data)
        _mtools(path, "mcopy", str(staged), f"::/{plant.name}")

    put(extras[0])
    put(extras[1])
    _mtools(path, "mdel", "::/pad-a.bin")
    _fat32_forget_free_hint(path)
    put(extras[2])
    for plant in plants:
        put(plant)
    for plant in (*plants, extras[2]):
        if plant.deleted:
            _mtools(path, "mdel", f"::/{plant.name}")
    shutil.rmtree(stage, ignore_errors=True)
    notes = {
        "pad-a.bin": "deleted; its clusters were reused for frag.jpg's head",
        "frag.jpg": "head in pad-a.bin's freed clusters, tail after live pad-b.bin",
    }
    return [*plants, *extras], notes


def build_media(images: Path, payloads: Path, *, seed: int = 0) -> list[Truth]:
    """The benchmark volumes, one per filesystem and proven cluster size."""
    from testkit.fsimage import PlantedFile, build_exfat, build_ext, build_ntfs

    truths: list[Truth] = []
    stage = images / "stage"
    specs = (
        ("media-fat32-255m", "fat32", 255 * MIB),
        ("media-fat32-511m", "fat32", 511 * MIB),
        ("media-exfat-255m", "exfat", 255 * MIB),
        ("media-ntfs-64m", "ntfs", 64 * MIB),
        ("media-ext4-64m", "ext4", 64 * MIB),
    )
    for index, (name, filesystem, size) in enumerate(specs):
        rng = random.Random(seed * 1000 + index)
        plants = media_plants(rng)
        path = images / f"{name}.img"
        notes: dict[str, str] = {}
        unformatted: frozenset[str] = frozenset()
        if filesystem == "fat32":
            plants, notes = _build_fat32_media(path, size, plants, rng, stage)
            unformatted = frozenset({"pad-a.bin", "pad-b.bin"})
        else:
            files = [PlantedFile(p.name, p.data, deleted=p.deleted) for p in plants]
            if filesystem == "exfat":
                build_exfat(
                    path,
                    files,
                    size=size,
                    contiguous=[p.name for p in plants if p.name != "shot.png"],
                )
                notes["shot.png"] = (
                    "stored with a FAT chain, one cluster gap between runs"
                )
            elif filesystem == "ntfs":
                build_ntfs(path, files, size=size, scratch=stage)
            else:
                build_ext(path, files, kind=filesystem, size=size, scratch=stage)
        truth = _truth_from_plants(
            path,
            corpus="media",
            model="delete",
            description=(
                f"{filesystem} volume, {size // MIB} MiB: {len(plants)} files "
                "written, the marked ones deleted"
            ),
            filesystem=filesystem,
            plants=plants,
            payloads=payloads,
            unformatted=unformatted,
            notes=notes,
            require=True,
        )
        if filesystem == "fat32":
            frag = truth.by_name("frag.jpg")
            if len(frag.extents) != 2:
                raise RuntimeError(f"frag.jpg is in {len(frag.extents)} runs, not 2")
        write_truth(truth, images / f"{name}{TRUTH_SUFFIX}")
        truths.append(truth)
    return truths


def build_damage(images: Path, bases: Sequence[Truth], *, seed: int = 0) -> list[Truth]:
    """Every damage model applied to every benchmark volume."""
    truths: list[Truth] = []
    for index, base in enumerate(bases):
        source = images / base.image
        stem = base.image.removesuffix(".img").removeprefix("media-")
        overwrites = interleave_overwrites(random.Random(seed * 1000 + 500 + index))
        made = [
            apply_truncation(base, source, images / f"dmg-truncation-{stem}.img"),
            apply_zeroed_regions(
                base, source, images / f"dmg-zeroed-{stem}.img", seed=seed + index
            ),
            apply_metadata_destruction(
                base, source, images / f"dmg-metadata-{stem}.img"
            ),
            apply_interleaved_overwrite(
                base, source, images / f"dmg-interleave-{stem}.img", overwrites
            ),
        ]
        for truth in made:
            write_truth(
                truth, images / f"{truth.image.removesuffix('.img')}{TRUTH_SUFFIX}"
            )
        truths.extend(made)
    return truths


_FLAT_FORMATS = {
    "jpg": "JPEG",
    "png": "PNG",
    "gif": "GIF",
    "pdf": "PDF",
    "sqlite": "SQLite",
    "mp4": "MP4",
    "docx": "DOCX",
    "docm": "DOCX",
    "xlsx": "XLSX",
    "zip": "ZIP",
}


def _format_of_name(name: str) -> str:
    return _FLAT_FORMATS.get(name.rsplit(".", 1)[-1].lower(), "unknown")


def build_flat(
    images: Path, payloads: Path, work: Path, *, seed: int = 0
) -> list[Truth]:
    """The synthetic carving corpus as it ships, and the same on sector boundaries."""
    from testkit.generate_corpus import FIRST_OFFSET, generate_corpus

    truths: list[Truth] = []
    for label, first in (("flat-offset1337", FIRST_OFFSET), ("flat-aligned", 4096)):
        source = work / label
        manifest = generate_corpus(source, seed=seed, first_offset=first)
        image = images / f"{label}.img"
        shutil.copyfile(source / manifest.image, image)
        medium = image.read_bytes()
        objects = []
        for item in manifest.objects:
            data = medium[item.offset : item.offset + item.length]
            truncated = item.kind == "truncated"
            _store(payloads, data)
            objects.append(
                TruthObject(
                    name=f"{item.name}@{item.offset}",
                    format=_format_of_name(item.name),
                    role="decoy" if item.kind == "decoy" else "file",
                    sha256="" if truncated else item.sha256,
                    # A truncated plant's original never existed on the medium;
                    # its size is what was written, and it is PARTIAL by fiat.
                    size=item.length,
                    extents=((item.offset, item.length),),
                    status="PARTIAL" if truncated else "FULL",
                    surviving_bytes=item.length,
                    note=(
                        "planted with its tail already removed"
                        if truncated
                        else "a header on bytes of another kind"
                        if item.kind == "decoy"
                        else "duplicate content of another plant"
                        if item.kind == "duplicate"
                        else ""
                    ),
                )
            )
        truth = Truth(
            image=image.name,
            corpus="flat",
            model="none",
            description=(
                f"synthetic canvas, seed {seed}, first object at byte {first}, "
                "pseudo-random filler between objects"
            ),
            size_bytes=len(medium),
            filesystem="none",
            cluster_bytes=512,
            parameters={"first_offset": first},
            objects=tuple(objects),
        )
        write_truth(truth, images / f"{label}{TRUTH_SUFFIX}")
        truths.append(truth)
    return truths


#: Damaged images in the filesystem corpus, and the image each was copied from.
_FS_DAMAGED_BASE = {
    "damaged-boot.img": ("ntfs.img", "boot_sector_zeroed"),
    "damaged-parttable.img": ("two-partitions.img", "partition_table_garbage"),
    "quick-formatted.img": ("fat32-plain.img", "quick_format"),
}


def build_filesystem(
    images: Path, payloads: Path, work: Path, *, seed: int = 0
) -> list[Truth]:
    """The existing filesystem corpus, with each file found on its medium."""
    from testkit.generate_corpus import generate_filesystem_corpus

    source = work / "fs"
    corpus = generate_filesystem_corpus(source, seed=seed, payload_dir=payloads)
    truths: list[Truth] = []
    for name in corpus.images:
        base, model = _FS_DAMAGED_BASE.get(name, (name, "delete"))
        rows = [row for row in corpus.files if row.image == base]
        filesystems = sorted({row.filesystem for row in rows})
        filesystem = filesystems[0] if len(filesystems) == 1 else "+".join(filesystems)
        target = images / f"fs-{name}"
        shutil.copyfile(source / name, target)
        plants = [
            Plant(
                row.name,
                "filler"
                if row.name.endswith(".pad")
                else "random"
                if row.name.endswith(".bin")
                else _format_of_name(row.name),
                (payloads / row.sha256).read_bytes(),
                row.deleted,
            )
            for row in rows
        ]
        unformatted = frozenset(
            plant.name for plant in plants if plant.format in ("filler", "random")
        )
        truth = _truth_from_plants(
            target,
            corpus="filesystem",
            model=model,
            description=corpus.damaged.get(
                name, f"{filesystem} image from generate_filesystem_corpus"
            ),
            filesystem=filesystem if "+" not in filesystem else "none",
            plants=plants,
            payloads=payloads,
            unformatted=unformatted,
            require=False,
        )
        truth = Truth(
            **{
                **asdict(truth),
                "objects": truth.objects,
                "base_image": f"fs-{base}" if base != name else "",
                "filesystem": filesystem,
            }
        )
        write_truth(truth, images / f"fs-{name.removesuffix('.img')}{TRUTH_SUFFIX}")
        truths.append(truth)
    return truths


def build(work: Path, *, seed: int = 0) -> list[Truth]:
    images = work / "images"
    payloads = work / "payloads"
    images.mkdir(parents=True, exist_ok=True)
    truths = build_flat(images, payloads, work / "src", seed=seed)
    truths += build_filesystem(images, payloads, work / "src", seed=seed)
    media = build_media(images, payloads, seed=seed)
    truths += media
    truths += build_damage(images, media, seed=seed)
    return truths


# --------------------------------------------------------------------------
# Running the tools
# --------------------------------------------------------------------------


def _first_line(argv: Sequence[str]) -> str:
    try:
        done = subprocess.run(list(argv), capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"unavailable: {exc}"
    lines = [line for line in (done.stdout + done.stderr).splitlines() if line.strip()]
    return lines[0].strip() if lines else ""


def tool_versions(foremost: str) -> dict[str, dict[str, str]]:
    """Name and version of every tool, and how each was obtained."""
    describe = _first_line(
        ["git", "-C", str(REPO), "describe", "--tags", "--always", "--dirty"]
    )
    sha = _first_line(["git", "-C", str(REPO), "rev-parse", "HEAD"])
    photorec = shutil.which("photorec") or ""
    return {
        "sanctum": {"version": describe, "commit": sha, "path": str(REPO)},
        "photorec": {
            "version": _first_line(["photorec", "/version"]) if photorec else "absent",
            "package": _first_line(["rpm", "-qf", photorec]) if photorec else "",
            "path": photorec,
        },
        "foremost": {
            "version": _first_line([foremost, "-V"])
            if shutil.which(foremost)
            else "absent",
            "package": _first_line(["rpm", "-qf", shutil.which(foremost) or foremost]),
            "path": shutil.which(foremost) or foremost,
        },
    }


def _sanctum_worker(image: Path, run_dir: Path, undelete: bool) -> None:
    """Run the product's carve pipeline with its defaults, and record what it wrote."""
    from api.carve_job import carve_generator

    out_dir = run_dir / "files" / "sanctum"
    generator = carve_generator(
        image, undelete=undelete, out_dir=out_dir, job_id="bench"
    )
    while True:
        try:
            next(generator)
        except StopIteration as finished:
            result = finished.value
            break
    candidates = result["candidates"]
    from core.carve.classify import output_filename
    from core.models import CarveCandidate

    written = []
    for raw in candidates:
        candidate = CarveCandidate.model_validate(raw)
        written.append(
            {
                "file": output_filename(candidate),
                "bucket": candidate.bucket,
                "source": candidate.source,
                "validation": candidate.validation,
                "reassembled": bool(candidate.fragments),
            }
        )
    (run_dir / "sanctum-result.json").write_text(
        json.dumps(
            {
                "candidates": len(candidates),
                "written": len(result["written"]),
                "objects": written,
            },
            indent=1,
        ),
        encoding="utf-8",
    )


def run_tool(
    tool: str,
    image: Path,
    run_dir: Path,
    *,
    foremost: str,
    timeout: int,
    keep_outputs: bool = False,
) -> dict[str, Any]:
    """Run one tool over one image with default settings, timed from outside."""
    if run_dir.exists():
        shutil.rmtree(run_dir)
    files = run_dir / "files"
    files.mkdir(parents=True)
    if tool in ("sanctum-carve", "sanctum-full"):
        argv = [
            sys.executable,
            "-m",
            "testkit.benchmark",
            "sanctum-worker",
            str(image),
            str(run_dir),
        ]
        if tool == "sanctum-carve":
            argv.append("--no-undelete")
        cwd = REPO
    elif tool == "photorec":
        argv = [
            "photorec",
            "/log",
            "/d",
            str(files / "recup"),
            "/cmd",
            str(image),
            PHOTOREC_OPTIONS,
        ]
        cwd = run_dir
    elif tool == "foremost":
        argv = [foremost, "-i", str(image), "-o", str(files / "foremost")]
        cwd = run_dir
    else:
        raise ValueError(tool)
    log = run_dir / "tool.log"
    started = time.perf_counter()
    timed_out = False
    with open(log, "wb") as sink:
        try:
            done = subprocess.run(
                argv,
                cwd=cwd,
                stdout=sink,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                timeout=timeout,
            )
            returncode = done.returncode
        except subprocess.TimeoutExpired:
            timed_out, returncode = True, -1
    seconds = time.perf_counter() - started
    meta = {
        "tool": tool,
        "image": image.name,
        "argv": argv,
        "seconds": round(seconds, 3),
        "returncode": returncode,
        "timed_out": timed_out,
    }
    # Indexed after the clock stopped: hashing is the scorer's cost, not the tool's.
    entries = index_outputs(files)
    (run_dir / OUTPUT_INDEX).write_text(json.dumps(entries), encoding="utf-8")
    meta["output_files"] = len(entries)
    meta["output_bytes"] = sum(int(entry["size"]) for entry in entries)
    (run_dir / "meta.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    if not keep_outputs:
        shutil.rmtree(files)
    return meta


def run(
    work: Path,
    *,
    tools: Sequence[str] = TOOLS,
    only: Sequence[str] = (),
    foremost: str = "foremost",
    timeout: int = 3600,
    keep_outputs: bool = False,
) -> None:
    images = work / "images"
    versions = tool_versions(foremost)
    (work / "versions.json").write_text(
        json.dumps(versions, indent=1), encoding="utf-8"
    )
    for truth_path in sorted(images.glob(f"*{TRUTH_SUFFIX}")):
        stem = truth_path.name.removesuffix(TRUTH_SUFFIX)
        if only and stem not in only:
            continue
        image = images / f"{stem}.img"
        for tool in tools:
            if tool == "foremost" and versions["foremost"]["version"] == "absent":
                continue
            if tool == "photorec" and versions["photorec"]["version"] == "absent":
                continue
            meta = run_tool(
                tool,
                image,
                work / "runs" / stem / tool,
                foremost=foremost,
                timeout=timeout,
                keep_outputs=keep_outputs,
            )
            print(  # noqa: T201 - a CLI's progress line
                f"{stem:<34} {tool:<14} {meta['seconds']:>8.2f}s "
                f"rc={meta['returncode']}",
                flush=True,
            )


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------


@dataclass
class RunScore:
    """One tool on one image, against that image's ground truth."""

    image: str
    corpus: str
    model: str
    tool: str
    #: FULL formatted objects, counted once per distinct content.
    full: int = 0
    exact: int = 0
    corrupt: int = 0
    missed: int = 0
    partial: int = 0
    partial_returned: int = 0
    #: PARTIAL on the raw medium, yet returned byte-identical: only possible
    #: through filesystem metadata, such as a resident NTFS file read with its
    #: fixups applied.
    partial_exact: int = 0
    gone: int = 0
    gone_returned: int = 0
    unformatted_full: int = 0
    unformatted_exact: int = 0
    outputs: int = 0
    duplicate_outputs: int = 0
    fp_fragment: int = 0
    fp_decoy: int = 0
    fp_ambiguous: int = 0
    fp_unrelated: int = 0
    seconds: float = 0.0
    returncode: int = 0
    timed_out: bool = False
    #: ``{format: {"full", "exact", "corrupt", "missed"}}``.
    formats: dict[str, dict[str, int]] = field(default_factory=dict)
    #: ``{object name: exact | corrupt | missed | returned | not_returned}``.
    outcomes: dict[str, str] = field(default_factory=dict)

    @property
    def fp_total(self) -> int:
        return self.fp_fragment + self.fp_decoy + self.fp_ambiguous + self.fp_unrelated

    @property
    def recovered(self) -> int:
        return self.exact + self.corrupt


#: Kept under its old name for callers of the private helper.
_agreement = common_prefix


def _reference(obj: TruthObject, medium: bytes | None, payloads: Path) -> bytes:
    if obj.sha256 and (payloads / obj.sha256).exists():
        return (payloads / obj.sha256).read_bytes()
    if medium is None:
        return b""
    return b"".join(medium[offset : offset + length] for offset, length in obj.extents)


def score_run(
    truth: Truth,
    files: Path,
    payloads: Path,
    *,
    tool: str,
    image_path: Path | None = None,
    only: set[str] | None = None,
) -> RunScore:
    """Score a tool's outputs against ``truth``. The same for every tool.

    ``files`` is the output directory, or the :data:`OUTPUT_INDEX` written from
    it; both give the same score.
    """
    medium = image_path.read_bytes() if image_path is not None else None
    result = RunScore(
        image=truth.image, corpus=truth.corpus, model=truth.model, tool=tool
    )

    references = {obj.name: _reference(obj, medium, payloads) for obj in truth.objects}
    outputs = select_outputs(load_outputs(files), only)
    result.outputs = len(outputs)
    attribution = attribute_outputs(truth.objects, references, outputs)
    exact, corrupt = attribution.exact, attribution.corrupt
    result.duplicate_outputs = attribution.duplicate_outputs
    result.fp_fragment = attribution.count("fp_fragment")
    result.fp_decoy = attribution.count("fp_decoy")
    result.fp_ambiguous = attribution.count("fp_ambiguous")
    result.fp_unrelated = attribution.count("fp_unrelated")

    groups: dict[str, list[TruthObject]] = {}
    for obj in truth.objects:
        if obj.role != "decoy":
            groups.setdefault(obj.sha256 or obj.name, []).append(obj)
    for members in groups.values():
        lead = min(members, key=lambda obj: _SEVERITY_ORDER[obj.status])
        names = {obj.name for obj in members}
        hit_exact = bool(names & exact)
        hit_any = hit_exact or bool(names & corrupt)
        if lead.role == "unformatted":
            if lead.status == "FULL":
                result.unformatted_full += 1
                result.unformatted_exact += int(hit_exact)
            continue
        if lead.status == "FULL":
            result.full += 1
            outcome = "exact" if hit_exact else "corrupt" if hit_any else "missed"
            setattr(result, outcome, getattr(result, outcome) + 1)
            row = result.formats.setdefault(
                lead.format, {"full": 0, "exact": 0, "corrupt": 0, "missed": 0}
            )
            row["full"] += 1
            row[outcome] += 1
        elif lead.status == "PARTIAL":
            result.partial += 1
            result.partial_returned += int(hit_any)
            result.partial_exact += int(hit_exact)
            outcome = "returned" if hit_any else "not_returned"
        else:
            result.gone += 1
            result.gone_returned += int(hit_any)
            outcome = "returned" if hit_any else "not_returned"
        for obj in members:
            result.outcomes[obj.name] = outcome
    return result


_SEVERITY_ORDER = {"FULL": 0, "PARTIAL": 1, "GONE": 2}


def score(work: Path) -> list[RunScore]:
    images = work / "images"
    payloads = work / "payloads"
    scores: list[RunScore] = []
    for truth_path in sorted(images.glob(f"*{TRUTH_SUFFIX}")):
        truth = load_truth(truth_path)
        stem = truth_path.name.removesuffix(TRUTH_SUFFIX)
        image_path = images / f"{stem}.img"
        for tool in TOOLS:
            run_dir = work / "runs" / stem / tool
            if not (run_dir / "meta.json").exists():
                continue
            meta = json.loads((run_dir / "meta.json").read_text(encoding="utf-8"))
            source = (
                run_dir / OUTPUT_INDEX
                if (run_dir / OUTPUT_INDEX).exists()
                else run_dir / "files"
            )
            result = score_run(
                truth, source, payloads, tool=tool, image_path=image_path
            )
            result.seconds = float(meta["seconds"])
            result.returncode = int(meta["returncode"])
            result.timed_out = bool(meta["timed_out"])
            scores.append(result)
            if (
                tool.startswith("sanctum")
                and (run_dir / "sanctum-result.json").exists()
            ):
                detail = json.loads((run_dir / "sanctum-result.json").read_text())
                confident = {
                    item["file"]
                    for item in detail["objects"]
                    if item["bucket"] in ("HIGH", "MEDIUM")
                }
                filtered = score_run(
                    truth,
                    source,
                    payloads,
                    tool=f"{tool}@HIGH+MEDIUM",
                    image_path=image_path,
                    only=confident,
                )
                filtered.seconds = result.seconds
                scores.append(filtered)
    serialised = [
        {**asdict(item), "fp_total": item.fp_total, "recovered": item.recovered}
        for item in scores
    ]
    (work / "scores.json").write_text(
        json.dumps(serialised, indent=1), encoding="utf-8"
    )
    return scores


CSV_COLUMNS = (
    "corpus",
    "model",
    "image",
    "tool",
    "full",
    "recovered",
    "exact",
    "corrupt",
    "missed",
    "partial",
    "partial_returned",
    "partial_exact",
    "gone",
    "gone_returned",
    "unformatted_full",
    "unformatted_exact",
    "outputs",
    "duplicate_outputs",
    "fp_total",
    "fp_fragment",
    "fp_decoy",
    "fp_ambiguous",
    "fp_unrelated",
    "seconds",
    "returncode",
    "timed_out",
)


def write_csv(scores: Sequence[RunScore], path: Path) -> Path:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=list(CSV_COLUMNS), lineterminator="\n"
        )
        writer.writeheader()
        for item in scores:
            row = {
                **asdict(item),
                "fp_total": item.fp_total,
                "recovered": item.recovered,
            }
            writer.writerow({key: row[key] for key in CSV_COLUMNS})
    return path


# --------------------------------------------------------------------------
# Report tables
# --------------------------------------------------------------------------

_SUMMED = (
    "full",
    "exact",
    "corrupt",
    "missed",
    "partial",
    "partial_returned",
    "partial_exact",
    "gone",
    "gone_returned",
    "unformatted_full",
    "unformatted_exact",
    "outputs",
    "duplicate_outputs",
    "fp_fragment",
    "fp_decoy",
    "fp_ambiguous",
    "fp_unrelated",
    "seconds",
)

LABELS = {
    "sanctum-carve": "Sanctum, carve only",
    "photorec": "PhotoRec",
    "foremost": "Foremost",
    "sanctum-full": "Sanctum, undelete + carve",
    "sanctum-carve@HIGH+MEDIUM": "Sanctum carve, HIGH+MEDIUM only",
    "sanctum-full@HIGH+MEDIUM": "Sanctum full, HIGH+MEDIUM only",
}

REPORT_GROUPS: tuple[tuple[str, str], ...] = (
    ("flat-offset1337", "Flat corpus as shipped (objects at byte 1337 + k x 512 KiB)"),
    (
        "flat-aligned",
        "Flat corpus, sector-aligned (objects at byte 4096 + k x 512 KiB)",
    ),
    ("filesystem", "Filesystem corpus (13 images, generate_filesystem_corpus)"),
    ("media", "Benchmark volumes, files written then some deleted (5 volumes)"),
    ("truncation", "Damage model: truncation (5 volumes)"),
    ("zeroed_regions", "Damage model: zeroed regions (5 volumes)"),
    ("metadata_destroyed", "Damage model: filesystem metadata destroyed (5 volumes)"),
    ("interleaved_overwrite", "Damage model: interleaved overwrite (5 volumes)"),
)

_HEADER = (
    "| Row | FULL files | Byte-identical | Corrupt | Missed | Identical / FULL "
    "| PARTIAL returned | GONE returned | False positives (frag/decoy/amb/unrel) "
    "| Outputs | Time (s) |"
)
_RULE = "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"


def _group_of(item: dict[str, Any]) -> str:
    if item["corpus"] == "flat":
        return str(item["image"]).removesuffix(".img")
    if item["corpus"] == "filesystem":
        return "filesystem"
    return "media" if item["model"] == "delete" else str(item["model"])


def _sum(rows: Sequence[dict[str, Any]]) -> dict[str, float]:
    return {key: sum(float(row[key]) for row in rows) for key in _SUMMED}


def _table_row(label: str, total: dict[str, float]) -> str:
    full, exact = int(total["full"]), int(total["exact"])
    share = f"{100 * exact / full:.1f}%" if full else "-"
    partial = f"{int(total['partial_returned'])}/{int(total['partial'])}"
    if total["partial_exact"]:
        partial += f" ({int(total['partial_exact'])} identical)"
    fps = [
        int(total[key])
        for key in ("fp_fragment", "fp_decoy", "fp_ambiguous", "fp_unrelated")
    ]
    return (
        f"| {label} | {full} | **{exact}** | {int(total['corrupt'])} "
        f"| {int(total['missed'])} | {share} | {partial} "
        f"| {int(total['gone_returned'])}/{int(total['gone'])} "
        f"| {sum(fps)} ({'/'.join(str(n) for n in fps)}) | {int(total['outputs'])} "
        f"| {total['seconds']:.1f} |"
    )


def _signature_formats(work: Path) -> dict[str, bool]:
    """Whether each planted format's header is in Sanctum's signature table."""
    import yaml

    table = yaml.safe_load((REPO / "testkit" / "signatures.yaml").read_text())
    entries = [
        (bytes.fromhex(item["header"]), int(item.get("header_offset", 0)))
        for item in table["signatures"]
    ]
    # Enough bytes for the deepest header in the table, not a fixed 64. A tar's
    # "ustar" magic sits at byte 257 of its first member header, so a 64-byte
    # read reported every signature past that offset as absent - which would
    # print "no" in the column that says which formats Sanctum can find.
    probe_bytes = max(offset + len(magic) for magic, offset in entries)
    found: dict[str, bool] = {}
    for path in sorted((work / "images").glob(f"media-*{TRUTH_SUFFIX}")):
        for obj in load_truth(path).objects:
            if obj.role != "file" or obj.format in found:
                continue
            head = (work / "payloads" / obj.sha256).read_bytes()[:probe_bytes]
            found[obj.format] = any(
                head[offset : offset + len(magic)] == magic for magic, offset in entries
            )
    return found


def format_report(work: Path) -> str:
    """Every table the performance evaluation quotes, from ``scores.json``."""
    scores: list[dict[str, Any]] = json.loads(
        (work / "scores.json").read_text(encoding="utf-8")
    )
    lines: list[str] = []
    for key, title in REPORT_GROUPS:
        rows = [item for item in scores if _group_of(item) == key]
        if not rows:
            continue
        images = sorted({str(item["image"]) for item in rows})
        lines += [f"#### {title}", "", "Images: " + ", ".join(f"`{i}`" for i in images)]
        lines += ["", _HEADER, _RULE]
        for tool in COMPARABLE:
            chosen = [item for item in rows if item["tool"] == tool]
            if chosen:
                lines.append(_table_row(LABELS[tool], _sum(chosen)))
        full = [item for item in rows if item["tool"] == "sanctum-full"]
        if full:
            lines.append("| *not a carver's peer:* | | | | | | | | | | |")
            lines.append(_table_row(LABELS["sanctum-full"], _sum(full)))
        failed = [
            f"`{item['tool']}` on `{item['image']}` (exit {item['returncode']}"
            + (", timed out" if item["timed_out"] else "")
            + ")"
            for item in rows
            if "@" not in str(item["tool"])
            and (item["returncode"] != 0 or item["timed_out"])
        ]
        if failed:
            lines += ["", "Runs that did not exit 0: " + "; ".join(failed) + "."]
        lines.append("")

    signature = _signature_formats(work)
    lines += [
        "#### By format: benchmark volumes and every damage model (25 images)",
        "",
        "Cells are byte-identical / corrupt, over FULL objects of that format.",
        "",
        "| Format | Header in Sanctum's table | FULL | Sanctum carve | PhotoRec "
        "| Foremost | Sanctum full |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    formats: dict[str, dict[str, list[int]]] = {}
    for item in scores:
        if item["corpus"] != "media" or "@" in str(item["tool"]):
            continue
        for fmt, counts in item["formats"].items():
            cell = formats.setdefault(fmt, {}).setdefault(str(item["tool"]), [0, 0, 0])
            cell[0] += counts["full"]
            cell[1] += counts["exact"]
            cell[2] += counts["corrupt"]
    for fmt in sorted(formats, key=lambda name: (not signature.get(name, False), name)):
        cells = formats[fmt]
        planted = max(cell[0] for cell in cells.values())
        rendered = [
            f"{cells[tool][1]}/{cells[tool][2]}" if tool in cells else "-"
            for tool in ("sanctum-carve", "photorec", "foremost", "sanctum-full")
        ]
        lines.append(
            f"| {fmt} | {'yes' if signature.get(fmt) else 'no'} | {planted} | "
            + " | ".join(rendered)
            + " |"
        )
    lines.append("")

    lines += [
        "#### Object by object: who returned a FULL file byte-identical",
        "",
        "| Pair | Both | Only Sanctum carve | Only the other tool | Neither |",
        "|---|---:|---:|---:|---:|",
    ]
    outcome: dict[tuple[str, str, str], str] = {}
    for item in scores:
        for name, result in item["outcomes"].items():
            if result in ("exact", "corrupt", "missed"):
                outcome[(str(item["tool"]), str(item["image"]), name)] = result
    keys = {(image, name) for (_tool, image, name) in outcome}
    wins: dict[str, dict[str, list[str]]] = {}
    for other in ("photorec", "foremost"):
        tally = {"both": 0, "mine": 0, "theirs": 0, "neither": 0}
        for image, name in keys:
            mine = outcome.get(("sanctum-carve", image, name)) == "exact"
            theirs = outcome.get((other, image, name)) == "exact"
            if (other, image, name) not in outcome:
                continue
            slot = (
                "both"
                if mine and theirs
                else "mine"
                if mine
                else ("theirs" if theirs else "neither")
            )
            tally[slot] += 1
            if slot in ("mine", "theirs"):
                wins.setdefault(other, {}).setdefault(slot, []).append(
                    f"{image}:{name}"
                )
        lines.append(
            f"| Sanctum carve vs {LABELS[other]} | {tally['both']} | {tally['mine']} "
            f"| {tally['theirs']} | {tally['neither']} |"
        )
    lines.append("")
    for other, sides in wins.items():
        for side, items in sides.items():
            who = "Sanctum carve only" if side == "mine" else f"{LABELS[other]} only"
            lines.append(
                f"<details><summary>{who} (Sanctum carve vs {LABELS[other]}): "
                f"{len(items)} "
                "objects</summary>\n\n"
                + ", ".join(f"`{entry}`" for entry in sorted(items))
                + "\n\n</details>\n"
            )

    lines += [
        "#### Supplementary, not comparable: Sanctum HIGH and MEDIUM only",
        "",
        _HEADER,
        _RULE,
    ]
    for tool in ("sanctum-carve@HIGH+MEDIUM", "sanctum-full@HIGH+MEDIUM"):
        chosen = [item for item in scores if item["tool"] == tool]
        if chosen:
            lines.append(_table_row(LABELS[tool] + " (all 40 images)", _sum(chosen)))
    lines.append("")

    lines += [
        "#### Every run",
        "",
        "| Image | Row | FULL | Identical | Corrupt | Missed | PARTIAL ret. "
        "| FP | Outputs | Time (s) | Exit |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in sorted(
        scores,
        key=lambda row: (
            row["image"],
            TOOLS.index(str(row["tool"]).split("@")[0]),
            row["tool"],
        ),
    ):
        if "@" in str(item["tool"]):
            continue
        fps = sum(
            int(item[key])
            for key in ("fp_fragment", "fp_decoy", "fp_ambiguous", "fp_unrelated")
        )
        lines.append(
            f"| `{item['image']}` | {LABELS[str(item['tool'])]} | {item['full']} "
            f"| {item['exact']} | {item['corrupt']} | {item['missed']} "
            f"| {item['partial_returned']}/{item['partial']} | {fps} "
            f"| {item['outputs']} | {float(item['seconds']):.2f} "
            f"| {item['returncode']}{' (timeout)' if item['timed_out'] else ''} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    build_cmd = sub.add_parser("build")
    build_cmd.add_argument("--work", type=Path, required=True)
    build_cmd.add_argument("--seed", type=int, default=0)
    run_cmd = sub.add_parser("run")
    run_cmd.add_argument("--work", type=Path, required=True)
    run_cmd.add_argument("--tool", action="append", choices=TOOLS)
    run_cmd.add_argument("--image", action="append", default=[])
    run_cmd.add_argument("--foremost", default="foremost")
    run_cmd.add_argument("--timeout", type=int, default=3600)
    run_cmd.add_argument("--keep-outputs", action="store_true")
    score_cmd = sub.add_parser("score")
    score_cmd.add_argument("--work", type=Path, required=True)
    score_cmd.add_argument("--csv", type=Path)
    report_cmd = sub.add_parser("report")
    report_cmd.add_argument("--work", type=Path, required=True)
    report_cmd.add_argument("--out", type=Path, required=True)
    worker = sub.add_parser("sanctum-worker")
    worker.add_argument("image", type=Path)
    worker.add_argument("run_dir", type=Path)
    worker.add_argument("--no-undelete", action="store_true")
    args = parser.parse_args(argv)

    if args.command == "build":
        truths = build(args.work, seed=args.seed)
        for truth in truths:
            counts = truth.counts()
            print(  # noqa: T201 - a CLI
                f"{truth.image:<34} {truth.model:<24} FULL {counts['FULL']:>3} "
                f"PARTIAL {counts['PARTIAL']:>3} GONE {counts['GONE']:>3}"
            )
    elif args.command == "run":
        run(
            args.work,
            tools=args.tool or TOOLS,
            only=args.image,
            foremost=args.foremost,
            timeout=args.timeout,
            keep_outputs=args.keep_outputs,
        )
    elif args.command == "score":
        scores = score(args.work)
        if args.csv:
            write_csv([item for item in scores if "@" not in item.tool], args.csv)
        print(f"scored {len(scores)} runs")  # noqa: T201 - a CLI
    elif args.command == "report":
        args.out.write_text(format_report(args.work), encoding="utf-8")
        print(f"wrote {args.out}")  # noqa: T201 - a CLI
    else:
        _sanctum_worker(args.image, args.run_dir, undelete=not args.no_undelete)


if __name__ == "__main__":
    main()
