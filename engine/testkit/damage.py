"""Damage models for the recovery benchmark, and the ground truth each one leaves.

Every image the corpus builders make is intact, then deleted from or quick
formatted. Damaged media are a different problem: bytes are *gone*, and a
recall figure that still counts a file whose sectors no longer exist is
measuring the damage, not the tool. So each model here rewrites a copy of an
image and re-derives, for every planted object, how much of it is still on the
medium:

``FULL``
    Every byte of the object as planted is still where it was written. Only
    these can come back byte-identical, and only these are in a recall
    denominator.
``PARTIAL``
    Some of its bytes survive and some do not. A tool can return something for
    it, but never the original file.
``GONE``
    None of its bytes survive. Anything a tool returns for it was not recovered
    from this medium.

The status is computed, never declared. A planted object's **extents** - where
its bytes lie on the medium, in object order - are found by searching the
medium for the planted bytes (:func:`locate`), and a model records the byte
ranges it destroyed. Status is the overlap between the two. If a model's
ranges happen to hit a file nobody meant to hit, the manifest says so.

Four models:

* **truncation** - the image ends early, as an acquisition that died does.
* **zeroed regions** - bands of zeros, which is how a failing drive's
  unreadable sectors look after imaging with a tool that zero-fills them.
* **metadata destroyed** - the boot sector, FAT copies, MFT, superblocks and
  inode tables are zeroed while file data is untouched: the case undelete
  cannot help with and carving must.
* **interleaved overwrite** - a later file written partly over an earlier one,
  over its head as first-fit cluster reuse does, or over its tail.

Nothing here opens a device. Every model writes a copy of an image file.
"""

from __future__ import annotations

import hashlib
import json
import mmap
import os
import random
import struct
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Literal

from testkit.fsimage import (
    _apply_fixups,
    _decode_runs,
    _iter_attributes,
    _ntfs_geometry,
    sparse_copy,
)

__all__ = [
    "Status",
    "Role",
    "TruthObject",
    "Truth",
    "Overwrite",
    "TRUTH_SUFFIX",
    "locate",
    "status_of",
    "write_truth",
    "load_truth",
    "rederive",
    "planted_span",
    "metadata_ranges",
    "apply_truncation",
    "apply_zeroed_regions",
    "apply_metadata_destruction",
    "apply_interleaved_overwrite",
]

KIB = 1024
MIB = 1024 * KIB
SECTOR = 512

#: Suffix of the ground-truth manifest written beside each image.
TRUTH_SUFFIX = ".truth.json"

Status = Literal["FULL", "PARTIAL", "GONE"]
#: ``file`` is a planted object with a real format. ``unformatted`` is planted
#: content with no format at all - fillers and random bytes - which no carver
#: can find by signature and which is kept out of carving denominators.
#: ``decoy`` is a valid header on bytes of another kind: never a recovery.
Role = Literal["file", "unformatted", "decoy"]

_SEVERITY: dict[str, int] = {"FULL": 0, "PARTIAL": 1, "GONE": 2}

Range = tuple[int, int]


@dataclass(frozen=True)
class TruthObject:
    """One planted object and what the medium still holds of it."""

    name: str
    #: Format label, e.g. ``JPEG``; ``filler`` or ``random`` for unformatted.
    format: str
    role: Role
    #: SHA-256 of the object as planted. Empty when the whole object never
    #: existed on the medium (a plant written with its tail already removed).
    sha256: str
    #: Bytes as planted.
    size: int
    #: ``(offset, length)`` runs holding the planted bytes, in object order.
    extents: tuple[Range, ...]
    status: Status
    #: Bytes of the extents that no damage range covers.
    surviving_bytes: int
    deleted: bool = False
    note: str = ""
    #: Bytes of all-zero blocks the filesystem stored as holes. They were never
    #: on the medium, so they are not in ``extents`` and cannot be damaged.
    hole_bytes: int = 0

    @property
    def fragmented(self) -> bool:
        return len(self.extents) > 1


@dataclass(frozen=True)
class Truth:
    """Ground truth for one image: what was planted, what damage did to it."""

    image: str
    #: Which corpus the image belongs to, for grouping result tables.
    corpus: str
    #: ``none``, ``delete``, ``quick_format``, or a model name from this module.
    model: str
    description: str
    size_bytes: int
    filesystem: str
    #: Cluster size of the volume, or 512 where there is no filesystem.
    cluster_bytes: int
    base_image: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    #: ``(offset, length, what)`` for every range the model destroyed.
    damaged: tuple[tuple[int, int, str], ...] = ()
    objects: tuple[TruthObject, ...] = ()

    def counts(self, role: Role = "file") -> dict[str, int]:
        """Objects of ``role`` by status."""
        tally = {"FULL": 0, "PARTIAL": 0, "GONE": 0}
        for item in self.objects:
            if item.role == role:
                tally[item.status] += 1
        return tally

    def by_name(self, name: str) -> TruthObject:
        for item in self.objects:
            if item.name == name:
                return item
        raise KeyError(name)


@dataclass(frozen=True)
class Overwrite:
    """A later file written over part of an earlier one."""

    victim: str
    name: str
    format: str
    data: bytes
    #: Where in the victim the later file starts: 0 is its first cluster.
    start_fraction: float


# --------------------------------------------------------------------------
# Ranges and status
# --------------------------------------------------------------------------


def _merge(ranges: Iterable[Range]) -> list[Range]:
    merged: list[list[int]] = []
    for offset, length in sorted(ranges):
        if length <= 0:
            continue
        if merged and offset <= merged[-1][0] + merged[-1][1]:
            end = max(merged[-1][0] + merged[-1][1], offset + length)
            merged[-1][1] = end - merged[-1][0]
        else:
            merged.append([offset, length])
    return [(offset, length) for offset, length in merged]


def _covered(extent: Range, damaged: Sequence[Range]) -> int:
    start, end = extent[0], extent[0] + extent[1]
    total = 0
    for offset, length in damaged:
        low, high = max(start, offset), min(end, offset + length)
        if high > low:
            total += high - low
    return total


def status_of(
    extents: Sequence[Range], size: int, damaged: Iterable[Range]
) -> tuple[Status, int]:
    """Status and surviving bytes of an object of ``size`` bytes at ``extents``."""
    ranges = _merge(damaged)
    present = sum(length for _offset, length in extents)
    alive = present - sum(_covered(extent, ranges) for extent in extents)
    if alive <= 0:
        return "GONE", 0
    if alive >= size:
        return "FULL", alive
    return "PARTIAL", alive


def _align_down(value: int, grid: int) -> int:
    return value - value % grid


def _align_up(value: int, grid: int) -> int:
    return -(-value // grid) * grid


# --------------------------------------------------------------------------
# Finding planted bytes on the medium
# --------------------------------------------------------------------------


def _match_length(
    medium: bytes | mmap.mmap, at: int, data: bytes, position: int, grid: int
) -> int:
    matched = 0
    while position + matched < len(data):
        step = min(grid, len(data) - position - matched)
        start = at + matched
        expected = data[position + matched : position + matched + step]
        if medium[start : start + step] != expected:
            break
        matched += step
    return matched


def locate(
    medium: bytes | mmap.mmap,
    data: bytes,
    *,
    grid: int = SECTOR,
    max_probes: int = 256,
    holes: bool = False,
) -> tuple[Range, ...] | None:
    """Where ``data`` lies on ``medium``, or None if it is not there.

    A contiguous copy anywhere is one run, preferring one on ``grid``. Otherwise
    the object is assumed to be laid out in runs on ``grid``, which is how every
    allocator stores a fragmented file, and each run is found in turn by its
    first ``grid`` bytes and extended as far as the bytes keep matching. Only
    the first ``max_probes`` occurrences of a probe are tried, so a run of a
    very common block (all zeros) can fail to be placed; that returns None
    rather than a guess.

    ``holes`` allows all-zero blocks that are nowhere near the runs around them
    to be absent: a sparse file, which ``debugfs write`` produces for any block
    of zeros. The bytes not covered by the returned runs are then those holes.
    """
    if not data:
        return ()
    hit = medium.find(data)
    if hit != -1:
        aligned, probes = hit, 0
        while aligned != -1 and aligned % grid and probes < max_probes:
            aligned = medium.find(data, aligned + 1)
            probes += 1
        chosen = aligned if aligned != -1 and aligned % grid == 0 else hit
        return ((chosen, len(data)),)

    runs: list[Range] = []
    position = 0
    while position < len(data):
        if runs:
            # The next block usually follows the previous run directly.
            floor = runs[-1][0] + runs[-1][1]
            length = _match_length(medium, floor, data, position, grid)
            if length:
                runs[-1] = (runs[-1][0], runs[-1][1] + length)
                position += length
                continue
        block = data[position : position + grid]
        if holes and not any(block):
            # A sparse file: zero blocks that do not continue the run before
            # them were never written. Placing them would only find some other
            # zeros on the medium - free space, an inode table - and call it the
            # file.
            while position < len(data) and not any(data[position : position + grid]):
                position += grid
            continue
        placed = _place_run(medium, data, position, grid, max_probes)
        if placed is None:
            return None
        runs.append(placed)
        position += placed[1]
    return tuple(runs)


def _repetitive(block: bytes) -> bool:
    return block.count(block[:1]) == len(block)


def _place_run(
    medium: bytes | mmap.mmap, data: bytes, position: int, grid: int, max_probes: int
) -> Range | None:
    """Find where the run holding ``data[position:]`` starts on the medium.

    A block of one repeated byte (zeros, above all) occurs everywhere, so it is
    never searched for directly while a distinctive block follows it: the run is
    found by the first distinctive block and the start is worked back from
    there. Only a run made entirely of repeated bytes is searched as it stands,
    and then only its occurrences on ``grid`` count towards ``max_probes``.
    """
    anchor = position
    while anchor < len(data) and _repetitive(data[anchor : anchor + grid]):
        anchor += grid
    if anchor >= len(data):
        anchor = position
    back = anchor - position
    probe = data[anchor : anchor + grid]
    best_at, best_length = -1, 0
    at, probes = medium.find(probe), 0
    while at != -1 and probes < max_probes:
        start = at - back
        if at % grid == 0 and start >= 0:
            probes += 1
            length = _match_length(medium, start, data, position, grid)
            if length > best_length:
                best_at, best_length = start, length
                if position + length == len(data):
                    break
        at = medium.find(probe, at + 1 if at % grid == 0 else at + (grid - at % grid))
    if best_length == 0:
        return None
    return best_at, best_length


# --------------------------------------------------------------------------
# Manifests
# --------------------------------------------------------------------------


def write_truth(truth: Truth, path: Path | str) -> Path:
    """Write ``truth`` as JSON. Extents are written as ``[offset, length]``."""
    target = Path(path)
    payload = asdict(truth)
    payload["version"] = 1
    target.write_text(json.dumps(payload, indent=1) + "\n", encoding="utf-8")
    return target


def load_truth(path: Path | str) -> Truth:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    raw.pop("version", None)
    objects = tuple(
        TruthObject(
            **{
                **item,
                "extents": tuple(tuple(extent) for extent in item["extents"]),
            }
        )
        for item in raw.pop("objects")
    )
    damaged = tuple(tuple(entry) for entry in raw.pop("damaged"))
    return Truth(**raw, objects=objects, damaged=damaged)  # type: ignore[arg-type]


def rederive(
    base: Truth,
    *,
    image: str,
    model: str,
    description: str,
    damaged: Sequence[tuple[int, int, str]],
    size_bytes: int | None = None,
    parameters: dict[str, Any] | None = None,
    extra: Sequence[TruthObject] = (),
    own_ranges: dict[str, Range] | None = None,
) -> Truth:
    """The truth for a damaged copy of ``base``.

    Status can only get worse: an object already PARTIAL on the base stays at
    least PARTIAL. ``own_ranges`` names, per object, a damage range that is that
    object's own write, so a later file is not counted as damaged by itself.
    """
    size = base.size_bytes if size_bytes is None else size_bytes
    ranges = [(offset, length) for offset, length, _what in damaged]
    if size < base.size_bytes:
        ranges.append((size, base.size_bytes - size))
    own = own_ranges or {}
    objects: list[TruthObject] = []
    for item in (*base.objects, *extra):
        mine = own.get(item.name)
        applicable = [entry for entry in ranges if entry != mine]
        status, alive = status_of(item.extents, item.size - item.hole_bytes, applicable)
        if status != "GONE" and _SEVERITY[item.status] > _SEVERITY[status]:
            status = item.status
        objects.append(
            TruthObject(
                **{
                    **asdict(item),
                    "status": status,
                    "surviving_bytes": alive,
                    "extents": item.extents,
                }
            )
        )
    recorded = list(damaged)
    if size < base.size_bytes:
        recorded.append((size, base.size_bytes - size, "truncated away"))
    return Truth(
        image=image,
        corpus=base.corpus,
        model=model,
        description=description,
        size_bytes=size,
        filesystem=base.filesystem,
        cluster_bytes=base.cluster_bytes,
        base_image=base.image,
        parameters=dict(parameters or {}),
        damaged=tuple(recorded),
        objects=tuple(objects),
    )


def planted_span(truth: Truth) -> Range:
    """From the first to the last byte of every FULL formatted object."""
    extents = [
        extent
        for item in truth.objects
        if item.role == "file" and item.status == "FULL"
        for extent in item.extents
    ]
    if not extents:
        raise ValueError(f"{truth.image} holds no intact formatted object")
    start = min(offset for offset, _length in extents)
    end = max(offset + length for offset, length in extents)
    return start, end - start


# --------------------------------------------------------------------------
# Filesystem metadata, located from the volume's own structures
# --------------------------------------------------------------------------


def _read(handle: BinaryIO, offset: int, size: int) -> bytes:
    handle.seek(offset)
    return handle.read(size)


def _u16(data: bytes, at: int) -> int:
    return int(struct.unpack_from("<H", data, at)[0])


def _u32(data: bytes, at: int) -> int:
    return int(struct.unpack_from("<I", data, at)[0])


def _u64(data: bytes, at: int) -> int:
    return int(struct.unpack_from("<Q", data, at)[0])


def _chain(fat: bytes, first: int, end: int, mask: int = 0xFFFFFFFF) -> list[int]:
    clusters: list[int] = []
    seen: set[int] = set()
    cluster = first
    while 2 <= cluster < end and cluster not in seen and cluster * 4 + 4 <= len(fat):
        seen.add(cluster)
        clusters.append(cluster)
        cluster = _u32(fat, cluster * 4) & mask
    return clusters


def _fat32_metadata(handle: BinaryIO) -> list[tuple[int, int, str]]:
    boot = _read(handle, 0, 512)
    sector = _u16(boot, 0x0B)
    cluster = sector * boot[0x0D]
    reserved = _u16(boot, 0x0E) * sector
    copies = boot[0x10]
    fat_bytes = _u32(boot, 0x24) * sector
    heap = reserved + copies * fat_bytes
    fat = _read(handle, reserved, fat_bytes)
    ranges = [
        (0, reserved, "boot sector, FSINFO and backup boot sector (reserved region)"),
        (reserved, copies * fat_bytes, f"{copies} FAT copies"),
    ]
    for number in _chain(fat, _u32(boot, 0x2C), 0x0FFFFFF8, 0x0FFFFFFF):
        at = heap + (number - 2) * cluster
        ranges.append((at, cluster, "root directory cluster"))
    return ranges


def _exfat_metadata(handle: BinaryIO) -> list[tuple[int, int, str]]:
    boot = _read(handle, 0, 512)
    sector = 1 << boot[0x6C]
    cluster = sector << boot[0x6D]
    fat_at = _u32(boot, 0x50) * sector
    fat_bytes = _u32(boot, 0x54) * sector
    heap = _u32(boot, 0x58) * sector
    fat = _read(handle, fat_at, fat_bytes)
    root = _chain(fat, _u32(boot, 0x60), 0xFFFFFFF7)
    ranges = [
        (0, 24 * sector, "main and backup boot regions"),
        (fat_at, fat_bytes, "FAT"),
    ]
    directory = b"".join(
        _read(handle, heap + (number - 2) * cluster, cluster) for number in root
    )
    labels = {0x81: "allocation bitmap", 0x82: "up-case table"}
    for at in range(0, len(directory), 32):
        kind = directory[at]
        if kind == 0:
            break
        if kind not in labels:
            continue
        first = _u32(directory, at + 0x14)
        count = max(1, -(-_u64(directory, at + 0x18) // cluster))
        chained = _chain(fat, first, 0xFFFFFFF7)
        numbers = (
            chained if len(chained) >= count else list(range(first, first + count))
        )
        for number in numbers[:count]:
            ranges.append((heap + (number - 2) * cluster, cluster, labels[kind]))
    for number in root:
        at = heap + (number - 2) * cluster
        ranges.append((at, cluster, "root directory cluster"))
    return ranges


def _ntfs_metadata(handle: BinaryIO, size: int) -> list[tuple[int, int, str]]:
    boot = _read(handle, 0, 512)
    geometry = _ntfs_geometry(boot)
    sector = geometry.bytes_per_sector
    backup = min(_u64(boot, 0x28) * sector, size - sector)
    ranges = [(0, sector, "boot sector"), (backup, sector, "backup boot sector")]
    for record, label in ((0, "$MFT"), (1, "$MFTMirr")):
        raw = bytearray(
            _read(
                handle,
                geometry.mft_offset + record * geometry.record_size,
                geometry.record_size,
            )
        )
        if raw[:4] != b"FILE" or not _apply_fixups(raw):
            raise RuntimeError(f"MFT record {record} is not readable")
        for kind, at, _length in _iter_attributes(bytes(raw)):
            if kind == 0x80 and raw[at + 8]:
                for lcn, count in _decode_runs(bytes(raw), at):
                    if lcn >= 0:
                        ranges.append(
                            (
                                lcn * geometry.cluster_bytes,
                                count * geometry.cluster_bytes,
                                label,
                            )
                        )
                break
    return ranges


def _ext_has_backup(group: int, sparse: bool) -> bool:
    if not sparse or group in (0, 1):
        return True
    for base in (3, 5, 7):
        power = base
        while power < group:
            power *= base
        if power == group:
            return True
    return False


def _ext_metadata(handle: BinaryIO) -> list[tuple[int, int, str]]:
    sb = _read(handle, 1024, 1024)
    incompat = _u32(sb, 0x60)
    if incompat & 0x10:
        raise NotImplementedError("meta_bg ext volumes are not modelled")
    wide = bool(incompat & 0x80)
    blocks = _u32(sb, 0x04) | ((_u32(sb, 0x150) << 32) if wide else 0)
    first_data = _u32(sb, 0x14)
    block = 1024 << _u32(sb, 0x18)
    per_group = _u32(sb, 0x20)
    inodes_per_group = _u32(sb, 0x28)
    inode_size = _u16(sb, 0x58) if _u32(sb, 0x4C) >= 1 else 128
    descriptor = (_u16(sb, 0xFE) if wide else 32) or 32
    groups = -(-(blocks - first_data) // per_group)
    gdt_blocks = -(-(groups * descriptor) // block)
    reserved = _u16(sb, 0xCE) if _u32(sb, 0x5C) & 0x10 else 0
    sparse = bool(_u32(sb, 0x64) & 0x1)

    ranges: list[tuple[int, int, str]] = []
    for group in range(groups):
        if not _ext_has_backup(group, sparse):
            continue
        sb_block = first_data + group * per_group
        start = 0 if group == 0 else sb_block * block
        end = (sb_block + 1 + gdt_blocks + reserved) * block
        ranges.append((start, end - start, "superblock and group descriptor copy"))

    table = _read(handle, (first_data + 1) * block, gdt_blocks * block)
    table_blocks = -(-(inodes_per_group * inode_size) // block)
    for group in range(groups):
        entry = table[group * descriptor : (group + 1) * descriptor]
        block_bitmap, inode_bitmap, inode_table = (
            _u32(entry, 0),
            _u32(entry, 4),
            _u32(entry, 8),
        )
        if descriptor >= 64:
            block_bitmap |= _u32(entry, 0x20) << 32
            inode_bitmap |= _u32(entry, 0x24) << 32
            inode_table |= _u32(entry, 0x28) << 32
        ranges.append((block_bitmap * block, block, "block bitmap"))
        ranges.append((inode_bitmap * block, block, "inode bitmap"))
        ranges.append((inode_table * block, table_blocks * block, "inode table"))
    return ranges


def metadata_ranges(path: Path | str, filesystem: str) -> list[tuple[int, int, str]]:
    """Every range holding the metadata a volume needs to find its files.

    Read from the volume's own structures, not from a table of usual offsets,
    so a volume laid out unusually is still covered. File data is not in any
    range; a file stored inside metadata (a resident NTFS file) is, and the
    manifest will show it GONE.
    """
    target = Path(path)
    with open(target, "rb") as handle:
        if filesystem == "fat32":
            return _fat32_metadata(handle)
        if filesystem == "exfat":
            return _exfat_metadata(handle)
        if filesystem == "ntfs":
            return _ntfs_metadata(handle, target.stat().st_size)
        if filesystem in ("ext2", "ext3", "ext4"):
            return _ext_metadata(handle)
    raise ValueError(f"no metadata model for {filesystem!r}")


# --------------------------------------------------------------------------
# The models
# --------------------------------------------------------------------------


def _zero(path: Path, ranges: Iterable[tuple[int, int, str]]) -> None:
    with open(path, "r+b") as handle:
        for offset, length, _what in ranges:
            handle.seek(offset)
            remaining = length
            while remaining > 0:
                step = min(MIB, remaining)
                handle.write(b"\x00" * step)
                remaining -= step


def apply_truncation(base: Truth, base_path: Path, out: Path) -> Truth:
    """Cut the image halfway through the span its planted files occupy.

    The cut is placed relative to the files, not at a fixed percentage of the
    image: on a mostly empty volume a fixed cut can miss every file and measure
    nothing. The percentage of the image lost is recorded.
    """
    files = sorted(
        (
            item
            for item in base.objects
            if item.role == "file" and item.status == "FULL" and item.extents
        ),
        key=lambda item: item.extents[0][0],
    )
    if not files:
        raise ValueError(f"{base.image} holds no intact formatted object")
    # Through the middle of the median file in medium order: about half the
    # files survive whole, one is cut, the rest are gone. Cutting at half the
    # span's *bytes* instead left three of twenty-two files on FAT32, because one
    # large photo sits early and holds most of the bytes.
    median = files[len(files) // 2]
    offset, length = median.extents[0]
    keep = _align_down(offset + length // 2, SECTOR)
    sparse_copy(base_path, out)
    os.truncate(out, keep)
    lost = base.size_bytes - keep
    return rederive(
        base,
        image=out.name,
        model="truncation",
        description=(
            f"image ends at byte {keep}: the last {lost} bytes "
            f"({100 * lost / base.size_bytes:.1f}%) are gone"
        ),
        damaged=[],
        size_bytes=keep,
        parameters={
            "kept_bytes": keep,
            "lost_percent": round(100 * lost / base.size_bytes, 1),
        },
    )


def apply_zeroed_regions(
    base: Truth,
    base_path: Path,
    out: Path,
    *,
    seed: int = 0,
    band_bytes: int = 256 * KIB,
    seeded_bands: int = 6,
) -> Truth:
    """Zero bands across the medium, as zero-filled unreadable sectors appear.

    Two bands are placed deliberately so that every status is exercised: one
    covering the median-sized contiguous file whole, one over the middle third
    of the largest. ``seeded_bands`` more of ``band_bytes`` are placed by
    ``seed`` anywhere on the medium, and hit whatever they hit.
    """
    files = sorted(
        (
            item
            for item in base.objects
            if item.role == "file" and item.status == "FULL" and len(item.extents) == 1
        ),
        key=lambda item: (item.size, item.name),
    )
    if len(files) < 2:
        raise ValueError(f"{base.image} has too few contiguous files to band")
    whole, largest = files[len(files) // 2], files[-1]
    bands: list[tuple[int, int, str]] = []
    offset, length = whole.extents[0]
    start = _align_down(offset, SECTOR)
    end = _align_up(offset + length, SECTOR)
    bands.append((start, end - start, f"covers {whole.name}"))
    offset, length = largest.extents[0]
    low = _align_down(offset + length // 3, SECTOR)
    high = _align_down(offset + 2 * length // 3, SECTOR)
    bands.append((low, max(SECTOR, high - low), f"middle third of {largest.name}"))
    rng = random.Random(seed)
    for _index in range(seeded_bands):
        at = _align_down(rng.randrange(0, base.size_bytes - band_bytes), SECTOR)
        bands.append((at, band_bytes, f"seeded band (seed {seed})"))

    sparse_copy(base_path, out)
    _zero(out, bands)
    zeroed = sum(length for _offset, length in _merge((o, n) for o, n, _w in bands))
    return rederive(
        base,
        image=out.name,
        model="zeroed_regions",
        description=(
            f"{len(bands)} zero-filled bands, {zeroed} bytes "
            f"({100 * zeroed / base.size_bytes:.2f}% of the medium)"
        ),
        damaged=bands,
        parameters={"seed": seed, "band_bytes": band_bytes, "bands": len(bands)},
    )


def apply_metadata_destruction(base: Truth, base_path: Path, out: Path) -> Truth:
    """Zero every structure the volume needs to find its files; leave the data."""
    ranges = metadata_ranges(base_path, base.filesystem)
    sparse_copy(base_path, out)
    _zero(out, ranges)
    labels = sorted({what for _offset, _length, what in ranges})
    destroyed = sum(length for _offset, length in _merge((o, n) for o, n, _w in ranges))
    return rederive(
        base,
        image=out.name,
        model="metadata_destroyed",
        description=(
            f"{base.filesystem} metadata zeroed ({destroyed} bytes): "
            + ", ".join(labels)
        ),
        damaged=ranges,
        parameters={"structures": labels, "bytes": destroyed},
    )


def apply_interleaved_overwrite(
    base: Truth, base_path: Path, out: Path, overwrites: Sequence[Overwrite]
) -> Truth:
    """Write later files over parts of earlier ones, on the cluster grid.

    Bytes only: no filesystem record is updated. That is the state after the
    later file was written and itself deleted, and it leaves the earlier file's
    record (if any) pointing at clusters that now hold something else.
    """
    grid = base.cluster_bytes or SECTOR
    sparse_copy(base_path, out)
    writes: list[tuple[int, int, str]] = []
    extra: list[TruthObject] = []
    own: dict[str, Range] = {}
    detail: list[dict[str, Any]] = []
    with open(out, "r+b") as handle:
        for overwrite in overwrites:
            victim = base.by_name(overwrite.victim)
            offset, length = victim.extents[0]
            at = _align_down(offset + int(length * overwrite.start_fraction), grid)
            if overwrite.start_fraction and at <= offset:
                at = _align_up(offset + 1, grid)
            handle.seek(at)
            handle.write(overwrite.data)
            span = (at, len(overwrite.data))
            writes.append((*span, f"{overwrite.name} written over {victim.name}"))
            own[overwrite.name] = span
            extra.append(
                TruthObject(
                    name=overwrite.name,
                    format=overwrite.format,
                    role="file",
                    sha256=hashlib.sha256(overwrite.data).hexdigest(),
                    size=len(overwrite.data),
                    extents=(span,),
                    status="FULL",
                    surviving_bytes=len(overwrite.data),
                    note=f"later file written over {victim.name}",
                )
            )
            detail.append(
                {
                    "victim": victim.name,
                    "later": overwrite.name,
                    "at": at,
                    "length": len(overwrite.data),
                }
            )
    return rederive(
        base,
        image=out.name,
        model="interleaved_overwrite",
        description="; ".join(
            f"{item['later']} ({item['length']} bytes) over {item['victim']}"
            f" at {item['at']}"
            for item in detail
        ),
        damaged=writes,
        parameters={"overwrites": detail},
        extra=extra,
        own_ranges=own,
    )
