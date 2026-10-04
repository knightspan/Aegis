"""Build real filesystem images for the corpus, without root.

Every image here is made by the real ``mkfs`` for the filesystem and populated
through a tool that writes the real on-disk structures. Nothing is a hand-rolled
approximation of a filesystem, because an approximation would measure the
generator rather than the recovery.

**No image needs root.** That is a deliberate constraint, not a convenience:
a corpus that only builds under ``sudo`` is a corpus that silently stops being
tested, and the first anyone notices is the day it matters. Mounting a
filesystem needs ``CAP_SYS_ADMIN`` in the initial user namespace, so nothing
here mounts anything:

=========  =====================================================================
NTFS       ``mkfs.ntfs`` then ``ntfscp``, which writes into the volume directly.
           Deletion is performed here, byte by byte, because no unprivileged
           tool deletes from an unmounted NTFS volume - see :func:`ntfs_delete`.
FAT32      ``mkfs.vfat`` then ``mtools`` (``mcopy``/``mdel``), which speak the
           on-disk format and never mount.
exFAT      ``mkfs.exfat``, then this module writes the directory entries, the
           FAT chains and the allocation bitmap itself. Fedora ships no
           unprivileged exFAT writer at all - there is no ``fuse-exfat``, and
           ``exfatprogs`` has ``exfatlabel`` and ``fsck.exfat`` but no way to
           put a file in - so the entries are built from the specification.
           ``fsck.exfat`` is then run over the result, so the claim that these
           are valid volumes is checked rather than asserted.
ext2/3/4   ``mkfs.ext*`` then ``debugfs``, which edits the filesystem offline.
=========  =====================================================================

Deletion is modelled as the kernel performs it, which is not the same on every
filesystem and is the reason recall differs so much between them:

* **NTFS** clears the MFT record's in-use flag, frees the clusters in
  ``$Bitmap``, and removes the entry from the parent's ``$I30`` index by moving
  the following entries down over it. The run list survives untouched, which is
  why NTFS recovery is exact.
* **FAT** replaces the first byte of the directory entry with ``0xE5`` and
  zeroes the file's cluster chain. ``mdel`` does exactly this.
* **exFAT** clears the in-use bit on every entry of the set and clears the
  file's bits in the allocation bitmap.
* **ext4** frees the blocks *and zeroes the inode's extent tree*, which is what
  ``ext4_ext_remove_space`` does on unlink. ``debugfs rm`` alone does not - it
  only unlinks - so an ext4 corpus built with ``rm`` would make ext4 undelete
  look like NTFS and would be a lie. The extent tree is zeroed here explicitly.
* **ext2/ext3** free the blocks and set ``i_dtime``, leaving the block pointers
  in place. That is exactly true of ext2. For ext3 it is an **upper bound**:
  a Linux 2.6 or later kernel runs ``ext3_truncate`` on delete, which zeroes
  ``i_block`` as well, so real ext3 recall is at or below what this corpus
  measures. The limitation is recorded in ``docs/limitations.md`` rather than
  hidden inside a favourable number.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "ToolReport",
    "probe_tools",
    "MissingTool",
    "PlantedFile",
    "build_ntfs",
    "build_fat32",
    "build_exfat",
    "build_ext",
    "build_two_partition_image",
    "sparse_copy",
    "damage_boot_sector",
    "damage_partition_table",
    "quick_format",
    "ntfs_delete",
    "REQUIRED_TOOLS",
]

KIB = 1024
MIB = 1024 * KIB

#: Every external tool the builders use, and which filesystem needs it. All of
#: them run unprivileged.
REQUIRED_TOOLS: dict[str, tuple[str, ...]] = {
    "ntfs": ("mkfs.ntfs", "ntfscp"),
    "fat32": ("mkfs.vfat", "mcopy", "mdel"),
    "exfat": ("mkfs.exfat",),
    "ext2": ("mkfs.ext2", "debugfs"),
    "ext3": ("mkfs.ext3", "debugfs"),
    "ext4": ("mkfs.ext4", "debugfs"),
}


class MissingTool(RuntimeError):
    """A builder was asked for a filesystem whose tooling is not installed."""


@dataclass(frozen=True)
class ToolReport:
    """Which filesystems can be built on this host, and what is missing."""

    available: tuple[str, ...]
    missing: dict[str, tuple[str, ...]]

    @property
    def complete(self) -> bool:
        return not self.missing

    def reason(self) -> str:
        """A skip reason naming the tool and the package, not just 'missing'."""
        parts = [
            f"{name} needs {', '.join(tools)}"
            for name, tools in sorted(self.missing.items())
        ]
        return "; ".join(parts)


def probe_tools() -> ToolReport:
    """Which of :data:`REQUIRED_TOOLS` are on PATH. Never raises."""
    available: list[str] = []
    missing: dict[str, tuple[str, ...]] = {}
    for filesystem, tools in REQUIRED_TOOLS.items():
        absent = tuple(tool for tool in tools if shutil.which(tool) is None)
        if absent:
            missing[filesystem] = absent
        else:
            available.append(filesystem)
    return ToolReport(available=tuple(available), missing=missing)


def _require(filesystem: str) -> None:
    report = probe_tools()
    if filesystem in report.missing:
        raise MissingTool(
            f"cannot build {filesystem}: missing "
            f"{', '.join(report.missing[filesystem])}"
        )


def _run(command: Sequence[str], *, env: dict[str, str] | None = None) -> str:
    """Run a builder tool, raising with its own words on failure."""
    merged = dict(os.environ)
    merged.update(env or {})
    completed = subprocess.run(
        list(command), capture_output=True, text=True, env=merged
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"{command[0]} failed ({completed.returncode}): "
            f"{(completed.stderr or completed.stdout).strip()[:500]}"
        )
    return completed.stdout


@dataclass(frozen=True)
class PlantedFile:
    """One file placed in an image, and what was done to it afterwards."""

    name: str
    data: bytes
    #: True when the file was deleted after being written.
    deleted: bool = False
    #: True when the layout was deliberately made non-contiguous.
    fragmented: bool = False


#: Chunk size for sparse copying. Large enough that the scan is cheap, small
#: enough that a hole between two small files is still detected as a hole.
_SPARSE_CHUNK = 1 * MIB


def sparse_copy(source: Path | str, destination: Path | str) -> None:
    """Copy an image, leaving all-zero regions as holes.

    ``shutil.copyfile`` materialises every hole. That matters here because the
    corpus is built into pytest's ``tmp_path``, which is usually a tmpfs: a
    24 MiB NTFS image holding two megabytes of files costs two megabytes as
    built and twenty-four as copied, and the corpus is copied several times to
    make its damaged variants. On a host with a 6 GiB ``/tmp`` and pytest
    keeping three sessions of temporary directories, that is the difference
    between a corpus that fits and one that fills the machine's memory.

    Zero regions are skipped with ``seek`` rather than written, which is what
    creates the hole. The copy is byte-identical either way; only its
    allocation differs.
    """
    source, destination = Path(source), Path(destination)
    size = source.stat().st_size
    with open(source, "rb") as reader, open(destination, "wb") as writer:
        writer.truncate(size)
        while True:
            offset = reader.tell()
            chunk = reader.read(_SPARSE_CHUNK)
            if not chunk:
                break
            if chunk.strip(b"\x00"):
                writer.seek(offset)
                writer.write(chunk)
    # truncate() set the length; the final seek may sit before it.
    with open(destination, "r+b") as writer:
        writer.truncate(size)


def _blank(path: Path, size: int) -> None:
    """A sparse file of ``size`` bytes. mkfs writes only what it needs."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as handle:
        handle.truncate(size)


# --------------------------------------------------------------------------
# NTFS
# --------------------------------------------------------------------------
#
# Nothing unprivileged deletes a file from an unmounted NTFS volume: ntfsprogs
# ships ntfscp but no ntfsrm on Fedora, and ntfs-3g refuses to mount without
# root. So deletion is performed here, on the structures, exactly as the driver
# performs it. That is not a shortcut around the real thing - it *is* the real
# thing, and writing it out is what makes the corpus reproducible on any
# developer's machine.

_NTFS_ATTR_END = 0xFFFF_FFFF
_NTFS_ATTR_FILE_NAME = 0x30
_NTFS_ATTR_DATA = 0x80
_NTFS_ATTR_INDEX_ROOT = 0x90
_NTFS_ATTR_INDEX_ALLOCATION = 0xA0

_NTFS_RECORD_IN_USE = 0x0001
_NTFS_SECTOR = 512

#: $Bitmap always occupies MFT record 6, and the root directory record 5.
_NTFS_BITMAP_RECORD = 6
_NTFS_ROOT_RECORD = 5


@dataclass(frozen=True)
class _NtfsGeometry:
    bytes_per_sector: int
    sectors_per_cluster: int
    mft_offset: int
    record_size: int

    @property
    def cluster_bytes(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster


def _ntfs_geometry(boot: bytes) -> _NtfsGeometry:
    bytes_per_sector = struct.unpack_from("<H", boot, 0x0B)[0]
    sectors_per_cluster = boot[0x0D]
    mft_lcn = struct.unpack_from("<Q", boot, 0x30)[0]
    clusters_per_record = struct.unpack_from("<b", boot, 0x40)[0]
    cluster_bytes = bytes_per_sector * sectors_per_cluster
    record_size = (
        clusters_per_record * cluster_bytes
        if clusters_per_record > 0
        else 1 << (-clusters_per_record)
    )
    return _NtfsGeometry(
        bytes_per_sector=bytes_per_sector,
        sectors_per_cluster=sectors_per_cluster,
        mft_offset=mft_lcn * cluster_bytes,
        record_size=record_size,
    )


def _apply_fixups(record: bytearray) -> bool:
    """Reverse the update-sequence substitution in place."""
    usa_offset, usa_count = struct.unpack_from("<HH", record, 4)
    if usa_count < 1 or usa_offset + usa_count * 2 > len(record):
        return False
    for index in range(1, usa_count):
        end = index * _NTFS_SECTOR - 2
        if end + 2 > len(record):
            return False
        original = record[usa_offset + index * 2 : usa_offset + index * 2 + 2]
        record[end : end + 2] = original
    return True


def _reapply_fixups(record: bytearray) -> None:
    """Re-impose the update sequence before writing a record back.

    Skipping this is the classic way to produce an image that reads fine in the
    tool that made it and is rejected by every other one: the check values would
    no longer match the sector tails.
    """
    usa_offset, usa_count = struct.unpack_from("<HH", record, 4)
    usn = struct.unpack_from("<H", record, usa_offset)[0]
    usn = (usn + 1) & 0xFFFF
    if usn in (0, 0xFFFF):
        usn = 1
    struct.pack_into("<H", record, usa_offset, usn)
    for index in range(1, usa_count):
        end = index * _NTFS_SECTOR - 2
        record[usa_offset + index * 2 : usa_offset + index * 2 + 2] = record[
            end : end + 2
        ]
        struct.pack_into("<H", record, end, usn)


def _iter_attributes(record: bytes) -> Iterable[tuple[int, int, int]]:
    """Yield ``(type, offset, length)`` for each attribute in a record."""
    at = struct.unpack_from("<H", record, 0x14)[0]
    while at + 8 <= len(record):
        attr_type, length = struct.unpack_from("<II", record, at)
        if attr_type == _NTFS_ATTR_END or length < 8 or at + length > len(record):
            return
        yield attr_type, at, length
        at += length


def _resident_value(record: bytes, at: int) -> bytes:
    length = struct.unpack_from("<I", record, at + 0x10)[0]
    offset = struct.unpack_from("<H", record, at + 0x14)[0]
    return record[at + offset : at + offset + length]


def _decode_runs(record: bytes, at: int) -> list[tuple[int, int]]:
    """Decode a non-resident attribute's run list into ``(lcn, clusters)``."""
    run_offset = struct.unpack_from("<H", record, at + 0x20)[0]
    cursor = at + run_offset
    runs: list[tuple[int, int]] = []
    lcn = 0
    while cursor < len(record):
        header = record[cursor]
        if header == 0:
            break
        length_bytes = header & 0x0F
        offset_bytes = header >> 4
        cursor += 1
        if length_bytes == 0 or cursor + length_bytes + offset_bytes > len(record):
            break
        count = int.from_bytes(record[cursor : cursor + length_bytes], "little")
        cursor += length_bytes
        if offset_bytes:
            delta = int.from_bytes(
                record[cursor : cursor + offset_bytes], "little", signed=True
            )
            cursor += offset_bytes
            lcn += delta
            runs.append((lcn, count))
        else:
            runs.append((-1, count))  # sparse
    return runs


def _filename_of(record: bytes) -> str | None:
    """The long name from a record's ``$FILE_NAME``, if it has one."""
    best: str | None = None
    for attr_type, at, _length in _iter_attributes(record):
        if attr_type != _NTFS_ATTR_FILE_NAME:
            continue
        value = _resident_value(record, at)
        if len(value) < 0x42:
            continue
        name_length = value[0x40]
        namespace = value[0x41]
        raw = value[0x42 : 0x42 + name_length * 2]
        if len(raw) < name_length * 2:
            continue
        try:
            name = raw.decode("utf-16-le")
        except UnicodeDecodeError:
            continue
        if namespace == 2 and best is not None:  # DOS short name
            continue
        best = name
    return best


def ntfs_delete(
    image: Path | str, names: Sequence[str], *, unlink: bool = True
) -> dict[str, int]:
    """Delete files from an unmounted NTFS image, as the driver would.

    Three separate things happen, and each one matters to a different part of
    recovery:

    1. **The MFT record's in-use flag is cleared.** The record, its
       ``$FILE_NAME`` and its ``$DATA`` run list all survive, which is why NTFS
       undelete returns the original bytes rather than a guess at them.
    2. **The file's clusters are freed in ``$Bitmap``.** Without this the
       volume would claim space no file owns and every consistency check would
       disagree with the recovery.
    3. **The entry is removed from the parent's ``$I30``** by moving the
       following entries down over it and shrinking the index header's used
       length. The bytes past the new length are left alone, which is what
       leaves a deleted name in index slack - the phenomenon
       ``core.carve.fsaware`` reads.

    ``unlink=False`` performs the first two steps only, leaving the directory
    entry in place. That is not a normal deletion; it exists for the
    fragmentation scaffolding, where a hundred throwaway filler files have to
    free their clusters and where removing a hundred entries from the root
    index would rewrite a B-tree this module has no business rewriting.

    Returns ``{name: mft record number}`` so a caller can record which record
    each deleted file occupied, and later assert that it was reused.
    """
    path = Path(image)
    with open(path, "r+b") as handle:
        boot = handle.read(512)
        if boot[3:11] != b"NTFS    ":
            raise RuntimeError(f"{path} is not an NTFS volume")
        geometry = _ntfs_geometry(boot)

        # $MFT is only contiguous while it is small. As soon as it grows past
        # its initial run - a few hundred records is enough - NTFS extends it
        # elsewhere on the volume, and `mft_offset + index * record_size` then
        # addresses unrelated data. That failure is quiet: the record does not
        # start with "FILE", the file "is not found", and the corpus silently
        # loses the files it was meant to delete. So the run list is read from
        # $MFT's own $DATA attribute and record numbers are mapped through it.
        handle.seek(geometry.mft_offset)
        first = bytearray(handle.read(geometry.record_size))
        mft_runs: list[tuple[int, int]] = []
        if first[:4] == b"FILE" and _apply_fixups(first):
            for attr_type, at, _length in _iter_attributes(bytes(first)):
                if attr_type == _NTFS_ATTR_DATA and first[at + 8]:
                    mft_runs = _decode_runs(bytes(first), at)
                    break
        if not mft_runs:
            mft_runs = [(geometry.mft_offset // geometry.cluster_bytes, 1 << 30)]

        records_per_cluster = max(geometry.cluster_bytes // geometry.record_size, 1)

        def record_offset(index: int) -> int | None:
            """Byte offset of MFT record ``index``, walking $MFT's runs."""
            walked = 0
            for lcn, clusters in mft_runs:
                if lcn < 0:
                    walked += clusters * records_per_cluster
                    continue
                held = clusters * records_per_cluster
                if index < walked + held:
                    return (
                        lcn * geometry.cluster_bytes
                        + (index - walked) * geometry.record_size
                    )
                walked += held
            return None

        def read_record(index: int) -> bytearray | None:
            at = record_offset(index)
            if at is None:
                return None
            handle.seek(at)
            raw = bytearray(handle.read(geometry.record_size))
            if len(raw) < geometry.record_size or raw[:4] != b"FILE":
                return None
            return raw if _apply_fixups(raw) else None

        def write_record(index: int, record: bytearray) -> None:
            at = record_offset(index)
            if at is None:
                raise RuntimeError(f"MFT record {index} is outside every $MFT run")
            _reapply_fixups(record)
            handle.seek(at)
            handle.write(bytes(record))

        # Where is $Bitmap, so freed clusters can actually be freed?
        bitmap_record = read_record(_NTFS_BITMAP_RECORD)
        bitmap_runs: list[tuple[int, int]] = []
        if bitmap_record is not None:
            for attr_type, at, _length in _iter_attributes(bitmap_record):
                if attr_type == _NTFS_ATTR_DATA and bitmap_record[at + 8]:
                    bitmap_runs = _decode_runs(bitmap_record, at)
                    break

        def free_clusters(runs: Sequence[tuple[int, int]]) -> None:
            for lcn, count in runs:
                if lcn < 0:
                    continue
                for cluster in range(lcn, lcn + count):
                    bit_index = cluster
                    byte_index = bit_index // 8
                    walked = 0
                    for run_lcn, run_count in bitmap_runs:
                        span = run_count * geometry.cluster_bytes
                        if byte_index < walked + span:
                            at = (
                                run_lcn * geometry.cluster_bytes
                                + (byte_index - walked)
                            )
                            handle.seek(at)
                            current = handle.read(1)
                            if not current:
                                break
                            handle.seek(at)
                            handle.write(
                                bytes([current[0] & ~(1 << (bit_index % 8))])
                            )
                            break
                        walked += span

        # Locate every requested name in the MFT.
        wanted = {name: -1 for name in names}
        total_records = sum(
            clusters * records_per_cluster for lcn, clusters in mft_runs if lcn >= 0
        )
        for index in range(min(total_records, 65536)):
            record = read_record(index)
            if record is None:
                continue
            flags = struct.unpack_from("<H", record, 0x16)[0]
            if not flags & _NTFS_RECORD_IN_USE or flags & 0x0002:
                continue
            name = _filename_of(record)
            if name in wanted and wanted[name] == -1:
                wanted[name] = index

        missing = [name for name, index in wanted.items() if index == -1]
        if missing:
            raise RuntimeError(f"not found in {path.name}: {', '.join(missing)}")

        for index in wanted.values():
            record = read_record(index)
            assert record is not None
            for attr_type, at, _length in _iter_attributes(record):
                if attr_type == _NTFS_ATTR_DATA and record[at + 8]:
                    free_clusters(_decode_runs(record, at))
            flags = struct.unpack_from("<H", record, 0x16)[0]
            struct.pack_into("<H", record, 0x16, flags & ~_NTFS_RECORD_IN_USE)
            write_record(index, record)

        if unlink:
            _remove_index_entries(handle, geometry, read_record, write_record, names)

    return dict(wanted)


def _attr_name(record: bytes, at: int) -> str:
    """An attribute's name, e.g. ``$I30``. Empty for the unnamed ones."""
    name_length = record[at + 0x09]
    if not name_length:
        return ""
    name_offset = struct.unpack_from("<H", record, at + 0x0A)[0]
    raw = bytes(record[at + name_offset : at + name_offset + name_length * 2])
    try:
        return raw.decode("utf-16-le")
    except UnicodeDecodeError:
        return ""


def _remove_entry_from_node(
    node: bytearray, header: int, names: Sequence[str]
) -> bool:
    """Remove named entries from one index node, leaving the tail as slack.

    The removal is a move, not an erase, which is the whole point. NTFS shifts
    the entries after the removed one down over it and reduces the index
    header's used length; the bytes between the new used length and the
    allocated size are never touched. Those bytes are a stale copy of what used
    to sit at the end of the node, and they are exactly what
    ``core.carve.fsaware`` reads out of ``$I30`` slack.

    ``header`` is where the INDEX_HEADER begins inside ``node``: 0x10 into an
    ``$INDEX_ROOT`` value, 0x18 into an ``INDX`` record.
    """
    wanted = set(names)
    changed = False
    for _pass in range(len(wanted) + 1):
        entries_offset, index_length = struct.unpack_from("<II", node, header)
        used_end = header + index_length
        cursor = header + entries_offset
        removed = False
        while cursor + 0x10 <= used_end:
            entry_length, key_length, entry_flags = struct.unpack_from(
                "<HHH", node, cursor + 8
            )
            if entry_length < 0x10 or cursor + entry_length > len(node):
                break
            if entry_flags & 0x02:  # end marker: nothing real follows
                break
            if entry_flags & 0x01:
                # This entry carries a pointer to a child node. Removing it
                # would orphan that whole subtree, and the volume stops being
                # mountable - which is how this guard came to exist. NTFS
                # handles the case by promoting a replacement key; the corpus
                # does not need that, so such entries are left alone.
                cursor += entry_length
                continue
            name = ""
            if key_length >= 0x42:
                key = cursor + 0x10
                name_length = node[key + 0x40]
                raw = bytes(node[key + 0x42 : key + 0x42 + name_length * 2])
                if len(raw) == name_length * 2:
                    try:
                        name = raw.decode("utf-16-le")
                    except UnicodeDecodeError:
                        name = ""
            if name in wanted:
                tail = bytes(node[cursor + entry_length : used_end])
                node[cursor : cursor + len(tail)] = tail
                struct.pack_into("<I", node, header + 4, index_length - entry_length)
                changed = removed = True
                break
            cursor += entry_length
        if not removed:
            break
    return changed


def _remove_index_entries(
    handle: object,
    geometry: _NtfsGeometry,
    read_record: object,
    write_record: object,
    names: Sequence[str],
) -> None:
    """Remove entries from the root directory's ``$I30``, wherever it lives.

    A directory small enough to fit keeps its index inside the MFT record, in
    ``$INDEX_ROOT``. As soon as it does not - twenty files is already enough -
    NTFS spills the index into ``$INDEX_ALLOCATION``, a chain of 4 KiB ``INDX``
    records out on the volume. Those records are also the only place index
    *slack* exists: a resident ``$INDEX_ROOT`` is sized exactly to its entries,
    so its allocated size equals its used length and there is no room for a
    stale entry to survive in. An implementation that handled only
    ``$INDEX_ROOT`` would appear to work and would silently never produce the
    thing it exists to produce.
    """
    read = read_record  # closures over the one open file handle
    write = write_record
    record = read(_NTFS_ROOT_RECORD)  # type: ignore[operator]
    if record is None:
        return

    block_size = 4096
    runs: list[tuple[int, int]] = []
    for attr_type, at, _length in list(_iter_attributes(bytes(record))):
        name = _attr_name(bytes(record), at)
        if attr_type == _NTFS_ATTR_INDEX_ROOT and name == "$I30":
            value_offset = struct.unpack_from("<H", record, at + 0x14)[0]
            node_at = at + value_offset
            block_size = (
                struct.unpack_from("<I", record, node_at + 0x08)[0] or block_size
            )
            if _remove_entry_from_node(record, node_at + 0x10, names):
                write(_NTFS_ROOT_RECORD, record)  # type: ignore[operator]
                record = read(_NTFS_ROOT_RECORD)  # type: ignore[operator]
                assert record is not None
        elif attr_type == _NTFS_ATTR_INDEX_ALLOCATION and name == "$I30":
            if record[at + 8]:  # non-resident, as it always is
                runs = _decode_runs(bytes(record), at)

    if not runs:
        return

    file_handle = handle  # typed loosely; it is the open image
    for lcn, clusters in runs:
        if lcn < 0:
            continue
        span = clusters * geometry.cluster_bytes
        base = lcn * geometry.cluster_bytes
        for offset in range(0, span, block_size):
            file_handle.seek(base + offset)  # type: ignore[attr-defined]
            block = bytearray(
                file_handle.read(block_size)  # type: ignore[attr-defined]
            )
            if len(block) < block_size or block[:4] != b"INDX":
                continue
            if not _apply_fixups(block):
                continue
            if not _remove_entry_from_node(block, 0x18, names):
                continue
            _reapply_fixups(block)
            file_handle.seek(base + offset)  # type: ignore[attr-defined]
            file_handle.write(bytes(block))  # type: ignore[attr-defined]


def ntfs_reuse_record(image: Path | str, record: int, new_name: str) -> None:
    """Put a freed MFT record back into use under a different name.

    This is a **fixture operation**, and it is written out rather than obtained
    by asking a tool because no unprivileged tool will do it: ``ntfscp``
    allocates a fresh record for every file it writes and never reuses a freed
    one, so the state cannot be reached by writing files.

    The state itself is ordinary. NTFS reuses a freed record as soon as it
    needs one, and when it does it sets the in-use flag, increments the
    record's sequence number, and writes the new file's ``$FILE_NAME``. This
    reproduces exactly those three changes. The point is what it does to the
    *old* file: its name may still be sitting in the parent's ``$I30`` slack,
    and that name is now the only surviving trace of it - the record behind it
    describes somebody else's file.

    ``new_name`` must be the same length as the old one so the record's
    attribute layout does not have to be rebuilt.
    """
    path = Path(image)
    with open(path, "r+b") as handle:
        boot = handle.read(512)
        geometry = _ntfs_geometry(boot)
        handle.seek(geometry.mft_offset)
        first = bytearray(handle.read(geometry.record_size))
        runs: list[tuple[int, int]] = []
        if first[:4] == b"FILE" and _apply_fixups(first):
            for attr_type, at, _length in _iter_attributes(bytes(first)):
                if attr_type == _NTFS_ATTR_DATA and first[at + 8]:
                    runs = _decode_runs(bytes(first), at)
                    break
        if not runs:
            runs = [(geometry.mft_offset // geometry.cluster_bytes, 1 << 30)]
        per_cluster = max(geometry.cluster_bytes // geometry.record_size, 1)

        walked = 0
        offset = None
        for lcn, clusters in runs:
            held = clusters * per_cluster
            if lcn >= 0 and record < walked + held:
                offset = (
                    lcn * geometry.cluster_bytes
                    + (record - walked) * geometry.record_size
                )
                break
            walked += held
        if offset is None:
            raise RuntimeError(f"MFT record {record} is outside every $MFT run")

        handle.seek(offset)
        raw = bytearray(handle.read(geometry.record_size))
        if raw[:4] != b"FILE" or not _apply_fixups(raw):
            raise RuntimeError(f"MFT record {record} is not a readable FILE record")

        encoded = new_name.encode("utf-16-le")
        replaced = False
        for attr_type, at, _length in _iter_attributes(bytes(raw)):
            if attr_type != _NTFS_ATTR_FILE_NAME:
                continue
            value_offset = struct.unpack_from("<H", raw, at + 0x14)[0]
            key = at + value_offset
            name_length = raw[key + 0x40]
            if name_length * 2 != len(encoded):
                raise ValueError(
                    f"new_name must be {name_length} characters to fit the "
                    f"existing $FILE_NAME in record {record}"
                )
            raw[key + 0x42 : key + 0x42 + len(encoded)] = encoded
            replaced = True
        if not replaced:
            raise RuntimeError(f"MFT record {record} has no $FILE_NAME to rewrite")

        flags = struct.unpack_from("<H", raw, 0x16)[0]
        struct.pack_into("<H", raw, 0x16, flags | _NTFS_RECORD_IN_USE)
        sequence = struct.unpack_from("<H", raw, 0x10)[0]
        struct.pack_into("<H", raw, 0x10, (sequence + 1) & 0xFFFF or 1)

        _reapply_fixups(raw)
        handle.seek(offset)
        handle.write(bytes(raw))


def build_ntfs(
    path: Path | str,
    files: Sequence[PlantedFile],
    *,
    size: int = 64 * MIB,
    reuse_after_delete: Sequence[PlantedFile] = (),
    scratch: Path | None = None,
) -> dict[str, int]:
    """Create an NTFS volume, write every file, then delete the marked ones.

    ``PlantedFile.fragmented`` is **not** honoured here, and asking for it is
    not silently ignored either - :func:`build_ntfs` raises. ``ntfscp`` gives no
    control over allocation, and NTFS looks hard for a single free run before it
    splits a file, so the filler-and-hole trick that reliably fragments a FAT32
    file does not reliably fragment an NTFS one. A builder that claimed to plant
    a fragmented file and usually planted a contiguous one would put a wrong row
    in the manifest, and every recall figure derived from it would inherit the
    error. Fragmented recovery is exercised on FAT32, where the layout can
    actually be forced.

    Returns ``{name: MFT record}`` for the deleted files.
    """
    if any(planted.fragmented for planted in files):
        raise ValueError(
            "build_ntfs cannot force fragmentation; plant the fragmented case "
            "on FAT32, where the allocator can be driven into holes"
        )
    _require("ntfs")
    target = Path(path)
    _blank(target, size)
    _run(["mkfs.ntfs", "-F", "-q", "-L", "SANCTUM", str(target)])

    work = Path(scratch or target.parent / f"{target.stem}-stage")
    work.mkdir(parents=True, exist_ok=True)

    try:
        for planted in files:
            staged = work / planted.name
            staged.write_bytes(planted.data)
            _run(["ntfscp", str(target), str(staged), f"/{planted.name}"])
    finally:
        shutil.rmtree(work, ignore_errors=True)

    deleted = [planted.name for planted in files if planted.deleted]
    records = ntfs_delete(target, deleted) if deleted else {}

    if reuse_after_delete:
        # Written after the deletions, so NTFS allocates them into the MFT
        # records just freed. That is what produces the case fsaware has to get
        # right: a name surviving in $I30 slack whose record now belongs to a
        # different file, so the name is recoverable and the content is not.
        stage = Path(scratch or target.parent / f"{target.stem}-reuse")
        stage.mkdir(parents=True, exist_ok=True)
        try:
            for planted in reuse_after_delete:
                staged = stage / planted.name
                staged.write_bytes(planted.data)
                _run(["ntfscp", str(target), str(staged), f"/{planted.name}"])
        finally:
            shutil.rmtree(stage, ignore_errors=True)
    return records


# --------------------------------------------------------------------------
# FAT32
# --------------------------------------------------------------------------


def _fat32_forget_free_hint(path: Path) -> None:
    """Clear the FSINFO next-free-cluster hint, so allocation scans from zero.

    ``0xFFFFFFFF`` is the value FAT32 defines for "unknown", so this is asking
    the allocator to work it out rather than lying to it.
    """
    with open(path, "r+b") as handle:
        boot = handle.read(512)
        fsinfo_sector = struct.unpack_from("<H", boot, 0x30)[0]
        bytes_per_sector = struct.unpack_from("<H", boot, 0x0B)[0]
        if not fsinfo_sector:
            return
        at = fsinfo_sector * bytes_per_sector
        handle.seek(at)
        info = handle.read(bytes_per_sector)
        if len(info) < 512 or info[:4] != b"RRaA" or info[484:488] != b"rrAa":
            return
        handle.seek(at + 488)
        handle.write(struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF))


def build_fat32(
    path: Path | str,
    files: Sequence[PlantedFile],
    *,
    size: int = 64 * MIB,
    filler_bytes: int = 128 * KIB,
    keep_fillers: bool = False,
    scratch: Path | None = None,
) -> list[PlantedFile]:
    """Create a FAT32 volume through ``mtools``, then delete the marked files.

    A file marked ``fragmented`` is fragmented the way a real volume fragments
    one: the volume is first filled with alternating filler files, every other
    filler is deleted, and the target is then written into the holes that
    leaves. FAT allocates from the first free cluster, so the target lands
    across several holes with live fillers between them - which is exactly the
    state that makes the contiguity assumption *provably* wrong, because the
    clusters in between are still allocated to files that exist.

    **Returns the filler files**, with their own deleted flags. They are not
    scaffolding to be ignored: a deleted filler is a deleted file, recovery
    finds it, and a manifest that omitted it would count several hundred
    correct recoveries as false positives and report FAT precision near zero.
    """
    _require("fat32")
    target = Path(path)
    _blank(target, size)
    _run(["mkfs.vfat", "-F", "32", "-n", "SANCTUM", str(target)])

    work = Path(scratch or target.parent / f"{target.stem}-stage")
    work.mkdir(parents=True, exist_ok=True)
    environment = {"MTOOLS_SKIP_CHECK": "1"}

    def copy_in(name: str, data: bytes) -> None:
        staged = work / name
        staged.write_bytes(data)
        _run(["mcopy", "-i", str(target), str(staged), f"::/{name}"], env=environment)

    def remove(name: str) -> None:
        _run(["mdel", "-i", str(target), f"::/{name}"], env=environment)

    try:
        plain = [item for item in files if not item.fragmented]
        fragmented = [item for item in files if item.fragmented]
        fillers: list[PlantedFile] = []

        for item in plain:
            copy_in(item.name, item.data)

        if fragmented:
            # Fill the volume to capacity first. Leaving any contiguous free
            # space at the end would defeat the whole exercise: FAT allocates
            # from the first free cluster, but a target that fits in the tail
            # still comes out contiguous, and the corpus would claim to contain
            # a fragmented file that is not one.
            filler_count = 0
            while filler_count < 4096:
                payload = bytes([filler_count & 0xFF]) * filler_bytes
                try:
                    copy_in(f"fill{filler_count:04d}.pad", payload)
                except RuntimeError:
                    break
                fillers.append(
                    PlantedFile(f"fill{filler_count:04d}.pad", payload)
                )
                filler_count += 1
            if filler_count < 8:
                raise RuntimeError(
                    "FAT32 image is too small to fragment anything in; give "
                    "build_fat32 a larger size or a smaller filler_bytes"
                )
            # Every other filler goes, leaving holes of exactly filler_bytes
            # with a live file between each pair.
            for index in range(0, filler_count, 2):
                remove(f"fill{index:04d}.pad")
                fillers[index] = PlantedFile(
                    fillers[index].name, fillers[index].data, deleted=True
                )
            # FAT32 keeps a "next free cluster" hint in FSINFO, and mtools
            # trusts it. After filling the volume that hint points at the end,
            # so the target would be allocated past every hole - contiguously,
            # off the end of the volume, and not fragmented at all. Clearing
            # the hint forces the allocator to scan from the first cluster,
            # which is where the holes are.
            _fat32_forget_free_hint(target)
            for item in fragmented:
                if len(item.data) <= filler_bytes:
                    raise RuntimeError(
                        f"{item.name} is {len(item.data)} bytes and fits in one "
                        f"{filler_bytes}-byte hole, so it would not fragment"
                    )
                copy_in(item.name, item.data)
            if not keep_fillers:
                # Delete the fillers the target was threaded between. This is
                # the case that actually defeats FAT recovery, and it is the
                # ordinary one: on a real volume files are deleted all the
                # time. While the neighbours are live, TSK reconstructs a
                # fragmented file by skipping the clusters they own and often
                # gets it exactly right. Once they are deleted too, their freed
                # clusters look exactly like the target's, get pulled into the
                # reconstruction, and the result is wrong - with nothing on the
                # volume able to say so.
                for index in range(1, filler_count, 2):
                    remove(f"fill{index:04d}.pad")
                    fillers[index] = PlantedFile(
                        fillers[index].name, fillers[index].data, deleted=True
                    )

        for item in files:
            if item.deleted:
                remove(item.name)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return fillers


# --------------------------------------------------------------------------
# exFAT
# --------------------------------------------------------------------------
#
# Fedora ships no unprivileged way to put a file into an exFAT image. There is
# no fuse-exfat package, and exfatprogs provides mkfs.exfat, exfatlabel and
# fsck.exfat but nothing that writes a file. Mounting the kernel driver needs
# root. So the directory entries, the FAT chains and the allocation bitmap are
# written here from the specification - and fsck.exfat is run over the result,
# so "these are valid exFAT volumes" is a checked claim rather than a hope.
#
# Writing it by hand also buys the thing that makes exFAT worth testing: full
# control of the NoFatChain flag, so the corpus can contain both a genuinely
# contiguous file and a chained one and the recovery can be judged on each.

_EXFAT_ENTRY_FILE = 0x85
_EXFAT_ENTRY_STREAM = 0xC0
_EXFAT_ENTRY_NAME = 0xC1
_EXFAT_ENTRY_BITMAP = 0x81


def _exfat_set_checksum(entries: bytes) -> int:
    """The 16-bit checksum over a directory entry set.

    Bytes 2 and 3 of the first entry are skipped: that is where the checksum
    itself lives.
    """
    checksum = 0
    for index, byte in enumerate(entries):
        if index in (2, 3):
            continue
        checksum = (((checksum << 15) | (checksum >> 1)) + byte) & 0xFFFF
    return checksum


def _exfat_name_hash(name: str) -> int:
    """The 16-bit hash exFAT keeps beside a name, over the up-cased name."""
    raw = name.upper().encode("utf-16-le")
    value = 0
    for byte in raw:
        value = (((value << 15) | (value >> 1)) + byte) & 0xFFFF
    return value


def _exfat_time(when: int = 0x5A000000) -> int:
    """A fixed, valid exFAT timestamp. Determinism beats realism in a corpus."""
    return when


def build_exfat(
    path: Path | str,
    files: Sequence[PlantedFile],
    *,
    size: int = 64 * MIB,
    contiguous: Sequence[str] = (),
    check: bool = True,
) -> dict[str, bool]:
    """Create an exFAT volume and write the entries by hand.

    ``contiguous`` names the files to store as one run with ``NoFatChain`` set.
    Every other file gets a real FAT chain, and is deliberately laid out
    non-contiguously so that the two cases differ on disk and not only in a
    flag.

    Returns ``{name: no_fat_chain}`` so the caller can record which case each
    file exercised.
    """
    _require("exfat")
    target = Path(path)
    _blank(target, size)
    _run(["mkfs.exfat", "-L", "SANCTUM", str(target)])

    wants_contiguous = set(contiguous)
    result: dict[str, bool] = {}

    with open(target, "r+b") as handle:
        boot = handle.read(512)
        if boot[3:11] != b"EXFAT   ":
            raise RuntimeError(f"{target} is not exFAT")
        fat_offset_sectors, _fat_length, heap_sectors, cluster_count, root_cluster = (
            struct.unpack_from("<IIIII", boot, 0x50)
        )
        bytes_per_sector = 1 << boot[0x6C]
        cluster_bytes = bytes_per_sector << boot[0x6D]
        fat_offset = fat_offset_sectors * bytes_per_sector
        heap_offset = heap_sectors * bytes_per_sector

        def cluster_at(cluster: int) -> int:
            return heap_offset + (cluster - 2) * cluster_bytes

        def read_cluster(cluster: int) -> bytes:
            handle.seek(cluster_at(cluster))
            return handle.read(cluster_bytes)

        def set_fat(cluster: int, value: int) -> None:
            handle.seek(fat_offset + cluster * 4)
            handle.write(struct.pack("<I", value))

        # The allocation bitmap announces itself in the root directory.
        root = read_cluster(root_cluster)
        bitmap_cluster = 0
        bitmap_length = 0
        directory_end = 0
        for at in range(0, len(root), 32):
            entry_type = root[at]
            if entry_type == 0:
                directory_end = at
                break
            if entry_type == _EXFAT_ENTRY_BITMAP:
                bitmap_cluster, raw_length = struct.unpack_from("<IQ", root, at + 0x14)
                bitmap_length = int(raw_length)
        if not bitmap_cluster:
            raise RuntimeError("no allocation bitmap in the exFAT root directory")
        bitmap_at = cluster_at(bitmap_cluster)

        def bitmap_get(cluster: int) -> bool:
            bit = cluster - 2
            handle.seek(bitmap_at + bit // 8)
            byte = handle.read(1)
            return bool(byte) and bool(byte[0] & (1 << (bit % 8)))

        def bitmap_set(cluster: int, allocated: bool) -> None:
            bit = cluster - 2
            at = bitmap_at + bit // 8
            handle.seek(at)
            current = handle.read(1) or b"\x00"
            mask = 1 << (bit % 8)
            value = current[0] | mask if allocated else current[0] & ~mask
            handle.seek(at)
            handle.write(bytes([value]))

        def find_free(count: int, *, adjacent: bool) -> list[int]:
            """Allocate clusters, contiguously or deliberately scattered."""
            limit = min(cluster_count + 2, 2 + bitmap_length * 8)
            found: list[int] = []
            cluster = 2
            while cluster < limit and len(found) < count:
                if bitmap_get(cluster):
                    cluster += 1
                    continue
                if adjacent:
                    run = []
                    probe = cluster
                    while probe < limit and len(run) < count and not bitmap_get(probe):
                        run.append(probe)
                        probe += 1
                    if len(run) == count:
                        return run
                    cluster = probe + 1
                    continue
                found.append(cluster)
                # Leave a gap, so a chained file is genuinely fragmented and a
                # contiguous read of it returns the wrong bytes.
                cluster += 2
            if len(found) < count:
                raise RuntimeError("exFAT image has no room left")
            return found

        cursor = directory_end
        pending_deletes: list[tuple[int, bytes, tuple[int, ...], bool]] = []
        for planted in files:
            no_chain = planted.name in wants_contiguous
            needed = max(1, -(-len(planted.data) // cluster_bytes))
            clusters = find_free(needed, adjacent=no_chain)

            remaining = planted.data
            for index, cluster in enumerate(clusters):
                handle.seek(cluster_at(cluster))
                handle.write(remaining[:cluster_bytes].ljust(cluster_bytes, b"\x00"))
                remaining = remaining[cluster_bytes:]
                bitmap_set(cluster, True)
                if not no_chain:
                    following = (
                        clusters[index + 1] if index + 1 < len(clusters) else 0xFFFFFFFF
                    )
                    set_fat(cluster, following)

            name = planted.name
            secondary = 1 + -(-len(name) // 15)
            file_entry = bytearray(32)
            file_entry[0] = _EXFAT_ENTRY_FILE
            file_entry[1] = secondary
            struct.pack_into("<H", file_entry, 4, 0x20)  # archive
            struct.pack_into(
                "<III", file_entry, 8, _exfat_time(), _exfat_time(), _exfat_time()
            )

            stream = bytearray(32)
            stream[0] = _EXFAT_ENTRY_STREAM
            stream[1] = 0x01 | (0x02 if no_chain else 0x00)
            stream[3] = len(name)
            struct.pack_into("<H", stream, 4, _exfat_name_hash(name))
            struct.pack_into("<Q", stream, 8, len(planted.data))
            struct.pack_into("<I", stream, 0x14, clusters[0])
            struct.pack_into("<Q", stream, 0x18, len(planted.data))

            name_entries = bytearray()
            encoded = name.encode("utf-16-le")
            for start in range(0, len(encoded), 30):
                chunk = bytearray(32)
                chunk[0] = _EXFAT_ENTRY_NAME
                chunk[2:32] = encoded[start : start + 30].ljust(30, b"\x00")
                name_entries += chunk

            entry_set = bytes(file_entry) + bytes(stream) + bytes(name_entries)
            struct.pack_into(
                "<H", file_entry, 2, _exfat_set_checksum(entry_set)
            )
            entry_set = bytes(file_entry) + bytes(stream) + bytes(name_entries)

            handle.seek(cluster_at(root_cluster) + cursor)
            handle.write(entry_set)
            cursor += len(entry_set)
            if cursor + 128 > cluster_bytes:
                raise RuntimeError("exFAT root directory is full")

            if planted.deleted:
                # Deferred: freeing this file's clusters now would let the very
                # next file be allocated straight over the content this corpus
                # exists to try to recover.
                pending_deletes.append(
                    (cursor - len(entry_set), entry_set, tuple(clusters), no_chain)
                )

            result[planted.name] = no_chain

        for entry_at, entry_set, clusters, no_chain in pending_deletes:
            # The driver clears the in-use bit on every entry of the set, frees
            # the bitmap bits, and zeroes the FAT chain.
            cleared = bytearray(entry_set)
            for at in range(0, len(cleared), 32):
                cleared[at] &= 0x7F
            handle.seek(cluster_at(root_cluster) + entry_at)
            handle.write(bytes(cleared))
            for cluster in clusters:
                bitmap_set(cluster, False)
                if not no_chain:
                    set_fat(cluster, 0)

    if check:
        # exfatprogs exits non-zero on a dirty volume, so this is a real check
        # that the entries written above are ones the reference tool accepts.
        _run(["fsck.exfat", "-n", str(target)])
    return result


# --------------------------------------------------------------------------
# ext2 / ext3 / ext4
# --------------------------------------------------------------------------


def _debugfs(image: Path, commands: Sequence[str], *, write: bool = True) -> str:
    """Run a debugfs request list against an unmounted image.

    debugfs reports most failures on stdout with a zero exit status, so the
    output is returned for the caller to check rather than trusted.
    """
    # debugfs takes a single -R, so a list of requests is a list of runs.
    output = []
    for command in commands:
        output.append(
            _run(
                ["debugfs", *(["-w"] if write else []), "-R", command, str(image)]
            )
        )
    return "\n".join(output)


def build_ext(
    path: Path | str,
    files: Sequence[PlantedFile],
    *,
    kind: str = "ext4",
    size: int = 64 * MIB,
    scratch: Path | None = None,
) -> dict[str, int]:
    """Create an ext2/ext3/ext4 volume through ``debugfs`` and delete files.

    Deletion is modelled as the kernel performs it, which differs between ext4
    and its predecessors and is the entire reason their recall differs:

    * **ext2 and ext3**: unlink, free the blocks, set ``i_dtime``. The block
      pointers stay in the inode, so the content is recoverable from it.
      That is exactly true of ext2. For ext3 it is an upper bound - a Linux
      2.6 or later kernel also runs ``ext3_truncate``, which zeroes
      ``i_block`` - and the limitation is recorded rather than papered over.
    * **ext4**: the same, **plus zeroing the inode's extent tree**, which is
      what ``ext4_ext_remove_space`` does on unlink. ``debugfs rm`` does not do
      this on its own; an ext4 corpus built without it would leave the extent
      tree intact, make ext4 undelete look like NTFS, and produce a recall
      figure that is simply false.

    Returns ``{name: inode}`` for every file written.
    """
    _require(kind)
    target = Path(path)
    _blank(target, size)
    _run([f"mkfs.{kind}", "-q", "-F", str(target)])

    work = Path(scratch or target.parent / f"{target.stem}-stage")
    work.mkdir(parents=True, exist_ok=True)
    inodes: dict[str, int] = {}
    try:
        for planted in files:
            staged = work / planted.name
            staged.write_bytes(planted.data)
            output = _run(
                ["debugfs", "-w", "-R", f"write {staged} {planted.name}", str(target)]
            )
            for line in output.splitlines():
                if line.startswith("Allocated inode:"):
                    inodes[planted.name] = int(line.split(":")[1])
        for planted in files:
            if not planted.deleted:
                continue
            inode = inodes[planted.name]
            commands = [f"rm {planted.name}", f"kill_file <{inode}>"]
            if kind == "ext4":
                # ext4_ext_remove_space zeroes the whole of i_block, header
                # included. Without this the corpus would not be ext4.
                commands += [f"sif <{inode}> block[{index}] 0" for index in range(15)]
            _debugfs(target, commands)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return inodes


# --------------------------------------------------------------------------
# Partitioning and damage
# --------------------------------------------------------------------------

#: MBR partition type bytes, so a partition announces the filesystem in it.
MBR_TYPES = {
    "ntfs": 0x07,
    "exfat": 0x07,
    "fat32": 0x0C,
    "ext2": 0x83,
    "ext3": 0x83,
    "ext4": 0x83,
}

SECTOR = 512
#: Where the first partition starts, in sectors. 2048 is what every partitioner
#: has used since 2009, and using anything else would make the corpus unlike
#: any disk an examiner will meet.
FIRST_PARTITION_LBA = 2048


def build_two_partition_image(
    path: Path | str,
    parts: Sequence[tuple[Path, str]],
    *,
    gap_sectors: int = 2048,
) -> list[int]:
    """Concatenate filesystem images behind an MBR. Returns their byte offsets.

    The point of this in the corpus is one assertion: that a file in the second
    partition is reported at an offset that addresses the *image*, not the
    partition. That mistake is invisible - every recovered file still opens,
    every hash still matches - until somebody tries to find the bytes again.
    """
    target = Path(path)
    entries: list[tuple[int, int, str]] = []
    lba = FIRST_PARTITION_LBA
    for source, kind in parts:
        sectors = -(-Path(source).stat().st_size // SECTOR)
        entries.append((lba, sectors, kind))
        lba += sectors + gap_sectors

    total = lba * SECTOR
    with open(target, "wb") as out:
        out.truncate(total)
        mbr = bytearray(SECTOR)
        for index, (start, sectors, kind) in enumerate(entries):
            at = 0x1BE + index * 16
            mbr[at] = 0x00
            mbr[at + 1 : at + 4] = b"\xfe\xff\xff"
            mbr[at + 4] = MBR_TYPES.get(kind, 0x83)
            mbr[at + 5 : at + 8] = b"\xfe\xff\xff"
            struct.pack_into("<II", mbr, at + 8, start, sectors)
        mbr[510:512] = b"\x55\xaa"
        out.write(bytes(mbr))
        for (start, _sectors, _kind), (source, _) in zip(entries, parts, strict=True):
            # Copied a megabyte at a time, skipping all-zero chunks, so a
            # partition image that was sparse stays sparse inside the combined
            # image. Reading each source whole would materialise every hole and
            # multiply the corpus's footprint in tmpfs.
            with open(source, "rb") as reader:
                while True:
                    offset = reader.tell()
                    chunk = reader.read(_SPARSE_CHUNK)
                    if not chunk:
                        break
                    if chunk.strip(b"\x00"):
                        out.seek(start * SECTOR + offset)
                        out.write(chunk)
        out.truncate(total)
    return [start * SECTOR for start, _sectors, _kind in entries]


def damage_boot_sector(path: Path | str, *, offset: int = 0) -> None:
    """Zero a volume's first sector, as a partial wipe or a bad block would."""
    with open(path, "r+b") as handle:
        handle.seek(offset)
        handle.write(b"\x00" * SECTOR)


def damage_partition_table(path: Path | str) -> None:
    """Overwrite the MBR partition entries, leaving the signature in place.

    Deliberately not a zeroed sector: a table full of garbage that still ends
    in ``55 AA`` is the harder case, because a volume system will try to parse
    it and has to fail cleanly rather than return four impossible partitions.
    """
    with open(path, "r+b") as handle:
        handle.seek(0x1BE)
        handle.write(bytes(range(0x40, 0x40 + 64)))
        handle.seek(510)
        handle.write(b"\x55\xaa")


def quick_format(path: Path | str, *, kind: str) -> None:
    """Re-run mkfs over a populated volume, as a quick format does.

    A quick format writes new metadata and leaves every data block untouched,
    which is why it is the case that most flatters a signature carver and most
    embarrasses an undelete: the old records are gone and the old content is
    all still there.
    """
    if kind == "fat32":
        _run(["mkfs.vfat", "-F", "32", "-n", "WIPED", str(path)])
    elif kind == "ntfs":
        _run(["mkfs.ntfs", "-F", "-q", "-L", "WIPED", str(path)])
    elif kind == "exfat":
        _run(["mkfs.exfat", "-L", "WIPED", str(path)])
    else:
        _run([f"mkfs.{kind}", "-q", "-F", str(path)])
