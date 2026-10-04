"""Filesystem-metadata-aware recovery (undelete), read-only.

Carving finds objects by their content. **Undelete** finds them by their
filesystem record, which is a different and usually better kind of evidence:
the record carries the original name, the recorded size and the MAC timestamps,
and it says where the bytes were rather than guessing from a header. These are
the highest-confidence candidates the pipeline produces, and the only ones that
carry a real filename.

What that is worth is not the same on every filesystem, and this module refuses
to average them into one number.

``NTFS``
    The best case, and the demo filesystem. A deleted file's MFT record
    survives with its in-use flag cleared, and its ``$DATA`` run list survives
    with it, so the file is recovered exactly - fragmented or not - and named.
    ``$I30`` index slack is parsed as well: when a record has already been
    reused, the directory entry can still be sitting in the slack of its
    parent's index, which yields **a name with no content**. That is still
    evidence, and it is reported as a candidate with a name, a recorded size
    and zero recoverable bytes. It must never be scored HIGH, because nothing
    about the content was recovered.

``FAT32``
    A deleted entry keeps its start cluster and its size but its **cluster
    chain is destroyed** - the FAT entries are zeroed. Recovery reads the
    recorded size contiguously from the start cluster, which is correct only
    for an unfragmented file. Every such candidate is marked
    ``contiguity_assumed`` and says so; where a cluster in the assumed run is
    allocated to a live file the assumption is provably wrong, and the
    candidate is additionally marked ``contiguity_contradicted``. It is still
    reported: a partial recovery that admits it is partial is evidence.

``exFAT``
    The same shape as FAT32 with one important difference. The stream extension
    directory entry carries a ``NoFatChain`` flag, and when it is set the file
    genuinely *was* contiguous - the FAT held no chain for it even while it was
    live. In that case the contiguous read is a fact rather than an assumption,
    and ``contiguity_assumed`` is false. Which case applied is recorded on
    every exFAT candidate. exFAT is parsed directly here rather than through
    pytsk3, because that flag is what separates a certain recovery from a
    guess and TSK does not expose it.

``ext2`` / ``ext3``
    Full inode-based undelete. The inode keeps its block pointers when the file
    is unlinked, so the content is recovered from the inode.

``ext4``
    **Undelete recovers very little on ext4, by design.** ``ext4_ext_remove_space``
    zeroes the extent tree in the inode when a file is unlinked, so the inode
    survives with its size and timestamps and no pointer to a single block.
    There is nothing to follow. This module parses the jbd2 journal for stale
    copies of inode-table blocks and recovers whatever inodes still hold an
    intact extent tree there, which is real but partial: the journal is a
    circular buffer, so it holds only the recent past, and a file deleted
    before the journal wrapped is gone from it. The measured recall is in
    ``docs/performance/calibration.md`` and it is low. That row is a finding
    about ext4, not a defect in this module, and **ext4 is not demonstrated**.
    Use the signature carver there.

Two structural rules, both of which exist to stop a whole class of silent
error:

**One path to the evidence bytes.** ``pytsk3`` is given
:class:`EvidenceImgInfo`, a ``pytsk3.Img_Info`` subclass whose ``read`` calls
:meth:`EvidenceHandle.read`. It is never handed a path. Nothing in this module
opens a device or an image, and the substitution bookkeeping on the handle
therefore covers filesystem parsing exactly as it covers carving. If pytsk3
opened the file itself, a region the acquisition filled with invented bytes
would be indistinguishable from one it read.

**Offsets are image-absolute.** Every partition is wrapped in
:class:`WindowedEvidence` so its filesystem parses at offset zero, and the
window's base is added back before a candidate is emitted. A candidate offset
from this module addresses the image, not the partition. Getting this wrong is
not a visible failure: it is a report full of offsets that are quietly wrong by
the size of the first partition.
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import pytsk3
import structlog

from core.carve.evidence import EvidenceHandle, WindowedEvidence
from core.carve.signature import load_signatures
from core.models import CarveCandidate, MacTimestamps

__all__ = [
    "EvidenceImgInfo",
    "Extent",
    "PartitionInfo",
    "RecoveredFile",
    "UndeleteReport",
    "undelete",
    "undelete_report",
    "read_recovered",
    "EXT4_EXTENTS_ZEROED",
    "FAT_CHAIN_LOST",
    "EXFAT_NO_FAT_CHAIN",
    "EXFAT_CHAIN_LOST",
    "NTFS_NAME_ONLY",
    "NO_PARTITION_TABLE",
    "PARTITION_TABLE_UNREADABLE",
]

logger = structlog.get_logger(__name__)

KIB = 1024
MIB = 1024 * KIB

#: Cap on a single recovered object. A corrupt size field in a deleted record
#: is common, and a 16 EiB "file" would otherwise be hashed byte by byte.
MAX_RECOVERED_BYTES = 2 * 1024 * MIB

# --------------------------------------------------------------------------
# Limitations, in the operator's words
# --------------------------------------------------------------------------

EXT4_EXTENTS_ZEROED = (
    "EXT4_EXTENTS_ZEROED: ext4 clears the inode's extent tree when a file is "
    "unlinked, so a surviving inode names a file and its size but points at no "
    "blocks at all. Undelete on ext4 recovers metadata, not content. What "
    "content is recovered here comes from stale inode-table blocks still held "
    "in the jbd2 journal, which is a circular buffer covering only the recent "
    "past. Expect a low recovery rate on ext4 and use signature carving over "
    "the unallocated map instead."
)

FAT_CHAIN_LOST = (
    "FAT_CHAIN_LOST: FAT deletion zeroes the file's cluster chain. The start "
    "cluster and the recorded size survive and the layout does not, so the "
    "layout is inferred: the recovery walks forward from the start cluster "
    "taking clusters the FAT currently shows as free, skipping any that a live "
    "file now owns. That reconstruction is right when the file was "
    "unfragmented, and it is also right surprisingly often when it was "
    "fragmented around files that still exist. It is wrong whenever a "
    "neighbouring file was ALSO deleted, because then its freed clusters are "
    "indistinguishable from this file's and get pulled in. Nothing on the "
    "volume can tell those two cases apart, which is why every candidate from "
    "this filesystem is marked contiguity_assumed no matter how clean the "
    "result looks."
)

EXFAT_CHAIN_LOST = (
    "EXFAT_CHAIN_LOST: this file's stream extension had NoFatChain clear, so "
    "it used a FAT chain that deletion destroyed. Recovered contiguously from "
    "the start cluster; contiguity is assumed, not established."
)

EXFAT_NO_FAT_CHAIN = (
    "EXFAT_NO_FAT_CHAIN: this file's stream extension had NoFatChain set, so "
    "exFAT stored it as one contiguous run and kept no chain for it even while "
    "it was live. The contiguous read is therefore a fact about the layout, "
    "not an assumption about it."
)

NTFS_NAME_ONLY = (
    "NTFS_NAME_ONLY: this name was recovered from $I30 index slack. The MFT "
    "record it refers to has already been reused by another file, so the name, "
    "the recorded size and the timestamps survive and none of the content "
    "does. Zero bytes were recovered."
)

NO_PARTITION_TABLE = (
    "NO_PARTITION_TABLE: no partition table was found, so the whole image was "
    "treated as one volume."
)

PARTITION_TABLE_UNREADABLE = (
    "PARTITION_TABLE_UNREADABLE: a partition table was present but could not "
    "be parsed ({reason}). The whole image was treated as one volume and, "
    "where no filesystem could be opened either, the unallocated map covers "
    "the entire image so that signature carving still runs over all of it."
)

NO_FILESYSTEM = (
    "NO_FILESYSTEM: no filesystem could be opened in {where} ({reason}). "
    "Nothing was recovered from metadata there and the region is reported "
    "unallocated in full, so signature carving covers it."
)


# --------------------------------------------------------------------------
# The one path to the evidence bytes
# --------------------------------------------------------------------------


class EvidenceImgInfo(pytsk3.Img_Info):  # type: ignore[misc]
    """A ``pytsk3.Img_Info`` backed by an :class:`EvidenceHandle`.

    This exists so there is exactly one path to the evidence bytes. pytsk3 will
    happily open an image by path, and if it did, three things this codebase
    guarantees would quietly stop being true inside filesystem parsing: the
    read-only open, the block cache, and above all the substitution record - a
    region the acquisition filled with invented bytes would come back through
    TSK looking exactly like a region that was read.

    ``reads`` and ``bytes_read`` are counted so a test can assert that TSK's
    traffic went through the handle rather than around it.
    """

    def __init__(self, handle: EvidenceHandle) -> None:
        self._handle = handle
        #: Number of ``read`` calls TSK has made through this shim.
        self.reads = 0
        #: Bytes TSK has taken through this shim.
        self.bytes_read = 0
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self) -> None:
        """Never closes the handle: the handle outlives this shim and may be
        shared by several windows."""

    def read(self, offset: int, size: int) -> bytes:
        self.reads += 1
        data = self._handle.read(offset, size)
        self.bytes_read += len(data)
        return data

    def get_size(self) -> int:
        return int(self._handle.size)


# --------------------------------------------------------------------------
# Result types
# --------------------------------------------------------------------------


@dataclass(frozen=True, order=True)
class Extent:
    """A byte range in the image. Always image-absolute, never window-relative."""

    offset: int
    length: int

    @property
    def end(self) -> int:
        """First byte after the extent."""
        return self.offset + self.length


@dataclass(frozen=True)
class PartitionInfo:
    """One partition, as the volume system described it."""

    index: int
    #: Image-absolute byte offset of the partition's first byte.
    offset: int
    length: int
    description: str
    allocated: bool
    #: Filesystem opened there, e.g. ``ntfs``. Empty when none could be opened.
    fs_type: str = ""
    #: The filesystem's allocation unit in bytes, read from its own boot sector
    #: or superblock. 0 when no filesystem was opened or the field is not a
    #: power of two of at least 512, which is what "unknown" looks like to the
    #: reassembler.
    cluster_bytes: int = 0


@dataclass(frozen=True)
class RecoveredFile:
    """A candidate together with where its bytes actually live.

    :class:`~core.models.CarveCandidate` describes one contiguous range, which
    is the right shape for a carved object and the wrong shape for a fragmented
    NTFS file. The extents are kept beside it so :func:`read_recovered` can
    reassemble the real content through the evidence handle, and so a report
    can show that a file came back in nine pieces.
    """

    candidate: CarveCandidate
    #: Image-absolute, in file order. Empty for a name-only recovery.
    extents: tuple[Extent, ...]


@dataclass
class UndeleteReport:
    """Everything one undelete pass established about an image.

    The allocated and unallocated maps are returned rather than left for the
    caller to recompute, because the caller would have to re-parse every
    filesystem to do it and would get a different answer if it drifted.
    """

    files: list[RecoveredFile] = field(default_factory=list)
    partitions: list[PartitionInfo] = field(default_factory=list)
    #: Image-absolute ranges claimed by a live file or by filesystem metadata.
    allocated: list[Extent] = field(default_factory=list)
    #: Image-absolute ranges nothing live claims. Hand these to the signature
    #: carver: they are where deleted content with no surviving record lives.
    unallocated: list[Extent] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    #: True when no volume system or no filesystem could be read and the pass
    #: fell back to treating the image as one undifferentiated region.
    degraded_to_whole_image: bool = False
    #: How many reads TSK made through :class:`EvidenceImgInfo`. Reported so a
    #: test can assert that filesystem parsing went through the evidence handle
    #: rather than around it.
    image_reads: int = 0

    @property
    def candidates(self) -> list[CarveCandidate]:
        return [item.candidate for item in self.files]


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------


def _merge(extents: Sequence[Extent]) -> list[Extent]:
    """Sort and coalesce touching or overlapping ranges."""
    ordered = sorted(item for item in extents if item.length > 0)
    merged: list[Extent] = []
    for item in ordered:
        if merged and item.offset <= merged[-1].end:
            end = max(merged[-1].end, item.end)
            merged[-1] = Extent(merged[-1].offset, end - merged[-1].offset)
            continue
        merged.append(item)
    return merged


def _complement(covered: Sequence[Extent], start: int, end: int) -> list[Extent]:
    """Everything in ``[start, end)`` that ``covered`` does not claim."""
    out: list[Extent] = []
    cursor = start
    for item in _merge(covered):
        if item.end <= start or item.offset >= end:
            continue
        if item.offset > cursor:
            out.append(Extent(cursor, item.offset - cursor))
        cursor = max(cursor, item.end)
    if cursor < end:
        out.append(Extent(cursor, end - cursor))
    return out


_MIME_BY_EXT: dict[str, str] | None = None


def _mime_for(ext: str) -> str:
    """The signature table's MIME for an extension, or the generic one."""
    global _MIME_BY_EXT
    if _MIME_BY_EXT is None:
        _MIME_BY_EXT = {
            signature.ext: signature.mime for signature in load_signatures()
        }
    return _MIME_BY_EXT.get(ext.lower(), "application/octet-stream")


def _ext_of(name: str) -> str:
    """The extension a filesystem name claims, lower-cased and without a dot.

    Taken from the name because that is what the filesystem recorded. It is a
    claim, not a verdict: validation downstream decides whether the bytes agree.
    """
    _, _, suffix = name.rpartition(".")
    if not suffix or suffix == name or len(suffix) > 8 or not suffix.isalnum():
        return "bin"
    return suffix.lower()


def _utc(seconds: int | None, nanos: int = 0) -> datetime | None:
    """A UTC datetime, or None when the record did not carry the field.

    Zero is treated as absent. Every filesystem here writes zero into a
    timestamp it never set, and reporting 1970-01-01 as an observation would
    put a fabricated row in a timeline.
    """
    if not seconds:
        return None
    try:
        return datetime.fromtimestamp(seconds + nanos / 1_000_000_000, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


# --------------------------------------------------------------------------
# NTFS: enough of the on-disk layout to read $I30 index slack
# --------------------------------------------------------------------------
#
# pytsk3 walks the MFT and resolves $DATA runs, which is the hard part and is
# used for exactly that below. What it does not expose is the *slack* of a
# directory index. When a file is deleted, its entry is removed from the parent
# directory's $I30 index by shrinking the index header's used length; the
# entry's bytes usually stay where they were, now beyond the used length. If
# the file's MFT record is later reused by another file, that slack entry is
# the only surviving record of the original name. Reading it needs the raw
# structures, so they are here.


#: NTFS ``FILE`` record magic. A record that does not start with it was never
#: written, or was overwritten by something that is not an MFT record.
NTFS_FILE_MAGIC = b"FILE"
NTFS_INDX_MAGIC = b"INDX"

NTFS_ATTR_FILE_NAME = 0x30
NTFS_ATTR_INDEX_ROOT = 0x90
NTFS_ATTR_INDEX_ALLOCATION = 0xA0

#: Namespace 2 is the 8.3 short name. It is a second name for the same file,
#: so reporting it as well would double-count every recovered entry.
NTFS_NAMESPACE_DOS = 2

#: NTFS timestamps are 100 ns intervals since 1601-01-01 UTC. This is the gap
#: to the Unix epoch, in the same units.
NTFS_EPOCH_DELTA_100NS = 116_444_736_000_000_000


def _ntfs_time(raw: int) -> datetime | None:
    """Convert an NTFS FILETIME to UTC, or None when it was never set."""
    if raw <= 0:
        return None
    seconds, remainder = divmod(raw - NTFS_EPOCH_DELTA_100NS, 10_000_000)
    return _utc(seconds, remainder * 100)


def _apply_fixups(record: bytearray, sector_size: int) -> bool:
    """Undo the update-sequence substitution in place.

    NTFS replaces the last two bytes of every sector of a multi-sector
    structure with a check value, and keeps the originals in an array in the
    header. A record read without reversing that has two wrong bytes per
    sector, which is exactly enough to make a name or a length silently wrong.

    Returns False when the check values do not match, which means the record
    was torn or is not a record at all.
    """
    if len(record) < 8:
        return False
    usa_offset, usa_count = struct.unpack_from("<HH", record, 4)
    if usa_count < 1 or usa_offset + usa_count * 2 > len(record):
        return False
    check = record[usa_offset : usa_offset + 2]
    for index in range(1, usa_count):
        end = index * sector_size - 2
        if end + 2 > len(record):
            return False
        if record[end : end + 2] != check:
            return False
        original = record[usa_offset + index * 2 : usa_offset + index * 2 + 2]
        record[end : end + 2] = original
    return True


@dataclass(frozen=True)
class _IndexName:
    """A ``$FILE_NAME`` key recovered from an index entry."""

    name: str
    #: MFT entry the index pointed at, or ``None`` when the entry's 16-byte
    #: header no longer survives - which is the common case, because the end
    #: marker NTFS writes when it shrinks an index lands exactly there.
    mft_entry: int | None
    sequence: int | None
    real_size: int
    allocated_size: int
    mac: MacTimestamps


#: Plausible bounds for a FILETIME in a $FILE_NAME key, used to reject random
#: bytes. 1990-01-01 and 2100-01-01 in 100 ns units since 1601.
_FILETIME_FLOOR = 119_600_064_000_000_000
_FILETIME_CEILING = 157_472_640_000_000_000

#: Characters NTFS does not allow in a name. Finding one means the bytes are
#: not a name, whatever else they satisfied.
_ILLEGAL_NAME_CHARS = frozenset('\\/:*?"<>|')


def _parse_filename_key(data: bytes, at: int) -> _IndexName | None:
    """Validate and read a ``$FILE_NAME`` attribute value at ``at``.

    Every check here exists to keep random slack bytes from becoming a
    fabricated filename in a report. A key must have a plausible parent
    reference, a namespace NTFS defines, a name length that fits, at least one
    timestamp inside a believable range, and a name that decodes without
    control or illegal characters. Bytes clearing all five are a name.
    """
    if at + 0x42 > len(data):
        return None
    parent_ref = struct.unpack_from("<Q", data, at)[0]
    parent_entry = parent_ref & 0x0000_FFFF_FFFF_FFFF
    if not 1 <= parent_entry < (1 << 32):
        return None

    crtime, mtime, ctime, atime, allocated_size, real_size = struct.unpack_from(
        "<QQQQQQ", data, at + 8
    )
    if not any(
        _FILETIME_FLOOR <= stamp <= _FILETIME_CEILING
        for stamp in (crtime, mtime, ctime, atime)
    ):
        return None
    if real_size > allocated_size + (1 << 20) or real_size > MAX_RECOVERED_BYTES:
        return None

    name_length = data[at + 0x40]
    namespace = data[at + 0x41]
    if not 1 <= name_length <= 255 or namespace > 3:
        return None
    if namespace == NTFS_NAMESPACE_DOS:
        return None
    end = at + 0x42 + name_length * 2
    if end > len(data):
        return None
    try:
        name = data[at + 0x42 : end].decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    if not name or any(character < " " for character in name):
        return None
    if any(character in _ILLEGAL_NAME_CHARS for character in name):
        return None

    return _IndexName(
        name=name,
        mft_entry=None,
        sequence=None,
        real_size=int(real_size),
        allocated_size=int(allocated_size),
        mac=MacTimestamps(
            modified=_ntfs_time(mtime),
            accessed=_ntfs_time(atime),
            changed=_ntfs_time(ctime),
            created=_ntfs_time(crtime),
        ),
    )


def _entry_header_at(data: bytes, key_at: int) -> tuple[int, int] | None:
    """The MFT reference from the index-entry header preceding a key, if intact.

    NTFS removes an entry by moving the entries after it down and shrinking the
    header's used length, which usually leaves the *last* entry's bytes in
    slack complete. It shrinks a trailing entry by writing the end marker over
    that entry's own 16-byte header, which destroys the reference and leaves
    the key. Both happen, so the reference is read when it is there and
    reported absent when it is not - never guessed.
    """
    at = key_at - 0x10
    if at < 0:
        return None
    file_ref, entry_length, key_length, _flags = struct.unpack_from("<QHHH", data, at)
    if key_length < 0x42 or entry_length < 0x10 + key_length:
        return None
    if at + entry_length > len(data):
        return None
    entry = file_ref & 0x0000_FFFF_FFFF_FFFF
    if not 1 <= entry < (1 << 32):
        return None
    return entry, file_ref >> 48


def _index_slack_names(node: bytes, node_start: int) -> list[_IndexName]:
    """Every ``$FILE_NAME`` key sitting *past* the index header's used length.

    Entries before ``index_length`` are live and belong to files that still
    exist. Everything from there to ``allocated_size`` is slack, and that is
    where a deleted entry's bytes remain.

    The slack is *scanned* on an 8-byte grid rather than walked as a chain of
    entries. Walking assumes each entry's header survives, and the header is
    the one part that reliably does not: NTFS writes its new end marker over
    exactly those 16 bytes. Scanning finds the key regardless, and
    :func:`_entry_header_at` recovers the MFT reference where it is still there.
    """
    if node_start + 16 > len(node):
        return []
    entries_offset, used_length, allocated_size = struct.unpack_from(
        "<III", node, node_start
    )
    if entries_offset <= 0:
        return []
    live_end = node_start + used_length
    slack_end = min(node_start + allocated_size, len(node))
    if live_end >= slack_end:
        return []

    found: list[_IndexName] = []
    seen: set[str] = set()
    for at in range(live_end, slack_end - 0x42 + 1, 8):
        key = _parse_filename_key(node, at)
        if key is None or key.name in seen:
            continue
        seen.add(key.name)
        reference = _entry_header_at(node, at)
        if reference is not None:
            key = _IndexName(
                name=key.name,
                mft_entry=reference[0],
                sequence=reference[1],
                real_size=key.real_size,
                allocated_size=key.allocated_size,
                mac=key.mac,
            )
        found.append(key)
    return found


def _ntfs_slack_names(fs: Any, image: EvidenceHandle, base: int) -> list[_IndexName]:
    """Walk every directory's $I30 and collect the names left in its slack.

    ``base`` is the partition's image-absolute offset and is used only for
    logging; the index contents are read through ``fs``, which is already
    reading through the shim.
    """
    del image, base
    found: list[_IndexName] = []
    first = int(fs.info.first_inum)
    last = int(fs.info.last_inum)
    for inode in range(first, min(last, first + _MFT_SCAN_CAP) + 1):
        try:
            entry = fs.open_meta(inode=inode)
        except OSError:
            continue
        meta = entry.info.meta
        if meta is None or meta.type != pytsk3.TSK_FS_META_TYPE_DIR:
            continue
        for attribute in entry:
            info = attribute.info
            if info.type == NTFS_ATTR_INDEX_ROOT:
                node = _read_attribute(entry, info)
                # The INDEX_ROOT attribute begins with a 16-byte header of its
                # own; the INDEX_HEADER the slack walk needs follows it.
                found.extend(_index_slack_names(node, 0x10))
            elif info.type == NTFS_ATTR_INDEX_ALLOCATION:
                found.extend(_indx_slack_names(_read_attribute(entry, info)))
    return found


def _indx_slack_names(data: bytes) -> list[_IndexName]:
    """Slack names from every INDX record in an $INDEX_ALLOCATION run."""
    found: list[_IndexName] = []
    for start in range(0, len(data) - 0x18, _INDX_RECORD_BYTES):
        block = bytearray(data[start : start + _INDX_RECORD_BYTES])
        if bytes(block[:4]) != NTFS_INDX_MAGIC:
            continue
        if not _apply_fixups(block, _NTFS_SECTOR_BYTES):
            continue
        # In an INDX record the INDEX_HEADER sits at 0x18.
        found.extend(_index_slack_names(bytes(block), 0x18))
    return found


#: Standard INDX record size. NTFS records it in $INDEX_ROOT; every volume
#: mkfs.ntfs produces uses 4096, and a wrong guess only costs slack names.
_INDX_RECORD_BYTES = 4096
_NTFS_SECTOR_BYTES = 512

#: Upper bound on the MFT range scanned for directories and orphans. A full
#: MFT on a terabyte volume holds millions of records; the corpus and any demo
#: image sit far below this, and an unbounded walk would turn a triage pass
#: into an overnight job.
_MFT_SCAN_CAP = 200_000


@dataclass(frozen=True)
class _MftMap:
    """Where MFT records live, so a resident attribute can be addressed.

    ``$MFT`` is contiguous only while it is small. Once a volume holds a few
    hundred files NTFS extends it elsewhere, and ``mft_start + n * record_size``
    starts addressing unrelated data - quietly, because the result is simply
    not a ``FILE`` record and the file "is not found".
    """

    runs: tuple[tuple[int, int], ...]
    cluster_bytes: int
    record_bytes: int

    def offset_of(self, record: int) -> int | None:
        """Volume-relative byte offset of one MFT record."""
        per_cluster = max(self.cluster_bytes // self.record_bytes, 1)
        walked = 0
        for lcn, clusters in self.runs:
            held = clusters * per_cluster
            if record < walked + held:
                return lcn * self.cluster_bytes + (record - walked) * self.record_bytes
            walked += held
        return None


def _read_mft_map(volume: EvidenceHandle) -> _MftMap | None:
    """Read the geometry and ``$MFT`` run list straight from the boot sector."""
    boot = volume.read(0, 512)
    if len(boot) < 512 or boot[3:11] != b"NTFS    ":
        return None
    bytes_per_sector = struct.unpack_from("<H", boot, 0x0B)[0]
    sectors_per_cluster = boot[0x0D]
    mft_lcn = struct.unpack_from("<Q", boot, 0x30)[0]
    per_record = struct.unpack_from("<b", boot, 0x40)[0]
    if not bytes_per_sector or not sectors_per_cluster:
        return None
    cluster_bytes = bytes_per_sector * sectors_per_cluster
    record_bytes = (
        per_record * cluster_bytes if per_record > 0 else 1 << max(-per_record, 0)
    )
    if record_bytes <= 0 or record_bytes > 64 * KIB:
        return None

    first = bytearray(volume.read(mft_lcn * cluster_bytes, record_bytes))
    runs: list[tuple[int, int]] = []
    if len(first) == record_bytes and bytes(first[:4]) == NTFS_FILE_MAGIC:
        if _apply_fixups(first, bytes_per_sector):
            at = struct.unpack_from("<H", first, 0x14)[0]
            while at + 8 <= len(first):
                attr_type, length = struct.unpack_from("<II", first, at)
                if attr_type == 0xFFFF_FFFF or length < 8 or at + length > len(first):
                    break
                if attr_type == 0x80 and first[at + 8]:
                    runs = _decode_data_runs(bytes(first), at)
                    break
                at += length
    if not runs:
        runs = [(mft_lcn, 1 << 20)]
    return _MftMap(
        runs=tuple(runs), cluster_bytes=cluster_bytes, record_bytes=record_bytes
    )


def _decode_data_runs(record: bytes, at: int) -> list[tuple[int, int]]:
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
        if not offset_bytes:
            runs.append((-1, count))
            continue
        lcn += int.from_bytes(
            record[cursor : cursor + offset_bytes], "little", signed=True
        )
        cursor += offset_bytes
        runs.append((lcn, count))
    return runs


def _resident_data_extents(
    volume: EvidenceHandle, mft: _MftMap, record_number: int, base: int
) -> tuple[list[Extent], int]:
    """Extents for a resident ``$DATA``, threading around the fixup positions.

    A file small enough to fit inside its MFT record has no run list at all -
    its content *is* part of the record. Ignoring that case loses every small
    file on the volume, which on a real disk is most of the files.

    The complication is the update sequence. NTFS overwrites the last two bytes
    of every sector of a record with a check value and keeps the originals in
    an array in the header, so a resident value that spans a sector boundary
    has two bytes of check value sitting in the middle of it *on disk*. Rather
    than read the value through TSK and hand back extents that do not
    reconstruct it, the extents are split around each such position and a
    two-byte extent pointing at the saved original is spliced in. The result
    reads back byte-exact through :func:`read_recovered`, which is what keeps
    ``candidate.sha256`` a claim the caller can check.

    Returns ``(extents, recorded size)``; an empty list means no resident
    ``$DATA`` was found.
    """
    record_at = mft.offset_of(record_number)
    if record_at is None:
        return [], 0
    raw = bytearray(volume.read(record_at, mft.record_bytes))
    if len(raw) < mft.record_bytes or bytes(raw[:4]) != NTFS_FILE_MAGIC:
        return [], 0
    sector = _NTFS_SECTOR_BYTES
    usa_offset, usa_count = struct.unpack_from("<HH", raw, 4)
    if not _apply_fixups(raw, sector):
        return [], 0

    at = struct.unpack_from("<H", raw, 0x14)[0]
    while at + 8 <= len(raw):
        attr_type, length = struct.unpack_from("<II", raw, at)
        if attr_type == 0xFFFF_FFFF or length < 8 or at + length > len(raw):
            break
        if attr_type == 0x80 and not raw[at + 8] and not raw[at + 0x09]:
            value_length = struct.unpack_from("<I", raw, at + 0x10)[0]
            value_offset = struct.unpack_from("<H", raw, at + 0x14)[0]
            start = at + value_offset
            end = start + value_length
            if value_length <= 0 or end > len(raw):
                return [], 0
            pieces: list[tuple[int, int]] = []
            cursor = start
            for index in range(1, usa_count):
                position = index * sector - 2
                if start <= position < end:
                    pieces.append((cursor, position - cursor))
                    pieces.append((usa_offset + index * 2, 2))
                    cursor = position + 2
            pieces.append((cursor, end - cursor))
            extents = [
                Extent(base + record_at + offset, size)
                for offset, size in pieces
                if size > 0
            ]
            return extents, value_length
        at += length
    return [], 0


def _ntfs_record_name(entry: Any) -> str:
    """The long name from a record's own ``$FILE_NAME`` attribute.

    A deleted NTFS file has usually lost its directory entry - the driver
    removes it from the parent's ``$I30`` on unlink - so the directory walk
    finds nothing and TSK reports no name. The name is still in the MFT record
    itself: every file carries a ``$FILE_NAME`` attribute holding the name and
    the parent reference. Reading it is what turns an orphaned record from
    "some bytes" into a named file, which is most of what undelete is for.

    The Win32 name is preferred over the 8.3 short name when both are present,
    because ``BUDGET~1.XLS`` is not what the user called the file.
    """
    best = ""
    best_namespace = -1
    for attribute in entry:
        info = attribute.info
        if info.type != pytsk3.TSK_FS_ATTR_TYPE_NTFS_FNAME:
            continue
        value = _read_attribute(entry, info)
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
        # Namespaces: 0 POSIX, 1 Win32, 2 DOS, 3 Win32+DOS. Anything but the
        # bare DOS name is preferable, and a longer one is more specific.
        rank = 0 if namespace == NTFS_NAMESPACE_DOS else 1
        if rank > best_namespace or (rank == best_namespace and len(name) > len(best)):
            best, best_namespace = name, rank
    return best


def _read_attribute(entry: Any, info: Any) -> bytes:
    """Read one attribute's whole value, resident or not, through TSK."""
    size = int(info.size)
    if size <= 0 or size > MAX_RECOVERED_BYTES:
        return b""
    try:
        return bytes(entry.read_random(0, size, info.type, info.id))
    except OSError:
        return b""


# --------------------------------------------------------------------------
# exFAT: parsed here rather than through pytsk3, for one flag
# --------------------------------------------------------------------------
#
# TSK reads exFAT and finds deleted entries. What it does not report is the
# stream extension's NoFatChain flag, and that flag is the whole difference
# between "recovered, contiguity assumed" and "recovered, and the file
# genuinely was contiguous". On an SD card - the case exFAT exists for - most
# files are written once and NoFatChain is set, so the difference decides
# whether a recovery is a fact or a guess. It is worth 200 lines.

EXFAT_MAGIC = b"EXFAT   "

#: Directory entry type codes, with the in-use bit (0x80) already cleared, so
#: one constant matches a live entry and a deleted one alike.
_EXFAT_TYPE_FILE = 0x05
_EXFAT_TYPE_STREAM = 0x40
_EXFAT_TYPE_NAME = 0x41
_EXFAT_TYPE_BITMAP = 0x01

_EXFAT_IN_USE = 0x80
#: GeneralSecondaryFlags bit 1. Set means exFAT stored the file as one run and
#: kept no FAT chain for it, so the run is a recorded fact.
_EXFAT_NO_FAT_CHAIN = 0x02

#: Bound on a directory walk, so a cross-linked or hostile chain cannot loop.
_EXFAT_MAX_CLUSTERS = 1 << 20


@dataclass(frozen=True)
class ExfatBoot:
    """The fields of the exFAT boot sector this module uses."""

    bytes_per_sector: int
    sectors_per_cluster: int
    fat_offset_sectors: int
    fat_length_sectors: int
    cluster_heap_offset_sectors: int
    cluster_count: int
    root_cluster: int

    @property
    def cluster_bytes(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster

    @property
    def heap_offset(self) -> int:
        return self.cluster_heap_offset_sectors * self.bytes_per_sector

    @property
    def fat_offset(self) -> int:
        return self.fat_offset_sectors * self.bytes_per_sector

    def cluster_offset(self, cluster: int) -> int:
        """Volume-relative byte offset of a cluster. Cluster 2 is the first."""
        return self.heap_offset + (cluster - 2) * self.cluster_bytes


def read_exfat_boot(volume: EvidenceHandle) -> ExfatBoot | None:
    """Parse the exFAT boot sector, or return None when this is not exFAT."""
    sector = volume.read(0, 512)
    if len(sector) < 0x70 or sector[3:11] != EXFAT_MAGIC:
        return None
    (
        fat_offset,
        fat_length,
        heap_offset,
        cluster_count,
        root_cluster,
    ) = struct.unpack_from("<IIIII", sector, 0x50)
    sector_shift = sector[0x6C]
    cluster_shift = sector[0x6D]
    if not 9 <= sector_shift <= 12 or cluster_shift > 25:
        return None
    return ExfatBoot(
        bytes_per_sector=1 << sector_shift,
        sectors_per_cluster=1 << cluster_shift,
        fat_offset_sectors=fat_offset,
        fat_length_sectors=fat_length,
        cluster_heap_offset_sectors=heap_offset,
        cluster_count=cluster_count,
        root_cluster=root_cluster,
    )


def _exfat_time(raw: int, ten_ms: int = 0) -> datetime | None:
    """Convert an exFAT (DOS-shaped) timestamp to UTC.

    exFAT records local time plus a separate UTC-offset byte. The offset is not
    read here, so the value is treated as UTC and that is stated rather than
    quietly assumed - an hour of skew in a timeline is worth knowing about.
    """
    if raw == 0:
        return None
    second = (raw & 0x1F) * 2 + ten_ms // 100
    minute = (raw >> 5) & 0x3F
    hour = (raw >> 11) & 0x1F
    day = (raw >> 16) & 0x1F
    month = (raw >> 21) & 0x0F
    year = ((raw >> 25) & 0x7F) + 1980
    try:
        return datetime(year, month, day, hour, minute, min(second, 59), tzinfo=UTC)
    except ValueError:
        return None


@dataclass(frozen=True)
class ExfatEntry:
    """One exFAT directory entry set, live or deleted."""

    name: str
    first_cluster: int
    data_length: int
    valid_data_length: int
    no_fat_chain: bool
    deleted: bool
    is_directory: bool
    mac: MacTimestamps


def _exfat_read_cluster_chain(
    volume: EvidenceHandle, boot: ExfatBoot, start: int, *, contiguous: bool
) -> list[int]:
    """Cluster numbers for a chain, following the FAT unless told not to."""
    if contiguous:
        return [start]
    chain: list[int] = []
    cluster = start
    seen: set[int] = set()
    while 2 <= cluster < boot.cluster_count + 2 and cluster not in seen:
        seen.add(cluster)
        chain.append(cluster)
        raw = volume.read(boot.fat_offset + cluster * 4, 4)
        if len(raw) < 4:
            break
        cluster = struct.unpack("<I", raw)[0]
        if cluster >= 0xFFFF_FFF7 or len(chain) > _EXFAT_MAX_CLUSTERS:
            break
    return chain


def _exfat_directory_bytes(
    volume: EvidenceHandle, boot: ExfatBoot, first_cluster: int
) -> bytes:
    """Every byte of a directory, following its FAT chain."""
    out = bytearray()
    for cluster in _exfat_read_cluster_chain(
        volume, boot, first_cluster, contiguous=False
    ):
        out += volume.read(boot.cluster_offset(cluster), boot.cluster_bytes)
        if len(out) > _EXFAT_MAX_CLUSTERS * 32:
            break
    return bytes(out)


def _parse_exfat_directory(data: bytes) -> tuple[list[ExfatEntry], tuple[int, int]]:
    """Parse one directory's entries.

    Returns the entries and the allocation bitmap's ``(first_cluster, length)``
    if this directory declared one, which only the root does.
    """
    entries: list[ExfatEntry] = []
    bitmap = (0, 0)
    index = 0
    while index + 32 <= len(data):
        entry_type = data[index]
        if entry_type == 0x00:  # end of directory
            break
        code = entry_type & 0x7F
        in_use = bool(entry_type & _EXFAT_IN_USE)

        if code == _EXFAT_TYPE_BITMAP and in_use:
            first, length = struct.unpack_from("<IQ", data, index + 0x14)
            bitmap = (first, int(length))
            index += 32
            continue

        if code != _EXFAT_TYPE_FILE:
            index += 32
            continue

        secondary = data[index + 1]
        attributes = struct.unpack_from("<H", data, index + 4)[0]
        create, modify, access = struct.unpack_from("<III", data, index + 8)
        create_ms, modify_ms = data[index + 0x14], data[index + 0x15]
        set_end = index + 32 * (secondary + 1)
        if secondary < 2 or set_end > len(data):
            index += 32
            continue

        stream_at = index + 32
        stream_type = data[stream_at] & 0x7F
        if stream_type != _EXFAT_TYPE_STREAM:
            index += 32
            continue
        secondary_flags = data[stream_at + 1]
        name_length = data[stream_at + 3]
        valid_length = struct.unpack_from("<Q", data, stream_at + 8)[0]
        first_cluster = struct.unpack_from("<I", data, stream_at + 0x14)[0]
        data_length = struct.unpack_from("<Q", data, stream_at + 0x18)[0]

        name_parts: list[str] = []
        for offset in range(stream_at + 32, set_end, 32):
            if data[offset] & 0x7F != _EXFAT_TYPE_NAME:
                continue
            name_parts.append(data[offset + 2 : offset + 32].decode("utf-16-le"))
        name = "".join(name_parts)[:name_length].rstrip("\x00")

        if name:
            entries.append(
                ExfatEntry(
                    name=name,
                    first_cluster=first_cluster,
                    data_length=int(data_length),
                    valid_data_length=int(valid_length),
                    no_fat_chain=bool(secondary_flags & _EXFAT_NO_FAT_CHAIN),
                    deleted=not in_use,
                    is_directory=bool(attributes & 0x10),
                    mac=MacTimestamps(
                        modified=_exfat_time(modify, modify_ms),
                        accessed=_exfat_time(access),
                        changed=None,
                        created=_exfat_time(create, create_ms),
                    ),
                )
            )
        index = set_end
    return entries, bitmap


# --------------------------------------------------------------------------
# ext: the superblock, and the jbd2 journal ext4 forces us to read
# --------------------------------------------------------------------------

EXT_SUPERBLOCK_OFFSET = 1024
EXT_MAGIC = 0xEF53

#: jbd2 block header magic, big-endian on disk like every other jbd2 field.
JBD2_MAGIC = 0xC03B3998
JBD2_DESCRIPTOR_BLOCK = 1
JBD2_COMMIT_BLOCK = 2
JBD2_SUPERBLOCK_V1 = 3
JBD2_SUPERBLOCK_V2 = 4
JBD2_REVOKE_BLOCK = 5

#: ext4 extent header magic, at the head of ``i_block`` when the inode uses
#: extents rather than the old indirect blocks.
EXT4_EXTENT_MAGIC = 0xF30A

#: Cap on how much journal is read. mke2fs sizes a journal from the volume; a
#: triage pass must not be turned into an overnight one by a large volume.
MAX_JOURNAL_BYTES = 256 * MIB


@dataclass(frozen=True)
class ExtSuperblock:
    """The ext2/3/4 superblock fields this module uses."""

    block_size: int
    inode_size: int
    inodes_per_group: int
    blocks_count: int


def read_ext_superblock(volume: EvidenceHandle) -> ExtSuperblock | None:
    """Parse the ext superblock, or return None when this is not ext."""
    raw = volume.read(EXT_SUPERBLOCK_OFFSET, 1024)
    if len(raw) < 0x60 or struct.unpack_from("<H", raw, 0x38)[0] != EXT_MAGIC:
        return None
    blocks_count = struct.unpack_from("<I", raw, 0x04)[0]
    log_block_size = struct.unpack_from("<I", raw, 0x18)[0]
    inodes_per_group = struct.unpack_from("<I", raw, 0x28)[0]
    inode_size = struct.unpack_from("<H", raw, 0x58)[0] or 128
    return ExtSuperblock(
        block_size=1024 << log_block_size,
        inode_size=inode_size,
        inodes_per_group=inodes_per_group,
        blocks_count=blocks_count,
    )


@dataclass(frozen=True)
class JournalledInode:
    """A deleted inode found in the journal that still points at its blocks."""

    size: int
    extents: tuple[Extent, ...]
    mac: MacTimestamps


def _parse_ext4_inode(raw: bytes, block_size: int, base: int) -> JournalledInode | None:
    """Read one ext4 inode, keeping it only if it is a deleted file with extents.

    The three conditions together are what make a hit trustworthy without
    knowing which inode number this is: links are zero and a deletion time is
    set (so the file was unlinked), and ``i_block`` still opens with a valid
    depth-zero extent header (so this copy predates the tree being zeroed).
    Random bytes satisfying all three are vanishingly unlikely.
    """
    if len(raw) < 0x68:
        return None
    mode, size_lo = struct.unpack_from("<HxxI", raw, 0)
    atime, ctime, mtime, dtime = struct.unpack_from("<IIII", raw, 0x08)
    links = struct.unpack_from("<H", raw, 0x1A)[0]
    if links != 0 or dtime == 0 or size_lo == 0:
        return None
    # 0x8000 is S_IFREG. A deleted directory has no content worth recovering.
    if mode & 0xF000 != 0x8000:
        return None

    magic, entries, max_entries, depth = struct.unpack_from("<HHHH", raw, 0x28)
    if magic != EXT4_EXTENT_MAGIC or depth != 0:
        return None
    if not 1 <= entries <= max_entries or entries > 4:
        return None

    size_high = struct.unpack_from("<I", raw, 0x6C)[0] if len(raw) >= 0x70 else 0
    size = size_lo | (size_high << 32)
    if not 0 < size <= MAX_RECOVERED_BYTES:
        return None

    extents: list[Extent] = []
    remaining = size
    for index in range(entries):
        at = 0x28 + 12 + index * 12
        if at + 12 > len(raw):
            return None
        _logical, length, start_hi, start_lo = struct.unpack_from("<IHHI", raw, at)
        if length == 0 or length > 32768:
            return None
        start = start_lo | (start_hi << 16)
        span = min(length * block_size, remaining)
        extents.append(Extent(base + start * block_size, span))
        remaining -= span
        if remaining <= 0:
            break
    if not extents:
        return None

    return JournalledInode(
        size=size,
        extents=tuple(extents),
        mac=MacTimestamps(
            modified=_utc(mtime),
            accessed=_utc(atime),
            changed=_utc(ctime),
            created=None,
        ),
    )


def _scan_journal_for_inodes(
    journal: bytes, superblock: ExtSuperblock, base: int
) -> list[JournalledInode]:
    """Find deleted-but-intact inodes in stale inode-table blocks.

    This is a structural scan of the journal's blocks rather than a transaction
    replay. Replaying needs the tag format, which varies with three separate
    feature flags, and the extra precision buys nothing here: what is wanted is
    every *copy* of an inode-table block the journal still holds, whichever
    transaction wrote it, and an inode-table block identifies itself by its
    contents. jbd2's own descriptor, commit and revoke blocks carry a magic at
    their head and are skipped.

    The result is content without names. ext4 stores names in directory blocks,
    and a directory block copy in the journal cannot be tied to an inode number
    without the group descriptors and a matching transaction - so these
    candidates are honest about having no name rather than guessing at one.
    """
    block_size = superblock.block_size
    inode_size = superblock.inode_size
    if inode_size <= 0 or block_size < inode_size:
        return []

    found: list[JournalledInode] = []
    seen: set[tuple[int, ...]] = set()
    for start in range(0, len(journal) - block_size + 1, block_size):
        block = journal[start : start + block_size]
        if struct.unpack_from(">I", block, 0)[0] == JBD2_MAGIC:
            continue  # jbd2's own bookkeeping, not a copy of a filesystem block
        for at in range(0, block_size - inode_size + 1, inode_size):
            inode = _parse_ext4_inode(block[at : at + inode_size], block_size, base)
            if inode is None:
                continue
            key = tuple(item.offset for item in inode.extents) + (inode.size,)
            if key in seen:
                continue
            seen.add(key)
            found.append(inode)
    return found


def _read_journal(fs: Any, superblock: ExtSuperblock) -> bytes:
    """Read the jbd2 journal inode's content, capped.

    The journal is inode 8 on every ext2/3/4 volume mke2fs creates. It is read
    through TSK, which is reading through the shim, so it is still the one path
    to the evidence bytes.
    """
    try:
        journal_inode = fs.open_meta(inode=8)
    except OSError:
        return b""
    meta = journal_inode.info.meta
    if meta is None or meta.size <= 0:
        return b""
    size = min(int(meta.size), MAX_JOURNAL_BYTES)
    out = bytearray()
    while len(out) < size:
        take = min(4 * MIB, size - len(out))
        try:
            piece = journal_inode.read_random(len(out), take)
        except OSError:
            break
        if not piece:
            break
        out += piece
    if len(out) < 12 or struct.unpack_from(">I", bytes(out), 0)[0] != JBD2_MAGIC:
        # No journal superblock at block zero: ext2, or a journal that was
        # never initialised. Either way there is nothing to scan.
        return b""
    del superblock
    return bytes(out)


# --------------------------------------------------------------------------
# FAT32: the allocation table, read to contradict the contiguity assumption
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class FatBoot:
    """The FAT32 BPB fields needed to test the contiguity assumption."""

    bytes_per_sector: int
    sectors_per_cluster: int
    fat_offset: int
    data_offset: int
    cluster_count: int

    @property
    def cluster_bytes(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster

    def cluster_of(self, volume_offset: int) -> int:
        """Cluster number containing a volume-relative offset."""
        return (volume_offset - self.data_offset) // self.cluster_bytes + 2


def read_fat32_boot(volume: EvidenceHandle) -> FatBoot | None:
    """Parse a FAT32 BPB, or return None when this is not FAT32."""
    sector = volume.read(0, 512)
    if len(sector) < 512 or sector[510:512] != b"\x55\xaa":
        return None
    bytes_per_sector = struct.unpack_from("<H", sector, 0x0B)[0]
    sectors_per_cluster = sector[0x0D]
    reserved = struct.unpack_from("<H", sector, 0x0E)[0]
    number_of_fats = sector[0x10]
    total_sectors = struct.unpack_from("<I", sector, 0x20)[0]
    fat_sectors = struct.unpack_from("<I", sector, 0x24)[0]
    if bytes_per_sector not in (512, 1024, 2048, 4096):
        return None
    if not sectors_per_cluster or not fat_sectors or not number_of_fats:
        return None
    data_sector = reserved + number_of_fats * fat_sectors
    if total_sectors <= data_sector:
        return None
    return FatBoot(
        bytes_per_sector=bytes_per_sector,
        sectors_per_cluster=sectors_per_cluster,
        fat_offset=reserved * bytes_per_sector,
        data_offset=data_sector * bytes_per_sector,
        cluster_count=(total_sectors - data_sector) // sectors_per_cluster,
    )


def volume_cluster_bytes(volume: EvidenceHandle, fs_type: str, fs: Any = None) -> int:
    """The allocation unit of the filesystem ``volume`` holds, or 0 if unknown.

    Read from the volume's own structures rather than from TSK's
    ``block_size``, because TSK means different things by it: a sector on FAT
    and exFAT, a cluster on NTFS, a block on ext. The carver needs the unit a
    file's fragments are allocated in, since that is the only grid a fragment
    boundary can fall on.
    """
    size = 0
    if fs_type == "exfat":
        boot = read_exfat_boot(volume)
        size = boot.cluster_bytes if boot is not None else 0
    elif fs_type in {"fat12", "fat16", "fat32", "ntfs"}:
        sector = volume.read(0, 512)
        if len(sector) == 512:
            per_sector = struct.unpack_from("<H", sector, 0x0B)[0]
            raw = sector[0x0D]
            # NTFS stores clusters above 64 KiB as a negative power of two.
            per_cluster = 1 << (256 - raw) if fs_type == "ntfs" and raw > 0x80 else raw
            size = per_sector * per_cluster
    elif fs_type.startswith("ext") and fs is not None:
        size = int(fs.info.block_size)
    # Sectors are at least 512 bytes and clusters are whole powers of two of
    # them; anything else is a damaged field, and a wrong grid would refuse
    # every genuine join on the volume.
    if size < 512 or size & (size - 1):
        return 0
    return size


def _fat_entries_allocated(
    volume: EvidenceHandle, boot: FatBoot, first: int, count: int
) -> bool:
    """True when any cluster after the first is allocated to something live.

    That is a *contradiction*, not a suspicion. A deleted file's own chain was
    zeroed, so every cluster the contiguous read walks into should be free. One
    that is allocated belongs to a file that still exists, which means the
    deleted file was fragmented around it and the recovered bytes include
    somebody else's data.
    """
    for cluster in range(first + 1, min(first + count, boot.cluster_count + 2)):
        raw = volume.read(boot.fat_offset + cluster * 4, 4)
        if len(raw) < 4:
            return False
        if struct.unpack("<I", raw)[0] & 0x0FFF_FFFF:
            return True
    return False


def _exfat_bitmap_allocated(
    volume: EvidenceHandle,
    boot: ExfatBoot,
    bitmap: tuple[int, int],
    first: int,
    count: int,
) -> bool:
    """The exFAT equivalent, read from the allocation bitmap."""
    bitmap_cluster, bitmap_length = bitmap
    if bitmap_cluster < 2 or bitmap_length <= 0:
        return False
    base = boot.cluster_offset(bitmap_cluster)
    for cluster in range(first + 1, min(first + count, boot.cluster_count + 2)):
        bit = cluster - 2
        byte_at = base + bit // 8
        if byte_at >= base + bitmap_length:
            return False
        raw = volume.read(byte_at, 1)
        if not raw:
            return False
        if raw[0] & (1 << (bit % 8)):
            return True
    return False


# --------------------------------------------------------------------------
# Turning what was found into candidates
# --------------------------------------------------------------------------


_FS_TYPE_NAMES: dict[int, str] = {}


def _fs_type_name(fs: Any) -> str:
    """A short, stable filesystem name for the report."""
    if not _FS_TYPE_NAMES:
        for attribute, name in (
            ("TSK_FS_TYPE_NTFS", "ntfs"),
            ("TSK_FS_TYPE_FAT12", "fat12"),
            ("TSK_FS_TYPE_FAT16", "fat16"),
            ("TSK_FS_TYPE_FAT32", "fat32"),
            ("TSK_FS_TYPE_EXFAT", "exfat"),
            ("TSK_FS_TYPE_EXT2", "ext2"),
            ("TSK_FS_TYPE_EXT3", "ext3"),
            ("TSK_FS_TYPE_EXT4", "ext4"),
        ):
            value = getattr(pytsk3, attribute, None)
            if value is not None:
                _FS_TYPE_NAMES[int(value)] = name
    return _FS_TYPE_NAMES.get(int(fs.info.ftype), str(fs.info.ftype))


def _hash_extents(handle: EvidenceHandle, extents: Sequence[Extent]) -> tuple[str, int]:
    """SHA-256 over the extents, read through the handle, and the byte count.

    Hashing the same bytes :func:`read_recovered` returns - rather than the
    bytes TSK would hand back - is what makes ``candidate.sha256`` a claim the
    caller can check for itself.
    """
    digest = hashlib.sha256()
    total = 0
    for extent in extents:
        cursor = extent.offset
        remaining = extent.length
        while remaining > 0:
            piece = handle.read(cursor, min(MIB, remaining))
            if not piece:
                break
            digest.update(piece)
            cursor += len(piece)
            remaining -= len(piece)
            total += len(piece)
    return digest.hexdigest(), total


def _make_candidate(
    handle: EvidenceHandle,
    *,
    name: str,
    extents: Sequence[Extent],
    recorded_size: int,
    fs_type: str,
    mac: MacTimestamps,
    details: Sequence[str],
    contiguity_assumed: bool = False,
    contiguity_contradicted: bool = False,
    fragmented: bool = False,
) -> RecoveredFile:
    """Build one ``source="fs_metadata"`` candidate and its extents.

    ``validation`` is always ``decoder_unavailable`` here. Nothing in this
    module decodes anything: it reads filesystem records. The real decoder runs
    later in :mod:`core.carve.validate`, and claiming a verdict this module did
    not reach would put a number in the score that no check produced.
    """
    # Kept in *file* order, never sorted. A resident NTFS $DATA is
    # reconstructed by splicing a two-byte extent from the record's update
    # sequence array into the middle of the value, and that extent sits at a
    # lower offset than the pieces around it. Sorting would reassemble the file
    # with those two bytes at the front.
    ordered = tuple(extents)
    digest, recovered = _hash_extents(handle, ordered)
    offset = ordered[0].offset if ordered else 0
    notes = list(details)
    if recovered < recorded_size:
        notes.append(
            f"{recovered} of {recorded_size} recorded bytes were recoverable; "
            "the rest lies outside any surviving extent"
        )
    candidate = CarveCandidate(
        offset=offset,
        length=recorded_size,
        ext=_ext_of(name) if name else "bin",
        mime=_mime_for(_ext_of(name)) if name else "application/octet-stream",
        source="fs_metadata",
        validation="decoder_unavailable",
        confidence_bp=0,
        bucket="LOW",
        sha256=digest,
        original_name=name or None,
        possibly_fragmented=fragmented or contiguity_assumed,
        validation_detail=" ".join(notes),
        fs_type=fs_type,
        mac=mac,
        contiguity_assumed=contiguity_assumed,
        contiguity_contradicted=contiguity_contradicted,
    )
    return RecoveredFile(candidate=candidate, extents=ordered)


def _extents_of(
    entry: Any, attr_type: Any, block_size: int, base: int, size: int
) -> tuple[list[Extent], bool, bool]:
    """Extents for a file's default data stream.

    Returns ``(extents, sparse, fragmented)``. ``sparse`` means a run the
    filesystem never allocated was skipped, so the recovered bytes are shorter
    than the recorded size. ``fragmented`` means the runs are not adjacent,
    which is a fact worth reporting even when recovery was exact.
    """
    if size <= 0 or size > MAX_RECOVERED_BYTES:
        return [], False, False

    sparse_flag = int(getattr(pytsk3, "TSK_FS_ATTR_RUN_FLAG_SPARSE", 0x01))
    filler_flag = int(getattr(pytsk3, "TSK_FS_ATTR_RUN_FLAG_FILLER", 0x02))

    extents: list[Extent] = []
    remaining = size
    sparse = False
    for attribute in entry:
        info = attribute.info
        if info.type != attr_type:
            continue
        # NTFS alternate data streams have a name; the file's content is the
        # unnamed $DATA. Recovering a stream under the file's own name would
        # report the wrong bytes with the right filename.
        if info.name:
            continue
        for run in attribute:
            if remaining <= 0:
                break
            flags = int(run.flags)
            length = int(run.len) * block_size
            if flags & (sparse_flag | filler_flag):
                sparse = True
                remaining -= min(length, remaining)
                continue
            span = min(length, remaining)
            if span > 0:
                extents.append(Extent(base + int(run.addr) * block_size, span))
                remaining -= span
        break

    fragmented = any(
        extents[index].end != extents[index + 1].offset
        for index in range(len(extents) - 1)
    )
    return extents, sparse, fragmented


def _iter_entries(fs: Any) -> Iterator[tuple[str, Any]]:
    """Depth-first walk of every directory, deleted entries included."""
    stack: list[tuple[str, int]] = [("", int(fs.info.root_inum))]
    visited: set[int] = set()
    while stack:
        path, inode = stack.pop()
        if inode in visited:
            continue
        visited.add(inode)
        try:
            directory = fs.open_dir(inode=inode)
        except OSError:
            continue
        for entry in directory:
            name_info = entry.info.name
            if name_info is None or name_info.name in (b".", b".."):
                continue
            raw = name_info.name
            name = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
            if name.startswith("$") and name != "$OrphanFiles":
                # NTFS metadata files. They are not user content and their
                # runs are added to the allocated map by the metadata pass.
                continue
            yield path, entry
            meta = entry.info.meta
            if (
                meta is not None
                and meta.type == pytsk3.TSK_FS_META_TYPE_DIR
                and not (meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC)
            ):
                stack.append((f"{path}/{name}", int(meta.addr)))


def _recover_via_tsk(
    image: EvidenceHandle,
    fs: Any,
    *,
    base: int,
    fs_type: str,
    volume: EvidenceHandle,
    report: UndeleteReport,
) -> list[Extent]:
    """Recover deleted files from one filesystem. Returns the allocated map."""
    block_size = int(fs.info.block_size)
    attr_type = (
        pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA
        if fs_type == "ntfs"
        else pytsk3.TSK_FS_ATTR_TYPE_DEFAULT
    )
    is_fat = fs_type in {"fat12", "fat16", "fat32"}
    fat_boot = read_fat32_boot(volume) if is_fat else None
    mft = _read_mft_map(volume) if fs_type == "ntfs" else None

    allocated: list[Extent] = []
    seen_meta: set[int] = set()

    for _path, entry in _iter_entries(fs):
        name_info = entry.info.name
        meta = entry.info.meta
        raw = name_info.name
        name = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
        deleted = bool(name_info.flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC)

        if meta is None:
            if deleted:
                report.files.append(
                    _make_candidate(
                        image,
                        name=name,
                        extents=(),
                        recorded_size=0,
                        fs_type=fs_type,
                        mac=MacTimestamps(),
                        details=[NTFS_NAME_ONLY] if fs_type == "ntfs" else [],
                    )
                )
            continue

        if meta.type != pytsk3.TSK_FS_META_TYPE_REG:
            continue

        if deleted and not meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC:
            # The directory entry is deleted but the record it points at is in
            # use. That is a reused record: the name belongs to the old file
            # and the content belongs to the new one. Reporting the content
            # under this name would attribute one file's bytes to another,
            # which is the single worst thing an undelete can do.
            report.files.append(
                _make_candidate(
                    image,
                    name=name,
                    extents=(),
                    recorded_size=int(meta.size) if fs_type != "ntfs" else 0,
                    fs_type=fs_type,
                    mac=MacTimestamps(),
                    details=[NTFS_NAME_ONLY] if fs_type == "ntfs" else [],
                )
            )
            continue

        seen_meta.add(int(meta.addr))

        size = int(meta.size)
        extents, sparse, fragmented = _extents_of(
            entry, attr_type, block_size, base, size
        )
        if not extents and mft is not None and size > 0:
            extents, resident_size = _resident_data_extents(
                volume, mft, int(meta.addr), base
            )
            if extents:
                size = resident_size
                sparse = False
        if not deleted:
            allocated.extend(extents)
            continue
        if not extents:
            report.files.append(
                _make_candidate(
                    image,
                    name=name,
                    extents=(),
                    recorded_size=size,
                    fs_type=fs_type,
                    mac=_mac_from_meta(meta),
                    details=[EXT4_EXTENTS_ZEROED] if fs_type == "ext4" else [],
                )
            )
            continue

        details: list[str] = []
        contiguity_assumed = False
        contradicted = False
        if is_fat:
            contiguity_assumed = True
            details.append(FAT_CHAIN_LOST)
            if fat_boot is not None:
                first_cluster = fat_boot.cluster_of(extents[0].offset - base)
                clusters = -(-size // fat_boot.cluster_bytes)
                contradicted = _fat_entries_allocated(
                    volume, fat_boot, first_cluster, clusters
                )
                if contradicted:
                    details.append(
                        "FRAGMENTATION_PROVEN: a cluster between this file's "
                        "first and last is allocated to a file that still "
                        "exists, so this file was definitely fragmented and "
                        "its layout was inferred rather than read. The "
                        "reconstruction routed around the live clusters, which "
                        "is the best available guess and is not a record of "
                        "what was there."
                    )
                else:
                    details.append(
                        "NO_LIVE_NEIGHBOUR: no cluster in this file's span "
                        "belongs to a live file, so nothing contradicts the "
                        "reconstruction - and nothing confirms it either. If a "
                        "neighbouring file was deleted too, its bytes are in "
                        "this result and no check on this volume can say so."
                    )
        if sparse:
            details.append(
                "SPARSE_RUN_SKIPPED: part of this file was never allocated on "
                "the volume and could not be read from anywhere."
            )
        if fragmented:
            details.append(
                f"FRAGMENTED: recovered from {len(extents)} separate runs "
                "recorded by the filesystem."
            )

        report.files.append(
            _make_candidate(
                image,
                name=name,
                extents=extents,
                recorded_size=size,
                fs_type=fs_type,
                mac=_mac_from_meta(meta),
                details=details,
                contiguity_assumed=contiguity_assumed,
                contiguity_contradicted=contradicted,
                fragmented=fragmented,
            )
        )

    if fs_type == "ntfs":
        allocated.extend(
            _recover_ntfs_orphans(
                image,
                fs,
                volume=volume,
                mft=mft,
                base=base,
                block_size=block_size,
                seen=seen_meta,
                report=report,
            )
        )
    return allocated


def _mac_from_meta(meta: Any) -> MacTimestamps:
    """MAC timestamps from a TSK metadata record."""
    return MacTimestamps(
        modified=_utc(int(getattr(meta, "mtime", 0) or 0)),
        accessed=_utc(int(getattr(meta, "atime", 0) or 0)),
        changed=_utc(int(getattr(meta, "ctime", 0) or 0)),
        created=_utc(int(getattr(meta, "crtime", 0) or 0)),
    )


def _recover_ntfs_orphans(
    image: EvidenceHandle,
    fs: Any,
    *,
    volume: EvidenceHandle,
    mft: _MftMap | None,
    base: int,
    block_size: int,
    seen: set[int],
    report: UndeleteReport,
) -> list[Extent]:
    """Walk the MFT itself for deleted records no directory entry points at.

    The directory walk finds a deleted file whose entry is still in its
    parent's index. It does not find one whose parent was deleted too, or whose
    index entry has already been overwritten. Those records are still in the
    MFT with the in-use flag cleared and their run lists intact, so they are
    recovered here - without a name, because the name lived in the index.
    """
    allocated: list[Extent] = []
    first = int(fs.info.first_inum)
    last = min(int(fs.info.last_inum), first + _MFT_SCAN_CAP)
    for inode in range(first, last + 1):
        if inode in seen:
            continue
        try:
            entry = fs.open_meta(inode=inode)
        except OSError:
            continue
        meta = entry.info.meta
        if meta is None or meta.type != pytsk3.TSK_FS_META_TYPE_REG:
            continue
        size = int(meta.size)
        extents, sparse, fragmented = _extents_of(
            entry, pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA, block_size, base, size
        )
        resident = False
        if not extents and mft is not None and size > 0:
            extents, resident_size = _resident_data_extents(
                volume, mft, int(meta.addr), base
            )
            if extents:
                size = resident_size
                sparse = False
                resident = True
        if not meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC:
            allocated.extend(extents)
            continue
        if not extents:
            continue
        name = _ntfs_record_name(entry)
        details = [
            "ORPHANED_MFT_RECORD: this record's in-use flag is clear and no "
            "surviving directory entry points at it. NTFS removes the entry "
            "from the parent's $I30 on unlink, so this is the normal state of "
            "a deleted NTFS file rather than an unusual one."
            + (
                " The name was read from the record's own $FILE_NAME."
                if name
                else " The record carries no readable $FILE_NAME, so this "
                "content is unnamed."
            )
        ]
        if resident:
            details.append(
                "RESIDENT_DATA: the file was small enough to live inside its "
                "MFT record, so the content came out of the record itself "
                "rather than from any cluster on the volume."
            )
        if sparse:
            details.append("SPARSE_RUN_SKIPPED: part of the file was never allocated.")
        if fragmented and not resident:
            details.append(f"FRAGMENTED: recovered from {len(extents)} runs.")
        report.files.append(
            _make_candidate(
                image,
                name=name,
                extents=extents,
                recorded_size=size,
                fs_type="ntfs",
                mac=_mac_from_meta(meta),
                details=details,
                fragmented=fragmented,
            )
        )
    return allocated


def _recover_ntfs_slack(
    image: EvidenceHandle,
    fs: Any,
    *,
    base: int,
    report: UndeleteReport,
) -> None:
    """Emit a name-only candidate for every $I30 slack entry whose record is gone.

    A slack entry whose MFT record is still unallocated has usually already
    been recovered with its content by the directory walk, so it is skipped:
    reporting it twice would turn one deleted file into two findings. What is
    kept is the entry whose record has been **reused** - the name survives, the
    content does not, and nothing else on the volume records that the file ever
    existed.
    """
    recovered_names = {
        item.candidate.original_name
        for item in report.files
        if item.candidate.original_name
    }
    # A file that still exists also leaves stale copies of its index entry in
    # slack, because removing a *different* entry shifts it down and leaves the
    # old bytes behind. Reporting those as recovered names would invent a
    # deleted file for every live one.
    live_names = {
        (
            entry.info.name.name.decode("utf-8", "replace")
            if isinstance(entry.info.name.name, bytes)
            else str(entry.info.name.name)
        )
        for _path, entry in _iter_entries(fs)
        if entry.info.name is not None
        and not entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC
    }
    for entry in _ntfs_slack_names(fs, image, base):
        if entry.name in recovered_names or entry.name in live_names:
            continue
        record = None
        if entry.mft_entry is not None:
            try:
                record = fs.open_meta(inode=entry.mft_entry)
            except OSError:
                record = None
        if record is not None and record.info.meta is not None:
            meta = record.info.meta
            in_use = not (meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC)
            sequence = int(getattr(meta, "seq", -1))
            moved = entry.sequence is not None and sequence != entry.sequence
            reused = bool(in_use or moved)
        else:
            # No usable reference. The name is in slack and nothing on the
            # volume can say which record it belonged to, which is exactly the
            # case this pass exists for: a name with no content behind it.
            reused = True
        if not reused:
            continue
        report.files.append(
            _make_candidate(
                image,
                name=entry.name,
                extents=(),
                recorded_size=entry.real_size,
                fs_type="ntfs",
                mac=entry.mac,
                details=[NTFS_NAME_ONLY],
            )
        )


def _recover_exfat(
    image: EvidenceHandle,
    volume: EvidenceHandle,
    *,
    base: int,
    report: UndeleteReport,
) -> list[Extent] | None:
    """Recover deleted exFAT files, reading NoFatChain for each one.

    Returns the allocated map, or None when this volume is not exFAT.
    """
    boot = read_exfat_boot(volume)
    if boot is None:
        return None

    allocated: list[Extent] = []
    root = _exfat_directory_bytes(volume, boot, boot.root_cluster)
    entries, bitmap = _parse_exfat_directory(root)
    pending = [entries]
    visited: set[int] = {boot.root_cluster}

    while pending:
        for entry in pending.pop():
            if entry.is_directory:
                if not entry.deleted and entry.first_cluster not in visited:
                    visited.add(entry.first_cluster)
                    child, _ = _parse_exfat_directory(
                        _exfat_directory_bytes(volume, boot, entry.first_cluster)
                    )
                    pending.append(child)
                continue

            size = min(entry.data_length, MAX_RECOVERED_BYTES)
            if entry.first_cluster < 2 or size <= 0:
                if entry.deleted:
                    report.files.append(
                        _make_candidate(
                            image,
                            name=entry.name,
                            extents=(),
                            recorded_size=entry.data_length,
                            fs_type="exfat",
                            mac=entry.mac,
                            details=[
                                "NO_START_CLUSTER: the entry records no first "
                                "cluster, so only the name and size survive."
                            ],
                        )
                    )
                continue

            clusters = -(-size // boot.cluster_bytes)
            if entry.no_fat_chain or entry.deleted:
                start = base + boot.cluster_offset(entry.first_cluster)
                extents = [Extent(start, size)]
            else:
                chain = _exfat_read_cluster_chain(
                    volume, boot, entry.first_cluster, contiguous=False
                )
                extents = []
                remaining = size
                for cluster in chain:
                    span = min(boot.cluster_bytes, remaining)
                    extents.append(
                        Extent(base + boot.cluster_offset(cluster), span)
                    )
                    remaining -= span
                    if remaining <= 0:
                        break

            if not entry.deleted:
                allocated.extend(extents)
                continue

            if entry.no_fat_chain:
                details = [EXFAT_NO_FAT_CHAIN]
                assumed = False
                contradicted = False
            else:
                details = [EXFAT_CHAIN_LOST]
                assumed = True
                contradicted = _exfat_bitmap_allocated(
                    volume, boot, bitmap, entry.first_cluster, clusters
                )
                if contradicted:
                    details.append(
                        "CONTIGUITY_CONTRADICTED: a cluster inside the assumed "
                        "run is marked allocated in the volume bitmap, so this "
                        "recovery is partial."
                    )
            report.files.append(
                _make_candidate(
                    image,
                    name=entry.name,
                    extents=extents,
                    recorded_size=entry.data_length,
                    fs_type="exfat",
                    mac=entry.mac,
                    details=details,
                    contiguity_assumed=assumed,
                    contiguity_contradicted=contradicted,
                )
            )
    return allocated


def _recover_ext4_journal(
    image: EvidenceHandle,
    fs: Any,
    volume: EvidenceHandle,
    *,
    base: int,
    report: UndeleteReport,
) -> None:
    """Recover deleted ext4 content from stale inode copies in the journal."""
    superblock = read_ext_superblock(volume)
    if superblock is None:
        return
    journal = _read_journal(fs, superblock)
    if not journal:
        return
    for inode in _scan_journal_for_inodes(journal, superblock, base):
        report.files.append(
            _make_candidate(
                image,
                name="",
                extents=inode.extents,
                recorded_size=inode.size,
                fs_type="ext4",
                mac=inode.mac,
                details=[
                    EXT4_EXTENTS_ZEROED,
                    "JBD2_STALE_INODE: recovered from a copy of an inode-table "
                    "block still held in the jbd2 journal. The live inode's "
                    "extent tree was zeroed on unlink; this copy predates that. "
                    "No filename: ext4 keeps names in directory blocks, which "
                    "cannot be tied to this inode without the transaction that "
                    "wrote both.",
                ],
                fragmented=len(inode.extents) > 1,
            )
        )


# --------------------------------------------------------------------------
# Public interface
# --------------------------------------------------------------------------


def _enumerate_partitions(
    img: EvidenceImgInfo, handle: EvidenceHandle, report: UndeleteReport
) -> list[PartitionInfo]:
    """Partitions from the volume system, or one covering the whole image.

    A missing or unreadable partition table is not an error. It is the normal
    case for a partition image, and it is also what a wiped or damaged first
    sector looks like - in both cases the right answer is to carry on over the
    whole image rather than to stop.
    """
    try:
        volume = pytsk3.Volume_Info(img)
    except OSError as exc:
        message = str(exc)
        report.limitations.append(
            NO_PARTITION_TABLE
            if "not found" in message.lower() or "cannot determine" in message.lower()
            else PARTITION_TABLE_UNREADABLE.format(reason=message)
        )
        return [
            PartitionInfo(
                index=0,
                offset=0,
                length=handle.size,
                description="whole image (no volume system)",
                allocated=True,
            )
        ]

    sector = int(volume.info.block_size) or handle.sector_size
    alloc_flag = int(getattr(pytsk3, "TSK_VS_PART_FLAG_ALLOC", 0x01))
    found: list[PartitionInfo] = []
    for part in volume:
        offset = int(part.start) * sector
        length = int(part.len) * sector
        if offset >= handle.size:
            continue
        length = min(length, handle.size - offset)
        description = part.desc
        found.append(
            PartitionInfo(
                index=int(part.addr),
                offset=offset,
                length=length,
                description=(
                    description.decode("utf-8", "replace")
                    if isinstance(description, bytes)
                    else str(description)
                ),
                allocated=bool(int(part.flags) & alloc_flag),
            )
        )
    if not found:
        report.limitations.append(NO_PARTITION_TABLE)
        return [
            PartitionInfo(
                index=0,
                offset=0,
                length=handle.size,
                description="whole image (empty volume system)",
                allocated=True,
            )
        ]
    return found


def undelete_report(handle: EvidenceHandle) -> UndeleteReport:
    """Recover every deleted entry the surviving filesystem metadata records.

    Returns the candidates *and* the allocated/unallocated map, because the
    caller's next step is to hand the unallocated regions to the signature
    carver and recomputing that map would mean re-parsing every filesystem.

    Never raises for a damaged image. A missing volume system, an unparsable
    partition table and a filesystem that will not open are all recorded as
    limitations, and the region involved is reported unallocated in full so
    that carving still covers it.
    """
    report = UndeleteReport()
    root_img = EvidenceImgInfo(handle)
    shims: list[EvidenceImgInfo] = [root_img]
    allocated: list[Extent] = []

    partitions = _enumerate_partitions(root_img, handle, report)
    resolved: list[PartitionInfo] = []

    for partition in partitions:
        if not partition.allocated or partition.length <= 0:
            resolved.append(partition)
            continue

        window = WindowedEvidence(
            handle, base_offset=partition.offset, length=partition.length
        )
        window_img = EvidenceImgInfo(window)
        shims.append(window_img)
        try:
            fs = pytsk3.FS_Info(window_img)
        except OSError as exc:
            report.limitations.append(
                NO_FILESYSTEM.format(
                    where=f"partition {partition.index} at offset {partition.offset}",
                    reason=str(exc),
                )
            )
            resolved.append(partition)
            continue

        fs_type = _fs_type_name(fs)
        resolved.append(
            PartitionInfo(
                index=partition.index,
                offset=partition.offset,
                length=partition.length,
                description=partition.description,
                allocated=partition.allocated,
                fs_type=fs_type,
                cluster_bytes=volume_cluster_bytes(window, fs_type, fs),
            )
        )

        if fs_type == "exfat":
            # Parsed here rather than through TSK, for NoFatChain. TSK still
            # opened the volume, which is what confirmed the type.
            found = _recover_exfat(handle, window, base=partition.offset, report=report)
            allocated.extend(found or [])
        else:
            allocated.extend(
                _recover_via_tsk(
                    handle,
                    fs,
                    base=partition.offset,
                    fs_type=fs_type,
                    volume=window,
                    report=report,
                )
            )

        if fs_type == "ntfs":
            _recover_ntfs_slack(handle, fs, base=partition.offset, report=report)
        if fs_type == "ext4":
            report.limitations.append(EXT4_EXTENTS_ZEROED)
            _recover_ext4_journal(
                handle, fs, window, base=partition.offset, report=report
            )
        if fs_type in {"fat12", "fat16", "fat32"}:
            report.limitations.append(FAT_CHAIN_LOST)

    _drop_shadowed_names(report)
    report.partitions = resolved
    report.allocated = _merge(allocated)
    report.unallocated = _complement(report.allocated, 0, handle.size)
    report.degraded_to_whole_image = not any(item.fs_type for item in resolved)
    report.image_reads = sum(shim.reads for shim in shims)
    report.files.sort(key=lambda item: (item.candidate.offset, item.candidate.length))

    logger.info(
        "undelete.complete",
        partitions=len(resolved),
        candidates=len(report.files),
        unallocated_bytes=sum(item.length for item in report.unallocated),
        degraded=report.degraded_to_whole_image,
    )
    return report


def _drop_shadowed_names(report: UndeleteReport) -> None:
    """Remove a name-only candidate when the same name came back with content.

    One deleted file can be seen twice: TSK surfaces the entry still sitting in
    ``$I30`` slack, which yields a name and no metadata, and the MFT walk finds
    the record itself, which yields the name *and* the run list. They are the
    same file, and reporting both would double every NTFS recall figure.

    Only the empty one is dropped, and only when a candidate with the same name
    and the same filesystem actually recovered bytes. A name-only candidate
    whose content was never found is kept, because that is a real finding.
    """
    with_content = {
        (item.candidate.fs_type, item.candidate.original_name)
        for item in report.files
        if item.extents and item.candidate.original_name
    }
    report.files = [
        item
        for item in report.files
        if item.extents
        or (item.candidate.fs_type, item.candidate.original_name) not in with_content
    ]


def undelete(handle: EvidenceHandle) -> Iterator[CarveCandidate]:
    """Yield a candidate per recoverable entry found in filesystem metadata.

    A thin view over :func:`undelete_report`. Use the report directly when the
    allocated/unallocated map or a candidate's extents are needed - which is
    every caller that intends to hand the unallocated regions to the signature
    carver, or to write a recovered file out.
    """
    yield from undelete_report(handle).candidates


def read_recovered(handle: EvidenceHandle, recovered: RecoveredFile) -> bytes:
    """Reassemble one recovered file's bytes, in order, through the handle.

    Reads the same extents that produced ``candidate.sha256``, so a caller can
    hash the result and check the claim rather than take it. Returns ``b""``
    for a name-only recovery, which is the honest answer: the name survived and
    the content did not.
    """
    out = bytearray()
    for extent in recovered.extents:
        cursor = extent.offset
        remaining = extent.length
        while remaining > 0:
            piece = handle.read(cursor, min(MIB, remaining))
            if not piece:
                break
            out += piece
            cursor += len(piece)
            remaining -= len(piece)
    return bytes(out)
