"""Structure-aware carving: derive the length, do not guess it.

A signature carver finds a header and then guesses where the object ends -
usually by searching for a footer, which fails whenever the footer byte
sequence also occurs inside the object. A JPEG's ``FFD9`` appears at the end of
its own EXIF thumbnail; a PDF holds one ``%%EOF`` per incremental update. The
guess produces a file that is a few hundred bytes wrong, and a file that is a
few hundred bytes wrong does not open.

Every parser here walks the format's own length fields instead, so the answer
is exact or the parser declines. That is the difference between this and
photorec, and it is what makes a recovered object presentable rather than
merely plausible.

**Every parser is bounded, in three ways at once**, because these length fields
come from a disk that may be damaged or hostile:

* a byte cap - never read past the signature's ``max_size``;
* an iteration cap - :data:`MAX_ITERATIONS`, so a zero-length or backward
  "next" pointer cannot spin forever;
* a wall-clock deadline - :data:`PARSE_DEADLINE_S` per object.

A malformed box size of ``0xFFFFFFFF`` must cost microseconds and return
nothing, not attempt a four-gigabyte read.
"""

from __future__ import annotations

import weakref

import hashlib
import re
import time
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Literal

import structlog

from core.carve.evidence import EvidenceHandle
from core.carve.fragmentation import (
    accounts_for_scan,
    is_whole_jpeg,
    reassemble_bifragmented_jpeg_runs,
    reassemble_bifragmented_png_runs,
)
from core.carve.signature import (
    Signature,
    load_signatures,
    scan,
    tar_header_is_valid,
)
from core.carve import signature as _signature_module
from core.models import CarveCandidate

__all__ = [
    "ParsedObject",
    "MAX_ITERATIONS",
    "PARSE_DEADLINE_S",
    "parse_zip",
    "parse_pdf",
    "parse_jpeg",
    "parse_sqlite",
    "parse_png",
    "parse_mp4",
    "parse_tiff",
    "parse_bmp",
    "parse_riff",
    "parse_gzip",
    "parse_tar",
    "parse_rtf",
    "MAX_INFLATE_BYTES",
    "PARSERS",
    "carve_structures",
]

logger = structlog.get_logger(__name__)

MIB = 1024 * 1024

#: Cap on any parser's walk. Chosen well above a legitimate object's structure
#: count (a ZIP with 100k entries, a PNG with 100k chunks) and far below a
#: number that costs noticeable time.
MAX_ITERATIONS = 200_000

#: Wall-clock budget for parsing one object. A damaged image can present
#: pathological structure that is bounded in theory and slow in practice.
PARSE_DEADLINE_S = 5.0

Validation = Literal["valid", "truncated", "corrupt"]


@dataclass(frozen=True)
class ParsedObject:
    """A length derived from the format's own structure."""

    length: int
    validation: Validation
    #: What the parser learned that a footer search could not, for the report.
    detail: str = ""
    #: Set when the header this parse began at is not the start of an object at
    #: all, but a member inside a larger one beginning at this offset. An
    #: archive's members each carry the archive's own magic, and reporting one
    #: object per member describes files that were never on the medium.
    member_of: int | None = None


class _Budget:
    """Iteration and time bound shared by every parser."""

    def __init__(self, deadline_s: float = PARSE_DEADLINE_S) -> None:
        self._started = time.monotonic()
        self._deadline = deadline_s
        self._steps = 0

    def step(self) -> bool:
        """False once the walk must stop. Callers return what they have."""
        self._steps += 1
        if self._steps > MAX_ITERATIONS:
            return False
        if self._steps % 256 == 0:
            return time.monotonic() - self._started < self._deadline
        return True


def _read(handle: EvidenceHandle, offset: int, length: int, cap: int) -> bytes:
    """Read, never crossing the object's byte cap."""
    if offset >= cap:
        return b""
    return handle.read(offset, min(length, cap - offset))


# --------------------------------------------------------------------------
# ZIP
# --------------------------------------------------------------------------

_EOCD = b"PK\x05\x06"
_EOCD64_LOCATOR = b"PK\x06\x07"


class _EocdMemo:
    """End-of-central-directory records already found on one handle.

    AEGIS integration (2026-10-03), a pure performance change. Every member of
    an archive begins ``PK\\x03\\x04``, so every member's parse searched up to a
    gigabyte for the same end record; on a volume of Office documents the same
    bytes were re-read thousands of times. The fields of each ``PK\\x05\\x06``
    record are query-independent and are read once; whether a record ends this
    parse (``_eocd_match``) is still decided per parse, from that parse's own
    start and cap, in the same order the uncached search used, so the derived
    archive is identical.
    """

    def __init__(self) -> None:
        self.records: dict[int, tuple[int, int, int, int] | None] = {}
        self.ranges: list[tuple[int, int]] = []
        self._sorted: list[int] = []
        self._dirty = False

    def cover(self, a: int, b: int) -> None:
        # Consecutive windows overlap, so the ranges merge into a few runs.
        self.ranges.append((a, b))
        self.ranges.sort()
        merged: list[tuple[int, int]] = []
        for lo, hi in self.ranges:
            if merged and lo <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
            else:
                merged.append((lo, hi))
        self.ranges = merged
        self._dirty = True

    def covering(self, offset: int) -> int | None:
        best = None
        for lo, hi in self.ranges:
            if lo <= offset < hi and (best is None or hi > best):
                best = hi
        return best

    def positions_between(self, lo: int, hi: int) -> list[int]:
        if self._dirty:
            self._sorted = sorted(self.records)
            self._dirty = False
        import bisect

        return self._sorted[bisect.bisect_left(self._sorted, lo):bisect.bisect_left(self._sorted, hi)]


_EOCD_MEMOS: "weakref.WeakKeyDictionary[Any, _EocdMemo]" = weakref.WeakKeyDictionary()


def _eocd_memo(handle: EvidenceHandle) -> _EocdMemo:
    try:
        memo = _EOCD_MEMOS.get(handle)
        if memo is None:
            memo = _EocdMemo()
            _EOCD_MEMOS[handle] = memo
        return memo
    except TypeError:
        return _EocdMemo()


def _eocd_fields(handle: EvidenceHandle, absolute: int) -> tuple[int, int, int, int] | None:
    """(end, cd_size, cd_offset, archive_start) of the record at ``absolute``, uncapped."""
    trailer = handle.read(absolute, 22) if absolute + 22 <= handle.size else b""
    if len(trailer) != 22:
        return None
    comment_length = int.from_bytes(trailer[20:22], "little")
    cd_size = int.from_bytes(trailer[12:16], "little")
    cd_offset = int.from_bytes(trailer[16:20], "little")
    return (absolute + 22 + comment_length, cd_size, cd_offset, absolute - cd_size - cd_offset)


def _eocd_match(
    handle: EvidenceHandle, fields: tuple[int, int, int, int] | None, absolute: int, start: int, cap: int
) -> tuple[int, int] | None:
    """The uncached parse's acceptance test for one record, for this start and cap."""
    if fields is None or absolute + 22 > cap:
        return None
    end, cd_size, _cd_offset, archive_start = fields
    if not (end <= cap and 0 <= archive_start <= start):
        return None
    if _read(handle, archive_start, 4, cap) != b"PK\x03\x04":
        return None
    if cd_size and _read(handle, archive_start + _cd_offset, 4, cap) != b"PK\x01\x02":
        return None
    return (archive_start, end)


def parse_zip(
    handle: EvidenceHandle, start: int, *, max_size: int
) -> ParsedObject | None:
    """Walk local file headers to the end-of-central-directory record.

    The EOCD carries the central directory's offset and size, and its own
    position plus its own length is the archive's exact end. That is why a ZIP
    can be carved exactly while a footer search cannot: the EOCD signature also
    occurs inside compressed data.

    The *first* consistent record wins, not the last one inside ``max_size``.
    An unallocated region holds many archives, and a ZIP's cap is a gigabyte,
    so "last record in the window" hands one archive an end address belonging
    to another one megabytes away. Consistency is what settles it: the central
    directory this record describes must start at ``PK\x01\x02`` and must end
    exactly where the record itself begins.

    **The record's offsets are measured from the archive's first byte, not from
    where this parse began.** Every member of an archive starts with the same
    ``PK\x03\x04`` magic, so the scan finds a header at each of them, and a
    parse beginning at a member used to read the archive's own end record as
    inconsistent and fall back to a length of "the rest of the image". The
    central directory ends where its end record begins, and the record says how
    far that directory sits from the archive's start, so those two numbers
    locate the archive wherever the parse began - and a parse that began after
    it is reporting a member, not an object.
    """
    cap = min(start + max_size, handle.size)
    budget = _Budget()
    window = 1 * MIB
    cursor = start
    archive: tuple[int, int] | None = None
    memo = _eocd_memo(handle)

    while cursor < cap and budget.step() and archive is None:
        covered = memo.covering(cursor)
        if covered is not None:
            # Already scanned by an earlier member's parse: evaluate the recorded
            # end records against this parse's start and cap without re-reading.
            for absolute in memo.positions_between(cursor, min(covered, cap)):
                archive = _eocd_match(handle, memo.records[absolute], absolute, start, cap)
                if archive is not None:
                    break
            cursor = max(cursor + 1, covered - len(_EOCD) + 1)
            continue
        block = _read(handle, cursor, window, cap)
        if not block:
            break
        found_here: list[int] = []
        position = 0
        while True:
            found = block.find(_EOCD, position)
            if found == -1:
                break
            found_here.append(cursor + found)
            position = found + 1
        for absolute in found_here:
            memo.records[absolute] = _eocd_fields(handle, absolute)
        memo.cover(cursor, cursor + len(block))
        for absolute in found_here:
            archive = _eocd_match(handle, memo.records[absolute], absolute, start, cap)
            if archive is not None:
                break
        cursor += max(len(block) - len(_EOCD) - 1, 1)

    if archive is None:
        # Nothing was derived. Returning a length here would replace the bound
        # the scan already established - the next header of any type - with a
        # worse one, so the candidate keeps the scan's answer instead.
        return None
    archive_start, end_of_archive = archive
    if archive_start != start:
        return ParsedObject(
            length=0,
            validation="valid",
            detail=(
                f"a local file header inside the archive at byte {archive_start}, "
                "not the start of an archive"
            ),
            member_of=archive_start,
        )
    return ParsedObject(
        length=end_of_archive - start,
        validation="valid",
        detail="length from the end-of-central-directory record",
    )


# --------------------------------------------------------------------------
# PDF
# --------------------------------------------------------------------------


def parse_pdf(
    handle: EvidenceHandle, start: int, *, max_size: int
) -> ParsedObject | None:
    """Take the last ``%%EOF`` that a ``startxref`` corroborates.

    An incrementally updated PDF holds one ``%%EOF`` per revision, and every
    earlier one is a valid-looking but wrong end. Following ``startxref`` from
    each marker confirms which revisions actually belong to *this* document,
    and incidentally proves earlier revisions are still present - a fact the
    report states, because those revisions can hold content the author believed
    deleted.

    Corroboration is what stops the walk running into the next PDF in
    unallocated space. That document's ``startxref`` holds an offset relative
    to *its* first byte, so measured from this object's start it points at
    filler rather than at an ``xref`` keyword or an object header, and the
    marker is rejected.
    """
    cap = min(start + max_size, handle.size)
    budget = _Budget()
    window = 1 * MIB
    cursor = start
    accepted: list[int] = []
    rejected = 0

    while cursor < cap and budget.step() and rejected == 0:
        block = _read(handle, cursor, window, cap)
        if not block:
            break
        position = 0
        while True:
            found = block.find(b"%%EOF", position)
            if found == -1:
                break
            marker = cursor + found
            contiguous = not accepted or _revision_follows(
                handle, accepted[-1], marker, cap
            )
            if contiguous and _startxref_corroborates(handle, start, marker, cap):
                accepted.append(marker + 5)
            elif accepted:
                # A marker this object cannot account for is where this object
                # ends. Anything past it belongs to something else.
                rejected += 1
                break
            position = found + 1
        if rejected:
            break
        cursor += max(len(block) - 5, 1)

    if not accepted:
        # No revision of this document was corroborated, so no length was
        # derived. The scan's neighbour bound stands; see :func:`parse_zip`.
        return None

    end = accepted[-1]
    # Consume a trailing newline so the length matches the file on disk.
    tail = _read(handle, end, 2, cap)
    if tail.startswith(b"\r\n"):
        end += 2
    elif tail[:1] in (b"\n", b"\r"):
        end += 1

    detail = "length from the final corroborated %%EOF"
    if len(accepted) > 1:
        detail += (
            f"; {len(accepted) - 1} earlier revision(s) present, which may retain "
            "content removed in later ones"
        )
    return ParsedObject(length=end - start, validation="valid", detail=detail)


#: What the first bytes of a PDF revision look like: a comment, an object
#: header, a cross-reference table or a trailer.
_REVISION_START = re.compile(
    rb"^[ \t\r\n]*(%|[0-9]+[ \t\r\n]+[0-9]+[ \t\r\n]+obj|xref|trailer)"
)


def _revision_follows(
    handle: EvidenceHandle, previous_end: int, marker: int, cap: int
) -> bool:
    """Whether the bytes after the previous ``%%EOF`` continue the same document.

    An incremental update begins immediately after the revision it updates.
    Random unallocated bytes between one ``%%EOF`` and the next mean the second
    marker belongs to a different file that happens to lie further along the
    image - which is exactly the case that hands one PDF an end address five
    megabytes away.
    """
    if marker <= previous_end:
        return False
    if not _REVISION_START.match(_read(handle, previous_end, 24, cap)):
        return False
    # The prefix test alone is one byte of evidence when the byte is ``%``,
    # and uniform filler starts with ``%`` or whitespace often enough to
    # matter: on the 1 GiB validation image (docs/validation/large-image.md),
    # a 453-byte PDF took the ``%%EOF`` of an identical PDF 11 MB later - whose
    # ``startxref`` necessarily pointed back at this one's xref - and scored
    # HIGH at 11 MB. An incremental update appends revisions; it never contains
    # a second ``%PDF-`` header. One between the two markers means the second
    # marker ends a different document.
    return not _contains(handle, b"%PDF-", previous_end, marker, cap)


def _contains(
    handle: EvidenceHandle, needle: bytes, start: int, end: int, cap: int
) -> bool:
    """Whether ``needle`` occurs in ``[start, end)``, read in bounded windows."""
    window = 1 * MIB
    cursor = start
    stop = min(end, cap)
    while cursor < stop:
        block = _read(handle, cursor, min(window, stop - cursor), cap)
        if not block:
            return False
        if block.find(needle) != -1:
            return True
        if cursor + len(block) >= stop:
            return False
        cursor += max(len(block) - (len(needle) - 1), 1)
    return False


#: How far back from a ``%%EOF`` the ``startxref`` keyword and its operand sit.
#: The trailer between them is short by construction.
_STARTXREF_LOOKBACK = 128

_XREF_OBJECT = re.compile(rb"^\d+\s+\d+\s+obj")


def _startxref_corroborates(
    handle: EvidenceHandle, start: int, marker: int, cap: int
) -> bool:
    """Whether the ``startxref`` before ``marker`` points into this object.

    The offset is relative to the first byte of the document, which is exactly
    what makes it useful here: measured from a *different* document's start it
    lands on nothing.
    """
    look_from = max(start, marker - _STARTXREF_LOOKBACK)
    tail = _read(handle, look_from, marker - look_from, cap)
    keyword = tail.rfind(b"startxref")
    if keyword == -1:
        return False
    digits = tail[keyword + len(b"startxref") :].strip()
    number = digits.split(b"%")[0].strip()
    if not number.isdigit():
        return False
    target = start + int(number)
    if not start <= target < marker:
        return False
    at_target = _read(handle, target, 24, cap)
    return at_target.startswith(b"xref") or bool(_XREF_OBJECT.match(at_target))


# --------------------------------------------------------------------------
# JPEG
# --------------------------------------------------------------------------


def parse_jpeg(
    handle: EvidenceHandle, start: int, *, max_size: int
) -> ParsedObject | None:
    """Walk SOI, segment markers, SOS, entropy-coded data, EOI.

    Walking segments is what lets truncation be *detected* rather than assumed:
    reaching the cap without an EOI means the object really is short, and the
    thumbnail's own ``FFD9`` never terminates the walk because it lives inside
    an APP1 segment whose declared length steps straight over it.
    """
    cap = min(start + max_size, handle.size)
    budget = _Budget()
    header = _read(handle, start, 2, cap)
    if header != b"\xff\xd8":
        return None

    cursor = start + 2
    while cursor < cap and budget.step():
        marker = _read(handle, cursor, 2, cap)
        if len(marker) < 2:
            return ParsedObject(
                length=cap - start, validation="truncated", detail="ran out of data"
            )
        if marker[0] != 0xFF:
            return ParsedObject(
                length=cursor - start,
                validation="corrupt",
                detail=f"expected a marker at {cursor}, found {marker[0]:#04x}",
            )
        kind = marker[1]
        if kind == 0xD9:  # EOI
            return ParsedObject(
                length=cursor + 2 - start,
                validation="valid",
                detail="length from the EOI marker after a full segment walk",
            )
        if kind in (0x01,) or 0xD0 <= kind <= 0xD8:
            cursor += 2  # standalone markers carry no length
            continue

        size_bytes = _read(handle, cursor + 2, 2, cap)
        if len(size_bytes) < 2:
            return ParsedObject(
                length=cap - start, validation="truncated", detail="segment truncated"
            )
        segment_length = int.from_bytes(size_bytes, "big")
        if segment_length < 2:
            return ParsedObject(
                length=cursor - start,
                validation="corrupt",
                detail=f"segment length {segment_length} at {cursor} is impossible",
            )

        if kind == 0xDA:  # SOS: entropy-coded data follows, scan for EOI
            cursor += 2 + segment_length
            return _scan_entropy_to_eoi(handle, start, cursor, cap, budget)
        cursor += 2 + segment_length

    return ParsedObject(
        length=cap - start, validation="truncated", detail="no EOI within max_size"
    )


def _scan_entropy_to_eoi(
    handle: EvidenceHandle,
    start: int,
    cursor: int,
    cap: int,
    budget: _Budget,
) -> ParsedObject:
    """Find EOI past the scan header, skipping stuffed bytes and RST markers."""
    window = 64 * 1024
    position = cursor
    while position < cap and budget.step():
        block = _read(handle, position, window, cap)
        if not block:
            break
        index = 0
        while index < len(block) - 1:
            if block[index] != 0xFF:
                index += 1
                continue
            following = block[index + 1]
            # 0x00 is a stuffed byte, 0xD0-0xD7 are restart markers: both are
            # part of the entropy stream, not the end of it.
            if following == 0x00 or 0xD0 <= following <= 0xD7:
                index += 2
                continue
            if following == 0xD9:
                return ParsedObject(
                    length=position + index + 2 - start,
                    validation="valid",
                    detail="length from the EOI marker after a full segment walk",
                )
            index += 1
        position += max(len(block) - 1, 1)
    return ParsedObject(
        length=cap - start,
        validation="truncated",
        detail="entropy-coded data ran to max_size with no EOI",
    )


# --------------------------------------------------------------------------
# SQLite
# --------------------------------------------------------------------------


def parse_sqlite(
    handle: EvidenceHandle, start: int, *, max_size: int
) -> ParsedObject | None:
    """page_size x page_count, both read straight from the 100-byte header."""
    cap = min(start + max_size, handle.size)
    header = _read(handle, start, 32, cap)
    if len(header) < 32 or not header.startswith(b"SQLite format 3\x00"):
        return None

    raw_page_size = int.from_bytes(header[16:18], "big")
    # 1 is the format's escape for 65536, which does not fit the 16-bit field.
    page_size = 65536 if raw_page_size == 1 else raw_page_size
    # Each of these three is a header this parser cannot turn into a length.
    # None of them is a reason to claim the rest of the image: the scan's
    # neighbour bound is always tighter. See :func:`parse_zip`.
    if page_size < 512 or (page_size & (page_size - 1)):
        return None

    page_count = int.from_bytes(header[28:32], "big")
    if page_count == 0:
        return None

    length = page_size * page_count
    if length > max_size or start + length > handle.size:
        return None
    return ParsedObject(
        length=length,
        validation="valid",
        detail=f"length from page_size {page_size} x page_count {page_count}",
    )


# --------------------------------------------------------------------------
# PNG
# --------------------------------------------------------------------------

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def parse_png(
    handle: EvidenceHandle, start: int, *, max_size: int
) -> ParsedObject | None:
    """Walk length-prefixed chunks to IEND, verifying each chunk's CRC32.

    The CRC check is the reason this reports ``corrupt`` rather than ``valid``
    for damaged data. A carver that only checks the IEND marker hands back a
    file that opens to a grey smear, and calls it recovered.
    """
    cap = min(start + max_size, handle.size)
    budget = _Budget()
    if _read(handle, start, 8, cap) != _PNG_MAGIC:
        return None

    cursor = start + 8
    saw_ihdr = False
    while cursor < cap and budget.step():
        head = _read(handle, cursor, 8, cap)
        if len(head) < 8:
            return ParsedObject(
                length=cap - start, validation="truncated", detail="chunk header short"
            )
        length = int.from_bytes(head[0:4], "big")
        kind = head[4:8]
        if length > max_size:
            return ParsedObject(
                length=cursor - start,
                validation="corrupt",
                detail=f"chunk {kind!r} declares {length} bytes",
            )
        payload = _read(handle, cursor + 8, length, cap)
        crc_bytes = _read(handle, cursor + 8 + length, 4, cap)
        if len(payload) < length or len(crc_bytes) < 4:
            return ParsedObject(
                length=cap - start,
                validation="truncated",
                detail=f"chunk {kind!r} runs past the available data",
            )
        expected = int.from_bytes(crc_bytes, "big")
        if zlib.crc32(kind + payload) & 0xFFFFFFFF != expected:
            return ParsedObject(
                length=cursor + 12 + length - start,
                validation="corrupt",
                detail=f"CRC mismatch in chunk {kind.decode('latin-1')}",
            )
        if kind == b"IHDR":
            saw_ihdr = True
        cursor += 12 + length
        if kind == b"IEND":
            return ParsedObject(
                length=cursor - start,
                validation="valid" if saw_ihdr else "corrupt",
                detail="length from the IEND chunk, every CRC verified",
            )

    return ParsedObject(
        length=cap - start, validation="truncated", detail="no IEND within max_size"
    )


# --------------------------------------------------------------------------
# MP4
# --------------------------------------------------------------------------


def parse_mp4(
    handle: EvidenceHandle, start: int, *, max_size: int
) -> ParsedObject | None:
    """Walk top-level boxes by their size field, honouring the 64-bit escape.

    ``size == 1`` means the real size follows as a 64-bit ``largesize``;
    ``size == 0`` means "to end of file" and may only appear last. Both are
    common sources of runaway reads in naive parsers, along with a corrupt
    ``0xFFFFFFFF``: every one of them is bounded here rather than trusted.
    """
    cap = min(start + max_size, handle.size)
    budget = _Budget()
    cursor = start
    saw_ftyp = False

    while cursor < cap and budget.step():
        head = _read(handle, cursor, 8, cap)
        if len(head) < 8:
            break
        size = int.from_bytes(head[0:4], "big")
        kind = head[4:8]
        header_bytes = 8

        if size == 1:
            large = _read(handle, cursor + 8, 8, cap)
            if len(large) < 8:
                return ParsedObject(
                    length=cursor - start,
                    validation="truncated",
                    detail="64-bit box size is itself truncated",
                )
            size = int.from_bytes(large, "big")
            header_bytes = 16
        elif size == 0:
            # "To end of file", and legal only as the final box. The bytes
            # after a file in its last cluster are zeros, and eight zero bytes
            # read as a box of size 0 with a name of four NULs - which is not a
            # box. Read that way, every MP4 on a volume became a candidate
            # running to the end of the image. Either way the walk stops here
            # and the length is the boxes that actually parsed.
            if not saw_ftyp:
                return None
            if head == bytes(8):
                return ParsedObject(
                    length=cursor - start,
                    validation="valid",
                    detail=(
                        "length from walking the top-level box sizes; the data "
                        f"at byte {cursor - start} is zero fill, not a box"
                    ),
                )
            return ParsedObject(
                length=cursor - start,
                validation="truncated",
                detail=(
                    f"box {kind!r} at {cursor} declares size 0, meaning it runs "
                    "to the end of the data; nothing in the file bounds it, so "
                    "the length is the boxes that parsed"
                ),
            )

        if size < header_bytes or cursor + size > cap:
            return ParsedObject(
                length=cursor - start if saw_ftyp else 0,
                validation="corrupt",
                detail=(
                    f"box {kind!r} at {cursor} declares {size} bytes, which "
                    f"exceeds the {cap - start} byte bound"
                ),
            )
        if kind == b"ftyp":
            saw_ftyp = True
        cursor += size

    if not saw_ftyp:
        return None
    return ParsedObject(
        length=cursor - start,
        validation="valid",
        detail="length from walking the top-level box sizes",
    )


# --------------------------------------------------------------------------
# TIFF
# --------------------------------------------------------------------------

#: Bytes per TIFF field type, by the code an IFD entry stores. Types above 12
#: were added by later specifications; an entry using one is stepped over
#: rather than sized by guesswork.
_TIFF_TYPE_BYTES = {
    1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8
}

#: Tags holding a list of offsets, each paired with the tag holding the
#: matching list of lengths. This is where a TIFF's pixels actually are: the
#: IFD chain alone describes a few hundred bytes of a file that is megabytes.
_TIFF_DATA_TAGS = {
    273: 279,  # StripOffsets / StripByteCounts
    324: 325,  # TileOffsets / TileByteCounts
    513: 514,  # JPEGInterchangeFormat / JPEGInterchangeFormatLength
}

#: Most strips or tiles one IFD may claim. A corrupt count field would
#: otherwise ask for a list of four billion offsets.
_TIFF_MAX_STRIPS = 1_000_000


def _tiff_values(
    handle: EvidenceHandle,
    entry: bytes,
    order: Literal["little", "big"],
    start: int,
    cap: int,
) -> list[int]:
    """The integer list an IFD entry holds, inline when it fits or at its offset."""
    kind = int.from_bytes(entry[2:4], order)
    number = int.from_bytes(entry[4:8], order)
    width = _TIFF_TYPE_BYTES.get(kind)
    if width is None or width > 4 or number > _TIFF_MAX_STRIPS:
        return []
    size = width * number
    if size <= 4:
        raw = entry[8 : 8 + size]
    else:
        raw = _read(handle, start + int.from_bytes(entry[8:12], order), size, cap)
    if len(raw) < size:
        return []
    return [
        int.from_bytes(raw[index * width : (index + 1) * width], order)
        for index in range(number)
    ]


def parse_tiff(
    handle: EvidenceHandle, start: int, *, max_size: int
) -> ParsedObject | None:
    """Walk the IFD chain and every strip of pixels it points at.

    A TIFF has no footer and no field saying how long it is. What it has is a
    chain of image file directories, each listing where its pixel data sits and
    how many bytes it occupies, so the object ends at the furthest byte any of
    those records reaches. Nothing else can say where a TIFF ends - the bytes
    after one look exactly like the bytes inside it - which is why this format
    having a signature and no parser produced candidates that ran to the end of
    the image.
    """
    cap = min(start + max_size, handle.size)
    budget = _Budget()
    head = _read(handle, start, 8, cap)
    if len(head) < 8:
        return None
    if head[:2] == b"II":
        order: Literal["little", "big"] = "little"
    elif head[:2] == b"MM":
        order = "big"
    else:
        return None
    if int.from_bytes(head[2:4], order) != 42:
        return None

    end = start + 8
    next_ifd = int.from_bytes(head[4:8], order)
    seen: set[int] = set()
    while next_ifd and budget.step():
        if next_ifd in seen:
            break  # a chain pointing back at itself is not a longer file
        seen.add(next_ifd)
        directory = start + next_ifd
        count_bytes = _read(handle, directory, 2, cap)
        if len(count_bytes) < 2:
            return _tiff_short(start, end, cap, "the IFD header")
        entries = int.from_bytes(count_bytes, order)
        table = _read(handle, directory + 2, entries * 12 + 4, cap)
        if len(table) < entries * 12 + 4:
            return _tiff_short(start, end, cap, "an IFD's entry table")
        end = max(end, directory + 2 + entries * 12 + 4)

        lists: dict[int, list[int]] = {}
        for index in range(entries):
            entry = table[index * 12 : index * 12 + 12]
            tag = int.from_bytes(entry[0:2], order)
            kind = int.from_bytes(entry[2:4], order)
            number = int.from_bytes(entry[4:8], order)
            width = _TIFF_TYPE_BYTES.get(kind)
            if width is None:
                continue
            size = width * number
            if size > 4:
                # The value did not fit the entry, so the entry holds its
                # address and those bytes are part of the file too.
                end = max(end, start + int.from_bytes(entry[8:12], order) + size)
            if tag in _TIFF_DATA_TAGS or tag in _TIFF_DATA_TAGS.values():
                lists[tag] = _tiff_values(handle, entry, order, start, cap)

        for offsets_tag, counts_tag in _TIFF_DATA_TAGS.items():
            for offset, length in zip(
                lists.get(offsets_tag, []), lists.get(counts_tag, []), strict=False
            ):
                end = max(end, start + offset + length)
        next_ifd = int.from_bytes(table[entries * 12 : entries * 12 + 4], order)

    if end > cap:
        return _tiff_short(start, end, cap, "the strips an IFD points at")
    return ParsedObject(
        length=end - start,
        validation="valid",
        detail="length from the IFD chain and the strip offsets it points at",
    )


def _tiff_short(start: int, end: int, cap: int, what: str) -> ParsedObject:
    """What to report when the IFD chain reaches past the bytes available."""
    return ParsedObject(
        length=min(end, cap) - start,
        validation="truncated",
        detail=f"{what} runs past the {cap - start} bytes available",
    )


# --------------------------------------------------------------------------
# BMP
# --------------------------------------------------------------------------


def parse_bmp(
    handle: EvidenceHandle, start: int, *, max_size: int
) -> ParsedObject | None:
    """The file header's own 32-bit size field, checked against the DIB header."""
    cap = min(start + max_size, handle.size)
    head = _read(handle, start, 18, cap)
    if len(head) < 18 or head[:2] != b"BM":
        return None
    declared = int.from_bytes(head[2:6], "little")
    pixels_at = int.from_bytes(head[10:14], "little")
    dib_size = int.from_bytes(head[14:18], "little")
    if declared < 14 + dib_size or pixels_at > declared or declared > max_size:
        return None
    if start + declared > cap:
        return ParsedObject(
            length=cap - start,
            validation="truncated",
            detail=f"the header declares {declared} bytes, more than remains",
        )
    return ParsedObject(
        length=declared,
        validation="valid",
        detail=f"length from the {declared}-byte file size in the BMP header",
    )


# --------------------------------------------------------------------------
# RIFF: WebP and WAV
# --------------------------------------------------------------------------


def parse_riff(
    handle: EvidenceHandle, start: int, *, max_size: int
) -> ParsedObject | None:
    """``RIFF`` plus its size field, which counts everything after those 8 bytes."""
    cap = min(start + max_size, handle.size)
    head = _read(handle, start, 12, cap)
    if len(head) < 12 or head[:4] != b"RIFF":
        return None
    declared = int.from_bytes(head[4:8], "little")
    length = declared + 8
    if declared < 4 or length > max_size:
        return None
    form = head[8:12].decode("latin-1")
    if start + length > cap:
        return ParsedObject(
            length=cap - start,
            validation="truncated",
            detail=f"the RIFF size field declares {length} bytes, more than remains",
        )
    return ParsedObject(
        length=length,
        validation="valid",
        detail=f"length from the RIFF size field of a {form} container",
    )


# --------------------------------------------------------------------------
# GZIP
# --------------------------------------------------------------------------

_GZIP_MAGIC = b"\x1f\x8b\x08"

#: Compressed bytes handed to the decompressor at a time.
_GZIP_READ_BYTES = 64 * 1024

#: Decompressed bytes produced per call. The output is counted and discarded,
#: never accumulated, so this bounds the transient allocation rather than the
#: total.
_INFLATE_STEP_BYTES = 1 * MIB

#: Most bytes a member may inflate to before this parser gives up on it. A
#: gzip bomb is a small file that decompresses to gigabytes, and deriving a
#: length is not worth that much work on a carved candidate.
MAX_INFLATE_BYTES = 256 * MIB


def parse_gzip(
    handle: EvidenceHandle, start: int, *, max_size: int
) -> ParsedObject | None:
    """Inflate the member to find where its compressed stream stops.

    A gzip member has no footer a search can find: its 8-byte trailer is a CRC
    and a length, and both are arbitrary bytes that occur everywhere, including
    inside the compressed data itself. The only thing that says where the
    stream ends is the stream, so it is inflated - the output counted and
    thrown away, never held, bounded by :data:`MAX_INFLATE_BYTES` - and the end
    is where the decompressor reports it. Members written one after another are
    one file, so the walk continues while the next bytes are another header.
    """
    cap = min(start + max_size, handle.size)
    budget = _Budget()
    cursor = start
    produced = 0
    members = 0

    while cursor < cap and budget.step():
        if _read(handle, cursor, 3, cap) != _GZIP_MAGIC:
            break
        engine = zlib.decompressobj(16 + zlib.MAX_WBITS)
        position = cursor
        finished = False
        while position < cap and budget.step():
            block = _read(handle, position, _GZIP_READ_BYTES, cap)
            if not block:
                break
            try:
                produced += len(engine.decompress(block, _INFLATE_STEP_BYTES))
                while engine.unconsumed_tail and not engine.eof:
                    if produced > MAX_INFLATE_BYTES:
                        return None
                    produced += len(
                        engine.decompress(
                            engine.unconsumed_tail, _INFLATE_STEP_BYTES
                        )
                    )
            except zlib.error:
                if not members:
                    return None
                break
            if produced > MAX_INFLATE_BYTES:
                return None
            if engine.eof:
                position += len(block) - len(engine.unused_data)
                finished = True
                break
            position += len(block)
        if not finished:
            if not members:
                return ParsedObject(
                    length=cap - start,
                    validation="truncated",
                    detail="the deflate stream does not end within the data available",
                )
            break
        cursor = position
        members += 1

    if not members:
        return None
    return ParsedObject(
        length=cursor - start,
        validation="valid",
        detail=f"length from inflating {members} gzip member(s)",
    )


# --------------------------------------------------------------------------
# TAR
# --------------------------------------------------------------------------

_TAR_BLOCK = 512
_TAR_SIZE_AT = 124
_TAR_SIZE_BYTES = 12


def _tar_octal(field: bytes) -> int | None:
    """A ustar numeric field, which is octal digits ended by a NUL or a space."""
    digits = field.split(b"\x00")[0].split(b" ")[0]
    if not digits:
        return 0
    try:
        return int(digits, 8)
    except ValueError:
        return None


def parse_tar(
    handle: EvidenceHandle, start: int, *, max_size: int
) -> ParsedObject | None:
    """Walk 512-byte member headers to the end-of-archive marker.

    **What one tar candidate is.** A tar is a run of members, each a 512-byte
    header whose own checksum verifies followed by its contents padded to 512,
    and it has no archive-level length field. One candidate is the whole run,
    not one per member: a member header is not a file that was on the medium,
    it is a record inside one that was.

    The archive ends at the marker the format defines, two zero blocks. **The
    padding a writer adds after that marker is not claimed.** GNU tar pads to
    its blocking factor, 10,240 bytes by default, and those bytes are zeros -
    indistinguishable from the zeros of the last cluster's slack. Claiming them
    would be the same defect as reading cluster slack as an MP4 box. The
    consequence is stated rather than hidden: an archive its writer padded is
    returned without that padding, so it is not byte-identical to the file as
    written, and this parser reports the length it can account for.
    """
    cap = min(start + max_size, handle.size)
    budget = _Budget()
    cursor = start
    members = 0

    while cursor < cap and budget.step():
        block = _read(handle, cursor, _TAR_BLOCK, cap)
        if len(block) < _TAR_BLOCK:
            break
        if not block.strip(b"\x00"):
            if not members:
                return None
            following = _read(handle, cursor + _TAR_BLOCK, _TAR_BLOCK, cap)
            pair = len(following) == _TAR_BLOCK and not following.strip(b"\x00")
            end = cursor + _TAR_BLOCK * (2 if pair else 1)
            return ParsedObject(
                length=min(end, cap) - start,
                validation="valid",
                detail=(
                    f"length from {members} member header(s) and the "
                    "end-of-archive marker"
                ),
            )
        if not tar_header_is_valid(block):
            break
        size = _tar_octal(block[_TAR_SIZE_AT : _TAR_SIZE_AT + _TAR_SIZE_BYTES])
        if size is None:
            break
        padded = (size + _TAR_BLOCK - 1) // _TAR_BLOCK * _TAR_BLOCK
        cursor += _TAR_BLOCK + padded
        members += 1

    if not members:
        return None
    if cursor > cap:
        return ParsedObject(
            length=cap - start,
            validation="truncated",
            detail=f"member {members} runs past the bytes available",
        )
    return ParsedObject(
        length=cursor - start,
        validation="truncated",
        detail=(
            f"{members} member header(s) parsed, and no end-of-archive marker "
            "follows them: the archive is not complete here"
        ),
    )


# --------------------------------------------------------------------------
# RTF
# --------------------------------------------------------------------------


def parse_rtf(
    handle: EvidenceHandle, start: int, *, max_size: int
) -> ParsedObject | None:
    """Count braces to the one that closes the document's outermost group.

    An RTF document is one group: it opens with ``{\\rtf1`` and ends at the
    brace matching that first one. Groups nest, and a literal brace in the text
    is written ``\\{``, so the end is found by counting with the escape
    honoured - not by searching for the last ``}``, which is inside the text as
    often as it is the end of the file.
    """
    cap = min(start + max_size, handle.size)
    budget = _Budget()
    if _read(handle, start, 6, cap) != b"{\\rtf1":
        return None

    depth = 0
    cursor = start
    window = 64 * 1024
    while cursor < cap and budget.step():
        block = _read(handle, cursor, window, cap)
        if not block:
            break
        index = 0
        while index < len(block):
            byte = block[index]
            if byte == 0x5C:  # a backslash escapes whatever follows it
                index += 2
                continue
            if byte == 0x7B:
                depth += 1
            elif byte == 0x7D:
                depth -= 1
                if depth == 0:
                    return ParsedObject(
                        length=cursor + index + 1 - start,
                        validation="valid",
                        detail="length from the brace closing the document group",
                    )
            index += 1
        # ``index`` can end one past the block when its last byte was an escape,
        # which is exactly where the next read must begin.
        cursor += max(index, 1)

    return ParsedObject(
        length=cap - start,
        validation="truncated",
        detail=f"the document group is still {depth} deep at the end of the data",
    )


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------

_HTML_CLOSE = b"</html>"


def parse_html(
    handle: EvidenceHandle, start: int, *, max_size: int
) -> ParsedObject | None:
    """Bound the document at its closing tag, with the newline after it.

    **This is a footer bound, not a derived length, and it is reported as
    one.** HTML carries no length field anywhere, and ``</html>`` is a
    convention rather than a requirement: a document written without it is left
    to the bound the scan took from the next object, and says so by declining
    here. The trailing line terminator is consumed for the same reason
    :func:`parse_pdf` consumes one - a text file written by an editor ends with
    it, and a length one byte short is a file that differs from the original.
    """
    cap = min(start + max_size, handle.size)
    budget = _Budget()
    window = 1 * MIB
    overlap = len(_HTML_CLOSE) - 1
    cursor = start

    while cursor < cap and budget.step():
        block = _read(handle, cursor, window, cap)
        if not block:
            break
        found = block.find(_HTML_CLOSE)
        if found != -1:
            end = cursor + found + len(_HTML_CLOSE)
            tail = _read(handle, end, 2, cap)
            if tail.startswith(b"\r\n"):
                end += 2
            elif tail[:1] in (b"\n", b"\r"):
                end += 1
            return ParsedObject(
                length=end - start,
                validation="valid",
                detail="length from the closing </html> tag",
            )
        cursor += max(len(block) - overlap, 1)
    return None


# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------

#: Signature name -> parser. A format absent here falls back to the signature
#: carver's footer bound, and its candidate says ``source="signature"``.
PARSERS = {
    "ZIP": parse_zip,
    "PDF": parse_pdf,
    "JPEG": parse_jpeg,
    "SQLite": parse_sqlite,
    "PNG": parse_png,
    "MP4": parse_mp4,
    "TIFF-LE": parse_tiff,
    "TIFF-BE": parse_tiff,
    "BMP": parse_bmp,
    "WebP": parse_riff,
    "WAV": parse_riff,
    "GZIP": parse_gzip,
    "TAR": parse_tar,
    "RTF": parse_rtf,
    "HTML": parse_html,
    "HTML-tag": parse_html,
}

#: Formats whose objects hold headers of their own format. Every member of an
#: archive carries the archive's magic, and an HTML document carries ``<html>``
#: after its doctype. A header of the same format inside an object whose length
#: a parser derived belongs to that object; reported on its own it is a file
#: that was never on the medium.
_SELF_NESTING_EXTS = frozenset({"zip", "tar", "html"})

#: Formats for which bifragment reassembly is attempted. Deliberately one.
#: Formats with a reassembler, and the reassembler. Each one accounts for the
#: object's bytes exactly (JPEG: Huffman scan accounting; PNG: chunk CRCs plus
#: an exact-length zlib stream) rather than trusting a decoder that tolerates.
_FRAGMENT_CAPABLE = {
    "JPEG": reassemble_bifragmented_jpeg_runs,
    "PNG": reassemble_bifragmented_png_runs,
}


def _signature_by_ext(signatures: list[Signature]) -> dict[str, Signature]:
    return {signature.ext: signature for signature in signatures}


def carve_structures(
    image: EvidenceHandle,
    *,
    attempt_reassembly: bool = True,
    cluster_bytes_at: Callable[[int], int | None] | None = None,
) -> Iterator[CarveCandidate]:
    """Locate objects, then derive each one's length by parsing it.

    Candidates a parser resolved carry ``source="structure"``. Candidates whose
    format has no parser, or whose parse declined, keep ``source="signature"``
    and the footer-derived bound.

    ``cluster_bytes_at`` maps an image offset to the cluster size of the volume
    holding it, or ``None`` where no filesystem was recognised. This function
    has no filesystem context of its own; the undelete pass does. A known size
    restricts a reassembled object's runs to that grid, since no allocator
    produces any other layout; an unknown one leaves the search on the 512-byte
    sector grid, which every allocator's layout lies on.
    """
    signatures = load_signatures()
    by_ext = _signature_by_ext(signatures)
    by_name = {signature.name: signature for signature in signatures}
    report = scan(image, signatures=signatures)
    # Where each container format's last derived object ends. A header of the
    # same format inside that range is one of its members. Candidates arrive in
    # offset order, so one high-water mark per format is all this needs.
    covered: dict[str, int] = {}

    for position, candidate in enumerate(report.candidates):
        # AEGIS integration: progress for this otherwise silent loop (see
        # signature.STAGE_PROGRESS_HOOK). Looked up per call so a hook set after
        # import is honoured; it changes nothing that is parsed.
        if _signature_module.STAGE_PROGRESS_HOOK is not None:
            _signature_module.STAGE_PROGRESS_HOOK("parse", position, len(report.candidates))
        signature = by_ext.get(candidate.ext)
        name = signature.name if signature else ""
        # GIF87a/GIF89a share an ext; the parser table is keyed by name.
        parser = PARSERS.get(name) or next(
            (PARSERS[key] for key in PARSERS if by_name[key].ext == candidate.ext),
            None,
        )
        if parser is None or signature is None:
            yield candidate
            continue
        if candidate.offset < covered.get(candidate.ext, 0):
            # Inside an object of this format whose length a parser derived.
            continue

        parsed = parser(image, candidate.offset, max_size=signature.max_size)
        if parsed is None:
            yield candidate
            continue
        if parsed.member_of is not None:
            continue

        length = parsed.length
        validation = parsed.validation
        if validation != "valid" and length > candidate.length:
            # A parse that derived nothing must not claim more than the scan
            # already established. The scan bounds a footerless object by the
            # next header of any type; a parser's "the rest of my window" is
            # never tighter than that, and where an image holds one object of a
            # format it is the rest of the image.
            length = candidate.length
        if candidate.ext in _SELF_NESTING_EXTS and validation == "valid":
            covered[candidate.ext] = candidate.offset + length
        reassembly_capable = attempt_reassembly and name in _FRAGMENT_CAPABLE

        if reassembly_capable and name == "JPEG" and validation == "valid":
            # A JPEG segment walk cannot tell a contiguous object from
            # head + gap + tail. Entropy-coded data is arbitrary bytes, so
            # _scan_entropy_to_eoi steps over an unrelated 32 KiB of somebody
            # else's file and stops at the real EOI on the far side of the gap
            # - reporting "valid" for a span that was never one object. The
            # only thing that can tell the difference is a decoder, so ask one
            # before the verdict leaves this function - and a decoder is not
            # enough on its own: when the gap holds zeros, text or directory
            # entries the span decodes cleanly. Exact scan accounting sees it.
            # Gated on _FRAGMENT_CAPABLE: this is one extra decode per JPEG
            # candidate and it buys nothing for a format with no reassembler.
            span = _read_range(image, candidate.offset, length)
            if not is_whole_jpeg(span) or accounts_for_scan(span) is False:
                validation = "corrupt"

        if reassembly_capable and validation != "valid":
            cluster = None if cluster_bytes_at is None else cluster_bytes_at(
                candidate.offset
            )
            rebuilt = _FRAGMENT_CAPABLE[name](
                image,
                candidate.offset,
                max_size=signature.max_size,
                cluster_size=cluster,
            )
            if rebuilt is not None:
                # The digest is of the reassembled content. The runs say where
                # each byte of it was, so the claim can be checked against the
                # medium; without them offset+length would describe the gap as
                # part of the file. A single run means the search found the
                # object contiguous after all, at a length the parser got
                # wrong, and it is recorded as the contiguous object it is.
                yield candidate.model_copy(
                    update={
                        "offset": rebuilt.runs[0].offset,
                        "length": len(rebuilt.payload),
                        "source": "structure",
                        "validation": "valid",
                        "confidence_bp": 7500,
                        "bucket": "MEDIUM",
                        "sha256": hashlib.sha256(rebuilt.payload).hexdigest(),
                        "possibly_fragmented": rebuilt.fragmented,
                        "fragments": list(rebuilt.runs) if rebuilt.fragmented else [],
                    }
                )
                continue

        # Reassembly was not attempted, or was attempted and failed. Either way
        # the candidate keeps the span the parser delineated, which really is on
        # the medium and really does hash to the digest below. It says
        # possibly_fragmented, it does not say valid, and it does not claim a
        # digest for bytes nobody can point at - the downstream decoder in
        # core.carve.validate then has the last word on the verdict.
        fragmented = validation != "valid"
        yield candidate.model_copy(
            update={
                "length": length,
                "source": "structure",
                "validation": validation,
                "confidence_bp": 9500 if validation == "valid" else 4000,
                "bucket": "HIGH" if validation == "valid" else "LOW",
                "sha256": _hash_range(image, candidate.offset, length),
                "possibly_fragmented": fragmented,
            }
        )


def _read_range(handle: EvidenceHandle, offset: int, length: int) -> bytes:
    """Copy one span out of the evidence, a megabyte at a time."""
    out = bytearray()
    cursor = offset
    remaining = length
    while remaining > 0:
        piece = handle.read(cursor, min(MIB, remaining))
        if not piece:
            break
        out += piece
        cursor += len(piece)
        remaining -= len(piece)
    return bytes(out)


def _hash_range(handle: EvidenceHandle, offset: int, length: int) -> str:
    digest = hashlib.sha256()
    cursor = offset
    remaining = length
    while remaining > 0:
        piece = handle.read(cursor, min(MIB, remaining))
        if not piece:
            break
        digest.update(piece)
        cursor += len(piece)
        remaining -= len(piece)
    return digest.hexdigest()
