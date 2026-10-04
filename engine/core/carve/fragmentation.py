"""Bifragment gap carving, for baseline JPEG and PNG and for nothing else.

**Read this before extending it.** General fragment reassembly - "SmartCarving"
in the literature - is an open research problem. Deciding which of a million
clusters continue a given object is combinatorial, and published systems reach
useful accuracy only on narrow corpora with format-specific decoders. A tool
that claims to reassemble arbitrary fragmented files is a tool that will be
taken apart by anyone who asks how, and rightly.

What is tractable is the *bifragmented* case: an object split into exactly two
runs separated by one gap, which is what a filesystem produces when an existing
extent blocks a contiguous allocation. It is tractable only because a baseline
JPEG's scan can be *accounted for* bit by bit, so the search has an oracle
rather than a heuristic.

**The acceptance rule is the one thing here that must not be weakened.** A
forensic tool that emits an object which was never on the medium is inventing
evidence; a missed recovery is a stated limit. Every choice below refuses rather
than guesses.

Why the oracle is an exact entropy walk and not a decoder
---------------------------------------------------------

Two cheaper oracles were shipped before this one and both fabricated objects:

* **Pillow's decode.** ``Image.load`` accepts ``jpeg[:4096] + FFD9`` and reports
  a fully decoded image: libjpeg treats a short scan, an overlong scan, a bad
  Huffman code and a marker in the wrong place as *warnings*, fills what it
  could not decode, and returns. A decode that "succeeds" says nothing about
  whether the bytes between SOS and EOI were this object's.
* **:func:`is_whole_jpeg`**, which adds a structural check for reserved marker
  codes. Measured at ``hwval-run4`` it still accepted 537 of 538 joins of an
  object to *its own* bytes at the wrong offset, 598 of 600 objects with a
  directory cluster, zeros or text spliced into the scan, and 399 of 400
  chimeras of one JPEG's head and another's scan. The product shipped that
  class at HIGH: PREFLIGHT2 FINDING 1 is a real head joined to the real tail
  read 3,584 bytes late.

:func:`scan_is_exact` walks the entropy-coded data itself. Every Huffman code
must be one the image's own tables define; no block may run past coefficient
63; restart markers must arrive in sequence exactly at the restart interval;
and the scan must end at EOI having produced **exactly** the number of MCUs the
frame header implies, with nothing but 1-bit padding left over. A join that
drops, duplicates or substitutes bytes shifts the bit stream and has to come out
at exactly the right count at exactly the right byte to pass. Measured on the
same populations: 0 of 600 insertions, 0 of 400 chimeras, FINDING 1 rejected at
every offset from 512 to 3,584 bytes late. It is the Huffman layer of a decoder
and nothing more - no IDCT, no pixels - which is what keeps it small enough to
read: 28 ms for a 74 KB object, 0.65 s for 1.5 MB.

**It is not a proof, and the residual is measured rather than assumed.** A
join that loses or replaces between 512 and 1,536 bytes of the object's own
scan passes about one time in twenty on JPEGs of pure noise, and far more rarely
on photographic content (0 of 3,200 on a smooth image). The search below is
ordered so that the true join, when it is on the medium, is examined before any
such pair; the residual applies when it is not - a tail whose first sectors were
overwritten. That is why a reassembled object is scored below HIGH
(:mod:`core.carve.score`) whatever this module says about it.

Progressive, arithmetic-coded, lossless, 12-bit and multi-scan JPEGs cannot be
accounted for here, and are never reassembled.

How the join is found
---------------------

The search never trusts the first join a check tolerates. It uses what the
medium's layout says about where the gap can be:

* **Bounded edges.** A byte pair that cannot occur inside entropy-coded data
  (``FF`` followed by anything but ``00`` or a restart code) cannot be in the
  object's head or tail. The first such pair after the scan starts bounds how
  long the head can be; the last one before a candidate EOI bounds how early
  that tail can start. Gap bytes that happen to contain no such pair - zeros, a
  directory cluster, text, another JPEG's scan data - are the only ambiguity.
* **Ordered by what is assumed.** Joins are tried in order of how many of those
  ambiguous bytes they assign to the object, fewest first, across every
  candidate EOI at once. A join that assigns *fewer* ambiguous bytes than the
  truth necessarily splices gap bytes in, which the oracle rejects; so when the
  true join is on the medium it is the first to pass.
* **Unique at its level.** Every other join assigning the same number of
  ambiguous bytes is checked too. If a second one passes, the object is refused:
  the medium does not say which is the file.
* **On the cluster grid.** Heads and gaps are whole clusters, because that is
  the only layout an allocator produces. When the volume's cluster size is known
  it is the grid. When it is not - raw carving with no recognisable filesystem -
  the grid is :data:`SECTOR_BYTES`, the smallest unit any filesystem this tool
  reads allocates in, so the true layout is always on it. A finer grid costs
  search time; it does not change what is accepted.

The search is bounded on every axis, because an unrecoverable object must cost
a fixed budget rather than the rest of the image:

* :data:`MAX_GAP_CANDIDATES` joins handed to the oracle;
* :data:`MAX_SEARCH_STEPS` joins enumerated, including the ones skipped;
* :data:`MAX_SEARCH_WINDOW` bytes from the header to the end of the object;
* :data:`DECODE_DEADLINE_S` seconds of wall clock per candidate object.

Reach is therefore a byte distance, not a count of steps: the distance between
the two runs costs nothing by itself. What costs budget is ambiguous gap bytes
next to the runs and other JPEG ends between them.

PNG has its own section at the end of this module. Its oracle is chunk CRC-32s
plus an exact-length zlib stream, which is stronger than the JPEG one, and the
same rules apply: exhaustive inside a budget, unique or refused.

Everything that is neither a baseline JPEG nor a PNG gets
``possibly_fragmented=True`` and no reconstruction attempt at all.
"""

from __future__ import annotations

import io
import re
import time
import zlib
from bisect import bisect_left
from collections.abc import Sequence
from dataclasses import dataclass

import structlog

from core.carve.evidence import EvidenceHandle
from core.models import CarveFragment

__all__ = [
    "MAX_GAP_CANDIDATES",
    "MAX_SEARCH_STEPS",
    "MAX_SEARCH_WINDOW",
    "DECODE_DEADLINE_S",
    "SECTOR_BYTES",
    "Reassembly",
    "decodes_cleanly",
    "is_whole_jpeg",
    "accounts_for_scan",
    "scan_is_exact",
    "read_fragments",
    "reassemble_bifragmented_jpeg",
    "reassemble_bifragmented_jpeg_runs",
    "MAX_PNG_SEARCH_STEPS",
    "MAX_PNG_CRC_CHECKS",
    "reassemble_bifragmented_png_runs",
]

logger = structlog.get_logger(__name__)

KIB = 1024
MIB = 1024 * KIB

#: Joins handed to :func:`scan_is_exact` before giving up. Each walks the whole
#: candidate object, so this is the dominant cost and the number that keeps it
#: bounded.
MAX_GAP_CANDIDATES = 64

#: How far past the header the end of the object is searched for. This, not a
#: step count, is the reassembler's reach.
MAX_SEARCH_WINDOW = 8 * MIB

#: Wall-clock budget for one object's entire reassembly search.
DECODE_DEADLINE_S = 10.0

#: Joins enumerated before giving up, counting the ones rejected without a walk
#: (off the grid, over ``max_size``, gap shorter than a cluster). Separate from
#: :data:`MAX_GAP_CANDIDATES` because a hostile image can present thousands of
#: ``FFD9`` bytes that cost nothing individually and everything in aggregate.
MAX_SEARCH_STEPS = 20_000

#: The smallest allocation unit of any filesystem this tool reads. Clusters are
#: whole sectors and sectors are at least 512 bytes, so every fragment boundary
#: of every file lies on this grid, measured from the file's first byte. It is
#: the grid used when the volume's own cluster size is not known.
SECTOR_BYTES = 512

_SOI = b"\xff\xd8\xff"
_EOI = b"\xff\xd9"

#: ``FF`` followed by a byte that cannot follow it inside entropy-coded data.
#: A lookahead, so ``FF FF D9`` reports both positions.
_ILLEGAL_IN_SCAN = re.compile(rb"\xff(?=[^\x00\xd0-\xd7])")
_RESTART = re.compile(rb"\xff[\xd0-\xd7]")

#: Frame markers this module can account for: baseline and extended sequential,
#: Huffman-coded.
_SEQUENTIAL_HUFFMAN = (0xC0, 0xC1)
#: Frame markers it cannot: progressive, lossless, arithmetic, hierarchical.
_UNSUPPORTED_FRAMES = frozenset(range(0xC2, 0xD0)) - {0xC4, 0xC8, 0xCC}


@dataclass(frozen=True)
class Reassembly:
    """Reassembled bytes together with where on the medium they came from.

    The runs are the point. Returning only the bytes would leave the caller
    holding a digest it cannot describe the provenance of, and a candidate that
    reports a digest for bytes nobody can locate again is not evidence.
    """

    #: The object, in file order, ready to hash or write.
    payload: bytes
    #: Image-absolute runs, in file order. One run means the object turned out
    #: to be contiguous after all.
    runs: tuple[CarveFragment, ...]

    @property
    def fragmented(self) -> bool:
        """True when the object was recovered from more than one run."""
        return len(self.runs) > 1


def decodes_cleanly(payload: bytes) -> bool:
    """True when Pillow loads the object without raising.

    **Not an oracle for reassembly**, and kept only as the last of several
    checks: libjpeg reports short, overlong and corrupt scans as warnings and
    returns an image regardless. See the module docstring.
    """
    try:
        from PIL import Image

        with Image.open(io.BytesIO(payload)) as image:
            image.load()
        return True
    except Exception:
        return False


#: Bytes that may legally follow ``0xFF`` inside entropy-coded data: ``0x00``
#: is a stuffed byte, ``0xFF`` is a fill byte, and ``0xC0``-``0xFE`` are the
#: defined markers. ``0x01`` is TEM. Everything from ``0x02`` to ``0xBF`` is
#: reserved and cannot appear in a JPEG at all, which is what makes it a
#: usable rejection test for foreign bytes spliced into a scan.
def _entropy_data_is_well_formed(payload: bytes) -> bool:
    """Whether the scan data carries no reserved marker code and no early EOI.

    A cheap structural check, and a weak one: foreign bytes containing no
    ``0xFF`` pass it, and so does the object's own scan data joined at the
    wrong place. It decides whether a contiguous span is plausibly whole; it
    does not decide whether a join is right. :func:`scan_is_exact` does that.
    """
    scan_at = _scan_start(payload)
    if scan_at is None:
        return False
    if not payload.endswith(_EOI):
        return False
    end = len(payload) - 2
    position = payload.find(b"\xff", scan_at, end)
    while position != -1:
        following = payload[position + 1]
        if following == 0xD9:
            return False  # the image ended before the bytes did
        if following in (0x00, 0x01, 0xFF) or following >= 0xC0:
            position = payload.find(b"\xff", position + 1, end)
            continue
        return False
    return True


def _scan_start(payload: bytes) -> int | None:
    """Offset of the first byte of entropy-coded data, or ``None``."""
    if not payload.startswith(b"\xff\xd8"):
        return None
    cursor = 2
    limit = len(payload)
    while cursor + 4 <= limit:
        if payload[cursor] != 0xFF:
            return None
        kind = payload[cursor + 1]
        if kind == 0xDA:  # SOS: the scan begins after its header
            return cursor + 2 + int.from_bytes(payload[cursor + 2 : cursor + 4], "big")
        if kind == 0x01 or 0xD0 <= kind <= 0xD8:
            cursor += 2
            continue
        cursor += 2 + int.from_bytes(payload[cursor + 2 : cursor + 4], "big")
    return None


def is_whole_jpeg(payload: bytes) -> bool:
    """Whether a *contiguous* span is plausibly one whole JPEG.

    Structure first, because it is cheap, then Pillow. This is the trigger's
    question - "does the parser's span need reassembly?" - and it is answered
    generously on purpose, since a yes leaves the span as it is. It is **not**
    the acceptance test for a join; see :func:`scan_is_exact`.
    """
    return _entropy_data_is_well_formed(payload) and decodes_cleanly(payload)


# --------------------------------------------------------------------------
# Exact accounting of a baseline scan
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class _Frame:
    """What a baseline JPEG's header says its scan must contain."""

    #: Offset of the first byte of entropy-coded data.
    scan_offset: int
    #: MCUs in the scan (or blocks, for a single-component image).
    units: int
    #: (DC lookup, AC lookup) for every block of one unit, in scan order.
    blocks: tuple[tuple[list[int], list[int]], ...]
    #: MCUs between restart markers; 0 when there are none.
    restart_interval: int


def _huffman_lookup(counts: bytes, symbols: bytes) -> list[int] | None:
    """A 16-bit-prefix table: ``(code length << 8) | symbol``, 0 where invalid."""
    lookup = [0] * 65536
    code = 0
    index = 0
    for length in range(1, 17):
        for _ in range(counts[length - 1]):
            if index >= len(symbols) or code >= (1 << length):
                return None
            span = 1 << (16 - length)
            base = code << (16 - length)
            lookup[base : base + span] = [(length << 8) | symbols[index]] * span
            code += 1
            index += 1
        code <<= 1
    return lookup


def _parse_frame(payload: bytes) -> _Frame | None:
    """Read the header up to SOS, or ``None`` for anything not accountable."""
    if not payload.startswith(b"\xff\xd8"):
        return None
    tables: dict[tuple[int, int], list[int]] = {}
    components: dict[int, tuple[int, int]] = {}
    order: list[int] = []
    width = height = 0
    restart = 0
    cursor = 2
    limit = len(payload)
    while cursor + 4 <= limit:
        if payload[cursor] != 0xFF:
            return None
        kind = payload[cursor + 1]
        if kind == 0xFF:
            cursor += 1
            continue
        if kind == 0x01 or 0xD0 <= kind <= 0xD8:
            cursor += 2
            continue
        if kind == 0xD9 or kind in _UNSUPPORTED_FRAMES:
            return None
        length = int.from_bytes(payload[cursor + 2 : cursor + 4], "big")
        if length < 2 or cursor + 2 + length > limit:
            return None
        segment = payload[cursor + 4 : cursor + 2 + length]
        if kind in _SEQUENTIAL_HUFFMAN:
            if order or len(segment) < 6 or segment[0] != 8:
                return None  # a second frame, or not 8-bit
            height = int.from_bytes(segment[1:3], "big")
            width = int.from_bytes(segment[3:5], "big")
            count = segment[5]
            if not width or not height or not 1 <= count <= 4:
                return None
            if len(segment) < 6 + 3 * count:
                return None
            for item in range(count):
                identifier = segment[6 + 3 * item]
                sampling = segment[7 + 3 * item]
                horizontal, vertical = sampling >> 4, sampling & 0x0F
                if not (1 <= horizontal <= 4 and 1 <= vertical <= 4):
                    return None
                components[identifier] = (horizontal, vertical)
                order.append(identifier)
        elif kind == 0xC4:
            at = 0
            while at < len(segment):
                if at + 17 > len(segment):
                    return None
                table_class, table_id = segment[at] >> 4, segment[at] & 0x0F
                counts = segment[at + 1 : at + 17]
                total = sum(counts)
                symbols = segment[at + 17 : at + 17 + total]
                built = _huffman_lookup(counts, symbols)
                if built is None or table_class > 1 or table_id > 3:
                    return None
                tables[(table_class, table_id)] = built
                at += 17 + total
        elif kind == 0xDD:
            if len(segment) < 2:
                return None
            restart = int.from_bytes(segment[0:2], "big")
        elif kind == 0xDA:
            return _frame_from_scan_header(
                segment,
                scan_offset=cursor + 2 + length,
                tables=tables,
                components=components,
                order=order,
                width=width,
                height=height,
                restart=restart,
            )
        cursor += 2 + length
    return None


def _ceil_div(numerator: int, denominator: int) -> int:
    return (numerator + denominator - 1) // denominator


def _frame_from_scan_header(
    segment: bytes,
    *,
    scan_offset: int,
    tables: dict[tuple[int, int], list[int]],
    components: dict[int, tuple[int, int]],
    order: list[int],
    width: int,
    height: int,
    restart: int,
) -> _Frame | None:
    if not components or not segment:
        return None
    selected = segment[0]
    # One scan holding every component. A scan of fewer means more scans follow,
    # and their markers inside the "scan data" would be a different object.
    if selected != len(order) or len(segment) < 1 + 2 * selected:
        return None
    max_h = max(h for h, _ in components.values())
    max_v = max(v for _, v in components.values())
    blocks: list[tuple[list[int], list[int]]] = []
    for item in range(selected):
        identifier = segment[1 + 2 * item]
        selector = segment[2 + 2 * item]
        if identifier not in components:
            return None
        dc = tables.get((0, selector >> 4))
        ac = tables.get((1, selector & 0x0F))
        if dc is None or ac is None:
            return None
        horizontal, vertical = components[identifier]
        repeat = 1 if selected == 1 else horizontal * vertical
        blocks.extend([(dc, ac)] * repeat)
    if selected == 1:
        horizontal, vertical = components[order[0]]
        columns = _ceil_div(_ceil_div(width * horizontal, max_h), 8)
        rows = _ceil_div(_ceil_div(height * vertical, max_v), 8)
    else:
        if len(blocks) > 10:
            return None
        columns = _ceil_div(width, 8 * max_h)
        rows = _ceil_div(height, 8 * max_v)
    return _Frame(
        scan_offset=scan_offset,
        units=columns * rows,
        blocks=tuple(blocks),
        restart_interval=restart,
    )


def scan_is_exact(payload: bytes, *, deadline: float | None = None) -> bool:
    """Whether ``payload`` is exactly one whole JPEG, ending at its own EOI.

    True only for a baseline or extended-sequential Huffman JPEG whose every
    code is defined by its own tables, whose every block stays within 64
    coefficients, whose restart markers arrive in sequence at the declared
    interval, and whose scan ends at the final EOI after exactly the declared
    number of MCUs with only 1-bit padding left. Anything this cannot account
    for - progressive, arithmetic, several scans - is ``False``: not "bad", but
    not something a join can be accepted on. ``deadline`` is a
    ``time.monotonic`` value past which the answer is ``False``.
    """
    frame = _parse_frame(payload)
    if frame is None or not payload.endswith(_EOI):
        return False
    if _scan_end(payload, frame.scan_offset) != len(payload) - 2:
        return False
    return _scan_accounts(frame, payload[frame.scan_offset : -2], deadline)


def accounts_for_scan(payload: bytes, *, deadline: float | None = None) -> bool | None:
    """Whether a decoded JPEG's scan is exactly the image its header declares.

    The question a validator asks of a *contiguous* object, which may legally
    carry bytes after its EOI (a motion photo appends a video there). Three
    answers, because declining is not condemning:

    * ``True`` - a baseline scan, ended by EOI, accounting for every MCU.
    * ``False`` - a baseline scan that does not: bytes inside it are missing,
      extra or out of place, a reserved marker code sits in it, or it never
      ends. A decoder reports all of these as warnings and returns an image.
    * ``None`` - nothing this module can judge: not a JPEG, not baseline, or a
      scan ended by a legal marker other than EOI (another scan, DNL).
    """
    frame = _parse_frame(payload)
    if frame is None:
        return None
    end = _scan_end(payload, frame.scan_offset)
    if end is None:
        return False
    following = payload[end + 1]
    if following != 0xD9:
        return False if 0x02 <= following <= 0xBF else None
    return _scan_accounts(frame, payload[frame.scan_offset : end], deadline)


def _scan_end(payload: bytes, scan_at: int) -> int | None:
    """Position of the marker ending the entropy-coded data, past any fill bytes."""
    for match in _ILLEGAL_IN_SCAN.finditer(payload, scan_at):
        position = match.start()
        if payload[position + 1] != 0xFF:
            return position
    return None


def _scan_accounts(frame: _Frame, data: bytes, deadline: float | None) -> bool:
    markers = _RESTART.findall(data)
    for index, marker in enumerate(markers):
        if marker[1] != 0xD0 + index % 8:
            return False
    segments = _RESTART.split(data)
    interval = frame.restart_interval
    if interval:
        if len(segments) != -(-frame.units // interval):
            return False
    elif len(segments) != 1:
        return False
    remaining = frame.units
    for raw_segment in segments:
        units = min(interval, remaining) if interval else remaining
        remaining -= units
        # 0xFF fill bytes may precede any marker and carry no data.
        segment = raw_segment.rstrip(b"\xff")
        if b"\xff" in segment.replace(b"\xff\x00", b""):
            return False  # a marker, or a fill byte, where only data may be
        if not _decode_units(
            segment.replace(b"\xff\x00", b"\xff"), units, frame.blocks, deadline
        ):
            return False
    return remaining == 0


def _decode_units(
    raw: bytes,
    units: int,
    blocks: tuple[tuple[list[int], list[int]], ...],
    deadline: float | None,
) -> bool:
    """Walk ``units`` MCUs of Huffman codes; exactly all of ``raw``, no more."""
    acc = 0
    nbits = 0
    position = 0
    size = len(raw)
    for unit in range(units):
        if deadline is not None and not unit & 0xFF and time.monotonic() > deadline:
            return False
        for dc, ac in blocks:
            while nbits < 32 and position < size:
                acc = ((acc & 0xFFFFFFFF) << 8) | raw[position]
                position += 1
                nbits += 8
            if nbits >= 16:
                peek = (acc >> (nbits - 16)) & 0xFFFF
            else:
                peek = ((acc << (16 - nbits)) & 0xFFFF) | ((1 << (16 - nbits)) - 1)
            entry = dc[peek]
            length = entry >> 8
            category = entry & 0xFF
            if not entry or length > nbits or category > 11:
                return False
            nbits -= length
            if category > nbits:
                return False
            nbits -= category
            coefficient = 1
            while coefficient < 64:
                if nbits < 26:
                    while nbits < 32 and position < size:
                        acc = ((acc & 0xFFFFFFFF) << 8) | raw[position]
                        position += 1
                        nbits += 8
                if nbits >= 16:
                    peek = (acc >> (nbits - 16)) & 0xFFFF
                else:
                    peek = ((acc << (16 - nbits)) & 0xFFFF) | (
                        (1 << (16 - nbits)) - 1
                    )
                entry = ac[peek]
                length = entry >> 8
                if not entry or length > nbits:
                    return False
                nbits -= length
                run = entry >> 4 & 0x0F
                category = entry & 0x0F
                if category == 0:
                    if run != 15:
                        break  # end of block
                    coefficient += 16
                    if coefficient > 64:
                        return False
                    continue
                coefficient += run
                if coefficient > 63 or category > 10 or category > nbits:
                    return False
                nbits -= category
                coefficient += 1
    if position != size or nbits >= 8:
        return False
    return (acc & ((1 << nbits) - 1)) == (1 << nbits) - 1


# --------------------------------------------------------------------------
# Reading and searching
# --------------------------------------------------------------------------


def read_fragments(
    handle: EvidenceHandle, fragments: Sequence[CarveFragment]
) -> bytes:
    """Read a candidate's runs back through the handle, in file order.

    The counterpart to :attr:`Reassembly.runs`: it reads the same bytes that
    produced ``candidate.sha256``, so anyone holding the evidence can recompute
    the digest rather than take the candidate's word for it.
    """
    out = bytearray()
    for fragment in fragments:
        cursor = fragment.offset
        remaining = fragment.length
        while remaining > 0:
            piece = handle.read(cursor, min(MIB, remaining))
            if not piece:
                break
            out += piece
            cursor += len(piece)
            remaining -= len(piece)
    return bytes(out)


def _read_window(handle: EvidenceHandle, start: int, length: int) -> bytes:
    return read_fragments(handle, [CarveFragment(offset=start, length=length)])


def _whole(payload: bytes, deadline: float) -> bool:
    return _entropy_data_is_well_formed(payload) and scan_is_exact(
        payload, deadline=deadline
    )


def reassemble_bifragmented_jpeg(
    handle: EvidenceHandle,
    start: int,
    *,
    max_size: int,
    cluster_size: int | None = None,
) -> bytes | None:
    """The reassembled bytes only. See :func:`reassemble_bifragmented_jpeg_runs`."""
    found = reassemble_bifragmented_jpeg_runs(
        handle, start, max_size=max_size, cluster_size=cluster_size
    )
    return None if found is None else found.payload


@dataclass(frozen=True)
class _TailEnd:
    """One candidate EOI and the tail starts its bytes allow."""

    end: int
    first_start: int
    last_start: int


def reassemble_bifragmented_jpeg_runs(
    handle: EvidenceHandle,
    start: int,
    *,
    max_size: int,
    cluster_size: int | None = None,
) -> Reassembly | None:
    """Recover a JPEG split into two runs by one gap, or return ``None``.

    ``cluster_size`` is the volume's cluster size when it is known, and ``None``
    when it is not, in which case the search walks :data:`SECTOR_BYTES`. See
    the module docstring for why that grid cannot admit a join the volume's own
    grid would have refused.

    Returns the reassembled bytes *and the runs they came from*. Returns
    ``None`` when no join accounts for the object, when more than one does,
    and when the budget runs out before either is known.
    """
    grid = SECTOR_BYTES if cluster_size is None else cluster_size
    if grid <= 0 or grid % SECTOR_BYTES:
        raise ValueError(
            f"cluster size {cluster_size} is not a whole number of "
            f"{SECTOR_BYTES}-byte sectors"
        )
    deadline = time.monotonic() + DECODE_DEADLINE_S
    limit = min(start + max_size, handle.size, start + MAX_SEARCH_WINDOW)
    if limit - start < 4 or handle.read(start, 3) != _SOI:
        return None
    window = _read_window(handle, start, limit - start)
    eoi_ends = [match.start() + 2 for match in re.finditer(_EOI, window)]

    # 1. Contiguous. Cheapest and by far the most common.
    for end in eoi_ends[:8]:
        if _whole(window[:end], deadline):
            return Reassembly(
                payload=window[:end],
                runs=(CarveFragment(offset=start, length=end),),
            )
        if time.monotonic() > deadline:
            return None

    frame = _parse_frame(window)
    if frame is None:
        return None
    scan_at = frame.scan_offset
    illegal = [
        match.start() for match in _ILLEGAL_IN_SCAN.finditer(window, scan_at)
    ]

    def up(value: int) -> int:
        return _ceil_div(value, grid) * grid

    # The head holds the header and cannot hold a byte pair no scan contains.
    head_min = up(max(scan_at, 1))
    head_max = ((illegal[0] + 1 if illegal else len(window)) // grid) * grid
    if head_min > head_max:
        return None

    ends: list[_TailEnd] = []
    for end in eoi_ends:
        if end <= head_min + grid + 2:
            continue
        # The tail cannot hold an illegal pair either, except its own EOI.
        before = bisect_left(illegal, end - 2) - 1
        floor = illegal[before] + 1 if before >= 0 else head_min + grid
        first = max(up(floor), head_min + grid)
        last = ((end - 3) // grid) * grid
        if first <= last:
            ends.append(_TailEnd(end=end, first_start=first, last_start=last))
    if not ends:
        return None

    deepest = max(
        (head_max - head_min) // grid + (item.last_start - item.first_start) // grid
        for item in ends
    )
    attempts = 0
    steps = 0
    for level in range(deepest + 1):
        accepted: tuple[int, int, int] | None = None
        for tail in ends:
            for shortened in range(level + 1):
                head = head_max - shortened * grid
                if head < head_min:
                    break
                tail_start = tail.first_start + (level - shortened) * grid
                steps += 1
                if steps > MAX_SEARCH_STEPS:
                    _log_exhausted(start, attempts, steps, accepted)
                    return None
                if tail_start > tail.last_start or tail_start < head + grid:
                    continue
                if head + tail.end - tail_start > max_size:
                    continue
                if attempts >= MAX_GAP_CANDIDATES or time.monotonic() > deadline:
                    _log_exhausted(start, attempts, steps, accepted)
                    return None
                attempts += 1
                payload = window[:head] + window[tail_start : tail.end]
                if not _scan_accounts(frame, payload[scan_at:-2], deadline):
                    continue
                if accepted is not None:
                    logger.info(
                        "bifragment join ambiguous; refused",
                        offset=start,
                        joins=[accepted, (head, tail_start, tail.end)],
                    )
                    return None
                accepted = (head, tail_start, tail.end)
        if accepted is not None:
            head, tail_start, end = accepted
            payload = window[:head] + window[tail_start:end]
            if not decodes_cleanly(payload):
                return None
            logger.info(
                "bifragmented jpeg reassembled",
                offset=start,
                head_bytes=head,
                gap_bytes=tail_start - head,
                grid_bytes=grid,
                attempts=attempts,
            )
            return Reassembly(
                payload=payload,
                runs=(
                    CarveFragment(offset=start, length=head),
                    CarveFragment(offset=start + tail_start, length=end - tail_start),
                ),
            )
    return None


def _log_exhausted(
    start: int, attempts: int, steps: int, accepted: tuple[int, int, int] | None
) -> None:
    """Out of budget. A join found but not yet shown unique is refused too."""
    logger.debug(
        "bifragment search exhausted",
        offset=start,
        attempts=attempts,
        steps=steps,
        unconfirmed=accepted,
    )


# PNG
# --------------------------------------------------------------------------
#
# A PNG is the other format whose bytes can be *accounted for* rather than
# merely decoded, and its oracle is stronger than the JPEG one. Every chunk ends
# in a CRC-32 over its type and data. All image data is one zlib stream, split
# across IDAT chunks, whose Adler-32 covers every inflated byte and whose
# inflated length is fixed exactly by the IHDR. A join is accepted only when all
# of these hold at once:
#
# * every chunk from the break to IEND has a valid type and a matching CRC;
# * the IDAT data inflates to **exactly** the byte count the IHDR implies, the
#   stream ends there, its Adler-32 matches, and nothing is left over;
# * the join is *bound*: either a chunk straddles it, so one CRC covers bytes
#   from both runs, or IDAT data lies on both sides of it, so the deflate state
#   and the Adler-32 run across it. A join at a chunk boundary with all image
#   data on one side proves nothing about the other side, and is refused - that
#   is how a header of one PNG and the image data of another with the same
#   dimensions would otherwise pass;
# * it is the only join in the window that passes. A second passing join, even
#   one that yields identical bytes, means the medium does not say where the
#   file was, and the runs would be a guess.
#
# The search is exhaustive inside its budget, not first-match. Running out of
# budget before uniqueness is known is a refusal.

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_IEND = b"IEND"
_IDAT = b"IDAT"

#: (head end, tail start) pairs the PNG search may enumerate.
MAX_PNG_SEARCH_STEPS = 4_000_000
#: Chunk CRCs the PNG search may compute across the join.
MAX_PNG_CRC_CHECKS = 200_000

#: Channels per pixel, keyed by IHDR colour type, with the bit depths each
#: allows (PNG specification, Table 11.1).
_PNG_COLOUR = {
    0: (1, (1, 2, 4, 8, 16)),
    2: (3, (8, 16)),
    3: (1, (1, 2, 4, 8)),
    4: (2, (8, 16)),
    6: (4, (8, 16)),
}
#: Adam7 passes: (x0, y0, dx, dy).
_ADAM7 = (
    (0, 0, 8, 8),
    (4, 0, 8, 8),
    (0, 4, 4, 8),
    (2, 0, 4, 4),
    (0, 2, 2, 4),
    (1, 0, 2, 2),
    (0, 1, 1, 2),
)
_ALPHA4 = re.compile(rb"(?=[A-Za-z]{4})")


def _png_raw_size(ihdr: bytes) -> int | None:
    """Bytes the image data must inflate to, from a 13-byte IHDR, or None."""
    if len(ihdr) != 13:
        return None
    width = int.from_bytes(ihdr[0:4], "big")
    height = int.from_bytes(ihdr[4:8], "big")
    depth, colour, compression, filtering, interlace = ihdr[8:13]
    spec = _PNG_COLOUR.get(colour)
    if (
        spec is None
        or depth not in spec[1]
        or compression
        or filtering
        or interlace not in (0, 1)
        or not 0 < width < 1 << 31
        or not 0 < height < 1 << 31
    ):
        return None
    bits = spec[0] * depth

    def rows(w: int, h: int) -> int:
        return 0 if w == 0 or h == 0 else h * (1 + _ceil_div(w * bits, 8))

    if not interlace:
        return rows(width, height)
    return sum(
        rows(_ceil_div(max(width - x0, 0), dx), _ceil_div(max(height - y0, 0), dy))
        for x0, y0, dx, dy in _ADAM7
    )


def _inflates_exactly(pieces: Sequence[bytes], expected: int) -> bool:
    """True when the pieces are one zlib stream of exactly ``expected`` bytes.

    Streams the output in bounded slices so a lying IHDR or a decompression
    bomb costs a counter, not memory. zlib checks the Adler-32 at stream end.
    """
    inflater = zlib.decompressobj()
    total = 0
    try:
        for index, piece in enumerate(pieces):
            data = piece
            while data and not inflater.eof:
                total += len(inflater.decompress(data, MIB))
                if total > expected:
                    return False
                data = inflater.unconsumed_tail
            if inflater.eof:
                trailing = inflater.unused_data or any(pieces[index + 1 :])
                return not trailing and total == expected
        total += len(inflater.flush())
    except zlib.error:
        return False
    return inflater.eof and total == expected


@dataclass(frozen=True)
class _PngPrefix:
    """What the head, read as laid on the medium, establishes."""

    raw_size: int
    #: Offset (window-relative) of the first chunk that does not verify, or
    #: None when the object verified contiguously to IEND.
    bad_at: int | None
    #: IDAT payloads wholly before ``bad_at``, in order.
    idat: tuple[bytes, ...]
    #: End of IEND when ``bad_at`` is None.
    end: int


def _png_prefix(window: bytes) -> _PngPrefix | None:
    if not window.startswith(_PNG_MAGIC) or len(window) < 33:
        return None
    if window[12:16] != b"IHDR" or int.from_bytes(window[8:12], "big") != 13:
        return None
    if zlib.crc32(window[12:29]) & 0xFFFFFFFF != int.from_bytes(window[29:33], "big"):
        return None
    raw_size = _png_raw_size(window[16:29])
    if raw_size is None:
        return None
    idat: list[bytes] = []
    cursor = 33
    while True:
        if cursor + 12 > len(window):
            return _PngPrefix(raw_size, cursor, tuple(idat), 0)
        length = int.from_bytes(window[cursor : cursor + 4], "big")
        kind = window[cursor + 4 : cursor + 8]
        end = cursor + 12 + length
        if not kind.isalpha() or end > len(window):
            return _PngPrefix(raw_size, cursor, tuple(idat), 0)
        body = window[cursor + 8 : end - 4]
        if zlib.crc32(kind + body) & 0xFFFFFFFF != int.from_bytes(
            window[end - 4 : end], "big"
        ):
            return _PngPrefix(raw_size, cursor, tuple(idat), 0)
        if kind == _IDAT:
            idat.append(body)
        if kind == _IEND:
            return _PngPrefix(raw_size, None, tuple(idat), end)
        cursor = end


class _Crcs:
    """The CRC budget, shared across one object's search."""

    def __init__(self) -> None:
        self.used = 0

    def spend(self) -> bool:
        self.used += 1
        return self.used <= MAX_PNG_CRC_CHECKS


def _png_join_end(
    window: bytes,
    prefix: _PngPrefix,
    head: int,
    tail: int,
    crcs: _Crcs,
) -> int | None:
    """Joined-stream end of IEND when head + tail verifies, bound, else None.

    Offsets are in joined coordinates: ``[0, head)`` is ``window[:head]`` and
    ``[head, ...)`` is ``window[tail:]``.
    """
    assert prefix.bad_at is not None
    shift = tail - head

    def get(lo: int, hi: int) -> bytes | None:
        if hi <= head:
            return window[lo:hi]
        if hi + shift > len(window):
            return None
        if lo >= head:
            return window[lo + shift : hi + shift]
        return window[lo:head] + window[tail : hi + shift]

    idat = list(prefix.idat)
    idat_before = bool(idat)
    idat_after = False
    straddled = False
    cursor = prefix.bad_at
    while True:
        header = get(cursor, cursor + 8)
        if header is None:
            return None
        length = int.from_bytes(header[0:4], "big")
        kind = header[4:8]
        end = cursor + 12 + length
        if not kind.isalpha() or end + shift > len(window):
            return None
        if not crcs.spend():
            return None
        body = get(cursor + 8, end - 4)
        crc = get(end - 4, end)
        if body is None or crc is None:
            return None
        if zlib.crc32(kind + body) & 0xFFFFFFFF != int.from_bytes(crc, "big"):
            return None
        if cursor < head < end and kind != _IEND:
            straddled = True
        if kind == _IDAT:
            idat.append(body)
            if cursor + 8 < head:
                idat_before = True
            if end - 4 > head:
                idat_after = True
        if kind == _IEND:
            if end <= head:
                return None
            bound = straddled or (idat_before and idat_after)
            if not bound or not _inflates_exactly(idat, prefix.raw_size):
                return None
            return end
        cursor = end


def reassemble_bifragmented_png_runs(
    handle: EvidenceHandle,
    start: int,
    *,
    max_size: int,
    cluster_size: int | None = None,
) -> Reassembly | None:
    """Recover a PNG split into two runs by one gap, or return ``None``.

    The grid rules are the JPEG search's: the head and the gap are whole
    clusters when ``cluster_size`` is known, whole sectors when it is not.
    Returns ``None`` when no join verifies, when more than one does, when the
    only verifying join is not bound across both runs, and when the budget runs
    out before either is known. Interlaced (Adam7) images are handled; the
    inflated length is computed per pass.
    """
    grid = SECTOR_BYTES if cluster_size is None else cluster_size
    if grid <= 0 or grid % SECTOR_BYTES:
        raise ValueError(
            f"cluster size {cluster_size} is not a whole number of "
            f"{SECTOR_BYTES}-byte sectors"
        )
    deadline = time.monotonic() + DECODE_DEADLINE_S
    limit = min(start + max_size, handle.size, start + MAX_SEARCH_WINDOW)
    if limit - start < 33 or handle.read(start, 8) != _PNG_MAGIC:
        return None
    window = _read_window(handle, start, limit - start)
    prefix = _png_prefix(window)
    if prefix is None:
        return None
    if prefix.bad_at is None:
        if not _inflates_exactly(prefix.idat, prefix.raw_size):
            return None
        return Reassembly(
            payload=window[: prefix.end],
            runs=(CarveFragment(offset=start, length=prefix.end),),
        )

    bad_at = prefix.bad_at
    laid_length = int.from_bytes(window[bad_at : bad_at + 4], "big")
    laid_kind = window[bad_at + 4 : bad_at + 8]
    laid_end = bad_at + 12 + laid_length
    # The break is at or after the first unverified chunk, and before that
    # chunk's end when its header was the file's own; inside the header when
    # the header itself is foreign.
    if len(laid_kind) == 4 and laid_kind.isalpha():
        highest = min(laid_end - 1, len(window) - grid)
    else:
        highest = min(bad_at + 7, len(window) - grid)
    heads = range(_ceil_div(bad_at, grid) * grid, highest + 1, grid)

    by_residue: dict[int, list[int]] = {}
    for match in _ALPHA4.finditer(window):
        by_residue.setdefault(match.start() % grid, []).append(match.start())

    crcs = _Crcs()
    accepted: list[tuple[int, int, int]] = []
    steps = 0
    for head in heads:
        if head <= 0:
            continue
        if head >= bad_at + 8 and laid_kind.isalpha():
            if laid_kind == _IEND:
                continue
            # Fast path: the header is the head's, so the next chunk's type sits
            # at a fixed distance into the tail. Only tails that put four
            # letters there, behind a length field that fits in the window, are
            # worth a CRC. Text in the gap puts letters everywhere; its "length"
            # fields read as billions and fall out here.
            reach = laid_end + 4 - head
            positions = by_residue.get(reach % grid, [])
            first = bisect_left(positions, head + grid + reach)
            tails: Sequence[int] = [
                q - reach
                for q in positions[first:]
                if int.from_bytes(window[q - 4 : q], "big") <= len(window) - q
            ]
        else:
            tails = range(head + grid, len(window), grid)
        for tail in tails:
            steps += 1
            if steps > MAX_PNG_SEARCH_STEPS or time.monotonic() > deadline:
                _log_png_refusal(start, "budget", steps, crcs.used, accepted)
                return None
            end = _png_join_end(window, prefix, head, tail, crcs)
            if crcs.used > MAX_PNG_CRC_CHECKS:
                _log_png_refusal(start, "budget", steps, crcs.used, accepted)
                return None
            if end is None:
                continue
            if end - head + tail > len(window) or end > max_size:
                continue
            accepted.append((head, tail, end))
            if len(accepted) > 1:
                _log_png_refusal(start, "ambiguous", steps, crcs.used, accepted)
                return None

    if not accepted:
        return None
    head, tail, end = accepted[0]
    payload = window[:head] + window[tail : tail + end - head]
    logger.info(
        "bifragmented png reassembled",
        offset=start,
        head_bytes=head,
        gap_bytes=tail - head,
        grid_bytes=grid,
        crc_checks=crcs.used,
    )
    return Reassembly(
        payload=payload,
        runs=(
            CarveFragment(offset=start, length=head),
            CarveFragment(offset=start + tail, length=end - head),
        ),
    )


def _log_png_refusal(
    start: int,
    reason: str,
    steps: int,
    crcs: int,
    accepted: list[tuple[int, int, int]],
) -> None:
    logger.info(
        "bifragment png search refused",
        offset=start,
        reason=reason,
        steps=steps,
        crc_checks=crcs,
        joins=accepted,
    )
