"""Signature carving: one Aho-Corasick pass over the image, not one per pattern.

Looping the image once per signature is the obvious implementation and it is
roughly thirty times slower with a sixteen-entry table, because the cost is
dominated by moving bytes rather than by comparing them. One automaton built
from every header finds all of them in a single pass, so scan time is set by
read throughput instead of by table size. That difference is the demo not
stalling.

Three details decide whether the results are trustworthy:

**Chunk seams.** The image is read in 8 MiB chunks, and a header that straddles
a seam would be missed by a naive split. Each chunk therefore overlaps the
previous one by ``max_pattern_length - 1`` bytes, which is exactly enough for
any pattern to appear whole in at least one chunk. A hit landing in the overlap
would then be reported twice, so hits are deduplicated by absolute offset.

**Parallelism.** Workers scan disjoint byte ranges and each opens its own
handle, because a handle does not cross a process boundary (see
:mod:`core.carve.evidence`). Every range seam gets the same overlap treatment as
a chunk seam, so splitting the work cannot change what is found.

**Substituted bytes.** A header sitting inside a range that was filled in during
acquisition is not evidence, it is this tool's own fill byte pattern. Carving it
would manufacture an object that never existed on the media, which is the worst
failure this module could have. Those candidates are suppressed and counted, and
the count is reported rather than hidden.
"""

from __future__ import annotations

import hashlib
import weakref
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog
import yaml

from core.carve.evidence import EvidenceHandle, open_evidence
from core.errors import EvidenceIntegrityError
from core.models import CarveCandidate

__all__ = [
    "Signature",
    "ScanReport",
    "load_signatures",
    "build_automaton",
    "scan",
    "carve_signatures",
    "tar_header_is_valid",
    "CHUNK_BYTES",
    "PARALLEL_FLOOR_BYTES",
    "SIGNATURE_DB_PATH",
]

logger = structlog.get_logger(__name__)

MIB = 1024 * 1024

#: Read granularity for the scan. Large enough to amortise per-read overhead,
#: small enough that a worker's resident set stays bounded.
CHUNK_BYTES = 8 * MIB

#: Below this size a worker pool costs more than it saves. See the measured
#: figures in :func:`carve_signatures`.
PARALLEL_FLOOR_BYTES = 256 * MIB

SIGNATURE_DB_PATH = Path(__file__).resolve().parents[2] / "testkit" / "signatures.yaml"


@dataclass(frozen=True)
class Signature:
    """One entry of the signature table."""

    name: str
    ext: str
    mime: str
    header: bytes
    max_size: int
    min_size: int = 0
    header_offset: int = 0
    footer: bytes | None = None
    notes: str = ""


@dataclass
class ScanReport:
    """Everything one scan found, and everything it declined to report."""

    candidates: list[CarveCandidate] = field(default_factory=list)
    bytes_scanned: int = 0
    #: Headers dropped because they sat inside acquisition fill. Reported, never
    #: silently discarded: a suppressed count of zero and a suppressed count of
    #: four hundred mean very different things about the evidence.
    suppressed_substituted: int = 0
    #: Headers dropped for failing their signature's ``min_size`` floor.
    suppressed_too_small: int = 0
    #: Short headers that failed their second-stage check, e.g. a stray
    #: ``4D5A`` with no PE signature behind it.
    suppressed_uncorroborated: int = 0

    def merge(self, other: ScanReport) -> None:
        self.candidates.extend(other.candidates)
        self.bytes_scanned += other.bytes_scanned
        self.suppressed_substituted += other.suppressed_substituted
        self.suppressed_too_small += other.suppressed_too_small
        self.suppressed_uncorroborated += other.suppressed_uncorroborated


# --------------------------------------------------------------------------
# Signature table
# --------------------------------------------------------------------------


#: Parsed tables keyed by (path, mtime_ns, size). AEGIS integration
#: (2026-10-03), performance only: the scorer loads the table once per candidate,
#: and YAML parsing was 6% of a real recovery run. A changed file has a new key,
#: so the table is still read from disk whenever it changes; Signature is frozen
#: and each caller gets its own list.
_SIGNATURE_CACHE: dict[tuple[str, int, int], tuple[Signature, ...]] = {}


def load_signatures(path: Path | str | None = None) -> list[Signature]:
    """Load the signature table from YAML. Never hardcoded, always from disk."""
    target = Path(path) if path is not None else SIGNATURE_DB_PATH
    try:
        info = target.stat()
        key = (str(target.resolve()), info.st_mtime_ns, info.st_size)
    except OSError:
        key = None
    if key is not None and key in _SIGNATURE_CACHE:
        return list(_SIGNATURE_CACHE[key])
    if not target.exists():
        raise EvidenceIntegrityError(
            f"signature table not found: {target}",
            remediation=(
                "Restore testkit/signatures.yaml. Carving without a table would "
                "silently find nothing, which looks identical to a clean disk."
            ),
        )
    document: dict[str, Any] = yaml.safe_load(target.read_text(encoding="utf-8"))
    entries: list[Signature] = []
    for raw in document.get("signatures", []):
        entries.append(
            Signature(
                name=str(raw["name"]),
                ext=str(raw["ext"]),
                mime=str(raw["mime"]),
                header=bytes.fromhex(str(raw["header"])),
                footer=(
                    bytes.fromhex(str(raw["footer"])) if raw.get("footer") else None
                ),
                max_size=int(raw["max_size"]),
                min_size=int(raw.get("min_size", 0)),
                header_offset=int(raw.get("header_offset", 0)),
                notes=str(raw.get("notes", "")),
            )
        )
    if not entries:
        raise EvidenceIntegrityError(
            f"signature table {target} contains no signatures",
            remediation="Populate it; an empty table finds nothing on any disk.",
        )
    if key is not None:
        _SIGNATURE_CACHE[key] = tuple(entries)
    return entries


def build_automaton(signatures: Sequence[Signature]) -> Any:
    """Build one Aho-Corasick automaton over every header in the table.

    Patterns are stored as latin-1 text because pyahocorasick keys on ``str``.
    The mapping is one-to-one over 0-255, so no byte is lost or aliased.

    **Each pattern carries every signature that declares it.** Two formats can
    share a header - WebP and WAV are both ``RIFF``, and what separates them is
    the form type four bytes later, which :func:`_corroborated` checks. Storing
    one signature per pattern would let the second silently overwrite the
    first, and the overwritten format would never be found on any image.
    """
    import ahocorasick

    automaton = ahocorasick.Automaton()
    patterns: dict[str, list[Signature]] = {}
    for signature in signatures:
        patterns.setdefault(signature.header.decode("latin-1"), []).append(signature)
    for pattern, sharing in patterns.items():
        automaton.add_word(pattern, tuple(sharing))
    automaton.make_automaton()
    return automaton


def _max_pattern_length(signatures: Sequence[Signature]) -> int:
    return max(len(signature.header) for signature in signatures)


# --------------------------------------------------------------------------
# Footer bounding
# --------------------------------------------------------------------------


#: Formats whose objects legitimately contain a header of their own format:
#: every archive member carries the archive's magic, an HTML document carries
#: ``<html>`` after its doctype, and a JPEG carries an EXIF thumbnail with its
#: own SOI. For these a same-format header inside the object is part of it, so
#: it cannot bound the footer search. Every other footered format's header
#: starting a new object means the previous one has ended.
_NESTING_EXTS = frozenset({"zip", "tar", "html", "jpg", "docx", "xlsx", "pptx"})


#: Progress hook for the single-pass scan. AEGIS integration (2026-10-03): the
#: scan is one uninterrupted pass with no yield, so a caller that shows progress
#: sets this to ``fn(bytes_done, bytes_total)``. It is only ever called, never
#: consulted, and changes nothing the scan finds.
SCAN_PROGRESS_HOOK: Callable[[int, int], None] | None = None

#: Progress hook for the loops that follow the scan, which are also silent:
#: building one candidate per hit (``"candidates"``) and, in
#: ``structure.carve_structures``, parsing each candidate (``"parse"``). AEGIS
#: integration (2026-10-04): called as ``fn(stage, done, total)``; like the scan
#: hook it is only ever called and changes nothing that is found.
STAGE_PROGRESS_HOOK: Callable[[str, int, int], None] | None = None


class _FooterMemo:
    """What earlier footer searches on one handle already established.

    AEGIS integration (2026-10-03), a pure performance change. Every search
    returns the first full footer occurrence at or after ``start`` that ends
    before ``limit``. Many hits search for the same footer from nearby starts
    (every member of an OOXML archive begins ``PK\\x03\\x04`` and searches up to
    1 GiB for the end-of-central-directory), so without this the same bytes were
    re-read once per hit. An interval ``[a, b)`` with ``first`` records that the
    first occurrence lying wholly inside it is at ``first`` (or that there is
    none). A search starting at ``s >= a`` reuses that fact and reads only what
    no earlier search covered; the answer is identical.
    """

    def __init__(self) -> None:
        self.intervals: list[tuple[int, int, int | None]] = []

    def lookup(self, start: int) -> tuple[int, int, int | None] | None:
        best = None
        for a, b, first in self.intervals:
            if a <= start < b and (best is None or b > best[1]):
                best = (a, b, first)
        return best

    def record(self, a: int, b: int, first: int | None) -> None:
        self.intervals.append((a, b, first))
        if len(self.intervals) > 256:
            del self.intervals[:64]


_FOOTER_MEMOS: "weakref.WeakKeyDictionary[Any, dict[bytes, _FooterMemo]]" = weakref.WeakKeyDictionary()


def _footer_memo(handle: EvidenceHandle, footer: bytes) -> _FooterMemo:
    """The memo for this handle and footer; a fresh, unshared one if the handle
    cannot be weakly referenced (so a memo can never outlive its evidence)."""
    try:
        per_handle = _FOOTER_MEMOS.get(handle)
        if per_handle is None:
            per_handle = {}
            _FOOTER_MEMOS[handle] = per_handle
    except TypeError:
        return _FooterMemo()
    memo = per_handle.get(footer)
    if memo is None:
        memo = _FooterMemo()
        per_handle[footer] = memo
    return memo


def _find_footer(
    handle: EvidenceHandle,
    signature: Signature,
    start: int,
    *,
    stop_at: int | None = None,
) -> int | None:
    """Locate the end of the object, searching no further than ``max_size``.

    Returns the offset just past the footer, or ``None`` when no footer was
    found inside the cap. ``None`` does not mean "discard": an object whose
    footer was overwritten is still recoverable and still evidence.

    ``stop_at`` is where the next header of the *same* non-nesting format
    begins. The search stops there, because a footer beyond it belongs to that
    object. Without this, a truncated PDF whose ``%%EOF`` was lost ran on to the
    next PDF's ``%%EOF`` megabytes away; the decoder, which repairs from any
    trailer it can find, then called the span valid and it scored HIGH. That
    was measured on the 7 GiB validation image (``docs/validation/
    large-image.md``) and never on the small corpora, where every object sat
    512 KiB from its neighbour.
    """
    if signature.footer is None:
        return None
    footer = signature.footer
    limit = min(start + signature.max_size, handle.size)
    if stop_at is not None and stop_at > start:
        # The footer may straddle nothing past the next object's first byte.
        limit = min(limit, stop_at)
    memo = _footer_memo(handle, footer)
    cursor = start
    known = memo.lookup(start)
    if known is not None:
        a, b, first = known
        if first is not None and first >= start:
            end = first + len(footer)
            return end if end <= limit else None
        if first is None:
            # Nothing lies wholly inside [start, b): resume where a footer could
            # still straddle b.
            cursor = max(start, b - len(footer) + 1)
    window = 1 * MIB
    overlap = len(footer) - 1
    scanned_from = cursor
    while cursor < limit:
        block = handle.read(cursor, min(window, limit - cursor))
        if not block:
            break
        position = block.find(footer)
        if position != -1:
            found = cursor + position
            memo.record(scanned_from if known is None or known[2] is not None else known[0], found + len(footer), found)
            return found + len(footer)
        cursor += max(len(block) - overlap, 1)
    covered_to = min(cursor + overlap, limit)
    memo.record(scanned_from if known is None or known[2] is not None else known[0], covered_to, None)
    return None


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------


def _iter_hits(
    handle: EvidenceHandle,
    automaton: Any,
    *,
    start: int,
    end: int,
    overlap: int,
) -> Iterator[tuple[int, Signature]]:
    """Yield ``(absolute_offset_of_header, signature)`` over ``[start, end)``.

    Chunks overlap by ``overlap`` bytes so a pattern spanning a seam is whole in
    at least one chunk; ``seen`` then removes the duplicate that creates.
    """
    seen: set[tuple[int, str]] = set()
    cursor = start
    while cursor < end:
        length = min(CHUNK_BYTES, end - cursor)
        # Extend past the range end so a pattern straddling the seam is intact.
        block = handle.read(cursor, length + overlap)
        if not block:
            break
        haystack = block.decode("latin-1")
        for last_index, sharing in automaton.iter(haystack):
            for signature in sharing:
                header_at = cursor + last_index - len(signature.header) + 1
                if header_at < start or header_at >= end:
                    continue
                key = (header_at, signature.name)
                if key in seen:
                    continue
                seen.add(key)
                yield header_at, signature
        cursor += length
        if SCAN_PROGRESS_HOOK is not None:
            SCAN_PROGRESS_HOOK(cursor - start, end - start)


def _pe_is_corroborated(handle: EvidenceHandle, header_at: int) -> bool:
    """A DOS stub whose ``e_lfanew`` really points at a PE signature.

    ``4D5A`` is two bytes, so it occurs about once per 32 KiB of random data -
    roughly seventy times in every 4 MiB. Reported unchecked it buries the real
    findings in noise. A DOS stub carries the PE header offset at ``e_lfanew``
    (0x3C), and a real executable has ``PE\\0\\0`` there, so one extra four-byte
    read separates a program from a coincidence.
    """
    stub = handle.read(header_at + 0x3C, 4)
    if len(stub) < 4:
        return False
    e_lfanew = int.from_bytes(stub, "little")
    if e_lfanew <= 0 or e_lfanew > 0x1000:
        return False
    return handle.read(header_at + e_lfanew, 4) == b"PE\x00\x00"


#: DIB header sizes a BMP may declare: BITMAPCOREHEADER through
#: BITMAPV5HEADER. Anything else is not a bitmap this format defines.
_BMP_DIB_SIZES = frozenset({12, 16, 40, 52, 56, 64, 108, 124})


def _bmp_is_corroborated(handle: EvidenceHandle, header_at: int) -> bool:
    """``BM`` plus three size fields that agree with each other.

    Two bytes match by chance about once per 64 KiB of random data. A real
    bitmap's file header says how long the file is and where the pixels start,
    and the DIB header behind it declares its own length; a coincidence gets
    all three consistent only by accident.
    """
    head = handle.read(header_at, 18)
    if len(head) < 18:
        return False
    declared = int.from_bytes(head[2:6], "little")
    pixels_at = int.from_bytes(head[10:14], "little")
    dib_size = int.from_bytes(head[14:18], "little")
    if dib_size not in _BMP_DIB_SIZES:
        return False
    if declared < 14 + dib_size or pixels_at < 14 + dib_size:
        return False
    return pixels_at <= declared


def _riff_form(form: bytes) -> Callable[[EvidenceHandle, int], bool]:
    """A RIFF container whose form type at byte 8 is ``form``.

    ``RIFF`` is shared by WebP, WAV and AVI, so the four bytes naming the form
    are what separate them. Without this check one signature would claim every
    RIFF file for its own format.
    """

    def check(handle: EvidenceHandle, header_at: int) -> bool:
        return handle.read(header_at + 8, 4) == form

    return check


def _gzip_is_corroborated(handle: EvidenceHandle, header_at: int) -> bool:
    """A gzip member whose flag byte sets no reserved bit.

    RFC 1952 reserves the top three bits of ``FLG`` and requires them to be
    zero. It is one byte of check, and it removes most of the random matches
    the three-byte magic makes on compressed data.
    """
    head = handle.read(header_at, 4)
    return len(head) == 4 and not head[3] & 0xE0


#: Where a ustar member header keeps its own checksum and its magic, and how
#: long a member header is.
_TAR_CHECKSUM_AT = 148
_TAR_CHECKSUM_BYTES = 8
_TAR_MAGIC_AT = 257
_TAR_BLOCK_BYTES = 512


def tar_header_is_valid(block: bytes) -> bool:
    """Whether a 512-byte ustar header's own checksum verifies.

    Every member header carries the octal sum of its own bytes, computed with
    the checksum field itself read as eight spaces. Historic writers disagreed
    on whether the bytes are signed, so both readings are accepted - which is
    what every tar reader does. This is what makes a five-byte ``ustar`` magic
    trustworthy: noise does not add up.
    """
    if len(block) < _TAR_BLOCK_BYTES:
        return False
    field = block[_TAR_CHECKSUM_AT : _TAR_CHECKSUM_AT + _TAR_CHECKSUM_BYTES]
    digits = field.split(b"\x00")[0].split(b" ")[0]
    if not digits:
        return False
    try:
        declared = int(digits, 8)
    except ValueError:
        return False
    blanked = (
        block[:_TAR_CHECKSUM_AT]
        + b" " * _TAR_CHECKSUM_BYTES
        + block[_TAR_CHECKSUM_AT + _TAR_CHECKSUM_BYTES : _TAR_BLOCK_BYTES]
    )
    unsigned = sum(blanked)
    signed = sum(byte - 256 if byte > 127 else byte for byte in blanked)
    return declared in (unsigned, signed)


def _tar_is_corroborated(handle: EvidenceHandle, header_at: int) -> bool:
    """The ``ustar`` magic sits at byte 257 of the block it belongs to."""
    block_at = header_at - _TAR_MAGIC_AT
    if block_at < 0:
        return False
    return tar_header_is_valid(handle.read(block_at, _TAR_BLOCK_BYTES))


#: Signature name -> the check a match must pass before it becomes a candidate.
#: A name absent here needs no second stage: its magic is long enough, or
#: distinctive enough, to stand on its own.
_SECOND_STAGE: dict[str, Callable[[EvidenceHandle, int], bool]] = {
    "PE": _pe_is_corroborated,
    "BMP": _bmp_is_corroborated,
    "WebP": _riff_form(b"WEBP"),
    "WAV": _riff_form(b"WAVE"),
    "GZIP": _gzip_is_corroborated,
    "TAR": _tar_is_corroborated,
}


def _corroborated(handle: EvidenceHandle, header_at: int, signature: Signature) -> bool:
    """Second-stage check for headers too short to be credible on their own.

    A short magic reported unchecked buries the real findings in noise, and
    every check here is a handful of bytes read at a fixed place. See
    :data:`_SECOND_STAGE` for which signatures have one and why.
    """
    check = _SECOND_STAGE.get(signature.name)
    return True if check is None else check(handle, header_at)


def _candidate_for(
    handle: EvidenceHandle,
    header_at: int,
    signature: Signature,
    *,
    next_header_at: int,
    next_same_header_at: int | None = None,
) -> CarveCandidate | None:
    """Build a candidate from a header hit, bounding it by footer or neighbour.

    ``next_header_at`` is where the following header of any type begins. When
    no footer is found, that neighbour is the bound: an object cannot plausibly
    run past the start of the next one, and ``max_size`` alone is a cap rather
    than a length - using it would claim a 4 GiB MP4 for every stray ``ftyp``
    and hash the whole image once per hit.
    """
    object_start = header_at - signature.header_offset
    if object_start < 0:
        return None

    footer_end = _find_footer(
        handle,
        signature,
        object_start,
        stop_at=(
            None if signature.ext in _NESTING_EXTS else next_same_header_at
        ),
    )
    if footer_end is not None:
        length = footer_end - object_start
        validation: str = "valid"
    else:
        length = min(
            signature.max_size,
            handle.size - object_start,
            max(next_header_at - object_start, 0) or (handle.size - object_start),
        )
        validation = "truncated"

    if length < signature.min_size:
        return None

    digest = hashlib.sha256()
    cursor = object_start
    remaining = length
    while remaining > 0:
        piece = handle.read(cursor, min(MIB, remaining))
        if not piece:
            break
        digest.update(piece)
        cursor += len(piece)
        remaining -= len(piece)

    return CarveCandidate(
        offset=object_start,
        length=length,
        ext=signature.ext,
        mime=signature.mime,
        source="signature",
        validation="valid" if validation == "valid" else "truncated",
        confidence_bp=6000 if footer_end is not None else 3000,
        bucket="MEDIUM" if footer_end is not None else "LOW",
        sha256=digest.hexdigest(),
        original_name=None,
        possibly_fragmented=footer_end is None,
    )


def scan(
    handle: EvidenceHandle,
    *,
    signatures: Sequence[Signature] | None = None,
    start: int = 0,
    end: int | None = None,
) -> ScanReport:
    """Scan ``[start, end)`` of one handle in a single automaton pass."""
    table = list(signatures) if signatures is not None else load_signatures()
    automaton = build_automaton(table)
    overlap = _max_pattern_length(table) - 1
    stop = handle.size if end is None else min(end, handle.size)

    report = ScanReport(bytes_scanned=max(stop - start, 0))

    # Collect every hit before building any candidate. Bounding a footerless
    # object needs to know where the next header starts, and the scan is one
    # pass either way.
    hits: list[tuple[int, Signature]] = []
    for header_at, signature in _iter_hits(
        handle, automaton, start=start, end=stop, overlap=overlap
    ):
        # A header inside acquisition fill is this tool's own bytes. Carving it
        # would produce an object that was never on the media.
        if handle.was_substituted(header_at, len(signature.header)):
            report.suppressed_substituted += 1
            continue
        if not _corroborated(handle, header_at, signature):
            report.suppressed_uncorroborated += 1
            continue
        hits.append((header_at, signature))

    hits.sort(key=lambda item: item[0])
    # For each hit, where the next header of the same format begins, computed
    # in one backward pass rather than a search per hit.
    next_same: list[int | None] = [None] * len(hits)
    seen: dict[str, int] = {}
    for index in range(len(hits) - 1, -1, -1):
        header_at, signature = hits[index]
        start_of = header_at - signature.header_offset
        next_same[index] = seen.get(signature.ext)
        seen[signature.ext] = start_of
    for index, (header_at, signature) in enumerate(hits):
        if STAGE_PROGRESS_HOOK is not None:
            STAGE_PROGRESS_HOOK("candidates", index, len(hits))
        next_at = hits[index + 1][0] if index + 1 < len(hits) else handle.size
        candidate = _candidate_for(
            handle,
            header_at,
            signature,
            next_header_at=next_at,
            next_same_header_at=next_same[index],
        )
        if candidate is None:
            report.suppressed_too_small += 1
            continue
        report.candidates.append(candidate)

    report.candidates.sort(key=lambda c: (c.offset, c.ext))
    return report


# --------------------------------------------------------------------------
# Parallel scanning
# --------------------------------------------------------------------------


def _plan_ranges(size: int, workers: int) -> list[tuple[int, int]]:
    """Split the image into disjoint ranges, one per worker."""
    if workers <= 1 or size == 0:
        return [(0, size)]
    span = size // workers
    ranges: list[tuple[int, int]] = []
    for index in range(workers):
        start = index * span
        end = size if index == workers - 1 else (index + 1) * span
        if end > start:
            ranges.append((start, end))
    return ranges


def _scan_range(job: tuple[str, int, int, str | None]) -> ScanReport:
    """Worker entry point. Opens its own handle: handles do not cross processes."""
    path, start, end, db_path = job
    table = load_signatures(db_path)
    with open_evidence(path) as handle:
        return scan(handle, signatures=table, start=start, end=end)


def carve_signatures(
    image: EvidenceHandle | Path | str,
    *,
    workers: int = 1,
    signatures: Sequence[Signature] | None = None,
    db_path: Path | str | None = None,
    parallel_floor_bytes: int = PARALLEL_FLOOR_BYTES,
) -> ScanReport:
    """Scan a whole image, optionally across several processes.

    Parallelism changes only the speed. Every range seam is overlapped exactly
    as a chunk seam is, and results are merged and re-sorted, so a four-process
    scan returns the same candidate set as a one-process scan - verified at
    64, 256 and 512 MiB.

    ``workers > 1`` starts a process pool, and on Windows and macOS that uses
    spawn rather than fork: the calling module is re-imported in each worker,
    so an application entry point must sit behind ``if __name__ ==
    "__main__":``. Without it the workers re-execute the caller and the pool
    fails to start.
    """
    if isinstance(image, (str, Path)):
        path = Path(image)
        if workers <= 1:
            with open_evidence(path) as handle:
                return scan(handle, signatures=signatures)
        with open_evidence(path) as probe:
            size = probe.size
        if size < parallel_floor_bytes:
            # Measured on the development box: a four-process pool costs ~0.48s
            # to start, against ~0.75s to scan 64 MiB serially, so splitting a
            # small image is a net loss (0.96x). The crossover sits near
            # 256 MiB (1.77x) and reaches 2.10x by 512 MiB, bounded by read
            # bandwidth rather than CPU. Below the floor, do the honest thing
            # and scan serially rather than charge the caller for the pool.
            with open_evidence(path) as handle:
                return scan(handle, signatures=signatures)
        overlap = _max_pattern_length(
            list(signatures) if signatures else load_signatures(db_path)
        )
        jobs = [
            # Extend each range's end by the overlap so an object whose header
            # sits just before a seam is still attributed to exactly one worker.
            (
                str(path),
                start,
                min(end + overlap, size),
                str(db_path) if db_path else None,
            )
            for start, end in _plan_ranges(size, workers)
        ]
        import multiprocessing

        with multiprocessing.Pool(processes=workers) as pool:
            parts = pool.map(_scan_range, jobs)

        merged = ScanReport()
        seen: set[tuple[int, str]] = set()
        for part in parts:
            merged.bytes_scanned += part.bytes_scanned
            merged.suppressed_substituted += part.suppressed_substituted
            merged.suppressed_too_small += part.suppressed_too_small
            merged.suppressed_uncorroborated += part.suppressed_uncorroborated
            for candidate in part.candidates:
                key = (candidate.offset, candidate.ext)
                if key in seen:
                    continue
                seen.add(key)
                merged.candidates.append(candidate)
        merged.candidates.sort(key=lambda c: (c.offset, c.ext))
        return merged

    return scan(image, signatures=signatures)
