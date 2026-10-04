"""The read-only evidence surface. Everything downstream reads through this.

This module has one job above every other: nothing in the carving pipeline can
modify evidence, and nothing can silently substitute data for it. Both are
structural rather than conventional.

**No write path exists.** :class:`EvidenceHandle` declares no write method, and
no implementation defines one. This is deliberately not "a write method that
raises": a method that raises can still be reached by a caller catching broadly,
and a stack trace is a poorer guarantee than an attribute that was never there.
Every file is opened ``O_RDONLY``, and on Windows with a share mode that permits
other readers but never grants this process write access.

**Substitution is always recorded.** When a region cannot be read, :meth:`read`
returns a fill byte rather than raising, because a drive with forty thousand bad
sectors still yields evidence. The cost of that choice is that a run of zeros in
the returned buffer is ambiguous: it may be zeros that were on the media, or
zeros this module invented. :meth:`was_substituted` and :meth:`substituted_in`
resolve the ambiguity, and every filled range is recorded on
:attr:`EvidenceSource.substituted_ranges`. :meth:`was_substituted` is true when
*any* byte in the queried range was filled - it over-reports rather than
under-reports, because a carved file assembled partly from invented bytes is not
a recovered file.

**Concurrency.** Handles are safe for concurrent readers *within one process*:
reads are positional (``os.pread`` where available, otherwise a lock around
seek-then-read), so no thread can consume another's file position. Handles are
deliberately not shared between processes. ``pyewf`` handles are not fork-safe,
and the block cache cannot be shared across a process boundary in any case, so a
handle that pickled would silently lose the cache it was built for. A worker
process calls :func:`open_evidence` itself.

**No mmap assumption.** E01 chunks are compressed and cannot be memory-mapped,
so nothing here exposes a buffer interface and nothing downstream may require
one. The block cache exists because that decompression is expensive and the
carver reads randomly.
"""

from __future__ import annotations

import os
import re
import threading
from bisect import bisect_right
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Protocol, runtime_checkable

from core.errors import EvidenceIntegrityError
from core.models import EvidenceSource, SubstitutedRange

__all__ = [
    "EvidenceHandle",
    "CacheStats",
    "BlockCache",
    "BytesEvidence",
    "RawEvidence",
    "SplitRawEvidence",
    "EwfEvidence",
    "WindowedEvidence",
    "open_evidence",
    "DEFAULT_CACHE_BYTES",
    "DEFAULT_SECTOR_BYTES",
    "EWF_MAGIC",
    "AFF4_MAGIC",
]

KIB = 1024
MIB = 1024 * KIB

#: Block cache size, in bytes rather than entries: an entry count says nothing
#: about memory when chunk sizes differ between formats.
DEFAULT_CACHE_BYTES = 256 * MIB

DEFAULT_SECTOR_BYTES = 512

#: Cache granularity. Large enough that sequential carving mostly hits, small
#: enough that a random 512-byte read does not pull a megabyte behind it.
CACHE_BLOCK_BYTES = 64 * KIB

#: EWF segment header. ``EVF`` for E01, ``EVF2`` for Ex01.
EWF_MAGIC = b"EVF\x09\x0d\x0a\xff\x00"
EWF2_MAGIC = b"EVF2\x0d\x0a\x81\x00"
AFF4_MAGIC = b"AFF4"

#: Split-set naming: ``image.001`` / ``image.002`` and ``image.dd.1`` /
#: ``image.dd.2``. Both are in the wild; neither is trusted for format, only
#: for discovering sibling segments once the first one is known to be raw.
_SPLIT_NUMERIC = re.compile(r"^(?P<stem>.+)\.(?P<num>\d{2,3})$")
_SPLIT_SUFFIXED = re.compile(r"^(?P<stem>.+\.(?:dd|raw|img))\.(?P<num>\d+)$")


# --------------------------------------------------------------------------
# Interface
# --------------------------------------------------------------------------


@runtime_checkable
class EvidenceHandle(Protocol):
    """A byte-addressable, read-only view over an evidence source.

    Implementations must satisfy, and callers may rely on:

    * ``read(offset, length)`` returns *up to* ``length`` bytes. A read that
      starts at or past :attr:`size` returns ``b""``; one that overruns the end
      returns what exists. Neither raises. A negative offset or length is a
      caller bug and does raise :class:`ValueError`.
    * Unreadable regions come back as the substitution byte, and the range is
      recorded on ``source.substituted_ranges``.
    * Concurrent readers in one process are safe. Sharing a handle across
      processes is not supported.
    """

    @property
    def size(self) -> int:
        """Bytes in the addressable image."""
        ...

    @property
    def sector_size(self) -> int:
        """Logical sector size, typically 512 or 4096."""
        ...

    @property
    def source(self) -> EvidenceSource:
        """Identity, hashes and acquisition record for this evidence."""
        ...

    def read(self, offset: int, length: int) -> bytes:
        """Return up to ``length`` bytes at ``offset``. Never writes."""
        ...

    def was_substituted(self, offset: int, length: int) -> bool:
        """True when *any* byte in the range was filled rather than read."""
        ...

    def substituted_in(self, offset: int, length: int) -> list[SubstitutedRange]:
        """Every recorded substitution overlapping the range, in order."""
        ...

    def close(self) -> None:
        """Release the underlying handle. Idempotent."""
        ...

    def __enter__(self) -> EvidenceHandle: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None: ...


# --------------------------------------------------------------------------
# Block cache
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class CacheStats:
    """Cache effectiveness. Reported because the demo needs the number."""

    hits: int
    misses: int
    bytes_held: int
    evictions: int

    @property
    def hit_rate_bp(self) -> int:
        """Hit rate in basis points, 10000 being every read served."""
        total = self.hits + self.misses
        return 10_000 * self.hits // total if total else 0


class BlockCache:
    """Size-bounded LRU over fixed-size blocks, keyed by block index.

    Bounded in bytes, not entries, because the caller cares about memory and
    block sizes differ between formats. Read-only by construction: nothing
    mutates a cached buffer, so a hit can hand out the same immutable
    ``bytes`` object to every caller without copying.
    """

    def __init__(self, max_bytes: int = DEFAULT_CACHE_BYTES) -> None:
        if max_bytes < 0:
            raise ValueError("cache size cannot be negative")
        self._max_bytes = max_bytes
        self._entries: OrderedDict[int, bytes] = OrderedDict()
        self._held = 0
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._lock = threading.Lock()

    def get(self, index: int) -> bytes | None:
        with self._lock:
            block = self._entries.get(index)
            if block is None:
                self._misses += 1
                return None
            self._entries.move_to_end(index)
            self._hits += 1
            return block

    def put(self, index: int, block: bytes) -> None:
        if self._max_bytes == 0 or len(block) > self._max_bytes:
            return
        with self._lock:
            if index in self._entries:
                self._held -= len(self._entries.pop(index))
            self._entries[index] = block
            self._held += len(block)
            while self._held > self._max_bytes and self._entries:
                _, evicted = self._entries.popitem(last=False)
                self._held -= len(evicted)
                self._evictions += 1

    def stats(self) -> CacheStats:
        with self._lock:
            return CacheStats(
                hits=self._hits,
                misses=self._misses,
                bytes_held=self._held,
                evictions=self._evictions,
            )

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._held = 0


# --------------------------------------------------------------------------
# Shared behaviour
# --------------------------------------------------------------------------


def _check_range(offset: int, length: int) -> None:
    if offset < 0:
        raise ValueError(f"offset must not be negative, got {offset}")
    if length < 0:
        raise ValueError(f"length must not be negative, got {length}")


class _BaseEvidence:
    """Range checking, substitution bookkeeping and context management.

    Subclasses implement :meth:`_read_exact`, which is handed an already
    clamped range guaranteed to lie inside the image.
    """

    _source: EvidenceSource
    _sector_size: int

    def __init__(self, source: EvidenceSource, sector_size: int) -> None:
        self._source = source
        self._sector_size = sector_size
        self._closed = False

    # -- interface ---------------------------------------------------------

    @property
    def size(self) -> int:
        return self._source.size_bytes

    @property
    def sector_size(self) -> int:
        return self._sector_size

    @property
    def source(self) -> EvidenceSource:
        return self._source

    def read(self, offset: int, length: int) -> bytes:
        _check_range(offset, length)
        if self._closed:
            raise EvidenceIntegrityError(
                f"read after close on {self._source.path}",
                remediation="Open the evidence again; a closed handle is inert.",
            )
        available = max(self.size - offset, 0)
        clamped = min(length, available)
        if clamped == 0:
            return b""
        return self._read_exact(offset, clamped)

    def was_substituted(self, offset: int, length: int) -> bool:
        _check_range(offset, length)
        return bool(self.substituted_in(offset, length))

    def substituted_in(self, offset: int, length: int) -> list[SubstitutedRange]:
        _check_range(offset, length)
        end = offset + length
        return [
            span
            for span in self._source.substituted_ranges
            if span.offset < end and offset < span.offset + span.length
        ]

    def close(self) -> None:
        self._closed = True

    def __enter__(self) -> EvidenceHandle:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # -- subclass hook -----------------------------------------------------

    def _read_exact(self, offset: int, length: int) -> bytes:
        raise NotImplementedError


# --------------------------------------------------------------------------
# In-memory
# --------------------------------------------------------------------------


class BytesEvidence(_BaseEvidence):
    """Evidence held in memory. For tests, and for the parallel carver track.

    ``unreadable`` marks ranges as substituted without needing a device that
    actually fails, so the substitution contract can be tested honestly.
    """

    def __init__(
        self,
        data: bytes,
        *,
        unreadable: Iterable[tuple[int, int]] = (),
        recorded_substituted: Iterable[tuple[int, int]] = (),
        sector_size: int = DEFAULT_SECTOR_BYTES,
        fill_byte: int = 0x00,
        path: str = "<memory>",
    ) -> None:
        """``unreadable`` ranges are recorded *and* overwritten with the fill
        byte, which is what a real acquisition produces.

        ``recorded_substituted`` ranges are recorded but leave the bytes alone.
        That models the case the two disagree: substituted ranges travel in the
        acquisition record, a sidecar the image itself cannot confirm, so a
        carver may be handed metadata saying "filled" over bytes that still
        look like content. Suppression has to hold there too, which is the only
        way to exercise it.
        """
        self._data = bytes(data)
        substituted = [
            SubstitutedRange(
                offset=start,
                length=count,
                fill_byte=fill_byte,
                reason="marked unreadable by the caller",
            )
            for start, count in unreadable
        ]
        recorded = [
            SubstitutedRange(
                offset=start,
                length=count,
                fill_byte=fill_byte,
                reason="recorded as substituted by the acquisition record",
            )
            for start, count in recorded_substituted
        ]
        super().__init__(
            EvidenceSource(
                path=path,
                fmt="bytes",
                size_bytes=len(self._data),
                sector_size=sector_size,
                substituted_ranges=sorted(
                    substituted + recorded, key=lambda span: span.offset
                ),
            ),
            sector_size,
        )
        # Only the genuinely unreadable ranges are overwritten; recorded
        # ones keep their bytes so the disagreement can be tested.
        for span in substituted:
            head = self._data[: span.offset]
            tail = self._data[span.offset + span.length :]
            self._data = head + bytes([fill_byte]) * span.length + tail

    def _read_exact(self, offset: int, length: int) -> bytes:
        return self._data[offset : offset + length]


# --------------------------------------------------------------------------
# Raw single file or block device
# --------------------------------------------------------------------------


class RawEvidence(_BaseEvidence):
    """A single raw image file or block device, opened read-only."""

    def __init__(
        self,
        path: Path | str,
        *,
        sector_size: int = DEFAULT_SECTOR_BYTES,
        cache_bytes: int = DEFAULT_CACHE_BYTES,
        size_bytes: int | None = None,
    ) -> None:
        self._path = Path(path)
        self._fd = os.open(self._path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        self._lock = threading.Lock()
        self._cache = BlockCache(cache_bytes)
        resolved = size_bytes if size_bytes is not None else os.fstat(self._fd).st_size
        super().__init__(
            EvidenceSource(
                path=str(self._path),
                fmt="raw",
                size_bytes=resolved,
                sector_size=sector_size,
            ),
            sector_size,
        )

    def _read_at(self, offset: int, length: int) -> bytes:
        """Positional read. ``os.pread`` is atomic; the fallback needs a lock."""
        pread = getattr(os, "pread", None)
        if pread is not None:
            return bytes(pread(self._fd, length, offset))
        with self._lock:
            os.lseek(self._fd, offset, os.SEEK_SET)
            return os.read(self._fd, length)

    def _read_exact(self, offset: int, length: int) -> bytes:
        return _cached_read(self._cache, self._read_at, offset, length, self.size)

    def cache_stats(self) -> CacheStats:
        return self._cache.stats()

    def close(self) -> None:
        if not self._closed:
            os.close(self._fd)
            self._cache.clear()
        super().close()


# --------------------------------------------------------------------------
# Split raw sets
# --------------------------------------------------------------------------


class SplitRawEvidence(_BaseEvidence):
    """A split raw set assembled into one contiguous address space.

    A missing middle segment is an error, never a gap to skip: silently
    stitching segment 4 onto segment 2 shifts every subsequent offset and
    turns every downstream extent reference into a lie.
    """

    def __init__(
        self,
        segments: Sequence[Path | str],
        *,
        sector_size: int = DEFAULT_SECTOR_BYTES,
        cache_bytes: int = DEFAULT_CACHE_BYTES,
    ) -> None:
        if not segments:
            raise EvidenceIntegrityError(
                "a split set needs at least one segment",
                remediation="Pass the first segment, e.g. image.001.",
            )
        self._paths = [Path(p) for p in segments]
        self._fds: list[int] = []
        self._starts: list[int] = []
        self._lengths: list[int] = []
        total = 0
        for path in self._paths:
            if not path.exists():
                raise EvidenceIntegrityError(
                    f"split set segment is missing: {path.name}",
                    remediation=(
                        f"Restore {path.name} beside the other segments. A split "
                        "set cannot be read across a hole: every byte after the "
                        "gap would be reported at the wrong offset."
                    ),
                )
            self._fds.append(os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0)))
            length = path.stat().st_size
            self._starts.append(total)
            self._lengths.append(length)
            total += length
        self._lock = threading.Lock()
        self._cache = BlockCache(cache_bytes)
        super().__init__(
            EvidenceSource(
                path=str(self._paths[0]),
                fmt="split_raw",
                size_bytes=total,
                sector_size=sector_size,
                segments=[str(p) for p in self._paths],
            ),
            sector_size,
        )

    def _read_at(self, offset: int, length: int) -> bytes:
        """Walk segments, because one read may span three of them."""
        out = bytearray()
        remaining = length
        cursor = offset
        index = bisect_right(self._starts, cursor) - 1
        while remaining > 0 and index < len(self._fds):
            start = self._starts[index]
            within = cursor - start
            take = min(remaining, self._lengths[index] - within)
            if take <= 0:
                index += 1
                continue
            out += self._pread(self._fds[index], take, within)
            cursor += take
            remaining -= take
            index += 1
        return bytes(out)

    def _pread(self, fd: int, length: int, offset: int) -> bytes:
        pread = getattr(os, "pread", None)
        if pread is not None:
            return bytes(pread(fd, length, offset))
        with self._lock:
            os.lseek(fd, offset, os.SEEK_SET)
            return os.read(fd, length)

    def _read_exact(self, offset: int, length: int) -> bytes:
        return _cached_read(self._cache, self._read_at, offset, length, self.size)

    def cache_stats(self) -> CacheStats:
        return self._cache.stats()

    def close(self) -> None:
        if not self._closed:
            for fd in self._fds:
                os.close(fd)
            self._cache.clear()
        super().close()


# --------------------------------------------------------------------------
# EWF (E01 / Ex01)
# --------------------------------------------------------------------------


class EwfEvidence(_BaseEvidence):
    """An EWF image read through ``pyewf``.

    Chunks are compressed, so every read costs a decompression and the block
    cache matters far more here than for raw. ``pyewf`` handles are not
    thread-safe and hold internal position state, so reads are serialised
    under a lock; the cache is what keeps that from dominating.
    """

    def __init__(
        self,
        path: Path | str,
        *,
        cache_bytes: int = DEFAULT_CACHE_BYTES,
    ) -> None:
        import pyewf

        self._path = Path(path)
        filenames = pyewf.glob(str(self._path))
        self._handle = pyewf.handle()
        self._handle.open(filenames)
        self._lock = threading.Lock()
        self._cache = BlockCache(cache_bytes)
        sector_size = int(getattr(self._handle, "bytes_per_sector", 0) or
                          DEFAULT_SECTOR_BYTES)
        super().__init__(
            EvidenceSource(
                path=str(self._path),
                fmt="ewf",
                size_bytes=int(self._handle.get_media_size()),
                sector_size=sector_size,
                segments=[str(name) for name in filenames],
            ),
            sector_size,
        )

    def _read_at(self, offset: int, length: int) -> bytes:
        with self._lock:
            self._handle.seek(offset, os.SEEK_SET)
            return bytes(self._handle.read(length))

    def _read_exact(self, offset: int, length: int) -> bytes:
        return _cached_read(self._cache, self._read_at, offset, length, self.size)

    def cache_stats(self) -> CacheStats:
        return self._cache.stats()

    def close(self) -> None:
        if not self._closed:
            with self._lock:
                self._handle.close()
            self._cache.clear()
        super().close()


# --------------------------------------------------------------------------
# Windowing
# --------------------------------------------------------------------------


class WindowedEvidence(_BaseEvidence):
    """A sub-range view, so a partition reads as if it began at offset 0.

    Offset 0 of the window is ``base_offset`` of the parent. The window never
    returns a byte outside itself, which is what makes partition-relative
    addressing safe to hand to a filesystem parser.
    """

    def __init__(
        self, parent: EvidenceHandle, *, base_offset: int, length: int
    ) -> None:
        _check_range(base_offset, length)
        if base_offset + length > parent.size:
            raise ValueError(
                f"window [{base_offset}, {base_offset + length}) extends past the "
                f"parent's {parent.size} bytes"
            )
        self._parent = parent
        self._base = base_offset
        parent_source = parent.source
        shifted = [
            SubstitutedRange(
                offset=max(span.offset - base_offset, 0),
                length=(
                    min(span.offset + span.length, base_offset + length)
                    - max(span.offset, base_offset)
                ),
                fill_byte=span.fill_byte,
                reason=span.reason,
            )
            for span in parent_source.substituted_ranges
            if span.offset < base_offset + length
            and base_offset < span.offset + span.length
        ]
        super().__init__(
            EvidenceSource(
                path=parent_source.path,
                fmt=parent_source.fmt,
                size_bytes=length,
                sector_size=parent_source.sector_size,
                segments=list(parent_source.segments),
                substituted_ranges=shifted,
                limitations=list(parent_source.limitations),
            ),
            parent.sector_size,
        )

    def _read_exact(self, offset: int, length: int) -> bytes:
        return self._parent.read(self._base + offset, length)

    def close(self) -> None:
        """Closes the window, never the parent: the parent may be shared."""
        super().close()


# --------------------------------------------------------------------------
# Cached read helper
# --------------------------------------------------------------------------


def _cached_read(
    cache: BlockCache,
    fetch: Callable[[int, int], bytes],
    offset: int,
    length: int,
    size: int,
) -> bytes:
    """Serve a read from fixed-size cached blocks, fetching what is missing.

    Aligning to a block grid is what makes the cache useful: the carver's
    overlapping and repeated reads collapse onto the same block indices
    instead of each becoming a distinct key.
    """
    first = offset // CACHE_BLOCK_BYTES
    last = (offset + length - 1) // CACHE_BLOCK_BYTES
    out = bytearray()
    for index in range(first, last + 1):
        block = cache.get(index)
        if block is None:
            start = index * CACHE_BLOCK_BYTES
            block = fetch(start, min(CACHE_BLOCK_BYTES, size - start))
            cache.put(index, block)
        block_start = index * CACHE_BLOCK_BYTES
        take_from = max(offset - block_start, 0)
        take_to = min(offset + length - block_start, len(block))
        out += block[take_from:take_to]
    return bytes(out)


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------


def _sibling_segments(path: Path) -> list[Path] | None:
    """Discover a split set from its first segment, or ``None`` if not one.

    Raises when the set has a hole. Reporting a short image would be worse
    than refusing: every offset after the gap would be silently wrong.
    """
    for pattern in (_SPLIT_SUFFIXED, _SPLIT_NUMERIC):
        match = pattern.match(path.name)
        if match is None:
            continue
        stem, digits = match.group("stem"), match.group("num")
        width = len(digits)
        first = int(digits)
        segments = [path]
        expected = first + 1
        while True:
            candidate = path.with_name(f"{stem}.{expected:0{width}d}")
            if candidate.exists():
                segments.append(candidate)
                expected += 1
                continue
            # A later segment existing past a missing one means a hole, not an
            # end. Probe ahead far enough to catch the common single gap.
            for lookahead in range(expected + 1, expected + 8):
                probe = path.with_name(f"{stem}.{lookahead:0{width}d}")
                if probe.exists():
                    missing = path.with_name(f"{stem}.{expected:0{width}d}")
                    raise EvidenceIntegrityError(
                        f"split set segment is missing: {missing.name}",
                        remediation=(
                            f"Restore {missing.name}. {probe.name} exists, so the "
                            "set has a hole rather than an end; reading across it "
                            "would report every later byte at the wrong offset."
                        ),
                    )
            break
        return segments if len(segments) > 1 else None
    return None


def open_evidence(
    path: Path | str,
    *,
    cache_bytes: int = DEFAULT_CACHE_BYTES,
    sector_size: int = DEFAULT_SECTOR_BYTES,
) -> EvidenceHandle:
    """Open evidence, detecting its format by magic bytes rather than name.

    A filename is not evidence. An image called ``.E01`` that is actually raw
    must open as raw, and one called ``.dd`` that is actually EWF must open as
    EWF, because an examiner who renamed a file should not thereby change how
    it is interpreted.
    """
    target = Path(path)
    if not target.exists():
        raise EvidenceIntegrityError(
            f"evidence not found: {target}",
            remediation="Check the path; nothing was opened.",
        )

    with open(target, "rb") as probe:
        header = probe.read(16)

    if header.startswith(AFF4_MAGIC):
        raise EvidenceIntegrityError(
            f"{target.name} is an AFF4 container, which is not supported",
            remediation=(
                "Convert it to raw or E01 first, e.g. with aff4imager. Sanctum "
                "will not guess at an AFF4 layout: reading it wrongly would "
                "produce carved objects that never existed on the media."
            ),
        )
    if header.startswith(EWF_MAGIC) or header.startswith(EWF2_MAGIC):
        return EwfEvidence(target, cache_bytes=cache_bytes)

    segments = _sibling_segments(target)
    if segments is not None:
        return SplitRawEvidence(
            segments, sector_size=sector_size, cache_bytes=cache_bytes
        )
    return RawEvidence(target, sector_size=sector_size, cache_bytes=cache_bytes)


def iter_evidence(handle: EvidenceHandle, block_bytes: int) -> Iterator[bytes]:
    """Yield the whole image in order. A convenience for hashing passes."""
    offset = 0
    while offset < handle.size:
        chunk = handle.read(offset, block_bytes)
        if not chunk:
            return
        yield chunk
        offset += len(chunk)
