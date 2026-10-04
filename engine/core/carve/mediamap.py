"""A map of what an evidence image holds, from the statistics of its bytes.

Before a long carve, an examiner wants to know where the data is: which
stretches of the image are zeroed, which hold a fill pattern (erased flash
reads 0xFF; the free-space wipe leaves 0xA5), which are text, which are
structured binary, and which are high-entropy - compressed media, encrypted
volumes or random fill. This module answers that from byte statistics, region
by region, and counts the file headers the carver knows where they sit on
sector boundaries.

Two uses. **Triage**: the map shows where recoverable content can be, and where
it cannot, before the carve runs. **Corroborating a wipe**: an image of a
sanitized medium maps as zero or fill from end to end, and a region that does
not is a region the wipe did not reach.

What it cannot do is said in the result, not left to the reader: byte
statistics do not identify content. A high-entropy region is compressed,
encrypted or random, and the bytes alone do not say which. A header count is
of headers, not of files: nothing here validates what follows one. And a map
built from samples classes each region by its samples, so a region can hold
something its samples missed.

Read-only: the image is read through :mod:`core.carve.evidence`, which has no
write path. Every number is an integer, so the map can enter a signed report
and the ledger unchanged.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Generator, Sequence

import structlog

from core.carve.evidence import EvidenceHandle
from core.carve.signature import Signature, load_signatures
from core.models import MediaMap, MediaRegion, Progress

__all__ = [
    "BLOCK_BYTES",
    "DEFAULT_READ_BUDGET",
    "DEFAULT_REGIONS",
    "KINDS",
    "classify_block",
    "map_media",
]

logger = structlog.get_logger(__name__)

#: The unit each statistic is taken over. A 4 KiB block is one page and, on
#: every current medium, a whole number of sectors.
BLOCK_BYTES = 4096

#: How many regions the map divides an image into.
DEFAULT_REGIONS = 256

#: Up to this many bytes are read. An image no larger is read in full; a larger
#: one is sampled, evenly and deterministically, within this budget.
DEFAULT_READ_BUDGET = 64 * 1024 * 1024

#: The classes, in the order the map and the legend draw them.
KINDS = ("ZERO", "FILL", "TEXT", "STRUCTURED", "HIGH_ENTROPY")

#: Mean bits per byte at or above which a block is called high-entropy.
#: Compressed and encrypted data measure 7.9 and above over 4 KiB; English
#: text about 4.5; structured binary sits between.
_HIGH_ENTROPY_MILLIBITS = 7_500

#: Share of printable bytes at or above which a block is called text.
_TEXT_SHARE_BP = 9_500

_PRINTABLE = bytes([0x09, 0x0A, 0x0D, *range(0x20, 0x7F)])

#: Headers shorter than this are too common in arbitrary bytes to count
#: without the corroboration the carver gives them (``MZ``, ``BM``).
_MIN_HEADER = 3

_SECTOR = 512


def classify_block(block: bytes) -> tuple[str, int, int | None]:
    """``(kind, entropy in millibits per byte, fill byte)`` for one block."""
    if not block:
        return "ZERO", 0, None
    first = block[0]
    if block.count(first) == len(block):
        return ("ZERO", 0, None) if first == 0 else ("FILL", 0, first)
    total = len(block)
    entropy = -sum(
        (count / total) * math.log2(count / total) for count in Counter(block).values()
    )
    millibits = round(entropy * 1000)
    printable = total - len(block.translate(None, _PRINTABLE))
    if printable * 10_000 >= _TEXT_SHARE_BP * total:
        return "TEXT", millibits, None
    if millibits >= _HIGH_ENTROPY_MILLIBITS:
        return "HIGH_ENTROPY", millibits, None
    return "STRUCTURED", millibits, None


def _header_table(signatures: Sequence[Signature]) -> list[tuple[int, bytes, str]]:
    """``(offset, header, label)`` for each distinct header worth counting.

    Two formats sharing one header (RIFF: WebP and WAV) are counted once, under
    both names, because the header alone cannot tell them apart.
    """
    labels: dict[tuple[int, bytes], list[str]] = {}
    for signature in signatures:
        if len(signature.header) < _MIN_HEADER:
            continue
        key = (signature.header_offset, signature.header)
        names = labels.setdefault(key, [])
        if signature.ext not in names:
            names.append(signature.ext)
    return [
        (offset, header, "/".join(names)) for (offset, header), names in labels.items()
    ]


def _headers_in(block: bytes, table: list[tuple[int, bytes, str]]) -> Counter[str]:
    """File headers that start on a sector boundary inside ``block``."""
    found: Counter[str] = Counter()
    for start in range(0, len(block), _SECTOR):
        for offset, header, label in table:
            at = start + offset
            if block[at : at + len(header)] == header:
                found[label] += 1
    return found


def _plan(size: int, regions: int, budget: int) -> tuple[int, int, bool]:
    """``(region bytes, blocks read per region, sampled)`` for an image."""
    blocks = max(1, math.ceil(size / BLOCK_BYTES))
    count = max(1, min(regions, blocks))
    region_blocks = math.ceil(blocks / count)
    per_region = max(1, budget // (count * BLOCK_BYTES))
    sampled = per_region < region_blocks
    return region_blocks * BLOCK_BYTES, min(per_region, region_blocks), sampled


def _offsets(start: int, length: int, reads: int) -> list[int]:
    """Evenly spaced block offsets in a region: every block, or ``reads`` of them."""
    blocks = max(1, math.ceil(length / BLOCK_BYTES))
    if reads >= blocks:
        return [start + index * BLOCK_BYTES for index in range(blocks)]
    stride = blocks / reads
    return [
        start + int(index * stride + stride / 2) * BLOCK_BYTES for index in range(reads)
    ]


def _progress(job_id: str, done: int, total: int, read: int, message: str) -> Progress:
    return Progress(
        job_id=job_id,
        phase="MAP",
        pct_bp=10_000 * done // total if total else 10_000,
        bytes_done=read,
        bytes_total=0,
        throughput_bytes_per_sec=0,
        eta_seconds=0,
        message=message,
    )


def map_media(
    handle: EvidenceHandle,
    *,
    job_id: str = "map",
    regions: int = DEFAULT_REGIONS,
    read_budget: int = DEFAULT_READ_BUDGET,
    signatures: Sequence[Signature] | None = None,
) -> Generator[Progress, None, MediaMap]:
    """Class every region of the image by the statistics of its bytes.

    Deterministic: the same image, region count and budget give the same map,
    because the samples are evenly spaced rather than random.
    """
    size = handle.size
    region_bytes, reads, sampled = _plan(size, regions, read_budget)
    table = _header_table(signatures if signatures is not None else load_signatures())
    starts = list(range(0, size, region_bytes)) or [0]
    mapped: list[MediaRegion] = []
    by_kind: dict[str, int] = dict.fromkeys(KINDS, 0)
    headers: Counter[str] = Counter()
    bytes_read = 0
    yield _progress(job_id, 0, len(starts), 0, f"{len(starts)} region(s)")

    for index, start in enumerate(starts):
        length = min(region_bytes, size - start)
        kinds: Counter[str] = Counter()
        fills: Counter[int] = Counter()
        found: Counter[str] = Counter()
        entropy = 0
        read_here = 0
        blocks = 0
        substituted = False
        for offset in _offsets(start, length, reads):
            block = handle.read(offset, min(BLOCK_BYTES, start + length - offset))
            if not block:
                continue
            kind, millibits, fill = classify_block(block)
            kinds[kind] += 1
            if fill is not None:
                fills[fill] += 1
            entropy += millibits
            found += _headers_in(block, table)
            read_here += len(block)
            blocks += 1
            substituted = substituted or handle.was_substituted(offset, len(block))
        if not blocks:
            continue
        kind, share = kinds.most_common(1)[0]
        # Bytes per class, shared out by block count; the remainder goes to the
        # majority class so the classes always sum to the image's size.
        assigned = 0
        for name, count in kinds.items():
            portion = length * count // blocks
            by_kind[name] += portion
            assigned += portion
        by_kind[kind] += length - assigned
        headers += found
        bytes_read += read_here
        mapped.append(
            MediaRegion(
                offset=start,
                length=length,
                kind=kind,
                share_bp=10_000 * share // blocks,
                entropy_mb=entropy // blocks,
                fill_byte=fills.most_common(1)[0][0] if kind == "FILL" else None,
                headers=dict(sorted(found.items())),
                bytes_read=read_here,
                substituted=substituted,
            )
        )
        if index % 16 == 15:
            yield _progress(
                job_id,
                index + 1,
                len(starts),
                bytes_read,
                f"{index + 1} region(s) mapped",
            )

    limitations = [
        "Byte statistics do not identify content: a high-entropy region is "
        "compressed, encrypted or random, and the bytes alone do not say which.",
        "Header counts are of file headers on sector boundaries, not of files: "
        "nothing here validates what follows a header.",
    ]
    if sampled:
        limitations.append(
            f"SAMPLED: {reads} evenly spaced {BLOCK_BYTES}-byte block(s) were read "
            f"per {region_bytes:,}-byte region, {bytes_read:,} bytes of "
            f"{size:,}. A region is classed by its samples and can hold something "
            "they missed."
        )
    if any(region.substituted for region in mapped):
        limitations.append(
            "Some bytes read were substituted for unreadable ones; the regions "
            "that hold them are marked, and their class is of the fill, not the media."
        )
    result = MediaMap(
        size_bytes=size,
        region_bytes=region_bytes,
        block_bytes=BLOCK_BYTES,
        sampled=sampled,
        bytes_read=bytes_read,
        regions=mapped,
        by_kind={name: value for name, value in by_kind.items()},
        headers=dict(sorted(headers.items())),
        limitations=limitations,
    )
    yield _progress(job_id, len(starts), len(starts), bytes_read, "mapped")
    logger.info(
        "media_map_complete",
        job_id=job_id,
        regions=len(mapped),
        sampled=sampled,
        bytes_read=bytes_read,
    )
    return result
