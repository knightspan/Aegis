"""Count identity and financial identifiers in a recovered object. Never keep them.

An examiner facing hundreds of recovered files needs to know which of them hold
personal data before opening any. This module answers that with a **type and a
count** per object, and nothing else.

**The values are never retained.** A forensic tool that copies the Aadhaar
numbers it found into its report, its ledger or its logs has made a second copy
of the data it was recovering, and that copy is signed, hash-chained and built
to travel. So a match is counted and discarded inside :func:`_count_window`:

* no matched string, prefix, suffix or mask is returned or logged;
* no hash of a value either - a 12-digit Aadhaar space holds 10**11 numbers
  after the checksum, which a laptop enumerates against a SHA-256 in minutes;
* **no offsets**. An offset plus the recovered object reconstructs the value,
  and the report travels further than the object does. An examiner who wants
  the value opens the recovered file, which is where the value already is.

A count is a signal to look, not a finding. Every detector here matches a
*shape* and, where the format has one, a checksum; neither establishes that the
digits are the identifier they resemble.

Detectors, Indian-first:

=============  ============================================================
aadhaar        12 digits, first digit 2-9, optionally grouped 4-4-4 with one
               consistent space or hyphen, **Verhoeff checksum valid**.
pan            ``AAA[ABCFGHLJPT]A9999A``: the fourth character is the holder
               type, which excludes most random uppercase runs.
ifsc           four letters, a literal ``0``, six letters or digits.
indian_mobile  ten digits starting 6-9, optionally prefixed ``+91`` or
               ``0091``, with or without one separator after the prefix.
payment_card   13-19 digits, optionally separated by single spaces or
               hyphens, **Luhn valid**.
email          a bounded local part, ``@``, one to four DNS labels and an
               alphabetic TLD.
=============  ============================================================

Every pattern requires a non-alphanumeric boundary on both sides, so a
detector never counts the middle of a longer run.

**Where it looks.** Raw bytes for plain text and for types the text lives in
uncompressed; the inflated XML parts of an OOXML package; the decoded streams
of a PDF. Pixel data, compressed media and executables are not scanned at all:
the false-positive rates measured on JPEG entropy data are in
``docs/limitations.md``, and the scope decision in :data:`SCANNED_CATEGORIES`
rests on them.

**Memory.** Scanning is windowed: :data:`WINDOW_BYTES` at a time, each window
carrying :data:`CONTEXT_BYTES` of the bytes on either side, so a value that
spans a window boundary is still seen whole and is counted exactly once. The
longest thing any pattern can match is bounded well below the context.
"""

from __future__ import annotations

import io
import re
import zipfile
import zlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass

import structlog

__all__ = [
    "PII_KINDS",
    "WINDOW_BYTES",
    "CONTEXT_BYTES",
    "SCANNED_CATEGORIES",
    "MAX_EXTRACT_BYTES",
    "PiiScan",
    "DETECTORS",
    "verhoeff_valid",
    "luhn_valid",
    "count_bytes",
    "count_reader",
    "scan_content",
]

logger = structlog.get_logger(__name__)

KIB = 1024
MIB = 1024 * KIB

#: Every kind this module can report, in display order.
PII_KINDS = (
    "aadhaar",
    "pan",
    "ifsc",
    "indian_mobile",
    "payment_card",
    "email",
)

#: Bytes each window is responsible for. A match is counted by the window whose
#: responsibility its first byte falls in, and by no other.
WINDOW_BYTES = 1 * MIB

#: Bytes of neighbouring data each window also sees, on both sides. Must exceed
#: the longest possible match (an email: 64 + 1 + 4 * 64 + 24 = 345 bytes) plus
#: the one boundary byte either side, so a value spanning a boundary is whole in
#: the window that counts it.
CONTEXT_BYTES = 512

#: Upper bound on text extracted from one container (OOXML parts, PDF streams).
#: The same budget the validator gives a candidate's raw bytes.
MAX_EXTRACT_BYTES = 64 * MIB

#: Categories whose content is scanned. Set from the false-positive
#: measurement, not from intuition; see ``docs/limitations.md``.
SCANNED_CATEGORIES = frozenset({"document", "database", "unknown"})

_B = rb"(?<![0-9A-Za-z])"
_E = rb"(?![0-9A-Za-z])"

_AADHAAR = re.compile(_B + rb"[2-9][0-9]{3}([ -]?)[0-9]{4}\1[0-9]{4}" + _E)
_PAN = re.compile(_B + rb"[A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z]" + _E)
_IFSC = re.compile(_B + rb"[A-Z]{4}0[A-Z0-9]{6}" + _E)
_MOBILE = re.compile(rb"(?<![0-9A-Za-z+])(?:(?:\+91|0091)[ -]?)?[6-9][0-9]{9}" + _E)
_CARD = re.compile(_B + rb"[0-9](?:[ -]?[0-9]){12,18}" + _E)
_EMAIL = re.compile(
    rb"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@"
    rb"(?:[A-Za-z0-9-]{1,63}\.){1,4}[A-Za-z]{2,24}(?![A-Za-z0-9-])"
)
_DIGITS = re.compile(rb"[0-9]")

# Prefilters. Each precise pattern above runs at about 50 MiB/s on JPEG data
# because its leading lookbehind defeats the regex engine's fast scan; six in
# sequence gave 7 MiB/s. One cheap pass per family finds the few spans that
# could hold a match, and the precise patterns run only over those spans plus
# one byte either side, so their boundary checks still see the real neighbours.
# tests/carve/test_pii_detectors.py checks the result equals the naive scan.

#: Every numeric identifier is made of digits, spaces, hyphens and a leading
#: plus, and is at least ten characters long.
_NUMERIC_RUN = re.compile(rb"[+0-9][0-9 -]{8,}[0-9]")
#: PAN and IFSC both open with four capitals and are ten or eleven characters.
_UPPER_RUN = re.compile(rb"[A-Z]{4}[0-9A-Z]{6,7}")
#: The domain half of an email, matched from just after its ``@``.
_EMAIL_DOMAIN = re.compile(
    rb"(?:[A-Za-z0-9-]{1,63}\.){1,4}[A-Za-z]{2,24}(?![A-Za-z0-9-])"
)
_EMAIL_LOCAL = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._%+-"
)

# Verhoeff: dihedral group D5 multiplication, position permutation, inverse.
_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def verhoeff_valid(digits: str) -> bool:
    """True when ``digits`` (check digit last) passes the Verhoeff check."""
    check = 0
    for position, char in enumerate(reversed(digits)):
        check = _VERHOEFF_D[check][_VERHOEFF_P[position % 8][ord(char) - 48]]
    return check == 0


def luhn_valid(digits: str) -> bool:
    """True when ``digits`` (check digit last) passes the Luhn check."""
    total = 0
    for position, char in enumerate(reversed(digits)):
        value = ord(char) - 48
        if position % 2:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _only_digits(raw: bytes) -> str:
    return b"".join(_DIGITS.findall(raw)).decode("ascii")


_Detector = tuple[str, re.Pattern[bytes], Callable[[str], bool] | None]

#: (kind, precise pattern, checksum over the digits or None), by prefilter.
_NUMERIC: tuple[_Detector, ...] = (
    ("aadhaar", _AADHAAR, verhoeff_valid),
    ("indian_mobile", _MOBILE, None),
    ("payment_card", _CARD, luhn_valid),
)
_UPPER: tuple[_Detector, ...] = (("pan", _PAN, None), ("ifsc", _IFSC, None))

#: Every detector in its precise form: the reference the prefiltered scan is
#: tested against, and the definition of what each kind matches.
DETECTORS: tuple[_Detector, ...] = (*_NUMERIC, *_UPPER, ("email", _EMAIL, None))


def _count_spans(
    window: bytes,
    prefilter: re.Pattern[bytes],
    detectors: tuple[_Detector, ...],
    first: int,
    last: int,
    counts: dict[str, int],
) -> None:
    for span in prefilter.finditer(window):
        low = max(0, span.start() - 1)
        piece = window[low : span.end() + 1]
        for kind, pattern, checksum in detectors:
            for match in pattern.finditer(piece):
                start = low + match.start()
                if start < first or start >= last:
                    continue
                if checksum is not None and not checksum(_only_digits(match.group())):
                    continue
                counts[kind] = counts.get(kind, 0) + 1


def _count_emails(window: bytes, first: int, last: int, counts: dict[str, int]) -> None:
    # `consumed` mirrors a regex scan's non-overlap: bytes inside an address
    # already matched cannot begin another, so "a@b.in@c.in" is one address.
    consumed = 0
    at = window.find(b"@")
    while at != -1:
        start = at
        while start > 0 and window[start - 1] in _EMAIL_LOCAL and at - start < 65:
            start -= 1
        local = at - start
        domain = (
            _EMAIL_DOMAIN.match(window, at + 1)
            if 0 < local <= 64
            and start >= consumed
            and (start == 0 or window[start - 1] not in _EMAIL_LOCAL)
            else None
        )
        if domain is not None:
            consumed = domain.end()
            if first <= start < last:
                counts["email"] = counts.get("email", 0) + 1
        at = window.find(b"@", at + 1)


def _count_window(
    window: bytes | memoryview, first: int, last: int, counts: dict[str, int]
) -> None:
    """Add to ``counts`` every match in ``window`` starting in ``[first, last)``.

    The only place a matched value exists. It is inspected for its checksum and
    dropped; nothing about it leaves this function except one increment.
    """
    data = bytes(window)
    _count_spans(data, _NUMERIC_RUN, _NUMERIC, first, last, counts)
    _count_spans(data, _UPPER_RUN, _UPPER, first, last, counts)
    _count_emails(data, first, last, counts)


def count_reader(
    read: Callable[[int, int], bytes | memoryview], length: int
) -> dict[str, int]:
    """Count identifiers in ``length`` bytes reachable through ``read(offset, n)``.

    At most one window plus its context is held at once, whatever ``length``
    is. ``read`` may return fewer bytes than asked near the end.
    """
    counts: dict[str, int] = {}
    start = 0
    while start < length:
        left = max(0, start - CONTEXT_BYTES)
        end = min(length, start + WINDOW_BYTES)
        right = min(length, end + CONTEXT_BYTES)
        window = read(left, right - left)
        _count_window(window, start - left, end - left, counts)
        start = end
    return counts


def count_bytes(data: bytes | memoryview) -> dict[str, int]:
    """Count identifiers in ``data``, which is already in memory. No copy is made."""
    view = memoryview(data)
    return count_reader(lambda offset, size: view[offset : offset + size], len(view))


class _StreamCounter:
    """:func:`count_bytes` over text that arrives in pieces, holding one window.

    Extracted text has no random access: an OOXML part is inflated as it is
    read. Bytes are appended with :meth:`feed`; each time a full window plus its
    context on both sides is buffered, the window is counted and everything
    that no later window can need is discarded. Counts equal
    :func:`count_bytes` over the concatenation, however the pieces are cut.
    """

    def __init__(self, counts: dict[str, int]) -> None:
        self._counts = counts
        self._buffer = bytearray()
        #: Index in the buffer of the first byte no window has counted yet.
        self._start = 0

    def feed(self, piece: bytes) -> None:
        self._buffer += piece
        while len(self._buffer) >= self._start + WINDOW_BYTES + CONTEXT_BYTES:
            end = self._start + WINDOW_BYTES
            _count_window(
                memoryview(self._buffer)[: end + CONTEXT_BYTES],
                self._start,
                end,
                self._counts,
            )
            del self._buffer[: end - CONTEXT_BYTES]
            self._start = CONTEXT_BYTES

    def finish(self) -> None:
        if len(self._buffer) > self._start:
            _count_window(
                memoryview(self._buffer),
                self._start,
                len(self._buffer),
                self._counts,
            )
        self._buffer.clear()
        self._start = 0


# --------------------------------------------------------------------------
# Text extraction
# --------------------------------------------------------------------------

#: XML elements that end a unit of text. Replaced with a newline so two
#: paragraphs, cells or rows never fuse into one digit run; every other tag is
#: removed outright, because Word splits one word across runs freely.
_XML_BREAK = re.compile(
    rb"</(?:w:p|a:p|w:tc|w:tr|c|row|si|t|v|text:p|p)>|<(?:w:tab|w:br|a:br)\s*/>"
)
_XML_TAG = re.compile(rb"<[^>]{0,4096}>")
_XML_ENTITIES = (
    (b"&lt;", b"<"),
    (b"&gt;", b">"),
    (b"&quot;", b'"'),
    (b"&apos;", b"'"),
    (b"&amp;", b"&"),
)


def _xml_text(raw: bytes) -> bytes:
    text = _XML_TAG.sub(b"", _XML_BREAK.sub(b"\n", raw))
    for entity, char in _XML_ENTITIES:
        text = text.replace(entity, char)
    return text


#: Inflated XML read per step. The part is never held whole. 64 KiB rather than
#: the 1 MiB scan window because stripping tags from dense WordprocessingML is
#: the costly step: ``re.sub`` holds every piece between tags at once, and on a
#: 1 MiB chunk that measured 13.5 MiB of Python allocation.
_XML_CHUNK_BYTES = 64 * KIB

#: Longest entity in :data:`_XML_ENTITIES`, so a split one is carried whole.
_ENTITY_BYTES = 6


def _xml_safe_cut(data: bytes) -> int:
    """Where ``data`` can be cut without splitting a tag or an entity."""
    cut = len(data)
    tag = data.rfind(b"<")
    if tag != -1 and data.find(b">", tag) == -1 and len(data) - tag <= 4096:
        cut = tag
    amp = data.rfind(b"&", max(0, cut - _ENTITY_BYTES))
    if amp != -1 and data.find(b";", amp, cut) == -1:
        cut = amp
    return cut


def _count_ooxml(data: bytes, counts: dict[str, int]) -> int | None:
    """Count identifiers in the text of each XML part; the number of parts read.

    None when ``data`` is not a readable ZIP. Each part is inflated in
    :data:`_XML_CHUNK_BYTES` steps, stripped of tags a step at a time, and fed
    to its own :class:`_StreamCounter`, so two parts never fuse and peak memory
    is a few chunks whatever the part's size. At most
    :data:`MAX_EXTRACT_BYTES` of inflated XML is read across the package.
    """
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError, ValueError, EOFError):
        return None

    budget = MAX_EXTRACT_BYTES
    parts = 0
    with archive:
        for info in archive.infolist():
            if budget <= 0:
                break
            if not info.filename.endswith((".xml", ".rels")) or info.flag_bits & 0x1:
                continue
            stream = _StreamCounter(counts)
            carry = b""
            try:
                with archive.open(info) as member:
                    while budget > 0:
                        chunk = member.read(min(_XML_CHUNK_BYTES, budget))
                        if not chunk:
                            break
                        budget -= len(chunk)
                        pending = carry + chunk
                        cut = _xml_safe_cut(pending)
                        stream.feed(_xml_text(pending[:cut]))
                        carry = pending[cut:]
            except (zipfile.BadZipFile, OSError, ValueError, EOFError, RuntimeError):
                # A damaged member still contributes what inflated before the
                # damage; the counts say what was seen, not what was present.
                pass
            stream.feed(_xml_text(carry))
            stream.finish()
            parts += 1
    return parts


#: Inflated PDF stream bytes produced per step. A stream is never held whole.
_PDF_CHUNK_BYTES = 64 * KIB

#: Largest inflated size allowed for an object stream or cross-reference
#: stream. qpdf inflates these whole while it opens the file, before any budget
#: here can apply, so they are measured first and the file is not opened if one
#: is larger. Real object streams are a few MiB at most.
MAX_PDF_STRUCTURE_BYTES = 16 * MIB

_PDF_STRUCTURAL = re.compile(rb"/Type\s*/(?:ObjStm|XRef)(?![A-Za-z0-9])")
_PDF_FILTER_NAME = re.compile(rb"/([A-Za-z0-9]+Decode|AHx|A85|LZW|Fl|RL|CCF|DCT)\b")


def _inflate_pieces(raw: bytes, limit: int) -> Iterable[bytes]:
    """Inflate ``raw`` in :data:`_PDF_CHUNK_BYTES` steps, stopping at ``limit``.

    The whole inflated stream never exists at once, which is the point: a
    compressed stream of a few hundred KiB can inflate to gigabytes. A stream
    damaged part way yields what inflated before the damage.
    """
    inflater = zlib.decompressobj()
    pending = raw
    produced = 0
    while produced < limit:
        step = min(_PDF_CHUNK_BYTES, limit - produced)
        try:
            piece = inflater.decompress(pending, step)
        except zlib.error:
            return
        pending = inflater.unconsumed_tail
        if not piece:
            return
        produced += len(piece)
        yield piece


def _inflates_beyond(raw: bytes, limit: int) -> bool:
    """True when ``raw`` inflates to more than ``limit`` bytes. Holds one step."""
    produced = 0
    for piece in _inflate_pieces(raw, limit + 1):
        produced += len(piece)
    return produced > limit


def _structure_is_bounded(data: bytes) -> bool:
    """Whether every object and cross-reference stream inflates within bounds.

    Found in the raw bytes, not through pikepdf, because opening the file is
    what inflates them. A structural stream behind a filter other than Flate
    cannot be measured this way, so it is not trusted either.
    """
    for match in _PDF_STRUCTURAL.finditer(data):
        keyword = data.find(b"stream", match.end(), match.end() + 64 * KIB)
        if keyword == -1:
            continue
        dictionary = data[max(0, data.rfind(b"obj", 0, match.start())) : keyword]
        start = keyword + len(b"stream")
        if data[start : start + 2] == b"\r\n":
            start += 2
        elif data[start : start + 1] in (b"\n", b"\r"):
            start += 1
        end = data.find(b"endstream", start)
        raw = data[start : end if end != -1 else len(data)]
        filters = {name.group(1) for name in _PDF_FILTER_NAME.finditer(dictionary)}
        if not filters:
            continue
        if filters - {b"FlateDecode", b"Fl"}:
            return False
        if _inflates_beyond(raw, MAX_PDF_STRUCTURE_BYTES):
            return False
    return True


def _count_pdf(data: bytes, counts: dict[str, int]) -> tuple[int, int, bool] | str:
    """Count identifiers in a PDF's content streams, never holding one whole.

    Returns ``(streams read, streams not decoded, budget reached)``, or the
    reason nothing was read: the file cannot be opened, or its structure would
    inflate beyond :data:`MAX_PDF_STRUCTURE_BYTES` while it was being opened.

    Each stream's **raw** bytes are read; its bytes are therefore bounded by the
    object's own size. Unfiltered streams are counted as they are. A
    ``FlateDecode`` stream is inflated :data:`_PDF_CHUNK_BYTES` at a time into a
    streaming counter, so a stream that inflates to gigabytes costs one step of
    memory and stops at :data:`MAX_EXTRACT_BYTES`. Any other filter, a predictor,
    or an encrypted file is not decoded, because decoding it would mean handing
    the whole stream to qpdf; such streams are counted in the second value.
    """
    import pikepdf

    if not _structure_is_bounded(data):
        return (
            "Not scanned: an object or cross-reference stream in the .pdf would "
            f"inflate beyond {MAX_PDF_STRUCTURE_BYTES // MIB} MiB, or uses a filter "
            "whose inflated size cannot be measured, and opening the file would "
            "inflate it whole."
        )
    try:
        pdf = pikepdf.open(io.BytesIO(data))
    except (pikepdf.PdfError, pikepdf.PasswordError, OSError, ValueError, RuntimeError):
        return "Not scanned: the .pdf container could not be opened."

    budget = MAX_EXTRACT_BYTES
    read = skipped = 0
    with pdf:
        encrypted = pdf.is_encrypted
        for obj in pdf.objects:
            if budget <= 0:
                break
            if not isinstance(obj, pikepdf.Stream):
                continue
            # Image and font programs are binary, and a JPEG in a PDF is
            # still JPEG entropy data: the rates that keep images out of
            # scope apply to it here too.
            if obj.get("/Subtype") == "/Image" or any(
                key in obj for key in ("/Length1", "/Length2", "/Length3")
            ):
                continue
            filters = obj.get("/Filter")
            names = (
                [str(item) for item in filters]
                if isinstance(filters, pikepdf.Array)
                else [] if filters is None else [str(filters)]
            )
            parms = obj.get("/DecodeParms")
            if encrypted or names not in ([], ["/FlateDecode"]) or parms is not None:
                skipped += 1
                continue
            try:
                raw = obj.read_raw_bytes()
            except (pikepdf.PdfError, OSError, ValueError, RuntimeError):
                continue
            pieces = (
                _inflate_pieces(raw, budget) if names else iter((raw[:budget],))
            )
            stream = _StreamCounter(counts)
            for piece in pieces:
                budget -= len(piece)
                stream.feed(piece)
            stream.finish()
            read += 1
    return read, skipped, budget <= 0


@dataclass(frozen=True)
class PiiScan:
    """What one object was scanned for, how, and how many of each were seen.

    ``inspected`` False means nothing was looked at and ``counts`` says nothing:
    an empty ``counts`` on an inspected object is "none seen by these
    detectors", which is still not "none present".
    """

    inspected: bool
    #: How the bytes were read, or why they were not. A sentence for the report.
    basis: str
    counts: dict[str, int]


_OOXML_EXTS = frozenset({"docx", "docm", "xlsx", "xlsm", "pptx", "pptm"})


def scan_content(
    data: bytes | memoryview | None,
    *,
    ext: str,
    category: str,
    length: int,
    read: Callable[[int, int], bytes | memoryview] | None = None,
) -> PiiScan:
    """Scan one recovered object according to its classified type.

    Args:
        data: The object's bytes when they are already in memory, else None.
        ext: The classified extension.
        category: The classified category; only :data:`SCANNED_CATEGORIES`
            are scanned.
        length: The object's length in bytes.
        read: Random access to the object's bytes, used when ``data`` is None
            for types scanned as raw bytes. Containers need ``data``.
    """
    lowered = ext.lower()
    if category not in SCANNED_CATEGORIES:
        return PiiScan(
            inspected=False,
            basis=(
                f"Not scanned: {category} content. The detectors' false-positive "
                "rate on image, media, archive and executable bytes is too high "
                "for a count to mean anything (docs/limitations.md)."
            ),
            counts={},
        )

    counts: dict[str, int] = {}
    if lowered in _OOXML_EXTS or lowered == "pdf":
        if data is None:
            return PiiScan(
                inspected=False,
                basis=(
                    f"Not scanned: the .{lowered} was larger than the in-memory budget."
                ),
                counts={},
            )
        blob = bytes(data)
        seen: int | None
        if lowered in _OOXML_EXTS:
            seen = _count_ooxml(blob, counts)
            basis = f"Text of {seen} XML parts, tags removed"
        else:
            outcome = _count_pdf(blob, counts)
            if isinstance(outcome, str):
                return PiiScan(inspected=False, basis=outcome, counts={})
            seen, skipped, exhausted = outcome
            basis = f"{seen} decoded PDF streams"
            if skipped:
                basis += (
                    f"; {skipped} not decoded (a filter other than FlateDecode,"
                    " a predictor, or encryption)"
                )
            if exhausted:
                basis += (
                    f"; stopped at the {MAX_EXTRACT_BYTES // MIB} MiB extraction"
                    " budget"
                )
        if seen is None:
            return PiiScan(
                inspected=False,
                basis=f"Not scanned: the .{lowered} container could not be opened.",
                counts={},
            )
    elif data is not None:
        counts = count_bytes(data)
        basis = "Raw bytes, as ASCII/UTF-8"
    elif read is not None:
        counts = count_reader(read, length)
        basis = "Raw bytes, as ASCII/UTF-8, read in windows"
    else:
        return PiiScan(
            inspected=False, basis="Not scanned: no bytes were available.", counts={}
        )

    # Counts only. Never a value, a mask of one, or where one was.
    logger.debug(
        "pii.scanned", ext=lowered, kinds=sorted(counts), total=sum(counts.values())
    )
    return PiiScan(inspected=True, basis=basis, counts=counts)
