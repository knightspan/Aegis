"""Validate a carved candidate by decoding it.

A header match says a file *might* start here. Only a full decode says the
bytes are a file. Every validator in this module parses the candidate all the
way through - ``Image.open`` reads a JPEG header and cheerfully accepts a file
whose second half is missing, so every image validator follows it with
``.load()`` to force the decode that catches the truncation.

Four outcomes, and the fourth is the one that keeps the report honest:

``valid``
    The decoder walked the whole object and found it consistent.
``truncated``
    The decoder parsed a prefix and ran out of bytes. Real, and common: a
    carved object bounded by the next header rather than by its own footer.
``corrupt``
    The decoder rejected the bytes.
``decoder_unavailable``
    No verdict. The optional dependency is not installed, the object needs a
    password, or the decode exceeded its deadline. A missing decoder is not
    evidence about the file, and reporting it as ``corrupt`` would be a claim
    this module cannot support.

**Every validator is bounded.** A crafted PNG header declaring 40000x40000
pixels asks Pillow for 4.8 GB before it has read a single row of image data, so
:data:`MAX_IMAGE_PIXELS` caps the decode and the resulting
``DecompressionBombError`` is reported as ``corrupt`` rather than allowed to
take the process out. Candidates larger than :data:`MAX_VALIDATE_BYTES` are not
decoded at all, because the guard has to hold before the allocation, not after.

Validators never write to disk and never execute embedded content: no macro is
run, no external entity is fetched, no ``ffprobe`` filter graph is built.
"""

from __future__ import annotations

import io
import json
import shutil
import sqlite3
import subprocess
import tarfile
import time
import wave
import xml.etree.ElementTree as ElementTree
import zipfile
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import PIL
import structlog
from PIL import Image, ImageFile, UnidentifiedImageError
from PIL.MpoImagePlugin import MpoImageFile

from core.carve.evidence import BytesEvidence, EvidenceHandle
from core.carve.fragmentation import accounts_for_scan
from core.models import CarveCandidate, Validation
from core.platform.host import windows_creationflags

__all__ = [
    "ValidationReport",
    "Validator",
    "VALIDATORS",
    "DEADLINE_S",
    "MAX_VALIDATE_BYTES",
    "MAX_IMAGE_PIXELS",
    "OOXML_PARTS",
    "validate_bytes",
    "validate_candidate",
    "validate_wav",
    "validate_gzip",
    "validate_tar",
]

logger = structlog.get_logger(__name__)

MIB = 1024 * 1024

#: Wall-clock budget for one candidate's decode. Generous for a real file of a
#: sane size, short enough that a pathological one cannot stall a run.
DEADLINE_S = 10.0

#: Largest candidate that gets decoded. The decoders here work on an in-memory
#: buffer - they never spool to disk - so this is a memory ceiling, and a
#: candidate above it is reported unjudged rather than silently skipped.
MAX_VALIDATE_BYTES = 64 * MIB

#: Pillow pixel ceiling: 8000x8000. Pillow raises ``DecompressionBombError``
#: above twice this, which is the behaviour the guard depends on.
MAX_IMAGE_PIXELS = 64_000_000

#: The part every OOXML package of a given type must carry. Presence of
#: ``[Content_Types].xml`` alone only proves the archive is *some* OPC package.
OOXML_PARTS: dict[str, str] = {
    "word/document.xml": "WordprocessingML document",
    "xl/workbook.xml": "SpreadsheetML workbook",
    "ppt/presentation.xml": "PresentationML presentation",
}

#: Cap on a single XML part read out of an OOXML package. A 20 KB part that
#: inflates to gigabytes is the oldest trick against a naive parser.
MAX_XML_PART_BYTES = 16 * MIB

#: Cap on the number of archive members walked. An archive claiming millions of
#: entries costs time long before it costs correctness.
MAX_ARCHIVE_MEMBERS = 100_000

#: Sample frames read from a WAV per call, and compressed bytes handed to the
#: gzip decompressor per call. Both bound the transient buffer, not the file.
WAV_FRAMES_PER_READ = 65_536
GZIP_BLOCK_BYTES = 64 * 1024

#: One tar member header, and the size of the zero block the format ends with.
TAR_BLOCK_BYTES = 512


@dataclass(frozen=True)
class ValidationReport:
    """What one decoder concluded about one candidate."""

    verdict: Validation
    #: Plain-language detail, rendered verbatim in the report.
    detail: str
    #: Which decoder produced the verdict, or which one was missing.
    decoder: str
    #: Images an MPF index declares at or past the end of the candidate, as
    #: (index, offset from the candidate's first byte). Outside the candidate,
    #: not failed to decode: see :func:`validate_image`.
    absent_frames: tuple[tuple[int, int], ...] = ()


Validator = Callable[[bytes, "_Deadline"], ValidationReport]


class _Deadline:
    """Wall-clock bound shared by every validator.

    Validators check it between phases rather than being killed mid-decode:
    interrupting a C decoder from Python is not something this process can do
    safely, so the bound is cooperative and every loop is finite on its own.
    """

    def __init__(self, seconds: float = DEADLINE_S) -> None:
        self._started = time.monotonic()
        self._seconds = seconds

    @property
    def expired(self) -> bool:
        return time.monotonic() - self._started >= self._seconds

    @property
    def remaining(self) -> float:
        return max(0.0, self._seconds - (time.monotonic() - self._started))

    def note(self) -> str:
        return f"decode exceeded the {self._seconds:g}s validation deadline"


def _unavailable(decoder: str, why: str) -> ValidationReport:
    return ValidationReport(verdict="decoder_unavailable", detail=why, decoder=decoder)


# --------------------------------------------------------------------------
# Images: Pillow
# --------------------------------------------------------------------------

#: Pillow message fragments that mean "ran out of bytes" rather than "these
#: bytes are wrong". The distinction is the whole point of the TRUNCATED
#: verdict, and Pillow only expresses it in the message text.
_TRUNCATION_MARKERS = (
    "truncated",
    "unexpected end",
    "broken data stream",
    "not enough data",
    "incomplete",
)


def _pillow_verdict(error: Exception, decoder: str) -> ValidationReport:
    text = str(error)
    lowered = text.lower()
    if any(marker in lowered for marker in _TRUNCATION_MARKERS):
        return ValidationReport(
            verdict="truncated", detail=f"decode stopped early: {text}", decoder=decoder
        )
    return ValidationReport(
        verdict="corrupt", detail=f"decode failed: {text}", decoder=decoder
    )


#: Pillow formats whose first image exact scan accounting can judge. ``MPO`` is
#: a JPEG whose APP2 MPF index lists further images; its first image runs from
#: SOI to EOI like any other JPEG.
_EXACT_ACCOUNTING_FORMATS = frozenset({"JPEG", "MPO"})


def _mpf_index_base(data: bytes) -> int | None:
    """Where MPF ``DataOffset`` values are counted from: the byte after ``MPF\\0``.

    Walks the first image's segments up to its scan, bounded by ``data``.
    """
    cursor = 2
    limit = len(data)
    while cursor + 4 <= limit and data[cursor] == 0xFF:
        kind = data[cursor + 1]
        if kind == 0xFF:
            cursor += 1
            continue
        if kind in (0x01, 0xD8) or 0xD0 <= kind <= 0xD7:
            cursor += 2
            continue
        if kind in (0xD9, 0xDA):
            return None
        length = int.from_bytes(data[cursor + 2 : cursor + 4], "big")
        if length < 2:
            return None
        if kind == 0xE2 and data[cursor + 4 : cursor + 8] == b"MPF\x00":
            return cursor + 8
        cursor += 2 + length
    return None


def _frames_held(
    image: Image.Image, data: bytes, frames: int
) -> tuple[list[int], list[tuple[int, int]]]:
    """Which declared frames lie inside ``data``, and where the others were declared.

    A carved JPEG object ends at the EOI its scan reaches. A phone photo's MPF
    index declares a second image - its HDR gain map - stored after that EOI,
    so the object holds frame 0 and an index pointing past its own end. A frame
    declared at or beyond the end of ``data`` is outside this candidate: the
    object says it had one, and where. A frame that starts inside ``data`` is
    held, and must decode like any other.

    When the index cannot be located, every frame counts as held - what the
    validator did before it looked - so a doubt here can only fail a decode,
    never excuse one.
    """
    every = list(range(frames))
    if frames <= 1 or not isinstance(image, MpoImageFile):
        return every, []
    base = _mpf_index_base(data)
    entries = image.mpinfo.get(0xB002) if image.mpinfo else None
    if base is None or not entries or len(entries) != frames:
        return every, []
    held = [0]
    absent: list[tuple[int, int]] = []
    for index in range(1, frames):
        declared = base + int(entries[index]["DataOffset"])
        if declared >= len(data):
            absent.append((index, declared))
        else:
            held.append(index)
    return held, absent


def _decoded_detail(
    fmt: str,
    size: tuple[int, int],
    decoded: int,
    frames: int,
    absent: list[tuple[int, int]],
    length: int,
) -> str:
    dimensions = f"{fmt} {size[0]}x{size[1]}"
    if not absent:
        if frames > 1:
            return f"{dimensions}, {decoded} frame(s) fully decoded"
        return f"{dimensions} fully decoded"
    missing = "; ".join(
        f"image {index + 1}, declared at byte {declared}" for index, declared in absent
    )
    return (
        f"{dimensions}: this object holds {decoded} of the {frames} images its MPF "
        f"index declares, fully decoded. Not in this object ({length} bytes): "
        f"{missing}, at or past its end. The index describes a file that "
        "continues after this image's EOI - an HDR gain map or a second view - "
        "and that image, where it survives on the medium, is carved as an object "
        "of its own."
    )


def validate_image(data: bytes, deadline: _Deadline) -> ValidationReport:
    """Decode with Pillow, forcing the full pass.

    ``Image.open`` reads only enough to identify the format, so on its own it
    reports a half-written JPEG as openable. ``.load()`` is what actually
    decodes the pixels, and ``LOAD_TRUNCATED_IMAGES`` stays False so that a
    short file raises instead of being silently padded with grey.
    """
    decoder = f"Pillow {PIL.__version__}"
    if ImageFile.LOAD_TRUNCATED_IMAGES:  # pragma: no cover - defensive
        raise RuntimeError(
            "ImageFile.LOAD_TRUNCATED_IMAGES is True; truncated images would "
            "validate as valid"
        )
    previous = Image.MAX_IMAGE_PIXELS
    Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
    try:
        with Image.open(io.BytesIO(data)) as image:
            fmt = image.format or "unknown"
            size = image.size
            image.load()
            frames = getattr(image, "n_frames", 1)
            # Only the frames this candidate holds are decoded. One its MPF
            # index declares past its end is recorded, not sought: seeking it
            # raises "No data found for frame", which used to mark every
            # carved iPhone photo corrupt.
            held, absent = _frames_held(image, data, frames)
            decoded = 1
            for index in held[1:]:
                if deadline.expired:
                    return ValidationReport(
                        verdict="valid",
                        detail=(
                            f"{fmt} {size[0]}x{size[1]}, {decoded} of {len(held)} "
                            f"frames decoded before {deadline.note()}"
                        ),
                        decoder=decoder,
                        absent_frames=tuple(absent),
                    )
                image.seek(index)
                image.load()
                decoded += 1
        # An MPO's first image is counted exactly as a JPEG is. Undelete has no
        # other check: without this, one reused cluster in a deleted two-image
        # phone photo came back valid at HIGH, where the same damage to a plain
        # JPEG came back corrupt. Further frames get the decoder's word only.
        if fmt in _EXACT_ACCOUNTING_FORMATS:
            # libjpeg reports a scan with bytes missing, extra or out of place as
            # a warning and returns an image regardless, so a JPEG head, a
            # cluster of zeros or directory entries, and the real tail decode
            # "fully". Counting the scan against the frame header does not.
            exact = accounts_for_scan(
                data, deadline=time.monotonic() + deadline.remaining
            )
            if exact is False:
                scan = "the scan of its first image" if fmt == "MPO" else "its scan"
                return ValidationReport(
                    verdict="corrupt",
                    detail=(
                        f"{fmt} {size[0]}x{size[1]} decoded, but {scan} does not "
                        "account for the frame: entropy-coded bytes are missing, "
                        "extra or out of place, which the decoder reports only as "
                        "a warning"
                    ),
                    decoder=f"{decoder} + exact scan accounting",
                )
        if fmt == "TIFF":
            # Pillow reads a TIFF's IFD chain and ignores everything after it,
            # so a candidate holding the image plus sixty megabytes of the rest
            # of the medium decodes exactly as cleanly as the image alone. The
            # IFD chain says how far the object reaches, and calling the whole
            # span valid would claim those other bytes were part of it. Same
            # reasoning as the exact scan accounting for JPEG above.
            from core.carve.structure import parse_tiff

            with BytesEvidence(data) as probe:
                measured = parse_tiff(probe, 0, max_size=len(data))
            if (
                measured is not None
                and measured.validation == "valid"
                and measured.length < len(data)
            ):
                return ValidationReport(
                    verdict="corrupt",
                    detail=(
                        f"TIFF {size[0]}x{size[1]} decoded, but its IFD chain "
                        f"accounts for {measured.length} of this candidate's "
                        f"{len(data)} bytes: the rest is not part of the image"
                    ),
                    decoder=f"{decoder} + IFD length accounting",
                )
        return ValidationReport(
            verdict="valid",
            detail=_decoded_detail(fmt, size, decoded, frames, absent, len(data)),
            decoder=decoder,
            absent_frames=tuple(absent),
        )
    except Image.DecompressionBombError as error:
        # A declared pixel count this large is a property of the header, not of
        # any image that was ever written. Reject it as content, not as a crash.
        return ValidationReport(
            verdict="corrupt",
            detail=(
                f"declared pixel count exceeds the {MAX_IMAGE_PIXELS} pixel "
                f"decode limit: {error}"
            ),
            decoder=decoder,
        )
    except UnidentifiedImageError as error:
        return ValidationReport(
            verdict="corrupt",
            detail=f"not a decodable image: {error}",
            decoder=decoder,
        )
    except (OSError, ValueError, SyntaxError, EOFError) as error:
        return _pillow_verdict(error, decoder)
    finally:
        Image.MAX_IMAGE_PIXELS = previous


# --------------------------------------------------------------------------
# PDF: pikepdf
# --------------------------------------------------------------------------


def validate_pdf(data: bytes, deadline: _Deadline) -> ValidationReport:
    """Open with pikepdf, then walk every page so the object graph is exercised."""
    try:
        import pikepdf
    except ImportError:  # pragma: no cover - pikepdf is a hard dependency
        return _unavailable("pikepdf", "pikepdf is not installed")

    decoder = f"pikepdf {pikepdf.__version__}"
    try:
        with pikepdf.open(io.BytesIO(data)) as pdf:
            pages = 0
            for _ in pdf.pages:
                pages += 1
                if deadline.expired:
                    return ValidationReport(
                        verdict="valid",
                        detail=(
                            f"{pages} page(s) walked before {deadline.note()}; "
                            "remaining pages unchecked"
                        ),
                        decoder=decoder,
                    )
            objects = len(pdf.objects)
        return ValidationReport(
            verdict="valid",
            detail=f"{pages} page(s), {objects} indirect object(s)",
            decoder=decoder,
        )
    except pikepdf.PasswordError:
        # The trailer parsed - that is how the encryption dictionary was found -
        # but nothing behind it can be read. Neither valid nor corrupt.
        return _unavailable(
            decoder, "encrypted: a password is required to decode the contents"
        )
    except pikepdf.PdfError as error:
        text = str(error).lower()
        if "eof" in text or "expected" in text and "trailer" in text:
            return ValidationReport(
                verdict="truncated",
                detail=f"PDF ends before its structure does: {error}",
                decoder=decoder,
            )
        return ValidationReport(
            verdict="corrupt", detail=f"PDF parse failed: {error}", decoder=decoder
        )
    except (OSError, ValueError, RuntimeError) as error:
        return ValidationReport(
            verdict="corrupt", detail=f"PDF parse failed: {error}", decoder=decoder
        )


# --------------------------------------------------------------------------
# ZIP and OOXML: zipfile
# --------------------------------------------------------------------------


def _encrypted_members(archive: zipfile.ZipFile) -> list[str]:
    """Names of members with the encryption bit set in their local header.

    Read from the flag bits rather than discovered by attempting extraction:
    ``testzip`` on an encrypted member raises, and on some archives a decrypt
    attempt is exactly the expensive thing this must not do.
    """
    return [item.filename for item in archive.infolist() if item.flag_bits & 0x1]


def _read_part(archive: zipfile.ZipFile, name: str) -> bytes:
    with archive.open(name) as handle:
        return handle.read(MAX_XML_PART_BYTES + 1)


def validate_zip(data: bytes, deadline: _Deadline) -> ValidationReport:
    """CRC-check the archive, and check the required parts when it is OOXML.

    OOXML is a ZIP with rules: ``[Content_Types].xml`` plus one part that says
    which kind of document it is. Both are parsed as XML, because a package
    whose ``document.xml`` is a truncated blob is not a document even when
    every CRC in the archive agrees.
    """
    decoder = "zipfile"
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = archive.namelist()[:MAX_ARCHIVE_MEMBERS]
            encrypted = _encrypted_members(archive)
            if encrypted and len(encrypted) == len(archive.infolist()):
                return _unavailable(
                    decoder,
                    f"every one of the {len(encrypted)} member(s) is encrypted; "
                    "CRCs cannot be verified without the password",
                )

            # testzip() decompresses each member and compares CRCs. Encrypted
            # members are excluded by name: passing them would raise, and
            # attempting to decrypt them is work this must never start.
            clear = [item for item in archive.infolist() if not item.flag_bits & 0x1]
            for item in clear[:MAX_ARCHIVE_MEMBERS]:
                if deadline.expired:
                    return ValidationReport(
                        verdict="valid",
                        detail=(
                            f"{len(clear)} member(s); CRC check stopped after "
                            f"{deadline.note()}"
                        ),
                        decoder=decoder,
                    )
                try:
                    with archive.open(item) as member:
                        while member.read(MIB):
                            pass
                except zipfile.BadZipFile as error:
                    return ValidationReport(
                        verdict="corrupt",
                        detail=f"CRC mismatch in {item.filename}: {error}",
                        decoder=decoder,
                    )

            suffix = (
                f"; {len(encrypted)} encrypted member(s) not decoded"
                if encrypted
                else ""
            )
            if "[Content_Types].xml" not in names:
                return ValidationReport(
                    verdict="valid",
                    detail=f"{len(names)} member(s), every CRC verified{suffix}",
                    decoder=decoder,
                )
            return _validate_ooxml(archive, names, suffix, decoder)
    except zipfile.BadZipFile as error:
        text = str(error).lower()
        if "truncated" in text or "end of central directory" in text:
            return ValidationReport(
                verdict="truncated",
                detail=f"archive ends before its central directory: {error}",
                decoder=decoder,
            )
        return ValidationReport(
            verdict="corrupt",
            detail=f"not a readable archive: {error}",
            decoder=decoder,
        )
    except (OSError, ValueError, RuntimeError, EOFError) as error:
        return ValidationReport(
            verdict="corrupt", detail=f"archive read failed: {error}", decoder=decoder
        )


def _validate_ooxml(
    archive: zipfile.ZipFile, names: list[str], suffix: str, decoder: str
) -> ValidationReport:
    """Assert the content-types part and the type's own part exist and parse."""
    try:
        ElementTree.fromstring(_read_part(archive, "[Content_Types].xml"))
    except ElementTree.ParseError as error:
        return ValidationReport(
            verdict="corrupt",
            detail=f"[Content_Types].xml is not well-formed XML: {error}",
            decoder=decoder,
        )

    present = [part for part in OOXML_PARTS if part in names]
    if not present:
        return ValidationReport(
            verdict="valid",
            detail=(
                "OPC package with [Content_Types].xml but no recognised "
                f"document part; {len(names)} member(s), every CRC verified{suffix}"
            ),
            decoder=decoder,
        )
    for part in present:
        try:
            ElementTree.fromstring(_read_part(archive, part))
        except ElementTree.ParseError as error:
            return ValidationReport(
                verdict="corrupt",
                detail=f"{part} is not well-formed XML: {error}",
                decoder=decoder,
            )
    kinds = ", ".join(OOXML_PARTS[part] for part in present)
    return ValidationReport(
        verdict="valid",
        detail=f"OOXML {kinds}; {len(names)} member(s), every CRC verified{suffix}",
        decoder=decoder,
    )


# --------------------------------------------------------------------------
# SQLite
# --------------------------------------------------------------------------

_SQLITE_HEADER = b"SQLite format 3\x00"


def _sqlite_declared_size(data: bytes) -> int | None:
    """Bytes the header says the database occupies, or None if unreadable."""
    if len(data) < 32 or not data.startswith(_SQLITE_HEADER):
        return None
    raw_page_size = int.from_bytes(data[16:18], "big")
    # 1 is the on-disk encoding of a 65536-byte page: the field is 16 bits and
    # the largest legal page does not fit in it.
    page_size = 65536 if raw_page_size == 1 else raw_page_size
    page_count = int.from_bytes(data[28:32], "big")
    if page_size < 512 or page_count == 0:
        return None
    return page_size * page_count


def validate_sqlite(data: bytes, deadline: _Deadline) -> ValidationReport:
    """Deserialize into a private in-memory database and run integrity_check.

    ``sqlite3`` needs a database, not a buffer, and this module must not write
    one to disk. ``Connection.deserialize`` loads the bytes into an in-memory
    database instead; the connection is opened with no file, so
    ``integrity_check`` reads only the candidate's own pages.
    """
    decoder = f"sqlite3 {sqlite3.sqlite_version}"
    declared = _sqlite_declared_size(data)
    if declared is not None and len(data) < declared:
        return ValidationReport(
            verdict="truncated",
            detail=(
                f"header declares {declared} bytes, candidate holds {len(data)}"
            ),
            decoder=decoder,
        )

    connection = sqlite3.connect(":memory:")
    try:
        connection.deserialize(data)
        rows = connection.execute("PRAGMA integrity_check").fetchall()
        results = [str(row[0]) for row in rows]
        tables = connection.execute(
            "SELECT count(*) FROM sqlite_schema WHERE type = 'table'"
        ).fetchone()
    except sqlite3.NotSupportedError as error:  # pragma: no cover - build-specific
        return _unavailable(
            decoder, f"this sqlite3 build cannot deserialize a buffer: {error}"
        )
    except sqlite3.DatabaseError as error:
        text = str(error).lower()
        verdict: Validation = "truncated" if "short" in text else "corrupt"
        return ValidationReport(
            verdict=verdict,
            detail=f"integrity check could not run: {error}",
            decoder=decoder,
        )
    finally:
        connection.close()

    if results == ["ok"]:
        count = int(tables[0]) if tables else 0
        note = f" (deadline reached: {deadline.note()})" if deadline.expired else ""
        return ValidationReport(
            verdict="valid",
            detail=f"integrity_check ok, {count} table(s){note}",
            decoder=decoder,
        )
    return ValidationReport(
        verdict="corrupt",
        detail="integrity_check: " + "; ".join(results[:5]),
        decoder=decoder,
    )


# --------------------------------------------------------------------------
# MP4
# --------------------------------------------------------------------------


def _ffprobe_path() -> str | None:
    return shutil.which("ffprobe")


def validate_mp4(data: bytes, deadline: _Deadline) -> ValidationReport:
    """Walk the box tree, and hand the bytes to ffprobe only if it is installed.

    A complete box tree is not proof of a playable file, so a clean structural
    walk with no ffprobe on PATH reports ``decoder_unavailable``. A *failed*
    walk is a different matter: a box that runs past the end of the candidate
    is a finding the structure alone supports, and it is reported as such.
    """
    from core.carve.structure import parse_mp4

    with BytesEvidence(data) as handle:
        parsed = parse_mp4(handle, 0, max_size=len(data))

    if parsed is None:
        return ValidationReport(
            verdict="corrupt",
            detail="no readable MP4 box structure at offset 0",
            decoder="structure walk",
        )
    if parsed.validation != "valid":
        return ValidationReport(
            verdict=parsed.validation,
            detail=f"box walk: {parsed.detail}",
            decoder="structure walk",
        )

    ffprobe = _ffprobe_path()
    if ffprobe is None:
        return _unavailable(
            "structure walk",
            f"box structure is complete ({parsed.detail}) but ffprobe is not on "
            "PATH, so the streams were not decoded",
        )
    return _ffprobe(ffprobe, data, parsed.detail, deadline)


def _ffprobe(
    ffprobe: str, data: bytes, structure_detail: str, deadline: _Deadline
) -> ValidationReport:
    """Run ffprobe over stdin. Demux only: no filters, no decoding of content."""
    decoder = "ffprobe"
    command = [
        ffprobe,
        "-v",
        "error",
        "-print_format",
        "json",
        "-show_format",
        "-show_streams",
        "-",
    ]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            command,
            input=data,
            capture_output=True,
            timeout=max(1.0, deadline.remaining),
            check=False,
            creationflags=windows_creationflags(),
        )
    except subprocess.TimeoutExpired:
        return _unavailable(decoder, deadline.note())
    except OSError as error:  # pragma: no cover - ffprobe vanished mid-run
        return _unavailable(decoder, f"ffprobe could not be executed: {error}")

    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", "replace").strip()
        lowered = message.lower()
        if "truncat" in lowered or "invalid data found" in lowered:
            return ValidationReport(
                verdict="truncated",
                detail=f"ffprobe stopped early: {message}",
                decoder=decoder,
            )
        return ValidationReport(
            verdict="corrupt", detail=f"ffprobe rejected the file: {message}",
            decoder=decoder,
        )
    try:
        probed: dict[str, Any] = json.loads(completed.stdout or b"{}")
    except json.JSONDecodeError:  # pragma: no cover - ffprobe emits valid JSON
        probed = {}
    streams = probed.get("streams", [])
    kinds = ", ".join(str(stream.get("codec_type", "?")) for stream in streams)
    return ValidationReport(
        verdict="valid",
        detail=f"{structure_detail}; ffprobe read {len(streams)} stream(s): {kinds}",
        decoder=decoder,
    )


# --------------------------------------------------------------------------
# WAV: the stdlib wave reader
# --------------------------------------------------------------------------


def validate_wav(data: bytes, deadline: _Deadline) -> ValidationReport:
    """Open with ``wave`` and read every sample frame the header declares.

    Opening alone reads the ``fmt `` chunk, which a file cut in half still has.
    Reading the frames is what establishes that the ``data`` chunk holds as
    many bytes as it says. Frames are read and discarded in blocks, so a long
    recording is never held whole.
    """
    decoder = "wave"
    try:
        with wave.open(io.BytesIO(data), "rb") as sound:
            channels = sound.getnchannels()
            width = sound.getsampwidth()
            rate = sound.getframerate()
            frames = sound.getnframes()
            declared = frames * channels * width
            read = 0
            while read < declared:
                if deadline.expired:
                    return _unavailable(decoder, deadline.note())
                block = sound.readframes(WAV_FRAMES_PER_READ)
                if not block:
                    break
                read += len(block)
    except wave.Error as error:
        text = str(error).lower()
        if "unknown format" in text or "compress" in text:
            # A RIFF/WAVE file this reader cannot decode is not a broken file.
            return _unavailable(decoder, f"this WAV is not PCM: {error}")
        return ValidationReport(
            verdict="corrupt", detail=f"not a readable WAV: {error}", decoder=decoder
        )
    except (OSError, ValueError, EOFError) as error:
        return ValidationReport(
            verdict="corrupt", detail=f"WAV read failed: {error}", decoder=decoder
        )
    except RuntimeError as error:
        # `wave` raises a **bare** RuntimeError - no message, no subclass - from
        # its internal Chunk.seek when a chunk header declares a size the file
        # does not have (CPython Lib/wave.py:155). It is not documented and it
        # is not a wave.Error, so the handlers above do not catch it, and it
        # escaped this function into the carve pipeline: a malformed RIFF
        # header on a seized disk crashed the whole recovery job.
        #
        # Found by testkit/fuzz.py, seed 0, category "hostile size field"; the
        # regression is tests/carve/test_validate_malformed.py.
        #
        # Caught narrowly here rather than broadly upstream: this is one known
        # standard-library behaviour on one decoder, and a blanket RuntimeError
        # handler around every validator would swallow genuine bugs in ours.
        return ValidationReport(
            verdict="corrupt",
            detail=(
                "not a readable WAV: a chunk header declares more bytes than "
                f"the object holds ({type(error).__name__} from the wave module)"
            ),
            decoder=decoder,
        )

    if read < declared:
        return ValidationReport(
            verdict="truncated",
            detail=(
                f"the data chunk declares {declared} bytes of samples and "
                f"{read} are present"
            ),
            decoder=decoder,
        )
    return ValidationReport(
        verdict="valid",
        detail=(
            f"PCM, {channels} channel(s), {width * 8}-bit, {rate} Hz, "
            f"{frames} frame(s) fully read"
        ),
        decoder=decoder,
    )


# --------------------------------------------------------------------------
# GZIP
# --------------------------------------------------------------------------


def validate_gzip(data: bytes, deadline: _Deadline) -> ValidationReport:
    """Inflate the member so zlib checks its CRC and length trailer.

    The output is counted and thrown away a megabyte at a time. A gzip bomb is
    a small file that inflates to gigabytes, and a carved candidate is exactly
    the kind of untrusted input that is one.
    """
    from core.carve.structure import MAX_INFLATE_BYTES

    decoder = f"zlib {zlib.ZLIB_VERSION}"
    engine = zlib.decompressobj(16 + zlib.MAX_WBITS)
    produced = 0
    position = 0
    try:
        while position < len(data) and not engine.eof:
            if deadline.expired:
                return _unavailable(decoder, deadline.note())
            block = data[position : position + GZIP_BLOCK_BYTES]
            produced += len(engine.decompress(block, MIB))
            while engine.unconsumed_tail and not engine.eof:
                if produced > MAX_INFLATE_BYTES:
                    return _unavailable(
                        decoder,
                        f"the member inflates past the {MAX_INFLATE_BYTES} byte "
                        "budget, so it was not decoded",
                    )
                produced += len(engine.decompress(engine.unconsumed_tail, MIB))
            position += len(block)
    except zlib.error as error:
        text = str(error).lower()
        verdict: Validation = (
            "truncated" if "incomplete" in text or "unexpected end" in text
            else "corrupt"
        )
        return ValidationReport(
            verdict=verdict, detail=f"inflate failed: {error}", decoder=decoder
        )

    if not engine.eof:
        return ValidationReport(
            verdict="truncated",
            detail="the deflate stream does not end within this object",
            decoder=decoder,
        )
    trailing = len(engine.unused_data)
    note = f"; {trailing} byte(s) follow the member" if trailing else ""
    return ValidationReport(
        verdict="valid",
        detail=(
            f"inflated to {produced} bytes; zlib verified the CRC and length "
            f"trailer{note}"
        ),
        decoder=decoder,
    )


# --------------------------------------------------------------------------
# TAR
# --------------------------------------------------------------------------


def validate_tar(data: bytes, deadline: _Deadline) -> ValidationReport:
    """Walk every member, read its bytes, and require the end-of-archive marker.

    Nothing is ever extracted to disk. The marker matters as much as the
    members do: a tar has no length field, so an archive cut after a whole
    member is a sequence of perfectly good members that simply stops, and
    ``tarfile`` reads it without complaint. Only the two zero blocks the format
    ends with say that the archive is all here.
    """
    decoder = "tarfile"
    members = 0
    end_of_members = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            for member in archive:
                if members >= MAX_ARCHIVE_MEMBERS or deadline.expired:
                    break
                members += 1
                if not member.isfile():
                    continue
                stream = archive.extractfile(member)
                if stream is None:
                    continue
                read = 0
                while True:
                    block = stream.read(MIB)
                    if not block:
                        break
                    read += len(block)
                if read < member.size:
                    return ValidationReport(
                        verdict="truncated",
                        detail=(
                            f"{member.name} declares {member.size} bytes and "
                            f"{read} are present"
                        ),
                        decoder=decoder,
                    )
            end_of_members = archive.offset
    except tarfile.ReadError as error:
        text = str(error).lower()
        if "unexpected end" in text or "truncated" in text:
            return ValidationReport(
                verdict="truncated",
                detail=f"the archive ends inside a member: {error}",
                decoder=decoder,
            )
        return ValidationReport(
            verdict="corrupt",
            detail=f"not a readable archive: {error}",
            decoder=decoder,
        )
    except (OSError, ValueError, EOFError) as error:
        return ValidationReport(
            verdict="corrupt", detail=f"archive read failed: {error}", decoder=decoder
        )

    if not members:
        return ValidationReport(
            verdict="corrupt",
            detail="no member header in this object is readable",
            decoder=decoder,
        )
    marker = data[end_of_members : end_of_members + TAR_BLOCK_BYTES]
    if len(marker) < TAR_BLOCK_BYTES or marker.strip(b"\x00"):
        return ValidationReport(
            verdict="truncated",
            detail=(
                f"{members} member(s) read, and no end-of-archive marker follows "
                "them: the archive does not end inside this object"
            ),
            decoder=decoder,
        )
    return ValidationReport(
        verdict="valid",
        detail=(
            f"{members} member(s); every declared size is present and the "
            "end-of-archive marker follows them"
        ),
        decoder=decoder,
    )


# --------------------------------------------------------------------------
# OLE compound files
# --------------------------------------------------------------------------


def validate_ole(data: bytes, deadline: _Deadline) -> ValidationReport:
    """List the streams and read SummaryInformation. Never opens a macro stream."""
    try:
        import olefile
    except ImportError:
        return _unavailable(
            "olefile", "olefile is not installed, so OLE streams were not read"
        )

    decoder = f"olefile {olefile.__version__}"
    if not olefile.isOleFile(io.BytesIO(data)):
        return ValidationReport(
            verdict="corrupt",
            detail="OLE header present but the compound-file structure is not",
            decoder=decoder,
        )
    try:
        with olefile.OleFileIO(io.BytesIO(data)) as ole:
            streams = ["/".join(entry) for entry in ole.listdir(streams=True)]
            summary = ""
            if ole.exists("\x05SummaryInformation"):
                metadata = ole.getproperties("\x05SummaryInformation")
                summary = f", SummaryInformation holds {len(metadata)} property(s)"
            elif not deadline.expired:
                summary = ", no SummaryInformation stream"
        return ValidationReport(
            verdict="valid",
            detail=f"{len(streams)} stream(s){summary}",
            decoder=decoder,
        )
    except OSError as error:
        text = str(error).lower()
        if "incomplete" in text or "truncated" in text or "end of file" in text:
            return ValidationReport(
                verdict="truncated",
                detail=f"compound file ends early: {error}",
                decoder=decoder,
            )
        return ValidationReport(
            verdict="corrupt",
            detail=f"compound file could not be read: {error}",
            decoder=decoder,
        )
    except ValueError as error:
        return ValidationReport(
            verdict="corrupt",
            detail=f"compound file could not be read: {error}",
            decoder=decoder,
        )


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

#: Keyed by the canonical extension the signature table assigns. Formats absent
#: here have no decoder in this build and validate as ``decoder_unavailable``.
VALIDATORS: dict[str, Validator] = {
    "jpg": validate_image,
    "png": validate_image,
    "gif": validate_image,
    "tiff": validate_image,
    "webp": validate_image,
    "bmp": validate_image,
    "pdf": validate_pdf,
    "zip": validate_zip,
    "docx": validate_zip,
    "xlsx": validate_zip,
    "pptx": validate_zip,
    "sqlite": validate_sqlite,
    "mp4": validate_mp4,
    "wav": validate_wav,
    "gz": validate_gzip,
    "tar": validate_tar,
    "doc": validate_ole,
}


def validate_bytes(
    data: bytes, ext: str, *, deadline_s: float = DEADLINE_S
) -> ValidationReport:
    """Decode ``data`` as ``ext`` and report what the decoder concluded."""
    validator = VALIDATORS.get(ext.lower().lstrip("."))
    if validator is None:
        return _unavailable(
            "none", f"no decoder is registered for .{ext} in this build"
        )
    if not data:
        return ValidationReport(
            verdict="truncated", detail="candidate holds no bytes", decoder="none"
        )
    if len(data) > MAX_VALIDATE_BYTES:
        return _unavailable(
            "none",
            f"candidate is {len(data)} bytes, above the {MAX_VALIDATE_BYTES} byte "
            "in-memory validation budget",
        )

    deadline = _Deadline(deadline_s)
    report = validator(data, deadline)
    if deadline.expired and report.verdict == "corrupt":
        # A decode that ran out of time and then failed cannot be told apart
        # from one that failed on its merits. Report the weaker claim.
        return _unavailable(report.decoder, f"{deadline.note()}: {report.detail}")
    return report


def _locate_absent_frames(
    report: ValidationReport, candidate: CarveCandidate, *, contiguous: bool
) -> str:
    """The detail, plus where on the medium each absent declared image would begin.

    Only for a contiguous candidate, whose offset plus a declared offset is a
    position on the medium. A reassembled or multi-extent object's own byte
    numbering does not map onto the medium that simply, so it keeps the
    object-relative offsets the detail already gives.
    """
    if not report.absent_frames or not contiguous:
        return report.detail
    where = "; ".join(
        f"image {index + 1} at offset {candidate.offset + declared}"
        for index, declared in report.absent_frames
    )
    return f"{report.detail} On the medium, reading on from this object: {where}."


def validate_candidate(
    candidate: CarveCandidate,
    image: EvidenceHandle | None = None,
    *,
    data: bytes | None = None,
) -> CarveCandidate:
    """Return ``candidate`` with ``validation`` set from a real decode attempt.

    The evidence handle is read-only, and the candidate's bytes are copied into
    memory before any decoder sees them, so nothing a decoder does can reach
    the image.

    ``data`` supplies the bytes directly, and a caller that has them **must**
    pass them. ``candidate.offset`` and ``candidate.length`` describe one
    contiguous range, which is the wrong shape for a file the filesystem stored
    in several runs: reading that range back from the image would hand the
    decoder the right length of the wrong bytes, and the verdict would be about
    something that was never a file. :func:`core.carve.fsaware.read_recovered`
    produces the correct bytes for those candidates, and this is where they go
    in - mirroring ``data`` on :func:`~core.carve.classify.classify_candidate`
    and :func:`~core.carve.score.score_candidate`.
    """
    if data is None and image is None:
        raise ValueError("validate_candidate needs either data or an image to read")

    if data is None and candidate.length > MAX_VALIDATE_BYTES:
        report = _unavailable(
            "none",
            f"candidate is {candidate.length} bytes, above the "
            f"{MAX_VALIDATE_BYTES} byte in-memory validation budget",
        )
    else:
        payload = data
        if payload is None:
            assert image is not None
            payload = _read_candidate(candidate, image)
        report = validate_bytes(payload, candidate.ext)

    logger.debug(
        "candidate.validated",
        offset=candidate.offset,
        ext=candidate.ext,
        verdict=report.verdict,
        decoder=report.decoder,
    )
    return candidate.model_copy(
        update={
            "validation": report.verdict,
            "validation_detail": _locate_absent_frames(
                report, candidate, contiguous=data is None
            ),
        }
    )


def _read_candidate(candidate: CarveCandidate, image: EvidenceHandle) -> bytes:
    """Copy the candidate's bytes out of the evidence, one chunk at a time."""
    out = bytearray()
    cursor = candidate.offset
    remaining = candidate.length
    while remaining > 0:
        piece = image.read(cursor, min(MIB, remaining))
        if not piece:
            break
        out += piece
        cursor += len(piece)
        remaining -= len(piece)
    return bytes(out)
