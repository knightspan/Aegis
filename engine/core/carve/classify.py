"""Classify a carved candidate by type and by the properties a case turns on.

Three jobs, in the order they matter to an investigator:

**Type from content.** The MIME type comes from the parse, never from an
extension: a carved object has no filename to lie with, and the extension the
signature table assigns is a starting guess. A ZIP that turns out to hold
``word/document.xml`` is a WordprocessingML document, and it is reported as one.

**Flags.** ``has_exif_gps`` and ``contains_macros`` are the two highest-value
hits in a real case - a photograph that carries where it was taken, and a
document that carries code. ``is_password_protected``, ``is_encrypted``,
``has_embedded_files`` and ``is_signed`` are the rest of what an examiner
filters on. Every flag defaults to False and is only set from something the
decoder actually saw; when no decoder ran, ``flags.inspected`` stays False so a
reader can tell "no macros" from "nobody looked".

**Dedupe.** The same file lands in a carve output several times - a copy in a
backup directory, a copy in unallocated space, a copy in a temporary file - and
reporting it three times pads the results without adding a finding. Identical
content is reported once, carrying every offset it was found at.

Recovered bytes are written to an output directory. Never back to the evidence:
:func:`write_recovered` refuses an output path that resolves inside the
evidence source, and the evidence handle is only ever read from.
"""

from __future__ import annotations

import io
import re
import zipfile
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog
from PIL import ExifTags, Image, UnidentifiedImageError

from core.carve.evidence import EvidenceHandle
from core.carve.validate import MAX_IMAGE_PIXELS, MAX_VALIDATE_BYTES
from core.models import CarveCandidate, CarveCategory, CarveFlags

__all__ = [
    "ContentFacts",
    "CATEGORY_BY_EXT",
    "OOXML_TYPES",
    "OLE_TYPES",
    "classify_bytes",
    "classify_candidate",
    "dedupe",
    "output_filename",
    "write_recovered",
]

logger = structlog.get_logger(__name__)

MIB = 1024 * 1024

#: What each extension is, one step coarser than the MIME type. This is the
#: axis an examiner filters on first: "show me the documents".
CATEGORY_BY_EXT: dict[str, CarveCategory] = {
    "jpg": "image",
    "png": "image",
    "gif": "image",
    "tiff": "image",
    "webp": "image",
    "bmp": "image",
    "mp4": "media",
    "wav": "media",
    "pdf": "document",
    "html": "document",
    "rtf": "document",
    "doc": "document",
    "xls": "document",
    "ppt": "document",
    "docx": "document",
    "xlsx": "document",
    "pptx": "document",
    "docm": "document",
    "xlsm": "document",
    "pptm": "document",
    "txt": "document",
    "zip": "archive",
    "rar": "archive",
    "7z": "archive",
    "gz": "archive",
    "tar": "archive",
    "sqlite": "database",
    "evtx": "database",
    "exe": "executable",
    "elf": "executable",
}

#: OOXML part -> (extension, MIME type, macro-bearing extension). The macro
#: variant matters because a ``.docm`` and a ``.docx`` differ by exactly one
#: part, and that part is the reason to look at the file at all.
OOXML_TYPES: dict[str, tuple[str, str, str]] = {
    "word/document.xml": (
        "docx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "docm",
    ),
    "xl/workbook.xml": (
        "xlsx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "xlsm",
    ),
    "ppt/presentation.xml": (
        "pptx",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "pptm",
    ),
}

#: OLE stream name -> (extension, MIME type). The stream is the only honest way
#: to tell a Word document from a spreadsheet inside a compound file.
OLE_TYPES: dict[str, tuple[str, str]] = {
    "WordDocument": ("doc", "application/msword"),
    "Workbook": ("xls", "application/vnd.ms-excel"),
    "Book": ("xls", "application/vnd.ms-excel"),
    "PowerPoint Document": ("ppt", "application/vnd.ms-powerpoint"),
}

#: OLE streams that hold VBA. ``_VBA_PROJECT`` is the project itself; a
#: ``Macros`` or ``VBA`` storage is where the modules live. None of them is
#: ever opened for execution - only their presence is recorded.
_OLE_MACRO_MARKERS = ("_VBA_PROJECT", "VBA", "Macros")

#: Windows forbids these in a filename and POSIX tolerates most of them. A
#: recovered name is attacker-controlled data, so it is rewritten, never
#: trusted.
_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")

_MAX_NAME_CHARS = 64


@dataclass(frozen=True)
class ContentFacts:
    """What a decoder observed about a candidate's content."""

    ext: str
    mime: str
    category: CarveCategory
    flags: CarveFlags = field(default_factory=CarveFlags)
    #: A name the content carries about itself, when the format has one.
    original_name: str | None = None


def _category_for(ext: str) -> CarveCategory:
    return CATEGORY_BY_EXT.get(ext.lower(), "unknown")


# --------------------------------------------------------------------------
# Per-format inspection
# --------------------------------------------------------------------------

_PILLOW_MIME = {
    "JPEG": ("jpg", "image/jpeg"),
    "PNG": ("png", "image/png"),
    "GIF": ("gif", "image/gif"),
    "TIFF": ("tiff", "image/tiff"),
    "WEBP": ("webp", "image/webp"),
    "BMP": ("bmp", "image/bmp"),
}


def _inspect_image(data: bytes, fallback_ext: str) -> ContentFacts:
    """Read the format and the EXIF GPS block. Pixels are not needed here."""
    previous = Image.MAX_IMAGE_PIXELS
    Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
    try:
        with Image.open(io.BytesIO(data)) as image:
            fmt = image.format or ""
            ext, mime = _PILLOW_MIME.get(
                fmt, (fallback_ext, f"image/{fmt.lower() or 'unknown'}")
            )
            gps: dict[int, Any] = {}
            try:
                gps = dict(image.getexif().get_ifd(ExifTags.IFD.GPSInfo))
            except (AttributeError, KeyError, OSError, ValueError, TypeError):
                # A damaged EXIF block is not a reason to lose the whole
                # classification; it only means the GPS question is unanswered.
                gps = {}
            return ContentFacts(
                ext=ext,
                mime=mime,
                category="image",
                flags=CarveFlags(has_exif_gps=bool(gps), inspected=True),
            )
    except (
        Image.DecompressionBombError,
        UnidentifiedImageError,
        OSError,
        ValueError,
        SyntaxError,
        EOFError,
    ):
        return ContentFacts(
            ext=fallback_ext,
            mime=f"image/{fallback_ext}",
            category="image",
            flags=CarveFlags(inspected=False),
        )
    finally:
        Image.MAX_IMAGE_PIXELS = previous


def _inspect_zip(data: bytes, fallback_ext: str) -> ContentFacts:
    """Tell an OOXML package from a plain archive, and find its macros."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = archive.namelist()
            infos = archive.infolist()
    except (zipfile.BadZipFile, OSError, ValueError, EOFError):
        return ContentFacts(
            ext=fallback_ext,
            mime="application/zip",
            category="archive",
            flags=CarveFlags(inspected=False),
        )

    encrypted = any(info.flag_bits & 0x1 for info in infos)
    macros = any(name.rsplit("/", 1)[-1] == "vbaProject.bin" for name in names)
    signed = any(name.startswith("_xmlsignatures/") for name in names)
    flags = CarveFlags(
        is_password_protected=encrypted,
        is_encrypted=encrypted,
        contains_macros=macros,
        is_signed=signed,
        inspected=True,
    )

    for part, (ext, mime, macro_ext) in OOXML_TYPES.items():
        if part in names:
            return ContentFacts(
                ext=macro_ext if macros else ext,
                mime=mime,
                category="document",
                flags=flags,
            )
    return ContentFacts(
        ext="zip", mime="application/zip", category="archive", flags=flags
    )


def _inspect_pdf(data: bytes, fallback_ext: str) -> ContentFacts:
    """Read the trailer for encryption, embedded files and signatures."""
    mime = "application/pdf"
    try:
        import pikepdf
    except ImportError:  # pragma: no cover - pikepdf is a hard dependency
        return ContentFacts(
            ext="pdf",
            mime=mime,
            category="document",
            flags=CarveFlags(inspected=False),
        )

    try:
        with pikepdf.open(io.BytesIO(data)) as pdf:
            root = pdf.Root
            names = root.get("/Names")
            embedded = bool(names is not None and names.get("/EmbeddedFiles"))
            if not embedded:
                embedded = any(
                    obj.get("/Type") == "/EmbeddedFile"
                    for obj in pdf.objects
                    if isinstance(obj, pikepdf.Dictionary)
                )
            acroform = root.get("/AcroForm")
            signed = bool(acroform is not None and acroform.get("/SigFlags"))
            if not signed:
                signed = any(
                    obj.get("/Type") == "/Sig"
                    for obj in pdf.objects
                    if isinstance(obj, pikepdf.Dictionary)
                )
            title = None
            with pdf.open_metadata() as meta:
                raw_title = meta.get("dc:title")
                if isinstance(raw_title, str) and raw_title.strip():
                    title = raw_title.strip()
            return ContentFacts(
                ext="pdf",
                mime=mime,
                category="document",
                flags=CarveFlags(
                    is_encrypted=pdf.is_encrypted,
                    has_embedded_files=embedded,
                    is_signed=signed,
                    inspected=True,
                ),
                original_name=title,
            )
    except pikepdf.PasswordError:
        return ContentFacts(
            ext="pdf",
            mime=mime,
            category="document",
            flags=CarveFlags(
                is_password_protected=True, is_encrypted=True, inspected=True
            ),
        )
    except (pikepdf.PdfError, OSError, ValueError, RuntimeError):
        return ContentFacts(
            ext=fallback_ext or "pdf",
            mime=mime,
            category="document",
            flags=CarveFlags(inspected=False),
        )


def _inspect_ole(data: bytes, fallback_ext: str) -> ContentFacts:
    """Name the compound file from its streams, and spot VBA storages."""
    try:
        import olefile
    except ImportError:
        return ContentFacts(
            ext=fallback_ext or "doc",
            mime="application/x-ole-storage",
            category="document",
            flags=CarveFlags(inspected=False),
        )

    try:
        with olefile.OleFileIO(io.BytesIO(data)) as ole:
            entries = ole.listdir(streams=True, storages=True)
    except (OSError, ValueError):
        return ContentFacts(
            ext=fallback_ext or "doc",
            mime="application/x-ole-storage",
            category="document",
            flags=CarveFlags(inspected=False),
        )

    parts = {name for entry in entries for name in entry}
    macros = any(marker in parts for marker in _OLE_MACRO_MARKERS)
    encrypted = "EncryptedPackage" in parts
    ext, mime = "doc", "application/x-ole-storage"
    for stream, (candidate_ext, candidate_mime) in OLE_TYPES.items():
        if stream in parts:
            ext, mime = candidate_ext, candidate_mime
            break
    return ContentFacts(
        ext=ext,
        mime=mime,
        category="document",
        flags=CarveFlags(
            contains_macros=macros,
            is_encrypted=encrypted,
            is_password_protected=encrypted,
            inspected=True,
        ),
    )


def classify_bytes(data: bytes, ext: str) -> ContentFacts:
    """Classify ``data``, using ``ext`` only as the fallback when no parse works."""
    lowered = ext.lower().lstrip(".")
    if lowered in {"jpg", "png", "gif", "tiff", "webp", "bmp"}:
        return _inspect_image(data, lowered)
    if lowered in {"zip", "docx", "xlsx", "pptx"}:
        return _inspect_zip(data, lowered)
    if lowered == "pdf":
        return _inspect_pdf(data, lowered)
    if lowered in {"doc", "xls", "ppt"}:
        return _inspect_ole(data, lowered)
    return ContentFacts(
        ext=lowered,
        mime=_MIME_BY_EXT.get(lowered, "application/octet-stream"),
        category=_category_for(lowered),
        flags=CarveFlags(inspected=False),
    )


#: Types with no decoder in this build. The MIME still comes from the signature
#: match rather than from a filename, but nothing about the content is claimed.
_MIME_BY_EXT = {
    "mp4": "video/mp4",
    "wav": "audio/x-wav",
    "gz": "application/gzip",
    "tar": "application/x-tar",
    "html": "text/html",
    "rtf": "application/rtf",
    "sqlite": "application/vnd.sqlite3",
    "elf": "application/x-elf",
    "exe": "application/vnd.microsoft.portable-executable",
    "rar": "application/vnd.rar",
    "7z": "application/x-7z-compressed",
    "evtx": "application/x-ms-evtx",
}


def classify_candidate(
    candidate: CarveCandidate,
    *,
    data: bytes | None = None,
    image: EvidenceHandle | None = None,
) -> CarveCandidate:
    """Return ``candidate`` with type fields normalised and enriched.

    With neither ``data`` nor ``image``, only the category is derived - from
    the extension the signature match already assigned - and the flags stay
    uninspected. Nothing is inferred from a name.
    """
    payload = data
    if payload is None and image is not None and candidate.length <= MAX_VALIDATE_BYTES:
        payload = _read_candidate(candidate, image)

    if payload is None:
        return candidate.model_copy(
            update={"category": _category_for(candidate.ext)}
        )

    facts = classify_bytes(payload, candidate.ext)
    logger.debug(
        "candidate.classified",
        offset=candidate.offset,
        ext=facts.ext,
        mime=facts.mime,
        category=facts.category,
    )
    return candidate.model_copy(
        update={
            "ext": facts.ext,
            "mime": facts.mime,
            "category": facts.category,
            "flags": facts.flags,
            "original_name": candidate.original_name or facts.original_name,
        }
    )


# --------------------------------------------------------------------------
# Dedupe
# --------------------------------------------------------------------------


def dedupe(candidates: Sequence[CarveCandidate]) -> list[CarveCandidate]:
    """Report identical content once, carrying every offset it was found at.

    The kept copy is the highest-scoring one, and ties break on the lowest
    offset so a run is reproducible. ``duplicate_offsets`` holds the offsets of
    the copies that were folded in, ascending, so nothing about where the
    content appeared is lost.
    """
    by_digest: dict[str, list[CarveCandidate]] = {}
    for candidate in candidates:
        by_digest.setdefault(candidate.sha256, []).append(candidate)

    kept: list[CarveCandidate] = []
    for group in by_digest.values():
        best = min(group, key=lambda item: (-item.confidence_bp, item.offset))
        others = sorted(
            item.offset for item in group if item.offset != best.offset
        )
        kept.append(
            best.model_copy(update={"duplicate_offsets": others})
            if others
            else best
        )
    return sorted(kept, key=lambda item: (item.offset, item.length))


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


def _safe_name(candidate: CarveCandidate) -> str:
    """A filename stem from the recovered name, or one generated from the offset."""
    if candidate.original_name:
        stem = _UNSAFE_NAME.sub("_", Path(candidate.original_name).stem).strip("._-")
        if stem:
            return stem[:_MAX_NAME_CHARS]
    return f"carved-{candidate.offset:012d}"


def output_filename(candidate: CarveCandidate) -> str:
    """``<offset>_<confidence>_<name>.<ext>``: sortable, with its provenance in it.

    The offset is zero-padded so a directory listing sorts in image order, and
    the confidence is the basis-point figure rather than the bucket, so two
    candidates in the same bucket still sort by how well they scored.
    """
    ext = _UNSAFE_NAME.sub("", candidate.ext.lower()) or "bin"
    return (
        f"{candidate.offset:012d}_{candidate.confidence_bp:05d}_"
        f"{_safe_name(candidate)}.{ext}"
    )


def write_recovered(
    candidates: Sequence[CarveCandidate],
    image: EvidenceHandle,
    out_dir: Path | str,
) -> Iterator[dict[str, Any]]:
    """Write each candidate's bytes into ``out_dir``, yielding progress.

    The evidence is opened read-only by the layer above and is only read here.
    An output directory that resolves inside the evidence source is refused
    outright: writing a recovered file back into the image under examination
    would destroy the thing being examined.
    """
    destination = Path(out_dir).resolve()
    source = Path(image.source.path)
    if source.exists():
        resolved_source = source.resolve()
        if destination == resolved_source or resolved_source in destination.parents:
            raise ValueError(
                f"refusing to write recovered files into the evidence path "
                f"{resolved_source}"
            )
    destination.mkdir(parents=True, exist_ok=True)

    total = len(candidates)
    for index, candidate in enumerate(candidates, start=1):
        path = destination / output_filename(candidate)
        written = 0
        with path.open("wb") as handle:
            cursor = candidate.offset
            remaining = candidate.length
            while remaining > 0:
                piece = image.read(cursor, min(MIB, remaining))
                if not piece:
                    break
                handle.write(piece)
                written += len(piece)
                cursor += len(piece)
                remaining -= len(piece)
        logger.info(
            "candidate.written",
            offset=candidate.offset,
            path=str(path),
            bytes_written=written,
        )
        yield {
            "phase": "WRITE",
            "index": index,
            "total": total,
            "offset": candidate.offset,
            "path": str(path),
            "bytes_written": written,
            "short": written < candidate.length,
        }


def _read_candidate(candidate: CarveCandidate, image: EvidenceHandle) -> bytes:
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
