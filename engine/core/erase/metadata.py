"""Metadata cleansing: strip identifying fields before the content is destroyed.

Order matters and it is not obvious. Cleansing runs **before** the overwrite,
so the bytes that get overwritten are the cleansed ones. Doing it the other way
round would leave the original EXIF block sitting in whatever the overwrite did
not reach - the journal, the slack, a snapshot - which is the exact set of
places :mod:`core.erase.residual` exists to enumerate.

Two rules govern every handler:

**Never claim clean on a file that was not parsed.** ``parsed=False`` with a
limitation saying why is the honest result for a corrupt JPEG or a format with
no handler. A result that silently reported zero fields removed would read, in
the report, exactly like a file that had no metadata to begin with.

**Report what was found, not what was attempted.** Each
:class:`~core.models.MetadataField` records whether that specific field was
removed, so a partial cleanse is visible as a partial cleanse.

Format detection is by content, never by extension: a ``.txt`` that is really a
JPEG is exactly the case where the metadata matters.
"""

from __future__ import annotations

import io
import zipfile
from collections.abc import Callable
from pathlib import Path
from xml.etree import ElementTree

import structlog

from core.models import MetadataCleanseResult, MetadataField

__all__ = [
    "cleanse_only",
    "detect_format",
    "HANDLERS",
    "Handler",
    "OOXML_PROPERTY_PARTS",
]

logger = structlog.get_logger(__name__)

Handler = Callable[[Path], MetadataCleanseResult]

#: OPC parts holding document properties. Removing these removes the author,
#: the company, the revision count and the editing time - the fields that
#: identify who produced a document and on whose machine.
OOXML_PROPERTY_PARTS = (
    "docProps/core.xml",
    "docProps/app.xml",
    "docProps/custom.xml",
)

#: Magic bytes, longest first so a prefix never wins over a longer match.
_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
    (b"%PDF-", "PDF"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE"),
    (b"ID3", "AUDIO"),
    (b"fLaC", "AUDIO"),
    (b"OggS", "AUDIO"),
)


def detect_format(path: Path) -> str:
    """Identify a file by content. Returns ``""`` when nothing matches.

    By content and never by extension, because a file named ``.txt`` that is
    really a JPEG is precisely the file whose EXIF block someone hoped nobody
    would look at.
    """
    try:
        with open(path, "rb") as handle:
            header = handle.read(16)
    except OSError:
        return ""

    for magic, name in _MAGIC:
        if header.startswith(magic):
            return name

    if header[:2] == b"PK":
        # A ZIP. OOXML if it carries the OPC content-types part, otherwise a
        # plain archive this module does not cleanse.
        try:
            with zipfile.ZipFile(path) as archive:
                names = set(archive.namelist())
        except (OSError, zipfile.BadZipFile):
            return "ZIP"
        return "OOXML" if "[Content_Types].xml" in names else "ZIP"

    head = header.lstrip()
    if head.startswith(b"<?xml") or head.startswith(b"<svg"):
        return "SVG"
    if head[:1] == b"<":
        return "HTML"
    return ""


def _unparsed(path: Path, fmt: str, why: str) -> MetadataCleanseResult:
    """The honest result for a file no handler could read."""
    return MetadataCleanseResult(
        path=str(path), format=fmt, parsed=False, limitations=[why]
    )


# --------------------------------------------------------------------------
# Images
# --------------------------------------------------------------------------


def cleanse_jpeg(path: Path) -> MetadataCleanseResult:
    """Strip every EXIF IFD, GPS included, and re-save without them."""
    import piexif

    try:
        raw = piexif.load(str(path))
    except (ValueError, OSError, KeyError, piexif.InvalidImageDataError) as exc:
        return _unparsed(
            path,
            "JPEG",
            f"{path} could not be parsed as JPEG EXIF ({exc}), so no metadata "
            "was removed and none is claimed to have been.",
        )

    fields: list[MetadataField] = []
    for container in ("0th", "Exif", "GPS", "1st", "Interop"):
        block = raw.get(container) or {}
        if not isinstance(block, dict):
            continue
        for tag in block:
            fields.append(
                MetadataField(
                    container=container,
                    name=_jpeg_tag_name(container, tag),
                    removed=True,
                )
            )
    if raw.get("thumbnail"):
        # An embedded thumbnail is a second, smaller copy of the image, and it
        # is not regenerated when the main image is edited - so it can show
        # what the picture looked like before a crop removed something.
        fields.append(
            MetadataField(container="thumbnail", name="thumbnail", removed=True)
        )

    try:
        piexif.remove(str(path))
    except (ValueError, OSError) as exc:
        # parsed=False, not True. `piexif.load` reading a header does not mean
        # the file is a JPEG this module can rewrite, and a result carrying
        # parsed=True with zero removed fields is indistinguishable in a report
        # from a file that genuinely had no metadata. Found by
        # test_an_unparsable_file_is_never_reported_as_clean.
        return MetadataCleanseResult(
            path=str(path),
            format="JPEG",
            parsed=False,
            fields=[
                MetadataField(container=item.container, name=item.name, removed=False)
                for item in fields
            ],
            limitations=[
                f"EXIF in {path} could not be removed ({exc}), so this file was "
                "not cleansed and is not claimed to have been."
            ],
        )

    return MetadataCleanseResult(
        path=str(path), format="JPEG", parsed=True, fields=fields
    )


def _jpeg_tag_name(container: str, tag: int) -> str:
    """A readable EXIF tag name, falling back to the numeric tag."""
    import piexif

    tables = {
        "0th": piexif.ImageIFD,
        "1st": piexif.ImageIFD,
        "Exif": piexif.ExifIFD,
        "GPS": piexif.GPSIFD,
        "Interop": piexif.InteropIFD,
    }
    table = tables.get(container)
    if table is not None:
        for name in dir(table):
            if not name.startswith("_") and getattr(table, name) == tag:
                return name
    return f"tag-{tag}"


def cleanse_png(path: Path) -> MetadataCleanseResult:
    """Drop every ancillary text and timestamp chunk, keep the image chunks.

    PNG has no EXIF block in the JPEG sense; it carries ``tEXt``, ``iTXt``,
    ``zTXt``, ``tIME`` and ``eXIf`` chunks. Rewriting the file with only the
    critical chunks plus the ones the image genuinely needs is both simpler and
    safer than editing in place.
    """
    from PIL import Image

    try:
        with Image.open(path) as image:
            image.load()
            fields = [
                MetadataField(container="PNG", name=str(key), removed=True)
                for key in sorted(image.info)
                if key not in {"transparency", "gamma", "dpi", "icc_profile"}
            ]
            # Rebuilt from the pixels rather than copied, so nothing in
            # `image.info` can survive into the new file. `Image.copy()` would
            # carry the info dict across, which is the thing being removed.
            clean = Image.new(image.mode, image.size)
            clean.paste(image)
    except (OSError, ValueError) as exc:
        return _unparsed(
            path,
            "PNG",
            f"{path} could not be decoded as PNG ({exc}), so no metadata was "
            "removed and none is claimed to have been.",
        )

    try:
        clean.save(path, "PNG")
    except (OSError, ValueError) as exc:
        return MetadataCleanseResult(
            path=str(path),
            format="PNG",
            parsed=False,
            fields=[
                MetadataField(container=item.container, name=item.name, removed=False)
                for item in fields
            ],
            limitations=[f"{path} could not be rewritten without metadata: {exc}."],
        )
    return MetadataCleanseResult(
        path=str(path), format="PNG", parsed=True, fields=fields
    )


# --------------------------------------------------------------------------
# PDF
# --------------------------------------------------------------------------


def cleanse_pdf(path: Path) -> MetadataCleanseResult:
    """Clear the document info dictionary and the XMP packet.

    Both, because they are separate stores that usually disagree. Readers show
    the info dictionary; forensic tools read the XMP, which often retains a
    producer string and a creation date after the visible fields are cleared.
    """
    try:
        import pikepdf
    except ImportError:  # pragma: no cover - pikepdf is a hard dependency
        return _unparsed(path, "PDF", "pikepdf is not installed in this build.")

    try:
        with pikepdf.open(path, allow_overwriting_input=True) as document:
            fields: list[MetadataField] = []

            # XMP first, and /Info last. `open_metadata` writes the XMP back
            # into the document info dictionary when its context exits, so
            # deleting /Info before this block would see it silently recreated -
            # with pikepdf's own name stamped into /Producer, which identifies
            # the tool that cleansed the file. Both defaults are turned off for
            # the same reason.
            with document.open_metadata(
                set_pikepdf_as_editor=False, update_docinfo=False
            ) as meta:
                for key in list(meta.keys()):
                    fields.append(
                        MetadataField(container="XMP", name=str(key), removed=True)
                    )
                    del meta[key]

            info = document.trailer.get("/Info")
            if info is not None:
                for key in list(info.keys()):
                    fields.append(
                        MetadataField(container="Info", name=str(key), removed=True)
                    )
                del document.trailer["/Info"]

            document.save(path)
    except (OSError, ValueError, RuntimeError) as exc:
        return _unparsed(
            path,
            "PDF",
            f"{path} could not be parsed as PDF ({exc}), so no metadata was "
            "removed and none is claimed to have been.",
        )

    return MetadataCleanseResult(
        path=str(path),
        format="PDF",
        parsed=True,
        fields=fields,
        limitations=[
            "A PDF that was updated incrementally keeps its earlier revisions "
            "in the same file. Removing the current metadata does not remove a "
            "copy held in a previous revision; only a full rewrite does, and "
            "that would change the content this erase is about to destroy."
        ],
    )


# --------------------------------------------------------------------------
# OOXML and OLE documents
# --------------------------------------------------------------------------


def cleanse_ooxml(path: Path) -> MetadataCleanseResult:
    """Rewrite the package without its property parts.

    OOXML is a ZIP, so the parts are removed by rebuilding the archive rather
    than by patching it: a ZIP cannot have an entry deleted in place without
    rewriting the central directory anyway.
    """
    try:
        with zipfile.ZipFile(path) as archive:
            entries = [
                (item, archive.read(item.filename)) for item in archive.infolist()
            ]
    except (OSError, zipfile.BadZipFile) as exc:
        return _unparsed(
            path,
            "OOXML",
            f"{path} could not be read as an OPC package ({exc}), so no "
            "metadata was removed and none is claimed to have been.",
        )

    fields: list[MetadataField] = []
    keep: list[tuple[zipfile.ZipInfo, bytes]] = []
    for info, payload in entries:
        if info.filename not in OOXML_PROPERTY_PARTS:
            keep.append((info, payload))
            continue
        for name in _xml_leaf_names(payload):
            fields.append(
                MetadataField(container=info.filename, name=name, removed=True)
            )

    if not fields:
        return MetadataCleanseResult(
            path=str(path), format="OOXML", parsed=True, fields=[]
        )

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as out:
        for info, payload in keep:
            out.writestr(info.filename, payload)
    try:
        path.write_bytes(buffer.getvalue())
    except OSError as exc:
        return MetadataCleanseResult(
            path=str(path),
            format="OOXML",
            parsed=False,
            fields=[
                MetadataField(container=item.container, name=item.name, removed=False)
                for item in fields
            ],
            limitations=[f"{path} could not be rewritten: {exc}."],
        )
    return MetadataCleanseResult(
        path=str(path), format="OOXML", parsed=True, fields=fields
    )


def _xml_leaf_names(payload: bytes) -> list[str]:
    """Element names in an OPC property part, with their namespace prefix.

    Reported as ``dc:creator`` rather than as a Clark-notation URL, because the
    report is read by a person who knows the document format, not the XML spec.
    """
    prefixes = {
        "http://purl.org/dc/elements/1.1/": "dc",
        "http://purl.org/dc/terms/": "dcterms",
        "http://schemas.openxmlformats.org/package/2006/metadata/"
        "core-properties": "cp",
    }
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError:
        return []
    names: list[str] = []
    for element in root.iter():
        if element is root:
            continue
        tag = element.tag
        if tag.startswith("{"):
            namespace, _, local = tag[1:].partition("}")
            prefix = prefixes.get(namespace)
            names.append(f"{prefix}:{local}" if prefix else local)
        else:
            names.append(tag)
    return names


def cleanse_ole(path: Path) -> MetadataCleanseResult:
    """Report the OLE property streams; do not attempt to rewrite the container.

    Legacy ``.doc``/``.xls``/``.ppt`` store properties in the
    ``\\x05SummaryInformation`` streams inside a compound file. Rewriting a
    compound file without a full OLE writer risks producing a document that no
    longer opens, and this module runs immediately before the file is destroyed
    anyway - so the honest thing is to name what is in there and record that it
    was not removed.
    """
    import olefile

    try:
        if not olefile.isOleFile(str(path)):
            return _unparsed(path, "OLE", f"{path} is not an OLE compound file.")
        with olefile.OleFileIO(str(path)) as document:
            streams = ["/".join(entry) for entry in document.listdir()]
            found = [name for name in streams if "SummaryInformation" in name]
    except (OSError, ValueError) as exc:
        return _unparsed(
            path,
            "OLE",
            f"{path} could not be parsed as an OLE compound file ({exc}).",
        )

    return MetadataCleanseResult(
        path=str(path),
        format="OLE",
        parsed=True,
        fields=[
            MetadataField(container="OLE", name=name, removed=False) for name in found
        ],
        limitations=[
            "OLE property streams were identified but not removed: rewriting a "
            "compound file safely needs a full OLE writer, and a partial "
            "rewrite would risk a document that no longer opens. The streams "
            "are destroyed with the rest of the file by the overwrite that "
            "follows."
        ]
        if found
        else [],
    )


# --------------------------------------------------------------------------
# Audio, SVG and HTML
# --------------------------------------------------------------------------


def cleanse_audio(path: Path) -> MetadataCleanseResult:
    """Delete every tag mutagen recognises: ID3, Vorbis comments, MP4 atoms."""
    import mutagen

    try:
        audio = mutagen.File(str(path))
    except (OSError, ValueError, mutagen.MutagenError) as exc:
        return _unparsed(path, "AUDIO", f"{path} could not be parsed as audio: {exc}.")
    if audio is None:
        return _unparsed(
            path, "AUDIO", f"{path} was not recognised as an audio file by mutagen."
        )

    fields = [
        MetadataField(container=type(audio).__name__, name=str(key), removed=True)
        for key in sorted(audio.keys() if audio.tags else [])
    ]
    try:
        audio.delete()
        audio.save()
    except (OSError, ValueError, mutagen.MutagenError) as exc:
        return MetadataCleanseResult(
            path=str(path),
            format="AUDIO",
            parsed=False,
            fields=[
                MetadataField(container=item.container, name=item.name, removed=False)
                for item in fields
            ],
            limitations=[f"Tags in {path} were found but could not be removed: {exc}."],
        )
    return MetadataCleanseResult(
        path=str(path), format="AUDIO", parsed=True, fields=fields
    )


def cleanse_svg(path: Path) -> MetadataCleanseResult:
    """Remove ``<metadata>``, ``<title>``, ``<desc>`` and XML comments."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        root = ElementTree.fromstring(text)
    except (OSError, ElementTree.ParseError) as exc:
        return _unparsed(path, "SVG", f"{path} could not be parsed as XML: {exc}.")

    fields: list[MetadataField] = []
    for parent in root.iter():
        for child in list(parent):
            local = child.tag.rpartition("}")[2]
            if local in {"metadata", "title", "desc"}:
                fields.append(
                    MetadataField(container="SVG", name=local, removed=True)
                )
                parent.remove(child)

    try:
        path.write_bytes(ElementTree.tostring(root, encoding="utf-8"))
    except OSError as exc:
        return MetadataCleanseResult(
            path=str(path),
            format="SVG",
            parsed=False,
            fields=[
                MetadataField(container=item.container, name=item.name, removed=False)
                for item in fields
            ],
            limitations=[f"{path} could not be rewritten: {exc}."],
        )
    return MetadataCleanseResult(
        path=str(path), format="SVG", parsed=True, fields=fields
    )


def cleanse_html(path: Path) -> MetadataCleanseResult:
    """Report ``<meta>`` tags and comments without rewriting the document.

    HTML is not reliably parseable as XML and a regex rewrite of real-world
    markup is a good way to corrupt a file. The tags are named so the report
    carries them; the overwrite that follows destroys them with the rest.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return _unparsed(path, "HTML", f"{path} could not be read: {exc}.")

    import re

    found = re.findall(r"<meta\s[^>]*>", text, flags=re.IGNORECASE)
    comments = re.findall(r"<!--.*?-->", text, flags=re.DOTALL)
    fields = [
        MetadataField(container="HTML", name=item[:80], removed=False)
        for item in found + comments
    ]
    return MetadataCleanseResult(
        path=str(path),
        format="HTML",
        parsed=True,
        fields=fields,
        limitations=[
            f"{len(fields)} meta tag(s) and comment(s) were identified in "
            f"{path} but not removed: HTML is not reliably rewritable without a "
            "full parser, and a partial rewrite risks corrupting the document. "
            "They are destroyed with the rest of the file by the overwrite."
        ]
        if fields
        else [],
    )


#: Format name to handler. Detection is by content; see :func:`detect_format`.
HANDLERS: dict[str, Handler] = {
    "JPEG": cleanse_jpeg,
    "PNG": cleanse_png,
    "PDF": cleanse_pdf,
    "OOXML": cleanse_ooxml,
    "OLE": cleanse_ole,
    "AUDIO": cleanse_audio,
    "SVG": cleanse_svg,
    "HTML": cleanse_html,
}


def cleanse_only(path: Path | str) -> MetadataCleanseResult:
    """Strip identifying metadata from one file, in place.

    Called by the erase path before the overwrite, and usable on its own by an
    operator who wants a document sanitised rather than destroyed - which is
    why it is public and why it never unlinks anything.
    """
    target = Path(path)
    fmt = detect_format(target)
    handler = HANDLERS.get(fmt)
    if handler is None:
        return _unparsed(
            target,
            fmt,
            f"{target} is "
            + (f"a {fmt} file" if fmt else "of an unrecognised format")
            + ", which this build has no metadata handler for. Nothing was "
            "removed and nothing is claimed to have been.",
        )

    result = handler(target)
    logger.info(
        "metadata_cleansed",
        path=str(target),
        format=result.format,
        parsed=result.parsed,
        removed=result.removed_count,
    )
    return result
