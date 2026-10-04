"""Confinement and content typing for everything the API serves off disk.

The API serves two kinds of file it did not author: objects carved out of a
seized image, and reports it generated for a case. Both have to reach the
browser, and one of them is **attacker-controlled bytes with an
attacker-chosen name**, recovered from a disk somebody else filled. That shapes
every rule here.

Three separate questions, answered separately
---------------------------------------------
**Which file.** :func:`resolve_artifact` takes a root *name* from a closed set
(:data:`ARTIFACT_ROOTS`) and a relative path, and returns a real path or
raises. The client never names a directory, so there is no string a client can
send that reaches a directory the deployment did not configure. Symlinks are
resolved before the containment test, so a link planted inside the output
directory cannot point out of it, and the resolved target must be a regular
file - a directory, a FIFO or a device node is refused rather than opened.

**What type.** :func:`content_type_for` maps the extension to a type from a
closed table. It never sniffs and never asks ``mimetypes`` for an answer it
would then trust: a recovered object's extension is derived from the signature
the carver matched, which is a statement about bytes the tool found, not a
promise about what they are. Anything not in the table is
``application/octet-stream``.

**Whether it may render.** :func:`disposition_for` decides ``inline`` or
``attachment``. Only images render inline, and only from the recovered tree, up
to :data:`MAX_INLINE_BYTES`. Everything else downloads. In particular:

* **PDFs never render inline from the recovered tree.** A PDF viewer is a
  scripting engine, and the file came off the evidence. The report PDF this
  tool generated itself is a different provenance and renders inline.
* **Nothing is ever served as ``text/html`` or ``image/svg+xml``**, from either
  tree. Both execute script in the origin that serves them, and this origin is
  the one the UI lives in. A recovered ``.html`` downloads as
  ``application/octet-stream``.

No server-side decoding
-----------------------
A thumbnail is the browser rendering the bytes at a CSS size, not this process
decoding an untrusted image with Pillow and re-encoding it. The browser's
decoders are sandboxed, fuzzed continuously and updated without us; ours would
be a decompression-bomb target inside the process that holds the ledger. The
cost is that a 40 MB recovered JPEG would be sent whole to draw a 200-pixel
tile, which is why the inline path is bounded and larger objects are offered as
a download instead.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

import structlog

if TYPE_CHECKING:  # pragma: no cover - import cycle avoidance only
    from api.deps import AppServices

__all__ = [
    "ARTIFACT_ROOTS",
    "ArtifactRef",
    "ArtifactRefused",
    "resolve_artifact",
    "content_type_for",
    "disposition_for",
    "safe_download_name",
    "MAX_INLINE_BYTES",
    "list_artifacts",
]

logger = structlog.get_logger(__name__)

#: The only root names a client may use. Each maps to an :class:`AppServices`
#: property. A name outside this set is refused before any path work happens,
#: which is what makes "serve an arbitrary host file" unreachable rather than
#: merely unlikely.
ARTIFACT_ROOTS: dict[str, str] = {
    "recovered": "recovered_dir",
    "reports": "reports_dir",
}

#: Above this, an image is offered as a download rather than rendered inline.
#: A gallery tile is 200 pixels and a recovered JPEG can be 40 MB; the bound is
#: what stops a grid of them from being a self-inflicted denial of service on
#: the browser.
MAX_INLINE_BYTES = 24 * 1024 * 1024

#: Extension to content type. A closed table, consulted instead of
#: ``mimetypes``, so adding a signature to the carver cannot quietly add a
#: renderable type to the API. Deliberately absent: ``html``, ``htm``, ``svg``,
#: ``xhtml``, ``xml`` - every one of them executes script in this origin.
_CONTENT_TYPES: dict[str, str] = {
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "png": "image/png",
    "gif": "image/gif",
    "bmp": "image/bmp",
    "webp": "image/webp",
    "tif": "image/tiff",
    "tiff": "image/tiff",
    "pdf": "application/pdf",
    "json": "application/json",
    "txt": "text/plain; charset=utf-8",
    "csv": "text/csv; charset=utf-8",
    "zip": "application/zip",
    "mp4": "video/mp4",
    "mp3": "audio/mpeg",
    "wav": "audio/wav",
    "sqlite": "application/vnd.sqlite3",
    "db": "application/vnd.sqlite3",
}

#: Types a browser may render in place. Images only, and only the raster ones:
#: an SVG is a document with script in it and is not on this list at any size.
_INLINE_TYPES = frozenset(
    {
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/bmp",
        "image/webp",
        "image/tiff",
    }
)


class ArtifactRefused(Exception):
    """An artifact request was refused. Carries a client-safe explanation.

    ``message`` never contains a host path. The client asked for a name inside
    a root it named, and telling it where that root lives on this host is a
    disclosure with no benefit to the person reading the screen.
    """

    def __init__(self, message: str, remediation: str, *, status: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.remediation = remediation
        self.status = status


@dataclass(frozen=True)
class ArtifactRef:
    """A resolved, confined artifact."""

    root: str
    #: The path relative to its root, normalised, as the client should quote it.
    name: str
    path: Path
    size: int
    content_type: str
    disposition: Literal["inline", "attachment"]


def _root_dir(services: AppServices, root: str) -> Path:
    attribute = ARTIFACT_ROOTS.get(root)
    if attribute is None:
        raise ArtifactRefused(
            f"{root!r} is not a servable artifact root. "
            f"Allowed: {', '.join(sorted(ARTIFACT_ROOTS))}.",
            "Ask for an artifact under one of the listed roots.",
            status=404,
        )
    base: Path = getattr(services, attribute)
    return base


def resolve_artifact(services: AppServices, root: str, name: str) -> Path:
    """Resolve ``name`` inside the configured ``root`` or refuse it.

    The checks, in the order they run and for the reason each exists:

    1. ``root`` must be a key of :data:`ARTIFACT_ROOTS`. A client cannot name
       a directory, only one of two words.
    2. ``name`` must not be absolute and must contain no ``..`` component. An
       absolute path is refused rather than joined, because ``Path("/a") /
       "/etc/passwd"`` is ``/etc/passwd``.
    3. The join is resolved - which follows every symlink - and the result must
       be the root or inside it. This is what makes a planted link inside the
       output directory useless: the link resolves first, then is tested.
    4. The resolved target must be a **regular file**. A directory, a FIFO or a
       device node would otherwise be opened by the response, and reading a
       FIFO inside the state directory would hang the worker thread.

    Raises:
        ArtifactRefused: with a message that names no host path.
    """
    base = _root_dir(services, root).resolve()
    requested = Path(name)
    if requested.is_absolute() or any(part == ".." for part in requested.parts):
        raise ArtifactRefused(
            f"Refusing to serve {name!r}: an artifact is named relative to its "
            "root, and a path that is absolute or walks upward out of it is "
            "not an artifact this deployment serves.",
            "Quote the name exactly as the artifact listing returned it.",
            status=400,
        )

    target = (base / requested).resolve()
    if target != base and base not in target.parents:
        # The symlink case lands here: resolve() followed it, and the far end
        # is outside the root.
        raise ArtifactRefused(
            f"Refusing to serve {name!r}: it resolves outside the "
            f"{root!r} directory this deployment serves.",
            "Artifacts are served only from the configured output "
            "directories. Nothing was read.",
            status=400,
        )
    if not target.is_file():
        raise ArtifactRefused(
            f"No artifact named {name!r} exists under {root!r}, or it is not a "
            "regular file.",
            "Re-run the listing; a recovered object only exists when the "
            "recovery was run with an output directory.",
            status=404,
        )
    return target


def content_type_for(path: Path) -> str:
    """The content type this deployment will claim for ``path``.

    From a closed table keyed on the extension, never from sniffing and never
    from ``mimetypes``. An unknown extension is ``application/octet-stream``,
    which combined with the global ``X-Content-Type-Options: nosniff`` header
    means the browser will not go looking for a better answer either.
    """
    suffix = path.suffix.lower().lstrip(".")
    return _CONTENT_TYPES.get(suffix, "application/octet-stream")


def disposition_for(
    root: str, content_type: str, size: int
) -> Literal["inline", "attachment"]:
    """Whether the browser may render this artifact in place.

    Images render inline from either root, under :data:`MAX_INLINE_BYTES`. A
    PDF renders inline **only from the reports root**, because that one this
    tool generated and the other came off the evidence; a PDF viewer runs
    script, and an examiner opening a recovered document should do it
    deliberately, in a program of their choosing, from a file they downloaded.
    Everything else is an attachment.
    """
    if content_type in _INLINE_TYPES and size <= MAX_INLINE_BYTES:
        return "inline"
    if root == "reports" and content_type in {"application/pdf", "application/json"}:
        return "inline"
    return "attachment"


def safe_download_name(name: str) -> str:
    """A filename safe to put in a ``Content-Disposition`` header.

    A recovered object's name can come from a filesystem record written by
    whoever filled the disk, so it can hold a quote, a newline, a semicolon or
    a right-to-left override. Everything outside a conservative set is replaced
    rather than escaped, because a header that needs escaping to be safe is one
    change away from not being.
    """
    normalised = unicodedata.normalize("NFKD", str(name or ""))
    cleaned = "".join(
        character if (character.isalnum() or character in "._-") else "_"
        for character in normalised
    )
    cleaned = cleaned.strip("._") or "artifact"
    return cleaned[:128]


def list_artifacts(
    services: AppServices, root: str, *, limit: int = 5000
) -> list[ArtifactRef]:
    """Every regular file under one root, as confined references.

    Walks with ``rglob`` and keeps only files that still resolve inside the
    root, so a symlink into ``/etc`` planted in the output directory is listed
    by nobody. The listing is bounded: a carve of a large image can write tens
    of thousands of objects, and an unbounded listing is a denial of service on
    the screen that renders it.
    """
    base = _root_dir(services, root).resolve()
    found: list[ArtifactRef] = []
    if not base.is_dir():
        return found
    for path in sorted(base.rglob("*")):
        if len(found) >= limit:
            break
        try:
            if not path.is_file():
                continue
            resolved = path.resolve()
            if base not in resolved.parents:
                continue
            size = resolved.stat().st_size
        except OSError:
            continue
        content_type = content_type_for(resolved)
        found.append(
            ArtifactRef(
                root=root,
                name=path.relative_to(base).as_posix(),
                path=resolved,
                size=size,
                content_type=content_type,
                disposition=disposition_for(root, content_type, size),
            )
        )
    return found
