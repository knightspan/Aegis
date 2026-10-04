"""``/artifacts`` - serving recovered objects and generated reports.

The Recovery screen used to draw a grey box saying a preview would appear once
the carve wrote the file out, and the Audit screen printed the absolute path of
a report the operator then had to find in a file manager. Both were the same
missing piece: there was no way to get a byte of output back out of the tool
through the tool.

Every rule about *which* bytes may leave, under *what* type, and whether a
browser may render them, lives in :mod:`api.artifacts`. This module is the HTTP
shape around it and holds no path logic of its own, which is what makes the
confinement checkable in one file rather than three.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse

from api.artifacts import (
    ARTIFACT_ROOTS,
    ArtifactRefused,
    content_type_for,
    disposition_for,
    list_artifacts,
    resolve_artifact,
    safe_download_name,
)
from api.deps import AppServices
from api.routes.common import get_services, sanctum_error_response

__all__ = ["router"]

router = APIRouter(tags=["artifacts"])


def _refusal(exc: ArtifactRefused) -> Exception:
    from fastapi import HTTPException

    return HTTPException(
        status_code=exc.status,
        detail={
            "error": exc.message,
            "kind": "ArtifactRefused",
            "remediation": exc.remediation,
        },
    )


@router.get("/artifacts")
def index(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    """The roots this deployment serves, and how many files are under each.

    No host paths. The client addresses artifacts by root name and relative
    name and never needs to know where the root lives, and a UI that printed
    the absolute path would be putting the host's layout on a screen that gets
    shared in a demo.
    """
    return {
        "roots": [
            {
                "root": name,
                "count": len(list_artifacts(services, name)),
            }
            for name in sorted(ARTIFACT_ROOTS)
        ]
    }


@router.get("/artifacts/{root}")
def listing(
    root: str,
    limit: int = 2000,
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    """Every artifact under one root, with its type and whether it may render."""
    try:
        items = list_artifacts(services, root, limit=max(1, min(limit, 20000)))
    except ArtifactRefused as exc:
        raise _refusal(exc) from exc
    return {
        "root": root,
        "count": len(items),
        "artifacts": [
            {
                "name": item.name,
                "size": item.size,
                "content_type": item.content_type,
                "disposition": item.disposition,
                "url": f"/artifacts/{root}/{item.name}",
            }
            for item in items
        ],
    }


@router.get("/artifacts/{root}/{name:path}")
def fetch(
    root: str,
    name: str,
    download: bool = False,
    services: AppServices = Depends(get_services),
) -> FileResponse:
    """Serve one artifact.

    ``download=true`` forces an attachment even for something that would have
    rendered. The reverse is deliberately impossible: there is no parameter
    that makes an attachment render, because that decision is about what the
    bytes are and not about what the caller wants.
    """
    try:
        target = resolve_artifact(services, root, name)
    except ArtifactRefused as exc:
        raise _refusal(exc) from exc

    try:
        size = target.stat().st_size
    except OSError as exc:
        raise sanctum_error_response(
            "ArtifactRefused",
            f"The artifact {name!r} could not be read.",
            "It was removed or its permissions changed since it was listed.",
        ) from exc

    content_type = content_type_for(target)
    disposition = "attachment" if download else disposition_for(
        root, content_type, size
    )
    filename = safe_download_name(target.name)
    return FileResponse(
        target,
        media_type=content_type,
        headers={
            "Content-Disposition": f'{disposition}; filename="{filename}"',
            # Belt and braces with the app-wide header. These bytes came off a
            # seized disk; a browser must not go looking for a better type than
            # the closed table gave it.
            "X-Content-Type-Options": "nosniff",
            # A recovered object is evidence-derived. It should not sit in a
            # shared cache, and it should not persist in the browser's.
            "Cache-Control": "no-store",
        },
    )
