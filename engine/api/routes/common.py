"""Shared dependencies and error translation for the routers.

The services object is stashed on ``app.state`` at creation and read back
through :func:`get_services`. That is what lets one process host two
independently configured apps, which the test suite needs and a module-level
singleton would prevent.

:func:`sanctum_error_response` is the reason the API can be thin. Every core
exception already carries a ``remediation`` written by whoever implemented the
operation, and this hands that sentence to the client **verbatim**. An API that
rewrote it would be inventing advice about a subsystem it does not implement,
and the operator would read the API author's guess instead of the library
author's instruction.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import HTTPException, Request

from api.deps import AppServices

__all__ = [
    "get_services",
    "sanctum_error_response",
    "resolve_output_path",
    "STATUS_FOR_ERROR",
]

#: HTTP status per core exception. A refusal is 409 rather than 400: the
#: request was well formed and the *state of the world* is what made it
#: unacceptable, which is what 409 means. A 400 would suggest the operator
#: mistyped something they can fix in the body.
STATUS_FOR_ERROR: dict[str, int] = {
    "ConfirmationMismatch": 409,
    "WorkflowGateRefused": 409,
    "MountedRefused": 409,
    "SystemDiskRefused": 409,
    "DeviceFrozen": 409,
    "DeviceVanished": 410,
    "UnsupportedCapability": 422,
    "PlatformUnsupported": 501,
    "EvidenceIntegrityError": 422,
    # 404 rather than 410: the report was never generated, as opposed to having
    # existed and gone. The endpoint used to answer this case with somebody
    # else's report and a green tick.
    "ReportNotFound": 404,
    "LedgerChainBroken": 500,
    "SignatureInvalid": 422,
    # The key is missing a passphrase or is unsafely permissioned. 503 rather
    # than 500: the server is fine, a precondition for this operation is not,
    # and the remediation names it.
    "KeyPassphraseMissing": 503,
    "KeyPermissionsUnsafe": 503,
    # Another writer held the ledger lock past the retry bound. 503 for the
    # same reason as the key errors: the request was fine, a shared resource
    # was not available, and the entry was not written.
    "LedgerBusy": 503,
    # A report was asked for a job that has not reached a terminal state. 409:
    # the request is well formed and the state of the job is what refuses it.
    "JobNotFinished": 409,
    # A report was asked for a job this process holds no record of - never
    # submitted, or forgotten by a restart. Not the same verdict as running.
    "JobNotKnown": 404,
    # The case does not exist. 404, like any other missing resource.
    "CaseNotFound": 404,
    # The case id is illegal, or a case with that id already exists. 409: the
    # request is well formed and the state of the world is what refuses it.
    "CaseRefused": 409,
    # An artifact request named a root that is not served, walked out of the
    # one it named, or pointed at something that is not a regular file. The
    # status travels on the exception because the three cases differ.
    "ArtifactRefused": 400,
    # A resume was asked for a job that cannot be resumed - a firmware
    # sanitize, or an overwrite that never reached a checkpoint. 409: the
    # request is well formed and the state of the world refuses it.
    "ResumeNotAvailable": 409,
    # A destruction dated after this machine's clock. 422: the body is well
    # formed, and its content cannot be true.
    "DestructionDateInFuture": 422,
}


def get_services(request: Request) -> AppServices:
    """The process's services, from ``app.state``."""
    services: AppServices = request.app.state.services
    return services


def sanctum_error_response(kind: str, message: str, remediation: str) -> HTTPException:
    """Turn a core or helper error into an HTTP error, remediation intact."""
    detail: dict[str, Any] = {
        "error": message,
        "kind": kind,
        # Verbatim. The operator reads the sentence the library author wrote.
        "remediation": remediation,
    }
    return HTTPException(status_code=STATUS_FOR_ERROR.get(kind, 400), detail=detail)


def resolve_output_path(root: Path, candidate: str, *, field: str) -> Path:
    """Resolve ``candidate`` and refuse it unless it lands inside ``root``.

    The API takes destination paths from a request body and has no
    authentication of any kind, so an unchecked ``dest`` is a write-anything
    primitive available to any local process that can open the port. Its blast
    radius is whatever the API process can write - which the demo runbook used
    to make *root*, by starting the API under ``sudo``. Confining the write to a
    directory the deployment configured turns "anywhere this process can write"
    into "one directory the operator chose", which is the part this layer can
    fix on its own; the missing authentication is not, and is recorded as a
    finding rather than papered over here.

    A relative path is taken as relative to ``root``, so the common case needs
    no absolute path at all. An absolute path is accepted only if it is inside
    ``root``.

    Symlinks are resolved **before** the comparison, not after, so a link
    planted inside the output directory cannot point the write out of it. That
    is the check that makes this a boundary rather than a string prefix test.

    Raises:
        HTTPException: 400, naming the directory the deployment allows.
    """
    base = root.resolve()
    requested = Path(candidate)
    target = (base / requested if not requested.is_absolute() else requested).resolve()
    if target != base and base not in target.parents:
        raise sanctum_error_response(
            "OutputPathRefused",
            f"Refusing to write {field}={candidate!r}: it resolves to {target}, "
            f"which is outside the configured output directory {base}. "
            "Nothing was created.",
            f"Pass a path inside {base}, or a relative path - it is taken as "
            "relative to that directory. Set SANCTUM_STATE_DIR to move it.",
        )
    return target
