"""FastAPI application factory.

The API layer is unprivileged and non-blocking. Every long operation is run on
a worker thread by :mod:`api.jobs` and streamed by :mod:`api.sse`, never
executed inline in a request handler: a four-terabyte overwrite is hours long
and an HTTP request that lived that long would be dead well before the work was.

Two deployment properties, both enforced here rather than documented and hoped
for:

**It binds 127.0.0.1 and nothing else.** :func:`run` passes the loopback
address explicitly. An erase console reachable from the network is a remote
wipe primitive, and no authentication scheme this project could ship would make
that a good trade.

**It serves the UI from disk with no outbound requests.** The built bundle is
mounted as static files and every asset it needs is inside it. There is no CDN
link, no external font, no analytics beacon and no telemetry, so the whole
thing works with the ethernet unplugged - which is the state a forensic
workstation should be in and the state the venue may put it in regardless.

Run with ``python -m api.main`` or
``uvicorn api.main:create_app --factory --host 127.0.0.1``.
"""

from __future__ import annotations

import os
import secrets
import sys
import traceback
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import structlog
from core.platform.host import build_info
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from api.deps import AppServices, default_services, signing_key_limitations
from api.routes import all_routers
from api.security import install as install_security

__all__ = ["create_app", "run", "dev_session_token", "UI_DIST", "LOOPBACK_HOST"]

logger = structlog.get_logger(__name__)

#: The only address this application is ever served on.
LOOPBACK_HOST = "127.0.0.1"
DEFAULT_PORT = 8787

#: Where ``npm run build`` puts the bundle.
UI_DIST = Path(__file__).resolve().parents[1] / "ui" / "dist"

#: Sent on every response. `default-src 'self'` is the one that matters: it
#: makes an accidental CDN link fail loudly in the browser console rather than
#: silently work on the developer's machine and break at the venue.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'none'; "
        "frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}


def create_app(
    *,
    services: AppServices | None = None,
    state_dir: Path | None = None,
    serve_ui: bool = True,
    session_token: str | None = None,
) -> FastAPI:
    """Build and return the configured FastAPI application.

    ``session_token`` defaults to ``SANCTUM_SESSION_TOKEN``, which only the
    desktop launcher sets. See :mod:`api.security`.
    """
    app = FastAPI(
        title="Sanctum Forensics",
        version="0.0.0",
        description=(
            "Local-only control surface for secure sanitization and forensic "
            "recovery. Binds 127.0.0.1; every privileged operation goes through "
            "the helper daemon."
        ),
        # No external docs assets: FastAPI's default Swagger UI is loaded from
        # a CDN, which is exactly what must not happen here.
        docs_url=None,
        redoc_url=None,
    )
    app.state.services = services or default_services(state_dir=state_dir)

    for router in all_routers():
        app.include_router(router)

    # Registered before the header middleware so it runs *inside* it: a
    # refusal still carries the security headers.
    install_security(
        app,
        session_token=(
            session_token
            if session_token is not None
            else os.environ.get("SANCTUM_SESSION_TOKEN", "")
        ),
    )

    @app.middleware("http")
    async def _security_headers(request: Request, call_next: Any) -> Any:
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        return response

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        # Neither the traceback nor the message reaches the client.
        #
        # The traceback never did. The *message* used to: the body was
        # f"{type(exc).__name__}: {exc}", and the exceptions that reach this
        # handler are the ones nobody anticipated - an OSError whose str() is
        # "[Errno 13] Permission denied: '/var/lib/sanctum/ledger/chain.jsonl'",
        # a KeyError naming an internal field, a pikepdf error quoting a path
        # inside the evidence tree. Every one of those describes this host to
        # whatever opened the socket. An error a layer *did* anticipate carries
        # a remediation its author wrote and is returned verbatim by
        # sanctum_error_response long before it could arrive here; reaching
        # this handler means no such sentence exists, so there is nothing to
        # pass through and an incident id is the honest thing to hand back.
        #
        # The full message and type are logged server-side, against that id, so
        # the operator loses nothing but the person reading the response is not
        # told the filesystem layout.
        incident = uuid.uuid4().hex[:12]
        logger.warning(
            "api_unhandled",
            incident=incident,
            path=request.url.path,
            error=str(exc),
            kind=type(exc).__name__,
            traceback=traceback.format_exc(limit=8),
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": (
                    "The request failed for a reason this layer did not "
                    f"anticipate. Incident {incident}."
                ),
                "kind": "InternalError",
                "incident": incident,
                "remediation": (
                    "The failure was logged on the server with this incident "
                    f"id. Search the API log for {incident!r} to see what went "
                    "wrong; the message is withheld here because an "
                    "unanticipated error usually quotes a host path."
                ),
            },
        )

    @app.get("/health")
    def health() -> dict[str, Any]:
        state: AppServices = app.state.services
        return {
            "status": "ok",
            "tool_version": state.tool_version,
            "state_dir": str(state.state_dir),
            "ui_bundled": UI_DIST.is_dir(),
            # What this build is, from packaging/build_info.py. Empty from a
            # source checkout, where there is no build to identify.
            "build": build_info(),
            "launcher": getattr(app.state, "quit_event", None) is not None,
            "session_protected": bool(
                session_token
                if session_token is not None
                else os.environ.get("SANCTUM_SESSION_TOKEN", "")
            ),
            # Computed per request: the key and the chain can both come into
            # existence after startup, and the second one is permanent.
            "limitations": state.limitations + signing_key_limitations(state),
        }

    @app.post("/app/quit")
    def quit_app() -> dict[str, Any]:
        """Stop a launcher-started app. Refused everywhere else.

        Only :mod:`api.desktop` sets ``quit_event``, and it only ever runs
        with a session token, so the request that reaches this already
        carried the window's cookie. A server started any other way has no
        event and answers 409: ``make run`` is stopped from its terminal.
        """
        event = getattr(app.state, "quit_event", None)
        if event is None:
            from api.routes.common import sanctum_error_response

            raise sanctum_error_response(
                "UnsupportedCapability",
                "This server was not started by the desktop launcher.",
                "Stop it from the terminal that started it.",
            )
        event.set()
        return {"quitting": True}

    if serve_ui and UI_DIST.is_dir():
        assets = UI_DIST / "assets"
        if assets.is_dir():
            app.mount("/assets", StaticFiles(directory=assets), name="assets")

        @app.get("/", include_in_schema=False)
        def index() -> FileResponse:
            return FileResponse(UI_DIST / "index.html")

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str) -> FileResponse:
            """Serve a bundled file, falling back to the SPA entry point.

            The fallback is what lets a deep link survive a reload: the router
            is client-side, so ``/recovery`` is not a file and must return the
            app shell rather than a 404.
            """
            candidate = (UI_DIST / path).resolve()
            if candidate.is_file() and UI_DIST.resolve() in candidate.parents:
                return FileResponse(candidate)
            return FileResponse(UI_DIST / "index.html")

    logger.info("api_ready", ui_bundled=UI_DIST.is_dir())
    return app


def dev_session_token(
    environ: Mapping[str, str] | None = None,
) -> tuple[str, str]:
    """The token ``python -m api.main`` serves with, and how it was decided.

    The development server used to have no session protection at all: it bound
    loopback, and every other process and account on the machine could drive
    it, including the endpoints that erase files. Loopback is not an
    authorisation boundary on a shared machine.

    So it now behaves like the packaged app by default - a token per start,
    printed as the one URL that opens it. Two escape hatches, both explicit:
    ``SANCTUM_SESSION_TOKEN`` supplies your own (for a script that needs a
    stable one), and ``SANCTUM_DEV_INSECURE=1`` turns it off and says loudly
    what that means.
    """
    env: Mapping[str, str] = os.environ if environ is None else environ
    if env.get("SANCTUM_DEV_INSECURE") == "1":
        return "", "insecure"
    existing = (env.get("SANCTUM_SESSION_TOKEN") or "").strip()
    if existing:
        return existing, "environment"
    return secrets.token_urlsafe(32), "generated"


def run() -> None:  # pragma: no cover - the process entry point
    """Serve on loopback only, with a session token unless told otherwise."""
    import uvicorn

    port = int(os.environ.get("SANCTUM_PORT", DEFAULT_PORT))
    token, basis = dev_session_token()
    banner = [
        "",
        "  Sanctum development server",
        f"  Address     http://{LOOPBACK_HOST}:{port}  (loopback only; never a "
        "wildcard address)",
    ]
    if token:
        banner += [
            f"  Open this   http://{LOOPBACK_HOST}:{port}/session/{token}",
            "  Session     one token for this run"
            + (" (from SANCTUM_SESSION_TOKEN)" if basis == "environment" else ""),
            "              every request without its cookie is refused",
        ]
    else:
        banner += [
            "  Session     OFF (SANCTUM_DEV_INSECURE=1)",
            "  WARNING     any process or account on this machine can drive",
            "              this server, including the endpoints that erase",
            "              files. Development machines only.",
        ]
    banner.append("")
    print("\n".join(banner), file=sys.stderr)

    uvicorn.run(
        create_app(session_token=token),
        host=LOOPBACK_HOST,
        port=port,
        log_level="info",
    )


if __name__ == "__main__":  # pragma: no cover
    run()
