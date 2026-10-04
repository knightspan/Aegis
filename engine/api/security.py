"""Two checks in front of every route: who is asking, and by what name.

Binding 127.0.0.1 keeps the network out. It does not keep out two things that
are already on the machine, and both matter for an API that can erase files:

**DNS rebinding.** A web page from ``evil.example`` can make the browser
resolve that name to ``127.0.0.1`` and then talk to this API *as the same
origin*, with none of the cross-origin protection a browser normally applies.
The request still arrives with ``Host: evil.example:8787``. Every request
whose ``Host`` is not a loopback name is refused, which is the whole defence
and costs nothing.

**Other local accounts and processes.** Loopback is shared by every account on
the host. When the desktop launcher starts the API it generates a random
session token, passes it in ``SANCTUM_SESSION_TOKEN``, and opens the window at
``/session/<token>``. That one request sets an ``HttpOnly``, ``SameSite=Strict``
cookie, and from then on every request must carry it. A process that did not
receive the token from the launcher - another user's, or a page in some other
browser tab - gets 401 and nothing else. The comparison is constant-time.

When no token is configured (development with ``make run``, and the test
suite) only the host check applies, exactly as before this module existed.
"""

from __future__ import annotations

import hmac
from collections.abc import Awaitable, Callable, Iterable

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

__all__ = [
    "LOOPBACK_NAMES",
    "SESSION_COOKIE",
    "install",
    "host_allowed",
]

#: Host names a loopback-bound server is legitimately addressed by.
LOOPBACK_NAMES = frozenset({"127.0.0.1", "localhost", "[::1]", "::1"})

SESSION_COOKIE = "sanctum_session"
_SESSION_PREFIX = "/session/"


def _hostname(header: str) -> str:
    """``Host`` header without its port. IPv6 literals keep their brackets."""
    value = header.strip().lower()
    if value.startswith("["):
        end = value.find("]")
        return value[: end + 1] if end != -1 else value
    return value.rsplit(":", 1)[0] if ":" in value else value


def host_allowed(header: str | None, allowed: Iterable[str] = LOOPBACK_NAMES) -> bool:
    """Whether a ``Host`` header names this loopback server."""
    if not header:
        return False
    return _hostname(header) in set(allowed)


def _refusal(status: int, error: str, kind: str, remediation: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": error, "kind": kind, "remediation": remediation},
    )


def install(
    app: FastAPI,
    *,
    session_token: str = "",
    allowed_hosts: Iterable[str] = LOOPBACK_NAMES,
) -> None:
    """Add the host check, and the session check when a token is configured."""
    hosts = frozenset(name.lower() for name in allowed_hosts)
    token = session_token.strip()

    @app.middleware("http")
    async def _guard(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if not host_allowed(request.headers.get("host"), hosts):
            return _refusal(
                400,
                "Refused: this API answers only to a loopback host name.",
                "HostRefused",
                "Open the app through 127.0.0.1 or localhost. A request "
                "addressed to any other name is treated as DNS rebinding.",
            )
        if not token:
            return await call_next(request)

        path = request.url.path
        if path.startswith(_SESSION_PREFIX):
            offered = path[len(_SESSION_PREFIX) :]
            if not hmac.compare_digest(offered.encode(), token.encode()):
                return _refusal(
                    403,
                    "Refused: that session link is not valid for this launch.",
                    "SessionRefused",
                    "Close this window and start Sanctum again from its launcher.",
                )
            response = RedirectResponse("/", status_code=303)
            response.set_cookie(
                SESSION_COOKIE,
                token,
                httponly=True,
                samesite="strict",
                secure=False,  # plain http on loopback; the cookie never leaves it
                path="/",
            )
            return response

        presented = request.cookies.get(SESSION_COOKIE, "")
        if not presented or not hmac.compare_digest(presented.encode(), token.encode()):
            return _refusal(
                401,
                "Refused: this request did not come from the Sanctum window.",
                "SessionRequired",
                "Start Sanctum from its launcher. The API accepts requests only "
                "from the window the launcher opened.",
            )
        return await call_next(request)
