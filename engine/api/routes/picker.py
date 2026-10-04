"""``/native-picker`` - the desktop window's own file and folder chooser.

pywebview's usual route to the page, ``window.pywebview.api``, is built with
``new Function`` and this app's Content-Security-Policy forbids that
(``script-src 'self'``, deliberately). Weakening the policy for a file dialog
would be the wrong trade, so the chooser is an ordinary same-origin request
instead: it carries the session cookie like every other call and the policy
stays as strict as it was.

The route answers one question - which path did the operator choose - and does
nothing with the answer. Outside the desktop window nothing is registered on
``app.state.native_picker`` and the page falls back to typing the path.
"""

from __future__ import annotations

import asyncio
from typing import Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel

from api.native_picker import NativePicker, PickKind

__all__ = ["router"]

router = APIRouter(tags=["native-picker"])


class PickRequest(BaseModel):
    kind: Literal["file", "files", "folder"]


def _picker(request: Request) -> NativePicker | None:
    picker = getattr(request.app.state, "native_picker", None)
    return picker if isinstance(picker, NativePicker) else None


@router.get("/native-picker")
def availability(request: Request) -> dict[str, bool]:
    """Whether this launch has a native window to open a dialog on."""
    return {"available": _picker(request) is not None}


@router.post("/native-picker")
async def pick(body: PickRequest, request: Request) -> dict[str, list[str]]:
    """Open the dialog and wait for the operator; ``[]`` if cancelled."""
    picker = _picker(request)
    if picker is None:
        return {"paths": []}
    kind: PickKind = body.kind
    # The dialog blocks until the operator answers, so it never runs on the
    # event loop.
    return {"paths": await asyncio.to_thread(picker.pick, kind)}
