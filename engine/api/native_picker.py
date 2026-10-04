"""The native file and folder chooser the desktop window offers the page.

The page cannot learn where a file lives from a browser file input, so the
desktop window hands it this object through the pywebview bridge. It answers
one question - which path did the operator choose - and does nothing with the
answer: no read, no open, no approval. The path lands in a text field and goes
through the same validation as a path the operator typed.

Only :meth:`NativePicker.pick` is public. pywebview exposes every public
attribute of the bridge object to the page, so anything else stays private.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any, Literal

import structlog

__all__ = ["NativePicker", "PickKind"]

logger = structlog.get_logger(__name__)

PickKind = Literal["file", "files", "folder"]


class NativePicker:
    """Opens the operating system's own file dialog on the app window."""

    def __init__(
        self,
        get_window: Callable[[], Any],
        *,
        open_dialog: int,
        folder_dialog: int,
    ) -> None:
        self._get_window = get_window
        self._open_dialog = open_dialog
        self._folder_dialog = folder_dialog

    def pick(self, kind: PickKind) -> list[str]:
        """Absolute paths the operator chose; ``[]`` if none, or none possible.

        A cancelled dialog, a missing window and a dialog that failed to open
        all return ``[]``: the field the page fills stays as it was.
        """
        if kind not in ("file", "files", "folder"):
            raise ValueError(f"unknown picker kind {kind!r}")
        window = self._get_window()
        if window is None:
            logger.warning("native_picker_no_window", kind=kind)
            return []
        dialog = self._folder_dialog if kind == "folder" else self._open_dialog
        try:
            chosen = window.create_file_dialog(
                dialog, allow_multiple=kind == "files"
            )
        except Exception as exc:  # noqa: BLE001 - a toolkit failure must not reach the page
            logger.warning("native_picker_failed", kind=kind, error=str(exc))
            return []
        return [
            item
            for item in (chosen or ())
            if isinstance(item, str) and os.path.isabs(item)
        ]
