"""The native file/folder chooser the desktop window offers the page."""

from __future__ import annotations

from typing import Any

import pytest
from api.native_picker import NativePicker

OPEN, FOLDER = 10, 20


class FakeWindow:
    """Stands in for a pywebview window; records the dialog it was asked for."""

    def __init__(self, answer: Any = None, error: Exception | None = None) -> None:
        self.answer = answer
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def create_file_dialog(self, dialog_type: int, **kw: Any) -> Any:
        self.calls.append({"dialog_type": dialog_type, **kw})
        if self.error is not None:
            raise self.error
        return self.answer


def _picker(window: FakeWindow | None) -> NativePicker:
    return NativePicker(lambda: window, open_dialog=OPEN, folder_dialog=FOLDER)


def test_one_file_opens_the_open_dialog_without_multi_select() -> None:
    window = FakeWindow(("/evidence/case.dd",))
    assert _picker(window).pick("file") == ["/evidence/case.dd"]
    assert window.calls == [{"dialog_type": OPEN, "allow_multiple": False}]


def test_several_files_allow_multi_select() -> None:
    window = FakeWindow(("/a/one.txt", "/a/two.txt"))
    assert _picker(window).pick("files") == ["/a/one.txt", "/a/two.txt"]
    assert window.calls == [{"dialog_type": OPEN, "allow_multiple": True}]


def test_a_folder_opens_the_folder_dialog() -> None:
    window = FakeWindow(["/run/media/me/VOLUME"])
    assert _picker(window).pick("folder") == ["/run/media/me/VOLUME"]
    assert window.calls[0]["dialog_type"] == FOLDER
    assert window.calls[0]["allow_multiple"] is False


def test_a_cancelled_dialog_returns_nothing() -> None:
    assert _picker(FakeWindow(None)).pick("file") == []
    assert _picker(FakeWindow(())).pick("folder") == []


def test_a_failing_dialog_returns_nothing_instead_of_raising() -> None:
    assert _picker(FakeWindow(error=RuntimeError("no display"))).pick("file") == []


def test_no_window_returns_nothing() -> None:
    assert _picker(None).pick("file") == []


def test_an_unknown_kind_is_refused_and_opens_no_dialog() -> None:
    window = FakeWindow(("/x",))
    with pytest.raises(ValueError, match="kind"):
        _picker(window).pick("device")  # type: ignore[arg-type]
    assert window.calls == []


def test_only_absolute_string_paths_are_returned() -> None:
    window = FakeWindow(("/ok/file", "relative/file", 7, ""))
    assert _picker(window).pick("files") == ["/ok/file"]


def test_the_page_can_call_nothing_but_pick() -> None:
    public = {name for name in dir(_picker(None)) if not name.startswith("_")}
    assert public == {"pick"}
