"""``/native-picker``: the dialog is served over HTTP, not the pywebview bridge."""

from __future__ import annotations

from typing import Any

from api.main import SECURITY_HEADERS, create_app
from api.native_picker import NativePicker
from fastapi.testclient import TestClient

OPEN, FOLDER = 10, 20


class FakeWindow:
    def __init__(self, answer: Any) -> None:
        self.answer = answer
        self.calls: list[dict[str, Any]] = []

    def create_file_dialog(self, dialog_type: int, **kw: Any) -> Any:
        self.calls.append({"dialog_type": dialog_type, **kw})
        return self.answer


def _client(window: FakeWindow | None, tmp_path: Any) -> TestClient:
    app = create_app(state_dir=tmp_path, serve_ui=False, session_token="")
    if window is not None:
        app.state.native_picker = NativePicker(
            lambda: window, open_dialog=OPEN, folder_dialog=FOLDER
        )
    return TestClient(app, base_url="http://127.0.0.1")


def test_without_a_native_window_the_picker_is_unavailable(tmp_path: Any) -> None:
    client = _client(None, tmp_path)
    assert client.get("/native-picker").json() == {"available": False}
    assert client.post("/native-picker", json={"kind": "file"}).json() == {"paths": []}


def test_with_a_native_window_the_chosen_paths_come_back(tmp_path: Any) -> None:
    window = FakeWindow(("/evidence/case.dd",))
    client = _client(window, tmp_path)
    assert client.get("/native-picker").json() == {"available": True}
    answer = client.post("/native-picker", json={"kind": "folder"})
    assert answer.json() == {"paths": ["/evidence/case.dd"]}
    assert window.calls == [{"dialog_type": FOLDER, "allow_multiple": False}]


def test_a_cancelled_dialog_is_an_empty_list(tmp_path: Any) -> None:
    client = _client(FakeWindow(None), tmp_path)
    assert client.post("/native-picker", json={"kind": "file"}).json() == {"paths": []}


def test_an_unknown_kind_is_refused(tmp_path: Any) -> None:
    client = _client(FakeWindow(("/a",)), tmp_path)
    assert client.post("/native-picker", json={"kind": "save"}).status_code == 422


def test_the_policy_that_blocks_the_pywebview_bridge_stays_strict() -> None:
    # The bridge needs 'unsafe-eval'. The picker exists so that never has to
    # be granted.
    assert "'unsafe-eval'" not in SECURITY_HEADERS["Content-Security-Policy"]
