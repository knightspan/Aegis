"""The privilege boundary, the API's front door, and the file-erase walk.

* The helper stamps how privileged work is reached; a request cannot claim it.
* On a platform with no whole-drive engine, ``run_erase`` refuses through the
  adapter and the Linux engine is never reached.
* The API refuses a non-loopback ``Host`` (DNS rebinding) and, when the
  launcher configured a session token, anything without the session cookie.
* A folder erase never descends through a link or a Windows junction.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from api.deps import default_services
from api.main import create_app
from api.security import SESSION_COOKIE, host_allowed
from core.errors import PlatformUnsupported
from fastapi.testclient import TestClient
from helper.daemon import HelperDaemon, InProcessHelper
from helper.rpc import RpcError

from tests._loopback import LOOPBACK_BASE_URL

from .conftest import FakeRunner, ok, windows_api_for

# --------------------------------------------------------------------------
# Helper boundary
# --------------------------------------------------------------------------


def test_helper_mode_is_stamped_by_the_daemon_never_taken_from_the_request(
    tmp_path: Path,
) -> None:
    uid = int(getattr(os, "getuid", lambda: -1)())
    in_process = HelperDaemon(operator_uid=uid)
    socket_daemon = HelperDaemon(operator_uid=uid, state_dir=tmp_path)

    assert in_process.apply_policy({"helper_mode": "socket"})["helper_mode"] == (
        "in-process"
    )
    assert socket_daemon.apply_policy({"helper_mode": "in-process"})["helper_mode"] == (
        "socket"
    )


def test_platform_status_is_served_through_the_allowlist(
    no_host_discovery: None,
) -> None:
    answer = InProcessHelper().call("platform_status", {"helper_mode": "socket"})

    assert answer["privilege"]["helper"] == "in-process", (
        "the request's claim is ignored"
    )
    assert {row["operation"] for row in answer["operations"]} >= {
        "file_erase",
        "whole_drive_clear",
        "device_discovery",
    }
    assert all(row["source"] for row in answer["operations"])


def test_run_erase_on_a_platform_without_an_engine_never_reaches_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.platform.base import BaseAdapter

    monkeypatch.setattr(
        "core.platform.current_adapter", lambda **kw: BaseAdapter(**kw)
    )
    reached: list[str] = []
    monkeypatch.setattr(
        "core.platform.linux.LinuxAdapter.execute_drive_sanitization",
        lambda self, params: reached.append("engine"),
    )

    helper = InProcessHelper()
    with pytest.raises(RpcError) as excinfo:
        list(
            helper.call_stream(
                "run_erase",
                {
                    "path": "disk9",
                    "typed_serial": "X",
                    "ledger_root": "l",
                    "job_id": "j",
                },
            )
        )
    assert excinfo.value.kind == "PlatformUnsupported"
    assert "No operation was performed" in str(excinfo.value)
    assert reached == []
    with pytest.raises(RpcError, match="No operation was performed"):
        helper.call("probe_capabilities", {"path": "disk9"})


def test_a_real_windows_erase_without_authorization_opens_nothing(
    monkeypatch: pytest.MonkeyPatch, windows_inventory: dict[str, Any]
) -> None:
    """Windows has an engine now; the write seam's authorization still comes first."""
    from core.platform.windows import WindowsAdapter

    runner = FakeRunner(lambda argv: ok(argv, json.dumps(windows_inventory)))
    api = windows_api_for(windows_inventory)
    monkeypatch.setattr(
        "core.platform.current_adapter",
        lambda **kw: WindowsAdapter(runner=runner, native=api, **kw),
    )
    helper = InProcessHelper()
    with pytest.raises(RpcError) as excinfo:
        list(
            helper.call_stream(
                "run_erase",
                {
                    "path": "PhysicalDrive2",
                    "typed_serial": "E0D55EA574E2F4B1",
                    "ledger_root": "l",
                    "job_id": "j",
                },
            )
        )
    assert excinfo.value.kind == "WorkflowGateRefused"
    assert "no authorization" in str(excinfo.value)
    assert runner.calls == [], "refused before discovery ran"
    assert api.calls == []
    probe = helper.call("probe_capabilities", {"path": "PhysicalDrive2"})
    assert probe["device"]["serial"] == "E0D55EA574E2F4B1"


def test_assess_device_rereads_the_device_now(
    monkeypatch: pytest.MonkeyPatch, windows_inventory: dict[str, Any]
) -> None:
    from core.platform.windows import WindowsAdapter

    runner = FakeRunner(lambda argv: ok(argv, json.dumps(windows_inventory)))
    api = windows_api_for(windows_inventory)
    monkeypatch.setattr(
        "core.platform.current_adapter",
        lambda **kw: WindowsAdapter(runner=runner, native=api, **kw),
    )
    helper = InProcessHelper()

    first = helper.call("assess_device", {"path": "PhysicalDrive2"})
    second = helper.call("assess_device", {"path": "E0D55EA574E2F4B1"})

    assert first["normalized"]["id"] == second["normalized"]["id"] == "PhysicalDrive2"
    assert len(runner.calls) == 2, "each assessment re-ran discovery"
    with pytest.raises(RpcError) as excinfo:
        helper.call("assess_device", {"path": "PhysicalDrive9"})
    assert excinfo.value.kind == "DeviceVanished"


def test_the_linux_adapter_raises_platform_unsupported_off_linux(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reason on a non-Linux host comes from the engine's own import guard."""
    from core.platform.linux import LinuxAdapter

    def refuse(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "core.erase.drive":
            raise PlatformUnsupported("needs Linux block-device semantics")
        return real_import(name, *args, **kwargs)

    import builtins

    real_import = builtins.__import__
    monkeypatch.setattr(builtins, "__import__", refuse)
    assert "Linux" in LinuxAdapter().whole_drive_unavailable_reason()


# --------------------------------------------------------------------------
# API front door
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "allowed"),
    [
        ("127.0.0.1:8787", True),
        ("localhost:8787", True),
        ("LOCALHOST", True),
        ("[::1]:8787", True),
        ("evil.example:8787", False),
        ("127.0.0.1.evil.example", False),
        ("", False),
        (None, False),
    ],
)
def test_host_check(header: str | None, allowed: bool) -> None:
    assert host_allowed(header) is allowed


def _app(tmp_path: Path, token: str = "") -> Any:
    services = default_services(state_dir=tmp_path)
    return create_app(services=services, serve_ui=False, session_token=token)


def test_a_rebinding_host_is_refused_before_any_route(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path), base_url="http://evil.example:8787") as client:
        response = client.get("/health")
    assert response.status_code == 400
    assert response.json()["kind"] == "HostRefused"
    assert response.headers["x-frame-options"] == "DENY", "refusals keep the headers"


def test_without_a_token_only_the_host_is_checked(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path), base_url=LOOPBACK_BASE_URL) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/health").json()["session_protected"] is False


def test_with_a_token_only_the_launched_window_gets_in(tmp_path: Path) -> None:
    token = "t" * 43
    with TestClient(_app(tmp_path, token), base_url=LOOPBACK_BASE_URL) as client:
        refused = client.get("/health")
        assert refused.status_code == 401
        assert refused.json()["kind"] == "SessionRequired"

        wrong = client.get("/session/" + "x" * 43, follow_redirects=False)
        assert wrong.status_code == 403
        assert SESSION_COOKIE not in wrong.cookies

        opened = client.get(f"/session/{token}", follow_redirects=False)
        assert opened.status_code == 303
        cookie = opened.headers["set-cookie"].lower()
        assert "httponly" in cookie and "samesite=strict" in cookie

        client.cookies.set(SESSION_COOKIE, token)
        assert client.get("/health").status_code == 200
        assert client.get("/health").json()["session_protected"] is True
        assert client.post("/jobs/erase-files", json={"paths": []}).status_code != 401


def test_the_platform_route_answers(tmp_path: Path, no_host_discovery: None) -> None:
    with TestClient(_app(tmp_path), base_url=LOOPBACK_BASE_URL) as client:
        answer = client.get("/platform").json()
    assert answer["platform"]["family"] in {"linux", "windows", "macos", "other"}
    assert answer["operations"]
    assert answer["filesystems"]


# --------------------------------------------------------------------------
# File-erase walk
# --------------------------------------------------------------------------


def test_a_reparse_attribute_alone_marks_a_directory_as_a_link() -> None:
    """Windows junctions: a directory, not a symlink, and a reparse point."""
    import stat
    from types import SimpleNamespace

    from core.erase.files import _stat_is_link_or_reparse

    junction = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_file_attributes=0x400)
    plain = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_file_attributes=0x10)
    link = SimpleNamespace(st_mode=stat.S_IFLNK | 0o777)

    assert _stat_is_link_or_reparse(junction) is True  # type: ignore[arg-type]
    assert _stat_is_link_or_reparse(plain) is False  # type: ignore[arg-type]
    assert _stat_is_link_or_reparse(link) is True  # type: ignore[arg-type]


@pytest.mark.skipif(
    sys.platform == "win32",
    reason=(
        "simulated here through the stat check; Windows runs the real thing "
        "in tests/platform/test_windows_filesystem.py, where a DirEntry's "
        "st_ino is 0 and this simulation cannot work"
    ),
)
def test_a_folder_erase_does_not_descend_through_a_junction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Simulate a junction: a real directory the stat check reports as reparse.

    Without the attribute check, a walk trusting ``is_dir(follow_symlinks=
    False)`` descends into it and queues everything behind it for erasure.
    """
    from core.erase import files

    root = tmp_path / "case"
    (root / "junction").mkdir(parents=True)
    (root / "junction" / "outside.txt").write_text("not yours")
    (root / "mine.txt").write_text("erase me")
    real = files._stat_is_link_or_reparse

    def fake(info: os.stat_result) -> bool:
        return real(info) or info.st_ino == (root / "junction").stat().st_ino

    monkeypatch.setattr(files, "_stat_is_link_or_reparse", fake)

    targets = files.expand_targets([root])

    assert root / "junction" / "outside.txt" not in targets
    assert root / "junction" in targets, "emitted as itself, for erase_one to refuse"
    assert root / "mine.txt" in targets


def test_a_symlinked_directory_is_not_descended(tmp_path: Path) -> None:
    from core.erase.files import expand_targets

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep")
    root = tmp_path / "case"
    root.mkdir()
    try:
        (root / "link").symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    targets = expand_targets([root])

    assert outside / "keep.txt" not in targets
    assert root / "link" / "keep.txt" not in targets
    assert expand_targets([root / "link"]) == [root / "link"]


# --------------------------------------------------------------------------
# Desktop launcher
# --------------------------------------------------------------------------


def test_the_launcher_uses_a_private_loopback_port_and_a_session_url() -> None:
    from api.desktop import free_loopback_port, session_url, wait_for_health

    port = free_loopback_port()
    assert 1024 < port < 65536
    assert session_url(port, "tok") == f"http://127.0.0.1:{port}/session/tok"
    assert wait_for_health(port, "tok", timeout_s=0.3) is False


@pytest.mark.parametrize(
    "stdout_missing, stderr_missing",
    [
        pytest.param(True, True, id="both-none"),
        pytest.param(True, False, id="stdout-only-none"),
        pytest.param(False, True, id="stderr-only-none"),
    ],
)
def test_launcher_gives_logging_somewhere_to_write_when_there_is_no_console(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stdout_missing: bool,
    stderr_missing: bool,
) -> None:
    """A frozen windowed build (``console=False`` on Windows and macOS,
    ``packaging/sanctum.spec``) has no console. Opened the only way a real
    user opens it - a double-click, the Start menu, the Dock - Python leaves
    ``sys.stdout``/``sys.stderr`` as ``None``. structlog's builtin default
    logger factory was built once, at import time, with ``file=None``, and
    falls back to ``structlog._output.stdout`` - itself captured with
    ``from sys import stdout`` at *that* module's own import time - so
    reassigning ``sys.stdout`` later never reaches it. The first structured
    log call anywhere then builds a ``PrintLogger(file=None)`` and crashes
    with ``TypeError: cannot create weak reference to 'NoneType' object``
    before the server ever starts (seen for real on installed Windows
    hardware, 2026-09-27; independently reproduced and fixed end to end on
    the rebuilt package the same day). Configuring structlog explicitly,
    with a real file, sidesteps the stale default instead of racing its
    import order.

    This is a mechanism-level test: it forces ``sys.stdout``/``sys.stderr``
    to ``None`` directly rather than launching a real windowed process, so
    it runs the same on any host pytest runs on. It is deliberately *not* a
    genuine macOS GUI launch - the underlying Python behaviour once a stream
    is ``None`` is platform-independent, but no macOS hardware backs this
    parametrization; only the three ``sys.std*`` combinations a frozen
    Windows or macOS process can actually present are covered.
    """
    import structlog
    from api.desktop import _ensure_logging_has_somewhere_to_write

    if stdout_missing:
        monkeypatch.setattr(sys, "stdout", None)
    if stderr_missing:
        monkeypatch.setattr(sys, "stderr", None)
    original_config = structlog.get_config()
    try:
        _ensure_logging_has_somewhere_to_write(tmp_path)

        assert sys.stdout is not None
        assert sys.stderr is not None

        log_file = tmp_path / "logs" / "launcher.log"
        assert log_file.is_file()

        # structlog is now explicitly configured, not left on the stale
        # default - true regardless of which stream(s) were missing.
        factory = structlog.get_config()["logger_factory"]
        assert isinstance(factory, structlog.PrintLoggerFactory)
        assert factory._file is not None
        assert factory._file.name == str(log_file)

        # The actual crash: building a PrintLogger from whatever structlog
        # is now configured to use must not raise, even though a stream was
        # None a moment ago. WARNING, not INFO: the suite's own
        # pytest_configure() filters below WARNING.
        structlog.get_logger("regression-check").warning("post_fix_smoke")
        assert "post_fix_smoke" in log_file.read_text(encoding="utf-8")
    finally:
        structlog.configure(**original_config)


def test_ensure_logging_is_a_no_op_with_a_real_console(
    tmp_path: Path,
) -> None:
    """The dev path (``python -m api.main``) and the Linux package
    (``console=True``) always have real streams; nothing here should touch
    them or write a log file that was never asked for."""
    from api.desktop import _ensure_logging_has_somewhere_to_write

    real_stdout, real_stderr = sys.stdout, sys.stderr

    _ensure_logging_has_somewhere_to_write(tmp_path)

    assert sys.stdout is real_stdout
    assert sys.stderr is real_stderr
    assert not (tmp_path / "logs").exists()


def test_quit_is_refused_unless_the_launcher_started_the_app(tmp_path: Path) -> None:
    with TestClient(_app(tmp_path), base_url=LOOPBACK_BASE_URL) as client:
        assert client.post("/app/quit").status_code == 422
        assert client.get("/health").json()["launcher"] is False

    import threading

    app = _app(tmp_path / "launched", token="t" * 43)
    stop = threading.Event()
    app.state.quit_event = stop
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        assert client.post("/app/quit").status_code == 401, "needs the session"
        client.cookies.set(SESSION_COOKIE, "t" * 43)
        assert client.post("/app/quit").json() == {"quitting": True}
    assert stop.is_set()


# --------------------------------------------------------------------------
# Session protection, in depth
# --------------------------------------------------------------------------


def test_the_development_server_protects_itself_by_default() -> None:
    """Loopback is not an authorisation boundary on a shared machine."""
    from api.main import dev_session_token

    generated, basis = dev_session_token({})
    assert basis == "generated"
    assert len(generated) >= 32
    assert dev_session_token({})[0] != generated, "a token per start, not a constant"

    supplied, basis = dev_session_token({"SANCTUM_SESSION_TOKEN": "mine"})
    assert (supplied, basis) == ("mine", "environment")

    off, basis = dev_session_token({"SANCTUM_DEV_INSECURE": "1"})
    assert (off, basis) == ("", "insecure")


@pytest.mark.parametrize(
    ("cookie", "expected"),
    [
        (None, 401),
        ("", 401),
        ("wrong-token-entirely", 401),
        ("t" * 42, 401),
        ("T" * 43, 401),
    ],
)
def test_every_wrong_session_cookie_is_refused(
    tmp_path: Path, cookie: str | None, expected: int
) -> None:
    token = "t" * 43
    with TestClient(_app(tmp_path, token), base_url=LOOPBACK_BASE_URL) as client:
        if cookie is not None:
            client.cookies.set(SESSION_COOKIE, cookie)
        for path in ("/health", "/platform", "/devices", "/ledger/verify"):
            assert client.get(path).status_code == expected, path
        assert (
            client.post("/jobs/erase-files", json={"paths": []}).status_code == expected
        )


def test_a_token_from_a_previous_launch_does_not_open_the_next_one(
    tmp_path: Path,
) -> None:
    """Each launch mints its own; a stale URL from a closed window is useless."""
    first, second = "a" * 43, "b" * 43
    with TestClient(_app(tmp_path, first), base_url=LOOPBACK_BASE_URL) as client:
        client.cookies.set(SESSION_COOKIE, first)
        assert client.get("/health").status_code == 200

    with TestClient(
        _app(tmp_path / "next", second), base_url=LOOPBACK_BASE_URL
    ) as client:
        client.cookies.set(SESSION_COOKIE, first)
        assert client.get("/health").status_code == 401
        assert (
            client.get(f"/session/{first}", follow_redirects=False).status_code == 403
        )
        client.cookies.set(SESSION_COOKIE, second)
        assert client.get("/health").status_code == 200


def test_a_cross_origin_page_cannot_use_the_session(tmp_path: Path) -> None:
    """The cookie is SameSite=Strict, and the Host check is the other half.

    A page on another origin cannot make the browser send this cookie, and a
    rebinding page that reaches the port arrives with its own Host and is
    refused before routing - both checked here.
    """
    token = "c" * 43
    with TestClient(_app(tmp_path, token), base_url=LOOPBACK_BASE_URL) as client:
        opened = client.get(f"/session/{token}", follow_redirects=False)
        assert "samesite=strict" in opened.headers["set-cookie"].lower()

        client.cookies.set(SESSION_COOKIE, token)
        rebinding = client.get(
            "/devices",
            headers={"Host": "attacker.example", "Origin": "http://attacker.example"},
        )
        assert rebinding.status_code == 400
        assert rebinding.json()["kind"] == "HostRefused"


def test_the_session_link_is_the_only_way_in(tmp_path: Path) -> None:
    token = "d" * 43
    with TestClient(_app(tmp_path, token), base_url=LOOPBACK_BASE_URL) as client:
        assert client.get("/session/", follow_redirects=False).status_code == 403
        assert client.get("/session/x", follow_redirects=False).status_code == 403
        assert (
            client.get(f"/session/{token}", follow_redirects=False).status_code == 303
        )
