"""Protected paths per platform, host facts, and the default state directory."""

from __future__ import annotations

from pathlib import Path

import pytest
from api.deps import default_state_dir
from core.platform import host
from core.platform.paths import LINUX_EXACT, protected_reason

WIN_ENV = {
    "SystemDrive": "D:",
    "SystemRoot": "D:\\Windows",
    "ProgramFiles": "D:\\Program Files",
    "ProgramFiles(x86)": "D:\\Program Files (x86)",
    "ProgramData": "D:\\ProgramData",
    "USERPROFILE": "D:\\Users\\alice",
}


@pytest.mark.parametrize(
    "path",
    [
        "D:\\Windows",
        "d:\\windows\\system32\\drivers\\etc\\hosts",
        "D:\\WINDOWS\\SysWOW64",
        "D:\\Program Files\\Vendor\\app.exe",
        "D:\\ProgramData",
        "D:\\Users",
        "D:\\Users\\alice",
        "D:\\",
        "E:\\",
        "D:\\System Volume Information\\tracking.log",
    ],
)
def test_windows_system_locations_are_refused_case_insensitively(path: str) -> None:
    assert protected_reason(path, "windows", WIN_ENV), path


@pytest.mark.parametrize(
    "path",
    [
        "D:\\Users\\alice\\Documents\\secret.docx",
        "D:\\Users\\alice\\Desktop",
        "E:\\evidence\\copy.bin",
        "D:\\WindowsOld\\notes.txt",
    ],
)
def test_ordinary_windows_files_are_allowed(path: str) -> None:
    assert protected_reason(path, "windows", WIN_ENV) == ""


def test_windows_protection_follows_the_real_system_drive() -> None:
    """Windows installed on D: must not leave D:\\Windows unprotected."""
    assert protected_reason("D:\\Windows\\explorer.exe", "windows", WIN_ENV)
    assert protected_reason("C:\\Windows\\explorer.exe", "windows", {}) != ""


@pytest.mark.parametrize(
    "path",
    [
        "/System/Library/Kernels/kernel",
        "/usr/lib/dyld",
        "/private/var/vm/swapfile0",
        "/",
        "/Users",
        "/Applications",
        "/Library",
    ],
)
def test_macos_system_locations_are_refused(path: str) -> None:
    assert protected_reason(path, "macos")


@pytest.mark.parametrize(
    "path",
    [
        "/Users/alice/Documents/a.pdf",
        "/Volumes/USB/b.jpg",
        "/private/var/folders/xy/T/tmp1",
        "/usr/local/bin/tool",
        "/Library/Caches/x",
    ],
)
def test_ordinary_macos_files_are_allowed(path: str) -> None:
    assert protected_reason(path, "macos") == ""


def test_linux_rules_are_the_historical_exact_list_unchanged() -> None:
    for item in LINUX_EXACT:
        assert protected_reason(item, "linux")
    # Exact, not subtree: the Linux file eraser always allowed these.
    assert protected_reason("/var/tmp/x", "linux") == ""
    assert protected_reason("/home/alice/x", "linux") == ""


def test_family_mapping() -> None:
    assert host.family("linux") == "linux"
    assert host.family("win32") == "windows"
    assert host.family("darwin") == "macos"
    assert host.family("freebsd13") == "other"


@pytest.mark.parametrize(
    ("release", "version", "expected"),
    [
        ("10", "10.0.26100", "Windows 11"),
        ("10", "10.0.19045", "Windows 10"),
        ("11", "10.0.22631", "Windows 11"),
        ("", "", "Windows"),
    ],
)
def test_windows_11_is_told_apart_by_build_number(
    release: str, version: str, expected: str
) -> None:
    assert host.windows_product_name(release, version) == expected


def test_linux_pretty_name() -> None:
    assert host.linux_pretty_name('NAME="Fedora"\nPRETTY_NAME="Fedora Linux 44"\n') == (
        "Fedora Linux 44"
    )
    assert host.linux_pretty_name(None) == "Linux"


def test_privilege_state_comes_from_the_os_on_posix() -> None:
    import os

    if not hasattr(os, "geteuid"):
        pytest.skip("POSIX only")
    state = host.privilege_state(helper="socket", helper_basis="b")
    assert state.elevated is (os.geteuid() == 0)
    assert "geteuid" in state.basis
    assert state.helper == "socket"


def test_platform_info_describes_this_host() -> None:
    import sys

    info = host.platform_info()
    assert info.sys_platform == sys.platform
    assert info.family == host.family()
    assert info.os_name
    assert info.packaged is False


@pytest.mark.parametrize(
    ("platform", "env", "expected_tail"),
    [
        ("win32", {"LOCALAPPDATA": "C:\\Users\\a\\AppData\\Local"}, "Sanctum"),
        ("darwin", {}, "Library/Application Support/Sanctum"),
        ("linux", {}, ".local/share/sanctum"),
        ("linux", {"XDG_DATA_HOME": "/data/xdg"}, "/data/xdg/sanctum"),
    ],
)
def test_default_state_dir_is_the_platform_user_data_dir(
    platform: str, env: dict[str, str], expected_tail: str
) -> None:
    assert (
        str(default_state_dir(env, platform))
        .replace("\\", "/")
        .endswith(expected_tail.replace("\\", "/"))
    )


def test_an_empty_state_dir_variable_is_not_the_current_directory() -> None:
    """``Path("")`` is ``Path(".")``, which is truthy - the historical bug."""
    chosen = default_state_dir({"SANCTUM_STATE_DIR": ""}, "linux")
    assert chosen != Path(".")
    assert chosen.is_absolute()
    assert default_state_dir({"SANCTUM_STATE_DIR": "/srv/s"}, "linux") == Path("/srv/s")


def test_windows_creationflags_asks_for_a_hidden_console_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The console flash a windowed (console=False) packaged app produces for
    any subprocess.run of a console-subsystem child (powershell, git,
    vssadmin, fsutil, ffprobe, ...) - seen for real when clicking a nav item
    that triggers Windows device inventory, 2026-09-27. Every call site that
    might run on Windows must pass this."""
    import subprocess
    import sys

    # CREATE_NO_WINDOW only exists on the real subprocess module on real
    # Windows; raising=False lets this test inject it on every CI host so
    # the assertion below is meaningful there too, not just on Windows.
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    assert host.windows_creationflags() == 0x08000000


def test_windows_creationflags_is_a_no_op_off_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sys

    monkeypatch.setattr(sys, "platform", "linux")
    assert host.windows_creationflags() == 0
    monkeypatch.setattr(sys, "platform", "darwin")
    assert host.windows_creationflags() == 0


def test_git_asks_for_a_hidden_console_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """git (dev-checkout builds only) is a console-subsystem tool too; same
    defect, same fix as core.device._sysio.SubprocessRunner, found in the
    same audit, 2026-09-27."""
    import subprocess
    import sys
    from unittest.mock import patch

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess([], 0, "abc123\n", "")
        host._git(tmp_path, "rev-parse", "HEAD")

    assert mock_run.call_args.kwargs["creationflags"] == 0x08000000
