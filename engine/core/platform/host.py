"""Host facts: which OS this is, which build of the app, and what it may do.

Each answer comes from the OS, not from a table keyed on ``sys.platform``:
the Windows name is read from the build number the kernel reports, the macOS
version from ``platform.mac_ver``, the Linux distribution from
``/etc/os-release``, and privilege from ``geteuid`` or ``IsUserAnAdmin``. When
a call fails the answer is ``unknown`` with the failure in ``basis``; it is
never guessed.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
from importlib import metadata
from pathlib import Path

import structlog

from core.platform.model import PlatformFamily, PlatformInfo, PrivilegeState

__all__ = [
    "APP_NAME",
    "app_version",
    "build_info",
    "live_source_identity",
    "family",
    "platform_info",
    "privilege_state",
    "windows_product_name",
    "linux_pretty_name",
    "windows_creationflags",
]


def windows_creationflags() -> int:
    """``creationflags=`` for ``subprocess.run()`` that stops a console
    flashing on Windows; ``0`` (a no-op) everywhere else.

    A packaged, windowed (``console=False``) app has no console of its own.
    ``CreateProcess`` then opens a brand new one for any console-subsystem
    child - ``powershell.exe``, ``git``, ``vssadmin``, ``fsutil``,
    ``ffprobe``, anything - because the child needs one and the parent has
    none to give it. That window is visible for the child's whole lifetime
    even though its output is piped and captured; nothing about
    ``capture_output=True`` suppresses it. Every ``subprocess.run`` call this
    project makes that might run on Windows needs this - pass it as
    ``creationflags=windows_creationflags()`` (not ``**kwargs``: mypy cannot
    resolve ``subprocess.run``'s overloads against a splatted dict, and
    ``creationflags`` is in every overload's signature regardless of
    platform, so a plain ``int`` keyword is both correct and simpler).

    ``CREATE_NO_WINDOW`` does not exist off Windows, so it is looked up only
    inside the ``win32`` branch, with a fallback so a test that simulates
    ``win32`` on another host cannot crash on the lookup itself.
    """
    if sys.platform == "win32":
        return int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return 0


logger = structlog.get_logger(__name__)

APP_NAME = "Sanctum"
_DIST_NAME = "sanctum-forensics"

#: Windows 11 kept the 10.0 kernel version; the build number is what separates
#: them. 22000 is the first Windows 11 release build.
_WINDOWS_11_FIRST_BUILD = 22000


def family(sys_platform: str | None = None) -> PlatformFamily:
    """Map ``sys.platform`` onto the four families the adapters implement."""
    value = sys_platform if sys_platform is not None else sys.platform
    if value.startswith("linux"):
        return "linux"
    if value == "win32":
        return "windows"
    if value == "darwin":
        return "macos"
    return "other"


def app_version() -> str:
    """The installed distribution's version, or ``0.0.0`` from a raw checkout."""
    try:
        return metadata.version(_DIST_NAME)
    except metadata.PackageNotFoundError:
        return "0.0.0"


def windows_product_name(release: str, version: str) -> str:
    """``Windows 11`` or ``Windows 10`` from ``platform.win32_ver``.

    ``platform.release()`` returns ``10`` on Windows 11 under many Python
    builds, so the build number is authoritative.
    """
    try:
        build = int(version.split(".")[2]) if version.count(".") >= 2 else 0
    except ValueError:
        build = 0
    if release in {"10", "11"} and build >= _WINDOWS_11_FIRST_BUILD:
        return "Windows 11"
    if release:
        return f"Windows {release}"
    return "Windows"


def linux_pretty_name(os_release: str | None) -> str:
    """``PRETTY_NAME`` from ``/etc/os-release``, or ``Linux``."""
    if not os_release:
        return "Linux"
    for line in os_release.splitlines():
        if line.startswith("PRETTY_NAME="):
            value = line.split("=", 1)[1].strip().strip('"').strip("'")
            if value:
                return value
    return "Linux"


_REPO_ROOT = Path(__file__).resolve().parents[2]


def _git(root: Path, *argv: str) -> str:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ("git", *argv), cwd=root, capture_output=True, text=True,
            check=False, timeout=15, creationflags=windows_creationflags(),
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout.strip() if completed.returncode == 0 else ""


def live_source_identity(root: Path | None = None) -> dict[str, str]:
    """The commit this source tree is at *now*, or empty outside a checkout."""
    where = root or _REPO_ROOT
    if not (where / ".git").exists():
        return {}
    head = _git(where, "rev-parse", "HEAD")
    if not head:
        return {}
    dirty = bool(_git(where, "status", "--porcelain", "--untracked-files=no"))
    return {
        "commit": head + ("+dirty" if dirty else ""),
        "branch": _git(where, "rev-parse", "--abbrev-ref", "HEAD"),
    }


def build_info(path: Path | None = None, root: Path | None = None) -> dict[str, str]:
    """The one authoritative build identity, for ``/health`` and every screen.

    A packaged build reads the record ``packaging/build_info.py`` wrote into it.
    A source checkout reads the git tree it is running from. The record is a
    generated, untracked file, so in a checkout it can outlive the commit it
    describes; it is then **ignored, and said to be ignored**, rather than
    shown as this code's identity. Empty when neither source can say.
    """
    target = path or Path(__file__).with_name("build_info.json")
    try:
        loaded = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        loaded = None
    recorded = (
        {str(k): str(v) for k, v in loaded.items()} if isinstance(loaded, dict) else {}
    )
    if getattr(sys, "frozen", False):
        return recorded
    live = live_source_identity(root)
    if not live:
        return recorded
    recorded_commit = recorded.get("commit", "").removesuffix("+dirty")
    if recorded_commit and live["commit"].removesuffix("+dirty") == recorded_commit:
        return {**recorded, "commit": live["commit"]}
    identity = {**live, "source": "git checkout (live)"}
    if recorded_commit:
        identity["ignored_stale_build_record"] = recorded["commit"]
    return identity


def platform_info() -> PlatformInfo:
    """Describe this host."""
    fam = family()
    machine = platform.machine()
    packaged = bool(getattr(sys, "frozen", False))
    if fam == "windows":
        release, version, _csd, _ptype = platform.win32_ver()
        return PlatformInfo(
            family=fam,
            os_name=windows_product_name(release, version),
            os_version=release,
            os_build=version,
            machine=machine,
            app_version=app_version(),
            packaged=packaged,
            sys_platform=sys.platform,
            build=build_info(),
        )
    if fam == "macos":
        release = platform.mac_ver()[0]
        return PlatformInfo(
            family=fam,
            os_name=f"macOS {release}".strip(),
            os_version=release,
            os_build=platform.release(),
            machine=machine,
            app_version=app_version(),
            packaged=packaged,
            sys_platform=sys.platform,
            build=build_info(),
        )
    os_release: str | None
    try:
        os_release = Path("/etc/os-release").read_text(encoding="utf-8")
    except OSError:
        os_release = None
    return PlatformInfo(
        family=fam,
        os_name=linux_pretty_name(os_release) if fam == "linux" else platform.system(),
        os_version=platform.release(),
        os_build=platform.release(),
        machine=machine,
        app_version=app_version(),
        packaged=packaged,
        sys_platform=sys.platform,
        build=build_info(),
    )


def _windows_is_admin() -> tuple[bool | None, str]:
    """``shell32.IsUserAnAdmin``: whether this token is elevated."""
    try:
        import ctypes

        windll = getattr(ctypes, "windll", None)
        if windll is None:
            return None, "ctypes.windll is unavailable, so elevation is unknown"
        return bool(windll.shell32.IsUserAnAdmin()), "shell32.IsUserAnAdmin()"
    except (OSError, AttributeError) as exc:
        return None, f"IsUserAnAdmin could not be called ({exc})"


def privilege_state(
    *, helper: str = "in-process", helper_basis: str = ""
) -> PrivilegeState:
    """Whether this process is elevated, and how privileged work is reached."""
    fam = family()
    helper_mode = helper if helper in {"socket", "in-process", "none"} else "none"
    if fam == "windows":
        elevated, basis = _windows_is_admin()
        return PrivilegeState(
            level=(
                "administrator"
                if elevated
                else "standard"
                if elevated is False
                else "unknown"
            ),
            elevated=elevated,
            basis=basis,
            helper=helper_mode,
            helper_basis=helper_basis,
        )
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return PrivilegeState(
            level="unknown",
            elevated=None,
            basis="os.geteuid is unavailable on this platform",
            helper=helper_mode,
            helper_basis=helper_basis,
        )
    euid = int(geteuid())
    return PrivilegeState(
        level="root" if euid == 0 else "standard",
        elevated=euid == 0,
        basis=f"os.geteuid() returned {euid}",
        helper=helper_mode,
        helper_basis=helper_basis,
    )
