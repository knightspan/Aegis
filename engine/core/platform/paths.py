"""Paths a file erase must refuse, per platform.

Two kinds of protection, because they protect different things:

* **exact** - the directory itself is refused, its contents are not. Erasing
  ``/home`` would take every user's data with it; erasing ``/home/alice/x``
  is an ordinary request. This is the Linux behaviour the file eraser has
  always had, and it is kept unchanged.
* **subtree** - the directory and everything under it. ``C:\\Windows\\System32``
  and ``/System`` hold nothing an examiner means to shred, and an erase aimed
  inside them is a mistake or an attack on the host.

Windows comparisons are case-insensitive and read the real system locations
from the environment (``SystemRoot``, ``ProgramFiles`` ...), because Windows is
not always installed on ``C:``. A missing variable falls back to the default
location rather than dropping the protection.

Every function here is pure over strings, so the Windows and macOS rules are
tested on any host.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import PurePosixPath, PureWindowsPath

from core.platform.model import PlatformFamily

__all__ = ["protected_prefixes", "protected_reason", "LINUX_EXACT"]

#: The historical Linux list, matched exactly. Unchanged.
LINUX_EXACT = (
    "/",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/lib64",
    "/proc",
    "/sbin",
    "/sys",
    "/usr",
    "/var",
)

_MACOS_EXACT = (
    "/",
    "/Applications",
    "/Library",
    "/Users",
    "/Volumes",
    "/private",
    "/private/etc",
    "/private/var",
    "/usr",
    "/opt",
    "/cores",
)

_MACOS_SUBTREE = (
    "/System",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/libexec",
    "/private/var/vm",
    "/private/var/db",
)


def _windows_locations(env: Mapping[str, str]) -> tuple[list[str], list[str]]:
    drive = (env.get("SystemDrive") or "C:").rstrip("\\/")
    root = env.get("SystemRoot") or env.get("windir") or f"{drive}\\Windows"
    subtree = [
        root,
        env.get("ProgramFiles") or f"{drive}\\Program Files",
        env.get("ProgramFiles(x86)") or f"{drive}\\Program Files (x86)",
        env.get("ProgramW6432") or f"{drive}\\Program Files",
        f"{drive}\\System Volume Information",
        f"{drive}\\Boot",
        f"{drive}\\Recovery",
        f"{drive}\\$WinREAgent",
    ]
    exact = [
        f"{drive}\\",
        env.get("ProgramData") or f"{drive}\\ProgramData",
        f"{drive}\\Users",
        env.get("PUBLIC") or f"{drive}\\Users\\Public",
    ]
    profile = env.get("USERPROFILE")
    if profile:
        exact.append(profile)
    return exact, subtree


def protected_prefixes(
    family: PlatformFamily, env: Mapping[str, str] | None = None
) -> list[str]:
    """Every protected location for ``family``, exact and subtree together."""
    environ = os.environ if env is None else env
    if family == "windows":
        exact, subtree = _windows_locations(environ)
        return exact + subtree
    if family == "macos":
        return list(_MACOS_EXACT + _MACOS_SUBTREE)
    return list(LINUX_EXACT)


def protected_reason(
    path: str, family: PlatformFamily, env: Mapping[str, str] | None = None
) -> str:
    """Why ``path`` must not be erased, or ``""`` when it may be.

    ``path`` should already be resolved: a relative path or an unresolved
    symlink would be compared as written, and the caller is the one that
    knows how to resolve it on the running host.
    """
    environ = os.environ if env is None else env
    if family == "windows":
        target = PureWindowsPath(path)
        if target.parent == target:
            return f"{path} is a drive root."
        exact, subtree = _windows_locations(environ)
        folded = str(target).casefold().rstrip("\\")
        for item in exact:
            if folded == str(PureWindowsPath(item)).casefold().rstrip("\\"):
                return f"{path} is a protected Windows location."
        for item in subtree:
            base = PureWindowsPath(item)
            if target == base or _is_under_windows(target, base):
                return (
                    f"{path} is inside {item}, which the running Windows "
                    "installation needs."
                )
        return ""

    posix_path = PurePosixPath(path)
    if posix_path.parent == posix_path:
        return f"{path} is a filesystem root."
    if family == "macos":
        text = str(posix_path)
        if text in _MACOS_EXACT:
            return f"{path} is a protected macOS location."
        for item in _MACOS_SUBTREE:
            posix_base = PurePosixPath(item)
            # /private/var/folders is where macOS puts per-user temporary
            # directories, and it is not under a protected subtree.
            if posix_path == posix_base or posix_base in posix_path.parents:
                return f"{path} is inside {item}, which macOS needs to run."
        return ""
    if str(posix_path) in LINUX_EXACT:
        return f"{path} is a protected system location."
    return ""


def _is_under_windows(target: PureWindowsPath, base: PureWindowsPath) -> bool:
    folded_base = [part.casefold() for part in base.parts]
    folded_target = [part.casefold() for part in target.parts]
    return (
        len(folded_target) > len(folded_base)
        and folded_target[: len(folded_base)] == folded_base
    )
