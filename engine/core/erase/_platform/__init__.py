"""Selects one platform backend for this host, once.

Importing this package is safe on every platform: the OS-specific module is
imported lazily inside :func:`backend`, so a Windows-only module is never
parsed on Linux and vice versa.
"""

from __future__ import annotations

import sys
from functools import lru_cache

from core.erase._platform.base import (
    UNSUPPORTED,
    Flags,
    PlatformBackend,
    PortableBackend,
)

__all__ = ["Flags", "PlatformBackend", "PortableBackend", "UNSUPPORTED", "backend"]


@lru_cache(maxsize=1)
def backend() -> PlatformBackend:
    """The backend for this host. Never raises: worst case is PortableBackend.

    An ImportError from an OS-specific module falls back rather than
    propagating. A missing capability must degrade the report, never stop an
    erase from running at all.
    """
    if sys.platform == "win32":  # pragma: no cover - exercised on Windows
        try:
            from core.erase._platform.win import WindowsBackend

            return WindowsBackend()
        except ImportError:
            return PortableBackend()
    if sys.platform in {"linux", "darwin"}:
        try:
            from core.erase._platform.posix import PosixBackend

            return PosixBackend()
        except ImportError:  # pragma: no cover - stdlib only, should not happen
            return PortableBackend()
    return PortableBackend()  # pragma: no cover - no such CI platform
