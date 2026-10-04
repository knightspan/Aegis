"""Platform capability seam.

One rule governs every method here: **a backend never raises for a capability
the platform does not have.** It returns the unknown value (``None``, ``[]``,
``0``) together with a sentence saying why, and that sentence reaches the
report.

A module that raised instead would force every caller into ``try``/``except``
and would tempt someone into swallowing the exception and reporting ``False``,
which is the tool claiming a guarantee it does not have. The difference between
"this volume has no snapshots" and "nobody could ask this volume about
snapshots" is the difference between an operator deleting a file and an
operator deleting a file plus three snapshots, so it must survive all the way
into the report.

Every method returns ``(value, limitations)``. The limitations accumulate into
:attr:`~core.models.FileInspection.limitations` and are rendered verbatim.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from core.models import Extent

__all__ = ["Flags", "PlatformBackend", "PortableBackend", "UNSUPPORTED"]

UNSUPPORTED = "This platform exposes no API for it, so it was not determined."


@dataclass(frozen=True)
class Flags:
    """Per-file filesystem flags. ``None`` means the platform could not say."""

    sparse: bool | None = None
    compressed: bool | None = None
    encrypted: bool | None = None
    immutable: bool | None = None


class PlatformBackend(Protocol):
    """Everything the erase path needs from the operating system.

    Implemented once per OS family. :class:`PortableBackend` is both the
    fallback for an unrecognised platform and the base class the real backends
    inherit, so adding a capability method here can never silently break an OS
    that cannot implement it - it inherits the honest unknown.
    """

    name: str

    def fs_type(self, path: Path) -> tuple[str, list[str]]: ...

    def cluster_bytes(self, path: Path) -> tuple[int, list[str]]: ...

    def extents(self, path: Path) -> tuple[list[Extent], list[str]]: ...

    def is_resident(self, path: Path) -> tuple[bool | None, list[str]]: ...

    def alt_data_streams(self, path: Path) -> tuple[list[str], list[str]]: ...

    def xattrs(self, path: Path) -> tuple[list[str], list[str]]: ...

    def flags(self, path: Path) -> tuple[Flags, list[str]]: ...

    def cow_snapshots(self, path: Path) -> tuple[list[str] | None, list[str]]: ...

    def vss_shadows(self, path: Path) -> tuple[list[str] | None, list[str]]: ...

    def trim_likely(self, path: Path) -> tuple[bool | None, list[str]]: ...

    def clear_immutable(self, path: Path) -> tuple[bool, str]: ...

    def open_unbuffered_write(self, path: Path) -> tuple[int, bool, list[str]]: ...

    def fsync_dir(self, path: Path) -> tuple[bool, str]: ...

    def block_device_for(self, path: Path) -> tuple[str | None, list[str]]: ...


class PortableBackend:
    """Answers every platform question with an honest unknown.

    Used on platforms with no specific backend, and inherited by the real ones.
    """

    name = "portable"

    def fs_type(self, path: Path) -> tuple[str, list[str]]:
        return "", [f"Filesystem type for {path} was not determined. {UNSUPPORTED}"]

    def cluster_bytes(self, path: Path) -> tuple[int, list[str]]:
        return 0, [
            f"Cluster size for {path} was not determined, so file slack cannot "
            f"be computed. {UNSUPPORTED}"
        ]

    def extents(self, path: Path) -> tuple[list[Extent], list[str]]:
        return [], [
            f"No physical extent map was captured for {path}, so a post-erase "
            "physical read cannot be performed and the overwrite cannot be "
            f"independently verified. {UNSUPPORTED}"
        ]

    def is_resident(self, path: Path) -> tuple[bool | None, list[str]]:
        return None, [
            f"Whether {path} stores its data resident in a filesystem metadata "
            f"record was not determined. {UNSUPPORTED}"
        ]

    def alt_data_streams(self, path: Path) -> tuple[list[str], list[str]]:
        # An empty list rather than an unknown: alternate data streams are an
        # NTFS feature, and on a filesystem that has no such concept "none
        # exist" is a fact rather than a guess.
        return [], []

    def xattrs(self, path: Path) -> tuple[list[str], list[str]]:
        names = getattr(os, "listxattr", None)
        if names is None:
            return [], []
        try:
            return list(names(path, follow_symlinks=False)), []
        except OSError as exc:
            return [], [f"Extended attributes on {path} could not be listed: {exc}."]

    def flags(self, path: Path) -> tuple[Flags, list[str]]:
        return Flags(), [f"Filesystem flags for {path} were not read. {UNSUPPORTED}"]

    def cow_snapshots(self, path: Path) -> tuple[list[str] | None, list[str]]:
        return None, [
            f"Whether snapshots reference {path}'s old extents was not "
            f"determined. {UNSUPPORTED}"
        ]

    def vss_shadows(self, path: Path) -> tuple[list[str] | None, list[str]]:
        # Volume Shadow Copy is a Windows service. Elsewhere there is nothing
        # to ask, so an empty list is honest; the Windows backend overrides
        # this with None when it cannot ask (which is the usual case: no admin).
        return [], []

    def trim_likely(self, path: Path) -> tuple[bool | None, list[str]]:
        return None, [
            f"Whether the volume holding {path} issues TRIM was not "
            f"determined. {UNSUPPORTED}"
        ]

    def clear_immutable(self, path: Path) -> tuple[bool, str]:
        return False, f"No immutable attribute was cleared on {path}. {UNSUPPORTED}"

    def open_unbuffered_write(self, path: Path) -> tuple[int, bool, list[str]]:
        """Open for writing. Returns ``(fd, reaches_medium, limitations)``.

        ``reaches_medium`` is False when the platform offers no write-through
        flag, which means bytes may still be in a cache when the write returns.
        The caller fsyncs regardless; the flag decides whether a limitation is
        recorded saying so.
        """
        flag = getattr(os, "O_SYNC", 0) or getattr(os, "O_DSYNC", 0)
        fd = os.open(path, os.O_WRONLY | getattr(os, "O_BINARY", 0) | flag)
        if flag:
            return fd, True, []
        return (
            fd,
            False,
            [
                f"Writes to {path} were buffered: this platform offers no "
                "write-through open flag here, so bytes may not have reached "
                "the medium before the call returned."
            ],
        )

    def fsync_dir(self, path: Path) -> tuple[bool, str]:
        """Flush a directory's own entry, so a rename is durable.

        Correct on POSIX and impossible on Windows, which is why the Windows
        backend overrides it with a recorded limitation rather than a silent
        no-op.
        """
        try:
            fd = os.open(path, os.O_RDONLY)
        except OSError as exc:
            return False, (
                f"The directory {path} could not be opened for fsync ({exc}), "
                "so the rename chain may not be durable on disk."
            )
        try:
            os.fsync(fd)
        except OSError as exc:
            return False, f"fsync on directory {path} failed: {exc}."
        finally:
            os.close(fd)
        return True, ""

    def block_device_for(self, path: Path) -> tuple[str | None, list[str]]:
        """The raw device holding ``path``, for a physical verification read."""
        return None, [
            f"The block device holding {path} was not identified, so the "
            f"original physical blocks cannot be read back. {UNSUPPORTED}"
        ]
