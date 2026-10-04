"""Filesystem capability registry: detect, read, erase, metadata, free space, drive.

**Detecting a filesystem is not supporting it.** Every filesystem here has six
separate rows, and a cell is filled from the code that implements (or refuses)
that operation, not from whether the name is recognised:

``detect``
    The platform's file backend names the filesystem of a path
    (:meth:`core.erase._platform.base.PlatformBackend.fs_type`): ``/proc/mounts``
    on Linux, ``GetVolumeInformationW`` on Windows, ``statfs`` on macOS. A
    filesystem the OS cannot mount cannot be detected on a live path.
``read``
    Forensic recovery from an image (M3). Undelete is implemented for the
    filesystems :mod:`core.carve.fsaware` parses; everything else is signature
    carving only. Recovery reads images, so the host OS does not change the
    answer - but it has only been exercised on Linux, and the cells say so.
``erase_files``
    :mod:`core.erase.files` over a mounted, writable volume. Always *with
    limitations*: journals, copy-on-write and flash remapping all keep copies.
    On a copy-on-write filesystem the overwrite lands in new blocks.
``metadata``
    Filesystem metadata the erase can disturb: the name (rename chain), the
    size (truncation), the timestamps. Directory-index slack and journals keep
    older copies; the residual report lists them.
``free_space``
    :mod:`core.erase.freespace`, from its own ``SUPPORTED`` table and platform
    gate.
``whole_drive``
    Filesystem-independent: the device is erased, not the filesystem. The cell
    is the platform's whole-drive status.
"""

from __future__ import annotations

from core.platform.model import CapabilityStatus, FilesystemSupport

__all__ = ["registry", "FILESYSTEMS", "PLATFORMS"]

S = CapabilityStatus.SUPPORTED
L = CapabilityStatus.SUPPORTED_WITH_LIMITATIONS
U = CapabilityStatus.UNSUPPORTED
V = CapabilityStatus.UNVERIFIED
N = CapabilityStatus.NOT_VERIFIABLE

PLATFORMS = ("linux", "windows", "macos")

#: Family name -> ``sys.platform``, for gates written against the latter.
_SYS_PLATFORM = {"linux": "linux", "windows": "win32", "macos": "darwin"}

#: name -> (linux kernel name, windows name, macos name); ``""`` = not mountable
#: read-write there, so no live path on it can be detected or erased.
_NATIVE: dict[str, tuple[str, str, str]] = {
    "NTFS": ("ntfs3", "NTFS", "ntfs"),
    "FAT32": ("vfat", "FAT32", "msdos"),
    "exFAT": ("exfat", "exFAT", "exfat"),
    "ext4": ("ext4", "", ""),
    "XFS": ("xfs", "", ""),
    "Btrfs": ("btrfs", "", ""),
    "APFS": ("", "", "apfs"),
    "HFS+": ("hfsplus", "", "hfs"),
    "ReFS": ("", "ReFS", ""),
    "F2FS": ("f2fs", "", ""),
}

#: Filesystems :mod:`core.carve.fsaware` undeletes from; the rest are carved.
_UNDELETE = frozenset({"NTFS", "FAT32", "exFAT", "ext4"})
#: Copy-on-write: overwrite lands beside the old data, never on it.
_COW = frozenset({"Btrfs", "APFS", "ReFS", "F2FS"})

#: Mountable, but only read-only by the OS itself: detected, never erased.
_READ_ONLY = frozenset({("NTFS", "macos")})

FILESYSTEMS = tuple(_NATIVE)


def _drive_status(platform: str) -> CapabilityStatus:
    """Whole-drive clear is filesystem-independent; this is its platform word.

    Linux has a physically validated run (usb-flash); Windows and macOS have
    an engine that no physical run has exercised. Per-device answers come
    from the capability resolver, not from this table.
    """
    return L if platform == "linux" else CapabilityStatus.UNVERIFIED


def registry() -> list[FilesystemSupport]:
    """Every filesystem, six rows each, one cell per platform."""
    from core.erase.freespace import FREE_SPACE_PLATFORMS, SUPPORTED
    from core.platform.validation import load_record, suite_passed

    record = load_record()
    free_names = set(SUPPORTED.values())
    rows: list[FilesystemSupport] = []
    for name, natives in _NATIVE.items():
        cells: dict[str, dict[str, CapabilityStatus]] = {
            key: {}
            for key in (
                "detect",
                "read",
                "erase_files",
                "metadata",
                "free_space",
                "whole_drive",
            )
        }
        for platform, native in zip(PLATFORMS, natives, strict=True):
            mountable = bool(native)
            cells["detect"][platform] = S if mountable else U
            if suite_passed(platform, "recovery", record):
                cells["read"][platform] = S if name in _UNDELETE - {"ext4"} else L
            else:
                cells["read"][platform] = V
            erase_validated = suite_passed(platform, "file_erase", record)
            if not mountable or (name, platform) in _READ_ONLY:
                cells["erase_files"][platform] = U
                cells["metadata"][platform] = U
            elif name in _COW:
                cells["erase_files"][platform] = N
                cells["metadata"][platform] = L
            elif erase_validated:
                cells["erase_files"][platform] = L
                cells["metadata"][platform] = L
            else:
                cells["erase_files"][platform] = V
                cells["metadata"][platform] = V
            cells["free_space"][platform] = (
                L
                if _SYS_PLATFORM[platform] in FREE_SPACE_PLATFORMS
                and name in free_names
                else U
            )
            cells["whole_drive"][platform] = _drive_status(platform)
        notes = {
            "detect": "Named by the platform's file backend on a mounted path.",
            "read": (
                "Undelete from filesystem records plus signature carving."
                if name in _UNDELETE
                else "Signature carving only; no undelete for this filesystem."
            )
            + " UNVERIFIED where the recovery suite has not been recorded as "
            "passing on that platform.",
            "erase_files": (
                "Copy-on-write: the overwrite is written to new blocks, so the "
                "old content is released, not destroyed, and cannot be verified."
                if name in _COW
                else "In-place overwrite, rename chain, truncate, delete; "
                "journal and flash remapping are reported as residuals. "
                "UNVERIFIED where the platform's file-erase suite has not been "
                "recorded as passing."
            ),
            "metadata": "Name, size and timestamps are disturbed; journal and "
            "directory-index copies are reported, not removed.",
            "free_space": "Implemented and measured for "
            + ", ".join(sorted(free_names))
            + " on Linux only.",
            "whole_drive": "Filesystem-independent; decided per device by the "
            "capability resolver. Linux: core.erase.drive, physically validated "
            "on USB flash. Windows and macOS: core.erase.blockclear, implemented, "
            "not physically validated.",
        }
        rows.append(FilesystemSupport(filesystem=name, cells=cells, notes=notes))
    return rows
