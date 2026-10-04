"""Pre-erase inspection. Read-only, and it drives every decision that follows.

:func:`inspect_path` runs before a single byte is written. Everything the erase
path decides -- whether to overwrite at all, which streams to clear, what the
residual scanner will be told -- comes from the :class:`FileInspection` it
returns.

**The extent map can only be captured here.** Once the file is unlinked there is
no handle left that maps to those physical blocks, so a map taken afterwards
does not exist and verification would have nothing to read back. That single
fact is why inspection is a separate phase rather than something the overwrite
does on its way past.

The function is named ``inspect_path`` rather than ``inspect`` so it never
shadows the standard library module in a caller's namespace.
"""

from __future__ import annotations

import stat as stat_mod
from pathlib import Path

import structlog

from core.erase._platform import backend
from core.models import FileInspection

__all__ = ["inspect_path", "SYNC_DIR_MARKERS", "in_sync_directory"]

logger = structlog.get_logger(__name__)

#: Path components that mean the file is very likely mirrored somewhere else.
#: Matched case-insensitively against the resolved path's parts. A cloud-synced
#: file is the commonest way a "shredded" document survives: the local copy goes
#: and the provider's version history keeps it.
SYNC_DIR_MARKERS = (
    "onedrive",
    "dropbox",
    "google drive",
    "googledrive",
    "icloud drive",
    "com~apple~clouddocs",
    "nextcloud",
    "owncloud",
    "sync.com",
    "box sync",
    "pcloud",
    "mega",
    "yandexdisk",
)

#: Windows file attribute for a reparse point (junction, symlink, mount point).
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400


def in_sync_directory(path: Path) -> bool:
    """Whether any component of ``path`` names a known cloud-sync directory."""
    try:
        parts = Path(path).resolve().parts
    except OSError:  # pragma: no cover - a resolve that fails is not a sync dir
        parts = Path(path).parts
    lowered = [part.lower() for part in parts]
    return any(marker in part for part in lowered for marker in SYNC_DIR_MARKERS)


def inspect_path(path: Path | str) -> FileInspection:
    """Everything knowable about ``path`` before anything is written to it.

    Never writes, never follows a link, and never raises for a capability the
    platform lacks: an unknown comes back as ``None`` with a sentence saying
    why, and that sentence reaches the report.
    """
    target = Path(path)
    host = backend()
    limitations: list[str] = []

    try:
        stat = target.lstat()
    except OSError as exc:
        return FileInspection(
            path=str(target),
            size_bytes=0,
            limitations=[f"{target} could not be stat'd: {exc}."],
        )

    is_reparse = bool(
        int(getattr(stat, "st_file_attributes", 0)) & FILE_ATTRIBUTE_REPARSE_POINT
    ) or stat_mod.S_ISLNK(stat.st_mode)

    if is_reparse:
        # Stop here, deliberately. Following the link would inspect - and
        # later erase - a file the operator did not name. Unlinking a junction
        # someone pointed at by mistake destroys nothing but reports that it
        # did, which is the more dangerous outcome.
        return FileInspection(
            path=str(target),
            size_bytes=int(stat.st_size),
            is_reparse_point=True,
            hardlink_count=int(stat.st_nlink),
            limitations=[
                f"{target} is a link or reparse point. Its target was not "
                "examined and will not be erased; erase the target by name if "
                "that is what was intended."
            ],
        )

    fs_type, limits = host.fs_type(target)
    limitations.extend(limits)
    cluster_bytes, limits = host.cluster_bytes(target)
    limitations.extend(limits)
    resident, limits = host.is_resident(target)
    limitations.extend(limits)
    extents, limits = host.extents(target)
    limitations.extend(limits)
    streams, limits = host.alt_data_streams(target)
    limitations.extend(limits)
    xattrs, limits = host.xattrs(target)
    limitations.extend(limits)
    flags, limits = host.flags(target)
    limitations.extend(limits)
    snapshots, limits = host.cow_snapshots(target)
    limitations.extend(limits)
    shadows, limits = host.vss_shadows(target)
    limitations.extend(limits)
    trim, limits = host.trim_likely(target)
    limitations.extend(limits)

    synced = in_sync_directory(target)
    if synced:
        limitations.append(
            f"{target} lies under a directory that a cloud-sync client mirrors. "
            "The provider very likely holds a copy, and its version history may "
            "hold several; erasing the local file does not reach any of them."
        )

    inspection = FileInspection(
        path=str(target),
        size_bytes=int(stat.st_size),
        fs_type=fs_type,
        cluster_bytes=cluster_bytes,
        is_resident=resident,
        extents=extents,
        is_sparse=flags.sparse,
        is_compressed=flags.compressed,
        is_encrypted=flags.encrypted,
        hardlink_count=int(stat.st_nlink),
        alt_data_streams=streams,
        xattrs=xattrs,
        is_immutable=flags.immutable,
        is_reparse_point=False,
        cow_snapshots=snapshots,
        vss_shadow_ids=shadows,
        # None stays None: "nobody could ask" must not become "there are none".
        vss_present=None if shadows is None else bool(shadows),
        trim_likely=trim,
        in_sync_directory=synced,
        limitations=limitations,
    )

    logger.info(
        "file_inspected",
        path=str(target),
        fs_type=fs_type,
        resident=resident,
        streams=len(streams),
        extents=len(extents),
        hardlinks=inspection.hardlink_count,
    )
    return inspection
