"""Free-space wipe for a mounted volume (M2). Destructive: every call writes.

What it does: creates one directory of its own on the volume, fills the volume's
unallocated space with :data:`FILL_BYTE` through files in that directory until
the filesystem answers ``ENOSPC``, forces every file to disk, and deletes the
files and the directory. **It creates, writes and deletes nothing else.** Every
other file on the volume is evidence, and nothing here opens one.

Why filling to ``ENOSPC`` covers the free space regardless of the allocator: the
filesystem hands out every block it can before it refuses, whatever order it
searches in. Every allocator measured here is next-fit - a file written after a
deletion did not land on the freed clusters - which is exactly why a partial
fill is worth nothing and a fill to ``ENOSPC`` is required. Measured on kernel
``vfat`` (512 and 4096-byte clusters), ``exfat`` (4096 and 32768) and ``ext4``
(4096) over udisks loop devices; see ``docs/limitations.md``.

What it does not reach, and says so in every result (:data:`NOT_REACHED`): blocks
the filesystem reserves for root, which an unprivileged ``ENOSPC`` leaves free
and unwritten; file slack inside other files' last clusters; deleted directory
entries; journals and filesystem metadata; and, on flash, pages the translation
layer has remapped. Nothing is read back, so ``verified`` is always ``None``.

**Only filesystems whose behaviour was measured are accepted** (:data:`SUPPORTED`).
Anything else - NTFS, copy-on-write filesystems, FUSE - is refused rather than
wiped on an assumption.

**The pattern is 0xA5, not zero.** Some flash controllers acknowledge a zero fill
without programming the cells (``docs/limitations.md``, "Some controllers do not
program a zero fill at all"); a non-zero byte has to be written.

Two entry points. :func:`plan_volume` is read-only: it resolves the volume,
applies every refusal and reports the identifier the operator must type.
:func:`wipe_free_space` always fills; there is no non-writing mode.

Linux only: the volume is identified from ``/proc/mounts``.
"""

from __future__ import annotations

import errno
import os
import sys
from collections.abc import Generator, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from core.device import guard
from core.errors import PlatformUnsupported, UnsupportedCapability
from core.models import (
    FreeSpaceWipeOptions,
    FreeSpaceWipeResult,
    Progress,
    VolumeInfo,
)

if TYPE_CHECKING:  # pragma: no cover - import cycle avoidance only
    from core.ledger.chain import Ledger

__all__ = [
    "FILL_BYTE",
    "FILL_FILE_BYTES",
    "NOT_REACHED",
    "SUPPORTED",
    "FREE_SPACE_PLATFORMS",
    "plan_volume",
    "resolve_volume",
    "wipe_free_space",
]

logger = structlog.get_logger(__name__)

MIB = 1024 * 1024

#: The fill pattern. Non-zero on purpose; see the module docstring.
FILL_BYTE = 0xA5

#: One filler file never exceeds this. FAT32 cannot hold a file of 4 GiB.
FILL_FILE_BYTES = 1024 * MIB

#: Write size for the main fill.
_WRITE_BYTES = 1 * MIB

#: Extra empty filler entries created before any data is written, beyond one per
#: FILL_FILE_BYTES of free space. Creating the entries first grows the filler
#: directory before the fill, not in the middle of it: the fragment plant learned
#: on FAT32 that a directory growing mid-fill lands a directory cluster between
#: data clusters and can fail with ENOSPC when a new name is needed.
_SPARE_ENTRIES = 32

#: Kernel filesystem types whose fill behaviour has been measured, and the name
#: this module reports for each.
SUPPORTED = {"vfat": "FAT32", "exfat": "exFAT", "ext4": "ext4"}

#: ``sys.platform`` values the wipe runs on. Read by the platform capability
#: matrix, so the matrix and this gate cannot disagree.
FREE_SPACE_PLATFORMS = frozenset({"linux"})

#: Always reported. A free-space wipe that left these out would read as complete.
NOT_REACHED = (
    "File slack: the bytes between the end of each existing file and the end of "
    "its last cluster belong to that file's allocation, not to free space. "
    "Reaching them means writing past the end of a file the operator did not "
    "name, which this tool does not do.",
    "Deleted directory entries: names, sizes and timestamps of deleted files "
    "stay in their parent directory's entries (0xE5 entries on FAT, unused "
    "entry sets on exFAT, directory blocks on ext4), and the tool's own "
    "undelete still lists them. The one exception is not a guarantee: on FAT "
    "and exFAT the filesystem may place this job's filler directory entry in "
    "the slots of a deleted entry in the volume root, which overwrites that "
    "one name.",
    "Filesystem metadata and journals: the ext4 journal, inode tables and group "
    "descriptors, and the FAT and exFAT allocation structures are not free space "
    "and are not written.",
    "Blocks the filesystem reserves for root: an unprivileged fill stops at "
    "ENOSPC while those blocks are still free, so they are not written; the "
    "result counts them.",
    "Clusters taken by this job's own filler directory: they are written with "
    "directory entries by the filesystem, not with the fill pattern.",
)


def _mounts(mounts_text: str | None) -> list[tuple[str, str, str]]:
    if mounts_text is None:
        mounts_text = Path("/proc/mounts").read_text(encoding="utf-8", errors="replace")
    found: list[tuple[str, str, str]] = []
    for line in mounts_text.splitlines():
        fields = line.split()
        if len(fields) >= 3:
            found.append(
                (
                    fields[0].replace("\\040", " "),
                    fields[1].replace("\\040", " "),
                    fields[2],
                )
            )
    return found


def _uuid_for(source: str, by_uuid: Path) -> str | None:
    try:
        target = os.path.realpath(source)
        for link in sorted(by_uuid.iterdir()):
            if os.path.realpath(link) == target:
                return link.name
    except OSError:
        return None
    return None


def resolve_volume(
    mount_point: Path | str,
    *,
    mounts_text: str | None = None,
    by_uuid: Path = Path("/dev/disk/by-uuid"),
) -> VolumeInfo:
    """Identify the mounted volume at exactly ``mount_point``.

    The path must be the mount point itself. A directory inside a volume is
    refused rather than widened to its whole volume: an operator who named a
    folder did not ask for every free block on the disk around it.

    Raises:
        PlatformUnsupported: Not Linux.
        UnsupportedCapability: Not a mount point, or a filesystem whose fill
            behaviour has not been measured.
    """
    if sys.platform not in FREE_SPACE_PLATFORMS:
        raise PlatformUnsupported(
            "Free-space wipe identifies the volume from /proc/mounts and is "
            "implemented for Linux only."
        )
    resolved = Path(mount_point).resolve()
    entries = _mounts(mounts_text)
    matches = [entry for entry in entries if Path(entry[1]) == resolved]
    if not matches:
        covering = sorted(
            (entry for entry in entries if resolved.is_relative_to(entry[1])),
            key=lambda entry: len(entry[1]),
        )
        where = (
            f" It lies on the volume mounted at {covering[-1][1]}." if covering else ""
        )
        raise UnsupportedCapability(
            f"{resolved} is not a mount point.{where} A free-space wipe acts on a "
            "whole volume and must be given its mount point.",
            remediation="Name the volume's mount point exactly.",
        )
    source, point, fs_type = matches[-1]
    if fs_type not in SUPPORTED:
        raise UnsupportedCapability(
            f"{point} is {fs_type}. Free-space wipe is implemented only for "
            f"{', '.join(SUPPORTED.values())}, the filesystems its fill was "
            "measured on. Copy-on-write filesystems would place the fill beside "
            "old data rather than over it, and NTFS has not been measured.",
            remediation="Use a FAT32, exFAT or ext4 volume, or destroy the media.",
        )
    stats = os.statvfs(point)
    uuid = _uuid_for(source, by_uuid) if source.startswith("/dev/") else None

    from core.erase._platform import backend

    trim, _limits = backend().trim_likely(Path(point))
    return VolumeInfo(
        mount_point=point,
        fs_type=fs_type,
        source=source,
        fs_uuid=uuid,
        identifier=uuid or point,
        st_dev=os.stat(point).st_dev,
        frsize=int(stats.f_frsize),
        trim_likely=trim,
    )


def _free(point: str) -> tuple[int, int]:
    """(f_bavail bytes, f_bfree bytes)."""
    stats = os.statvfs(point)
    return (
        int(stats.f_bavail) * int(stats.f_frsize),
        int(stats.f_bfree) * int(stats.f_frsize),
    )


def _append(
    ledger: Ledger | None, operator: str, step: str, params: dict[str, Any]
) -> None:
    if ledger is not None:
        ledger.append(
            actor=operator,
            operation=f"erase.freespace.{step}",
            params=params,
            result={},
        )


def _progress(
    job_id: str, phase: str, pct_bp: int, done: int, total: int, message: str
) -> Progress:
    return Progress(
        job_id=job_id,
        phase=phase,
        pct_bp=max(0, min(pct_bp, 10_000)),
        bytes_done=done,
        bytes_total=total,
        throughput_bytes_per_sec=0,
        eta_seconds=0,
        message=message,
    )


def plan_volume(
    mount_point: Path | str,
    *,
    protected: Sequence[Path] = (),
    volume: VolumeInfo | None = None,
) -> dict[str, Any]:
    """Resolve a volume and apply every refusal, writing nothing. Read-only.

    What the operator reads before a wipe: the filesystem, the identifier they
    must type to confirm, the free space the fill will cover, and what it will
    not reach. The refusals :func:`wipe_free_space` applies run here too, so a
    volume this plans is one the wipe accepts once the identifier is typed.

    Raises:
        SystemDiskRefused, UnsupportedCapability, PlatformUnsupported: the
        volume would be refused by the wipe.
    """
    target = volume or resolve_volume(mount_point)
    guard.assert_volume_wipeable(target, protected=protected)
    free_before, blocks_before = _free(target.mount_point)
    return {
        "volume": target.model_dump(mode="json"),
        "filesystem": SUPPORTED[target.fs_type],
        "identifier": target.identifier,
        "fill_byte": FILL_BYTE,
        "free_bytes": free_before,
        "free_blocks_bytes": blocks_before,
        "not_reached": list(NOT_REACHED),
        "limitations": _limitations(target, free_before, blocks_before),
    }


def _limitations(
    target: VolumeInfo, free_before: int, blocks_before: int
) -> list[str]:
    """What a fill of this volume cannot promise, measured now."""
    limitations: list[str] = []
    if target.trim_likely is True:
        limitations.append(
            "The volume is on flash that likely remaps writes. The fill reaches "
            "the logical blocks the filesystem calls free; the flash translation "
            "layer decides which physical pages receive it, and pages holding "
            "old data may not be among them. Only a firmware sanitize or a "
            "cryptographic erase of the whole device reaches those."
        )
    elif target.trim_likely is None:
        limitations.append(
            "Whether the volume is on flash could not be determined; if it is, "
            "the fill may not reach pages the translation layer has remapped."
        )
    reserved = blocks_before - free_before
    if reserved > 0:
        limitations.append(
            f"{reserved} bytes of free blocks are reserved for root on this "
            "volume. This fill runs unprivileged, stops at ENOSPC while they are "
            "still free, and does not write them."
        )
    return limitations


def wipe_free_space(
    mount_point: Path | str,
    options: FreeSpaceWipeOptions | None = None,
    *,
    job_id: str,
    ledger: Ledger | None,
    operator: str = "sanctum",
    protected: Sequence[Path] = (),
    volume: VolumeInfo | None = None,
) -> Generator[Progress, None, FreeSpaceWipeResult]:
    """Fill a volume's free space and release it, yielding progress.

    Args:
        protected: Paths whose volume must never be filled - the caller's state,
            ledger and report directories.
        volume: A pre-resolved volume, for tests. Resolved from ``mount_point``
            when ``None``.
        ledger: Where every step is recorded. ``None`` is for tests only; the API
            always passes one.

    Raises:
        SystemDiskRefused, UnsupportedCapability, ConfirmationMismatch,
        PlatformUnsupported: a gate refused before anything was written.
    """
    settings = options or FreeSpaceWipeOptions()
    started_at = datetime.now(UTC)
    target = volume or resolve_volume(mount_point)
    guard.assert_volume_wipeable(target, protected=protected)
    guard.assert_volume_confirmed(target, settings.typed_identifier)

    free_before, blocks_before = _free(target.mount_point)
    limitations = _limitations(target, free_before, blocks_before)

    base = {
        "job_id": job_id,
        "volume": target.model_dump(mode="json"),
        "fill_byte": FILL_BYTE,
        "free_bytes_before": free_before,
        "free_blocks_bytes_before": blocks_before,
    }
    _append(ledger, operator, "preflight", base | {"limitations": limitations})
    yield _progress(
        job_id,
        "preflight",
        0,
        0,
        free_before,
        f"{SUPPORTED[target.fs_type]} at {target.mount_point}: {free_before} bytes "
        f"free to an unprivileged writer; identifier {target.identifier}",
    )

    result = FreeSpaceWipeResult(
        job_id=job_id,
        started_at=started_at,
        finished_at=started_at,
        volume=target,
        fill_byte=FILL_BYTE,
        free_bytes_before=free_before,
        free_blocks_bytes_before=blocks_before,
        not_reached=list(NOT_REACHED),
        limitations=limitations,
    )

    state = _FillState(
        directory=Path(target.mount_point) / f".sanctum-freespace-{job_id}"
    )
    try:
        yield from _fill(target, state, job_id=job_id, total=free_before)
    except GeneratorExit:
        state.stopped_by = "cancelled"
        _release(state)
        result.bytes_written = state.written
        result.filler_files = len(state.created)
        result.stopped_by = "cancelled"
        result.filler_removed = state.removed
        _append(
            ledger,
            operator,
            "cancelled",
            base
            | {
                "bytes_written": state.written,
                "filler_removed": state.removed,
                "left_behind": [str(path) for path in state.left_behind],
                "note": (
                    "CANCELLED FREE-SPACE WIPE: the fill stopped before ENOSPC, "
                    "so free space past the written bytes was not overwritten. "
                    "No coverage is claimed."
                ),
            },
        )
        raise

    result.free_bytes_at_full, result.free_blocks_bytes_at_full = _free(
        target.mount_point
    )
    _append(
        ledger,
        operator,
        "fill",
        base
        | {
            "bytes_written": state.written,
            "filler_files": len(state.created),
            "stopped_by": state.stopped_by,
            "free_bytes_at_full": result.free_bytes_at_full,
            "free_blocks_bytes_at_full": result.free_blocks_bytes_at_full,
            "errors": state.errors,
        },
    )
    yield _progress(
        job_id,
        "release",
        9_500,
        state.written,
        free_before,
        f"stopped by {state.stopped_by}; deleting {len(state.created)} filler file(s)",
    )

    _release(state)
    result.bytes_written = state.written
    result.filler_files = len(state.created)
    result.stopped_by = state.stopped_by
    result.filler_removed = state.removed
    result.free_bytes_after, _ = _free(target.mount_point)
    result.limitations.extend(state.errors)
    if state.stopped_by != "ENOSPC":
        result.limitations.append(
            f"The fill stopped on {state.stopped_by}, not ENOSPC, so free space "
            "past the written bytes was not overwritten."
        )
    if result.free_blocks_bytes_at_full > 0:
        result.limitations.append(
            f"{result.free_blocks_bytes_at_full} bytes of blocks were still free "
            "when the fill stopped and were not written."
        )
    if not state.removed:
        result.limitations.append(
            "Not every filler file could be removed: "
            + ", ".join(str(path) for path in state.left_behind)
        )
    result.finished_at = datetime.now(UTC)
    _append(ledger, operator, "complete", base | _summary(result))
    yield _progress(
        job_id,
        "complete",
        10_000,
        state.written,
        free_before,
        f"wrote {state.written} bytes of 0x{FILL_BYTE:02X}",
    )
    logger.info(
        "free_space_wipe_complete",
        job_id=job_id,
        mount_point=target.mount_point,
        bytes_written=state.written,
        stopped_by=state.stopped_by,
    )
    return result


class _FillState:
    """What the fill has created, so release and cancellation can undo exactly that."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory_created = False
        self.created: list[Path] = []
        self.written = 0
        self.stopped_by = ""
        self.errors: list[str] = []
        self.removed = False
        self.left_behind: list[Path] = []


def _fill(
    volume: VolumeInfo, state: _FillState, *, job_id: str, total: int
) -> Generator[Progress, None, None]:
    """Write the pattern until ENOSPC.

    Creates only ``state.directory`` and the files inside it.
    """
    os.mkdir(state.directory, 0o700)
    state.directory_created = True

    entries = total // FILL_FILE_BYTES + _SPARE_ENTRIES
    for index in range(entries):
        path = state.directory / f"fill{index:06d}.bin"
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError as exc:
            if exc.errno != errno.ENOSPC:
                raise
            break
        os.close(fd)
        state.created.append(path)
    os.sync()

    reported = 0
    # The main fill in 1 MiB writes, then one pass in single blocks for whatever
    # a 1 MiB write could not place. Each phase ends at ENOSPC.
    phases = (_WRITE_BYTES, max(volume.frsize, 512))
    slot = 0
    for size in phases:
        block = bytes([FILL_BYTE]) * size
        full = False
        while not full and slot < len(state.created):
            path = state.created[slot]
            fd = os.open(path, os.O_WRONLY | os.O_APPEND)
            try:
                length = os.fstat(fd).st_size
                while length < FILL_FILE_BYTES:
                    try:
                        count = os.write(
                            fd, block[: min(size, FILL_FILE_BYTES - length)]
                        )
                    except OSError as exc:
                        if exc.errno != errno.ENOSPC:
                            state.errors.append(
                                f"Writing {path.name} failed: {exc}"
                            )
                            state.stopped_by = errno.errorcode.get(
                                exc.errno or 0, "OSError"
                            )
                            full = True
                            break
                        full = True
                        break
                    if count <= 0:
                        full = True
                        break
                    length += count
                    state.written += count
                    if state.written - reported >= 64 * MIB:
                        reported = state.written
                        yield _progress(
                            job_id,
                            "fill",
                            9_000 * state.written // max(total, 1),
                            state.written,
                            total,
                            f"{state.written} of about {total} bytes",
                        )
                try:
                    os.fsync(fd)
                except OSError as exc:
                    if exc.errno != errno.ENOSPC:
                        state.errors.append(f"fsync of {path.name} failed: {exc}")
                        state.stopped_by = errno.errorcode.get(
                            exc.errno or 0, "OSError"
                        )
                    full = True
            finally:
                os.close(fd)
            if not full:
                slot += 1
            if state.stopped_by and state.stopped_by != "ENOSPC":
                return
        if not full:
            state.stopped_by = "filler entries exhausted"
            return
    state.stopped_by = state.stopped_by or "ENOSPC"
    os.sync()


def _release(state: _FillState) -> None:
    """Delete exactly the files this job created, then its directory."""
    left: list[Path] = []
    for path in state.created:
        try:
            os.unlink(path)
        except FileNotFoundError:
            continue
        except OSError:
            left.append(path)
    if state.directory_created:
        try:
            os.rmdir(state.directory)
        except OSError:
            left.append(state.directory)
    os.sync()
    state.left_behind = left
    state.removed = not left


def _summary(result: FreeSpaceWipeResult) -> dict[str, Any]:
    return {
        "bytes_written": result.bytes_written,
        "filler_files": result.filler_files,
        "stopped_by": result.stopped_by,
        "free_bytes_at_full": result.free_bytes_at_full,
        "free_blocks_bytes_at_full": result.free_blocks_bytes_at_full,
        "free_bytes_after": result.free_bytes_after,
        "filler_removed": result.filler_removed,
        "not_reached": result.not_reached,
        "limitations": result.limitations,
        "verified": None,
    }
