"""Secure file and folder erasure (M2). Destructive: every call erases.

The honest claim this module makes: **overwriting a file through the filesystem
does not reliably destroy it.** Journals, copy-on-write, resident data, slack,
snapshots and TRIM all keep copies the OS will not hand back. So this module
does two things, and the second is the deliverable: it performs the best-effort
destruction, and it enumerates - by name, with a derived severity and with the
concrete identifiers - everything it could not guarantee. See
:mod:`core.erase.residual`.

**Cross-platform by construction.** There is no platform gate here and there
must never be one: where a platform cannot support a step, the step degrades
and the reason is recorded, never raised at import. That is the opposite of
:mod:`core.erase.drive`, which refuses to load off Linux, and the difference is
deliberate - a whole-device wipe that guessed at ``O_DIRECT`` alignment would
destroy the wrong bytes, while a file erase that cannot enumerate alternate
data streams can still erase the file and say what it could not check.

**The gate is closed by default.** ``confirm`` is False, and an erase without
it raises before any path is inspected. There is no non-writing mode: every
confirmed call overwrites, renames and unlinks, then runs the residual scan.
"""

from __future__ import annotations

import errno
import os
import secrets
import stat as stat_mod
import string
import time
from collections.abc import Generator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import structlog

from core.erase import residual as residual_mod
from core.erase import traces as traces_mod
from core.erase._platform import PlatformBackend, backend
from core.erase.inspect import inspect_path
from core.erase.metadata import cleanse_only
from core.erase.sink import LedgerSink
from core.erase.verify import verify_file_erase
from core.errors import ConfirmationMismatch, SystemDiskRefused
from core.models import (
    FileEraseOptions,
    FileErasePhase,
    FileEraseRecord,
    FileEraseResult,
    FileInspection,
    Progress,
    TraceSweepResult,
)

__all__ = [
    "erase_paths",
    "erase_one",
    "expand_targets",
    "PROTECTED_PREFIXES",
    "TRUNCATE_FRACTIONS",
    "OVERWRITE_BYTE",
]

logger = structlog.get_logger(__name__)

MIB = 1024 * 1024

#: Written over the file's data. Zero rather than random: a zeroed region can be
#: read back and confirmed, and an unverifiable erase is not one this project
#: reports as verified. The same reasoning as ``docs/limitations.md`` gives for
#: the DoD third pass.
OVERWRITE_BYTE = 0x00

#: Chunk size for the overwrite loop.
_BUFFER_BYTES = 1 * MIB

#: The file is truncated through these fractions of its original size before
#: being unlinked, so the size recorded in the directory entry or MFT record is
#: disturbed rather than left pointing at the original length.
TRUNCATE_FRACTIONS = (0.75, 0.50, 0.25, 0.0)

#: Characters a replacement filename is drawn from.
_NAME_ALPHABET = string.ascii_lowercase + string.digits

#: Paths this module refuses outright. Erasing any of these breaks the running
#: system, and an operator who typed one meant something else.
PROTECTED_PREFIXES = (
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
    "/System",
    "/Library",
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
)


def _refuse_protected(path: Path) -> None:
    """Raise for a filesystem root or a system directory.

    Two layers. :data:`PROTECTED_PREFIXES` is the historical list, matched
    exactly, unchanged. :func:`core.platform.paths.protected_reason` adds the
    running platform's own rules: on Windows the real ``%SystemRoot%`` and
    Program Files trees (which are not always on ``C:``) compared
    case-insensitively, and whole subtrees such as ``System32`` rather than
    only the directory itself; on macOS ``/System`` and the swap directory.
    """
    from core.platform.host import family
    from core.platform.paths import protected_reason

    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    if resolved.parent == resolved:
        raise SystemDiskRefused(
            f"Refusing to erase {resolved}: it is a filesystem root."
        )
    text = str(resolved)
    for prefix in PROTECTED_PREFIXES:
        if text == prefix or text == prefix.rstrip("/\\"):
            raise SystemDiskRefused(
                f"Refusing to erase {resolved}: it is a protected system "
                "location, and erasing it would break the running system."
            )
    why = protected_reason(text, family())
    if why:
        raise SystemDiskRefused(
            f"Refusing to erase {resolved}: {why} Erasing it would break the "
            "running system."
        )


def _random_same_length_name(original: str) -> str:
    """A random name of **exactly** the original's length.

    The length is the point. A directory entry, and NTFS's ``$FILE_NAME``
    attribute, hold the name in place; a shorter replacement leaves the tail of
    the original name in the bytes beyond it, which is precisely what
    ``core.carve.fsaware`` reads out of ``$I30`` slack.
    """
    return "".join(secrets.choice(_NAME_ALPHABET) for _ in range(len(original)))


def _stream_path(path: Path, stream: str) -> str:
    """``file.txt:hidden`` from ``file.txt`` and ``:hidden:$DATA``."""
    name = stream.strip(":")
    if name.endswith(":$DATA"):
        name = name[: -len(":$DATA")]
    return f"{path}:{name}"


def _overwrite_fd(fd: int, size: int) -> int:
    """Write the pattern over ``size`` bytes and fsync. Returns bytes written."""
    block = bytes([OVERWRITE_BYTE]) * min(_BUFFER_BYTES, max(size, 1))
    written = 0
    os.lseek(fd, 0, os.SEEK_SET)
    while written < size:
        chunk = block[: min(_BUFFER_BYTES, size - written)]
        written += os.write(fd, chunk)
    os.fsync(fd)
    return written


def erase_one(  # noqa: C901 - eleven ordered steps, read top to bottom
    path: Path | str, options: FileEraseOptions
) -> FileEraseRecord:
    """Erase one path, returning what happened and what survived.

    Runs eleven steps in a fixed order and never raises for a per-file problem:
    an ``OSError`` anywhere sets ``ok=False`` with the errno name and returns
    the partial record, because a batch must never abort for one bad file. The
    two gate violations *do* raise - they are caller errors, not file errors.

    Module-level and taking only picklable arguments, because
    :func:`erase_paths` hands it to a process pool under spawn semantics.
    **It never ledgers**: every entry is written by the parent, so the chain has
    exactly one writer.
    """
    target = Path(path)

    if not options.confirm:
        raise ConfirmationMismatch(
            f"Refusing to erase {target}: confirm was not set. Destructive "
            "file erasure needs an explicit confirmation."
        )
    _refuse_protected(target)

    inspection = inspect_path(target)
    record = FileEraseRecord(
        path=str(target),
        ok=True,
        inspection=inspection,
        is_directory=target.is_dir() and not inspection.is_reparse_point,
    )

    if inspection.is_reparse_point:
        record.ok = False
        record.error_kind = "REPARSE_POINT_REFUSED"
        record.error = (
            f"{target} is a link or reparse point. It was not followed, not "
            "overwritten and not unlinked: erasing a link destroys nothing "
            "while reporting that it did. Name the target directly if that is "
            "what was intended."
        )
        record.findings = residual_mod.scan(inspection, record)
        return record

    host = backend()
    record.attempted = True
    try:
        if inspection.is_immutable is True:
            cleared, why = host.clear_immutable(target)
            record.limitations.append(
                f"The immutable attribute on {target} was cleared before "
                "erasing."
                if cleared
                else why
            )

        if record.is_directory:
            _erase_directory(target, options, record)
        else:
            _erase_file(target, options, record, inspection, host)
    except OSError as exc:
        record.ok = False
        record.error = str(exc)
        record.error_kind = errno.errorcode.get(exc.errno or 0, "OSERROR")
        logger.warning(
            "file_erase_failed",
            path=str(target),
            error=str(exc),
            kind=record.error_kind,
        )

    if record.unlinked:
        record.verification = verify_file_erase(inspection)

    record.findings = residual_mod.scan(inspection, record)
    return record


def _erase_file(
    target: Path,
    options: FileEraseOptions,
    record: FileEraseRecord,
    inspection: FileInspection,
    host: PlatformBackend,
) -> None:
    """Steps 4-10 for a regular file. Raises OSError; the caller records it."""
    if options.cleanse_metadata:
        record.cleanse = cleanse_only(target)

    size = target.stat().st_size

    shared = inspection.hardlink_count > 1
    if shared and not options.break_hardlinks:
        # Not a failure, a refusal. The inode is reachable under names the
        # operator did not give us, and overwriting it would destroy their
        # content too. Unlink this name only, and let the HARDLINK_SURVIVES
        # finding report that the data is still alive.
        record.limitations.append(
            f"{target} has {inspection.hardlink_count} hard links. Overwriting "
            f"its data would destroy the content of "
            f"{inspection.hardlink_count - 1} other name(s) the operator did "
            "not name, so only this name was unlinked. The data survives; see "
            "the HARDLINK_SURVIVES finding."
        )
    elif size > 0:
        fd, reaches_medium, limits = host.open_unbuffered_write(target)
        record.limitations.extend(limits)
        try:
            record.bytes_overwritten = _overwrite_fd(fd, size)
            for fraction in TRUNCATE_FRACTIONS:
                step = int(size * fraction)
                os.ftruncate(fd, step)
                os.fsync(fd)
                record.truncate_steps.append(step)
        finally:
            os.close(fd)
        if not reaches_medium:
            record.limitations.append(
                f"Writes to {target} were buffered by the platform, so the "
                "overwrite may not have reached the medium before the handle "
                "was closed."
            )

    _erase_streams(target, record, inspection)
    _erase_xattrs(target, record, inspection)

    if inspection.is_resident is True:
        record.limitations.append(
            f"{target} stored its data resident inside a filesystem metadata "
            "record. The overwrite wrote through the file handle, which does "
            "not reach that record, so the original bytes are still in it. "
            "This is recorded as an unremovable residual, not as a success."
        )

    _rename_and_unlink(target, options, record, host)


def _erase_streams(
    target: Path, record: FileEraseRecord, inspection: FileInspection
) -> None:
    """Overwrite each alternate data stream, then remove it."""
    for stream in inspection.alt_data_streams:
        location = _stream_path(target, stream)
        try:
            length = os.stat(location).st_size
            # O_BINARY: without it the Windows CRT opens the stream in text
            # mode. Zeros survive text mode today, but a pattern containing
            # 0x0A would be written as 0x0D 0x0A and overrun the stream.
            fd = os.open(location, os.O_WRONLY | getattr(os, "O_BINARY", 0))
            try:
                _overwrite_fd(fd, length)
            finally:
                os.close(fd)
            os.remove(location)
        except OSError as exc:
            record.limitations.append(
                f"The alternate data stream {stream} on {target} could not be "
                f"overwritten and removed ({exc}); its content survives."
            )
            continue
        record.streams_removed.append(stream)


def _erase_xattrs(
    target: Path, record: FileEraseRecord, inspection: FileInspection
) -> None:
    """Overwrite each extended attribute's value, then remove the attribute.

    Overwritten first: removing an xattr frees the block holding its value
    without clearing it, so a removal on its own leaves the value behind in
    exactly the way this module exists to avoid.
    """
    setter = getattr(os, "setxattr", None)
    remover = getattr(os, "removexattr", None)
    getter = getattr(os, "getxattr", None)
    if setter is None or remover is None or getter is None:
        return
    for name in inspection.xattrs:
        if name.startswith(("system.", "security.")):
            # Owned by the kernel (SELinux labels, POSIX ACLs). Removing these
            # changes the file's access control rather than erasing content.
            continue
        try:
            value = getter(target, name)
            setter(target, name, b"\x00" * len(value))
            remover(target, name)
        except OSError as exc:
            record.limitations.append(
                f"The extended attribute {name} on {target} could not be "
                f"cleared ({exc}); its value survives."
            )
            continue
        record.xattrs_removed.append(name)


def _rename_and_unlink(
    target: Path,
    options: FileEraseOptions,
    record: FileEraseRecord,
    host: PlatformBackend,
) -> None:
    """Rename through N random same-length names, then unlink."""
    current = target
    fsync_warned = False
    for _ in range(options.rename_rounds):
        candidate = current.with_name(_random_same_length_name(target.name))
        os.rename(current, candidate)
        current = candidate
        record.rename_chain.append(candidate.name)
        ok, why = host.fsync_dir(current.parent)
        if not ok and not fsync_warned and why:
            # Once, not once per round: eight copies of the same sentence in a
            # report is noise, and the fact does not get truer by repetition.
            record.limitations.append(why)
            fsync_warned = True

    if record.is_directory:
        os.rmdir(current)
    else:
        os.unlink(current)
    record.unlinked = True
    host.fsync_dir(current.parent)


def _erase_directory(
    target: Path, options: FileEraseOptions, record: FileEraseRecord
) -> None:
    """A directory: no content to overwrite, but its name is still evidence.

    By the time this runs, :func:`expand_targets` has already erased everything
    inside. What is left is the directory's own entry in its parent, and a
    directory name is often as telling as a filename - so it goes through the
    same rename chain before ``rmdir``.
    """
    if any(target.iterdir()):
        # Checked before the rename chain: renaming a directory that then
        # cannot be removed would leave its contents under a name nobody chose.
        raise OSError(errno.ENOTEMPTY, os.strerror(errno.ENOTEMPTY), str(target))
    _rename_and_unlink(target, options, record, backend())


def expand_targets(
    paths: Sequence[Path | str], *, recursive: bool = True
) -> list[Path]:
    """Flatten directory arguments depth-first, contents before their container.

    A directory is erased only after everything inside it, so the rename chain
    on the directory's own name is the last thing to touch that directory
    entry - and ``rmdir`` cannot fail on a non-empty directory.

    A reparse point is emitted as itself and never descended into. Following
    one would walk out of the tree the operator named and erase files elsewhere.
    """
    out: list[Path] = []
    for entry in paths:
        target = Path(entry)
        if not target.is_dir() or _is_link_or_reparse(target) or not recursive:
            out.append(target)
            continue
        try:
            _refuse_protected(target)
        except SystemDiskRefused:
            # Emitted as itself, so erase_one records the refusal. Expanding it
            # would erase every child first, and the refusal of the directory
            # itself would come last.
            out.append(target)
            continue
        out.extend(_walk_depth_first(target))
    return out


def _stat_is_link_or_reparse(info: os.stat_result) -> bool:
    """A symlink, or any Windows reparse point, from an ``lstat`` result.

    ``is_symlink()`` is not enough on Windows. A directory **junction** is a
    reparse point but not a symlink, so ``is_symlink()`` is False for it and
    ``DirEntry.is_dir(follow_symlinks=False)`` is True - and a walk that
    trusted those two would descend through the junction and erase whatever
    tree it points at, which is typically outside the folder the operator
    named. ``FILE_ATTRIBUTE_REPARSE_POINT`` catches junctions, mount points,
    symlinks and cloud placeholders alike.
    """
    from core.erase.inspect import FILE_ATTRIBUTE_REPARSE_POINT

    if stat_mod.S_ISLNK(info.st_mode):
        return True
    attributes = int(getattr(info, "st_file_attributes", 0))
    return bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)


def _is_link_or_reparse(path: Path) -> bool:
    try:
        return _stat_is_link_or_reparse(os.lstat(path))
    except OSError:
        return False


def _walk_depth_first(root: Path) -> list[Path]:
    """Every path under ``root``, children before parents, ``root`` last.

    A link or reparse point inside the tree is emitted as itself and never
    descended into; :func:`erase_one` then refuses it by name.
    """
    found: list[Path] = []

    def descend(directory: Path) -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError:
            return
        for item in entries:
            child = Path(item.path)
            try:
                linked = _stat_is_link_or_reparse(item.stat(follow_symlinks=False))
            except OSError:
                linked = True  # cannot tell: do not descend
            if not linked and item.is_dir(follow_symlinks=False):
                descend(child)
                found.append(child)
            else:
                found.append(child)

    descend(root)
    found.append(root)
    return found


# --------------------------------------------------------------------------
# Batch
# --------------------------------------------------------------------------


def _worker(job: tuple[int, str, FileEraseOptions]) -> tuple[int, FileEraseRecord]:
    """Pool entry point. Module-level and picklable, for spawn on Windows.

    Returns the input index alongside the record so the parent can restore the
    caller's order regardless of which worker finished first.
    """
    index, path, options = job
    try:
        return index, erase_one(Path(path), options)
    except (OSError, ValueError, ConfirmationMismatch, SystemDiskRefused) as exc:
        # A worker that raises kills the pool's result for the whole batch, so
        # even a gate violation comes back as a failed record here.
        return index, FileEraseRecord(
            path=path,
            ok=False,
            inspection=FileInspection(path=path, size_bytes=0),
            error=str(exc),
            error_kind=type(exc).__name__,
        )


def _phase_payload(record: FileEraseRecord, phase: FileErasePhase) -> dict[str, object]:
    """What one phase did for one record, as a ledgerable dict.

    Every phase gets an entry even when it did nothing, with ``skipped`` and a
    reason. A phase missing from the chain would be indistinguishable from a
    phase that ran and was not recorded.
    """
    common: dict[str, object] = {"path": record.path, "phase": phase.value}
    if phase is FileErasePhase.INSPECT:
        return common | {
            "fs_type": record.inspection.fs_type,
            "size_bytes": record.inspection.size_bytes,
            "hardlink_count": record.inspection.hardlink_count,
            "extents": len(record.inspection.extents),
            "is_resident": record.inspection.is_resident,
            "limitations": record.inspection.limitations,
        }
    if phase is FileErasePhase.CLEANSE:
        if record.cleanse is None:
            return common | {"skipped": True, "reason": "metadata cleansing not run"}
        return common | {
            "format": record.cleanse.format,
            "parsed": record.cleanse.parsed,
            "removed": record.cleanse.removed_count,
        }
    if phase is FileErasePhase.OVERWRITE:
        return common | {
            "bytes_overwritten": record.bytes_overwritten,
            "skipped": record.bytes_overwritten == 0,
            "reason": "" if record.bytes_overwritten else "no bytes were overwritten",
        }
    if phase is FileErasePhase.STREAMS:
        return common | {
            "streams_removed": record.streams_removed,
            "xattrs_removed": record.xattrs_removed,
            "skipped": not (record.streams_removed or record.xattrs_removed),
        }
    if phase is FileErasePhase.TRUNCATE:
        return common | {
            "steps": record.truncate_steps,
            "skipped": not record.truncate_steps,
        }
    if phase is FileErasePhase.RENAME:
        return common | {
            "rounds": len(record.rename_chain),
            "chain": record.rename_chain,
            "skipped": not record.rename_chain,
        }
    if phase is FileErasePhase.UNLINK:
        return common | {"unlinked": record.unlinked, "skipped": not record.unlinked}
    if phase is FileErasePhase.RESIDUAL:
        return common | {
            "findings": [
                {
                    "kind": finding.kind.value,
                    "severity": finding.severity.value,
                    "addressable": finding.addressable,
                }
                for finding in record.findings
            ],
            "highest_severity": (
                record.highest_severity.value if record.highest_severity else None
            ),
        }
    verification = record.verification
    if verification is None:
        return common | {
            "skipped": True,
            "reason": "verification was not attempted (nothing was unlinked)",
        }
    return common | {
        "passed": verification.passed,
        "strategy": verification.strategy,
        "reason": verification.reason,
        "extents_checked": verification.extents_checked,
        "bytes_checked": verification.bytes_checked,
    }


class _Throughput:
    """Bytes per second over a rolling window, as whole bytes.

    Integer by construction: this number reaches a ledger entry and a report,
    and a float there would be a lossy rewrite of something measured.
    """

    def __init__(self) -> None:
        self._started = time.monotonic()
        self._bytes = 0

    def add(self, count: int) -> None:
        self._bytes += count

    def rate(self) -> int:
        elapsed = max(time.monotonic() - self._started, 1e-6)
        return int(self._bytes / elapsed)

    @property
    def total(self) -> int:
        return self._bytes


def erase_paths(
    paths: Sequence[Path | str],
    options: FileEraseOptions | None = None,
    *,
    job_id: str,
    ledger: LedgerSink,
) -> Generator[Progress, None, FileEraseResult]:
    """Erase every path, yielding progress and returning the full record.

    Directory arguments are expanded depth-first so a directory is erased only
    after its contents. Results come back **in the caller's input order**
    regardless of which worker finished first, because a report that listed
    files in completion order would be non-deterministic between runs over the
    same input.

    All ledgering happens here, in the parent, one entry per phase per record.
    A pool worker appending would race the chain head.

    **A cancelled batch records ``erase.file.cancelled``.** The per-phase
    entries are written after every file is processed, so a batch closed
    part-way would otherwise leave the files it reached destroyed and the chain
    silent about which ones. See :func:`_record_cancelled_batch`.
    """
    settings = options or FileEraseOptions()
    if not settings.confirm:
        # Refused before a single path is expanded or inspected: an erase with
        # no confirmation is a caller error, not a batch of failed files.
        raise ConfirmationMismatch(
            "Refusing to erase: confirm was not set. Destructive file erasure "
            "needs an explicit confirmation."
        )
    targets = expand_targets(paths, recursive=settings.recursive)
    state = _BatchState(targets=targets)
    try:
        return (yield from _erase_batch(settings, state, job_id=job_id, ledger=ledger))
    except GeneratorExit:
        # The caller closed this generator between yields. No progress can be
        # yielded while closing; the ledger is the only channel out.
        _record_cancelled_batch(ledger, job_id=job_id, settings=settings, state=state)
        raise


@dataclass
class _BatchState:
    """What a batch has done so far, readable by the cancellation handler."""

    targets: list[Path]
    results: dict[int, FileEraseRecord] = field(default_factory=dict)
    pooled: bool = False
    phase_entries_recorded: bool = False


def _erase_batch(
    settings: FileEraseOptions,
    state: _BatchState,
    *,
    job_id: str,
    ledger: LedgerSink,
) -> Generator[Progress, None, FileEraseResult]:
    """The body of :func:`erase_paths`, keeping ``state`` current as it goes."""
    started_at = datetime.now(UTC)
    targets = state.targets

    yield Progress(
        job_id=job_id,
        phase=FileErasePhase.INSPECT.value,
        pct_bp=0,
        bytes_done=0,
        bytes_total=0,
        throughput_bytes_per_sec=0,
        eta_seconds=0,
        message=f"{len(targets)} target(s)",
    )

    ledger.record_file(
        "inspect.batch",
        {
            "job_id": job_id,
            "targets": len(targets),
            "break_hardlinks": settings.break_hardlinks,
            "cleanse_metadata": settings.cleanse_metadata,
            "rename_rounds": settings.rename_rounds,
        },
    )

    workers = settings.workers or os.cpu_count() or 1
    use_pool = len(targets) >= settings.pool_threshold and workers > 1
    state.pooled = use_pool
    results = state.results
    throughput = _Throughput()
    completed = 0

    if use_pool:
        import multiprocessing

        jobs = [(index, str(path), settings) for index, path in enumerate(targets)]
        with multiprocessing.Pool(processes=workers) as pool:
            for index, record in pool.imap_unordered(_worker, jobs):
                results[index] = record
                completed += 1
                throughput.add(record.bytes_overwritten)
                yield _batch_progress(
                    job_id, completed, len(targets), throughput, record
                )
    else:
        for index, path in enumerate(targets):
            _, record = _worker((index, str(path), settings))
            results[index] = record
            completed += 1
            throughput.add(record.bytes_overwritten)
            yield _batch_progress(
                job_id, completed, len(targets), throughput, record
            )

    ordered = [results[index] for index in range(len(targets))]

    for record in ordered:
        for phase in FileErasePhase:
            ledger.record_file(
                f"{phase.value.lower()}.result",
                {"job_id": job_id} | _phase_payload(record, phase),
            )
    state.phase_entries_recorded = True

    # After the phase entries, so the chain says what happened to every target
    # before it says anything about their traces.
    trace_sweep: TraceSweepResult | None = None
    if settings.sweep_traces:
        trace_sweep = yield from traces_mod.sweep(
            ordered, settings, job_id=job_id, ledger=ledger
        )

    finished_at = datetime.now(UTC)
    limitations: list[str] = []

    yield Progress(
        job_id=job_id,
        phase=FileErasePhase.RESIDUAL.value,
        pct_bp=10_000,
        bytes_done=throughput.total,
        bytes_total=throughput.total,
        throughput_bytes_per_sec=throughput.rate(),
        eta_seconds=0,
        message=f"{len(ordered)} record(s)",
    )

    result = FileEraseResult(
        job_id=job_id,
        started_at=started_at,
        finished_at=finished_at,
        records=ordered,
        limitations=limitations,
        trace_sweep=trace_sweep,
    )
    logger.info(
        "file_erase_complete",
        job_id=job_id,
        targets=len(ordered),
        succeeded=result.succeeded,
        failed=result.failed,
        highest_severity=(
            result.highest_severity.value if result.highest_severity else None
        ),
    )
    return result


def _record_cancelled_batch(
    ledger: LedgerSink,
    *,
    job_id: str,
    settings: FileEraseOptions,
    state: _BatchState,
) -> None:
    """Append the entry that says which files a cancelled batch reached.

    Every target is named exactly once, on one of three lists:

    * ``processed`` - the erase ran to the end of its steps for this path, and
      the phases it reached are listed. On the inline path a file is never
      half-done at cancellation: :func:`erase_one` has no yield inside it.
    * ``not_processed`` - the inline path never reached it. Untouched.
    * ``in_flight_unknown`` - the pool path only. Every task is queued to the
      pool at once and the pool's workers are terminated when the batch is
      closed, so a path with no result may be untouched, partly overwritten or
      fully erased. This entry does not guess which.

    No batch verdict is recorded - no success count, no verification result, no
    severity summary. A cancelled batch is not an erasure certificate, and a
    field shaped like one would be read as one.
    """
    processed: list[dict[str, object]] = []
    unresulted: list[str] = []
    for index, path in enumerate(state.targets):
        record = state.results.get(index)
        if record is None:
            unresulted.append(str(path))
            continue
        processed.append(
            {
                "path": record.path,
                "ok": record.ok,
                "error_kind": record.error_kind,
                "unlinked": record.unlinked,
                "phases_reached": [
                    phase.value
                    for phase in FileErasePhase
                    if not _phase_payload(record, phase).get("skipped")
                ],
            }
        )

    not_processed = [] if state.pooled else unresulted
    in_flight = unresulted if state.pooled else []
    total = len(state.targets)
    if state.pooled:
        rest = (
            f"{len(in_flight)} were queued to a process pool whose workers were "
            "terminated on cancel; each of those may be untouched, partly "
            "overwritten or fully erased, and must be checked on disk. "
        )
    else:
        rest = f"{len(not_processed)} were not reached and were not touched. "
    ledgered = (
        "The per-file phase entries were recorded before the cancellation. "
        if state.phase_entries_recorded
        else "No per-file phase entries were recorded for this batch; this "
        "entry is the only record of what it did. "
    )
    ledger.record_file(
        "cancelled",
        {
            "job_id": job_id,
            "targets": total,
            "processed": processed,
            "not_processed": not_processed,
            "in_flight_unknown": in_flight,
            "phase_entries_recorded": state.phase_entries_recorded,
            "note": (
                f"CANCELLED FILE ERASE: {len(processed)} of {total} target(s) "
                "were processed and are listed with the phases each reached. "
                + rest
                + ledgered
                + "No batch verdict is recorded: this is not evidence that any "
                "file was erased beyond what is listed here."
            ),
        },
    )


def _batch_progress(
    job_id: str,
    completed: int,
    total: int,
    throughput: _Throughput,
    record: FileEraseRecord,
) -> Progress:
    """One progress record per completed file."""
    return Progress(
        job_id=job_id,
        phase=FileErasePhase.OVERWRITE.value,
        pct_bp=10_000 * completed // total if total else 10_000,
        bytes_done=throughput.total,
        bytes_total=throughput.total,
        throughput_bytes_per_sec=throughput.rate(),
        eta_seconds=0,
        message=record.path,
    )
