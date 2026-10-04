"""Restore planning, execution and post-restore verification.

A restore writes a verified backup image onto a target block device. It is a
destructive operation on the target - every byte in the planned range is
replaced - and is gated exactly like an erase: a recorded human approval,
the target serial typed by hand and re-checked by the process that writes, a
single-use authorization. Those gates live in
:mod:`api.authorization` and :mod:`helper.authorization`; this module is the
engine they guard, and it refuses on its own too.

The write seam is :class:`BlockTarget`, a small protocol any platform backend
can implement. This module ships two: :class:`FileBlockTarget` (an image file,
for tests and for restoring onto an image) and :class:`LinuxBlockDeviceTarget`
(``O_WRONLY | O_SYNC``), which is only ever constructed inside the privileged
helper.

What the engine guarantees
--------------------------
* Every chunk read from the image is hashed and compared with the record's
  chunk hash **before** it is written. A mismatch stops the run: the target
  never receives bytes the record does not vouch for.
* Byte accounting is exact: at the end, bytes written plus bytes recorded as
  unwritable equal the planned length, or :class:`~core.errors.OverwriteIncomplete`
  is raised.
* A cancelled run appends a ledger entry naming the byte range written.
* After the write, the range is read back and hashed; the result records
  whether it equals the image's SHA-256 and chunk hashes.

What it does not guarantee
--------------------------
Read-back goes through the operating system. On a block device it runs after
``fsync`` and a ``POSIX_FADV_DONTNEED`` hint, so it is unlikely to be served
from the page cache, but a drive's own volatile cache can still answer it: a
passing verification shows the target returns the image's bytes when read now,
not that they survive a power loss. Bytes of the target beyond the image are
not touched and not verified.
"""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import sys
import time
from collections.abc import Callable, Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

import structlog
from pydantic import BaseModel, ConfigDict

from core.backup import (
    BackupRecord,
    ChunkMismatch,
    SourceIdentity,
    check_record_digest,
)
from core.errors import (
    EvidenceIntegrityError,
    OverwriteIncomplete,
    PlatformUnsupported,
    WorkflowGateRefused,
)
from core.ledger.canon import canonical_bytes
from core.ledger.chain import Ledger
from core.models import Progress

__all__ = [
    "ASSUMED_WRITE_BYTES_PER_SEC",
    "BlockTarget",
    "FileBlockTarget",
    "LinuxBlockDeviceTarget",
    "RestorePlan",
    "RestoreResult",
    "RestoreVerification",
    "TargetIdentity",
    "UnwritableSpan",
    "confirmation_token",
    "execute_restore",
    "file_target_identity",
    "plan_binding",
    "plan_digest_of",
    "plan_restore",
    "require_executable",
    "restore_plan_drift",
    "target_identity_from_probe",
    "verify_restored",
]

logger = structlog.get_logger(__name__)

#: The rate a time estimate assumes. An assumption, stated as one in the plan:
#: nothing here measures the target before it is written.
ASSUMED_WRITE_BYTES_PER_SEC = 100 * 1000 * 1000

#: How often a running restore appends a checkpoint entry to the ledger.
CHECKPOINT_BYTES = 256 * 1024 * 1024

#: A restore stops once the target has refused this many bytes in a row. A few
#: bad sectors are salvaged around; a target refusing everything is not a
#: target, and walking a whole image sector by sector only burns time and
#: memory (2026-09-29: 14.7 million refused sectors froze the host).
MAX_CONSECUTIVE_UNWRITABLE_BYTES = 1024 * 1024

#: How many separate refused ranges a run keeps in full. Adjacent refused
#: sectors with the same error merge into one range; past this cap only the
#: byte count of further ranges is kept, so memory and the ledger stay bounded.
MAX_RECORDED_SPANS = 1024

_LIMIT_READBACK = (
    "READ_BACK_THROUGH_OS: post-restore verification reads the range back "
    "through the operating system after a flush. A drive's volatile write cache "
    "can still answer the read, so a pass shows the target returns the image's "
    "bytes now, not that they survive a power loss."
)
_LIMIT_TAIL = (
    "TAIL_UNTOUCHED: {tail} byte(s) of the target beyond the image were not "
    "written and are not verified; they keep whatever they held before."
)
_LIMIT_PROVENANCE = (
    "A restore reproduces the backup image's bytes. It inherits every limitation "
    "of the backup record, including that the record's hashes are not proof of "
    "where the image came from."
)


# --------------------------------------------------------------------------
# The write seam
# --------------------------------------------------------------------------


@runtime_checkable
class BlockTarget(Protocol):
    """A writable block target. Windows and macOS backends implement this too."""

    @property
    def size_bytes(self) -> int: ...

    @property
    def logical_sector(self) -> int: ...

    def write_at(self, offset: int, data: bytes) -> int:
        """Write ``data`` at ``offset``; return the count written (may be short)."""
        ...

    def read_at(self, offset: int, length: int) -> bytes: ...

    def flush(self) -> None:
        """Make every completed write durable before returning."""
        ...

    def close(self) -> None: ...


class FileBlockTarget:
    """A regular file used as a block target. Never an evidence image.

    The file must already exist at the size to restore onto; :meth:`create`
    makes a sparse one. Opened read-write because a restore writes it and then
    reads the range back.
    """

    def __init__(self, path: Path | str, *, logical_sector: int = 512) -> None:
        self.path = Path(path)
        info = self.path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise EvidenceIntegrityError(
                f"{self.path} is not a regular file",
                remediation="A file target must be a regular image file.",
            )
        flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        self._fd = os.open(self.path, flags)
        self._size = info.st_size
        self._sector = logical_sector

    @classmethod
    def create(
        cls, path: Path | str, size_bytes: int, *, logical_sector: int = 512
    ) -> FileBlockTarget:
        """Create a new sparse file of ``size_bytes`` and open it. Never overwrites."""
        target = Path(path)
        with target.open("xb") as handle:
            handle.truncate(size_bytes)
        return cls(target, logical_sector=logical_sector)

    @property
    def size_bytes(self) -> int:
        return self._size

    @property
    def logical_sector(self) -> int:
        return self._sector

    def write_at(self, offset: int, data: bytes) -> int:
        os.lseek(self._fd, offset, os.SEEK_SET)
        return os.write(self._fd, data)

    def read_at(self, offset: int, length: int) -> bytes:
        os.lseek(self._fd, offset, os.SEEK_SET)
        out = bytearray()
        while len(out) < length:
            piece = os.read(self._fd, length - len(out))
            if not piece:
                break
            out.extend(piece)
        return bytes(out)

    def flush(self) -> None:
        os.fsync(self._fd)

    def close(self) -> None:
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1


#: Linux block-layer ioctls: the device size in bytes, and its logical sector.
_BLKGETSIZE64 = 0x80081272
_BLKSSZGET = 0x1268


class LinuxBlockDeviceTarget:  # pragma: no cover - needs a real block device
    """A Linux block device opened ``O_WRONLY | O_SYNC`` for a restore.

    Constructed only inside the privileged helper, after the write-seam
    authorization check passed. ``O_DIRECT`` is not used: it would require
    page-aligned buffers for every write, and ``O_SYNC`` already makes each
    write reach the device before the call returns. Reads for verification use
    a separate ``O_RDONLY`` descriptor, after ``fsync`` and a
    ``POSIX_FADV_DONTNEED`` hint.
    """

    def __init__(self, path: str) -> None:
        if sys.platform != "linux":
            raise PlatformUnsupported(
                "restore onto a block device is implemented for Linux only in "
                "this module; other platforms plug in their own BlockTarget.",
                remediation="Restore from a Linux host. Nothing was opened.",
            )
        import fcntl
        import struct

        info = os.stat(path)
        if not stat.S_ISBLK(info.st_mode):
            raise EvidenceIntegrityError(
                f"{path} is not a block device",
                remediation="Name the whole-device node. Nothing was opened.",
            )
        cloexec = getattr(os, "O_CLOEXEC", 0)
        self.path = path
        self._wfd = os.open(path, os.O_WRONLY | os.O_SYNC | cloexec)
        try:
            self._rfd = os.open(path, os.O_RDONLY | cloexec)
        except OSError:
            os.close(self._wfd)
            raise
        raw = fcntl.ioctl(self._rfd, _BLKGETSIZE64, struct.pack("Q", 0))
        self._size = int(struct.unpack("Q", raw)[0])
        raw = fcntl.ioctl(self._rfd, _BLKSSZGET, struct.pack("i", 0))
        self._sector = int(struct.unpack("i", raw)[0])

    @property
    def size_bytes(self) -> int:
        return self._size

    @property
    def logical_sector(self) -> int:
        return self._sector

    def write_at(self, offset: int, data: bytes) -> int:
        return os.pwrite(self._wfd, data, offset)

    def read_at(self, offset: int, length: int) -> bytes:
        out = bytearray()
        while len(out) < length:
            piece = os.pread(self._rfd, length - len(out), offset + len(out))
            if not piece:
                break
            out.extend(piece)
        return bytes(out)

    def flush(self) -> None:
        os.fsync(self._wfd)
        advise = getattr(os, "posix_fadvise", None)
        if advise is not None:
            advise(self._rfd, 0, 0, os.POSIX_FADV_DONTNEED)

    def close(self) -> None:
        for fd in (self._wfd, self._rfd):
            try:
                os.close(fd)
            except OSError:
                logger.warning("restore_target_close_failed", path=self.path)


# --------------------------------------------------------------------------
# Identity and plan
# --------------------------------------------------------------------------


class TargetIdentity(BaseModel):
    """The restore target as read from the host when the plan was made."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    serial: str
    model: str
    size_bytes: int
    stable_id: str | None = None
    is_system_disk: bool = False
    mounted_at: tuple[str, ...] = ()
    kind: Literal["block_device", "file"] = "block_device"


def target_identity_from_probe(probe: dict[str, Any]) -> TargetIdentity:
    """A target identity from a helper ``probe_capabilities``-shaped answer."""
    device = probe.get("device") or {}
    return TargetIdentity(
        path=str(device.get("path", "")),
        serial=str(device.get("serial", "") or ""),
        model=str(device.get("model", "") or ""),
        size_bytes=int(device.get("size_bytes", 0) or 0),
        stable_id=(str(device["by_id_path"]) if device.get("by_id_path") else None),
        is_system_disk=bool(device.get("is_system_disk")),
        mounted_at=tuple(str(m) for m in device.get("mounted_at") or ()),
        kind="block_device",
    )


def file_target_identity(path: Path | str) -> TargetIdentity:
    """Identity of an image file used as a restore target.

    A file has no serial; its stable id is its device and inode number, which
    is also the value an operator types to confirm (see
    :func:`confirmation_token`).
    """
    target = Path(path)
    info = target.stat()
    return TargetIdentity(
        path=str(target),
        serial="",
        model="regular-file",
        size_bytes=info.st_size,
        stable_id=f"file-inode:{info.st_dev}:{info.st_ino}",
        kind="file",
    )


def confirmation_token(identity: TargetIdentity) -> str:
    """What the operator types to confirm: the serial, else the stable id."""
    return identity.serial or (identity.stable_id or "")


class RestorePlan(BaseModel):
    """What a restore would write, where, and why it may or may not run."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    backup_id: str
    backup_record_digest: str
    image_path: str
    image_sha256: str
    image_size_bytes: int
    chunk_bytes: int
    source: SourceIdentity
    target: TargetIdentity
    identity_relation: Literal["same_device", "different_device", "undetermined"]
    identity_statement: str
    write_offset: int
    write_length: int
    #: Exclusive end of the written range.
    write_end: int
    target_tail_untouched_bytes: int
    assumed_write_bytes_per_sec: int
    estimated_write_seconds: int
    estimated_verify_seconds: int
    blocking: tuple[str, ...]
    limitations: tuple[str, ...]
    planned_at: datetime
    plan_digest: str = ""

    @property
    def executable(self) -> bool:
        return not self.blocking


def plan_digest_of(plan: RestorePlan) -> str:
    """SHA-256 of the canonical bytes of every field but the digest itself."""
    body = plan.model_dump(mode="json", exclude={"plan_digest"})
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def _relation(
    source: SourceIdentity, target: TargetIdentity
) -> tuple[Literal["same_device", "different_device", "undetermined"], str]:
    if source.stable_id and target.stable_id and source.stable_id == target.stable_id:
        return "same_device", (
            f"The target {target.path} has the stable id recorded for the backup's "
            "source: this restores the device from its own backup."
        )
    if source.serial and target.serial:
        same = (source.serial, source.model, source.size_bytes) == (
            target.serial,
            target.model,
            target.size_bytes,
        )
        if same:
            return "same_device", (
                f"The target {target.path} reports the serial, model and size "
                "recorded for the backup's source: this restores the device from "
                "its own backup."
            )
        return "different_device", (
            f"The target {target.path} (serial {target.serial}) is NOT the "
            f"backup's source (serial {source.serial}). Restoring onto a "
            "different device is allowed; its current contents are replaced."
        )
    return "undetermined", (
        "Whether the target is the backup's source cannot be established: one of "
        "them reports no serial. The restore is treated as onto a different "
        "device, and its current contents are replaced."
    )


def plan_restore(
    record: BackupRecord,
    target: TargetIdentity,
    *,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    assumed_rate: int = ASSUMED_WRITE_BYTES_PER_SEC,
) -> RestorePlan:
    """Plan a restore of ``record`` onto ``target``. Pure, apart from a ``stat``.

    Never raises for an unsafe target: the reasons are the plan's ``blocking``
    list, and :func:`require_executable` refuses on them. A record whose digest
    does not hold raises, because nothing it says can be planned from.
    """
    check_record_digest(record)
    blocking: list[str] = []
    if target.is_system_disk:
        blocking.append(f"{target.path} hosts the running system (boot/root disk)")
    if target.mounted_at:
        blocking.append(
            f"{target.path} has mounted filesystems: {', '.join(target.mounted_at)}"
        )
    if target.size_bytes < record.image_size_bytes:
        blocking.append(
            f"{target.path} is {target.size_bytes} bytes; the image is "
            f"{record.image_size_bytes}. The target is too small."
        )
    if record.image_size_bytes <= 0:
        blocking.append("the backup image is empty")
    if not confirmation_token(target):
        blocking.append(
            f"{target.path} reports no serial and no stable id, so it cannot be "
            "confirmed by typing one"
        )
    image = Path(record.image_path)
    try:
        if target.kind == "file" and image.exists() and image.samefile(target.path):
            blocking.append("the target is the backup image itself")
    except OSError:
        blocking.append(f"{target.path} could not be compared with the image")
    for sector in (512, 4096):
        if record.chunk_bytes % sector:
            blocking.append(
                f"the record's chunk size {record.chunk_bytes} is not a multiple "
                f"of {sector}-byte sectors"
            )
            break

    relation, statement = _relation(record.source, target)
    length = record.image_size_bytes
    tail = max(0, target.size_bytes - length)
    limitations = [_LIMIT_READBACK, _LIMIT_PROVENANCE]
    if tail:
        limitations.append(_LIMIT_TAIL.format(tail=tail))
    limitations.extend(record.limitations)
    rate = max(1, assumed_rate)
    draft = RestorePlan(
        backup_id=record.backup_id,
        backup_record_digest=record.record_digest,
        image_path=record.image_path,
        image_sha256=record.image_sha256,
        image_size_bytes=length,
        chunk_bytes=record.chunk_bytes,
        source=record.source,
        target=target,
        identity_relation=relation,
        identity_statement=statement,
        write_offset=0,
        write_length=length,
        write_end=length,
        target_tail_untouched_bytes=tail,
        assumed_write_bytes_per_sec=rate,
        estimated_write_seconds=-(-length // rate),
        estimated_verify_seconds=-(-length // rate),
        blocking=tuple(blocking),
        limitations=tuple(limitations),
        planned_at=clock(),
    )
    return draft.model_copy(update={"plan_digest": plan_digest_of(draft)})


def require_executable(plan: RestorePlan) -> None:
    """Raise :class:`WorkflowGateRefused` if the plan's digest or blocking fails."""
    reasons = list(plan.blocking)
    if plan.plan_digest != plan_digest_of(plan):
        reasons.append("the restore plan was altered after it was made")
    if reasons:
        raise WorkflowGateRefused(
            "REFUSED: the restore plan cannot run: "
            + "; ".join(reasons)
            + ". Nothing was written.",
            why_blocked=reasons,
            remediation=(
                "Resolve every reason by hand and open a new restore workflow. "
                "Nothing here unmounts or retries on its own."
            ),
        )


def plan_binding(plan: RestorePlan) -> dict[str, Any]:
    """The fields of a plan that must not change between approval and write."""
    target = plan.target
    return {
        "target_path": target.path,
        "target_serial": target.serial,
        "target_model": target.model,
        "target_size_bytes": target.size_bytes,
        "target_stable_id": target.stable_id,
        "target_kind": target.kind,
        "identity_relation": plan.identity_relation,
        "backup_record_digest": plan.backup_record_digest,
        "image_sha256": plan.image_sha256,
        "image_size_bytes": plan.image_size_bytes,
        "write_offset": plan.write_offset,
        "write_length": plan.write_length,
        "chunk_bytes": plan.chunk_bytes,
    }


def restore_plan_drift(approved: RestorePlan, fresh: RestorePlan) -> list[str]:
    """One sentence per bound field that differs, plus the fresh plan's blocking."""
    was, now = plan_binding(approved), plan_binding(fresh)
    out = [
        f"{key.replace('_', ' ')} changed since the restore was planned: recorded "
        f"{was[key]!r}, now {now[key]!r}"
        for key in was
        if was[key] != now[key]
    ]
    out.extend(fresh.blocking)
    return out


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------


class UnwritableSpan(BaseModel):
    """A byte range the target refused to accept."""

    model_config = ConfigDict(frozen=True)

    offset: int
    length: int
    error: str


class RestoreVerification(BaseModel):
    """Read-back of the written range, compared with the image."""

    model_config = ConfigDict(frozen=True)

    passed: bool
    expected_sha256: str
    actual_sha256: str
    bytes_verified: int
    mismatched_chunks: tuple[int, ...]
    first_mismatch: ChunkMismatch | None
    unreadable_chunks: tuple[int, ...]
    verified_at: datetime


class RestoreResult(BaseModel):
    """What a restore did. Ledgered in full."""

    model_config = ConfigDict(frozen=True)

    job_id: str
    result: Literal["RESTORED_VERIFIED", "RESTORED_VERIFY_FAILED", "INCOMPLETE"]
    backup_id: str
    backup_record_digest: str
    backup_image_path: str
    image_sha256: str
    source: SourceIdentity
    target: TargetIdentity
    identity_relation: str
    plan_digest: str
    write_offset: int
    bytes_planned: int
    bytes_written: int
    unwritable: tuple[UnwritableSpan, ...]
    #: Refused bytes in ranges beyond ``MAX_RECORDED_SPANS``; counted, not listed.
    unwritable_omitted_bytes: int = 0
    verification: RestoreVerification | None
    verification_sha256: str
    started_at: datetime
    finished_at: datetime
    limitations: tuple[str, ...]


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------


class _Tally:
    """How far a run has got. Read by the cancellation handler."""

    def __init__(
        self,
        offset: int,
        *,
        max_consecutive_unwritable: int = MAX_CONSECUTIVE_UNWRITABLE_BYTES,
        max_recorded_spans: int = MAX_RECORDED_SPANS,
    ) -> None:
        self.start = offset
        self.written = 0
        self.unwritable = 0
        self.unwritable_omitted = 0
        self.run = 0
        self.first_error = ""
        self.max_run = max_consecutive_unwritable
        self.max_spans = max_recorded_spans
        # [offset, length, error]: mutable so a long bad run extends in place.
        self._spans: list[list[Any]] = []
        self.phase = "RESTORE"

    def refused(self, offset: int, size: int, exc: OSError) -> None:
        """Account ``size`` refused bytes at ``offset``, merging adjacent runs."""
        name = errno.errorcode.get(exc.errno or 0, type(exc).__name__)
        if not self.first_error:
            self.first_error = f"{name} ({exc.strerror or exc})"
        self.unwritable += size
        self.run += size
        last = self._spans[-1] if self._spans else None
        if last is not None and last[0] + last[1] == offset and last[2] == name:
            last[1] += size
        elif len(self._spans) < self.max_spans:
            self._spans.append([offset, size, name])
        else:
            self.unwritable_omitted += size

    def unwritable_spans(self) -> tuple[UnwritableSpan, ...]:
        return tuple(
            UnwritableSpan(offset=o, length=n, error=e) for o, n, e in self._spans
        )

    @property
    def accounted(self) -> int:
        return self.written + self.unwritable


def _append(
    ledger: Ledger | None,
    actor: str,
    operation: str,
    params: dict[str, Any],
    result: dict[str, Any] | None = None,
) -> None:
    if ledger is not None:
        ledger.append(
            actor=actor, operation=operation, params=params, result=result or {}
        )


def _write_fully(
    target: BlockTarget, offset: int, data: bytes, tally: _Tally
) -> None:
    """Write ``data`` at ``offset``, sector by sector where the target refuses.

    A short write continues from where it stopped. An ``OSError`` falls back to
    writing each remaining sector alone, recording each one that still fails
    as unwritable. A write that returns 0 raises: it made no progress and did
    not say why. So does a target that refuses more than
    ``tally.max_run`` bytes in a row.
    """
    view = memoryview(data)
    done = 0
    try:
        while done < len(view):
            count = target.write_at(offset + done, bytes(view[done:]))
            if count <= 0:
                raise OverwriteIncomplete(
                    f"the restore write at offset {offset + done} returned "
                    f"{count} and made no progress",
                    remediation=(
                        "The target is failing writes without an error. Do not "
                        "rely on it; the restore is incomplete."
                    ),
                )
            done += count
            tally.written += count
            tally.run = 0
    except OSError:
        sector = max(1, target.logical_sector)
        position = done
        while position < len(view):
            size = min(sector, len(view) - position)
            try:
                piece = bytes(view[position : position + size])
                count = target.write_at(offset + position, piece)
            except OSError as exc:
                tally.refused(offset + position, size, exc)
                position += size
                if tally.run > tally.max_run:
                    raise OverwriteIncomplete(
                        f"the target refused {tally.run} consecutive bytes ending "
                        f"at offset {offset + position}: {tally.first_error}. "
                        "The restore stops rather than walk the rest of the image "
                        "against a target that is not accepting writes",
                        remediation=(
                            "Do not rely on the target. Check the device, its "
                            "cable and its write protection, then restore again."
                        ),
                    ) from exc
                continue
            if count != size:
                raise OverwriteIncomplete(
                    f"the sector write at offset {offset + position} wrote {count} "
                    f"of {size} bytes",
                    remediation="The restore is incomplete. Do not rely on the target.",
                ) from None
            tally.written += size
            tally.run = 0
            position += size


def execute_restore(
    record: BackupRecord,
    plan: RestorePlan,
    target: BlockTarget,
    *,
    job_id: str,
    actor: str = "sanctum",
    ledger: Ledger | None = None,
    verify: bool = True,
    checkpoint_bytes: int = CHECKPOINT_BYTES,
    max_consecutive_unwritable: int = MAX_CONSECUTIVE_UNWRITABLE_BYTES,
    max_recorded_spans: int = MAX_RECORDED_SPANS,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> Generator[Progress, None, RestoreResult]:
    """Write the backup image onto ``target`` as planned, then read it back.

    Every call writes: there is no non-writing mode. The caller owns
    ``target`` and closes it.
    """
    check_record_digest(record)
    require_executable(plan)
    if plan.backup_record_digest != record.record_digest:
        raise WorkflowGateRefused(
            "REFUSED: the restore plan was made for a different backup record. "
            "Nothing was written.",
            why_blocked=["the plan's backup record digest is not this record's"],
        )
    started_at = clock()
    common = {
        "job_id": job_id,
        "backup_id": record.backup_id,
        "plan_digest": plan.plan_digest,
        "target": plan.target.model_dump(mode="json"),
        "write_offset": plan.write_offset,
        "write_length": plan.write_length,
    }

    if target is None:  # a caller outside the type checker; fail closed
        raise WorkflowGateRefused(
            "REFUSED: a restore needs an opened target. Nothing was written.",
            why_blocked=["no target was opened"],
        )
    reasons: list[str] = []
    if target.size_bytes != plan.target.size_bytes:
        reasons.append(
            f"the opened target is {target.size_bytes} bytes; the plan recorded "
            f"{plan.target.size_bytes}"
        )
    sector = target.logical_sector
    if sector <= 0 or plan.write_length % sector or plan.chunk_bytes % sector:
        reasons.append(
            f"the image length {plan.write_length} and chunk size "
            f"{plan.chunk_bytes} are not whole {sector}-byte sectors of the target"
        )
    image = Path(record.image_path)
    try:
        if image.stat().st_size != record.image_size_bytes:
            reasons.append("the backup image is no longer the recorded size")
    except OSError:
        reasons.append("the backup image is not readable")
    if reasons:
        raise WorkflowGateRefused(
            "REFUSED at the restore engine: " + "; ".join(reasons)
            + ". Nothing was written.",
            why_blocked=reasons,
        )

    _append(ledger, actor, "restore.start", common)
    tally = _Tally(
        plan.write_offset,
        max_consecutive_unwritable=max_consecutive_unwritable,
        max_recorded_spans=max_recorded_spans,
    )
    whole = hashlib.sha256()
    begun = time.monotonic()
    next_checkpoint = checkpoint_bytes
    try:
        yield _progress(
            job_id, "RESTORE", 0, plan.write_length, 0,
            f"restoring {plan.write_length} bytes onto {plan.target.path}",
        )
        with image.open("rb") as source:  # read-only by construction
            index = 0
            while tally.accounted < plan.write_length:
                want = min(plan.chunk_bytes, plan.write_length - tally.accounted)
                data = source.read(want)
                if len(data) != want:
                    raise EvidenceIntegrityError(
                        f"the backup image ended at byte {tally.accounted + len(data)}"
                        f"; the record says {plan.write_length}",
                        remediation="Verify the backup before restoring from it.",
                    )
                actual = hashlib.sha256(data).hexdigest()
                expected = (
                    record.chunk_hashes[index]
                    if index < len(record.chunk_hashes)
                    else ""
                )
                if actual != expected:
                    raise EvidenceIntegrityError(
                        f"chunk {index} of the backup image (bytes "
                        f"{index * plan.chunk_bytes}-"
                        f"{index * plan.chunk_bytes + len(data) - 1}) does not match "
                        "its recorded hash; it was not written",
                        remediation=(
                            "The image changed since it was recorded. Verify the "
                            "backup and do not restore from it."
                        ),
                    )
                whole.update(data)
                _write_fully(
                    target, plan.write_offset + tally.accounted, data, tally
                )
                index += 1
                if tally.accounted >= next_checkpoint:
                    _append(
                        ledger, actor, "restore.checkpoint",
                        {
                            **common,
                            "bytes_written": tally.written,
                            "bytes_unwritable": tally.unwritable,
                            "range_accounted": [
                                plan.write_offset,
                                plan.write_offset + tally.accounted,
                            ],
                        },
                    )
                    next_checkpoint += checkpoint_bytes
                yield _progress(
                    job_id, "RESTORE", tally.accounted, plan.write_length,
                    _rate(tally.accounted, begun),
                    f"restored chunk {index}",
                )
        target.flush()
        if tally.accounted != plan.write_length:
            raise OverwriteIncomplete(
                f"the restore accounted for {tally.accounted} of "
                f"{plan.write_length} planned bytes",
                remediation="The restore is incomplete. Do not rely on the target.",
            )
        if whole.hexdigest() != record.image_sha256:
            raise EvidenceIntegrityError(
                "every chunk matched its recorded hash but the whole image does "
                "not match the recorded SHA-256; the record is inconsistent",
                remediation="Re-create the backup record and verify it.",
            )
    except GeneratorExit:
        _record_stop(ledger, actor, "restore.cancelled", common, tally, "cancelled")
        raise
    except (OSError, EvidenceIntegrityError, OverwriteIncomplete) as exc:
        _record_stop(ledger, actor, "restore.aborted", common, tally, str(exc))
        raise

    _append(
        ledger, actor, "restore.complete",
        {
            **common,
            "bytes_written": tally.written,
            "bytes_unwritable": tally.unwritable,
            "unwritable": [
                span.model_dump(mode="json") for span in tally.unwritable_spans()
            ],
            "unwritable_omitted_bytes": tally.unwritable_omitted,
        },
        {"image_sha256": record.image_sha256},
    )

    verification: RestoreVerification | None = None
    if verify:
        tally.phase = "VERIFY"
        try:
            verification = yield from verify_restored(
                record, plan, target, job_id=job_id, clock=clock
            )
        except GeneratorExit:
            _record_stop(
                ledger, actor, "restore.verify_cancelled", common, tally,
                "the write completed; read-back verification was cancelled",
            )
            raise
        _append(
            ledger, actor, "restore.verify",
            {**common, "verification": verification.model_dump(mode="json")},
            {"passed": verification.passed},
        )

    if tally.unwritable:
        outcome: Literal[
            "RESTORED_VERIFIED", "RESTORED_VERIFY_FAILED", "INCOMPLETE"
        ] = "INCOMPLETE"
    elif verification is not None and verification.passed:
        outcome = "RESTORED_VERIFIED"
    else:
        outcome = "RESTORED_VERIFY_FAILED"
    return _result(
        record, plan, job_id, outcome, tally, verification, started_at, clock()
    )


def verify_restored(
    record: BackupRecord,
    plan: RestorePlan,
    target: BlockTarget,
    *,
    job_id: str = "restore-verify",
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> Generator[Progress, None, RestoreVerification]:
    """Read the written range back, hash it, and compare with the image's hashes."""
    whole = hashlib.sha256()
    mismatched: list[int] = []
    unreadable: list[int] = []
    first: ChunkMismatch | None = None
    done = 0
    index = 0
    begun = time.monotonic()
    while done < plan.write_length:
        want = min(plan.chunk_bytes, plan.write_length - done)
        expected = (
            record.chunk_hashes[index] if index < len(record.chunk_hashes) else ""
        )
        try:
            data = target.read_at(plan.write_offset + done, want)
        except OSError:
            data = b""
            unreadable.append(index)
        whole.update(data)
        actual = hashlib.sha256(data).hexdigest()
        if len(data) != want or actual != expected:
            mismatched.append(index)
            if first is None:
                first = ChunkMismatch(
                    index=index,
                    offset=plan.write_offset + done,
                    length=want,
                    expected_sha256=expected,
                    actual_sha256=actual,
                )
        done += want
        index += 1
        yield _progress(
            job_id, "VERIFY", done, plan.write_length, _rate(done, begun),
            f"read back chunk {index}",
        )
    actual_sha = whole.hexdigest()
    return RestoreVerification(
        passed=not mismatched and actual_sha == record.image_sha256,
        expected_sha256=record.image_sha256,
        actual_sha256=actual_sha,
        bytes_verified=done,
        mismatched_chunks=tuple(mismatched),
        first_mismatch=first,
        unreadable_chunks=tuple(unreadable),
        verified_at=clock(),
    )


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _stop_note(tally: _Tally, end: int) -> str:
    if tally.phase != "RESTORE":
        return (
            "The full range was written; its read-back was not completed, so "
            "the restore is unverified."
        )
    if tally.written == 0:
        return (
            "Nothing was written: the target refused every write and still "
            "holds what it held before."
        )
    note = (
        f"The target is PARTIALLY OVERWRITTEN: bytes {tally.start} to "
        f"{end} (exclusive) were reached, {tally.written} of them written with "
        "the backup image; the rest of the planned range holds whatever it held "
        "before. It is neither the backup nor its previous contents."
    )
    if tally.unwritable:
        note += (
            f" {tally.unwritable} byte(s) inside that range were refused and "
            "keep their previous contents."
        )
    return note


def _record_stop(
    ledger: Ledger | None,
    actor: str,
    operation: str,
    common: dict[str, Any],
    tally: _Tally,
    reason: str,
) -> None:
    """The entry that says how much of the target was overwritten."""
    end = tally.start + tally.accounted
    try:
        _append(
            ledger, actor, operation,
            {
                **common,
                "phase": tally.phase,
                "reason": reason,
                "bytes_written": tally.written,
                "bytes_unwritable": tally.unwritable,
                "range_written": [tally.start, end],
                "note": _stop_note(tally, end),
            },
        )
    except (OSError, ValueError, RuntimeError) as exc:  # pragma: no cover
        logger.warning("restore_stop_not_recorded", error=str(exc))


def _rate(done: int, begun: float) -> int:
    span = time.monotonic() - begun
    return int(done / span) if span > 0 else 0


def _progress(
    job_id: str, phase: str, done: int, total: int, rate: int, message: str
) -> Progress:
    pct = 10_000 if total <= 0 else min(10_000, done * 10_000 // total)
    eta = (total - done) // rate if rate > 0 else 0
    return Progress(
        job_id=job_id,
        phase=phase,
        pct_bp=pct,
        bytes_done=done,
        bytes_total=total,
        throughput_bytes_per_sec=rate,
        eta_seconds=eta,
        message=message,
    )


def _result(
    record: BackupRecord,
    plan: RestorePlan,
    job_id: str,
    outcome: Literal["RESTORED_VERIFIED", "RESTORED_VERIFY_FAILED", "INCOMPLETE"],
    tally: _Tally,
    verification: RestoreVerification | None,
    started_at: datetime,
    finished_at: datetime,
) -> RestoreResult:
    limitations = list(plan.limitations)
    if verification is None:
        limitations.insert(0, "UNVERIFIED: the written range was not read back.")
    return RestoreResult(
        job_id=job_id,
        result=outcome,
        backup_id=record.backup_id,
        backup_record_digest=record.record_digest,
        backup_image_path=record.image_path,
        image_sha256=record.image_sha256,
        source=record.source,
        target=plan.target,
        identity_relation=plan.identity_relation,
        plan_digest=plan.plan_digest,
        write_offset=plan.write_offset,
        bytes_planned=plan.write_length,
        bytes_written=tally.written,
        unwritable=tally.unwritable_spans(),
        unwritable_omitted_bytes=tally.unwritable_omitted,
        verification=verification,
        verification_sha256=verification.actual_sha256 if verification else "",
        started_at=started_at,
        finished_at=finished_at,
        limitations=tuple(limitations),
    )
