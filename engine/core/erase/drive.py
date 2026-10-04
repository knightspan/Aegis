"""Whole-device sanitization. Destructive: every call writes to the device.

The read-only decision is :func:`preview`; :func:`execute` always executes.

Linux only, by construction. The overwrite path needs ``O_DIRECT`` with
logical-block alignment, the ``BLKGETSIZE64`` ioctl and sysfs queue attributes;
the firmware paths need ATA and NVMe pass-through. A cross-platform shim would
have to fake all of that, and being wrong here destroys evidence, so this module
refuses to import anywhere else. ``core.erase.files`` stays cross-platform.

Structure:

* :func:`select_method` decides *what* to do. It delegates the capability
  decision table to :func:`core.device.capabilities.recommend_method` and only
  layers policy on top: honour an explicitly requested legacy method with a
  warning attached, and refuse rather than downgrade when a freeze blocks the
  only Purge mechanism.
* :func:`execute` runs the job as a generator over six phases, emitting
  :class:`Progress` and recording a ledger entry for each.
* One private dispatcher per :class:`EraseMethod`. Only ``_overwrite`` is
  performed by this process; the rest hand off to drive firmware.

The single most important rule in this file: **never silently downgrade.** If a
Purge was asked for and cannot be delivered, raise. An operator who believes
they purged a drive that was only cleared is worse off than one who got an
error.
"""

from __future__ import annotations

import errno
import mmap
import os
import struct
import sys
import time
from collections import deque
from collections.abc import Callable, Generator, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

from core.device import guard, hidden_areas, media
from core.device._sysio import SystemProbe
from core.device.capabilities import purge_mechanisms, recommend_method
from core.device.enumerate import get_device
from core.erase import calibrate as calibrate_mod
from core.erase import patterns as pattern_mod
from core.erase import verify as verify_mod
from core.erase.sink import ChainLedgerSink, LedgerSink
from core.errors import (
    DeviceFrozen,
    DeviceVanished,
    GeometryRefused,
    OverwriteIncomplete,
    PlatformUnsupported,
    UnsupportedCapability,
)
from core.models import (
    Device,
    DeviceCapabilities,
    EraseCheckpoint,
    EraseJob,
    EraseMethod,
    ErasePhase,
    ErasePlan,
    ErasePreview,
    EraseResult,
    HiddenAreaReport,
    PlannedErase,
    Progress,
    ResidualFinding,
    SanitizationLevel,
    UnwritableRange,
    VerificationResult,
)

__all__ = [
    "Geometry",
    "LedgerSink",
    "ChainLedgerSink",
    "select_method",
    "preview",
    "device_geometry",
    "execute",
    "resume",
    "ATA_RECOVERY_PASSWORD",
]

logger = structlog.get_logger(__name__)


def _require_linux() -> None:
    """Refuse to load on a platform whose block-device semantics differ."""
    if sys.platform != "linux":
        raise PlatformUnsupported(
            "Whole-device sanitization requires Linux block-device semantics "
            f"(O_DIRECT alignment, BLKGETSIZE64, ATA/NVMe pass-through); this "
            f"host reports sys.platform={sys.platform!r}.",
            remediation=(
                "This module is the Linux engine. On Windows and macOS the "
                "whole-drive clear runs through the platform adapter and "
                "core.erase.blockclear; use the Sanitize screen there."
            ),
        )


_require_linux()


KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB

#: ioctl request number for the 64-bit device size, in bytes.
BLKGETSIZE64 = 0x80081272

DEFAULT_BUFFER_BYTES = 4 * MIB
CHECKPOINT_INTERVAL_BYTES = 256 * MIB
THROUGHPUT_WINDOW_S = 30.0
DEFAULT_SECTOR_BYTES = 512

#: Fixed password used for the ATA SECURITY ERASE sequence.
#:
#: The sequence is SET PASSWORD -> ERASE PREPARE -> ERASE UNIT. A process that
#: dies between the first and last step leaves the drive LOCKED and unusable
#: until the password is cleared. A fixed, published value means an operator can
#: always recover the drive by hand. This is a deliberate trade of secrecy for
#: recoverability: the password protects nothing here, it is a transient
#: precondition of the erase command. Documented in docs/limitations.md.
ATA_RECOVERY_PASSWORD = "SanctumForensics"

_LEGACY_DOD_WARNING = (
    "DOD_5220_22_M_3PASS is a legacy method. NIST SP 800-88r2 (September 2025) "
    "states that multi-pass overwrite is not needed for clear, and calls the "
    "DoD 5220.22-M pass-count language obsolete (Appendix D). This tool "
    "measures no benefit over a single pass, and on flash media it is actively "
    "harmful: each extra pass consumes program/erase cycles without reaching "
    "remapped or over-provisioned blocks."
)

#: Methods executed by drive firmware, which cover the full media including any
#: HPA/DCO by design. The host does not need to unlock hidden areas for these.
_FIRMWARE_METHODS = frozenset(set(EraseMethod) - set(pattern_mod.SOFTWARE_METHODS))

#: Methods an operator may request explicitly. Firmware methods are never
#: overridable: they are selected from probed capability or not at all.
_OVERRIDABLE = frozenset(
    {EraseMethod.SINGLE_PASS_OVERWRITE, EraseMethod.DOD_5220_22_M_3PASS}
)


# --------------------------------------------------------------------------
# Geometry
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Geometry:
    """Authoritative device geometry, read from the kernel rather than lsblk."""

    size_bytes: int
    logical_block_size: int
    physical_block_size: int


def _sysfs_int(probe: SystemProbe, kernel_name: str, attr: str, default: int) -> int:
    text = probe.read_text(probe.sysfs_root / "block" / kernel_name / "queue" / attr)
    if text is None:
        return default
    try:
        return int(text.strip())
    except ValueError:
        return default


def device_geometry(path: str, probe: SystemProbe | None = None) -> Geometry:
    """Read the true size and block sizes for ``path``.

    ``lsblk`` reports a cached size that can disagree with the device after an
    HPA change, so the size comes from the ``BLKGETSIZE64`` ioctl. Block sizes
    come from sysfs. Every offset calculation in this module uses these values.
    """
    import fcntl  # Linux-only; imported after the platform guard has run.

    probe = probe or SystemProbe()
    kernel_name = os.path.basename(path)

    fd = os.open(path, os.O_RDONLY)
    try:
        raw = fcntl.ioctl(fd, BLKGETSIZE64, struct.pack("Q", 0))
        (size_bytes,) = struct.unpack("Q", raw)
    finally:
        os.close(fd)

    return Geometry(
        size_bytes=size_bytes,
        logical_block_size=_sysfs_int(
            probe, kernel_name, "logical_block_size", DEFAULT_SECTOR_BYTES
        ),
        physical_block_size=_sysfs_int(
            probe, kernel_name, "physical_block_size", DEFAULT_SECTOR_BYTES
        ),
    )


# --------------------------------------------------------------------------
# Method selection
# --------------------------------------------------------------------------


def select_method(
    device: Device,
    capabilities: DeviceCapabilities,
    target_level: SanitizationLevel,
    *,
    requested: EraseMethod | None = None,
) -> tuple[EraseMethod, list[str]]:
    """Choose the method for ``target_level``, with any caveats attached.

    The capability decision table is not reimplemented here; it lives in
    :func:`core.device.capabilities.recommend_method`. This function adds only
    the two policy rules that sit above it.

    Args:
        device: The target, used for media-specific warnings.
        capabilities: Probed capability for that device.
        target_level: The NIST SP 800-88r2 sanitization method being asked for.
        requested: A method the operator named explicitly. Only the two software
            methods may be requested; firmware methods are capability-selected.

    Returns:
        The chosen method and a list of limitation strings to carry into the
        report.

    Raises:
        DeviceFrozen: ``target_level`` is PURGE and an ATA security freeze is
            what stands between this drive and a Purge. Never downgraded.
        UnsupportedCapability: ``target_level`` is unreachable, or ``requested``
            names a method that is not operator-selectable.
    """
    limitations: list[str] = []

    if requested is not None:
        if requested not in _OVERRIDABLE:
            raise UnsupportedCapability(
                f"{requested.value} cannot be requested directly; firmware "
                "methods are selected from probed capability only.",
                remediation=(
                    "Ask for a sanitization level and let capability probing "
                    "choose the mechanism."
                ),
            )
        if target_level is not SanitizationLevel.CLEAR:
            # Refused here, at planning, rather than left to _achieved_level at
            # the report: a plan for a Purge that is really a host overwrite
            # would run the whole overwrite before anything said it was not one.
            raise UnsupportedCapability(
                f"{requested.value} is a host overwrite and reaches Clear at "
                f"most; it cannot deliver the {target_level.value} requested.",
                remediation=(
                    "Request CLEAR with this method, or request PURGE without "
                    "naming a method so capability probing chooses one the "
                    "device implements."
                ),
            )
        if requested is EraseMethod.DOD_5220_22_M_3PASS:
            limitations.append(_LEGACY_DOD_WARNING)
            # Not `not device.rotational`: a USB bridge does not clear the
            # kernel's rotational flag, so that test was False for every USB
            # flash stick and this warning never reached the operator holding
            # one. See core.device.media.is_flash.
            flash, flash_reason = media.is_flash(device)
            if flash:
                limitations.append(
                    "Target is flash media; the extra DoD passes consume "
                    "program/erase cycles for no security benefit. "
                    f"Determined to be flash because {flash_reason}."
                )
        logger.info(
            "method_override", requested=requested.value, path=device.path
        )
        return requested, limitations

    # On flash an enhanced erase is a Clear mechanism whether frozen or not, so
    # the freeze is not what stands between this drive and a Purge, and saying
    # it is would send the operator to power-cycle for nothing.
    frozen_blocks_purge = (
        target_level is SanitizationLevel.PURGE
        and capabilities.security_frozen
        and capabilities.ata_enhanced_erase
        and SanitizationLevel.PURGE not in capabilities.achievable_levels
        and not media.is_flash(device)[0]
    )
    if frozen_blocks_purge:
        raise DeviceFrozen(
            f"{device.path} supports an enhanced security erase, but ATA "
            "security is frozen so it cannot be issued. Refusing to fall back "
            "to a Clear-level overwrite, which would not be the Purge you asked "
            "for."
        )

    method = recommend_method(capabilities, target_level, device=device)
    limitations.extend(capabilities.limitations)
    return method, limitations


def _method_evidence(
    method: EraseMethod,
    capabilities: DeviceCapabilities,
    flash: bool,
    flash_reason: str,
) -> list[str]:
    """The probed facts that put ``method`` first, one sentence each.

    Stated as what the probe returned rather than as a conclusion, so a reader
    who doubts the choice has something to check it against.
    """
    nvme = capabilities.nvme_sanicap
    medium = (
        f"The device was determined to be flash because {flash_reason}."
        if flash
        else f"The device was not determined to be flash: {flash_reason}."
    )
    if method is EraseMethod.ATA_SANITIZE_BLOCK_ERASE:
        return [
            "hdparm -I listed BLOCK_ERASE_EXT in the ATA SANITIZE feature set. "
            "The drive erases every block internally, including remapped and "
            "over-provisioned ones a host overwrite cannot address."
        ]
    if method is EraseMethod.ATA_SANITIZE_CRYPTO_SCRAMBLE:
        return [
            "hdparm -I listed CRYPTO_SCRAMBLE_EXT in the ATA SANITIZE feature "
            "set, and BLOCK_ERASE_EXT was not listed. The drive replaces its "
            "media encryption key."
        ]
    if method is EraseMethod.ATA_SANITIZE_OVERWRITE:
        return [
            "hdparm -I listed OVERWRITE_EXT in the ATA SANITIZE feature set, and "
            "neither BLOCK_ERASE_EXT nor CRYPTO_SCRAMBLE_EXT was listed.",
            medium + " SANITIZE overwrite counts as Purge on magnetic media only.",
        ]
    if method is EraseMethod.NVME_SANITIZE_BLOCK:
        reported = [
            name for name in ("block_erase", "crypto_erase") if nvme.get(name)
        ]
        return [
            "nvme id-ctrl reported SANICAP " + " and ".join(reported) + ". NVMe "
            "sanitize acts at controller scope: it destroys every namespace on "
            "the controller, not only the one named."
        ]
    if method is EraseMethod.SED_CRYPTO_ERASE:
        return [
            "sedutil-cli reported an Opal SSC, and no ATA or NVMe sanitize "
            "mechanism ranked above it was reported."
        ]
    if method is EraseMethod.NVME_FORMAT_SES1:
        return [
            "nvme id-ctrl reported cryptographic erase as a Format NVM attribute "
            "(FNA), and SANICAP reported neither block erase nor crypto erase."
        ]
    if method is EraseMethod.ATA_SECURITY_ERASE_ENHANCED:
        return [
            "hdparm -I reported enhanced SECURITY ERASE support with security not "
            "frozen, and no mechanism the engine ranks above it was reported.",
            medium + " Enhanced erase counts as Purge on magnetic media only.",
        ]
    notes = [
        "Clear is always delivered by one host overwrite pass over every "
        "addressable LBA. NIST SP 800-88r2 states that multi-pass overwrite is "
        "not needed for clear."
    ]
    if flash:
        notes.append(
            medium + " A host overwrite cannot reach blocks the flash translation "
            "layer has remapped, over-provisioned capacity, or the write cache."
        )
    return notes


def _purge_requires(device: Device, flash: bool) -> str:
    """What ``device`` would have to report before Purge became reachable."""
    opal = (
        " A TCG Opal cryptographic erase would also count, but this build cannot "
        "issue one: it has no way to accept the PSID printed on the drive label."
    )
    if device.transport == "nvme":
        return (
            "NVMe SANITIZE with block erase or crypto erase in SANICAP, or Format "
            "NVM with cryptographic erase in FNA." + opal
        )
    bridge = (
        f" On the {device.transport} bus these ATA commands usually do not pass "
        "the bridge at all; connect the drive directly to a SATA port and re-probe."
        if device.transport in {"usb", "mmc"}
        else ""
    )
    if flash:
        return (
            "ATA SANITIZE block erase or crypto scramble. Enhanced SECURITY ERASE "
            "and SANITIZE overwrite do not count on flash." + bridge + opal
        )
    return (
        "ATA SANITIZE block erase, crypto scramble or overwrite, or enhanced "
        "SECURITY ERASE with security not frozen." + bridge + opal
    )


def preview(device: Device, capabilities: DeviceCapabilities) -> ErasePreview:
    """What an erase request would run on ``device``, for each level.

    Calls :func:`select_method` exactly as :func:`execute` does, with no method
    requested, and records its answer or its refusal. Nothing is opened and
    nothing is written. The operator sees this before committing; the job
    re-probes the device and re-runs the same selection, so the two agree
    unless the device's capabilities changed in between.
    """
    flash, flash_reason = media.is_flash(device)
    plans: list[PlannedErase] = []
    for level in (SanitizationLevel.CLEAR, SanitizationLevel.PURGE):
        try:
            method, limits = select_method(device, capabilities, level)
        except (DeviceFrozen, UnsupportedCapability) as exc:
            plans.append(
                PlannedErase(
                    level=level,
                    reachable=False,
                    limitations=list(capabilities.limitations),
                    refusal=exc.message,
                    remediation=exc.remediation,
                )
            )
            continue
        executable = method is not EraseMethod.SED_CRYPTO_ERASE
        plans.append(
            PlannedErase(
                level=level,
                reachable=True,
                method=method,
                justification=_justify(method, level, device),
                evidence=_method_evidence(method, capabilities, flash, flash_reason),
                executable=executable,
                not_executable_reason=(
                    ""
                    if executable
                    else "An Opal revert needs the PSID printed on the drive "
                    "label, and this build has no way to accept it. The job "
                    "would refuse rather than erase."
                ),
                limitations=limits,
            )
        )
    return ErasePreview(
        flash=flash,
        flash_reason=flash_reason,
        purge_mechanisms=purge_mechanisms(capabilities, device),
        purge_requires=_purge_requires(device, flash),
        plans=plans,
    )


def _achieved_level(
    job: EraseJob,
    method: EraseMethod,
    capabilities: DeviceCapabilities,
    verification: VerificationResult,
) -> SanitizationLevel:
    """The sanitization method a finished job may put on its report.

    Purge is claimed only when ``method`` is itself a Purge mechanism for this
    device, as :func:`core.device.capabilities.purge_mechanisms` decides it.
    ``select_method`` already refuses to plan anything else, so this is a
    second check at the point the claim is written, not the first: a report
    must not say Purge for an enhanced erase on flash, or for a host overwrite
    passed in through ``EraseJob.method``, whatever path led there.
    """
    if not verification.passed:
        return SanitizationLevel.CLEAR
    if job.level is SanitizationLevel.PURGE and method not in purge_mechanisms(
        capabilities, job.device
    ):
        return SanitizationLevel.CLEAR
    return job.level


# --------------------------------------------------------------------------
# Overwrite path
# --------------------------------------------------------------------------


@dataclass
class _Throughput:
    """Rolling-window throughput, so a slow tail is visible rather than averaged."""

    window_s: float = THROUGHPUT_WINDOW_S
    samples: deque[tuple[float, int]] = field(default_factory=deque)
    _total: int = 0

    def add(self, nbytes: int, now: float | None = None) -> None:
        stamp = time.monotonic() if now is None else now
        self.samples.append((stamp, nbytes))
        self._total += nbytes
        while self.samples and stamp - self.samples[0][0] > self.window_s:
            self._total -= self.samples.popleft()[1]

    def bps(self, now: float | None = None) -> int:
        """Whole bytes per second. Reported and ledgered, so never a float."""
        if len(self.samples) < 2:
            return 0
        stamp = time.monotonic() if now is None else now
        span = stamp - self.samples[0][0]
        return int(self._total / span) if span > 0 else 0

    def eta_seconds(self, remaining: int, now: float | None = None) -> int:
        rate = self.bps(now)
        return remaining // rate if rate > 0 else 0


def _open_for_write(
    path: str, limitations: list[str]
) -> tuple[int, bool]:
    """Open ``path`` for writing, preferring O_DIRECT. Returns ``(fd, direct)``."""
    direct_flag = getattr(os, "O_DIRECT", 0)
    if direct_flag:
        try:
            return os.open(path, os.O_WRONLY | os.O_SYNC | direct_flag), True
        except OSError as exc:
            if exc.errno not in {errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP}:
                raise
            limitations.append(
                f"{path} rejected O_DIRECT ({errno.errorcode.get(exc.errno, '?')}); "
                "fell back to O_DSYNC buffered writes. Writes still reach the "
                "medium before the call returns, but they pass through the page "
                "cache."
            )
    return os.open(path, os.O_WRONLY | getattr(os, "O_DSYNC", os.O_SYNC)), False


def _stalled(offset: int, remaining: int, count: int) -> OverwriteIncomplete:
    """The exception for a write that returned without writing anything."""
    return OverwriteIncomplete(
        f"the write at offset {offset} returned {count} and made no progress, "
        f"leaving {remaining} byte(s) there unwritten. The run stops rather "
        f"than reporting a complete overwrite over a span it never wrote."
    )


def _write_all(fd: int, buffer: memoryview, offset: int) -> int:
    """Issue ``buffer`` at ``offset`` until every byte of it is written.

    ``os.write`` is allowed to return a short count and no error - a large
    request split by the kernel, a signal, a device that takes part of what it
    was handed. Advancing by the length requested rather than the length
    returned leaves an unwritten hole behind a run that still reports success,
    so the remainder is re-issued from where the count says it stopped.

    Raises:
        OSError: the write failed. What ``EIO`` means is the caller's to decide.
        OverwriteIncomplete: a write returned zero and made no progress. There
            is nothing useful to do with that except stop.
    """
    written = 0
    span = len(buffer)
    while written < span:
        with buffer[written:] as chunk:
            os.lseek(fd, offset + written, os.SEEK_SET)
            count = os.write(fd, chunk)
        if count <= 0:
            raise _stalled(offset + written, span - written, count)
        written += count
    return written


def _write_span(
    fd: int, buffer: memoryview, offset: int, block: int
) -> tuple[int, list[UnwritableRange]]:
    """Write one whole span, and account for every byte of it.

    Returns ``(written, unwritable)``, where ``written`` plus the lengths of the
    unwritable ranges always equals ``len(buffer)``. Nothing is skipped
    silently: a byte is either written or named.

    A short write is finished rather than stepped over. An ``EIO`` hands the
    rest of the span to :func:`_write_block_by_block`, which localises the bad
    sectors so a single one does not cost a four-terabyte wipe.

    A short write on a block device comes back block-aligned, so the salvage
    below starts on a block boundary. If some device ever returns an unaligned
    count, O_DIRECT rejects the next write with ``EINVAL`` and it is raised -
    loudly wrong beats quietly holed.
    """
    span = len(buffer)
    written = 0
    while written < span:
        try:
            with buffer[written:] as chunk:
                os.lseek(fd, offset + written, os.SEEK_SET)
                count = os.write(fd, chunk)
        except OSError as exc:
            if exc.errno != errno.EIO:
                raise
            with buffer[written:] as rest:
                salvaged, bad = _write_block_by_block(
                    fd, rest, offset + written, block
                )
            return written + salvaged, bad
        if count <= 0:
            raise _stalled(offset + written, span - written, count)
        written += count
    return written, []


def _write_block_by_block(
    fd: int, buffer: memoryview, offset: int, block: int
) -> tuple[int, list[UnwritableRange]]:
    """Retry a failed span one block at a time to localise the bad sectors."""
    written = 0
    bad: list[UnwritableRange] = []
    for start in range(0, len(buffer), block):
        # Released explicitly: a slice of a memoryview is itself an export of
        # the underlying mmap, and an mmap with a live export refuses to close.
        # Leaving these to the garbage collector made the whole wipe end in
        # "BufferError: cannot close exported pointers exist" from the finally
        # block that releases the buffer.
        with buffer[start : start + block] as chunk:
            try:
                # Every byte of the block, not one call and a hope: this path
                # runs on media that is already misbehaving, which is where a
                # short write is least surprising and most costly.
                count = _write_all(fd, chunk, offset + start)
            except OSError as exc:
                if exc.errno != errno.EIO:
                    raise
                bad.append(
                    UnwritableRange(
                        offset=offset + start, length=len(chunk), errno=exc.errno
                    )
                )
            else:
                written += count
    return written, bad


@dataclass
class _OverwriteOutcome:
    bytes_written: int
    unwritable: list[UnwritableRange]
    limitations: list[str]
    passes: int


def _overwrite(
    device: Device,
    geometry: Geometry,
    method: EraseMethod,
    *,
    job_id: str,
    ledger: LedgerSink,
    buffer_bytes: int = DEFAULT_BUFFER_BYTES,
    checkpoint_bytes: int = CHECKPOINT_INTERVAL_BYTES,
    start_offset: int = 0,
    start_pass: int = 0,
    fills: tuple[int, ...] | None = None,
) -> Generator[Progress, None, _OverwriteOutcome]:
    """Overwrite the whole device, yielding progress. The path we fully control.

    O_DIRECT requires the buffer address, the file offset and the length to all
    be aligned to the logical block size, so the buffer comes from
    :func:`mmap.mmap` (page aligned) and every length is a block multiple. A
    trailing partial block is padded rather than short-written.

    A short ``os.write`` is finished rather than stepped over, and the run
    reconciles what it planned against what it wrote before returning. Both
    exist for the same reason: an overwrite that leaves a hole and still
    reports success is worse than one that fails.

    An ``EIO`` does not abort the job: the failing span is retried block by
    block to localise it, the bad blocks are recorded, and the wipe continues. A
    single bad sector must not cost a four-terabyte wipe.
    """
    block = geometry.logical_block_size
    size = geometry.size_bytes
    buf_size = max(block, (buffer_bytes // block) * block)

    limitations: list[str] = []
    fd, direct = _open_for_write(device.path, limitations)
    unwritable: list[UnwritableRange] = []
    total_written = 0
    planned = 0
    throughput = _Throughput()
    pass_total = len(fills) if fills is not None else pattern_mod.pass_count(method)
    all_patterns = list(
        pattern_mod.pattern_passes(method, block_size=block, fills=fills)
    )

    buffer = mmap.mmap(-1, buf_size)
    try:
        for pass_index in range(start_pass, pass_total):
            pattern_block = all_patterns[pass_index]
            buffer.seek(0)
            buffer.write(pattern_block * (buf_size // block))

            offset = start_offset if pass_index == start_pass else 0
            next_checkpoint = offset + checkpoint_bytes
            os.lseek(fd, offset, os.SEEK_SET)

            while offset < size:
                remaining = size - offset
                span = min(buf_size, remaining)
                if span % block:
                    # Final partial block: pad up to a whole block. Never a
                    # short write, and never an unaligned length under O_DIRECT.
                    span = ((span // block) + 1) * block
                # ``with``, so the export is dropped before the next iteration
                # and before the mmap is closed. Without it every pass leaks a
                # view and ``buffer.close()`` raises BufferError at the end of
                # an otherwise complete wipe.
                with memoryview(buffer)[:span] as view:
                    written, bad = _write_span(fd, view, offset, block)
                    unwritable.extend(bad)

                # What the loop set out to cover, counted separately from what
                # it managed. The two are reconciled once, at the end.
                planned += span
                total_written += written
                throughput.add(written)
                offset += span

                if offset >= next_checkpoint or offset >= size:
                    point = EraseCheckpoint(
                        job_id=job_id,
                        pass_index=pass_index,
                        offset=min(offset, size),
                        bytes_written=total_written,
                        ts_utc=datetime.now(UTC),
                    )
                    ledger.record(
                        ErasePhase.ERASE, "checkpoint", point.model_dump(mode="json")
                    )
                    next_checkpoint = offset + checkpoint_bytes

                done = pass_index * size + min(offset, size)
                grand_total = pass_total * size
                yield Progress(
                    job_id=job_id,
                    phase=ErasePhase.ERASE.value,
                    pct_bp=(
                        10_000 * done // grand_total if grand_total else 10_000
                    ),
                    bytes_done=done,
                    bytes_total=grand_total,
                    throughput_bytes_per_sec=throughput.bps(),
                    eta_seconds=throughput.eta_seconds(grand_total - done),
                    message=(
                        f"pass {pass_index + 1}/{pass_total}"
                        + ("" if direct else " (buffered)")
                    ),
                )
    finally:
        buffer.close()
        os.close(fd)

    # Every byte the loop set out to write is either written or named in
    # ``unwritable``. A byte that is neither is a hole, and a hole under a
    # report that says the medium was sanitized is the one result this module
    # must never produce - so this is a raise, not a limitation.
    #
    # Note what is deliberately *not* checked: ``total_written == passes *
    # size``. An EIO block is legitimately skipped and recorded, and measuring
    # against a whole device would fail every run that salvaged one. What has
    # to hold is that nothing is skipped silently.
    skipped = sum(item.length for item in unwritable)
    if total_written + skipped != planned:
        raise OverwriteIncomplete(
            f"the overwrite planned {planned} byte(s) over {pass_total - start_pass} "
            f"pass(es) of {device.path} but accounts for only "
            f"{total_written + skipped}: {total_written} written and {skipped} "
            f"recorded unwritable. {planned - total_written - skipped} byte(s) "
            f"are unaccounted for and the medium is not erased."
        )

    return _OverwriteOutcome(
        bytes_written=total_written,
        unwritable=unwritable,
        limitations=limitations,
        passes=pass_total,
    )


# --------------------------------------------------------------------------
# Firmware dispatchers
# --------------------------------------------------------------------------


@dataclass
class _FirmwareOutcome:
    limitations: list[str]
    hw_attested: bool


def _poll(
    io: SystemProbe,
    argv: tuple[str, ...],
    parse: Callable[[str], int | None],
    *,
    job_id: str,
    phase_message: str,
    est_seconds: int,
    sleep: Callable[[float], None],
    interval_s: float = 5.0,
    max_polls: int = 100_000,
) -> Iterator[Progress]:
    """Poll a firmware operation, reporting its own percentage where it gives one.

    ``parse`` returns completion in basis points, or ``None`` when the drive
    declines to report any. Elapsed-time arithmetic stays in floats because
    :func:`time.monotonic` is a float; only the reported fields are integers.
    """
    started = time.monotonic()
    deadline_s = max(est_seconds, 1)
    for _ in range(max_polls):
        result = io.run(*argv)
        reported = parse(result.stdout) if result.ok else None
        elapsed = time.monotonic() - started
        if reported is None:
            pct_bp = min(9_900, int(10_000 * elapsed / deadline_s))
            message = f"{phase_message} (drive reports no percentage; estimate only)"
        else:
            pct_bp = reported
            message = phase_message
        yield Progress(
            job_id=job_id,
            phase=ErasePhase.ERASE.value,
            pct_bp=pct_bp,
            bytes_done=0,
            bytes_total=0,
            throughput_bytes_per_sec=0,
            eta_seconds=max(int(deadline_s - elapsed), 0),
            message=message,
        )
        if reported is not None and reported >= 10_000:
            return
        if reported is None and elapsed >= deadline_s:
            return
        sleep(interval_s)


def _parse_ata_sanitize_progress(text: str) -> int | None:
    """Completion in basis points, or ``None`` when the drive reports none."""
    lowered = text.lower()
    if "idle" in lowered or "completed" in lowered or "succeeded" in lowered:
        return 10_000
    return None


def _parse_ata_security_cleared(text: str) -> int | None:
    """10000 basis points once hdparm reports ATA security is no longer enabled."""
    lowered = text.lower()
    if "not	enabled" in lowered or "not enabled" in lowered:
        return 10_000
    return None


def _parse_nvme_sprog(text: str) -> int | None:
    """Completion in basis points, read from the NVMe sanitize status log."""
    import json

    try:
        payload = json.loads(text)
    except ValueError:
        return None
    if (int(payload.get("sstat") or 0) & 0x7) in {1, 4}:
        return 10_000
    sprog = payload.get("sprog")
    if sprog is None:
        return None
    # SPROG is a 16-bit fraction of 65536, not a percentage. Integer division
    # keeps the conversion exact; cap below 10000 so only sstat reports done.
    return min(9_990, 10_000 * int(sprog) // 65_536)


def _ata_security_erase(
    device: Device,
    capabilities: DeviceCapabilities,
    *,
    enhanced: bool,
    job_id: str,
    io: SystemProbe,
    ledger: LedgerSink,
    sleep: Callable[[float], None],
) -> Generator[Progress, None, _FirmwareOutcome]:
    """ATA SECURITY ERASE UNIT.

    DANGER, read before changing anything here.

    The sequence is::

        SECURITY SET PASSWORD -> SECURITY ERASE PREPARE -> SECURITY ERASE UNIT

    Between the first and last step the drive is password-locked. If this
    process dies in that window - a crash, a SIGKILL, a power cut - the drive
    stays LOCKED and is unusable until someone clears the password by hand.

    Three mitigations, all mandatory:

    1. The password is a fixed, published constant
       (:data:`ATA_RECOVERY_PASSWORD`) and is written to the ledger *before*
       SET PASSWORD is issued, so the recovery value survives the crash that
       makes it necessary.
    2. A SIGINT/SIGTERM handler and an ``atexit`` hook both attempt SECURITY
       DISABLE PASSWORD, so an orderly or semi-orderly exit unlocks the drive.
    3. The command refuses to start on a frozen drive, because SET PASSWORD
       would fail and leave the state ambiguous.
    """
    import atexit
    import signal

    if capabilities.security_frozen:
        raise DeviceFrozen(
            f"{device.path} has ATA security frozen; SECURITY SET PASSWORD "
            "cannot be issued."
        )

    ledger.record(
        ErasePhase.ERASE,
        "ata_security_password_set",
        {
            "path": device.path,
            "password": ATA_RECOVERY_PASSWORD,
            "note": (
                "Recorded before SET PASSWORD. If the process dies before ERASE "
                "UNIT completes, clear the drive with: hdparm "
                f"--user-master u --security-disable {ATA_RECOVERY_PASSWORD} "
                f"{device.path}"
            ),
        },
    )

    def _unlock() -> None:
        io.run(
            "hdparm",
            "--user-master",
            "u",
            "--security-disable",
            ATA_RECOVERY_PASSWORD,
            device.path,
        )

    def _on_signal(signum: int, _frame: Any) -> None:
        _unlock()
        raise KeyboardInterrupt(f"interrupted by signal {signum}")

    atexit.register(_unlock)
    previous = {
        sig: signal.signal(sig, _on_signal)
        for sig in (signal.SIGINT, signal.SIGTERM)
    }
    try:
        io.run(
            "hdparm",
            "--user-master",
            "u",
            "--security-set-pass",
            ATA_RECOVERY_PASSWORD,
            device.path,
        )
        mode = "--security-erase-enhanced" if enhanced else "--security-erase"
        io.run("hdparm", "--user-master", "u", mode, ATA_RECOVERY_PASSWORD, device.path)
        yield from _poll(
            io,
            ("hdparm", "-I", device.path),
            _parse_ata_security_cleared,
            job_id=job_id,
            phase_message="ATA security erase in progress (not interruptible)",
            est_seconds=capabilities.est_erase_seconds,
            sleep=sleep,
        )
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        _unlock()
        atexit.unregister(_unlock)

    final = io.run("hdparm", "-I", device.path)
    text = final.stdout.lower()
    clean = "not\tenabled" in text or "not enabled" in text
    limitations: list[str] = []
    if not clean:
        limitations.append(
            f"{device.path} still reports ATA security enabled or locked after "
            f"the erase. Clear it manually with the password recorded in the "
            f"ledger before returning this drive to service."
        )
    return _FirmwareOutcome(limitations=limitations, hw_attested=clean)


def _ata_sanitize(
    device: Device,
    *,
    op: str,
    job_id: str,
    io: SystemProbe,
    est_seconds: int,
    sleep: Callable[[float], None],
) -> Generator[Progress, None, _FirmwareOutcome]:
    """Issue an ATA SANITIZE operation and poll SANITIZE STATUS EXT.

    Once issued the operation cannot be interrupted, cancelled or resumed. The
    caller must have told the operator that before this is reached.
    """
    io.run("hdparm", f"--{op}", "--yes-i-know-what-i-am-doing", device.path)
    yield from _poll(
        io,
        ("hdparm", "--sanitize-status", device.path),
        _parse_ata_sanitize_progress,
        job_id=job_id,
        phase_message=f"ATA SANITIZE {op} in progress (not interruptible)",
        est_seconds=est_seconds,
        sleep=sleep,
    )
    status = io.run("hdparm", "--sanitize-status", device.path)
    ok = status.ok and "fail" not in status.stdout.lower()
    return _FirmwareOutcome(
        limitations=[]
        if ok
        else [f"ATA SANITIZE {op} did not report clean completion."],
        hw_attested=ok,
    )


def _nvme_sanitize(
    device: Device,
    capabilities: DeviceCapabilities,
    *,
    action: int,
    job_id: str,
    io: SystemProbe,
    sleep: Callable[[float], None],
) -> Generator[Progress, None, _FirmwareOutcome]:
    """Issue ``nvme sanitize`` and poll the sanitize log page (LID 0x81).

    Sanitize is controller scope: it destroys every namespace on the controller,
    not just the one named. If the controller has more than one namespace the
    caller is told so in plain words rather than discovering it afterwards.
    """
    limitations: list[str] = []
    namespaces = int(capabilities.nvme_sanicap.get("namespace_count") or 1)
    if namespaces > 1:
        limitations.append(
            f"NVMe sanitize is controller-scope: all {namespaces} namespaces on "
            f"this controller will be destroyed, not only {device.path}."
        )

    io.run("nvme", "sanitize", device.path, "-a", str(action))
    yield from _poll(
        io,
        ("nvme", "sanitize-log", device.path, "-o", "json"),
        _parse_nvme_sprog,
        job_id=job_id,
        phase_message="NVMe sanitize in progress (not interruptible)",
        est_seconds=capabilities.est_erase_seconds,
        sleep=sleep,
    )
    log = io.run("nvme", "sanitize-log", device.path, "-o", "json")
    ok = _parse_nvme_sprog(log.stdout) == 10_000 if log.ok else False
    if not ok:
        limitations.append("NVMe sanitize log did not report clean completion.")
    return _FirmwareOutcome(limitations=limitations, hw_attested=ok)


def _nvme_format_ses1(
    device: Device,
    capabilities: DeviceCapabilities,
    *,
    job_id: str,
    io: SystemProbe,
) -> Generator[Progress, None, _FirmwareOutcome]:
    """Format NVM with cryptographic erase, per namespace.

    Unlike sanitize, format acts on one namespace at a time, so every namespace
    is iterated and named.
    """
    namespaces = max(int(capabilities.nvme_sanicap.get("namespace_count") or 1), 1)
    limitations = [
        f"Format NVM is per-namespace; {namespaces} namespace(s) were formatted "
        "individually. Any namespace created after this run is not covered."
    ]
    failures: list[int] = []
    for index in range(1, namespaces + 1):
        result = io.run(
            "nvme", "format", device.path, "-n", str(index), "-s", "1", "-f"
        )
        if not result.ok:
            failures.append(index)
        yield Progress(
            job_id=job_id,
            phase=ErasePhase.ERASE.value,
            pct_bp=10_000 * index // namespaces,
            bytes_done=0,
            bytes_total=0,
            throughput_bytes_per_sec=0,
            eta_seconds=0,
            message=f"format namespace {index}/{namespaces} (SES=1 crypto erase)",
        )
    if failures:
        limitations.append(f"Format failed on namespace(s): {failures}.")
    return _FirmwareOutcome(limitations=limitations, hw_attested=not failures)


def _sed_crypto_erase(
    device: Device,
    *,
    job_id: str,
    io: SystemProbe,
    psid: str | None,
) -> Generator[Progress, None, _FirmwareOutcome]:
    """Opal PSID revert. Requires the PSID printed on the drive label.

    The PSID is never guessed and never derived. Without it a locked Opal drive
    cannot be reverted by software at all, and saying so is the only honest
    outcome.
    """
    if not psid:
        raise UnsupportedCapability(
            f"{device.path} is an Opal drive; a PSID revert needs the PSID "
            "printed on the physical drive label.",
            remediation=(
                "Read the 32-character PSID from the label and supply it. "
                "Without it this drive cannot be crypto-erased in software; "
                "physical destruction is the remaining option."
            ),
        )
    yield Progress(
        job_id=job_id,
        phase=ErasePhase.ERASE.value,
        pct_bp=0,
        bytes_done=0,
        bytes_total=0,
        throughput_bytes_per_sec=0,
        eta_seconds=0,
        message="Opal PSID revert (not interruptible)",
    )
    result = io.run("sedutil-cli", "--PSIDrevert", psid, device.path)
    ok = result.ok
    yield Progress(
        job_id=job_id,
        phase=ErasePhase.ERASE.value,
        pct_bp=10_000,
        bytes_done=0,
        bytes_total=0,
        throughput_bytes_per_sec=0,
        eta_seconds=0,
        message="Opal PSID revert complete" if ok else "Opal PSID revert failed",
    )
    return _FirmwareOutcome(
        limitations=[]
        if ok
        else [f"sedutil-cli PSID revert failed: {result.stderr.strip()}"],
        hw_attested=ok,
    )


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------


def _justify(method: EraseMethod, level: SanitizationLevel, device: Device) -> str:
    if method in _FIRMWARE_METHODS:
        return (
            f"{method.value} was selected because the drive's own firmware "
            f"reports it, which is the only way to reach {level.value} on "
            f"{device.transport} media."
        )
    return (
        f"{method.value} was selected because no firmware sanitize mechanism "
        f"was observed on this device; host overwrite reaches {level.value}."
    )


def _reread_serial(device: Device, probe: SystemProbe) -> None:
    """Confirm the disk at the kernel path is still the one that was confirmed.

    An operator can unplug ``sdb`` and insert a different disk between typing
    the serial and the job starting. The kernel path is reused; the serial is
    not. This closes that window.
    """
    current = get_device(device.path, probe)
    if current.serial != device.serial:
        raise DeviceVanished(
            f"{device.path} now reports serial {current.serial!r}, not "
            f"{device.serial!r}. A different device is present at this path."
        )
    if current.by_id_path and device.by_id_path:
        if current.by_id_path != device.by_id_path:
            raise DeviceVanished(
                f"{device.path} now resolves to {current.by_id_path}, not "
                f"{device.by_id_path}."
            )


def _progress(
    job_id: str, phase: ErasePhase, pct_bp: int, message: str
) -> Progress:
    """A phase marker with no byte accounting. ``pct_bp`` is basis points."""
    return Progress(
        job_id=job_id,
        phase=phase.value,
        pct_bp=pct_bp,
        bytes_done=0,
        bytes_total=0,
        throughput_bytes_per_sec=0,
        eta_seconds=0,
        message=message,
    )


def execute(
    job: EraseJob,
    capabilities: DeviceCapabilities,
    *,
    io: SystemProbe | None = None,
    ledger: LedgerSink | None = None,
    psid: str | None = None,
    sleep: Callable[[float], None] = time.sleep,
    verify_config: verify_mod.VerifyConfig = verify_mod.DEFAULT_CONFIG,
    buffer_bytes: int = DEFAULT_BUFFER_BYTES,
    checkpoint_bytes: int = CHECKPOINT_INTERVAL_BYTES,
    resume_from: EraseCheckpoint | None = None,
) -> Generator[Progress, None, EraseResult]:
    """Run ``job`` through all six phases, yielding progress.

    Phase order is PREFLIGHT, HIDDEN_AREA_UNLOCK, ERASE, HIDDEN_AREA_RESTORE,
    VERIFY, REPORT. Each phase emits at least one :class:`Progress` and records
    a ledger entry.

    The two hidden-area phases only *record*: an ordinary erase never unlocks
    or modifies an HPA or a DCO. Hidden bytes found by the probe are left
    alone, the erase covers the accessible range, and the result says the
    hidden region was not covered. Exposing it is the separate, approved
    workflow in :mod:`core.device.hidden_area_workflow`.

    There is no non-writing mode. Every call that passes the gates writes to
    the device; the read-only answer to "what would run" is :func:`preview`,
    which makes the same :func:`select_method` call without a job.

    Raises:
        SystemDiskRefused, MountedRefused: the guard rejected the target.
        ConfirmationMismatch: the typed serial does not match.
        DeviceVanished: a different device is now at this path.
        DeviceFrozen, UnsupportedCapability: the level cannot be delivered.
    """
    io = io or SystemProbe()
    if ledger is None:
        raise ValueError(
            "execute() needs a ledger: every phase must be recorded in the "
            "hash-chained audit log. Pass ChainLedgerSink(Ledger(root, ...))."
        )
    sink: LedgerSink = ledger
    device = job.device
    started_at = datetime.now(UTC)
    limitations: list[str] = []

    # ---------------- PREFLIGHT ----------------
    yield _progress(job.job_id, ErasePhase.PREFLIGHT, 0, "checking target")
    guard.assert_erasable(device)
    guard.assert_serial_confirmed(device, job.confirmed_serial or "")
    _reread_serial(device, io)

    geometry = device_geometry(device.path, io)
    # The floor for everything below. BLKGETSIZE64 is the size the kernel
    # will let this process write, so an erase covering less than it has
    # left addressable data behind whatever any probe claims.
    kernel_size_bytes = geometry.size_bytes
    method, method_limits = select_method(
        device, capabilities, job.level, requested=job.method
    )
    limitations.extend(method_limits)

    hidden: HiddenAreaReport | None = hidden_areas.detect_hidden_areas(device, io)

    # ---- write calibration -------------------------------------------------
    # Destructive: it writes twice over the first 64 MiB. It runs here and not
    # earlier because every confirmation gate above has already passed, and not
    # at all on a firmware method that streams no host pattern, or on a resume -
    # a resumed job would leave the calibration's own bytes at offset 0 in a
    # region the erase has already covered.
    calibration: calibrate_mod.CalibrationResult | None = None
    software = method in pattern_mod.SOFTWARE_METHODS
    if software and resume_from is None:
        calibration = calibrate_mod.calibrate_write(
            device.path,
            size_bytes=geometry.size_bytes,
            block_size=geometry.logical_block_size,
        )
        sink.record(
            ErasePhase.PREFLIGHT,
            "write_calibration",
            {"job_id": job.job_id, "path": device.path, **calibration.as_detail()},
        )
        yield _progress(
            job.job_id,
            ErasePhase.PREFLIGHT,
            0,
            (
                f"write calibration: zero fill {calibration.zero_mib_per_sec} "
                f"MiB/s against non-zero {calibration.nonzero_mib_per_sec} "
                f"MiB/s; elision_detected={calibration.elision_detected}"
            ),
        )
        if calibration.unavailable_reason:
            limitations.append(
                "The write calibration could not be taken: "
                f"{calibration.unavailable_reason} Whether this controller "
                "programs a zero fill is therefore unknown."
            )

    elision = calibration.elision_detected if calibration else None
    flash, flash_reason = media.is_flash(device, elision_detected=elision)
    fills: tuple[int, ...] | None = None
    fill_reason = ""
    if software:
        fills, fill_reason = pattern_mod.select_fills(
            method, elision_detected=elision, flash=flash
        )
        if fills != pattern_mod.pattern_defaults(method):
            limitations.append(
                "The overwrite pattern was changed from this method's default "
                f"because {fill_reason}. The medium will hold "
                f"0x{fills[-1]:02X} afterwards, not zeros."
            )

    est_seconds, est_basis = (
        calibrate_mod.estimate_seconds(fills, geometry.size_bytes, calibration)
        if software and fills is not None
        else (capabilities.est_erase_seconds, "the drive's own estimate")
    )
    if est_seconds == 0 and software:
        est_seconds, est_basis = (
            capabilities.est_erase_seconds,
            "the drive's own estimate; no rate was measured on this device",
        )

    plan = ErasePlan(
        method=method,
        level=job.level,
        justification=_justify(method, job.level, device),
        est_seconds=est_seconds,
        limitations=list(limitations),
        hidden_bytes=hidden.hidden_bytes if hidden else 0,
        fill_bytes=[f"0x{fill:02X}" for fill in (fills or ())],
        fill_reason=fill_reason,
        est_basis=est_basis,
    )
    sink.record(
        ErasePhase.PREFLIGHT,
        "plan",
        {
            "job_id": job.job_id,
            "path": device.path,
            "serial": device.serial,
            "by_id_path": device.by_id_path,
            "geometry": {
                "size_bytes": geometry.size_bytes,
                "logical_block_size": geometry.logical_block_size,
                "physical_block_size": geometry.physical_block_size,
            },
            "plan": plan.model_dump(mode="json"),
        },
    )
    yield _progress(
        job.job_id,
        ErasePhase.PREFLIGHT,
        10_000,
        f"plan: {method.value} for {job.level.value}; {plan.justification}",
    )

    # ---------------- HIDDEN_AREA_UNLOCK ----------------
    # An ordinary erase NEVER changes the HPA or the DCO. Widening the
    # accessible maximum is a configuration change to the drive, and it goes
    # through the guarded HPA/DCO workflow (core.device.hidden_area_workflow):
    # a verified backup, a human approval and a typed serial of its own. What
    # this phase does is record what was found, so a chain reader can tell
    # "probed and found none" from "found and deliberately not unlocked".
    firmware = method in _FIRMWARE_METHODS
    hidden_covered = True
    # A probe that did not work reports no hidden bytes and knows nothing; the
    # limitation it carries is what the operator needs instead.
    probe_failed = bool(hidden and hidden.probe_failed)
    if hidden is not None and hidden.limitations:
        limitations.extend(hidden.limitations)
    hidden_found = bool(
        hidden and hidden.hidden_bytes > 0 and not firmware and not probe_failed
    )

    if firmware and hidden and hidden.hidden_bytes > 0:
        reason = (
            f"{method.value} is executed by drive firmware and covers the full "
            "media including HPA/DCO, so no host-side unlock was needed."
        )
        limitations.append(reason)
        sink.record(
            ErasePhase.HIDDEN_AREA_UNLOCK,
            "skipped",
            {"job_id": job.job_id, "reason": reason},
        )
        yield _progress(job.job_id, ErasePhase.HIDDEN_AREA_UNLOCK, 10_000, reason)
    elif hidden_found and hidden is not None:
        hidden_covered = False
        reason = (
            f"{hidden.hidden_bytes} bytes are hidden by an HPA/DCO: the drive "
            f"reports an accessible maximum of {hidden.accessible_sectors} "
            f"sectors and a native maximum of {hidden.native_max_sectors}. An "
            "ordinary erase never changes the HPA or the DCO, so only the "
            "accessible range was erased and the hidden region was NOT "
            "sanitized and may still hold data. To cover it, run the HPA/DCO "
            "workflow first (verified backup, human approval, typed serial) "
            "and then erase again."
        )
        limitations.append(reason)
        sink.record(
            ErasePhase.HIDDEN_AREA_UNLOCK,
            "not_authorized",
            {
                "job_id": job.job_id,
                "hidden_bytes": hidden.hidden_bytes,
                "accessible_sectors": hidden.accessible_sectors,
                "native_max_sectors": hidden.native_max_sectors,
                "hpa_present": hidden.hpa_present,
                "dco_present": hidden.dco_present,
                "hidden_covered": False,
                "reason": reason,
            },
        )
        yield _progress(
            job.job_id,
            ErasePhase.HIDDEN_AREA_UNLOCK,
            10_000,
            f"{hidden.hidden_bytes} hidden bytes found and NOT unlocked; "
            "use the HPA/DCO workflow",
        )
    else:
        # Ledgered even though there is nothing to unlock, and this is not
        # bookkeeping for its own sake. HIDDEN_AREA_RESTORE already records
        # "not_required" in exactly the analogous negative case; without the
        # matching entry here, a chain read afterwards cannot tell "the tool
        # probed for an HPA and found none" from "the tool never probed", and
        # those two support opposite conclusions about whether the sectors
        # beyond the accessible max were ever considered.
        sink.record(
            ErasePhase.HIDDEN_AREA_UNLOCK,
            "not_required",
            {
                "job_id": job.job_id,
                "hidden_bytes": hidden.hidden_bytes if hidden else 0,
                "accessible_sectors": hidden.accessible_sectors if hidden else 0,
                "native_max_sectors": hidden.native_max_sectors if hidden else 0,
                "reason": (
                    "The drive reported no HPA or DCO, so the accessible max "
                    "already covers the whole medium and there was nothing to "
                    "unlock."
                ),
            },
        )
        yield _progress(
            job.job_id, ErasePhase.HIDDEN_AREA_UNLOCK, 10_000, "no hidden areas"
        )

    # ---------------- ERASE ----------------
    if geometry.size_bytes < kernel_size_bytes:
        # Unreachable by design: nothing between the kernel read and here
        # touches the geometry. Checked anyway, because the failure this
        # guards against is silent - a wipe that covers a fraction of a device
        # and still ends in a report saying the medium was sanitized.
        raise GeometryRefused(
            f"The erase geometry for {device.path} is {geometry.size_bytes} "
            f"bytes, smaller than the {kernel_size_bytes} bytes the kernel "
            "reports. Refusing to erase part of a device and call it done."
        )

    try:
        outcome = yield from _dispatch(
            device,
            capabilities,
            geometry,
            method,
            job_id=job.job_id,
            io=io,
            ledger=sink,
            psid=psid,
            sleep=sleep,
            buffer_bytes=buffer_bytes,
            checkpoint_bytes=checkpoint_bytes,
            resume_from=resume_from,
            fills=fills,
        )
    except GeneratorExit:
        # The caller closed this generator: an operator pressed Cancel, or
        # the client that asked for the wipe went away. The write stopped at
        # a yield point, never between an lseek and a write - but the device
        # is now *partially* sanitized, and that is a fact about a physical
        # object that outlives this process. It goes in the chain before the
        # exception is allowed to continue, because a cancelled wipe that
        # leaves no record is indistinguishable from one that never ran.
        #
        # No progress is yielded here and none can be: a generator that
        # yields while closing raises RuntimeError. The ledger is the only
        # channel out, which is the right one anyway.
        sink.record(
            ErasePhase.ERASE,
            "cancelled",
            {
                "job_id": job.job_id,
                "method": method.value,
                "note": (
                    "Erase cancelled before completion. The device is "
                    "PARTIALLY SANITIZED: data up to the last recorded "
                    "checkpoint was overwritten and the remainder was not. "
                    "No verification ran, so no sanitization level was "
                    "achieved and no certificate is issued for this job."
                    + (
                        ""
                        if method in pattern_mod.SOFTWARE_METHODS
                        else " This method runs inside the drive's own "
                        "firmware: cancelling stopped this tool from "
                        "watching it, and does not stop the drive. Re-probe "
                        "the device before drawing any conclusion about it."
                    )
                ),
                "resumable": method in pattern_mod.SOFTWARE_METHODS,
            },
        )
        raise
    bytes_written = outcome[0]
    passes = outcome[1]
    unwritable: list[UnwritableRange] = outcome[2]
    limitations.extend(outcome[3])
    hw_attested = outcome[4]
    sink.record(
        ErasePhase.ERASE,
        "complete",
        {
            "job_id": job.job_id,
            "method": method.value,
            "bytes_written": bytes_written,
            "unwritable_ranges": len(unwritable),
        },
    )

    # ---------------- HIDDEN_AREA_RESTORE ----------------
    # Nothing to restore, ever: this erase did not change the HPA. The entry
    # stays so the six-phase shape of the chain is the same for every job.
    sink.record(
        ErasePhase.HIDDEN_AREA_RESTORE,
        "not_required",
        {
            "job_id": job.job_id,
            "reason": "An ordinary erase does not change the HPA or the DCO, "
            "so there is no accessible maximum to restore.",
        },
    )
    yield _progress(
        job.job_id, ErasePhase.HIDDEN_AREA_RESTORE, 10_000, "nothing to restore"
    )

    # ---------------- VERIFY ----------------
    # `fills` matters: on a zero-eliding controller the medium holds 0xA5, and
    # verifying the method's default 0x00 would fail a good erase - or, worse,
    # pass a bad one on a device where the FTL answers zero for free.
    verify_started = time.monotonic()
    verification = verify_mod.verify(
        device, method, config=verify_config, io=io, fills=fills
    )
    verify_seconds = time.monotonic() - verify_started
    sink.record(
        ErasePhase.VERIFY,
        "result",
        {"job_id": job.job_id, **verification.model_dump(mode="json")},
    )
    yield _progress(
        job.job_id,
        ErasePhase.VERIFY,
        10_000,
        f"{verification.strategy}: "
        + ("passed" if verification.passed else "FAILED"),
    )

    # ---------------- REPORT ----------------
    achieved = _achieved_level(job, method, capabilities, verification)
    findings: list[ResidualFinding] = []
    if calibration is not None and calibration.elision_detected:
        findings.append(
            calibrate_mod.elision_finding(
                calibration,
                read_back_bytes_per_sec=(
                    int(verification.bytes_checked / verify_seconds)
                    if verify_seconds > 0 and verification.bytes_checked
                    else None
                ),
            )
        )
    residual = verify_mod.assess_residual_risk(
        device=device,
        capabilities=capabilities,
        method=method,
        requested_level=job.level,
        achieved_level=achieved,
        verification=verification,
        hidden=hidden,
        hidden_covered=hidden_covered,
        unwritable_ranges=unwritable,
        limitations=limitations,
        elision_detected=calibration.elision_detected if calibration else None,
        findings=findings,
    )
    result = EraseResult(
        job_id=job.job_id,
        method=method,
        level=job.level,
        started_at=started_at,
        finished_at=datetime.now(UTC),
        bytes_written=bytes_written,
        passes=passes,
        plan=plan,
        residual_risk=residual,
        unwritable_ranges=unwritable,
        limitations=limitations,
        hw_attested=hw_attested,
        device=device,
        logical_block_size=geometry.logical_block_size,
        physical_block_size=geometry.physical_block_size,
        hidden_areas=hidden,
        hidden_covered=hidden_covered,
        verification=verification,
        achieved_level=achieved,
    )
    sink.record(
        ErasePhase.REPORT,
        "result",
        {"job_id": job.job_id, **result.model_dump(mode="json")},
    )
    yield _progress(
        job.job_id,
        ErasePhase.REPORT,
        10_000,
        f"residual risk {residual.level}: {residual.notes}",
    )
    return result


def _dispatch(
    device: Device,
    capabilities: DeviceCapabilities,
    geometry: Geometry,
    method: EraseMethod,
    *,
    job_id: str,
    io: SystemProbe,
    ledger: LedgerSink,
    psid: str | None,
    sleep: Callable[[float], None],
    buffer_bytes: int,
    checkpoint_bytes: int,
    resume_from: EraseCheckpoint | None,
    fills: tuple[int, ...] | None = None,
) -> Generator[
    Progress, None, tuple[int, int, list[UnwritableRange], list[str], bool]
]:
    """Route ``method`` to its one dispatcher. No method is handled twice."""
    if method in pattern_mod.SOFTWARE_METHODS:
        outcome = yield from _overwrite(
            device,
            geometry,
            method,
            job_id=job_id,
            ledger=ledger,
            buffer_bytes=buffer_bytes,
            checkpoint_bytes=checkpoint_bytes,
            start_offset=resume_from.offset if resume_from else 0,
            start_pass=resume_from.pass_index if resume_from else 0,
            fills=fills,
        )
        return (
            outcome.bytes_written,
            outcome.passes,
            outcome.unwritable,
            outcome.limitations,
            False,
        )

    firmware: _FirmwareOutcome
    if method is EraseMethod.ATA_SECURITY_ERASE_ENHANCED:
        firmware = yield from _ata_security_erase(
            device,
            capabilities,
            enhanced=True,
            job_id=job_id,
            io=io,
            ledger=ledger,
            sleep=sleep,
        )
    elif method is EraseMethod.ATA_SANITIZE_BLOCK_ERASE:
        firmware = yield from _ata_sanitize(
            device,
            op="sanitize-block-erase",
            job_id=job_id,
            io=io,
            est_seconds=capabilities.est_erase_seconds,
            sleep=sleep,
        )
    elif method is EraseMethod.ATA_SANITIZE_OVERWRITE:
        firmware = yield from _ata_sanitize(
            device,
            op="sanitize-overwrite",
            job_id=job_id,
            io=io,
            est_seconds=capabilities.est_erase_seconds,
            sleep=sleep,
        )
    elif method is EraseMethod.ATA_SANITIZE_CRYPTO_SCRAMBLE:
        firmware = yield from _ata_sanitize(
            device,
            op="sanitize-crypto-scramble",
            job_id=job_id,
            io=io,
            est_seconds=capabilities.est_erase_seconds,
            sleep=sleep,
        )
    elif method is EraseMethod.NVME_SANITIZE_BLOCK:
        action = 1 if capabilities.nvme_sanicap.get("crypto_erase") else 2
        firmware = yield from _nvme_sanitize(
            device,
            capabilities,
            action=action,
            job_id=job_id,
            io=io,
            sleep=sleep,
        )
    elif method is EraseMethod.NVME_FORMAT_SES1:
        firmware = yield from _nvme_format_ses1(
            device, capabilities, job_id=job_id, io=io
        )
    elif method is EraseMethod.SED_CRYPTO_ERASE:
        firmware = yield from _sed_crypto_erase(
            device, job_id=job_id, io=io, psid=psid
        )
    else:  # pragma: no cover - every member is handled above
        raise UnsupportedCapability(
            f"No dispatcher is registered for {method.value}.",
            remediation="Add a dispatcher in core.erase.drive._dispatch.",
        )
    return 0, 1, [], firmware.limitations, firmware.hw_attested


def resume(
    job: EraseJob,
    capabilities: DeviceCapabilities,
    ledger: LedgerSink,
    **kwargs: Any,
) -> Generator[Progress, None, EraseResult]:
    """Continue an interrupted overwrite from its last recorded checkpoint.

    Only the overwrite path is resumable. Firmware sanitize operations cannot be
    interrupted or restarted partway, so resuming one means running it again.
    """
    checkpoint = ledger.last_checkpoint(job.job_id)
    if checkpoint is None:
        raise UnsupportedCapability(
            f"No checkpoint was recorded for job {job.job_id}.",
            remediation="Start the job again from the beginning.",
        )
    logger.info(
        "resuming",
        job_id=job.job_id,
        offset=checkpoint.offset,
        pass_index=checkpoint.pass_index,
    )
    return execute(
        job, capabilities, ledger=ledger, resume_from=checkpoint, **kwargs
    )
