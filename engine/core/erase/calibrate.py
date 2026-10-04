"""Measure whether this controller actually programs the bytes it is given.

A flash controller may acknowledge an all-zero write without programming a
single cell: it maps the affected addresses to a zero token, or compresses the
buffer away. Either way the medium reads back as zeros and no host-side read can
tell the difference. The write's *duration* can.

Measured on the hardware-validation stick (Toshiba TransMemory, USB, 7.76 GB),
all writes ``O_DIRECT`` with the same 4 MiB buffer:

===================================  ===========  ==========
write                                  seconds     MiB/s
===================================  ===========  ==========
``0x00``, whole device                     521.5       14.19
``0xA5``, whole device                    1886.75       3.92
``0xFF``, 1 GiB, via pipe                  242.2        4.23
``0xFF``, 1 GiB, via ``cat``               266.2        3.85
===================================  ===========  ==========

Non-zero fills span 3.85-4.23 MiB/s - a 10% spread across two fill bytes, two
tools and two transfer sizes. Zeros run 3.6x faster than the fastest of them.
A write that completes faster than the medium can be programmed was not
programmed.

The threshold is 2.0 rather than something tighter because the honest-write
spread is 10% and the signal here is 260%: there is an enormous gap to place a
line in, and a wide inconclusive band below it costs nothing. A ratio under the
threshold is reported as "no elision detected", never as "the write was
performed" - this measures the controller's behaviour, not the state of the
cells.

**This is destructive.** It writes twice over a region of the target. It runs
only after the confirmation gates, and never on a firmware method or a resume.
"""

from __future__ import annotations

import errno
import mmap
import os
import time
from dataclasses import dataclass

import structlog

from core.models import ResidualFinding, ResidualKind, Severity

__all__ = [
    "CALIBRATION_BYTES",
    "ELISION_RATIO_THRESHOLD",
    "NONZERO_FILL",
    "ZERO_FILL",
    "CalibrationResult",
    "calibrate_write",
    "elision_finding",
    "estimate_seconds",
]

logger = structlog.get_logger(__name__)

MIB = 1024 * 1024

#: Bytes written per fill. Two of these are destroyed, so 128 MiB total. Large
#: enough to swamp per-call overhead and any single-block cache effect at the
#: ~4 MiB/s these devices run at, small enough to cost about half a minute.
CALIBRATION_BYTES = 64 * MIB

#: Ratio of non-zero seconds to zero seconds above which the zero fill was not
#: programmed. See the module docstring for why 2.0 and not 1.5 or 3.
ELISION_RATIO_THRESHOLD = 2.0

#: The fills compared. The non-zero value is neither 0x00 nor 0xFF, so it is not
#: a value a controller is likely to special-case for its own reasons.
ZERO_FILL = 0x00
NONZERO_FILL = 0xA5


@dataclass(frozen=True)
class CalibrationResult:
    """What the two timed writes established, and what they did not.

    ``elision_detected`` is ``None`` when the measurement could not be taken at
    all - too small a device, an unwritable region, a clock that produced a zero
    duration. ``None`` means unknown and must never be read as ``False``.
    """

    elision_detected: bool | None
    zero_seconds: float
    nonzero_seconds: float
    ratio: float | None
    sample_bytes: int
    threshold: float = ELISION_RATIO_THRESHOLD
    zero_fill: int = ZERO_FILL
    nonzero_fill: int = NONZERO_FILL
    #: Why no measurement was taken, when there is none.
    unavailable_reason: str = ""

    @property
    def zero_mib_per_sec(self) -> float:
        return (
            round(self.sample_bytes / MIB / self.zero_seconds, 2)
            if self.zero_seconds > 0
            else 0.0
        )

    @property
    def nonzero_mib_per_sec(self) -> float:
        return (
            round(self.sample_bytes / MIB / self.nonzero_seconds, 2)
            if self.nonzero_seconds > 0
            else 0.0
        )

    def as_detail(self) -> dict[str, object]:
        """The measurement, for a finding's ``detail`` and for the ledger.

        Integers only. ``core.ledger.canon`` rejects floats, because a float
        that round-trips differently on another host would change an entry hash
        and break the chain for a reason that has nothing to do with tampering.
        Durations are whole milliseconds, rates whole bytes per second, and the
        ratio is basis points. ``summary`` carries the same numbers in the units
        a reader thinks in.
        """
        return {
            "zero_fill": f"0x{self.zero_fill:02X}",
            "nonzero_fill": f"0x{self.nonzero_fill:02X}",
            "sample_bytes": self.sample_bytes,
            "zero_ms": int(round(self.zero_seconds * 1000)),
            "nonzero_ms": int(round(self.nonzero_seconds * 1000)),
            "zero_bytes_per_sec": (
                int(self.sample_bytes / self.zero_seconds)
                if self.zero_seconds > 0
                else 0
            ),
            "nonzero_bytes_per_sec": (
                int(self.sample_bytes / self.nonzero_seconds)
                if self.nonzero_seconds > 0
                else 0
            ),
            "ratio_bp": (
                int(round(self.ratio * 10_000)) if self.ratio is not None else None
            ),
            "threshold_bp": int(round(self.threshold * 10_000)),
            "elision_detected": self.elision_detected,
            "unavailable_reason": self.unavailable_reason,
            "summary": (
                f"zero fill {self.zero_mib_per_sec} MiB/s against non-zero "
                f"{self.nonzero_mib_per_sec} MiB/s over {self.sample_bytes} "
                f"bytes per sample"
            ),
        }


def _timed_fill(fd: int, offset: int, fill: int, span: int, block: int) -> float:
    """Write ``span`` bytes of ``fill`` at ``offset``. Returns seconds elapsed."""
    buf_size = max(block, (4 * MIB // block) * block)
    buffer = mmap.mmap(-1, buf_size)  # page-aligned, which O_DIRECT requires
    buffer.write(bytes([fill]) * buf_size)
    view = memoryview(buffer)
    written = 0
    os.lseek(fd, offset, os.SEEK_SET)
    started = time.monotonic()
    try:
        while written < span:
            chunk_span = min(buf_size, span - written)
            position = 0
            while position < chunk_span:
                chunk = view[position:chunk_span]
                try:
                    count = os.write(fd, chunk)
                finally:
                    chunk.release()
                if count <= 0:
                    raise OSError(errno.EIO, "short write during calibration")
                position += count
                written += count
        os.fsync(fd)
    finally:
        view.release()
        buffer.close()
    return time.monotonic() - started


def calibrate_write(
    path: str,
    *,
    size_bytes: int,
    block_size: int,
    sample_bytes: int = CALIBRATION_BYTES,
    threshold: float = ELISION_RATIO_THRESHOLD,
) -> CalibrationResult:
    """Time a non-zero fill against a zero fill over the same region.

    Both writes land on the same offset so wear-levelling state, block
    alignment and any address-dependent behaviour are identical between them.
    The non-zero fill goes first: it leaves the region holding ``0xA5``, so the
    zero write that follows cannot be skipped as a no-op against matching
    content.

    Args:
        path: Block device to calibrate. **Written to.**
        size_bytes: The device's size, so the sample can be clamped to it.
        block_size: Logical block size, for O_DIRECT alignment.
        sample_bytes: Bytes per fill. Two fills are written.
        threshold: Ratio at or above which elision is reported.

    Returns:
        A :class:`CalibrationResult`. Never raises for a measurement that could
        not be taken; that is reported as ``elision_detected=None`` with a
        reason, because "we could not find out" and "there is no elision" are
        different claims.
    """
    span = min(sample_bytes, size_bytes)
    span = (span // block_size) * block_size
    if span <= 0:
        return CalibrationResult(
            elision_detected=None,
            zero_seconds=0.0,
            nonzero_seconds=0.0,
            ratio=None,
            sample_bytes=0,
            threshold=threshold,
            unavailable_reason=(
                f"{path} is {size_bytes} bytes, too small to calibrate a write "
                f"against a {block_size}-byte block."
            ),
        )

    direct_flag = getattr(os, "O_DIRECT", 0)
    fd = -1
    if direct_flag:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_SYNC | direct_flag)
        except OSError:
            fd = -1
    if fd == -1:
        try:
            fd = os.open(path, os.O_WRONLY | getattr(os, "O_DSYNC", os.O_SYNC))
        except OSError as exc:
            return CalibrationResult(
                elision_detected=None,
                zero_seconds=0.0,
                nonzero_seconds=0.0,
                ratio=None,
                sample_bytes=0,
                threshold=threshold,
                unavailable_reason=f"{path} could not be opened for writing: {exc}",
            )

    try:
        nonzero_seconds = _timed_fill(fd, 0, NONZERO_FILL, span, block_size)
        zero_seconds = _timed_fill(fd, 0, ZERO_FILL, span, block_size)
    except OSError as exc:
        os.close(fd)
        return CalibrationResult(
            elision_detected=None,
            zero_seconds=0.0,
            nonzero_seconds=0.0,
            ratio=None,
            sample_bytes=span,
            threshold=threshold,
            unavailable_reason=f"the calibration write to {path} failed: {exc}",
        )
    os.close(fd)

    if zero_seconds <= 0 or nonzero_seconds <= 0:
        return CalibrationResult(
            elision_detected=None,
            zero_seconds=zero_seconds,
            nonzero_seconds=nonzero_seconds,
            ratio=None,
            sample_bytes=span,
            threshold=threshold,
            unavailable_reason=(
                "a calibration write completed in no measurable time, so the "
                "two rates cannot be compared."
            ),
        )

    ratio = nonzero_seconds / zero_seconds
    result = CalibrationResult(
        elision_detected=ratio >= threshold,
        zero_seconds=zero_seconds,
        nonzero_seconds=nonzero_seconds,
        ratio=ratio,
        sample_bytes=span,
        threshold=threshold,
    )
    logger.info(
        "write_calibration",
        path=path,
        ratio=round(ratio, 2),
        threshold=threshold,
        elision_detected=result.elision_detected,
        zero_mib_per_sec=result.zero_mib_per_sec,
        nonzero_mib_per_sec=result.nonzero_mib_per_sec,
    )
    return result


def elision_finding(
    calibration: CalibrationResult, *, read_back_bytes_per_sec: int | None = None
) -> ResidualFinding:
    """The finding for a controller that did not program what it was given.

    ``read_back_bytes_per_sec`` is an integer for the same reason every other
    number here is: the finding is ledgered, and ``core.ledger.canon`` refuses
    floats.
    """
    detail = calibration.as_detail()
    if read_back_bytes_per_sec is not None:
        detail["read_back_bytes_per_sec"] = int(read_back_bytes_per_sec)
    ratio = calibration.ratio or 0.0
    return ResidualFinding(
        kind=ResidualKind.CONTROLLER_WRITE_ELISION,
        # HIGH for the same reason TRIM_REMAP is HIGH: the full original content
        # plausibly survives, in cells this pass never touched.
        severity=Severity.HIGH,
        addressable=False,
        explanation=(
            f"This device's controller acknowledged the zero-fill overwrite about "
            f"{ratio:.1f}x faster than it programs any non-zero pattern, measured "
            "on this device immediately before the erase. A write that completes "
            "faster than the medium can be programmed was not programmed: the "
            "controller either mapped the affected addresses to a zero token or "
            "compressed the all-zero buffer away. Either way the flash cells "
            "still hold whatever they held before. Every logical block now reads "
            "as zero through the device's own interface, and that is all a "
            "host-side read can ever establish on flash. The prior contents are "
            "not host-addressable but remain readable by the controller or by a "
            "chip-off, and unlike a performed overwrite this pass created no "
            "free-block pressure, so garbage collection is unlikely to have "
            "erased them. Only a firmware sanitize or a cryptographic erase of "
            "the whole device reaches them."
        ),
        detail=detail,
    )


def estimate_seconds(
    fills: tuple[int, ...], size_bytes: int, calibration: CalibrationResult | None
) -> tuple[int, str]:
    """Seconds this overwrite should take, from rates measured on this device.

    Each pass is costed at the rate measured for the byte that pass writes,
    because on a zero-eliding controller those rates differ by 3.6x. Costing
    every pass at the zero rate is what turns a 49-minute three-pass wipe into a
    26-minute estimate, and an operator discovering that mid-run has already
    committed the device.

    Returns ``(seconds, basis)``. ``basis`` says where the number came from, so
    an estimate from the drive's own claim is never mistaken for an observation.
    """
    if calibration is None or calibration.ratio is None:
        return 0, "no rate was measured on this device"
    per_byte_zero = calibration.zero_seconds / calibration.sample_bytes
    per_byte_nonzero = calibration.nonzero_seconds / calibration.sample_bytes
    total = sum(
        size_bytes * (per_byte_zero if fill == ZERO_FILL else per_byte_nonzero)
        for fill in fills
    )
    def rate(fill: int) -> float:
        return (
            calibration.zero_mib_per_sec
            if fill == ZERO_FILL
            else calibration.nonzero_mib_per_sec
        )

    passes = ", ".join(f"0x{fill:02X} at {rate(fill)} MiB/s" for fill in fills)
    return int(total), (
        f"measured on this device before the run: {passes} "
        f"over {calibration.sample_bytes} bytes per sample"
    )
