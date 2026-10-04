"""Addressable whole-drive clear over any bound block target. Destructive.

:mod:`core.erase.drive` is the Linux engine and stays Linux-only: it needs
``O_DIRECT``, ``BLKGETSIZE64`` and hdparm/nvme-cli. This module is the engine
the Windows and macOS adapters use. It never opens a device itself. It is
handed a callable that opens the target **and binds it** to the planned
identity (:meth:`core.device.win.disk.WindowsDisk.bind`,
:meth:`core.device.mac.rawdisk.MacRawDisk.bind`), so by the time the first
byte is written the handle has proven which disk it is.

What "clear" means here, and what it does not
---------------------------------------------
Every LBA the operating system exposes is overwritten, in order, with the
planned fill, and read back. That is a NIST SP 800-88 Rev. 2 **Clear of the
addressable storage**. It is not a Purge: flash keeps remapped and spare
blocks the host cannot address, and an HPA/DCO region the host cannot see is
not written unless the HPA/DCO workflow restored it first. The result says
so in its limitations; the certificate prints them.

Byte accounting is exact. Every byte of every pass is either written or named
in ``unwritable_ranges``; a byte that is neither is a hole, and the run raises
rather than report a medium it did not cover. A medium error localises to the
sector and is recorded; a device that disappears stops the run, which ledgers
how far it got.

There is no non-writing mode. :func:`clear` is only reached past the
adapter's revalidation and the helper's write-seam authorization, and every
call opens, binds, writes and verifies the device.
"""

from __future__ import annotations

import errno
import hashlib
import json
import mmap
import random
import time
from collections import deque
from collections.abc import Callable, Generator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

import structlog

from core.erase import patterns as pattern_mod
from core.erase.sink import LedgerSink
from core.erase.verify import (
    DEFAULT_CONFIG,
    VerifyConfig,
    detection_probability,
    probability_statement,
)
from core.errors import DeviceVanished, OverwriteIncomplete
from core.models import (
    Device,
    EraseCheckpoint,
    EraseMethod,
    ErasePhase,
    ErasePlan,
    EraseResult,
    Progress,
    ResidualRiskAssessment,
    SanitizationLevel,
    UnwritableRange,
    VerificationResult,
)

__all__ = [
    "BlockTarget",
    "ClearRequest",
    "clear",
    "is_medium_error",
    "is_gone_error",
    "plan_digest",
    "verify_target",
]

logger = structlog.get_logger(__name__)

MIB = 1024 * 1024
DEFAULT_BUFFER_BYTES = 4 * MIB
CHECKPOINT_INTERVAL_BYTES = 256 * MIB

#: Win32 medium errors (CRC, sector not found, I/O device error) and the POSIX
#: one. Salvaged sector by sector and recorded.
_WIN_MEDIUM = frozenset({23, 27, 1117})
#: Win32 "the device is gone" errors, and their POSIX counterparts.
_WIN_GONE = frozenset({2, 3, 6, 21, 433, 1167})
_POSIX_GONE = frozenset({errno.ENODEV, errno.ENXIO, errno.ENOENT})


def is_medium_error(exc: BaseException) -> bool:
    """A read or write the medium refused at this address."""
    if not isinstance(exc, OSError):
        return False
    code = getattr(exc, "winerror", None)
    if isinstance(code, int) and code in _WIN_MEDIUM:
        return True
    return exc.errno == errno.EIO


def is_gone_error(exc: BaseException) -> bool:
    """The device went away under the handle."""
    if not isinstance(exc, OSError):
        return False
    code = getattr(exc, "winerror", None)
    if isinstance(code, int) and code in _WIN_GONE:
        return True
    return exc.errno in _POSIX_GONE


class BlockTarget(Protocol):
    """An open, identity-bound whole-device handle."""

    path: str
    size_bytes: int
    logical_sector: int

    def write_at(self, offset: int, data: memoryview) -> int: ...

    def read_at(self, offset: int, length: int) -> bytes: ...

    def flush(self) -> None: ...

    def close(self) -> None: ...


@dataclass(frozen=True)
class ClearRequest:
    """Everything the engine is told. The adapter builds it after revalidation."""

    job_id: str
    device: Device
    #: The bound identity recorded in the plan (serial, size, OS id).
    identity: dict[str, Any]
    platform: str
    mechanism: str
    device_class: str
    flash: bool
    method: EraseMethod = EraseMethod.SINGLE_PASS_OVERWRITE
    fills: tuple[int, ...] | None = None
    fill_reason: str = ""
    buffer_bytes: int = DEFAULT_BUFFER_BYTES
    checkpoint_bytes: int = CHECKPOINT_INTERVAL_BYTES
    verify: VerifyConfig = DEFAULT_CONFIG
    limitations: tuple[str, ...] = ()
    resume_from: EraseCheckpoint | None = None
    est_bytes_per_sec: int = 30 * MIB
    #: Where est_bytes_per_sec came from.
    est_basis: str = (
        "a conservative 30 MiB/s assumption; no rate was measured on this "
        "device before the run"
    )
    extra: dict[str, Any] = field(default_factory=dict)


def plan_digest(request: ClearRequest, fills: tuple[int, ...]) -> str:
    """SHA-256 over what the operator approved. A stale plan will not match."""
    body = {
        "job_id": request.job_id,
        "identity": request.identity,
        "platform": request.platform,
        "mechanism": request.mechanism,
        "method": request.method.value,
        "fills": [f"0x{value:02X}" for value in fills],
        "size_bytes": request.device.size_bytes,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class _Throughput:
    def __init__(self, window_s: float = 30.0) -> None:
        self._window = window_s
        self._samples: deque[tuple[float, int]] = deque()

    def add(self, nbytes: int) -> None:
        now = time.monotonic()
        self._samples.append((now, nbytes))
        while self._samples and now - self._samples[0][0] > self._window:
            self._samples.popleft()

    def bps(self) -> int:
        if len(self._samples) < 2:
            return 0
        span = self._samples[-1][0] - self._samples[0][0]
        if span <= 0:
            return 0
        return int(sum(n for _, n in self._samples) / span)

    def eta(self, remaining: int) -> int:
        rate = self.bps()
        return int(remaining / rate) if rate else 0


def _progress(
    job_id: str,
    phase: ErasePhase,
    done: int,
    total: int,
    message: str,
    *,
    bps: int = 0,
    eta: int = 0,
) -> Progress:
    return Progress(
        job_id=job_id,
        phase=phase.value,
        pct_bp=10_000 * done // total if total else 10_000,
        bytes_done=done,
        bytes_total=total,
        throughput_bytes_per_sec=bps,
        eta_seconds=eta,
        message=message,
    )


def _write_span(
    target: BlockTarget, view: memoryview, offset: int, sector: int
) -> tuple[int, list[UnwritableRange]]:
    """Write one span, finishing short writes, salvaging medium errors.

    Returns ``(written, unwritable)`` whose lengths always sum to ``len(view)``.
    """
    span = len(view)
    written = 0
    while written < span:
        try:
            with view[written:] as rest:
                count = target.write_at(offset + written, rest)
        except OSError as exc:
            if is_gone_error(exc):
                raise DeviceVanished(
                    f"{target.path} disappeared at offset {offset + written}: {exc}"
                ) from exc
            if not is_medium_error(exc):
                raise
            with view[written:] as rest:
                salvaged, bad = _write_sectors(target, rest, offset + written, sector)
            return written + salvaged, bad
        if count <= 0:
            raise OverwriteIncomplete(
                f"the write at offset {offset + written} returned {count} and made "
                "no progress; the run stops rather than report a span it never wrote."
            )
        if count % sector:
            raise OverwriteIncomplete(
                f"the write at offset {offset + written} returned {count} bytes, "
                f"not a multiple of the {sector}-byte sector."
            )
        written += count
    return written, []


def _write_sectors(
    target: BlockTarget, view: memoryview, offset: int, sector: int
) -> tuple[int, list[UnwritableRange]]:
    written = 0
    bad: list[UnwritableRange] = []
    for start in range(0, len(view), sector):
        with view[start : start + sector] as chunk:
            try:
                count = target.write_at(offset + start, chunk)
            except OSError as exc:
                if is_gone_error(exc):
                    raise DeviceVanished(
                        f"{target.path} disappeared at offset {offset + start}"
                    ) from exc
                if not is_medium_error(exc):
                    raise
                code = getattr(exc, "winerror", None) or exc.errno or errno.EIO
                bad.append(
                    UnwritableRange(
                        offset=offset + start, length=len(chunk), errno=code
                    )
                )
                continue
            if count != len(chunk):
                raise OverwriteIncomplete(
                    f"sector write at {offset + start} returned {count} of "
                    f"{len(chunk)} bytes."
                )
            written += count
    return written, bad


def _aligned_window(
    offset: int, length: int, sector: int, size: int
) -> tuple[int, int]:
    start = (offset // sector) * sector
    end = min(size, -(-(offset + length) // sector) * sector)
    return start, max(0, end - start)


def _read(target: BlockTarget, offset: int, length: int) -> bytes | None:
    try:
        return target.read_at(offset, length)
    except OSError as exc:
        if is_gone_error(exc):
            raise DeviceVanished(
                f"{target.path} disappeared during verification"
            ) from exc
        if is_medium_error(exc):
            return None
        raise


def verify_target(
    target: BlockTarget,
    allowed: frozenset[int],
    *,
    config: VerifyConfig = DEFAULT_CONFIG,
    force_sampled: bool = False,
) -> Generator[int, None, VerificationResult]:
    """Read the target back; every byte must be in ``allowed``.

    Full read up to ``config.full_read_max_bytes``, otherwise both edges and
    seeded random windows. Windows are widened to sector boundaries, because an
    unbuffered handle cannot read anything else. Yields bytes checked so far.
    An unreadable window is a failure at its offset, never a pass.
    """
    size = target.size_bytes
    sector = target.logical_sector
    sampled = force_sampled or size > config.full_read_max_bytes
    windows: list[tuple[int, int]] = []
    draws = 0
    if not sampled:
        offset = 0
        while offset < size:
            windows.append((offset, min(config.read_chunk, size - offset)))
            offset += config.read_chunk
    else:
        edge = min(config.edge_bytes, size // 2)
        if edge:
            windows += [(0, edge), (size - edge, edge)]
        low, high = edge, size - edge - config.sample_bytes
        if high > low:
            rng = random.Random(config.seed)
            for _ in range(config.sample_count):
                windows.append((rng.randrange(low, high + 1), config.sample_bytes))
                draws += 1
    checked = 0
    failed: list[int] = []
    for offset, length in windows:
        start, span = _aligned_window(offset, length, sector, size)
        position = start
        while position < start + span:
            piece = min(config.read_chunk, start + span - position)
            data = _read(target, position, piece)
            if data is None or len(data) != piece:
                failed.append(position)
            else:
                checked += len(data)
                if not any(data.count(value) == len(data) for value in allowed):
                    for index, byte in enumerate(data):
                        if byte not in allowed:
                            failed.append(position + index)
                            break
            position += piece
        yield checked
    if not sampled:
        confidence = 10_000
        note = (
            "Every addressable block was read back and compared. No sampling "
            "assumption applies."
        )
    else:
        probability = detection_probability(
            max(size, 1),
            config.sample_bytes,
            sample_bytes=config.sample_bytes,
            draws=max(draws, 1),
        )
        confidence = int(probability * 10_000)
        note = probability_statement(
            total_bytes=max(size, 1),
            residual_bytes=config.sample_bytes,
            sample_bytes=config.sample_bytes,
            draws=max(draws, 1),
        )
    return VerificationResult(
        passed=not failed,
        strategy="sampled" if sampled else "full_read",
        bytes_checked=checked,
        sample_count=draws,
        confidence_bp=confidence,
        failed_offsets=sorted(failed)[:1000],
        sample_seed=config.seed if draws else None,
        probability_note=note,
    )


def _residual(
    request: ClearRequest,
    verification: VerificationResult | None,
    unwritable: list[UnwritableRange],
) -> ResidualRiskAssessment:
    factors: list[str] = []
    if request.flash:
        factors.append(
            "Flash medium: remapped and over-provisioned blocks are not "
            "addressable and were not overwritten."
        )
    if unwritable:
        factors.append(
            f"{len(unwritable)} range(s) could not be written and still hold "
            "their old contents."
        )
    if verification is None:
        factors.append("Not verified: verification did not run.")
    elif not verification.passed:
        factors.append("Read-back verification failed.")
    elif verification.strategy == "sampled":
        factors.append("Verification was sampled; see the stated probability.")
    level: Literal["low", "medium", "high"] = "low"
    if request.flash or verification is None or verification.strategy == "sampled":
        level = "medium"
    if unwritable or (verification is not None and not verification.passed):
        level = "high"
    return ResidualRiskAssessment(
        level=level,
        factors=factors,
        purge_achieved=False,
        notes=(
            "Addressable whole-drive clear: NIST SP 800-88 Rev. 2 Clear of the "
            "LBAs the operating system exposes. Not a Purge and not NAND-level "
            "destruction."
        ),
    )


def clear(
    request: ClearRequest,
    open_target: Callable[[], BlockTarget],
    *,
    ledger: LedgerSink,
) -> Generator[Progress, None, EraseResult]:
    """Overwrite and verify the whole addressable device, yielding progress.

    ``open_target`` is called once, after the plan is ledgered; it must open
    **and bind** the device, raising on any identity difference.
    """
    started = datetime.now(UTC)
    device = request.device
    fills = request.fills
    fill_reason = request.fill_reason
    if fills is None:
        fills, fill_reason = pattern_mod.select_fills(
            request.method, elision_detected=None, flash=request.flash
        )
    digest = plan_digest(request, fills)
    passes = len(fills)
    total = passes * device.size_bytes
    limitations = list(request.limitations)
    plan = ErasePlan(
        method=request.method,
        level=SanitizationLevel.CLEAR,
        justification=(
            f"Addressable overwrite through {request.mechanism}. The overwrite is "
            "performed by this computer, so its coverage is exactly the LBA "
            "range the operating system exposes."
        ),
        est_seconds=int(total / max(request.est_bytes_per_sec, 1)),
        limitations=limitations,
        fill_bytes=[f"0x{value:02X}" for value in fills],
        fill_reason=fill_reason,
        est_basis=request.est_basis,
    )
    ledger.record(
        ErasePhase.PREFLIGHT,
        "plan",
        {
            "job_id": request.job_id,
            "plan_digest": digest,
            "platform": request.platform,
            "mechanism": request.mechanism,
            "device_class": request.device_class,
            "identity": request.identity,
            "plan": plan.model_dump(mode="json"),
            "resume_from": (
                request.resume_from.model_dump(mode="json")
                if request.resume_from
                else None
            ),
        },
    )
    yield _progress(request.job_id, ErasePhase.PREFLIGHT, 1, 1, "plan recorded")

    target = open_target()
    unwritable: list[UnwritableRange] = []
    written_total = 0
    planned = 0
    throughput = _Throughput()
    size = target.size_bytes
    sector = target.logical_sector
    if size != device.size_bytes:
        target.close()
        raise OverwriteIncomplete(
            f"the bound target is {size} bytes but the plan is for "
            f"{device.size_bytes}; nothing was written."
        )
    buf_size = max(sector, (request.buffer_bytes // sector) * sector)
    buffer = mmap.mmap(-1, buf_size)
    start_pass = request.resume_from.pass_index if request.resume_from else 0
    start_offset = request.resume_from.offset if request.resume_from else 0
    if start_offset % sector:
        start_offset -= start_offset % sector
    position = start_offset
    pass_index = start_pass
    finished = False
    try:
        for pass_index in range(start_pass, passes):
            buffer.seek(0)
            buffer.write(bytes([fills[pass_index]]) * buf_size)
            position = start_offset if pass_index == start_pass else 0
            next_checkpoint = position + request.checkpoint_bytes
            while position < size:
                span = min(buf_size, size - position)
                with memoryview(buffer)[:span] as view:
                    written, bad = _write_span(target, view, position, sector)
                unwritable.extend(bad)
                planned += span
                written_total += written
                throughput.add(written)
                position += span
                if position >= next_checkpoint or position >= size:
                    ledger.record(
                        ErasePhase.ERASE,
                        "checkpoint",
                        EraseCheckpoint(
                            job_id=request.job_id,
                            pass_index=pass_index,
                            offset=position,
                            bytes_written=written_total,
                            ts_utc=datetime.now(UTC),
                        ).model_dump(mode="json"),
                    )
                    next_checkpoint = position + request.checkpoint_bytes
                done = pass_index * size + position
                yield _progress(
                    request.job_id,
                    ErasePhase.ERASE,
                    done,
                    total,
                    f"pass {pass_index + 1}/{passes}",
                    bps=throughput.bps(),
                    eta=throughput.eta(total - done),
                )
        target.flush()
        finished = True
    except GeneratorExit:
        ledger.record(
            ErasePhase.ERASE,
            "cancelled",
            {
                "job_id": request.job_id,
                "pass_index": pass_index,
                "offset": position,
                "bytes_written": written_total,
                "state": "PARTIALLY CLEARED: the device holds new data up to the "
                "offset and old data after it",
            },
        )
        raise
    except BaseException as exc:
        ledger.record(
            ErasePhase.ERASE,
            "interrupted",
            {
                "job_id": request.job_id,
                "pass_index": pass_index,
                "offset": position,
                "bytes_written": written_total,
                "error": f"{type(exc).__name__}: {exc}",
            },
        )
        raise
    finally:
        buffer.close()
        if not finished:
            target.close()

    skipped = sum(item.length for item in unwritable)
    if written_total + skipped != planned:
        target.close()
        raise OverwriteIncomplete(
            f"the clear planned {planned} bytes but accounts for "
            f"{written_total + skipped} ({written_total} written, {skipped} "
            "recorded unwritable); the medium is not cleared."
        )
    ledger.record(
        ErasePhase.ERASE,
        "complete",
        {
            "job_id": request.job_id,
            "bytes_written": written_total,
            "unwritable_ranges": len(unwritable),
            "passes": passes,
        },
    )

    allowed = frozenset({fills[-1]})
    try:
        verifier = verify_target(target, allowed, config=request.verify)
        while True:
            try:
                checked = next(verifier)
            except StopIteration as stop:
                verification: VerificationResult = stop.value
                break
            yield _progress(
                request.job_id,
                ErasePhase.VERIFY,
                checked,
                min(size, request.verify.full_read_max_bytes) or 1,
                "reading back",
            )
    finally:
        target.close()
    if unwritable and verification.passed:
        verification = verification.model_copy(
            update={
                "passed": False,
                "probability_note": verification.probability_note
                + " Ranges that could not be written are not cleared, so the "
                "device as a whole does not pass.",
            }
        )
    ledger.record(
        ErasePhase.VERIFY,
        "result",
        {"job_id": request.job_id, **verification.model_dump(mode="json")},
    )
    result = EraseResult(
        job_id=request.job_id,
        method=request.method,
        level=SanitizationLevel.CLEAR,
        started_at=started,
        finished_at=datetime.now(UTC),
        bytes_written=written_total,
        passes=passes,
        plan=plan,
        residual_risk=_residual(request, verification, unwritable),
        unwritable_ranges=unwritable,
        limitations=limitations,
        device=device,
        logical_block_size=sector,
        physical_block_size=int(request.identity.get("physical_sector") or sector),
        verification=verification,
        achieved_level=SanitizationLevel.CLEAR if verification.passed else None,
    )
    ledger.record(
        ErasePhase.REPORT,
        "result",
        {
            "job_id": request.job_id,
            "plan_digest": digest,
            "achieved": bool(result.achieved_level),
        },
    )
    yield _progress(request.job_id, ErasePhase.REPORT, 1, 1, "complete")
    return result
