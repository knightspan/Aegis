"""Post-erase verification and residual-risk assessment. Read-only.

Three strategies, chosen from the method and the media size:

``full_read``
    Every block is read and compared. Used at or below 64 GiB.

``sampled``
    The first and last 1 GiB in full, plus a fixed number of uniformly random
    fixed-size windows drawn from a seeded RNG. The seed is recorded so a third
    party can redraw exactly the same sample set from the report.

``hw_attested``
    Used for firmware sanitize. The drive's own sanitize log is read, *and* a
    sampled read is performed anyway. Attestation is a claim the drive makes
    about itself; it is evidence, not proof, so it never replaces reading the
    medium.

The device is opened ``O_RDONLY``. Nothing in this module ever opens for write.
"""

from __future__ import annotations

import json
import os
import random
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

import structlog

from core.device._sysio import SystemProbe
from core.device.capabilities import R1_TABLE_A8_SECURE_ERASE_NOTE
from core.device.media import is_flash
from core.erase.patterns import SOFTWARE_METHODS, final_pattern
from core.models import (
    Device,
    DeviceCapabilities,
    EraseMethod,
    Extent,
    FileInspection,
    FileVerificationResult,
    HiddenAreaReport,
    ResidualFinding,
    ResidualRiskAssessment,
    SanitizationLevel,
    UnwritableRange,
    VerificationResult,
)

__all__ = [
    "VerifyConfig",
    "Strategy",
    "verify",
    "choose_strategy",
    "detection_probability",
    "probability_statement",
    "assess_residual_risk",
    "verify_file_erase",
]

logger = structlog.get_logger(__name__)

KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB

Strategy = Literal["full_read", "sampled", "hw_attested"]

#: Methods executed by drive firmware. These get hardware attestation.
FIRMWARE_METHODS = frozenset(set(EraseMethod) - set(SOFTWARE_METHODS))

#: Byte values a firmware sanitize may legitimately leave behind. Vendors
#: differ: block erase commonly leaves 0x00, some leave 0xFF. Anything else is
#: residual data.
_FIRMWARE_EXPECTED = frozenset({0x00, 0xFF})

#: NVMe sanitize log SSTAT status field (bits 2:0) values that mean success.
_NVME_SSTAT_OK = frozenset({1, 4})
_NVME_SSTAT_MASK = 0x7

_READ_ONLY_FLAGS = os.O_RDONLY | getattr(os, "O_BINARY", 0)

_PROBABILITY_FORMULA = "P = 1 - (1 - (r + u - 1) / n)^k"


@dataclass(frozen=True)
class VerifyConfig:
    """Tunables for verification. Defaults are the shipped policy."""

    full_read_max_bytes: int = 64 * GIB
    edge_bytes: int = 1 * GIB
    sample_count: int = 4096
    sample_bytes: int = 1 * MIB
    seed: int = 0x5A4E4354
    read_chunk: int = 1 * MIB

    def with_seed(self, seed: int) -> VerifyConfig:
        """Return a copy using ``seed``."""
        return replace(self, seed=seed)


DEFAULT_CONFIG = VerifyConfig()


# --------------------------------------------------------------------------
# Probability
# --------------------------------------------------------------------------


def detection_probability(
    total_bytes: int, residual_bytes: int, *, sample_bytes: int, draws: int
) -> float:
    """Probability that ``draws`` random windows hit a residual region.

    Models each draw as a uniformly placed window of ``sample_bytes`` over
    ``total_bytes``. A window overlaps a residual region of ``residual_bytes``
    when its start falls anywhere in a span of ``residual_bytes + sample_bytes
    - 1``, so a single draw hits with probability ``(r + u - 1) / n`` and
    ``k`` independent draws miss with ``(1 - (r + u - 1) / n) ** k``.
    """
    if total_bytes <= 0 or draws <= 0 or residual_bytes <= 0:
        return 0.0
    per_draw = min(1.0, (residual_bytes + sample_bytes - 1) / total_bytes)
    return 1.0 - (1.0 - per_draw) ** draws


def probability_statement(
    *, total_bytes: int, residual_bytes: int, sample_bytes: int, draws: int
) -> str:
    """Render the detection-probability formula with this run's values."""
    probability = detection_probability(
        total_bytes, residual_bytes, sample_bytes=sample_bytes, draws=draws
    )
    return (
        f"{_PROBABILITY_FORMULA}, where n=total bytes, u=sample window, "
        f"r=size of a hypothetical residual region, k=random draws. "
        f"Here n={total_bytes}, u={sample_bytes}, r={residual_bytes}, "
        f"k={draws}, giving P={probability:.6f}. This is the chance of "
        f"detecting a residual region of {residual_bytes} bytes; it is not a "
        f"guarantee that none exists."
    )


# --------------------------------------------------------------------------
# Strategy
# --------------------------------------------------------------------------


def choose_strategy(
    size_bytes: int, method: EraseMethod, config: VerifyConfig = DEFAULT_CONFIG
) -> Strategy:
    """Pick the verification strategy for this method and media size."""
    if method in FIRMWARE_METHODS:
        return "hw_attested"
    if size_bytes <= config.full_read_max_bytes:
        return "full_read"
    return "sampled"


def _expected_bytes(
    method: EraseMethod, fills: tuple[int, ...] | None = None
) -> frozenset[int]:
    """Byte values the medium may legitimately hold after ``method``.

    ``fills`` must be the fills the erase actually used. Verification compares
    against the pattern that was written, not against the method's default: on
    a zero-eliding controller the default is 0x00, which is exactly the value
    the flash translation layer answers with for free.
    """
    if method in SOFTWARE_METHODS:
        return frozenset({final_pattern(method, block_size=1, fills=fills)[0]})
    return _FIRMWARE_EXPECTED


def _first_bad_index(chunk: bytes, allowed: frozenset[int]) -> int | None:
    """Index of the first byte in ``chunk`` outside ``allowed``, else ``None``."""
    for value in allowed:
        if chunk.count(value) == len(chunk):
            return None
    for index, byte in enumerate(chunk):
        if byte not in allowed:
            return index
    return None


# --------------------------------------------------------------------------
# Reading
# --------------------------------------------------------------------------


def _read_windows(
    fd: int, windows: Iterator[tuple[int, int]], allowed: frozenset[int]
) -> tuple[int, list[int]]:
    """Read each ``(offset, length)`` window, returning bytes read and failures."""
    checked = 0
    failed: list[int] = []
    for offset, length in windows:
        os.lseek(fd, offset, os.SEEK_SET)
        remaining = length
        position = offset
        while remaining > 0:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            checked += len(chunk)
            bad = _first_bad_index(chunk, allowed)
            if bad is not None:
                failed.append(position + bad)
            position += len(chunk)
            remaining -= len(chunk)
    return checked, failed


def _full_read_windows(size: int, config: VerifyConfig) -> Iterator[tuple[int, int]]:
    offset = 0
    while offset < size:
        yield offset, min(config.read_chunk, size - offset)
        offset += config.read_chunk


def _sample_windows(
    size: int, config: VerifyConfig
) -> tuple[list[tuple[int, int]], int]:
    """Both edges in full plus seeded random windows over the middle."""
    edge = min(config.edge_bytes, size // 2)
    windows: list[tuple[int, int]] = []
    if edge > 0:
        windows.append((0, edge))
        windows.append((size - edge, edge))
    else:
        windows.append((0, size))

    low = edge
    high = size - edge - config.sample_bytes
    draws = 0
    if high > low:
        rng = random.Random(config.seed)
        for _ in range(config.sample_count):
            windows.append((rng.randrange(low, high + 1), config.sample_bytes))
            draws += 1
    return windows, draws


# --------------------------------------------------------------------------
# Hardware attestation
# --------------------------------------------------------------------------


def _ata_attested(device: Device, io: SystemProbe) -> bool | None:
    result = io.run("hdparm", "--sanitize-status", device.path)
    if not result.ok:
        return None
    text = result.stdout.lower()
    if "fail" in text:
        return False
    return "without error" in text or "idle" in text


def _nvme_attested(device: Device, io: SystemProbe) -> bool | None:
    result = io.run("nvme", "sanitize-log", device.path, "-o", "json")
    if not result.ok:
        return None
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    sstat = int(payload.get("sstat") or 0)
    return (sstat & _NVME_SSTAT_MASK) in _NVME_SSTAT_OK


_ATTESTERS = {
    EraseMethod.ATA_SANITIZE_BLOCK_ERASE: _ata_attested,
    EraseMethod.ATA_SANITIZE_OVERWRITE: _ata_attested,
    EraseMethod.ATA_SANITIZE_CRYPTO_SCRAMBLE: _ata_attested,
    EraseMethod.NVME_SANITIZE_BLOCK: _nvme_attested,
}


def _attestation(
    device: Device, method: EraseMethod, io: SystemProbe | None
) -> bool | None:
    """Read the drive's own sanitize status. ``None`` when none is available."""
    attester = _ATTESTERS.get(method)
    if attester is None:
        return None
    return attester(device, io or SystemProbe())


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def verify(
    device: Device,
    method: EraseMethod,
    *,
    source_path: Path | str | None = None,
    config: VerifyConfig = DEFAULT_CONFIG,
    io: SystemProbe | None = None,
    fills: tuple[int, ...] | None = None,
) -> VerificationResult:
    """Read the medium back and report whether it looks sanitized.

    Args:
        device: The device that was erased.
        method: The method that was used; decides the expected pattern.
        source_path: Read this path instead of ``device.path``. Used by tests
            and by callers verifying an image rather than a live device.
        config: Verification tunables.
        io: Host access seam for reading the drive's sanitize log.
        fills: The fill bytes the erase actually wrote, when they differ from
            the method's defaults. Verification must check the pattern that was
            written; checking 0x00 by default would pass against a controller
            that synthesizes zeros without programming anything.

    Returns:
        A :class:`VerificationResult`. ``passed`` is false if any block holds
        unexpected data, or if hardware attestation reported a failure.
    """
    path = Path(source_path) if source_path is not None else Path(device.path)
    strategy = choose_strategy(device.size_bytes, method, config)
    allowed = _expected_bytes(method, fills)

    attested = _attestation(device, method, io) if strategy == "hw_attested" else None

    fd = os.open(path, _READ_ONLY_FLAGS)
    try:
        size = os.lseek(fd, 0, os.SEEK_END)
        if strategy == "full_read":
            windows: list[tuple[int, int]] = list(_full_read_windows(size, config))
            draws = 0
        else:
            windows, draws = _sample_windows(size, config)
        checked, failed = _read_windows(fd, iter(windows), allowed)
    finally:
        os.close(fd)

    if strategy == "full_read":
        confidence_bp = 10_000
        note = (
            "Every addressable block was read and compared. No sampling "
            "assumption applies."
        )
    else:
        note = probability_statement(
            total_bytes=max(size, 1),
            residual_bytes=config.sample_bytes,
            sample_bytes=config.sample_bytes,
            draws=max(draws, 1),
        )
        # detection_probability returns a fraction in [0, 1]; 10000 basis
        # points is 100%. Truncating rather than rounding keeps the reported
        # confidence at or below the computed one, never above it.
        confidence_bp = int(
            detection_probability(
                max(size, 1),
                config.sample_bytes,
                sample_bytes=config.sample_bytes,
                draws=max(draws, 1),
            )
            * 10_000
        )

    passed = not failed and attested is not False
    result = VerificationResult(
        passed=passed,
        strategy=strategy,
        bytes_checked=checked,
        sample_count=draws,
        confidence_bp=confidence_bp,
        failed_offsets=sorted(failed),
        sample_seed=config.seed if draws else None,
        probability_note=note,
        hw_attested=bool(attested),
    )
    logger.info(
        "verification_complete",
        path=str(path),
        strategy=strategy,
        passed=passed,
        bytes_checked=checked,
        failures=len(result.failed_offsets),
        hw_attested=result.hw_attested,
    )
    return result


def assess_residual_risk(
    *,
    device: Device,
    capabilities: DeviceCapabilities,
    method: EraseMethod,
    requested_level: SanitizationLevel,
    achieved_level: SanitizationLevel,
    verification: VerificationResult,
    hidden: HiddenAreaReport | None = None,
    hidden_covered: bool = True,
    unwritable_ranges: list[UnwritableRange] | None = None,
    limitations: list[str] | None = None,
    elision_detected: bool | None = None,
    findings: list[ResidualFinding] | None = None,
) -> ResidualRiskAssessment:
    """State plainly what this erase could not guarantee.

    Always emitted. Where a guarantee cannot be made, it is named rather than
    omitted (CLAUDE.md non-negotiable).
    """
    unwritable = unwritable_ranges or []
    factors: list[str] = list(limitations or [])
    overwrite_only = method in SOFTWARE_METHODS
    # Positive determination, not a negated kernel flag. `not device.rotational`
    # was False for the USB flash stick used in hardware validation, because the
    # bridge never cleared queue/rotational, and every flash caveat below was
    # silently skipped for exactly the class of device that needs them.
    flash, flash_reason = is_flash(device, elision_detected=elision_detected)

    if device.transport in {"usb", "mmc"}:
        factors.append(
            f"Device is behind a {device.transport} bridge; no firmware sanitize "
            "could be issued, so erasure is limited to what host writes reach."
        )
    if overwrite_only and flash:
        factors.append(
            "Flash media erased by overwrite only. Remapped bad blocks and "
            "over-provisioned capacity are not host-addressable and cannot be "
            "reached by any host write pattern. No host-side read can establish "
            "physical removal on flash: every read is answered by the flash "
            f"translation layer. Determined to be flash because {flash_reason}."
        )
    enhanced_on_flash = method is EraseMethod.ATA_SECURITY_ERASE_ENHANCED and flash
    if enhanced_on_flash:
        factors.append(
            "ATA enhanced SECURITY ERASE was run on flash media, where it counts "
            "as Clear only, not Purge. NIST SP 800-88r1 Table A-8 (ATA SSDs): "
            f'"{R1_TABLE_A8_SECURE_ERASE_NOTE}" r1 was withdrawn on 2025-09-26, '
            "and SP 800-88r2 defers technique acceptability to IEEE 2883, whose "
            "text has not been checked. What the firmware did is vendor specific "
            "and cannot be observed from the host. Determined to be flash because "
            f"{flash_reason}."
        )
    if unwritable:
        total = sum(item.length for item in unwritable)
        factors.append(
            f"{len(unwritable)} unwritable range(s) totalling {total} bytes were "
            "skipped after I/O errors; their prior contents remain."
        )
    if hidden is not None and hidden.hidden_bytes > 0:
        if hidden_covered:
            factors.append(
                f"{hidden.hidden_bytes} bytes were hidden by HPA/DCO and were "
                "unlocked and covered by this erase."
            )
        else:
            factors.append(
                f"{hidden.hidden_bytes} bytes hidden by HPA/DCO were NOT covered "
                "by this erase and may still hold data."
            )
    if capabilities.is_sed_opal and method is not EraseMethod.SED_CRYPTO_ERASE:
        factors.append(
            "Drive is self-encrypting (Opal) but was not crypto-erased; the "
            "media encryption key was left in place."
        )
    if verification.strategy == "sampled":
        factors.append(
            "Verification was sampled, not exhaustive. " + verification.probability_note
        )
    if verification.hw_attested:
        factors.append(
            "The drive reported clean sanitize completion. That is the drive's "
            "own claim about itself and was corroborated, not replaced, by "
            "reading the medium."
        )
    factors.extend(capabilities.limitations)

    purge_achieved = achieved_level is SanitizationLevel.PURGE

    if not verification.passed:
        level: Literal["low", "medium", "high"] = "high"
        notes = "Verification failed: residual data was read back after the erase."
    elif requested_level is SanitizationLevel.PURGE and not purge_achieved:
        level = "high"
        notes = (
            "A Purge was requested but only Clear was achieved. Data may be "
            "recoverable with laboratory techniques."
        )
    elif unwritable or (
        hidden is not None and hidden.hidden_bytes > 0 and not hidden_covered
    ):
        level = "high"
        notes = "Part of the medium was not erased. See factors."
    elif overwrite_only and elision_detected:
        # Worse than the generic flash caveat below, and for a different reason:
        # there, the write happened and could not reach everything. Here the
        # controller did not perform the write at all, so it created none of the
        # free-block pressure that makes a flash overwrite worth anything.
        level = "high"
        notes = (
            "The controller acknowledged the zero fill far faster than it can "
            "program this medium, so the cells were not written. Every block "
            "reads as zero through the device's own interface, which is all a "
            "host-side read can establish on flash. Use a firmware sanitize or "
            "crypto-erase where available; otherwise destroy the media."
        )
    elif overwrite_only and flash:
        level = "medium"
        notes = (
            "Overwrite on flash cannot reach remapped or over-provisioned "
            "blocks, and no host-side read can establish physical removal. Use "
            "a firmware sanitize or crypto-erase where available."
        )
    elif enhanced_on_flash:
        level = "medium"
        notes = (
            "ATA enhanced SECURITY ERASE on flash is a Clear. Spare cells rotated "
            "out of use may still hold data, and the command's implementation "
            "varies by vendor. For a Purge use ATA SANITIZE block erase or crypto "
            "scramble, or an Opal cryptographic erase."
        )
    elif purge_achieved and verification.hw_attested and verification.passed:
        level = "low"
        notes = "Hardware-attested purge with clean verification."
    else:
        level = "medium"
        notes = "Erase completed and verified within the stated sampling limits."

    return ResidualRiskAssessment(
        level=level,
        factors=factors,
        purge_achieved=purge_achieved,
        notes=notes,
        findings=list(findings or []),
    )


# --------------------------------------------------------------------------
# File-level verification
# --------------------------------------------------------------------------
#
# The single worst bug this project can ship is a verifier that reports a pass
# it did not earn: it tells an operator that data is gone when the tool never
# looked at the place the data used to be. For a whole-device erase the medium
# is right there to read. For a *file* erase it usually is not - the file is
# unlinked, its extents may be reallocated, and reading the block device needs
# root - so `passed` here is tri-state and `None` is the common answer.
#
# The structure enforces it rather than the discipline. There is exactly one
# function in this module that can construct `passed=True`, it is only
# reachable after a physical read has happened, and a test asserts both facts
# against the source text.

#: Filesystems whose writes land somewhere other than the original blocks. On
#: these, reading the pre-erase extents proves nothing about the old content:
#: the overwrite went to freshly allocated blocks and the originals are still
#: out there, referenced by a snapshot or waiting to be reused.
_COW_FILESYSTEMS = frozenset({"btrfs", "zfs", "apfs", "refs", "bcachefs", "nilfs2"})

#: Cap on bytes read back per extent, so verifying a 40 GiB file does not read
#: 40 GiB. The prefix is what an overwrite would have changed first.
_VERIFY_EXTENT_CAP = 8 * MIB


def _passed_after_physical_read(
    *, extents_checked: int, bytes_checked: int, failed_offsets: list[int]
) -> FileVerificationResult:
    """The ONLY constructor that may report a file erase as verified.

    Reaching this function means :func:`_read_physical_extents` opened the block
    device ``O_RDONLY``, seeked to the pre-erase physical offsets and compared
    the bytes it found there. Every other path in this module returns
    ``passed=None`` with a reason.

    Keep it that way. A second ``passed=True`` anywhere in this file would let a
    future edit ship a verification the tool never performed, and
    ``test_exactly_one_construction_site_can_produce_a_pass`` fails the build if
    one appears.
    """
    return FileVerificationResult(
        passed=True if not failed_offsets else False,
        strategy="physical_extent_read",
        reason=(
            f"Read {bytes_checked} bytes at {extents_checked} pre-erase "
            "physical extent(s) directly from the block device and compared "
            "the overwrite pattern."
            + (
                ""
                if not failed_offsets
                else f" {len(failed_offsets)} offset(s) still held other data."
            )
        ),
        extents_checked=extents_checked,
        bytes_checked=bytes_checked,
        failed_offsets=failed_offsets,
    )


def _not_possible(reason: str) -> FileVerificationResult:
    """Every refusal. ``passed`` is None: nothing is claimed in either direction."""
    return FileVerificationResult(passed=None, strategy="not_possible", reason=reason)


def _read_physical_extents(
    device: str, extents: Sequence[Extent], expected_byte: int
) -> tuple[int, int, list[int]]:
    """Read each extent from the raw device. Returns (extents, bytes, failures).

    Opened ``O_RDONLY`` with the same read-only flags the device verifier uses.
    Nothing in this module ever opens a device for writing.
    """
    pattern = bytes([expected_byte])
    fd = os.open(device, _READ_ONLY_FLAGS)
    checked = 0
    total = 0
    failures: list[int] = []
    try:
        for extent in extents:
            remaining = min(extent.length, _VERIFY_EXTENT_CAP)
            cursor = extent.physical_offset
            checked += 1
            while remaining > 0:
                os.lseek(fd, cursor, os.SEEK_SET)
                chunk = os.read(fd, min(remaining, MIB))
                if not chunk:
                    break
                total += len(chunk)
                if chunk.strip(pattern):
                    failures.append(cursor)
                    break
                cursor += len(chunk)
                remaining -= len(chunk)
    finally:
        os.close(fd)
    return checked, total, failures


def verify_file_erase(
    inspection: FileInspection,
    *,
    device_path: str | None = None,
    expected_byte: int = 0x00,
) -> FileVerificationResult:
    """Confirm, by reading the medium, that a file's old blocks no longer hold it.

    Refuses in four distinct situations, each with its own reason, and returns
    ``passed=None`` for every one of them. Only after all four are cleared does
    it read the raw device and hand the result to
    :func:`_passed_after_physical_read`.

    ``None`` is the honest answer far more often than not: an unprivileged file
    erase on a copy-on-write filesystem, or one whose filesystem would not
    produce an extent map, cannot be verified at all. Saying so is the point.
    """
    if not inspection.extents:
        return _not_possible(
            "No physical extent map was captured before the erase, so there is "
            "no address to read back. This is the usual case on a filesystem "
            "that does not answer FIEMAP or FSCTL_GET_RETRIEVAL_POINTERS, and "
            "on a file whose data was resident in its metadata record. Nothing "
            "is claimed."
        )

    if inspection.fs_type.lower() in _COW_FILESYSTEMS:
        return _not_possible(
            f"{inspection.fs_type} is copy-on-write: the overwrite was written "
            "to newly allocated blocks, so reading the pre-erase extents would "
            "test blocks the overwrite never touched. A clean read here would "
            "mean nothing and a dirty one would mean nothing either. Nothing "
            "is claimed."
        )

    if inspection.is_resident is True:
        return _not_possible(
            "The file's data was resident inside a filesystem metadata record, "
            "which has no data extent to read. Nothing is claimed."
        )

    device = device_path
    if device is None:
        from core.erase._platform import backend

        device, limitations = backend().block_device_for(Path(inspection.path))
        if device is None:
            return _not_possible(
                "The block device holding this file could not be identified, so "
                "its original physical blocks cannot be read back. "
                + " ".join(limitations)
            )

    try:
        checked, total, failures = _read_physical_extents(
            device, inspection.extents, expected_byte
        )
    except OSError as exc:
        return _not_possible(
            f"Raw read access to {device} was refused ({exc}). Verifying a file "
            "erase requires reading the original physical blocks, which needs "
            "root or administrator. Nothing is claimed."
        )

    logger.info(
        "file_erase_verified",
        path=inspection.path,
        device=device,
        extents=checked,
        bytes_checked=total,
        failures=len(failures),
    )
    return _passed_after_physical_read(
        extents_checked=checked, bytes_checked=total, failed_offsets=failures
    )
