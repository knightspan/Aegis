"""Device sanitize (firmware Purge) around a platform's command, with read-back.

The command itself is the platform's: ATA SANITIZE through
``IOCTL_ATA_PASS_THROUGH``, NVMe Sanitize through
``IOCTL_STORAGE_REINITIALIZE_MEDIA``. This module wraps whichever one the
resolver selected in the same shape every erase has: a ledgered plan, the
command, the drive's (or driver's) own completion status, a read-back of the
medium, and an :class:`~core.models.EraseResult` whose level is PURGE only when
the command reported success **and** the read-back agrees.

What the read-back can and cannot show
--------------------------------------
* **Block erase** leaves the medium reading a vendor-defined value; ACS and
  NVMe allow all-zeros or all-ones. The sampled read requires one of those.
* **Crypto erase** leaves ciphertext under a new key, which reads as noise. No
  pattern can be required of it. What *can* be checked is that the medium
  changed: the same seeded windows are hashed before and after, and every one
  must differ. That proves the command did something to every sampled
  window; it cannot prove the old key is gone.

Nothing here downgrades. A refused or failed command raises; it is never
followed by an overwrite presented as the same thing.
"""

from __future__ import annotations

import hashlib
import random
from collections.abc import Callable, Generator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from core.erase.blockclear import BlockTarget, verify_target
from core.erase.sink import LedgerSink
from core.erase.verify import VerifyConfig
from core.models import (
    Device,
    EraseMethod,
    ErasePhase,
    ErasePlan,
    EraseResult,
    Progress,
    ResidualRiskAssessment,
    SanitizationLevel,
    VerificationResult,
)

__all__ = ["CRYPTO_METHODS", "SanitizeRequest", "run"]

CRYPTO_METHODS = frozenset(
    {
        EraseMethod.ATA_SANITIZE_CRYPTO_SCRAMBLE,
        EraseMethod.NVME_SANITIZE_CRYPTO,
        EraseMethod.SED_CRYPTO_ERASE,
    }
)

#: What an issuer returns: whether the device itself attested completion, and
#: the details the report prints.
Attestation = dict[str, Any]


@dataclass(frozen=True)
class SanitizeRequest:
    job_id: str
    device: Device
    identity: dict[str, Any]
    platform: str
    method: EraseMethod
    capability: str
    protocol: str
    mechanism: str
    device_class: str
    limitations: tuple[str, ...] = ()
    verify: VerifyConfig = field(default_factory=lambda: VerifyConfig(sample_count=256))
    est_seconds: int = 0


def _windows(size: int, sector: int, config: VerifyConfig) -> list[tuple[int, int]]:
    rng = random.Random(config.seed)
    span = max(sector, (config.sample_bytes // sector) * sector)
    if size <= span:
        return [(0, size)]
    slots = (size - span) // sector
    return [
        (rng.randrange(0, slots + 1) * sector, span) for _ in range(config.sample_count)
    ]


def _fingerprints(target: BlockTarget, windows: list[tuple[int, int]]) -> list[str]:
    out: list[str] = []
    for offset, length in windows:
        try:
            out.append(hashlib.sha256(target.read_at(offset, length)).hexdigest())
        except OSError:
            out.append("")
    return out


def _crypto_verify(
    before: list[str], after: list[str], windows: list[tuple[int, int]]
) -> VerificationResult:
    unchanged = [
        windows[index][0]
        for index, (old, new) in enumerate(zip(before, after, strict=True))
        if not old or not new or old == new
    ]
    return VerificationResult(
        passed=not unchanged,
        strategy="hw_attested",
        bytes_checked=sum(length for _, length in windows) * 2,
        sample_count=len(windows),
        confidence_bp=0,
        failed_offsets=unchanged[:1000],
        probability_note=(
            f"Crypto erase leaves ciphertext, so no pattern can be required. "
            f"{len(windows)} seeded windows were hashed before and after the "
            f"command; {len(windows) - len(unchanged)} changed. This shows the "
            "command acted on every sampled window. It cannot show the old key "
            "is unrecoverable; that rests on the drive's key management."
        ),
    )


def run(
    request: SanitizeRequest,
    *,
    issue: Callable[[], Generator[Progress, None, Attestation]],
    open_reader: Callable[[], BlockTarget],
    ledger: LedgerSink,
) -> Generator[Progress, None, EraseResult]:
    """Issue the platform's sanitize command, then read the medium back."""
    started = datetime.now(UTC)
    crypto = request.method in CRYPTO_METHODS
    plan = ErasePlan(
        method=request.method,
        level=SanitizationLevel.PURGE,
        justification=(
            f"The device reported {request.capability} and the resolver chose it. "
            f"Issued as {request.mechanism}. Executed by the device's own "
            "firmware, so its coverage includes spare and remapped blocks the "
            "host cannot address, as far as the firmware implements it."
        ),
        est_seconds=request.est_seconds,
        limitations=list(request.limitations),
        est_basis="no rate can be measured before a firmware sanitize",
    )
    ledger.record(
        ErasePhase.PREFLIGHT,
        "plan",
        {
            "job_id": request.job_id,
            "platform": request.platform,
            "capability": request.capability,
            "protocol": request.protocol,
            "mechanism": request.mechanism,
            "device_class": request.device_class,
            "identity": request.identity,
            "plan": plan.model_dump(mode="json"),
        },
    )
    yield Progress(
        job_id=request.job_id,
        phase=ErasePhase.PREFLIGHT.value,
        pct_bp=10_000,
        bytes_done=0,
        bytes_total=request.device.size_bytes,
        throughput_bytes_per_sec=0,
        eta_seconds=0,
        message="plan recorded",
    )
    windows: list[tuple[int, int]] = []
    before: list[str] = []
    if crypto:
        reader = open_reader()
        try:
            windows = _windows(reader.size_bytes, reader.logical_sector, request.verify)
            before = _fingerprints(reader, windows)
        finally:
            reader.close()

    issuer = issue()
    try:
        while True:
            try:
                yield next(issuer)
            except StopIteration as stop:
                attestation: Attestation = stop.value
                break
    except BaseException as exc:
        ledger.record(
            ErasePhase.ERASE,
            "failed",
            {
                "job_id": request.job_id,
                "mechanism": request.mechanism,
                "error": f"{type(exc).__name__}: {exc}",
                "state": "UNKNOWN: the command was issued or attempted; the "
                "medium's state must be checked before it is relied on",
            },
        )
        raise
    ledger.record(
        ErasePhase.ERASE,
        "complete",
        {"job_id": request.job_id, "attestation": attestation},
    )

    reader = open_reader()
    try:
        if crypto:
            after = _fingerprints(reader, windows)
            verification = _crypto_verify(before, after, windows)
        else:
            check = verify_target(
                reader,
                frozenset({0x00, 0xFF}),
                config=request.verify,
                force_sampled=True,
            )
            while True:
                try:
                    next(check)
                except StopIteration as stop:
                    verification = stop.value
                    break
            verification = verification.model_copy(
                update={
                    "strategy": "hw_attested",
                    "hw_attested": bool(attestation.get("hw_attested")),
                }
            )
    finally:
        reader.close()
    ledger.record(
        ErasePhase.VERIFY,
        "result",
        {"job_id": request.job_id, **verification.model_dump(mode="json")},
    )
    hw = bool(attestation.get("hw_attested"))
    passed = verification.passed
    factors = []
    if not hw:
        factors.append(
            "The device did not attest completion itself; the driver reported "
            "success. The read-back is the only independent check."
        )
    if not passed:
        factors.append("The read-back did not agree with the command's success.")
    if crypto:
        factors.append(
            "Crypto erase: the ciphertext remains; unrecoverability rests on the "
            "drive's key management."
        )
    result = EraseResult(
        job_id=request.job_id,
        method=request.method,
        level=SanitizationLevel.PURGE,
        started_at=started,
        finished_at=datetime.now(UTC),
        bytes_written=0,
        passes=1,
        plan=plan,
        residual_risk=ResidualRiskAssessment(
            level="low" if (passed and hw) else "medium" if passed else "high",
            factors=factors,
            purge_achieved=passed,
            notes=(
                f"Device sanitize ({request.capability}) through {request.mechanism}."
            ),
        ),
        limitations=[*request.limitations, *attestation.get("limitations", [])],
        hw_attested=hw,
        device=request.device,
        verification=verification,
        achieved_level=SanitizationLevel.PURGE if passed else None,
    )
    return result
