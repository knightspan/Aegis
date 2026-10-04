"""Destroy, recorded: the third NIST SP 800-88 Rev. 2 outcome, attested by people.

Clear and Purge are things this tool does to a medium and then reads back.
Destroy is not: a shredder, a disintegrator or a furnace does it, and no
software can perform or observe it. What software can do is keep the record
honestly - bind what the people who did it attest to the hash chain, sign it,
and say in the record itself that the tool saw none of it.

So this module writes one ledger entry, ``destroy.recorded``, carrying the whole
attestation, and returns the record with the limitations every report built
from it must carry. It opens no device and touches no file. The date the
destruction happened is the attesters' statement; the date it was recorded is
this machine's clock, and the two are kept apart.
"""

from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from core.errors import SanctumError
from core.ledger.chain import Ledger
from core.models import DestructionRecord, Progress

__all__ = [
    "ATTESTED_NOT_OBSERVED",
    "destruction_limitations",
    "record_destruction",
    "refuse_a_future_date",
]

logger = structlog.get_logger(__name__)

#: The first limitation of every destruction record, and the phrase a verdict
#: on one is tested for.
ATTESTED_NOT_OBSERVED = (
    "ATTESTED, NOT OBSERVED: this tool did not see, perform or measure the "
    "destruction. The record states what the people named in it attested. Its "
    "signature proves the record has not changed since it was signed, not that "
    "the destruction took place."
)

#: A destruction dated this far past the recording clock is refused: nobody
#: can attest to something that has not happened yet.
_CLOCK_SKEW = timedelta(minutes=5)


def destruction_limitations(record: DestructionRecord) -> list[str]:
    """What a report on ``record`` must say it cannot vouch for."""
    lines = [
        ATTESTED_NOT_OBSERVED,
        "The names of the person who destroyed the medium and of the witness "
        "were typed in. This API does not authenticate a person.",
        "Whether the technique and fragment size reach Destroy for this kind of "
        "medium is the facility's and the operator's determination; the tool "
        "records it and does not judge it.",
    ]
    if not record.witnessed_by.strip():
        lines.append("NO WITNESS was recorded for this destruction.")
    if record.particle_size_mm is None:
        lines.append("No fragment size was recorded.")
    return lines


def refuse_a_future_date(
    record: DestructionRecord, *, now: datetime | None = None
) -> None:
    """Raise when the destruction is dated after this machine's clock.

    Nobody can attest to something that has not happened yet. A time with no
    zone is read as UTC.
    """
    clock = now or datetime.now(UTC)
    performed_at = record.performed_at
    if performed_at.tzinfo is None:
        performed_at = performed_at.replace(tzinfo=UTC)
    if performed_at > clock + _CLOCK_SKEW:
        raise SanctumError(
            f"The destruction is dated {performed_at.isoformat()}, after this "
            f"machine's clock ({clock.isoformat()}).",
            remediation="Enter the date and time the medium was destroyed. "
            "Nothing was recorded.",
        )


def record_destruction(
    record: DestructionRecord,
    *,
    ledger: Ledger,
    job_id: str,
    actor: str,
    case_id: str = "",
    now: datetime | None = None,
) -> Generator[Progress, None, dict[str, Any]]:
    """Chain one destruction record and return it with its limitations.

    A generator, like every long operation, so the job registry can run it; it
    has one step. Raises :class:`SanctumError` for a destruction dated in the
    future, before anything is written.
    """
    recorded_at = now or datetime.now(UTC)
    refuse_a_future_date(record, now=recorded_at)
    attested = record.model_dump(mode="json")
    ledger.append(
        actor=actor,
        operation="destroy.recorded",
        params={
            "job_id": job_id,
            "case_id": case_id,
            "record": attested,
            "recorded_at": recorded_at.isoformat(),
            "observed_by_tool": False,
        },
        result={},
    )
    yield Progress(
        job_id=job_id,
        phase="RECORD",
        pct_bp=10_000,
        bytes_done=0,
        bytes_total=0,
        throughput_bytes_per_sec=0,
        eta_seconds=0,
        message=f"destruction of {record.serial} recorded",
    )
    logger.info("destruction_recorded", job_id=job_id, serial=record.serial)
    return {
        "record": attested,
        "recorded_at": recorded_at.isoformat(),
        "observed_by_tool": False,
        "limitations": destruction_limitations(record),
    }
