"""Destroy is recorded as attested, never as observed.

The record binds what people state to the chain; it opens nothing. These pin
the entry it writes, the limitations every report on it carries, and the
refusal of a destruction dated in the future.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from core.destroy import ATTESTED_NOT_OBSERVED, record_destruction
from core.errors import SanctumError
from core.ledger.chain import ChainStatus, Ledger
from core.models import DestructionRecord
from pydantic import ValidationError

NOW = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)


def record(**overrides: Any) -> DestructionRecord:
    fields: dict[str, Any] = {
        "serial": "WD-WX41A12345",
        "model": "WDC WD10EZEX",
        "capacity_bytes": 1_000_204_886_016,
        "media_type": "HDD",
        "technique": "SHRED",
        "particle_size_mm": 20,
        "reason": "Heads failed; the drive cannot be purged.",
        "performed_by": "A. Rao",
        "witnessed_by": "S. Iyer",
        "performed_at": "2026-09-24T15:30:00+05:30",
        "location": "Evidence room 2",
    }
    fields.update(overrides)
    return DestructionRecord.model_validate(fields)


def drain(generator: Any) -> Any:
    try:
        while True:
            next(generator)
    except StopIteration as stop:
        return stop.value


def test_one_chained_entry_carries_the_whole_attestation(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path / "ledger", tool_version="t", pubkey_fingerprint="")
    result = drain(
        record_destruction(
            record(), ledger=ledger, job_id="destroy-1", actor="op", now=NOW
        )
    )
    (entry,) = [e for e in ledger.entries() if e.operation == "destroy.recorded"]
    params = ledger.params_of(entry)
    assert params["job_id"] == "destroy-1"
    assert params["record"]["serial"] == "WD-WX41A12345"
    assert params["observed_by_tool"] is False
    assert result["recorded_at"] == NOW.isoformat()
    assert result["limitations"][0] == ATTESTED_NOT_OBSERVED
    assert ledger.verify().status is ChainStatus.VALID


def test_a_missing_witness_and_fragment_size_are_named(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path / "ledger", tool_version="t", pubkey_fingerprint="")
    result = drain(
        record_destruction(
            record(witnessed_by="", particle_size_mm=None),
            ledger=ledger,
            job_id="destroy-2",
            actor="op",
            now=NOW,
        )
    )
    joined = " ".join(result["limitations"])
    assert "NO WITNESS" in joined and "No fragment size" in joined


def test_a_destruction_dated_in_the_future_is_refused_before_any_write(
    tmp_path: Path,
) -> None:
    ledger = Ledger(tmp_path / "ledger", tool_version="t", pubkey_fingerprint="")
    later = (NOW + timedelta(days=1)).isoformat()
    with pytest.raises(SanctumError, match="after this machine's clock"):
        drain(
            record_destruction(
                record(performed_at=later),
                ledger=ledger,
                job_id="destroy-3",
                actor="op",
                now=NOW,
            )
        )
    assert not [e for e in ledger.entries() if e.operation == "destroy.recorded"]


@pytest.mark.parametrize(
    "overrides",
    [
        {"serial": "   "},
        {"performed_by": ""},
        {"reason": " "},
        {"technique": "OTHER"},
        {"technique": "SHRED", "particle_size_mm": 0},
        {"media_type": "FLOPPY"},
    ],
    ids=["blank-serial", "no-one", "no-reason", "other-undescribed", "zero-mm", "type"],
)
def test_an_incomplete_attestation_is_refused(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        record(**overrides)


def test_other_is_accepted_when_it_says_what_was_done() -> None:
    assert record(
        technique="OTHER", technique_detail="Platters sanded"
    ).technique_detail
