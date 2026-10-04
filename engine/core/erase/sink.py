"""Where erase phase records go: the hash-chained ledger, behind one seam.

This lives outside :mod:`core.erase.drive` because that module refuses to
import off Linux - whole-device sanitization needs ``O_DIRECT`` alignment,
``BLKGETSIZE64`` and ATA/NVMe pass-through, none of which have a faithful
equivalent elsewhere. :mod:`core.erase.files` has no such constraint and must
ledger on every platform, so the sink cannot live behind that gate.

Nothing here is platform-specific.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

from core.ledger.chain import GENESIS_OPERATION, Ledger
from core.models import EraseCheckpoint, ErasePhase

__all__ = ["LedgerSink", "ChainLedgerSink"]


class LedgerSink(Protocol):
    """Where phase records go.

    A seam rather than a direct dependency, so a caller can substitute a
    recorder in a test without standing up a chain on disk. Every production
    caller passes :class:`ChainLedgerSink`.
    """

    def record(
        self, phase: ErasePhase, operation: str, payload: dict[str, Any]
    ) -> None:
        """Append one entry."""
        ...

    def last_checkpoint(self, job_id: str) -> EraseCheckpoint | None:
        """Most recent checkpoint for ``job_id``, if any."""
        ...

    def record_file(self, operation: str, payload: dict[str, Any]) -> None:
        """Append one entry for a file-erase phase."""
        ...


class ChainLedgerSink:
    """Adapts the hash-chained :class:`core.ledger.chain.Ledger` to erase phases.

    Every phase becomes one real ledger entry: the payload is stored as a blob
    and the chain records its hash, so the entry stays a fixed size while still
    proving exactly what was written.

    Payloads are passed to the chain unchanged. Every model that reaches here
    carries integers where it once carried floats, so there is nothing for this
    adapter to rewrite: what a verifier reads back is what the operation
    measured, in the unit the field name states.
    """

    def __init__(self, ledger: Ledger, *, actor: str = "sanctum") -> None:
        self.ledger = ledger
        self.actor = actor

    def record(
        self, phase: ErasePhase, operation: str, payload: dict[str, Any]
    ) -> None:
        """Append one chained entry for this phase."""
        self.ledger.append(
            actor=self.actor,
            operation=f"erase.{phase.value.lower()}.{operation}",
            params=payload,
            result={},
        )

    def record_file(self, operation: str, payload: dict[str, Any]) -> None:
        """Append one chained entry for a file-erase phase.

        Separate from :meth:`record` because file erasure has its own phase
        vocabulary (:class:`~core.models.FileErasePhase`) and its operations
        are namespaced ``erase.file.*``. Sharing :meth:`record` would have meant
        widening its ``phase`` parameter to a union and letting a drive phase
        and a file phase collide in the same namespace.
        """
        self.ledger.append(
            actor=self.actor,
            operation=f"erase.file.{operation}",
            params=payload,
            result={},
        )

    def last_checkpoint(self, job_id: str) -> EraseCheckpoint | None:
        """Most recent overwrite checkpoint recorded for ``job_id``."""
        for entry in reversed(self.ledger.entries()):
            if not entry.operation.endswith(".checkpoint"):
                continue
            params = self.ledger.params_of(entry)
            if params.get("job_id") != job_id:
                continue
            return EraseCheckpoint.model_validate(params)
        return None

    def entries_for(self, job_id: str) -> list[dict[str, Any]]:
        """Ledger entries belonging to ``job_id``, as plain dicts for the report."""
        selected: list[dict[str, Any]] = []
        for entry in self.ledger.entries():
            if entry.operation == GENESIS_OPERATION:
                selected.append(json.loads(entry.model_dump_json()))
                continue
            if not entry.operation.startswith("erase."):
                continue
            if self.ledger.params_of(entry).get("job_id") == job_id:
                selected.append(json.loads(entry.model_dump_json()))
        return selected
