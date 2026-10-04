"""External anchoring of Merkle roots, and an honest statement of its limits.

What a local hash chain proves
------------------------------
A hash chain proves *internal consistency*. Anyone who alters an entry has to
recompute every entry after it, so tampering by a party without write access to
the chain file is detected. That is real and useful.

What it does not prove
----------------------
It does **not** prove existence-at-a-time to a third party. Someone with write
access to the whole store can rebuild the chain from scratch, backdate every
timestamp, and produce a chain that verifies perfectly. Nothing inside the file
can rule that out, because every value in it is under the same control.

Only *external anchoring* closes that gap: publishing a Merkle root of a range
of entries somewhere the operator cannot retroactively edit fixes those entries
in time relative to that publication. A newspaper classified, a transparency
log, a countersigned receipt from another organisation, and a blockchain are all
instances of the same idea.

This module exposes the interface and ships two local implementations. It
deliberately ships **no network anchor**. Sanctum is meant to run air-gapped on
seized media; a component that silently needs the internet would either fail in
the field or tempt an operator to connect an evidence machine to a network. If
asked what proves existence-at-a-time, the honest answer is: this interface,
plus whatever external witness the deploying organisation chooses to wire into
it. Not this file on its own.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

import structlog

__all__ = ["AnchorReceipt", "Anchor", "NullAnchor", "FileAnchor"]

logger = structlog.get_logger(__name__)

_BINARY = getattr(os, "O_BINARY", 0)


@dataclass(frozen=True)
class AnchorReceipt:
    """Evidence that a Merkle root was published, and where."""

    anchor_type: str
    root: str
    from_seq: int
    to_seq: int
    anchored_at: str
    location: str
    note: str


def _now() -> str:
    stamp = datetime.now(UTC)
    return (
        f"{stamp.year:04d}-{stamp.month:02d}-{stamp.day:02d}"
        f"T{stamp.hour:02d}:{stamp.minute:02d}:{stamp.second:02d}"
        f".{stamp.microsecond:06d}Z"
    )


class Anchor(Protocol):
    """Publishes a Merkle root for a range of ledger entries."""

    def publish(self, root: str, seq_range: tuple[int, int]) -> AnchorReceipt:
        """Publish ``root`` covering ``seq_range`` inclusive."""
        ...


class NullAnchor:
    """The default. Records plainly that no external witness was configured."""

    def publish(self, root: str, seq_range: tuple[int, int]) -> AnchorReceipt:
        """Return a receipt stating that nothing was published externally."""
        return AnchorReceipt(
            anchor_type="null",
            root=root,
            from_seq=seq_range[0],
            to_seq=seq_range[1],
            anchored_at=_now(),
            location="",
            note=(
                "No external anchor was configured. This chain proves internal "
                "consistency and detects tampering by anyone without write "
                "access to the store, but it does not prove to a third party "
                "that these entries existed at the recorded times."
            ),
        )


class FileAnchor:
    """Appends roots to a separate file, intended for write-once media.

    The value comes entirely from where the file lives. On the same writable
    disk as the chain it adds nothing; on a WORM volume, a append-only network
    share, or a partition controlled by a different custodian, it is a real
    external witness.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def publish(self, root: str, seq_range: tuple[int, int]) -> AnchorReceipt:
        """Append the root, range and timestamp as one JSON line."""
        anchored_at = _now()
        record = {
            "root": root,
            "from_seq": seq_range[0],
            "to_seq": seq_range[1],
            "anchored_at": anchored_at,
        }
        line = json.dumps(record, separators=(",", ":"), sort_keys=True)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(
            self.path, os.O_APPEND | os.O_CREAT | os.O_WRONLY | _BINARY, 0o600
        )
        try:
            os.write(fd, line.encode("utf-8") + b"\n")
            os.fsync(fd)
        finally:
            os.close(fd)
        logger.info("anchor_published", root=root[:12], range=seq_range)
        return AnchorReceipt(
            anchor_type="file",
            root=root,
            from_seq=seq_range[0],
            to_seq=seq_range[1],
            anchored_at=anchored_at,
            location=str(self.path),
            note=(
                "Published to a local append-only file. This is only an "
                "external witness if that path is on media the operator cannot "
                "rewrite."
            ),
        )
