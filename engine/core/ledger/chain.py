"""Hash-chain construction and verification.

Entry N binds to entry N-1: ``prev_entry_hash`` is the SHA-256 of entry N-1's
canonical serialisation, and ``entry_hash`` is the SHA-256 of entry N including
that link. Changing anything in the middle of the chain therefore invalidates
every entry after it, and the verifier can say exactly where trust stops.

Two design points worth stating outright:

**A crash is not an attack.** A process killed mid-append leaves a partial final
line. That is reported as :attr:`ChainStatus.INCOMPLETE_TAIL`, never as
``BROKEN``. A forensic tool that cries tampering every time a laptop loses power
will not be believed the one time it matters.

**Time needs a boot identity.** ``monotonic_ns`` is only comparable within a
single boot. Without ``boot_id`` a verifier cannot distinguish a legitimate
reboot from a clock rollback, so both are recorded: monotonic time must increase
within a ``boot_id``, and wall-clock time must not go backwards across the whole
chain.

The verifier reports the *first* break and keeps scanning, so a report can say
"chain valid for 0..417, broken at 418, 12 further entries unverifiable" rather
than simply "invalid".
"""

from __future__ import annotations

import hashlib
import json
import random
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

import structlog

from core.errors import LedgerBusy
from core.ledger._filelock import LockUnavailable
from core.ledger.canon import CANON_VERSION, canonical_bytes
from core.ledger.store import BlobStore, LedgerStore
from core.models import LedgerEntry

__all__ = [
    "ChainStatus",
    "FailureKind",
    "ChainVerification",
    "Ledger",
    "GENESIS_OPERATION",
    "NO_SIGNING_KEY",
    "GENESIS_PREV_HASH",
    "boot_id",
    "entry_hash_of",
    "genesis_fingerprint",
    "APPEND_LOCK_ATTEMPTS",
    "APPEND_BACKOFF_INITIAL_SECONDS",
    "APPEND_BACKOFF_CAP_SECONDS",
    "APPEND_BACKOFF_JITTER_FLOOR",
]

logger = structlog.get_logger(__name__)

GENESIS_OPERATION = "GENESIS"
#: Recorded as the genesis ``pubkey_fingerprint`` when a chain is created before
#: any signing key exists. An empty string was indistinguishable from "the field
#: was never populated", and a verifier reading it reported a *missing genesis
#: entry* for a chain whose genesis was right there. Callers that have a key
#: should load it before the first append and pass its fingerprint.
NO_SIGNING_KEY = "NO_SIGNING_KEY_AT_CHAIN_CREATION"
GENESIS_PREV_HASH = "0" * 64
GENESIS_ACTOR = "sanctum"

#: How many times :meth:`Ledger.append` tries the writer lock before it fails.
#:
#: The lock is held for one append: read the chain, build one entry, write and
#: ``fsync`` one line. Measured on this project's development host, that is
#: 0.5 ms on a 100-entry chain and 39 ms on a 10,000-entry chain, because the
#: read is linear in the chain; a slow USB ``fsync`` adds tens to hundreds of
#: milliseconds on top. With doubling backoff from 10 ms capped at 1 s, twenty
#: attempts wait about 10 seconds in total - several hundred appends' worth of
#: contention - before the append is refused.
APPEND_LOCK_ATTEMPTS = 20
#: First wait between attempts; doubled after each one.
APPEND_BACKOFF_INITIAL_SECONDS = 0.01
#: Longest single wait between attempts.
APPEND_BACKOFF_CAP_SECONDS = 1.0
#: Smallest fraction of the current backoff a writer actually sleeps. The rest
#: is chosen at random from the interval, so writers that collide do not go on
#: waking together. Without it, eight threads that lose the same first attempt
#: converge on the same one-second rhythm and one of them can lose every
#: subsequent attempt as well: the Windows runner failed exactly that way
#: (``tests/ledger/test_concurrent_writers.py``, run 35682651431). The lock is
#: not queued and cannot be fair, so the retries must not be synchronised.
APPEND_BACKOFF_JITTER_FLOOR = 0.5

_BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
_HASHED_FIELDS = (
    "seq",
    "ts_utc",
    "monotonic_ns",
    "boot_id",
    "actor",
    "operation",
    "params_hash",
    "result_hash",
    "prev_entry_hash",
)


class ChainStatus(StrEnum):
    """Overall verdict for a chain."""

    VALID = "VALID"
    BROKEN = "BROKEN"
    INCOMPLETE_TAIL = "INCOMPLETE_TAIL"


class FailureKind(StrEnum):
    """What specifically went wrong. ``None`` alongside INCOMPLETE_TAIL."""

    HASH_MISMATCH = "HASH_MISMATCH"
    LINK_MISMATCH = "LINK_MISMATCH"
    SEQ_GAP = "SEQ_GAP"
    SEQ_DUPLICATE = "SEQ_DUPLICATE"
    TIME_REGRESSION = "TIME_REGRESSION"
    PARSE_ERROR = "PARSE_ERROR"
    MISSING_BLOB = "MISSING_BLOB"


@dataclass(frozen=True)
class ChainVerification:
    """Result of walking a chain from genesis."""

    status: ChainStatus
    explanation: str
    first_bad_seq: int | None = None
    failure_kind: FailureKind | None = None
    verified_through: int | None = None
    unverifiable_count: int = 0
    entry_count: int = 0


def boot_id() -> str:
    """A UUID that is stable for this boot and changes across reboots.

    Linux exposes one directly. Elsewhere the per-process fallback still changes
    across reboots, which is what the monotonic comparison actually needs, and
    the value is recorded so a verifier can see which entries share a clock.
    """
    try:
        text = _BOOT_ID_PATH.read_text(encoding="utf-8").strip()
        if text:
            return text
    except OSError:
        pass
    return str(uuid.UUID(int=uuid.getnode() ^ int(_process_boot_seed())))


def _process_boot_seed() -> int:
    """Stable within this process; distinct across restarts."""
    return int(time.time() - time.monotonic()) & ((1 << 96) - 1)


def genesis_fingerprint(root: Path | str) -> str | None:
    """The signing fingerprint the chain under ``root`` recorded at genesis.

    Returns :data:`NO_SIGNING_KEY` for a chain started before any key existed
    (including chains that recorded an empty string before that constant
    existed), and ``None`` when there is no readable genesis to ask. Reads the
    first line and one blob, never the whole chain, so a health check can call
    it on every poll.
    """
    store = LedgerStore(root)
    try:
        with store.path.open("rb") as handle:
            first = handle.readline()
    except OSError:
        return None
    if not first.endswith(b"\n"):
        return None
    try:
        entry = LedgerEntry.model_validate_json(first)
    except ValueError:
        return None
    if entry.operation != GENESIS_OPERATION:
        return None
    raw = BlobStore(root).get(entry.params_hash)
    if raw is None:
        return None
    try:
        params = json.loads(raw)
    except ValueError:
        return None
    value = params.get("pubkey_fingerprint") if isinstance(params, dict) else None
    return str(value) if value else NO_SIGNING_KEY


def entry_hash_of(fields: dict[str, Any]) -> str:
    """SHA-256 hex of an entry's canonical bytes, excluding ``entry_hash``."""
    payload = {name: fields[name] for name in _HASHED_FIELDS}
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def _entry_to_record(entry: LedgerEntry) -> dict[str, Any]:
    """The exact dict shape that gets canonicalised and written."""
    return {
        "seq": entry.seq,
        "ts_utc": entry.ts_utc,
        "monotonic_ns": entry.monotonic_ns,
        "boot_id": entry.boot_id,
        "actor": entry.actor,
        "operation": entry.operation,
        "params_hash": entry.params_hash,
        "result_hash": entry.result_hash,
        "prev_entry_hash": entry.prev_entry_hash,
        "entry_hash": entry.entry_hash,
    }


class Ledger:
    """Append-only hash-chained audit log."""

    def __init__(
        self,
        root: Path | str,
        *,
        tool_version: str,
        pubkey_fingerprint: str,
        boot_id_value: str | None = None,
        monotonic_source: Callable[[], int] = time.monotonic_ns,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        owner_uid: int | None = None,
        **kwargs: str,
    ) -> None:
        self.root = Path(root)
        # ``owner_uid`` is set by the root helper and by nothing else: it is the
        # operator uid the daemon was started with, so a chain the helper writes
        # during a wipe stays readable to the unprivileged API that has to turn
        # it into a certificate. See :mod:`core.ledger._ownership`.
        self.owner_uid = owner_uid
        self.store = LedgerStore(self.root, owner_uid=owner_uid)
        self.blobs = BlobStore(self.root, owner_uid=owner_uid)
        self.tool_version = tool_version
        self.pubkey_fingerprint = pubkey_fingerprint
        self.boot_id = boot_id_value or kwargs.get("boot_id") or boot_id()
        self._monotonic = monotonic_source
        self._clock = clock

    # -- reading ---------------------------------------------------------

    def entries(self) -> list[LedgerEntry]:
        """Every complete entry, in file order."""
        parsed, _, _ = self._parse()
        return parsed

    def _parse(self) -> tuple[list[LedgerEntry], bool, int | None]:
        """Return ``(entries, incomplete_tail, parse_error_index)``."""
        read = self.store.read()
        entries: list[LedgerEntry] = []
        for index, line in enumerate(read.lines):
            try:
                entries.append(LedgerEntry.model_validate_json(line))
            except (ValueError, json.JSONDecodeError):
                return entries, read.incomplete_tail, index
        return entries, read.incomplete_tail, None

    def params_of(self, entry: LedgerEntry) -> dict[str, Any]:
        """Load the stored parameters for ``entry``."""
        return self._blob_json(entry.params_hash)

    def result_of(self, entry: LedgerEntry) -> dict[str, Any]:
        """Load the stored result for ``entry``."""
        return self._blob_json(entry.result_hash)

    def _blob_json(self, digest: str) -> dict[str, Any]:
        raw = self.blobs.get(digest)
        if raw is None:
            raise FileNotFoundError(f"blob {digest} is missing from the store")
        loaded: dict[str, Any] = json.loads(raw)
        return loaded

    # -- writing ---------------------------------------------------------

    def append(
        self,
        *,
        actor: str,
        operation: str,
        params: dict[str, Any],
        result: dict[str, Any],
    ) -> LedgerEntry:
        """Append one entry, writing genesis first if the chain is empty.

        **The chain may have several writers**: the API's routes, a job's
        engine, and the root helper during a wipe each hold their own instance.
        So the head is read, the entry is built on it, and the line is written
        all under the chain's writer lock, and the head is always the one on
        disk at that moment - never one this instance remembers from an earlier
        append. Remembering it is what turned a report generated during a carve
        into a failed carve (MANUAL_REPORT FINDING 2).

        The lock is taken without blocking and retried with backoff, bounded by
        :data:`APPEND_LOCK_ATTEMPTS`. ``flock`` has no timeout, and a writer
        that waited forever behind a hung process would hang the job with it.

        Raises:
            LedgerBusy: another writer held the lock through every attempt. The
                entry was **not** written; the caller's operation must fail
                rather than continue without its record.
            RuntimeError: the chain ends in an incomplete line, or a line does
                not parse.
        """
        # Content-addressed and idempotent, so written before the lock: the
        # critical section stays one read, one build and one line.
        self.blobs.put(canonical_bytes(params))
        self.blobs.put(canonical_bytes(result))

        delay = APPEND_BACKOFF_INITIAL_SECONDS
        waited = 0.0
        for attempt in range(1, APPEND_LOCK_ATTEMPTS + 1):
            try:
                with self.store.writer_lock(blocking=False):
                    return self._append_locked(
                        actor=actor, operation=operation, params=params, result=result
                    )
            except LockUnavailable:
                if attempt == APPEND_LOCK_ATTEMPTS:
                    break
                logger.debug(
                    "ledger_lock_contended", attempt=attempt, operation=operation
                )
                pause = random.uniform(delay * APPEND_BACKOFF_JITTER_FLOOR, delay)
                time.sleep(pause)
                waited += pause
                delay = min(delay * 2, APPEND_BACKOFF_CAP_SECONDS)

        raise LedgerBusy(
            f"Ledger entry {operation!r} was NOT recorded: the writer lock "
            f"{self.store.lock_path} was held by another writer through "
            f"{APPEND_LOCK_ATTEMPTS} attempts over {waited:.1f} s. No single "
            "append holds the lock for more than a fraction of a second, so "
            "either a process is hung while holding it, or this many writers "
            "are contending for one chain."
        )

    def _append_locked(
        self,
        *,
        actor: str,
        operation: str,
        params: dict[str, Any],
        result: dict[str, Any],
    ) -> LedgerEntry:
        """The append itself. The caller holds the store's writer lock."""
        existing, incomplete, parse_error = self._parse()
        if incomplete:
            raise RuntimeError(
                "the chain ends in an incomplete line left by a write that did "
                "not finish. Refusing to append past it: archive the truncated "
                "file as evidence and start a new chain rather than editing it."
            )
        if parse_error is not None:
            raise RuntimeError(
                f"chain line {parse_error} does not parse; refusing to append "
                "to a chain that cannot be verified."
            )

        if not existing:
            genesis = self._build(
                seq=0,
                actor=GENESIS_ACTOR,
                operation=GENESIS_OPERATION,
                params={
                    "tool_version": self.tool_version,
                    "canon_version": CANON_VERSION,
                    # Never an empty string: the absence is stated, so a reader
                    # can tell "no key existed yet" from "this field was not
                    # written". See NO_SIGNING_KEY.
                    "pubkey_fingerprint": (
                        self.pubkey_fingerprint or NO_SIGNING_KEY
                    ),
                },
                result={},
                prev_entry_hash=GENESIS_PREV_HASH,
            )
            self._write(genesis)
            existing = [genesis]

        head = existing[-1]
        entry = self._build(
            seq=head.seq + 1,
            actor=actor,
            operation=operation,
            params=params,
            result=result,
            prev_entry_hash=head.entry_hash,
        )
        self._write(entry)
        return entry

    def _build(
        self,
        *,
        seq: int,
        actor: str,
        operation: str,
        params: dict[str, Any],
        result: dict[str, Any],
        prev_entry_hash: str,
    ) -> LedgerEntry:
        fields: dict[str, Any] = {
            "seq": seq,
            "ts_utc": self._clock(),
            "monotonic_ns": self._monotonic(),
            "boot_id": self.boot_id,
            "actor": actor,
            "operation": operation,
            "params_hash": self.blobs.put(canonical_bytes(params)),
            "result_hash": self.blobs.put(canonical_bytes(result)),
            "prev_entry_hash": prev_entry_hash,
        }
        fields["entry_hash"] = entry_hash_of(fields)
        return LedgerEntry.model_validate(fields)

    def _write(self, entry: LedgerEntry) -> None:
        self.store.append_locked(canonical_bytes(_entry_to_record(entry)))
        logger.debug("ledger_append", seq=entry.seq, operation=entry.operation)

    # -- verification ----------------------------------------------------

    def verify(self, *, check_blobs: bool = False) -> ChainVerification:
        """Walk the chain from genesis and classify the first problem found."""
        entries, incomplete, parse_error = self._parse()
        total = len(entries)

        if parse_error is not None:
            return ChainVerification(
                status=ChainStatus.BROKEN,
                failure_kind=FailureKind.PARSE_ERROR,
                first_bad_seq=parse_error,
                verified_through=parse_error - 1 if parse_error else None,
                unverifiable_count=0,
                entry_count=total,
                explanation=(
                    f"Line {parse_error} of the chain is not valid JSON. "
                    f"Entries 0..{parse_error - 1} parsed; nothing after line "
                    f"{parse_error} could be read."
                ),
            )

        if not entries:
            return ChainVerification(
                status=ChainStatus.INCOMPLETE_TAIL if incomplete else ChainStatus.VALID,
                explanation=(
                    "The chain contains only a partial line from a write that "
                    "did not finish."
                    if incomplete
                    else "The chain is empty; nothing has been recorded yet."
                ),
                entry_count=0,
            )

        structural = self._structural_break(entries, incomplete, total)
        if structural is not None:
            return structural

        walk = self._walk(entries, incomplete, total, check_blobs=check_blobs)
        return walk

    def _structural_break(
        self, entries: list[LedgerEntry], incomplete: bool, total: int
    ) -> ChainVerification | None:
        """Classify a missing or repeated seq before walking the links.

        A deletion and a reorder both break the link at the same position, so
        the distinction has to come from the multiset of sequence numbers: a
        missing one means an entry was removed, a repeated one means an entry
        was duplicated, and a clean permutation means the file was reordered.
        """
        seen: dict[int, int] = {}
        for entry in entries:
            if entry.seq in seen:
                return ChainVerification(
                    status=ChainStatus.BROKEN,
                    failure_kind=FailureKind.SEQ_DUPLICATE,
                    first_bad_seq=entry.seq,
                    verified_through=entry.seq - 1 if entry.seq else None,
                    unverifiable_count=total - seen[entry.seq] - 1,
                    entry_count=total,
                    explanation=(
                        f"Sequence number {entry.seq} appears more than once. "
                        f"The chain is valid for 0..{entry.seq - 1}; every "
                        "entry from the duplicate onward is unverifiable."
                    ),
                )
            seen[entry.seq] = len(seen)

        highest = max(seen)
        missing = sorted(set(range(highest + 1)) - set(seen))
        if missing:
            first = missing[0]
            return ChainVerification(
                status=ChainStatus.BROKEN,
                failure_kind=FailureKind.SEQ_GAP,
                first_bad_seq=first,
                verified_through=first - 1 if first else None,
                unverifiable_count=sum(1 for s in seen if s > first),
                entry_count=total,
                explanation=(
                    f"Sequence number {first} is missing from the chain. "
                    f"Entries 0..{first - 1} are intact; "
                    f"{sum(1 for s in seen if s > first)} later entries "
                    "cannot be linked back to them."
                ),
            )
        _ = incomplete
        return None

    def _walk(
        self,
        entries: list[LedgerEntry],
        incomplete: bool,
        total: int,
        *,
        check_blobs: bool,
    ) -> ChainVerification:
        previous: LedgerEntry | None = None
        monotonic_by_boot: dict[str, int] = {}

        for entry in entries:
            problem = self._check_entry(
                entry, previous, monotonic_by_boot, check_blobs=check_blobs
            )
            if problem is not None:
                kind, detail = problem
                verified = previous.seq if previous is not None else None
                remaining = total - entries.index(entry) - 1
                return ChainVerification(
                    status=ChainStatus.BROKEN,
                    failure_kind=kind,
                    first_bad_seq=entry.seq,
                    verified_through=verified,
                    unverifiable_count=remaining,
                    entry_count=total,
                    explanation=(
                        f"Chain valid for 0..{verified if verified is not None else 0}"
                        f", broken at {entry.seq} ({kind.value}: {detail}), "
                        f"{remaining} further entries unverifiable."
                    ),
                )
            monotonic_by_boot[entry.boot_id] = entry.monotonic_ns
            previous = entry

        last = entries[-1].seq
        if incomplete:
            return ChainVerification(
                status=ChainStatus.INCOMPLETE_TAIL,
                verified_through=last,
                entry_count=total,
                explanation=(
                    f"Entries 0..{last} verify. The file ends in a partial line "
                    "from a write that did not finish, which is a crash, not "
                    "tampering."
                ),
            )
        return ChainVerification(
            status=ChainStatus.VALID,
            verified_through=last,
            entry_count=total,
            explanation=f"All {total} entries verify, 0..{last}.",
        )

    def _check_entry(
        self,
        entry: LedgerEntry,
        previous: LedgerEntry | None,
        monotonic_by_boot: dict[str, int],
        *,
        check_blobs: bool,
    ) -> tuple[FailureKind, str] | None:
        expected_prev = (
            GENESIS_PREV_HASH if previous is None else previous.entry_hash
        )
        if entry.prev_entry_hash != expected_prev:
            return (
                FailureKind.LINK_MISMATCH,
                f"prev_entry_hash is {entry.prev_entry_hash[:12]}..., expected "
                f"{expected_prev[:12]}...",
            )

        recomputed = entry_hash_of(_entry_to_record(entry))
        if recomputed != entry.entry_hash:
            return (
                FailureKind.HASH_MISMATCH,
                f"stored entry_hash {entry.entry_hash[:12]}... does not match "
                f"the recomputed {recomputed[:12]}...; the entry's contents "
                "were altered",
            )

        if previous is not None and entry.ts_utc < previous.ts_utc:
            return (
                FailureKind.TIME_REGRESSION,
                f"ts_utc {entry.ts_utc.isoformat()} precedes the previous "
                f"entry's {previous.ts_utc.isoformat()}",
            )

        last_monotonic = monotonic_by_boot.get(entry.boot_id)
        if last_monotonic is not None and entry.monotonic_ns < last_monotonic:
            return (
                FailureKind.TIME_REGRESSION,
                f"monotonic_ns {entry.monotonic_ns} is below {last_monotonic} "
                f"within boot {entry.boot_id}",
            )

        if check_blobs:
            for label, digest in (
                ("params", entry.params_hash),
                ("result", entry.result_hash),
            ):
                if not self.blobs.has(digest):
                    return (
                        FailureKind.MISSING_BLOB,
                        f"{label} blob {digest[:12]}... is not in the store, so "
                        "the recorded content cannot be produced",
                    )
        return None

    # -- merkle ----------------------------------------------------------

    def merkle_root(self, from_seq: int, to_seq: int) -> str:
        """Binary Merkle root over ``entry_hash`` for the inclusive range.

        On an odd number of nodes at any level the last node is duplicated and
        paired with itself. That choice changes the root, so it is stated here
        and in the report: a verifier reproducing the root must do the same.
        """
        entries = self.entries()
        available = {entry.seq: entry for entry in entries}
        if from_seq > to_seq or from_seq not in available or to_seq not in available:
            raise ValueError(
                f"range {from_seq}..{to_seq} is not covered by the chain "
                f"(0..{max(available) if available else 'empty'})"
            )
        level = [
            bytes.fromhex(available[seq].entry_hash)
            for seq in range(from_seq, to_seq + 1)
        ]
        while len(level) > 1:
            if len(level) % 2:
                level.append(level[-1])
            level = [
                hashlib.sha256(level[i] + level[i + 1]).digest()
                for i in range(0, len(level), 2)
            ]
        return level[0].hex()
