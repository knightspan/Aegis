"""Append-only persistence for the audit ledger.

Two stores, deliberately separate:

:class:`BlobStore`
    Content-addressed. Full operation parameters and results are large and
    variable, so they live here under their own SHA-256 and the chain holds only
    the digest. That keeps every ledger entry a fixed shape while still proving
    exactly what was recorded: change a blob and its hash stops matching the
    entry that names it.

:class:`LedgerStore`
    The chain itself, one canonical JSON object per line. Opened
    ``O_APPEND | O_CREAT | O_WRONLY``, written in a single ``os.write``, then
    ``fsync``ed; the containing directory is ``fsync``ed when the file is
    created. Nothing here seeks, truncates or rewrites - any code path that
    opens the chain for writing at an offset is a bug.

**Crash is not tampering.** A process killed mid-append leaves a partial final
line. :meth:`LedgerStore.read` reports that as ``incomplete_tail`` and keeps the
complete lines, so verification can say "the chain is intact and the last write
did not finish" instead of accusing someone of forgery. Confusing the two in a
forensic tool is a credibility problem, so they are separate states everywhere.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import structlog

from core.ledger._filelock import file_lock
from core.ledger._ownership import hand_over_fd, makedirs_owned

__all__ = ["BlobStore", "LedgerStore", "ChainRead", "CHAIN_FILENAME"]

logger = structlog.get_logger(__name__)

CHAIN_FILENAME = "chain.jsonl"
_LOCK_FILENAME = ".chain.lock"
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
_NEWLINE = b"\n"
#: Windows opens in text mode by default, which would translate every "\n" the
#: chain writes into "\r\n" and change the bytes that were hashed.
_BINARY = getattr(os, "O_BINARY", 0)


def _require_hex(digest: str) -> str:
    if not _HEX64.match(digest):
        raise ValueError(
            f"{digest!r} is not a 64-character lowercase hex SHA-256 digest"
        )
    return digest


def _fsync_dir(path: Path) -> None:
    """Flush a directory entry so a newly created file survives a power cut."""
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return  # Windows cannot open a directory this way; nothing to flush.
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _replace_content_addressed(staging: Path, target: Path, payload: bytes) -> None:
    """``os.replace`` that tolerates Windows' transient sharing violations.

    AEGIS integration (2026-10-03). On Windows, a rename onto a file another
    process has open (antivirus, the search indexer, a second writer of the same
    blob) fails with ERROR_ACCESS_DENIED. A blob is content-addressed, so a
    target that already holds exactly these bytes is the correct outcome and the
    staging copy is discarded; otherwise the rename is retried briefly and the
    last error is raised. Nothing is ever accepted that does not match.
    """
    import time as _time

    last: OSError | None = None
    for attempt in range(6):
        try:
            os.replace(staging, target)
            return
        except PermissionError as exc:
            last = exc
            try:
                if target.exists() and target.read_bytes() == payload:
                    staging.unlink(missing_ok=True)
                    return
            except OSError:
                pass
            _time.sleep(0.05 * (attempt + 1))
    assert last is not None
    raise last


class BlobStore:
    """Content-addressed store for operation params and results.

    ``owner_uid`` is the operator this store hands new files to when the
    writing process is root. See :mod:`core.ledger._ownership` for why the
    chain has two writers and what that costs if the artefacts are not
    readable by both.
    """

    def __init__(self, root: Path | str, *, owner_uid: int | None = None) -> None:
        self.root = Path(root)
        self.blobs = self.root / "blobs"
        self.owner_uid = owner_uid

    def _path_for(self, digest: str) -> Path:
        return self.blobs / digest[:2] / digest

    def put(self, payload: bytes) -> str:
        """Store ``payload`` and return its SHA-256 hex digest. Idempotent."""
        digest = hashlib.sha256(payload).hexdigest()
        target = self._path_for(digest)
        if target.exists():
            return digest
        makedirs_owned(target.parent, self.owner_uid)
        staging = target.with_name(f".{digest}.partial")
        fd = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _BINARY, 0o600)
        try:
            os.write(fd, payload)
            os.fsync(fd)
            # Handed over on the descriptor this call created, before the
            # rename: os.replace preserves ownership, so the blob arrives at
            # its final name already belonging to the operator.
            hand_over_fd(fd, self.owner_uid)
        finally:
            os.close(fd)
        _replace_content_addressed(staging, target, payload)
        _fsync_dir(target.parent)
        return digest

    def get(self, digest: str) -> bytes | None:
        """Return the blob for ``digest``, or ``None`` if it is not stored."""
        path = self._path_for(_require_hex(digest))
        try:
            return path.read_bytes()
        except OSError:
            return None

    def has(self, digest: str) -> bool:
        """Whether ``digest`` is present."""
        return self._path_for(_require_hex(digest)).exists()


@dataclass(frozen=True)
class ChainRead:
    """What one read of the chain file found."""

    lines: list[bytes]
    incomplete_tail: bool
    partial_tail: bytes | None = None


class LedgerStore:
    """The append-only chain file.

    ``owner_uid`` is the operator this store hands the chain, its lock and any
    directory it creates to when the writing process is root.
    """

    def __init__(self, root: Path | str, *, owner_uid: int | None = None) -> None:
        self.root = Path(root)
        self.directory = self.root / "ledger"
        self.path = self.directory / CHAIN_FILENAME
        self.lock_path = self.directory / _LOCK_FILENAME
        self.owner_uid = owner_uid

    def read(self) -> ChainRead:
        """Read every complete line, reporting a partial final line separately."""
        try:
            raw = self.path.read_bytes()
        except OSError:
            return ChainRead(lines=[], incomplete_tail=False)
        if not raw:
            return ChainRead(lines=[], incomplete_tail=False)

        complete, partial = raw, b""
        if not raw.endswith(_NEWLINE):
            cut = raw.rfind(_NEWLINE)
            if cut == -1:
                complete, partial = b"", raw
            else:
                complete, partial = raw[: cut + 1], raw[cut + 1 :]

        lines = complete.split(_NEWLINE)[:-1] if complete else []
        return ChainRead(
            lines=lines,
            incomplete_tail=bool(partial),
            partial_tail=partial or None,
        )

    @contextmanager
    def writer_lock(self, *, blocking: bool = True) -> Iterator[None]:
        """Hold the chain's single-writer lock for the duration of the block.

        A writer that builds an entry has to hold this across reading the head,
        building the entry that links to it, and writing it. Holding it for the
        write alone serialises two writes of a forked chain.

        Raises:
            LockUnavailable: ``blocking`` is false and another writer holds it.
        """
        makedirs_owned(self.directory, self.owner_uid)
        with file_lock(self.lock_path, blocking=blocking, owner_uid=self.owner_uid):
            yield

    def append(self, payload: bytes) -> None:
        """Append one canonical line under the writer lock.

        See :meth:`append_locked` for what is refused.
        """
        with self.writer_lock():
            self.append_locked(payload)

    def append_locked(self, payload: bytes) -> None:
        """Append one canonical line. The caller must hold :meth:`writer_lock`.

        Raises:
            ValueError: ``payload`` contains a newline, which would split one
                logical entry across two lines.
            RuntimeError: The chain ends in a partial line. Appending past it
                would bury evidence of the interrupted write.
        """
        if _NEWLINE in payload:
            raise ValueError(
                "a ledger payload may not contain a newline; canonical JSON "
                "escapes them, so this indicates a caller bypassed canon"
            )
        existing = self.read()
        if existing.incomplete_tail:
            raise RuntimeError(
                f"{self.path} ends in an incomplete line of "
                f"{len(existing.partial_tail or b'')} bytes, left by a write "
                "that did not finish. Refusing to append past it. "
                "Recover by archiving the truncated file for the record, "
                "then starting a new chain; do not edit it in place."
            )
        is_new = not self.path.exists()
        fd = os.open(
            self.path,
            os.O_APPEND | os.O_CREAT | os.O_WRONLY | _BINARY,
            0o600,
        )
        try:
            os.write(fd, payload + _NEWLINE)
            os.fsync(fd)
            if is_new:
                # Only when this call created it. Re-owning a chain that
                # was already there would let a root append change who owns
                # an existing audit trail, which is not this module's
                # business.
                hand_over_fd(fd, self.owner_uid)
        finally:
            os.close(fd)
        if is_new:
            _fsync_dir(self.directory)
        logger.debug("ledger_line_appended", path=str(self.path), size=len(payload))
