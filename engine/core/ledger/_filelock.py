"""Single-writer advisory lock, hiding the POSIX/Windows split.

``fcntl.flock`` and ``msvcrt.locking`` have different semantics and different
signatures. Everything above this module works with one context manager and
never learns which platform it is on.

The lock lives in its own file next to the resource, never on the chain file
itself: locking the chain would mean opening it for writing at an offset, and
nothing is allowed to do that.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from core.ledger._ownership import hand_over_fd, makedirs_owned

__all__ = ["file_lock", "LockUnavailable"]

_LOCK_BYTES = 1


class LockUnavailable(RuntimeError):
    """Another process or thread holds the writer lock."""


@contextmanager
def file_lock(
    path: Path, *, blocking: bool = True, owner_uid: int | None = None
) -> Iterator[None]:
    """Hold an exclusive advisory lock on ``path`` for the duration of the block.

    Args:
        path: Lock file. Created if absent; never truncated.
        blocking: Wait for the lock when true, raise
            :class:`LockUnavailable` immediately when false.
        owner_uid: Operator to hand a newly created lock file to when this
            process is root. Without it a root writer leaves a ``0600``
            root-owned lock file, and the *next* writer - the unprivileged API -
            cannot open it for writing at all, so the lock that exists to keep
            the chain single-writer becomes the thing that locks the operator
            out of their own audit trail. See :mod:`core.ledger._ownership`.
    """
    makedirs_owned(path.parent, owner_uid)
    is_new = not path.exists()
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    if is_new:
        hand_over_fd(fd, owner_uid)
    try:
        _acquire(fd, blocking=blocking)
        try:
            yield
        finally:
            _release(fd)
    finally:
        os.close(fd)


if sys.platform == "win32":  # pragma: no cover - platform split

    def _acquire(fd: int, *, blocking: bool) -> None:
        import msvcrt

        mode = msvcrt.LK_LOCK if blocking else msvcrt.LK_NBLCK
        try:
            msvcrt.locking(fd, mode, _LOCK_BYTES)
        except OSError as exc:
            raise LockUnavailable("another writer holds the ledger lock") from exc

    def _release(fd: int) -> None:
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_UNLCK, _LOCK_BYTES)
        except OSError:
            # Already released, or never held. Nothing useful to do here.
            pass

else:

    def _acquire(fd: int, *, blocking: bool) -> None:
        import fcntl

        flags = fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB
        try:
            fcntl.flock(fd, flags)
        except OSError as exc:
            raise LockUnavailable("another writer holds the ledger lock") from exc

    def _release(fd: int) -> None:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_UN)
