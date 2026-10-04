"""Who owns the files the ledger creates.

The chain has two writers by design. The unprivileged API appends carve, file
erase and report entries; the root helper appends the phases of a drive erase,
because the engine that produces them is the one thing that must run as root.
Both write to the *same* chain, which is what makes it one audit trail rather
than two.

That is only workable if the artefacts are readable by both. Every file the
stores create is mode ``0600`` - deliberately, because operation parameters are
case material and must not be world-readable - so a blob created by root is
unreadable to the operator, and the operator is who generates the report that
has to read it back. Before this module existed, a helper-run wipe produced a
chain the API could not turn into a certificate: ``POST /reports/{id}`` failed
on a permission error against a blob path, and the demo carried a manual
``sudo chown -R`` to paper over it.

So: **when the writing process is root and it has been told which uid the
operator is, the file it just created is handed to that operator.** Mode stays
``0600``; only the owner changes.

Two things this deliberately is not:

* It is **not** a privilege escalation. The uid is fixed when the daemon starts
  (``python -m helper --operator-uid``) and never comes from a request, and the
  path is one the store itself just created under a root the daemon confined at
  startup. Nothing here walks a tree, and nothing here follows a symlink -
  ``follow_symlinks=False`` on every call, so a link planted in the ledger
  directory cannot redirect the change onto another file.
* It does **not** weaken the chain. Tamper-evidence comes from entry *N*
  containing the SHA-256 of *N-1*, not from file ownership: the operator could
  already append to this chain, because the API writes to it for every job that
  does not go through the helper. Handing over a blob gives the operator no
  capability they did not already have, and hiding one from them only breaks
  the report.

A failure to hand over is logged and swallowed. The alternative is aborting an
erase because a chown failed, which trades a readable audit trail for no audit
trail at all.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import structlog

__all__ = ["hand_over", "hand_over_fd", "makedirs_owned"]

logger = structlog.get_logger(__name__)


def _root_handing_over(owner_uid: int | None) -> bool:
    """Whether this process both can and should change ownership."""
    if owner_uid is None:
        return False
    if sys.platform == "win32":  # pragma: no cover - POSIX ownership only
        return False
    return os.geteuid() == 0


def hand_over(path: Path, owner_uid: int | None) -> None:
    """Give ``path`` to ``owner_uid``, if this process is root and was told one.

    A no-op for an unprivileged writer, which already creates files the
    operator owns.
    """
    if not _root_handing_over(owner_uid):
        return
    try:
        # Never follows a symlink: as root, following one would let a link
        # planted in the ledger directory move the ownership change onto a file
        # outside it.
        os.chown(path, owner_uid, -1, follow_symlinks=False)  # type: ignore[arg-type]
    except OSError as exc:
        logger.warning("ledger_handover_failed", path=str(path), error=str(exc))


def hand_over_fd(fd: int, owner_uid: int | None) -> None:
    """Give an already-open file to ``owner_uid``.

    Used where the store still holds the descriptor it created the file with,
    which is both cheaper and safer than naming the path a second time: there
    is no window in which the name could come to mean a different file.
    """
    if not _root_handing_over(owner_uid):
        return
    try:
        os.fchown(fd, owner_uid, -1)  # type: ignore[arg-type]
    except OSError as exc:
        logger.warning("ledger_handover_failed", fd=fd, error=str(exc))


def makedirs_owned(path: Path, owner_uid: int | None) -> None:
    """``mkdir -p`` for ``path``, handing over every directory it had to create.

    Only the components this call creates are handed over. A directory that was
    already there keeps whatever owner it had, so pointing the ledger at an
    existing tree never silently re-owns it.
    """
    if path.is_dir():
        return
    missing: list[Path] = []
    probe = path
    while not probe.exists():
        missing.append(probe)
        if probe.parent == probe:
            break
        probe = probe.parent
    path.mkdir(parents=True, exist_ok=True)
    for created in reversed(missing):
        hand_over(created, owner_uid)
