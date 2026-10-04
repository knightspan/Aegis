"""Who owns the files a root-written chain leaves behind.

The chain has two writers by design: the unprivileged API for carve, file erase
and report entries, the root helper for the phases of a drive erase. Every file
the stores create is ``0600``, deliberately, because operation parameters are
case material. A blob created by root is therefore unreadable to the operator -
and the operator is who generates the certificate that has to read it back.

Batch 4 found this by reading the file modes and papered over it with a manual
``sudo chown -R`` in the runbook. These tests pin the mechanism that replaced
it: when the writing process is root **and** was told an operator uid at
startup, each file it creates is handed to that operator, mode unchanged.

The decision logic is tested with ``geteuid`` and ``chown`` substituted, because
this suite does not run as root and must not need to. What is asserted is the
rule - who gets handed what, and under exactly which conditions - not the
kernel's implementation of chown.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest
from core.ledger._ownership import hand_over, hand_over_fd, makedirs_owned
from core.ledger.chain import ChainStatus, Ledger

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason=(
        "POSIX file ownership: core.ledger._ownership is a documented no-op "
        "on Windows, where the model is ACLs rather than uid/gid"
    ),
)


class RecordingChown:
    """Stands in for ``os.chown``/``os.fchown``, remembering every call."""

    def __init__(self) -> None:
        self.calls: list[tuple[Any, int, int, bool]] = []

    def chown(
        self, path: Any, uid: int, gid: int, *, follow_symlinks: bool = True
    ) -> None:
        self.calls.append((path, uid, gid, follow_symlinks))

    def fchown(self, fd: int, uid: int, gid: int) -> None:
        self.calls.append((fd, uid, gid, False))


@pytest.fixture
def as_root(monkeypatch: pytest.MonkeyPatch) -> RecordingChown:
    """Pretend to be root, and record what would have been chowned."""
    recorder = RecordingChown()
    monkeypatch.setattr("core.ledger._ownership.os.geteuid", lambda: 0)
    monkeypatch.setattr("core.ledger._ownership.os.chown", recorder.chown)
    monkeypatch.setattr("core.ledger._ownership.os.fchown", recorder.fchown)
    return recorder


# --------------------------------------------------------------------------
# The rule
# --------------------------------------------------------------------------


def test_root_hands_a_created_file_to_the_operator(
    as_root: RecordingChown, tmp_path: Path
) -> None:
    target = tmp_path / "blob"
    target.write_bytes(b"x")

    hand_over(target, 1000)

    assert as_root.calls == [(target, 1000, -1, False)]


def test_the_handover_never_follows_a_symlink(
    as_root: RecordingChown, tmp_path: Path
) -> None:
    """As root, following a link would move the change onto another file.

    A link planted in the ledger directory pointing at ``/etc/shadow`` must not
    turn a routine ledger write into a change of that file's owner.
    """
    target = tmp_path / "blob"
    target.write_bytes(b"x")

    hand_over(target, 1000)
    hand_over_fd(7, 1000)

    assert all(follow is False for _, _, _, follow in as_root.calls)


def test_an_unprivileged_writer_hands_over_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The API already creates files the operator owns; there is nothing to do."""
    recorder = RecordingChown()
    monkeypatch.setattr("core.ledger._ownership.os.geteuid", lambda: 1000)
    monkeypatch.setattr("core.ledger._ownership.os.chown", recorder.chown)

    hand_over(tmp_path, 1000)

    assert recorder.calls == []


def test_root_with_no_operator_uid_hands_over_nothing(
    as_root: RecordingChown, tmp_path: Path
) -> None:
    """No uid means the daemon is unconfined - the in-process helper.

    Handing a file to a uid nobody named is a guess, and a guess about
    ownership made by a root process is the thing this module exists not to do.
    """
    hand_over(tmp_path, None)
    hand_over_fd(7, None)

    assert as_root.calls == []


def test_a_failed_handover_is_logged_and_not_raised(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An erase must not abort because a chown failed.

    The trade is a readable audit trail against no audit trail at all, and a
    wipe that stopped halfway through because of an ownership problem would
    leave a partially sanitized device to fix a cosmetic one.
    """

    def refuse(*args: Any, **kwargs: Any) -> None:
        raise PermissionError("nope")

    monkeypatch.setattr("core.ledger._ownership.os.geteuid", lambda: 0)
    monkeypatch.setattr("core.ledger._ownership.os.chown", refuse)

    hand_over(tmp_path, 1000)  # must not raise


def test_makedirs_owned_hands_over_only_what_it_created(
    as_root: RecordingChown, tmp_path: Path
) -> None:
    """Pointing the ledger at an existing tree must not re-own that tree."""
    existing = tmp_path / "state"
    existing.mkdir()

    makedirs_owned(existing / "ledger" / "blobs", 1000)

    handed = [path for path, *_ in as_root.calls]
    assert existing not in handed
    assert existing / "ledger" in handed
    assert existing / "ledger" / "blobs" in handed


def test_makedirs_owned_is_a_noop_for_a_directory_that_exists(
    as_root: RecordingChown, tmp_path: Path
) -> None:
    makedirs_owned(tmp_path, 1000)

    assert as_root.calls == []


# --------------------------------------------------------------------------
# Wiring: the uid reaches every file the chain creates
# --------------------------------------------------------------------------


def test_the_ledger_passes_the_owner_uid_to_both_of_its_stores(
    tmp_path: Path,
) -> None:
    chain = Ledger(
        tmp_path / "ledger",
        tool_version="0.0.0-test",
        pubkey_fingerprint="AA:BB",
        owner_uid=1000,
    )

    assert chain.owner_uid == 1000
    assert chain.store.owner_uid == 1000
    assert chain.blobs.owner_uid == 1000


def test_a_root_written_chain_hands_over_its_chain_file_lock_and_blobs(
    as_root: RecordingChown, tmp_path: Path
) -> None:
    """Every artefact a wipe leaves behind, not just the obvious one.

    The chain file is the obvious one. The *lock* file matters just as much and
    is easy to miss: a root-owned ``0600`` lock cannot be opened ``O_RDWR`` by
    the operator at all, so the file that exists to keep the chain single-writer
    would be the thing that locks the operator out of their own audit trail.
    """
    chain = Ledger(
        tmp_path / "ledger",
        tool_version="0.0.0-test",
        pubkey_fingerprint="AA:BB",
        owner_uid=1000,
    )
    chain.append(
        actor="helper", operation="erase.erase.checkpoint", params={}, result={}
    )

    assert as_root.calls, "a root writer handed over nothing at all"
    assert all(uid == 1000 for _, uid, _, _ in as_root.calls)
    # Descriptors for the chain and the blobs, paths for the directories and
    # the lock file. Both kinds must be present or something went unhanded.
    assert any(isinstance(first, int) for first, *_ in as_root.calls)
    assert any(isinstance(first, Path) for first, *_ in as_root.calls)


def test_ownership_changes_nothing_about_the_chain_itself(tmp_path: Path) -> None:
    """The audit properties are unchanged; only the owner of the bytes moves."""
    chain = Ledger(
        tmp_path / "ledger",
        tool_version="0.0.0-test",
        pubkey_fingerprint="AA:BB",
        owner_uid=os.getuid(),
    )
    chain.append(
        actor="helper", operation="erase.erase.complete", params={"a": 1}, result={}
    )
    chain.append(
        actor="api", operation="report.generated", params={"b": 2}, result={}
    )

    verification = chain.verify(check_blobs=True)
    assert verification.status is ChainStatus.VALID, verification.explanation
    assert len(chain.entries()) == 3  # genesis plus the two


def test_the_files_are_still_owner_only(tmp_path: Path) -> None:
    """Handing a blob over must not widen who can read it.

    Operation parameters are case material. The fix for "the operator cannot
    read this" is not "everybody can read this".
    """
    import stat

    chain = Ledger(
        tmp_path / "ledger",
        tool_version="0.0.0-test",
        pubkey_fingerprint="AA:BB",
        owner_uid=os.getuid(),
    )
    chain.append(
        actor="helper", operation="erase.erase.complete", params={"a": 1}, result={}
    )

    blob_root = tmp_path / "ledger" / "blobs"
    blobs = [path for path in blob_root.rglob("*") if path.is_file()]
    assert blobs
    for path in [chain.store.path, *blobs]:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, path
