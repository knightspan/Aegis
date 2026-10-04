"""Two writers on one chain: both land, the chain verifies, nobody loses.

MANUAL_REPORT FINDING 2, BATCH5 FINDING 6. ``Ledger.append`` used to read the
chain head, build the next entry, compare the head against the one this
instance last saw, and only *then* take the file lock for the write itself. Two
defects followed from that ordering, and they are different defects:

* **The collision the walk hit was not a race at all.** The head comparison
  used the head this instance remembered from its *previous* append. A carve
  writes ``carve.start``, runs for a minute, and writes ``carve.complete``; a
  report generated anywhere in that minute moved the head, and the carve's
  second append refused. The window was the length of the job, not
  milliseconds, and the loser was the engine after its work was on disk.
* **The real race was not detected.** Two writers that read the same head
  before either wrote both built ``seq = N + 1`` on the same ``prev_entry_hash``
  and both passed the comparison, because both remembered the head they had
  just read. The lock then serialised two writes of a forked chain.

Both come from the lock covering a narrower critical section than the one that
needed it: read-head, build, write. These tests pin the widened section.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest
from core.errors import LedgerBusy, SanctumError
from core.ledger import chain as chain_mod
from core.ledger._filelock import file_lock
from core.ledger.chain import ChainStatus, Ledger


def make_ledger(root: Path) -> Ledger:
    return Ledger(root, tool_version="0.0.0-test", pubkey_fingerprint="AA:BB")


def test_a_long_lived_writer_appends_after_another_writer_moved_the_head(
    tmp_path: Path,
) -> None:
    """The walk's Break 2, reduced to three appends.

    The engine's instance writes its start entry, somebody else appends, and
    the engine's terminal entry must still land - linked to the real head, not
    to the one the engine remembered.
    """
    engine = make_ledger(tmp_path)
    engine.append(actor="engine", operation="carve.start", params={}, result={})

    make_ledger(tmp_path).append(
        actor="report", operation="report.generated", params={}, result={}
    )

    terminal = engine.append(
        actor="engine", operation="carve.complete", params={}, result={}
    )

    entries = make_ledger(tmp_path).entries()
    assert [entry.operation for entry in entries] == [
        "GENESIS",
        "carve.start",
        "report.generated",
        "carve.complete",
    ]
    assert terminal.prev_entry_hash == entries[2].entry_hash
    assert make_ledger(tmp_path).verify().status is ChainStatus.VALID


def test_writers_racing_on_threads_all_land_and_the_chain_verifies(
    tmp_path: Path,
) -> None:
    """Many writers, each with its own instance, as the API's routes have.

    A barrier releases them together so their head reads overlap. Before the
    fix this either raised in some threads or forked the chain with a
    duplicate sequence number.
    """
    make_ledger(tmp_path).append(actor="setup", operation="op", params={}, result={})

    writers, per_writer = 8, 25
    barrier = threading.Barrier(writers)
    errors: list[BaseException] = []

    def run(index: int) -> None:
        ledger = make_ledger(tmp_path)
        ledger.entries()
        barrier.wait()
        try:
            for step in range(per_writer):
                ledger.append(
                    actor=f"writer-{index}",
                    operation="op",
                    params={"writer": index, "step": step},
                    result={},
                )
        except BaseException as exc:  # noqa: BLE001 - reported by the assertion
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(writers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    verification = make_ledger(tmp_path).verify(check_blobs=True)
    assert verification.status is ChainStatus.VALID, verification.explanation
    assert verification.entry_count == 2 + writers * per_writer


def test_an_exhausted_retry_is_loud_names_the_lock_and_carries_remediation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A writer that cannot get the lock must fail, never drop the entry.

    A silently missing ledger entry is worse than a failed operation: the
    failure is visible and the gap is not.
    """
    monkeypatch.setattr(chain_mod, "APPEND_LOCK_ATTEMPTS", 3)
    monkeypatch.setattr(chain_mod, "APPEND_BACKOFF_INITIAL_SECONDS", 0.001)
    ledger = make_ledger(tmp_path)
    ledger.append(actor="setup", operation="op", params={}, result={})
    before = len(make_ledger(tmp_path).entries())

    with file_lock(ledger.store.lock_path):
        with pytest.raises(LedgerBusy) as excinfo:
            ledger.append(actor="loser", operation="op", params={}, result={})

    error = excinfo.value
    assert isinstance(error, SanctumError)
    assert "3 attempts" in error.message
    assert str(ledger.store.lock_path) in error.message
    assert "NOT recorded" in error.message
    assert error.remediation
    assert "lock" in error.remediation.lower()
    assert len(make_ledger(tmp_path).entries()) == before


def test_the_writer_gets_the_lock_once_the_holder_releases_it(
    tmp_path: Path,
) -> None:
    """Contention that ends inside the bound is retried, not reported."""
    ledger = make_ledger(tmp_path)
    ledger.append(actor="setup", operation="op", params={}, result={})

    held = threading.Event()
    release = threading.Event()

    def holder() -> None:
        with file_lock(ledger.store.lock_path):
            held.set()
            release.wait(timeout=5)

    thread = threading.Thread(target=holder)
    thread.start()
    held.wait(timeout=5)
    threading.Timer(0.2, release.set).start()

    entry = ledger.append(actor="waiter", operation="op", params={}, result={})
    thread.join()

    assert entry.seq == 2
    assert make_ledger(tmp_path).verify().status is ChainStatus.VALID


def test_retries_are_jittered_so_colliding_writers_stop_waking_together(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The backoff is a range, not a metronome.

    The lock is taken without blocking, so it has no queue and cannot be fair.
    With a fixed doubling backoff, writers that lose the same attempt wait the
    same time and collide again at the same instant; once they reach the cap
    they retry in lockstep for good, and one of them can lose all twenty
    attempts while the chain is being written normally by the others. The
    Windows runner failed that way. Each wait is therefore drawn from
    ``[floor x delay, delay]``.
    """
    slept: list[float] = []
    monkeypatch.setattr(chain_mod.time, "sleep", slept.append)
    monkeypatch.setattr(chain_mod, "APPEND_LOCK_ATTEMPTS", 12)
    ledger = make_ledger(tmp_path)
    ledger.append(actor="setup", operation="op", params={}, result={})

    with file_lock(ledger.store.lock_path):
        with pytest.raises(LedgerBusy):
            ledger.append(actor="loser", operation="op", params={}, result={})

    assert len(slept) == 11, "one wait between each pair of attempts"

    delay = chain_mod.APPEND_BACKOFF_INITIAL_SECONDS
    for pause in slept:
        assert chain_mod.APPEND_BACKOFF_JITTER_FLOOR * delay <= pause <= delay
        delay = min(delay * 2, chain_mod.APPEND_BACKOFF_CAP_SECONDS)

    at_the_cap = slept[-4:]
    assert len(set(at_the_cap)) > 1, (
        "waits at the cap are identical, so writers that collide there stay "
        f"in lockstep: {at_the_cap}"
    )
