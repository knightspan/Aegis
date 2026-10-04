"""What a cancelled wipe leaves behind, and what the chain says about it.

Cancellation is now real: the UI's button closes the job generator, the API
closes the helper stream, the helper closes the engine's generator, and the
engine stops at its next yield. Every step of that is only defensible if the
last one records what it did, because a cancelled erase leaves a device in a
state no examiner can infer from the outside - **partially sanitized**, with
some of its data overwritten and the rest still there.

An erase that stopped and said nothing would be indistinguishable in the ledger
from one that never ran. That is the failure this file exists to prevent.

Linux only and no root: the medium is a regular file, which is all
``_overwrite`` needs. ``device_geometry`` is stubbed because BLKGETSIZE64 only
answers for a block device.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from core.models import ErasePhase

from .conftest import make_caps, make_device, make_job

if sys.platform != "linux":  # pragma: no cover - platform gate
    pytest.skip("core.erase.drive is Linux-only", allow_module_level=True)

from core.erase import drive  # noqa: E402
from core.erase.drive import ChainLedgerSink, Geometry, execute  # noqa: E402
from core.ledger.chain import Ledger  # noqa: E402

MIB = 1024 * 1024
SECTOR = 512
DEVICE_BYTES = 8 * MIB


def run_until_erase_then_cancel(
    tmp_path: Path, medium: Path
) -> tuple[Ledger, list[Any]]:
    """Drive a real overwrite as far as its first ERASE record, then close it."""
    device = make_device(path=str(medium), serial="SYN-0001", by_id_path=None)
    job = make_job(device)
    chain = Ledger(
        tmp_path / "ledger", tool_version="0.0.0-test", pubkey_fingerprint="AA:BB"
    )
    geometry = Geometry(
        size_bytes=DEVICE_BYTES, logical_block_size=SECTOR, physical_block_size=SECTOR
    )
    progress: list[Any] = []
    with (
        mock.patch.object(drive, "device_geometry", return_value=geometry),
        mock.patch.object(drive.guard, "assert_erasable"),
        mock.patch.object(drive, "_reread_serial"),
    ):
        generator = execute(job, make_caps(), io=None, ledger=ChainLedgerSink(chain))
        for record in generator:
            progress.append(record)
            if record.phase == ErasePhase.ERASE.value and record.bytes_done > 0:
                break
        # Exactly what api.jobs.JobRegistry.cancel does, and what the helper
        # then does to the engine: ask it to stop at its next yield.
        generator.close()
    return chain, progress


def erase_operations(chain: Ledger) -> list[str]:
    return [
        entry.operation
        for entry in chain.entries()
        if entry.operation.startswith("erase.")
    ]


def cancellation_payload(chain: Ledger) -> dict[str, Any]:
    """The stored payload of the cancellation entry, read back through the store.

    Through ``params_of`` rather than off the entry: the chain records a blob
    *hash*, and reading the blob is what proves the sentence an operator will be
    shown is the one the hash commits to.
    """
    entry = next(
        item for item in chain.entries() if item.operation == "erase.erase.cancelled"
    )
    return chain.params_of(entry)


def test_a_cancelled_erase_records_that_the_device_is_partly_sanitized(
    tmp_path: Path, backing_file: Path
) -> None:
    """The entry a later reader needs, written before the exception continues."""
    chain, progress = run_until_erase_then_cancel(tmp_path, backing_file)

    operations = erase_operations(chain)
    assert "erase.erase.cancelled" in operations, (
        f"a cancelled wipe wrote no cancellation entry; chain holds {operations}. "
        "A partially sanitized device with no record of it is the worst outcome "
        "in this file."
    )
    assert "erase.erase.complete" not in operations, (
        "a cancelled erase must never record completion"
    )

    payload = cancellation_payload(chain)
    note = str(payload["note"])
    assert "PARTIALLY SANITIZED" in note
    assert "no certificate" in note
    assert payload["job_id"] == "job-0001"


def test_a_cancelled_erase_neither_verifies_nor_claims_a_level(
    tmp_path: Path, backing_file: Path
) -> None:
    """Nothing downstream of the ERASE phase may run, or the result is a lie.

    A VERIFY entry after a cancellation would say a sample of the medium held
    the pattern - true of the part that was written, and evidence of nothing
    about the part that was not.
    """
    chain, _ = run_until_erase_then_cancel(tmp_path, backing_file)

    operations = erase_operations(chain)
    assert not any(item.startswith("erase.verify.") for item in operations), operations
    assert not any(item.startswith("erase.report.") for item in operations), operations


def test_the_cancellation_entry_says_whether_the_job_can_be_resumed(
    tmp_path: Path, backing_file: Path
) -> None:
    """A host-pattern overwrite has checkpoints; a firmware erase has none.

    The distinction matters to the operator standing in front of the drive: a
    software overwrite can be picked up from its last checkpoint, and a
    firmware erase that this tool merely stopped *watching* is still running
    inside the drive.
    """
    chain, _ = run_until_erase_then_cancel(tmp_path, backing_file)

    payload = cancellation_payload(chain)
    assert payload["resumable"] is True
    assert payload["method"]


def test_the_chain_is_still_valid_after_a_cancellation(
    tmp_path: Path, backing_file: Path
) -> None:
    """Writing the entry during generator teardown must not break the chain."""
    chain, _ = run_until_erase_then_cancel(tmp_path, backing_file)

    status = chain.verify()
    assert status.status.value == "VALID", status.explanation
