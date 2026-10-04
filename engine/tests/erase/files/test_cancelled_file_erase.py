"""What a cancelled file erase leaves behind, and what the chain says about it.

MANUAL_REPORT FINDING 3. A file-erase batch ledgers its ten per-file phase
entries after every file has been processed, so a batch cancelled part-way used
to leave ``erase.file.inspect.batch`` and nothing else - while the files it had
already reached were overwritten, renamed and unlinked. That is worse than the
carve case: the operation is destructive, and the chain did not say which files
it destroyed.

``erase.file.cancelled`` names every target and which side of the cancellation
it fell on, and for each processed file which of the phases it reached. It
publishes no batch verdict: a cancelled batch is not an erasure certificate for
anything.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.erase.files import erase_paths
from core.erase.sink import ChainLedgerSink
from core.ledger.chain import ChainStatus, Ledger

from .conftest import drain, real_erase


def _chain(tmp_path: Path) -> Ledger:
    return Ledger(
        tmp_path / "ledger", tool_version="0.0.0-test", pubkey_fingerprint="AA:BB"
    )


def _targets(directory: Path, count: int = 5) -> list[Path]:
    paths = []
    for index in range(count):
        path = directory / f"target-{index}.bin"
        path.write_bytes(bytes([index + 1]) * 2048)
        paths.append(path)
    return paths


def _payload(chain: Ledger) -> dict[str, Any]:
    entry = next(e for e in chain.entries() if e.operation == "erase.file.cancelled")
    return chain.params_of(entry)


def _operations(chain: Ledger) -> list[str]:
    return [entry.operation for entry in chain.entries()]


def _cancel_after_files(
    paths: list[Path], chain: Ledger, files: int, **options: Any
) -> None:
    generator = erase_paths(
        paths,
        real_erase(**options),
        job_id="files-cancel",
        ledger=ChainLedgerSink(chain),
    )
    next(generator)  # the batch INSPECT record, before any file
    for _ in range(files):
        next(generator)
    generator.close()


def test_a_cancelled_batch_names_which_files_were_and_were_not_processed(
    real_fs_dir: Path, tmp_path: Path
) -> None:
    chain = _chain(tmp_path)
    paths = _targets(real_fs_dir)

    _cancel_after_files(paths, chain, 2, workers=1, recursive=False)

    assert "erase.file.cancelled" in _operations(chain)
    payload = _payload(chain)
    assert payload["job_id"] == "files-cancel"
    processed = [item["path"] for item in payload["processed"]]
    assert processed == [str(p) for p in paths[:2]]
    assert payload["not_processed"] == [str(p) for p in paths[2:]]
    assert payload["in_flight_unknown"] == []
    assert payload["phase_entries_recorded"] is False
    assert "CANCELLED" in payload["note"]

    # And the chain matches the disk.
    assert not paths[0].exists() and not paths[1].exists()
    assert all(path.exists() for path in paths[2:])


def test_each_processed_file_names_the_phases_it_reached(
    real_fs_dir: Path, tmp_path: Path
) -> None:
    chain = _chain(tmp_path)
    paths = _targets(real_fs_dir)

    _cancel_after_files(
        paths, chain, 1, workers=1, recursive=False, cleanse_metadata=False
    )

    first = _payload(chain)["processed"][0]
    assert first["ok"] is True
    for phase in ("INSPECT", "OVERWRITE", "TRUNCATE", "RENAME", "UNLINK"):
        assert phase in first["phases_reached"], first
    assert "CLEANSE" not in first["phases_reached"]


def test_a_cancelled_batch_writes_no_per_phase_results_and_no_verdict(
    real_fs_dir: Path, tmp_path: Path
) -> None:
    """Nothing in the chain reads as though the batch finished."""
    chain = _chain(tmp_path)

    _cancel_after_files(_targets(real_fs_dir), chain, 2, workers=1, recursive=False)

    results = [op for op in _operations(chain) if op.endswith(".result")]
    assert results == []
    payload = _payload(chain)
    for forbidden in ("succeeded", "failed", "passed", "highest_severity"):
        assert forbidden not in payload


def test_a_batch_cancelled_after_its_phase_entries_says_so(
    real_fs_dir: Path, tmp_path: Path
) -> None:
    """The last yield comes after the phase entries. Cancel there, and say that."""
    chain = _chain(tmp_path)
    paths = _targets(real_fs_dir, 3)

    _cancel_after_files(paths, chain, 4, workers=1, recursive=False)

    payload = _payload(chain)
    assert payload["phase_entries_recorded"] is True
    assert payload["not_processed"] == []
    assert len(payload["processed"]) == 3


def test_a_pooled_batch_reports_files_whose_state_is_unknown(
    real_fs_dir: Path, tmp_path: Path
) -> None:
    """Pool workers are terminated on cancel. Their files cannot be vouched for."""
    chain = _chain(tmp_path)
    paths = _targets(real_fs_dir, 12)

    _cancel_after_files(
        paths, chain, 1, workers=2, pool_threshold=2, recursive=False
    )

    payload = _payload(chain)
    named = (
        [item["path"] for item in payload["processed"]]
        + payload["not_processed"]
        + payload["in_flight_unknown"]
    )
    assert sorted(named) == sorted(str(p) for p in paths)
    assert payload["in_flight_unknown"] or payload["not_processed"] == []
    assert "pool" in payload["note"]


def test_the_chain_is_still_valid_after_a_cancelled_batch(
    real_fs_dir: Path, tmp_path: Path
) -> None:
    chain = _chain(tmp_path)

    _cancel_after_files(_targets(real_fs_dir), chain, 2, workers=1, recursive=False)

    verification = chain.verify(check_blobs=True)
    assert verification.status is ChainStatus.VALID, verification.explanation


def test_a_completed_batch_records_no_cancellation(
    real_fs_dir: Path, tmp_path: Path
) -> None:
    chain = _chain(tmp_path)

    drain(
        erase_paths(
            _targets(real_fs_dir),
            real_erase(workers=1, recursive=False),
            job_id="files-whole",
            ledger=ChainLedgerSink(chain),
        )
    )

    assert "erase.file.cancelled" not in _operations(chain)
