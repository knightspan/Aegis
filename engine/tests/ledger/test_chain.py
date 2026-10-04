"""Hash-chain construction and verification.

Every tampering mode gets its own classification. Crash and attack must never
be reported as the same thing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from core.ledger.canon import canonical_bytes
from core.ledger.chain import (
    GENESIS_OPERATION,
    GENESIS_PREV_HASH,
    ChainStatus,
    FailureKind,
    Ledger,
)
from core.ledger.store import LedgerStore

CHAIN_LEN = 200


def make_ledger(root: Path) -> Ledger:
    return Ledger(
        root,
        tool_version="0.0.0-test",
        pubkey_fingerprint="AA:BB:CC",
    )


@pytest.fixture
def chain(tmp_path: Path) -> Ledger:
    ledger = make_ledger(tmp_path)
    for index in range(CHAIN_LEN - 1):  # genesis takes seq 0
        ledger.append(
            actor="tester",
            operation="erase.phase",
            params={"index": index, "path": "/dev/sdz"},
            result={"ok": True, "bytes": index * 4096},
        )
    return ledger


def chain_path(root: Path) -> Path:
    return LedgerStore(root).path


def read_lines(root: Path) -> list[bytes]:
    return chain_path(root).read_bytes().rstrip(b"\n").split(b"\n")


def write_lines(root: Path, lines: list[bytes]) -> None:
    chain_path(root).write_bytes(b"\n".join(lines) + b"\n")


# --------------------------------------------------------------------------
# Genesis
# --------------------------------------------------------------------------


def test_genesis_is_written_automatically_on_first_append(tmp_path: Path) -> None:
    ledger = make_ledger(tmp_path)
    ledger.append(actor="a", operation="op", params={}, result={})
    entries = ledger.entries()
    assert entries[0].seq == 0
    assert entries[0].operation == GENESIS_OPERATION
    assert entries[0].prev_entry_hash == GENESIS_PREV_HASH


def test_genesis_records_tool_canon_and_key_fingerprint(tmp_path: Path) -> None:
    ledger = make_ledger(tmp_path)
    ledger.append(actor="a", operation="op", params={}, result={})
    params = ledger.params_of(ledger.entries()[0])
    assert params["tool_version"] == "0.0.0-test"
    assert params["pubkey_fingerprint"] == "AA:BB:CC"
    assert params["canon_version"]


def test_seq_starts_at_zero_and_is_contiguous(chain: Ledger) -> None:
    assert [entry.seq for entry in chain.entries()] == list(range(CHAIN_LEN))


# --------------------------------------------------------------------------
# Spec test 3: a clean chain verifies
# --------------------------------------------------------------------------


def test_two_hundred_entry_chain_verifies_valid(chain: Ledger) -> None:
    report = chain.verify()
    assert report.status is ChainStatus.VALID
    assert report.failure_kind is None
    assert report.first_bad_seq is None
    assert report.verified_through == CHAIN_LEN - 1


def test_params_and_results_round_trip_through_the_blob_store(
    chain: Ledger,
) -> None:
    entry = chain.entries()[5]
    assert chain.params_of(entry)["index"] == 4
    assert chain.result_of(entry)["ok"] is True


# --------------------------------------------------------------------------
# Spec test 4: mutate one byte
# --------------------------------------------------------------------------


def test_mutating_entry_137_params_hash_is_a_hash_mismatch(
    chain: Ledger, tmp_path: Path
) -> None:
    lines = read_lines(tmp_path)
    record = json.loads(lines[137])
    original = record["params_hash"]
    record["params_hash"] = ("0" if original[0] != "0" else "1") + original[1:]
    lines[137] = canonical_bytes(record)
    write_lines(tmp_path, lines)

    report = make_ledger(tmp_path).verify()
    assert report.status is ChainStatus.BROKEN
    assert report.first_bad_seq == 137
    assert report.failure_kind is FailureKind.HASH_MISMATCH
    assert "137" in report.explanation


def test_a_break_reports_what_is_still_trustworthy(
    chain: Ledger, tmp_path: Path
) -> None:
    lines = read_lines(tmp_path)
    record = json.loads(lines[137])
    record["actor"] = "impostor"
    lines[137] = canonical_bytes(record)
    write_lines(tmp_path, lines)

    report = make_ledger(tmp_path).verify()
    assert report.verified_through == 136
    assert report.unverifiable_count == CHAIN_LEN - 138
    assert "0..136" in report.explanation


# --------------------------------------------------------------------------
# Spec tests 5, 6, 7: structural tampering
# --------------------------------------------------------------------------


def test_deleting_entry_137_is_a_seq_gap(chain: Ledger, tmp_path: Path) -> None:
    lines = read_lines(tmp_path)
    del lines[137]
    write_lines(tmp_path, lines)

    report = make_ledger(tmp_path).verify()
    assert report.status is ChainStatus.BROKEN
    assert report.failure_kind is FailureKind.SEQ_GAP
    assert report.first_bad_seq == 137


def test_duplicating_entry_137_is_a_seq_duplicate(
    chain: Ledger, tmp_path: Path
) -> None:
    lines = read_lines(tmp_path)
    lines.insert(138, lines[137])
    write_lines(tmp_path, lines)

    report = make_ledger(tmp_path).verify()
    assert report.status is ChainStatus.BROKEN
    assert report.failure_kind is FailureKind.SEQ_DUPLICATE
    assert report.first_bad_seq == 137


def test_reordering_two_entries_is_a_link_mismatch(
    chain: Ledger, tmp_path: Path
) -> None:
    lines = read_lines(tmp_path)
    lines[137], lines[138] = lines[138], lines[137]
    write_lines(tmp_path, lines)

    report = make_ledger(tmp_path).verify()
    assert report.status is ChainStatus.BROKEN
    assert report.failure_kind is FailureKind.LINK_MISMATCH


def test_unparseable_line_is_a_parse_error(chain: Ledger, tmp_path: Path) -> None:
    lines = read_lines(tmp_path)
    lines[50] = b'{"seq": 50, "broken"'
    write_lines(tmp_path, lines)

    report = make_ledger(tmp_path).verify()
    assert report.failure_kind is FailureKind.PARSE_ERROR
    assert report.status is ChainStatus.BROKEN


# --------------------------------------------------------------------------
# Spec test 8 and 9: a crash is not an attack
# --------------------------------------------------------------------------


def test_truncated_final_line_is_incomplete_tail_not_broken(
    chain: Ledger, tmp_path: Path
) -> None:
    path = chain_path(tmp_path)
    path.write_bytes(path.read_bytes()[:-20])

    report = make_ledger(tmp_path).verify()
    assert report.status is ChainStatus.INCOMPLETE_TAIL
    assert report.failure_kind is None
    assert "did not finish" in report.explanation or "crash" in report.explanation


def test_incomplete_tail_still_verifies_the_complete_prefix(
    chain: Ledger, tmp_path: Path
) -> None:
    path = chain_path(tmp_path)
    path.write_bytes(path.read_bytes()[:-20])
    report = make_ledger(tmp_path).verify()
    assert report.verified_through == CHAIN_LEN - 2


def test_appending_after_an_incomplete_tail_is_refused_with_remediation(
    chain: Ledger, tmp_path: Path
) -> None:
    path = chain_path(tmp_path)
    path.write_bytes(path.read_bytes()[:-20])

    ledger = make_ledger(tmp_path)
    with pytest.raises(RuntimeError) as excinfo:
        ledger.append(actor="a", operation="op", params={}, result={})
    message = str(excinfo.value).lower()
    assert "incomplete" in message
    assert "archiv" in message or "new chain" in message


# --------------------------------------------------------------------------
# Spec test 10: concurrent writers
# --------------------------------------------------------------------------


def test_a_stale_writer_links_to_the_real_head_and_the_chain_stays_valid(
    chain: Ledger, tmp_path: Path
) -> None:
    """A writer that last looked before somebody else appended still appends.

    This used to assert a refusal. The refusal was the defect: an instance
    that remembered an old head rejected its own next append, and when that
    instance was a carve engine the carve was marked failed after its work was
    done (MANUAL_REPORT FINDING 2). The head is now read under the writer lock,
    so there is no stale head to refuse over. See test_concurrent_writers.py.
    """
    stale = make_ledger(tmp_path)
    stale.entries()
    winner = make_ledger(tmp_path)
    won = winner.append(actor="winner", operation="op", params={}, result={})

    late = stale.append(actor="late", operation="op", params={}, result={})

    assert late.prev_entry_hash == won.entry_hash
    assert late.seq == won.seq + 1
    assert make_ledger(tmp_path).verify().status is ChainStatus.VALID


# --------------------------------------------------------------------------
# Time rules
# --------------------------------------------------------------------------


def test_monotonic_regression_within_one_boot_is_detected(
    chain: Ledger, tmp_path: Path
) -> None:
    lines = read_lines(tmp_path)
    record = json.loads(lines[100])
    record["monotonic_ns"] = 0
    lines[100] = canonical_bytes(record)
    write_lines(tmp_path, lines)

    report = make_ledger(tmp_path).verify()
    assert report.failure_kind in {
        FailureKind.TIME_REGRESSION,
        FailureKind.HASH_MISMATCH,
    }


def test_wall_clock_regression_is_reported(tmp_path: Path) -> None:
    ledger = make_ledger(tmp_path)
    for _ in range(3):
        ledger.append(actor="a", operation="op", params={}, result={})
    lines = read_lines(tmp_path)
    record = json.loads(lines[2])
    record["ts_utc"] = "2000-01-01T00:00:00.000000Z"
    lines[2] = canonical_bytes(record)
    write_lines(tmp_path, lines)

    report = make_ledger(tmp_path).verify()
    assert report.status is ChainStatus.BROKEN


def test_a_new_boot_id_resets_monotonic_comparison(tmp_path: Path) -> None:
    ledger = make_ledger(tmp_path)
    ledger.append(actor="a", operation="op", params={}, result={})
    later = Ledger(
        tmp_path,
        tool_version="0.0.0-test",
        pubkey_fingerprint="AA:BB:CC",
        boot_id="11111111-2222-3333-4444-555555555555",
        monotonic_source=lambda: 1,
    )
    later.append(actor="a", operation="op", params={}, result={})
    assert later.verify().status is ChainStatus.VALID


# --------------------------------------------------------------------------
# Blob availability
# --------------------------------------------------------------------------


def test_missing_blob_is_reported_when_checking_is_requested(
    chain: Ledger, tmp_path: Path
) -> None:
    entry = chain.entries()[10]
    blob = tmp_path / "blobs" / entry.params_hash[:2] / entry.params_hash
    blob.unlink()

    report = make_ledger(tmp_path).verify(check_blobs=True)
    assert report.failure_kind is FailureKind.MISSING_BLOB
    assert report.first_bad_seq == 10


def test_missing_blob_is_ignored_when_not_requested(
    chain: Ledger, tmp_path: Path
) -> None:
    entry = chain.entries()[10]
    (tmp_path / "blobs" / entry.params_hash[:2] / entry.params_hash).unlink()
    assert make_ledger(tmp_path).verify().status is ChainStatus.VALID


# --------------------------------------------------------------------------
# Merkle root
# --------------------------------------------------------------------------


def test_merkle_root_is_stable_for_the_same_range(chain: Ledger) -> None:
    assert chain.merkle_root(0, 99) == chain.merkle_root(0, 99)


def test_merkle_root_differs_between_ranges(chain: Ledger) -> None:
    assert chain.merkle_root(0, 99) != chain.merkle_root(0, 100)


def test_merkle_root_of_a_single_entry_is_that_entry_hash(chain: Ledger) -> None:
    assert chain.merkle_root(7, 7) == chain.entries()[7].entry_hash


def test_odd_leaf_count_duplicates_the_last_leaf(tmp_path: Path) -> None:
    import hashlib

    ledger = make_ledger(tmp_path)
    for _ in range(2):
        ledger.append(actor="a", operation="op", params={}, result={})
    leaves = [bytes.fromhex(e.entry_hash) for e in ledger.entries()[0:3]]
    pair = hashlib.sha256(leaves[0] + leaves[1]).digest()
    odd = hashlib.sha256(leaves[2] + leaves[2]).digest()
    expected = hashlib.sha256(pair + odd).hexdigest()
    assert ledger.merkle_root(0, 2) == expected


def test_merkle_root_rejects_an_out_of_range_request(chain: Ledger) -> None:
    with pytest.raises(ValueError, match="range"):
        chain.merkle_root(0, CHAIN_LEN + 50)
