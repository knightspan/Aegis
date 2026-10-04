"""Content-addressed blobs and the append-only chain file."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest
from core.ledger.store import BlobStore, LedgerStore

# --------------------------------------------------------------------------
# BlobStore
# --------------------------------------------------------------------------


def test_put_returns_the_sha256_of_the_content(tmp_path: Path) -> None:
    store = BlobStore(tmp_path)
    payload = b'{"a":1}'
    digest = store.put(payload)
    assert digest == hashlib.sha256(payload).hexdigest()


def test_blob_is_sharded_by_the_first_two_hex_characters(tmp_path: Path) -> None:
    store = BlobStore(tmp_path)
    digest = store.put(b"hello")
    assert (tmp_path / "blobs" / digest[:2] / digest).read_bytes() == b"hello"


def test_put_is_idempotent(tmp_path: Path) -> None:
    store = BlobStore(tmp_path)
    first = store.put(b"same")
    second = store.put(b"same")
    assert first == second
    assert len(list((tmp_path / "blobs").rglob("*"))) == 2  # shard dir + one blob


def test_get_round_trips(tmp_path: Path) -> None:
    store = BlobStore(tmp_path)
    digest = store.put(b"payload")
    assert store.get(digest) == b"payload"


def test_get_returns_none_for_an_unknown_hash(tmp_path: Path) -> None:
    assert BlobStore(tmp_path).get("0" * 64) is None


def test_has_reports_availability(tmp_path: Path) -> None:
    store = BlobStore(tmp_path)
    digest = store.put(b"x")
    assert store.has(digest) is True
    assert store.has("f" * 64) is False


def test_get_rejects_a_path_traversal_attempt(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="hex"):
        BlobStore(tmp_path).get("../../etc/passwd")


# --------------------------------------------------------------------------
# LedgerStore
# --------------------------------------------------------------------------


def test_append_creates_the_chain_file(tmp_path: Path) -> None:
    store = LedgerStore(tmp_path)
    store.append(b'{"seq":0}')
    assert (tmp_path / "ledger" / "chain.jsonl").exists()


def test_lines_round_trip_in_order(tmp_path: Path) -> None:
    store = LedgerStore(tmp_path)
    for index in range(3):
        store.append(f'{{"seq":{index}}}'.encode())
    read = store.read()
    assert [line.decode() for line in read.lines] == [
        '{"seq":0}',
        '{"seq":1}',
        '{"seq":2}',
    ]
    assert read.incomplete_tail is False


def test_each_entry_is_one_newline_terminated_line(tmp_path: Path) -> None:
    store = LedgerStore(tmp_path)
    store.append(b'{"seq":0}')
    store.append(b'{"seq":1}')
    raw = (tmp_path / "ledger" / "chain.jsonl").read_bytes()
    assert raw == b'{"seq":0}\n{"seq":1}\n'


def test_append_refuses_a_payload_containing_a_newline(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="newline"):
        LedgerStore(tmp_path).append(b'{"a":1}\n{"b":2}')


def test_reading_an_absent_chain_yields_nothing(tmp_path: Path) -> None:
    read = LedgerStore(tmp_path).read()
    assert read.lines == []
    assert read.incomplete_tail is False


def test_truncated_final_line_is_reported_as_an_incomplete_tail(
    tmp_path: Path,
) -> None:
    store = LedgerStore(tmp_path)
    store.append(b'{"seq":0}')
    store.append(b'{"seq":1}')
    chain = tmp_path / "ledger" / "chain.jsonl"
    raw = chain.read_bytes()
    chain.write_bytes(raw[:-5])  # kill the newline and part of the JSON

    read = store.read()
    assert read.incomplete_tail is True
    assert [line.decode() for line in read.lines] == ['{"seq":0}']
    assert read.partial_tail is not None


def test_appending_after_an_incomplete_tail_is_refused(tmp_path: Path) -> None:
    store = LedgerStore(tmp_path)
    store.append(b'{"seq":0}')
    chain = tmp_path / "ledger" / "chain.jsonl"
    chain.write_bytes(chain.read_bytes()[:-3])

    with pytest.raises(RuntimeError) as excinfo:
        store.append(b'{"seq":1}')
    message = str(excinfo.value)
    assert "incomplete" in message.lower()
    assert "truncat" in message.lower() or "recover" in message.lower()


def test_store_never_opens_the_chain_for_seeking_or_truncation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[str, int]] = []
    real_open = os.open

    def recording_open(path: object, flags: int, *args: object) -> int:
        seen.append((str(path), flags))
        return real_open(path, flags, *args)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", recording_open)
    store = LedgerStore(tmp_path)
    store.append(b'{"seq":0}')
    store.append(b'{"seq":1}')

    chain = str(tmp_path / "ledger" / "chain.jsonl")
    chain_writes = [
        flags
        for path, flags in seen
        if path == chain and flags & (os.O_WRONLY | os.O_RDWR)
    ]
    assert chain_writes, "expected at least one write open of the chain"
    for flags in chain_writes:
        assert flags & os.O_APPEND, "chain must be opened O_APPEND"
        assert not flags & os.O_TRUNC, "chain must never be truncated"


def test_concurrent_appends_are_serialised_by_the_lock(tmp_path: Path) -> None:
    first = LedgerStore(tmp_path)
    second = LedgerStore(tmp_path)
    first.append(b'{"seq":0}')
    second.append(b'{"seq":1}')
    assert len(first.read().lines) == 2
