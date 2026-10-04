"""External anchoring, and the honest statement of what it does not prove."""

from __future__ import annotations

import json
from pathlib import Path

import core.ledger.anchor as anchor_module
from core.ledger.anchor import FileAnchor, NullAnchor

ROOT = "a" * 64


def test_null_anchor_records_that_nothing_external_was_configured() -> None:
    receipt = NullAnchor().publish(ROOT, (0, 199))
    assert receipt.anchor_type == "null"
    assert receipt.root == ROOT
    assert receipt.from_seq == 0
    assert receipt.to_seq == 199
    assert "no external anchor" in receipt.note.lower()


def test_file_anchor_appends_a_line_per_publication(tmp_path: Path) -> None:
    target = tmp_path / "anchors.jsonl"
    anchor = FileAnchor(target)
    anchor.publish(ROOT, (0, 99))
    anchor.publish("b" * 64, (100, 199))

    lines = target.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["root"] == ROOT
    assert first["from_seq"] == 0
    assert first["to_seq"] == 99
    assert first["anchored_at"].endswith("Z")


def test_file_anchor_never_rewrites_earlier_lines(tmp_path: Path) -> None:
    target = tmp_path / "anchors.jsonl"
    anchor = FileAnchor(target)
    anchor.publish(ROOT, (0, 9))
    first_bytes = target.read_bytes()
    anchor.publish("c" * 64, (10, 19))
    assert target.read_bytes().startswith(first_bytes)


def test_file_anchor_receipt_names_the_location(tmp_path: Path) -> None:
    target = tmp_path / "anchors.jsonl"
    receipt = FileAnchor(target).publish(ROOT, (0, 9))
    assert receipt.anchor_type == "file"
    assert str(target) in receipt.location


def test_module_states_what_a_local_chain_cannot_prove() -> None:
    doc = anchor_module.__doc__ or ""
    assert "existence-at-a-time" in doc
    assert "third party" in doc


def test_no_network_anchor_is_shipped() -> None:
    names = dir(anchor_module)
    assert not any(
        token in name.lower()
        for name in names
        for token in ("http", "blockchain", "chainpoint", "opentimestamps")
    )
