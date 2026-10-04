"""A report carries the chain's Merkle root and says whether it was anchored.

Internal integrity and externally anchored existence are different claims, and
the report has to keep them apart: a root in the report proves nothing against
an insider who can rewrite the whole state directory, and only a root published
somewhere that insider cannot reach does.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from api.deps import AppServices
from core.ledger.chain import Ledger
from fastapi.testclient import TestClient

from .conftest import settle


def _job_and_report(
    client: TestClient, services: AppServices, tmp_path: Path
) -> dict[str, object]:
    source = tmp_path / "exhibit.bin"
    source.write_bytes(b"\x00" * 1024)
    job_id = client.post(
        "/jobs/acquire", json={"source": str(source), "dest": "anchor.dd"}
    ).json()["job_id"]
    assert settle(services, job_id) == "complete"
    answer = client.post(f"/reports/{job_id}", json={"case_id": "C"})
    assert answer.status_code == 200, answer.text
    loaded: dict[str, object] = json.loads(
        Path(answer.json()["json_path"]).read_text()
    )
    return loaded


def _audit(document: dict[str, object]) -> dict[str, object]:
    sections = document["sections"]
    assert isinstance(sections, dict)
    audit = sections["audit_trail"]
    assert isinstance(audit, dict)
    return audit


def test_without_an_anchor_the_report_says_nothing_was_published(
    client: TestClient,
    services: AppServices,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SANCTUM_ANCHOR_FILE", raising=False)

    audit = _audit(_job_and_report(client, services, tmp_path))

    assert len(str(audit["merkle_root"])) == 64
    anchor = audit["anchor"]
    assert isinstance(anchor, dict)
    assert anchor["anchor_type"] == "null"
    assert "does not prove" in str(anchor["note"])


def test_the_root_matches_the_chain_it_was_computed_over(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    document = _job_and_report(client, services, tmp_path)
    audit = _audit(document)
    anchor = audit["anchor"]
    assert isinstance(anchor, dict)

    chain = Ledger(services.ledger_root, tool_version="t", pubkey_fingerprint="")
    recomputed = chain.merkle_root(int(anchor["from_seq"]), int(anchor["to_seq"]))

    assert audit["merkle_root"] == recomputed


def test_a_configured_file_anchor_receives_the_root(
    client: TestClient,
    services: AppServices,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "worm" / "anchors.jsonl"
    monkeypatch.setenv("SANCTUM_ANCHOR_FILE", str(target))

    audit = _audit(_job_and_report(client, services, tmp_path))

    anchor = audit["anchor"]
    assert isinstance(anchor, dict)
    assert anchor["anchor_type"] == "file"
    published = [json.loads(line) for line in target.read_text().splitlines()]
    assert published[-1]["root"] == audit["merkle_root"]
