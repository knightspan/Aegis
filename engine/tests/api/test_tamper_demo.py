"""The tamper demonstration runs the real verifier on a copy.

Two claims, and the second is the one that has to be tested hardest:

* the verdict is produced by :meth:`core.ledger.chain.Ledger.verify` - the same
  code that guards the live chain - and not by a demo implementation that could
  say BROKEN without anything being broken;
* **the production ledger is not modified**, which is checked here by hashing
  the chain file and its blob store before and after.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

from api.deps import AppServices
from fastapi.testclient import TestClient


def _tree_digest(root: Path) -> str:
    """One digest over every *stored* file under ``root``, path and content.

    Staging files (``.<digest>.partial``) are skipped: they are a blob write
    in flight, not ledger content, and one can be renamed away between the
    listing and the read.
    """
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        if path.name.startswith(".") and path.name.endswith(".partial"):
            continue
        digest.update(str(path.relative_to(root)).encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _busy_chain(client: TestClient, tmp_path: Path, runs: int = 3) -> None:
    source = tmp_path / "exhibit.bin"
    source.write_bytes(b"\x00" * 1024)
    for index in range(runs):
        accepted = client.post(
            "/jobs/acquire",
            json={"source": str(source), "dest": f"t{index}.dd"},
        )
        job_id = accepted.json()["job_id"]
        # Until it has *settled*: a job that is merely terminal may still have
        # a blob write in flight, and this test then hashes a tree that is
        # still being written.
        deadline = time.monotonic() + 30
        while not client.get(f"/jobs/{job_id}").json()["settled"]:
            assert time.monotonic() < deadline, "the acquisition never settled"
            time.sleep(0.01)


def test_the_demonstration_breaks_a_copy_and_reports_the_exact_sequence(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    _busy_chain(client, tmp_path)
    before_state = client.get("/ledger/verify").json()
    assert before_state["status"] == "VALID"

    answer = client.post("/ledger/tamper-demo", json={})

    assert answer.status_code == 200, answer.text
    body = answer.json()
    assert body["before"]["status"] == "VALID"
    assert body["after"]["status"] == "BROKEN"
    # The break is reported at exactly the sequence that was altered, not
    # merely "somewhere".
    assert body["after"]["first_broken_seq"] == body["tampered_seq"]
    assert body["after"]["failure_kind"] == "HASH_MISMATCH"


def test_entries_before_the_break_remain_verified(
    client: TestClient, tmp_path: Path
) -> None:
    """An examiner needs to know how much of the chain is still trustworthy."""
    _busy_chain(client, tmp_path)

    body = client.post("/ledger/tamper-demo", json={}).json()

    assert body["after"]["verified_through"] == body["tampered_seq"] - 1
    assert body["after"]["unverifiable_count"] >= 0


def test_the_production_ledger_is_byte_identical_afterwards(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    """The claim the whole feature rests on."""
    _busy_chain(client, tmp_path)
    before = _tree_digest(services.ledger_root)

    client.post("/ledger/tamper-demo", json={})

    assert _tree_digest(services.ledger_root) == before
    assert client.get("/ledger/verify").json()["status"] == "VALID"


def test_the_scratch_copy_is_removed(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    _busy_chain(client, tmp_path)

    client.post("/ledger/tamper-demo", json={})

    leftovers = [p for p in services.work_dir.glob("tamper-demo-*")]
    assert leftovers == []


def test_a_named_sequence_is_the_one_that_breaks(
    client: TestClient, tmp_path: Path
) -> None:
    _busy_chain(client, tmp_path)

    body = client.post("/ledger/tamper-demo", json={"seq": 2}).json()

    assert body["tampered_seq"] == 2
    assert body["after"]["first_broken_seq"] == 2


def test_the_genesis_entry_cannot_be_chosen(
    client: TestClient, tmp_path: Path
) -> None:
    """Breaking genesis leaves no verified prefix to point at."""
    _busy_chain(client, tmp_path)

    answer = client.post("/ledger/tamper-demo", json={"seq": 0})

    assert answer.status_code >= 400
    assert answer.json()["detail"]["remediation"]


def test_a_sequence_outside_the_chain_is_refused(
    client: TestClient, tmp_path: Path
) -> None:
    _busy_chain(client, tmp_path)

    answer = client.post("/ledger/tamper-demo", json={"seq": 99_999})

    assert answer.status_code >= 400
    assert "Nothing was modified" in answer.json()["detail"]["remediation"]


def test_a_chain_too_short_to_demonstrate_on_is_refused(client: TestClient) -> None:
    answer = client.post("/ledger/tamper-demo", json={})

    assert answer.status_code >= 400
    assert answer.json()["detail"]["remediation"]
