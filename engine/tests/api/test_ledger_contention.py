"""The ledger collision, at the two places the walk found it.

MANUAL_REPORT FINDING 2. Generating a report during a carve made the carve's
``carve.complete`` append lose: the job went to ``failed`` with all 33 recovered
objects on disk, and the chain kept ``carve.start`` with no terminal entry. The
secondary point was the other direction - had the *report* append lost, the
``RuntimeError`` escaped ``_record_report_generated`` as a bare 500 with no
remediation.
"""

from __future__ import annotations

import io
import threading
from pathlib import Path
from typing import Any

import pytest
from api.carve_job import carve_generator
from api.deps import AppServices
from core.ledger import chain as chain_mod
from core.ledger._filelock import file_lock
from core.ledger.chain import ChainStatus, Ledger
from fastapi.testclient import TestClient
from PIL import Image

MIB = 1024 * 1024


def _image(path: Path) -> Path:
    canvas = bytearray()
    seed = 0x2468ACE0
    while len(canvas) < 2 * MIB:
        seed = (seed * 1103515245 + 12345) & 0xFFFFFFFF
        canvas += seed.to_bytes(4, "little")
    buffer = io.BytesIO()
    Image.new("RGB", (64, 64), (200, 30, 30)).save(buffer, "JPEG", quality=90)
    canvas[4096 : 4096 + len(buffer.getvalue())] = buffer.getvalue()
    path.write_bytes(bytes(canvas[: 2 * MIB]))
    return path


def test_the_engine_terminal_entry_lands_when_another_writer_appends_between_yields(
    tmp_path: Path,
) -> None:
    """Break 2, deterministically: a foreign append at every yield of a carve."""
    image = _image(tmp_path / "case.dd")
    engine = Ledger(tmp_path / "ledger", tool_version="t", pubkey_fingerprint="AA")
    generator = carve_generator(
        image, undelete=False, job_id="carve-interleaved", ledger=engine
    )

    foreign = 0
    try:
        while True:
            next(generator)
            other = Ledger(
                tmp_path / "ledger", tool_version="t", pubkey_fingerprint="AA"
            )
            other.append(
                actor="report",
                operation="report.generated",
                params={"job_id": "someone-else", "n": foreign},
                result={},
            )
            foreign += 1
    except StopIteration:
        pass

    chain = Ledger(tmp_path / "ledger", tool_version="t", pubkey_fingerprint="AA")
    operations = [entry.operation for entry in chain.entries()]
    assert foreign > 1
    assert operations[1] == "carve.start"
    assert operations[-1] == "carve.complete"
    assert chain.verify(check_blobs=True).status is ChainStatus.VALID


def test_a_carve_job_completes_while_another_thread_hammers_the_chain(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    """The same thing through the real route, the real registry and real threads."""
    image = _image(tmp_path / "case.dd")
    stop = threading.Event()

    def hammer() -> None:
        n = 0
        while not stop.is_set():
            Ledger(
                services.ledger_root, tool_version="t", pubkey_fingerprint=""
            ).append(
                actor="report", operation="report.generated",
                params={"job_id": "other", "n": n}, result={},
            )
            n += 1

    Ledger(services.ledger_root, tool_version="t", pubkey_fingerprint="").append(
        actor="setup", operation="setup", params={}, result={}
    )
    thread = threading.Thread(target=hammer)
    thread.start()
    try:
        accepted = client.post(
            "/jobs/carve",
            json={"image": str(image), "undelete": False, "out_dir": "case-001"},
        )
        assert accepted.status_code == 200, accepted.text
        job_id = accepted.json()["job_id"]
        record = services.registry.wait(job_id, timeout=60)
    finally:
        stop.set()
        thread.join()

    assert record.state == "complete", (record.error, record.error_kind)
    chain = Ledger(services.ledger_root, tool_version="t", pubkey_fingerprint="")
    mine = [
        entry.operation
        for entry in chain.entries()
        if chain.params_of(entry).get("job_id") == job_id
    ]
    # job.outcome is appended by the registry once the job is terminal, which
    # is what lets a report survive a restart (api/durable.py). It is written
    # under the same contention as the engine's own entries, so it belongs in
    # this assertion rather than being filtered out of it.
    assert mine == ["carve.start", "carve.mediamap", "carve.complete", "job.outcome"]
    assert chain.verify(check_blobs=True).status is ChainStatus.VALID


def test_a_report_whose_append_cannot_get_the_lock_is_a_503_with_remediation(
    client: TestClient,
    services: AppServices,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Never a bare 500. The operator is told the entry was not recorded, and why."""
    source = tmp_path / "src.dd"
    source.write_bytes(b"x" * 4096)
    job_id = client.post(
        "/jobs/acquire", json={"source": str(source), "dest": "src.dd"}
    ).json()["job_id"]
    services.registry.wait(job_id)

    monkeypatch.setattr(chain_mod, "APPEND_LOCK_ATTEMPTS", 2)
    monkeypatch.setattr(chain_mod, "APPEND_BACKOFF_INITIAL_SECONDS", 0.001)
    lock_path = services.ledger_root / "ledger" / ".chain.lock"
    with file_lock(lock_path):
        answer = client.post(
            f"/reports/{job_id}", json={"case_id": "BUSY", "operator": "tester"}
        )

    assert answer.status_code == 503, answer.text
    detail: dict[str, Any] = answer.json()["detail"]
    assert detail["kind"] == "LedgerBusy"
    assert "NOT recorded" in detail["error"]
    assert "BUSY.forensic.json" in detail["error"]
    assert detail["remediation"]
    # And nothing half-happened in the chain.
    chain = Ledger(services.ledger_root, tool_version="t", pubkey_fingerprint="")
    assert all(e.operation != "report.generated" for e in chain.entries())
