"""Gate properties beyond the happy/refusal matrix: ctime, plan drift, races.

Each test is deterministic. The concurrency test does not sleep or retry: it
starts N threads behind a barrier and asserts the exactly-once outcome of the
exclusive-create marker, which is the mechanism ``authorize_execution`` uses.
"""

from __future__ import annotations

import copy
import os
import sys
import threading
from typing import Any

import pytest
from api.authorization import (
    AuthorizationStore,
    GateRefused,
    authorize_execution,
)
from api.deps import AppServices
from fastapi.testclient import TestClient

from . import conftest
from .conftest import RecordingHelper, approve_workflow, open_workflow

REAL = {"path": "/dev/sdz", "typed_serial": "SYN-PURGE-1"}


def _writes(helper: RecordingHelper) -> list[Any]:
    return [
        c for c in helper.calls if c[0] == "run_erase"
    ]


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="NT st_ctime is the creation time; the backup gate guards whole-drive "
    "erase, which only Linux offers",
)
def test_an_in_place_edit_with_the_mtime_restored_is_refused(
    client: TestClient, services: AppServices, helper: RecordingHelper
) -> None:
    """Same size, same mtime, different bytes: only ctime/inode can tell."""
    auth_id = open_workflow(client, services)
    approve_workflow(client, auth_id)
    image = services.evidence_dir / "backup.img"
    before = image.stat()
    with image.open("r+b") as handle:
        handle.write(b"tampered")
    os.utime(image, ns=(before.st_atime_ns, before.st_mtime_ns))
    after = image.stat()
    assert (after.st_size, after.st_mtime_ns) == (before.st_size, before.st_mtime_ns)

    answer = client.post(
        "/jobs/erase-drive", json={**REAL, "authorization_id": auth_id}
    )
    assert answer.status_code == 409
    assert "backup" in " ".join(answer.json()["detail"]["WHY BLOCKED"])
    assert _writes(helper) == []


def test_a_replaced_backup_image_is_refused(
    client: TestClient, services: AppServices, helper: RecordingHelper
) -> None:
    """A new file with the same name, size and (restored) mtime has a new inode."""
    auth_id = open_workflow(client, services)
    approve_workflow(client, auth_id)
    image = services.evidence_dir / "backup.img"
    before = image.stat()
    replacement = services.evidence_dir / "other.img"
    replacement.write_bytes(b"\0" * before.st_size)
    os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
    os.replace(replacement, image)
    answer = client.post(
        "/jobs/erase-drive", json={**REAL, "authorization_id": auth_id}
    )
    assert answer.status_code == 409
    assert _writes(helper) == []


def test_a_record_without_the_new_fingerprint_fails_closed(
    client: TestClient, services: AppServices, helper: RecordingHelper
) -> None:
    auth_id = open_workflow(client, services)
    approve_workflow(client, auth_id)
    store = AuthorizationStore(services.state_dir / "authorizations")
    record = store.load(auth_id)
    assert record is not None
    record.backup.pop("ctime_ns")
    record.backup.pop("inode")
    store.save(record)
    answer = client.post(
        "/jobs/erase-drive", json={**REAL, "authorization_id": auth_id}
    )
    assert answer.status_code == 409
    assert _writes(helper) == []


def test_a_capability_plan_that_changed_after_approval_is_refused(
    client: TestClient,
    services: AppServices,
    helper: RecordingHelper,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    auth_id = open_workflow(client, services)
    approve_workflow(client, auth_id)
    changed = copy.deepcopy(conftest.FAKE_DEVICES)
    changed[0]["capabilities"]["limitations"] = ["a new limitation appeared"]
    monkeypatch.setattr(conftest, "FAKE_DEVICES", changed)
    answer = client.post(
        "/jobs/erase-drive", json={**REAL, "authorization_id": auth_id}
    )
    assert answer.status_code == 409
    assert "limitations changed" in " ".join(answer.json()["detail"]["WHY BLOCKED"])
    assert _writes(helper) == []
    assert not AuthorizationStore(services.state_dir / "authorizations").is_spent(
        auth_id
    )


def test_concurrent_executions_of_one_authorization_admit_exactly_one(
    client: TestClient, services: AppServices, helper: RecordingHelper
) -> None:
    """Twelve threads race one approved authorization; one passes the gate."""
    auth_id = open_workflow(client, services)
    approve_workflow(client, auth_id)
    probe = helper.call("probe_capabilities", {"path": "/dev/sdz"})
    barrier = threading.Barrier(12)
    outcomes: list[str] = []
    lock = threading.Lock()

    def attempt() -> None:
        barrier.wait()
        try:
            authorize_execution(
                services,
                auth_id=auth_id,
                path="/dev/sdz",
                level="CLEAR",
                probe=probe,
                actor="race-test",
            )
            result = "admitted"
        except GateRefused:
            result = "refused"
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=attempt) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert sorted(outcomes) == ["admitted"] + ["refused"] * 11


def test_a_refusal_never_spends_and_a_later_valid_run_still_works(
    client: TestClient, services: AppServices, helper: RecordingHelper
) -> None:
    """Refusing must not burn the authorization: the operator can fix and retry."""
    auth_id = open_workflow(client, services)
    approve_workflow(client, auth_id)
    wrong = client.post(
        "/jobs/erase-drive",
        json={**REAL, "typed_serial": "WRONG", "authorization_id": auth_id},
    )
    assert wrong.status_code == 409
    store = AuthorizationStore(services.state_dir / "authorizations")
    assert not store.is_spent(auth_id)
    ok = client.post("/jobs/erase-drive", json={**REAL, "authorization_id": auth_id})
    assert ok.status_code == 200
    assert store.is_spent(auth_id)
