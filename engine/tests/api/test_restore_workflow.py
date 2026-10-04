"""Backup records and the restore workflow over the API.

The helper is the recording double from conftest, except ``run_restore``, which
is driven through the helper's **real** streaming handler so the write-seam
revalidation runs exactly as it would in the daemon. Its target re-read answers
from the same fixture table, and the device it would open is a sparse file
under ``tmp_path``. No device node is opened.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
from api.deps import AppServices
from core.restore import FileBlockTarget
from fastapi.testclient import TestClient
from helper.daemon import STREAMING_OPERATIONS, _rpc_errors

from . import conftest
from .conftest import MIB, RecordingHelper, authorize

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="the restore write seam exists only on Linux"
)

SERIAL = "SYN-PURGE-1"
IMAGE_SIZE = 5 * MIB  # two 4 MiB chunks, the second partial


class RestoreHelper(RecordingHelper):
    """The recording helper, with ``run_restore`` served by the real handler."""

    def call_stream(
        self, method: str, params: dict[str, Any]
    ) -> Generator[dict[str, Any], None, dict[str, Any]]:
        if method != "run_restore":
            return (yield from super().call_stream(method, params))
        self.calls.append((method, dict(params)))
        with _rpc_errors(method):
            generator = STREAMING_OPERATIONS["run_restore"](params)
            try:
                while True:
                    try:
                        record = next(generator)
                    except StopIteration as stop:
                        answer: dict[str, Any] = stop.value
                        return answer
                    yield record
            finally:
                generator.close()


@pytest.fixture
def helper() -> RestoreHelper:
    return RestoreHelper()


@pytest.fixture
def seam(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """The write seam's view of the host: probe overrides and the target file."""
    target = tmp_path / "sdz.img"
    with target.open("wb") as handle:
        handle.truncate(64 * MIB)
    state: dict[str, Any] = {"target": target, "override": {}, "opened": []}

    def probe(path: str) -> dict[str, Any]:
        for row in conftest.FAKE_DEVICES:
            if row["device"]["path"] == path:
                return {"device": {**row["device"], **state["override"]}}
        raise LookupError(path)

    def opener(planned: Any) -> FileBlockTarget:
        state["opened"].append(planned.path)
        return FileBlockTarget(target)

    monkeypatch.setattr("helper.authorization._fresh_restore_probe", probe)
    monkeypatch.setattr("helper.daemon._open_restore_target", opener)
    return state


def _image_bytes() -> bytes:
    return bytes((i * 13 + i // 65536) % 256 for i in range(IMAGE_SIZE))


def _finish(client: TestClient, services: AppServices, job_id: str) -> dict[str, Any]:
    services.registry.wait(job_id, timeout=30)
    status = client.get(f"/jobs/{job_id}").json()
    return dict(status)


def record_backup(client: TestClient, services: AppServices) -> str:
    (services.evidence_dir / "disk.img").write_bytes(_image_bytes())
    answer = client.post(
        "/workflow/backup",
        json={"backup_image": "disk.img", "source_path": "/dev/sdz"},
    )
    assert answer.status_code == 200, answer.text
    status = _finish(client, services, answer.json()["job_id"])
    assert status["state"] == "complete", status
    return str(status["result"]["backup_id"])


def open_restore(client: TestClient, backup_id: str, target: str = "/dev/sdz") -> Any:
    return client.post(
        "/workflow/restore", json={"backup_id": backup_id, "target_path": target}
    )


def approve(client: TestClient, auth_id: str, serial: str = SERIAL) -> Any:
    return client.post(
        f"/workflow/restore/{auth_id}/approve",
        json={"typed_serial": serial, "acknowledge_data_overwrite": True},
    )


def planned(client: TestClient, services: AppServices) -> str:
    """Record, open and approve. Returns the restore authorization id."""
    backup_id = record_backup(client, services)
    opened = open_restore(client, backup_id)
    assert opened.status_code == 200, opened.text
    auth_id = str(opened.json()["authorization_id"])
    assert approve(client, auth_id).status_code == 200
    return auth_id


def _ops(services: AppServices) -> list[str]:
    return [entry.operation for entry in services.ledger().entries()]


def _untouched(seam: dict[str, Any]) -> bool:
    with seam["target"].open("rb") as handle:
        return handle.read(IMAGE_SIZE) == b"\0" * IMAGE_SIZE


# -- backups ----------------------------------------------------------------


def test_a_backup_record_is_created_as_a_job_and_ledgered(
    client: TestClient, services: AppServices
) -> None:
    backup_id = record_backup(client, services)
    body = client.get(f"/workflow/backup/{backup_id}").json()["backup"]
    assert body["source"]["serial"] == SERIAL
    assert body["image_size_bytes"] == IMAGE_SIZE
    assert len(body["chunk_hashes"]) == 2
    assert any("NOT_PROOF_OF_PROVENANCE" in item for item in body["limitations"])
    assert "backup.record" in _ops(services)


def test_backup_verification_names_the_first_bad_chunk(
    client: TestClient, services: AppServices
) -> None:
    backup_id = record_backup(client, services)
    ok = _finish(
        client, services,
        client.post(f"/workflow/backup/{backup_id}/verify").json()["job_id"],
    )
    assert ok["result"]["passed"] is True
    image = services.evidence_dir / "disk.img"
    data = bytearray(image.read_bytes())
    data[4 * MIB + 3] ^= 0xFF
    image.write_bytes(bytes(data))
    bad = _finish(
        client, services,
        client.post(f"/workflow/backup/{backup_id}/verify").json()["job_id"],
    )
    assert bad["result"]["passed"] is False
    assert bad["result"]["first_mismatch"]["index"] == 1
    assert _ops(services).count("backup.verify") == 2


def test_a_backup_record_edited_on_disk_is_refused(
    client: TestClient, services: AppServices
) -> None:
    backup_id = record_backup(client, services)
    path = services.state_dir / "backups" / f"{backup_id}.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["image_sha256"] = "0" * 64
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert client.get(f"/workflow/backup/{backup_id}").status_code == 422
    assert open_restore(client, backup_id).status_code == 422


def test_an_acquisition_of_something_else_is_not_recorded_as_this_device(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    source = tmp_path / "somewhere.bin"
    source.write_bytes(b"\x01" * 65536)
    accepted = client.post(
        "/jobs/acquire", json={"source": str(source), "dest": "acq.img"}
    ).json()
    assert _finish(client, services, accepted["job_id"])["state"] == "complete"
    answer = client.post(
        "/workflow/backup",
        json={
            "backup_image": "acq.img",
            "source_path": "/dev/sdz",
            "acquisition_job_id": accepted["job_id"],
        },
    )
    assert answer.status_code == 422
    assert "not /dev/sdz" in answer.json()["detail"]["error"]


# -- restore ----------------------------------------------------------------


def test_the_full_restore_flow_writes_the_real_target(
    client: TestClient, services: AppServices, seam: dict[str, Any]
) -> None:
    backup_id = record_backup(client, services)
    opened = open_restore(client, backup_id).json()
    assert opened["workflow"]["state"] == "HUMAN_APPROVAL_REQUIRED"
    assert opened["plan"]["identity_relation"] == "same_device"
    assert opened["plan"]["write_length"] == IMAGE_SIZE
    auth_id = opened["authorization_id"]
    approved = approve(client, auth_id).json()
    assert approved["workflow"]["state"] == "PLAN_READY"

    # No serial: refused, nothing opened, nothing spent.
    bare = client.post(f"/workflow/restore/{auth_id}/execute", json={})
    assert bare.status_code == 409, bare.text
    assert seam["opened"] == [] and _untouched(seam)
    # A removed rehearsal switch: rejected, nothing opened, nothing spent.
    rehearsal = client.post(
        f"/workflow/restore/{auth_id}/execute",
        json={"dry_run": True, "typed_serial": SERIAL},
    )
    assert rehearsal.status_code == 422, rehearsal.text
    assert seam["opened"] == [] and _untouched(seam)
    assert client.get(f"/workflow/restore/{auth_id}").json()["spent"] is False

    real = client.post(
        f"/workflow/restore/{auth_id}/execute",
        json={"typed_serial": SERIAL},
    )
    assert real.status_code == 200, real.text
    status = _finish(client, services, real.json()["job_id"])
    assert status["state"] == "complete", status
    result = status["result"]
    assert result["result"] == "RESTORED_VERIFIED"
    assert result["verification_sha256"] == result["image_sha256"]
    assert result["bytes_written"] == IMAGE_SIZE
    assert seam["target"].read_bytes()[:IMAGE_SIZE] == _image_bytes()
    ops = _ops(services)
    for op in (
        "restore.plan",
        "restore.authorize",
        "restore.start",
        "restore.complete",
        "restore.verify",
    ):
        assert op in ops, op
    state = client.get(f"/workflow/restore/{auth_id}").json()
    assert state["executed"] is True and state["spent"] is True


def test_an_authorization_executes_once(
    client: TestClient, services: AppServices, seam: dict[str, Any]
) -> None:
    auth_id = planned(client, services)
    body = {"typed_serial": SERIAL}
    first = client.post(f"/workflow/restore/{auth_id}/execute", json=body)
    _finish(client, services, first.json()["job_id"])
    again = client.post(f"/workflow/restore/{auth_id}/execute", json=body)
    assert again.status_code == 409
    assert "already used" in " ".join(again.json()["detail"]["WHY BLOCKED"])
    assert seam["opened"] == ["/dev/sdz"]


def test_a_wrong_typed_serial_writes_nothing_and_spends_nothing(
    client: TestClient, services: AppServices, seam: dict[str, Any]
) -> None:
    auth_id = planned(client, services)
    answer = client.post(
        f"/workflow/restore/{auth_id}/execute",
        json={"typed_serial": "NOT-IT"},
    )
    assert answer.status_code == 409
    assert answer.json()["detail"]["physical_device_modified"] is False
    assert client.get(f"/workflow/restore/{auth_id}").json()["spent"] is False
    assert seam["opened"] == [] and _untouched(seam)
    assert "restore.refused" in _ops(services)


def test_a_real_restore_without_approval_is_refused(
    client: TestClient, services: AppServices, seam: dict[str, Any]
) -> None:
    backup_id = record_backup(client, services)
    auth_id = open_restore(client, backup_id).json()["authorization_id"]
    answer = client.post(
        f"/workflow/restore/{auth_id}/execute",
        json={"typed_serial": SERIAL},
    )
    assert answer.status_code == 409
    assert answer.json()["detail"]["workflow_state"] == "HUMAN_APPROVAL_REQUIRED"
    assert seam["opened"] == []


def test_approval_needs_the_typed_serial_and_the_acknowledgement(
    client: TestClient, services: AppServices, seam: dict[str, Any]
) -> None:
    backup_id = record_backup(client, services)
    auth_id = open_restore(client, backup_id).json()["authorization_id"]
    assert approve(client, auth_id, serial="WRONG").status_code == 409
    no_ack = client.post(
        f"/workflow/restore/{auth_id}/approve", json={"typed_serial": SERIAL}
    )
    assert no_ack.status_code == 409
    assert "restore.authorize" not in _ops(services)


def test_a_system_disk_target_is_refused_at_planning(
    client: TestClient, services: AppServices, seam: dict[str, Any]
) -> None:
    backup_id = record_backup(client, services)
    answer = open_restore(client, backup_id, target="/dev/sdx")
    assert answer.status_code == 409
    why = " ".join(answer.json()["detail"]["WHY BLOCKED"])
    assert "boot/root" in why and "mounted" in why


def test_drift_seen_only_by_the_helper_fails_the_job_and_writes_nothing(
    client: TestClient, services: AppServices, seam: dict[str, Any]
) -> None:
    """The API's probe still matches; the write seam's own re-read does not."""
    auth_id = planned(client, services)
    seam["override"] = {"mounted_at": ["/mnt/late"]}
    accepted = client.post(
        f"/workflow/restore/{auth_id}/execute",
        json={"typed_serial": SERIAL},
    )
    assert accepted.status_code == 200
    status = _finish(client, services, accepted.json()["job_id"])
    assert status["state"] == "failed"
    assert status["error_kind"] == "WorkflowGateRefused"
    assert "/mnt/late" in status["error"]
    assert seam["opened"] == [] and _untouched(seam)


# -- kind separation --------------------------------------------------------


def test_an_erase_authorization_cannot_execute_a_restore(
    client: TestClient, services: AppServices, seam: dict[str, Any]
) -> None:
    erase_id = authorize(client, services)
    answer = client.post(
        f"/workflow/restore/{erase_id}/execute",
        json={"typed_serial": SERIAL},
    )
    assert answer.status_code == 409
    assert "'erase' authorization" in " ".join(answer.json()["detail"]["WHY BLOCKED"])
    assert approve(client, erase_id).status_code == 404
    assert seam["opened"] == []


def test_a_restore_authorization_cannot_execute_an_erase(
    client: TestClient,
    services: AppServices,
    seam: dict[str, Any],
    helper: RecordingHelper,
) -> None:
    restore_id = planned(client, services)
    answer = client.post(
        "/jobs/erase-drive",
        json={
            "path": "/dev/sdz",
            "typed_serial": SERIAL,
            "authorization_id": restore_id,
        },
    )
    assert answer.status_code == 409
    assert "cannot authorize an erase" in " ".join(
        answer.json()["detail"]["WHY BLOCKED"]
    )
    assert [c for c in helper.calls if c[0] == "run_erase"] == []
    assert client.get(f"/workflow/erase-drive/{restore_id}").status_code == 404
