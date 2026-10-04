"""The guarded HPA/DCO workflow over the API, through the helper's real handlers.

``discover_hidden_area`` and ``run_hpa_change`` are served by the helper's
**real** operations, so the write-seam revalidation and the engine run exactly
as they would in the daemon. Only the host is faked: the platform backend is
the Linux hdparm backend over a runner that answers like a SATA drive with a
3 MiB HPA and records every argv, and the device re-read answers from the API
suite's fixture table. No device node is opened and no hdparm is executed.
"""

from __future__ import annotations

import json
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
from api.deps import AppServices
from core.device._sysio import CommandResult, SystemProbe
from core.device.hidden_area_workflow import LinuxHpaBackend
from core.errors import PlatformUnsupported, WorkflowGateRefused
from core.models import Device
from fastapi.testclient import TestClient
from helper.authorization import revalidate_execution, revalidate_hpa
from helper.daemon import OPERATIONS, STREAMING_OPERATIONS, _rpc_errors

from . import conftest
from .conftest import MIB, RecordingHelper, authorize

SERIAL = "SYN-PURGE-1"
PATH = "/dev/sdz"
ACCESSIBLE_SECTORS = 64 * MIB // 512
NATIVE_SECTORS = ACCESSIBLE_SECTORS + 6144  # 3 MiB hidden


class Drive:
    """``hdparm`` as a SATA drive with an HPA would answer it."""

    def __init__(self) -> None:
        self.accessible = ACCESSIBLE_SECTORS
        self.native = NATIVE_SECTORS
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: Any) -> CommandResult:
        key = tuple(argv)
        self.calls.append(key)
        if key[:2] == ("hdparm", "-N") and len(key) == 3:
            return CommandResult(
                list(key), 0,
                f"{key[2]}:\n max sectors   = {self.accessible}/{self.native}, "
                "HPA is enabled\n", "",
            )
        if key[:2] == ("hdparm", "-N") and len(key) == 4:
            self.accessible = int(key[2].lstrip("p"))
            return CommandResult(list(key), 0, "setting max visible sectors\n", "")
        if key[:2] == ("hdparm", "--dco-identify"):
            return CommandResult(
                list(key), 0, f" Real max sectors: {self.native}\n", ""
            )
        return CommandResult(list(key), 127, "", "command not found")

    @property
    def sets(self) -> list[tuple[str, ...]]:
        return [call for call in self.calls if len(call) == 4]


class HpaHelper(RecordingHelper):
    """The recording helper, with the two HPA operations served by the real ones."""

    def call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method != "discover_hidden_area":
            return super().call(method, params)
        self.calls.append((method, dict(params)))
        with _rpc_errors(method):
            return OPERATIONS[method](params)

    def call_stream(
        self, method: str, params: dict[str, Any]
    ) -> Generator[dict[str, Any], None, dict[str, Any]]:
        if method != "run_hpa_change":
            return (yield from super().call_stream(method, params))
        self.calls.append((method, dict(params)))
        with _rpc_errors(method):
            generator = STREAMING_OPERATIONS[method](params)
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
def helper() -> HpaHelper:
    return HpaHelper()


@pytest.fixture
def drive(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Drive:
    """The faked host: backend, device re-read and sysfs sector size."""
    fake = Drive()
    queue = tmp_path / "sys" / "block" / "sdz" / "queue"
    queue.mkdir(parents=True)
    (queue / "logical_block_size").write_text("512\n")
    backend = LinuxHpaBackend(SystemProbe(runner=fake, sysfs_root=tmp_path / "sys"))
    state: dict[str, Any] = {"override": {}}

    def row(path: str) -> dict[str, Any]:
        for item in conftest.FAKE_DEVICES:
            if item["device"]["path"] == path:
                return {**item["device"], **state["override"]}
        raise LookupError(path)

    monkeypatch.setattr("helper.daemon._hpa_backend", lambda: backend)
    monkeypatch.setattr(
        "helper.daemon._hpa_device", lambda path: Device.model_validate(row(path))
    )
    monkeypatch.setattr(
        "helper.authorization._fresh_hpa_probe", lambda path: {"device": row(path)}
    )
    fake.override = state["override"]  # type: ignore[attr-defined]
    return fake


def _finish(client: TestClient, services: AppServices, job_id: str) -> dict[str, Any]:
    services.registry.wait(job_id, timeout=30)
    return dict(client.get(f"/jobs/{job_id}").json())


def record_backup(
    client: TestClient, services: AppServices, *, verify: bool = True,
    size: int = 64 * MIB,
) -> str:
    image = services.evidence_dir / "sdz.img"
    with image.open("wb") as handle:
        handle.truncate(size)
    answer = client.post(
        "/workflow/backup", json={"backup_image": "sdz.img", "source_path": PATH}
    )
    assert answer.status_code == 200, answer.text
    status = _finish(client, services, answer.json()["job_id"])
    assert status["state"] == "complete", status
    backup_id = str(status["result"]["backup_id"])
    if verify:
        verified = client.post(f"/workflow/backup/{backup_id}/verify")
        assert verified.status_code == 200, verified.text
        done = _finish(client, services, verified.json()["job_id"])
        assert done["result"]["passed"] is True, done
    return backup_id


def open_hpa(client: TestClient, backup_id: str = "", **extra: Any) -> Any:
    return client.post(
        "/workflow/hidden-area", json={"path": PATH, "backup_id": backup_id, **extra}
    )


def approve(client: TestClient, auth_id: str, **over: Any) -> Any:
    body = {"typed_serial": SERIAL, "acknowledge_configuration_change": True}
    body.update(over)
    return client.post(f"/workflow/hidden-area/{auth_id}/approve", json=body)


def execute(client: TestClient, auth_id: str, **body: Any) -> Any:
    return client.post(f"/workflow/hidden-area/{auth_id}/execute", json=body)


def ready(client: TestClient, services: AppServices, **extra: Any) -> str:
    """Backup recorded and verified, workflow opened and approved."""
    backup_id = record_backup(client, services)
    opened = open_hpa(client, backup_id, **extra)
    assert opened.status_code == 200, opened.text
    auth_id = str(opened.json()["authorization_id"])
    over = {"acknowledge_permanent": True} if extra.get("volatile") is False else {}
    answer = approve(client, auth_id, **over)
    assert answer.status_code == 200, answer.text
    return auth_id


def _ops(services: AppServices) -> list[str]:
    return [entry.operation for entry in services.ledger().entries()]


# -- open ---------------------------------------------------------------------


def test_open_discovers_analyzes_and_plans_without_touching_the_drive(
    client: TestClient, drive: Drive
) -> None:
    answer = open_hpa(client)
    assert answer.status_code == 200, answer.text
    body = answer.json()
    assert body["kind"] == "hpa"
    state = body["hidden_area_state"]
    assert state["accessible_max_lba"] == ACCESSIBLE_SECTORS - 1
    assert state["native_max_lba"] == NATIVE_SECTORS - 1
    assert state["hidden_bytes"] == 6144 * 512
    plan = body["plan"]
    assert plan["volatile"] is True
    assert plan["operation"] == f"hdparm -N {NATIVE_SECTORS} {PATH}"
    assert plan["requested_accessible_max_lba"] == NATIVE_SECTORS - 1
    assert body["workflow"]["state"] == "ANALYZED"
    assert body["workflow"]["why_blocked"]
    assert body["workflow"]["next_action"]
    assert drive.sets == []


def test_an_unverified_backup_holds_the_workflow_at_analyzed(
    client: TestClient, services: AppServices, drive: Drive
) -> None:
    backup_id = record_backup(client, services, verify=False)
    body = open_hpa(client, backup_id).json()
    assert body["workflow"]["state"] == "ANALYZED"
    assert any("not been verified" in r for r in body["workflow"]["why_blocked"])
    assert approve(client, body["authorization_id"]).status_code == 409


def test_a_verified_backup_moves_the_workflow_to_approval(
    client: TestClient, services: AppServices, drive: Drive
) -> None:
    backup_id = record_backup(client, services)
    body = open_hpa(client, backup_id).json()
    assert body["workflow"]["state"] == "APPROVAL_REQUIRED", body["workflow"]


def test_a_backup_that_does_not_cover_the_accessible_range_is_refused(
    client: TestClient, services: AppServices, drive: Drive
) -> None:
    backup_id = record_backup(client, services, size=MIB)
    body = open_hpa(client, backup_id).json()
    assert body["workflow"]["state"] == "ANALYZED"
    assert any("does not cover" in r for r in body["workflow"]["why_blocked"])


def test_a_bridged_device_is_refused_and_reported(
    client: TestClient, drive: Drive
) -> None:
    answer = client.post("/workflow/hidden-area", json={"path": "/dev/sdy"})
    assert answer.status_code == 409
    detail = answer.json()["detail"]
    assert detail["workflow_state"] == "BLOCKED"
    assert "bridge" in " ".join(detail["WHY BLOCKED"])
    assert drive.calls == [], "nothing may be sent through a bridge"


def test_a_mounted_device_is_refused(client: TestClient, drive: Drive) -> None:
    drive.override["mounted_at"] = ["/mnt/x"]  # type: ignore[attr-defined]
    answer = open_hpa(client)
    assert answer.status_code == 409
    assert "mounted" in " ".join(answer.json()["detail"]["WHY BLOCKED"])


def test_a_drive_with_no_hpa_has_nothing_to_plan(
    client: TestClient, drive: Drive
) -> None:
    drive.native = drive.accessible
    answer = open_hpa(client)
    assert answer.status_code == 409
    assert "no HPA to remove" in " ".join(answer.json()["detail"]["WHY BLOCKED"])


def test_an_implausible_native_max_is_rejected(
    client: TestClient, drive: Drive
) -> None:
    drive.native = drive.accessible * 20
    answer = open_hpa(client)
    assert answer.status_code == 409
    assert "implausible" in " ".join(answer.json()["detail"]["WHY BLOCKED"])


# -- approve ------------------------------------------------------------------


def test_approval_needs_the_typed_serial_and_the_acknowledgement(
    client: TestClient, services: AppServices, drive: Drive
) -> None:
    backup_id = record_backup(client, services)
    auth_id = open_hpa(client, backup_id).json()["authorization_id"]
    assert approve(client, auth_id, typed_serial="WRONG").status_code == 409
    assert (
        approve(client, auth_id, acknowledge_configuration_change=False).status_code
        == 409
    )
    ok = approve(client, auth_id)
    assert ok.status_code == 200, ok.text
    assert ok.json()["workflow"]["state"] == "PLAN_READY"
    assert "hpa.approved" in _ops(services)
    assert approve(client, auth_id).status_code == 409, "approval is written once"


def test_a_permanent_plan_needs_a_second_acknowledgement(
    client: TestClient, services: AppServices, drive: Drive
) -> None:
    backup_id = record_backup(client, services)
    body = open_hpa(client, backup_id, volatile=False).json()
    assert body["plan"]["volatile"] is False
    assert body["plan"]["operation"] == f"hdparm -N p{NATIVE_SECTORS} {PATH}"
    auth_id = body["authorization_id"]
    refused = approve(client, auth_id)
    assert refused.status_code == 409
    assert "PERMANENT" in refused.json()["detail"]["error"]
    assert approve(client, auth_id, acknowledge_permanent=True).status_code == 200


# -- execute ------------------------------------------------------------------


def test_execute_without_a_typed_serial_is_refused_and_changes_nothing(
    client: TestClient, services: AppServices, drive: Drive
) -> None:
    """Execute is always the real change; without the serial it is refused."""
    auth_id = ready(client, services)
    answer = execute(client, auth_id)
    assert answer.status_code == 409, answer.text
    assert drive.sets == []
    assert drive.accessible == ACCESSIBLE_SECTORS
    assert client.get(f"/workflow/hidden-area/{auth_id}").json()["spent"] is False


@pytest.mark.parametrize("key", ["dry_run", "simulation", "simulate"])
def test_execute_rejects_a_simulation_switch(
    client: TestClient, services: AppServices, drive: Drive, key: str
) -> None:
    auth_id = ready(client, services)
    answer = execute(client, auth_id, typed_serial=SERIAL, **{key: True})
    assert answer.status_code == 422, answer.text
    assert drive.sets == []
    assert client.get(f"/workflow/hidden-area/{auth_id}").json()["spent"] is False


def test_a_real_change_is_volatile_verified_and_single_use(
    client: TestClient, services: AppServices, drive: Drive
) -> None:
    auth_id = ready(client, services)
    answer = execute(client, auth_id, typed_serial=SERIAL)
    assert answer.status_code == 200, answer.text
    status = _finish(client, services, answer.json()["job_id"])
    assert status["state"] == "complete", status
    result = status["result"]
    assert result["outcome"] == "COMPLETE"
    assert result["verification_passed"] is True
    assert result["volatile"] is True
    assert drive.sets == [("hdparm", "-N", str(NATIVE_SECTORS), PATH)]
    ops = _ops(services)
    for op in ("hpa.open", "hpa.approved", "hpa.plan", "hpa.modify", "hpa.verify",
               "hpa.complete"):
        assert op in ops, op
    assert services.ledger().verify().status.value == "VALID"
    view = client.get(f"/workflow/hidden-area/{auth_id}").json()
    assert view["workflow"]["state"] == "COMPLETE"
    again = execute(client, auth_id, typed_serial=SERIAL)
    assert again.status_code == 409
    assert "already used" in " ".join(again.json()["detail"]["WHY BLOCKED"])
    assert len(drive.sets) == 1


def test_a_real_change_needs_the_typed_serial(
    client: TestClient, services: AppServices, drive: Drive
) -> None:
    auth_id = ready(client, services)
    assert execute(client, auth_id).status_code == 409
    wrong = execute(client, auth_id, typed_serial="WRONG")
    assert wrong.status_code == 409
    assert drive.sets == []
    assert client.get(f"/workflow/hidden-area/{auth_id}").json()["spent"] is False


def test_an_unapproved_workflow_cannot_execute(
    client: TestClient, services: AppServices, drive: Drive
) -> None:
    backup_id = record_backup(client, services)
    auth_id = open_hpa(client, backup_id).json()["authorization_id"]
    answer = execute(client, auth_id, typed_serial=SERIAL)
    assert answer.status_code == 409
    assert answer.json()["detail"]["workflow_state"] == "APPROVAL_REQUIRED"
    assert drive.sets == []


def test_a_stale_plan_is_refused_at_the_api_gate(
    client: TestClient, services: AppServices, drive: Drive
) -> None:
    auth_id = ready(client, services)
    drive.native += 2048  # the drive's native max changed after approval
    answer = execute(client, auth_id, typed_serial=SERIAL)
    assert answer.status_code == 409
    assert "native max LBA" in " ".join(answer.json()["detail"]["WHY BLOCKED"])
    assert drive.sets == []


def test_a_stale_plan_is_refused_by_the_engine_too(
    client: TestClient,
    services: AppServices,
    drive: Drive,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The drive changes after the API gate passed: the engine's re-read refuses."""
    auth_id = ready(client, services)
    original = HpaHelper.call_stream

    def late_change(
        self: HpaHelper, method: str, params: dict[str, Any]
    ) -> Generator[dict[str, Any], None, dict[str, Any]]:
        if method == "run_hpa_change":
            drive.accessible -= 8
        return (yield from original(self, method, params))

    monkeypatch.setattr(HpaHelper, "call_stream", late_change)
    answer = execute(client, auth_id, typed_serial=SERIAL)
    status = _finish(client, services, answer.json()["job_id"])
    assert status["state"] == "failed", status
    assert "stale" in status["error"]
    assert drive.sets == []
    assert "hpa.blocked" in _ops(services)


# -- kind separation ---------------------------------------------------------


def test_an_hpa_authorization_cannot_be_spent_as_an_erase(
    client: TestClient, services: AppServices, drive: Drive, helper: HpaHelper
) -> None:
    auth_id = ready(client, services)
    answer = client.post(
        "/jobs/erase-drive",
        json={
            "path": PATH, "typed_serial": SERIAL,
            "authorization_id": auth_id,
        },
    )
    assert answer.status_code == 409
    assert "cannot authorize an erase" in " ".join(
        answer.json()["detail"]["WHY BLOCKED"]
    )
    assert [c for c in helper.calls if c[0] == "run_erase"] == []
    assert client.get(f"/workflow/erase-drive/{auth_id}").status_code == 404


def test_an_hpa_authorization_cannot_be_spent_as_a_restore(
    client: TestClient, services: AppServices, drive: Drive
) -> None:
    auth_id = ready(client, services)
    answer = client.post(
        f"/workflow/restore/{auth_id}/execute",
        json={"typed_serial": SERIAL},
    )
    assert answer.status_code == 409
    assert "cannot authorize a restore" in " ".join(
        answer.json()["detail"]["WHY BLOCKED"]
    )


def test_an_erase_authorization_cannot_be_spent_as_an_hpa_change(
    client: TestClient, services: AppServices, drive: Drive
) -> None:
    erase_id = authorize(client, services)
    answer = execute(client, erase_id, typed_serial=SERIAL)
    assert answer.status_code == 409
    assert "cannot authorize an HPA change" in " ".join(
        answer.json()["detail"]["WHY BLOCKED"]
    )
    assert client.get(f"/workflow/hidden-area/{erase_id}").status_code == 404
    assert drive.sets == []


def test_the_write_seams_keep_the_kinds_apart(
    client: TestClient, services: AppServices, drive: Drive
) -> None:
    """Each seam re-reads the record and refuses a kind that is not its own."""
    hpa_id = ready(client, services)
    erase_id = authorize(client, services)
    root = services.state_dir / "authorizations"
    hpa_record = json.loads((root / f"{hpa_id}.json").read_text())
    erase_record = json.loads((root / f"{erase_id}.json").read_text())

    with pytest.raises(WorkflowGateRefused, match="cannot authorize an erase"):
        revalidate_execution(
            {
                "path": PATH, "level": "HPA",
                "authorization": {"auth_id": hpa_id, **hpa_record},
                "authorization_dir": str(root),
            }
        )
    with pytest.raises(WorkflowGateRefused, match="cannot authorize an HPA change"):
        revalidate_hpa(
            {
                "path": PATH, "typed_serial": SERIAL,
                "authorization": {"auth_id": erase_id, **erase_record},
                "authorization_dir": str(root),
            }
        )


def test_the_write_seam_refuses_a_real_change_the_api_did_not_spend(
    client: TestClient, services: AppServices, drive: Drive
) -> None:
    auth_id = ready(client, services)
    root = services.state_dir / "authorizations"
    record = json.loads((root / f"{auth_id}.json").read_text())
    binding = {key: record[key] for key in ("path", "device", "backup", "plan")}
    with pytest.raises(WorkflowGateRefused, match="not consumed by the API gate"):
        revalidate_hpa(
            {
                "path": PATH, "typed_serial": SERIAL,
                "authorization": {"auth_id": auth_id, "kind": "hpa", **binding},
                "authorization_dir": str(root),
            }
        )
    assert not (root / f"{auth_id}.executed").exists()


def test_the_write_seam_refuses_a_tampered_plan(
    client: TestClient, services: AppServices, drive: Drive
) -> None:
    auth_id = ready(client, services)
    root = services.state_dir / "authorizations"
    path = root / f"{auth_id}.json"
    record = json.loads(path.read_text())
    record["plan"]["volatile"] = False
    path.write_text(json.dumps(record))
    binding = {key: record[key] for key in ("path", "device", "backup", "plan")}
    # As if the API gate had spent it, so the plan check is what refuses.
    (root / f"{auth_id}.spent").touch()
    with pytest.raises(WorkflowGateRefused, match="altered"):
        revalidate_hpa(
            {
                "path": PATH, "typed_serial": SERIAL,
                "authorization": {"auth_id": auth_id, "kind": "hpa", **binding},
                "authorization_dir": str(root),
            }
        )


def test_macos_is_refused_before_any_record_is_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("core.platform.host.family", lambda *a: "macos")
    generator = STREAMING_OPERATIONS["run_hpa_change"]({"path": PATH})
    with pytest.raises(PlatformUnsupported, match="macOS"):
        next(generator)
    with pytest.raises(PlatformUnsupported):
        OPERATIONS["discover_hidden_area"]({"path": PATH})
