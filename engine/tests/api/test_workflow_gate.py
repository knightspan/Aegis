"""API CANNOT BYPASS WORKFLOW SAFETY GATES.

Judge-facing security property: a real drive erase cannot start through the API
unless the same state the workflow state machine (``core/workflow.py``) requires
for PLAN_READY has been reached - recorded human approval, verified backup,
unchanged device identity, achievable level, no mounted or system disk. The
typed serial is a confirmation token and never substitutes for any of them.

Every refusal below must be a structured REFUSED with a ``WHY BLOCKED`` list and
must show the fake helper received no ``run_erase`` call, which is the only path
that writes. No test opens a real device.
"""

from __future__ import annotations

import copy
import time
from typing import Any

import pytest
from api.deps import AppServices
from fastapi.testclient import TestClient

from . import conftest
from .conftest import RecordingHelper, approve_workflow, authorize, open_workflow

REAL = {"path": "/dev/sdz", "typed_serial": "SYN-PURGE-1"}


def _writes(helper: RecordingHelper) -> list[str]:
    return [name for name, _ in helper.calls if name in {"run_erase", "resume_erase"}]


def _assert_refused(
    answer: Any, helper: RecordingHelper, services: AppServices
) -> dict[str, Any]:
    assert answer.status_code == 409, answer.text
    detail = answer.json()["detail"]
    assert detail["verdict"] == "REFUSED"
    assert detail["kind"] == "WorkflowGateRefused"
    assert detail["WHY BLOCKED"], "the refusal must name the missing prerequisite"
    assert detail["physical_device_modified"] is False
    assert _writes(helper) == [], "no write path may be reached on a refusal"
    assert not list(services.reports_dir.glob("*")), "no certificate on a refusal"
    return dict(detail)


def test_api_cannot_bypass_workflow_safety_gates(
    client: TestClient, helper: RecordingHelper, services: AppServices
) -> None:
    """Case A: correct device, correct serial, no workflow."""
    answer = client.post("/jobs/erase-drive", json=REAL)
    detail = _assert_refused(answer, helper, services)
    assert any("approv" in reason for reason in detail["WHY BLOCKED"])


def test_an_invented_authorization_id_is_refused(
    client: TestClient, helper: RecordingHelper, services: AppServices
) -> None:
    answer = client.post(
        "/jobs/erase-drive", json={**REAL, "authorization_id": "auth-0000000000000000"}
    )
    _assert_refused(answer, helper, services)


def test_plan_ready_without_human_approval_is_refused(
    client: TestClient, helper: RecordingHelper, services: AppServices
) -> None:
    """Case B: backup verified, plan generated, nobody approved."""
    auth_id = open_workflow(client, services)
    state = client.get(f"/workflow/erase-drive/{auth_id}").json()["workflow"]
    assert state["state"] == "HUMAN_APPROVAL_REQUIRED"

    detail = _assert_refused(
        client.post("/jobs/erase-drive", json={**REAL, "authorization_id": auth_id}),
        helper,
        services,
    )
    assert detail["workflow_state"] == "HUMAN_APPROVAL_REQUIRED"


def test_approval_needs_the_ack_and_the_serial_not_the_serial_alone(
    client: TestClient, services: AppServices
) -> None:
    auth_id = open_workflow(client, services)
    for body in (
        {"typed_serial": "SYN-PURGE-1"},
        {"typed_serial": "WRONG", "acknowledge_data_destruction": True},
    ):
        answer = client.post(f"/workflow/erase-drive/{auth_id}/approve", json=body)
        assert answer.status_code == 409
    assert client.get(f"/workflow/erase-drive/{auth_id}").json()["approved"] is False


def test_approval_without_a_verified_backup_is_refused(
    client: TestClient, helper: RecordingHelper, services: AppServices
) -> None:
    """Case C: an approval cannot exist without a backup, and a backup that
    disappears after approval blocks execution."""
    too_small = client.post(
        "/workflow/erase-drive",
        json={"path": "/dev/sdz", "backup_image": "missing.img"},
    )
    assert too_small.status_code in {400, 409, 422}
    conftest.make_backup(services, size=1024, name="tiny.img")
    tiny = client.post(
        "/workflow/erase-drive", json={"path": "/dev/sdz", "backup_image": "tiny.img"}
    )
    assert tiny.status_code == 422, "a backup smaller than the device is not a backup"

    auth_id = authorize(client, services)
    (services.evidence_dir / "backup.img").unlink()
    detail = _assert_refused(
        client.post("/jobs/erase-drive", json={**REAL, "authorization_id": auth_id}),
        helper,
        services,
    )
    assert detail["workflow_state"] == "BACKUP_REQUIRED"


def test_a_modified_backup_image_is_refused(
    client: TestClient, helper: RecordingHelper, services: AppServices
) -> None:
    auth_id = authorize(client, services)
    with (services.evidence_dir / "backup.img").open("r+b") as handle:
        handle.truncate(1024)
    _assert_refused(
        client.post("/jobs/erase-drive", json={**REAL, "authorization_id": auth_id}),
        helper,
        services,
    )


def test_identity_change_before_execution_is_refused(
    client: TestClient,
    helper: RecordingHelper,
    services: AppServices,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Case D: backup verified and approved, then the device serial changes."""
    auth_id = authorize(client, services)
    swapped = copy.deepcopy(conftest.FAKE_DEVICES)
    swapped[0]["device"]["serial"] = "SWAPPED-9"
    monkeypatch.setattr(conftest, "FAKE_DEVICES", swapped)

    detail = _assert_refused(
        client.post(
            "/jobs/erase-drive",
            json={**REAL, "typed_serial": "SWAPPED-9", "authorization_id": auth_id},
        ),
        helper,
        services,
    )
    assert any("serial" in reason for reason in detail["WHY BLOCKED"])


def test_all_gates_satisfied_reaches_the_execution_path_once(
    client: TestClient, helper: RecordingHelper, services: AppServices
) -> None:
    """Case E: every gate genuinely satisfied, against the synthetic helper."""
    auth_id = authorize(client, services)
    body = {**REAL, "authorization_id": auth_id}

    first = client.post("/jobs/erase-drive", json=body)
    assert first.status_code == 200, first.text
    assert set(first.json()) == {"job_id", "kind", "state", "stream_url"}
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and _writes(helper) == []:
        time.sleep(0.02)
    assert _writes(helper) == ["run_erase"], "the existing execution path ran"

    # One authorization authorizes one execution.
    again = client.post("/jobs/erase-drive", json=body)
    assert again.status_code == 409
    assert "already used" in " ".join(again.json()["detail"]["WHY BLOCKED"])


def test_a_refusal_is_recorded_in_the_ledger(
    client: TestClient, services: AppServices
) -> None:
    client.post("/jobs/erase-drive", json=REAL)
    operations = [entry.operation for entry in services.ledger().entries()]
    assert "erase.refused" in operations


def test_an_approval_is_bound_to_its_device(
    client: TestClient, helper: RecordingHelper, services: AppServices
) -> None:
    auth_id = authorize(client, services)
    detail = _assert_refused(
        client.post(
            "/jobs/erase-drive",
            json={
                "path": "/dev/sdy",
                "typed_serial": "SYN-CLEAR-2",
                "authorization_id": auth_id,
            },
        ),
        helper,
        services,
    )
    assert any("/dev/sdz" in reason for reason in detail["WHY BLOCKED"])


def test_a_mounted_device_cannot_open_a_workflow(
    client: TestClient,
    services: AppServices,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mounted = copy.deepcopy(conftest.FAKE_DEVICES)
    mounted[0]["device"]["mounted_at"] = ["/run/media/x/STICK"]
    monkeypatch.setattr(conftest, "FAKE_DEVICES", mounted)
    conftest.make_backup(services)
    answer = client.post(
        "/workflow/erase-drive", json={"path": "/dev/sdz", "backup_image": "backup.img"}
    )
    assert answer.status_code == 409
    assert answer.json()["detail"]["kind"] == "MountedRefused"


def test_a_real_resume_needs_the_gate_too(
    client: TestClient, helper: RecordingHelper, services: AppServices
) -> None:
    from tests.api.test_resume import _checkpoint, _plan

    _plan(services, "erase-drive-abc", "SINGLE_PASS_OVERWRITE")
    _checkpoint(services, "erase-drive-abc", 1024)
    answer = client.post(
        "/jobs/erase-drive-abc/resume",
        json={"typed_serial": "SYN-PURGE-1"},
    )
    _assert_refused(answer, helper, services)


def test_there_is_no_approval_free_mode(
    client: TestClient, helper: RecordingHelper, services: AppServices
) -> None:
    """Case F. Once a rehearsal ran without approval; now nothing does.

    A bare body is a real erase with nothing authorized, and a body asking for
    the removed rehearsal is rejected before anything else is looked at.
    """
    bare = client.post("/jobs/erase-drive", json={"path": "/dev/sdz"})
    assert bare.status_code == 409
    assert bare.json()["detail"]["verdict"] == "REFUSED"
    rehearsal = client.post(
        "/jobs/erase-drive", json={"path": "/dev/sdz", "dry_run": True}
    )
    assert rehearsal.status_code == 422
    assert _writes(helper) == []
    assert not list(services.reports_dir.glob("*"))


def test_approve_helper_is_used_by_the_positive_path(
    client: TestClient, services: AppServices
) -> None:
    auth_id = open_workflow(client, services)
    approve_workflow(client, auth_id)
    state = client.get(f"/workflow/erase-drive/{auth_id}").json()["workflow"]
    assert state["state"] == "PLAN_READY"
