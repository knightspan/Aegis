"""API gate and helper seam together, over the real helper dispatch.

Unlike the rest of the API suite, the helper here is ``InProcessHelper`` - the
real allowlist, the real ``run_erase`` handler and the real write-seam check -
over a *synthetic, mutable device*. Only two things are replaced: the host reads
(``get_device`` and the capability probe, which answer from a dict this test can
change) and the engine itself (a tripwire that records if it was entered). No
device is opened.

The second test is the approval-to-write race made deterministic: the device is
changed *after* the API gate has passed and *before* the helper starts, exactly
the window the API cannot see. The helper must refuse it.
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from api.authorization import AuthorizationStore
from api.deps import AppServices
from api.jobs import JobRegistry
from api.main import create_app
from core.models import Device, DeviceCapabilities, SanitizationLevel
from fastapi.testclient import TestClient
from helper.daemon import InProcessHelper

from tests._loopback import LOOPBACK_BASE_URL

from .conftest import MIB, approve_workflow, open_workflow

# The helper acts through the host's adapter, and only the Linux adapter has a
# whole-drive engine: macOS and Windows refuse the probe with PlatformUnsupported
# before the seam is reached, which tests/platform asserts on its own.
pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="the whole-drive write seam exists only on Linux"
)

REAL = {"path": "/dev/sdz", "typed_serial": "SYN-PURGE-1"}


class World:
    """The synthetic host: what the helper would read from the device now."""

    def __init__(self) -> None:
        self.fields: dict[str, Any] = {
            "path": "/dev/sdz",
            "model": "SYNTHETIC-PURGE",
            "serial": "SYN-PURGE-1",
            "size_bytes": 64 * MIB,
            "rotational": False,
            "transport": "sata",
            "is_system_disk": False,
            "mounted_at": [],
            "pt_type": "gpt",
            "by_id_path": None,
        }
        self.caps: dict[str, Any] = {
            "ata_security_erase": True,
            "ata_enhanced_erase": True,
            "ata_sanitize_ops": [],
            "nvme_sanicap": {},
            "is_sed_opal": False,
            "security_frozen": False,
            "est_erase_seconds": 120,
            "achievable_levels": {SanitizationLevel.CLEAR, SanitizationLevel.PURGE},
            "limitations": [],
        }
        self.engine_entries: list[Any] = []

    def device(self) -> Device:
        return Device(**self.fields)


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> World:
    state = World()
    monkeypatch.setattr(
        "core.device.enumerate.get_device", lambda path, *a, **k: state.device()
    )
    monkeypatch.setattr(
        "core.device.capabilities.probe",
        lambda device, *a, **k: DeviceCapabilities.model_validate(state.caps),
    )

    def engine(self: Any, params: dict[str, Any]) -> Any:
        state.engine_entries.append(params.get("path"))
        yield from ()
        return {"result": {}}

    for name in ("execute_drive_sanitization", "resume_drive_sanitization"):
        monkeypatch.setattr(f"core.platform.linux.LinuxAdapter.{name}", engine)
    return state


@pytest.fixture
def seam_services(tmp_path: Path, world: World) -> AppServices:
    built = AppServices(
        registry=JobRegistry(),
        helper=InProcessHelper(),
        state_dir=tmp_path / "state",
        key_dir=tmp_path / "keys",
    )
    built.prepare()
    return built


@pytest.fixture
def seam_client(seam_services: AppServices) -> Iterator[TestClient]:
    app = create_app(services=seam_services, serve_ui=False)
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as client:
        yield client


def _finish(client: TestClient, job_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        status = client.get(f"/jobs/{job_id}").json()
        if status["state"] != "running":
            return dict(status)
        time.sleep(0.02)
    raise AssertionError("the job did not finish")


def test_the_whole_chain_reaches_the_engine_through_the_real_helper(
    seam_client: TestClient, seam_services: AppServices, world: World
) -> None:
    auth_id = open_workflow(seam_client, seam_services)
    approve_workflow(seam_client, auth_id)
    accepted = seam_client.post(
        "/jobs/erase-drive", json={**REAL, "authorization_id": auth_id}
    )
    assert accepted.status_code == 200, accepted.text
    status = _finish(seam_client, accepted.json()["job_id"])
    assert status["state"] == "complete", status
    assert world.engine_entries == ["/dev/sdz"]
    # The binding is for the helper; a client reading the job never sees it.
    assert status["params"]["authorization"] == "<redacted>"
    assert status["params"]["authorization_dir"] == "<redacted>"


def test_a_device_changed_after_the_api_gate_is_refused_by_the_helper(
    seam_client: TestClient,
    seam_services: AppServices,
    world: World,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The window the API cannot see: after its gate, before the helper writes."""
    auth_id = open_workflow(seam_client, seam_services)
    approve_workflow(seam_client, auth_id)

    real_stream = seam_services.helper.call_stream

    def swapped_before_helper_starts(method: str, params: dict[str, Any]) -> Any:
        world.fields["model"] = (
            "A-DIFFERENT-DISK"  # model is not what typed serial covers
        )
        return real_stream(method, params)

    monkeypatch.setattr(
        seam_services.helper, "call_stream", swapped_before_helper_starts
    )
    accepted = seam_client.post(
        "/jobs/erase-drive", json={**REAL, "authorization_id": auth_id}
    )
    assert accepted.status_code == 200, "the API gate passed; that is the premise"
    status = _finish(seam_client, accepted.json()["job_id"])
    assert status["state"] == "failed"
    # The kind the helper raised, not the transport's: the UI shows this as a
    # refusal (BLOCKED), not as a failed erase of unknown outcome.
    assert status["error_kind"] == "WorkflowGateRefused"
    assert "model changed" in (status["error"] or "")
    assert "Nothing was erased" in (status["error"] or "")
    assert world.engine_entries == [], "the helper never entered the engine"
    assert not list(seam_services.reports_dir.rglob("*.json")), "no certificate"
    # The API had already spent it: fail closed, the operator opens a new one.
    assert AuthorizationStore(seam_services.state_dir / "authorizations").is_spent(
        auth_id
    )


def test_a_write_seam_refusal_reaches_the_case_as_a_refusal(
    seam_client: TestClient,
    seam_services: AppServices,
    world: World,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The case record carries the structured kind, so Cases can say BLOCKED.

    Without it the case screen and the overview see only ``failed`` and call a
    refusal that wrote nothing a failed, partially sanitizing erase.
    """
    opened = seam_client.post("/cases", json={"case_id": "CASE-SEAM-1"})
    assert opened.status_code == 200, opened.text
    auth_id = open_workflow(seam_client, seam_services)
    approve_workflow(seam_client, auth_id)
    real_stream = seam_services.helper.call_stream

    def swapped_before_helper_starts(method: str, params: dict[str, Any]) -> Any:
        world.fields["model"] = "A-DIFFERENT-DISK"
        return real_stream(method, params)

    monkeypatch.setattr(
        seam_services.helper, "call_stream", swapped_before_helper_starts
    )
    accepted = seam_client.post(
        "/jobs/erase-drive",
        json={**REAL, "authorization_id": auth_id, "case_id": "CASE-SEAM-1"},
    )
    job_id = accepted.json()["job_id"]
    assert _finish(seam_client, job_id)["error_kind"] == "WorkflowGateRefused"

    detail = seam_client.get("/cases/CASE-SEAM-1").json()
    [operation] = detail["operations"]
    assert operation["operation_id"] == job_id
    assert operation["status"] == "failed"
    assert operation["error_kind"] == "WorkflowGateRefused"
    assert "verification_passed" not in operation
    assert world.engine_entries == []


def test_a_failed_read_back_reaches_the_case_as_a_failed_verification(
    seam_client: TestClient,
    seam_services: AppServices,
    world: World,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A job that completes with a FAILED read-back is not a completed erasure."""

    def engine(self: Any, params: dict[str, Any]) -> Any:
        world.engine_entries.append(params.get("path"))
        yield from ()
        return {"result": {"verification": {"passed": False, "failed_offsets": [4096]}}}

    monkeypatch.setattr(
        "core.platform.linux.LinuxAdapter.execute_drive_sanitization", engine
    )
    opened = seam_client.post("/cases", json={"case_id": "CASE-READBACK-1"})
    assert opened.status_code == 200, opened.text
    auth_id = open_workflow(seam_client, seam_services)
    approve_workflow(seam_client, auth_id)
    accepted = seam_client.post(
        "/jobs/erase-drive",
        json={**REAL, "authorization_id": auth_id, "case_id": "CASE-READBACK-1"},
    )
    status = _finish(seam_client, accepted.json()["job_id"])
    assert status["state"] == "complete", status
    assert status["result"]["verification"]["passed"] is False

    [operation] = seam_client.get("/cases/CASE-READBACK-1").json()["operations"]
    assert operation["status"] == "complete"
    assert operation["verification_passed"] is False
    assert "error_kind" not in operation


def test_a_backup_changed_after_the_api_gate_is_refused_by_the_helper(
    seam_client: TestClient,
    seam_services: AppServices,
    world: World,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    auth_id = open_workflow(seam_client, seam_services)
    approve_workflow(seam_client, auth_id)
    real_stream = seam_services.helper.call_stream
    image = seam_services.evidence_dir / "backup.img"

    def edited_before_helper_starts(method: str, params: dict[str, Any]) -> Any:
        with image.open("r+b") as handle:
            handle.write(b"edited after the gate")
        return real_stream(method, params)

    monkeypatch.setattr(
        seam_services.helper, "call_stream", edited_before_helper_starts
    )
    accepted = seam_client.post(
        "/jobs/erase-drive", json={**REAL, "authorization_id": auth_id}
    )
    status = _finish(seam_client, accepted.json()["job_id"])
    assert status["state"] == "failed"
    assert status["error_kind"] == "WorkflowGateRefused"
    assert "backup" in (status["error"] or "")
    assert world.engine_entries == []


@pytest.mark.parametrize("key", ["dry_run", "simulation", "simulate"])
def test_the_real_helper_refuses_a_simulation_switch_at_the_write_seam(
    seam_services: AppServices, world: World, key: str
) -> None:
    """Even a caller that bypasses the API cannot ask the helper to rehearse.

    Handed straight to the in-process helper with an otherwise well-formed
    request, a removed simulation switch is refused before the adapter's
    engine is entered - it is neither run nor dropped.
    """
    from helper.rpc import RpcError

    stream = seam_services.helper.call_stream(
        "run_erase",
        {**REAL, key: True, "job_id": "erase-drive-x", "ledger_root": "/nonexistent"},
    )
    with pytest.raises(RpcError) as refused:
        next(stream)
    assert refused.value.kind == "WorkflowGateRefused"
    assert key in str(refused.value)
    assert world.engine_entries == []


def test_a_record_requested_after_a_refusal_claims_nothing_was_sanitized(
    seam_client: TestClient,
    seam_services: AppServices,
    world: World,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No certificate appears on its own, and one asked for documents a failure.

    A signed record of a refused job is legitimate - the audit trail needs it -
    but every section that could read as a sanitization claim must be empty or
    negative, and the refusal must be named inside the signed bytes.
    """
    auth_id = open_workflow(seam_client, seam_services)
    approve_workflow(seam_client, auth_id)
    real_stream = seam_services.helper.call_stream

    def swapped(method: str, params: dict[str, Any]) -> Any:
        world.fields["serial"] = "ANOTHER-SERIAL"
        return real_stream(method, params)

    monkeypatch.setattr(seam_services.helper, "call_stream", swapped)
    job_id = seam_client.post(
        "/jobs/erase-drive", json={**REAL, "authorization_id": auth_id}
    ).json()["job_id"]
    assert _finish(seam_client, job_id)["state"] == "failed"
    assert not list(seam_services.reports_dir.rglob("*.json"))

    answer = seam_client.post(
        f"/reports/{job_id}", json={"case_id": "CASE-REFUSED", "operator": "t"}
    )
    assert answer.status_code == 200, answer.text
    document = json.loads(Path(answer.json()["json_path"]).read_text())
    sections = document["sections"]
    assert sections["case_identity"]["job_state"] == "failed"
    caveat = sections["limitations"]["items"][0]
    assert "WorkflowGateRefused" in caveat and "Nothing was erased" in caveat
    assert sections["method"]["level_achieved"] == ""
    assert sections["verification"]["passed"] is False
    assert sections["residual_risk"]["purge_achieved"] is False
    assert world.engine_entries == []
