"""Every workflow failure class answers in its own structured, honest shape.

The classes must stay distinct: a safety *refusal* (409 with a verdict and a
WHY BLOCKED list), an unavailable device (410), a platform/helper problem (501),
a malformed request (422), and an *unexpected* failure (500 ``InternalError``
with an incident id). None may carry a traceback or a host path, none may
present as SAFE or COMPLETE, and none may reach a write.
"""

from __future__ import annotations

import os
import stat
import sys
from typing import Any

import pytest
from api.authorization import AuthorizationStore
from api.deps import AppServices
from api.main import create_app
from fastapi.testclient import TestClient
from helper.rpc import RpcError

from tests._loopback import LOOPBACK_BASE_URL

from .conftest import RecordingHelper, approve_workflow, make_backup, open_workflow


@pytest.fixture
def tolerant(services: AppServices) -> TestClient:
    """A client that returns the 500 the server sends instead of re-raising it."""
    app = create_app(services=services, serve_ui=False)
    return TestClient(app, base_url=LOOPBACK_BASE_URL, raise_server_exceptions=False)


OPEN = {"path": "/dev/sdz", "backup_image": "backup.img"}
REAL = {"path": "/dev/sdz", "typed_serial": "SYN-PURGE-1"}


def _writes(helper: RecordingHelper) -> list[Any]:
    return [
        c for c in helper.calls if c[0] == "run_erase"
    ]


def _clean(answer: Any) -> dict[str, Any]:
    text = answer.text
    assert "Traceback" not in text and 'File "' not in text
    return dict(answer.json()["detail"] if "detail" in answer.json() else answer.json())


def test_a_missing_device_is_410_device_vanished(
    client: TestClient, services: AppServices, helper: RecordingHelper
) -> None:
    make_backup(services)
    for path in ("/dev/does-not-exist", "/dev/disk/by-id/ata-STALE_LINK_123"):
        answer = client.post("/workflow/erase-drive", json={**OPEN, "path": path})
        assert answer.status_code == 410
        detail = _clean(answer)
        assert detail["kind"] == "DeviceVanished" and detail["remediation"]
        assert "verdict" not in detail, "unavailable is not a safety refusal"
    assert _writes(helper) == []


def test_a_missing_backup_is_refused_with_what_to_do(
    client: TestClient, services: AppServices
) -> None:
    answer = client.post(
        "/workflow/erase-drive", json={**OPEN, "backup_image": "nope.img"}
    )
    assert answer.status_code == 422
    detail = _clean(answer)
    assert detail["kind"] == "EvidenceIntegrityError"
    assert "backup" in detail["remediation"].lower()


def test_a_backup_path_outside_the_evidence_directory_is_refused(
    client: TestClient, services: AppServices
) -> None:
    answer = client.post(
        "/workflow/erase-drive", json={**OPEN, "backup_image": "../../etc/passwd"}
    )
    assert answer.status_code in {400, 422}
    assert "root:" not in answer.text


def test_malformed_requests_are_422_not_500(client: TestClient) -> None:
    assert (
        client.post("/workflow/erase-drive", json={"path": "/dev/sdz"}).status_code
        == 422
    )
    assert client.post("/workflow/erase-drive", content=b"{not json").status_code == 422
    bad_level = client.post("/workflow/erase-drive", json={**OPEN, "level": "GUTMANN"})
    assert bad_level.status_code == 422


def test_a_malformed_authorization_id_is_unknown_not_a_crash(
    client: TestClient, helper: RecordingHelper
) -> None:
    for bad in ("../../etc/passwd", "auth-XYZ", "", "auth-0123456789abcdef0"):
        got = client.get(f"/workflow/erase-drive/{bad}")
        assert got.status_code in {404, 405}
        assert "Traceback" not in got.text
    exec_answer = client.post(
        "/jobs/erase-drive", json={**REAL, "authorization_id": "../../etc/passwd"}
    )
    assert exec_answer.status_code == 409
    assert exec_answer.json()["detail"]["verdict"] == "REFUSED"
    assert _writes(helper) == []


def test_approval_is_written_once_and_never_after_use(
    client: TestClient, services: AppServices
) -> None:
    auth_id = open_workflow(client, services)
    approve_workflow(client, auth_id)
    again = client.post(
        f"/workflow/erase-drive/{auth_id}/approve",
        json={"typed_serial": "SYN-PURGE-1", "acknowledge_data_destruction": True},
    )
    assert again.status_code == 409
    assert "already approved" in again.json()["detail"]["error"]

    assert (
        client.post(
            "/jobs/erase-drive", json={**REAL, "authorization_id": auth_id}
        ).status_code
        == 200
    )
    late = client.post(
        f"/workflow/erase-drive/{auth_id}/approve",
        json={"typed_serial": "SYN-PURGE-1", "acknowledge_data_destruction": True},
    )
    assert late.status_code == 409
    assert "already used" in late.json()["detail"]["error"]
    approvals = [
        e for e in services.ledger().entries() if e.operation == "erase.approved"
    ]
    assert len(approvals) == 1


@pytest.mark.skipif(
    sys.platform == "win32", reason="NT file modes cannot make a file unreadable"
)
@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores file modes"
)
def test_an_unreadable_backup_is_an_internal_error_not_a_safety_refusal(
    tolerant: TestClient, services: AppServices, helper: RecordingHelper
) -> None:
    """Unexpected I/O keeps its own kind: no verdict, no host path, no write."""
    image = make_backup(services)
    image.chmod(0)
    try:
        answer = tolerant.post("/workflow/erase-drive", json=OPEN)
    finally:
        image.chmod(stat.S_IRUSR | stat.S_IWUSR)
    assert answer.status_code == 500
    body = answer.json()
    assert body["kind"] == "InternalError" and body["incident"]
    assert "verdict" not in body and "WHY BLOCKED" not in body
    assert str(image) not in answer.text and "Permission denied" not in answer.text
    assert _writes(helper) == []
    assert not list((services.state_dir / "authorizations").glob("*.json"))


def test_a_helper_that_cannot_be_reached_is_501_not_a_refusal(
    client: TestClient, services: AppServices, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_backup(services)

    def down(method: str, params: dict[str, Any]) -> Any:
        raise OSError(111, "Connection refused: /run/sanctum/helper.sock")

    monkeypatch.setattr(services.helper, "call", down)
    answer = client.post("/workflow/erase-drive", json=OPEN)
    assert answer.status_code == 501
    detail = _clean(answer)
    assert detail["kind"] == "PlatformUnsupported" and "verdict" not in detail


def test_an_unexpected_probe_exception_is_500_with_no_leak(
    tolerant: TestClient, services: AppServices, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_backup(services)

    def boom(method: str, params: dict[str, Any]) -> Any:
        raise RuntimeError("secret internal detail at /var/lib/sanctum/x")

    monkeypatch.setattr(services.helper, "call", boom)
    answer = tolerant.post("/workflow/erase-drive", json=OPEN)
    assert answer.status_code == 500
    assert answer.json()["kind"] == "InternalError"
    assert "secret internal detail" not in answer.text
    assert "/var/lib/sanctum" not in answer.text


def test_a_helper_error_of_an_unknown_kind_is_not_dressed_as_a_refusal(
    client: TestClient, services: AppServices, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_backup(services)

    def io_error(method: str, params: dict[str, Any]) -> Any:
        raise RpcError(
            "read error on device", remediation="check cabling", kind="IOError"
        )

    monkeypatch.setattr(services.helper, "call", io_error)
    answer = client.post("/workflow/erase-drive", json=OPEN)
    assert answer.status_code not in {200, 409}
    detail = _clean(answer)
    assert detail["kind"] == "IOError" and "verdict" not in detail


def test_the_device_vanishing_before_execution_refuses_and_spends_nothing(
    client: TestClient,
    services: AppServices,
    helper: RecordingHelper,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    auth_id = open_workflow(client, services)
    approve_workflow(client, auth_id)
    real_call = helper.call

    def gone(method: str, params: dict[str, Any]) -> Any:
        if method == "probe_capabilities":
            raise RpcError(
                "device gone", remediation="reconnect", kind="DeviceVanished"
            )
        return real_call(method, params)

    monkeypatch.setattr(helper, "call", gone)
    answer = client.post(
        "/jobs/erase-drive", json={**REAL, "authorization_id": auth_id}
    )
    assert answer.status_code == 410
    assert _writes(helper) == []
    assert not AuthorizationStore(services.state_dir / "authorizations").is_spent(
        auth_id
    )


def test_no_certificate_exists_for_a_refused_erase(
    client: TestClient, services: AppServices
) -> None:
    client.post("/jobs/erase-drive", json=REAL)
    assert not list(services.reports_dir.glob("*"))
