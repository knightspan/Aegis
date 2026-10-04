"""Every endpoint, and the two properties that must not regress.

The properties, stated once so the tests below can be read as instances of
them:

1. **An incomplete request never wipes anything, and there is no rehearsal
   switch to forget.** Every destructive body is a real operation, refused
   unless its confirmation (and, for a device, its authorization) is present.
   A body that still carries ``dry_run``, ``simulation`` or ``simulate`` is
   rejected with 422 rather than executed or ignored.
2. **A mismatched serial is refused with the core's own remediation text.** The
   API does not paraphrase it. An operator reads the sentence the library
   author wrote, not the API author's guess about a subsystem it does not
   implement.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from api.deps import AppServices
from fastapi.testclient import TestClient

from tests._loopback import LOOPBACK_BASE_URL

from .conftest import RecordingHelper, authorize

CONFIRMATION_REMEDIATION = (
    "Re-read the device serial from the capability report and type it exactly."
)


# --------------------------------------------------------------------------
# Devices
# --------------------------------------------------------------------------


def test_devices_returns_capability_and_hidden_area_reports(
    client: TestClient,
) -> None:
    answer = client.get("/devices").json()

    assert len(answer["devices"]) == 3
    first = answer["devices"][0]
    assert first["device"]["serial"] == "SYN-PURGE-1"
    assert first["capabilities"]["ata_sanitize_ops"] == ["BLOCK_ERASE_EXT"]
    assert first["hidden_areas"]["hidden_bytes"] == 3145728


def test_a_failed_probe_does_not_fail_the_whole_list(client: TestClient) -> None:
    """A USB bridge that blocks pass-through is the common case, not an error.

    A device list that returned 500 because one disk could not be interrogated
    would be useless on exactly the hardware an operator most needs to look at.
    """
    answer = client.get("/devices").json()
    system_disk = answer["devices"][2]

    assert system_disk["capabilities"] is None
    assert "root filesystem" in system_disk["capability_error"]


def test_devices_reports_helper_failure_as_a_limitation_not_a_500(
    services: object, tmp_path: Path
) -> None:
    """An unreachable helper must be actionable, and a 500 is not."""
    from api.deps import AppServices
    from api.jobs import JobRegistry
    from api.main import create_app

    class Unreachable:
        def call(self, method: str, params: dict[str, object]) -> dict[str, object]:
            raise OSError("connection refused")

    broken = AppServices(
        registry=JobRegistry(),
        helper=Unreachable(),
        state_dir=tmp_path / "state",
    )
    broken.prepare()
    with TestClient(
        create_app(services=broken, serve_ui=False), base_url=LOOPBACK_BASE_URL
    ) as probe:
        answer = probe.get("/devices")

    assert answer.status_code == 200
    assert answer.json()["devices"] == []
    assert any("helper" in item for item in answer.json()["limitations"])


# --------------------------------------------------------------------------
# No rehearsal mode, and an incomplete request is refused
# --------------------------------------------------------------------------


def test_an_erase_drive_body_with_nothing_confirmed_never_reaches_the_helper(
    client: TestClient, helper: RecordingHelper
) -> None:
    """The single most important assertion in this file.

    A body with no serial and no authorization must write nothing. It used to
    start a rehearsal; with no rehearsal left it is refused outright, before
    the helper is asked anything.
    """
    answer = client.post("/jobs/erase-drive", json={"path": "/dev/sdz"})

    assert answer.status_code == 409
    assert answer.json()["detail"]["kind"] == "ConfirmationMismatch"
    assert helper.calls == [], "nothing should reach the helper at all"


def test_erase_files_without_confirm_is_refused_and_writes_nothing(
    client: TestClient, tmp_path: Path
) -> None:
    target = tmp_path / "keep.bin"
    target.write_bytes(b"intact")

    answer = client.post("/jobs/erase-files", json={"paths": [str(target)]})

    assert answer.status_code == 409
    detail = answer.json()["detail"]
    assert detail["kind"] == "ConfirmationMismatch"
    assert "confirm" in detail["error"]
    assert target.read_bytes() == b"intact", "an unconfirmed request wrote to disk"


@pytest.mark.parametrize(
    ("route", "body"),
    [
        ("/jobs/erase-drive", {"path": "/dev/sdz", "typed_serial": "SYN-PURGE-1"}),
        ("/jobs/erase-files", {"paths": ["/tmp/x"], "confirm": True}),
        ("/jobs/wipe-free-space", {"mount_point": "/mnt/x", "typed_identifier": "x"}),
        ("/jobs/erase-drive-abc/resume", {"typed_serial": "SYN-PURGE-1"}),
        ("/workflow/restore/rst-x/execute", {"typed_serial": "SYN-PURGE-1"}),
        ("/workflow/hidden-area/hpa-x/execute", {"typed_serial": "SYN-PURGE-1"}),
        ("/devices/prepare", {"path": "disk4", "typed_serial": "S"}),
    ],
)
@pytest.mark.parametrize("key", ["dry_run", "simulation", "simulate"])
@pytest.mark.parametrize("value", [True, False])
def test_every_destructive_route_rejects_a_simulation_switch(
    client: TestClient,
    helper: RecordingHelper,
    tmp_path: Path,
    route: str,
    body: dict[str, Any],
    key: str,
    value: bool,
) -> None:
    """A removed simulation switch is rejected, whatever its value.

    Honouring it is impossible (there is no simulation) and ignoring it would
    run for real a request whose sender expected nothing to be written.
    """
    answer = client.post(route, json={**body, key: value})
    assert answer.status_code == 422, answer.text
    assert key in answer.text
    assert helper.calls == [], "a rejected body must not reach the helper"


# --------------------------------------------------------------------------
# Serial confirmation
# --------------------------------------------------------------------------


def test_a_mismatched_serial_is_refused_with_the_remediation_verbatim(
    client: TestClient, helper: RecordingHelper
) -> None:
    answer = client.post(
        "/jobs/erase-drive",
        json={"path": "/dev/sdz", "typed_serial": "WRONG"},
    )

    assert answer.status_code == 409
    detail = answer.json()["detail"]
    assert detail["kind"] == "ConfirmationMismatch"
    assert detail["remediation"] == CONFIRMATION_REMEDIATION, (
        "the remediation must cross the boundary verbatim, not paraphrased"
    )
    assert "SYN-PURGE-1" in detail["error"]

    assert not [name for name, _ in helper.calls if name == "run_erase"], (
        "a refused request must never reach the erase handler"
    )


def test_a_missing_serial_is_refused_before_the_helper(
    client: TestClient, helper: RecordingHelper
) -> None:
    answer = client.post(
        "/jobs/erase-drive", json={"path": "/dev/sdz", "authorization_id": "x"}
    )

    assert answer.status_code == 409
    assert answer.json()["detail"]["kind"] == "ConfirmationMismatch"
    assert helper.calls == [], "nothing should reach the helper at all"


def test_a_matching_serial_is_accepted(
    client: TestClient, services: AppServices
) -> None:
    answer = client.post(
        "/jobs/erase-drive",
        json={
            "path": "/dev/sdz",
            "typed_serial": "SYN-PURGE-1",
            "authorization_id": authorize(client, services),
        },
    )

    assert answer.status_code == 200
    assert answer.json()["kind"] == "erase-drive"


def test_the_typed_serial_is_never_echoed_back(
    client: TestClient, services: AppServices
) -> None:
    """It is a confirmation token, not a fact worth repeating.

    Echoing it into a UI that may be screen-shared, or into a browser cache,
    spreads the one string that authorises a destructive operation.
    """
    accepted = client.post(
        "/jobs/erase-drive",
        json={
            "path": "/dev/sdz",
            "typed_serial": "SYN-PURGE-1",
            "authorization_id": authorize(client, services),
        },
    ).json()

    status = client.get(f"/jobs/{accepted['job_id']}").json()
    assert status["params"]["typed_serial"] == "<redacted>"
    assert "SYN-PURGE-1" not in json.dumps(status["params"])


def test_an_unknown_device_is_refused_with_its_remediation(
    client: TestClient,
) -> None:
    answer = client.post("/jobs/erase-drive", json={"path": "/dev/nope"})

    assert answer.status_code in {409, 410}
    assert answer.json()["detail"]["remediation"]


# --------------------------------------------------------------------------
# Acquire and carve
# --------------------------------------------------------------------------


def test_acquire_rejects_a_missing_source(client: TestClient) -> None:
    answer = client.post(
        "/jobs/acquire", json={"source": "/nope.dd", "dest": "/tmp/out.dd"}
    )
    assert answer.status_code == 422
    assert answer.json()["detail"]["kind"] == "EvidenceIntegrityError"


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="about a host that is not Windows; on Windows the path is a real device "
    "path, covered by tests/carve/test_platform_sources.py",
)
def test_acquire_of_a_win32_device_off_windows_says_why(
    client: TestClient,
) -> None:
    # A Win32 device path on a host that is not Windows is refused by name,
    # never reported as "not found".
    answer = client.post(
        "/jobs/acquire",
        json={"source": "\\\\.\\PhysicalDrive2", "dest": "/tmp/out.dd"},
    )
    assert answer.status_code == 422
    detail = answer.json()["detail"]
    assert detail["kind"] == "EvidenceIntegrityError"
    assert "not Windows" in detail["error"]
    assert "not found" not in detail["error"]


def test_carve_rejects_a_missing_image(client: TestClient) -> None:
    answer = client.post("/jobs/carve", json={"image": "/nope.dd"})
    assert answer.status_code == 422
    assert answer.json()["detail"]["kind"] == "EvidenceIntegrityError"


# --------------------------------------------------------------------------
# Job lifecycle
# --------------------------------------------------------------------------


def test_an_unknown_job_is_a_clean_error_not_a_traceback(
    client: TestClient,
) -> None:
    answer = client.get("/jobs/does-not-exist")
    assert answer.status_code in {409, 410}
    assert "remediation" in answer.json()["detail"]
    assert "Traceback" not in answer.text


def test_cancel_is_accepted_and_recorded(
    client: TestClient, services: AppServices
) -> None:
    accepted = client.post(
        "/jobs/erase-drive",
        json={
            "path": "/dev/sdz",
            "typed_serial": "SYN-PURGE-1",
            "authorization_id": authorize(client, services),
        },
    ).json()
    answer = client.post(f"/jobs/{accepted['job_id']}/cancel")
    assert answer.status_code == 200
    assert "cancel_requested" in answer.json()


def test_job_status_carries_its_ledger_entries(
    client: TestClient, tmp_path: Path
) -> None:
    """The registry's buffer dies with the process; the chain does not.

    That is what makes a job resumable beyond a page reload, and it is why the
    status endpoint joins the two.
    """
    target = tmp_path / "f.bin"
    target.write_bytes(b"x" * 64)
    accepted = client.post(
        "/jobs/erase-files",
        json={"paths": [str(target)], "confirm": True, "sweep_traces": False},
    ).json()

    import time

    for _ in range(200):
        status = client.get(f"/jobs/{accepted['job_id']}").json()
        if status["state"] in {"complete", "failed"}:
            break
        time.sleep(0.02)

    assert status["state"] == "complete", status.get("error")
    assert status["ledger_entries"], "the file erase must have ledgered its phases"


# --------------------------------------------------------------------------
# Ledger
# --------------------------------------------------------------------------


def test_ledger_verify_reports_a_valid_chain(client: TestClient) -> None:
    answer = client.get("/ledger/verify")
    assert answer.status_code == 200
    assert answer.json()["status"] in {"VALID", "EMPTY"}


def test_ledger_entries_come_back_newest_first(
    client: TestClient, tmp_path: Path
) -> None:
    target = tmp_path / "f.bin"
    target.write_bytes(b"x" * 32)
    client.post("/jobs/erase-files", json={"paths": [str(target)]})

    import time

    time.sleep(0.6)
    entries = client.get("/ledger/entries").json()["entries"]
    if len(entries) > 1:
        assert entries[0]["seq"] > entries[-1]["seq"]


# --------------------------------------------------------------------------
# Transport safety
# --------------------------------------------------------------------------


def test_every_response_carries_a_restrictive_csp(client: TestClient) -> None:
    """`default-src 'self'` makes an accidental CDN link fail loudly.

    Without it a stray external reference works on the developer's machine and
    breaks at the venue, which is the worst possible place to find out.
    """
    headers = client.get("/health").headers
    policy = headers["Content-Security-Policy"]
    assert "default-src 'self'" in policy
    assert "connect-src 'self'" in policy
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Referrer-Policy"] == "no-referrer"


def test_the_interactive_docs_are_not_served(client: TestClient) -> None:
    """FastAPI's default Swagger UI loads its assets from a CDN."""
    assert client.get("/docs").status_code in {404, 405}
    assert client.get("/redoc").status_code in {404, 405}


def test_the_app_is_configured_for_loopback_only() -> None:
    from api.main import LOOPBACK_HOST

    assert LOOPBACK_HOST == "127.0.0.1"

    source = Path("api/main.py").read_text(encoding="utf-8")
    assert "0.0.0.0" not in source, (
        "binding a wildcard address would make this a remote wipe primitive"
    )


# --------------------------------------------------------------------------
# The unhandled-exception handler discloses nothing about this host
# --------------------------------------------------------------------------


def test_an_unanticipated_failure_returns_an_incident_id_and_not_the_message(
    services: AppServices,
) -> None:
    """The body used to be ``f"{type(exc).__name__}: {exc}"``.

    The exceptions that reach this handler are the ones nobody anticipated, and
    their messages quote host paths: "[Errno 13] Permission denied:
    '/var/lib/sanctum/ledger/chain.jsonl'". An error a layer *did* anticipate
    carries a remediation its author wrote and is returned verbatim long before
    it could get here, so reaching this handler means there is no such sentence
    to pass through.
    """
    from api.main import create_app
    from fastapi.testclient import TestClient

    app = create_app(services=services, serve_ui=False)

    @app.get("/boom-for-the-test")
    def _boom() -> dict[str, str]:
        raise OSError(
            "[Errno 13] Permission denied: '/var/lib/sanctum/secret/chain.jsonl'"
        )

    with TestClient(
        app, raise_server_exceptions=False, base_url=LOOPBACK_BASE_URL
    ) as client:
        answer = client.get("/boom-for-the-test")

    assert answer.status_code == 500
    body = answer.json()
    assert "/var/lib/sanctum" not in answer.text
    assert "Permission denied" not in answer.text
    assert "Errno" not in answer.text
    assert body["kind"] == "InternalError"
    # The operator is given the string to grep the server log for.
    assert len(body["incident"]) == 12
    assert body["incident"] in body["error"]
    assert body["incident"] in body["remediation"]


def test_acquire_of_a_windows_disk_binds_to_the_serial_the_os_reports_now(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The operator's serial is checked against a fresh read, never trusted."""
    import json as _json

    from core.device._sysio import CommandResult
    from core.platform.windows import WindowsAdapter

    from tests.platform.conftest import windows_api_for

    inventory = _json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "platform"
            / "fixtures"
            / "windows_inventory.json"
        ).read_text(encoding="utf-8")
    )

    class _Runner:
        def run(self, argv: list[str]) -> CommandResult:
            return CommandResult(argv, 0, _json.dumps(inventory), "")

    monkeypatch.setattr("api.routes.jobs.sys.platform", "win32")
    monkeypatch.setattr(
        "core.platform.current_adapter",
        lambda **kw: WindowsAdapter(
            runner=_Runner(), native=windows_api_for(inventory), **kw
        ),
    )
    for serial, word in (("", "needs the serial"), ("WRONG", "must match")):
        answer = client.post(
            "/jobs/acquire",
            json={
                "source": "\\\\.\\PhysicalDrive2",
                "dest": "out.dd",
                "expected_serial": serial,
            },
        )
        assert answer.status_code == 422, answer.text
        assert word in answer.json()["detail"]["error"]


def test_prepare_device_is_a_separate_explicit_step(
    client: TestClient, helper: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unmount / offline is its own call, with the typed serial, errors kept."""
    from helper.rpc import RpcError

    seen: list[dict[str, Any]] = []

    def call(method: str, params: dict[str, Any]) -> dict[str, Any]:
        assert method == "prepare_device"
        seen.append(params)
        if params["path"] == "disk0":
            raise RpcError(
                "Refusing to unmount disk0: it is internal Mac storage.",
                remediation="",
                kind="SystemDiskRefused",
            )
        return {"device": params["path"], "performed": True}

    monkeypatch.setattr(helper, "call", call)
    answer = client.post(
        "/devices/prepare", json={"path": "disk4", "typed_serial": "S123"}
    )
    assert answer.status_code == 200
    assert answer.json()["performed"] is True
    assert "dry_run" not in seen[0]
    assert seen[0]["typed_serial"] == "S123"
    refused = client.post("/devices/prepare", json={"path": "disk0"})
    assert refused.status_code >= 400
    assert refused.json()["detail"]["kind"] == "SystemDiskRefused"
