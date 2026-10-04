"""Make an erased device usable again, over the API and through the helper's handler.

``run_format`` is served by the helper's **real** operation, so the write-seam
revalidation and the engine run as they do in the daemon. Only the host is
faked: the command runner records every argv and answers like a healthy
``mkfs``, the partition check answers true and the device re-read answers from
the API suite's fixture table. No device is opened and no command is executed.
"""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

import pytest
from api.deps import AppServices
from core.format import CommandResult
from core.ledger.chain import Ledger
from fastapi.testclient import TestClient
from helper.daemon import _stream_run_format

from .conftest import (
    FAKE_DEVICES,
    MIB,
    RecordingHelper,
    approve_workflow,
    open_workflow,
    settle,
)

PATH = "/dev/sdy"
SERIAL = "SYN-CLEAR-2"


class FormatHelper(RecordingHelper):
    """The suite's helper double, with ``run_format`` served by the real handler."""

    def call_stream(
        self, method: str, params: dict[str, Any]
    ) -> Generator[dict[str, Any], None, dict[str, Any]]:
        if method != "run_format":
            return (yield from super().call_stream(method, params))
        self.calls.append((method, dict(params)))
        return (yield from _stream_run_format(params))


class Commands:
    def __init__(self) -> None:
        self.argv: list[list[str]] = []

    def __call__(self, argv: list[str], stdin: str | None = None) -> CommandResult:
        self.argv.append(argv)
        if argv[0] == "blkid":
            return CommandResult(0, "exfat\n" if "TYPE" in argv else "USB\n", "")
        return CommandResult(0, "", "")

    def programs(self) -> list[str]:
        return [a[0] for a in self.argv]


@pytest.fixture
def helper() -> FormatHelper:
    return FormatHelper()


@pytest.fixture
def commands(monkeypatch: pytest.MonkeyPatch) -> Commands:
    spy = Commands()
    row = next(r for r in FAKE_DEVICES if r["device"]["path"] == PATH)
    monkeypatch.setattr("core.format.run_command", spy)
    monkeypatch.setattr("helper.daemon._partition_exists", lambda _p: True)
    monkeypatch.setattr("helper.daemon._format_platform", lambda: "linux")
    monkeypatch.setattr("helper.daemon._require_drive_engine", lambda _p: None)
    monkeypatch.setattr(
        "helper.authorization._fresh_probe",
        lambda path: {"device": row["device"], "capabilities": row["capabilities"]},
    )
    return spy


@pytest.fixture
def erased(client: TestClient, services: AppServices) -> str:
    """One completed erase of the usb device; returns its job id."""
    auth_id = open_workflow(client, services, path=PATH, size=32 * MIB)
    approve_workflow(client, auth_id, serial=SERIAL)
    answer = client.post(
        "/jobs/erase-drive",
        json={"path": PATH, "typed_serial": SERIAL, "authorization_id": auth_id},
    )
    assert answer.status_code == 200, answer.text
    job_id = str(answer.json()["job_id"])
    assert settle(services, job_id) == "complete"
    return job_id


def _open(client: TestClient, path: str = PATH, **over: Any) -> Any:
    body = {"path": path, "filesystem": "exfat", "label": "USB"} | over
    return client.post("/workflow/format", json=body)


def _approve(
    client: TestClient, auth_id: str, serial: str = SERIAL, ack: bool = True
) -> Any:
    return client.post(
        f"/workflow/format/{auth_id}/approve",
        json={"typed_serial": serial, "acknowledge_format": ack},
    )


def _execute(client: TestClient, auth_id: str, serial: str = SERIAL) -> Any:
    return client.post(
        f"/workflow/format/{auth_id}/execute", json={"typed_serial": serial}
    )


def _operations(services: AppServices) -> list[str]:
    ledger = Ledger(services.ledger_root, tool_version="t", pubkey_fingerprint="")
    return [e.operation for e in ledger.entries()]


# ---- opening ---------------------------------------------------------------


def test_a_device_that_was_never_erased_here_is_refused(
    client: TestClient, commands: Commands
) -> None:
    answer = _open(client)
    assert answer.status_code == 409
    assert "erase" in str(answer.json()).lower()
    assert commands.argv == []


def test_the_system_disk_is_refused_even_after_an_erase_record_exists(
    client: TestClient, erased: str
) -> None:
    answer = _open(client, path="/dev/sdx")
    assert answer.status_code == 409


def test_an_erased_device_opens_a_plan_bound_to_that_erase(
    client: TestClient, erased: str, services: AppServices
) -> None:
    answer = _open(client)
    assert answer.status_code == 200, answer.text
    body = answer.json()
    assert body["plan"]["follows_job"] == erased
    assert body["plan"]["filesystem"] == "exfat"
    assert body["approved"] is False
    assert "format.open" in _operations(services)


@pytest.mark.parametrize("over", [{"filesystem": "ntfs"}, {"label": "X" * 40}])
def test_an_unsupported_filesystem_or_label_is_refused(
    client: TestClient, erased: str, over: dict[str, str]
) -> None:
    assert _open(client, **over).status_code == 409


# ---- approving -------------------------------------------------------------


def test_approval_needs_the_exact_serial_and_the_acknowledgement(
    client: TestClient, erased: str
) -> None:
    auth_id = _open(client).json()["authorization_id"]
    assert _approve(client, auth_id, serial="WRONG").status_code == 409
    assert _approve(client, auth_id, ack=False).status_code == 409
    assert _approve(client, auth_id).status_code == 200


def test_an_erase_authorization_cannot_be_approved_as_a_format(
    client: TestClient, services: AppServices, erased: str
) -> None:
    erase_auth = open_workflow(client, services, path=PATH, size=32 * MIB)
    answer = _approve(client, erase_auth)
    assert answer.status_code in (404, 409)


# ---- executing -------------------------------------------------------------


def test_an_unapproved_authorization_cannot_be_executed(
    client: TestClient, erased: str, commands: Commands
) -> None:
    auth_id = _open(client).json()["authorization_id"]
    assert _execute(client, auth_id).status_code == 409
    assert commands.argv == []


def test_execute_needs_the_typed_serial(
    client: TestClient, erased: str, commands: Commands
) -> None:
    auth_id = _open(client).json()["authorization_id"]
    _approve(client, auth_id)
    assert _execute(client, auth_id, serial="").status_code == 409
    assert _execute(client, auth_id, serial="WRONG").status_code == 409
    assert commands.argv == []


def test_the_full_path_formats_the_device_and_ledgers_it(
    client: TestClient, services: AppServices, erased: str, commands: Commands
) -> None:
    auth_id = _open(client).json()["authorization_id"]
    assert _approve(client, auth_id).status_code == 200
    accepted = _execute(client, auth_id)
    assert accepted.status_code == 200, accepted.text
    job_id = accepted.json()["job_id"]
    assert settle(services, job_id) == "complete"
    assert commands.programs() == [
        "wipefs",
        "sfdisk",
        "udevadm",
        "mkfs.exfat",
        "blkid",
        "blkid",
    ]
    status = client.get(f"/jobs/{job_id}").json()
    assert status["result"]["verified"] is True
    operations = _operations(services)
    assert {"format.approved", "format.begin", "format.complete"} <= set(operations)


def test_an_authorization_is_single_use(
    client: TestClient, services: AppServices, erased: str, commands: Commands
) -> None:
    auth_id = _open(client).json()["authorization_id"]
    _approve(client, auth_id)
    first = _execute(client, auth_id)
    settle(services, first.json()["job_id"])
    ran = len(commands.argv)
    assert _execute(client, auth_id).status_code == 409
    assert len(commands.argv) == ran


def test_a_device_that_was_formatted_is_not_offered_another_format(
    client: TestClient, services: AppServices, erased: str, commands: Commands
) -> None:
    auth_id = _open(client).json()["authorization_id"]
    _approve(client, auth_id)
    settle(services, _execute(client, auth_id).json()["job_id"])
    assert _open(client).status_code == 409


@pytest.mark.parametrize("key", ["dry_run", "simulation", "simulate"])
def test_a_simulation_switch_is_refused_at_every_step(
    client: TestClient, erased: str, commands: Commands, key: str
) -> None:
    assert _open(client, **{key: True}).status_code >= 400
    auth_id = _open(client).json()["authorization_id"]
    approve = client.post(
        f"/workflow/format/{auth_id}/approve",
        json={"typed_serial": SERIAL, "acknowledge_format": True, key: True},
    )
    assert approve.status_code >= 400
    _approve(client, auth_id)
    execute = client.post(
        f"/workflow/format/{auth_id}/execute", json={"typed_serial": SERIAL, key: True}
    )
    assert execute.status_code >= 400
    assert commands.argv == []


# ---- eligibility -----------------------------------------------------------


def test_eligibility_says_no_before_an_erase_and_why(
    client: TestClient, commands: Commands
) -> None:
    answer = client.get("/workflow/format/eligibility", params={"path": PATH})
    assert answer.status_code == 200
    body = answer.json()
    assert body["eligible"] is False
    assert any("erase" in reason for reason in body["reasons"])


def test_eligibility_says_yes_after_an_erase_and_names_the_job(
    client: TestClient, erased: str
) -> None:
    body = client.get("/workflow/format/eligibility", params={"path": PATH}).json()
    assert body == {"eligible": True, "follows_job": erased, "reasons": []}


def test_eligibility_survives_a_restart_because_it_reads_the_ledger(
    client: TestClient, services: AppServices, erased: str
) -> None:
    services.registry = type(services.registry)()
    body = client.get("/workflow/format/eligibility", params={"path": PATH}).json()
    assert body["eligible"] is True


def test_eligibility_ends_once_the_device_is_formatted(
    client: TestClient, services: AppServices, erased: str, commands: Commands
) -> None:
    auth_id = _open(client).json()["authorization_id"]
    _approve(client, auth_id)
    settle(services, _execute(client, auth_id).json()["job_id"])
    body = client.get("/workflow/format/eligibility", params={"path": PATH}).json()
    assert body["eligible"] is False


def test_eligibility_is_false_for_the_system_disk(
    client: TestClient, erased: str
) -> None:
    body = client.get(
        "/workflow/format/eligibility", params={"path": "/dev/sdx"}
    ).json()
    assert body["eligible"] is False
