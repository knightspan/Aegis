"""Fixtures for the API suite.

Every test drives the app in-process through ``TestClient``. No socket is bound
and no port is opened, which is the only way a test suite can assert things
about a server that must only ever listen on loopback.

The helper is a recorder rather than the real daemon. A test that needed a root
daemon on a Unix socket would be a test nobody runs, and the recorder runs the
**same** operation names through the same allowlist - it simply answers them
from a fixture instead of from hardware.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Generator, Iterator
from pathlib import Path
from typing import Any

import pytest
from api.deps import AppServices, default_services
from api.jobs import JobRegistry
from api.main import create_app
from fastapi.testclient import TestClient
from helper.rpc import RpcError

from tests._loopback import LOOPBACK_BASE_URL

MIB = 1024 * 1024

#: One synthetic device per capability badge the UI renders, so the device
#: screen's whole decision table is reachable from a test.
FAKE_DEVICES: list[dict[str, Any]] = [
    {
        "device": {
            "path": "/dev/sdz",
            "model": "SYNTHETIC-PURGE",
            "serial": "SYN-PURGE-1",
            "size_bytes": 64 * MIB,
            "rotational": False,
            "transport": "sata",
            "is_system_disk": False,
            "mounted_at": [],
            "pt_type": "gpt",
            "by_id_path": "/dev/disk/by-id/ata-SYNTHETIC_SYN-PURGE-1",
        },
        "capabilities": {
            "ata_security_erase": True,
            "ata_enhanced_erase": True,
            "ata_sanitize_ops": ["BLOCK_ERASE_EXT"],
            "nvme_sanicap": {},
            "is_sed_opal": False,
            "security_frozen": False,
            "est_erase_seconds": 120,
            "achievable_levels": ["CLEAR", "PURGE"],
            "limitations": [],
        },
        "hidden_areas": {
            "hpa_present": True,
            "dco_present": False,
            "native_max_sectors": 131072,
            "accessible_sectors": 126976,
            "hidden_bytes": 3145728,
        },
    },
    {
        "device": {
            "path": "/dev/sdy",
            "model": "SYNTHETIC-CLEAR",
            "serial": "SYN-CLEAR-2",
            "size_bytes": 32 * MIB,
            "rotational": True,
            "transport": "usb",
            "is_system_disk": False,
            "mounted_at": [],
            "pt_type": None,
            "by_id_path": None,
        },
        "capabilities": {
            "ata_security_erase": False,
            "ata_enhanced_erase": False,
            "ata_sanitize_ops": [],
            "nvme_sanicap": {},
            "is_sed_opal": False,
            "security_frozen": False,
            "est_erase_seconds": 600,
            "achievable_levels": ["CLEAR"],
            "limitations": [
                "USB bridge blocks ATA pass-through; PURGE cannot be established."
            ],
        },
        "hidden_areas": {
            "hpa_present": False,
            "dco_present": False,
            "native_max_sectors": 65536,
            "accessible_sectors": 65536,
            "hidden_bytes": 0,
        },
    },
    {
        "device": {
            "path": "/dev/sdx",
            "model": "SYNTHETIC-SYSTEM",
            "serial": "SYN-SYSTEM-3",
            "size_bytes": 128 * MIB,
            "rotational": False,
            "transport": "nvme",
            "is_system_disk": True,
            "mounted_at": ["/"],
            "pt_type": "gpt",
            "by_id_path": None,
        },
        "capabilities": None,
        "capability_error": "Refused: this device hosts the running root filesystem.",
        "hidden_areas": None,
    },
]


class RecordingHelper:
    """A helper transport that answers from fixtures and records every call.

    It enforces the gates the real handler does - a request carrying a removed
    simulation switch is refused, a request with no authorization is refused,
    and the typed serial must match - because those are the behaviours the API
    tests exist to check, and a stub that skipped them would let a regression
    in the API's own gating pass unnoticed. It is test infrastructure: it never
    touches a device, and nothing it answers is physical evidence.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((method, dict(params)))

        if method == "enumerate_devices":
            return {"devices": FAKE_DEVICES}

        if method == "probe_capabilities":
            row = self._row(params.get("path", ""))
            return {"device": row["device"], "capabilities": row["capabilities"]}

        if method == "detect_hidden_areas":
            return {"hidden_areas": self._row(params.get("path", ""))["hidden_areas"]}

        if method == "whoami":
            # Answered from the process, never from the request - the same
            # rule the real handler holds. A test that let the body name a uid
            # would let a spoof pass unnoticed.
            import os

            return {
                "uid": os.getuid(),
                "username": f"test-operator-{os.getuid()}",
                "gid": os.getgid(),
                "group": "testers",
                "basis": "in-process test helper; this process's own uid",
            }

        if method == "resume_erase":
            # Resume returns the same result shape run_erase does, with
            # `resumed` set: it is the same engine continuing the same job.
            answer = self.call("run_erase", params)
            answer["result"]["resumed"] = True
            return answer

        if method == "run_erase":
            from core.device.guard import refuse_removed_mode_keys
            from core.errors import WorkflowGateRefused

            try:
                refuse_removed_mode_keys(params)
            except WorkflowGateRefused as exc:
                raise RpcError(
                    exc.message, remediation=exc.remediation,
                    kind="WorkflowGateRefused",
                ) from exc
            if not isinstance(params.get("authorization"), dict):
                raise RpcError(
                    "REFUSED at the write seam: the request carries no "
                    "authorization. Nothing was erased.",
                    remediation="Open, approve and spend a workflow first.",
                    kind="WorkflowGateRefused",
                )
            row = self._row(params.get("path", ""))
            typed = str(params.get("typed_serial") or "")
            serial = str(row["device"]["serial"])
            if typed != serial:
                raise RpcError(
                    f"The typed serial {typed!r} does not match "
                    f"{row['device']['path']}, whose serial is {serial!r}. "
                    "Nothing was erased.",
                    remediation=(
                        "Re-read the device serial from the capability report "
                        "and type it exactly."
                    ),
                    kind="ConfirmationMismatch",
                )
            level = str(params.get("level") or "CLEAR")
            return {
                "result": {
                    "job_id": params.get("job_id", "erase"),
                    # The shape core.erase.drive.execute returns: the plan, the
                    # level asked for and the level achieved, and a read-back
                    # verdict.
                    "method": "SINGLE_PASS_OVERWRITE",
                    "level": level,
                    "plan": {
                        "method": "SINGLE_PASS_OVERWRITE",
                        "level": level,
                        "justification": "fixture",
                        "est_seconds": 1,
                    },
                    "achieved_level": level,
                    "verification": {
                        "passed": True,
                        "strategy": "full_read",
                        "bytes_checked": int(row["device"]["size_bytes"]),
                        "sample_count": 0,
                        "confidence_bp": 10_000,
                        "failed_offsets": [],
                        "probability_note": "fixture",
                        "hw_attested": False,
                    },
                    "logical_block_size": 512,
                    "physical_block_size": 512,
                    "device": row["device"],
                    "residual_risk": {
                        "level": "medium",
                        "factors": ["Synthetic run: no medium was written."],
                        "purge_achieved": False,
                        "notes": "fixture",
                    },
                    "limitations": [],
                },
                "progress": [
                    {
                        "job_id": params.get("job_id", "erase"),
                        "phase": phase,
                        "pct_bp": bp,
                        "bytes_done": bp * 100,
                        "bytes_total": 1_000_000,
                        "throughput_bytes_per_sec": 5_000_000,
                        "eta_seconds": 10,
                        "message": f"{phase} on {row['device']['path']}",
                    }
                    for phase, bp in (
                        ("PREFLIGHT", 0),
                        ("ERASE", 5000),
                        ("VERIFY", 9000),
                        ("REPORT", 10000),
                    )
                ],
            }

        raise RpcError(
            f"{method!r} is not an allowed helper operation.",
            remediation="Only the operations in the allowlist are served.",
            kind="KeyError",
        )

    def call_stream(
        self, method: str, params: dict[str, Any]
    ) -> Generator[dict[str, Any], None, dict[str, Any]]:
        """The streaming half of the transport, over the same fixtures.

        The real transports stream: they yield each progress record as the
        engine produces it and return the result. This double reproduces that
        shape by yielding the fixture's progress list one record at a time, so
        an API test exercises the same code path the product does - including
        cancellation, which reaches a generator only if there is one.
        """
        answer = self.call(method, params)
        yield from answer.get("progress", [])
        return {key: value for key, value in answer.items() if key != "progress"}

    def _row(self, path: str) -> dict[str, Any]:
        for row in FAKE_DEVICES:
            if row["device"]["path"] == path:
                return row
        raise RpcError(
            f"No device matches {path!r}.",
            remediation="Re-enumerate devices and confirm the target is present.",
            kind="DeviceVanished",
        )


@pytest.fixture
def helper() -> RecordingHelper:
    return RecordingHelper()


@pytest.fixture(autouse=True)
def signing_passphrase(monkeypatch: pytest.MonkeyPatch) -> None:
    """A passphrase for the report signing key.

    ``core.report.sign`` refuses to write an unprotected private key, which is
    correct and means the suite has to supply one. A fixed test value rather
    than a generated one, so a failure is reproducible from the source alone.
    """
    monkeypatch.setenv("SANCTUM_KEY_PASSPHRASE", "sanctum-test-passphrase")


@pytest.fixture
def services(tmp_path: Path, helper: RecordingHelper) -> AppServices:
    built = AppServices(
        registry=JobRegistry(),
        helper=helper,
        state_dir=tmp_path / "state",
        key_dir=tmp_path / "keys",
    )
    built.prepare()
    return built


@pytest.fixture
def client(services: AppServices) -> Iterator[TestClient]:
    app = create_app(services=services, serve_ui=False)
    with TestClient(app, base_url=LOOPBACK_BASE_URL) as test_client:
        yield test_client


@pytest.fixture(scope="session")
def ui_dist() -> Path:
    """The built UI bundle, built on demand if it is not already there.

    Built rather than skipped: "no external origin in the bundle" is an
    acceptance criterion, and a test that skipped when the bundle was missing
    would report green on exactly the run where nobody had checked.
    """
    root = Path(__file__).resolve().parents[2]
    dist = root / "ui" / "dist"
    if dist.is_dir() and (dist / "index.html").exists():
        return dist
    if shutil.which("npm") is None:
        pytest.skip("npm is not installed, so the UI bundle cannot be built here")
    subprocess.run(
        ["npm", "run", "build"], cwd=root / "ui", check=True, capture_output=True
    )
    return dist


def _default_services_for(tmp_path: Path) -> AppServices:
    return default_services(state_dir=tmp_path / "state")


def make_backup(
    services: AppServices, size: int = 64 * MIB, name: str = "backup.img"
) -> Path:
    """A sparse stand-in backup image inside the evidence directory."""
    image = services.evidence_dir / name
    with image.open("wb") as handle:
        handle.truncate(size)
    return image


def open_workflow(
    client: TestClient,
    services: AppServices,
    *,
    path: str = "/dev/sdz",
    level: str = "CLEAR",
    size: int = 64 * MIB,
) -> str:
    """Open a workflow record over the API and return its authorization id."""
    make_backup(services, size)
    answer = client.post(
        "/workflow/erase-drive",
        json={"path": path, "level": level, "backup_image": "backup.img"},
    )
    assert answer.status_code == 200, answer.text
    return str(answer.json()["authorization_id"])


def approve_workflow(
    client: TestClient, auth_id: str, serial: str = "SYN-PURGE-1"
) -> None:
    answer = client.post(
        f"/workflow/erase-drive/{auth_id}/approve",
        json={"typed_serial": serial, "acknowledge_data_destruction": True},
    )
    assert answer.status_code == 200, answer.text


def settle(services: AppServices, job_id: str, timeout: float = 60.0) -> str:
    """Block until the job is terminal and its outcome is in the chain.

    Waits on :attr:`JobRecord.settled`, the event the registry sets last. A
    loop over ``GET /jobs/{id}`` that stops at ``state != "running"`` is wrong
    twice: ``pending`` is not ``running``, so a worker thread that has not
    started yet reads as finished, and a bounded loop that runs out falls
    through to the next request with the job still going. Both were seen on
    the Windows runner as a report refused with ``JobNotFinished``.
    """
    record = services.registry.wait(job_id, timeout=timeout)
    assert record.settled.is_set(), f"job {job_id} did not settle in {timeout} s"
    return record.state


def authorize(client: TestClient, services: AppServices) -> str:
    """The full, legitimate path: open, then approve. Returns the id."""
    auth_id = open_workflow(client, services)
    approve_workflow(client, auth_id)
    return auth_id
