"""Resume is exposed where it exists and refused plainly where it does not.

The core has had checkpointed overwrite resume for a long time
(:func:`core.erase.drive.resume`) and nothing above it could reach the feature.
Exposing it is most of this; the part worth testing hardest is the refusal,
because a UI that offered a Resume button for a firmware sanitize would be
claiming the drive can tell us how far it got, and it cannot.
"""

from __future__ import annotations

from typing import Any

from api.deps import AppServices
from core.ledger.chain import Ledger
from fastapi.testclient import TestClient
from helper.daemon import OPERATIONS, STREAMING_OPERATIONS


def _append(services: AppServices, operation: str, params: dict[str, Any]) -> None:
    Ledger(
        services.ledger_root, tool_version="t", pubkey_fingerprint=""
    ).append(actor="tester", operation=operation, params=params, result={})


def _plan(services: AppServices, job_id: str, method: str) -> None:
    _append(
        services,
        "erase.preflight.plan",
        {
            "job_id": job_id,
            "path": "/dev/sdz",
            "serial": "SYN-PURGE-1",
            "plan": {"method": method, "level_requested": "CLEAR"},
        },
    )


def _checkpoint(services: AppServices, job_id: str, offset: int) -> None:
    _append(
        services,
        "erase.erase.checkpoint",
        {"job_id": job_id, "offset": offset, "pass_index": 0},
    )


# --------------------------------------------------------------------------
# Availability
# --------------------------------------------------------------------------


def test_an_overwrite_with_a_checkpoint_is_resumable(
    client: TestClient, services: AppServices
) -> None:
    _plan(services, "erase-drive-abc", "SINGLE_PASS_OVERWRITE")
    _checkpoint(services, "erase-drive-abc", 4_194_304)

    state = client.get("/jobs/erase-drive-abc/resume").json()

    assert state["resumable"] is True
    assert state["checkpoint"]["offset"] == 4_194_304
    assert "4194304" in state["reason"]


def test_the_latest_checkpoint_wins(
    client: TestClient, services: AppServices
) -> None:
    _plan(services, "erase-drive-abc", "SINGLE_PASS_OVERWRITE")
    _checkpoint(services, "erase-drive-abc", 1024)
    _checkpoint(services, "erase-drive-abc", 8192)

    state = client.get("/jobs/erase-drive-abc/resume").json()

    assert state["checkpoint"]["offset"] == 8192


# --------------------------------------------------------------------------
# Refusals: each states its own reason rather than a disabled button
# --------------------------------------------------------------------------


def test_a_firmware_sanitize_is_not_resumable_and_says_why(
    client: TestClient, services: AppServices
) -> None:
    """The drive executes it alone and reports no progress.

    Offering resume here would claim the device told us where it stopped.
    """
    _plan(services, "erase-drive-fw", "ATA_SANITIZE_BLOCK_ERASE")

    state = client.get("/jobs/erase-drive-fw/resume").json()

    assert state["resumable"] is False
    assert "RESUME NOT AVAILABLE" in state["reason"]
    assert "firmware operation" in state["reason"]


def test_an_overwrite_that_never_checkpointed_is_not_resumable(
    client: TestClient, services: AppServices
) -> None:
    _plan(services, "erase-drive-early", "SINGLE_PASS_OVERWRITE")

    state = client.get("/jobs/erase-drive-early/resume").json()

    assert state["resumable"] is False
    assert "never reached its first checkpoint" in state["reason"]


def test_an_unknown_job_is_not_resumable(client: TestClient) -> None:
    state = client.get("/jobs/nothing-here/resume").json()

    assert state["resumable"] is False
    assert "no erase entries" in state["reason"]


def test_posting_a_resume_for_a_firmware_job_is_refused(
    client: TestClient, services: AppServices
) -> None:
    _plan(services, "erase-drive-fw", "ATA_SANITIZE_BLOCK_ERASE")

    answer = client.post(
        "/jobs/erase-drive-fw/resume", json={"typed_serial": "SYN-PURGE-1"}
    )

    assert answer.status_code == 409, answer.text
    assert answer.json()["detail"]["kind"] == "ResumeNotAvailable"


# --------------------------------------------------------------------------
# A resume keeps every gate
# --------------------------------------------------------------------------


def test_a_real_resume_without_a_typed_serial_is_refused(
    client: TestClient, services: AppServices
) -> None:
    """A resume writes to the medium. It is not confirmed more cheaply."""
    _plan(services, "erase-drive-abc", "SINGLE_PASS_OVERWRITE")
    _checkpoint(services, "erase-drive-abc", 1024)

    answer = client.post(
        "/jobs/erase-drive-abc/resume", json={"typed_serial": ""}
    )

    assert answer.status_code == 409
    assert answer.json()["detail"]["kind"] == "ConfirmationMismatch"


def test_a_resume_without_an_authorization_is_refused(
    client: TestClient, services: AppServices
) -> None:
    """There is no rehearsal resume: an empty body is refused, not simulated."""
    _plan(services, "erase-drive-abc", "SINGLE_PASS_OVERWRITE")
    _checkpoint(services, "erase-drive-abc", 1024)

    empty = client.post("/jobs/erase-drive-abc/resume", json={})
    assert empty.status_code == 409, empty.text
    unauthorized = client.post(
        "/jobs/erase-drive-abc/resume", json={"typed_serial": "SYN-PURGE-1"}
    )
    assert unauthorized.status_code == 409, unauthorized.text
    assert unauthorized.json()["detail"]["kind"] == "WorkflowGateRefused"
    rehearsal = client.post(
        "/jobs/erase-drive-abc/resume",
        json={"typed_serial": "SYN-PURGE-1", "dry_run": True},
    )
    assert rehearsal.status_code == 422


def test_resume_is_in_the_helper_allowlist_on_both_paths() -> None:
    """The allowlist is one list, not two."""
    assert "resume_erase" in OPERATIONS
    assert "resume_erase" in STREAMING_OPERATIONS
    assert set(STREAMING_OPERATIONS) <= set(OPERATIONS)
