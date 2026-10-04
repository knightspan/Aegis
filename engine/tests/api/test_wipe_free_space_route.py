"""POST /jobs/wipe-free-space: every gate answers before a job exists.

Nothing here fills a volume. The fill is exercised on udisks loop volumes in
``tests/erase/files/test_free_space_wipe_carve.py``; this file checks that the
route refuses what it must with the right status and remediation, and that the
read-only plan (``POST /workflow/wipe-free-space``) reports the identifier to
type without creating a job or writing anything.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from core.models import VolumeInfo
from fastapi.testclient import TestClient

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="the volume is resolved from /proc/mounts"
)


def _fake_volume(point: Path, st_dev: int) -> VolumeInfo:
    return VolumeInfo(
        mount_point=str(point),
        fs_type="exfat",
        source="/dev/sdz1",
        fs_uuid="7BF9-380B",
        identifier="7BF9-380B",
        st_dev=st_dev,
        frsize=4096,
        trim_likely=None,
    )


def _patch_volume(monkeypatch: pytest.MonkeyPatch, volume: VolumeInfo) -> None:
    from core.erase import freespace

    monkeypatch.setattr(freespace, "resolve_volume", lambda path: volume)


def test_a_folder_that_is_not_a_mount_point_is_refused(
    client: TestClient, tmp_path: Path
) -> None:
    answer = client.post("/jobs/wipe-free-space", json={"mount_point": str(tmp_path)})

    assert answer.status_code == 422
    detail = answer.json()["detail"]
    assert detail["kind"] == "UnsupportedCapability"
    assert "not a mount point" in detail["error"]


def test_the_system_volume_is_refused_before_a_job_exists(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_volume(monkeypatch, _fake_volume(tmp_path, os.stat("/").st_dev))

    answer = client.post("/jobs/wipe-free-space", json={"mount_point": str(tmp_path)})

    assert answer.status_code == 409
    detail = answer.json()["detail"]
    assert detail["kind"] == "SystemDiskRefused"
    assert detail["remediation"]


def test_the_volume_holding_the_ledger_is_refused(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, services: object
) -> None:
    ledger_root = services.ledger_root  # type: ignore[attr-defined]
    ledger_root.mkdir(parents=True, exist_ok=True)
    _patch_volume(monkeypatch, _fake_volume(ledger_root, os.stat(ledger_root).st_dev))

    answer = client.post(
        "/jobs/wipe-free-space", json={"mount_point": str(ledger_root)}
    )

    assert answer.status_code == 409
    assert answer.json()["detail"]["kind"] == "SystemDiskRefused"


def test_a_real_run_without_the_identifier_is_refused(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    point = tmp_path / "volume"
    point.mkdir()
    _patch_volume(monkeypatch, _fake_volume(point, -1))

    answer = client.post(
        "/jobs/wipe-free-space",
        json={"mount_point": str(point), "typed_identifier": ""},
    )

    assert answer.status_code == 409
    detail = answer.json()["detail"]
    assert detail["kind"] == "ConfirmationMismatch"
    assert "7BF9-380B" in detail["remediation"]
    assert list(point.iterdir()) == []


def test_the_plan_reports_the_identifier_and_writes_nothing(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    services: object,
) -> None:
    point = tmp_path / "volume"
    point.mkdir()
    _patch_volume(monkeypatch, _fake_volume(point, -1))

    answer = client.post("/workflow/wipe-free-space", json={"mount_point": str(point)})

    assert answer.status_code == 200, answer.text
    body = answer.json()
    assert body["identifier"] == "7BF9-380B"
    assert body["volume"]["mount_point"] == str(point)
    assert body["not_reached"]
    assert "job_id" not in body
    assert services.registry.ids() == []  # type: ignore[attr-defined]
    assert list(point.iterdir()) == []


def test_the_plan_refuses_what_the_wipe_refuses(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _patch_volume(monkeypatch, _fake_volume(tmp_path, os.stat("/").st_dev))

    answer = client.post(
        "/workflow/wipe-free-space", json={"mount_point": str(tmp_path)}
    )

    assert answer.status_code == 409
    assert answer.json()["detail"]["kind"] == "SystemDiskRefused"


@pytest.mark.parametrize("key", ["dry_run", "simulation", "simulate"])
def test_a_wipe_with_a_simulation_switch_is_rejected(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, key: str
) -> None:
    point = tmp_path / "volume"
    point.mkdir()
    _patch_volume(monkeypatch, _fake_volume(point, -1))

    answer = client.post(
        "/jobs/wipe-free-space",
        json={"mount_point": str(point), "typed_identifier": "7BF9-380B", key: True},
    )

    assert answer.status_code == 422, answer.text
    assert list(point.iterdir()) == []
