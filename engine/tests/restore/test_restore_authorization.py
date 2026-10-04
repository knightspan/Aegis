"""The helper's restore write seam: single use, kind separation, typed serial.

Drives ``run_restore`` through the helper's own streaming handler with the API
out of the picture. The target re-read is replaced with a fixture probe and the
device opener with a file-backed target; nothing opens a device node.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from core.authorization import authorization_kind, kind_mismatch
from core.backup import BackupRecord
from core.errors import WorkflowGateRefused
from core.models import Device
from core.restore import FileBlockTarget, plan_restore, target_identity_from_probe
from helper.authorization import revalidate_execution, revalidate_restore
from helper.daemon import OPERATIONS, STREAMING_OPERATIONS

from tests.helper.authfx import make_authorization

from .conftest import (
    IMAGE_SIZE,
    TARGET_SIZE,
    device_probe,
    image_bytes,
    make_restore_authorization,
)

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="the restore write seam exists only on Linux"
)


@pytest.fixture
def seam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, Any]:
    """Patch the target re-read and the device opener; record what was opened."""
    state: dict[str, Any] = {"probe": device_probe(), "opened": []}
    target_file = tmp_path / "target.img"
    target_file.write_bytes(b"\xaa" * TARGET_SIZE)
    state["file"] = target_file

    monkeypatch.setattr(
        "helper.authorization._fresh_restore_probe", lambda path: state["probe"]
    )

    def opener(target: Any) -> FileBlockTarget:
        state["opened"].append(target.path)
        return FileBlockTarget(target_file)

    monkeypatch.setattr("helper.daemon._open_restore_target", opener)
    return state


def _params(
    tmp_path: Path, record: BackupRecord, **over: Any
) -> dict[str, Any]:
    probe = device_probe()
    plan = plan_restore(record, target_identity_from_probe(probe))
    extras = make_restore_authorization(
        tmp_path,
        record,
        plan,
        probe,
        approved=over.pop("approved", True),
        spent=over.pop("spent", True),
    )
    base = {
        "job_id": "restore-test",
        "typed_serial": "TGT-1",
        "ledger_root": str(tmp_path / "ledger"),
        "actor": "tester",
        **extras,
    }
    base.update(over)
    return base


def _run(params: dict[str, Any]) -> dict[str, Any]:
    generator = STREAMING_OPERATIONS["run_restore"](params)
    while True:
        try:
            next(generator)
        except StopIteration as stop:
            answer: dict[str, Any] = stop.value
            return answer


def test_run_restore_is_an_allowlisted_streaming_operation() -> None:
    assert "run_restore" in OPERATIONS
    assert "run_restore" in STREAMING_OPERATIONS


def test_an_unapproved_unspent_restore_is_refused_and_opens_nothing(
    tmp_path: Path, record: BackupRecord, seam: dict[str, Any]
) -> None:
    """There is no rehearsal restore that skips approval: it is refused."""
    params = _params(tmp_path, record, approved=False, spent=False)
    with pytest.raises(WorkflowGateRefused, match="approved"):
        _run(params)
    assert seam["opened"] == []
    assert seam["file"].read_bytes() == b"\xaa" * TARGET_SIZE
    assert not (tmp_path / "authorizations" / "auth-00000000000000aa.executed").exists()


@pytest.mark.parametrize("key", ["dry_run", "simulation", "simulate"])
def test_a_simulation_switch_is_refused_at_the_restore_seam(
    tmp_path: Path, record: BackupRecord, seam: dict[str, Any], key: str
) -> None:
    params = _params(tmp_path, record, **{key: True})
    with pytest.raises(WorkflowGateRefused, match=key):
        _run(params)
    assert seam["opened"] == []
    assert not (tmp_path / "authorizations" / "auth-00000000000000aa.executed").exists()


def test_a_real_restore_passes_once_and_only_once(
    tmp_path: Path, record: BackupRecord, seam: dict[str, Any]
) -> None:
    params = _params(tmp_path, record)
    answer = _run(params)
    assert answer["result"]["result"] == "RESTORED_VERIFIED"
    assert seam["opened"] == ["/dev/fake-target"]
    assert seam["file"].read_bytes()[:IMAGE_SIZE] == image_bytes()
    with pytest.raises(WorkflowGateRefused, match="already executed"):
        _run(params)
    assert seam["opened"] == ["/dev/fake-target"]


def test_a_typed_serial_mismatch_is_refused_and_burns_nothing(
    tmp_path: Path, record: BackupRecord, seam: dict[str, Any]
) -> None:
    params = _params(tmp_path, record, typed_serial="WRONG")
    with pytest.raises(WorkflowGateRefused, match="typed serial"):
        _run(params)
    assert seam["opened"] == []
    assert not (tmp_path / "authorizations" / "auth-00000000000000aa.executed").exists()


def test_no_typed_serial_is_refused(
    tmp_path: Path, record: BackupRecord, seam: dict[str, Any]
) -> None:
    with pytest.raises(WorkflowGateRefused, match="no serial was typed"):
        _run(_params(tmp_path, record, typed_serial=""))
    assert seam["opened"] == []


@pytest.mark.parametrize(
    ("approved", "spent", "reason"),
    [
        (False, True, "no person has approved"),
        (True, False, "not consumed by the API gate"),
    ],
)
def test_an_unapproved_or_unspent_authorization_is_refused(
    tmp_path: Path,
    record: BackupRecord,
    seam: dict[str, Any],
    approved: bool,
    spent: bool,
    reason: str,
) -> None:
    with pytest.raises(WorkflowGateRefused, match=reason):
        _run(_params(tmp_path, record, approved=approved, spent=spent))
    assert seam["opened"] == []


def test_a_target_swapped_after_approval_is_refused(
    tmp_path: Path, record: BackupRecord, seam: dict[str, Any]
) -> None:
    params = _params(tmp_path, record)
    seam["probe"] = device_probe(serial="SWAPPED")
    with pytest.raises(WorkflowGateRefused) as refused:
        _run({**params, "typed_serial": "SWAPPED"})
    assert any("serial" in reason for reason in refused.value.why_blocked)
    assert seam["opened"] == []


def test_a_target_mounted_after_approval_is_refused(
    tmp_path: Path, record: BackupRecord, seam: dict[str, Any]
) -> None:
    params = _params(tmp_path, record)
    seam["probe"] = device_probe(mounted_at=["/mnt/now"])
    with pytest.raises(WorkflowGateRefused, match="/mnt/now"):
        _run(params)
    assert seam["opened"] == []


def test_an_image_replaced_after_approval_is_refused(
    tmp_path: Path, record: BackupRecord, seam: dict[str, Any]
) -> None:
    params = _params(tmp_path, record)
    image = Path(record.image_path)
    replacement = image.with_name("replacement.img")
    replacement.write_bytes(image.read_bytes())
    os.replace(replacement, image)
    with pytest.raises(WorkflowGateRefused, match="backup image changed"):
        _run(params)
    assert seam["opened"] == []


def test_a_request_binding_that_differs_from_the_record_is_refused(
    tmp_path: Path, record: BackupRecord, seam: dict[str, Any]
) -> None:
    params = _params(tmp_path, record)
    params["authorization"] = {
        **params["authorization"],
        "plan": {**params["authorization"]["plan"], "write_length": 512},
    }
    with pytest.raises(WorkflowGateRefused, match="plan does not match"):
        _run(params)


def test_an_altered_stored_backup_record_is_refused(
    tmp_path: Path, record: BackupRecord, seam: dict[str, Any]
) -> None:
    params = _params(tmp_path, record)
    path = tmp_path / "authorizations" / "auth-00000000000000aa.json"
    stored = json.loads(path.read_text(encoding="utf-8"))
    stored["backup"]["record"]["image_sha256"] = "0" * 64
    path.write_text(json.dumps(stored), encoding="utf-8")
    params["authorization"]["backup"] = stored["backup"]
    with pytest.raises(WorkflowGateRefused, match="altered"):
        _run(params)
    assert seam["opened"] == []


# -- kind separation --------------------------------------------------------


def _erase_device() -> Device:
    return Device(
        path="/dev/fake-target",
        model="SYNTHETIC-TARGET",
        serial="TGT-1",
        size_bytes=TARGET_SIZE,
        rotational=True,
        transport="sata",
        is_system_disk=False,
        mounted_at=[],
        pt_type=None,
        by_id_path=None,
    )


def test_an_erase_authorization_cannot_be_spent_as_a_restore(
    tmp_path: Path, seam: dict[str, Any]
) -> None:
    extras = make_authorization(tmp_path, _erase_device())
    params = {
        "path": "/dev/fake-target",
        "typed_serial": "TGT-1",
        **extras,
    }
    with pytest.raises(WorkflowGateRefused, match="'erase' authorization"):
        revalidate_restore(params)
    assert seam["opened"] == []


def test_a_restore_authorization_cannot_be_spent_as_an_erase(
    tmp_path: Path, record: BackupRecord, seam: dict[str, Any]
) -> None:
    params = _params(tmp_path, record)
    with pytest.raises(WorkflowGateRefused, match="cannot authorize an erase"):
        revalidate_execution({**params, "level": "CLEAR"})
    assert not (tmp_path / "authorizations" / "auth-00000000000000aa.executed").exists()


def test_a_record_without_a_kind_is_an_erase_authorization(tmp_path: Path) -> None:
    extras = make_authorization(tmp_path, _erase_device())
    stored = json.loads(
        (Path(extras["authorization_dir"]) / f"{extras['authorization']['auth_id']}"
         ".json").read_text(encoding="utf-8")
    )
    assert "kind" not in stored
    assert authorization_kind(stored) == "erase"
    assert kind_mismatch(stored, "erase") == []
    assert kind_mismatch(stored, "restore")
