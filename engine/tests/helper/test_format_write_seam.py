"""The helper re-checks a format authorization itself, at the write seam.

A ``format`` approval is never spendable as an erase, restore or HPA change, and
none of those is spendable as a format. Every refusal here happens before any
command runs and before the single-use marker is taken.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from core.authorization import AUTH_KINDS, device_identity, kind_mismatch
from core.errors import WorkflowGateRefused
from core.format import plan_format
from core.models import Device
from helper.authorization import revalidate_format

from .authfx import AUTH_ID, patch_probe, probe_of


def _device(**over: Any) -> Device:
    fields: dict[str, Any] = {
        "path": "/dev/fake",
        "model": "SYNTHETIC",
        "serial": "SYN-1",
        "size_bytes": 1024 * 1024,
        "rotational": False,
        "transport": "usb",
        "is_system_disk": False,
        "mounted_at": [],
        "pt_type": None,
        "by_id_path": None,
    }
    fields.update(over)
    return Device(**fields)


def _authorization(
    tmp_path: Path,
    device: Device,
    *,
    approved: bool = True,
    spent: bool = True,
    kind: str = "format",
) -> dict[str, Any]:
    root = tmp_path / "authorizations"
    root.mkdir(parents=True, exist_ok=True)
    plan = plan_format(
        device, "exfat", "USB", follows_job="erase-drive-abc"
    ).model_dump(mode="json")
    record = {
        "auth_id": AUTH_ID,
        "path": device.path,
        "level": "FORMAT",
        "device": device_identity(probe_of(device)),
        "backup": {},
        "plan": plan,
        "opened_by": "test",
        "opened_at": "now",
        "approved_by": "approver" if approved else "",
        "approved_at": "now" if approved else "",
        "consumed_at": "",
        "kind": kind,
    }
    (root / f"{AUTH_ID}.json").write_text(json.dumps(record), encoding="utf-8")
    if spent:
        (root / f"{AUTH_ID}.spent").write_text("x", encoding="utf-8")
    return {
        "path": device.path,
        "typed_serial": device.serial,
        "authorization": {
            key: record[key]
            for key in ("auth_id", "kind", "path", "device", "backup", "plan")
        },
        "authorization_dir": str(root),
    }


def test_format_is_a_kind_of_its_own() -> None:
    assert "format" in AUTH_KINDS
    assert kind_mismatch({"auth_id": "a", "kind": "erase"}, "format")
    assert not kind_mismatch({"auth_id": "a", "kind": "format"}, "format")


def test_a_complete_authorization_passes_and_takes_the_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    device = _device()
    patch_probe(monkeypatch, device)
    params = _authorization(tmp_path, device)
    authorized = revalidate_format(params)
    assert authorized.auth_id == AUTH_ID
    assert authorized.plan.filesystem == "exfat"
    assert (tmp_path / "authorizations" / f"{AUTH_ID}.executed").exists()


def test_a_second_use_of_the_same_authorization_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    device = _device()
    patch_probe(monkeypatch, device)
    params = _authorization(tmp_path, device)
    revalidate_format(params)
    with pytest.raises(WorkflowGateRefused, match="already executed"):
        revalidate_format(params)


@pytest.mark.parametrize("kind", ["erase", "restore", "hpa"])
def test_another_kind_of_approval_is_not_spendable_as_a_format(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    device = _device()
    patch_probe(monkeypatch, device)
    params = _authorization(tmp_path, device, kind=kind)
    with pytest.raises(WorkflowGateRefused, match="cannot authorize"):
        revalidate_format(params)


def test_an_unapproved_record_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    device = _device()
    patch_probe(monkeypatch, device)
    with pytest.raises(WorkflowGateRefused, match="approved"):
        revalidate_format(_authorization(tmp_path, device, approved=False))


def test_a_record_the_api_did_not_spend_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    device = _device()
    patch_probe(monkeypatch, device)
    with pytest.raises(WorkflowGateRefused, match="API gate"):
        revalidate_format(_authorization(tmp_path, device, spent=False))


@pytest.mark.parametrize(
    ("fresh", "fragment"),
    [
        (dict(serial="OTHER"), "serial changed"),
        (dict(size_bytes=2048), "size_bytes changed"),
        (dict(is_system_disk=True), "running system"),
        (dict(mounted_at=["/mnt/x"]), "mounted"),
    ],
)
def test_a_device_that_changed_since_approval_is_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fresh: dict[str, Any],
    fragment: str,
) -> None:
    approved = _device()
    params = _authorization(tmp_path, approved)
    patch_probe(monkeypatch, _device(**fresh))
    with pytest.raises(WorkflowGateRefused, match=fragment):
        revalidate_format(params)
    assert not (tmp_path / "authorizations" / f"{AUTH_ID}.executed").exists()


@pytest.mark.parametrize("typed", ["", "wrong"])
def test_the_typed_serial_must_match_the_device_read_now(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, typed: str
) -> None:
    device = _device()
    patch_probe(monkeypatch, device)
    params = _authorization(tmp_path, device) | {"typed_serial": typed}
    with pytest.raises(WorkflowGateRefused, match="serial"):
        revalidate_format(params)


def test_a_plan_altered_after_approval_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    device = _device()
    patch_probe(monkeypatch, device)
    params = _authorization(tmp_path, device)
    params["authorization"]["plan"]["filesystem"] = "ext4"
    with pytest.raises(WorkflowGateRefused, match="does not match|altered"):
        revalidate_format(params)


@pytest.mark.parametrize("key", ["dry_run", "simulation", "simulate"])
def test_a_simulation_switch_is_refused_not_honoured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, key: str
) -> None:
    device = _device()
    patch_probe(monkeypatch, device)
    params = _authorization(tmp_path, device) | {key: True}
    with pytest.raises(Exception, match="dry_run|simulat|mode"):
        revalidate_format(params)


# --------------------------------------------------------------------------
# The helper operation itself
# --------------------------------------------------------------------------


class _Spy:
    """Stands in for the command runner; records what would have been run."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], stdin: str | None = None) -> Any:
        from core.format import CommandResult

        self.calls.append(argv)
        if argv[0] == "blkid":
            return CommandResult(0, "exfat\n" if "TYPE" in argv else "USB\n", "")
        return CommandResult(0, "", "")


def _patch_engine(monkeypatch: pytest.MonkeyPatch, spy: _Spy) -> None:
    monkeypatch.setattr("core.format.run_command", spy)
    monkeypatch.setattr("helper.daemon._partition_exists", lambda _p: True)
    monkeypatch.setattr("helper.daemon._format_platform", lambda: "linux")
    monkeypatch.setattr("helper.daemon._require_drive_engine", lambda _p: None)


def test_the_operation_is_in_the_closed_allowlist_and_streams() -> None:
    from helper.daemon import OPERATIONS, STREAMING_OPERATIONS

    assert "run_format" in OPERATIONS
    assert "run_format" in STREAMING_OPERATIONS


def test_a_request_with_no_authorization_runs_no_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from helper.daemon import _op_run_format

    spy = _Spy()
    _patch_engine(monkeypatch, spy)
    with pytest.raises(WorkflowGateRefused):
        _op_run_format({"path": "/dev/fake", "typed_serial": "SYN-1"})
    assert spy.calls == []


def test_a_request_with_no_ledger_is_refused_before_the_marker_is_taken(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from helper.daemon import _op_run_format

    device = _device()
    patch_probe(monkeypatch, device)
    spy = _Spy()
    _patch_engine(monkeypatch, spy)
    params = _authorization(tmp_path, device)
    with pytest.raises(WorkflowGateRefused, match="ledger"):
        _op_run_format(params)
    assert spy.calls == []
    assert not (tmp_path / "authorizations" / f"{AUTH_ID}.executed").exists()


def test_an_authorized_request_formats_and_is_ledgered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from helper.daemon import _op_run_format

    device = _device()
    patch_probe(monkeypatch, device)
    spy = _Spy()
    _patch_engine(monkeypatch, spy)
    params = _authorization(tmp_path, device) | {
        "ledger_root": str(tmp_path / "ledger"),
        "job_id": "format-1",
    }
    answer = _op_run_format(params)
    assert answer["result"]["verified"] is True
    assert [c[0] for c in spy.calls][:2] == ["wipefs", "sfdisk"]
    from core.ledger.chain import Ledger

    ledger = Ledger(tmp_path / "ledger", tool_version="t", pubkey_fingerprint="")
    assert [e.operation for e in ledger.entries()][-2:] == [
        "format.begin",
        "format.complete",
    ]
