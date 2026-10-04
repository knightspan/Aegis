"""The helper re-checks an erase authorization itself, at the write seam.

The API gate (tests/api/test_workflow_gate.py) is the first check. These tests
drive the *helper's* dispatch with the API out of the picture: a request that
reaches ``run_erase`` or ``resume_erase`` must carry an authorization that
holds up against a fresh read of the device and the backup, or the engine is
never entered. The engine is replaced by a tripwire that
records if it was reached; no device is opened.

What this cannot show: a process that can rewrite the authorization directory
as the operator can forge a consistent record (see helper/authorization.py), and
nothing here proves the window between this check and the first write is closed.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path
from typing import Any

import pytest
from core.errors import WorkflowGateRefused
from core.models import Device
from helper.daemon import HelperDaemon

from .authfx import AUTH_ID, CAPS, make_authorization, patch_probe

# The engine tripwire is on LinuxAdapter, the only adapter with a whole-drive
# engine. On macOS and Windows the helper's probe refuses with
# PlatformUnsupported before any authorization is read; tests/platform asserts
# that refusal on its own.
pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="the whole-drive write seam exists only on Linux"
)


def _uid() -> int:
    return os.getuid() if hasattr(os, "getuid") else -1


def _device(**over: Any) -> Device:
    fields: dict[str, Any] = {
        "path": "/dev/fake",
        "model": "SYNTHETIC",
        "serial": "SYN-1",
        "size_bytes": 1024 * 1024,
        "rotational": True,
        "transport": "sata",
        "is_system_disk": False,
        "mounted_at": [],
        "pt_type": None,
        "by_id_path": None,
    }
    fields.update(over)
    return Device(**fields)


@pytest.fixture
def reached(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Replace the engine with a tripwire that records each entry."""
    seen: list[dict[str, Any]] = []

    def engine(self: Any, params: dict[str, Any]) -> Any:
        seen.append({"path": params.get("path")})
        yield from ()
        return {"result": {}}

    for name in ("execute_drive_sanitization", "resume_drive_sanitization"):
        monkeypatch.setattr(f"core.platform.linux.LinuxAdapter.{name}", engine)
    return seen


def _request(tmp_path: Path, extras: dict[str, Any], **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "path": "/dev/fake",
        "job_id": "j",
        "level": "CLEAR",
        "typed_serial": "SYN-1",
        "ledger_root": str(tmp_path / "ledger"),
    }
    return {**base, **extras, **over}


def _send(params: dict[str, Any], method: str = "run_erase") -> Any:
    return HelperDaemon(operator_uid=_uid())._dispatch(method, params)


def _refused(params: dict[str, Any], method: str = "run_erase") -> WorkflowGateRefused:
    with pytest.raises(WorkflowGateRefused) as caught:
        _send(params, method)
    return caught.value


def test_a_valid_authorization_reaches_the_engine_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reached: list[Any]
) -> None:
    patch_probe(monkeypatch, _device())
    extras = make_authorization(tmp_path, _device())
    _send(_request(tmp_path, extras))
    assert reached == [{"path": "/dev/fake"}]
    again = _refused(_request(tmp_path, extras))
    assert "already executed" in " ".join(again.why_blocked)
    assert reached == [{"path": "/dev/fake"}], "the second attempt never reached it"


@pytest.mark.parametrize("method", ["run_erase", "resume_erase"])
def test_a_missing_authorization_is_refused_for_run_and_resume(
    tmp_path: Path, reached: list[Any], method: str
) -> None:
    refusal = _refused(_request(tmp_path, {}), method)
    assert "no authorization" in " ".join(refusal.why_blocked)
    assert refusal.remediation
    assert reached == []


def test_a_fabricated_or_malformed_authorization_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reached: list[Any]
) -> None:
    patch_probe(monkeypatch, _device())
    good = make_authorization(tmp_path, _device())
    fabricated = {
        "authorization": {**good["authorization"], "auth_id": "auth-ffffffffffffffff"},
        "authorization_dir": good["authorization_dir"],
    }
    assert "does not exist" in " ".join(
        _refused(_request(tmp_path, fabricated)).why_blocked
    )
    malformed = {
        "authorization": {**good["authorization"], "auth_id": "../../etc/passwd"},
        "authorization_dir": good["authorization_dir"],
    }
    assert "malformed" in " ".join(_refused(_request(tmp_path, malformed)).why_blocked)
    assert reached == []


@pytest.mark.parametrize(
    ("kwargs", "needle"),
    [
        ({"approved": False}, "approved"),
        ({"spent": False}, "not consumed"),
    ],
)
def test_an_unapproved_or_unspent_record_is_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reached: list[Any],
    kwargs: dict[str, Any],
    needle: str,
) -> None:
    patch_probe(monkeypatch, _device())
    extras = make_authorization(tmp_path, _device(), **kwargs)
    assert needle in " ".join(_refused(_request(tmp_path, extras)).why_blocked)
    assert reached == []


def test_a_request_that_disagrees_with_the_record_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reached: list[Any]
) -> None:
    patch_probe(monkeypatch, _device())
    extras = make_authorization(tmp_path, _device())
    forged = {**extras, "authorization": {**extras["authorization"], "plan": {"x": 1}}}
    assert "plan does not match" in " ".join(
        _refused(_request(tmp_path, forged)).why_blocked
    )
    other_level = _refused(_request(tmp_path, extras, level="PURGE"))
    assert "level" in " ".join(other_level.why_blocked)
    other_path = _refused(_request(tmp_path, extras, path="/dev/other"))
    assert "path" in " ".join(other_path.why_blocked)
    assert reached == []


@pytest.mark.parametrize(
    ("changed", "needle"),
    [
        (_device(serial="SWAPPED"), "serial changed"),
        (_device(model="OTHER-MODEL"), "model changed"),
        (_device(size_bytes=2 * 1024 * 1024), "size_bytes changed"),
        (_device(mounted_at=["/mnt/x"]), "mounted filesystems"),
        (_device(is_system_disk=True), "root filesystem"),
    ],
)
def test_a_device_that_changed_since_approval_is_refused_at_the_seam(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reached: list[Any],
    changed: Device,
    needle: str,
) -> None:
    extras = make_authorization(tmp_path, _device())
    patch_probe(monkeypatch, changed)  # the host now reads something else
    refusal = _refused(_request(tmp_path, extras))
    assert needle in " ".join(refusal.why_blocked)
    assert reached == []
    assert not (Path(extras["authorization_dir"]) / f"{AUTH_ID}.executed").exists(), (
        "a refusal must not burn the execution marker"
    )


def test_a_changed_plan_or_lost_level_is_refused_at_the_seam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reached: list[Any]
) -> None:
    extras = make_authorization(tmp_path, _device())
    patch_probe(monkeypatch, _device(), {**CAPS, "limitations": ["now frozen"]})
    assert "limitations changed" in " ".join(
        _refused(_request(tmp_path, extras)).why_blocked
    )
    patch_probe(monkeypatch, _device(), {**CAPS, "achievable_levels": ["PURGE"]})
    assert "not achievable" in " ".join(
        _refused(_request(tmp_path, extras)).why_blocked
    )
    patch_probe(monkeypatch, _device(), None)
    assert "could not be probed" in " ".join(
        _refused(_request(tmp_path, extras)).why_blocked
    )
    assert reached == []


def test_a_changed_backup_is_refused_at_the_seam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reached: list[Any]
) -> None:
    patch_probe(monkeypatch, _device())
    extras = make_authorization(tmp_path, _device())
    image = tmp_path / "backup.img"
    before = image.stat()
    with image.open("r+b") as handle:
        handle.write(b"tampered")
    os.utime(image, ns=(before.st_atime_ns, before.st_mtime_ns))  # mtime restored
    assert "backup" in " ".join(_refused(_request(tmp_path, extras)).why_blocked)
    image.unlink()
    assert "backup" in " ".join(_refused(_request(tmp_path, extras)).why_blocked)
    assert reached == []


def test_a_record_without_the_backup_fingerprint_is_refused_at_the_seam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reached: list[Any]
) -> None:
    """A record from before inode and ctime were bound: refused, not assumed."""
    patch_probe(monkeypatch, _device())
    extras = make_authorization(tmp_path, _device())
    record_file = Path(extras["authorization_dir"]) / f"{AUTH_ID}.json"
    record = json.loads(record_file.read_text(encoding="utf-8"))
    for field in ("ctime_ns", "inode"):
        record["backup"].pop(field)
        extras["authorization"]["backup"].pop(field, None)
    record_file.write_text(json.dumps(record), encoding="utf-8")
    assert "backup" in " ".join(_refused(_request(tmp_path, extras)).why_blocked)
    assert reached == []


def test_a_device_that_cannot_be_reread_is_refused_not_assumed_fine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reached: list[Any]
) -> None:
    extras = make_authorization(tmp_path, _device())

    def gone(path: str) -> Any:
        raise OSError("no such device: /secret/path")

    monkeypatch.setattr("helper.authorization._fresh_probe", gone)
    refusal = _refused(_request(tmp_path, extras))
    assert "could not be re-read" in " ".join(refusal.why_blocked)
    assert "/secret/path" not in refusal.message, "the OS message is not echoed"
    assert reached == []


def test_concurrent_attempts_with_one_authorization_admit_exactly_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reached: list[Any]
) -> None:
    """Twelve threads pass every check; the exclusive marker admits one."""
    patch_probe(monkeypatch, _device())
    extras = make_authorization(tmp_path, _device())
    barrier = threading.Barrier(12)
    outcomes: list[str] = []
    lock = threading.Lock()

    def attempt() -> None:
        barrier.wait()
        try:
            _send(_request(tmp_path, extras))
            result = "admitted"
        except WorkflowGateRefused:
            result = "refused"
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=attempt) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert sorted(outcomes) == ["admitted"] + ["refused"] * 11
    assert len(reached) == 1


@pytest.mark.parametrize("method", ["run_erase", "resume_erase"])
def test_a_request_without_an_authorization_never_reaches_the_engine(
    tmp_path: Path, reached: list[Any], method: str
) -> None:
    """There is no exempt mode: a bare request is refused at the seam."""
    refusal = _refused(_request(tmp_path, {}), method)
    assert "no authorization" in " ".join(refusal.why_blocked)
    assert reached == []


@pytest.mark.parametrize("method", ["run_erase", "resume_erase"])
@pytest.mark.parametrize("key", ["dry_run", "simulation", "simulate"])
@pytest.mark.parametrize("value", [True, False])
def test_a_simulation_switch_is_refused_even_with_a_valid_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reached: list[Any],
    method: str,
    key: str,
    value: bool,
) -> None:
    """Neither honoured nor dropped: refused before the record is spent."""
    patch_probe(monkeypatch, _device())
    extras = make_authorization(tmp_path, _device())
    refusal = _refused(_request(tmp_path, extras, **{key: value}), method)
    assert key in refusal.message
    assert reached == []
    # The authorization is still good for one real run.
    _send(_request(tmp_path, extras), method)
    assert len(reached) == 1
