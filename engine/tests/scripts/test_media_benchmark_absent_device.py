"""A device that is not there fails cleanly, and nothing stands in for it.

``plan`` and ``verify-backup`` used to let ``lsblk``'s exit status escape as a
``CalledProcessError`` traceback when ``--device`` named a path that no longer
existed - a stick pulled after the preflight, or a ``/dev/disk/by-id`` link
left dangling. The operator saw a stack trace instead of a reason.

These tests drive ``main`` the way the operator does and assert four things
for every absent-device case: a structured refusal on stdout, no traceback, no
file created on host storage, and no probe run against any other path. The
last one is the substitution guard: an absent ``/dev/sdb`` must never quietly
become a check of ``/dev/sdc``.

No test here touches a real device. The only host probe that runs is the
existence check, and it runs against paths under ``tmp_path``.
"""

from __future__ import annotations

import errno
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from scripts.media_benchmark import DeviceUnavailable, Refused, _lsblk, main

SERIAL = "B103B9C19DE1CCC1BD535ACB"


@pytest.fixture
def probes(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Record every subprocess the script starts, and start none of them."""
    calls: list[list[str]] = []

    def record(argv: Any, *args: Any, **kwargs: Any) -> Any:
        calls.append([str(part) for part in argv])
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr("scripts.media_benchmark.subprocess.run", record)
    return calls


def _run(command: str, device: str, work: Path) -> list[str]:
    argv = [command, "--device", device, "--work", str(work), "--expect-serial", SERIAL]
    return argv + (["--json"] if command == "plan" else [])


@pytest.mark.parametrize("command", ["plan", "verify-backup", "backup", "preflight"])
def test_a_missing_device_is_a_clean_refusal(
    command: str,
    tmp_path: Path,
    probes: list[list[str]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    device = tmp_path / "sdzz"
    work = tmp_path / "work"
    argv = _run(command, str(device), work)
    if command == "preflight":
        argv = ["preflight", "--device", str(device), "--expect-serial", SERIAL]
    code = main(argv)
    out = capsys.readouterr()
    reply = json.loads(out.out)
    assert code == 2
    assert reply["kind"] == "unavailable"
    assert "does not exist" in reply["refused"]
    assert "No other device was substituted" in reply["refused"]
    assert "Traceback" not in out.out + out.err
    assert "SAFE" not in out.out
    # Nothing probed, nothing created.
    assert probes == []
    assert not work.exists()
    assert not device.exists()


@pytest.mark.parametrize("command", ["plan", "verify-backup"])
def test_a_stale_by_id_link_names_itself_and_is_not_followed_elsewhere(
    command: str,
    tmp_path: Path,
    probes: list[list[str]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    by_id = tmp_path / "by-id"
    by_id.mkdir()
    link = by_id / f"usb-TransMemory_{SERIAL}-0:0"
    link.symlink_to("../../sdb")
    # A different, present "device" next to it. It must not be looked at.
    (tmp_path / "sdc").write_bytes(b"\0" * 512)
    work = tmp_path / "work"
    code = main(_run(command, str(link), work))
    out = capsys.readouterr()
    reply = json.loads(out.out)
    assert code == 2
    assert reply["kind"] == "unavailable"
    assert "../../sdb" in reply["refused"]
    assert "stale" in reply["refused"]
    assert "Traceback" not in out.out + out.err
    assert "SAFE" not in out.out
    assert probes == []
    assert not work.exists()


def test_a_device_lsblk_will_not_describe_is_unavailable_not_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The path exists, but the kernel no longer has a block device behind it."""
    node = tmp_path / "sdb"
    node.write_bytes(b"")

    def gone(argv: Any, *args: Any, **kwargs: Any) -> Any:
        raise subprocess.CalledProcessError(
            32, argv, output="", stderr=f"lsblk: {node}: not a block device"
        )

    monkeypatch.setattr("scripts.media_benchmark.subprocess.run", gone)
    with pytest.raises(DeviceUnavailable, match="not a block device") as refused:
        _lsblk(str(node))
    assert refused.value.kind == "unavailable"
    assert node.read_bytes() == b""


def test_unparseable_lsblk_output_is_a_refusal_not_a_guess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    node = tmp_path / "sdb"
    node.write_bytes(b"")
    monkeypatch.setattr(
        "scripts.media_benchmark.subprocess.run",
        lambda argv, *a, **k: subprocess.CompletedProcess(
            argv, 0, stdout="{", stderr=""
        ),
    )
    with pytest.raises(Refused, match="could not be parsed"):
        _lsblk(str(node))


@pytest.mark.parametrize("command", ["plan", "verify-backup"])
def test_an_unrelated_io_error_is_reported_as_an_error_not_a_verdict(
    command: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def failing(device: str) -> Any:
        raise OSError(errno.EIO, "Input/output error", device)

    monkeypatch.setattr("scripts.media_benchmark._lsblk", failing)
    work = tmp_path / "work"
    code = main(_run(command, str(tmp_path / "sdb"), work))
    out = capsys.readouterr()
    reply = json.loads(out.out)
    assert code == 3
    assert reply["kind"] == "io"
    assert reply["errno"] == errno.EIO
    assert reply["device_state"] == "not written by this command"
    assert "refused" not in reply
    assert "Traceback" not in out.out + out.err
    assert "SAFE" not in out.out
    assert not work.exists()


def test_an_io_error_during_write_does_not_claim_the_device_is_untouched(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def failing(*args: Any, **kwargs: Any) -> Any:
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr("scripts.media_benchmark.write_image", failing)
    code = main(
        [
            "write",
            "--device",
            str(tmp_path / "sdb"),
            "--work",
            str(tmp_path),
            "--expect-serial",
            SERIAL,
            "--confirm-serial",
            SERIAL,
            "--i-understand-this-destroys-data",
        ]
    )
    reply = json.loads(capsys.readouterr().out)
    assert code == 3
    assert reply["device_state"].startswith("unknown")


def test_a_present_device_still_reaches_the_permission_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The absent-device check must not swallow the privilege refusal.

    A device that exists but cannot be opened is a different answer - the
    right target, missing privilege - and the existing ``kind == "privilege"``
    path is what reports it. Here the existence check passes and the probe
    that follows it runs, which is the precondition for that path.
    """
    node = tmp_path / "sdb"
    node.write_bytes(b"")
    seen: list[str] = []

    def described(argv: Any, *args: Any, **kwargs: Any) -> Any:
        seen.append(str(argv[-1]))
        return subprocess.CompletedProcess(
            argv, 0, stdout=json.dumps({"blockdevices": [{"name": "sdb"}]}), stderr=""
        )

    monkeypatch.setattr("scripts.media_benchmark.subprocess.run", described)
    assert _lsblk(str(node))["name"] == "sdb"
    assert seen == [str(node)]
