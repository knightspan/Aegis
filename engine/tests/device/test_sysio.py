"""SubprocessRunner: the real Runner, not a fake.

A console=False packaged app has no console of its own; CreateProcess then
opens a brand new one for any console-subsystem child (powershell.exe here)
unless told not to - visible for the whole call even though output is
piped. Seen for real: a Windows Terminal window flashing on every nav click
that reached device inventory, 2026-09-27.
"""

from __future__ import annotations

import subprocess
import sys
from unittest.mock import patch

from core.device._sysio import SubprocessRunner


def _fake_completed(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(argv, 0, "ok", "")


def test_windows_subprocess_calls_ask_for_a_hidden_console() -> None:
    # CREATE_NO_WINDOW only exists on the real subprocess module on real
    # Windows; create=True lets this test inject it on every CI host so the
    # assertion below is meaningful there too, not just on a Windows runner.
    with (
        patch.object(sys, "platform", "win32"),
        patch.object(subprocess, "CREATE_NO_WINDOW", 0x08000000, create=True),
        patch("subprocess.run") as mock_run,
    ):
        mock_run.return_value = _fake_completed(["powershell.exe"])
        SubprocessRunner(timeout_s=5.0).run(["powershell.exe", "-NoProfile"])

    assert mock_run.call_args.kwargs["creationflags"] == 0x08000000


def test_non_windows_subprocess_calls_pass_a_no_op_creationflags() -> None:
    with patch.object(sys, "platform", "linux"), patch("subprocess.run") as mock_run:
        mock_run.return_value = _fake_completed(["lsblk"])
        SubprocessRunner(timeout_s=5.0).run(["lsblk"])

    assert mock_run.call_args.kwargs["creationflags"] == 0


def test_the_command_result_is_unchanged_by_the_fix() -> None:
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = _fake_completed(["echo", "hi"])
        result = SubprocessRunner(timeout_s=5.0).run(["echo", "hi"])

    assert result.returncode == 0
    assert result.stdout == "ok"
