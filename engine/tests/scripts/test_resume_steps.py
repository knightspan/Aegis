"""Resuming a --full stage instead of restarting it.

demo-reset.sh --full is a ninety-five-minute job whose steps write to a real
device. It crashed thirty-three minutes in, at step 3 of 7 - ``line 716: label:
unbound variable`` - and the only way to retry was to start again from the
thirty-minute pattern write.

These drive the step bookkeeping directly. What they do not cover is a real
--full run: that needs root and a device.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
STEPS = REPO / "scripts" / "harness-steps.sh"

ORDER = (
    "state key pattern plant photorec-before erase verify photorec-after "
    "report livewipe recovery snapshot"
)


def run(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "bash",
            "-c",
            "set -uo pipefail\n"
            f'PY="{REPO}/.venv/bin/python"\n'
            f'source "{STEPS}"\nharness_reset\n'
            f"harness_steps_define {ORDER}\n{script}",
        ],
        capture_output=True,
        text=True,
        cwd=REPO,
    )


def selection(resume_from: str | None) -> list[str]:
    """Which steps a run would execute, given a resume point."""
    resume = f'harness_resume_from "{resume_from}"\n' if resume_from else ""
    result = run(
        resume + "for s in " + ORDER + '; do\n'
        '  harness_should_run "$s" && echo "$s"\n'
        "done\n"
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.split()


def test_without_resume_every_step_runs() -> None:
    assert selection(None) == ORDER.split()


def test_resuming_skips_only_what_came_before() -> None:
    """The case that cost thirty-three minutes: restart at the failing step."""
    assert selection("photorec-before") == [
        "photorec-before",
        "erase",
        "verify",
        "photorec-after",
        "report",
        "livewipe",
        "recovery",
        "snapshot",
    ]


def test_resuming_from_the_first_step_runs_everything() -> None:
    assert selection("state") == ORDER.split()


def test_an_unknown_step_is_refused() -> None:
    """Not silently ignored. A typo must not quietly skip destructive work."""
    result = run('harness_resume_from "photrec-before" && echo ACCEPTED')

    assert "ACCEPTED" not in result.stdout


def test_the_checkpoint_names_where_a_retry_starts(tmp_path: Path) -> None:
    """After a step completes, the retry point is the step after it."""
    marker = tmp_path / "last-step"
    result = run(
        f'harness_step_file "{marker}"\n'
        "harness_checkpoint pattern\n"
        'printf "next=%s\\n" "$(harness_next_step)"'
    )

    assert "next=plant" in result.stdout


def test_no_checkpoint_means_start_from_the_beginning(tmp_path: Path) -> None:
    result = run(
        f'harness_step_file "{tmp_path / "absent"}"\n'
        'printf "next=%s\\n" "$(harness_next_step)"'
    )

    assert "next=state" in result.stdout


def test_a_completed_run_has_nothing_to_resume(tmp_path: Path) -> None:
    """Otherwise every clean stage would end by offering a resume command."""
    marker = tmp_path / "last-step"
    result = run(
        f'harness_step_file "{marker}"\n'
        "harness_checkpoint snapshot\n"
        'printf "next=[%s]\\n" "$(harness_next_step)"'
    )

    assert "next=[]" in result.stdout


def test_list_steps_needs_no_root_and_no_device() -> None:
    """The operator has to be able to read the step names before staging."""
    result = subprocess.run(
        ["./scripts/demo-reset.sh", "--list-steps"],
        capture_output=True,
        text=True,
        cwd=REPO,
    )

    assert result.returncode == 0, result.stderr
    for step in ORDER.split():
        assert step in result.stdout
    assert "--resume-from" in result.stdout


def test_resume_from_is_rejected_before_anything_is_written() -> None:
    """A bad step name must not get as far as the device gates."""
    result = subprocess.run(
        [
            "./scripts/demo-reset.sh",
            "--full",
            "--usb",
            "/dev/null",
            "--i-understand-this-destroys-data",
            "--resume-from",
            "nonsense",
        ],
        capture_output=True,
        text=True,
        cwd=REPO,
    )

    assert result.returncode != 0
    assert "unknown step 'nonsense'" in result.stderr
    # It lists the real names rather than leaving the operator to guess.
    assert "photorec-before" in result.stdout
