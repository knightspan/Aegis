"""The shared PhotoRec invocation, driven with a stub instead of a scanner.

Two scripts used to hold a copy each of this call. The before/after count is
only worth anything because both runs are the *same* measurement, so a
difference either copy could acquire without anyone noticing is a difference in
a number that goes on a slide. There is one definition now, and these tests hold
down the three properties that made the duplication expensive:

* the option set is the recorded one unless someone deliberately changes it;
* a scan that runs too long is killed and reported, not waited on;
* a scan that is merely slow says so while it runs.

No real PhotoRec, no device. A stub on PATH stands in for the scanner.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

STEPS = Path(__file__).resolve().parents[2] / "scripts" / "harness-steps.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None, reason="bash is not available"
)


#: harness_photorec refuses a memory-backed or undersized output directory
#: before it runs anything - see tests/scripts/test_workdir_guard.py. pytest's
#: tmp_path is under /tmp, which is tmpfs on the development host, so these
#: tests would exercise that refusal instead of the scan. A `df` reporting a
#: roomy ext4 keeps them about PhotoRec.
DF_STUB = """#!/usr/bin/env bash
if [[ "$1" == "--output=fstype" ]]; then printf 'Type\next4\n'
else printf 'Avail\n999999999999\n'; fi
"""


def stub_photorec(tmp_path: Path, body: str) -> Path:
    """Put a fake `photorec` on PATH. ``body`` is its bash implementation."""
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir(exist_ok=True)
    script = binary_dir / "photorec"
    script.write_text(f"#!/usr/bin/env bash\n{body}\n")
    script.chmod(0o755)
    df = binary_dir / "df"
    df.write_text(DF_STUB)
    df.chmod(0o755)
    return binary_dir


def run_bash(
    script: str, tmp_path: Path, *, path_prefix: Path | None = None
) -> subprocess.CompletedProcess[str]:
    prefix = f'export PATH="{path_prefix}:$PATH"\n' if path_prefix else ""
    body = (
        f'set -uo pipefail\nPY="{shutil.which("python3")}"\n'
        f'{prefix}. "{STEPS}"\n{script}\n'
    )
    return subprocess.run(
        ["bash", "-c", body], capture_output=True, text=True, cwd=tmp_path, check=False
    )


def read_json(path: Path) -> dict:
    return json.loads(path.read_text())


# --------------------------------------------------------------------------
# The option set
# --------------------------------------------------------------------------


def test_the_default_option_set_is_the_one_the_published_numbers_used(
    tmp_path: Path,
) -> None:
    """docs/validation/hardware.md quotes this string. It is the baseline."""
    result = run_bash('printf "%s" "$HARNESS_PHOTOREC_OPTS_FULL"', tmp_path)
    assert result.stdout == "partition_none,fileopt,everything,enable,search"


def test_the_narrow_set_is_available_but_is_not_the_default(tmp_path: Path) -> None:
    """Narrowing breaks comparability with Phase A, so it has to be chosen."""
    result = run_bash(
        'printf "%s\\n%s" "${SANCTUM_PHOTOREC_OPTS:-$HARNESS_PHOTOREC_OPTS_FULL}" '
        '"$HARNESS_PHOTOREC_OPTS_PLANTED"',
        tmp_path,
    )
    default, planted = result.stdout.split("\n")
    assert default == "partition_none,fileopt,everything,enable,search"
    assert default != planted
    for fmt in ("jpg", "png", "pdf", "zip", "gif", "sqlite"):
        assert f"{fmt},enable" in planted


def test_the_chosen_options_are_recorded_in_the_result(tmp_path: Path) -> None:
    """A number is not comparable unless the run says what produced it."""
    binary_dir = stub_photorec(tmp_path, "exit 0")
    run_bash(
        'SANCTUM_PHOTOREC_OPTS="partition_none,search" '
        'harness_photorec before /dev/null out scan.json || true',
        tmp_path,
        path_prefix=binary_dir,
    )
    recorded = read_json(tmp_path / "scan.json")
    assert recorded["options"] == "partition_none,search"
    assert "partition_none,search" in recorded["command"]


# --------------------------------------------------------------------------
# The bound
# --------------------------------------------------------------------------


def test_a_scan_that_overruns_is_killed_and_reported(tmp_path: Path) -> None:
    """A step that can silently consume hours has no place in a pre-demo script."""
    binary_dir = stub_photorec(tmp_path, "sleep 30")
    result = run_bash(
        "SANCTUM_PHOTOREC_TIMEOUT_S=1 SANCTUM_PHOTOREC_HEARTBEAT_S=1 "
        "harness_photorec before /dev/null out scan.json || true\n"
        "harness_summary || true",
        tmp_path,
        path_prefix=binary_dir,
    )
    recorded = read_json(tmp_path / "scan.json")
    assert recorded["timed_out"] is True
    assert recorded["timeout_seconds"] == 1
    assert "still running after" in result.stdout
    assert recorded["returncode"] in (124, 137)


def test_a_timeout_is_a_recorded_failure_not_a_zero_count(tmp_path: Path) -> None:
    """`0 files` from a killed scan would read as `nothing was recoverable`."""
    binary_dir = stub_photorec(tmp_path, "sleep 30")
    result = run_bash(
        "SANCTUM_PHOTOREC_TIMEOUT_S=1 SANCTUM_PHOTOREC_HEARTBEAT_S=1 "
        "harness_photorec before /dev/null out scan.json || true\n"
        'printf "failures=%s" "$(harness_failure_count)"',
        tmp_path,
        path_prefix=binary_dir,
    )
    assert "failures=1" in result.stdout


def test_a_scan_that_finishes_inside_the_bound_is_not_a_failure(
    tmp_path: Path,
) -> None:
    binary_dir = stub_photorec(tmp_path, "exit 0")
    result = run_bash(
        "SANCTUM_PHOTOREC_TIMEOUT_S=30 SANCTUM_PHOTOREC_HEARTBEAT_S=1 "
        "harness_photorec before /dev/null out scan.json\n"
        'printf "failures=%s" "$(harness_failure_count)"',
        tmp_path,
        path_prefix=binary_dir,
    )
    assert "failures=0" in result.stdout
    assert read_json(tmp_path / "scan.json")["timed_out"] is False


def test_a_nonzero_photorec_is_a_failure_because_nobody_looked(
    tmp_path: Path,
) -> None:
    binary_dir = stub_photorec(tmp_path, 'echo "no such device" >&2; exit 3')
    result = run_bash(
        "SANCTUM_PHOTOREC_TIMEOUT_S=30 SANCTUM_PHOTOREC_HEARTBEAT_S=1 "
        "harness_photorec before /dev/null out scan.json || true\n"
        'printf "failures=%s" "$(harness_failure_count)"',
        tmp_path,
        path_prefix=binary_dir,
    )
    assert "failures=1" in result.stdout
    assert read_json(tmp_path / "scan.json")["returncode"] == 3


# --------------------------------------------------------------------------
# The pulse
# --------------------------------------------------------------------------


def test_a_running_scan_prints_a_heartbeat(tmp_path: Path) -> None:
    """Running and hung must not look the same on the console."""
    binary_dir = stub_photorec(tmp_path, "sleep 3")
    result = run_bash(
        "SANCTUM_PHOTOREC_TIMEOUT_S=30 SANCTUM_PHOTOREC_HEARTBEAT_S=1 "
        "harness_photorec before /dev/null out scan.json",
        tmp_path,
        path_prefix=binary_dir,
    )
    assert "alive at" in result.stdout
    assert "bound    30s" in result.stdout


# --------------------------------------------------------------------------
# Counting
# --------------------------------------------------------------------------


def test_photorec_s_own_report_and_log_are_not_counted_as_recoveries(
    tmp_path: Path,
) -> None:
    """They appear in both runs, and in the `after` run they would be the count."""
    recup = tmp_path / "out" / "recup.1"
    recup.mkdir(parents=True)
    (recup / "f0000001.jpg").write_bytes(b"x")
    (recup / "f0000002.png").write_bytes(b"x")
    (recup / "report.xml").write_bytes(b"x")
    (recup / "photorec.log").write_bytes(b"x")
    (tmp_path / "out" / "photorec.out").write_bytes(b"x")

    result = run_bash('harness_photorec_count out', tmp_path)
    assert result.stdout.strip() == "2"
