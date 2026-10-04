"""The hardware harness's step bookkeeping, driven without a device.

``scripts/harness-steps.sh`` is sourced by ``hardware-validation.sh`` and holds
every function that decides whether a phase failed. It is tested here because
the defect it exists to prevent is not a wrong number - it is a silence. The
Phase A run in ``docs/validation/results-20260904T163645Z`` printed "COMPLETE"
over a wipe that covered 512 bytes of a 7.76 GB device, because no step checked
an exit status, nothing printed a verification verdict, and the exit code was 0.

Each test drives bash directly. No block device, no root, no target.
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


def run_bash(script: str, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    """Source the step library and run ``script`` against it."""
    body = f'set -uo pipefail\nPY="{shutil.which("python3")}"\n. "{STEPS}"\n{script}\n'
    return subprocess.run(
        ["bash", "-c", body],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        check=False,
    )


# --------------------------------------------------------------------------
# A step that fails must be recorded, printed, and carried to the exit status
# --------------------------------------------------------------------------


def test_a_nonzero_exit_is_recorded_and_printed(tmp_path: Path) -> None:
    result = run_bash(
        """
        printf 'boom\\n' > err.txt
        harness_check "A.7 report" 1 out.json err.txt || true
        harness_summary
        """,
        tmp_path,
    )

    assert "A.7 report FAILED: exit 1" in result.stdout
    assert "| boom" in result.stdout, "the stderr file must reach the console"
    assert result.returncode != 0


def test_a_zero_byte_output_file_is_a_failure_not_a_pass(tmp_path: Path) -> None:
    """A.7 exited non-zero *and* left an empty a7-report.json.

    Either one alone is enough to call the phase failed.
    """
    (tmp_path / "out.json").write_text("")
    (tmp_path / "err.txt").write_text("Traceback (most recent call last):\n")

    result = run_bash(
        """
        harness_check "A.7 report" 0 out.json err.txt || true
        harness_summary
        """,
        tmp_path,
    )

    assert "zero bytes" in result.stdout
    assert "Traceback" in result.stdout
    assert result.returncode != 0


def test_a_good_step_records_nothing(tmp_path: Path) -> None:
    (tmp_path / "out.json").write_text('{"step": "ok"}')
    (tmp_path / "err.txt").write_text("")

    result = run_bash(
        """
        harness_check "A.1 enumerate" 0 out.json err.txt
        harness_summary
        """,
        tmp_path,
    )

    assert result.returncode == 0
    assert "FAILED" not in result.stdout


def test_harness_step_runs_the_command_and_captures_both_streams(
    tmp_path: Path,
) -> None:
    result = run_bash(
        """
        harness_step "step" out.json err.txt \
            bash -c 'echo "{}"; echo trouble >&2; exit 3' || true
        harness_summary
        """,
        tmp_path,
    )

    assert "step FAILED: exit 3" in result.stdout
    assert "| trouble" in result.stdout
    assert (tmp_path / "out.json").read_text().strip() == "{}"
    assert result.returncode != 0


def test_failures_are_written_where_the_write_up_can_find_them(
    tmp_path: Path,
) -> None:
    run_bash(
        """
        harness_fail "A.4 erase" "the erase covered less than the whole device"
        harness_write_failures failures.json
        """,
        tmp_path,
    )

    document = json.loads((tmp_path / "failures.json").read_text())
    assert document["failures"] == 1
    assert document["failed_phases"] == [
        "A.4 erase: the erase covered less than the whole device"
    ]


def test_an_empty_failure_list_is_still_written(tmp_path: Path) -> None:
    """"Nothing failed" is a claim, and it needs a file behind it."""
    run_bash("harness_write_failures failures.json", tmp_path)

    document = json.loads((tmp_path / "failures.json").read_text())
    assert document == {"failed_phases": [], "failures": 0}


# --------------------------------------------------------------------------
# The counting bug: grep -c prints 0 and exits 1
# --------------------------------------------------------------------------


def test_count_matches_returns_one_zero_not_two(tmp_path: Path) -> None:
    """A.1 logged "exit 0; 0\\n0 disagreement(s)" from `grep -c ... || echo 0`."""
    (tmp_path / "a1.json").write_text('{"disagreements": []}')

    result = run_bash('count_matches \'"field"\' a1.json', tmp_path)

    assert result.stdout == "0"


def test_count_matches_counts_real_matches(tmp_path: Path) -> None:
    (tmp_path / "a1.json").write_text('"field": 1\n"field": 2\n"other": 3\n')

    result = run_bash('count_matches \'"field"\' a1.json', tmp_path)

    assert result.stdout == "2"


def test_count_matches_on_a_missing_file_is_zero(tmp_path: Path) -> None:
    result = run_bash("count_matches 'x' nope.json", tmp_path)

    assert result.stdout == "0"


# --------------------------------------------------------------------------
# The verification verdict must be printed in full and must fail the run
# --------------------------------------------------------------------------


VERIFY_FAILED = {
    "step": "verify",
    "result": {
        "passed": False,
        "strategy": "full_read",
        "bytes_checked": 7759462400,
        "sample_count": 0,
        "confidence_bp": 10000,
        "failed_offsets": [9728, 1048576, 7758413824],
        "hw_attested": False,
        "probability_note": "Every addressable block was read and compared.",
    },
}

VERIFY_PASSED = {
    "step": "verify",
    "result": {
        **VERIFY_FAILED["result"],  # type: ignore[dict-item]
        "passed": True,
        "failed_offsets": [],
    },
}


def test_a_failed_verification_prints_every_field_and_fails_the_run(
    tmp_path: Path,
) -> None:
    """What A.5 should have printed. It printed "strategy=full_read"."""
    (tmp_path / "a5.json").write_text(json.dumps(VERIFY_FAILED))

    result = run_bash(
        'harness_report_verification "A.5 verify" a5.json || true; harness_summary',
        tmp_path,
    )

    assert "passed=False" in result.stdout
    assert "strategy=full_read" in result.stdout
    assert "bytes_checked=7759462400" in result.stdout
    assert "sample_count=0" in result.stdout
    assert "failed_offsets: 3 (min 9728, max 7758413824)" in result.stdout
    assert "A.5 verify FAILED: verification did not pass" in result.stdout
    assert result.returncode != 0


def test_a_passing_verification_prints_the_same_fields_and_does_not_fail(
    tmp_path: Path,
) -> None:
    (tmp_path / "a5.json").write_text(json.dumps(VERIFY_PASSED))

    result = run_bash(
        'harness_report_verification "A.5 verify" a5.json; harness_summary', tmp_path
    )

    assert "passed=True" in result.stdout
    assert "failed_offsets: 0" in result.stdout
    assert "FAILED" not in result.stdout
    assert result.returncode == 0


def test_an_empty_verification_file_is_a_failure(tmp_path: Path) -> None:
    (tmp_path / "a5.json").write_text("")

    result = run_bash(
        'harness_report_verification "A.5 verify" a5.json || true; harness_summary',
        tmp_path,
    )

    assert "NO RESULT IN OUTPUT" in result.stdout
    assert result.returncode != 0


# --------------------------------------------------------------------------
# The erase verdict must be printed and a short write must fail the run
# --------------------------------------------------------------------------


ERASE_SHORT = {
    "step": "erase",
    "result": {
        "bytes_written": 512,
        "method": "SINGLE_PASS_OVERWRITE",
        "level": "CLEAR",
        "passes": 1,
        "hw_attested": False,
        "limitations": [],
        "residual_risk": {
            "level": "high",
            "purge_achieved": False,
            "notes": "Verification failed: residual data was read back.",
        },
    },
}


def test_a_short_write_is_printed_and_fails_the_run(tmp_path: Path) -> None:
    """The exact shape of the defect: 512 bytes written to a 7.76 GB device."""
    (tmp_path / "a4.json").write_text(json.dumps(ERASE_SHORT))

    result = run_bash(
        'harness_report_erase "A.4 erase" a4.json 7759462400 || true; harness_summary',
        tmp_path,
    )

    assert "bytes_written: 512 of 7759462400 (0.00% of the device)" in result.stdout
    assert "residual risk: high purge_achieved=False" in result.stdout
    assert "Verification failed: residual data was read back." in result.stdout
    assert "SHORT WRITE" in result.stdout
    assert "A.4 erase FAILED" in result.stdout
    assert result.returncode != 0


def test_a_full_write_prints_the_risk_and_passes(tmp_path: Path) -> None:
    document = json.loads(json.dumps(ERASE_SHORT))
    document["result"]["bytes_written"] = 7759462400
    document["result"]["residual_risk"] = {
        "level": "medium",
        "purge_achieved": False,
        "notes": "Erase completed and verified within the stated sampling limits.",
    }
    (tmp_path / "a4.json").write_text(json.dumps(document))

    result = run_bash(
        'harness_report_erase "A.4 erase" a4.json 7759462400; harness_summary',
        tmp_path,
    )

    assert "100.00% of the device" in result.stdout
    assert "residual risk: medium" in result.stdout
    assert "FAILED" not in result.stdout
    assert result.returncode == 0


def test_an_erase_that_errored_reports_the_error(tmp_path: Path) -> None:
    (tmp_path / "a4.json").write_text(
        json.dumps({"step": "erase", "error": "device vanished"})
    )

    result = run_bash(
        'harness_report_erase "A.4 erase" a4.json 100 || true; harness_summary',
        tmp_path,
    )

    assert "erase error: device vanished" in result.stdout
    assert result.returncode != 0


# --------------------------------------------------------------------------
# The driver itself: no step may go unchecked again
# --------------------------------------------------------------------------

DRIVER = Path(__file__).resolve().parents[2] / "scripts" / "hardware-validation.sh"


def test_the_driver_sources_the_step_library() -> None:
    assert '. "$REPO/scripts/harness-steps.sh"' in DRIVER.read_text()


def test_every_python_subcommand_goes_through_harness_step() -> None:
    """The rule, enforced rather than remembered.

    Each unchecked invocation is one more way for a crashed step to leave a
    zero-byte JSON file and a clean console, which is exactly what A.7 did.
    """
    lines = DRIVER.read_text().splitlines()
    unchecked = [
        (number, line)
        for number, line in enumerate(lines, 1)
        if 'scripts/hardware_validation.py' in line
        and not lines[number - 2].lstrip().startswith(
            ("harness_step", '"$RUN_DIR', '"$PY"')
        )
    ]
    assert unchecked == [], f"unchecked python invocations: {unchecked}"


def test_the_driver_is_syntactically_valid() -> None:
    result = subprocess.run(
        ["bash", "-n", str(DRIVER)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr


def test_the_driver_exits_non_zero_when_a_phase_failed() -> None:
    text = DRIVER.read_text()
    assert "harness_write_failures" in text
    assert "if harness_summary; then" in text
    assert "COMPLETE WITH FAILURES" in text


# --------------------------------------------------------------------------
# Reading a count out of a step's own JSON, rather than grepping for a key
# --------------------------------------------------------------------------


def test_json_field_reads_the_recorded_count(tmp_path: Path) -> None:
    """"planted 11 files" for 14 planted files came from grepping key names."""
    (tmp_path / "plant.json").write_text(
        json.dumps({"files": 14, "unique_digests": 11, "duplicate_content_files": 3})
    )

    result = run_bash('harness_json_field plant.json files', tmp_path)

    assert result.stdout.strip() == "14"


def test_json_field_on_a_missing_field_is_empty(tmp_path: Path) -> None:
    (tmp_path / "plant.json").write_text("{}")

    result = run_bash('harness_json_field plant.json files', tmp_path)

    assert result.stdout.strip() == ""


def test_json_field_on_unparsable_json_does_not_crash(tmp_path: Path) -> None:
    (tmp_path / "plant.json").write_text("not json at all")

    result = run_bash('harness_json_field plant.json files', tmp_path)

    assert result.returncode == 0
    assert result.stdout.strip() == ""


# --------------------------------------------------------------------------
# A.5 must verify the byte the erase wrote, not the method's default
# --------------------------------------------------------------------------


def test_the_erase_fill_is_read_from_the_plan(tmp_path: Path) -> None:
    (tmp_path / "a4.json").write_text(
        json.dumps({"result": {"plan": {"fill_bytes": ["0xA5"]}}})
    )

    result = run_bash("harness_erase_fill a4.json", tmp_path)

    assert result.stdout.strip() == "0xA5"


def test_the_last_fill_wins_for_a_multi_pass_method(tmp_path: Path) -> None:
    """Verification checks what the medium holds at the end."""
    (tmp_path / "a4.json").write_text(
        json.dumps({"result": {"plan": {"fill_bytes": ["0xA5", "0xFF", "0xA5"]}}})
    )

    result = run_bash("harness_erase_fill a4.json", tmp_path)

    assert result.stdout.strip() == "0xA5"


def test_a_plan_without_fills_reports_empty(tmp_path: Path) -> None:
    (tmp_path / "a4.json").write_text(json.dumps({"result": {"plan": {}}}))

    result = run_bash("harness_erase_fill a4.json", tmp_path)

    assert result.stdout.strip() == ""


def test_an_unreadable_erase_json_reports_empty(tmp_path: Path) -> None:
    result = run_bash("harness_erase_fill nope.json", tmp_path)

    assert result.returncode == 0
    assert result.stdout.strip() == ""


def test_the_driver_passes_the_recorded_fill_to_a5() -> None:
    """Without this, a correct 0xA5 wipe is reported as a failed verification."""
    text = DRIVER.read_text()

    assert 'harness_erase_fill "$RUN_DIR/a4-erase.json"' in text
    assert '--expect-fill "$expect_fill"' in text


# --------------------------------------------------------------------------
# Clearing the write block is an explicit, logged, checked action
# --------------------------------------------------------------------------


def fake_device(tmp_path: Path, flag_script: str) -> Path:
    """A stand-in for $PY whose BLKROGET/BLKROSET answers are scripted."""
    stub = tmp_path / "fakepy"
    stub.write_text(f"#!/bin/sh\n{flag_script}\n")
    stub.chmod(0o755)
    return stub


def run_clear(tmp_path: Path, flag_script: str) -> subprocess.CompletedProcess[str]:
    stub = fake_device(tmp_path, flag_script)
    body = (
        f'set -uo pipefail\nPY="{stub}"\n. "{STEPS}"\n'
        'harness_clear_write_block /dev/fake "B.1 write block"; echo "rc=$?"\n'
        "harness_summary\n"
    )
    return subprocess.run(
        ["bash", "-c", body], capture_output=True, text=True, cwd=tmp_path, check=False
    )


def test_an_already_writable_device_needs_no_clearing(tmp_path: Path) -> None:
    result = run_clear(tmp_path, "echo 0")

    assert "already writable" in result.stdout
    assert "rc=0" in result.stdout
    assert "FAILED" not in result.stdout


def test_a_read_only_device_is_cleared_and_the_reason_is_logged(
    tmp_path: Path,
) -> None:
    """Phase B re-purposes an evidence device, so the clear is deliberate."""
    # First call reads 1, second reads back 0 after the clear.
    result = run_clear(
        tmp_path,
        'if [ -f seen ]; then echo 0; else touch seen; echo 1; fi',
    )

    assert "reads read-only (1)" in result.stdout
    assert "re-purposes this device as a test fixture" in result.stdout
    assert "cleared" in result.stdout
    assert "rc=0" in result.stdout
    assert result.returncode == 0


def test_a_clear_that_does_not_take_fails_the_phase(tmp_path: Path) -> None:
    """Silently proceeding would run parted against a read-only device."""
    result = run_clear(tmp_path, "echo 1")

    assert "B.1 write block FAILED" in result.stdout
    assert "could not be cleared" in result.stdout
    assert "rc=1" in result.stdout
    assert result.returncode != 0


# --------------------------------------------------------------------------
# parted and mkfs are checked, in both phases
# --------------------------------------------------------------------------


def test_neither_phase_discards_parted_or_mkfs_output() -> None:
    """They used to fail silently and surface later as "could not mount"."""
    lines = DRIVER.read_text().splitlines()
    discarded = [
        (number, line)
        for number, line in enumerate(lines, 1)
        if ("parted " in line or "mkfs." in line)
        and ">/dev/null" in line
        and "command -v" not in line
    ]

    assert discarded == [], f"unchecked partition or filesystem call: {discarded}"


def test_both_phases_clear_the_write_block_before_writing() -> None:
    text = DRIVER.read_text()

    assert 'harness_clear_write_block "$DEVICE" "A.2 write block"' in text
    assert 'harness_clear_write_block "$DEVICE" "B.1 write block"' in text


def test_a_failed_plant_fails_the_phase_rather_than_warning() -> None:
    """A.3's before-count is meaningless without the planted files."""
    text = DRIVER.read_text()

    assert 'harness_fail "A.2 mount"' in text
    assert "no files were planted" in text
