"""The write-block probe must not default to a device, and must gate the one it gets.

This script is the only destructive path in the repository that used to carry
none of the gates `scripts/device-gate.sh` applies to every other one. Two
things made that dangerous rather than merely untidy:

* it writes to its target **when the write block fails**, which is the case it
  exists to detect - so the failure mode is "wrote to the thing it was
  protecting";
* the confirmation flag is filtered out of ``argv`` before the target is
  chosen, so a run carrying only the flag and no device fell through to a
  hardcoded ``/dev/sda``, which on most hosts is the system disk.

These tests pin the absence of the default and the presence of the gates. The
gate tests drive :func:`_assert_scratch_media` directly rather than the whole
probe, because the probe's later half needs root and real media, and the gates
are the half that has to hold without either.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "probe-write-block.py"


def _load() -> ModuleType:
    """Import the script by path; its filename is not a valid module name."""
    spec = importlib.util.spec_from_file_location("probe_write_block", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def probe() -> ModuleType:
    return _load()


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=REPO,
    )


# --------------------------------------------------------------------------
# No default target
# --------------------------------------------------------------------------


def test_no_device_argument_exits_non_zero() -> None:
    result = _run()

    assert result.returncode != 0
    assert "usage" in result.stderr.lower()


def test_the_confirmation_flag_alone_is_not_a_target() -> None:
    """The exact accident: the flag is stripped from argv before the target."""
    result = _run("--i-understand-this-may-write-to-the-device")

    assert result.returncode != 0
    assert "usage" in result.stderr.lower()
    assert "/dev/sda" not in result.stderr


def test_the_source_carries_no_default_device() -> None:
    """Static guard, in the shape ``tests/test_stubs_raise.py`` uses.

    A default reintroduced anywhere in this file is a write to somebody's
    system disk, and no behavioural test can see it until the day it fires.

    Matched on a *quoted concrete* device path, which is what a default looks
    like. The ``/dev/sdX`` in the usage docstring is a placeholder in prose and
    is exactly what the operator should be reading there.
    """
    source = SCRIPT.read_text(encoding="utf-8")
    concrete_device = re.compile(r"""["']/dev/[a-z]+[0-9a-z]*["']""")
    offenders = [
        line.strip() for line in source.splitlines() if concrete_device.search(line)
    ]
    assert not offenders, f"a device path is hardcoded as a literal: {offenders}"


def test_a_device_is_still_required_before_the_confirmation_gate() -> None:
    """Both gates stand; neither substitutes for the other."""
    result = _run("/dev/definitely-not-a-device")

    assert result.returncode != 0
    # Refused for want of the flag, before anything touched the path.
    assert "--i-understand-this-may-write-to-the-device" in result.stderr


# --------------------------------------------------------------------------
# The device gates
# --------------------------------------------------------------------------


def test_a_missing_path_is_refused(probe: ModuleType, tmp_path: Path) -> None:
    reason = probe._assert_scratch_media(str(tmp_path / "nothing-here"))

    assert reason is not None
    assert "cannot be read" in reason


def test_a_directory_is_refused(probe: ModuleType, tmp_path: Path) -> None:
    """Neither a block device nor a regular file, so not a probe target."""
    reason = probe._assert_scratch_media(str(tmp_path))

    assert reason is not None
    assert "neither a block device nor a regular file" in reason


def test_a_regular_file_is_allowed_so_the_probe_stays_exercisable(
    probe: ModuleType, tmp_path: Path
) -> None:
    """An image has no system disk, no mount and no removable flag.

    Allowing it costs nothing - a regular file cannot be a raw device - and it
    is what lets this script be run at all without hardware.
    """
    image = tmp_path / "scratch.dd"
    image.write_bytes(b"\x00" * 4096)

    assert probe._assert_scratch_media(str(image)) is None


def test_the_gate_calls_the_same_guard_the_erase_engine_calls(
    probe: ModuleType,
) -> None:
    """Reused, not reimplemented, so the two cannot drift apart.

    A second copy of "refuse the system disk" is a second copy that can be
    fixed in one place and left wrong in the other.
    """
    source = SCRIPT.read_text(encoding="utf-8")

    assert "from core.device.guard import assert_erasable" in source
    assert "assert_erasable(device)" in source


def test_the_size_limit_matches_the_shell_gate() -> None:
    """Both destructive paths must refuse the same devices for the same reason."""
    gate = (REPO / "scripts" / "device-gate.sh").read_text(encoding="utf-8")
    probe_source = SCRIPT.read_text(encoding="utf-8")

    assert "137438953472" in gate
    assert "MAX_SANE_BYTES = 137438953472" in probe_source
