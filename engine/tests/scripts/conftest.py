"""Fixtures and platform gates for the harness suite.

Most of `scripts/` is the **Linux hardware-validation harness**: bash with GNU
coreutils, `timeout`, loop devices, `lsblk`, ext4. It is Linux-only by design
(`docs/platform-support.md`), and the tests that drive it are skipped
elsewhere with that reason rather than failing on a Mac's bash 3.2 or on
Windows, where there is no shell to run them at all.

The suites that test cross-platform Python - the demo workflow, the baseline
comparison, the supported-formats document - keep running everywhere.
"""

from __future__ import annotations

import sys

import pytest

#: Modules that execute the Linux harness shell scripts.
_LINUX_HARNESS = frozenset(
    {
        "test_harness_steps",
        "test_photorec_step",
        "test_script_syntax",
        "test_workdir_guard",
        "test_pattern_writer",
        "test_device_gate",
        "test_preflight_recording",
        "test_resume_steps",
        "test_verify_expect_fill",
        "test_probe_write_block",
        "test_fragment_plant",
        "test_manifest_keying",
        "test_compare_baseline",
        "test_record_code",
    }
)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    if sys.platform.startswith("linux"):
        return
    skip = pytest.mark.skip(
        reason=(
            "the hardware-validation harness is Linux-only: bash 4+, GNU "
            "coreutils (timeout, losetup), lsblk and ext4. See "
            "docs/platform-support.md."
        )
    )
    for item in items:
        if item.module.__name__.rsplit(".", 1)[-1] in _LINUX_HARNESS:
            item.add_marker(skip)
