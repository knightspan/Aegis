"""Run the UI's unit tests from the pytest gate.

The Sanitize screen's decisions live in ``ui/src/lib/erasePlan.ts`` and are
tested by ``ui/tests/*.test.ts`` under ``node --test``. Wrapping them here means
the one command every gate already runs cannot pass while they fail. Skips, with
the reason, where Node is absent or too old to strip TypeScript types itself.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

UI = Path(__file__).resolve().parents[2] / "ui"


def _node_major(node: str) -> int:
    out = subprocess.run(
        [node, "--version"], capture_output=True, text=True, check=False
    )
    match = re.match(r"v(\d+)", out.stdout.strip())
    return int(match.group(1)) if match else 0


def test_the_ui_unit_tests_pass() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed; run `npm test` in ui/ where it is")
    if _node_major(node) < 22:
        pytest.skip("node >= 22 is needed to run .ts tests without a build step")
    tests = sorted(str(path) for path in (UI / "tests").glob("*.test.ts"))
    assert tests, "ui/tests has no *.test.ts files"
    result = subprocess.run(
        [node, "--experimental-strip-types", "--no-warnings", "--test", *tests],
        cwd=UI,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
