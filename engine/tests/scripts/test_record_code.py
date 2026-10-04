"""Every results directory names the code it measured.

A results directory that cannot say which commit produced it is not evidence:
``docs/validation/hardware.md`` cites these directories, and a figure that
cannot be traced to code cannot be re-derived. ``harness_record_code`` writes
the commit, ``git describe`` and whether tracked files were modified at run
time, and refuses when there is nothing to name.

Untracked files deliberately do not count as dirty: the harness writes its own
results inside the repository, so counting them would mark every pass after the
first as dirty for a reason unrelated to the code.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

STEPS = Path(__file__).resolve().parents[2] / "scripts" / "harness-steps.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("git") is None,
    reason="bash and git are both required",
)


def run_bash(script: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    body = f'set -uo pipefail\nPY="{shutil.which("python3")}"\n. "{STEPS}"\n{script}\n'
    return subprocess.run(
        ["bash", "-c", body], capture_output=True, text=True, cwd=cwd, check=False
    )


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.email", "test@example.invalid")
    git(root, "config", "user.name", "test")
    (root / "code.py").write_text("x = 1\n")
    git(root, "add", "code.py")
    git(root, "commit", "-q", "-m", "one")
    git(root, "tag", "hwval-test")
    return root


def record(repo: Path, tmp_path: Path) -> tuple[subprocess.CompletedProcess[str], Path]:
    out = tmp_path / "00-code.json"
    return run_bash(f'harness_record_code "{repo}" "{out}"', tmp_path), out


def test_a_clean_tagged_tree_records_its_tag_sha_and_not_dirty(
    repo: Path, tmp_path: Path
) -> None:
    result, out = record(repo, tmp_path)
    assert result.returncode == 0, result.stderr
    recorded = json.loads(out.read_text())
    assert recorded["git_sha"] == git(repo, "rev-parse", "HEAD")
    assert recorded["git_describe"] == "hwval-test"
    assert recorded["git_dirty"] is False
    assert recorded["modified_tracked_files"] == 0


def test_a_modified_tracked_file_makes_the_tree_dirty(
    repo: Path, tmp_path: Path
) -> None:
    (repo / "code.py").write_text("x = 2\n")
    result, out = record(repo, tmp_path)
    assert result.returncode == 0, result.stderr
    recorded = json.loads(out.read_text())
    assert recorded["git_dirty"] is True
    assert recorded["git_describe"].endswith("-dirty")
    assert recorded["modified_tracked_files"] == 1
    assert "DIRTY" in result.stdout + result.stderr


def test_untracked_results_do_not_make_the_tree_dirty(
    repo: Path, tmp_path: Path
) -> None:
    (repo / "results-20260914T000000Z").mkdir()
    (repo / "results-20260914T000000Z" / "run.log").write_text("x")
    result, out = record(repo, tmp_path)
    assert result.returncode == 0, result.stderr
    assert json.loads(out.read_text())["git_dirty"] is False


def test_outside_a_repository_it_refuses(tmp_path: Path) -> None:
    plain = tmp_path / "not-a-repo"
    plain.mkdir()
    result, out = record(plain, tmp_path)
    assert result.returncode != 0
    assert not out.exists()
    assert "cannot name the code" in result.stdout + result.stderr
