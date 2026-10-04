"""Every shell script under scripts/ must parse.

This suite exists because a syntax error in a shell script is not found by
running the script: it is found by running the script far enough to reach the
broken line. The reset script reaches its resumed-run branches only after a
wipe that takes the better part of an hour, and the destructive scripts reach
their failure paths only when something has already gone wrong. A branch that
is entered once a month is a branch that is never parsed until the one run that
needed it.

``bash -n`` parses the whole file and executes none of it, so it reaches every
branch of every script for free, with no device and no root.

It does not catch everything. It is a parser, not an interpreter: an unset
variable, a wrong flag or a command that does not exist all parse cleanly. What
it does catch is the class that takes a script out at a line the author never
looked at - an unterminated quote, an unbalanced ``if``/``case``/``do``, a
heredoc whose terminator moved.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None, reason="bash is not available"
)


def _shell_scripts() -> list[Path]:
    """Every ``.sh`` under scripts/, plus anything with a bash shebang."""
    found = set(SCRIPTS.glob("*.sh"))
    for path in SCRIPTS.iterdir():
        if not path.is_file() or path in found:
            continue
        try:
            first = path.open("rb").readline()
        except OSError:  # pragma: no cover - unreadable file is not a script
            continue
        if first.startswith(b"#!") and b"bash" in first:
            found.add(path)
    return sorted(found)


SHELL_SCRIPTS = _shell_scripts()


def test_there_are_scripts_to_check() -> None:
    """A glob that silently matches nothing would pass every test below it."""
    assert SHELL_SCRIPTS, f"no shell scripts found under {SCRIPTS}"


@pytest.mark.parametrize("script", SHELL_SCRIPTS, ids=lambda p: p.name)
def test_script_parses(script: Path) -> None:
    """``bash -n`` reaches every branch, including the ones a demo never runs."""
    result = subprocess.run(
        ["bash", "-n", str(script)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, (
        f"{script.relative_to(REPO)} does not parse:\n{result.stderr}"
    )


def test_the_check_would_fail_on_a_broken_script(tmp_path: Path) -> None:
    """The guard is only worth having if it refuses something.

    The break used here is the one that bit: a branch body whose opening quote
    is missing, so the parenthesis inside the message reaches bash as syntax.
    """
    broken = tmp_path / "broken.sh"
    broken.write_text(
        "#!/usr/bin/env bash\n"
        "if true; then\n"
        '    echo skipped (resumed run)"\n'
        "fi\n"
    )

    result = subprocess.run(
        ["bash", "-n", str(broken)],
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "syntax error" in result.stderr
