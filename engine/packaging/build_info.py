"""Record what this build is, so an artifact can be traced back to a commit.

    python packaging/build_info.py            # writes core/platform/build_info.json

Written by each build script before PyInstaller runs, and bundled by the spec.
The app reads it (``core/platform/host.py``) and shows it on the Platform
screen and in ``/health``, so a tester holding an installer can say exactly
which source it came from.

Nothing here reads a secret, and nothing that identifies the build machine
beyond its OS goes in: the fields are the version, the commit, the target
platform and architecture, the build date, the Python and Node versions used
to build, and the CI run when there is one.

``SOURCE_DATE_EPOCH`` is honoured, so a build from the same commit records the
same date.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "core" / "platform" / "build_info.json"


def _run(*argv: str) -> str:
    try:
        completed = subprocess.run(  # noqa: S603 - argv list, no shell
            argv, cwd=ROOT, capture_output=True, text=True, check=False, timeout=30
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout.strip() if completed.returncode == 0 else ""


def _version() -> str:
    try:
        from importlib import metadata

        return metadata.version("sanctum-forensics")
    except Exception:  # noqa: BLE001 - not installed in this interpreter
        return "0.0.0"


def collect() -> dict[str, str]:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    when = time.gmtime(int(epoch)) if epoch and epoch.isdigit() else time.gmtime()
    commit = _run("git", "rev-parse", "HEAD")
    # Tracked files only. A CI job writes its own evidence into the tree
    # before this runs; untracked output does not change what was built.
    dirty = bool(_run("git", "status", "--porcelain", "--untracked-files=no"))
    return {
        "version": _version(),
        "commit": (commit + ("+dirty" if dirty else "")) if commit else "unknown",
        "branch": _run("git", "rev-parse", "--abbrev-ref", "HEAD"),
        "platform": sys.platform,
        "architecture": platform.machine(),
        "build_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", when),
        "python": platform.python_version(),
        "node": (_run("node", "--version") or "not recorded"),
        "builder": (
            f"GitHub Actions run {os.environ['GITHUB_RUN_ID']}"
            if os.environ.get("GITHUB_ACTIONS") == "true"
            else "local build"
        ),
        "signed": "no",
    }


def main() -> int:
    info = collect()
    OUT.write_text(json.dumps(info, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(info, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
