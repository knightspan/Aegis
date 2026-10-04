"""Install the project for CI, tolerating one known macOS gap.

``libewf-python`` publishes no macOS wheel and compiles from source. When that
compile fails on a runner, everything except E01 support still works (pyewf is
imported lazily, only by the E01 paths), so the install is retried without it
and the gap is printed - rather than failing every macOS test for a feature
none of the platform tests touch.

    python scripts/ci_install.py dev
"""

from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OPTIONAL_ON_FAILURE = {"libewf-python"}


def pip(*args: str) -> int:
    return subprocess.call([sys.executable, "-m", "pip", *args], cwd=ROOT)


def main(extras: str) -> int:
    if pip("install", "--constraint", "constraints.txt", "-e", f".[{extras}]") == 0:
        return 0
    if sys.platform != "darwin":
        return 1
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    wanted = [
        dep
        for dep in project["dependencies"]
        + [d for e in extras.split(",") for d in project["optional-dependencies"][e]]
        if dep.split("==")[0] not in OPTIONAL_ON_FAILURE
    ]
    print("NOTE: installing without", ", ".join(sorted(OPTIONAL_ON_FAILURE)),
          "- E01 read/write is unavailable in this environment.")
    if pip("install", *wanted) != 0:
        return 1
    return pip("install", "--no-deps", "-e", ".")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "dev"))
