"""Exports the AEGIS source repository (github.com/knightspan/Aegis) from this build workspace.

    python tools/export-github-repo.py <out dir>

Layout written to <out dir>:
    desktop/aegis-module      AEGIS NetBeans module (Java): working/autopsy/AegisSanitization
    desktop/autopsy-overlay   files AEGIS adds to or changes in upstream Autopsy 4.23.1
    desktop/branding          NetBeans branding (splash, icons, title)
    desktop/launcher          AEGIS.exe launcher source
    engine                    AEGIS engine (Python): external/aegis variant
    sanitizer                 C++ file/folder sanitizer
    tools                     build, staging, test and demo scripts
    docs, README.md, ...      documentation (written separately into the repo)

Never exported: build outputs, binaries, caches, test results, evidence images, the EDSR model
files (fetched by tools/fetch-models.ps1 with pinned SHA-256), and assistant working notes.
Files in <out dir> that this script does not own (README.md, docs/, .git) are left alone.
"""
from __future__ import annotations

import filecmp
import fnmatch
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UPSTREAM = ROOT / "autopsy-autopsy-4.23.1" / "autopsy-autopsy-4.23.1"
FORK = ROOT / "working" / "autopsy"

SKIP_DIRS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "node_modules", "build", "dist",
             "test-out", ".git", ".idea", ".vscode", "superpowers", "private", ".m2-scratch", "release"}
SKIP_FILES = ["*.pyc", "*.class", "*.exe", "*.dll", "*.so", "*.res", "*.o", "*.obj", "*.pdb", "*.log", "*.pb",
              "*.E0?", "*.e01", "*.dd", "*.img", "*.raw", "CLAUDE.md", "AGENTS.md", "*.zip", "*.rar"]
# Generated at build time from @NbBundle.Messages, or local outputs; never part of the overlay.
OVERLAY_SKIP = ["*Bundle*.properties-MERGED", "aegis_audit.json", "aegis_report.txt", "*.class"]
OVERLAY_SKIP_DIRS = SKIP_DIRS
# Top-level folders of the fork that are not upstream sources (exported separately or local only).
OVERLAY_SKIP_TOP = {"AegisSanitization", "launcher", "branding", "netbeans-plat", "org", "thirdparty", "Tools"}

OWNED = ["installer", "desktop/aegis-module", "desktop/autopsy-overlay", "desktop/branding", "desktop/launcher", "engine",
         "sanitizer", "tools"]
TOOLS = ["stage-aegis-package.ps1", "aegis-probe.ps1", "aegis-e2e.ps1", "aegis-screenshot.ps1", "aegis-env.sh",
         "build-aegis-branding.py", "set-exe-icon.py", "make-demo-evidence.py", "usb-demo-test.ps1",
         "export-github-repo.py", "fetch-models.ps1", "apply-autopsy-overlay.ps1"]


def skipped(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(name, p) for p in patterns)


def copy_tree(src: Path, dst: Path, extra_skip_dirs: set[str] = frozenset()) -> int:
    count = 0
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS | extra_skip_dirs and not d.startswith(".m2-scratch")]
        rel = Path(dirpath).relative_to(src)
        for f in filenames:
            if skipped(f, SKIP_FILES):
                continue
            target = dst / rel / f
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(Path(dirpath) / f, target)
            count += 1
    return count


def overlay(dst: Path) -> list[str]:
    """Files under working/autopsy that are new or differ from pristine upstream Autopsy 4.23.1."""
    changed: list[str] = []
    for dirpath, dirnames, filenames in os.walk(FORK):
        rel_dir = Path(dirpath).relative_to(FORK)
        top = rel_dir == Path(".")
        dirnames[:] = [d for d in dirnames if d not in OVERLAY_SKIP_DIRS and not (top and d in OVERLAY_SKIP_TOP)]
        for f in filenames:
            if skipped(f, OVERLAY_SKIP) or skipped(f, ["*.jar", "*.exe", "*.dll", "*.so", "*.zip", "*.log"]):
                continue
            rel = rel_dir / f
            up = UPSTREAM / rel
            if up.exists() and filecmp.cmp(up, FORK / rel, shallow=False):
                continue
            target = dst / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(FORK / rel, target)
            changed.append(("M " if up.exists() else "A ") + rel.as_posix())
    return sorted(changed, key=lambda s: s[2:])


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for owned in OWNED:
        shutil.rmtree(out / owned, ignore_errors=True)
    n = copy_tree(FORK / "AegisSanitization", out / "desktop/aegis-module")
    print(f"desktop/aegis-module: {n} files")
    changes = overlay(out / "desktop/autopsy-overlay")
    (out / "desktop/autopsy-overlay/OVERLAY_FILES.txt").write_text(
        "AEGIS overlay for Autopsy 4.23.1 (upstream tag autopsy-4.23.1, Apache License 2.0; licence text in\n"
        "licenses/Apache-2.0-Autopsy.txt). Change notice under section 4(b) of that licence: every file marked M\n"
        "below was modified by the AEGIS authors in 2026; files marked A were added by them and are part of\n"
        "AEGIS. Upstream copyright headers are kept. Apply with tools/apply-autopsy-overlay.ps1.\n\n"
        + "\n".join(changes) + "\n", encoding="utf-8")
    print(f"desktop/autopsy-overlay: {len(changes)} files")
    print(f"desktop/branding: {copy_tree(FORK / 'branding', out / 'desktop/branding')} files")
    launcher = out / "desktop/launcher"
    launcher.mkdir(parents=True, exist_ok=True)
    for f in ("aegis_launcher.cpp", "aegis_launcher.rc", "aegis.ico"):
        shutil.copy2(FORK / "launcher" / f, launcher / f)
    print(f"engine: {copy_tree(ROOT / 'external' / 'aegis variant', out / 'engine')} files")
    print(f"sanitizer: {copy_tree(ROOT / 'working' / 'sanitizer', out / 'sanitizer')} files")
    installer = out / "installer"
    shutil.rmtree(installer, ignore_errors=True)
    installer.mkdir(parents=True)
    for f in (ROOT / "installer").iterdir():
        if f.suffix.lower() in {".iss", ".bmp", ".ico", ".md"}:
            shutil.copy2(f, installer / f.name)
    print(f"installer: {len(list(installer.iterdir()))} files")
    (out / "tools").mkdir(parents=True, exist_ok=True)
    for t in TOOLS:
        if (ROOT / "tools" / t).exists():
            shutil.copy2(ROOT / "tools" / t, out / "tools" / t)
    print(f"tools: {len(list((out / 'tools').iterdir()))} files")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
