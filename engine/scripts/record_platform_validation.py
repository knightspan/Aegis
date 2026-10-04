"""Run the platform test suites on this host and record what actually passed.

    python scripts/record_platform_validation.py            # all suites
    python scripts/record_platform_validation.py file_erase # one suite

Writes ``core/platform/validation_record.json``, which the capability matrix
reads: a suite that is not recorded as ``PASS`` on a platform leaves every
capability it backs at UNVERIFIED on that platform. The record is only ever
written by this script from a real pytest run on the platform it names -
never by hand, and never for a platform other than the one it runs on.

Entries for other platforms are preserved, so a CI matrix can run this once
per OS and merge the three files (``--merge a.json b.json ...``).

Two shapes are written, for two readers:

* ``suites`` - what the capability model gates on. A suite that is not
  recorded as ``PASS`` for a platform leaves the capabilities it backs at
  UNVERIFIED there.
* ``features`` - one row per platform *feature*, the shape a reader wants:
  platform, OS version, architecture, commit, the tests behind it, the
  result, the date, the evidence file and the limitations that still apply.
  Never a blanket "Windows verified".

Hardware validation is a separate section (``hardware``) and is **not**
written by this script: a suite passing on a CI runner is not a USB stick
sanitized. Those entries are added from ``docs/validation/`` runs on
designated test media, and default to ``NOT RUN``.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "core" / "platform" / "validation_record.json"

#: suite -> pytest paths. Kept small and meaningful: each suite backs a named
#: group of capability rows.
SUITES: dict[str, list[str]] = {
    "file_erase": ["tests/erase/files", "tests/platform"],
    "recovery": ["tests/carve"],
    "whole_drive": ["tests/erase", "tests/device", "tests/helper"],
    "api": ["tests/api"],
    # The Windows and macOS disk layers, the block engine and the resolver,
    # through adapter doubles. Run on each OS so the struct packing and the
    # engines are exercised under that OS's Python; no device is touched.
    "platform_backends": [
        "tests/device/test_windows_native.py",
        "tests/erase/test_blockclear.py",
        "tests/carve/test_platform_sources.py",
        "tests/platform/test_windows_engine.py",
        "tests/platform/test_macos_engine.py",
        "tests/platform/test_capability_resolver.py",
        "tests/test_package_completeness.py",
    ],
}
#: whole_drive includes tests/erase, which contains the file suite too; the
#: file tests are excluded there so the two suites measure different code.
_EXCLUDE = {"whole_drive": ["tests/erase/files"]}


#: feature -> (suite that backs it, what still limits it). A feature with no
#: suite is decided by the platform, not by a test run.
FEATURES: dict[str, tuple[str | None, str]] = {
    "device_discovery": (
        None,
        "Runner disks only: no removable device is attached to a CI runner.",
    ),
    "file_folder_erase": (
        "file_erase",
        "Journals, snapshots and flash remapping are reported, never removed; "
        "on copy-on-write filesystems the overwrite cannot reach the old blocks.",
    ),
    "api_and_reporting": (
        "api",
        "In-process client; no browser and no packaged runtime involved.",
    ),
    "recovery": ("recovery", "Synthetic images; no physical evidence."),
    "whole_drive_sanitization": (
        "whole_drive",
        "Linux only, and never executed against a physical device in CI.",
    ),
    "packaged_application": (
        None,
        "Installed and driven by a script; no human, no desktop session.",
    ),
    "platform_backends": (
        "platform_backends",
        "Adapter doubles only: the Windows and macOS disk layers, the block "
        "engine and device sanitize were driven against byte buffers, never a "
        "real device. Not physical validation.",
    ),
}


def _family() -> str:
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "other"


def _commit() -> str:
    """The commit under test, marked ``+dirty`` if a tracked file differs.

    Untracked files are ignored on purpose: a CI job writes its own
    evidence (``platform-smoke-*.json``, ``build_info.json``) into the tree
    before this runs, and that output says nothing about the source that
    was tested.
    """
    try:
        head = subprocess.run(
            ["git", "rev-parse", "--short=12", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return f"{head}{'+dirty' if dirty else ''}" if head else "unknown"


def _runner() -> str:
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return (
            f"GitHub Actions {os.environ.get('RUNNER_OS', '')} runner, run "
            f"{os.environ.get('GITHUB_RUN_ID', '?')}"
        ).strip()
    return f"developer machine ({platform.system()} {platform.release()})"


def run_suite(name: str) -> dict[str, object]:
    """Run one suite with pytest and summarise its JUnit XML."""
    paths = SUITES[name]
    with tempfile.TemporaryDirectory() as scratch:
        junit = Path(scratch) / "junit.xml"
        argv = [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            f"--junitxml={junit}",
            *paths,
        ]
        for excluded in _EXCLUDE.get(name, []):
            argv.append(f"--ignore={excluded}")
        completed = subprocess.run(argv, cwd=ROOT, check=False)
        counts = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
        try:
            tree = ET.parse(junit)
        except (OSError, ET.ParseError):
            return {
                "state": "FAIL",
                "reason": "pytest produced no report",
                "exit_code": completed.returncode,
            }
        for suite in tree.getroot().iter("testsuite"):
            tests = int(suite.get("tests", 0))
            failures = int(suite.get("failures", 0))
            errors = int(suite.get("errors", 0))
            skipped = int(suite.get("skipped", 0))
            counts["failed"] += failures
            counts["errors"] += errors
            counts["skipped"] += skipped
            counts["passed"] += tests - failures - errors - skipped
    ok = completed.returncode == 0 and counts["failed"] == 0 and counts["errors"] == 0
    return {
        "state": "PASS" if ok and counts["passed"] > 0 else "FAIL",
        "counts": counts,
        "exit_code": completed.returncode,
        "paths": paths,
        "runner": _runner(),
        "python": platform.python_version(),
        "os": _suite_os(),
        "commit": _commit(),
        "date": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _evidence(path: Path | None) -> dict[str, Any]:
    """Read a smoke-test evidence file, or an empty mapping."""
    if path is None or not path.is_file():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def feature_rows(
    family: str,
    suites: dict[str, Any],
    smoke: dict[str, Any],
    package: dict[str, Any],
    smoke_name: str,
    package_name: str,
) -> list[dict[str, Any]]:
    """One row per feature, from the suites and the smoke evidence.

    ``NOT RUN`` where nothing was run, ``UNSUPPORTED`` where the platform
    refuses the feature by design, and ``PASS``/``FAIL`` only where something
    actually executed.
    """
    # The smoke evidence describes the host the adapter ran on. Without it -
    # the package job records no adapter smoke - ask this host directly, which
    # is the same probe, rather than falling back to ``platform.release()``:
    # that answers "10" on Windows 11 and would file real results under the
    # wrong operating system.
    platform_info = smoke.get("platform") or _host_description()
    common = {
        "platform": family,
        "os": platform_info.get("os_name") or _os_string(),
        "os_version": platform_info.get("os_build") or platform.version(),
        "architecture": platform_info.get("machine") or platform.machine(),
        "app_version": platform_info.get("app_version", ""),
        "commit": _commit(),
        "date": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "runner": _runner(),
    }
    rows: list[dict[str, Any]] = []
    for feature, (suite, limitation) in FEATURES.items():
        entry = suites.get(suite) if suite else None
        result = "NOT RUN"
        tests: list[str] = []
        evidence = ""
        if feature == "whole_drive_sanitization" and family != "linux":
            # Windows and macOS clear through core.erase.blockclear; what CI
            # can run is the platform_backends suite against adapter doubles.
            backends = suites.get("platform_backends")
            if isinstance(backends, dict):
                result = str(backends.get("state", "NOT RUN"))
                tests = list(backends.get("paths") or [])
                evidence = "pytest (adapter doubles; no device)"
            limitation = (
                "Adapter doubles only on this platform: never executed against a "
                "physical device in CI. Not physical validation."
            )
        elif feature == "device_discovery":
            if smoke:
                result = str(smoke.get("result", "NOT RUN"))
                evidence = smoke_name
                tests = ["scripts/platform_smoke.py"]
        elif feature == "packaged_application":
            if package:
                result = str(package.get("result", "NOT RUN"))
                evidence = package_name
                tests = ["scripts/package_smoke.py"]
        elif isinstance(entry, dict):
            result = str(entry.get("state", "NOT RUN"))
            tests = list(entry.get("paths") or [])
            evidence = "pytest"
        rows.append(
            {
                **common,
                "feature": feature,
                "result": result,
                "tests": tests,
                "evidence": evidence,
                "limitations": limitation,
            }
        )
    return rows


def _os_string() -> str:
    """The OS name without importing the project, for when that import fails.

    ``platform.release()`` answers "10" on Windows 11, and this is the value a
    row falls back to, so the build number decides here as it does in
    ``core.platform.host.windows_product_name``.
    """
    if sys.platform == "win32":
        release, version, _csd, _ptype = platform.win32_ver()
        try:
            build = int(version.split(".")[2]) if version.count(".") >= 2 else 0
        except ValueError:
            build = 0
        if release in {"10", "11"} and build >= 22000:
            return "Windows 11"
        return f"Windows {release}".strip()
    if sys.platform == "darwin":
        return f"macOS {platform.mac_ver()[0]}".strip()
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if line.startswith("PRETTY_NAME="):
                name = line.split("=", 1)[1].strip().strip('"').strip("'")
                if name:
                    return name
    except OSError:
        pass
    return f"{platform.system()} {platform.release()}"


def _suite_os() -> str:
    """The operating system this suite ran on, named as the OS names itself.

    ``platform.release()`` alone answers "10" on Windows 11, so the product
    name comes from the same probe the adapter uses and the kernel or build
    string follows it.
    """
    host = _host_description()
    name = str(host.get("os_name") or _os_string())
    build = str(host.get("os_build") or platform.version())
    return f"{name} {build}".strip()[:160]


def _host_description() -> dict[str, Any]:
    """This host as ``core.platform.host`` reports it, or an empty mapping.

    Imported lazily, and from the checkout: the package job records its
    evidence without installing the project, and there the import would
    otherwise fail and file a real Windows 11 run as "Windows 10". A failure
    that survives that still leaves the row's fallbacks in place rather than
    failing the recording.
    """
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    try:
        from core.platform.host import platform_info as probe
    except ImportError:
        return {}
    info = probe()
    return {
        "os_name": info.os_name,
        "os_build": info.os_build,
        "machine": info.machine,
        "app_version": info.app_version,
    }


def _load(path: Path) -> dict[str, object]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _skeleton() -> dict[str, object]:
    return {
        "note": (
            "Written by scripts/record_platform_validation.py from real pytest "
            "runs. Do not edit by hand. A missing entry means NOT RUN."
        ),
        "suites": {},
        "hardware": {},
    }


def merge(paths: list[Path], out: Path) -> None:
    """Fold per-platform records into one.

    Suites merge by platform. Features merge by *(platform, feature)*, and a
    row that says something ("PASS", "FAIL", "UNSUPPORTED") always beats one
    that says "NOT RUN": the package job records only the packaged-application
    feature, and must not blank the rows the test job recorded for the same
    platform minutes earlier.
    """
    merged = _load(out) or _skeleton()
    suites = merged.setdefault("suites", {})
    assert isinstance(suites, dict)
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for row in merged.get("features") or []:
        if isinstance(row, dict):
            rows[(str(row.get("platform")), str(row.get("feature")))] = row

    for path in paths:
        other = _load(path)
        for fam, entries in (other.get("suites") or {}).items():  # type: ignore[union-attr]
            suites.setdefault(fam, {}).update(entries)
        for row in other.get("features") or []:  # type: ignore[union-attr]
            if not isinstance(row, dict):
                continue
            key = (str(row.get("platform")), str(row.get("feature")))
            existing = rows.get(key)
            if (
                existing is not None
                and row.get("result") == "NOT RUN"
                and existing.get("result") != "NOT RUN"
            ):
                continue
            rows[key] = row

    merged["features"] = [rows[key] for key in sorted(rows)]
    out.write_text(
        json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("suites", nargs="*", help=", ".join(SUITES))
    parser.add_argument("--out", type=Path, default=RECORD)
    parser.add_argument("--merge", nargs="+", type=Path, default=None)
    parser.add_argument(
        "--smoke", type=Path, default=None, help="platform_smoke.py evidence file"
    )
    parser.add_argument(
        "--package", type=Path, default=None, help="package_smoke.py evidence file"
    )
    parser.add_argument(
        "--record-only",
        action="store_true",
        help="record the given evidence without running any test suite",
    )
    args = parser.parse_args(argv)

    if args.merge:
        merge(args.merge, args.out)
        return 0

    unknown = sorted(set(args.suites) - set(SUITES))
    if unknown:
        parser.error(
            f"unknown suite(s): {', '.join(unknown)}; known: {', '.join(SUITES)}"
        )

    record = _load(args.out) or _skeleton()
    suites = record.setdefault("suites", {})
    assert isinstance(suites, dict)
    family = _family()
    failed = False
    for name in args.suites if args.record_only else (args.suites or list(SUITES)):
        result = run_suite(name)
        suites.setdefault(family, {})[name] = result
        failed |= result["state"] != "PASS"
        print(f"{family} {name}: {result['state']} {result.get('counts')}")

    rows = feature_rows(
        family,
        suites.get(family, {}),
        _evidence(args.smoke),
        _evidence(args.package),
        # The file's name, not its path: this record is committed, and where
        # a developer's scratch directory lives is not evidence.
        args.smoke.name if args.smoke else "",
        args.package.name if args.package else "",
    )
    kept = [
        row
        for row in (record.get("features") or [])
        if isinstance(row, dict) and row.get("platform") != family
    ]
    record["features"] = kept + rows
    for row in rows:
        print(f"{family} {row['feature']}: {row['result']}")

    args.out.write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
