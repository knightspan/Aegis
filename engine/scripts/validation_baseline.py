#!/usr/bin/env python3
# ruff: noqa: E501, B905, E402
"""Phase 0 baseline snapshot of the SANCTUMREC stick. Read-only.

Reads sysfs, /proc and the mounted filesystem through normal user permissions.
Never opens a block device, never calls sudo, never writes to the stick.
Files are opened O_RDONLY | O_NOATIME so hashing does not dirty atime.

Usage: python scripts/validation_baseline.py <by-id-link> <mount-point> <out.json>
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

IO_FIELDS = (
    "reads_completed",
    "reads_merged",
    "sectors_read",
    "ms_reading",
    "writes_completed",
    "writes_merged",
    "sectors_written",
    "ms_writing",
    "io_in_flight",
    "ms_io",
    "weighted_ms_io",
)


def run(*cmd: str) -> str:
    return subprocess.run(
        cmd, capture_output=True, text=True, check=False
    ).stdout.strip()


def sysfs(dev: str, name: str) -> str:
    try:
        return Path(f"/sys/block/{dev}/{name}").read_text().strip()
    except OSError:
        return ""


def io_counters(dev: str) -> dict[str, int]:
    vals = sysfs(dev, "stat").split()
    return dict(zip(IO_FIELDS, (int(v) for v in vals)))


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOATIME", 0))
    with os.fdopen(fd, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot(root: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for p in sorted(root.rglob("*")):
        st = p.lstat()
        row: dict[str, object] = {
            "path": str(p.relative_to(root)),
            "type": "dir" if p.is_dir() else "file",
            "size": st.st_size,
            "mtime_ns": st.st_mtime_ns,
            "mode": oct(st.st_mode & 0o7777),
        }
        if p.is_file():
            row["sha256"] = sha256(p)
        rows.append(row)
    return rows


def main() -> int:
    by_id, mount, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    dev = os.path.realpath(by_id).rsplit("/", 1)[-1]
    lsblk = json.loads(
        run(
            "lsblk",
            "-J",
            "-b",
            "-o",
            "NAME,PATH,SIZE,RM,RO,TRAN,SERIAL,MODEL,VENDOR,FSTYPE,LABEL,UUID,PTTYPE,LOG-SEC,PHY-SEC,MOUNTPOINTS",
            f"/dev/{dev}",
        )
    )
    repo = Path(__file__).resolve().parent.parent
    doc = {
        "schema": "sanctum.validation.physical-module-baseline/1",
        "captured_utc": datetime.now(UTC).isoformat(),
        "population": "PHYSICAL",
        "software": {
            "commit": run("git", "-C", str(repo), "rev-parse", "HEAD"),
            "branch": run("git", "-C", str(repo), "rev-parse", "--abbrev-ref", "HEAD"),
            "git_status_porcelain": run(
                "git", "-C", str(repo), "status", "--porcelain"
            ),
            "tool_version": "sanctum-forensics/0.0.0 (api/deps.py default; pyproject version 0.0.0)",
            "python": sys.version.split()[0],
            "python_required": "==3.11.*",
        },
        "os": {"platform": platform.platform(), "kernel": platform.release()},
        "identity": {
            "by_id_path": str(by_id),
            "by_id_resolves_to_informational": f"/dev/{dev}",
            "serial_sysfs_lsblk": lsblk["blockdevices"][0].get("serial"),
            "serial_from_by_id_name": by_id.name.split("_", 2)[-1].rsplit("-0:0", 1)[0],
            "model": sysfs(dev, "device/model"),
            "vendor": sysfs(dev, "device/vendor"),
            "size_bytes": int(sysfs(dev, "size")) * 512,
            "removable": sysfs(dev, "removable"),
            "read_only_flag": sysfs(dev, "ro"),
            "logical_block_size": sysfs(dev, "queue/logical_block_size"),
            "physical_block_size": sysfs(dev, "queue/physical_block_size"),
        },
        "lsblk": lsblk,
        "mount": json.loads(run("findmnt", "-J", str(mount)) or "{}"),
        "io_counters_start": io_counters(dev),
        "permissions": {
            "euid": os.geteuid(),
            "groups": [os.getgroups()],
            "block_device_mode": oct(os.stat(f"/dev/{dev}").st_mode & 0o7777),
            "can_open_block_device_readonly": os.access(f"/dev/{dev}", os.R_OK),
            "can_open_block_device_write": os.access(f"/dev/{dev}", os.W_OK),
        },
        "files": snapshot(mount),
    }
    doc["io_counters_end"] = io_counters(dev)
    doc["io_write_counters_unchanged"] = (
        doc["io_counters_start"]["writes_completed"]
        == doc["io_counters_end"]["writes_completed"]
        and doc["io_counters_start"]["sectors_written"]
        == doc["io_counters_end"]["sectors_written"]
    )
    out.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    print(
        f"wrote {out}; files={len(doc['files'])}; writes_unchanged={doc['io_write_counters_unchanged']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
