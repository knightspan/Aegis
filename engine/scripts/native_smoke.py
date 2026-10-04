"""Read-only check of the native disk layer against a real OS, for CI.

    python scripts/native_smoke.py --out native-smoke-<OS>.json

On Windows: opens ``\\\\.\\PhysicalDrive0`` with ``GENERIC_READ`` only through
the real ``kernel32`` binding (:class:`core.device.win.native.Kernel32Api`),
asks the handle which disk it is (``IOCTL_STORAGE_GET_DEVICE_NUMBER``,
``IOCTL_STORAGE_QUERY_PROPERTY``, ``IOCTL_DISK_GET_LENGTH_INFO``), reads the
first sector unbuffered, and tries NVMe Identify Controller where the bus is
NVMe. On macOS (run under sudo): opens ``/dev/rdisk0`` ``O_RDONLY`` and reads
``DKIOCGETBLOCKSIZE`` / ``DKIOCGETBLOCKCOUNT`` and the first block.

**Nothing is written.** No handle with write access is opened, no ATA
pass-through is issued (Windows requires a read-write handle for it), and no
sanitize, HPA or offline command exists in this script. What it proves is that
the ctypes and ioctl bindings the destructive paths share work on the real
OS; it proves nothing about a destructive operation, and its evidence file
says so.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def windows() -> dict[str, Any]:
    from core.device.win import nvme
    from core.device.win.disk import WindowsDisk
    from core.device.win.native import Kernel32Api

    api = Kernel32Api()
    disk = WindowsDisk(api, 0, write=False).open()
    try:
        identity = disk.read_identity()
        sector = identity.logical_sector
        head = disk.read_at(0, sector)
        result: dict[str, Any] = {
            "number": identity.number,
            "bus": identity.bus,
            "model": identity.model,
            "serial_present": bool(identity.serial),
            "size_bytes": identity.size_bytes,
            "logical_sector": sector,
            "physical_sector": identity.physical_sector,
            "first_sector_sha256": hashlib.sha256(head).hexdigest(),
            "first_sector_bytes": len(head),
        }
        if identity.bus == "NVMe":
            try:
                ident = nvme.identify_controller(disk)
                result["nvme_identify"] = {
                    "block_erase": ident.block_erase,
                    "crypto_erase": ident.crypto_erase,
                }
            except Exception as exc:  # noqa: BLE001 - recorded, not raised
                result["nvme_identify_error"] = str(exc)
        return result
    finally:
        disk.close()


def macos() -> dict[str, Any]:
    from core.device.mac.rawdisk import MacRawDisk

    disk = MacRawDisk("disk0", write=False).open()
    try:
        head = disk.read_at(0, disk.logical_sector)
        return {
            "path": disk.path,
            "size_bytes": disk.size_bytes,
            "logical_sector": disk.logical_sector,
            "physical_sector": disk.physical_sector,
            "first_block_sha256": hashlib.sha256(head).hexdigest(),
        }
    finally:
        disk.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    evidence: dict[str, Any] = {
        "script": "scripts/native_smoke.py",
        "os": platform.platform(),
        "python": sys.version.split()[0],
        "scope": (
            "Read-only: one read handle, identity IOCTLs and one sector read. "
            "No write handle, no ATA pass-through, no destructive command. This "
            "is evidence that the native bindings work on this OS, not that "
            "any destructive operation was performed or validated."
        ),
    }
    try:
        if sys.platform == "win32":
            evidence["result"] = windows()
        elif sys.platform == "darwin":
            evidence["result"] = macos()
        else:
            evidence["result"] = None
            evidence["skipped"] = "Linux uses its own validated block engine."
        evidence["state"] = "PASS" if evidence.get("result") is not None else "NOT RUN"
    except Exception as exc:  # noqa: BLE001 - the evidence file records it
        evidence["state"] = "FAIL"
        evidence["error"] = f"{type(exc).__name__}: {exc}"
    args.out.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    sys.stdout.write(json.dumps(evidence, indent=2) + "\n")
    return 1 if evidence["state"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
