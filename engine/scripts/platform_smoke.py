"""Run this host's platform adapter for real, and check what it produced.

This is the step that separates "the parser passes on fixtures" from "the
adapter works on this operating system". It executes the real discovery
mechanism of the running OS - ``lsblk`` on Linux, the Storage module on
Windows, ``diskutil`` on macOS - and asserts the facts a safety decision
depends on:

* at least one device was found;
* every device has an id, a path and a capacity;
* at least one device is recognised as the system/boot disk, and its reasons
  are recorded (a runner that found no system disk at all would mean the
  protection is not working on this platform);
* every system or mounted device is assessed NOT AVAILABLE;
* every capability row carries a source and a reason;
* every capability row carries the resolver's precise state, and the
  whole-drive rows name a mechanism rather than a blanket UNSUPPORTED;
* every system or mounted device's destructive capabilities resolve to
  BLOCKED_BY_SAFETY_POLICY (or a platform/device limit), never runnable.

Writes a JSON evidence file (``--out``) with the normalized devices, the
capability rows and the host's own details, which CI uploads as the evidence
behind a validation record. Nothing is written to any device, and no
destructive operation is performed.

    python scripts/platform_smoke.py --out platform-smoke-Windows.json
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # pragma: no cover - script entry
    sys.path.insert(0, str(ROOT))


def collect() -> dict[str, Any]:
    from core.platform import current_adapter, platform_status

    adapter = current_adapter()
    devices = adapter.enumerate_devices(include_virtual=True)
    assessments = [adapter.assess_device(device) for device in devices]
    status = platform_status(adapter)
    return {
        "adapter": adapter.name,
        "platform": status.platform.model_dump(mode="json"),
        "privilege": status.privilege.model_dump(mode="json"),
        "python": platform.python_version(),
        "machine": platform.machine(),
        "devices": [device.model_dump(mode="json") for device in devices],
        "assessments": [item.model_dump(mode="json") for item in assessments],
        "operations": [row.model_dump(mode="json") for row in status.operations],
        "media_classes": [row.model_dump(mode="json") for row in status.media_classes],
        "restrictions": status.restrictions,
    }


def check(evidence: dict[str, Any]) -> list[str]:
    """Return the failures. An empty list means the adapter behaved."""
    problems: list[str] = []
    devices = evidence["devices"]
    assessments = {item["device_id"]: item for item in evidence["assessments"]}

    if not devices:
        problems.append("discovery found no storage devices at all")
    for device in devices:
        for field in ("id", "path"):
            if not device.get(field):
                problems.append(f"device {device!r} has no {field}")
        if device["interface"] != "virtual" and device["capacity_bytes"] <= 0:
            problems.append(f"{device['id']}: no capacity reported")
        assessment = assessments.get(device["id"])
        if assessment is None:
            problems.append(f"{device['id']}: no assessment")
            continue
        if (device["system_device"] or device["mounted"]) and assessment[
            "headline"
        ] != "NOT AVAILABLE":
            problems.append(
                f"{device['id']}: system/mounted device assessed "
                f"{assessment['headline']}, expected NOT AVAILABLE"
            )
        if device["system_device"] and not device["system_reasons"]:
            problems.append(f"{device['id']}: protected with no reason recorded")

    physical = [d for d in devices if d["interface"] != "virtual"]
    if physical and not any(d["system_device"] for d in physical):
        problems.append(
            "no device was recognised as the system or boot disk: on a runner "
            "that boots from local storage this means the protection did not "
            "fire"
        )

    for row in evidence["operations"]:
        if not row["source"].strip():
            problems.append(f"capability row {row['operation']} has no source")
        if not row["reason"].strip():
            problems.append(f"capability row {row['operation']} has no reason")
        if not row.get("state"):
            problems.append(f"capability row {row['operation']} has no state")
        if row["operation"] == "whole_drive_clear" and not row.get("mechanism"):
            problems.append("whole_drive_clear names no mechanism")

    runnable = {"VALIDATED_PHYSICAL", "IMPLEMENTED_NOT_PHYSICALLY_VALIDATED"}
    destructive = {
        "whole_drive_clear",
        "ata_sanitize",
        "ata_security_erase",
        "nvme_sanitize",
        "nvme_format",
        "crypto_erase",
        "hpa_dco_modify",
        "backup_restore",
    }
    for device in evidence["devices"]:
        if not (device.get("system_device") or device.get("mounted")):
            continue
        assessment = assessments.get(device["id"]) or {}
        for row in assessment.get("capabilities", []):
            if row["capability"] in destructive and row["state"] in runnable:
                problems.append(
                    f"{device['id']} is system or mounted, yet "
                    f"{row['capability']} resolves to {row['state']}"
                )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    evidence = collect()
    problems = check(evidence)
    evidence["problems"] = problems
    evidence["result"] = "PASS" if not problems else "FAIL"

    text = json.dumps(evidence, indent=2, sort_keys=True)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "adapter": evidence["adapter"],
                "os": evidence["platform"]["os_name"],
                "devices": len(evidence["devices"]),
                "system_devices": sum(
                    1 for d in evidence["devices"] if d["system_device"]
                ),
                "result": evidence["result"],
                "problems": problems,
            },
            indent=2,
        )
    )
    for device in evidence["devices"]:
        print(
            f"  {device['id']:<24} {device['media_type']:<8} "
            f"{device['interface']:<12} {device['capacity_bytes']:>16} "
            f"system={device['system_device']} mounted={device['mounted']}"
        )
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
