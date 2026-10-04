"""Record one physical-hardware validation run in the app's validation record.

    python scripts/record_physical_validation.py evidence.json [--check]

``evidence.json`` describes exactly one run on real hardware. The run is
appended to ``physical_validations`` in ``core/platform/validation_record.json``,
which :mod:`core.platform.capability` reads: a capability reads
``VALIDATED_PHYSICAL`` for a device only when an entry here matches its
platform, capability **and device class**. One device class never validates
another - an ATA SANITIZE run on a SATA SSD says nothing about NVMe sanitize,
and a clear of a USB stick says nothing about an internal disk.

The script refuses an entry unless:

* every required field is present and non-empty (``commit`` may say
  ``not recorded ...`` for a run that predates build stamping, and must then
  say so in words);
* ``capability`` is a :class:`core.platform.capability.Capability` value and
  ``device_class`` is a :data:`core.platform.capability.DeviceClass` value;
* ``result`` is ``PASS`` or ``FAIL`` (a failed run is recorded too - it is
  evidence);
* every path in ``artifacts`` exists in this repository, so the entry points
  at something a reader can open;
* the same (platform, capability, device class, serial, date) is not already
  recorded.

It never writes a synthetic or CI result: those are ``suites`` and
``features``, written by ``record_platform_validation.py``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, get_args

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.platform.capability import Capability, DeviceClass  # noqa: E402

RECORD = ROOT / "core" / "platform" / "validation_record.json"

REQUIRED = (
    "platform",
    "capability",
    "device_class",
    "model",
    "serial",
    "interface",
    "os",
    "date",
    "commit",
    "method",
    "preflight",
    "operation",
    "verification",
    "artifacts",
    "result",
)


def validate(entry: dict[str, Any], record: dict[str, Any]) -> list[str]:
    """Every reason ``entry`` may not be recorded. Empty when it may."""
    problems: list[str] = []
    for key in REQUIRED:
        value = entry.get(key)
        if value in (None, "", []):
            problems.append(f"{key} is missing or empty")
    if entry.get("platform") not in {"linux", "windows", "macos"}:
        problems.append("platform must be linux, windows or macos")
    capabilities = {item.value for item in Capability}
    if entry.get("capability") not in capabilities:
        problems.append(f"capability must be one of {sorted(capabilities)}")
    classes = set(get_args(DeviceClass))
    if entry.get("device_class") not in classes:
        problems.append(f"device_class must be one of {sorted(classes)}")
    if entry.get("result") not in {"PASS", "FAIL"}:
        problems.append("result must be PASS or FAIL")
    for artifact in entry.get("artifacts") or []:
        if not (ROOT / str(artifact)).exists():
            problems.append(f"artifact {artifact} does not exist in the repository")
    fields = ("platform", "capability", "device_class", "serial", "date")
    key = tuple(entry.get(name) for name in fields)
    for existing in record.get("physical_validations") or []:
        other = tuple(existing.get(name) for name in fields)
        if other == key:
            problems.append("this run is already recorded")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--record", type=Path, default=RECORD)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate the evidence and report problems; do not write the record.",
    )
    args = parser.parse_args(argv)

    entry = json.loads(args.evidence.read_text(encoding="utf-8"))
    entries = entry if isinstance(entry, list) else [entry]
    record: dict[str, Any] = json.loads(args.record.read_text(encoding="utf-8"))
    failed = False
    for item in entries:
        problems = validate(item, record)
        if problems:
            failed = True
            sys.stderr.write(
                f"refused {item.get('platform')}/{item.get('capability')}: "
                + "; ".join(problems)
                + "\n"
            )
            continue
        record.setdefault("physical_validations", []).append(
            {key: item[key] for key in sorted(item)}
        )
    if failed:
        return 1
    if not args.check:
        args.record.write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
