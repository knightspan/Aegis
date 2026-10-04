"""Write the capability-completion matrix from the resolver itself.

    python scripts/capability_matrix.py            # write both files
    python scripts/capability_matrix.py --check    # fail if they are stale

Every row is computed by :func:`core.platform.capability.resolve_platform`
with the process assumed privileged (the matrix describes what the build can
do, not what this terminal may do) and the committed validation record. The
Markdown table in the docs is therefore a projection of the code, and
``tests/platform/test_capability_matrix_doc.py`` fails when either drifts.

Columns:

* **Implementation** - the module that performs it, or NOT IMPLEMENTED /
  PLATFORM-LIMITED with the reason.
* **Runtime availability** - the resolver's state for an elevated process
  with no particular device: DEVICE-DEPENDENT where the device must report the
  command, SUPPORTED or IMPLEMENTED / UNVALIDATED otherwise.
* **Physical validation** - the device classes with a recorded PASS on real
  hardware, or "none recorded".
* **Limit** - the platform or device limit that remains.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.platform.capability import (  # noqa: E402
    IMPLEMENTATIONS,
    implementation,
    physical_evidence,
    resolve_platform,
)
from core.platform.model import CAPABILITY_LABELS, Capability  # noqa: E402

OUT = ROOT / "docs" / "validation" / "capability-completion-2026-09-28"
PLATFORMS = ("linux", "windows", "macos")
_NAMES = {"linux": "Linux", "windows": "Windows", "macos": "macOS"}


def _limit(platform: str, capability: Capability, row: Any) -> str:
    impl = implementation(platform, capability)  # type: ignore[arg-type]
    if impl.state is not None:
        return impl.reason
    parts: list[str] = []
    if impl.refused_classes:
        grouped: dict[str, list[str]] = {}
        for name, why in sorted(impl.refused_classes.items()):
            grouped.setdefault(why.split(".")[0], []).append(name)
        parts.append(
            "Refused on "
            + "; ".join(f"{', '.join(names)}: {why}" for why, names in grouped.items())
            + "."
        )
    if impl.limitations:
        parts.append(impl.limitations[0])
    elif capability in {
        Capability.ATA_SANITIZE,
        Capability.NVME_SANITIZE,
        Capability.CRYPTO_ERASE,
        Capability.NVME_FORMAT,
        Capability.ATA_SECURITY_ERASE,
    }:
        parts.append("Only when the controller reports it and no bridge hides it.")
    return " ".join(parts) or "-"


def rows() -> list[dict[str, Any]]:
    from core.platform.validation import load_record

    record = load_record()
    out: list[dict[str, Any]] = []
    for platform in PLATFORMS:
        resolved = {
            item.capability: item
            for item in resolve_platform(
                platform,  # type: ignore[arg-type]
                privileged=True,
                privilege_basis="matrix assumes an elevated process",
                record=record,
            )
        }
        for capability in Capability:
            item = resolved[capability]
            entry = IMPLEMENTATIONS.get((platform, capability))  # type: ignore[arg-type]
            implemented = entry is not None and entry.state is None
            evidence = physical_evidence(platform, capability, record=record)
            out.append(
                {
                    "platform": _NAMES[platform],
                    "capability": CAPABILITY_LABELS[capability],
                    "implementation": entry.module
                    if implemented and entry is not None
                    else item.state_label,
                    "runtime_availability": item.state_label,
                    "state": item.state.value,
                    "physical_validation": sorted(
                        {
                            "host disk, class not recorded"
                            if e.device_class == "unknown"
                            else e.device_class
                            for e in evidence
                        }
                    )
                    or "none recorded",
                    "limit": _limit(platform, capability, item),
                }
            )
    return out


def markdown(data: list[dict[str, Any]]) -> str:
    lines = [
        "| Platform | Capability | Implementation | Runtime availability "
        "| Physical validation | Limit |",
        "|---|---|---|---|---|---|",
    ]
    for row in data:
        validated = row["physical_validation"]
        validated_text = (
            ", ".join(validated) if isinstance(validated, list) else validated
        )
        limit = str(row["limit"]).replace("|", "/")
        lines.append(
            f"| {row['platform']} | {row['capability']} | "
            f"`{row['implementation']}` | {row['runtime_availability']} | "
            f"{validated_text} | {limit} |"
            if "." in str(row["implementation"])
            else f"| {row['platform']} | {row['capability']} | "
            f"{row['implementation']} | {row['runtime_availability']} | "
            f"{validated_text} | {limit} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    data = rows()
    json_text = json.dumps(data, indent=2) + "\n"
    md_text = (
        "<!-- Generated by scripts/capability_matrix.py from the capability "
        "resolver and core/platform/validation_record.json. Do not edit. -->\n\n"
        + markdown(data)
    )
    targets = {
        OUT / "capability-matrix.json": json_text,
        OUT / "capability-matrix.md": md_text,
    }
    if args.check:
        stale = [
            str(path.relative_to(ROOT))
            for path, text in targets.items()
            if not path.is_file() or path.read_text(encoding="utf-8") != text
        ]
        if stale:
            sys.stderr.write("stale: " + ", ".join(stale) + "\n")
            return 1
        return 0
    OUT.mkdir(parents=True, exist_ok=True)
    for path, text in targets.items():
        path.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
