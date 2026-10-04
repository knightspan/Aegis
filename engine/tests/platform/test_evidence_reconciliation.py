"""The evidence reconciliation, the app's validation record and the claims agree.

``docs/validation/evidence-reconciliation-2026-09-28/reconciliation.json`` is
the per-capability statement of what has been physically validated. The app
does not read it; the app reads ``core/platform/validation_record.json``. These
tests pin the two together, so a capability cannot be physically validated in
one and UNVERIFIED in the other, and pin the claims the README and the UI make
to the same states.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from core.platform.model import STATE_LABELS, CapabilityState
from core.platform.validation import hardware_passed, load_record

ROOT = Path(__file__).resolve().parents[2]
RECONCILIATION = (
    ROOT
    / "docs"
    / "validation"
    / "evidence-reconciliation-2026-09-28"
    / "reconciliation.json"
)
STATES = {
    "PHYSICALLY VALIDATED",
    "SOFTWARE/SYNTHETIC ONLY",
    "SUPPORTED BUT NOT PHYSICALLY VALIDATED",
    "UNSUPPORTED / NOT IMPLEMENTED",
    "EVIDENCE MISSING",
}


def _capabilities() -> dict[str, dict[str, Any]]:
    data = json.loads(RECONCILIATION.read_text(encoding="utf-8"))
    return {entry["id"]: entry for entry in data["capabilities"]}


def test_every_capability_has_exactly_one_known_state() -> None:
    for cap_id, entry in _capabilities().items():
        assert entry["status"] in STATES, cap_id


def test_physically_validated_means_a_recorded_physical_run() -> None:
    for cap_id, entry in _capabilities().items():
        if entry["status"] == "PHYSICALLY VALIDATED":
            assert entry["physical_runs"], cap_id
            for run in entry["physical_runs"]:
                for field in ("device", "date", "method", "result", "evidence"):
                    assert run.get(field), (cap_id, field)


@pytest.mark.parametrize(
    "cap_id",
    [cap_id for cap_id, entry in _capabilities().items() if "app_feature_key" in entry],
)
def test_the_app_record_agrees_with_the_reconciliation(cap_id: str) -> None:
    entry = _capabilities()[cap_id]
    platform, feature = entry["app_feature_key"].split(".", 1)
    record = load_record()
    if entry["status"] == "UNSUPPORTED / NOT IMPLEMENTED":
        rows = [
            row
            for row in record.get("features", [])
            if row.get("platform") == platform and row.get("feature") == feature
        ]
        assert rows and all(
            row["result"] in ("UNSUPPORTED", "IMPLEMENTED") for row in rows
        ), cap_id
        return
    validated = entry["status"] == "PHYSICALLY VALIDATED"
    assert hardware_passed(platform, feature, record) is validated, cap_id


def test_the_historical_reconciliation_keeps_the_state_it_recorded() -> None:
    # reconciliation.json is the record of 2026-09-28, before the Windows
    # backends existed. It is kept unchanged as history; the current state is
    # the generated capability matrix, which test_capability_matrix_doc pins.
    caps = _capabilities()
    for cap_id in ("windows_whole_drive", "windows_raw_acquisition"):
        assert caps[cap_id]["status"] == "UNSUPPORTED / NOT IMPLEMENTED"


def test_the_ui_names_each_unvalidated_capability_with_its_state() -> None:
    summary = (ROOT / "ui" / "src" / "lib" / "summary.ts").read_text(encoding="utf-8")
    block = summary[summary.index("export const NOT_PHYSICALLY_VALIDATED") :]
    block = block[block.index("= [") : block.index("\n]")]
    # The resolver's own label, so the UI line cannot drift from it.
    unvalidated = STATE_LABELS[CapabilityState.IMPLEMENTED_NOT_PHYSICALLY_VALIDATED]
    lines = [
        line.strip() for line in block.splitlines() if line.strip().startswith("'")
    ]

    def the_line(prefix: str) -> str:
        found = [line for line in lines if line.startswith(f"'{prefix}")]
        assert len(found) == 1, prefix
        return found[0]

    # Implemented now, and not run on a physical disk: said as exactly that,
    # never as "not implemented" and never as supported.
    for prefix in (
        "Windows whole-drive clear",
        "Windows raw physical-device acquisition",
        "Windows device sanitize",
        "macOS whole-drive clear and raw acquisition",
        "Backup restore",
    ):
        entry = the_line(prefix)
        assert unvalidated in entry, prefix
        assert "not implemented" not in entry.lower(), prefix
    assert "ATA SANITIZE" in the_line("Windows device sanitize")
    assert "NVMe Sanitize" in the_line("Windows device sanitize")
    # Still not available, each with its own state word and reason.
    assert "NOT IMPLEMENTED" in the_line("ATA SECURITY ERASE on Windows")
    assert "PLATFORM-LIMITED" in the_line("NVMe Format on Windows")
    assert "PLATFORM-LIMITED" in the_line("HPA/DCO discovery and modification on macOS")
    # Firmware purge has never run on a physical drive; macOS has no physical run.
    assert "never run on a physical drive" in the_line("Firmware Purge")
    assert "No macOS physical device run is recorded" in block
    assert "PLATFORM-LIMITED" in the_line("Device sanitize, crypto erase")
    assert "NOT IMPLEMENTED" in the_line("Free-space wipe on Windows and macOS")
    assert "never modified" in the_line("HPA change")
    # The old claims are gone: nothing implemented is called unimplemented.
    assert "Backup restoration: not implemented" not in block
    assert "Not implemented on Windows or macOS" not in block
    assert "Raw physical-device acquisition on Windows: not implemented" not in block
    assert "HPA/DCO unlock" not in block
    assert "NOT PHYSICALLY VALIDATED" not in block


def _readme_evidence_rows() -> dict[str, str]:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    return {
        line.split("|")[1].strip(): line
        for line in readme.splitlines()
        if line.startswith("> | ")
    }


def test_the_readme_separates_not_validated_from_not_implemented() -> None:
    rows = _readme_evidence_rows()
    not_validated = rows["Implemented, not physically validated"]
    not_implemented = rows["Not implemented"]
    # Implemented and never run on a physical disk: said as exactly that.
    for item in (
        "Firmware device sanitize",
        "Windows whole-drive clear",
        "Windows raw physical-device",
        "macOS whole-drive clear",
        "Backup restore",
    ):
        assert item in not_validated, item
    # Only what genuinely has no code is called not implemented.
    assert "ATA SECURITY ERASE UNIT on Windows" in not_implemented
    assert "Free-space wipe on Windows and macOS" in not_implemented
    for implemented in ("whole-drive", "raw", "acquisition", "restore", "Restore"):
        assert implemented not in not_implemented, implemented
    # Platform limits are neither of the above.
    assert "NVMe Format on Windows" in rows["Platform-limited"]


def test_the_readme_physical_row_names_only_recorded_runs() -> None:
    physical = _readme_evidence_rows()["Physically validated (device class)"]
    record = load_record()
    runs = record["physical_validations"]
    assert {run["device_class"] for run in runs} == {"usb-flash", "unknown"}
    assert "`usb-flash`" in physical
    assert "class not recorded" in physical
    assert "macOS" not in physical
    for never_run in ("Purge", "sanitize", "HPA"):
        assert never_run not in physical, never_run
    # A restore may be named only while the record holds one.
    restored = any(
        run["platform"] == "linux" and run["capability"] == "backup_restore"
        for run in runs
    )
    assert restored or not ("restore" in physical or "Restore" in physical)


# A bare "secure erase" is the undifferentiated label the certificate
# categories replaced; ATA command names never contain the phrase.
_BANNED = {
    "military-grade": re.compile(r"military[- ]grade", re.IGNORECASE),
    "unrecoverable": re.compile(r"unrecoverable", re.IGNORECASE),
    "secure erase": re.compile(r"secure[- ]erase", re.IGNORECASE),
}


@pytest.mark.parametrize(
    "doc",
    ["README.md", "docs/validation/judge-defense-card.md"],
)
def test_judge_facing_docs_make_no_marketing_claims(doc: str) -> None:
    text = (ROOT / doc).read_text(encoding="utf-8")
    for word, pattern in _BANNED.items():
        found = [m.group(0) for m in pattern.finditer(text)]
        assert not found, f"{doc} uses {word!r}: {found}"
