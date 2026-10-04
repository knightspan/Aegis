"""The committed capability matrix is a projection of the resolver, not prose.

``docs/validation/capability-completion-2026-09-28/capability-matrix.{json,md}``
are written by ``scripts/capability_matrix.py``. If the resolver, the
implementation table or the validation record changes, this fails until the
matrix is regenerated, so no document can claim a state the code does not.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "capability_matrix.py"
MATRIX = ROOT / "docs" / "validation" / "capability-completion-2026-09-28"


def _module() -> object:
    spec = importlib.util.spec_from_file_location("capability_matrix", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_committed_matrix_matches_the_resolver() -> None:
    module = _module()
    assert module.main(["--check"]) == 0, (  # type: ignore[attr-defined]
        "capability matrix is stale: run python scripts/capability_matrix.py"
    )


def test_no_row_claims_physical_validation_without_a_recorded_run() -> None:
    rows = json.loads((MATRIX / "capability-matrix.json").read_text(encoding="utf-8"))
    for row in rows:
        if row["state"] == "VALIDATED_PHYSICAL":
            assert row["physical_validation"] != "none recorded", row
        else:
            assert row["runtime_availability"] != "SUPPORTED", row


def test_windows_and_macos_rows_are_no_longer_blanket_unsupported() -> None:
    rows = json.loads((MATRIX / "capability-matrix.json").read_text(encoding="utf-8"))
    by_key = {(row["platform"], row["capability"]): row for row in rows}
    for platform in ("Windows", "macOS"):
        for capability in (
            "Whole-drive clear (addressable overwrite)",
            "Raw physical-device acquisition",
            "Backup restore",
        ):
            row = by_key[(platform, capability)]
            assert row["state"] not in {"NOT_IMPLEMENTED"}, row
            assert "." in row["implementation"], row
