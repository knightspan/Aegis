"""Scoring a real run against the synthetic baseline.

The first Phase B run produced three numbers that looked like findings and were
artefacts of how the comparison was built:

* a quick-format pass scored against a delete baseline, 94 points low, because
  the baseline was looked up by filesystem name alone;
* an ``n=2`` synthetic row flagged as diverging from 460 real measurements;
* an undelete-only synthetic precision subtracted from an
  undelete-plus-signature real precision under one column name.

And one that was a real scoring error: five live JPEGs recovered byte-exact out
of the unallocated map were counted as false positives, because correctness was
scored against the deleted set alone.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest import mock

import pytest

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def harness() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "hardware_validation_compare", REPO / "scripts" / "hardware_validation.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["hardware_validation_compare"] = module
    spec.loader.exec_module(module)
    return module


def candidate(sha: str, source: str, name: str | None = None) -> dict[str, Any]:
    return {
        "sha256": sha,
        "source": source,
        "fs_type": "fat32",
        "original_name": name,
        "bucket": "HIGH",
    }


def run_carve(
    harness: ModuleType,
    tmp_path: Path,
    capsys: Any,
    manifest: dict[str, dict[str, Any]],
    candidates: list[dict[str, Any]],
    damage: str = "delete",
) -> dict[str, Any]:
    """Drive cmd_carve over a fixed candidate list, with no image involved."""
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))

    def generator(*_args: Any, **_kwargs: Any) -> Any:
        outcome = {
            "candidates": candidates,
            "partitions": [],
            "unallocated_bytes": 0,
            "limitations": [],
        }
        if False:  # pragma: no cover - makes this a generator
            yield None
        return outcome

    module = ModuleType("api.carve_job")
    module.carve_generator = generator  # type: ignore[attr-defined]
    package = ModuleType("api")
    package.__path__ = []  # type: ignore[attr-defined]
    # Scoped, not assigned. This used to write the stub into sys.modules and
    # leave it there, so every later test in the same process that started a
    # carve ran this fake instead - it went unnoticed only because the tests
    # that carve for real happened to sort earlier.
    replacements: dict[str, Any] = {"api.carve_job": module}
    if "api" not in sys.modules:
        replacements["api"] = package
    with mock.patch.dict(sys.modules, replacements):
        harness.cmd_carve(
            SimpleNamespace(
                image="unused.dd",
                manifest=str(manifest_path),
                filesystem="fat32",
                damage=damage,
                out_dir=None,
            )
        )
    result: dict[str, Any] = json.loads(capsys.readouterr().out)
    return result


MANIFEST = {
    "gone00.bin": {"name": "gone00.bin", "sha256": "d0", "size": 1, "deleted": True},
    "gone01.bin": {"name": "gone01.bin", "sha256": "d1", "size": 1, "deleted": True},
    "here00.jpg": {"name": "here00.jpg", "sha256": "l0", "size": 1, "deleted": False},
}


def test_a_correctly_recovered_live_file_is_not_a_false_positive(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    """The five live JPEGs the FAT32 delete pass carved byte-exact."""
    candidates = [
        candidate("d0", "fs_metadata", "gone00.bin"),
        candidate("d1", "fs_metadata", "gone01.bin"),
        candidate("l0", "signature"),          # live file, carved, byte-exact
        candidate("junk", "signature"),        # the only actual false positive
    ]

    result = run_carve(harness, tmp_path, capsys, MANIFEST, candidates)
    row = result["per_filesystem"]["fat32"]

    assert row["deleted_hit_candidates"] == 2
    assert row["live_hit_candidates"] == 1
    assert row["false_positive_candidates"] == 1
    # Three of four candidates are correct, not two of four.
    assert row["precision_bp"] == 7500
    assert row["precision_deleted_only_bp"] == 5000
    # Recall is a question about deleted files, so the live hit stays out of it.
    assert row["recall_bp"] == 10000
    assert row["exact"] == 2


def test_candidates_are_sliced_by_pipeline(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    candidates = [
        candidate("d0", "fs_metadata", "gone00.bin"),
        candidate("d1", "fs_metadata", "gone01.bin"),
        candidate("junk", "signature"),
    ]

    result = run_carve(harness, tmp_path, capsys, MANIFEST, candidates)
    by_pipeline = result["per_filesystem"]["fat32"]["by_pipeline"]

    # The half a synthetic baseline measured: no signature carving, so no
    # signature-carve false positive either.
    assert by_pipeline["undelete"]["candidates"] == 2
    assert by_pipeline["undelete"]["precision_bp"] == 10000
    assert by_pipeline["signature"]["candidates"] == 1
    assert by_pipeline["signature"]["precision_bp"] == 0


def test_the_damage_model_is_recorded(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    result = run_carve(
        harness, tmp_path, capsys, MANIFEST, [], damage="quickformat"
    )
    assert result["damage"] == "quickformat"
    assert result["pipeline"] == "undelete+signature"


# --------------------------------------------------------------------------
# compare


def write_csv(tmp_path: Path, rows: str) -> Path:
    path = tmp_path / "calibration-filesystems.csv"
    path.write_text(
        "filesystem,damage,pipeline,deleted,candidates,named,exact,"
        "recall_bp,precision_bp\n" + rows
    )
    return path


def carve_json(
    tmp_path: Path,
    name: str,
    *,
    damage: str,
    filesystem: str = "fat32",
    deleted_planted: int = 456,
    recall_bp: int = 10000,
    precision_bp: int = 9809,
    undelete: dict[str, int] | None = None,
) -> str:
    row: dict[str, Any] = {
        "deleted_planted": deleted_planted,
        "exact": 456,
        "recall_bp": recall_bp,
        "precision_bp": precision_bp,
        "candidates": 470,
    }
    if undelete is not None:
        row["by_pipeline"] = {"undelete": undelete}
    path = tmp_path / name
    path.write_text(
        json.dumps(
            {
                "step": "carve",
                "damage": damage,
                "pipeline": "undelete+signature",
                "per_filesystem": {filesystem: row},
            }
        )
    )
    return str(path)


def run_compare(
    harness: ModuleType, capsys: Any, carve: list[str], csv_path: Path
) -> dict[str, Any]:
    harness.cmd_compare(
        SimpleNamespace(carve_json=carve, calibration_csv=str(csv_path))
    )
    result: dict[str, Any] = json.loads(capsys.readouterr().out)
    return result


def test_a_quickformat_run_is_not_scored_against_a_delete_baseline(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    """The -94.43 point "divergence" of the first quick-format pass."""
    csv_path = write_csv(tmp_path, "fat32,delete,undelete,246,244,244,235,9553,9631\n")
    carve = carve_json(
        tmp_path, "qf.json", damage="quickformat", deleted_planted=912, recall_bp=110
    )

    row = run_compare(harness, capsys, [carve], csv_path)["rows"][0]

    assert row["status"] == "no_baseline"
    assert row["diverges"] is None
    assert row["recall_delta_bp"] is None
    assert "quickformat" in row["note"]


def test_an_underpowered_baseline_is_not_a_divergence(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    """exFAT: 460 of 460 on real media against a synthetic row of two files."""
    csv_path = write_csv(tmp_path, "exfat,delete,undelete,2,2,2,1,5000,5000\n")
    carve = carve_json(
        tmp_path,
        "exfat.json",
        damage="delete",
        filesystem="exfat",
        deleted_planted=460,
        undelete={"candidates": 460, "recall_bp": 10000, "precision_bp": 10000},
    )

    result = run_compare(harness, capsys, [carve], csv_path)
    row = result["rows"][0]

    assert result["min_baseline_n"] == harness.MIN_BASELINE_N
    assert row["status"] == "baseline_underpowered"
    assert row["diverges"] is False
    # The gap is still reported. It is just not called a finding.
    assert row["recall_delta_bp"] == 5000
    assert "n=2" in row["note"]


def test_comparison_uses_the_pipeline_the_baseline_measured(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    """Undelete-only baseline, undelete+signature run: compare the slice."""
    csv_path = write_csv(tmp_path, "fat32,delete,undelete,246,244,244,235,9553,9631\n")
    carve = carve_json(
        tmp_path,
        "fat32.json",
        damage="delete",
        precision_bp=9809,          # whole run, signature false positives included
        undelete={"candidates": 456, "recall_bp": 10000, "precision_bp": 10000},
    )

    row = run_compare(harness, capsys, [carve], csv_path)["rows"][0]

    assert row["compared_pipeline"] == "undelete"
    assert row["compared_precision_bp"] == 10000
    assert row["compared_candidates"] == 456
    # 100.00% against the baseline's 96.31%, not the whole run's 98.09%.
    assert row["precision_delta_bp"] == 10000 - 9631
    assert row["real_precision_bp"] == 9809
    assert row["status"] == "agrees"
    assert row["diverges"] is False


def test_a_real_divergence_still_fires(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    csv_path = write_csv(tmp_path, "fat32,delete,undelete,246,244,244,235,9553,9631\n")
    carve = carve_json(
        tmp_path,
        "poor.json",
        damage="delete",
        undelete={"candidates": 456, "recall_bp": 4000, "precision_bp": 8000},
    )

    row = run_compare(harness, capsys, [carve], csv_path)["rows"][0]

    assert row["status"] == "diverges"
    assert row["diverges"] is True
    assert row["recall_delta_bp"] == 4000 - 9553
