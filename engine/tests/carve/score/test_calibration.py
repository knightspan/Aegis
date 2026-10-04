"""The calibration harness runs end to end and emits a populated table.

This is the test that keeps the score honest. If the harness stops running,
the weights in :mod:`core.carve.score` go back to being numbers somebody made
up, and nobody notices until an examiner asks where 0.35 came from.
"""

from __future__ import annotations

import csv
from pathlib import Path

from core.carve.score import HIGH_BUCKET_FLOOR_BP, MEDIUM_BUCKET_FLOOR_BP
from testkit.calibrate import CSV_COLUMNS, calibrate


def test_calibration_runs_end_to_end_and_populates_every_bucket(
    tmp_path: Path,
) -> None:
    result = calibrate(
        tmp_path / "corpus", tmp_path / "out", seed=1, chart=False
    )

    text = result.csv_path.read_text(encoding="utf-8").splitlines()
    rows = list(csv.DictReader(text))
    assert list(rows[0]) == list(CSV_COLUMNS)

    buckets = {row["key"]: row for row in rows if row["dimension"] == "bucket"}
    assert {"HIGH", "MEDIUM", "LOW", "ALL"} <= set(buckets)
    for name in ("HIGH", "MEDIUM", "LOW"):
        assert int(buckets[name]["count"]) > 0, f"{name} bucket was not exercised"

    # Every planted object is recovered byte for byte somewhere in the output.
    assert int(buckets["ALL"]["recall_bp"]) == 10_000


def test_buckets_mean_what_they_claim(tmp_path: Path) -> None:
    """HIGH above 95% precision, MEDIUM above 70%. The acceptance the report cites."""
    result = calibrate(tmp_path / "corpus", tmp_path / "out", seed=2, chart=False)

    assert result.bucket("HIGH").precision_bp >= 9500
    assert result.bucket("MEDIUM").precision_bp >= 7000


def test_scored_candidates_carry_their_components(tmp_path: Path) -> None:
    result = calibrate(tmp_path / "corpus", tmp_path / "out", seed=3, chart=False)

    for item in result.candidates:
        assert set(item.score_components) == {
            "header",
            "exact_length",
            "decoder",
            "entropy",
            "fs_metadata",
            "no_overlap",
            "reassembly",
        }
        assert sum(item.score_components.values()) >= item.confidence_bp or (
            item.confidence_bp == 10_000
        )
        if item.bucket == "HIGH":
            assert item.confidence_bp >= HIGH_BUCKET_FLOOR_BP
        elif item.bucket == "MEDIUM":
            assert MEDIUM_BUCKET_FLOOR_BP <= item.confidence_bp < HIGH_BUCKET_FLOOR_BP


def test_chart_is_written_when_matplotlib_is_installed(tmp_path: Path) -> None:
    result = calibrate(tmp_path / "corpus", tmp_path / "out", seed=4, chart=True)

    if result.chart_path is None:  # matplotlib is optional tooling
        return
    assert result.chart_path.exists()
    assert result.chart_path.stat().st_size > 0
