"""The fragmented-recovery demo prints what the presenter says it prints.

It runs the real pipeline over a deterministic synthetic image, so these
assertions are the demo's script: if the carver changes what it recovers, this
fails before the presenter says something the screen no longer shows.
"""

from __future__ import annotations

import random
from pathlib import Path
from typing import Any

import pytest
from scripts.demo_fragmented import SEED, build, render, run


@pytest.fixture(scope="module")
def report(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    return run(Path(tmp_path_factory.mktemp("demo")))


def _row(report: dict[str, Any], label: str) -> dict[str, Any]:
    return next(row for row in report["rows"] if row["label"] == label)


def test_the_image_is_deterministic() -> None:
    first, _ = build(random.Random(SEED))
    second, _ = build(random.Random(SEED))
    assert first == second


@pytest.mark.parametrize(
    "label", ["png split by a 32 KiB gap", "jpeg split by a 32 KiB gap"]
)
def test_split_objects_are_rebuilt_exactly_and_held_below_high(
    report: dict[str, Any], label: str
) -> None:
    row = _row(report, label)
    assert row["found"]
    assert row["digest_matches_ground_truth"]
    assert len(row["runs"]) == 2
    assert row["bucket"] != "HIGH"
    assert row["score_components"]["reassembly"] < 0


def test_the_intact_object_is_high(report: dict[str, Any]) -> None:
    row = _row(report, "intact png")
    assert row["bucket"] == "HIGH"
    assert row["digest_matches_ground_truth"]


def test_the_duplicate_is_folded_into_the_intact_copy(report: dict[str, Any]) -> None:
    row = _row(report, "duplicate of the intact png")
    assert row["duplicate_of"] == _row(report, "intact png")["offset"]


@pytest.mark.parametrize(
    "label", ["png whose tail was overwritten", "decoy png signature"]
)
def test_unrecoverable_and_decoy_objects_never_reach_high(
    report: dict[str, Any], label: str
) -> None:
    row = _row(report, label)
    assert row["bucket"] != "HIGH"
    assert row["validation"] != "valid"
    assert not row["runs"]


def test_the_output_labels_its_population(report: dict[str, Any]) -> None:
    text = render(report)
    assert text.startswith("SYNTHETIC IMAGE / NO PHYSICAL DEVICE OPENED")
    assert "not a probability" in text
