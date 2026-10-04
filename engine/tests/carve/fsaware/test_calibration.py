"""The filesystem calibration, and the boundaries it fixed the weight from.

``fs_metadata`` was the one score component the first calibration run could not
measure: the flat corpus produces no filesystem-metadata candidates at all, so
the weight kept its invented value and the calibration document said so. These
tests keep the measurement that replaced it from quietly stopping.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from core.carve.score import WEIGHTS
from testkit.calibrate import (
    calibrate_filesystems,
    measure_filesystems,
    sweep_fs_metadata_weight,
)
from testkit.fsimage import probe_tools
from testkit.generate_corpus import FilesystemCorpus

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="the filesystem builders are mkfs.ntfs/mtools/debugfs, which are Linux",
)


@pytest.fixture(scope="module")
def measured(corpus: FilesystemCorpus, corpus_dir: Path) -> object:
    report = probe_tools()
    if report.missing:
        pytest.skip(f"filesystem tooling missing: {report.reason()}")
    return measure_filesystems(corpus_dir, corpus)


def test_every_filesystem_in_the_corpus_gets_a_measured_row(
    measured: object,
) -> None:
    """One row per filesystem, and no filesystem silently absent.

    An averaged number over NTFS and ext4 describes neither, so the harness
    must never collapse them - and a filesystem that stopped being built would
    otherwise disappear from the table rather than fail.
    """
    rows = {row.filesystem: row for row in measured}  # type: ignore[attr-defined]
    assert {"ntfs", "fat32", "exfat", "ext2", "ext3", "ext4"} <= set(rows)
    for row in rows.values():
        assert row.deleted > 0, f"{row.filesystem} has no deleted files to measure"


def test_ntfs_recall_is_high_and_ext4_recall_is_not(measured: object) -> None:
    """The headline result, asserted in both directions.

    NTFS keeps the run list, so recall is near total. ext4 zeroes the extent
    tree, so recall is zero. Asserting only the first would let the second
    regress into a number that looks fine and means nothing.
    """
    rows = {row.filesystem: row for row in measured}  # type: ignore[attr-defined]
    assert rows["ntfs"].recall_bp >= 9000
    assert rows["ext2"].recall_bp == 10_000
    assert rows["ext3"].recall_bp == 10_000
    assert rows["ext4"].recall_bp == 0, (
        "ext4 undelete recovered content; either the kernel's behaviour was "
        "modelled wrongly in the corpus, or this is a genuine improvement worth "
        "understanding before it is celebrated"
    )


def test_every_recovered_candidate_carries_a_name(measured: object) -> None:
    """The thing undelete has that carving does not."""
    for row in measured:  # type: ignore[attr-defined]
        assert row.named == row.candidates, (
            f"{row.filesystem} produced {row.candidates - row.named} candidates "
            "with no original name; a filesystem record without a name is worth "
            "little more than a signature hit"
        )


def test_the_fs_metadata_weight_sits_at_its_measured_ceiling(
    corpus: FilesystemCorpus, corpus_dir: Path
) -> None:
    """The weight is bounded by measurement, and the bound is checked here.

    Two boundaries came out of the sweep, and the weight in force has to stay
    below both:

    * a weight at which a candidate that recovered **zero bytes** reaches
      MEDIUM - a filename from ``$I30`` slack with nothing behind it;
    * a weight at which the component alone carries a candidate **no decoder
      confirmed** into HIGH.

    Both are about the same mistake: a filesystem record saying a file lived at
    an offset is not evidence that the bytes there now are that file.
    """
    sweep = sweep_fs_metadata_weight(
        corpus_dir, corpus, weights=(WEIGHTS.fs_metadata, 2000, 4000)
    )

    at_weight = sweep[WEIGHTS.fs_metadata]
    assert at_weight.contentless_at_medium_or_above == 0, (
        "at the weight in force, a candidate that recovered nothing is being "
        "scored MEDIUM or better"
    )
    assert at_weight.unconfirmed_at_high == 0, (
        "at the weight in force, a candidate no decoder confirmed is scored HIGH"
    )

    assert sweep[2000].contentless_at_medium_or_above > 0, (
        "the 2000 boundary was expected to admit content-free candidates to "
        "MEDIUM; if it no longer does, the weight can be raised and this "
        "measurement should be redone rather than the assertion relaxed"
    )
    assert sweep[4000].unconfirmed_at_high > 0, (
        "the 4000 boundary was expected to carry unconfirmed candidates into HIGH"
    )
    assert WEIGHTS.fs_metadata < 2000


def test_the_harness_writes_a_table_a_reader_can_check(
    corpus_dir: Path, tmp_path: Path
) -> None:
    """An unreproducible measurement is an assertion. This one writes its work."""
    report = probe_tools()
    if report.missing:
        pytest.skip(f"filesystem tooling missing: {report.reason()}")

    result = calibrate_filesystems(corpus_dir, tmp_path, regenerate=False)
    assert result.csv_path is not None
    text = result.csv_path.read_text(encoding="utf-8")
    assert (
        "filesystem,damage,pipeline,deleted,candidates,named,exact,"
        "recall_bp,precision_bp"
    ) in text
    assert "ext4" in text and "ntfs" in text
    # A baseline row is a baseline only for the damage model and the pipeline
    # that produced it. Scoring a quick-format run against a delete row, or an
    # undelete+signature run against an undelete-only precision, compares two
    # experiments; the reader needs both stated in the table.
    assert "delete,undelete" in text
    assert result.candidates, "the run produced no scored candidates"
