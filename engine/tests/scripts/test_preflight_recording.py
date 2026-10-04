"""What the hardware run records, fixed before the run rather than after it.

Three gaps, each of which would have made a figure from the next hardware run
unwritable or misleading:

* ``cmd_report`` built its erase report without ``job_state`` (BATCH6 FINDING
  5), so a report for an erase the harness watched finish said
  ``"job_state": "none recorded"``.
* ``cmd_carve`` emitted no count of reassembled candidates and no split of HIGH
  true positives by ``fragments`` - BATCH5 §4.5 rows 5 and 6 had no source.
* Nothing recorded the cluster size a pass actually formatted with, so a zero in
  row 5 could not be told apart from "the feature does not work".
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import struct
import sys
from collections.abc import Generator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def harness() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "hardware_validation_preflight", REPO / "scripts" / "hardware_validation.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["hardware_validation_preflight"] = module
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------
# job_state
# --------------------------------------------------------------------------


def _report(
    harness: ModuleType,
    tmp_path: Path,
    capsys: Any,
    monkeypatch: pytest.MonkeyPatch,
    erase: dict[str, Any] | None,
) -> dict[str, Any]:
    monkeypatch.setenv("SANCTUM_KEY_PASSPHRASE", "preflight-test")
    erase_json = None
    if erase is not None:
        erase_json = tmp_path / "a4-erase.json"
        erase_json.write_text(json.dumps(erase))
    args = argparse.Namespace(
        job_id="hwval-real",
        ledger_root=str(tmp_path / "ledger"),
        key_dir=str(tmp_path / "keys"),
        out_dir=str(tmp_path / "reports"),
        case_id="HW-VALIDATION",
        operator="validation",
        erase_json=str(erase_json) if erase_json else None,
        verify_json=None,
    )
    capsys.readouterr()
    assert harness.cmd_report(args) == 0
    emitted = json.loads(capsys.readouterr().out)
    document: dict[str, Any] = json.loads(Path(emitted["json_path"]).read_text())
    return document


def test_a_report_for_an_erase_that_returned_a_result_says_complete(
    harness: ModuleType, tmp_path: Path, capsys: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    document = _report(
        harness, tmp_path, capsys, monkeypatch, {"step": "erase", "result": {}}
    )
    assert document["sections"]["case_identity"]["job_state"] == "complete"


def test_a_report_for_an_erase_that_raised_says_failed(
    harness: ModuleType, tmp_path: Path, capsys: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    document = _report(
        harness,
        tmp_path,
        capsys,
        monkeypatch,
        {"step": "erase", "error": "device went away", "error_kind": "OSError"},
    )
    assert document["sections"]["case_identity"]["job_state"] == "failed"


def test_a_report_with_no_erase_output_does_not_invent_a_state(
    harness: ModuleType, tmp_path: Path, capsys: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    document = _report(harness, tmp_path, capsys, monkeypatch, None)
    assert document["sections"]["case_identity"]["job_state"] == "none recorded"


# --------------------------------------------------------------------------
# rows 5 and 6: reassembly counts from the carve
# --------------------------------------------------------------------------


def _candidate(
    sha: str, bucket: str, *, fragments: list[list[int]] | None = None, offset: int = 0
) -> dict[str, Any]:
    return {
        "sha256": sha,
        "bucket": bucket,
        "source": "structure",
        "fs_type": "fat32",
        "original_name": "",
        "offset": offset,
        "length": 4096,
        "fragments": fragments or [],
    }


def test_the_carve_counts_reassembled_candidates_and_splits_high_by_fragments(
    harness: ModuleType, tmp_path: Path, capsys: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = {
        "img00.jpg": {"name": "img00.jpg", "sha256": "a" * 64, "deleted": True},
        "img01.jpg": {"name": "img01.jpg", "sha256": "b" * 64, "deleted": True},
        "img02.jpg": {"name": "img02.jpg", "sha256": "c" * 64, "deleted": False},
    }
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    candidates = [
        # HIGH, reassembled, byte-identical to a deleted planted file.
        _candidate("a" * 64, "HIGH", fragments=[[4096, 8192], [16384, 4096]]),
        # HIGH, contiguous, identical to a live file.
        _candidate("c" * 64, "HIGH", offset=65536),
        # HIGH, reassembled, matching nothing planted: the negative result.
        _candidate("f" * 64, "HIGH", fragments=[[0, 4096], [12288, 4096]], offset=4),
        # MEDIUM, contiguous, matching nothing.
        _candidate("e" * 64, "MEDIUM", offset=8),
    ]

    def fake_generator(*_: Any, **__: Any) -> Generator[None, None, dict[str, Any]]:
        yield None
        return {
            "candidates": candidates,
            "partitions": [],
            "unallocated_bytes": 0,
            "limitations": [],
        }

    # Through sys.modules, not an attribute on the ``api`` package: inside the
    # full suite ``api`` can already name another package, and cmd_carve's
    # ``from api.carve_job import carve_generator`` reads sys.modules directly.
    stub = ModuleType("api.carve_job")
    stub.carve_generator = fake_generator  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "api.carve_job", stub)
    args = argparse.Namespace(
        image=str(tmp_path / "vol.dd"),
        manifest=str(tmp_path / "manifest.json"),
        filesystem="fat32",
        damage="delete",
        out_dir=None,
    )
    capsys.readouterr()
    assert harness.cmd_carve(args) == 0
    out = json.loads(capsys.readouterr().out)

    assert out["reassembled_from_fragments"] == 2
    assert out["high_true_positives"] == {
        "high_candidates": 3,
        "true_positives": 2,
        "true_positives_with_fragments": 1,
        "true_positives_without_fragments": 1,
        "false_positives_with_fragments": 1,
    }
    rows = {row["sha256"]: row for row in out["fragment_candidates"]}
    assert rows["a" * 64]["matches"] == "deleted"
    assert rows["a" * 64]["planted_names"] == ["img00.jpg"]
    assert rows["f" * 64]["matches"] == "none"
    assert rows["f" * 64]["planted_names"] == []
    assert rows["f" * 64]["runs"] == [[0, 4096], [12288, 4096]]


# --------------------------------------------------------------------------
# the cluster size a pass actually formatted with
# --------------------------------------------------------------------------


def _boot_sector(path: Path, kind: str, sector: int, per_cluster: int) -> None:
    raw = bytearray(1024 * 1024)
    if kind == "fat32":
        struct.pack_into("<H", raw, 11, sector)
        raw[13] = per_cluster
        raw[82:90] = b"FAT32   "
    elif kind == "exfat":
        raw[3:11] = b"EXFAT   "
        raw[108] = sector.bit_length() - 1
        raw[109] = per_cluster.bit_length() - 1
    raw[510:512] = b"\x55\xaa"
    path.write_bytes(bytes(raw))


@pytest.mark.parametrize(
    ("kind", "sector", "per_cluster", "cluster"),
    [
        ("fat32", 512, 1, 512),
        ("fat32", 512, 8, 4096),
        ("exfat", 512, 8, 4096),
        ("exfat", 512, 64, 32768),
    ],
)
def test_fs_geometry_reads_the_cluster_size_from_the_boot_sector(
    harness: ModuleType,
    tmp_path: Path,
    capsys: Any,
    kind: str,
    sector: int,
    per_cluster: int,
    cluster: int,
) -> None:
    image = tmp_path / f"{kind}.img"
    _boot_sector(image, kind, sector, per_cluster)
    capsys.readouterr()
    assert harness.cmd_fs_geometry(argparse.Namespace(device=str(image))) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["filesystem"] == kind
    assert out["bytes_per_sector"] == sector
    assert out["sectors_per_cluster"] == per_cluster
    assert out["cluster_bytes"] == cluster
    # Batch 7: the reassembler walks the volume's own cluster size, so the
    # record says which grid a carve of this volume searches, not whether the
    # volume happens to match a fixed assumption.
    assert out["reassembly_grid_bytes"] == cluster
    assert out["reassembly_grid_source"] == "volume"
    assert "matches_reassembly_assumption" not in out


def test_fs_geometry_says_unknown_rather_than_guessing(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    image = tmp_path / "blank.img"
    image.write_bytes(bytes(1024 * 1024))
    capsys.readouterr()
    assert harness.cmd_fs_geometry(argparse.Namespace(device=str(image))) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["filesystem"] == "unknown"
    assert out["cluster_bytes"] is None
    assert out["reassembly_grid_bytes"] == 512
    assert out["reassembly_grid_source"] == "sector"


# --------------------------------------------------------------------------
# whether the planted files were fragmented at all
# --------------------------------------------------------------------------


@pytest.mark.skipif(
    __import__("shutil").which("mcopy") is None,
    reason="mtools builds the FAT32 image; not installed",
)
def test_extents_reads_runs_from_the_volume_and_names_missing_files(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    """Runs from the volume's own structures, because vfat refuses FIEMAP.

    The image is built with testkit's FAT32 builder, which fragments a file the
    way a real volume does. Nothing is mounted.
    """
    from testkit.fsimage import PlantedFile, build_fat32

    whole = bytes(range(256)) * 200
    split = bytes(reversed(range(256))) * 1200
    image = tmp_path / "fat32.img"
    build_fat32(
        image,
        [
            PlantedFile("whole.bin", whole),
            PlantedFile("split.bin", split, fragmented=True),
        ],
        scratch=tmp_path / "scratch",
    )
    capsys.readouterr()
    args = argparse.Namespace(
        device=str(image), names=["whole.bin", "split.bin", "gone.jpg"]
    )
    assert harness.cmd_extents(args) == 0
    out = json.loads(capsys.readouterr().out)

    rows = {row["name"]: row for row in out["per_file"]}
    assert rows["gone.jpg"]["extents"] is None
    assert rows["whole.bin"]["extents"] == 1
    assert rows["split.bin"]["extents"] >= 2
    assert out["fragmented_files"] >= 1
    assert out["unmeasured_files"] == 1
    assert out["cluster_bytes"] == 512

    # The runs are real: the bytes at them are the file.
    with image.open("rb") as handle:
        read = b""
        for run in rows["split.bin"]["runs"]:
            handle.seek(run["offset"])
            read += handle.read(run["length"])
    assert read[: len(split)] == split
