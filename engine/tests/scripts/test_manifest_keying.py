"""The planted-file manifest, and the recall denominators taken from it.

Keyed by SHA-256, files with identical content collapsed into one entry. Phase
A.2 planted 14 files - three byte-identical PDFs and two byte-identical docx
among them - and the manifest held 11. The console said "planted 11 files", and
a recall computed against 11 would have been 27% too high.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest import mock

import pytest

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def harness() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "hardware_validation_manifest", REPO / "scripts" / "hardware_validation.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["hardware_validation_manifest"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def planted(tmp_path: Path) -> Path:
    """Three files, two of them byte-identical. The shape that collapsed."""
    root = tmp_path / "mnt"
    root.mkdir()
    (root / "doc00.pdf").write_bytes(b"%PDF-1.4 identical\n")
    (root / "doc01.pdf").write_bytes(b"%PDF-1.4 identical\n")
    (root / "photo00.jpg").write_bytes(b"\xff\xd8\xff\xe0 unique\n")
    return root


def hash_tree(
    harness: ModuleType, root: Path, out: Path, capsys: Any
) -> dict[str, Any]:
    harness.cmd_hash_tree(mock.Mock(root=str(root), out=str(out)))
    result: dict[str, Any] = json.loads(capsys.readouterr().out)
    return result


def test_identical_files_are_two_entries_not_one(
    harness: ModuleType, planted: Path, tmp_path: Path, capsys: Any
) -> None:
    out = tmp_path / "manifest.json"

    summary = hash_tree(harness, planted, out, capsys)

    manifest = json.loads(out.read_text())
    assert summary["files"] == 3
    assert set(manifest) == {"doc00.pdf", "doc01.pdf", "photo00.jpg"}
    assert manifest["doc00.pdf"]["sha256"] == manifest["doc01.pdf"]["sha256"]


def test_the_summary_reports_the_duplicates_it_found(
    harness: ModuleType, planted: Path, tmp_path: Path, capsys: Any
) -> None:
    """Both numbers, because a recall figure cannot be read without both."""
    summary = hash_tree(harness, planted, tmp_path / "manifest.json", capsys)

    assert summary["files"] == 3
    assert summary["unique_digests"] == 2
    assert summary["duplicate_content_files"] == 1


def test_mark_deleted_still_works_on_the_path_keyed_manifest(
    harness: ModuleType, planted: Path, tmp_path: Path, capsys: Any
) -> None:
    out = tmp_path / "manifest.json"
    hash_tree(harness, planted, out, capsys)

    code = harness.cmd_mark_deleted(
        mock.Mock(manifest=str(out), names=["doc00.pdf", "photo00.jpg"])
    )
    summary = json.loads(capsys.readouterr().out)

    manifest = json.loads(out.read_text())
    assert code == 0
    assert summary["marked"] == 2
    assert summary["not_in_manifest"] == []
    assert manifest["doc00.pdf"]["deleted"] is True
    assert manifest["doc01.pdf"]["deleted"] is False


def test_mark_deleted_reports_a_name_it_could_not_find(
    harness: ModuleType, planted: Path, tmp_path: Path, capsys: Any
) -> None:
    """Silently marking nothing would leave the denominator quietly wrong."""
    out = tmp_path / "manifest.json"
    hash_tree(harness, planted, out, capsys)

    code = harness.cmd_mark_deleted(
        mock.Mock(manifest=str(out), names=["doc00.pdf", "nosuch.jpg"])
    )
    summary = json.loads(capsys.readouterr().out)

    assert code == 1
    assert summary["marked"] == 1
    assert summary["not_in_manifest"] == ["nosuch.jpg"]


# --------------------------------------------------------------------------
# Recall denominators
# --------------------------------------------------------------------------


def run_carve(
    harness: ModuleType,
    manifest: dict[str, dict[str, Any]],
    recovered_digests: list[str],
    tmp_path: Path,
    capsys: Any,
) -> dict[str, Any]:
    """Drive cmd_carve with a faked carve result, so only the scoring is tested."""
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    image = tmp_path / "card.dd"
    image.write_bytes(b"")

    def fake_generator(*_args: Any, **_kwargs: Any) -> Any:
        outcome = {
            "candidates": [
                {
                    "sha256": digest,
                    "bucket": "HIGH",
                    "fs_type": "fat32",
                    "original_name": None,
                }
                for digest in recovered_digests
            ],
            "partitions": [],
            "unallocated_bytes": 0,
            "limitations": [],
        }
        yield from ()
        return outcome

    module = type(sys)("api.carve_job")
    module.carve_generator = fake_generator  # type: ignore[attr-defined]
    with mock.patch.dict(sys.modules, {"api.carve_job": module}):
        harness.cmd_carve(
            mock.Mock(
                manifest=str(manifest_path),
                image=str(image),
                filesystem="fat32",
                out_dir=str(tmp_path / "recovered"),
            )
        )
    result: dict[str, Any] = json.loads(capsys.readouterr().out)
    return result


DUP = "a" * 64
UNIQUE = "b" * 64
LIVE = "c" * 64


MANIFEST = {
    "doc00.pdf": {"name": "doc00.pdf", "sha256": DUP, "size": 10, "deleted": True},
    "doc01.pdf": {"name": "doc01.pdf", "sha256": DUP, "size": 10, "deleted": True},
    "img00.jpg": {"name": "img00.jpg", "sha256": UNIQUE, "size": 10, "deleted": True},
    "img01.jpg": {"name": "img01.jpg", "sha256": LIVE, "size": 10, "deleted": False},
}


def test_the_denominator_counts_files_not_digests(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    """Three files were deleted, even though they hold two distinct digests."""
    result = run_carve(harness, MANIFEST, [], tmp_path, capsys)

    assert result["planted_files"] == 4
    assert result["planted_deleted"] == 3
    assert result["planted_deleted_unique"] == 2
    assert result["duplicate_content_files"] == 1
    assert result["overall_recall_bp"] == 0


def test_recovering_one_copy_counts_every_file_holding_that_content(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    """Stated rather than hidden: identical content is indistinguishable.

    ``duplicate_content_files`` is reported next to it so a reader can see the
    two files behind the one digest.
    """
    result = run_carve(harness, MANIFEST, [DUP], tmp_path, capsys)

    assert result["recovered_deleted_exact"] == 2
    assert result["overall_recall_bp"] == 6667


def test_a_full_recovery_is_ten_thousand_basis_points(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    result = run_carve(harness, MANIFEST, [DUP, UNIQUE], tmp_path, capsys)

    assert result["recovered_deleted_exact"] == 3
    assert result["overall_recall_bp"] == 10_000
    assert result["per_filesystem"]["fat32"]["deleted_planted"] == 3
