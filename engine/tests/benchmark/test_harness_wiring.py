"""``media_benchmark.py score`` produces the first-class result, from records only.

The work directory is laid out by hand, exactly as the harness's read-only steps
lay it out, with a tiny image standing in for the acquired one. No device is
opened: the preflight and acquisition records are fixture files, and the made-up
device in them exists only in ``tmp_path``.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from core.benchmark.manifest import load_manifest, sha256_file
from core.benchmark.result import load_result
from core.benchmark.sources import PhysicalWork
from scripts.media_benchmark import (
    ACQUISITION_RECORD,
    BASELINE_TOOL,
    BUILD_RECORD,
    PREFLIGHT_RECORD,
    first_class_result,
)
from testkit.benchmark import OUTPUT_INDEX, index_outputs, score_run
from testkit.damage import load_truth

from tests.benchmark.conftest import Corpus

PREFLIGHT = {
    "device": "/dev/disk/by-id/usb-TEST_STICK_0001-0:0",
    "model": "TEST STICK",
    "serial": "0001",
    "transport": "usb",
    "size_bytes": 8 << 30,
    "serial_check": {"status": "AGREE"},
    "verdict": "SAFE",
}


def _work(corpus: Corpus, *, preflight: bool = True) -> tuple[Path, Path]:
    work = corpus.root
    paths = PhysicalWork(work)
    assert paths.image == corpus.image and paths.truth == corpus.truth
    assert paths.build.name == BUILD_RECORD
    assert paths.preflight.name == PREFLIGHT_RECORD
    assert paths.acquisition.name == ACQUISITION_RECORD
    paths.build.write_text(json.dumps({"seed": 0}))
    if preflight:
        paths.preflight.write_text(json.dumps(PREFLIGHT))
    paths.acquired.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(corpus.image, paths.acquired)
    paths.acquisition.write_text(
        json.dumps(
            {
                "job_id": "media-benchmark-acquire-test",
                "sha256": sha256_file(paths.acquired),
                "bytes": paths.acquired.stat().st_size,
            }
        )
    )
    run_dir = work / "physical" / "runs" / "stem" / BASELINE_TOOL
    shutil.copytree(corpus.outputs, run_dir / "files")
    (run_dir / OUTPUT_INDEX).write_text(json.dumps(index_outputs(run_dir / "files")))
    (run_dir / "sanctum-result.json").write_text(
        json.dumps({"objects": [{"file": "noise.bin", "bucket": "HIGH"}]})
    )
    return work, run_dir


def _legacy(corpus: Corpus, run_dir: Path) -> dict[str, object]:
    from dataclasses import asdict

    legacy = score_run(
        load_truth(corpus.truth),
        run_dir / OUTPUT_INDEX,
        corpus.payloads,
        tool=BASELINE_TOOL,
        image_path=PhysicalWork(corpus.root).acquired,
    )
    return {**asdict(legacy), "fp_total": legacy.fp_total}


def test_score_seals_a_physical_manifest_and_a_result(filled: Corpus) -> None:
    work, run_dir = _work(filled)
    produced = first_class_result(
        work,
        run_dir=run_dir,
        image=PhysicalWork(work).acquired,
        run_meta={"seconds": 2.5, "returncode": 0, "timed_out": False},
        legacy=_legacy(filled, run_dir),
        benchmark_id="phy-wiring",
    )
    assert produced["produced"] is True, produced
    assert produced["matches_legacy_score"] is True, produced["legacy_disagreements"]
    assert produced["acquisition_recorded"] is True
    # 2 of 5 against the registered 21 of 22 is far more than 10 points below.
    assert produced["rule_outcome"] == "FAIL" and produced["rule_binding"] is True
    assert produced["signed"] is False

    manifest = load_manifest(Path(str(produced["manifest"])))
    assert manifest.kind == "PHYSICAL" and manifest.benchmark_id == "phy-wiring"
    result = load_result(Path(str(produced["result"])))
    assert result.manifest_digest == manifest.manifest_digest
    assert result.score.high_bucket.high_false_positives == ["g/noise.bin"]
    assert result.tool.run_ms == 2500

    # A second score reuses the sealed manifest; it is never re-derived.
    again = first_class_result(
        work,
        run_dir=run_dir,
        image=PhysicalWork(work).acquired,
        run_meta={},
        legacy=_legacy(filled, run_dir),
        benchmark_id="ignored",
    )
    assert again["manifest_digest"] == produced["manifest_digest"]


def test_without_a_preflight_record_no_result_is_produced(filled: Corpus) -> None:
    work, run_dir = _work(filled, preflight=False)
    produced = first_class_result(
        work,
        run_dir=run_dir,
        image=PhysicalWork(work).acquired,
        run_meta={},
        legacy=_legacy(filled, run_dir),
    )
    assert produced["produced"] is False
    assert "preflight.json" in str(produced["reason"])
    assert not (work / "physical" / "manifest.json").exists()


def test_a_disagreement_with_the_legacy_score_is_reported(filled: Corpus) -> None:
    work, run_dir = _work(filled)
    legacy = {**_legacy(filled, run_dir), "exact": 99}
    produced = first_class_result(
        work,
        run_dir=run_dir,
        image=PhysicalWork(work).acquired,
        run_meta={},
        legacy=legacy,
    )
    assert produced["matches_legacy_score"] is False
    assert produced["legacy_disagreements"] == {
        "exact": {"legacy": 99, "first_class": 2}
    }
