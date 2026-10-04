"""SYNTHETIC and PHYSICAL are never merged, and PHYSICALLY VALIDATED is earned.

The PHYSICAL manifests here are fixtures in memory and ``tmp_path``. They carry
a made-up device and exist only to exercise the status logic; nothing in the
repository is a physical result.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from core.benchmark.manifest import (
    AcquisitionIdentity,
    BenchmarkKind,
    GroundTruthManifest,
    PhysicalSource,
    seal_manifest,
)
from core.benchmark.result import BenchmarkResult, ToolIdentity, build_result
from core.benchmark.rule import BASELINE_IMAGE, Baseline, evaluate_rule
from core.benchmark.score import score_outputs
from core.benchmark.sources import synthetic_manifest
from core.benchmark.stats import (
    PHYSICAL_VALIDATION_REQUIRED,
    PHYSICALLY_RUN_NOT_VALIDATED,
    PHYSICALLY_VALIDATED,
    MixedBenchmarkKinds,
    aggregate,
    aggregate_by_kind,
    physical_validation_status,
)

from tests.benchmark.conftest import Corpus

WHEN = datetime(2026, 9, 28, tzinfo=UTC)
BASELINE = Baseline(image=BASELINE_IMAGE, tool="sanctum-carve", full=5, exact=2,
                    source="test")
TOOL = ToolIdentity(name="sanctum-carve", version="test")


def _synthetic(corpus: Corpus) -> GroundTruthManifest:
    return synthetic_manifest(
        truth_path=corpus.truth, image_path=corpus.image, benchmark_id="syn", seed=0,
        created=WHEN,
    )


def _physical(
    corpus: Corpus,
    *,
    by_id: str = "/dev/disk/by-id/usb-TEST_STICK_0001-0:0",
    acquisition: bool = True,
) -> GroundTruthManifest:
    fields = _synthetic(corpus).model_dump(mode="python")
    fields.update(
        benchmark_id="phy",
        kind=BenchmarkKind.PHYSICAL,
        source=PhysicalSource(
            model="TEST STICK",
            serial="0001",
            interface="usb",
            size_bytes=8 << 30,
            by_id_path=by_id,
            serial_check="AGREE",
        ),
        acquisition=(
            AcquisitionIdentity(
                job_id="media-benchmark-acquire-test",
                image_sha256="a" * 64,
                size_bytes=255 << 20,
            )
            if acquisition
            else None
        ),
    )
    return seal_manifest(**fields)


def _result(
    corpus: Corpus, manifest: GroundTruthManifest, baseline: Baseline = BASELINE
) -> BenchmarkResult:
    from core.benchmark.outputs import load_outputs
    from core.benchmark.score import load_references

    score = score_outputs(
        manifest,
        load_references(manifest, payloads=corpus.payloads),
        load_outputs(corpus.outputs),
    )
    rule = evaluate_rule(
        manifest.kind,
        exact=score.counts.exact,
        full=score.counts.full,
        baseline=baseline,
        image_name=manifest.image_name,
    )
    return build_result(manifest, score, rule, tool=TOOL, created=WHEN)


def test_aggregate_refuses_to_merge_kinds(filled: Corpus) -> None:
    synthetic = _result(filled, _synthetic(filled))
    physical = _result(filled, _physical(filled))
    with pytest.raises(MixedBenchmarkKinds):
        aggregate([synthetic, physical])
    with pytest.raises(ValueError):
        aggregate([])


def test_aggregate_sums_one_kind(filled: Corpus) -> None:
    one = _result(filled, _synthetic(filled))
    summary = aggregate([one, one])
    assert summary.kind is BenchmarkKind.SYNTHETIC
    assert summary.totals["full"] == 10 and summary.totals["exact"] == 4
    assert summary.recall_bp == 4000
    assert summary.fragmented_full == 4 and summary.fragmented_exact == 2
    assert summary.rule_outcomes == {"NOT_APPLICABLE": 2}


def test_aggregate_by_kind_keeps_them_apart(filled: Corpus) -> None:
    synthetic = _result(filled, _synthetic(filled))
    physical = _result(filled, _physical(filled))
    split = aggregate_by_kind([synthetic, physical, synthetic])
    assert set(split) == {"SYNTHETIC", "PHYSICAL"}
    assert split["SYNTHETIC"].results == 2 and split["PHYSICAL"].results == 1


def test_synthetic_results_never_validate_physically(filled: Corpus) -> None:
    manifest = _synthetic(filled)
    status = physical_validation_status([_result(filled, manifest)], [manifest])
    assert status.status == PHYSICAL_VALIDATION_REQUIRED
    assert status.qualifying_results == []


def test_a_passing_physical_run_with_full_identity_validates(filled: Corpus) -> None:
    manifest = _physical(filled)
    result = _result(filled, manifest)
    assert result.rule.outcome == "PASS"
    status = physical_validation_status([result], [manifest])
    assert status.status == PHYSICALLY_VALIDATED
    assert status.qualifying_results == [result.result_digest]


def test_a_physical_run_without_its_manifest_cannot_validate(filled: Corpus) -> None:
    result = _result(filled, _physical(filled))
    status = physical_validation_status([result], [])
    assert status.status == PHYSICAL_VALIDATION_REQUIRED
    assert "manifest was not provided" in status.reasons[0]


@pytest.mark.parametrize(
    "variant",
    [{"acquisition": False}, {"by_id": "/dev/sdb"}],
    ids=["no-acquisition", "kernel-name"],
)
def test_a_physical_run_with_incomplete_identity_cannot_validate(
    filled: Corpus, variant: dict[str, object]
) -> None:
    manifest = _physical(filled, **variant)  # type: ignore[arg-type]
    result = _result(filled, manifest)
    assert result.rule.outcome == "PASS"
    status = physical_validation_status([result], [manifest])
    assert status.status == PHYSICAL_VALIDATION_REQUIRED


def test_a_failing_physical_run_is_run_but_not_validated(filled: Corpus) -> None:
    manifest = _physical(filled)
    perfect = Baseline(image=BASELINE_IMAGE, tool="t", full=5, exact=5, source="test")
    result = _result(filled, manifest, perfect)
    assert result.rule.outcome == "FAIL"
    status = physical_validation_status([result], [manifest])
    assert status.status == PHYSICALLY_RUN_NOT_VALIDATED
    assert "FAIL" in status.reasons[0]
