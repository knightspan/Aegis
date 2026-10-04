"""The ground-truth manifest is sealed: frozen in memory, immutable on disk."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from core.benchmark.manifest import (
    AcquisitionIdentity,
    BenchmarkKind,
    GroundTruthManifest,
    ManifestExists,
    ManifestInvalid,
    ManifestTampered,
    PhysicalSource,
    load_manifest,
    manifest_digest_of,
    physical_identity_problems,
    seal_manifest,
    write_manifest,
)
from core.benchmark.sources import (
    PhysicalWork,
    physical_manifest,
    physical_manifest_from_work,
    synthetic_manifest,
)
from core.errors import EvidenceIntegrityError
from pydantic import ValidationError

from tests.benchmark.conftest import Corpus, build_corpus

REPO = Path(__file__).resolve().parents[2]

PREFLIGHT = {
    "device": "/dev/disk/by-id/usb-TEST_STICK_0001-0:0",
    "model": "TEST STICK",
    "serial": "0001",
    "transport": "usb",
    "size_bytes": 8 * 1024 * 1024 * 1024,
    "serial_check": {"status": "AGREE"},
    "verdict": "SAFE",
}


def _synthetic(corpus: Corpus) -> GroundTruthManifest:
    return synthetic_manifest(
        truth_path=corpus.truth,
        image_path=corpus.image,
        benchmark_id="syn-test",
        seed=26149,
    )


def test_a_sealed_manifest_round_trips_and_keeps_its_digest(
    corpus: Corpus, tmp_path: Path
) -> None:
    manifest = _synthetic(corpus)
    assert manifest.kind is BenchmarkKind.SYNTHETIC
    assert len(manifest.manifest_digest) == 64
    assert manifest.by_name("frag.png").fragmented
    assert [run.offset for run in manifest.by_name("frag.png").fragments] == [
        24 * 1024,
        40 * 1024,
    ]
    assert not manifest.by_name("exact.jpg").fragmented

    path = write_manifest(manifest, tmp_path / "manifest.json")
    loaded = load_manifest(path)
    assert loaded == manifest
    digest = manifest_digest_of(loaded.model_dump(mode="json"))
    assert digest == manifest.manifest_digest


def test_the_manifest_is_frozen_in_memory(corpus: Corpus) -> None:
    manifest = _synthetic(corpus)
    with pytest.raises(ValidationError):
        manifest.benchmark_id = "other"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        manifest.files[0].sha256 = "0" * 64  # type: ignore[misc]


@pytest.mark.parametrize(
    "tamper",
    [
        lambda d: d["files"][0].update(size=d["files"][0]["size"] + 1),
        lambda d: d["files"][1].update(sha256="0" * 64),
        lambda d: d["files"][3]["fragments"][1].update(offset=0),
        lambda d: d.update(kind="PHYSICAL"),
        lambda d: d.update(corpus_seed=1),
        lambda d: d["files"].pop(),
        lambda d: d.update(unexpected="field"),
    ],
    ids=["size", "sha256", "fragment", "kind", "seed", "dropped-file", "extra-field"],
)
def test_any_edit_after_sealing_is_refused_on_load(
    corpus: Corpus, tmp_path: Path, tamper: object
) -> None:
    path = write_manifest(_synthetic(corpus), tmp_path / "manifest.json")
    data = json.loads(path.read_text())
    tamper(data)  # type: ignore[operator]
    path.write_text(json.dumps(data))
    with pytest.raises(ManifestTampered):
        load_manifest(path)


def test_a_resealed_forgery_with_an_unknown_field_is_still_refused(
    corpus: Corpus, tmp_path: Path
) -> None:
    path = write_manifest(_synthetic(corpus), tmp_path / "manifest.json")
    data = json.loads(path.read_text())
    data["unexpected"] = "field"
    data["manifest_digest"] = manifest_digest_of(data)
    path.write_text(json.dumps(data))
    with pytest.raises(ManifestInvalid):
        load_manifest(path)


def test_a_missing_digest_is_refused(corpus: Corpus, tmp_path: Path) -> None:
    path = write_manifest(_synthetic(corpus), tmp_path / "manifest.json")
    data = json.loads(path.read_text())
    del data["manifest_digest"]
    path.write_text(json.dumps(data))
    with pytest.raises(ManifestTampered):
        load_manifest(path)


def test_a_written_manifest_is_never_overwritten(
    corpus: Corpus, tmp_path: Path
) -> None:
    path = write_manifest(_synthetic(corpus), tmp_path / "manifest.json")
    before = path.read_bytes()
    with pytest.raises(ManifestExists):
        write_manifest(_synthetic(corpus), path)
    assert path.read_bytes() == before


def test_an_unsealed_manifest_cannot_be_written(corpus: Corpus, tmp_path: Path) -> None:
    edited = _synthetic(corpus).model_copy(update={"benchmark_id": "edited"})
    with pytest.raises(ManifestTampered):
        write_manifest(edited, tmp_path / "manifest.json")
    assert not (tmp_path / "manifest.json").exists()


def test_a_supplied_digest_is_ignored_when_sealing(corpus: Corpus) -> None:
    manifest = _synthetic(corpus)
    data = manifest.model_dump(mode="python")
    data["manifest_digest"] = "f" * 64
    assert seal_manifest(**data).manifest_digest == manifest.manifest_digest


def test_kind_and_source_can_never_be_mixed(corpus: Corpus) -> None:
    fields = _synthetic(corpus).model_dump(mode="python")
    fields["kind"] = BenchmarkKind.PHYSICAL
    with pytest.raises(ValidationError):
        seal_manifest(**fields)
    fields["kind"] = BenchmarkKind.SYNTHETIC
    fields["source"] = PhysicalSource(**{
        "model": "m", "serial": "s", "interface": "usb", "size_bytes": 1,
        "by_id_path": "/dev/disk/by-id/x",
    })
    with pytest.raises(ValidationError):
        seal_manifest(**fields)


def test_a_fragmented_flag_must_match_the_runs(corpus: Corpus) -> None:
    fields = _synthetic(corpus).model_dump(mode="python")
    fields["files"][0]["fragmented"] = True
    with pytest.raises(ValidationError):
        seal_manifest(**fields)


def test_a_synthetic_manifest_names_the_image_it_describes(corpus: Corpus) -> None:
    other = build_corpus(corpus.root.parent / "other", image_name="other.img")
    with pytest.raises(ManifestInvalid):
        synthetic_manifest(
            truth_path=corpus.truth, image_path=other.image, benchmark_id="x", seed=0
        )


def _physical_work(corpus: Corpus, *, acquisition: bool = True) -> Path:
    work = corpus.root
    paths = PhysicalWork(work)
    paths.preflight.write_text(json.dumps(PREFLIGHT))
    paths.build.write_text(json.dumps({"seed": 3}))
    paths.acquired.parent.mkdir(parents=True, exist_ok=True)
    paths.acquired.write_bytes(corpus.image.read_bytes())
    if acquisition:
        from core.benchmark.manifest import sha256_file

        paths.acquisition.write_text(
            json.dumps(
                {
                    "job_id": "media-benchmark-acquire-test",
                    "sha256": sha256_file(paths.acquired),
                    "bytes": paths.acquired.stat().st_size,
                }
            )
        )
    return work


def test_a_physical_manifest_records_device_and_acquisition(corpus: Corpus) -> None:
    manifest = physical_manifest_from_work(_physical_work(corpus), benchmark_id="phy")
    assert manifest.kind is BenchmarkKind.PHYSICAL
    assert isinstance(manifest.source, PhysicalSource)
    assert manifest.source.serial == "0001"
    assert manifest.source.serial_check == "AGREE"
    assert manifest.corpus_seed == 3
    assert isinstance(manifest.acquisition, AcquisitionIdentity)
    assert manifest.acquisition.job_id == "media-benchmark-acquire-test"
    assert physical_identity_problems(manifest) == []


def test_a_physical_manifest_without_acquisition_cannot_qualify(corpus: Corpus) -> None:
    manifest = physical_manifest_from_work(
        _physical_work(corpus, acquisition=False), benchmark_id="phy"
    )
    assert manifest.acquisition is None
    assert "no acquisition of the device is recorded" in physical_identity_problems(
        manifest
    )


def test_a_physical_manifest_is_refused_without_a_preflight(corpus: Corpus) -> None:
    with pytest.raises(ManifestInvalid):
        physical_manifest_from_work(corpus.root, benchmark_id="phy")
    with pytest.raises(ManifestInvalid):
        physical_manifest(
            truth_path=corpus.truth,
            preflight={**PREFLIGHT, "verdict": "REFUSED"},
            acquisition_record=None,
            acquired_image=None,
            benchmark_id="phy",
            seed=0,
        )
    with pytest.raises(ManifestInvalid):
        physical_manifest(
            truth_path=corpus.truth,
            preflight={**PREFLIGHT, "serial": ""},
            acquisition_record=None,
            acquired_image=None,
            benchmark_id="phy",
            seed=0,
        )


def test_an_acquired_image_that_changed_since_acquisition_is_refused(
    corpus: Corpus,
) -> None:
    work = _physical_work(corpus)
    acquired = PhysicalWork(work).acquired
    acquired.write_bytes(b"\x00" + acquired.read_bytes()[1:])
    with pytest.raises(EvidenceIntegrityError):
        physical_manifest_from_work(work, benchmark_id="phy")


def test_a_kernel_device_name_is_not_a_stable_identity(corpus: Corpus) -> None:
    manifest = physical_manifest(
        truth_path=corpus.truth,
        preflight={**PREFLIGHT, "device": "/dev/sdb"},
        acquisition_record={"job_id": "j", "sha256": "a" * 64, "bytes": 1},
        acquired_image=None,
        benchmark_id="phy",
        seed=0,
    )
    assert any("by-id" in problem for problem in physical_identity_problems(manifest))


def test_importing_the_package_never_imports_testkit() -> None:
    """The frozen app excludes testkit; core.benchmark must not need it."""
    code = (
        "import sys, pkgutil, importlib, core.benchmark as b\n"
        "for m in pkgutil.iter_modules(b.__path__):\n"
        "    importlib.import_module('core.benchmark.' + m.name)\n"
        "print('testkit' in sys.modules)\n"
    )
    done = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
    )
    assert done.stdout.strip() == "False"
