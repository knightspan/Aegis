"""Build a sealed manifest from a synthetic build or from the physical harness.

Both read the ``.truth.json`` ground truth the testkit builders write, as JSON,
so nothing here imports testkit and the packaged app can run it.

The physical work directory is the one ``scripts/media_benchmark.py`` lays out:

    <work>/images/media-fat32-255m.img          the built corpus image
    <work>/images/media-fat32-255m.truth.json   its ground truth
    <work>/build.json                            the build record (seed)
    <work>/preflight.json                        the preflight record (identity)
    <work>/acquired/acquired.img                 the read-back of the device
    <work>/acquired/acquisition.json             the acquisition record

A PHYSICAL manifest is refused without a SAFE preflight record: without it the
device identity would be invented. A missing acquisition record is not a
refusal; the manifest then records no acquisition, and nothing scored against
it can be reported as physically validated.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from core.benchmark.manifest import (
    AcquisitionIdentity,
    BenchmarkKind,
    GroundTruthManifest,
    ManifestInvalid,
    PhysicalSource,
    SyntheticSource,
    expected_files_from_truth,
    seal_manifest,
    sha256_file,
    utc_stamp,
)
from core.benchmark.rule import BASELINE_IMAGE
from core.errors import EvidenceIntegrityError

__all__ = [
    "TRUTH_SUFFIX",
    "PhysicalWork",
    "load_truth_json",
    "synthetic_manifest",
    "physical_manifest",
    "physical_manifest_from_work",
    "read_json_record",
]

TRUTH_SUFFIX = ".truth.json"


class PhysicalWork:
    """Paths inside the physical harness work directory."""

    def __init__(self, work: Path, image: str = BASELINE_IMAGE) -> None:
        stem = image.removesuffix(".img")
        self.work = work
        self.image = work / "images" / image
        self.truth = work / "images" / f"{stem}{TRUTH_SUFFIX}"
        self.build = work / "build.json"
        self.preflight = work / "preflight.json"
        self.acquired = work / "acquired" / "acquired.img"
        self.acquisition = work / "acquired" / "acquisition.json"


def read_json_record(path: Path) -> dict[str, Any] | None:
    """A JSON object from ``path``, or ``None`` if absent or unreadable."""
    try:
        loaded: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return loaded if isinstance(loaded, dict) else None


def load_truth_json(path: Path) -> dict[str, Any]:
    """The ground truth a testkit builder wrote, as a plain mapping."""
    loaded = read_json_record(path)
    if loaded is None or not isinstance(loaded.get("objects"), list):
        raise ManifestInvalid(f"{path} is not a ground-truth file")
    return loaded


def _common(truth: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "corpus": str(truth.get("corpus") or ""),
        "image_name": str(truth["image"]),
        "filesystem": str(truth.get("filesystem") or ""),
        "cluster_bytes": int(truth.get("cluster_bytes") or 0),
        "files": tuple(expected_files_from_truth(truth["objects"])),
    }


def synthetic_manifest(
    *,
    truth_path: Path,
    image_path: Path,
    benchmark_id: str,
    seed: int,
    created: datetime | None = None,
    notes: Sequence[str] = (),
) -> GroundTruthManifest:
    """A SYNTHETIC manifest for a built image scored directly."""
    truth = load_truth_json(truth_path)
    if str(truth["image"]) != image_path.name:
        raise ManifestInvalid(
            f"{truth_path} describes {truth['image']}, not {image_path.name}"
        )
    if not image_path.is_file():
        raise ManifestInvalid(f"{image_path} is not a regular file")
    return seal_manifest(
        benchmark_id=benchmark_id,
        kind=BenchmarkKind.SYNTHETIC,
        corpus_seed=seed,
        **_common(truth),
        source=SyntheticSource(
            image_path=str(image_path),
            image_sha256=sha256_file(image_path),
            image_bytes=image_path.stat().st_size,
        ),
        acquisition=None,
        created_utc=utc_stamp(created),
        notes=(
            "SYNTHETIC: an image file on host storage, scored directly; no "
            "device, controller or acquisition is involved.",
            *notes,
        ),
    )


def _acquisition(
    record: Mapping[str, Any] | None, acquired: Path | None, label: str
) -> tuple[AcquisitionIdentity | None, list[str]]:
    notes: list[str] = []
    if record is None:
        notes.append(
            "no acquisition record was found, so no acquisition is recorded; "
            "a result against this manifest cannot be physically validated"
        )
        return None, notes
    job_id = str(record.get("job_id") or "").strip()
    recorded_sha = str(record.get("sha256") or "")
    size = int(record.get("bytes_read") or record.get("bytes") or 0)
    if acquired is not None and acquired.is_file():
        actual = sha256_file(acquired)
        if recorded_sha and actual != recorded_sha:
            raise EvidenceIntegrityError(
                f"{acquired} hashes to {actual}, but its acquisition record says "
                f"{recorded_sha}. The image changed after it was acquired."
            )
        recorded_sha = recorded_sha or actual
        size = size or acquired.stat().st_size
    if not job_id:
        notes.append("the acquisition record carries no job id")
        return None, notes
    return (
        AcquisitionIdentity(
            job_id=job_id, image_sha256=recorded_sha, size_bytes=size, record=label
        ),
        notes,
    )


def physical_manifest(
    *,
    truth_path: Path,
    preflight: Mapping[str, Any],
    acquisition_record: Mapping[str, Any] | None,
    acquired_image: Path | None,
    benchmark_id: str,
    seed: int | None,
    seed_note: str = "",
    acquisition_label: str = "",
    created: datetime | None = None,
) -> GroundTruthManifest:
    """A PHYSICAL manifest. Refuses without a SAFE preflight naming the device."""
    if preflight.get("verdict") != "SAFE":
        raise ManifestInvalid(
            "the preflight record is not SAFE, so it does not identify a device "
            "this benchmark may have used"
        )
    missing = [
        key
        for key in ("device", "model", "serial", "transport", "size_bytes")
        if not preflight.get(key)
    ]
    if missing:
        raise ManifestInvalid(
            "the preflight record lacks " + ", ".join(missing) + "; refusing to "
            "seal a PHYSICAL manifest with an incomplete device identity"
        )
    truth = load_truth_json(truth_path)
    acquisition, notes = _acquisition(
        acquisition_record, acquired_image, acquisition_label
    )
    serial_check = preflight.get("serial_check")
    return seal_manifest(
        benchmark_id=benchmark_id,
        kind=BenchmarkKind.PHYSICAL,
        corpus_seed=seed,
        corpus_seed_note=seed_note,
        **_common(truth),
        source=PhysicalSource(
            model=str(preflight["model"]),
            serial=str(preflight["serial"]),
            interface=str(preflight["transport"]),
            size_bytes=int(preflight["size_bytes"]),
            by_id_path=str(preflight["device"]),
            serial_check=(
                str(serial_check.get("status") or "UNRECORDED")
                if isinstance(serial_check, Mapping)
                else "UNRECORDED"
            ),
        ),
        acquisition=acquisition,
        created_utc=utc_stamp(created),
        notes=(
            "PHYSICAL: the corpus image was written to the device named here "
            "and read back; the expected files are the ones planted in the "
            "built image.",
            *notes,
        ),
    )


def physical_manifest_from_work(
    work: Path,
    *,
    benchmark_id: str,
    seed: int | None = None,
    created: datetime | None = None,
) -> GroundTruthManifest:
    """A PHYSICAL manifest from the harness work directory's records."""
    paths = PhysicalWork(work)
    preflight = read_json_record(paths.preflight)
    if preflight is None:
        raise ManifestInvalid(
            f"{paths.preflight} is missing: run `media_benchmark.py preflight "
            "--work` so the device identity is recorded, not typed in"
        )
    seed_note = ""
    if seed is None:
        build = read_json_record(paths.build) or {}
        recorded = build.get("seed")
        if isinstance(recorded, int):
            seed, seed_note = recorded, f"from {paths.build}"
        else:
            seed_note = f"not recorded: {paths.build} is missing or has no seed"
    else:
        seed_note = "given on the command line"
    return physical_manifest(
        truth_path=paths.truth,
        preflight=preflight,
        acquisition_record=read_json_record(paths.acquisition),
        acquired_image=paths.acquired if paths.acquired.is_file() else None,
        benchmark_id=benchmark_id,
        seed=seed,
        seed_note=seed_note,
        acquisition_label=str(paths.acquisition),
        created=created,
    )
