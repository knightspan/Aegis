"""The ground-truth manifest: what was planted, where, and on what medium.

A benchmark score means something only if the answer key was fixed before the
answers were marked. So the manifest is **sealed**: its digest is the SHA-256 of
its canonical JSON (:mod:`core.ledger.canon`, the same bytes the ledger hashes),
it is written once and never overwritten, and loading it recomputes the digest
and refuses a file whose contents no longer match.

Two kinds, never mixed:

``SYNTHETIC``
    An image file built on host storage and scored directly. Its identity is
    the image's path and SHA-256.
``PHYSICAL``
    A real device that the corpus was written to and then read back. Its
    identity is the device (model, serial, interface, size, by-id path) and
    the acquisition of it (job id, image SHA-256, size).

What sealing proves is narrow: that the manifest has not changed since it was
sealed. It does not prove that the device identity recorded in it is true. That
comes from the preflight and the operator, and the report says so.

Nothing here opens a device.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Final, Literal

import structlog
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from core.errors import EvidenceIntegrityError, SanctumError
from core.ledger.canon import CANON_VERSION, canonical_bytes

__all__ = [
    "MANIFEST_SCHEMA",
    "DIGEST_FIELD",
    "BY_ID_PREFIX",
    "BenchmarkKind",
    "Fragment",
    "ExpectedFile",
    "SyntheticSource",
    "PhysicalSource",
    "AcquisitionIdentity",
    "GroundTruthManifest",
    "ManifestTampered",
    "ManifestExists",
    "ManifestInvalid",
    "manifest_digest_of",
    "seal_manifest",
    "write_manifest",
    "load_manifest",
    "expected_files_from_truth",
    "physical_identity_problems",
    "sha256_file",
    "utc_stamp",
]

logger = structlog.get_logger(__name__)

MANIFEST_SCHEMA: Final = "sanctum-benchmark-manifest/1"
DIGEST_FIELD = "manifest_digest"
#: Where a stable device name lives on Linux. A kernel name such as /dev/sdb
#: is reassigned on every replug, so it does not identify a device.
BY_ID_PREFIX = "/dev/disk/by-id/"

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
NonEmpty = Annotated[str, Field(min_length=1)]


class ManifestTampered(EvidenceIntegrityError):
    """The manifest's contents no longer match the digest it was sealed with."""

    default_remediation = (
        "Do not score against this manifest. Restore the sealed copy from its "
        "ledger entry or backup, or build and seal a new manifest and say in "
        "the report that the ground truth was re-derived."
    )


class ManifestExists(SanctumError):
    """A sealed manifest is already at this path; it is never overwritten."""

    default_remediation = (
        "Load the existing manifest, or write the new one to a different path. "
        "A sealed manifest is replaced by a new file, never edited in place."
    )


class ManifestInvalid(SanctumError):
    """The manifest file does not parse or does not satisfy the schema."""

    default_remediation = (
        "Rebuild the manifest with `python -m core.benchmark manifest`."
    )


class BenchmarkKind(StrEnum):
    """Where the scored bytes came from. The two are never merged."""

    SYNTHETIC = "SYNTHETIC"
    PHYSICAL = "PHYSICAL"


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Fragment(_Frozen):
    """One run of a planted object's bytes on the medium, in object order."""

    offset: Annotated[int, Field(ge=0)]
    length: Annotated[int, Field(gt=0)]


class ExpectedFile(_Frozen):
    """One planted object: what it is, where it was written, what survives."""

    name: NonEmpty
    format: NonEmpty
    #: ``file`` has a real format; ``unformatted`` is filler no signature carver
    #: can find; ``decoy`` is a valid header on bytes of another kind.
    role: Literal["file", "unformatted", "decoy"]
    #: FULL: every planted byte is still on the medium. Only FULL files are in
    #: a recall denominator.
    status: Literal["FULL", "PARTIAL", "GONE"]
    size: Annotated[int, Field(ge=0)]
    #: SHA-256 of the object as planted; empty when the whole object never
    #: existed on the medium (a plant written with its tail already removed).
    sha256: Annotated[str, Field(pattern=r"^([0-9a-f]{64})?$")]
    fragments: tuple[Fragment, ...]
    fragmented: bool
    deleted: bool = False
    surviving_bytes: Annotated[int, Field(ge=0)] = 0
    hole_bytes: Annotated[int, Field(ge=0)] = 0
    note: str = ""

    @model_validator(mode="after")
    def _fragmented_matches_runs(self) -> ExpectedFile:
        if self.fragmented != (len(self.fragments) > 1):
            raise ValueError(
                f"{self.name}: fragmented={self.fragmented} but it has "
                f"{len(self.fragments)} run(s)"
            )
        return self


class SyntheticSource(_Frozen):
    """A built image file, scored directly."""

    source_type: Literal["image"] = "image"
    image_path: NonEmpty
    image_sha256: Sha256
    image_bytes: Annotated[int, Field(gt=0)]


class PhysicalSource(_Frozen):
    """The real device the corpus was written to, as the preflight read it."""

    source_type: Literal["device"] = "device"
    model: NonEmpty
    serial: NonEmpty
    #: Transport as the kernel reports it, e.g. ``usb``.
    interface: NonEmpty
    size_bytes: Annotated[int, Field(gt=0)]
    by_id_path: NonEmpty
    #: Whether two independent sources agreed on the serial (``AGREE``,
    #: ``DISAGREE`` or ``UNVERIFIED``), as the preflight recorded it.
    serial_check: str = "UNRECORDED"


class AcquisitionIdentity(_Frozen):
    """The read-back of the device that the scored image came from."""

    job_id: NonEmpty
    image_sha256: Sha256
    size_bytes: Annotated[int, Field(gt=0)]
    #: Where the record came from, e.g. the acquisition record file.
    record: str = ""


class GroundTruthManifest(_Frozen):
    """The sealed answer key for one benchmark run."""

    schema_version: Literal["sanctum-benchmark-manifest/1"] = MANIFEST_SCHEMA
    canon_version: str = CANON_VERSION
    benchmark_id: NonEmpty
    kind: BenchmarkKind
    #: Seed the corpus builder was run with, or ``None`` when it was not
    #: recorded; ``corpus_seed_note`` then says so.
    corpus_seed: int | None
    corpus_seed_note: str = ""
    corpus: str = ""
    #: Name of the built image the truth was derived from.
    image_name: NonEmpty
    filesystem: str = ""
    cluster_bytes: Annotated[int, Field(ge=0)] = 0
    files: tuple[ExpectedFile, ...]
    source: Annotated[
        SyntheticSource | PhysicalSource, Field(discriminator="source_type")
    ]
    acquisition: AcquisitionIdentity | None = None
    created_utc: NonEmpty
    notes: tuple[str, ...] = ()
    manifest_digest: str = ""

    @model_validator(mode="after")
    def _kind_matches_source(self) -> GroundTruthManifest:
        if self.kind is BenchmarkKind.SYNTHETIC and not isinstance(
            self.source, SyntheticSource
        ):
            raise ValueError("a SYNTHETIC manifest must name an image source")
        if self.kind is BenchmarkKind.PHYSICAL and not isinstance(
            self.source, PhysicalSource
        ):
            raise ValueError("a PHYSICAL manifest must name a device source")
        names = [item.name for item in self.files]
        if len(names) != len(set(names)):
            raise ValueError("expected file names must be unique")
        return self

    def by_name(self, name: str) -> ExpectedFile:
        """The expected file called ``name``."""
        for item in self.files:
            if item.name == name:
                return item
        raise KeyError(name)


def utc_stamp(value: datetime | None = None) -> str:
    """RFC 3339 UTC with six fractional digits, the ledger's timestamp shape."""
    stamp = (value or datetime.now(UTC)).astimezone(UTC)
    return (
        f"{stamp.year:04d}-{stamp.month:02d}-{stamp.day:02d}"
        f"T{stamp.hour:02d}:{stamp.minute:02d}:{stamp.second:02d}"
        f".{stamp.microsecond:06d}Z"
    )


def sha256_file(path: Path) -> str:
    """SHA-256 of a file, read in 1 MiB chunks. Read-only."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def manifest_digest_of(data: Mapping[str, Any]) -> str:
    """SHA-256 of the canonical JSON of ``data`` without its digest field."""
    body = {key: value for key, value in data.items() if key != DIGEST_FIELD}
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def seal_manifest(**fields: Any) -> GroundTruthManifest:
    """Build a manifest from ``fields`` and seal it with its digest.

    Any ``manifest_digest`` passed in is ignored: the digest is computed, never
    supplied.
    """
    fields.pop(DIGEST_FIELD, None)
    unsealed = GroundTruthManifest.model_validate(fields)
    data = unsealed.model_dump(mode="json")
    sealed = unsealed.model_copy(update={DIGEST_FIELD: manifest_digest_of(data)})
    logger.info(
        "benchmark_manifest_sealed",
        benchmark_id=sealed.benchmark_id,
        kind=str(sealed.kind),
        files=len(sealed.files),
        digest=sealed.manifest_digest,
    )
    return sealed


def write_manifest(manifest: GroundTruthManifest, path: Path) -> Path:
    """Write a sealed manifest to a new file. An existing file is never replaced."""
    data = manifest.model_dump(mode="json")
    if not _HEX64.match(manifest.manifest_digest) or manifest_digest_of(
        data
    ) != manifest.manifest_digest:
        raise ManifestTampered(
            "refusing to write a manifest whose digest does not match its "
            "contents; seal it with seal_manifest() first"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(path, "x", encoding="utf-8") as handle:
            handle.write(json.dumps(data, indent=1, sort_keys=True) + "\n")
    except FileExistsError as exists:
        raise ManifestExists(
            f"{path} already holds a manifest; a sealed manifest is never "
            "overwritten"
        ) from exists
    return path


def load_manifest(path: Path) -> GroundTruthManifest:
    """Load a manifest and re-verify its digest.

    Raises:
        ManifestInvalid: the file is not a manifest.
        ManifestTampered: the contents do not match the sealed digest.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as failure:
        raise ManifestInvalid(f"{path} could not be read as JSON: {failure}") from (
            failure
        )
    if not isinstance(raw, dict):
        raise ManifestInvalid(f"{path} is not a JSON object")
    recorded = raw.get(DIGEST_FIELD)
    if not isinstance(recorded, str) or not _HEX64.match(recorded):
        raise ManifestTampered(f"{path} carries no valid {DIGEST_FIELD}")
    # The digest is checked over the bytes as written, before the schema can
    # normalise anything: a field the schema would drop or coerce still counts.
    if manifest_digest_of(raw) != recorded:
        raise ManifestTampered(
            f"{path}: contents do not match the sealed digest {recorded}. The "
            "ground truth was changed after it was sealed."
        )
    try:
        manifest = GroundTruthManifest.model_validate(raw)
    except ValidationError as failure:
        raise ManifestInvalid(f"{path} is not a valid manifest: {failure}") from (
            failure
        )
    if manifest_digest_of(manifest.model_dump(mode="json")) != recorded:
        raise ManifestTampered(
            f"{path}: the parsed manifest does not reproduce its digest"
        )
    return manifest


def expected_files_from_truth(
    objects: Sequence[Mapping[str, Any]],
) -> list[ExpectedFile]:
    """Expected files from the ``objects`` of a testkit ``.truth.json`` file.

    Reads the JSON shape only, so the packaged app never imports testkit.
    """
    files: list[ExpectedFile] = []
    for item in objects:
        extents = [
            Fragment(offset=int(run[0]), length=int(run[1]))
            for run in item.get("extents") or []
        ]
        files.append(
            ExpectedFile(
                name=str(item["name"]),
                format=str(item["format"]),
                role=item["role"],
                status=item["status"],
                size=int(item["size"]),
                sha256=str(item.get("sha256") or ""),
                fragments=tuple(extents),
                fragmented=len(extents) > 1,
                deleted=bool(item.get("deleted", False)),
                surviving_bytes=int(item.get("surviving_bytes") or 0),
                hole_bytes=int(item.get("hole_bytes") or 0),
                note=str(item.get("note") or ""),
            )
        )
    return files


def physical_identity_problems(manifest: GroundTruthManifest) -> list[str]:
    """Why this manifest cannot back a PHYSICAL VALIDATED claim, or ``[]``.

    Structural checks only. They establish that a device and an acquisition
    were recorded in the shape a real run produces; they cannot establish that
    the values are true.
    """
    problems: list[str] = []
    if manifest.kind is not BenchmarkKind.PHYSICAL:
        problems.append(f"the manifest is {manifest.kind}, not PHYSICAL")
    source = manifest.source
    if not isinstance(source, PhysicalSource):
        problems.append("no source device is recorded")
    else:
        for label, value in (
            ("model", source.model),
            ("serial", source.serial),
            ("interface", source.interface),
        ):
            if not value.strip():
                problems.append(f"the device {label} is blank")
        if not source.by_id_path.startswith(BY_ID_PREFIX):
            problems.append(
                f"the device path {source.by_id_path!r} is not a stable "
                f"{BY_ID_PREFIX} name"
            )
        if source.serial_check == "DISAGREE":
            problems.append("two sources for the device serial disagreed")
    acquisition = manifest.acquisition
    if acquisition is None:
        problems.append("no acquisition of the device is recorded")
    elif not acquisition.job_id.strip():
        problems.append("the acquisition has no job id")
    return problems
