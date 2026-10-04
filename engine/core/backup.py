"""Backup identity records and read-only backup verification.

A backup record is the immutable statement "this image, of this size, hashed to
this SHA-256 (and these per-chunk hashes), was recorded against this source
device identity at this time". It exists so a later restore can name exactly
which bytes it is about to write, and so a later verification can say which
chunk of an image stopped matching instead of condemning the whole file.

What a record proves, and what it does not
------------------------------------------
Hashes prove an image has not changed **since it was hashed**. They do not prove
where the image came from. A record made from an operator-supplied image binds
the source identity by the operator's assertion alone, and says so in its
``limitations``. A record made from Sanctum's own acquisition of that exact
device identity carries the acquisition job id: the acquisition hashed the bytes
in the same pass that read them, which establishes the image equals what that
run read from that path - and still not that the device carried the identity
recorded here at the moment it was read, nor that the medium was unchanged
during the read unless a write block was applied and read back.

Nothing here writes to an image or a device. Images are opened ``rb``.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable, Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import structlog
from pydantic import BaseModel, ConfigDict

from core.errors import EvidenceIntegrityError
from core.ledger.canon import canonical_bytes
from core.models import AcquisitionRecord, Progress

__all__ = [
    "BACKUP_CHUNK_BYTES",
    "BACKUP_SCHEMA",
    "BackupRecord",
    "BackupVerification",
    "ChunkMismatch",
    "SourceIdentity",
    "check_record_digest",
    "create_backup_record",
    "load_backup_record",
    "record_digest_of",
    "record_from_acquisition",
    "save_backup_record",
    "source_identity_from_probe",
    "verify_backup",
]

logger = structlog.get_logger(__name__)

#: Chunk size for records whose chunk hashes are computed here. The same default
#: as acquisition, and a multiple of every logical sector size in use (512,
#: 4096), so a chunk is also a sector-aligned write unit for a restore.
BACKUP_CHUNK_BYTES = 4 * 1024 * 1024

BACKUP_SCHEMA = "sanctum.backup/1"

#: Read size while hashing. Independent of the chunk size.
_READ_BYTES = 1024 * 1024


class SourceIdentity(BaseModel):
    """The device a backup is recorded against, as the host reported it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    serial: str
    model: str
    size_bytes: int
    #: A path stable across replug (``/dev/disk/by-id/...``), when the host has one.
    stable_id: str | None = None


def source_identity_from_probe(probe: dict[str, Any]) -> SourceIdentity:
    """The identity fields of a helper ``probe_capabilities``-shaped answer."""
    device = probe.get("device") or {}
    return SourceIdentity(
        path=str(device.get("path", "")),
        serial=str(device.get("serial", "") or ""),
        model=str(device.get("model", "") or ""),
        size_bytes=int(device.get("size_bytes", 0) or 0),
        stable_id=(str(device["by_id_path"]) if device.get("by_id_path") else None),
    )


class BackupRecord(BaseModel):
    """Immutable identity of one backup image. See the module docstring."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = BACKUP_SCHEMA
    backup_id: str
    source: SourceIdentity
    source_size_bytes: int
    image_path: str
    image_size_bytes: int
    image_sha256: str
    chunk_bytes: int
    chunk_hashes: tuple[str, ...]
    #: ``acquisition`` when the chunk hashes were taken from the acquisition
    #: record (hashed during the read pass); ``computed`` when hashed here.
    chunk_hash_origin: Literal["acquisition", "computed"]
    produced_by: Literal["sanctum_acquisition", "operator_supplied"]
    acquisition_job_id: str | None = None
    created_at: datetime
    limitations: tuple[str, ...]
    #: SHA-256 over the canonical bytes of every other field.
    record_digest: str = ""


class ChunkMismatch(BaseModel):
    """The first chunk of an image that no longer matches its record."""

    model_config = ConfigDict(frozen=True)

    index: int
    offset: int
    length: int
    expected_sha256: str
    actual_sha256: str


class BackupVerification(BaseModel):
    """Outcome of re-hashing a backup image against its record."""

    model_config = ConfigDict(frozen=True)

    backup_id: str
    passed: bool
    record_digest_ok: bool
    size_matches: bool
    sha256_matches: bool
    expected_sha256: str
    actual_sha256: str
    expected_size_bytes: int
    actual_size_bytes: int
    mismatched_chunks: tuple[int, ...]
    first_mismatch: ChunkMismatch | None
    bytes_verified: int
    verified_at: datetime
    message: str


# --------------------------------------------------------------------------
# Digest
# --------------------------------------------------------------------------


def record_digest_of(record: BackupRecord) -> str:
    """SHA-256 of the canonical bytes of every field but the digest itself."""
    body = record.model_dump(mode="json", exclude={"record_digest"})
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def check_record_digest(record: BackupRecord) -> None:
    """Raise :class:`EvidenceIntegrityError` unless the digest is the record's."""
    expected = record_digest_of(record)
    if record.record_digest != expected:
        raise EvidenceIntegrityError(
            f"backup record {record.backup_id} was altered after it was made: its "
            f"digest is {record.record_digest or 'missing'}, its content hashes "
            f"to {expected}",
            remediation=(
                "Do not restore from this record. Re-create the record from the "
                "image and verify the image against an independent hash."
            ),
        )


def _sealed(fields: dict[str, Any]) -> BackupRecord:
    draft = BackupRecord(**fields)
    return draft.model_copy(update={"record_digest": record_digest_of(draft)})


def save_backup_record(record: BackupRecord, path: Path) -> None:
    """Write the record as JSON. Refuses to overwrite an existing record."""
    check_record_digest(record)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        handle.write(record.model_dump_json(indent=2))


def load_backup_record(path: Path) -> BackupRecord:
    """Read a record and refuse it if its digest does not hold."""
    try:
        record = BackupRecord.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise EvidenceIntegrityError(
            f"backup record {path} is unreadable: {type(exc).__name__}",
            remediation="Re-create the backup record from the image.",
        ) from exc
    check_record_digest(record)
    return record


# --------------------------------------------------------------------------
# Creation
# --------------------------------------------------------------------------


def _operator_supplied_limitations(
    source: SourceIdentity, created_at: datetime, image_size: int
) -> list[str]:
    out = [
        "NOT_PROOF_OF_PROVENANCE: this image was supplied by the operator. Its "
        "SHA-256 and chunk hashes prove only that the image has not changed "
        f"since it was hashed at {created_at.isoformat()}; they do not prove the "
        f"image was read from {source.path} (serial {source.serial or 'none'}). "
        "The source identity is what the host reported for that device when "
        "this record was made, bound to the image by the operator's assertion "
        "alone.",
    ]
    if image_size != source.size_bytes:
        out.append(
            f"IMAGE_SIZE_DIFFERS: the image is {image_size} bytes and the source "
            f"device reports {source.size_bytes}. A restore writes the image's "
            "bytes only."
        )
    return out


def create_backup_record(
    image: Path,
    source: SourceIdentity,
    *,
    job_id: str = "backup",
    chunk_bytes: int = BACKUP_CHUNK_BYTES,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> Generator[Progress, None, BackupRecord]:
    """Hash an operator-supplied image read-only and return its sealed record.

    Chunk hashes are computed in the same pass as the whole-image hash. The
    image must not change while it is read: size, mtime and inode are compared
    before and after, and a difference refuses.
    """
    if chunk_bytes <= 0:
        raise ValueError("chunk_bytes must be positive")
    if not image.is_file():
        raise EvidenceIntegrityError(
            f"backup image {image} is not a regular file",
            remediation="Name a regular image file.",
        )
    before = image.stat()
    total = before.st_size
    whole = hashlib.sha256()
    chunk = hashlib.sha256()
    filled = 0
    chunks: list[str] = []
    done = 0
    yield _progress(job_id, "HASH", 0, total, f"hashing {image.name}")
    with image.open("rb") as handle:  # read-only by construction
        while True:
            data = handle.read(_READ_BYTES)
            if not data:
                break
            whole.update(data)
            view = memoryview(data)
            while view:
                take = min(chunk_bytes - filled, len(view))
                chunk.update(view[:take])
                filled += take
                view = view[take:]
                if filled == chunk_bytes:
                    chunks.append(chunk.hexdigest())
                    chunk = hashlib.sha256()
                    filled = 0
            done += len(data)
            yield _progress(job_id, "HASH", done, total, f"hashed {done} bytes")
    if filled:
        chunks.append(chunk.hexdigest())
    after = image.stat()
    if (after.st_size, after.st_mtime_ns, after.st_ino) != (
        before.st_size,
        before.st_mtime_ns,
        before.st_ino,
    ) or done != total:
        raise EvidenceIntegrityError(
            f"backup image {image} changed while it was being hashed",
            remediation="Wait for whatever is writing the image to finish.",
        )
    created_at = clock()
    return _sealed(
        {
            "backup_id": _new_id(),
            "source": source,
            "source_size_bytes": source.size_bytes,
            "image_path": str(image),
            "image_size_bytes": total,
            "image_sha256": whole.hexdigest(),
            "chunk_bytes": chunk_bytes,
            "chunk_hashes": tuple(chunks),
            "chunk_hash_origin": "computed",
            "produced_by": "operator_supplied",
            "acquisition_job_id": None,
            "created_at": created_at,
            "limitations": tuple(
                _operator_supplied_limitations(source, created_at, total)
            ),
        }
    )


def record_from_acquisition(
    acquisition: AcquisitionRecord,
    source: SourceIdentity,
    *,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> BackupRecord:
    """A record for an image Sanctum acquired from this exact device identity.

    Reuses the acquisition's hashes, which were computed during the read. Refused
    unless the acquisition read the same path (or stable id) and the same size
    as the identity given, produced a single raw file, and that file is still
    the size the acquisition wrote. It is not re-hashed here; run
    :func:`verify_backup` for that.
    """
    read_from = acquisition.source.path
    if read_from not in {source.path, source.stable_id}:
        raise EvidenceIntegrityError(
            f"acquisition {acquisition.job_id} read {read_from}, not {source.path}; "
            "it cannot be recorded as a Sanctum acquisition of this device",
            remediation="Record the image as operator-supplied instead.",
        )
    if acquisition.source.size_bytes != source.size_bytes:
        raise EvidenceIntegrityError(
            f"acquisition {acquisition.job_id} read {acquisition.source.size_bytes} "
            f"bytes; {source.path} now reports {source.size_bytes}",
            remediation="The device changed since it was acquired. Re-acquire it.",
        )
    if acquisition.fmt != "raw" or len(acquisition.source.segments) > 1:
        raise EvidenceIntegrityError(
            f"acquisition {acquisition.job_id} is not a single raw file",
            remediation="Restore needs a single raw image. Acquire to raw.",
        )
    image = Path(acquisition.dest_path)
    try:
        size = image.stat().st_size
    except OSError as exc:
        raise EvidenceIntegrityError(
            f"the acquired image {image} is not readable",
            remediation="Check the path; nothing was recorded.",
        ) from exc
    if size != acquisition.bytes_read:
        raise EvidenceIntegrityError(
            f"the acquired image {image} is {size} bytes; the acquisition wrote "
            f"{acquisition.bytes_read}",
            remediation="The image changed since acquisition. Re-acquire.",
        )
    created_at = clock()
    limitations = [
        f"ACQUIRED_BY_SANCTUM: produced by acquisition job {acquisition.job_id}, "
        "which hashed the bytes in the same pass that read them from "
        f"{read_from} ({acquisition.bytes_read} bytes). This establishes the "
        "image equals what that run read from that path. It does NOT establish "
        "that the device at that path carried the identity recorded here at the "
        "moment it was read (the identity was re-read when this record was "
        "made), and hashes never prove provenance on their own.",
        (
            "WRITE_BLOCKED: a software write block was applied and read back "
            "during acquisition."
            if acquisition.write_blocked
            else "NOT_WRITE_BLOCKED: no software write block was verified during "
            "acquisition, so the medium may have changed while it was read."
        ),
    ]
    if acquisition.bad_sectors:
        count = sum(item.sector_count for item in acquisition.bad_sectors)
        limitations.append(
            f"BAD_SECTORS: {count} sector(s) could not be read during acquisition "
            "and hold tool-generated fill bytes in the image. A restore writes "
            "those fill bytes, not the original contents."
        )
    limitations.extend(acquisition.limitations)
    return _sealed(
        {
            "backup_id": _new_id(),
            "source": source,
            "source_size_bytes": source.size_bytes,
            "image_path": str(image),
            "image_size_bytes": acquisition.bytes_read,
            "image_sha256": acquisition.sha256,
            "chunk_bytes": acquisition.chunk_bytes,
            "chunk_hashes": tuple(acquisition.chunk_hashes),
            "chunk_hash_origin": "acquisition",
            "produced_by": "sanctum_acquisition",
            "acquisition_job_id": acquisition.job_id,
            "created_at": created_at,
            "limitations": tuple(limitations),
        }
    )


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------


def verify_backup(
    record: BackupRecord,
    *,
    job_id: str = "backup-verify",
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> Generator[Progress, None, BackupVerification]:
    """Re-hash the image read-only and compare it, chunk by chunk, to the record.

    A record whose own digest does not hold fails without reading the image:
    comparing an image to a tampered record proves nothing.
    """
    digest_ok = record.record_digest == record_digest_of(record)
    image = Path(record.image_path)
    total = record.image_size_bytes
    whole = hashlib.sha256()
    mismatched: list[int] = []
    first: ChunkMismatch | None = None
    verified = 0
    actual_size = -1
    if digest_ok:
        try:
            actual_size = image.stat().st_size
        except OSError:
            actual_size = -1
    if digest_ok and actual_size >= 0:
        yield _progress(job_id, "VERIFY", 0, total, f"verifying {image.name}")
        with image.open("rb") as handle:  # read-only by construction
            index = 0
            while True:
                piece = handle.read(record.chunk_bytes)
                if not piece:
                    break
                whole.update(piece)
                actual = hashlib.sha256(piece).hexdigest()
                expected = (
                    record.chunk_hashes[index]
                    if index < len(record.chunk_hashes)
                    else ""
                )
                if actual != expected:
                    mismatched.append(index)
                    if first is None:
                        first = ChunkMismatch(
                            index=index,
                            offset=index * record.chunk_bytes,
                            length=len(piece),
                            expected_sha256=expected,
                            actual_sha256=actual,
                        )
                verified += len(piece)
                index += 1
                yield _progress(
                    job_id, "VERIFY", verified, total, f"verified chunk {index}"
                )
    actual_sha = whole.hexdigest() if actual_size >= 0 else ""
    size_ok = actual_size == record.image_size_bytes
    sha_ok = actual_sha == record.image_sha256
    passed = digest_ok and size_ok and sha_ok and not mismatched
    if not digest_ok:
        message = "the backup record was altered after it was made; not verified"
    elif actual_size < 0:
        message = f"the image {image} is not readable"
    elif passed:
        message = "the image matches its record, chunk for chunk"
    elif first is not None:
        message = (
            f"chunk {first.index} (bytes {first.offset}-"
            f"{first.offset + first.length - 1}) is the first that no longer "
            "matches the record"
        )
    else:
        message = "the image's size or whole-image hash no longer matches"
    return BackupVerification(
        backup_id=record.backup_id,
        passed=passed,
        record_digest_ok=digest_ok,
        size_matches=size_ok,
        sha256_matches=sha_ok,
        expected_sha256=record.image_sha256,
        actual_sha256=actual_sha,
        expected_size_bytes=record.image_size_bytes,
        actual_size_bytes=actual_size,
        mismatched_chunks=tuple(mismatched),
        first_mismatch=first,
        bytes_verified=verified,
        verified_at=clock(),
        message=message,
    )


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _new_id() -> str:
    return f"bk-{secrets.token_hex(8)}"


def _progress(job_id: str, phase: str, done: int, total: int, message: str) -> Progress:
    pct = 10_000 if total <= 0 else min(10_000, done * 10_000 // total)
    return Progress(
        job_id=job_id,
        phase=phase,
        pct_bp=pct,
        bytes_done=done,
        bytes_total=total,
        throughput_bytes_per_sec=0,
        eta_seconds=0,
        message=message,
    )
