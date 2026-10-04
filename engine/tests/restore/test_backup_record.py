"""Backup records: creation, immutability, tamper detection, verification."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from core.backup import (
    BackupRecord,
    SourceIdentity,
    check_record_digest,
    load_backup_record,
    record_digest_of,
    record_from_acquisition,
    save_backup_record,
    verify_backup,
)
from core.carve.acquire import AcquireOptions, acquire
from core.errors import EvidenceIntegrityError
from pydantic import ValidationError

from .conftest import CHUNK, IMAGE_SIZE, drain, image_bytes


def test_a_record_binds_source_image_hashes_and_digest(
    record: BackupRecord, image: Path, source: SourceIdentity
) -> None:
    data = image_bytes()
    assert record.source == source
    assert record.image_path == str(image)
    assert record.image_size_bytes == IMAGE_SIZE
    assert record.image_sha256 == hashlib.sha256(data).hexdigest()
    assert record.chunk_bytes == CHUNK
    assert record.chunk_hashes == tuple(
        hashlib.sha256(data[i : i + CHUNK]).hexdigest()
        for i in range(0, len(data), CHUNK)
    )
    assert len(record.chunk_hashes) == 4
    assert record.chunk_hash_origin == "computed"
    assert record.produced_by == "operator_supplied"
    assert record.acquisition_job_id is None
    assert record.created_at.tzinfo is not None
    assert record.record_digest == record_digest_of(record)
    check_record_digest(record)


def test_an_operator_supplied_record_says_it_is_not_proof_of_provenance(
    record: BackupRecord,
) -> None:
    text = " ".join(record.limitations)
    assert "NOT_PROOF_OF_PROVENANCE" in text
    assert "not changed since it was hashed" in text


def test_a_record_is_immutable(record: BackupRecord) -> None:
    with pytest.raises(ValidationError):
        record.image_sha256 = "0" * 64  # type: ignore[misc]


def test_an_altered_record_is_refused(record: BackupRecord) -> None:
    forged = record.model_copy(update={"image_sha256": "0" * 64})
    with pytest.raises(EvidenceIntegrityError, match="altered"):
        check_record_digest(forged)


def test_a_record_edited_on_disk_is_refused_on_load(
    record: BackupRecord, tmp_path: Path
) -> None:
    path = tmp_path / "records" / f"{record.backup_id}.json"
    save_backup_record(record, path)
    assert load_backup_record(path) == record
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["source"]["serial"] = "SOMEONE-ELSE"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(EvidenceIntegrityError, match="altered"):
        load_backup_record(path)


def test_saving_never_overwrites_a_record(record: BackupRecord, tmp_path: Path) -> None:
    path = tmp_path / "r.json"
    save_backup_record(record, path)
    with pytest.raises(FileExistsError):
        save_backup_record(record, path)


def test_verification_passes_with_monotonic_progress(record: BackupRecord) -> None:
    progress, result = drain(verify_backup(record, job_id="v"))
    assert result.passed
    assert result.record_digest_ok and result.size_matches and result.sha256_matches
    assert result.mismatched_chunks == ()
    assert result.first_mismatch is None
    assert result.bytes_verified == IMAGE_SIZE
    done = [p.bytes_done for p in progress]
    assert done == sorted(done)
    assert progress[-1].pct_bp == 10_000
    assert {p.phase for p in progress} == {"VERIFY"}


def test_verification_names_the_first_mismatching_chunk(
    record: BackupRecord, image: Path
) -> None:
    data = bytearray(image.read_bytes())
    data[2 * CHUNK + 100] ^= 0xFF
    data[3 * CHUNK + 5] ^= 0xFF
    image.write_bytes(bytes(data))
    _, result = drain(verify_backup(record))
    assert not result.passed
    assert result.mismatched_chunks == (2, 3)
    assert result.first_mismatch is not None
    assert result.first_mismatch.index == 2
    assert result.first_mismatch.offset == 2 * CHUNK
    assert result.first_mismatch.length == CHUNK
    assert "chunk 2" in result.message


def test_verification_of_a_tampered_record_fails_without_trusting_it(
    record: BackupRecord,
) -> None:
    forged = record.model_copy(update={"image_size_bytes": 1})
    _, result = drain(verify_backup(forged))
    assert not result.passed
    assert not result.record_digest_ok
    assert result.bytes_verified == 0


def test_a_truncated_image_fails_verification(
    record: BackupRecord, image: Path
) -> None:
    image.write_bytes(image_bytes()[: IMAGE_SIZE - 4096])
    _, result = drain(verify_backup(record))
    assert not result.passed
    assert not result.size_matches


def test_a_record_from_sanctum_acquisition_reuses_its_hashes(tmp_path: Path) -> None:
    source_file = tmp_path / "source.bin"
    source_file.write_bytes(image_bytes())
    dest = tmp_path / "acquired.img"
    _, acquisition = drain(
        acquire(
            source_file,
            dest,
            options=AcquireOptions(chunk_bytes=CHUNK, operator="test"),
            job_id="acquire-test",
        )
    )
    identity = SourceIdentity(
        path=str(source_file), serial="SRC-1", model="M", size_bytes=IMAGE_SIZE
    )
    made = record_from_acquisition(acquisition, identity)
    assert made.produced_by == "sanctum_acquisition"
    assert made.acquisition_job_id == "acquire-test"
    assert made.chunk_hash_origin == "acquisition"
    assert made.chunk_hashes == tuple(acquisition.chunk_hashes)
    assert made.image_sha256 == acquisition.sha256
    text = " ".join(made.limitations)
    assert "ACQUIRED_BY_SANCTUM" in text and "acquire-test" in text
    assert "does NOT establish" in text
    check_record_digest(made)
    _, verified = drain(verify_backup(made))
    assert verified.passed


def test_an_acquisition_of_another_device_is_refused(tmp_path: Path) -> None:
    source_file = tmp_path / "source.bin"
    source_file.write_bytes(image_bytes())
    _, acquisition = drain(
        acquire(
            source_file,
            tmp_path / "acquired.img",
            options=AcquireOptions(chunk_bytes=CHUNK, operator="test"),
        )
    )
    other = SourceIdentity(
        path="/dev/some-other", serial="X", model="M", size_bytes=IMAGE_SIZE
    )
    with pytest.raises(EvidenceIntegrityError, match="not /dev/some-other"):
        record_from_acquisition(acquisition, other)
