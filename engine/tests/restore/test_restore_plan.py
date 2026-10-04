"""Restore planning: refusals, identity relation, byte range, drift, digest."""

from __future__ import annotations

from pathlib import Path

import pytest
from core.backup import BackupRecord
from core.errors import WorkflowGateRefused
from core.restore import (
    ASSUMED_WRITE_BYTES_PER_SEC,
    FileBlockTarget,
    file_target_identity,
    plan_digest_of,
    plan_restore,
    require_executable,
    restore_plan_drift,
    target_identity_from_probe,
)

from .conftest import IMAGE_SIZE, TARGET_SIZE, device_probe


def test_a_plan_names_the_exact_range_and_an_estimate(record: BackupRecord) -> None:
    plan = plan_restore(record, target_identity_from_probe(device_probe()))
    assert plan.executable
    assert plan.blocking == ()
    assert (plan.write_offset, plan.write_length, plan.write_end) == (
        0,
        IMAGE_SIZE,
        IMAGE_SIZE,
    )
    assert plan.target_tail_untouched_bytes == TARGET_SIZE - IMAGE_SIZE
    assert plan.assumed_write_bytes_per_sec == ASSUMED_WRITE_BYTES_PER_SEC
    assert plan.estimated_write_seconds >= 1
    assert plan.plan_digest == plan_digest_of(plan)
    text = " ".join(plan.limitations)
    assert "TAIL_UNTOUCHED" in text and "READ_BACK_THROUGH_OS" in text
    assert "NOT_PROOF_OF_PROVENANCE" in text
    require_executable(plan)


def test_a_system_disk_is_refused(record: BackupRecord) -> None:
    plan = plan_restore(
        record,
        target_identity_from_probe(device_probe(is_system_disk=True, mounted_at=[])),
    )
    assert any("boot/root" in reason for reason in plan.blocking)
    with pytest.raises(WorkflowGateRefused) as refused:
        require_executable(plan)
    assert "Nothing was written" in refused.value.message


def test_a_mounted_target_is_refused(record: BackupRecord) -> None:
    plan = plan_restore(
        record, target_identity_from_probe(device_probe(mounted_at=["/mnt/x"]))
    )
    assert any("/mnt/x" in reason for reason in plan.blocking)
    with pytest.raises(WorkflowGateRefused):
        require_executable(plan)


def test_a_target_smaller_than_the_image_is_refused(record: BackupRecord) -> None:
    plan = plan_restore(
        record, target_identity_from_probe(device_probe(size_bytes=IMAGE_SIZE - 512))
    )
    assert any("too small" in reason for reason in plan.blocking)


def test_a_target_with_nothing_to_type_is_refused(record: BackupRecord) -> None:
    plan = plan_restore(
        record, target_identity_from_probe(device_probe(serial="", by_id_path=None))
    )
    assert any("cannot be confirmed" in reason for reason in plan.blocking)


def test_the_image_itself_is_never_a_target(record: BackupRecord) -> None:
    plan = plan_restore(record, file_target_identity(record.image_path))
    assert any("backup image itself" in reason for reason in plan.blocking)


def test_the_same_device_is_recognised(record: BackupRecord) -> None:
    probe = device_probe(
        path="/dev/other-node",
        serial=record.source.serial,
        model=record.source.model,
        size_bytes=record.source.size_bytes,
    )
    plan = plan_restore(record, target_identity_from_probe(probe))
    assert plan.identity_relation == "same_device"
    assert "its own backup" in plan.identity_statement


def test_a_different_device_is_allowed_and_stated(record: BackupRecord) -> None:
    plan = plan_restore(record, target_identity_from_probe(device_probe()))
    assert plan.identity_relation == "different_device"
    assert "NOT the backup's source" in plan.identity_statement
    assert plan.executable


def test_a_file_target_has_undetermined_identity(
    record: BackupRecord, tmp_path: Path
) -> None:
    target = FileBlockTarget.create(tmp_path / "t.img", TARGET_SIZE)
    target.close()
    plan = plan_restore(record, file_target_identity(tmp_path / "t.img"))
    assert plan.identity_relation == "undetermined"
    assert plan.target.stable_id and plan.target.stable_id.startswith("file-inode:")
    assert plan.executable


def test_identity_drift_between_plan_and_now_is_named(record: BackupRecord) -> None:
    approved = plan_restore(record, target_identity_from_probe(device_probe()))
    fresh = plan_restore(
        record, target_identity_from_probe(device_probe(serial="SWAPPED"))
    )
    drift = restore_plan_drift(approved, fresh)
    assert any("target serial changed" in reason for reason in drift)
    assert restore_plan_drift(approved, approved) == []


def test_a_target_that_became_mounted_is_drift(record: BackupRecord) -> None:
    approved = plan_restore(record, target_identity_from_probe(device_probe()))
    fresh = plan_restore(
        record, target_identity_from_probe(device_probe(mounted_at=["/media/usb"]))
    )
    assert any("/media/usb" in reason for reason in restore_plan_drift(approved, fresh))


def test_an_altered_plan_is_refused(record: BackupRecord) -> None:
    plan = plan_restore(record, target_identity_from_probe(device_probe()))
    forged = plan.model_copy(update={"write_length": 512})
    with pytest.raises(WorkflowGateRefused, match="altered"):
        require_executable(forged)


def test_planning_from_a_tampered_record_raises(record: BackupRecord) -> None:
    from core.errors import EvidenceIntegrityError

    forged = record.model_copy(update={"image_size_bytes": 512})
    with pytest.raises(EvidenceIntegrityError):
        plan_restore(forged, target_identity_from_probe(device_probe()))
