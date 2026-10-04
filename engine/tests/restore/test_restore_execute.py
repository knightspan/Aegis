"""Restore execution over a file-backed write seam, and post-restore verification."""

from __future__ import annotations

import errno
from pathlib import Path

import pytest
from core.backup import BackupRecord
from core.errors import EvidenceIntegrityError, OverwriteIncomplete, WorkflowGateRefused
from core.ledger.chain import Ledger
from core.restore import (
    BlockTarget,
    FileBlockTarget,
    RestorePlan,
    execute_restore,
    file_target_identity,
    plan_restore,
    verify_restored,
)

from .conftest import (
    CHUNK,
    IMAGE_SIZE,
    TARGET_SIZE,
    drain,
    image_bytes,
    operations,
    params_for,
)

FILL = b"\xaa"


@pytest.fixture
def target_path(tmp_path: Path) -> Path:
    path = tmp_path / "target.img"
    path.write_bytes(FILL * TARGET_SIZE)
    return path


@pytest.fixture
def plan(record: BackupRecord, target_path: Path) -> RestorePlan:
    return plan_restore(record, file_target_identity(target_path))


class Recording(FileBlockTarget):
    """A file target that counts calls and can misbehave on request."""

    def __init__(self, path: Path, **kw: object) -> None:
        super().__init__(path)
        self.writes: list[tuple[int, int]] = []
        self.flushes = 0
        self.max_write: int | None = kw.get("max_write")  # type: ignore[assignment]
        self.bad_sector: int | None = kw.get("bad_sector")  # type: ignore[assignment]
        self.zero_at: int | None = kw.get("zero_at")  # type: ignore[assignment]
        self.lie_on_read = bool(kw.get("lie_on_read"))

    def write_at(self, offset: int, data: bytes) -> int:
        self.writes.append((offset, len(data)))
        if self.zero_at is not None and offset >= self.zero_at:
            return 0
        if self.bad_sector is not None and offset <= self.bad_sector < offset + len(
            data
        ):
            if len(data) > self.logical_sector or offset == self.bad_sector:
                raise OSError(5, "Input/output error")
        if self.max_write is not None:
            data = data[: self.max_write]
        return super().write_at(offset, data)

    def read_at(self, offset: int, length: int) -> bytes:
        data = super().read_at(offset, length)
        if self.lie_on_read and offset == 0:
            return bytes([data[0] ^ 0xFF]) + data[1:]
        return data

    def flush(self) -> None:
        self.flushes += 1
        super().flush()


class Refusing(Recording):
    """A file target whose writes fail with EIO inside chosen byte ranges."""

    def __init__(self, path: Path, refuse: list[tuple[int, int]]) -> None:
        super().__init__(path)
        self.refuse = refuse

    def write_at(self, offset: int, data: bytes) -> int:
        end = offset + len(data)
        if any(offset < stop and start < end for start, stop in self.refuse):
            self.writes.append((offset, len(data)))
            raise OSError(errno.EIO, "Input/output error")
        return super().write_at(offset, data)


def _run(
    record: BackupRecord,
    plan: RestorePlan,
    target: BlockTarget | None,
    ledger: Ledger | None = None,
    **kw: object,
) -> object:
    _, result = drain(
        execute_restore(record, plan, target, job_id="r1", ledger=ledger, **kw)  # type: ignore[arg-type]
    )
    return result


def test_the_engine_has_no_non_writing_mode(
    record: BackupRecord, plan: RestorePlan, target_path: Path, ledger: Ledger
) -> None:
    """A rehearsal flag is not a parameter any more; it cannot be passed."""
    target = Recording(target_path)
    with pytest.raises(TypeError):
        drain(
            execute_restore(  # type: ignore[call-arg]
                record, plan, target, job_id="r1", ledger=ledger, dry_run=True
            )
        )
    target.close()
    assert target.writes == []
    assert "restore.dry_run" not in operations(ledger)


def test_a_real_restore_writes_the_image_and_verifies_it(
    record: BackupRecord, plan: RestorePlan, target_path: Path, ledger: Ledger
) -> None:
    target = Recording(target_path)
    progress, result = drain(
        execute_restore(
            record, plan, target, job_id="r1", ledger=ledger,
            checkpoint_bytes=CHUNK,
        )
    )
    target.close()
    written = target_path.read_bytes()
    assert written[:IMAGE_SIZE] == image_bytes()
    assert written[IMAGE_SIZE:] == FILL * (TARGET_SIZE - IMAGE_SIZE)
    assert result.result == "RESTORED_VERIFIED"
    assert result.bytes_written == result.bytes_planned == IMAGE_SIZE
    assert result.unwritable == ()
    assert result.verification is not None and result.verification.passed
    assert result.verification_sha256 == record.image_sha256
    assert result.source == record.source and result.target == plan.target
    for offset, length in target.writes:
        assert offset % 512 == 0 and length % 512 == 0
    assert {p.phase for p in progress} >= {"RESTORE", "VERIFY"}
    ops = [op for op in operations(ledger) if op.startswith("restore.")]
    assert ops[0] == "restore.start"
    assert ops.count("restore.checkpoint") >= 3
    assert ops[-2:] == ["restore.complete", "restore.verify"]


def test_short_writes_are_continued_to_an_exact_total(
    record: BackupRecord, plan: RestorePlan, target_path: Path
) -> None:
    target = Recording(target_path, max_write=1000)
    result = _run(record, plan, target)
    target.close()
    assert result.result == "RESTORED_VERIFIED"  # type: ignore[attr-defined]
    assert target_path.read_bytes()[:IMAGE_SIZE] == image_bytes()


def test_unwritable_sectors_are_accounted_and_the_result_is_incomplete(
    record: BackupRecord, plan: RestorePlan, target_path: Path, ledger: Ledger
) -> None:
    bad = CHUNK + 4096
    target = Recording(target_path, bad_sector=bad)
    result = _run(record, plan, target, ledger)
    target.close()
    assert result.result == "INCOMPLETE"  # type: ignore[attr-defined]
    spans = result.unwritable  # type: ignore[attr-defined]
    assert [(s.offset, s.length) for s in spans] == [(bad, 512)]
    assert result.bytes_written + 512 == result.bytes_planned  # type: ignore[attr-defined]
    assert not result.verification.passed  # type: ignore[attr-defined]
    complete = params_for(ledger, "restore.complete")[0]
    assert complete["bytes_unwritable"] == 512


def test_a_write_that_makes_no_progress_raises_and_is_ledgered(
    record: BackupRecord, plan: RestorePlan, target_path: Path, ledger: Ledger
) -> None:
    target = Recording(target_path, zero_at=CHUNK)
    with pytest.raises(OverwriteIncomplete):
        _run(record, plan, target, ledger)
    target.close()
    aborted = params_for(ledger, "restore.aborted")
    assert aborted and aborted[0]["range_written"] == [0, CHUNK]


def test_cancellation_ledgers_the_byte_range_written(
    record: BackupRecord, plan: RestorePlan, target_path: Path, ledger: Ledger
) -> None:
    target = Recording(target_path)
    generator = execute_restore(
        record, plan, target, job_id="r1", ledger=ledger
    )
    next(generator)  # the start record
    next(generator)  # chunk 0 written
    next(generator)  # chunk 1 written
    generator.close()
    target.close()
    cancelled = params_for(ledger, "restore.cancelled")
    assert len(cancelled) == 1
    entry = cancelled[0]
    assert entry["range_written"] == [0, 2 * CHUNK]
    assert entry["bytes_written"] == 2 * CHUNK
    assert "PARTIALLY OVERWRITTEN" in entry["note"]
    data = target_path.read_bytes()
    assert data[: 2 * CHUNK] == image_bytes()[: 2 * CHUNK]
    assert data[2 * CHUNK :] == FILL * (TARGET_SIZE - 2 * CHUNK)
    assert "restore.complete" not in operations(ledger)


def test_an_image_changed_after_recording_stops_before_the_bad_chunk(
    record: BackupRecord, plan: RestorePlan, target_path: Path, ledger: Ledger
) -> None:
    image = Path(record.image_path)
    data = bytearray(image.read_bytes())
    data[CHUNK + 10] ^= 0xFF
    image.write_bytes(bytes(data))
    target = Recording(target_path)
    with pytest.raises(EvidenceIntegrityError, match="chunk 1"):
        _run(record, plan, target, ledger)
    target.close()
    after = target_path.read_bytes()
    assert after[:CHUNK] == image_bytes()[:CHUNK]
    assert after[CHUNK:] == FILL * (TARGET_SIZE - CHUNK)
    assert params_for(ledger, "restore.aborted")[0]["range_written"] == [0, CHUNK]


def test_a_target_whose_size_differs_from_the_plan_is_refused(
    record: BackupRecord, plan: RestorePlan, tmp_path: Path
) -> None:
    other = FileBlockTarget.create(tmp_path / "other.img", TARGET_SIZE + 4096)
    with pytest.raises(WorkflowGateRefused, match="Nothing was written"):
        _run(record, plan, other)
    other.close()
    assert (tmp_path / "other.img").read_bytes() == b"\0" * (TARGET_SIZE + 4096)


def test_a_run_without_a_target_is_refused(
    record: BackupRecord, plan: RestorePlan
) -> None:
    with pytest.raises(WorkflowGateRefused):
        _run(record, plan, None)


def test_post_restore_verification_fails_on_a_lying_target(
    record: BackupRecord, plan: RestorePlan, target_path: Path, ledger: Ledger
) -> None:
    target = Recording(target_path, lie_on_read=True)
    result = _run(record, plan, target, ledger)
    target.close()
    assert result.result == "RESTORED_VERIFY_FAILED"  # type: ignore[attr-defined]
    verification = result.verification  # type: ignore[attr-defined]
    assert verification.first_mismatch.index == 0
    assert verification.actual_sha256 != record.image_sha256
    assert params_for(ledger, "restore.verify")[0]["verification"]["passed"] is False


def test_post_restore_verification_names_a_later_corruption(
    record: BackupRecord, plan: RestorePlan, target_path: Path
) -> None:
    target = FileBlockTarget(target_path)
    _run(record, plan, target)
    target.write_at(3 * CHUNK + 1, b"\x00")
    _, verification = drain(verify_restored(record, plan, target))
    target.close()
    assert not verification.passed
    assert verification.mismatched_chunks == (3,)
    assert verification.first_mismatch is not None
    assert verification.first_mismatch.offset == 3 * CHUNK


def test_post_restore_verification_passes_on_an_exact_copy(
    record: BackupRecord, plan: RestorePlan, target_path: Path
) -> None:
    target = FileBlockTarget(target_path)
    _run(record, plan, target, verify=False)
    _, verification = drain(verify_restored(record, plan, target))
    target.close()
    assert verification.passed
    assert verification.actual_sha256 == record.image_sha256
    assert verification.bytes_verified == IMAGE_SIZE


def test_a_target_that_refuses_every_write_stops_early_and_says_why(
    record: BackupRecord, plan: RestorePlan, target_path: Path, ledger: Ledger
) -> None:
    """The 2026-09-29 freeze: 7 GiB of refused sectors, one object each, no stop."""
    target = Refusing(target_path, refuse=[(0, TARGET_SIZE)])
    limit = 16 * 1024
    with pytest.raises(OverwriteIncomplete, match="EIO") as raised:
        _run(record, plan, target, ledger, max_consecutive_unwritable=limit)
    target.close()
    assert "Input/output error" in str(raised.value)
    assert target_path.read_bytes() == FILL * TARGET_SIZE
    # The chunk write, then sectors until the limit is passed - not the image.
    assert len(target.writes) <= 1 + limit // 512 + 1
    aborted = params_for(ledger, "restore.aborted")
    assert len(aborted) == 1
    entry = aborted[0]
    assert entry["bytes_written"] == 0
    assert limit < entry["bytes_unwritable"] <= limit + 512
    assert "EIO" in entry["reason"]
    assert "Nothing was written" in entry["note"]
    assert "PARTIALLY OVERWRITTEN" not in entry["note"]
    assert "restore.complete" not in operations(ledger)


def test_a_contiguous_bad_run_is_one_span_carrying_the_errno_name(
    record: BackupRecord, plan: RestorePlan, target_path: Path, ledger: Ledger
) -> None:
    start = CHUNK + 4096
    target = Refusing(target_path, refuse=[(start, start + 8 * 512)])
    result = _run(record, plan, target, ledger)
    target.close()
    assert result.result == "INCOMPLETE"  # type: ignore[attr-defined]
    spans = result.unwritable  # type: ignore[attr-defined]
    assert [(s.offset, s.length, s.error) for s in spans] == [(start, 8 * 512, "EIO")]
    assert result.unwritable_omitted_bytes == 0  # type: ignore[attr-defined]
    assert result.bytes_written + 8 * 512 == result.bytes_planned  # type: ignore[attr-defined]


def test_scattered_bad_sectors_are_capped_but_every_byte_is_counted(
    record: BackupRecord, plan: RestorePlan, target_path: Path, ledger: Ledger
) -> None:
    bad = [(CHUNK + i * 1024, CHUNK + i * 1024 + 512) for i in range(10)]
    target = Refusing(target_path, refuse=bad)
    result = _run(record, plan, target, ledger, max_recorded_spans=4)
    target.close()
    spans = result.unwritable  # type: ignore[attr-defined]
    assert [s.offset for s in spans] == [start for start, _ in bad[:4]]
    assert result.unwritable_omitted_bytes == 6 * 512  # type: ignore[attr-defined]
    assert result.bytes_written + 10 * 512 == result.bytes_planned  # type: ignore[attr-defined]
    complete = params_for(ledger, "restore.complete")[0]
    assert complete["bytes_unwritable"] == 10 * 512
    assert complete["unwritable_omitted_bytes"] == 6 * 512
    assert len(complete["unwritable"]) == 4
