"""The platform-neutral whole-drive clear, over the Windows adapter double.

Every run here writes into a :class:`testkit.fake_windows.FakeDisk` byte
buffer through the same :class:`core.device.win.disk.WindowsDisk` handle the
Windows adapter uses. Nothing touches a real device.
"""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
from core.device.win.disk import WindowsDisk
from core.erase import blockclear
from core.erase.sink import ChainLedgerSink
from core.erase.verify import VerifyConfig
from core.errors import ConfirmationMismatch, DeviceVanished
from core.ledger.chain import Ledger
from core.models import Device, EraseResult, Progress
from testkit.fake_windows import FakeDisk, FakeWindowsApi

MIB = 1 << 20
SIZE = 2 * MIB


def _sink(tmp_path: Path) -> ChainLedgerSink:
    return ChainLedgerSink(
        Ledger(tmp_path / "ledger", tool_version="test", pubkey_fingerprint="AA")
    )


def _device(size: int = SIZE) -> Device:
    return Device(
        path="\\\\.\\PhysicalDrive2",
        model="FAKE Disk",
        serial="SER1",
        size_bytes=size,
        rotational=False,
        transport="usb",
        is_system_disk=False,
        mounted_at=[],
        pt_type=None,
    )


def _request(**over: Any) -> blockclear.ClearRequest:
    base: dict[str, Any] = {
        "job_id": "job-1",
        "device": _device(),
        "identity": {"serial": "SER1", "size_bytes": SIZE, "number": 2},
        "platform": "windows",
        "mechanism": "WriteFile to \\\\.\\PhysicalDriveN",
        "device_class": "usb-flash",
        "flash": True,
        "buffer_bytes": 256 * 1024,
        "checkpoint_bytes": 512 * 1024,
    }
    base.update(over)
    return blockclear.ClearRequest(**base)


def _opener(api: FakeWindowsApi, serial: str = "SER1", size: int = SIZE) -> Any:
    def open_target() -> WindowsDisk:
        disk = WindowsDisk(api, 2, write=True).open()
        disk.bind(serial=serial, size_bytes=size)
        return disk

    return open_target


def _drain(
    run: Generator[Progress, None, EraseResult],
) -> tuple[list[Progress], EraseResult]:
    seen: list[Progress] = []
    while True:
        try:
            seen.append(next(run))
        except StopIteration as stop:
            return seen, stop.value


def _ops(sink: ChainLedgerSink) -> list[str]:
    return [entry.operation for entry in sink.ledger.entries()]


def test_a_real_clear_overwrites_every_byte_and_verifies(tmp_path: Path) -> None:
    api = FakeWindowsApi([FakeDisk(number=2, size_bytes=SIZE, serial="SER1")])
    sink = _sink(tmp_path)
    progress, result = _drain(blockclear.clear(_request(), _opener(api), ledger=sink))
    data = api.disks[2].data
    assert bytes(data) == b"\xa5" * SIZE
    assert result.bytes_written == SIZE
    assert result.verification is not None and result.verification.passed
    assert result.verification.strategy == "full_read"
    assert result.achieved_level is not None and result.achieved_level.value == "CLEAR"
    assert result.residual_risk.purge_achieved is False
    assert "Not a Purge" in result.residual_risk.notes
    assert result.plan.fill_bytes == ["0xA5"]
    assert progress[-1].phase == "REPORT"
    ops = _ops(sink)
    assert "erase.preflight.plan" in ops
    assert "erase.erase.checkpoint" in ops
    assert "erase.verify.result" in ops


def test_the_clear_request_has_no_rehearsal_mode() -> None:
    """``clear`` always opens, writes and verifies; it cannot be told not to."""
    with pytest.raises(TypeError):
        _request(dry_run=True)


def test_a_swapped_disk_is_refused_before_the_first_write(tmp_path: Path) -> None:
    api = FakeWindowsApi([FakeDisk(number=2, size_bytes=SIZE, serial="OTHER")])
    before = bytes(api.disks[2].data)
    with pytest.raises(ConfirmationMismatch):
        _drain(blockclear.clear(_request(), _opener(api), ledger=_sink(tmp_path)))
    assert bytes(api.disks[2].data) == before
    assert api.disks[2].writes == 0


def test_bad_sectors_are_localised_recorded_and_fail_the_verdict(
    tmp_path: Path,
) -> None:
    disk = FakeDisk(number=2, size_bytes=SIZE, serial="SER1", bad_sectors={100, 101})
    api = FakeWindowsApi([disk])
    _, result = _drain(
        blockclear.clear(_request(), _opener(api), ledger=_sink(tmp_path))
    )
    assert [(r.offset, r.length) for r in result.unwritable_ranges] == [
        (100 * 512, 512),
        (101 * 512, 512),
    ]
    assert result.bytes_written == SIZE - 1024
    assert result.verification is not None and not result.verification.passed
    assert result.achieved_level is None
    assert result.residual_risk.level == "high"


def test_a_device_that_disappears_stops_the_run_and_ledgers_where(
    tmp_path: Path,
) -> None:
    disk = FakeDisk(number=2, size_bytes=SIZE, serial="SER1", vanish_after_writes=3)
    api = FakeWindowsApi([disk])
    sink = _sink(tmp_path)
    with pytest.raises(DeviceVanished):
        _drain(blockclear.clear(_request(), _opener(api), ledger=sink))
    assert "erase.erase.interrupted" in _ops(sink)
    params = sink.ledger.params_of(sink.ledger.entries()[-1])
    assert params["bytes_written"] == 3 * 256 * 1024


def test_cancelling_ledgers_a_partial_clear(tmp_path: Path) -> None:
    api = FakeWindowsApi([FakeDisk(number=2, size_bytes=SIZE, serial="SER1")])
    sink = _sink(tmp_path)
    run = blockclear.clear(_request(), _opener(api), ledger=sink)
    for _ in range(4):
        next(run)
    run.close()
    assert "erase.erase.cancelled" in _ops(sink)
    params = sink.ledger.params_of(sink.ledger.entries()[-1])
    assert "PARTIALLY CLEARED" in params["state"]


def test_resume_continues_from_the_last_checkpoint(tmp_path: Path) -> None:
    api = FakeWindowsApi([FakeDisk(number=2, size_bytes=SIZE, serial="SER1")])
    sink = _sink(tmp_path)
    run = blockclear.clear(_request(), _opener(api), ledger=sink)
    for _ in range(4):
        next(run)
    run.close()
    checkpoint = sink.last_checkpoint("job-1")
    assert checkpoint is not None and checkpoint.offset == 512 * 1024
    writes_before = api.disks[2].writes
    _, result = _drain(
        blockclear.clear(_request(resume_from=checkpoint), _opener(api), ledger=sink)
    )
    assert bytes(api.disks[2].data) == b"\xa5" * SIZE
    assert result.verification is not None and result.verification.passed
    assert api.disks[2].writes - writes_before == (SIZE - 512 * 1024) // (256 * 1024)


def test_a_sampled_verification_states_its_probability(tmp_path: Path) -> None:
    api = FakeWindowsApi([FakeDisk(number=2, size_bytes=SIZE, serial="SER1")])
    config = VerifyConfig(
        full_read_max_bytes=MIB,
        edge_bytes=64 * 1024,
        sample_count=16,
        sample_bytes=4096,
        read_chunk=64 * 1024,
    )
    _, result = _drain(
        blockclear.clear(_request(verify=config), _opener(api), ledger=_sink(tmp_path))
    )
    verification = result.verification
    assert verification is not None and verification.strategy == "sampled"
    assert verification.sample_seed == config.seed
    assert "not a guarantee" in verification.probability_note
    assert verification.confidence_bp < 10_000


def test_a_hdd_is_cleared_with_zeros(tmp_path: Path) -> None:
    api = FakeWindowsApi([FakeDisk(number=2, size_bytes=SIZE, serial="SER1")])
    _, result = _drain(
        blockclear.clear(_request(flash=False), _opener(api), ledger=_sink(tmp_path))
    )
    assert bytes(api.disks[2].data) == bytes(SIZE)
    assert result.plan.fill_bytes == ["0x00"]


def test_the_plan_digest_changes_with_the_identity() -> None:
    first = blockclear.plan_digest(_request(), (0xA5,))
    second = blockclear.plan_digest(
        _request(identity={"serial": "SER2", "size_bytes": SIZE, "number": 2}), (0xA5,)
    )
    assert first != second
