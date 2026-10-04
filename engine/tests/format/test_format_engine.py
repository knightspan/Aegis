"""The format engine: plan, run and read back one filesystem on an erased device.

No real device is touched. The engine takes a command runner and an existence
check, so every test drives it with a recording fake.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from typing import Any

import pytest
from core.errors import FormatFailed, PlatformUnsupported
from core.format import (
    CommandResult,
    FormatPlan,
    FormatResult,
    execute_format,
    partition_path,
    plan_digest_of,
    plan_format,
)
from core.models import Device, Progress


def _device(**over: Any) -> Device:
    base: dict[str, Any] = {
        "path": "/dev/sdz",
        "model": "TransMemory",
        "serial": "SER123",
        "size_bytes": 7_759_462_400,
        "rotational": False,
        "transport": "usb",
        "is_system_disk": False,
        "mounted_at": [],
        "pt_type": None,
    }
    base.update(over)
    return Device(**base)


class _Runner:
    """Records every command and answers from a script keyed by program name."""

    def __init__(self, fstype: str = "exfat", label: str = "USB") -> None:
        self.calls: list[tuple[list[str], str | None]] = []
        self.fail: dict[str, CommandResult] = {}
        self.fstype = fstype
        self.label = label

    def __call__(self, argv: list[str], stdin: str | None = None) -> CommandResult:
        self.calls.append((argv, stdin))
        program = argv[0]
        if program in self.fail:
            return self.fail[program]
        if program == "blkid" and "TYPE" in argv:
            return CommandResult(0, self.fstype + "\n", "")
        if program == "blkid" and "LABEL" in argv:
            return CommandResult(0, self.label + "\n", "")
        return CommandResult(0, "", "")

    def programs(self) -> list[str]:
        return [argv[0] for argv, _ in self.calls]


class _Ledger:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def append(self, **entry: Any) -> None:
        self.entries.append(entry)


def _run(
    plan: FormatPlan,
    runner: Callable[..., CommandResult],
    ledger: _Ledger | None = None,
    device: Device | None = None,
    **over: Any,
) -> tuple[list[Progress], FormatResult]:
    generator = execute_format(
        plan,
        device or _device(),
        runner=runner,
        exists=lambda _path: True,
        ledger=ledger,
        actor="tester",
        job_id="format-1",
        authorization_id="auth-0123456789abcdef",
        platform="linux",
        **over,
    )
    records: list[Progress] = []
    while True:
        try:
            records.append(next(generator))
        except StopIteration as stop:
            return records, stop.value


def test_plan_is_digested_and_carries_the_device_identity() -> None:
    plan = plan_format(_device(), "exfat", "USB")
    assert plan.blocking == []
    assert plan.plan_digest == plan_digest_of(plan)
    assert (plan.path, plan.serial, plan.size_bytes) == (
        "/dev/sdz",
        "SER123",
        7_759_462_400,
    )


def test_plan_digest_changes_when_the_filesystem_changes() -> None:
    a = plan_format(_device(), "exfat", "USB")
    b = plan_format(_device(), "ext4", "USB")
    assert a.plan_digest != b.plan_digest


@pytest.mark.parametrize(
    ("device", "fragment"),
    [
        (_device(is_system_disk=True), "hosts the running system"),
        (_device(mounted_at=["/run/media/x/USB"]), "mounted"),
        (_device(serial=""), "serial"),
    ],
)
def test_plan_blocks_a_device_that_may_not_be_formatted(
    device: Device, fragment: str
) -> None:
    plan = plan_format(device, "exfat", "USB")
    assert any(fragment in reason for reason in plan.blocking), plan.blocking


@pytest.mark.parametrize(
    ("filesystem", "label"),
    [
        ("ntfs", "USB"),
        ("exfat", "A" * 16),
        ("fat32", "A" * 12),
        ("ext4", "A" * 17),
        ("exfat", "bad/label"),
    ],
)
def test_plan_blocks_an_unsupported_filesystem_or_label(
    filesystem: str, label: str
) -> None:
    assert plan_format(_device(), filesystem, label).blocking


@pytest.mark.parametrize(
    ("path", "partition"),
    [
        ("/dev/sdz", "/dev/sdz1"),
        ("/dev/nvme0n1", "/dev/nvme0n1p1"),
        ("/dev/mmcblk0", "/dev/mmcblk0p1"),
    ],
)
def test_partition_path_follows_the_kernel_naming(path: str, partition: str) -> None:
    assert partition_path(path) == partition


def test_a_blocked_plan_is_never_executed() -> None:
    runner = _Runner()
    plan = plan_format(_device(mounted_at=["/mnt/x"]), "exfat", "USB")
    with pytest.raises(FormatFailed):
        _run(plan, runner)
    assert runner.calls == []


def test_runs_wipe_partition_settle_mkfs_then_reads_back() -> None:
    runner = _Runner(fstype="exfat", label="USB")
    plan = plan_format(_device(), "exfat", "USB")
    records, result = _run(plan, runner)
    assert runner.programs() == [
        "wipefs",
        "sfdisk",
        "udevadm",
        "mkfs.exfat",
        "blkid",
        "blkid",
    ]
    assert result.verified is True
    assert (result.partition_path, result.observed_fstype) == ("/dev/sdz1", "exfat")
    assert records[-1].pct_bp == 10_000


def test_the_partition_table_is_msdos_with_one_partition_spanning_the_device() -> None:
    runner = _Runner()
    _run(plan_format(_device(), "exfat", "USB"), runner)
    argv, stdin = next(c for c in runner.calls if c[0][0] == "sfdisk")
    assert argv == ["sfdisk", "--wipe", "always", "/dev/sdz"]
    assert stdin == "label: dos\n,,7\n"


@pytest.mark.parametrize(
    ("filesystem", "mkfs"),
    [
        ("exfat", ["mkfs.exfat", "-L", "USB", "/dev/sdz1"]),
        ("fat32", ["mkfs.vfat", "-F", "32", "-n", "USB", "/dev/sdz1"]),
        (
            "ext4",
            ["mkfs.ext4", "-F", "-L", "USB", "-E", "root_owner=1000:1000", "/dev/sdz1"],
        ),
    ],
)
def test_each_filesystem_uses_its_own_mkfs(filesystem: str, mkfs: list[str]) -> None:
    fstype = {"exfat": "exfat", "fat32": "vfat", "ext4": "ext4"}[filesystem]
    runner = _Runner(fstype=fstype)
    _run(plan_format(_device(), filesystem, "USB"), runner, owner_uid=1000)
    assert mkfs in [argv for argv, _ in runner.calls]


def test_a_read_back_that_finds_another_filesystem_is_not_verified() -> None:
    runner = _Runner(fstype="ntfs")
    _, result = _run(plan_format(_device(), "exfat", "USB"), runner)
    assert result.verified is False
    assert any("read-back" in text for text in result.limitations)


def test_a_failing_step_stops_the_run_and_is_ledgered() -> None:
    runner = _Runner()
    runner.fail["mkfs.exfat"] = CommandResult(1, "", "mkfs: no space")
    ledger = _Ledger()
    with pytest.raises(FormatFailed, match="mkfs.exfat"):
        _run(plan_format(_device(), "exfat", "USB"), runner, ledger)
    assert "blkid" not in runner.programs()
    assert [e["operation"] for e in ledger.entries] == ["format.begin", "format.failed"]


def test_success_is_ledgered_begin_then_complete_with_ints_only() -> None:
    ledger = _Ledger()
    _run(plan_format(_device(), "exfat", "USB"), _Runner(), ledger)
    assert [e["operation"] for e in ledger.entries] == [
        "format.begin",
        "format.complete",
    ]
    begin = ledger.entries[0]["params"]
    assert begin["authorization_id"] == "auth-0123456789abcdef"
    assert begin["plan_digest"]
    assert not any(isinstance(v, float) for v in begin.values())


def test_begin_is_ledgered_before_the_first_write() -> None:
    order: list[str] = []
    ledger = _Ledger()
    ledger.append = lambda **e: order.append(e["operation"])  # type: ignore[method-assign]

    def runner(argv: list[str], stdin: str | None = None) -> CommandResult:
        order.append(argv[0])
        return CommandResult(0, "exfat\n" if "TYPE" in argv else "USB\n", "")

    _run(plan_format(_device(), "exfat", "USB"), runner, ledger)
    assert order[0] == "format.begin"
    assert order.index("format.begin") < order.index("wipefs")


def test_a_partition_that_never_appears_fails_before_mkfs() -> None:
    runner = _Runner()
    plan = plan_format(_device(), "exfat", "USB")
    generator = execute_format(
        plan,
        _device(),
        runner=runner,
        exists=lambda _p: False,
        ledger=None,
        actor="t",
        job_id="j",
        authorization_id="auth-0123456789abcdef",
        platform="linux",
        wait_seconds=0,
    )
    with pytest.raises(FormatFailed, match="partition"):
        list(generator)
    assert "mkfs.exfat" not in runner.programs()


@pytest.mark.parametrize("platform", ["windows", "darwin"])
def test_a_platform_without_a_format_backend_is_refused_before_any_command(
    platform: str,
) -> None:
    runner = _Runner()
    generator = execute_format(
        plan_format(_device(), "exfat", "USB"),
        _device(),
        runner=runner,
        exists=lambda _p: True,
        ledger=None,
        actor="t",
        job_id="j",
        authorization_id="auth-0123456789abcdef",
        platform=platform,
    )
    with pytest.raises(PlatformUnsupported):
        list(generator)
    assert runner.calls == []


def test_the_default_runner_never_uses_a_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    from core import format as fmt

    seen: dict[str, Any] = {}

    def fake_run(argv: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen.update(kwargs, argv=argv)
        return subprocess.CompletedProcess(argv, 0, "out", "err")

    monkeypatch.setattr(fmt.subprocess, "run", fake_run)
    result = fmt.run_command(["echo", "x"], None)
    assert result == CommandResult(0, "out", "err")
    assert seen["argv"] == ["echo", "x"]
    assert not seen.get("shell")
