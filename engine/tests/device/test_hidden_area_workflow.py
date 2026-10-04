"""The guarded HPA/DCO workflow: state machine, plan, backends, execution.

No real device is touched. The Windows backend is driven through
:class:`testkit.fake_windows.FakeWindowsApi`, which decodes the packed
``ATA_PASS_THROUGH_EX`` requests exactly as Windows would receive them; the
Linux backend through a fake :class:`core.device._sysio.SystemProbe` whose
runner answers ``hdparm`` from captured output and records every argv.
"""

from __future__ import annotations

from collections.abc import Generator
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from core.backup import SourceIdentity, create_backup_record, verify_backup
from core.device._sysio import CommandResult, SystemProbe
from core.device.hidden_area_workflow import (
    DCO_NEVER_MODIFIED,
    TRANSITIONS,
    HiddenAreaState,
    HpaFacts,
    HpaPlan,
    HpaResult,
    HpaState,
    IllegalTransition,
    LinuxHpaBackend,
    WindowsHpaBackend,
    advance,
    backup_problems,
    derive,
    execute,
    hidden_area_state,
    plan_digest_of,
    plan_hpa_change,
    platform_backend,
    plausibility_problem,
)
from core.errors import (
    ConfirmationMismatch,
    MountedRefused,
    PlatformUnsupported,
    SystemDiskRefused,
    UnsupportedCapability,
    WorkflowGateRefused,
)
from core.ledger.chain import ChainStatus, Ledger
from core.models import Device
from testkit.fake_windows import FakeAta, FakeDisk, FakeWindowsApi

from .conftest import FakeRunner, ok

S = HpaState
SECTOR = 512
NATIVE = 16383  # 8 MiB
ACCESSIBLE = 14335  # 7 MiB
HIDDEN = (NATIVE - ACCESSIBLE) * SECTOR
WIN_SERIAL = "WD-HPA-0001"
LINUX_SERIAL = "ATA-HPA-0002"
WIN_PATH = "\\\\.\\PhysicalDrive1"

CMD_READ_NATIVE_MAX = 0x27
CMD_SET_MAX = 0x37
CMD_DCO = 0xB1
DCO_IDENTIFY = 0xC2


def _clock() -> datetime:
    return datetime(2026, 9, 28, 12, 0, tzinfo=UTC)


def _ledger(tmp_path: Path) -> Ledger:
    return Ledger(
        tmp_path / "ledger", tool_version="0.0.0-test", pubkey_fingerprint="AA:BB"
    )


def _ops(ledger: Ledger) -> list[str]:
    return [
        entry.operation
        for entry in ledger.entries()
        if entry.operation.startswith("hpa.")
    ]


def _run(
    generator: Generator[dict[str, Any], None, HpaResult],
) -> tuple[list[dict[str, Any]], HpaResult]:
    progress: list[dict[str, Any]] = []
    while True:
        try:
            progress.append(next(generator))
        except StopIteration as stop:
            return progress, stop.value


# --------------------------------------------------------------------------
# Fixtures: a Windows drive with an HPA, and a Linux one
# --------------------------------------------------------------------------


def _win_device(**over: Any) -> Device:
    fields: dict[str, Any] = {
        "path": WIN_PATH,
        "model": "FAKE Disk",
        "serial": WIN_SERIAL,
        "size_bytes": (ACCESSIBLE + 1) * SECTOR,
        "rotational": True,
        "transport": "sata",
        "is_system_disk": False,
        "mounted_at": [],
        "pt_type": None,
    }
    fields.update(over)
    return Device(**fields)


@pytest.fixture
def ata() -> FakeAta:
    return FakeAta(
        model="FAKE HPA DRIVE",
        serial=WIN_SERIAL,
        native_max_lba=NATIVE,
        accessible_max_lba=ACCESSIBLE,
    )


@pytest.fixture
def disk(ata: FakeAta) -> FakeDisk:
    return FakeDisk(
        number=1,
        size_bytes=(NATIVE + 1) * SECTOR,
        serial=WIN_SERIAL,
        bus_type=11,  # SATA
        removable=False,
        ata=ata,
    )


@pytest.fixture
def api(disk: FakeDisk) -> FakeWindowsApi:
    return FakeWindowsApi([disk])


@pytest.fixture
def win(api: FakeWindowsApi) -> WindowsHpaBackend:
    return WindowsHpaBackend(api)


def _win_plan(win: WindowsHpaBackend, *, volatile: bool = True) -> HpaPlan:
    device = _win_device()
    return plan_hpa_change(
        device,
        win.discover(device),
        platform="windows",
        volatile=volatile,
        clock=_clock,
    )


class StatefulHdparm:
    """A runner answering ``hdparm`` like a drive with an HPA, and remembering sets."""

    def __init__(
        self,
        *,
        accessible: int = ACCESSIBLE + 1,
        native: int = NATIVE + 1,
        dco: int | None = NATIVE + 1,
        ignore_set: bool = False,
    ) -> None:
        self.accessible = accessible
        self.native = native
        self.dco = dco
        self.ignore_set = ignore_set
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: Any) -> CommandResult:
        key = tuple(argv)
        self.calls.append(key)
        if key[:2] == ("hdparm", "-N") and len(key) == 3:
            state = "enabled" if self.accessible < self.native else "disabled"
            return CommandResult(
                list(key),
                0,
                f"{key[2]}:\n max sectors   = {self.accessible}/{self.native}, "
                f"HPA is {state}\n",
                "",
            )
        if key[:2] == ("hdparm", "-N") and len(key) == 4:
            if not self.ignore_set:
                self.accessible = int(key[2].lstrip("p"))
            return CommandResult(list(key), 0, "setting max visible sectors\n", "")
        if key[:2] == ("hdparm", "--dco-identify"):
            if self.dco is None:
                return CommandResult(list(key), 5, "", "DCO not supported")
            return CommandResult(
                list(key),
                0,
                f"DCO Revision: 0x0002\n Real max sectors: {self.dco}\n",
                "",
            )
        return CommandResult(list(key), 127, "", "command not found")


def _linux_device(**over: Any) -> Device:
    fields: dict[str, Any] = {
        "path": "/dev/sdq",
        "model": "SYNTHETIC HPA",
        "serial": LINUX_SERIAL,
        "size_bytes": (ACCESSIBLE + 1) * SECTOR,
        "rotational": True,
        "transport": "sata",
        "is_system_disk": False,
        "mounted_at": [],
        "pt_type": None,
    }
    fields.update(over)
    return Device(**fields)


@pytest.fixture
def hdparm() -> StatefulHdparm:
    return StatefulHdparm()


@pytest.fixture
def linux(tmp_path: Path, hdparm: StatefulHdparm) -> LinuxHpaBackend:
    queue = tmp_path / "sys" / "block" / "sdq" / "queue"
    queue.mkdir(parents=True)
    (queue / "logical_block_size").write_text("512\n")
    return LinuxHpaBackend(SystemProbe(runner=hdparm, sysfs_root=tmp_path / "sys"))


# --------------------------------------------------------------------------
# State machine
# --------------------------------------------------------------------------

READY = HpaFacts(
    device_present=True,
    discovered=True,
    plausible=True,
    hidden_area_present=True,
    backup_verified=True,
    plan_generated=True,
    human_approved=True,
)


@pytest.mark.parametrize(
    ("facts", "expected"),
    [
        (HpaFacts(), S.BLOCKED),
        (HpaFacts(device_present=True), S.DISCOVERED),
        (replace(READY, device_refusal="mounted"), S.BLOCKED),
        (replace(READY, discovery_refusal="usb bridge"), S.BLOCKED),
        (replace(READY, plausible=False, plausibility_reason="nope"), S.BLOCKED),
        (replace(READY, hidden_area_present=False), S.BLOCKED),
        (replace(READY, backup_verified=False), S.ANALYZED),
        (replace(READY, plan_generated=False), S.BACKUP_VERIFIED),
        (replace(READY, plan_blocking=("stale",)), S.BLOCKED),
        (replace(READY, human_approved=False), S.APPROVAL_REQUIRED),
        (READY, S.PLAN_READY),
        (replace(READY, modifying=True), S.MODIFYING),
        (replace(READY, verifying=True), S.VERIFYING),
        (replace(READY, complete=True), S.COMPLETE),
        (replace(READY, failed="boom"), S.FAILED),
    ],
)
def test_derive_names_the_earliest_unmet_gate(
    facts: HpaFacts, expected: HpaState
) -> None:
    assert derive(facts).state is expected


def test_every_blocked_or_waiting_state_says_why_and_what_next() -> None:
    for facts in (
        HpaFacts(),
        replace(READY, device_refusal="the device is mounted"),
        replace(READY, plausible=False),
        replace(READY, hidden_area_present=False),
        replace(READY, backup_verified=False),
        replace(READY, plan_blocking=("stale plan",)),
        replace(READY, human_approved=False),
    ):
        status = derive(facts)
        assert status.why_blocked, status
        assert status.next_action
        assert status.as_dict()["allowed_next"] == sorted(
            state.value for state in TRANSITIONS[status.state]
        )


def test_the_earliest_gate_wins_over_later_ones() -> None:
    facts = replace(
        READY, device_refusal="mounted", backup_verified=False, human_approved=False
    )
    assert derive(facts).why_blocked == ("mounted",)


def test_blocked_is_reachable_from_every_pre_execution_state_and_failed_is_not() -> (
    None
):
    pre = [
        S.DISCOVERED,
        S.ANALYZED,
        S.BACKUP_VERIFIED,
        S.APPROVAL_REQUIRED,
        S.PLAN_READY,
    ]
    for state in pre:
        assert S.BLOCKED in TRANSITIONS[state]
        assert S.FAILED not in TRANSITIONS[state]
    for state in (S.MODIFYING, S.VERIFYING):
        assert S.FAILED in TRANSITIONS[state]
        assert S.BLOCKED not in TRANSITIONS[state]
    assert TRANSITIONS[S.COMPLETE] == frozenset()
    assert TRANSITIONS[S.FAILED] == frozenset()


def test_the_happy_path_advances_edge_by_edge() -> None:
    state = S.DISCOVERED
    for target in (S.ANALYZED, S.BACKUP_VERIFIED, S.APPROVAL_REQUIRED, S.PLAN_READY):
        state = advance(state, target, READY)
    state = advance(state, S.MODIFYING, READY)
    state = advance(state, S.VERIFYING, replace(READY, verifying=True))
    assert advance(state, S.COMPLETE, replace(READY, complete=True)) is S.COMPLETE


def test_a_missing_edge_is_refused() -> None:
    with pytest.raises(IllegalTransition, match="not a legal transition"):
        advance(S.DISCOVERED, S.MODIFYING, READY)
    with pytest.raises(IllegalTransition):
        advance(S.ANALYZED, S.PLAN_READY, READY)
    with pytest.raises(IllegalTransition):
        advance(S.PLAN_READY, S.FAILED, READY)


def test_modifying_is_refused_without_an_approval() -> None:
    unapproved = replace(READY, human_approved=False)
    with pytest.raises(IllegalTransition, match="APPROVAL_REQUIRED"):
        advance(S.PLAN_READY, S.MODIFYING, unapproved)


def test_a_step_the_facts_do_not_support_is_refused() -> None:
    no_backup = replace(READY, backup_verified=False)
    with pytest.raises(IllegalTransition, match="ANALYZED"):
        advance(S.ANALYZED, S.BACKUP_VERIFIED, no_backup)


def test_blocked_is_always_allowed_and_leads_only_back_to_discovery() -> None:
    assert advance(S.PLAN_READY, S.BLOCKED, READY) is S.BLOCKED
    assert TRANSITIONS[S.BLOCKED] == frozenset({S.DISCOVERED})
    with pytest.raises(IllegalTransition):
        advance(S.BLOCKED, S.DISCOVERED, HpaFacts())


# --------------------------------------------------------------------------
# Plausibility
# --------------------------------------------------------------------------


def test_a_native_max_below_the_accessible_max_is_rejected() -> None:
    reason = plausibility_problem(
        native_max_lba=ACCESSIBLE - 1,
        accessible_max_lba=ACCESSIBLE,
        reported_capacity_bytes=(ACCESSIBLE + 1) * SECTOR,
        sector_bytes=SECTOR,
    )
    assert reason is not None and "not larger than" in reason


def test_a_native_max_more_than_ten_times_the_os_size_is_rejected() -> None:
    state = hidden_area_state(
        path="/dev/sdq",
        native_max_lba=(ACCESSIBLE + 1) * 11,
        accessible_max_lba=ACCESSIBLE,
        sector_bytes=SECTOR,
        reported_capacity_bytes=(ACCESSIBLE + 1) * SECTOR,
        hpa_supported=True,
        dco_supported=False,
        dco_max_lba=None,
        source_commands=("test",),
    )
    assert not state.plausible
    assert "10x" in state.plausibility_reason
    assert state.hidden_bytes == 0, "an unbelievable reading measures nothing"
    plan = plan_hpa_change(_linux_device(), state, platform="linux", clock=_clock)
    assert plan.blocking


def test_a_zero_reading_is_rejected() -> None:
    assert plausibility_problem(
        native_max_lba=0,
        accessible_max_lba=0,
        reported_capacity_bytes=1,
        sector_bytes=SECTOR,
    )


def test_no_hpa_is_a_believable_reading_that_the_plan_refuses() -> None:
    state = hidden_area_state(
        path="/dev/sdq",
        native_max_lba=ACCESSIBLE,
        accessible_max_lba=ACCESSIBLE,
        sector_bytes=SECTOR,
        reported_capacity_bytes=(ACCESSIBLE + 1) * SECTOR,
        hpa_supported=True,
        dco_supported=False,
        dco_max_lba=None,
        source_commands=("test",),
    )
    assert state.plausible and state.hidden_bytes == 0
    plan = plan_hpa_change(_linux_device(), state, platform="linux", clock=_clock)
    assert any("not larger than" in reason for reason in plan.blocking)


# --------------------------------------------------------------------------
# The plan
# --------------------------------------------------------------------------


def test_the_plan_is_volatile_by_default(win: WindowsHpaBackend) -> None:
    plan = _win_plan(win)
    assert plan.volatile is True
    assert "VV=1" in plan.operation
    assert plan.operation.startswith(f"SET MAX ADDRESS EXT (37h) LBA={NATIVE} VV=1")
    assert "IOCTL_ATA_PASS_THROUGH" in plan.operation
    assert any(note.startswith("VOLATILE") for note in plan.limitations)


def test_a_permanent_change_is_planned_only_when_asked(win: WindowsHpaBackend) -> None:
    plan = _win_plan(win, volatile=False)
    assert plan.volatile is False
    assert "VV=0" in plan.operation
    assert any(note.startswith("PERMANENT") for note in plan.limitations)


def test_the_linux_operation_text_is_the_exact_hdparm_command(
    linux: LinuxHpaBackend,
) -> None:
    device = _linux_device()
    state = linux.discover(device)
    volatile = plan_hpa_change(device, state, platform="linux", clock=_clock)
    permanent = plan_hpa_change(
        device, state, platform="linux", volatile=False, clock=_clock
    )
    assert volatile.operation == f"hdparm -N {NATIVE + 1} /dev/sdq"
    assert permanent.operation == f"hdparm -N p{NATIVE + 1} /dev/sdq"


def test_the_plan_records_identity_originals_and_a_digest(
    win: WindowsHpaBackend,
) -> None:
    plan = _win_plan(win)
    assert plan.device.serial == WIN_SERIAL
    assert plan.original_native_max_lba == NATIVE
    assert plan.original_accessible_max_lba == ACCESSIBLE
    assert plan.requested_accessible_max_lba == NATIVE
    assert plan.hidden_bytes == HIDDEN
    assert plan.blocking == ()
    assert plan.plan_digest == plan_digest_of(plan)
    tampered = plan.model_copy(update={"requested_accessible_max_lba": NATIVE + 5})
    assert tampered.plan_digest != plan_digest_of(tampered)


def test_the_plan_says_the_dco_is_never_modified(win: WindowsHpaBackend) -> None:
    plan = _win_plan(win)
    assert "never issued" in plan.dco_action
    assert DCO_NEVER_MODIFIED in plan.limitations


@pytest.mark.parametrize(
    ("override", "fragment"),
    [
        ({"mounted_at": ["/mnt/x"]}, "mounted"),
        ({"is_system_disk": True}, "running system"),
        ({"serial": ""}, "no serial"),
        ({"transport": "usb"}, "bridge"),
    ],
)
def test_the_plan_blocks_what_must_not_be_changed(
    win: WindowsHpaBackend, override: dict[str, Any], fragment: str
) -> None:
    state = win.discover(_win_device())
    plan = plan_hpa_change(
        _win_device(**override), state, platform="windows", clock=_clock
    )
    assert any(fragment in reason for reason in plan.blocking)


# --------------------------------------------------------------------------
# Windows backend
# --------------------------------------------------------------------------


def test_windows_discovery_reads_the_maxima_and_changes_nothing(
    win: WindowsHpaBackend, ata: FakeAta
) -> None:
    state = win.discover(_win_device())
    assert state.native_max_lba == NATIVE
    assert state.accessible_max_lba == ACCESSIBLE
    assert state.hidden_bytes == HIDDEN
    assert state.dco_max_lba == NATIVE
    assert state.plausible and state.hpa_supported and state.dco_supported
    assert "READ NATIVE MAX ADDRESS EXT (27h)" in state.source_commands
    assert ata.set_max_calls == []
    assert CMD_SET_MAX not in {command for command, _ in ata.commands}


def test_a_dco_hiding_more_than_the_hpa_is_reported_not_touched(
    api: FakeWindowsApi, ata: FakeAta
) -> None:
    ata.dco_max_lba = NATIVE + 2048
    state = WindowsHpaBackend(api).discover(_win_device())
    assert state.dco_hidden_bytes == 2048 * SECTOR
    assert any(DCO_NEVER_MODIFIED in note for note in state.limitations)


def test_windows_refuses_a_bridge_that_blocks_pass_through(
    disk: FakeDisk, api: FakeWindowsApi
) -> None:
    disk.bridge_blocks_ata = True
    with pytest.raises(UnsupportedCapability, match="did not pass ATA command"):
        WindowsHpaBackend(api).discover(_win_device())


def test_a_usb_transport_is_refused_before_anything_is_opened(
    api: FakeWindowsApi,
) -> None:
    with pytest.raises(UnsupportedCapability, match="bridge"):
        WindowsHpaBackend(api).discover(_win_device(transport="usb"))
    assert not [call for call in api.calls if call[0] == "open"]


def test_an_nvme_device_has_no_hpa(api: FakeWindowsApi) -> None:
    with pytest.raises(UnsupportedCapability, match="NVMe"):
        WindowsHpaBackend(api).discover(_win_device(transport="nvme"))


def test_windows_refuses_a_disk_that_is_not_the_planned_one(
    win: WindowsHpaBackend,
) -> None:
    with pytest.raises(ConfirmationMismatch):
        win.discover(_win_device(serial="SOMEONE-ELSE"))


def test_a_corrupt_identify_buffer_is_not_believed(
    api: FakeWindowsApi, ata: FakeAta
) -> None:
    ata.corrupt_checksum = True
    with pytest.raises(UnsupportedCapability, match="checksum"):
        WindowsHpaBackend(api).discover(_win_device())


# --------------------------------------------------------------------------
# Execution, Windows
# --------------------------------------------------------------------------


def test_a_real_windows_change_is_volatile_verified_and_ledgered(
    tmp_path: Path, win: WindowsHpaBackend, ata: FakeAta
) -> None:
    ledger = _ledger(tmp_path)
    plan = _win_plan(win)
    progress, result = _run(
        execute(
            plan,
            win,
            device=_win_device(),
            typed_serial=WIN_SERIAL,
            ledger=ledger,
        )
    )
    assert ata.set_max_calls == [(NATIVE, True)]
    assert ata.accessible_max_lba == NATIVE
    assert result.outcome == "COMPLETE"
    assert result.verification_passed
    assert result.device_modified == "yes"
    assert result.post_state is not None
    assert result.post_state.accessible_max_lba == NATIVE
    assert result.post_state.native_max_lba == NATIVE
    assert [item["phase"] for item in progress][-1] == S.COMPLETE.value
    assert _ops(ledger) == ["hpa.plan", "hpa.modify", "hpa.verify", "hpa.complete"]
    assert ledger.verify().status is ChainStatus.VALID


def test_read_native_max_immediately_precedes_set_max(
    win: WindowsHpaBackend, ata: FakeAta, tmp_path: Path
) -> None:
    plan = _win_plan(win)
    ata.commands.clear()
    _run(
        execute(
            plan,
            win,
            device=_win_device(),
            typed_serial=WIN_SERIAL,
            ledger=_ledger(tmp_path),
        )
    )
    opcodes = [command for command, _ in ata.commands]
    index = opcodes.index(CMD_SET_MAX)
    assert opcodes[index - 1] == CMD_READ_NATIVE_MAX
    assert opcodes.count(CMD_SET_MAX) == 1


def test_a_permanent_change_clears_the_volatile_bit_only_when_planned(
    win: WindowsHpaBackend, ata: FakeAta, tmp_path: Path
) -> None:
    plan = _win_plan(win, volatile=False)
    _run(
        execute(
            plan,
            win,
            device=_win_device(),
            typed_serial=WIN_SERIAL,
            ledger=_ledger(tmp_path),
        )
    )
    assert ata.set_max_calls == [(NATIVE, False)]


def test_the_dco_is_never_modified(
    win: WindowsHpaBackend, ata: FakeAta, tmp_path: Path
) -> None:
    plan = _win_plan(win)
    _run(
        execute(
            plan,
            win,
            device=_win_device(),
            typed_serial=WIN_SERIAL,
            ledger=_ledger(tmp_path),
        )
    )
    dco_features = {
        features for command, features in ata.commands if command == CMD_DCO
    }
    assert dco_features <= {DCO_IDENTIFY}, "only DEVICE CONFIGURATION IDENTIFY is sent"


def test_the_engine_has_no_non_writing_mode(
    win: WindowsHpaBackend, ata: FakeAta, tmp_path: Path
) -> None:
    """A rehearsal flag is not a parameter; the typed serial is required."""
    ledger = _ledger(tmp_path)
    plan = _win_plan(win)
    with pytest.raises(TypeError):
        _run(execute(plan, win, device=_win_device(), ledger=ledger))  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        _run(
            execute(  # type: ignore[call-arg]
                plan,
                win,
                device=_win_device(),
                typed_serial=WIN_SERIAL,
                dry_run=True,
                ledger=ledger,
            )
        )
    assert ata.set_max_calls == []
    assert ata.accessible_max_lba == ACCESSIBLE


def test_a_real_run_needs_the_typed_serial(
    win: WindowsHpaBackend, ata: FakeAta, tmp_path: Path
) -> None:
    ledger = _ledger(tmp_path)
    plan = _win_plan(win)
    for typed in ("", "WRONG-SERIAL"):
        with pytest.raises(ConfirmationMismatch):
            _run(
                execute(
                    plan,
                    win,
                    device=_win_device(),
                    typed_serial=typed,
                    ledger=ledger,
                )
            )
    assert ata.set_max_calls == []
    assert _ops(ledger).count("hpa.blocked") == 2


def test_the_typed_serial_is_case_and_space_tolerant(
    win: WindowsHpaBackend, ata: FakeAta, tmp_path: Path
) -> None:
    plan = _win_plan(win)
    _run(
        execute(
            plan,
            win,
            device=_win_device(),
            typed_serial=f"  {WIN_SERIAL.lower()} ",
            ledger=_ledger(tmp_path),
        )
    )
    assert ata.set_max_calls == [(NATIVE, True)]


def test_a_stale_plan_is_refused(
    win: WindowsHpaBackend, ata: FakeAta, tmp_path: Path
) -> None:
    """The drive's native max changed between approval and execution."""
    ledger = _ledger(tmp_path)
    plan = _win_plan(win)
    ata.native_max_lba = NATIVE + 1024
    with pytest.raises(WorkflowGateRefused, match="stale") as caught:
        _run(
            execute(
                plan,
                win,
                device=_win_device(),
                typed_serial=WIN_SERIAL,
                ledger=ledger,
            )
        )
    assert any("native max LBA" in reason for reason in caught.value.why_blocked)
    assert ata.set_max_calls == []
    assert "hpa.blocked" in _ops(ledger)


def test_a_changed_dco_makes_the_plan_stale(
    win: WindowsHpaBackend, ata: FakeAta, tmp_path: Path
) -> None:
    plan = _win_plan(win)
    ata.dco_max_lba = NATIVE + 7
    with pytest.raises(WorkflowGateRefused, match="DCO max LBA"):
        _run(
            execute(
                plan,
                win,
                device=_win_device(),
                typed_serial=WIN_SERIAL,
                ledger=_ledger(tmp_path),
            )
        )
    assert ata.set_max_calls == []


def test_a_changed_identity_makes_the_plan_stale(
    win: WindowsHpaBackend, tmp_path: Path
) -> None:
    plan = _win_plan(win)
    with pytest.raises(WorkflowGateRefused, match="model"):
        _run(
            execute(
                plan,
                win,
                device=_win_device(model="ANOTHER"),
                typed_serial=WIN_SERIAL,
                ledger=_ledger(tmp_path),
            )
        )


def test_an_altered_plan_is_refused(win: WindowsHpaBackend, tmp_path: Path) -> None:
    plan = _win_plan(win).model_copy(update={"volatile": False})
    with pytest.raises(WorkflowGateRefused, match="altered"):
        _run(
            execute(
                plan,
                win,
                device=_win_device(),
                typed_serial=WIN_SERIAL,
                ledger=_ledger(tmp_path),
            )
        )


@pytest.mark.parametrize(
    ("override", "error"),
    [
        ({"mounted_at": ["E:\\"]}, MountedRefused),
        ({"is_system_disk": True}, SystemDiskRefused),
    ],
)
def test_a_mounted_or_system_device_is_never_touched(
    win: WindowsHpaBackend,
    ata: FakeAta,
    tmp_path: Path,
    override: dict[str, Any],
    error: type[Exception],
) -> None:
    plan = _win_plan(win)
    with pytest.raises(error):
        _run(
            execute(
                plan,
                win,
                device=_win_device(**override),
                typed_serial=WIN_SERIAL,
                ledger=_ledger(tmp_path),
            )
        )
    assert ata.set_max_calls == []


def test_a_mounted_volume_found_at_the_write_seam_refuses(
    win: WindowsHpaBackend, disk: FakeDisk, ata: FakeAta, tmp_path: Path
) -> None:
    plan = _win_plan(win)
    disk.volumes = {"\\\\?\\Volume{abc}\\": ["F:\\"]}
    _, result = _run(
        execute(
            plan,
            win,
            device=_win_device(),
            typed_serial=WIN_SERIAL,
            ledger=_ledger(tmp_path),
        )
    )
    assert result.outcome == "FAILED"
    assert ata.set_max_calls == []


def test_a_blocked_plan_never_runs(win: WindowsHpaBackend, tmp_path: Path) -> None:
    device = _win_device()
    state = win.discover(device)
    plan = plan_hpa_change(
        device.model_copy(update={"serial": ""}),
        state,
        platform="windows",
        clock=_clock,
    )
    with pytest.raises(WorkflowGateRefused, match="no serial"):
        _run(
            execute(
                plan,
                win,
                device=device,
                typed_serial=device.serial,
                ledger=_ledger(tmp_path),
            )
        )


class _DriveIgnoresSetMax(WindowsHpaBackend):
    """A drive that acknowledges SET MAX and does not apply it."""

    def set_max(self, device: Device, lba: int, *, volatile: bool) -> None:
        return None


def test_a_change_the_drive_did_not_apply_fails_verification(
    api: FakeWindowsApi, ata: FakeAta, tmp_path: Path
) -> None:
    backend = _DriveIgnoresSetMax(api)
    ledger = _ledger(tmp_path)
    plan = _win_plan(backend)
    _, result = _run(
        execute(
            plan,
            backend,
            device=_win_device(),
            typed_serial=WIN_SERIAL,
            ledger=ledger,
        )
    )
    assert result.outcome == "FAILED"
    assert not result.verification_passed
    assert result.device_modified == "no"
    assert any("not the requested" in note for note in result.verification_notes)
    assert _ops(ledger) == ["hpa.plan", "hpa.modify", "hpa.verify", "hpa.failed"]


def test_a_refused_set_max_is_a_failure_with_an_unknown_state(
    api: FakeWindowsApi, ata: FakeAta, tmp_path: Path
) -> None:
    class Refusing(WindowsHpaBackend):
        def set_max(self, device: Device, lba: int, *, volatile: bool) -> None:
            raise UnsupportedCapability("aborted SET MAX ADDRESS EXT")

    backend = Refusing(api)
    ledger = _ledger(tmp_path)
    _, result = _run(
        execute(
            _win_plan(backend),
            backend,
            device=_win_device(),
            typed_serial=WIN_SERIAL,
            ledger=ledger,
        )
    )
    assert result.outcome == "FAILED"
    assert result.device_modified == "unknown"
    assert _ops(ledger)[-1] == "hpa.failed"


def test_cancelling_after_the_command_is_ledgered(
    win: WindowsHpaBackend, tmp_path: Path
) -> None:
    ledger = _ledger(tmp_path)
    generator = execute(
        _win_plan(win),
        win,
        device=_win_device(),
        typed_serial=WIN_SERIAL,
        ledger=ledger,
    )
    phases = []
    for record in generator:
        phases.append(record["phase"])
        if record["phase"] == S.VERIFYING.value:
            generator.close()
            break
    assert _ops(ledger)[-1] == "hpa.failed"
    params = ledger.params_of(list(ledger.entries())[-1])
    assert params["phase"] == S.VERIFYING.value


def test_a_linux_plan_is_refused_by_a_windows_backend(
    win: WindowsHpaBackend, tmp_path: Path
) -> None:
    plan = _win_plan(win).model_copy(update={"platform": "linux"})
    plan = plan.model_copy(update={"plan_digest": plan_digest_of(plan)})
    with pytest.raises(WorkflowGateRefused, match="for linux"):
        _run(
            execute(
                plan,
                win,
                device=_win_device(),
                typed_serial=WIN_SERIAL,
                ledger=_ledger(tmp_path),
            )
        )


# --------------------------------------------------------------------------
# Linux backend
# --------------------------------------------------------------------------


def test_linux_discovery_parses_hdparm(linux: LinuxHpaBackend) -> None:
    state = linux.discover(_linux_device())
    assert state.accessible_max_lba == ACCESSIBLE
    assert state.native_max_lba == NATIVE
    assert state.hidden_bytes == HIDDEN
    assert state.dco_max_lba == NATIVE
    assert state.source_commands == (
        "hdparm -N /dev/sdq",
        "hdparm --dco-identify /dev/sdq",
    )


def test_a_real_linux_change_sends_the_volatile_form(
    linux: LinuxHpaBackend, hdparm: StatefulHdparm, tmp_path: Path
) -> None:
    device = _linux_device()
    plan = plan_hpa_change(
        device, linux.discover(device), platform="linux", clock=_clock
    )
    _, result = _run(
        execute(
            plan,
            linux,
            device=device,
            typed_serial=LINUX_SERIAL,
            ledger=_ledger(tmp_path),
        )
    )
    sets = [call for call in hdparm.calls if len(call) == 4 and call[1] == "-N"]
    assert sets == [("hdparm", "-N", str(NATIVE + 1), "/dev/sdq")]
    assert result.outcome == "COMPLETE" and result.verification_passed
    assert any("kernel keeps the device size" in note for note in result.limitations)


def test_a_permanent_linux_change_uses_the_p_prefix_only_when_planned(
    linux: LinuxHpaBackend, hdparm: StatefulHdparm, tmp_path: Path
) -> None:
    device = _linux_device()
    plan = plan_hpa_change(
        device,
        linux.discover(device),
        platform="linux",
        volatile=False,
        clock=_clock,
    )
    _run(
        execute(
            plan,
            linux,
            device=device,
            typed_serial=LINUX_SERIAL,
            ledger=_ledger(tmp_path),
        )
    )
    sets = [call for call in hdparm.calls if len(call) == 4]
    assert sets == [("hdparm", "-N", f"p{NATIVE + 1}", "/dev/sdq")]


def test_a_linux_change_without_the_serial_sends_no_set(
    linux: LinuxHpaBackend, hdparm: StatefulHdparm, tmp_path: Path
) -> None:
    device = _linux_device()
    plan = plan_hpa_change(
        device, linux.discover(device), platform="linux", clock=_clock
    )
    with pytest.raises(ConfirmationMismatch):
        _run(
            execute(
                plan, linux, device=device, typed_serial="", ledger=_ledger(tmp_path)
            )
        )
    assert all(len(call) == 3 for call in hdparm.calls)
    assert hdparm.accessible == ACCESSIBLE + 1


def test_a_linux_drive_that_ignores_the_set_fails_verification(
    tmp_path: Path, linux: LinuxHpaBackend, hdparm: StatefulHdparm
) -> None:
    hdparm.ignore_set = True
    device = _linux_device()
    plan = plan_hpa_change(
        device, linux.discover(device), platform="linux", clock=_clock
    )
    _, result = _run(
        execute(
            plan,
            linux,
            device=device,
            typed_serial=LINUX_SERIAL,
            ledger=_ledger(tmp_path),
        )
    )
    assert result.outcome == "FAILED" and not result.verification_passed


@pytest.mark.parametrize("transport", ["usb", "mmc"])
def test_a_linux_bridge_is_refused_and_reported_not_guessed(
    tmp_path: Path, transport: str
) -> None:
    runner = FakeRunner(
        {("hdparm",): ok("max sectors = 0/1, HPA setting seems invalid")}
    )
    backend = LinuxHpaBackend(SystemProbe(runner=runner))  # type: ignore[arg-type]
    device = _linux_device(transport=transport)
    with pytest.raises(UnsupportedCapability, match="bridge"):
        backend.discover(device)
    with pytest.raises(UnsupportedCapability, match="bridge"):
        backend.set_max(device, NATIVE, volatile=True)
    assert runner.calls == [], "nothing may be sent through a bridge"


def test_an_invalid_hdparm_reading_is_discarded() -> None:
    runner = FakeRunner(
        {("hdparm", "-N"): ok(" max sectors   = 0/1, HPA setting seems invalid\n")}
    )
    backend = LinuxHpaBackend(SystemProbe(runner=runner))  # type: ignore[arg-type]
    with pytest.raises(UnsupportedCapability, match="invalid"):
        backend.discover(_linux_device())


def test_a_permission_failure_is_not_read_as_no_hpa() -> None:
    runner = FakeRunner(
        {("hdparm", "-N"): CommandResult([], 1, "", "Permission denied")}
    )
    backend = LinuxHpaBackend(SystemProbe(runner=runner))  # type: ignore[arg-type]
    with pytest.raises(UnsupportedCapability, match="permission denied"):
        backend.discover(_linux_device())


def test_an_unreadable_sector_size_is_assumed_and_said(tmp_path: Path) -> None:
    backend = LinuxHpaBackend(
        SystemProbe(runner=StatefulHdparm(), sysfs_root=tmp_path / "nothing")
    )
    state = backend.discover(_linux_device())
    assert state.sector_bytes == 512
    assert any("512 bytes was assumed" in note for note in state.limitations)


# --------------------------------------------------------------------------
# Platform selection
# --------------------------------------------------------------------------


def test_macos_has_no_backend() -> None:
    with pytest.raises(PlatformUnsupported, match="macOS"):
        platform_backend("macos")


def test_linux_and_windows_backends_are_selected(api: FakeWindowsApi) -> None:
    assert isinstance(platform_backend("linux"), LinuxHpaBackend)
    assert isinstance(platform_backend("windows", api=api), WindowsHpaBackend)


# --------------------------------------------------------------------------
# The backup gate
# --------------------------------------------------------------------------


def _backup(
    tmp_path: Path, *, serial: str = WIN_SERIAL, size: int = (ACCESSIBLE + 1) * SECTOR
) -> tuple[Any, Any]:
    image = tmp_path / "backup.img"
    image.write_bytes(b"\x5a" * size)
    source = SourceIdentity(
        path=WIN_PATH, serial=serial, model="FAKE Disk", size_bytes=size
    )
    record = None
    generator = create_backup_record(image, source)
    while True:
        try:
            next(generator)
        except StopIteration as stop:
            record = stop.value
            break
    verifier = verify_backup(record)
    while True:
        try:
            next(verifier)
        except StopIteration as stop:
            return record, stop.value


def test_a_verified_backup_of_the_accessible_range_meets_the_gate(
    tmp_path: Path, win: WindowsHpaBackend
) -> None:
    record, verification = _backup(tmp_path)
    state = win.discover(_win_device())
    assert (
        backup_problems(record, verification, device=_win_device(), state=state) == []
    )


def test_no_backup_or_no_verification_fails_the_gate(
    tmp_path: Path, win: WindowsHpaBackend
) -> None:
    state = win.discover(_win_device())
    assert backup_problems(None, None, device=_win_device(), state=state)
    record, _ = _backup(tmp_path)
    reasons = backup_problems(record, None, device=_win_device(), state=state)
    assert any("not been verified" in reason for reason in reasons)


def test_a_backup_of_another_device_fails_the_gate(
    tmp_path: Path, win: WindowsHpaBackend
) -> None:
    record, verification = _backup(tmp_path, serial="OTHER")
    state = win.discover(_win_device())
    reasons = backup_problems(record, verification, device=_win_device(), state=state)
    assert any("recorded against serial" in reason for reason in reasons)


def test_a_backup_smaller_than_the_accessible_range_fails_the_gate(
    tmp_path: Path, win: WindowsHpaBackend
) -> None:
    record, verification = _backup(tmp_path, size=SECTOR * 8)
    state = win.discover(_win_device())
    reasons = backup_problems(record, verification, device=_win_device(), state=state)
    assert any("does not cover" in reason for reason in reasons)


def test_a_failed_verification_fails_the_gate(
    tmp_path: Path, win: WindowsHpaBackend
) -> None:
    record, verification = _backup(tmp_path)
    failed = verification.model_copy(update={"passed": False, "message": "chunk 0"})
    state = win.discover(_win_device())
    reasons = backup_problems(record, failed, device=_win_device(), state=state)
    assert any("failed verification" in reason for reason in reasons)


def test_state_is_a_frozen_model() -> None:
    state = hidden_area_state(
        path="/dev/sdq",
        native_max_lba=NATIVE,
        accessible_max_lba=ACCESSIBLE,
        sector_bytes=SECTOR,
        reported_capacity_bytes=(ACCESSIBLE + 1) * SECTOR,
        hpa_supported=True,
        dco_supported=False,
        dco_max_lba=None,
        source_commands=("x",),
    )
    assert isinstance(state, HiddenAreaState)
    with pytest.raises(ValueError):
        state.native_max_lba = 1  # type: ignore[misc]
