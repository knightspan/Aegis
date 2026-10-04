"""End-to-end ``execute`` against a real loopback block device.

Needs Linux and root: only root can run ``losetup``. Everything here exercises
the full six-phase path including the BLKGETSIZE64 geometry read, which a
regular file cannot provide.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
from core.device._sysio import SystemProbe
from core.ledger.chain import ChainStatus, Ledger
from core.models import EraseMethod, ErasePhase, SanitizationLevel

from ..device.conftest import FakeRunner, ok
from .conftest import ROOT_ONLY, make_caps, make_device, make_job, sha256_of

if sys.platform != "linux":  # pragma: no cover - platform gate
    pytest.skip("core.erase.drive is Linux-only", allow_module_level=True)

from core.erase.drive import ChainLedgerSink, execute  # noqa: E402

pytestmark = ROOT_ONLY

MIB = 1024 * 1024

#: Every phase, unconditionally. A loop device has no HPA or DCO, so nothing is
#: ever unlocked here - but the phase is still ledgered as ``not_required``,
#: because a chain that omitted it could not be told apart from one where the
#: tool never probed for a hidden area at all. The branch where sectors really
#: are hidden cannot be reached with a loop device and is covered against a
#: faked hidden-area report in ``tests/erase/test_hidden_area_phases.py``.
EXPECTED_PHASES = [
    ErasePhase.PREFLIGHT,
    ErasePhase.HIDDEN_AREA_UNLOCK,
    ErasePhase.ERASE,
    ErasePhase.HIDDEN_AREA_RESTORE,
    ErasePhase.VERIFY,
    ErasePhase.REPORT,
]



def make_sink(root: Path) -> ChainLedgerSink:
    """A real hash-chained ledger rooted under the test's tmp_path."""
    return ChainLedgerSink(
        Ledger(
            root / "ledger-store",
            tool_version="0.0.0-test",
            pubkey_fingerprint="AA:BB:CC",
        )
    )


def probe_for(path: str, serial: str = "SYN-0001") -> SystemProbe:
    """A SystemProbe whose lsblk reports exactly this loop device."""
    import json

    payload = json.dumps(
        {
            "blockdevices": [
                {
                    "name": Path(path).name,
                    "path": path,
                    "type": "disk",
                    "model": "SYNTHETIC",
                    "serial": serial,
                    "size": 64 * MIB,
                    "rota": True,
                    "tran": "sata",
                    "pttype": None,
                    "mountpoints": [None],
                }
            ]
        }
    )
    return SystemProbe(
        runner=FakeRunner(  # type: ignore[arg-type]
            {
                ("lsblk",): ok(payload),
                ("findmnt",): ok("/dev/nvme0n1p2\n"),
                ("hdparm", "-N", path): ok(
                    f"{path}:\n max sectors = 131072/131072, HPA is disabled\n"
                ),
                ("hdparm", "--dco-identify", path): ok(
                    f"{path}:\nDCO Revision: 0x0002\n\tReal max sectors: 131072\n"
                ),
            }
        ),
        by_id_map={},
    )


def drain(generator: Any) -> tuple[Any, list[Any]]:
    progress: list[Any] = []
    try:
        while True:
            progress.append(next(generator))
    except StopIteration as stop:
        return stop.value, progress


# --------------------------------------------------------------------------
# Spec test 3: a refused run writes nothing, a real run states its plan first
# --------------------------------------------------------------------------


def test_a_refused_run_writes_zero_bytes(loop_device: str, tmp_path: Path) -> None:
    from core.errors import ConfirmationMismatch

    backing = Path(loop_device)
    before = sha256_of(backing)

    device = make_device(path=loop_device, serial="SYN-0001", by_id_path=None)
    job = make_job(device, confirmed_serial="WRONG")
    with pytest.raises(ConfirmationMismatch):
        drain(
            execute(
                job, make_caps(), io=probe_for(loop_device), ledger=make_sink(tmp_path)
            )
        )

    assert sha256_of(backing) == before


def test_a_real_run_emits_the_full_plan_before_writing(
    loop_device: str, tmp_path: Path
) -> None:
    device = make_device(path=loop_device, serial="SYN-0001", by_id_path=None)
    result, progress = drain(
        execute(
            make_job(device),
            make_caps(),
            io=probe_for(loop_device),
            ledger=make_sink(tmp_path),
        )
    )
    assert result.plan.method == EraseMethod.SINGLE_PASS_OVERWRITE
    assert result.plan.justification
    first_erase = next(
        index for index, item in enumerate(progress) if item.phase == "ERASE"
    )
    assert any(item.message.startswith("plan:") for item in progress[:first_erase])


# --------------------------------------------------------------------------
# Spec test 1 end-to-end
# --------------------------------------------------------------------------


def test_real_wipe_zeroes_the_device_and_verifies(
    loop_device: str, tmp_path: Path
) -> None:
    device = make_device(path=loop_device, serial="SYN-0001", by_id_path=None)
    ledger = make_sink(tmp_path)
    result, _ = drain(
        execute(
            make_job(device),
            make_caps(),
            io=probe_for(loop_device),
            ledger=ledger,
        )
    )
    assert result.bytes_written > 0
    assert result.residual_risk.level in {"low", "medium"}
    assert set(Path(loop_device).read_bytes()) == {0}


# --------------------------------------------------------------------------
# Spec test 7: ledger phase order
# --------------------------------------------------------------------------


def test_ledger_records_every_phase_in_order(loop_device: str, tmp_path: Path) -> None:
    device = make_device(path=loop_device, serial="SYN-0001", by_id_path=None)
    ledger = make_sink(tmp_path)
    drain(
        execute(
            make_job(device),
            make_caps(),
            io=probe_for(loop_device),
            ledger=ledger,
        )
    )
    recorded = [
        entry.operation.split('.')[1].upper()
        for entry in ledger.ledger.entries()
        if entry.operation.startswith('erase.')
    ]
    seen: list[str] = []
    for phase in recorded:
        if not seen or seen[-1] != phase:
            seen.append(phase)
    assert seen == [phase.value for phase in EXPECTED_PHASES]
    assert ledger.ledger.verify().status is ChainStatus.VALID


def test_progress_reports_every_phase_in_order(
    loop_device: str, tmp_path: Path
) -> None:
    device = make_device(path=loop_device, serial="SYN-0001", by_id_path=None)
    _, progress = drain(
        execute(
            make_job(device),
            make_caps(),
            io=probe_for(loop_device),
            ledger=make_sink(tmp_path),
        )
    )
    seen: list[str] = []
    for item in progress:
        if not seen or seen[-1] != item.phase:
            seen.append(item.phase)
    assert seen == [phase.value for phase in EXPECTED_PHASES]


# --------------------------------------------------------------------------
# Preflight guards
# --------------------------------------------------------------------------


def test_serial_swap_between_confirmation_and_execution_is_caught(
    loop_device: str, tmp_path: Path
) -> None:
    from core.errors import DeviceVanished

    device = make_device(path=loop_device, serial="SYN-0001", by_id_path=None)
    swapped = probe_for(loop_device, serial="DIFFERENT-DISK")
    with pytest.raises(DeviceVanished):
        drain(
            execute(
                make_job(device),
                make_caps(),
                io=swapped,
                ledger=make_sink(tmp_path),
            )
        )


def test_wrong_typed_serial_refuses(loop_device: str, tmp_path: Path) -> None:
    from core.errors import ConfirmationMismatch

    device = make_device(path=loop_device, serial="SYN-0001", by_id_path=None)
    job = make_job(device, confirmed_serial="WRONG")
    with pytest.raises(ConfirmationMismatch):
        drain(
            execute(
                job, make_caps(), io=probe_for(loop_device), ledger=make_sink(tmp_path)
            )
        )


def test_mounted_device_refuses(loop_device: str, tmp_path: Path) -> None:
    from core.errors import MountedRefused

    device = make_device(
        path=loop_device, serial="SYN-0001", by_id_path=None, mounted_at=["/mnt/x"]
    )
    with pytest.raises(MountedRefused):
        drain(
            execute(
                make_job(device),
                make_caps(),
                io=probe_for(loop_device),
                ledger=make_sink(tmp_path),
            )
        )


def test_system_disk_refuses(loop_device: str, tmp_path: Path) -> None:
    from core.errors import SystemDiskRefused

    device = make_device(
        path=loop_device, serial="SYN-0001", by_id_path=None, is_system_disk=True
    )
    with pytest.raises(SystemDiskRefused):
        drain(
            execute(
                make_job(device),
                make_caps(),
                io=probe_for(loop_device),
                ledger=make_sink(tmp_path),
            )
        )


def test_purge_on_a_frozen_drive_raises_rather_than_downgrading(
    loop_device: str, tmp_path: Path
) -> None:
    from core.errors import DeviceFrozen

    device = make_device(path=loop_device, serial="SYN-0001", by_id_path=None)
    caps = make_caps(
        ata_security_erase=True,
        ata_enhanced_erase=True,
        security_frozen=True,
        achievable_levels={SanitizationLevel.CLEAR},
    )
    job = make_job(device, level=SanitizationLevel.PURGE)
    with pytest.raises(DeviceFrozen):
        drain(execute(job, caps, io=probe_for(loop_device), ledger=make_sink(tmp_path)))
