"""The hidden-area phases, on a host with no HPA to find.

No loopback device will ever report an HPA or a DCO - they are ATA features of
real spinning and SATA flash media - so the branch that matters most cannot be
reached by pointing the erase engine at one. These tests fake the hidden-area
report instead, which is the only way to cover the case where sectors really are
hidden.

An ordinary erase never unlocks them. Changing the HPA is a configuration change
to the drive and belongs to the guarded HPA/DCO workflow
(``core.device.hidden_area_workflow``). What the erase must do is record that it
found hidden bytes, erase the accessible range, and say plainly that the hidden
region was not sanitized.

Faking the *probe* rather than the device is deliberate. Everything downstream
of ``detect_hidden_areas`` - the decision, the geometry, the ledger entries,
the report - is the code under test and runs unaltered.

Needs no root: ``device_geometry`` is stubbed because ``BLKGETSIZE64`` only
answers for a block device, and creating one needs privileges these tests
deliberately do not require.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from core.models import ErasePhase, HiddenAreaReport, SanitizationLevel

from .conftest import make_caps, make_device, make_job

if sys.platform != "linux":  # pragma: no cover - platform gate
    pytest.skip("core.erase.drive is Linux-only", allow_module_level=True)

from core.erase import drive  # noqa: E402
from core.erase.drive import ChainLedgerSink, Geometry, execute  # noqa: E402
from core.ledger.chain import ChainStatus, Ledger  # noqa: E402

MIB = 1024 * 1024
SECTOR = 512
DEVICE_BYTES = 64 * MIB

EXPECTED_PHASES = [
    ErasePhase.PREFLIGHT,
    ErasePhase.HIDDEN_AREA_UNLOCK,
    ErasePhase.ERASE,
    ErasePhase.HIDDEN_AREA_RESTORE,
    ErasePhase.VERIFY,
    ErasePhase.REPORT,
]


def hidden_report(hidden_bytes: int) -> HiddenAreaReport:
    """A report with ``hidden_bytes`` beyond the accessible max."""
    accessible = DEVICE_BYTES // SECTOR
    return HiddenAreaReport(
        hpa_present=hidden_bytes > 0,
        dco_present=False,
        native_max_sectors=accessible + hidden_bytes // SECTOR,
        accessible_sectors=accessible,
        hidden_bytes=hidden_bytes,
    )


def _fake_dispatch(
    _device: Any, _caps: Any, geo: Geometry, _method: Any, **kw: Any
) -> Any:
    """Stands in for the write: reports the whole geometry written, touches nothing."""
    yield drive._progress(kw["job_id"], ErasePhase.ERASE, 10_000, "faked write")
    return (geo.size_bytes, 1, [], [], False)


def _fake_verify(*_a: Any, **_kw: Any) -> Any:
    return drive.VerificationResult(
        passed=True,
        strategy="full_read",
        bytes_checked=DEVICE_BYTES,
        sample_count=0,
        failed_offsets=[],
        confidence_bp=10_000,
        probability_note="test",
        hw_attested=False,
    )


def _no_device_io(geometry: Geometry, hidden: HiddenAreaReport) -> Any:
    """Every seam that would touch a device, faked. The engine runs for real.

    There is no non-writing mode to lean on: ``execute`` always dispatches, so
    the write, the read-back and the calibration are replaced here instead.
    """
    from contextlib import ExitStack

    stack = ExitStack()
    for target, name, kwargs in (
        (drive, "device_geometry", {"return_value": geometry}),
        (drive.hidden_areas, "detect_hidden_areas", {"return_value": hidden}),
        (drive.guard, "assert_erasable", {}),
        (drive, "_reread_serial", {}),
        (drive, "_dispatch", {"new": _fake_dispatch}),
        (drive.verify_mod, "verify", {"new": _fake_verify}),
        (drive.calibrate_mod, "calibrate_write", {"return_value": honest()}),
    ):
        stack.enter_context(mock.patch.object(target, name, **kwargs))
    return stack


def run_execute(
    tmp_path: Path,
    *,
    hidden_bytes: int,
    **job_overrides: Any,
) -> tuple[Ledger, list[Any]]:
    """Drive ``execute`` with a faked hidden-area probe. Returns (ledger, progress)."""
    device = make_device(path="/dev/loop-fake", serial="SYN-0001", by_id_path=None)
    job = make_job(device, **job_overrides)
    chain = Ledger(
        tmp_path / "ledger", tool_version="0.0.0-test", pubkey_fingerprint="AA:BB"
    )
    sink = ChainLedgerSink(chain)
    geometry = Geometry(
        size_bytes=DEVICE_BYTES, logical_block_size=SECTOR, physical_block_size=SECTOR
    )

    progress: list[Any] = []
    with _no_device_io(geometry, hidden_report(hidden_bytes)):
        generator = execute(job, make_caps(), io=None, ledger=sink)
        try:
            while True:
                progress.append(next(generator))
        except StopIteration:
            pass
    return chain, progress


def ledgered_phases(chain: Ledger) -> list[str]:
    """The phase of each erase entry, collapsed to a run-length sequence."""
    seen: list[str] = []
    for entry in chain.entries():
        if not entry.operation.startswith("erase."):
            continue
        phase = entry.operation.split(".")[1].upper()
        if not seen or seen[-1] != phase:
            seen.append(phase)
    return seen


def operations(chain: Ledger) -> list[str]:
    return [
        entry.operation
        for entry in chain.entries()
        if entry.operation.startswith("erase.")
    ]


# --------------------------------------------------------------------------
# Both branches record the same six phases
# --------------------------------------------------------------------------


def test_a_drive_with_no_hidden_area_still_ledgers_the_unlock_phase(
    tmp_path: Path,
) -> None:
    """"Probed and found none" must be distinguishable from "never probed".

    This is the case a loopback device produces, and the one that used to
    record nothing at all: the phase yielded progress and wrote no entry, so a
    chain read afterwards could not tell that the tool had looked. Its sibling
    HIDDEN_AREA_RESTORE has always recorded ``not_required`` in exactly the
    analogous situation, which is what makes a fixed phase list the right
    invariant rather than a conditional one.
    """
    chain, _ = run_execute(tmp_path, hidden_bytes=0)

    assert ledgered_phases(chain) == [phase.value for phase in EXPECTED_PHASES]
    entry = next(
        item
        for item in operations(chain)
        if item.startswith("erase.hidden_area_unlock.")
    )
    assert entry == "erase.hidden_area_unlock.not_required"


def test_a_drive_with_a_hidden_area_is_not_unlocked_and_says_so(
    tmp_path: Path,
) -> None:
    """Found but not unlocked must be distinguishable from probed and found none.

    The entry names what was found and why nothing was done about it, so a
    chain reader can see that the sectors beyond the accessible maximum were
    considered and deliberately left alone.
    """
    chain, _ = run_execute(tmp_path, hidden_bytes=8 * MIB)

    assert ledgered_phases(chain) == [phase.value for phase in EXPECTED_PHASES]
    unlock = next(
        item
        for item in operations(chain)
        if item.startswith("erase.hidden_area_unlock.")
    )
    assert unlock == "erase.hidden_area_unlock.not_authorized"

    params = next(
        chain.params_of(entry)
        for entry in chain.entries()
        if entry.operation == "erase.hidden_area_unlock.not_authorized"
    )
    assert params["hidden_bytes"] == 8 * MIB
    assert params["accessible_sectors"] == DEVICE_BYTES // SECTOR
    assert params["native_max_sectors"] > params["accessible_sectors"]
    assert params["hidden_covered"] is False
    assert "HPA/DCO workflow" in params["reason"]


def test_the_restore_phase_is_not_required_when_nothing_was_changed(
    tmp_path: Path,
) -> None:
    chain, _ = run_execute(tmp_path, hidden_bytes=8 * MIB)

    restore = [
        item
        for item in operations(chain)
        if item.startswith("erase.hidden_area_restore.")
    ]
    assert restore == ["erase.hidden_area_restore.not_required"]


def test_the_not_required_entry_records_what_was_probed(tmp_path: Path) -> None:
    """An entry saying only "skipped" would be no better than no entry."""
    chain, _ = run_execute(tmp_path, hidden_bytes=0)

    params = next(
        chain.params_of(entry)
        for entry in chain.entries()
        if entry.operation == "erase.hidden_area_unlock.not_required"
    )
    assert params["hidden_bytes"] == 0
    assert params["accessible_sectors"] == DEVICE_BYTES // SECTOR
    assert params["native_max_sectors"] == params["accessible_sectors"]
    assert "no HPA or DCO" in params["reason"]


@pytest.mark.parametrize("hidden_bytes", [0, 8 * MIB])
def test_the_chain_verifies_either_way(tmp_path: Path, hidden_bytes: int) -> None:
    chain, _ = run_execute(tmp_path, hidden_bytes=hidden_bytes)
    verification = chain.verify()
    assert verification.status is ChainStatus.VALID, verification.explanation


@pytest.mark.parametrize("hidden_bytes", [0, 8 * MIB])
def test_progress_reports_the_same_six_phases_the_ledger_does(
    tmp_path: Path, hidden_bytes: int
) -> None:
    """The operator's view and the audit record must not disagree.

    A phase visible in the UI and absent from the chain, or the reverse, would
    mean the thing the operator watched happen is not the thing a third party
    can later check.
    """
    chain, progress = run_execute(tmp_path, hidden_bytes=hidden_bytes)

    seen: list[str] = []
    for item in progress:
        if not seen or seen[-1] != item.phase:
            seen.append(item.phase)

    assert seen == [phase.value for phase in EXPECTED_PHASES]
    assert seen == ledgered_phases(chain)


# --------------------------------------------------------------------------
# A firmware method covers the hidden area itself
# --------------------------------------------------------------------------


def test_a_firmware_method_records_that_it_covers_the_hidden_area(
    tmp_path: Path,
) -> None:
    """Not an omission: SANITIZE reaches the full media, HPA included.

    So there is no host-side unlock to perform, and the ledger has to say *why*
    rather than leave a reader to assume the phase was forgotten.
    """
    from core.models import EraseMethod

    device = make_device(path="/dev/loop-fake", serial="SYN-0001", by_id_path=None)
    job = make_job(
        device,
        level=SanitizationLevel.PURGE,
        method=None,
    )
    chain = Ledger(
        tmp_path / "ledger", tool_version="0.0.0-test", pubkey_fingerprint="AA:BB"
    )
    capabilities = make_caps(
        ata_sanitize_ops=["BLOCK_ERASE_EXT"],
        achievable_levels={SanitizationLevel.CLEAR, SanitizationLevel.PURGE},
    )
    geometry = Geometry(
        size_bytes=DEVICE_BYTES, logical_block_size=SECTOR, physical_block_size=SECTOR
    )

    with _no_device_io(geometry, hidden_report(8 * MIB)):
        generator = execute(job, capabilities, io=None, ledger=ChainLedgerSink(chain))
        try:
            while True:
                next(generator)
        except StopIteration:
            pass

    assert ledgered_phases(chain) == [phase.value for phase in EXPECTED_PHASES]
    unlock = next(
        item
        for item in operations(chain)
        if item.startswith("erase.hidden_area_unlock.")
    )
    assert unlock == "erase.hidden_area_unlock.skipped"

    params = next(
        chain.params_of(entry)
        for entry in chain.entries()
        if entry.operation == "erase.hidden_area_unlock.skipped"
    )
    assert "firmware" in params["reason"]
    assert "HPA/DCO" in params["reason"]
    assert EraseMethod.ATA_SANITIZE_BLOCK_ERASE.value in params["reason"]


def test_every_phase_appears_exactly_once_in_the_collapsed_sequence(
    tmp_path: Path,
) -> None:
    """No phase may be recorded twice in two separate runs of entries.

    Two runs of the same phase would mean the erase re-entered a phase it had
    left, and the chain would no longer describe a single forward pass.
    """
    chain, _ = run_execute(tmp_path, hidden_bytes=8 * MIB)
    phases = ledgered_phases(chain)
    assert len(phases) == len(set(phases))


# --------------------------------------------------------------------------
# A bridge's bogus native max must not shrink the erase
# --------------------------------------------------------------------------

#: Exactly what the TransMemory stick's USB bridge printed during hardware
#: validation, with a zero exit status. Parsed literally it says the drive is
#: one sector long.
HDPARM_N_INVALID = (
    "/dev/loop-fake:\n"
    " max sectors   = 0/1, HPA setting seems invalid (buggy kernel device driver?)\n"
)


def erase_geometry_for(
    tmp_path: Path, *, transport: str, hdparm_n: str
) -> tuple[Geometry, list[str], list[tuple[str, ...]], Any]:
    """Run ``execute`` for real up to ERASE and capture the geometry it dispatches.

    The hidden-area probe is *not* faked here - it is the code under test. Only
    ``hdparm`` is faked, at the process boundary, so the whole path from the
    tool's output through the unlock decision to the geometry the overwrite
    would receive runs unaltered.
    """
    from core.device._sysio import SystemProbe

    from ..device.conftest import FakeRunner, ok

    device = make_device(
        path="/dev/loop-fake", serial="SYN-0001", by_id_path=None, transport=transport
    )
    device = device.model_copy(update={"size_bytes": DEVICE_BYTES})
    job = make_job(device)
    sink = ChainLedgerSink(
        Ledger(tmp_path / "ledger", tool_version="0.0.0-test", pubkey_fingerprint="A")
    )
    geometry = Geometry(
        size_bytes=DEVICE_BYTES, logical_block_size=SECTOR, physical_block_size=SECTOR
    )
    runner = FakeRunner(
        {
            # A two-element prefix, so the same fake would answer an unlock
            # (``hdparm -N p<native> <dev>``) too - which is how the tests
            # below prove none is ever sent.
            ("hdparm", "-N"): ok(hdparm_n),
            ("hdparm", "--dco-identify", "/dev/loop-fake"): ok(""),
        }
    )
    probe = SystemProbe(runner=runner)  # type: ignore[arg-type]
    seen: list[Geometry] = []

    def fake_dispatch(
        _device: Any, _caps: Any, dispatched: Geometry, *_a: Any, **_kw: Any
    ) -> Any:
        seen.append(dispatched)
        yield from ()
        return (dispatched.size_bytes, 1, [], [], False)

    with (
        mock.patch.object(drive, "device_geometry", return_value=geometry),
        mock.patch.object(drive, "_dispatch", fake_dispatch),
        mock.patch.object(drive.guard, "assert_erasable"),
        mock.patch.object(drive, "_reread_serial"),
        mock.patch.object(
            drive.verify_mod,
            "verify",
            return_value=drive.VerificationResult(
                passed=True,
                strategy="full_read",
                bytes_checked=DEVICE_BYTES,
                sample_count=0,
                failed_offsets=[],
                confidence_bp=10_000,
                probability_note="test",
                hw_attested=False,
            ),
        ),
    ):
        result = None
        generator = execute(job, make_caps(), io=probe, ledger=sink)
        try:
            while True:
                next(generator)
        except StopIteration as stop:
            result = stop.value

    assert seen, "the erase never dispatched"
    return seen[0], list(result.limitations if result else []), runner.calls, result


def test_a_bogus_native_max_does_not_shrink_the_erase(tmp_path: Path) -> None:
    """The defect this whole fix exists for.

    ``max sectors = 0/1`` parsed to a native max of one sector, the unlock
    branch rebuilt the geometry from it, and the overwrite covered 512 bytes of
    a device the kernel reported as 7.76 GB. The wipe "succeeded" and PhotoRec
    recovered every planted file afterwards.
    """
    dispatched, _, _, _ = erase_geometry_for(
        tmp_path, transport="sata", hdparm_n=HDPARM_N_INVALID
    )

    assert dispatched.size_bytes == DEVICE_BYTES


def test_a_bridged_device_erases_the_whole_kernel_size(tmp_path: Path) -> None:
    dispatched, limitations, _, _ = erase_geometry_for(
        tmp_path, transport="usb", hdparm_n=HDPARM_N_INVALID
    )

    assert dispatched.size_bytes == DEVICE_BYTES
    assert any("bridge" in item for item in limitations), (
        "an unprobed drive must say so in its limitations"
    )


def _real_hidden_area(tmp_path: Path) -> tuple[Geometry, list[str], Any, Any]:
    native = DEVICE_BYTES // SECTOR + 2048
    accessible = DEVICE_BYTES // SECTOR
    hdparm_n = (
        f"/dev/loop-fake:\n max sectors   = {accessible}/{native}, "
        "HPA is enabled\n"
    )
    return erase_geometry_for(tmp_path, transport="sata", hdparm_n=hdparm_n)


def test_a_real_hidden_area_is_never_unlocked_by_an_ordinary_erase(
    tmp_path: Path,
) -> None:
    """The spec: never unlock or modify HPA/DCO implicitly during an erase.

    The only ``hdparm -N`` the erase may send is the read (``hdparm -N <dev>``).
    Any argument between ``-N`` and the device - ``p<n>`` or ``<n>`` - is a
    SET MAX ADDRESS, and must never appear.
    """
    _, _, calls, _ = _real_hidden_area(tmp_path)

    set_max = [
        call for call in calls if call[:2] == ("hdparm", "-N") and len(call) != 3
    ]
    assert set_max == []
    assert ("hdparm", "-N", "/dev/loop-fake") in calls


def test_a_real_hidden_area_erases_the_accessible_range_only(tmp_path: Path) -> None:
    dispatched, _, _, _ = _real_hidden_area(tmp_path)

    assert dispatched.size_bytes == DEVICE_BYTES


def test_a_real_hidden_area_is_reported_not_covered(tmp_path: Path) -> None:
    """Neither the result nor the residual risk may claim the hidden region."""
    _, limitations, _, result = _real_hidden_area(tmp_path)

    assert result is not None
    hidden_bytes = 2048 * SECTOR
    assert result.hidden_covered is False
    assert any(
        str(hidden_bytes) in item and "HPA/DCO workflow" in item
        for item in limitations
    )
    risk = result.residual_risk
    assert risk.level == "high"
    assert any("NOT covered" in factor for factor in risk.factors)
    assert not any("unlocked and covered" in factor for factor in risk.factors)


def test_the_report_says_the_hidden_region_was_not_covered(tmp_path: Path) -> None:
    from core.report.render import drive_report_inputs

    _, _, _, result = _real_hidden_area(tmp_path)

    sections = drive_report_inputs(result.model_dump(mode="json"))
    assert sections["hidden_areas"]["covered"] is False


# --------------------------------------------------------------------------
# Write calibration drives the fill, the ETA, the verification and the finding
# --------------------------------------------------------------------------


def run_with_calibration(
    tmp_path: Path,
    *,
    calibration: Any,
) -> tuple[Any, list[Any], Ledger, list[Geometry], list[tuple[int, ...] | None]]:
    """Drive ``execute`` with a faked calibration, capturing what it chose."""
    device = make_device(path="/dev/loop-fake", serial="SYN-0001", by_id_path=None)
    device = device.model_copy(update={"size_bytes": DEVICE_BYTES})
    job = make_job(device)
    chain = Ledger(
        tmp_path / "ledger", tool_version="0.0.0-test", pubkey_fingerprint="A"
    )
    geometry = Geometry(
        size_bytes=DEVICE_BYTES, logical_block_size=SECTOR, physical_block_size=SECTOR
    )
    dispatched: list[Geometry] = []
    used_fills: list[tuple[int, ...] | None] = []
    verified_fills: list[tuple[int, ...] | None] = []

    def fake_dispatch(
        _device: Any,
        _caps: Any,
        geo: Geometry,
        _method: Any,
        *,
        fills: tuple[int, ...] | None = None,
        **_kw: Any,
    ) -> Any:
        dispatched.append(geo)
        used_fills.append(fills)
        yield from ()
        return (geo.size_bytes, len(fills or (0,)), [], [], False)

    def fake_verify(*_a: Any, fills: tuple[int, ...] | None = None, **_kw: Any) -> Any:
        verified_fills.append(fills)
        return drive.VerificationResult(
            passed=True,
            strategy="full_read",
            bytes_checked=DEVICE_BYTES,
            sample_count=0,
            failed_offsets=[],
            confidence_bp=10_000,
            probability_note="test",
            hw_attested=False,
        )

    progress: list[Any] = []
    with (
        mock.patch.object(drive, "device_geometry", return_value=geometry),
        mock.patch.object(drive, "_dispatch", fake_dispatch),
        mock.patch.object(drive.guard, "assert_erasable"),
        mock.patch.object(drive, "_reread_serial"),
        mock.patch.object(
            drive.hidden_areas, "detect_hidden_areas", return_value=hidden_report(0)
        ),
        mock.patch.object(
            drive.calibrate_mod, "calibrate_write", return_value=calibration
        ),
        mock.patch.object(drive.verify_mod, "verify", fake_verify),
    ):
        generator = execute(job, make_caps(), io=None, ledger=ChainLedgerSink(chain))
        result = None
        try:
            while True:
                progress.append(next(generator))
        except StopIteration as stop:
            result = stop.value
    used_fills.extend(verified_fills)
    return result, progress, chain, dispatched, used_fills


def elided() -> Any:
    from core.erase.calibrate import CalibrationResult

    return CalibrationResult(
        elision_detected=True,
        zero_seconds=521.5,
        nonzero_seconds=1886.75,
        ratio=1886.75 / 521.5,
        sample_bytes=64 * MIB,
    )


def honest() -> Any:
    from core.erase.calibrate import CalibrationResult

    return CalibrationResult(
        elision_detected=False,
        zero_seconds=520.0,
        nonzero_seconds=530.0,
        ratio=530.0 / 520.0,
        sample_bytes=64 * MIB,
    )


def test_a_zero_eliding_controller_gets_a_non_zero_fill(tmp_path: Path) -> None:
    """The substitution the whole finding exists to justify.

    A zero pass on this controller is a deallocate, and the report would name
    SINGLE_PASS_OVERWRITE for something the device did not perform.
    """
    result, _, _, _, fills = run_with_calibration(tmp_path, calibration=elided())

    assert result is not None
    assert result.plan.fill_bytes == ["0xA5"]
    assert "calibration" in result.plan.fill_reason
    assert fills[0] == (0xA5,)


def test_verification_checks_the_pattern_that_was_written(tmp_path: Path) -> None:
    """Otherwise it compares against 0x00 — the value the FTL answers for free."""
    _, _, _, _, fills = run_with_calibration(tmp_path, calibration=elided())

    written, verified = fills[0], fills[-1]
    assert written == verified == (0xA5,)


def test_a_controller_that_programs_zeros_keeps_the_default_fill(
    tmp_path: Path,
) -> None:
    result, _, _, _, fills = run_with_calibration(tmp_path, calibration=honest())

    assert result is not None
    assert result.plan.fill_bytes == ["0x00"]
    assert fills[0] == (0x00,)


def test_the_eta_uses_the_chosen_fill_s_measured_rate(tmp_path: Path) -> None:
    """Not the zero rate. An operator must not discover the 3.6x mid-run."""
    result, _, _, _, _ = run_with_calibration(tmp_path, calibration=elided())

    assert result is not None
    assert result.plan.est_seconds > 0
    assert "measured on this device" in result.plan.est_basis
    assert "0xA5" in result.plan.est_basis


def test_the_calibration_is_ledgered_with_its_numbers(tmp_path: Path) -> None:
    _, _, chain, _, _ = run_with_calibration(tmp_path, calibration=elided())

    entry = next(
        item
        for item in chain.entries()
        if item.operation == "erase.preflight.write_calibration"
    )
    params = chain.params_of(entry)

    assert params["elision_detected"] is True
    assert params["ratio_bp"] == 36179
    assert params["threshold_bp"] == 20000
    assert params["sample_bytes"] == 64 * MIB


def test_the_elision_finding_reaches_the_result(tmp_path: Path) -> None:
    result, _, _, _, _ = run_with_calibration(tmp_path, calibration=elided())

    assert result is not None
    kinds = [finding.kind.value for finding in result.residual_risk.findings]
    assert kinds == ["CONTROLLER_WRITE_ELISION"]
    assert result.residual_risk.level == "high"
    assert "host-side read can establish" in result.residual_risk.notes


def test_a_resume_never_calibrates(tmp_path: Path) -> None:
    """The calibration writes over the first 64 MiB twice. A resume must not.

    A resumed job would leave the calibration's own bytes at offset 0, in a
    region the erase has already covered.
    """
    from core.models import EraseCheckpoint

    device = make_device(path="/dev/loop-fake", serial="SYN-0001", by_id_path=None)
    device = device.model_copy(update={"size_bytes": DEVICE_BYTES})
    chain = Ledger(
        tmp_path / "ledger", tool_version="0.0.0-test", pubkey_fingerprint="A"
    )
    geometry = Geometry(
        size_bytes=DEVICE_BYTES, logical_block_size=SECTOR, physical_block_size=SECTOR
    )
    checkpoint = EraseCheckpoint(
        job_id="job-0001",
        pass_index=0,
        offset=MIB,
        bytes_written=MIB,
        ts_utc=drive.datetime.now(drive.UTC),
    )

    def tripwire(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("a resume calibrated")

    with (
        _no_device_io(geometry, hidden_report(0)),
        mock.patch.object(drive.calibrate_mod, "calibrate_write", tripwire),
    ):
        generator = execute(
            make_job(device),
            make_caps(),
            io=None,
            ledger=ChainLedgerSink(chain),
            resume_from=checkpoint,
        )
        try:
            while True:
                next(generator)
        except StopIteration:
            pass

    operations = [item.operation for item in chain.entries()]
    assert "erase.preflight.write_calibration" not in operations
