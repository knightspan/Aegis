"""The write calibration, and the finding it produces.

A controller can acknowledge an all-zero write without programming a cell. The
medium then reads back as zeros and no host-side read can tell the difference —
every read on flash is answered by the flash translation layer. The write's
duration can tell the difference, and this is the code that measures it.

Runs against files, not devices: the measurement is a ratio between two timed
writes, and a file exercises the same loop.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest
from core.erase import calibrate
from core.erase.calibrate import (
    ELISION_RATIO_THRESHOLD,
    CalibrationResult,
    calibrate_write,
    elision_finding,
    estimate_seconds,
)
from core.models import ResidualKind, Severity

MIB = 1024 * 1024
SECTOR = 512

# The hardware-validation measurement, as the probe would have recorded it.
MEASURED = CalibrationResult(
    elision_detected=True,
    zero_seconds=521.5,
    nonzero_seconds=1886.75,
    ratio=1886.75 / 521.5,
    sample_bytes=7759462400,
)


pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason=(
        "write-elision calibration measures O_DIRECT/O_SYNC writes to a block "
        "device, and is part of the Linux-only whole-drive engine"
    ),
)


def run_calibration(tmp_path: Path, durations: list[float]) -> CalibrationResult:
    """Drive calibrate_write with the two fill writes taking known times."""
    target = tmp_path / "target.img"
    target.write_bytes(b"\x00" * (8 * MIB))
    # _timed_fill brackets each write with two monotonic() calls.
    times = []
    running = 0.0
    for duration in durations:
        times.extend([running, running + duration])
        running += duration
    with mock.patch.object(calibrate.time, "monotonic", side_effect=times):
        return calibrate_write(
            str(target), size_bytes=8 * MIB, block_size=SECTOR, sample_bytes=4 * MIB
        )


# --------------------------------------------------------------------------
# The measurement
# --------------------------------------------------------------------------


def test_a_zero_fill_that_finishes_far_faster_is_elision(tmp_path: Path) -> None:
    result = run_calibration(tmp_path, [8.0, 2.0])  # non-zero, then zero

    assert result.elision_detected is True
    assert result.ratio == 4.0
    assert result.nonzero_seconds == 8.0
    assert result.zero_seconds == 2.0


def test_two_writes_at_the_same_rate_are_not_elision(tmp_path: Path) -> None:
    result = run_calibration(tmp_path, [4.0, 4.0])

    assert result.elision_detected is False
    assert result.ratio == 1.0


def test_the_threshold_is_inclusive(tmp_path: Path) -> None:
    result = run_calibration(tmp_path, [4.0, 2.0])

    assert result.ratio == ELISION_RATIO_THRESHOLD
    assert result.elision_detected is True


def test_a_device_too_small_to_sample_reports_unknown_not_false(
    tmp_path: Path,
) -> None:
    """"We could not find out" and "there is no elision" are different claims."""
    target = tmp_path / "tiny.img"
    target.write_bytes(b"")

    result = calibrate_write(str(target), size_bytes=0, block_size=SECTOR)

    assert result.elision_detected is None
    assert "too small" in result.unavailable_reason


def test_an_unopenable_target_reports_unknown_not_false(tmp_path: Path) -> None:
    result = calibrate_write(
        str(tmp_path / "nope.img"), size_bytes=8 * MIB, block_size=SECTOR
    )

    assert result.elision_detected is None
    assert "could not be opened" in result.unavailable_reason


def test_the_non_zero_fill_is_written_first(tmp_path: Path) -> None:
    """So the zero write cannot be skipped as a no-op against matching content.

    A device that already holds zeros would let a controller answer a zero write
    instantly for a reason that is not elision. Writing 0xA5 first removes it.
    """
    target = tmp_path / "target.img"
    target.write_bytes(b"\x00" * (8 * MIB))
    seen: list[int] = []
    real = calibrate._timed_fill

    def record(fd: int, offset: int, fill: int, span: int, block: int) -> float:
        seen.append(fill)
        return real(fd, offset, fill, span, block)

    with mock.patch.object(calibrate, "_timed_fill", record):
        calibrate_write(
            str(target), size_bytes=8 * MIB, block_size=SECTOR, sample_bytes=MIB
        )

    assert seen == [calibrate.NONZERO_FILL, calibrate.ZERO_FILL]


def test_both_fills_write_the_same_region(tmp_path: Path) -> None:
    """Same offset, so wear state and alignment are identical between them."""
    target = tmp_path / "target.img"
    target.write_bytes(b"\x00" * (8 * MIB))
    offsets: list[int] = []

    def record(fd: int, offset: int, fill: int, span: int, block: int) -> float:
        offsets.append(offset)
        return 1.0

    with mock.patch.object(calibrate, "_timed_fill", record):
        calibrate_write(
            str(target), size_bytes=8 * MIB, block_size=SECTOR, sample_bytes=MIB
        )

    assert offsets == [0, 0]


# --------------------------------------------------------------------------
# The detail has to survive canonicalisation
# --------------------------------------------------------------------------


def test_the_detail_holds_no_floats() -> None:
    """core.ledger.canon rejects floats, and this detail is ledgered."""
    detail = MEASURED.as_detail()

    floats = {key: value for key, value in detail.items() if isinstance(value, float)}
    assert floats == {}, f"floats would break the chain: {floats}"


def test_the_detail_carries_the_measurement_a_reader_needs() -> None:
    detail = MEASURED.as_detail()

    assert detail["zero_fill"] == "0x00"
    assert detail["nonzero_fill"] == "0xA5"
    assert detail["ratio_bp"] == 36179
    assert detail["threshold_bp"] == 20000
    assert detail["sample_bytes"] == 7759462400
    assert "MiB/s" in str(detail["summary"])


# --------------------------------------------------------------------------
# The finding
# --------------------------------------------------------------------------


def test_the_finding_is_high_and_not_addressable() -> None:
    finding = elision_finding(MEASURED, read_back_bytes_per_sec=41030000)

    assert finding.kind is ResidualKind.CONTROLLER_WRITE_ELISION
    assert finding.severity is Severity.HIGH
    assert finding.addressable is False


def test_the_finding_keeps_the_sentence_that_states_the_limit() -> None:
    """The one claim that must not be softened in a rewrite."""
    finding = elision_finding(MEASURED)

    assert (
        "that is all a host-side read can ever establish on flash"
        in finding.explanation
    )


def test_the_finding_carries_the_measured_ratio() -> None:
    finding = elision_finding(MEASURED, read_back_bytes_per_sec=41030000)

    assert "3.6x faster" in finding.explanation
    assert finding.detail["ratio_bp"] == 36179
    assert finding.detail["read_back_bytes_per_sec"] == 41030000


# --------------------------------------------------------------------------
# The ETA has to know which byte each pass writes
# --------------------------------------------------------------------------


def test_a_single_zero_pass_is_costed_at_the_zero_rate() -> None:
    seconds, basis = estimate_seconds((0x00,), 7759462400, MEASURED)

    assert seconds == 521
    assert "measured on this device" in basis


def test_a_single_non_zero_pass_is_costed_at_the_real_write_rate() -> None:
    seconds, _ = estimate_seconds((0xA5,), 7759462400, MEASURED)

    assert seconds == 1886


def test_three_passes_are_costed_per_byte_not_uniformly() -> None:
    """The 26-versus-49-minute gap that a uniform rate hides.

    Costing every DoD pass at the zero rate gives 3 x 521s = 26 minutes. Two of
    the three passes write a byte this controller actually programs.
    """
    uniform = 3 * 521
    measured, _ = estimate_seconds((0x00, 0xFF, 0x00), 7759462400, MEASURED)

    assert measured == 2929
    assert measured / 60 > 48
    assert measured > uniform * 1.8


def test_all_non_zero_passes_are_the_upper_bound() -> None:
    seconds, _ = estimate_seconds((0xA5, 0xFF, 0xA5), 7759462400, MEASURED)

    assert seconds == 5660
    assert seconds / 60 > 94


def test_no_calibration_gives_no_estimate_rather_than_a_guess() -> None:
    seconds, basis = estimate_seconds((0x00,), 7759462400, None)

    assert seconds == 0
    assert "no rate was measured" in basis


def test_an_unavailable_calibration_gives_no_estimate() -> None:
    unavailable = CalibrationResult(
        elision_detected=None,
        zero_seconds=0.0,
        nonzero_seconds=0.0,
        ratio=None,
        sample_bytes=0,
        unavailable_reason="too small",
    )

    seconds, _ = estimate_seconds((0x00,), 100, unavailable)

    assert seconds == 0
