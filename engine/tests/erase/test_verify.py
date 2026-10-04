"""Post-erase verification. Runs against regular files, never a real device."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from core.erase.verify import (
    VerifyConfig,
    choose_strategy,
    detection_probability,
    probability_statement,
    verify,
)
from core.models import Device, EraseMethod

from ..device.conftest import FakeRunner, ok

KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB


def device(size_bytes: int, **overrides: object) -> Device:
    base: dict[str, object] = {
        "path": "/dev/sdb",
        "model": "SYNTHETIC",
        "serial": "SYN-1",
        "size_bytes": size_bytes,
        "rotational": True,
        "transport": "sata",
        "is_system_disk": False,
        "mounted_at": [],
        "pt_type": None,
    }
    base.update(overrides)
    return Device.model_validate(base)


def make_image(tmp_path: Path, size: int, fill: int = 0x00) -> Path:
    path = tmp_path / "image.bin"
    path.write_bytes(bytes([fill]) * size)
    return path


SMALL = VerifyConfig(
    full_read_max_bytes=64 * KIB,
    edge_bytes=4 * KIB,
    sample_count=256,
    sample_bytes=4 * KIB,
    seed=1234,
)


# --------------------------------------------------------------------------
# full_read
# --------------------------------------------------------------------------


def test_zeroed_image_passes_full_read(tmp_path: Path) -> None:
    image = make_image(tmp_path, 64 * KIB)
    result = verify(
        device(64 * KIB),
        EraseMethod.SINGLE_PASS_OVERWRITE,
        source_path=image,
        config=SMALL,
    )
    assert result.strategy == "full_read"
    assert result.passed is True
    assert result.failed_offsets == []
    assert result.bytes_checked == 64 * KIB


def test_residual_data_fails_and_reports_the_exact_offset(tmp_path: Path) -> None:
    image = make_image(tmp_path, 64 * KIB)
    dirty_at = 20 * KIB
    with image.open("r+b") as handle:
        handle.seek(dirty_at)
        handle.write(b"\xaa" * (4 * KIB))

    result = verify(
        device(64 * KIB),
        EraseMethod.SINGLE_PASS_OVERWRITE,
        source_path=image,
        config=SMALL,
    )
    assert result.passed is False
    assert dirty_at in result.failed_offsets


def test_dod_expects_zeros_on_the_final_pass(tmp_path: Path) -> None:
    image = make_image(tmp_path, 32 * KIB)
    result = verify(
        device(32 * KIB),
        EraseMethod.DOD_5220_22_M_3PASS,
        source_path=image,
        config=SMALL,
    )
    assert result.passed is True


# --------------------------------------------------------------------------
# strategy selection
# --------------------------------------------------------------------------


def test_full_read_below_the_threshold() -> None:
    assert (
        choose_strategy(64 * GIB, EraseMethod.SINGLE_PASS_OVERWRITE) == "full_read"
    )


def test_sampled_above_the_threshold() -> None:
    assert (
        choose_strategy(64 * GIB + 1, EraseMethod.SINGLE_PASS_OVERWRITE) == "sampled"
    )


@pytest.mark.parametrize(
    "method",
    [
        EraseMethod.ATA_SANITIZE_BLOCK_ERASE,
        EraseMethod.NVME_SANITIZE_BLOCK,
        EraseMethod.SED_CRYPTO_ERASE,
        EraseMethod.ATA_SECURITY_ERASE_ENHANCED,
    ],
)
def test_firmware_methods_are_hardware_attested(method: EraseMethod) -> None:
    assert choose_strategy(1 * MIB, method) == "hw_attested"


# --------------------------------------------------------------------------
# sampling
# --------------------------------------------------------------------------


def test_sampled_strategy_records_its_seed(tmp_path: Path) -> None:
    image = make_image(tmp_path, 1 * MIB)
    result = verify(
        device(1 * MIB),
        EraseMethod.SINGLE_PASS_OVERWRITE,
        source_path=image,
        config=SMALL,
    )
    assert result.strategy == "sampled"
    assert result.sample_seed == SMALL.seed


def test_same_seed_draws_the_same_samples(tmp_path: Path) -> None:
    image = make_image(tmp_path, 1 * MIB)
    with image.open("r+b") as handle:
        handle.seek(512 * KIB)
        handle.write(b"\xaa" * (64 * KIB))

    runs = [
        verify(
            device(1 * MIB),
            EraseMethod.SINGLE_PASS_OVERWRITE,
            source_path=image,
            config=SMALL,
        ).failed_offsets
        for _ in range(2)
    ]
    assert runs[0] == runs[1]
    assert runs[0], "a 64 KiB dirty region should be hit by 256 samples"


def test_a_different_seed_draws_a_different_sample_set(tmp_path: Path) -> None:
    image = make_image(tmp_path, 1 * MIB)
    first = verify(
        device(1 * MIB),
        EraseMethod.SINGLE_PASS_OVERWRITE,
        source_path=image,
        config=SMALL,
    )
    second = verify(
        device(1 * MIB),
        EraseMethod.SINGLE_PASS_OVERWRITE,
        source_path=image,
        config=SMALL.with_seed(9999),
    )
    assert first.sample_seed != second.sample_seed


def test_sampling_always_reads_both_edges_in_full(tmp_path: Path) -> None:
    image = make_image(tmp_path, 1 * MIB)
    with image.open("r+b") as handle:
        handle.write(b"\xaa" * 512)  # first block, inside the leading edge
    result = verify(
        device(1 * MIB),
        EraseMethod.SINGLE_PASS_OVERWRITE,
        source_path=image,
        config=SMALL,
    )
    assert result.passed is False
    assert 0 in result.failed_offsets


def test_sampling_catches_dirt_in_the_trailing_edge(tmp_path: Path) -> None:
    size = 1 * MIB
    image = make_image(tmp_path, size)
    with image.open("r+b") as handle:
        handle.seek(size - 512)
        handle.write(b"\xaa" * 512)
    result = verify(
        device(size),
        EraseMethod.SINGLE_PASS_OVERWRITE,
        source_path=image,
        config=SMALL,
    )
    assert result.passed is False


# --------------------------------------------------------------------------
# detection probability
# --------------------------------------------------------------------------


def test_detection_probability_rises_with_more_draws() -> None:
    low = detection_probability(1 * GIB, 1 * MIB, sample_bytes=1 * MIB, draws=10)
    high = detection_probability(1 * GIB, 1 * MIB, sample_bytes=1 * MIB, draws=1000)
    assert 0.0 < low < high < 1.0


def test_detection_probability_is_certain_when_sampling_everything() -> None:
    assert detection_probability(
        1 * MIB, 1 * MIB, sample_bytes=1 * MIB, draws=1
    ) == pytest.approx(1.0)


def test_probability_statement_carries_the_formula_not_just_a_number() -> None:
    statement = probability_statement(
        total_bytes=1 * GIB, residual_bytes=1 * MIB, sample_bytes=1 * MIB, draws=4096
    )
    assert "1 - (1 - (r + u - 1) / n)^k" in statement
    assert "n=" in statement and "k=" in statement


def test_result_carries_the_probability_statement(tmp_path: Path) -> None:
    image = make_image(tmp_path, 1 * MIB)
    result = verify(
        device(1 * MIB),
        EraseMethod.SINGLE_PASS_OVERWRITE,
        source_path=image,
        config=SMALL,
    )
    assert "1 - (1 - (r + u - 1) / n)^k" in result.probability_note


# --------------------------------------------------------------------------
# hardware attestation
# --------------------------------------------------------------------------

ATA_SANITIZE_IDLE = "Sanitize status: Idle, last operation completed without error\n"
ATA_SANITIZE_FAILED = "Sanitize status: last operation failed\n"
NVME_SANITIZE_LOG_OK = '{"sstat": 257, "sprog": 65535}'
NVME_SANITIZE_LOG_FAILED = '{"sstat": 3, "sprog": 65535}'


def attest_io(stdout: str, *, nvme: bool = False) -> object:
    key = (
        ("nvme", "sanitize-log", "/dev/sdb", "-o", "json")
        if nvme
        else ("hdparm", "--sanitize-status", "/dev/sdb")
    )
    from core.device._sysio import SystemProbe

    return SystemProbe(runner=FakeRunner({key: ok(stdout)}))  # type: ignore[arg-type]


def test_hw_attested_also_samples_the_medium(tmp_path: Path) -> None:
    image = make_image(tmp_path, 1 * MIB)
    result = verify(
        device(1 * MIB),
        EraseMethod.ATA_SANITIZE_BLOCK_ERASE,
        source_path=image,
        config=SMALL,
        io=attest_io(ATA_SANITIZE_IDLE),  # type: ignore[arg-type]
    )
    assert result.strategy == "hw_attested"
    assert result.passed is True
    assert result.bytes_checked > 0, "attestation alone is not verification"


def test_hw_attestation_failure_fails_verification(tmp_path: Path) -> None:
    image = make_image(tmp_path, 1 * MIB)
    result = verify(
        device(1 * MIB),
        EraseMethod.ATA_SANITIZE_BLOCK_ERASE,
        source_path=image,
        config=SMALL,
        io=attest_io(ATA_SANITIZE_FAILED),  # type: ignore[arg-type]
    )
    assert result.passed is False


def test_clean_attestation_does_not_excuse_residual_data(tmp_path: Path) -> None:
    image = make_image(tmp_path, 1 * MIB)
    with image.open("r+b") as handle:
        handle.write(b"\xaa" * 512)
    result = verify(
        device(1 * MIB),
        EraseMethod.ATA_SANITIZE_BLOCK_ERASE,
        source_path=image,
        config=SMALL,
        io=attest_io(ATA_SANITIZE_IDLE),  # type: ignore[arg-type]
    )
    assert result.passed is False


def test_nvme_sanitize_log_is_read_for_attestation(tmp_path: Path) -> None:
    image = make_image(tmp_path, 1 * MIB)
    result = verify(
        device(1 * MIB, transport="nvme"),
        EraseMethod.NVME_SANITIZE_BLOCK,
        source_path=image,
        config=SMALL,
        io=attest_io(NVME_SANITIZE_LOG_OK, nvme=True),  # type: ignore[arg-type]
    )
    assert result.passed is True


def test_nvme_sanitize_log_failure_fails_verification(tmp_path: Path) -> None:
    image = make_image(tmp_path, 1 * MIB)
    result = verify(
        device(1 * MIB, transport="nvme"),
        EraseMethod.NVME_SANITIZE_BLOCK,
        source_path=image,
        config=SMALL,
        io=attest_io(NVME_SANITIZE_LOG_FAILED, nvme=True),  # type: ignore[arg-type]
    )
    assert result.passed is False


# --------------------------------------------------------------------------
# read-only guarantee
# --------------------------------------------------------------------------


def test_verification_never_opens_the_device_for_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = make_image(tmp_path, 64 * KIB)
    seen: list[int] = []
    real_open = os.open

    def recording_open(path: object, flags: int, *args: object) -> int:
        seen.append(flags)
        return real_open(path, flags, *args)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", recording_open)
    verify(
        device(64 * KIB),
        EraseMethod.SINGLE_PASS_OVERWRITE,
        source_path=image,
        config=SMALL,
    )

    assert seen, "verify must open the medium"
    write_flags = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC
    for flags in seen:
        assert flags & write_flags == 0, f"opened with write flags: {flags:#o}"
