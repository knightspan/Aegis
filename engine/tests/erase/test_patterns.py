"""Overwrite pattern generation. Pure functions, no I/O."""

from __future__ import annotations

import pytest
from core.erase.patterns import final_pattern, pass_count, pattern_passes
from core.errors import UnsupportedCapability
from core.models import EraseMethod

BLOCK = 4096


def test_single_pass_yields_one_zero_filled_block() -> None:
    passes = list(pattern_passes(EraseMethod.SINGLE_PASS_OVERWRITE, block_size=BLOCK))
    assert len(passes) == 1
    assert passes[0] == b"\x00" * BLOCK


def test_dod_yields_three_passes_char_complement_char() -> None:
    passes = list(pattern_passes(EraseMethod.DOD_5220_22_M_3PASS, block_size=BLOCK))
    assert [bytes({p[0]}) for p in passes] == [b"\x00", b"\xff", b"\x00"]
    assert all(len(p) == BLOCK for p in passes)


def test_pass_count_matches_generated_passes() -> None:
    for method in (
        EraseMethod.SINGLE_PASS_OVERWRITE,
        EraseMethod.DOD_5220_22_M_3PASS,
    ):
        generated = list(pattern_passes(method, block_size=BLOCK))
        assert pass_count(method) == len(generated)


def test_final_pattern_is_zeros_for_both_software_methods() -> None:
    for method in (
        EraseMethod.SINGLE_PASS_OVERWRITE,
        EraseMethod.DOD_5220_22_M_3PASS,
    ):
        assert final_pattern(method, block_size=BLOCK) == b"\x00" * BLOCK


def test_final_pattern_matches_the_last_generated_pass() -> None:
    method = EraseMethod.DOD_5220_22_M_3PASS
    last = list(pattern_passes(method, block_size=BLOCK))[-1]
    assert final_pattern(method, block_size=BLOCK) == last


@pytest.mark.parametrize(
    "method",
    [
        EraseMethod.ATA_SANITIZE_BLOCK_ERASE,
        EraseMethod.ATA_SANITIZE_OVERWRITE,
        EraseMethod.ATA_SANITIZE_CRYPTO_SCRAMBLE,
        EraseMethod.ATA_SECURITY_ERASE_ENHANCED,
        EraseMethod.NVME_SANITIZE_BLOCK,
        EraseMethod.NVME_FORMAT_SES1,
        EraseMethod.SED_CRYPTO_ERASE,
    ],
)
def test_firmware_methods_stream_no_patterns(method: EraseMethod) -> None:
    with pytest.raises(UnsupportedCapability):
        list(pattern_passes(method, block_size=BLOCK))


@pytest.mark.parametrize("bad", [0, -1, -4096])
def test_block_size_must_be_positive(bad: int) -> None:
    with pytest.raises(ValueError, match="block_size"):
        list(pattern_passes(EraseMethod.SINGLE_PASS_OVERWRITE, block_size=bad))


def test_passes_are_independent_buffers() -> None:
    first, second, _ = pattern_passes(EraseMethod.DOD_5220_22_M_3PASS, block_size=BLOCK)
    assert first is not second
