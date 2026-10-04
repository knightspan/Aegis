"""``hardware_validation.py verify --expect-fill``.

Verification compares the medium against the pattern the erase wrote. On a
controller that does not program zeros the erase writes ``0xA5``, so checking
the method's default ``0x00`` would fail a good wipe — and on such a controller
``0x00`` is the one value the flash translation layer can answer for free, which
makes it the worst thing to check against.

It is also what makes a power-cycle check possible without re-running a phase:
unplug, replug, verify the medium still holds what the erase wrote.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest import mock

import pytest

REPO = Path(__file__).resolve().parents[2]
MIB = 1024 * 1024
SECTOR = 512


@pytest.fixture(scope="module")
def harness() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "hardware_validation_verify", REPO / "scripts" / "hardware_validation.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["hardware_validation_verify"] = module
    spec.loader.exec_module(module)
    return module


def run_verify(
    harness: ModuleType,
    target: Path,
    capsys: Any,
    *,
    expect_fill: str | None,
    method: str = "SINGLE_PASS_OVERWRITE",
) -> dict[str, Any]:
    """Drive cmd_verify against a file standing in for the device."""
    from core.models import Device

    device = Device.model_validate(
        {
            "path": str(target),
            "model": "TransMemory",
            "serial": "SYN-0001",
            "size_bytes": target.stat().st_size,
            "rotational": True,
            "transport": "usb",
            "is_system_disk": False,
            "mounted_at": [],
            "pt_type": None,
        }
    )
    args = mock.Mock(
        device=str(target),
        method=method,
        full_read_max=64 * MIB,
        expect_fill=expect_fill,
    )
    with mock.patch(
        "core.device.enumerate.get_device", return_value=device
    ):
        code = harness.cmd_verify(args)
    payload: dict[str, Any] = json.loads(capsys.readouterr().out)
    payload["exit_code"] = code
    return payload


def write(target: Path, fill: int, size: int = 2 * MIB) -> Path:
    target.write_bytes(bytes([fill]) * size)
    return target


def test_a_device_holding_the_expected_fill_passes(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    target = write(tmp_path / "dev.img", 0xA5)

    result = run_verify(harness, target, capsys, expect_fill="0xA5")

    assert result["result"]["passed"] is True
    assert result["result"]["failed_offsets"] == []
    assert result["expected_fill"] == "0xA5"
    assert result["expected_fill_source"] == "--expect-fill"


def test_a_device_holding_zeros_fails_an_expected_a5(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    """The power-cycle failure mode: the pattern did not survive."""
    target = write(tmp_path / "dev.img", 0x00)

    result = run_verify(harness, target, capsys, expect_fill="0xA5")

    assert result["result"]["passed"] is False
    assert result["result"]["failed_offsets"]


def test_without_the_flag_the_method_s_default_is_used(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    target = write(tmp_path / "dev.img", 0x00)

    result = run_verify(harness, target, capsys, expect_fill=None)

    assert result["result"]["passed"] is True
    assert result["expected_fill"] == "0x00"
    assert result["expected_fill_source"] == "the method's default"


def test_the_default_would_have_failed_the_wipe_this_flag_exists_for(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    """A correctly wiped elision-prone device holds 0xA5, not zeros."""
    target = write(tmp_path / "dev.img", 0xA5)

    without = run_verify(harness, target, capsys, expect_fill=None)
    with_flag = run_verify(harness, target, capsys, expect_fill="0xA5")

    assert without["result"]["passed"] is False
    assert with_flag["result"]["passed"] is True


def test_a_decimal_fill_is_accepted(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    target = write(tmp_path / "dev.img", 0xA5)

    result = run_verify(harness, target, capsys, expect_fill="165")

    assert result["expected_fill"] == "0xA5"
    assert result["result"]["passed"] is True


def test_a_value_outside_a_byte_is_refused(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    target = write(tmp_path / "dev.img", 0xA5)

    with pytest.raises(ValueError, match="single byte"):
        run_verify(harness, target, capsys, expect_fill="0x1FF")


def test_a_failed_verification_still_exits_zero(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    """This script's contract: a disappointing measurement is a finding.

    The caller reads ``.result.passed``. Exiting non-zero here would make a
    measured result indistinguishable from a step that could not run.
    """
    target = write(tmp_path / "dev.img", 0x00)

    result = run_verify(harness, target, capsys, expect_fill="0xA5")

    assert result["result"]["passed"] is False
    assert result["exit_code"] == 0


def test_the_result_says_what_it_compared_against(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    """A verdict without its expected pattern cannot be read afterwards."""
    target = write(tmp_path / "dev.img", 0xA5)

    result = run_verify(harness, target, capsys, expect_fill="0xA5")

    assert result["method"] == "SINGLE_PASS_OVERWRITE"
    assert result["expected_fill"] == "0xA5"
    assert result["result"]["bytes_checked"] == 2 * MIB
    assert result["result"]["strategy"] == "full_read"
