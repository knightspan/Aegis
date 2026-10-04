"""The harness's Phase A.2 pattern writer.

It replaced ``tr '\\0' '\\245' < /dev/zero | dd of=$DEVICE bs=4M``. dd reading
from a pipe with no ``iflag=fullblock`` never assembled a full block: on the
validation host 200 reads produced 200 partial records averaging 7414 bytes,
and filling a 7.76 GB stick took 1899.76s - 4.08 MB/s where the same device
reads at 26.7 MB/s. That number was headed for the performance report.

No device here: ``device_geometry`` is replaced and the target is a file.
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
SECTOR = 512
MIB = 1024 * 1024


@pytest.fixture(scope="module")
def harness() -> ModuleType:
    """Import ``scripts/hardware_validation.py``, which is not on the path."""
    spec = importlib.util.spec_from_file_location(
        "hardware_validation", REPO / "scripts" / "hardware_validation.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["hardware_validation"] = module
    spec.loader.exec_module(module)
    return module


def write_pattern(
    harness: ModuleType, target: Path, size: int, capsys: Any, byte: str = "0xA5"
) -> dict[str, Any]:
    from core.erase.drive import Geometry

    target.write_bytes(b"\x00" * size)
    args = mock.Mock(device=str(target), byte=byte)
    geometry = Geometry(
        size_bytes=size, logical_block_size=SECTOR, physical_block_size=SECTOR
    )
    with mock.patch("core.erase.drive.device_geometry", return_value=geometry):
        code = harness.cmd_pattern(args)
    payload: dict[str, Any] = json.loads(capsys.readouterr().out)
    payload["exit_code"] = code
    return payload


def test_the_whole_device_is_filled_with_the_pattern_byte(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    target = tmp_path / "target.img"

    result = write_pattern(harness, target, 2 * MIB, capsys)

    assert result["exit_code"] == 0
    assert result["complete"] is True
    assert result["bytes_written"] == 2 * MIB
    assert set(target.read_bytes()) == {0xA5}


def test_the_buffer_matches_the_erase_path(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    """The point of the fix: one aligned 4 MiB buffer, not 7 KiB dribbles.

    Comparing a pattern-write throughput against an erase throughput only means
    something if both writes are shaped the same way.
    """
    from core.erase.drive import DEFAULT_BUFFER_BYTES

    result = write_pattern(harness, tmp_path / "target.img", 8 * MIB, capsys)

    assert result["buffer_bytes"] == DEFAULT_BUFFER_BYTES
    assert result["block_size"] == SECTOR
    assert result["buffer_bytes"] % result["block_size"] == 0


def test_a_size_that_is_not_a_whole_buffer_still_finishes(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    target = tmp_path / "target.img"
    size = 4 * MIB + 3 * SECTOR

    result = write_pattern(harness, target, size, capsys)

    assert result["bytes_written"] == size
    assert set(target.read_bytes()) == {0xA5}


def test_the_fill_byte_is_selectable(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    target = tmp_path / "target.img"

    result = write_pattern(harness, target, SECTOR * 8, capsys, byte="0x5a")

    assert result["byte"] == "0x5a"
    assert set(target.read_bytes()) == {0x5A}


def test_a_byte_outside_a_byte_is_refused(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    with pytest.raises(ValueError, match="single byte"):
        write_pattern(harness, tmp_path / "target.img", SECTOR, capsys, byte="0x1ff")


def test_throughput_is_reported_so_the_write_up_has_a_comparable_number(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    result = write_pattern(harness, tmp_path / "target.img", MIB, capsys)

    assert result["elapsed_seconds"] >= 0
    assert result["throughput_mib_per_sec"] > 0
    assert "o_direct" in result, (
        "the report must say whether the page cache was bypassed"
    )


# --------------------------------------------------------------------------
# The pipeline it replaced must not come back
# --------------------------------------------------------------------------


def test_the_driver_no_longer_pipes_tr_into_dd() -> None:
    text = (REPO / "scripts" / "hardware-validation.sh").read_text()

    assert "tr '\\0'" not in text
    assert 'hardware_validation.py" pattern' in text
