"""Fixtures for the erase suite.

Three tiers, so as much as possible still runs on a plain unprivileged box:

* Anywhere: the platform gate.
* Linux, no root: the overwrite loop and verification, driven against a regular
  file used as the medium.
* Linux + root: end-to-end ``execute`` against a real loopback block device.

No test touches real hardware.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from core.models import Device, DeviceCapabilities, EraseJob, SanitizationLevel

MIB = 1024 * 1024

LINUX_ONLY = pytest.mark.skipif(
    sys.platform != "linux",
    reason="core.erase.drive is Linux-only by design (O_DIRECT, BLKGETSIZE64)",
)


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


ROOT_ONLY = pytest.mark.skipif(
    not (sys.platform == "linux" and _is_root()),
    reason="needs Linux and root to create a loopback device with losetup",
)


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 * MIB), b""):
            digest.update(chunk)
    return digest.hexdigest()


@pytest.fixture
def backing_file(tmp_path: Path) -> Path:
    """A 64 MiB regular file filled with 0xAA, standing in for a medium."""
    path = tmp_path / "medium.img"
    path.write_bytes(b"\xaa" * (64 * MIB))
    return path


@pytest.fixture
def loop_device(tmp_path: Path) -> Iterator[str]:
    """A real 64 MiB loopback block device, released on teardown."""
    if sys.platform != "linux" or not _is_root():
        pytest.skip("needs Linux and root to run losetup")
    backing = tmp_path / "loop.img"
    backing.write_bytes(b"\xaa" * (64 * MIB))
    created = subprocess.run(
        ["losetup", "--find", "--show", str(backing)],
        capture_output=True,
        text=True,
        check=False,
    )
    if created.returncode != 0:
        pytest.skip(f"losetup unavailable: {created.stderr.strip()}")
    path = created.stdout.strip()
    try:
        yield path
    finally:
        subprocess.run(["losetup", "-d", path], check=False, capture_output=True)


def make_device(**overrides: object) -> Device:
    base: dict[str, object] = {
        "path": "/dev/sdb",
        "model": "SYNTHETIC",
        "serial": "SYN-0001",
        "size_bytes": 64 * MIB,
        "rotational": True,
        "transport": "sata",
        "is_system_disk": False,
        "mounted_at": [],
        "pt_type": None,
        "by_id_path": "/dev/disk/by-id/ata-SYNTHETIC_SYN-0001",
    }
    base.update(overrides)
    return Device.model_validate(base)


def make_caps(**overrides: object) -> DeviceCapabilities:
    base: dict[str, object] = {
        "ata_security_erase": False,
        "ata_enhanced_erase": False,
        "ata_sanitize_ops": [],
        "nvme_sanicap": {},
        "is_sed_opal": False,
        "security_frozen": False,
        "est_erase_seconds": 60,
        "achievable_levels": {SanitizationLevel.CLEAR},
        "limitations": [],
    }
    base.update(overrides)
    return DeviceCapabilities.model_validate(base)


def make_job(device: Device, **overrides: object) -> EraseJob:
    base: dict[str, object] = {
        "job_id": "job-0001",
        "device": device,
        "level": SanitizationLevel.CLEAR,
        "confirmed_serial": device.serial,
        "method": None,
    }
    base.update(overrides)
    return EraseJob.model_validate(base)
