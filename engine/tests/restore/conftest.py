"""Fixtures for the backup and restore suite. Synthetic files only.

Every image and every target is a regular file under ``tmp_path``. A "device"
is a dict shaped like the helper's probe answer; nothing here opens a device
node, and the host-device guard in tests/conftest.py would refuse it if it did.
"""

from __future__ import annotations

import json
from collections.abc import Generator
from pathlib import Path
from typing import Any, TypeVar

import pytest
from core.authorization import device_identity, stat_fingerprint
from core.backup import BackupRecord, SourceIdentity, create_backup_record
from core.ledger.chain import Ledger
from core.models import Progress
from core.restore import RestorePlan

KIB = 1024
#: Small chunks so a test image spans several, and a multiple of 4096.
CHUNK = 64 * KIB
#: Three whole chunks and a partial one; sector aligned (512 and 4096).
IMAGE_SIZE = 3 * CHUNK + 8 * KIB
TARGET_SIZE = 4 * CHUNK + 16 * KIB

T = TypeVar("T")


def drain(generator: Generator[Progress, None, T]) -> tuple[list[Progress], T]:
    """Run a progress generator to the end: its records and its return value."""
    seen: list[Progress] = []
    while True:
        try:
            seen.append(next(generator))
        except StopIteration as stop:
            return seen, stop.value


def image_bytes(size: int = IMAGE_SIZE) -> bytes:
    """Deterministic, chunk-distinct content."""
    return bytes((index * 7 + index // 4096) % 251 for index in range(size))


def device_probe(**over: Any) -> dict[str, Any]:
    device: dict[str, Any] = {
        "path": "/dev/fake-target",
        "model": "SYNTHETIC-TARGET",
        "serial": "TGT-1",
        "size_bytes": TARGET_SIZE,
        "rotational": True,
        "transport": "sata",
        "is_system_disk": False,
        "mounted_at": [],
        "pt_type": None,
        "by_id_path": None,
    }
    device.update(over)
    return {"device": device}


@pytest.fixture
def source() -> SourceIdentity:
    return SourceIdentity(
        path="/dev/fake-source",
        serial="SRC-1",
        model="SYNTHETIC-SOURCE",
        size_bytes=IMAGE_SIZE,
    )


@pytest.fixture
def image(tmp_path: Path) -> Path:
    path = tmp_path / "evidence" / "backup.img"
    path.parent.mkdir()
    path.write_bytes(image_bytes())
    return path


@pytest.fixture
def record(image: Path, source: SourceIdentity) -> BackupRecord:
    _, made = drain(create_backup_record(image, source, chunk_bytes=CHUNK))
    return made


@pytest.fixture
def ledger(tmp_path: Path) -> Ledger:
    return Ledger(tmp_path / "ledger", tool_version="test", pubkey_fingerprint="")


def operations(ledger: Ledger) -> list[str]:
    return [entry.operation for entry in ledger.entries()]


def params_for(ledger: Ledger, operation: str) -> list[dict[str, Any]]:
    return [
        ledger.params_of(entry)
        for entry in ledger.entries()
        if entry.operation == operation
    ]


def make_restore_authorization(
    tmp_path: Path,
    record: BackupRecord,
    plan: RestorePlan,
    probe: dict[str, Any],
    *,
    approved: bool = True,
    spent: bool = True,
    auth_id: str = "auth-00000000000000aa",
) -> dict[str, Any]:
    """Write what the API leaves behind after open, approve and spend."""
    root = tmp_path / "authorizations"
    root.mkdir(parents=True, exist_ok=True)
    image = Path(record.image_path)
    stat = image.stat()
    stored = {
        "auth_id": auth_id,
        "kind": "restore",
        "path": plan.target.path,
        "level": "RESTORE",
        "device": device_identity(probe),
        "backup": {
            "backup_id": record.backup_id,
            "record": record.model_dump(mode="json"),
            "path": str(image),
            "sha256": record.image_sha256,
            "size_bytes": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
            **stat_fingerprint(image),
        },
        "plan": plan.model_dump(mode="json"),
        "opened_by": "test",
        "opened_at": "now",
        "approved_by": "test-approver" if approved else "",
        "approved_at": "now" if approved else "",
        "consumed_at": "",
    }
    (root / f"{auth_id}.json").write_text(json.dumps(stored), encoding="utf-8")
    if spent:
        (root / f"{auth_id}.spent").write_text("x", encoding="utf-8")
    return {
        "path": plan.target.path,
        "authorization": {
            key: stored[key]
            for key in ("auth_id", "kind", "path", "device", "backup", "plan")
        },
        "authorization_dir": str(root),
    }
