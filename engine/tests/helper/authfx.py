"""Synthetic authorization records for tests that reach the helper's write seam.

Builds exactly what the API leaves behind after open, approve and spend: a
record file, the ``.spent`` marker, a backup image, and the binding the helper
is handed. Nothing here touches a device; the fresh device read the helper does
at the seam is replaced with :func:`patch_probe`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from core.authorization import (
    build_plan,
    device_identity,
    stat_fingerprint,
)

CAPS: dict[str, Any] = {
    "achievable_levels": ["CLEAR", "PURGE"],
    "limitations": [],
    "est_erase_seconds": 5,
}
AUTH_ID = "auth-0123456789abcdef"


def probe_of(device: Any, caps: dict[str, Any] | None = CAPS) -> dict[str, Any]:
    return {"device": device.model_dump(mode="json"), "capabilities": caps}


def patch_probe(
    monkeypatch: pytest.MonkeyPatch, device: Any, caps: dict[str, Any] | None = CAPS
) -> None:
    """Make the helper's write-seam re-read answer from ``device``."""
    monkeypatch.setattr(
        "helper.authorization._fresh_probe", lambda path: probe_of(device, caps)
    )


def make_authorization(
    tmp_path: Path,
    device: Any,
    *,
    level: str = "CLEAR",
    approved: bool = True,
    spent: bool = True,
    auth_id: str = AUTH_ID,
) -> dict[str, Any]:
    """Write the record and return the request parameters that carry it."""
    root = tmp_path / "authorizations"
    root.mkdir(parents=True, exist_ok=True)
    image = tmp_path / "backup.img"
    with image.open("wb") as handle:
        handle.truncate(max(int(device.size_bytes), 1))
    stat = image.stat()
    backup = {
        "path": str(image),
        "sha256": "0" * 64,
        "size_bytes": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        **stat_fingerprint(image),
    }
    probe = probe_of(device)
    record = {
        "auth_id": auth_id,
        "path": device.path,
        "level": level,
        "device": device_identity(probe),
        "backup": backup,
        "plan": build_plan(probe, level),
        "opened_by": "test",
        "opened_at": "now",
        "approved_by": "test-approver" if approved else "",
        "approved_at": "now" if approved else "",
        "consumed_at": "",
    }
    (root / f"{auth_id}.json").write_text(json.dumps(record), encoding="utf-8")
    if spent:
        (root / f"{auth_id}.spent").write_text("x", encoding="utf-8")
    return {
        "authorization": {
            key: record[key]
            for key in ("auth_id", "path", "level", "device", "backup", "plan")
        },
        "authorization_dir": str(root),
    }
