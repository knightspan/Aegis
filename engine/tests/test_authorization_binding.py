"""core.authorization: every bound field, one at a time.

The API gate and the helper's write-seam check both call these comparisons, so
a field they miss is missed twice. Each case changes exactly one field of an
otherwise identical record and expects exactly one reason back. Changing the
record rather than the file is what isolates a field: a real edit moves ctime
along with whatever else it changed, and nothing in user space can move only
the inode.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from core.authorization import (
    backup_drift,
    build_plan,
    device_identity,
    identity_drift,
    plan_drift,
    stat_fingerprint,
)

SIZE = 4096


@pytest.fixture
def backup(tmp_path: Path) -> dict[str, Any]:
    """The record the API writes when it verifies an image, for a real file."""
    image = tmp_path / "backup.img"
    image.write_bytes(b"\0" * SIZE)
    stat = image.stat()
    return {
        "path": str(image),
        "sha256": "0" * 64,
        "size_bytes": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        **stat_fingerprint(image),
    }


def test_an_unchanged_backup_has_no_drift(backup: dict[str, Any]) -> None:
    assert backup_drift(backup, SIZE) == []


@pytest.mark.parametrize("field", ["size_bytes", "mtime_ns", "ctime_ns", "inode"])
def test_each_backup_field_is_bound_on_its_own(
    backup: dict[str, Any], field: str
) -> None:
    assert len(backup_drift({**backup, field: backup[field] + 1}, SIZE)) == 1


@pytest.mark.parametrize("field", ["ctime_ns", "inode"])
def test_a_record_without_a_fingerprint_field_fails_closed(
    backup: dict[str, Any], field: str
) -> None:
    """Written before the field existed: refused, never assumed unchanged."""
    assert backup_drift({k: v for k, v in backup.items() if k != field}, SIZE)


def test_a_backup_that_no_longer_covers_the_device_is_drift(
    backup: dict[str, Any],
) -> None:
    assert backup_drift(backup, SIZE + 1)
    assert backup_drift(backup, 0), "a zero-size device is not covered by anything"


def test_a_backup_that_is_gone_is_named_as_unreadable(
    backup: dict[str, Any],
) -> None:
    Path(backup["path"]).unlink()
    assert backup_drift(backup, SIZE) == [
        "the verified backup image is no longer readable"
    ]


PROBE: dict[str, Any] = {
    "device": {
        "path": "/dev/sdz",
        "serial": "SYN-1",
        "model": "SYNTHETIC",
        "size_bytes": 1 << 20,
    },
    "capabilities": {
        "achievable_levels": ["CLEAR", "PURGE"],
        "limitations": ["a known limit"],
        "est_erase_seconds": 5,
    },
}


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("path", "/dev/sdy"),
        ("serial", "OTHER"),
        ("model", "OTHER"),
        ("size_bytes", 2 << 20),
    ],
)
def test_each_identity_field_is_bound_on_its_own(key: str, value: Any) -> None:
    recorded = device_identity(PROBE)
    now = {**recorded, key: value}
    reasons = identity_drift(recorded, now)
    assert len(reasons) == 1 and reasons[0].startswith(key)
    assert identity_drift(recorded, dict(recorded)) == []


@pytest.mark.parametrize(
    ("change", "named"),
    [
        ({"achievable_levels": ["CLEAR"]}, "achievable levels"),
        ({"limitations": []}, "limitations"),
    ],
)
def test_each_plan_list_is_bound_on_its_own(change: dict[str, Any], named: str) -> None:
    recorded = build_plan(PROBE, "CLEAR")
    now = build_plan(
        {**PROBE, "capabilities": {**PROBE["capabilities"], **change}}, "CLEAR"
    )
    reasons = plan_drift(recorded, now)
    assert len(reasons) == 1 and named in reasons[0]


def test_a_level_that_becomes_unreachable_changes_the_blocking_list() -> None:
    recorded = build_plan(PROBE, "PURGE")
    now = build_plan(
        {
            **PROBE,
            "capabilities": {**PROBE["capabilities"], "achievable_levels": ["CLEAR"]},
        },
        "PURGE",
    )
    assert now["blocking"] and not recorded["blocking"]
    assert any("blocking" in reason for reason in plan_drift(recorded, now))


def test_the_order_levels_are_reported_in_is_not_drift() -> None:
    recorded = build_plan(PROBE, "CLEAR")
    reordered = {**PROBE["capabilities"], "achievable_levels": ["PURGE", "CLEAR"]}
    assert (
        plan_drift(recorded, build_plan({**PROBE, "capabilities": reordered}, "CLEAR"))
        == []
    )
