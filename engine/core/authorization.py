"""What an erase authorization binds, and how a change to it is detected.

Pure functions, no I/O beyond ``stat`` on the backup image. They are shared by
the API, which opens and spends an authorization, and by the privileged helper,
which checks it again immediately before it writes. Two processes computing the
same comparison from the same code is the point: the helper does not trust the
API's verdict, it re-derives its own.

An authorization binds four things: the target's identity (path, serial, model,
size), the capability plan the operator approved, the backup image that was
verified, and a recorded human approval. It does not bind the device's contents
and it cannot prove the backup is a copy of the target.

Every authorization also has a ``kind`` (``erase``, ``restore``, ``hpa`` or
``format``); see :func:`kind_mismatch`. A record written before kinds existed
carries none and is an erase authorization. An approval of one kind is never
spendable as another.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

__all__ = [
    "AUTH_ID",
    "AUTH_KINDS",
    "authorization_kind",
    "backup_drift",
    "build_plan",
    "device_identity",
    "identity_drift",
    "image_drift",
    "kind_mismatch",
    "plan_drift",
    "stat_fingerprint",
]

#: The only shape of authorization id. Anything else names no record.
AUTH_ID = re.compile(r"^auth-[0-9a-f]{16}$")

#: What an authorization may authorize. One record authorizes one kind.
AUTH_KINDS = frozenset({"erase", "restore", "hpa", "format"})

_PLAN_LISTS = ("achievable_levels", "limitations", "blocking")


def authorization_kind(record: Mapping[str, Any]) -> str:
    """The kind a stored record authorizes.

    Records written before kinds existed carry no ``kind`` and were all erase
    authorizations, so a missing or empty kind reads as ``erase``. An unknown
    kind is returned as given, and matches no expected kind.
    """
    kind = record.get("kind")
    return "erase" if kind is None or kind == "" else str(kind)


def kind_mismatch(record: Mapping[str, Any], expected: str) -> list[str]:
    """One sentence if ``record`` does not authorize ``expected``. Empty if it does.

    An erase, a restore, an HPA change and a format each need their own
    authorization: all four change a device, and an approval of one is not an
    approval of another.
    """
    kind = authorization_kind(record)
    if kind == expected:
        return []
    article = "an" if expected[:1] in "aeiouh" else "a"
    noun = "HPA change" if expected == "hpa" else expected
    return [
        f"authorization {record.get('auth_id', '?')} is a {kind!r} authorization; "
        f"it cannot authorize {article} {noun}"
    ]


def device_identity(probe: dict[str, Any]) -> dict[str, Any]:
    """The fields that must not change between approval and execution."""
    device = probe.get("device", {})
    return {
        "path": str(device.get("path", "")),
        "serial": str(device.get("serial", "")),
        "model": str(device.get("model", "")),
        "size_bytes": int(device.get("size_bytes", 0) or 0),
    }


def build_plan(probe: dict[str, Any], level: str) -> dict[str, Any]:
    """The plan a person approves: what would run, decided by capability."""
    caps = probe.get("capabilities") or {}
    achievable = sorted(str(x) for x in caps.get("achievable_levels", []))
    return {
        "level": level,
        "achievable_levels": achievable,
        "estimated_seconds": caps.get("est_erase_seconds"),
        "limitations": list(caps.get("limitations", [])),
        "blocking": (
            []
            if level in achievable
            else [
                f"level {level} is not achievable on this device "
                f"(achievable: {achievable or 'none'})"
            ]
        ),
    }


def stat_fingerprint(path: Path) -> dict[str, int]:
    """Inode and change time of ``path``, which ``utime`` cannot restore.

    ``st_mtime_ns`` alone is settable by any process that can write the file, so
    a same-size in-place edit followed by restoring the mtime would look
    unchanged. ``st_ctime_ns`` is set by the kernel on every content or metadata
    change and cannot be set from user space; the inode changes on replacement.
    This detects modification *through the filesystem*. It is not a re-hash: the
    sha256 recorded at open is not recomputed at execution (a multi-terabyte
    image would block the request), and raw-device tampering below the
    filesystem is not detected.
    """
    stat = path.stat()
    return {"ctime_ns": stat.st_ctime_ns, "inode": stat.st_ino}


def identity_drift(recorded: dict[str, Any], now: dict[str, Any]) -> list[str]:
    """One sentence per identity field that differs from what was approved."""
    return [
        f"{key} changed since the backup and approval: recorded "
        f"{recorded.get(key)!r}, now {now.get(key)!r}"
        for key in ("path", "serial", "model", "size_bytes")
        if recorded.get(key) != now.get(key)
    ]


def plan_drift(recorded: dict[str, Any], now: dict[str, Any]) -> list[str]:
    """One sentence per plan list that differs from what was approved."""
    out: list[str] = []
    for key in _PLAN_LISTS:
        was, is_ = recorded.get(key), now.get(key)
        if key == "achievable_levels":
            was = sorted(was) if isinstance(was, list) else was
            is_ = sorted(is_) if isinstance(is_, list) else is_
        if was != is_:
            out.append(
                f"the plan's {key.replace('_', ' ')} changed since it was "
                "approved; open a new workflow"
            )
    return out


def backup_drift(backup: dict[str, Any], device_size: int) -> list[str]:
    """Reasons the backup is no longer the one that was verified. Empty if none.

    A record missing the inode or ctime (written before they were recorded) is
    refused, never assumed unchanged.
    """
    try:
        stat = Path(str(backup.get("path", ""))).stat()
    except OSError:
        return ["the verified backup image is no longer readable"]
    same = (
        stat.st_size == backup.get("size_bytes")
        and stat.st_mtime_ns == backup.get("mtime_ns")
        and stat.st_ctime_ns == backup.get("ctime_ns")
        and stat.st_ino == backup.get("inode")
        and stat.st_size >= device_size > 0
    )
    return (
        []
        if same
        else ["the verified backup image changed or no longer covers the device"]
    )


def image_drift(backup: Mapping[str, Any]) -> list[str]:
    """Reasons an image is no longer the one that was recorded. Empty if none.

    Size, mtime, ctime and inode, as :func:`backup_drift` compares them, without
    its requirement that the image cover a device: a restore image need only
    fit on its target, which the restore plan checks. A record missing any of
    the four is refused, never assumed unchanged.
    """
    try:
        stat = Path(str(backup.get("path", ""))).stat()
    except OSError:
        return ["the recorded backup image is no longer readable"]
    same = (
        stat.st_size == backup.get("size_bytes")
        and stat.st_mtime_ns == backup.get("mtime_ns")
        and stat.st_ctime_ns == backup.get("ctime_ns")
        and stat.st_ino == backup.get("inode")
    )
    return [] if same else ["the recorded backup image changed since it was planned"]
