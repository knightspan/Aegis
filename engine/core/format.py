"""Make an erased device usable again: one partition table, one filesystem.

A sanitization leaves a device with nothing on it, which an operating system
reads as unformatted. This module writes the smallest thing that fixes that:
an MS-DOS partition table with a single partition spanning the device, and one
filesystem (exFAT, FAT32 or ext4) on it. It is a destructive operation on the
target and is gated like an erase, a restore or an HPA change: a recorded human
approval, the serial typed by hand and re-checked by the process that writes,
and a single-use authorization. Those gates live in :mod:`api.routes.format`
and :mod:`helper.authorization`; this module is the engine they guard, and it
refuses on its own too.

What it guarantees
------------------
* A ledger entry is appended before the first write and another when the run
  ends, whether it succeeded or failed.
* After the filesystem is made, the partition is probed and the filesystem type
  and label are compared with what was asked for; a difference is reported as
  not verified, never as success.

What it does not guarantee
--------------------------
* It does not sanitize. It writes filesystem metadata to a few sectors and
  leaves every other block as the erase left it. A sanitization certificate
  describes the device as it was when the erase's read-back finished, before
  this step.
* It is implemented for Linux only. Windows and macOS refuse with the
  platform's reason and no command runs.
* A step that fails after the first write can leave the device with no
  partition table; the failure says which step and says so.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
from collections.abc import Callable, Generator
from typing import Any, Literal, Protocol

import structlog
from pydantic import BaseModel, Field

from core.errors import FormatFailed, PlatformUnsupported
from core.models import Device, Progress

__all__ = [
    "CommandResult",
    "FILESYSTEMS",
    "FormatPlan",
    "FormatResult",
    "execute_format",
    "partition_path",
    "plan_digest_of",
    "plan_format",
    "run_command",
]

logger = structlog.get_logger(__name__)

Filesystem = Literal["exfat", "fat32", "ext4"]

#: filesystem -> (sfdisk partition type, longest label, blkid TYPE, mkfs program)
FILESYSTEMS: dict[str, tuple[str, int, str, str]] = {
    "exfat": ("7", 15, "exfat", "mkfs.exfat"),
    "fat32": ("c", 11, "vfat", "mkfs.vfat"),
    "ext4": ("83", 16, "ext4", "mkfs.ext4"),
}

_LABEL = re.compile(r"^[A-Za-z0-9_ -]*$")
_STDERR_TAIL = 500

_LIMITATION_NOT_A_SANITIZE = (
    "Formatting writes a partition table and filesystem metadata to a few "
    "sectors. It does not sanitize anything; every other block is as the erase "
    "left it. A sanitization certificate describes the device at the end of the "
    "erase, before this step."
)


class CommandResult(BaseModel):
    """What one external command returned."""

    returncode: int
    stdout: str
    stderr: str

    def __init__(self, returncode: int, stdout: str, stderr: str) -> None:
        super().__init__(returncode=returncode, stdout=stdout, stderr=stderr)


class Runner(Protocol):
    def __call__(self, argv: list[str], stdin: str | None = None) -> CommandResult: ...


class _Ledger(Protocol):
    def append(
        self,
        *,
        actor: str,
        operation: str,
        params: dict[str, Any],
        result: dict[str, Any],
    ) -> Any: ...


def run_command(argv: list[str], stdin: str | None = None) -> CommandResult:
    """Run one program with an argument list and no shell."""
    done = subprocess.run(  # noqa: S603 - argv list, never a shell string
        argv, input=stdin, capture_output=True, text=True, check=False, timeout=300
    )
    return CommandResult(done.returncode, done.stdout, done.stderr)


class FormatPlan(BaseModel):
    """What a person approves: which device, which filesystem, which label."""

    path: str
    serial: str
    model: str
    size_bytes: int
    filesystem: str
    label: str
    table: str = "dos"
    #: The erase job this format follows; part of what an approval covers.
    follows_job: str = ""
    blocking: list[str] = Field(default_factory=list)
    plan_digest: str = ""


class FormatResult(BaseModel):
    """How a format ended and what the read-back found."""

    path: str
    partition_path: str
    filesystem: str
    label: str
    observed_fstype: str
    observed_label: str
    verified: bool
    limitations: list[str]


def plan_digest_of(plan: FormatPlan) -> str:
    """SHA-256 over the fields an approval covers; the digest itself is excluded."""
    body = plan.model_dump(mode="json", exclude={"plan_digest"})
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def plan_format(
    device: Device, filesystem: str, label: str, follows_job: str = ""
) -> FormatPlan:
    """Plan one format of ``device``, listing every reason it may not run."""
    blocking: list[str] = []
    if device.is_system_disk:
        blocking.append(f"{device.path} hosts the running system")
    if device.mounted_at:
        blocking.append(
            f"{device.path} has mounted filesystems: " + ", ".join(device.mounted_at)
        )
    if not device.serial.strip():
        blocking.append(
            f"{device.path} reports no serial, so the typed-serial check cannot run"
        )
    spec = FILESYSTEMS.get(filesystem)
    if spec is None:
        blocking.append(
            f"filesystem {filesystem!r} is not offered (exfat, fat32 or ext4)"
        )
    elif len(label) > spec[1]:
        blocking.append(f"a {filesystem} label is at most {spec[1]} characters")
    if not _LABEL.match(label):
        blocking.append("a label may hold letters, digits, space, '_' and '-' only")
    plan = FormatPlan(
        path=device.path,
        serial=device.serial,
        model=device.model,
        size_bytes=device.size_bytes,
        filesystem=filesystem,
        label=label,
        follows_job=follows_job,
        blocking=blocking,
    )
    return plan.model_copy(update={"plan_digest": plan_digest_of(plan)})


def partition_path(path: str) -> str:
    """The first partition of ``path``, named as the Linux kernel names it."""
    return f"{path}p1" if path[-1:].isdigit() else f"{path}1"


def _progress(job_id: str, phase: str, pct_bp: int, message: str) -> Progress:
    return Progress(
        job_id=job_id,
        phase=phase,
        pct_bp=pct_bp,
        bytes_done=0,
        bytes_total=0,
        throughput_bytes_per_sec=0,
        eta_seconds=0,
        message=message,
    )


def execute_format(
    plan: FormatPlan,
    device: Device,
    *,
    runner: Runner,
    exists: Callable[[str], bool],
    ledger: _Ledger | None,
    actor: str,
    job_id: str,
    authorization_id: str,
    platform: str,
    owner_uid: int | None = None,
    wait_seconds: float = 10.0,
) -> Generator[Progress, None, FormatResult]:
    """Write the partition table and filesystem, then read them back.

    Raises :class:`~core.errors.PlatformUnsupported` off Linux before any
    command, and :class:`~core.errors.FormatFailed` when the plan is blocked or
    stale against ``device`` or a step fails.
    """
    if platform != "linux":
        raise PlatformUnsupported(
            f"Formatting is implemented for Linux only; this host is {platform}. "
            "No operation was performed on the device."
        )
    problems = list(plan.blocking)
    if plan.plan_digest != plan_digest_of(plan):
        problems.append("the plan was altered after it was made")
    if (plan.path, plan.serial, plan.size_bytes) != (
        device.path,
        device.serial,
        device.size_bytes,
    ):
        problems.append("the device is not the one the plan was made for")
    if device.is_system_disk or device.mounted_at:
        problems.append("the device is the system disk or has a mounted filesystem")
    if problems:
        raise FormatFailed(
            "REFUSED: " + "; ".join(problems) + ". Nothing was written.",
            remediation="Open a new format workflow once the reason is resolved.",
        )

    ptype, _longest, want_fstype, mkfs = FILESYSTEMS[plan.filesystem]
    partition = partition_path(plan.path)
    identity = {
        "authorization_id": authorization_id,
        "plan_digest": plan.plan_digest,
        "path": plan.path,
        "serial": plan.serial,
        "model": plan.model,
        "size_bytes": plan.size_bytes,
        "filesystem": plan.filesystem,
        "label": plan.label,
        "job_id": job_id,
    }

    def note(operation: str, params: dict[str, Any], result: dict[str, Any]) -> None:
        if ledger is not None:
            ledger.append(
                actor=actor, operation=operation, params=params, result=result
            )

    def step(name: str, argv: list[str], stdin: str | None = None) -> CommandResult:
        done = runner(argv, stdin)
        if done.returncode != 0:
            tail = (done.stderr or done.stdout).strip()[-_STDERR_TAIL:]
            note(
                "format.failed",
                identity,
                {
                    "step": name,
                    "program": argv[0],
                    "returncode": done.returncode,
                    "stderr": tail,
                },
            )
            raise FormatFailed(
                f"{argv[0]} failed at the {name} step (exit {done.returncode}): "
                f"{tail or 'no output'}. The device may be left without a "
                "partition table or filesystem."
            )
        return done

    note("format.begin", identity, {})
    yield _progress(job_id, "signatures", 2000, "clearing old signatures")
    step("signatures", ["wipefs", "-a", plan.path])
    yield _progress(job_id, "partition-table", 4000, "writing the partition table")
    step(
        "partition-table",
        ["sfdisk", "--wipe", "always", plan.path],
        f"label: dos\n,,{ptype}\n",
    )
    runner(["udevadm", "settle"], None)
    deadline = time.monotonic() + wait_seconds
    while not exists(partition):
        if time.monotonic() >= deadline:
            note(
                "format.failed",
                identity,
                {"step": "partition", "program": "", "returncode": -1, "stderr": ""},
            )
            raise FormatFailed(
                f"the partition {partition} did not appear after the partition "
                "table was written. The device is left with a partition table "
                "and no filesystem."
            )
        time.sleep(0.2)
    yield _progress(
        job_id, "filesystem", 6000, f"making the {plan.filesystem} filesystem"
    )
    if plan.filesystem == "fat32":
        argv = [mkfs, "-F", "32", "-n", plan.label, partition]
    elif plan.filesystem == "ext4":
        argv = [mkfs, "-F", "-L", plan.label]
        if owner_uid is not None:
            argv += ["-E", f"root_owner={owner_uid}:{owner_uid}"]
        argv.append(partition)
    else:
        argv = [mkfs, "-L", plan.label, partition]
    step("filesystem", argv)
    yield _progress(job_id, "verify", 8000, "reading the filesystem back")
    observed_type = step(
        "verify", ["blkid", "-p", "-s", "TYPE", "-o", "value", partition]
    ).stdout.strip()
    observed_label = step(
        "verify", ["blkid", "-p", "-s", "LABEL", "-o", "value", partition]
    ).stdout.strip()
    verified = (
        observed_type == want_fstype
        and observed_label.casefold() == plan.label.casefold()
    )
    limitations = [_LIMITATION_NOT_A_SANITIZE]
    if not verified:
        limitations.append(
            f"read-back found filesystem {observed_type!r} with label "
            f"{observed_label!r}, not {want_fstype!r} with {plan.label!r}; the "
            "format is not verified."
        )
    result = FormatResult(
        path=plan.path,
        partition_path=partition,
        filesystem=plan.filesystem,
        label=plan.label,
        observed_fstype=observed_type,
        observed_label=observed_label,
        verified=verified,
        limitations=limitations,
    )
    note("format.complete", identity, result.model_dump(mode="json"))
    yield _progress(job_id, "done", 10_000, "formatted" if verified else "not verified")
    return result
