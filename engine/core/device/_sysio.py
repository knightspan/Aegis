"""Process and filesystem seams for :mod:`core.device`.

Every external tool invocation and every ``/sys`` or ``/proc`` read in this
package goes through :class:`SystemProbe`. That keeps the device layer testable
without touching real hardware (CLAUDE.md: no real device access in the test
suite) and keeps the "never accept a shell string" rule enforceable in one
place: :class:`SubprocessRunner` always executes an argv list with
``shell=False``.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import structlog

from core.platform.host import windows_creationflags

__all__ = [
    "CommandResult",
    "Runner",
    "SubprocessRunner",
    "SystemProbe",
    "DEFAULT_TIMEOUT_S",
]

logger = structlog.get_logger(__name__)

DEFAULT_TIMEOUT_S = 30.0

#: Exit code this module uses when the tool binary is absent.
RC_NOT_FOUND = 127
#: Exit code this module uses when the tool could not be executed.
RC_NOT_EXECUTABLE = 126
#: Exit code this module uses when the tool exceeded its timeout.
RC_TIMEOUT = 124

_PERMISSION_MARKERS = (
    "permission denied",
    "operation not permitted",
    "must be run as root",
    "requires root",
    "you do not have enough privileges",
    "not permitted",
)


@dataclass(frozen=True)
class CommandResult:
    """Outcome of one external tool invocation."""

    argv: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        """True when the tool ran and exited zero."""
        return self.returncode == 0

    @property
    def missing(self) -> bool:
        """True when the tool binary could not be found."""
        return self.returncode == RC_NOT_FOUND

    @property
    def permission_denied(self) -> bool:
        """True when the tool refused for lack of privilege.

        Distinguishing this from "feature unsupported" matters: reporting a
        permission failure as an empty capability set would silently understate
        what the hardware can do.
        """
        if self.ok:
            return False
        blob = f"{self.stderr}\n{self.stdout}".lower()
        return any(marker in blob for marker in _PERMISSION_MARKERS)


class Runner(Protocol):
    """Executes an argv list and returns its result. Never uses a shell."""

    def run(self, argv: Sequence[str]) -> CommandResult:
        """Run ``argv`` and capture its output."""
        ...


class SubprocessRunner:
    """The real :class:`Runner`. Direct exec, no shell, bounded by a timeout."""

    def __init__(self, timeout_s: float = DEFAULT_TIMEOUT_S) -> None:
        self.timeout_s = timeout_s

    def run(self, argv: Sequence[str]) -> CommandResult:
        """Run ``argv`` with ``shell=False`` and capture stdout/stderr."""
        args = list(argv)
        try:
            proc = subprocess.run(  # noqa: S603 - argv list, shell=False by design
                args,
                capture_output=True,
                text=True,
                timeout=self.timeout_s,
                check=False,
                shell=False,
                creationflags=windows_creationflags(),
            )
        except FileNotFoundError:
            logger.debug("tool_missing", argv=args)
            return CommandResult(args, RC_NOT_FOUND, "", "command not found")
        except subprocess.TimeoutExpired:
            logger.warning("tool_timeout", argv=args, timeout_s=self.timeout_s)
            return CommandResult(args, RC_TIMEOUT, "", "timed out")
        except OSError as exc:
            logger.debug("tool_unrunnable", argv=args, error=str(exc))
            return CommandResult(args, RC_NOT_EXECUTABLE, "", str(exc))
        return CommandResult(args, proc.returncode, proc.stdout, proc.stderr)


@dataclass
class SystemProbe:
    """Bundles the host access the device layer needs.

    The ``*_map`` fields are test seams. When set they replace a filesystem
    lookup that depends on symlinks, which lets the suite run on hosts that do
    not permit creating them. Production code leaves them ``None``.
    """

    runner: Runner = field(default_factory=SubprocessRunner)
    sysfs_root: Path = Path("/sys")
    proc_root: Path = Path("/proc")
    dev_root: Path = Path("/dev")
    by_id_map: dict[str, str] | None = None
    block_syspath_map: dict[str, str] | None = None

    def run(self, *argv: str) -> CommandResult:
        """Run one external tool."""
        return self.runner.run(argv)

    def read_text(self, path: Path) -> str | None:
        """Read a small pseudo-file, returning ``None`` if it is unreadable."""
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    def by_id_links(self) -> dict[str, str]:
        """Map each ``/dev/disk/by-id`` link name to the kernel name it targets."""
        if self.by_id_map is not None:
            return self.by_id_map
        directory = self.dev_root / "disk" / "by-id"
        links: dict[str, str] = {}
        try:
            entries = sorted(directory.iterdir())
        except OSError:
            logger.debug("by_id_unreadable", path=str(directory))
            return links
        for entry in entries:
            try:
                links[entry.name] = Path(os.path.realpath(entry)).name
            except OSError:
                continue
        return links

    def block_syspath(self, kernel_name: str) -> str:
        """Return the resolved sysfs path of a block device, or ``""``."""
        if self.block_syspath_map is not None:
            return self.block_syspath_map.get(kernel_name, "")
        try:
            return os.path.realpath(self.sysfs_root / "block" / kernel_name)
        except OSError:
            return ""

    def list_block_names(self) -> list[str]:
        """Return every entry under ``/sys/block``."""
        try:
            return sorted(p.name for p in (self.sysfs_root / "block").iterdir())
        except OSError:
            logger.debug("sysfs_block_unreadable", path=str(self.sysfs_root / "block"))
            return []
