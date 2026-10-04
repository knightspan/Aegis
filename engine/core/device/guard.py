"""Safety gate for destructive operations.

Enforces the CLAUDE.md non-negotiables. Every destructive path calls both
checks before it touches a device:

* :func:`assert_erasable` - refuse the system disk, refuse anything mounted.
* :func:`assert_serial_confirmed` - the operator must type the device's own
  serial. The recorded human approval, bound to the plan and spent once at the
  API gate and again at the helper's write seam, is the other opt-in.

Both raise on refusal and return ``None`` on success, so a caller cannot
accidentally proceed by ignoring a boolean.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import structlog

from core.errors import (
    ConfirmationMismatch,
    MountedRefused,
    SystemDiskRefused,
    WorkflowGateRefused,
)
from core.models import Device, VolumeInfo

__all__ = [
    "REMOVED_MODE_KEYS",
    "SYSTEM_PATHS",
    "assert_erasable",
    "assert_serial_confirmed",
    "assert_volume_confirmed",
    "assert_volume_wipeable",
    "refuse_removed_mode_keys",
]

#: Directories the running host needs. A volume holding any of them is the
#: system volume for the purpose of a free-space wipe: filling it to zero free
#: space can stop the host from writing logs, journals or its own state.
SYSTEM_PATHS = (
    "/",
    "/boot",
    "/boot/efi",
    "/etc",
    "/home",
    "/opt",
    "/root",
    "/srv",
    "/usr",
    "/var",
)

logger = structlog.get_logger(__name__)

#: Request keys that once switched a destructive operation into a non-writing
#: simulation. That mode no longer exists. A request that still carries one is
#: from a client that believes it can ask for a rehearsal, and running it for
#: real on that belief would be the worst possible reading, so it is refused.
REMOVED_MODE_KEYS = ("dry_run", "simulation", "simulate")


def refuse_removed_mode_keys(params: Mapping[str, Any]) -> None:
    """Raise if ``params`` carries a simulation or dry-run switch.

    Never ignored and never honoured: there is no non-writing execution path to
    route such a request to, and dropping the key silently would execute a
    request whose sender expected nothing to be written.

    Raises:
        WorkflowGateRefused: One of :data:`REMOVED_MODE_KEYS` is present.
    """
    present = [key for key in REMOVED_MODE_KEYS if key in params]
    if not present:
        return
    reasons = [
        f"the request carries {key!r}, a simulation switch that no longer "
        "exists; every destructive operation now runs against the real device"
        for key in present
    ]
    raise WorkflowGateRefused(
        "REFUSED: " + "; ".join(reasons) + ". Nothing was written.",
        why_blocked=reasons,
        remediation=(
            "Remove the field and send the request only when the operation is "
            "meant to run on the real device."
        ),
    )


def assert_erasable(device: Device) -> None:
    """Raise if ``device`` is the system disk or has a mounted filesystem.

    Raises:
        SystemDiskRefused: The device holds the running root, ``/boot`` or swap.
        MountedRefused: One or more filesystems on the device are mounted.
    """
    if device.is_system_disk:
        logger.warning("erase_refused", path=device.path, reason="system_disk")
        raise SystemDiskRefused(
            f"{device.path} ({device.model}) holds the running system "
            "(root, /boot or active swap). Refusing to erase it."
        )
    if device.mounted_at:
        mounts = ", ".join(sorted(device.mounted_at))
        logger.warning("erase_refused", path=device.path, reason="mounted")
        raise MountedRefused(
            f"{device.path} has mounted filesystems: {mounts}. Refusing to erase it."
        )


def assert_serial_confirmed(device: Device, typed_serial: str) -> None:
    """Raise unless ``typed_serial`` identifies ``device``.

    The operator normally types the device serial. A device that reports no
    serial cannot be confirmed that way, so its stable ``/dev/disk/by-id`` path
    is accepted instead — still a value the operator must read off the
    capability report, never a value they can guess.

    Raises:
        ConfirmationMismatch: The typed value does not identify this device.
    """
    typed = typed_serial.strip()
    if not typed:
        raise ConfirmationMismatch(
            "No confirmation value was typed.",
            remediation=(
                f"Type the serial of {device.path} exactly as shown in the "
                "capability report to confirm."
            ),
        )

    if device.serial:
        if typed.casefold() == device.serial.strip().casefold():
            return
        logger.warning("confirmation_mismatch", path=device.path)
        raise ConfirmationMismatch(
            f"Typed value does not match the serial of {device.path}.",
            remediation=(
                "Re-read the device serial from the capability report and type "
                "it exactly. Nothing has been modified."
            ),
        )

    accepted = {value.casefold() for value in (device.by_id_path,) if value}
    if typed.casefold() in accepted:
        return
    logger.warning("confirmation_mismatch", path=device.path, reason="no_serial")
    raise ConfirmationMismatch(
        f"{device.path} reports no serial, and the typed value does not match "
        "its stable identifier.",
        remediation=(
            "This device exposes no serial. Confirm it by typing its full "
            "/dev/disk/by-id path from the capability report instead."
        ),
    )


def _stat_dev(path: Path) -> int | None:
    try:
        return os.stat(path).st_dev
    except OSError:
        return None


def _swap_files(proc_swaps: Path = Path("/proc/swaps")) -> list[Path]:
    try:
        lines = proc_swaps.read_text(encoding="utf-8").splitlines()[1:]
    except OSError:
        return []
    return [Path(line.split()[0]) for line in lines if line.split()]


def assert_volume_wipeable(
    volume: VolumeInfo,
    *,
    protected: Sequence[Path] = (),
    stat_dev: Callable[[Path], int | None] = _stat_dev,
    swap_files: Callable[[], list[Path]] = _swap_files,
) -> None:
    """Raise if filling ``volume`` to zero free space could break the host.

    The test is the device number, not the path: a volume is refused when it
    holds any of :data:`SYSTEM_PATHS`, any active swap file, or any path in
    ``protected`` - which callers use for this deployment's own state, ledger
    and report directories, since a ledger that cannot append would leave the
    wipe unrecorded.

    Raises:
        SystemDiskRefused: The volume is the system volume or holds protected
            state.
    """
    checks: list[tuple[Path, str]] = [
        (Path(item), "a directory the running system needs") for item in SYSTEM_PATHS
    ]
    checks += [(item, "an active swap file") for item in swap_files()]
    checks += [(Path(item), "this deployment's own state") for item in protected]
    for path, role in checks:
        if stat_dev(path) == volume.st_dev:
            logger.warning(
                "free_space_wipe_refused",
                mount_point=volume.mount_point,
                holds=str(path),
            )
            raise SystemDiskRefused(
                f"{volume.mount_point} is the volume holding {path}, {role}. "
                "Filling it to zero free space can stop the host or this tool "
                "from writing. Refusing to wipe its free space.",
                remediation=(
                    "Wipe free space only on a separate data volume, such as a "
                    "removable drive mounted on its own."
                ),
            )


def assert_volume_confirmed(volume: VolumeInfo, typed_identifier: str) -> None:
    """Raise unless ``typed_identifier`` is the volume's own identifier.

    The identifier is the filesystem UUID when one is known and the mount point
    otherwise, exactly as the read-only plan reports it.

    Raises:
        ConfirmationMismatch: Nothing was typed, or it does not match.
    """
    typed = typed_identifier.strip()
    if typed and typed.casefold() == volume.identifier.strip().casefold():
        return
    logger.warning("volume_confirmation_mismatch", mount_point=volume.mount_point)
    raise ConfirmationMismatch(
        (
            "No confirmation value was typed."
            if not typed
            else f"Typed value does not identify the volume at {volume.mount_point}."
        ),
        remediation=(
            f"Plan the wipe and type the volume identifier it reports "
            f"({volume.identifier}) exactly. Nothing has been written."
        ),
    )
