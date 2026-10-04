"""Enumerate host block devices. Read-only.

Primary source is ``lsblk -J -O -b``. When lsblk is absent or predates ``-J``
the walk degrades to ``/sys/block`` rather than failing: a partial device list
is far more useful than none, and every field that could not be established is
left empty rather than guessed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, get_args

import structlog

from core.device._sysio import SystemProbe
from core.errors import DeviceVanished
from core.models import Device, Transport

__all__ = ["enumerate_devices", "get_device"]

logger = structlog.get_logger(__name__)

#: Physical device types lsblk reports that we always enumerate.
PHYSICAL_TYPES = frozenset({"disk", "rom"})
#: Virtual types included only on request (the carving testkit uses loop devices).
VIRTUAL_TYPES = frozenset({"loop", "ram"})

_VALID_TRANSPORTS = frozenset(get_args(Transport))
#: lsblk's ``tran`` values that are not already a valid Transport literal.
_TRANSPORT_ALIASES = {"ata": "sata", "sas": "sata", "scsi": "sata"}

#: Sysfs subsystem-chain probes, most specific bus first. A USB-SATA bridge
#: exposes an ``ataN`` node *under* the USB node; the bridge is what limits
#: capability, so USB must win over ATA.
_SYSPATH_PATTERNS: tuple[tuple[str, Transport], ...] = (
    (r"/usb\d*(?:/|$)", "usb"),
    (r"/nvme(?:\d|/|$)", "nvme"),
    (r"/[^/]*mmc[^/]*(?:/|$)", "mmc"),
    (r"/ata\d+(?:/|$)", "sata"),
)

#: lsblk reports a swap partition here instead of a filesystem path.
_SWAP_PSEUDO_MOUNT = "[SWAP]"
_SECTOR_BYTES = 512

#: by-id link prefixes that identify the device by an opaque id rather than by
#: model and serial. Usable, but a worse thing to show an operator.
_OPAQUE_BY_ID_PREFIXES = ("wwn-", "nvme-eui.", "scsi-3", "scsi-1", "md-uuid-")

_BOOT_MOUNTS = ("/", "/boot")


# --------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------


def _transport_from_syspath(syspath: str) -> Transport:
    """Derive the transport from a resolved ``/sys/block/<dev>`` path."""
    if not syspath:
        return "unknown"
    probe = syspath.replace("\\", "/")
    for pattern, transport in _SYSPATH_PATTERNS:
        if re.search(pattern, probe):
            return transport
    return "unknown"


def _normalise_transport(raw: str | None) -> Transport:
    """Map an lsblk ``tran`` value onto the :data:`Transport` literal."""
    if not raw:
        return "unknown"
    value = raw.strip().lower()
    value = _TRANSPORT_ALIASES.get(value, value)
    if value in _VALID_TRANSPORTS:
        return value  # type: ignore[return-value]
    return "unknown"


def _mountpoints_of(node: dict[str, Any]) -> list[str]:
    """Read a node's mountpoints, tolerating the pre-2.37 scalar field."""
    found: list[str] = []
    raw = node.get("mountpoints")
    if raw is None and "mountpoint" in node:
        raw = [node.get("mountpoint")]
    for entry in raw or []:
        if isinstance(entry, str) and entry and entry != _SWAP_PSEUDO_MOUNT:
            found.append(entry)
    return found


def _walk(node: dict[str, Any]) -> list[dict[str, Any]]:
    """Return ``node`` followed by every descendant."""
    nodes = [node]
    for child in node.get("children") or []:
        nodes.extend(_walk(child))
    return nodes


def _strip_partition_suffix(name: str) -> str:
    """Best-effort parent-disk name for a partition, used without an lsblk tree."""
    if match := re.fullmatch(r"(.*?\d+)p\d+", name):
        return match.group(1)
    return re.sub(r"\d+$", "", name)


def _best_by_id_link(links: list[str]) -> str | None:
    """Pick the friendliest stable link name for one device."""
    if not links:
        return None
    ranked = sorted(
        links, key=lambda name: (name.startswith(_OPAQUE_BY_ID_PREFIXES), name)
    )
    return ranked[0]


def _holds_boot(mountpoints: list[str]) -> bool:
    """True when any mountpoint is the root or lives under ``/boot``."""
    return any(
        point == "/" or point == "/boot" or point.startswith("/boot/")
        for point in mountpoints
    )


# --------------------------------------------------------------------------
# Host facts
# --------------------------------------------------------------------------


def _root_source(probe: SystemProbe) -> str:
    """Kernel name of the block device backing ``/``, or ``""``."""
    result = probe.run("findmnt", "-n", "-o", "SOURCE", "/")
    if not result.ok:
        logger.debug("findmnt_failed", returncode=result.returncode)
        return ""
    # btrfs reports "/dev/sda2[/@root]"; overlay reports a non-device string.
    source = result.stdout.strip().split("[", 1)[0].strip()
    if not source.startswith("/dev/"):
        return ""
    return Path(source).name


def _swap_sources(probe: SystemProbe) -> set[str]:
    """Kernel names of every device backing an active swap area."""
    text = probe.read_text(probe.proc_root / "swaps")
    if text is None:
        return set()
    names: set[str] = set()
    for line in text.splitlines()[1:]:
        field = line.split()[:1]
        if field and field[0].startswith("/dev/"):
            names.add(Path(field[0]).name)
    return names


def _by_id_index(probe: SystemProbe) -> dict[str, list[str]]:
    """Invert the by-id link table into kernel name -> link names."""
    index: dict[str, list[str]] = {}
    for link, target in probe.by_id_links().items():
        index.setdefault(target, []).append(link)
    return index


# --------------------------------------------------------------------------
# lsblk path
# --------------------------------------------------------------------------


def _lsblk_payload(probe: SystemProbe) -> dict[str, Any] | None:
    """Return parsed ``lsblk -J -O -b`` output, or ``None`` to force fallback."""
    result = probe.run("lsblk", "-J", "-O", "-b")
    if not result.ok:
        logger.info(
            "lsblk_unavailable",
            returncode=result.returncode,
            reason="missing" if result.missing else "error",
        )
        return None
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        logger.info("lsblk_unparseable")
        return None
    if not isinstance(payload, dict) or "blockdevices" not in payload:
        return None
    return payload


def _devices_from_lsblk(
    payload: dict[str, Any], probe: SystemProbe, *, include_virtual: bool
) -> list[Device]:
    tops: list[dict[str, Any]] = payload.get("blockdevices") or []
    wanted = PHYSICAL_TYPES | (VIRTUAL_TYPES if include_virtual else frozenset())

    partition_owner: dict[str, str] = {}
    for top in tops:
        top_name = str(top.get("name") or "")
        for node in _walk(top):
            node_name = str(node.get("name") or "")
            if node_name:
                partition_owner[node_name] = top_name

    root_name = _root_source(probe)
    swap_names = _swap_sources(probe)
    system_disks = {
        partition_owner.get(name, _strip_partition_suffix(name))
        for name in ({root_name} | swap_names)
        if name
    }
    by_id = _by_id_index(probe)

    devices: list[Device] = []
    for top in tops:
        if str(top.get("type") or "") not in wanted:
            continue
        name = str(top.get("name") or "")
        if not name:
            continue
        mounted: list[str] = []
        for node in _walk(top):
            mounted.extend(_mountpoints_of(node))
        link = _best_by_id_link(by_id.get(name, []))
        devices.append(
            Device(
                path=str(top.get("path") or f"/dev/{name}"),
                model=str(top.get("model") or "").strip(),
                serial=str(top.get("serial") or "").strip(),
                size_bytes=int(top.get("size") or 0),
                rotational=bool(top.get("rota")),
                transport=_normalise_transport(top.get("tran")),
                is_system_disk=name in system_disks or _holds_boot(mounted),
                mounted_at=mounted,
                pt_type=(str(top["pttype"]) if top.get("pttype") else None),
                by_id_path=(f"/dev/disk/by-id/{link}" if link else None),
            )
        )
    return devices


# --------------------------------------------------------------------------
# sysfs fallback
# --------------------------------------------------------------------------


def _sysfs_attr(probe: SystemProbe, name: str, relative: str) -> str:
    """Read one ``/sys/block/<name>/<relative>`` attribute, or ``""``."""
    text = probe.read_text(probe.sysfs_root / "block" / name / relative)
    return text.strip() if text else ""


def _devices_from_sysfs(probe: SystemProbe, *, include_virtual: bool) -> list[Device]:
    root_name = _root_source(probe)
    swap_names = _swap_sources(probe)
    system_seeds = {name for name in ({root_name} | swap_names) if name}
    by_id = _by_id_index(probe)

    devices: list[Device] = []
    for name in probe.list_block_names():
        virtual = name.startswith(("loop", "ram", "zram"))
        if virtual and not include_virtual:
            continue
        sectors = _sysfs_attr(probe, name, "size")
        try:
            size_bytes = int(sectors) * _SECTOR_BYTES
        except ValueError:
            size_bytes = 0
        vendor = _sysfs_attr(probe, name, "device/vendor")
        model = _sysfs_attr(probe, name, "device/model")
        if vendor and vendor.upper() != "ATA" and model:
            model = f"{vendor} {model}"
        link = _best_by_id_link(by_id.get(name, []))
        owned = {seed for seed in system_seeds if _strip_partition_suffix(seed) == name}
        devices.append(
            Device(
                path=f"/dev/{name}",
                model=model,
                serial=_sysfs_attr(probe, name, "device/serial"),
                size_bytes=size_bytes,
                rotational=_sysfs_attr(probe, name, "queue/rotational") == "1",
                transport=_transport_from_syspath(probe.block_syspath(name)),
                is_system_disk=bool(owned) or name in system_seeds,
                mounted_at=[],
                pt_type=None,
                by_id_path=(f"/dev/disk/by-id/{link}" if link else None),
            )
        )
    if devices:
        logger.info("sysfs_fallback_used", device_count=len(devices))
    return devices


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def enumerate_devices(
    probe: SystemProbe | None = None, *, include_virtual: bool = False
) -> list[Device]:
    """Return every block device visible to the host, system disk included.

    Args:
        probe: Host access seam. Defaults to the real system.
        include_virtual: Also report loop and ram devices.
    """
    probe = probe or SystemProbe()
    payload = _lsblk_payload(probe)
    if payload is not None:
        return _devices_from_lsblk(payload, probe, include_virtual=include_virtual)
    return _devices_from_sysfs(probe, include_virtual=include_virtual)


def get_device(path_or_serial: str, probe: SystemProbe | None = None) -> Device:
    """Return the single device matching a path, kernel name, by-id link or serial.

    Raises:
        DeviceVanished: The device is no longer present.
    """
    probe = probe or SystemProbe()
    needle = path_or_serial.strip()
    if not needle:
        raise DeviceVanished("No device identifier was supplied.")
    bare = Path(needle).name
    for device in enumerate_devices(probe, include_virtual=True):
        candidates = {
            device.path,
            Path(device.path).name,
            device.serial,
            device.by_id_path or "",
            Path(device.by_id_path).name if device.by_id_path else "",
        }
        if needle in candidates or bare in candidates:
            return device
    raise DeviceVanished(f"No block device matches {path_or_serial!r}.")
