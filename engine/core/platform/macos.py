"""macOS adapter: ``diskutil`` discovery, APFS-aware protection, honest refusal.

Discovery
---------
``/usr/sbin/diskutil`` by absolute path, always with ``-plist``, parsed with
:mod:`plistlib`. Four calls, none of which needs root:

* ``diskutil list -plist`` - every disk, including the synthesized APFS
  container disks and their mounted volumes;
* ``diskutil apfs list -plist`` - containers, their physical stores, and the
  role of each volume (System, Data, VM, Preboot, Recovery);
* ``diskutil info -plist <disk>`` per physical whole disk - bus, internal,
  removable, solid-state, size;
* ``diskutil info -plist /`` - which container the running system boots from.

Parsing is pure (:func:`parse_inventory`) and tested from fixtures on every
host.

APFS, and why it matters for protection
---------------------------------------
On modern macOS the boot volume is not on a partition of a physical disk. It
is a volume in a *synthesized* container disk (``disk3``) whose *physical
store* is a partition (``disk0s2``) of the real disk. A check that looked only
at the physical disk's partitions would find nothing mounted on ``disk0`` and
call the internal SSD a free target. So a physical disk is protected when it
is a physical store of **any** container that holds the booted volume, or a
volume with the System, Data, VM (swap), Preboot or Recovery role, and it is
mounted when any volume of any container it backs is mounted.

Whole-drive clear, and what is never done
-----------------------------------------
Devices are classified before anything is offered:

* **Internal Mac storage** (``Internal: true``) - Apple silicon's fabric-attached
  SSD and the T2- or Intel-attached internal disk. Never raw-written, never
  raw-imaged: on Apple silicon and T2 Macs the Secure Enclave encrypts it, and
  the purge-capable path is macOS's own *Erase All Content and Settings*,
  which this app cannot perform or verify. The resolver reports it BLOCKED FOR
  SAFETY with that reason.
* **External disks** (USB flash, USB/Thunderbolt SSD and HDD, card readers) -
  whole-drive **Clear** through :mod:`core.erase.blockclear` over
  ``/dev/rdiskN``, bound to the planned size and re-read identity. macOS gives
  applications no ATA or NVMe sanitize path, so device sanitize is
  PLATFORM-LIMITED and a Purge request is refused, never downgraded.

A mounted disk is refused. Unmounting is its own explicit step
(:meth:`MacOSAdapter.prepare_device`, ``diskutil unmountDisk``), never part
of an erase. APFS file erase remains a filesystem operation with its own,
weaker semantics; it is never described as a physical sanitization.

Serial numbers come from ``system_profiler -json`` (USB, NVMe, SATA and
Thunderbolt reports), matched to the BSD name. A disk with no serial there
cannot be bound and is refused for destructive work.
"""

from __future__ import annotations

import json
import plistlib
import re
from collections.abc import Generator
from typing import Any

import structlog

from core.device.mac.rawdisk import MacIo, MacRawDisk
from core.errors import (
    ConfirmationMismatch,
    MountedRefused,
    PlatformUnsupported,
    SystemDiskRefused,
    UnsupportedCapability,
)
from core.platform.base import (
    FLASH_LIMITATION,
    BaseAdapter,
    core_device,
    json_records,
    ledger_sink,
    normalized_serial,
)
from core.platform.model import (
    RUNNABLE_STATES,
    Capability,
    Interface,
    MediaType,
    NormalizedDevice,
    OperationCapability,
    PartitionInfo,
    PrivilegeState,
    SanitizeOption,
)

__all__ = [
    "MacOSAdapter",
    "parse_inventory",
    "serial_map",
    "DISKUTIL",
    "SYSTEM_PROFILER",
    "PROTECTED_ROLES",
]

logger = structlog.get_logger(__name__)

#: Absolute, never looked up on PATH.
DISKUTIL = "/usr/sbin/diskutil"

#: APFS volume roles that belong to an installed macOS.
PROTECTED_ROLES = frozenset({"System", "Data", "VM", "Preboot", "Recovery", "Update"})

_BUS_TO_INTERFACE: dict[str, Interface] = {
    "usb": "usb",
    "pci-express": "nvme",
    "pci": "nvme",
    "nvme": "nvme",
    "apple fabric": "nvme",
    "sata": "sata",
    "ata": "sata",
    "sas": "sas",
    "thunderbolt": "thunderbolt",
    "secure digital": "mmc",
    "sd": "mmc",
    "disk image": "virtual",
    "virtual interface": "virtual",
}

_CONTENT_FS = {
    "apple_apfs": "APFS",
    "apple_hfs": "HFS+",
    "apple_hfsx": "HFS+",
    "microsoft basic data": "FAT/exFAT/NTFS",
    "windows_ntfs": "NTFS",
    "dos_fat_32": "FAT32",
    "dos_fat_16": "FAT16",
    "windows_fat_32": "FAT32",
    "linux filesystem": "Linux",
    "linux": "Linux",
    "efi": "EFI",
}

_WHOLE = re.compile(r"^(disk\d+)")


def _whole(identifier: str) -> str:
    match = _WHOLE.match(identifier or "")
    return match.group(1) if match else ""


def _load(blob: bytes | str | None) -> dict[str, Any]:
    if not blob:
        return {}
    data = blob.encode("utf-8") if isinstance(blob, str) else blob
    try:
        loaded = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _media(info: dict[str, Any], interface: Interface) -> tuple[MediaType, str]:
    solid = info.get("SolidState")
    if interface == "mmc":
        return "flash", "The disk is on an SD card reader, which carries only flash."
    if solid is True:
        return "ssd", "diskutil reports SolidState: true."
    if interface == "usb":
        return "flash", (
            "The disk is USB-attached and diskutil does not report it as "
            "solid-state. It is treated as flash, so the flash limitation is "
            "never left out."
        )
    if solid is False:
        return "hdd", "diskutil reports SolidState: false."
    return "unknown", "diskutil did not report whether the disk is solid-state."


#: Keys under which ``system_profiler -json`` reports a device serial.
_SERIAL_KEYS = ("serial_num", "device_serial", "spnvme_serial", "spsata_serial")


def serial_map(profile: dict[str, Any]) -> dict[str, str]:
    """BSD whole-disk name -> serial, from ``system_profiler -json``. Pure.

    Every dict carrying a serial key claims every ``bsd_name`` in its subtree;
    the nearest claim wins, so a hub's serial never labels the stick below it.
    """
    found: dict[str, str] = {}

    def walk(node: Any, serial: str) -> None:
        if isinstance(node, dict):
            for key in _SERIAL_KEYS:
                value = node.get(key)
                if isinstance(value, str) and value.strip():
                    serial = value.strip()
                    break
            name = node.get("bsd_name")
            if isinstance(name, str) and serial:
                whole = _whole(name)
                if whole:
                    found[whole] = serial
            for value in node.values():
                walk(value, serial)
        elif isinstance(node, list):
            for item in node:
                walk(item, serial)

    walk(profile, "")
    return found


def parse_inventory(
    listing: dict[str, Any],
    apfs: dict[str, Any],
    infos: dict[str, dict[str, Any]],
    root_info: dict[str, Any],
    serials: dict[str, str] | None = None,
) -> list[NormalizedDevice]:
    """Normalize ``diskutil`` plists. Pure; no I/O.

    Args:
        listing: ``diskutil list -plist``.
        apfs: ``diskutil apfs list -plist``.
        infos: ``diskutil info -plist <disk>`` per physical whole disk.
        root_info: ``diskutil info -plist /``.
    """
    entries = [
        item
        for item in listing.get("AllDisksAndPartitions") or []
        if isinstance(item, dict)
    ]

    # Container disk -> physical whole disks backing it.
    backing: dict[str, set[str]] = {}
    for entry in entries:
        stores = entry.get("APFSPhysicalStores") or []
        if stores:
            backing[str(entry.get("DeviceIdentifier"))] = {
                _whole(str(store.get("DeviceIdentifier", ""))) for store in stores
            }
    roles_by_container: dict[str, set[str]] = {}
    for container in apfs.get("Containers") or []:
        ref = str(container.get("ContainerReference") or "")
        stores = {
            _whole(str(store.get("DeviceIdentifier", "")))
            for store in container.get("PhysicalStores") or []
        }
        if ref and stores:
            backing.setdefault(ref, set()).update(stores)
        roles: set[str] = set()
        for volume in container.get("Volumes") or []:
            roles.update(str(role) for role in volume.get("Roles") or [])
        roles_by_container[ref] = roles

    # Where the running system boots from.
    boot_physical: set[str] = set()
    for store in root_info.get("APFSPhysicalStores") or []:
        boot_physical.add(
            _whole(
                str(
                    store.get("APFSPhysicalStore")
                    or store.get("DeviceIdentifier")
                    or ""
                )
            )
        )
    boot_container = str(root_info.get("APFSContainerReference") or "")
    if boot_container:
        boot_physical |= backing.get(boot_container, set())
    parent = str(root_info.get("ParentWholeDisk") or "")
    if parent:
        boot_physical |= backing.get(parent, {parent})
    boot_physical.discard("")

    # Mount points per physical disk, through containers.
    mounts: dict[str, list[str]] = {}
    fs_by_disk: dict[str, set[str]] = {}
    parts_by_disk: dict[str, list[PartitionInfo]] = {}
    role_reasons: dict[str, set[str]] = {}
    for entry in entries:
        ident = str(entry.get("DeviceIdentifier") or "")
        physical = backing.get(ident, {ident})
        volumes = list(entry.get("APFSVolumes") or []) + list(
            entry.get("Partitions") or []
        )
        if entry.get("MountPoint"):
            volumes.append(entry)
        for volume in volumes:
            point = str(volume.get("MountPoint") or "")
            content = str(volume.get("Content") or "")
            fs = _CONTENT_FS.get(content.lower(), "APFS" if ident in backing else "")
            for disk in physical:
                if point:
                    mounts.setdefault(disk, []).append(point)
                if fs and fs != "EFI":
                    fs_by_disk.setdefault(disk, set()).add(fs)
        if ident not in backing:
            parts_by_disk[ident] = [
                PartitionInfo(
                    id=str(part.get("DeviceIdentifier") or ""),
                    size_bytes=int(part.get("Size") or 0),
                    filesystem=_CONTENT_FS.get(
                        str(part.get("Content") or "").lower(),
                        str(part.get("Content") or ""),
                    ),
                    label=str(part.get("VolumeName") or ""),
                    mount_points=[str(part["MountPoint"])]
                    if part.get("MountPoint")
                    else [],
                )
                for part in entry.get("Partitions") or []
            ]
        roles = roles_by_container.get(ident, set()) & PROTECTED_ROLES
        if roles:
            for disk in physical:
                role_reasons.setdefault(disk, set()).update(roles)

    devices: list[NormalizedDevice] = []
    for ident, info in sorted(infos.items()):
        bus = str(info.get("BusProtocol") or "")
        interface = _BUS_TO_INTERFACE.get(bus.lower(), "unknown")
        if info.get("VirtualOrPhysical") == "Virtual":
            interface = "virtual"
        media_type, basis = _media(info, interface)
        reasons: list[str] = []
        if ident in boot_physical:
            reasons.append(
                "The running macOS boots from an APFS container on this disk."
            )
        roles = role_reasons.get(ident, set())
        if roles:
            reasons.append(
                "Backs APFS volumes with the "
                + ", ".join(sorted(roles))
                + " role(s), which belong to a macOS installation."
            )
        points = sorted(set(mounts.get(ident, [])))
        removable = info.get("RemovableMedia", info.get("Removable"))
        internal = info.get("Internal")
        if removable is None and internal is not None:
            removable = not bool(internal)
        serial = (serials or {}).get(ident, "")
        devices.append(
            NormalizedDevice(
                id=ident,
                platform="macos",
                path=f"/dev/{ident}",
                model=str(
                    info.get("MediaName") or info.get("IORegistryEntryName") or ""
                ).strip(),
                serial=serial,
                capacity_bytes=int(info.get("TotalSize") or info.get("Size") or 0),
                interface=interface,
                media_type=media_type,
                media_basis=basis,
                removable=bool(removable) if removable is not None else None,
                internal=bool(internal) if internal is not None else None,
                mounted=bool(points),
                mount_points=points,
                system_device=bool(reasons),
                system_reasons=reasons,
                filesystems=sorted(fs_by_disk.get(ident, set())),
                partitions=parts_by_disk.get(ident, []),
                stable_id=str(info.get("DiskUUID") or info.get("MediaUUID") or ""),
                limitations=(
                    []
                    if serial
                    else [
                        "No serial number was found for this disk (diskutil "
                        "reports none, and system_profiler did not name it), so "
                        "its identity cannot be bound for destructive work."
                    ]
                ),
            )
        )
    return devices


#: Absolute, never looked up on PATH.
SYSTEM_PROFILER = "/usr/sbin/system_profiler"
_PROFILER_TYPES = (
    "SPUSBDataType",
    "SPUSBHostDataType",
    "SPNVMeDataType",
    "SPSerialATADataType",
    "SPThunderboltDataType",
)


class MacOSAdapter(BaseAdapter):
    """macOS 12 and later."""

    name = "macos"
    family = "macos"

    def __init__(
        self,
        *,
        helper: str = "in-process",
        helper_basis: str = "",
        runner: Any = None,
        mac_io: MacIo | None = None,
        privilege: PrivilegeState | None = None,
    ) -> None:
        super().__init__(helper=helper, helper_basis=helper_basis, privilege=privilege)
        if runner is None:
            from core.device._sysio import SubprocessRunner

            runner = SubprocessRunner(timeout_s=60.0)
        self._runner = runner
        self._mac_io = mac_io

    def _diskutil(self, *args: str, required: bool = True) -> dict[str, Any]:
        result = self._runner.run([DISKUTIL, *args])
        if not result.ok:
            if not required:
                return {}
            raise PlatformUnsupported(
                f"diskutil {' '.join(args)} failed: "
                + (
                    (result.stderr or result.stdout).strip()[:300]
                    or f"exit {result.returncode}"
                ),
                remediation="Confirm /usr/sbin/diskutil runs from Terminal.",
            )
        return _load(result.stdout)

    def serials(self) -> dict[str, str]:
        """BSD name -> serial from ``system_profiler``, or empty if it fails."""
        result = self._runner.run([SYSTEM_PROFILER, "-json", *_PROFILER_TYPES])
        if not result.ok:
            return {}
        try:
            loaded = json.loads(result.stdout)
        except json.JSONDecodeError:
            return {}
        return serial_map(loaded) if isinstance(loaded, dict) else {}

    def inventory(self) -> list[NormalizedDevice]:
        listing = self._diskutil("list", "-plist")
        apfs = self._diskutil("apfs", "list", "-plist", required=False)
        root = self._diskutil("info", "-plist", "/", required=False)
        wholes = [str(name) for name in listing.get("WholeDisks") or []]
        backed = {
            str(entry.get("DeviceIdentifier"))
            for entry in listing.get("AllDisksAndPartitions") or []
            if entry.get("APFSPhysicalStores")
        }
        infos: dict[str, dict[str, Any]] = {}
        for ident in wholes:
            if ident in backed:
                continue  # synthesized container, reported through its stores
            if not re.fullmatch(r"disk\d+", ident):
                continue  # never pass anything but a BSD whole-disk name
            # A failed info call still lists the disk, with its unknowns
            # unknown, rather than hiding a device the listing showed.
            infos[ident] = self._diskutil("info", "-plist", ident, required=False)
        return parse_inventory(listing, apfs, infos, root, self.serials())

    def enumerate_devices(
        self, *, include_virtual: bool = False
    ) -> list[NormalizedDevice]:
        try:
            devices = self.inventory()
        except PlatformUnsupported as exc:
            self.discovery.record(
                ok=False, tool="diskutil", detail=exc.message, devices=[]
            )
            raise
        if not include_virtual:
            devices = [item for item in devices if item.interface != "virtual"]
        self.discovery.record(
            ok=True,
            tool="diskutil list / apfs list / info (-plist); system_profiler -json",
            detail="disks read from diskutil",
            devices=devices,
        )
        return devices

    # -- classification and options -------------------------------------------

    def apple_managed(self, device: NormalizedDevice) -> bool:
        return device.internal is True

    def whole_drive_unavailable_reason(self) -> str:
        return ""

    def whole_drive_recommended_action(self) -> str:
        return (
            "External disks: unmount every volume (Devices > Prepare, or diskutil "
            "unmountDisk) and start Sanctum with sudo. Internal Mac storage: use "
            "System Settings > General > Transfer or Reset > Erase All Content "
            "and Settings, which destroys the storage encryption keys."
        )

    def _system_disk_advice(self, device: NormalizedDevice) -> str:
        return (
            "Internal Mac storage is purged by macOS itself: System Settings > "
            "General > Transfer or Reset > Erase All Content and Settings (Apple "
            "silicon and T2), which destroys the storage encryption keys. This "
            "app cannot perform or verify that, and never raw-writes the disk."
        )

    def _elevation_advice(self) -> str:
        return (
            "Raw device access on macOS needs root: start Sanctum itself with "
            "sudo, then rescan."
        )

    def drive_options(
        self, device: NormalizedDevice
    ) -> tuple[list[SanitizeOption], str]:
        from core.platform.windows import options_from_resolution

        return options_from_resolution(
            self.device_resolution(device), nvme_bus=device.interface == "nvme"
        )

    def _platform_rows(self, privilege: PrivilegeState) -> list[OperationCapability]:
        return self._block_engine_rows(privilege)

    def authorization_probe(self, path: str) -> dict[str, Any]:
        device = self.inspect_device(path)
        resolution = self.device_resolution(device)
        clear = resolution.get(Capability.WHOLE_DRIVE_CLEAR)
        achievable = ["CLEAR"] if clear.state in RUNNABLE_STATES else []
        row = core_device(device).model_dump(mode="json")
        return {
            "device": row,
            "capabilities": {
                "achievable_levels": achievable,
                "est_erase_seconds": int(device.capacity_bytes / (30 * 1024 * 1024)),
                "limitations": sorted(set(clear.limitations)),
                "resolution": resolution.model_dump(mode="json"),
            },
        }

    # -- execution --------------------------------------------------------------

    def _open_bound(self, device: NormalizedDevice, *, write: bool) -> MacRawDisk:
        """Re-read the device from diskutil, then open and bind the raw node.

        macOS has no ioctl that names a drive's serial, so the serial is
        re-read from ``system_profiler`` here, immediately before the open,
        and the open descriptor is then bound by the kernel's size.
        """
        fresh = self.inspect_device(device.id)
        if normalized_serial(fresh.serial) != normalized_serial(device.serial):
            raise ConfirmationMismatch(
                f"{device.path} now reports serial {fresh.serial!r}, the plan "
                f"recorded {device.serial!r}. Nothing was written."
            )
        if write and fresh.mounted:
            raise MountedRefused(
                f"{device.path} has a mounted volume at "
                + ", ".join(fresh.mount_points)
                + " at the write seam. Nothing was written.",
                remediation=self.whole_drive_recommended_action(),
            )
        disk = MacRawDisk(device.id, write=write, io=self._mac_io).open()
        return disk.bind(size_bytes=device.capacity_bytes)

    def _clear_generator(
        self, params: dict[str, Any], *, resume: bool
    ) -> Generator[Any, None, Any]:
        from core.erase.blockclear import ClearRequest, clear

        device = self._revalidated(params)
        level = "CLEAR" if resume else str(params.get("level", "CLEAR"))
        _, resolution = self._choose(device, level)
        sink = ledger_sink(params)
        job_id = str(params["job_id"])
        checkpoint = sink.last_checkpoint(job_id) if resume else None
        if resume and checkpoint is None:
            raise UnsupportedCapability(
                f"No checkpoint was recorded for job {job_id}; only an "
                "interrupted clear resumes.",
                remediation="Start the clear again from the beginning.",
            )
        row = resolution.get(Capability.WHOLE_DRIVE_CLEAR)
        request = ClearRequest(
            job_id=job_id,
            device=core_device(device),
            identity={
                "bsd_name": device.id,
                "serial": device.serial,
                "model": device.model,
                "size_bytes": device.capacity_bytes,
            },
            platform="macos",
            mechanism=row.mechanism,
            device_class=resolution.device_class,
            flash=device.media_type != "hdd",
            limitations=(
                *row.limitations,
                "macOS gives no ioctl that names a drive's serial: the serial was "
                "re-read from system_profiler immediately before the raw device "
                "was opened, and the open device was bound by its kernel size. A "
                "different disk of exactly the same size swapped into the same "
                "BSD name between that read and the open would not be detected.",
            ),
            resume_from=checkpoint,
        )
        return clear(request, lambda: self._open_bound(device, write=True), ledger=sink)

    def execute_drive_sanitization(
        self, params: dict[str, Any]
    ) -> Generator[dict[str, Any], None, dict[str, Any]]:
        return (yield from json_records(self._clear_generator(params, resume=False)))

    def resume_drive_sanitization(
        self, params: dict[str, Any]
    ) -> Generator[dict[str, Any], None, dict[str, Any]]:
        return (yield from json_records(self._clear_generator(params, resume=True)))

    def prepare_device(self, params: dict[str, Any]) -> dict[str, Any]:
        """``diskutil unmountDisk`` for an external disk, as its own step.

        Needs the typed serial of the device read here. Internal and system
        disks are refused. Unmounting writes nothing to the medium.
        """
        from core.device.guard import refuse_removed_mode_keys

        refuse_removed_mode_keys(params)
        device = self.inspect_device(str(params["path"]))
        if device.system_device or device.internal is True:
            raise SystemDiskRefused(
                f"Refusing to unmount {device.path}: it is internal Mac storage "
                "or holds the running system."
            )
        if not normalized_serial(device.serial) or normalized_serial(
            str(params.get("typed_serial") or "")
        ) != normalized_serial(device.serial):
            raise ConfirmationMismatch(
                f"The typed serial does not match {device.path}. Nothing changed."
            )
        action = {
            "device": device.path,
            "serial": device.serial,
            "action": f"{DISKUTIL} unmountDisk {device.path}",
            "unmounts": device.mount_points,
        }
        result = self._runner.run([DISKUTIL, "unmountDisk", device.path])
        if not result.ok:
            raise UnsupportedCapability(
                f"diskutil unmountDisk {device.path} failed: "
                + ((result.stderr or result.stdout).strip()[:300] or "no output"),
                remediation="Close whatever holds the volume open, then retry.",
            )
        return {**action, "performed": True}

    def _file_limitations(self) -> list[str]:
        return [
            "APFS is copy-on-write: an overwrite is written to new blocks and "
            "the original blocks are only released, so the old content is not "
            "guaranteed destroyed and physical verification is not possible. "
            "The report records this for every file on APFS.",
            "Local Time Machine snapshots can keep a deleted file's content; "
            "they are listed only when tmutil can be queried.",
            FLASH_LIMITATION,
        ]

    def restrictions(self) -> list[str]:
        return [
            "Whole-drive clear is offered for external disks only, through the "
            "raw device node, with root. Internal Mac storage is never raw-written.",
            "macOS gives applications no ATA or NVMe sanitize command, so device "
            "sanitize (Purge) is not available on macOS; a Purge request is "
            "refused, never replaced by an overwrite.",
            "APFS copy-on-write means file overwrite cannot destroy the "
            "original blocks; file erase on APFS is removal plus a residual "
            "report, never a verified destruction.",
            "Free-space wipe is not implemented on macOS.",
            "A disk whose serial system_profiler does not report cannot be "
            "bound, and is refused for destructive work.",
        ]
