"""Windows adapter: Storage-module discovery, safety facts, honest refusal.

Discovery
---------
One PowerShell invocation of the in-box Storage module (``Get-Disk``,
``Get-PhysicalDisk``, ``Get-Partition``, ``Get-Volume``) plus
``Win32_PageFileUsage``, emitted as a single JSON document. The script is a
constant: **no value from a request, a path or the environment is ever
interpolated into it**, and it runs through an argv list with ``shell=False``
from the absolute path of ``powershell.exe`` in the system directory, so a
``powershell.exe`` planted earlier on ``PATH`` is never the one executed.

All of these cmdlets run unelevated. Discovery therefore works for a standard
user, which is the point: the UI stays unprivileged.

Parsing is a pure function of that JSON (:func:`parse_inventory`), tested on
every host from captured fixtures.

Safety facts
------------
A disk is a **system device** when ``Get-Disk`` says ``IsBoot`` or
``IsSystem``, when it holds the ``%SystemDrive%`` volume, a page file, or the
hibernation file. It is **mounted** when any partition has a drive letter or a
folder mount path. Both refuse a whole-drive operation, through the same
:meth:`BaseAdapter.assess_device` every platform uses.

Whole-drive clear and device sanitize
-------------------------------------
Implemented natively (:mod:`core.device.win`), never through a shell:

* **Clear** - :mod:`core.erase.blockclear` over ``\\\\.\\PhysicalDriveN``
  opened with ``FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH``. The handle
  is bound to the planned disk number, serial and length before the first
  write, and the volume manager is asked again, through the same API, whether
  any volume on the disk is mounted.
* **Device sanitize** - ATA SANITIZE (block erase, crypto scramble) through
  ``IOCTL_ATA_PASS_THROUGH``, NVMe Sanitize (block, crypto) through
  ``IOCTL_STORAGE_REINITIALIZE_MEDIA``; offered only when the controller's own
  IDENTIFY answer reports it, which :meth:`WindowsAdapter.device_probes` reads.
  ATA SECURITY ERASE and NVMe Format are not issued; the resolver says why.

A drive letter is never a target. A mounted disk is refused; taking it
offline is a separate, explicit step (:meth:`WindowsAdapter.prepare_device`).
Every destructive run needs an elevated process, the typed serial and, for a
real run, the workflow's authorization re-checked at the write seam.
"""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Generator
from typing import TYPE_CHECKING, Any

import structlog

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
    CapabilityState,
    Interface,
    MediaType,
    NormalizedDevice,
    OperationCapability,
    PartitionInfo,
    PrivilegeState,
    SanitizeOption,
)

if TYPE_CHECKING:  # pragma: no cover
    from core.device.win.native import NativeApi
    from core.platform.capability import MechanismProbe

__all__ = [
    "WindowsAdapter",
    "INVENTORY_SCRIPT",
    "parse_inventory",
    "powershell_path",
    "encoded_script",
    "BUS_TYPES",
]

logger = structlog.get_logger(__name__)

#: The whole discovery script. A constant: nothing is ever formatted into it.
#: Enum-typed properties are cast to strings so the JSON carries names where
#: PowerShell has them; the parser also accepts the numeric codes.
INVENTORY_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$disks = @(Get-Disk | ForEach-Object { [pscustomobject]@{
  Number = $_.Number; FriendlyName = $_.FriendlyName;
  SerialNumber = $_.SerialNumber; Size = $_.Size; BusType = [string]$_.BusType;
  IsBoot = $_.IsBoot; IsSystem = $_.IsSystem; IsOffline = $_.IsOffline;
  IsReadOnly = $_.IsReadOnly; PartitionStyle = [string]$_.PartitionStyle;
  UniqueId = $_.UniqueId; Manufacturer = $_.Manufacturer; Model = $_.Model;
  Location = $_.Location } })
$physical = @(Get-PhysicalDisk | ForEach-Object { [pscustomobject]@{
  DeviceId = [string]$_.DeviceId; MediaType = [string]$_.MediaType;
  BusType = [string]$_.BusType; SpindleSpeed = $_.SpindleSpeed;
  SerialNumber = $_.SerialNumber } })
$partitions = @(Get-Partition | ForEach-Object { [pscustomobject]@{
  DiskNumber = $_.DiskNumber; PartitionNumber = $_.PartitionNumber;
  DriveLetter = [string]$_.DriveLetter; Size = $_.Size; Type = [string]$_.Type;
  IsBoot = $_.IsBoot; IsSystem = $_.IsSystem; AccessPaths = @($_.AccessPaths) } })
$volumes = @(Get-Volume | ForEach-Object { [pscustomobject]@{
  DriveLetter = [string]$_.DriveLetter; FileSystem = $_.FileSystem;
  FileSystemLabel = $_.FileSystemLabel; DriveType = [string]$_.DriveType;
  Path = $_.Path } })
$pagefiles = @(Get-CimInstance -ClassName Win32_PageFileUsage |
  ForEach-Object { [string]$_.Name })
$sysdrive = $env:SystemDrive
[pscustomobject]@{
  disks = $disks; physical = $physical; partitions = $partitions;
  volumes = $volumes; pagefiles = $pagefiles; system_drive = $sysdrive;
  hiberfil = (Test-Path -LiteralPath ($sysdrive + '\hiberfil.sys'))
} | ConvertTo-Json -Depth 6 -Compress
"""

#: ``MSFT_Disk.BusType`` / ``STORAGE_BUS_TYPE``, by numeric code.
BUS_TYPES: dict[int, str] = {
    0: "Unknown",
    1: "SCSI",
    2: "ATAPI",
    3: "ATA",
    4: "1394",
    5: "SSA",
    6: "Fibre Channel",
    7: "USB",
    8: "RAID",
    9: "iSCSI",
    10: "SAS",
    11: "SATA",
    12: "SD",
    13: "MMC",
    14: "Virtual",
    15: "File Backed Virtual",
    16: "Storage Spaces",
    17: "NVMe",
    18: "SCM",
    19: "UFS",
}

_BUS_TO_INTERFACE: dict[str, Interface] = {
    "usb": "usb",
    "nvme": "nvme",
    "sata": "sata",
    "ata": "sata",
    "atapi": "sata",
    "sas": "sas",
    "scsi": "scsi",
    "raid": "scsi",
    "iscsi": "scsi",
    "fibre channel": "scsi",
    "sd": "mmc",
    "mmc": "mmc",
    "ufs": "mmc",
    "virtual": "virtual",
    "file backed virtual": "virtual",
    "storage spaces": "virtual",
    "spaces": "virtual",
}

#: ``MSFT_PhysicalDisk.MediaType``.
_MEDIA_CODES = {0: "Unspecified", 3: "HDD", 4: "SSD", 5: "SCM"}


def _as_list(value: Any) -> list[Any]:
    """ConvertTo-Json collapses a one-element array to a scalar."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _enum_name(value: Any, table: dict[int, str]) -> str:
    if value is None:
        return ""
    if isinstance(value, int):
        return table.get(value, str(value))
    text = str(value).strip()
    if text.isdigit():
        return table.get(int(text), text)
    return text


def _letter(value: Any) -> str:
    text = str(value or "").strip().strip("\x00").strip(":").strip()
    return text[:1].upper() if text and text[:1].isalpha() else ""


def _media(bus: str, media_name: str) -> tuple[MediaType, str]:
    upper = media_name.upper()
    if upper == "HDD":
        return "hdd", "Get-PhysicalDisk reports MediaType HDD."
    if upper in {"SSD", "SCM"}:
        return "ssd", f"Get-PhysicalDisk reports MediaType {upper}."
    lowered = bus.lower()
    if lowered == "nvme":
        return "ssd", "The disk is on the NVMe bus, which carries only flash."
    if lowered in {"sd", "mmc", "ufs"}:
        return "flash", f"The disk is on the {bus} bus, which carries only flash."
    if lowered == "usb":
        return "flash", (
            "The disk is USB-attached and Windows reports no media type. It is "
            "treated as flash, so the flash limitation is never left out."
        )
    return "unknown", (
        f"Get-PhysicalDisk reports MediaType {media_name or 'Unspecified'} on "
        f"the {bus or 'unknown'} bus, so the medium was not determined."
    )


def parse_inventory(payload: dict[str, Any]) -> list[NormalizedDevice]:
    """Turn the inventory JSON into normalized devices. Pure; no I/O."""
    system_drive = _letter(payload.get("system_drive") or "C")
    page_letters = {
        _letter(str(name).split(":", 1)[0])
        for name in _as_list(payload.get("pagefiles"))
        if name
    }
    hiberfil = bool(payload.get("hiberfil"))

    physical = {
        str(item.get("DeviceId")): item
        for item in _as_list(payload.get("physical"))
        if isinstance(item, dict)
    }
    volumes = {
        _letter(item.get("DriveLetter")): item
        for item in _as_list(payload.get("volumes"))
        if isinstance(item, dict) and _letter(item.get("DriveLetter"))
    }
    by_disk: dict[int, list[dict[str, Any]]] = {}
    for part in _as_list(payload.get("partitions")):
        if isinstance(part, dict) and part.get("DiskNumber") is not None:
            by_disk.setdefault(int(part["DiskNumber"]), []).append(part)

    devices: list[NormalizedDevice] = []
    for disk in _as_list(payload.get("disks")):
        if not isinstance(disk, dict) or disk.get("Number") is None:
            continue
        number = int(disk["Number"])
        bus = _enum_name(disk.get("BusType"), BUS_TYPES)
        interface = _BUS_TO_INTERFACE.get(bus.lower(), "unknown")
        phys = physical.get(str(number), {})
        media_name = _enum_name(phys.get("MediaType"), _MEDIA_CODES)
        media_type, media_basis = _media(bus, media_name)

        partitions: list[PartitionInfo] = []
        mount_points: list[str] = []
        filesystems: set[str] = set()
        letters: set[str] = set()
        reasons: list[str] = []
        for part in sorted(
            by_disk.get(number, []), key=lambda p: int(p.get("PartitionNumber") or 0)
        ):
            letter = _letter(part.get("DriveLetter"))
            paths = [
                str(item)
                for item in _as_list(part.get("AccessPaths"))
                if item and not str(item).startswith("\\\\?\\")
            ]
            if letter:
                letters.add(letter)
                paths = sorted({f"{letter}:\\", *paths})
            volume = volumes.get(letter, {}) if letter else {}
            fs = str(volume.get("FileSystem") or "")
            if fs:
                filesystems.add(fs)
            mount_points.extend(paths)
            partitions.append(
                PartitionInfo(
                    id=f"Disk {number} Partition {part.get('PartitionNumber')}",
                    size_bytes=int(part.get("Size") or 0),
                    filesystem=fs,
                    label=str(volume.get("FileSystemLabel") or ""),
                    mount_points=paths,
                )
            )

        if disk.get("IsBoot"):
            reasons.append("Windows reports this as the boot disk (IsBoot).")
        if disk.get("IsSystem"):
            reasons.append(
                "Windows reports this disk holds the system partition (IsSystem)."
            )
        if system_drive and system_drive in letters:
            reasons.append(f"Holds the Windows system volume {system_drive}:.")
        paged = sorted(letters & page_letters)
        if paged:
            reasons.append(
                "Holds an active page file on "
                + ", ".join(f"{p}:" for p in paged)
                + "."
            )
        if hiberfil and system_drive in letters:
            reasons.append("Holds the hibernation file (hiberfil.sys).")
        if interface == "virtual" and bus.lower() in {"storage spaces", "spaces"}:
            reasons.append(
                "Is a Storage Spaces virtual disk; its physical members are "
                "not addressable through it."
            )

        serial = str(disk.get("SerialNumber") or phys.get("SerialNumber") or "").strip()
        model = str(disk.get("Model") or disk.get("FriendlyName") or "").strip()
        limitations: list[str] = []
        if not serial:
            limitations.append(
                "Windows reported no serial number for this disk; it is "
                "identified by its UniqueId instead."
            )
        devices.append(
            NormalizedDevice(
                id=f"PhysicalDrive{number}",
                platform="windows",
                path=f"\\\\.\\PhysicalDrive{number}",
                vendor=str(disk.get("Manufacturer") or "").strip(),
                model=model,
                serial=serial,
                capacity_bytes=int(disk.get("Size") or 0),
                interface=interface,
                media_type=media_type,
                media_basis=media_basis,
                removable=(
                    True
                    if interface in {"usb", "mmc"}
                    else False
                    if interface in {"sata", "nvme", "sas", "scsi"}
                    else None
                ),
                mounted=bool(mount_points),
                mount_points=sorted(set(mount_points)),
                system_device=bool(reasons),
                system_reasons=reasons,
                filesystems=sorted(filesystems),
                partitions=partitions,
                stable_id=str(disk.get("UniqueId") or "").strip(),
                limitations=limitations,
            )
        )
    return devices


def encoded_script() -> str:
    """:data:`INVENTORY_SCRIPT` as ``-EncodedCommand`` wants it.

    Base64 of UTF-16LE. Passing the script this way means no character in it
    is ever subject to Windows command-line quoting, which PowerShell 5.1
    parses differently from ``CreateProcess``.
    """
    return base64.b64encode(INVENTORY_SCRIPT.encode("utf-16-le")).decode("ascii")


def powershell_path() -> str:
    """Absolute path of Windows PowerShell 5.1 in the real system directory.

    ``GetSystemDirectoryW`` rather than ``%SystemRoot%``: the environment is
    the caller's to change, the kernel's answer is not.
    """
    system_dir = ""
    try:
        import ctypes

        windll = getattr(ctypes, "windll", None)
        if windll is not None:
            buffer = ctypes.create_unicode_buffer(260)
            if windll.kernel32.GetSystemDirectoryW(buffer, 260):
                system_dir = buffer.value
    except (OSError, AttributeError):
        system_dir = ""
    if not system_dir:
        system_dir = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"), "System32"
        )
    return os.path.join(system_dir, "WindowsPowerShell", "v1.0", "powershell.exe")


class WindowsAdapter(BaseAdapter):
    """Windows 10/11."""

    name = "windows"
    family = "windows"
    sanitize_capabilities = (
        Capability.NVME_SANITIZE,
        Capability.ATA_SANITIZE,
        Capability.CRYPTO_ERASE,
    )

    def __init__(
        self,
        *,
        helper: str = "in-process",
        helper_basis: str = "",
        runner: Any = None,
        native: NativeApi | None = None,
        privilege: PrivilegeState | None = None,
        os_build: int | None = None,
        poll_s: float = 5.0,
    ) -> None:
        super().__init__(helper=helper, helper_basis=helper_basis, privilege=privilege)
        if runner is None:
            from core.device._sysio import SubprocessRunner

            runner = SubprocessRunner(timeout_s=60.0)
        self._runner = runner
        self._native = native
        self._os_build = os_build
        self._poll_s = poll_s
        self._probes: dict[str, dict[str, MechanismProbe]] = {}

    def native(self) -> NativeApi:
        """The kernel32 binding, created on first use (Windows only)."""
        if self._native is None:
            from core.device.win.native import default_api

            self._native = default_api()
        return self._native

    def os_build(self) -> int:
        if self._os_build is not None:
            return self._os_build
        import sys

        version = getattr(sys, "getwindowsversion", None)
        return int(version().build) if version is not None else 0

    def inventory(self) -> dict[str, Any]:
        """Run the inventory script. Raises :class:`PlatformUnsupported`."""
        argv = [
            powershell_path(),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            encoded_script(),
        ]
        result = self._runner.run(argv)
        if not result.ok:
            detail = (result.stderr or result.stdout).strip()[:300]
            raise PlatformUnsupported(
                "Windows storage discovery (Get-Disk) failed: "
                + (detail or f"exit code {result.returncode}"),
                remediation=(
                    "Confirm the Windows Storage module is present "
                    "(Get-Command Get-Disk) and that PowerShell is not blocked "
                    "by policy on this machine."
                ),
            )
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise PlatformUnsupported(
                f"Windows storage discovery returned unreadable output ({exc})."
            ) from exc
        if not isinstance(payload, dict):
            raise PlatformUnsupported("Windows storage discovery returned no object.")
        return payload

    def enumerate_devices(
        self, *, include_virtual: bool = False
    ) -> list[NormalizedDevice]:
        try:
            devices = parse_inventory(self.inventory())
        except PlatformUnsupported as exc:
            self.discovery.record(
                ok=False,
                tool="PowerShell Storage module",
                detail=exc.message,
                devices=[],
            )
            raise
        if not include_virtual:
            devices = [item for item in devices if item.interface != "virtual"]
        self.discovery.record(
            ok=True,
            tool="PowerShell Get-Disk / Get-PhysicalDisk / Get-Partition / Get-Volume",
            detail="disks read from the Windows Storage module",
            devices=devices,
        )
        return devices

    def whole_drive_unavailable_reason(self) -> str:
        return ""

    def whole_drive_recommended_action(self) -> str:
        return (
            "Run Sanctum as Administrator. Take the disk offline first (Devices > "
            "Prepare, or Disk Management > Offline) so no volume on it is "
            "mounted, then rescan."
        )

    def _elevation_advice(self) -> str:
        return (
            "Close Sanctum and start it again with Run as administrator. The "
            "Windows build has no separate helper: raw disk access is granted "
            "to an elevated process only."
        )

    # -- probes -------------------------------------------------------------

    def device_probes(self, device: NormalizedDevice) -> dict[str, MechanismProbe]:
        cached = self._probes.get(device.id)
        if cached is not None:
            return cached
        elevated = self._privileged_enough(self.privilege_state()) is True
        try:
            api = self.native() if elevated else None
        except OSError:
            api = None
        probes = probe_mechanisms(api, device)
        self._probes[device.id] = probes
        return probes

    def drive_options(
        self, device: NormalizedDevice
    ) -> tuple[list[SanitizeOption], str]:
        resolution = self.device_resolution(device)
        return options_from_resolution(resolution, nvme_bus=device.interface == "nvme")

    def _platform_rows(self, privilege: PrivilegeState) -> list[OperationCapability]:
        return self._block_engine_rows(privilege)

    # -- the workflow's fresh read ---------------------------------------------

    def authorization_probe(self, path: str) -> dict[str, Any]:
        device = self.inspect_device(path)
        resolution = self.device_resolution(device)
        achievable: list[str] = []
        clear = resolution.get(Capability.WHOLE_DRIVE_CLEAR)
        if clear.state in RUNNABLE_STATES:
            achievable.append("CLEAR")
        if resolution.sanitize_order:
            achievable.append("PURGE")
        limits = sorted(
            {text for row in resolution.capabilities for text in row.limitations}
        )
        row = core_device(device).model_dump(mode="json")
        row["stable_id"] = device.stable_id
        return {
            "device": row,
            "capabilities": {
                "achievable_levels": achievable,
                "est_erase_seconds": int(device.capacity_bytes / (30 * 1024 * 1024)),
                "limitations": limits,
                "resolution": resolution.model_dump(mode="json"),
            },
        }

    # -- execution ------------------------------------------------------------

    def execute_drive_sanitization(
        self, params: dict[str, Any]
    ) -> Generator[dict[str, Any], None, dict[str, Any]]:
        from core.device.win.disk import parse_disk_number

        level = str(params.get("level", "CLEAR"))
        device = self._revalidated(params)
        # AEGIS policy (2026-10-03): only removable USB / SD / MMC media are ever
        # sanitized; every internal drive is refused here as well as in the bridge.
        if str(device.interface or "").lower() not in {"usb", "sd", "mmc"} or device.internal is True:
            raise SystemDiskRefused(
                f"Refusing {device.path}: it is an internal or unidentified drive "
                f"(interface {device.interface or 'unknown'}). AEGIS sanitizes only removable "
                "USB or SD/MMC media. Nothing was written."
            )
        capability, resolution = self._choose(device, level)
        number = parse_disk_number(device.id)
        sink = ledger_sink(params)
        job_id = str(params["job_id"])
        if capability is Capability.WHOLE_DRIVE_CLEAR:
            generator: Any = self._clear(
                device, number, resolution, job_id, sink,
                method=_overwrite_method(params.get("overwrite_method")),
            )
        else:
            generator = self._sanitize(
                device, number, capability, resolution, job_id, sink
            )
        return (yield from json_records(generator))

    def resume_drive_sanitization(
        self, params: dict[str, Any]
    ) -> Generator[dict[str, Any], None, dict[str, Any]]:
        from core.device.win.disk import parse_disk_number

        device = self._revalidated(params)
        _, resolution = self._choose(device, "CLEAR")
        sink = ledger_sink(params)
        job_id = str(params["job_id"])
        checkpoint = sink.last_checkpoint(job_id)
        if checkpoint is None:
            raise UnsupportedCapability(
                f"No checkpoint was recorded for job {job_id}; only an "
                "interrupted clear resumes.",
                remediation="Start the clear again from the beginning.",
            )
        generator = self._clear(
            device,
            parse_disk_number(device.id),
            resolution,
            job_id,
            sink,
            resume_from=checkpoint,
        )
        return (yield from json_records(generator))

    def _open_bound(self, number: int, device: NormalizedDevice, *, write: bool) -> Any:
        """Open, bind, and (for a write) check the volume manager once more."""
        from core.device.win.disk import WindowsDisk, volumes_on_disk

        api = self.native()
        disk = WindowsDisk(api, number, write=write).open()
        disk.bind(serial=device.serial, size_bytes=device.capacity_bytes)
        if write:
            # Any volume the volume manager still exposes on this disk, with or
            # without a drive letter, can have a filesystem mounted on demand,
            # and Windows refuses raw writes inside a live volume's extent. An
            # offline disk exposes none, so that is the state required here.
            live = volumes_on_disk(api, number)
            if live:
                disk.close()
                shown = [
                    ", ".join(paths) if paths else volume for volume, paths in live
                ]
                raise MountedRefused(
                    f"{disk.path} still exposes volume(s) {'; '.join(shown)} at "
                    "the write seam. Nothing was written.",
                    remediation="Take the disk offline first (Devices > Prepare, "
                    "or Disk Management > Offline), then retry.",
                )
        return disk

    def _clear(
        self,
        device: NormalizedDevice,
        number: int,
        resolution: Any,
        job_id: str,
        sink: Any,
        *,
        resume_from: Any = None,
        method: Any = None,
    ) -> Any:
        from core.erase.blockclear import ClearRequest, clear
        from core.models import EraseMethod

        row = resolution.get(Capability.WHOLE_DRIVE_CLEAR)
        request = ClearRequest(
            job_id=job_id,
            device=core_device(device),
            identity={
                "number": number,
                "serial": device.serial,
                "model": device.model,
                "size_bytes": device.capacity_bytes,
                "stable_id": device.stable_id,
            },
            platform="windows",
            mechanism=row.mechanism,
            device_class=resolution.device_class,
            flash=device.media_type != "hdd",
            limitations=tuple(row.limitations),
            resume_from=resume_from,
            method=method or EraseMethod.SINGLE_PASS_OVERWRITE,
        )
        return clear(
            request,
            lambda: self._open_bound(number, device, write=True),
            ledger=sink,
        )

    def _sanitize(
        self,
        device: NormalizedDevice,
        number: int,
        capability: Capability,
        resolution: Any,
        job_id: str,
        sink: Any,
    ) -> Any:
        from core.device.win import ata, ioctl, nvme
        from core.erase.devicesanitize import SanitizeRequest, run
        from core.models import EraseMethod, ErasePhase, Progress

        row = resolution.get(capability)
        nvme_bus = device.interface == "nvme"
        if capability is Capability.NVME_SANITIZE:
            method = EraseMethod.NVME_SANITIZE_BLOCK
        elif capability is Capability.ATA_SANITIZE:
            method = EraseMethod.ATA_SANITIZE_BLOCK_ERASE
        elif nvme_bus:
            method = EraseMethod.NVME_SANITIZE_CRYPTO
        else:
            method = EraseMethod.ATA_SANITIZE_CRYPTO_SCRAMBLE
        request = SanitizeRequest(
            job_id=job_id,
            device=core_device(device),
            identity={
                "number": number,
                "serial": device.serial,
                "size_bytes": device.capacity_bytes,
            },
            platform="windows",
            method=method,
            capability=capability.value,
            protocol="NVMe" if nvme_bus else "ATA",
            mechanism=row.mechanism,
            device_class=resolution.device_class,
            limitations=tuple(row.limitations),
        )
        build = self.os_build()

        def issue() -> Generator[Progress, None, dict[str, Any]]:
            disk = self._open_bound(number, device, write=True)
            try:
                if nvme_bus:
                    code = (
                        ioctl.STORAGE_SANITIZE_CRYPTO_ERASE
                        if method is EraseMethod.NVME_SANITIZE_CRYPTO
                        else ioctl.STORAGE_SANITIZE_BLOCK_ERASE
                    )
                    record = nvme.reinitialize_media(
                        disk, code, timeout_s=6 * 3600, os_build=build
                    )
                    limits = [str(record["note"])]
                    return {"hw_attested": False, **record, "limitations": limits}
                action = (
                    ata.SANITIZE_BLOCK_ERASE
                    if method is EraseMethod.ATA_SANITIZE_BLOCK_ERASE
                    else ata.SANITIZE_CRYPTO_SCRAMBLE
                )
                polling = ata.sanitize(disk, action, poll_s=self._poll_s)
                while True:
                    try:
                        status = next(polling)
                    except StopIteration as stop:
                        final = stop.value
                        break
                    yield Progress(
                        job_id=job_id,
                        phase=ErasePhase.ERASE.value,
                        pct_bp=min(10_000, status.progress * 10_000 // 65_536),
                        bytes_done=0,
                        bytes_total=device.capacity_bytes,
                        throughput_bytes_per_sec=0,
                        eta_seconds=0,
                        message="drive sanitizing",
                    )
                return {
                    "hw_attested": bool(final.completed_ok),
                    "command": f"SANITIZE {ata.SANITIZE_NAMES[action]}",
                    "sanitize_status": "completed successfully",
                }
            finally:
                disk.close()

        return run(
            request,
            issue=issue,
            open_reader=lambda: self._open_bound(number, device, write=False),
            ledger=sink,
        )

    # -- preparation -------------------------------------------------------------

    def prepare_device(self, params: dict[str, Any]) -> dict[str, Any]:
        """Take a disk offline (non-persistently), as its own explicit step.

        Needs the typed serial, refuses the system disk, and binds the handle
        before the attribute is changed.
        Taking a disk offline dismounts its volumes; it writes nothing to the
        medium, and the disk returns online at the next replug or reboot.
        """
        from core.device.guard import refuse_removed_mode_keys
        from core.device.win.disk import WindowsDisk, parse_disk_number

        refuse_removed_mode_keys(params)
        device = self.inspect_device(str(params["path"]))
        if device.system_device:
            raise SystemDiskRefused(
                f"Refusing to take {device.path} offline: it is the system disk."
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
            "action": "IOCTL_DISK_SET_DISK_ATTRIBUTES offline, not persistent",
            "unmounts": device.mount_points,
        }
        disk = WindowsDisk(self.native(), parse_disk_number(device.id), write=True)
        disk.open()
        try:
            disk.bind(serial=device.serial, size_bytes=device.capacity_bytes)
            disk.set_offline(offline=True, persist=False)
        finally:
            disk.close()
        return {**action, "performed": True}

    def _file_limitations(self) -> list[str]:
        return [
            "NTFS keeps files smaller than roughly 700 bytes resident inside "
            "their MFT record, where an overwrite through the file handle does "
            "not reach; such files are reported as not destroyed.",
            "Volume Shadow Copies can only be listed from an elevated prompt; "
            "unelevated, whether one holds the old data is reported as unknown.",
            "Windows offers no unprivileged directory flush, so the rename "
            "chain may linger in the directory index until NTFS flushes it.",
            FLASH_LIMITATION,
        ]

    def restrictions(self) -> list[str]:
        return [
            "Whole-drive clear and device sanitize need Sanctum running as "
            "Administrator; the Windows build has no separate helper.",
            "A disk with a mounted volume is refused; take it offline first. A "
            "drive letter is never accepted as a whole-disk target.",
            "ATA SECURITY ERASE and NVMe Format NVM are not issued on Windows; "
            "ATA SANITIZE and NVMe Sanitize are, where the controller reports them.",
            "Free-space wipe is not implemented on Windows.",
            "Physical read-back of an erased file needs an elevated process "
            "(raw volume read of \\\\.\\C:); unelevated it is reported as not "
            "verified.",
        ]


# --------------------------------------------------------------------------
# Probes and options, pure given the native API
# --------------------------------------------------------------------------

_DEVICE_CAPS = (
    Capability.ATA_SANITIZE,
    Capability.ATA_SECURITY_ERASE,
    Capability.NVME_SANITIZE,
    Capability.NVME_FORMAT,
    Capability.CRYPTO_ERASE,
    Capability.HPA_DCO_DISCOVERY,
    Capability.HPA_DCO_MODIFY,
)


def _overwrite_method(value: Any) -> Any:
    """The software overwrite profile a Clear runs. AEGIS integration (2026-10-03).

    Only the profiles core.erase.patterns can generate and verify are accepted;
    anything else is refused rather than silently replaced by a default.
    """
    from core.erase.patterns import SOFTWARE_METHODS
    from core.models import EraseMethod

    if value in (None, ""):
        return EraseMethod.SINGLE_PASS_OVERWRITE
    try:
        method = EraseMethod(str(value))
    except ValueError as exc:
        raise UnsupportedCapability(f"Unknown overwrite profile {value!r}.") from exc
    if method not in SOFTWARE_METHODS:
        raise UnsupportedCapability(
            f"{method.value} is not a software overwrite profile; a Clear runs "
            "SINGLE_PASS_OVERWRITE or DOD_5220_22_M_3PASS."
        )
    return method


def _all(exposed: bool | None, basis: str, command: str) -> dict[str, MechanismProbe]:
    from core.platform.capability import MechanismProbe

    return {
        item.value: MechanismProbe(exposed=exposed, basis=basis, command=command)
        for item in _DEVICE_CAPS
    }


def probe_mechanisms(
    api: NativeApi | None, device: NormalizedDevice
) -> dict[str, MechanismProbe]:
    """Ask the controller what it supports. ``api=None`` means unelevated.

    Read-only commands only: IDENTIFY DEVICE, SANITIZE STATUS EXT, and the NVMe
    Identify Controller property query. A refusal is recorded as the answer
    for every mechanism it hides, with the reason; an untrustworthy IDENTIFY
    (bad checksum) settles nothing.
    """
    from core.device.win import ata, nvme
    from core.device.win.disk import WindowsDisk, parse_disk_number
    from core.platform.capability import MechanismProbe

    if api is None:
        return _all(
            None,
            "Not probed: asking the controller needs an Administrator process.",
            "not run (unelevated)",
        )
    if device.interface in {"mmc", "virtual"}:
        return _all(
            False,
            f"A {device.interface} device exposes no ATA or NVMe command set to "
            "the host.",
            "bus type from Get-Disk",
        )
    try:
        number = parse_disk_number(device.id)
    except UnsupportedCapability as exc:
        return _all(None, exc.message, "not run")
    probes: dict[str, MechanismProbe] = {}
    if device.interface == "nvme":
        try:
            with WindowsDisk(api, number) as disk:
                identity = nvme.identify_controller(disk)
        except (UnsupportedCapability, OSError) as exc:
            return _all(False, str(exc), "IOCTL_STORAGE_QUERY_PROPERTY Identify")
        command = "IOCTL_STORAGE_QUERY_PROPERTY NVMe Identify Controller"
        probes[Capability.NVME_SANITIZE.value] = MechanismProbe(
            exposed=identity.block_erase,
            basis=f"SANICAP block erase: {'yes' if identity.block_erase else 'no'}.",
            command=command,
        )
        probes[Capability.CRYPTO_ERASE.value] = MechanismProbe(
            exposed=identity.crypto_erase,
            basis=f"SANICAP crypto erase: {'yes' if identity.crypto_erase else 'no'}.",
            command=command,
        )
        probes[Capability.NVME_FORMAT.value] = MechanismProbe(
            exposed=identity.format_supported,
            basis=f"OACS Format NVM: {'yes' if identity.format_supported else 'no'}.",
            command=command,
        )
        for item in (
            Capability.ATA_SANITIZE,
            Capability.ATA_SECURITY_ERASE,
            Capability.HPA_DCO_DISCOVERY,
            Capability.HPA_DCO_MODIFY,
        ):
            probes[item.value] = MechanismProbe(
                exposed=False,
                basis="An NVMe controller has no ATA command set, HPA or DCO.",
                command=command,
            )
        return probes
    command = "IOCTL_ATA_PASS_THROUGH IDENTIFY DEVICE"
    try:
        with WindowsDisk(api, number, write=True) as disk:
            identity_ata = ata.identify(disk)
            frozen = False
            if identity_ata.sanitize_supported and identity_ata.trustworthy:
                try:
                    frozen = ata.sanitize_status(disk).frozen
                except (UnsupportedCapability, OSError):
                    frozen = False
    except (UnsupportedCapability, OSError) as exc:
        return _all(False, str(exc), command)
    if not identity_ata.trustworthy:
        return _all(
            None,
            "IDENTIFY DEVICE came back with a bad checksum; the answer was not "
            "the drive's, and nothing is inferred from it.",
            command,
        )
    sanitize_basis = (
        "SANITIZE feature set: "
        + ("yes" if identity_ata.sanitize_supported else "no")
        + f"; BLOCK ERASE EXT: {'yes' if identity_ata.block_erase else 'no'}"
        + f"; CRYPTO SCRAMBLE EXT: {'yes' if identity_ata.crypto_scramble else 'no'}."
    )
    frozen_basis = " SANITIZE FROZEN is set until the next power cycle."
    probes[Capability.ATA_SANITIZE.value] = MechanismProbe(
        exposed=identity_ata.sanitize_supported and identity_ata.block_erase,
        blocked=frozen,
        basis=sanitize_basis + (frozen_basis if frozen else ""),
        command=command,
    )
    probes[Capability.CRYPTO_ERASE.value] = MechanismProbe(
        exposed=identity_ata.sanitize_supported and identity_ata.crypto_scramble,
        blocked=frozen,
        basis=sanitize_basis + (frozen_basis if frozen else ""),
        command=command,
    )
    probes[Capability.ATA_SECURITY_ERASE.value] = MechanismProbe(
        exposed=identity_ata.security_supported,
        blocked=identity_ata.security_frozen,
        basis="Security feature set: "
        + ("yes" if identity_ata.security_supported else "no")
        + ("; frozen" if identity_ata.security_frozen else ""),
        command=command,
    )
    hpa_basis = (
        f"HPA feature set: {'yes' if identity_ata.hpa_supported else 'no'}; "
        f"DCO: {'yes' if identity_ata.dco_supported else 'no'}."
    )
    for item in (Capability.HPA_DCO_DISCOVERY, Capability.HPA_DCO_MODIFY):
        probes[item.value] = MechanismProbe(
            exposed=identity_ata.hpa_supported, basis=hpa_basis, command=command
        )
    for item in (Capability.NVME_SANITIZE, Capability.NVME_FORMAT):
        probes[item.value] = MechanismProbe(
            exposed=False,
            basis="The device answered as ATA, not NVMe.",
            command=command,
        )
    return probes


_OPTION_METHOD: dict[Capability, str] = {
    Capability.NVME_SANITIZE: "NVME_SANITIZE_BLOCK",
    Capability.ATA_SANITIZE: "ATA_SANITIZE_BLOCK_ERASE",
}


def options_from_resolution(
    resolution: Any, *, nvme_bus: bool = False
) -> tuple[list[SanitizeOption], str]:
    """Sanitize options straight from the resolver: Purge first, then Clear."""
    from core.platform.capability import legacy_status
    from core.platform.model import STATE_LABELS

    options: list[SanitizeOption] = []
    purge = None
    for capability in (
        Capability.NVME_SANITIZE,
        Capability.ATA_SANITIZE,
        Capability.CRYPTO_ERASE,
    ):
        row = resolution.get(capability)
        if row.state in RUNNABLE_STATES or (
            row.state is CapabilityState.AVAILABLE_BUT_REQUIRES_PRIVILEGE
        ):
            purge = row
            break
    if purge is None:
        # The reason shown is the one for the command set this device would
        # speak: NVMe for an NVMe device, ATA for everything else.
        order = (
            (Capability.NVME_SANITIZE, Capability.CRYPTO_ERASE, Capability.ATA_SANITIZE)
            if nvme_bus
            else (
                Capability.ATA_SANITIZE,
                Capability.CRYPTO_ERASE,
                Capability.NVME_SANITIZE,
            )
        )
        best = min(
            (resolution.get(item) for item in order),
            key=lambda row: row.state is CapabilityState.UNSUPPORTED_BY_PLATFORM,
        )
        options.append(
            SanitizeOption(
                level="PURGE",
                title="Device sanitize (Purge)",
                status=legacy_status(best.state),
                state=best.state,
                state_label=STATE_LABELS[best.state],
                capability=best.capability,
                why=best.reason,
                remediation="Choose Clear, or attach the drive directly.",
            )
        )
    else:
        crypto = purge.capability is Capability.CRYPTO_ERASE
        options.append(
            SanitizeOption(
                level="PURGE",
                title="Cryptographic erase (Purge)"
                if crypto
                else "Device sanitize (Purge)",
                status=legacy_status(purge.state),
                method=_OPTION_METHOD.get(
                    purge.capability,
                    "NVME_SANITIZE_CRYPTO"
                    if purge.protocol == "NVMe"
                    else "ATA_SANITIZE_CRYPTO_SCRAMBLE",
                ),
                why=purge.reason,
                technical=[purge.mechanism, purge.assurance],
                verification=purge.verification,
            )
        )
    clear = resolution.get(Capability.WHOLE_DRIVE_CLEAR)
    options.append(
        SanitizeOption(
            level="CLEAR",
            title="Addressable overwrite (Clear)",
            status=legacy_status(clear.state),
            method="SINGLE_PASS_OVERWRITE",
            why=clear.reason,
            technical=[clear.mechanism, clear.assurance],
            verification=clear.verification,
        )
    )
    return options, clear.verification
