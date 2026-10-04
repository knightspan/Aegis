"""A handle to one ``\\\\.\\PhysicalDriveN``, bound to the disk it names.

The rule this module exists for: **the identity is read from the open handle,
never trusted from the path.** Between discovery and the first write a USB
disk can be unplugged and another take its number. So after ``CreateFileW``
the handle itself is asked which disk it is (``IOCTL_STORAGE_GET_DEVICE_NUMBER``),
what serial it reports (``IOCTL_STORAGE_QUERY_PROPERTY``) and how long it is
(``IOCTL_DISK_GET_LENGTH_INFO``), and :meth:`WindowsDisk.bind` refuses on any
difference from what the plan recorded. Every later read or write goes through
that same handle.

A drive letter is never accepted here. ``E:\\`` is a volume, not a device:
clearing the volume leaves the partition table and every other partition, and
acquiring it misses unallocated space. :func:`disk_path` builds the only path
shape this module opens for a whole disk.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from types import TracebackType

from core.device.win import ioctl
from core.device.win.native import NativeApi, NativeError
from core.errors import ConfirmationMismatch, DeviceVanished, UnsupportedCapability

__all__ = [
    "DiskIdentity",
    "WindowsDisk",
    "disk_path",
    "parse_disk_number",
    "volumes_on_disk",
]

_PHYSICAL = re.compile(r"^(?:\\\\\.\\)?PhysicalDrive(\d{1,3})$", re.IGNORECASE)


def parse_disk_number(device_id: str) -> int:
    """``PhysicalDrive2`` or ``\\\\.\\PhysicalDrive2`` -> 2. Anything else refuses."""
    match = _PHYSICAL.match(device_id.strip())
    if match is None:
        raise UnsupportedCapability(
            f"{device_id!r} is not a physical disk. A drive letter or volume "
            "names a filesystem, not the device under it.",
            remediation="Select the physical disk (PhysicalDriveN) from the "
            "Devices screen. Nothing was opened.",
        )
    return int(match.group(1))


def disk_path(number: int) -> str:
    """The Win32 device path of disk ``number``."""
    if number < 0 or number > 999:
        raise ValueError(f"disk number {number} out of range")
    return f"\\\\.\\PhysicalDrive{number}"


@dataclass(frozen=True)
class DiskIdentity:
    """Who the open handle says it is."""

    number: int
    serial: str
    vendor: str
    product: str
    size_bytes: int
    logical_sector: int
    physical_sector: int
    bus: str
    removable: bool

    @property
    def model(self) -> str:
        return " ".join(part for part in (self.vendor, self.product) if part)


def _norm(serial: str) -> str:
    return "".join(serial.split()).upper()


class WindowsDisk:
    """One open, identity-bound handle to a physical disk."""

    def __init__(self, api: NativeApi, number: int, *, write: bool = False) -> None:
        self.api = api
        self.number = number
        self.path = disk_path(number)
        self.write = write
        self._handle: int | None = None
        self.identity: DiskIdentity | None = None

    # -- lifecycle --------------------------------------------------------------

    def open(self) -> WindowsDisk:
        try:
            self._handle = self.api.open(self.path, write=self.write)
        except NativeError as exc:
            if exc.winerror == ioctl.ERROR_ACCESS_DENIED:
                raise UnsupportedCapability(
                    f"Windows refused to open {self.path}"
                    + (" for writing" if self.write else "")
                    + " (access denied): raw disk access needs a process "
                    "running as Administrator.",
                    remediation="Raw disk access needs an elevated process: run "
                    "Sanctum as Administrator. Nothing was opened.",
                ) from exc
            if exc.winerror in ioctl.GONE_ERRORS:
                raise DeviceVanished(
                    f"{self.path} is not present (Win32 error {exc.winerror})."
                ) from exc
            raise
        return self

    def close(self) -> None:
        handle, self._handle = self._handle, None
        if handle is not None:
            try:
                self.api.close(handle)
            except NativeError:
                pass

    def __enter__(self) -> WindowsDisk:
        return self.open()

    def __exit__(
        self,
        kind: type[BaseException] | None,
        value: BaseException | None,
        trace: TracebackType | None,
    ) -> None:
        self.close()

    @property
    def size_bytes(self) -> int:
        """The bound length. Only meaningful after :meth:`bind`."""
        if self.identity is None:
            raise DeviceVanished(f"{self.path} was not bound.")
        return self.identity.size_bytes

    @property
    def logical_sector(self) -> int:
        if self.identity is None:
            raise DeviceVanished(f"{self.path} was not bound.")
        return self.identity.logical_sector

    @property
    def handle(self) -> int:
        if self._handle is None:
            raise DeviceVanished(f"{self.path} is not open.")
        return self._handle

    # -- identity -----------------------------------------------------------------

    def ioctl(self, code: int, data: bytes, out_size: int) -> bytes:
        return self.api.ioctl(self.handle, code, data, out_size)

    def read_identity(self) -> DiskIdentity:
        """Ask the open handle which disk it is. Every field from the handle."""
        _, number, _ = ioctl.parse_device_number(
            self.ioctl(ioctl.IOCTL_STORAGE_GET_DEVICE_NUMBER, b"", 12)
        )
        descriptor = ioctl.parse_device_descriptor(
            self.ioctl(
                ioctl.IOCTL_STORAGE_QUERY_PROPERTY,
                ioctl.pack_property_query(ioctl.STORAGE_DEVICE_PROPERTY),
                1024,
            )
        )
        size = ioctl.parse_length_info(
            self.ioctl(ioctl.IOCTL_DISK_GET_LENGTH_INFO, b"", 8)
        )
        logical, physical = self._sector_sizes()
        identity = DiskIdentity(
            number=number,
            serial=descriptor.serial,
            vendor=descriptor.vendor,
            product=descriptor.product,
            size_bytes=size,
            logical_sector=logical,
            physical_sector=physical,
            bus=descriptor.bus_name,
            removable=descriptor.removable,
        )
        self.identity = identity
        return identity

    def _sector_sizes(self) -> tuple[int, int]:
        try:
            return ioctl.parse_access_alignment(
                self.ioctl(
                    ioctl.IOCTL_STORAGE_QUERY_PROPERTY,
                    ioctl.pack_property_query(ioctl.STORAGE_ACCESS_ALIGNMENT_PROPERTY),
                    64,
                )
            )
        except (NativeError, ValueError):
            sector, _ = ioctl.parse_geometry_ex(
                self.ioctl(ioctl.IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, b"", 256)
            )
            return sector, sector

    def bind(self, *, serial: str, size_bytes: int) -> DiskIdentity:
        """Refuse unless the open handle is the disk the plan recorded.

        The disk number, the serial and the length must all match. A disk that
        reports no serial cannot be bound and is refused: without one, a
        different disk of the same size in the same slot is indistinguishable.
        """
        identity = self.read_identity()
        problems: list[str] = []
        if identity.number != self.number:
            problems.append(
                f"the handle for {self.path} reports disk {identity.number}"
            )
        if not _norm(serial):
            problems.append("no serial was recorded for this disk")
        elif _norm(identity.serial) != _norm(serial):
            problems.append(
                f"the disk now reports serial {identity.serial!r}, the plan "
                f"recorded {serial!r}"
            )
        if identity.size_bytes != size_bytes:
            problems.append(
                f"the disk is now {identity.size_bytes} bytes, the plan recorded "
                f"{size_bytes}"
            )
        if identity.logical_sector <= 0 or identity.logical_sector & (
            identity.logical_sector - 1
        ):
            problems.append(
                f"the logical sector size {identity.logical_sector} is not a "
                "power of two"
            )
        if problems:
            self.close()
            raise ConfirmationMismatch(
                f"{self.path} is not the disk that was planned: "
                + "; ".join(problems)
                + ". Nothing was written.",
                remediation="Rescan the devices and plan the operation again "
                "against the disk that is attached now.",
            )
        return identity

    # -- I/O ------------------------------------------------------------------------

    def _check_aligned(self, offset: int, length: int) -> int:
        identity = self.identity
        if identity is None:
            raise DeviceVanished(f"{self.path} was not bound before I/O.")
        sector = identity.logical_sector
        if offset % sector or length % sector:
            raise ValueError(
                f"unbuffered I/O at {offset}+{length} is not a multiple of the "
                f"{sector}-byte sector"
            )
        if offset + length > identity.size_bytes:
            raise ValueError(
                f"I/O at {offset}+{length} runs past the end of the "
                f"{identity.size_bytes}-byte disk"
            )
        return sector

    def read_at(self, offset: int, length: int) -> bytes:
        self._check_aligned(offset, length)
        return self.api.read(self.handle, offset, length)

    def write_at(self, offset: int, data: bytes | memoryview) -> int:
        if not self.write:
            raise PermissionError(f"{self.path} was opened read-only")
        self._check_aligned(offset, len(data))
        return self.api.write(self.handle, offset, data)

    def flush(self) -> None:
        if self.write:
            self.api.flush(self.handle)

    def set_offline(self, *, offline: bool = True, persist: bool = False) -> None:
        """Take the disk offline (or back online), dismounting its volumes.

        An explicit, operator-requested preparation step, never part of an
        erase. Not persistent by default: the disk comes back online at the
        next boot or replug. Needs a write handle, as Windows does.
        """
        if not self.write:
            raise PermissionError(f"{self.path} must be opened for writing")
        self.ioctl(
            ioctl.IOCTL_DISK_SET_DISK_ATTRIBUTES,
            ioctl.pack_set_disk_attributes(offline=offline, persist=persist),
            0,
        )

    def update_properties(self) -> None:
        """Tell Windows the partition table changed (after a clear or restore)."""
        try:
            self.ioctl(ioctl.IOCTL_DISK_UPDATE_PROPERTIES, b"", 0)
        except NativeError:
            pass


def volumes_on_disk(api: NativeApi, number: int) -> list[tuple[str, list[str]]]:
    """Every volume with an extent on disk ``number``, with its mount paths.

    A second, native check beside the Storage-module discovery: the write path
    asks the volume manager itself which volumes live on the target. A volume
    whose extents cannot be read (an empty optical drive, a volume being torn
    down) is skipped; discovery's ``Get-Partition`` answer still covers it.
    """
    found: list[tuple[str, list[str]]] = []
    for volume in api.volumes():
        target = volume.rstrip("\\")
        try:
            handle = api.open(target, write=False)
        except NativeError:
            continue
        try:
            raw = api.ioctl(
                handle, ioctl.IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, b"", 1024
            )
            disks = {disk for disk, _, _ in ioctl.parse_volume_disk_extents(raw)}
        except (NativeError, ValueError):
            continue
        finally:
            api.close(handle)
        if number in disks:
            try:
                paths = api.volume_paths(volume)
            except NativeError:
                paths = []
            found.append((volume, paths))
    return found
