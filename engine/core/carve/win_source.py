"""Read-only acquisition source for a Windows physical disk or volume.

The source is opened with ``GENERIC_READ`` only - never ``GENERIC_WRITE`` - and
``FILE_FLAG_NO_BUFFERING``, so every byte comes from the device rather than
the cache. Windows has no software write block equivalent to Linux
``BLKROSET``; opening without write access is what this build can do, and the
acquisition record says a hardware write blocker is still the correct control.

**The source is bound to the selected identity.** A physical disk is re-asked
which disk it is through the open handle, and its serial and length must equal
what the operator selected, or nothing is read. There is no silent
substitution: if ``PhysicalDrive2`` is now a different stick, the acquisition
refuses.

Reads from :mod:`core.carve.acquire` arrive in sector multiples except while
it salvages a failed block, when it asks for 512-byte pieces; on a 4Kn disk
those are widened to the enclosing sector here and sliced back, because an
unbuffered handle can read nothing smaller.

A device that disappears raises :class:`~core.errors.DeviceVanished`, never
``OSError``: the acquisition salvages ``OSError`` sector by sector, and a
missing device would otherwise become an image of fill bytes with every sector
"bad".
"""

from __future__ import annotations

import errno
import re

from core.device.win import ioctl
from core.device.win.disk import WindowsDisk, parse_disk_number
from core.device.win.native import NativeApi, NativeError
from core.errors import DeviceVanished, EvidenceIntegrityError, UnsupportedCapability

__all__ = [
    "WindowsDiskReader",
    "WindowsVolumeReader",
    "open_windows_source",
    "LIMITATION",
]

LIMITATION = (
    "Windows has no software write block. The device was opened with read "
    "access only (GENERIC_READ, FILE_FLAG_NO_BUFFERING); a hardware write "
    "blocker remains the correct control and was not verified by this tool."
)

_VOLUME = re.compile(r"^\\\\[.?]\\([A-Za-z]):$")


class _AlignedReads:
    """Sector-widening reads and error translation, shared by both readers."""

    path: str
    size: int
    sector_size: int
    _device_sector: int

    def _raw(self, offset: int, length: int) -> bytes:
        raise NotImplementedError

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise ValueError("negative read")
        length = min(length, self.size - offset)
        if length <= 0:
            return b""
        sector = self._device_sector
        start = (offset // sector) * sector
        end = min(self.size, -(-(offset + length) // sector) * sector)
        try:
            data = self._raw(start, end - start)
        except NativeError as exc:
            if exc.winerror in ioctl.GONE_ERRORS:
                raise DeviceVanished(
                    f"{self.path} disappeared during acquisition at offset "
                    f"{offset} (Win32 error {exc.winerror})."
                ) from exc
            if exc.winerror in ioctl.MEDIUM_ERRORS:
                raise OSError(errno.EIO, f"medium error at {offset}: {exc}") from exc
            raise
        return data[offset - start : offset - start + length]


class WindowsDiskReader(_AlignedReads):
    """``\\\\.\\PhysicalDriveN``, read-only, bound to serial and size."""

    def __init__(
        self,
        api: NativeApi,
        device_id: str,
        *,
        expected_serial: str,
        expected_size: int,
        sector_size: int = 512,
    ) -> None:
        number = parse_disk_number(device_id)
        self._disk = WindowsDisk(api, number, write=False).open()
        try:
            identity = self._disk.bind(serial=expected_serial, size_bytes=expected_size)
        except BaseException:
            self._disk.close()
            raise
        self.path = self._disk.path
        self.size = identity.size_bytes
        self._device_sector = identity.logical_sector
        self.sector_size = max(sector_size, 1)
        self.identity = identity

    def _raw(self, offset: int, length: int) -> bytes:
        return self._disk.read_at(offset, length)

    def close(self) -> None:
        self._disk.close()


class WindowsVolumeReader(_AlignedReads):
    """``\\\\.\\X:``, read-only. A volume, never mistaken for its disk."""

    def __init__(self, api: NativeApi, path: str, *, sector_size: int = 512) -> None:
        match = _VOLUME.match(path)
        if match is None:
            raise UnsupportedCapability(f"{path!r} is not a volume path (\\\\.\\X:).")
        self.path = f"\\\\.\\{match.group(1).upper()}:"
        self._api = api
        try:
            self._handle = api.open(self.path, write=False)
        except NativeError as exc:
            raise EvidenceIntegrityError(
                f"Windows refused to open volume {self.path} (Win32 error "
                f"{exc.winerror}).",
                remediation="Volume acquisition needs an elevated process. "
                "Nothing was read.",
            ) from exc
        self.size = ioctl.parse_length_info(
            api.ioctl(self._handle, ioctl.IOCTL_DISK_GET_LENGTH_INFO, b"", 8)
        )
        try:
            sector, _ = ioctl.parse_geometry_ex(
                api.ioctl(
                    self._handle, ioctl.IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, b"", 256
                )
            )
        except (NativeError, ValueError):
            sector = 512
        self._device_sector = sector or 512
        self.sector_size = max(sector_size, 1)

    def _raw(self, offset: int, length: int) -> bytes:
        return self._api.read(self._handle, offset, length)

    def close(self) -> None:
        try:
            self._api.close(self._handle)
        except NativeError:
            pass


def open_windows_source(
    path: str,
    *,
    expected_serial: str = "",
    expected_size: int = 0,
    api: NativeApi | None = None,
    sector_size: int = 512,
) -> WindowsDiskReader | WindowsVolumeReader:
    """The read-only reader for a Win32 device path.

    A physical disk requires the serial and size the operator selected; a
    request without them is refused rather than bound to whatever answers.
    """
    from core.device.win.native import default_api

    native = api or default_api()
    text = path.strip()
    if "physicaldrive" in text.lower():
        if not expected_serial or expected_size <= 0:
            raise EvidenceIntegrityError(
                f"raw acquisition of {text} needs the serial and size of the disk "
                "that was selected, so the handle can be bound to it",
                remediation="Start the acquisition from the Devices screen, which "
                "sends both. Nothing was opened.",
            )
        return WindowsDiskReader(
            native,
            text,
            expected_serial=expected_serial,
            expected_size=expected_size,
            sector_size=sector_size,
        )
    return WindowsVolumeReader(native, text, sector_size=sector_size)
