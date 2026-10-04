"""An adapter double for :class:`core.device.win.native.NativeApi`.

It answers the same calls the real ``kernel32`` binding answers, from byte
buffers, and it *parses the packed structures the code under test builds*:
an ``IOCTL_ATA_PASS_THROUGH`` request is decoded from its
``ATA_PASS_THROUGH_EX`` header, an NVMe identify query from its
``STORAGE_PROTOCOL_SPECIFIC_DATA``. A layout mistake in
:mod:`core.device.win.ioctl` therefore fails here exactly as it would against
Windows, instead of round-tripping through a fake that shares the mistake.

It never touches a real device. Failure modes are injected per disk:
access denied (unelevated), a USB bridge that refuses ATA pass-through,
medium errors at given sectors, a device that vanishes after N writes, and a
serial that changes between discovery and the write.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field

from core.device.win import ioctl
from core.device.win.native import NativeError

__all__ = ["FakeAta", "FakeDisk", "FakeNvme", "FakeWindowsApi", "build_identify"]


def _ata_string(text: str, words: int) -> bytes:
    raw = text.encode("ascii").ljust(words * 2, b" ")[: words * 2]
    swapped = bytearray()
    for index in range(0, len(raw), 2):
        swapped += bytes([raw[index + 1], raw[index]])
    return bytes(swapped)


def build_identify(
    *,
    model: str,
    serial: str,
    max_lba: int,
    sanitize: bool = False,
    block_erase: bool = False,
    crypto: bool = False,
    security: bool = True,
    frozen: bool = False,
    hpa: bool = True,
    dco: bool = True,
    checksum: bool = True,
    corrupt_checksum: bool = False,
) -> bytes:
    """A 512-byte IDENTIFY DEVICE buffer with the given capabilities."""
    words = [0] * 256
    data = bytearray(512)
    words[59] = (
        (1 << 12 if sanitize else 0)
        | (1 << 13 if crypto else 0)
        | (1 << 15 if block_erase else 0)
    )
    lba28 = min(max_lba, 0x0FFFFFFF)
    words[60] = lba28 & 0xFFFF
    words[61] = (lba28 >> 16) & 0xFFFF
    words[82] = 1 << 10 if hpa else 0
    words[83] = (1 << 10) | (1 << 11 if dco else 0)
    for index in range(4):
        words[100 + index] = (max_lba >> (16 * index)) & 0xFFFF
    words[128] = (0x01 if security else 0) | (0x08 if frozen else 0) | 0x20
    struct.pack_into("<256H", data, 0, *words)
    data[20:40] = _ata_string(serial, 10)
    data[54:94] = _ata_string(model, 20)
    if checksum:
        data[510] = 0xA5
        data[511] = (-sum(data[:511])) & 0xFF
        if corrupt_checksum:
            data[511] ^= 0x5A
    return bytes(data)


@dataclass
class FakeAta:
    """An ATA device behind the pass-through."""

    model: str
    serial: str
    native_max_lba: int
    accessible_max_lba: int
    sanitize: bool = False
    block_erase: bool = False
    crypto: bool = False
    frozen: bool = False
    sanitize_frozen: bool = False
    hpa: bool = True
    dco: bool = True
    dco_max_lba: int | None = None
    corrupt_checksum: bool = False
    #: Status polls a sanitize stays "in progress" for.
    sanitize_polls: int = 2
    abort_sanitize: bool = False
    _in_progress: int = 0
    _completed: bool = False
    commands: list[tuple[int, int]] = field(default_factory=list)
    set_max_calls: list[tuple[int, bool]] = field(default_factory=list)


@dataclass
class FakeNvme:
    model: str
    serial: str
    block_erase: bool = False
    crypto_erase: bool = False
    format_supported: bool = True
    refuse_reinitialize: bool = False
    reinitialize_calls: list[bytes] = field(default_factory=list)

    def identify(self) -> bytes:
        data = bytearray(4096)
        struct.pack_into("<H", data, 0, 0x144D)
        data[4:24] = self.serial.encode("ascii").ljust(20)[:20]
        data[24:64] = self.model.encode("ascii").ljust(40)[:40]
        data[64:72] = b"FW1.0   "
        struct.pack_into("<H", data, 256, 0x02 if self.format_supported else 0)
        struct.pack_into(
            "<I",
            data,
            328,
            (0x01 if self.crypto_erase else 0) | (0x02 if self.block_erase else 0),
        )
        data[524] = 0x04 if self.crypto_erase else 0
        return bytes(data)


@dataclass
class FakeDisk:
    number: int
    size_bytes: int
    serial: str = "FAKESERIAL01"
    vendor: str = "FAKE"
    product: str = "Disk"
    bus_type: int = 7  # USB
    removable: bool = True
    sector: int = 512
    physical_sector: int = 512
    ata: FakeAta | None = None
    nvme: FakeNvme | None = None
    #: USB bridges usually refuse IOCTL_ATA_PASS_THROUGH.
    bridge_blocks_ata: bool = False
    #: Volume GUID path -> mount paths, for volumes living on this disk.
    volumes: dict[str, list[str]] = field(default_factory=dict)
    bad_sectors: set[int] = field(default_factory=set)
    unreadable_sectors: set[int] = field(default_factory=set)
    #: Vanish (every call fails "device not connected") after this many writes.
    vanish_after_writes: int | None = None
    present: bool = True
    offline: bool = False
    #: Drive letters of volumes on this disk -> (offset, length) of the volume.
    letters: dict[str, tuple[int, int]] = field(default_factory=dict)
    data: bytearray = field(default_factory=bytearray)
    writes: int = 0
    opened_for_write: int = 0

    def __post_init__(self) -> None:
        if not self.data:
            self.data = bytearray(os.urandom(min(self.size_bytes, 1 << 16)))
            if self.size_bytes > len(self.data):
                self.data += bytearray(self.size_bytes - len(self.data))

    @property
    def length(self) -> int:
        if self.ata is not None:
            return (self.ata.accessible_max_lba + 1) * self.sector
        return self.size_bytes


class FakeWindowsApi:
    """:class:`NativeApi` over :class:`FakeDisk` objects."""

    def __init__(self, disks: list[FakeDisk], *, elevated: bool = True) -> None:
        self.disks = {disk.number: disk for disk in disks}
        self.elevated = elevated
        self.os_build = 26100
        self._handles: dict[int, tuple[str, int | str, bool]] = {}
        self._next = 100
        self.calls: list[tuple[str, object]] = []
        self.locked: list[str] = []

    # -- handles ----------------------------------------------------------------

    def _disk(self, handle: int) -> FakeDisk:
        kind, key, _ = self._handles.get(handle, ("", -1, False))
        if kind != "disk":
            raise NativeError(ioctl.ERROR_INVALID_HANDLE, "fake", "not a disk handle")
        disk = self.disks.get(int(key))
        if disk is None or not disk.present:
            raise NativeError(ioctl.ERROR_DEVICE_NOT_CONNECTED, "fake", "gone")
        return disk

    def open(self, path: str, *, write: bool) -> int:
        self.calls.append(("open", (path, write)))
        prefix = "\\\\.\\PhysicalDrive"
        if path.startswith(prefix):
            number = int(path[len(prefix) :])
            disk = self.disks.get(number)
            if disk is None or not disk.present:
                raise NativeError(ioctl.ERROR_FILE_NOT_FOUND, "CreateFileW", path)
            if not self.elevated:
                raise NativeError(ioctl.ERROR_ACCESS_DENIED, "CreateFileW", path)
            if write:
                disk.opened_for_write += 1
            handle = self._next
            self._next += 1
            self._handles[handle] = ("disk", number, write)
            return handle
        if len(path) == 6 and path.startswith("\\\\.\\") and path[5] == ":":
            letter = path[4].upper()
            for disk in self.disks.values():
                if letter in disk.letters and disk.present and not disk.offline:
                    if not self.elevated:
                        raise NativeError(
                            ioctl.ERROR_ACCESS_DENIED, "CreateFileW", path
                        )
                    handle = self._next
                    self._next += 1
                    self._handles[handle] = ("letter", f"{disk.number}:{letter}", write)
                    return handle
            raise NativeError(ioctl.ERROR_FILE_NOT_FOUND, "CreateFileW", path)
        if path.startswith("\\\\?\\Volume{"):
            handle = self._next
            self._next += 1
            self._handles[handle] = ("volume", path, write)
            return handle
        raise NativeError(ioctl.ERROR_FILE_NOT_FOUND, "CreateFileW", path)

    def close(self, handle: int) -> None:
        self._handles.pop(handle, None)

    # -- ioctl --------------------------------------------------------------------

    def ioctl(self, handle: int, code: int, data: bytes, out_size: int) -> bytes:
        self.calls.append(("ioctl", code))
        kind, key, write = self._handles.get(handle, ("", -1, False))
        if kind == "volume":
            return self._volume_ioctl(str(key), code)
        if kind == "letter":
            disk, (_, length) = self._letter(handle)
            if code == ioctl.IOCTL_DISK_GET_LENGTH_INFO:
                return struct.pack("<q", length)
            if code == ioctl.IOCTL_DISK_GET_DRIVE_GEOMETRY_EX:
                return struct.pack("<qIIII", 0, 12, 255, 63, disk.sector) + struct.pack(
                    "<q", length
                )
            raise NativeError(ioctl.ERROR_INVALID_FUNCTION, "DeviceIoControl")
        disk = self._disk(handle)
        if code == ioctl.IOCTL_STORAGE_GET_DEVICE_NUMBER:
            return struct.pack("<III", 7, disk.number, 0)
        if code == ioctl.IOCTL_DISK_GET_LENGTH_INFO:
            return struct.pack("<q", disk.length)
        if code == ioctl.IOCTL_DISK_GET_DRIVE_GEOMETRY_EX:
            return struct.pack("<qIIII", 0, 12, 255, 63, disk.sector) + struct.pack(
                "<q", disk.length
            )
        if code == ioctl.IOCTL_DISK_UPDATE_PROPERTIES:
            return b""
        if code == ioctl.IOCTL_DISK_SET_DISK_ATTRIBUTES:
            if not write:
                raise NativeError(ioctl.ERROR_ACCESS_DENIED, "DeviceIoControl")
            version, _persist, attributes, mask = struct.unpack("<IB3xQQ16x", data)
            if version != 40 or mask != ioctl.DISK_ATTRIBUTE_OFFLINE:
                raise NativeError(ioctl.ERROR_INVALID_PARAMETER, "DeviceIoControl")
            disk.offline = bool(attributes & ioctl.DISK_ATTRIBUTE_OFFLINE)
            if disk.offline:
                for volume in disk.volumes:
                    disk.volumes[volume] = []
            return b""
        if code == ioctl.IOCTL_STORAGE_QUERY_PROPERTY:
            return self._query(disk, data)
        if code == ioctl.IOCTL_ATA_PASS_THROUGH:
            if not write:
                raise NativeError(ioctl.ERROR_ACCESS_DENIED, "DeviceIoControl")
            return self._ata(disk, data)
        if code == ioctl.IOCTL_STORAGE_REINITIALIZE_MEDIA:
            return self._reinitialize(disk, data, write)
        raise NativeError(ioctl.ERROR_INVALID_FUNCTION, "DeviceIoControl", hex(code))

    def _volume_ioctl(self, volume: str, code: int) -> bytes:
        if code == ioctl.IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS:
            owners = [
                disk
                for disk in self.disks.values()
                if volume.rstrip("\\") in {v.rstrip("\\") for v in disk.volumes}
            ]
            body = struct.pack("<I4x", len(owners))
            for disk in owners:
                body += struct.pack("<I4xqq", disk.number, 1 << 20, 1 << 20)
            return body
        if code in {ioctl.FSCTL_LOCK_VOLUME, ioctl.FSCTL_DISMOUNT_VOLUME}:
            self.locked.append(volume)
            return b""
        raise NativeError(ioctl.ERROR_INVALID_FUNCTION, "DeviceIoControl", hex(code))

    def _query(self, disk: FakeDisk, data: bytes) -> bytes:
        property_id, _ = struct.unpack_from("<II", data, 0)
        if property_id == ioctl.STORAGE_DEVICE_PROPERTY:
            strings = b""
            offsets = []
            base = 40
            for text in (disk.vendor, disk.product, "1.00", disk.serial):
                offsets.append(base + len(strings) if text else 0)
                strings += text.encode("ascii") + b"\x00"
            head = struct.pack(
                "<IIBBBBIIIIII",
                1,
                base + len(strings),
                0,
                0,
                1 if disk.removable else 0,
                0,
                *offsets,
                disk.bus_type,
                0,
            )
            return head.ljust(base, b"\x00") + strings
        if property_id == ioctl.STORAGE_ACCESS_ALIGNMENT_PROPERTY:
            return struct.pack(
                "<IIIIIII", 28, 28, 64, 0, disk.sector, disk.physical_sector, 0
            )
        if property_id == ioctl.STORAGE_ADAPTER_PROTOCOL_SPECIFIC_PROPERTY:
            if disk.nvme is None:
                raise NativeError(ioctl.ERROR_NOT_SUPPORTED, "DeviceIoControl")
            fields = struct.unpack_from("<10I", data, 8)
            protocol, data_type, cns, _, offset, length = fields[:6]
            if (
                protocol != ioctl.PROTOCOL_TYPE_NVME
                or data_type != ioctl.NVME_DATA_TYPE_IDENTIFY
                or cns != ioctl.NVME_IDENTIFY_CNS_CONTROLLER
                or offset != 40
                or length != 4096
            ):
                raise NativeError(ioctl.ERROR_INVALID_PARAMETER, "DeviceIoControl")
            header = struct.pack("<II", 48, 48 + 4096)
            return header + data[8:48] + disk.nvme.identify()
        raise NativeError(ioctl.ERROR_NOT_SUPPORTED, "DeviceIoControl")

    def _reinitialize(self, disk: FakeDisk, data: bytes, write: bool) -> bytes:
        if not write:
            raise NativeError(ioctl.ERROR_ACCESS_DENIED, "DeviceIoControl")
        nvme = disk.nvme
        if nvme is None or nvme.refuse_reinitialize:
            raise NativeError(ioctl.ERROR_INVALID_FUNCTION, "DeviceIoControl")
        nvme.reinitialize_calls.append(bytes(data))
        method = ioctl.STORAGE_SANITIZE_BLOCK_ERASE
        if data:
            version, size, _, option = struct.unpack("<IIII", data)
            if version != 16 or size != 16:
                raise NativeError(ioctl.ERROR_INVALID_PARAMETER, "DeviceIoControl")
            method = option & 0xF
        if method == ioctl.STORAGE_SANITIZE_CRYPTO_ERASE:
            if not nvme.crypto_erase:
                raise NativeError(ioctl.ERROR_INVALID_FUNCTION, "DeviceIoControl")
            disk.data[:] = os.urandom(len(disk.data))
        else:
            if not nvme.block_erase:
                raise NativeError(ioctl.ERROR_INVALID_FUNCTION, "DeviceIoControl")
            disk.data[:] = bytes(len(disk.data))
        return b""

    # -- ATA ------------------------------------------------------------------------

    def _ata(self, disk: FakeDisk, request: bytes) -> bytes:
        if disk.bridge_blocks_ata or disk.ata is None:
            raise NativeError(ioctl.ERROR_INVALID_FUNCTION, "DeviceIoControl")
        ata = disk.ata
        (length_field, flags, _, _, _, _, transfer, _, _, offset, previous, current) = (
            struct.unpack_from("<HHBBBBIII4xQ8s8s", request, 0)
        )
        if length_field != ioctl.ATA_PASS_THROUGH_EX_SIZE or offset != 48:
            raise NativeError(ioctl.ERROR_INVALID_PARAMETER, "DeviceIoControl")
        ext = bool(flags & ioctl.ATA_FLAGS_48BIT_COMMAND)
        command = current[6]
        features = current[0] | ((previous[0] << 8) if ext else 0)
        count = current[1] | ((previous[1] << 8) if ext else 0)
        lba = current[2] | (current[3] << 8) | (current[4] << 16)
        if ext:
            lba |= (previous[2] << 24) | (previous[3] << 32) | (previous[4] << 40)
        ata.commands.append((command, features))
        status = 0x50
        error = 0
        out_count = count
        out_lba = lba
        payload = b""
        if command == 0xEC:
            payload = build_identify(
                model=ata.model,
                serial=ata.serial,
                max_lba=ata.accessible_max_lba + 1,
                sanitize=ata.sanitize,
                block_erase=ata.block_erase,
                crypto=ata.crypto,
                frozen=ata.frozen,
                hpa=ata.hpa,
                dco=ata.dco,
                corrupt_checksum=ata.corrupt_checksum,
            )
        elif command == 0x27:
            out_lba = ata.native_max_lba
        elif command == 0x37:
            if lba > ata.native_max_lba:
                status, error = 0x51, 0x04
            else:
                ata.set_max_calls.append((lba, bool(count & 1)))
                ata.accessible_max_lba = lba
        elif command == 0xB1 and features == 0xC2:
            if not ata.dco:
                status, error = 0x51, 0x04
            else:
                words = [0] * 256
                words[0] = 2
                dco_max = (
                    ata.dco_max_lba
                    if ata.dco_max_lba is not None
                    else ata.native_max_lba
                )
                for index in range(4):
                    words[3 + index] = (dco_max >> (16 * index)) & 0xFFFF
                payload = struct.pack("<256H", *words)
        elif command == 0xB4:
            status, error, out_count, out_lba = self._sanitize(disk, features, lba)
        else:
            status, error = 0x51, 0x04
        result = bytearray(request)
        cur = bytearray(current)
        prev = bytearray(previous)
        cur[0] = error
        cur[1] = out_count & 0xFF
        cur[2] = out_lba & 0xFF
        cur[3] = (out_lba >> 8) & 0xFF
        cur[4] = (out_lba >> 16) & 0xFF
        cur[6] = status
        if ext:
            prev[1] = (out_count >> 8) & 0xFF
            prev[2] = (out_lba >> 24) & 0xFF
            prev[3] = (out_lba >> 32) & 0xFF
            prev[4] = (out_lba >> 40) & 0xFF
        result[32:40] = bytes(prev)
        result[40:48] = bytes(cur)
        if payload:
            result[48 : 48 + transfer] = payload[:transfer]
        return bytes(result)

    def _sanitize(
        self, disk: FakeDisk, features: int, lba: int
    ) -> tuple[int, int, int, int]:
        ata = disk.ata
        assert ata is not None
        if features == 0x0000:
            if ata._in_progress > 0:
                ata._in_progress -= 1
                done = 0xFFFF - ata._in_progress * 0x1000
                if ata._in_progress == 0:
                    ata._completed = True
                    return 0x50, 0, 0x4000, done
                return 0x50, 0, 0x4000, done
            word = (0x8000 if ata._completed else 0) | (
                0x2000 if ata.sanitize_frozen else 0
            )
            return 0x50, 0, word, 0
        keys = {0x0011: (0x43727970, ata.crypto), 0x0012: (0x426B4572, ata.block_erase)}
        if features not in keys or ata.abort_sanitize:
            return 0x51, 0x04, 0, 0
        key, supported = keys[features]
        if lba & 0xFFFFFFFF != key or not supported or not ata.sanitize:
            return 0x51, 0x04, 0, 0
        if features == 0x0011:
            disk.data[:] = os.urandom(len(disk.data))
        else:
            disk.data[:] = bytes(len(disk.data))
        ata._in_progress = ata.sanitize_polls
        ata._completed = False
        return 0x50, 0, 0, 0

    # -- raw I/O --------------------------------------------------------------------

    def _check(self, disk: FakeDisk, offset: int, length: int) -> None:
        if offset % disk.sector or length % disk.sector or offset < 0:
            raise NativeError(ioctl.ERROR_INVALID_PARAMETER, "ReadFile/WriteFile")
        if offset + length > disk.length:
            raise NativeError(ioctl.ERROR_SECTOR_NOT_FOUND, "ReadFile/WriteFile")

    def _letter(self, handle: int) -> tuple[FakeDisk, tuple[int, int]]:
        _, key, _ = self._handles[handle]
        number, letter = str(key).split(":")
        disk = self.disks[int(number)]
        if not disk.present:
            raise NativeError(ioctl.ERROR_DEVICE_NOT_CONNECTED, "fake", "gone")
        return disk, disk.letters[letter]

    def read(self, handle: int, offset: int, length: int) -> bytes:
        if self._handles.get(handle, ("",))[0] == "letter":
            disk, (start, size) = self._letter(handle)
            self._check(disk, offset, length)
            if offset + length > size:
                raise NativeError(ioctl.ERROR_SECTOR_NOT_FOUND, "ReadFile")
            return bytes(disk.data[start + offset : start + offset + length])
        disk = self._disk(handle)
        self._check(disk, offset, length)
        first = offset // disk.sector
        last = (offset + length - 1) // disk.sector
        if any(first <= item <= last for item in disk.unreadable_sectors):
            raise NativeError(ioctl.ERROR_CRC, "ReadFile")
        return bytes(disk.data[offset : offset + length])

    def write(self, handle: int, offset: int, data: bytes | memoryview) -> int:
        kind, _, write = self._handles.get(handle, ("", -1, False))
        disk = self._disk(handle)
        if not write:
            raise NativeError(ioctl.ERROR_ACCESS_DENIED, "WriteFile")
        length = len(data)
        self._check(disk, offset, length)
        if (
            disk.vanish_after_writes is not None
            and disk.writes >= disk.vanish_after_writes
        ):
            disk.present = False
            raise NativeError(ioctl.ERROR_DEVICE_NOT_CONNECTED, "WriteFile")
        first = offset // disk.sector
        last = (offset + length - 1) // disk.sector
        if any(first <= item <= last for item in disk.bad_sectors):
            raise NativeError(ioctl.ERROR_CRC, "WriteFile")
        disk.data[offset : offset + length] = bytes(data)
        disk.writes += 1
        return length

    def flush(self, handle: int) -> None:
        self._disk(handle)

    def volumes(self) -> list[str]:
        """Volumes the volume manager exposes: none for an offline disk."""
        out: list[str] = []
        for disk in self.disks.values():
            if not disk.offline and disk.present:
                out.extend(disk.volumes)
        return out

    def volume_paths(self, volume: str) -> list[str]:
        for disk in self.disks.values():
            if volume in disk.volumes:
                return list(disk.volumes[volume])
        return []
