"""An adapter double for :class:`core.device.mac.rawdisk.MacIo`.

Serves ``/dev/rdiskN`` paths from byte buffers, answers the DKIOC size ioctls,
enforces the raw device's block alignment, and injects the failures a real
Mac produces: ``EACCES`` without root, ``EBUSY`` while a volume is mounted,
``EIO`` at chosen blocks, and ``ENXIO`` once a device is unplugged.
"""

from __future__ import annotations

import errno
import os
from dataclasses import dataclass, field

from core.device.mac.rawdisk import (
    DKIOCGETBLOCKCOUNT,
    DKIOCGETBLOCKSIZE,
    DKIOCGETPHYSICALBLOCKSIZE,
)

__all__ = ["FakeMacDisk", "FakeMacIo"]


@dataclass
class FakeMacDisk:
    name: str  # "disk4"
    size_bytes: int
    block: int = 512
    physical_block: int = 4096
    mounted: bool = False
    present: bool = True
    bad_blocks: set[int] = field(default_factory=set)
    vanish_after_writes: int | None = None
    data: bytearray = field(default_factory=bytearray)
    writes: int = 0

    def __post_init__(self) -> None:
        if not self.data:
            self.data = bytearray(os.urandom(min(self.size_bytes, 1 << 16)))
            self.data += bytearray(self.size_bytes - len(self.data))


class FakeMacIo:
    def __init__(self, disks: list[FakeMacDisk], *, root: bool = True) -> None:
        self.disks = {disk.name: disk for disk in disks}
        self.root = root
        self._fds: dict[int, tuple[FakeMacDisk, bool]] = {}
        self._next = 10
        self.opened: list[tuple[str, bool]] = []

    def _disk(self, fd: int) -> tuple[FakeMacDisk, bool]:
        disk, write = self._fds[fd]
        if not disk.present:
            raise OSError(errno.ENXIO, "Device not configured")
        return disk, write

    def open(self, path: str, *, write: bool) -> int:
        self.opened.append((path, write))
        if not path.startswith("/dev/rdisk"):
            raise FileNotFoundError(path)
        disk = self.disks.get(path[len("/dev/r") :])
        if disk is None or not disk.present:
            raise FileNotFoundError(path)
        if not self.root:
            raise PermissionError(errno.EACCES, "Permission denied", path)
        if write and disk.mounted:
            raise OSError(errno.EBUSY, "Resource busy", path)
        fd = self._next
        self._next += 1
        self._fds[fd] = (disk, write)
        return fd

    def ioctl_u32(self, fd: int, request: int) -> int:
        disk, _ = self._disk(fd)
        if request == DKIOCGETBLOCKSIZE:
            return disk.block
        if request == DKIOCGETPHYSICALBLOCKSIZE:
            return disk.physical_block
        raise OSError(errno.ENOTTY, "Inappropriate ioctl")

    def ioctl_u64(self, fd: int, request: int) -> int:
        disk, _ = self._disk(fd)
        if request == DKIOCGETBLOCKCOUNT:
            return disk.size_bytes // disk.block
        raise OSError(errno.ENOTTY, "Inappropriate ioctl")

    def _check(self, disk: FakeMacDisk, length: int, offset: int) -> None:
        if offset % disk.block or length % disk.block:
            raise OSError(errno.EINVAL, "Invalid argument")

    def pread(self, fd: int, length: int, offset: int) -> bytes:
        disk, _ = self._disk(fd)
        self._check(disk, length, offset)
        first, last = offset // disk.block, (offset + length - 1) // disk.block
        if any(first <= item <= last for item in disk.bad_blocks):
            raise OSError(errno.EIO, "Input/output error")
        return bytes(disk.data[offset : offset + length])

    def pwrite(self, fd: int, data: bytes | memoryview, offset: int) -> int:
        disk, write = self._disk(fd)
        if not write:
            raise OSError(errno.EBADF, "Bad file descriptor")
        self._check(disk, len(data), offset)
        if (
            disk.vanish_after_writes is not None
            and disk.writes >= disk.vanish_after_writes
        ):
            disk.present = False
            raise OSError(errno.ENXIO, "Device not configured")
        first, last = offset // disk.block, (offset + len(data) - 1) // disk.block
        if any(first <= item <= last for item in disk.bad_blocks):
            raise OSError(errno.EIO, "Input/output error")
        disk.data[offset : offset + len(data)] = bytes(data)
        disk.writes += 1
        return len(data)

    def fsync(self, fd: int) -> None:
        self._disk(fd)

    def close(self, fd: int) -> None:
        self._fds.pop(fd, None)
