"""One ``/dev/rdiskN`` handle, sized by the kernel and bound to the plan.

Size comes from ``DKIOCGETBLOCKCOUNT`` x ``DKIOCGETBLOCKSIZE``, read from the
open descriptor. macOS exposes no ioctl that returns a drive serial, so
binding here is by the kernel's size and block size against the plan; the
serial and media name are re-read from ``system_profiler`` / ``diskutil`` by
the adapter immediately before :meth:`MacRawDisk.open` (see
``MacOSAdapter._open_bound``). The window between that read and the open is
stated in the clear's limitations, which the report prints: a same-size disk
swapped into the same BSD name inside it would not be detected.

Only whole disks (``diskN``) and their partitions (``diskNsM``) are accepted.
A synthesized APFS container disk is refused by the adapter before this module
is reached.
"""

from __future__ import annotations

import errno
import os
import re
import struct
from types import TracebackType
from typing import Protocol

from core.errors import ConfirmationMismatch, DeviceVanished, UnsupportedCapability

__all__ = [
    "DKIOCGETBLOCKCOUNT",
    "DKIOCGETBLOCKSIZE",
    "DKIOCGETPHYSICALBLOCKSIZE",
    "MacIo",
    "MacRawDisk",
    "PosixMacIo",
    "raw_path",
]

#: ``_IOR('d', 24, uint32_t)``
DKIOCGETBLOCKSIZE = 0x40046418
#: ``_IOR('d', 25, uint64_t)``
DKIOCGETBLOCKCOUNT = 0x40086419
#: ``_IOR('d', 77, uint32_t)``
DKIOCGETPHYSICALBLOCKSIZE = 0x4004644D

_NAME = re.compile(r"^(?:/dev/)?r?(disk\d+(?:s\d+)?)$")


def raw_path(device: str) -> str:
    """``disk4`` / ``/dev/disk4`` / ``/dev/rdisk4s1`` -> ``/dev/rdisk4[s1]``."""
    match = _NAME.match(device.strip())
    if match is None:
        raise UnsupportedCapability(
            f"{device!r} is not a macOS disk or partition device.",
            remediation="Select the disk from the Devices screen. Nothing was opened.",
        )
    return f"/dev/r{match.group(1)}"


class MacIo(Protocol):
    """The OS calls this module makes. Replaced in tests."""

    def open(self, path: str, *, write: bool) -> int: ...

    def ioctl_u32(self, fd: int, request: int) -> int: ...

    def ioctl_u64(self, fd: int, request: int) -> int: ...

    def pread(self, fd: int, length: int, offset: int) -> bytes: ...

    def pwrite(self, fd: int, data: bytes | memoryview, offset: int) -> int: ...

    def fsync(self, fd: int) -> None: ...

    def close(self, fd: int) -> None: ...


class PosixMacIo:
    """:class:`MacIo` on a real Mac."""

    def open(self, path: str, *, write: bool) -> int:
        return os.open(path, os.O_RDWR if write else os.O_RDONLY)

    def _ioctl(self, fd: int, request: int, fmt: str) -> int:
        import fcntl

        size = struct.calcsize(fmt)
        raw = fcntl.ioctl(fd, request, bytes(size))
        (value,) = struct.unpack(fmt, raw)
        return int(value)

    def ioctl_u32(self, fd: int, request: int) -> int:
        return self._ioctl(fd, request, "I")

    def ioctl_u64(self, fd: int, request: int) -> int:
        return self._ioctl(fd, request, "Q")

    def pread(self, fd: int, length: int, offset: int) -> bytes:
        return os.pread(fd, length, offset)

    def pwrite(self, fd: int, data: bytes | memoryview, offset: int) -> int:
        return os.pwrite(fd, data, offset)

    def fsync(self, fd: int) -> None:
        os.fsync(fd)

    def close(self, fd: int) -> None:
        os.close(fd)


class MacRawDisk:
    """An open raw device, sized from the kernel, bound to the planned size."""

    def __init__(
        self, device: str, *, write: bool = False, io: MacIo | None = None
    ) -> None:
        self.path = raw_path(device)
        self.write = write
        self.io: MacIo = io or PosixMacIo()
        self._fd: int | None = None
        self.size_bytes = 0
        self.logical_sector = 0
        self.physical_sector = 0

    def open(self) -> MacRawDisk:
        try:
            self._fd = self.io.open(self.path, write=self.write)
        except PermissionError as exc:
            raise UnsupportedCapability(
                f"macOS refused to open {self.path}"
                + (" for writing" if self.write else "")
                + ": raw device access needs root.",
                remediation="Start Sanctum itself with sudo. Nothing was opened.",
            ) from exc
        except FileNotFoundError as exc:
            raise DeviceVanished(f"{self.path} is not present.") from exc
        except OSError as exc:
            if exc.errno == errno.EBUSY:
                raise UnsupportedCapability(
                    f"{self.path} is busy: a volume on it is still mounted.",
                    remediation="Unmount the disk (diskutil unmountDisk), then "
                    "retry. Nothing was opened.",
                ) from exc
            raise
        fd = self._fd
        self.logical_sector = self.io.ioctl_u32(fd, DKIOCGETBLOCKSIZE)
        count = self.io.ioctl_u64(fd, DKIOCGETBLOCKCOUNT)
        self.size_bytes = count * self.logical_sector
        try:
            self.physical_sector = self.io.ioctl_u32(fd, DKIOCGETPHYSICALBLOCKSIZE)
        except OSError:
            self.physical_sector = self.logical_sector
        return self

    def bind(self, *, size_bytes: int) -> MacRawDisk:
        problems: list[str] = []
        if self.size_bytes != size_bytes:
            problems.append(
                f"the kernel reports {self.size_bytes} bytes, the plan recorded "
                f"{size_bytes}"
            )
        sector = self.logical_sector
        if sector <= 0 or sector & (sector - 1):
            problems.append(f"block size {sector} is not a power of two")
        if problems:
            self.close()
            raise ConfirmationMismatch(
                f"{self.path} is not the disk that was planned: "
                + "; ".join(problems)
                + ". Nothing was written.",
                remediation="Rescan and plan again against the disk attached now.",
            )
        return self

    @property
    def fd(self) -> int:
        if self._fd is None:
            raise DeviceVanished(f"{self.path} is not open.")
        return self._fd

    def _check(self, offset: int, length: int) -> None:
        sector = self.logical_sector
        if not sector or offset % sector or length % sector:
            raise ValueError(
                f"raw I/O at {offset}+{length} is not a multiple of the "
                f"{sector}-byte block"
            )
        if offset + length > self.size_bytes:
            raise ValueError(f"I/O at {offset}+{length} runs past the end")

    def read_at(self, offset: int, length: int) -> bytes:
        self._check(offset, length)
        return self.io.pread(self.fd, length, offset)

    def write_at(self, offset: int, data: bytes | memoryview) -> int:
        if not self.write:
            raise PermissionError(f"{self.path} was opened read-only")
        self._check(offset, len(data))
        return self.io.pwrite(self.fd, data, offset)

    def flush(self) -> None:
        if self.write:
            self.io.fsync(self.fd)

    def close(self) -> None:
        fd, self._fd = self._fd, None
        if fd is not None:
            try:
                self.io.close(fd)
            except OSError:
                pass

    def __enter__(self) -> MacRawDisk:
        return self.open()

    def __exit__(
        self,
        kind: type[BaseException] | None,
        value: BaseException | None,
        trace: TracebackType | None,
    ) -> None:
        self.close()
