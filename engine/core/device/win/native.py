"""The one place that calls ``kernel32``: handles, DeviceIoControl, raw I/O.

:class:`NativeApi` is the seam. :class:`Kernel32Api` implements it with
:mod:`ctypes` on Windows; the test suite drives everything above it with the
adapter double in :mod:`testkit.fake_windows`, which answers the same calls
from a byte buffer and parses the same packed structures.

Unbuffered I/O (``FILE_FLAG_NO_BUFFERING``) requires the buffer *address*, the
file offset and the length all to be sector multiples. Offsets and lengths are
the caller's responsibility and are checked there; the address is this
module's: every transfer goes through a page-aligned buffer from
:func:`mmap.mmap`, whose address is a multiple of every sector size a disk
reports.

Errors are raised as :class:`NativeError` carrying the Win32 error code, so
callers can tell a medium error (salvage it) from a vanished device (stop).
"""

from __future__ import annotations

import mmap
import sys
from typing import Any, Protocol

from core.device.win.ioctl import (
    FILE_FLAG_NO_BUFFERING,
    FILE_FLAG_WRITE_THROUGH,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    GENERIC_READ,
    GENERIC_WRITE,
    OPEN_EXISTING,
)

__all__ = ["Kernel32Api", "NativeApi", "NativeError", "default_api"]


class NativeError(OSError):
    """A failed Win32 call, with its error code in ``winerror``."""

    def __init__(self, winerror: int, call: str, detail: str = "") -> None:
        super().__init__(
            f"{call} failed with Win32 error {winerror}"
            + (f": {detail}" if detail else "")
        )
        # After OSError.__init__, never before: on Windows OSError has a
        # ``winerror`` slot, and a one-argument __init__ resets it to None.
        # Set first, every Win32 code (access denied, device gone, bridge
        # refusal) read back as None and no translation matched.
        self.winerror = winerror
        self.call = call


class NativeApi(Protocol):
    """What the Windows backends need from the OS."""

    def open(self, path: str, *, write: bool) -> int:
        """A handle to ``path``; unbuffered, and write-through when ``write``."""
        ...

    def close(self, handle: int) -> None: ...

    def ioctl(self, handle: int, code: int, data: bytes, out_size: int) -> bytes:
        """DeviceIoControl with METHOD_BUFFERED; returns the bytes returned."""
        ...

    def read(self, handle: int, offset: int, length: int) -> bytes: ...

    def write(self, handle: int, offset: int, data: bytes | memoryview) -> int: ...

    def flush(self, handle: int) -> None: ...

    def volumes(self) -> list[str]:
        """Every volume GUID path (``\\\\?\\Volume{...}\\``)."""
        ...

    def volume_paths(self, volume: str) -> list[str]:
        """Drive letters and folder mount points of one volume."""
        ...


class _AlignedBuffer:
    """A reusable page-aligned buffer, grown on demand."""

    def __init__(self) -> None:
        self._map: mmap.mmap | None = None

    def get(self, size: int) -> mmap.mmap:
        if self._map is None or len(self._map) < size:
            if self._map is not None:
                self._map.close()
            pages = max(1, -(-size // mmap.PAGESIZE))
            self._map = mmap.mmap(-1, pages * mmap.PAGESIZE)
        return self._map


class Kernel32Api:
    """:class:`NativeApi` on real Windows, through ``kernel32``."""

    def __init__(self) -> None:
        if sys.platform != "win32":  # pragma: no cover - guarded by callers
            raise NativeError(50, "Kernel32Api", "kernel32 exists only on Windows")
        import ctypes
        from ctypes import wintypes

        self._ctypes: Any = ctypes
        self._wt: Any = wintypes
        k32: Any = ctypes.WinDLL(  # type: ignore[attr-defined, unused-ignore]
            "kernel32", use_last_error=True
        )
        handle = wintypes.HANDLE
        self._create: Any = k32.CreateFileW
        self._create.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            handle,
        ]
        self._create.restype = handle
        self._ioctl: Any = k32.DeviceIoControl
        self._ioctl.argtypes = [
            handle,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]
        self._ioctl.restype = wintypes.BOOL
        self._seek: Any = k32.SetFilePointerEx
        self._seek.argtypes = [
            handle,
            ctypes.c_longlong,
            ctypes.POINTER(ctypes.c_longlong),
            wintypes.DWORD,
        ]
        self._seek.restype = wintypes.BOOL
        self._read: Any = k32.ReadFile
        self._read.argtypes = [
            handle,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]
        self._read.restype = wintypes.BOOL
        self._write: Any = k32.WriteFile
        self._write.argtypes = self._read.argtypes
        self._write.restype = wintypes.BOOL
        self._flush: Any = k32.FlushFileBuffers
        self._flush.argtypes = [handle]
        self._flush.restype = wintypes.BOOL
        self._close: Any = k32.CloseHandle
        self._close.argtypes = [handle]
        self._close.restype = wintypes.BOOL
        self._first_volume: Any = k32.FindFirstVolumeW
        self._first_volume.argtypes = [wintypes.LPWSTR, wintypes.DWORD]
        self._first_volume.restype = handle
        self._next_volume: Any = k32.FindNextVolumeW
        self._next_volume.argtypes = [handle, wintypes.LPWSTR, wintypes.DWORD]
        self._next_volume.restype = wintypes.BOOL
        self._volume_close: Any = k32.FindVolumeClose
        self._volume_close.argtypes = [handle]
        self._volume_close.restype = wintypes.BOOL
        self._volume_paths: Any = k32.GetVolumePathNamesForVolumeNameW
        self._volume_paths.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPWSTR,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._volume_paths.restype = wintypes.BOOL
        self._invalid: Any = ctypes.c_void_p(-1).value
        self._buffer: _AlignedBuffer = _AlignedBuffer()

    def _fail(self, call: str) -> NativeError:
        code = int(self._ctypes.get_last_error())
        return NativeError(code, call)

    def _address(self, buffer: mmap.mmap) -> int:
        return int(self._ctypes.addressof(self._ctypes.c_char.from_buffer(buffer)))

    def open(self, path: str, *, write: bool) -> int:
        access = GENERIC_READ | (GENERIC_WRITE if write else 0)
        flags = FILE_FLAG_NO_BUFFERING | (FILE_FLAG_WRITE_THROUGH if write else 0)
        handle = self._create(
            path,
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
        if handle is None or handle == self._invalid:
            raise self._fail(f"CreateFileW({path})")
        return int(handle)

    def close(self, handle: int) -> None:
        if not self._close(handle):
            raise self._fail("CloseHandle")

    def ioctl(self, handle: int, code: int, data: bytes, out_size: int) -> bytes:
        ctypes = self._ctypes
        size = max(len(data), out_size, 1)
        buffer = ctypes.create_string_buffer(data, size)
        returned = self._wt.DWORD(0)
        ok = self._ioctl(
            handle,
            code,
            buffer if data else None,
            len(data),
            buffer if out_size else None,
            out_size,
            ctypes.byref(returned),
            None,
        )
        if not ok:
            raise self._fail(f"DeviceIoControl(0x{code:08X})")
        return bytes(buffer.raw[: returned.value])

    def _position(self, handle: int, offset: int) -> None:
        if not self._seek(handle, offset, None, 0):
            raise self._fail(f"SetFilePointerEx({offset})")

    def read(self, handle: int, offset: int, length: int) -> bytes:
        buffer = self._buffer.get(length)
        self._position(handle, offset)
        done = self._wt.DWORD(0)
        address = self._address(buffer)
        if not self._read(handle, address, length, self._ctypes.byref(done), None):
            raise self._fail(f"ReadFile({offset}, {length})")
        return bytes(buffer[: done.value])

    def write(self, handle: int, offset: int, data: bytes | memoryview) -> int:
        length = len(data)
        buffer = self._buffer.get(length)
        buffer.seek(0)
        buffer.write(data)
        self._position(handle, offset)
        done = self._wt.DWORD(0)
        if not self._write(
            handle, self._address(buffer), length, self._ctypes.byref(done), None
        ):
            raise self._fail(f"WriteFile({offset}, {length})")
        return int(done.value)

    def flush(self, handle: int) -> None:
        if not self._flush(handle):
            raise self._fail("FlushFileBuffers")

    def volumes(self) -> list[str]:
        name = self._ctypes.create_unicode_buffer(1024)
        handle = self._first_volume(name, 1024)
        if handle is None or handle == self._invalid:
            raise self._fail("FindFirstVolumeW")
        found = [name.value]
        try:
            while self._next_volume(handle, name, 1024):
                found.append(name.value)
        finally:
            self._volume_close(handle)
        return found

    def volume_paths(self, volume: str) -> list[str]:
        size = self._wt.DWORD(0)
        names = self._ctypes.create_unicode_buffer(4096)
        if not self._volume_paths(volume, names, 4096, self._ctypes.byref(size)):
            raise self._fail("GetVolumePathNamesForVolumeNameW")
        raw: str = names.value if size.value <= 1 else "".join(names[: size.value])
        return [item for item in raw.split("\x00") if item]


def default_api() -> NativeApi:
    """The real API on Windows. Anywhere else there is none to return."""
    return Kernel32Api()
