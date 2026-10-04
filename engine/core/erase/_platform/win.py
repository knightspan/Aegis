"""Windows backend: ctypes over Win32.

**Untested on this host.** Every function here degrades to the inherited
:class:`~core.erase._platform.base.PortableBackend` answer plus a recorded
limitation when a call fails, so the worst case on an untried Windows build is
a report full of honest unknowns rather than a crash or a false guarantee.
The Windows-specific tests in ``tests/erase/files/`` are skipped off Windows
with that stated as the reason.

The Win32 details that matter, and the traps in them:

* ``FSCTL_GET_RETRIEVAL_POINTERS`` returns ``ERROR_HANDLE_EOF`` (38) with zero
  extents for a file whose data is **resident in the MFT record**. That is not
  an error to swallow: it is the single most important signal this backend
  produces, because writing through the file handle never reaches those bytes.
* ``FindFirstStreamW`` needs explicit ``argtypes``. Without them ctypes raises
  ``OverflowError: int too long to convert`` on a 64-bit handle.
* Directory fsync has no Windows equivalent available unprivileged, so
  :meth:`fsync_dir` records a limitation rather than pretending.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path

from core.erase._platform.base import Flags, PortableBackend
from core.models import Extent
from core.platform.host import windows_creationflags

__all__ = ["WindowsBackend"]

FSCTL_GET_RETRIEVAL_POINTERS = 0x00090073
ERROR_HANDLE_EOF = 38
ERROR_MORE_DATA = 234

FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200
FILE_ATTRIBUTE_COMPRESSED = 0x00000800
FILE_ATTRIBUTE_ENCRYPTED = 0x00004000
FILE_ATTRIBUTE_READONLY = 0x00000001

GENERIC_READ = 0x80000000
FILE_SHARE_ALL = 0x00000007
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

#: Retrieval pointers come back as VCN/LCN pairs. Ask for this many at a time.
_EXTENT_BATCH = 512


class WindowsBackend(PortableBackend):
    """Windows. Every method degrades to an honest unknown on failure."""

    name = "windows"

    def __init__(self) -> None:
        if sys.platform != "win32":  # pragma: no cover - guarded by backend()
            raise ImportError("WindowsBackend requires Windows")
        self._k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._configure()

    def _configure(self) -> None:
        """Explicit argtypes. Without them a 64-bit HANDLE overflows in ctypes."""
        k32 = self._k32
        k32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
        ]
        k32.CreateFileW.restype = ctypes.c_void_p
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        k32.CloseHandle.restype = wintypes.BOOL
        k32.DeviceIoControl.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]
        k32.DeviceIoControl.restype = wintypes.BOOL
        k32.FindFirstStreamW.argtypes = [
            wintypes.LPCWSTR,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        k32.FindFirstStreamW.restype = ctypes.c_void_p
        k32.FindNextStreamW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        k32.FindNextStreamW.restype = wintypes.BOOL
        k32.FindClose.argtypes = [ctypes.c_void_p]
        k32.GetVolumeInformationW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPWSTR,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPWSTR,
            wintypes.DWORD,
        ]
        k32.GetDiskFreeSpaceW.argtypes = [
            wintypes.LPCWSTR,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
        ]

    # -- helpers ------------------------------------------------------------

    def _volume_root(self, path: Path) -> str:
        drive = Path(path).resolve().drive
        return f"{drive}\\" if drive else ""

    def _open_handle(self, path: Path) -> int | None:
        handle = self._k32.CreateFileW(
            str(path),
            GENERIC_READ,
            FILE_SHARE_ALL,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        if handle in (None, 0, INVALID_HANDLE_VALUE):
            return None
        return int(handle)

    # -- filesystem identity ------------------------------------------------

    def fs_type(self, path: Path) -> tuple[str, list[str]]:
        root = self._volume_root(path)
        if not root:
            return "", [f"{path} has no drive letter, so its filesystem is unknown."]
        name = ctypes.create_unicode_buffer(261)
        serial = wintypes.DWORD()
        components = wintypes.DWORD()
        flags = wintypes.DWORD()
        fs_name = ctypes.create_unicode_buffer(261)
        ok = self._k32.GetVolumeInformationW(
            root,
            name,
            261,
            ctypes.byref(serial),
            ctypes.byref(components),
            ctypes.byref(flags),
            fs_name,
            261,
        )
        if not ok:
            return "", [
                f"GetVolumeInformationW failed for {root} "
                f"(error {ctypes.get_last_error()})."
            ]
        return fs_name.value, []

    def cluster_bytes(self, path: Path) -> tuple[int, list[str]]:
        root = self._volume_root(path)
        if not root:
            return 0, [f"{path} has no drive letter, so its cluster size is unknown."]
        sectors = wintypes.DWORD()
        bytes_per_sector = wintypes.DWORD()
        free = wintypes.DWORD()
        total = wintypes.DWORD()
        ok = self._k32.GetDiskFreeSpaceW(
            root,
            ctypes.byref(sectors),
            ctypes.byref(bytes_per_sector),
            ctypes.byref(free),
            ctypes.byref(total),
        )
        if not ok:
            return 0, [
                f"GetDiskFreeSpaceW failed for {root} "
                f"(error {ctypes.get_last_error()}), so file slack is unknown."
            ]
        return int(sectors.value) * int(bytes_per_sector.value), []

    # -- extents and residency ---------------------------------------------

    def _retrieval_pointers(
        self, path: Path
    ) -> tuple[list[tuple[int, int, int]] | None, int, list[str]]:
        """``(vcn, next_vcn, lcn)`` runs, the last error, and limitations.

        The run *length* matters and used to be thrown away: NTFS describes a
        contiguous 256 KiB file as one run of 64 clusters, and a map that kept
        only the first cluster of each run made the post-erase read-back check
        4 KiB of it. Found by the Windows CI runner
        (``test_a_real_extent_map_is_captured_on_a_block_backed_filesystem``).

        ``None`` with ``ERROR_HANDLE_EOF`` is the resident-data signal, not a
        failure: NTFS returns it for a file small enough to live inside its own
        MFT record, which has no cluster to point at.
        """
        handle = self._open_handle(path)
        if handle is None:
            return None, 0, [
                f"{path} could not be opened to read its extent map "
                f"(error {ctypes.get_last_error()})."
            ]
        try:
            starting = ctypes.c_longlong(0)
            size = 16 + _EXTENT_BATCH * 16
            buffer = ctypes.create_string_buffer(size)
            returned = wintypes.DWORD()
            ok = self._k32.DeviceIoControl(
                ctypes.c_void_p(handle),
                FSCTL_GET_RETRIEVAL_POINTERS,
                ctypes.byref(starting),
                ctypes.sizeof(starting),
                buffer,
                size,
                ctypes.byref(returned),
                None,
            )
            error = ctypes.get_last_error()
            if not ok and error not in (ERROR_MORE_DATA,):
                return None, error, []

            count = int.from_bytes(buffer.raw[0:4], "little")
            start_vcn = int.from_bytes(buffer.raw[8:16], "little", signed=True)
            runs: list[tuple[int, int, int]] = []
            previous = start_vcn
            for index in range(min(count, _EXTENT_BATCH)):
                at = 16 + index * 16
                next_vcn = int.from_bytes(
                    buffer.raw[at : at + 8], "little", signed=True
                )
                lcn = int.from_bytes(
                    buffer.raw[at + 8 : at + 16], "little", signed=True
                )
                runs.append((previous, next_vcn, lcn))
                previous = next_vcn
            truncated: list[str] = []
            if count > _EXTENT_BATCH or error == ERROR_MORE_DATA:
                truncated.append(
                    f"{path} is fragmented into more than {_EXTENT_BATCH} runs; "
                    "the extent map was truncated there, so a read-back covers "
                    "only the runs that were captured."
                )
            return runs, error, truncated
        finally:
            self._k32.CloseHandle(ctypes.c_void_p(handle))

    def extents(self, path: Path) -> tuple[list[Extent], list[str]]:
        cluster, cluster_limits = self.cluster_bytes(path)
        if cluster <= 0:
            return [], cluster_limits + [
                f"Without a cluster size the extent map for {path} cannot be "
                "converted to byte offsets."
            ]
        runs, error, limits = self._retrieval_pointers(path)
        if runs is None:
            if error == ERROR_HANDLE_EOF:
                return [], [
                    f"{path} stores its data resident inside its MFT record, so "
                    "it occupies no clusters and there is no physical extent to "
                    "read back."
                ]
            return [], limits + [
                f"FSCTL_GET_RETRIEVAL_POINTERS failed for {path} (error "
                f"{error}), so no physical extent map was captured."
            ]

        try:
            size = path.stat().st_size
        except OSError as exc:
            return [], [f"{path} could not be stat'd for its extent map: {exc}."]

        found: list[Extent] = []
        for vcn, next_vcn, lcn in runs:
            if lcn < 0:  # a sparse hole: no physical address exists
                continue
            clusters = max(next_vcn - vcn, 0)
            if clusters == 0:
                continue
            logical = vcn * cluster
            # The last run of a file ends inside its final cluster; the rest of
            # that cluster is file slack, which belongs to this file's
            # allocation but is not its data.
            length = min(clusters * cluster, max(size - logical, 0))
            if length <= 0:
                continue
            found.append(
                Extent(
                    logical_offset=logical,
                    physical_offset=lcn * cluster,
                    length=length,
                )
            )
        return found, limits

    def is_resident(self, path: Path) -> tuple[bool | None, list[str]]:
        runs, error, limits = self._retrieval_pointers(path)
        if runs is None:
            if error == ERROR_HANDLE_EOF:
                return True, []
            return None, limits
        return not any(next_vcn > vcn for vcn, next_vcn, _ in runs), []

    # -- streams ------------------------------------------------------------

    def alt_data_streams(self, path: Path) -> tuple[list[str], list[str]]:
        """Enumerate ``:name:$DATA``, excluding the unnamed stream itself."""

        class _StreamData(ctypes.Structure):
            _fields_ = [
                ("StreamSize", ctypes.c_longlong),
                ("StreamName", ctypes.c_wchar * 296),
            ]

        data = _StreamData()
        handle = self._k32.FindFirstStreamW(str(path), 0, ctypes.byref(data), 0)
        if handle in (None, 0, INVALID_HANDLE_VALUE):
            return [], [
                f"Alternate data streams on {path} could not be enumerated "
                f"(error {ctypes.get_last_error()})."
            ]
        found: list[str] = []
        try:
            while True:
                name = data.StreamName
                if name and name != "::$DATA":
                    found.append(name)
                if not self._k32.FindNextStreamW(
                    ctypes.c_void_p(handle), ctypes.byref(data)
                ):
                    break
        finally:
            self._k32.FindClose(ctypes.c_void_p(handle))
        return found, []

    def xattrs(self, path: Path) -> tuple[list[str], list[str]]:
        # Windows has no extended attributes in the POSIX sense; alternate data
        # streams are the equivalent and are reported separately.
        return [], []

    # -- flags --------------------------------------------------------------

    def flags(self, path: Path) -> tuple[Flags, list[str]]:
        try:
            attributes = int(getattr(path.stat(), "st_file_attributes", 0))
        except OSError as exc:
            return Flags(), [f"{path} could not be stat'd for its attributes: {exc}."]
        return (
            Flags(
                sparse=bool(attributes & FILE_ATTRIBUTE_SPARSE_FILE),
                compressed=bool(attributes & FILE_ATTRIBUTE_COMPRESSED),
                encrypted=bool(attributes & FILE_ATTRIBUTE_ENCRYPTED),
                immutable=bool(attributes & FILE_ATTRIBUTE_READONLY),
            ),
            [],
        )

    def clear_immutable(self, path: Path) -> tuple[bool, str]:
        """Clears the read-only attribute, the nearest Windows equivalent."""
        import stat as stat_mod

        try:
            attributes = int(getattr(path.stat(), "st_file_attributes", 0))
            if not attributes & FILE_ATTRIBUTE_READONLY:
                return False, ""
            os.chmod(path, stat_mod.S_IWRITE)
        except OSError as exc:
            return False, (
                f"The read-only attribute on {path} could not be cleared: {exc}."
            )
        return True, ""

    # -- shadow copies ------------------------------------------------------

    def vss_shadows(self, path: Path) -> tuple[list[str] | None, list[str]]:
        """``vssadmin list shadows``. Needs administrator; unknown otherwise.

        Returns ``None`` rather than ``[]`` when the command cannot run. A
        volume with shadow copies nobody was allowed to enumerate is not a
        volume with no shadow copies.
        """
        root = self._volume_root(path)
        if not root:
            return None, [f"{path} has no drive letter, so VSS was not queried."]
        try:
            completed = subprocess.run(
                ["vssadmin", "list", "shadows", f"/for={root.rstrip(chr(92))}"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                creationflags=windows_creationflags(),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return None, [
                f"vssadmin could not be run ({exc}), so whether shadow copies "
                f"on {root} still hold {path}'s old blocks is unknown."
            ]
        if completed.returncode != 0:
            return None, [
                "vssadmin refused to list shadow copies "
                f"({completed.stdout.strip()[:160] or completed.returncode}); "
                "listing them needs an elevated prompt, so whether any hold "
                f"{path}'s old blocks is unknown."
            ]
        ids = [
            line.split(":", 1)[1].strip()
            for line in completed.stdout.splitlines()
            if "Shadow Copy ID" in line and ":" in line
        ]
        return ids, []

    def trim_likely(self, path: Path) -> tuple[bool | None, list[str]]:
        """``fsutil behavior query DisableDeleteNotify``: 0 means TRIM is on."""
        try:
            completed = subprocess.run(
                ["fsutil", "behavior", "query", "DisableDeleteNotify"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
                creationflags=windows_creationflags(),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return None, [
                f"fsutil could not be run ({exc}), so whether this volume "
                "issues TRIM is unknown."
            ]
        if completed.returncode != 0:
            return None, [
                "fsutil did not report the delete-notify setting, so whether "
                "this volume issues TRIM is unknown."
            ]
        text = completed.stdout
        if "= 0" in text:
            return True, []
        if "= 1" in text:
            return False, []
        return None, [f"fsutil returned an unrecognised delete-notify state: {text!r}."]

    def block_device_for(self, path: Path) -> tuple[str | None, list[str]]:
        drive = Path(path).resolve().drive
        if not drive:
            return None, [f"{path} has no drive letter, so it has no raw device path."]
        return f"\\\\.\\{drive}", []

    # -- writing ------------------------------------------------------------

    def open_unbuffered_write(self, path: Path) -> tuple[int, bool, list[str]]:
        """``os.open`` plus an explicit fsync by the caller.

        CPython's ``os.fsync`` calls ``FlushFileBuffers``, so the write does
        reach the medium; there is simply no ``O_SYNC`` to set on the open.
        """
        fd = os.open(path, os.O_WRONLY | os.O_BINARY)
        return fd, True, []

    def fsync_dir(self, path: Path) -> tuple[bool, str]:
        """Not possible unprivileged on Windows. Say so rather than no-op."""
        return False, (
            f"The directory {path} was not flushed to disk: Windows offers no "
            "unprivileged equivalent of fsync on a directory handle, so the "
            "rename chain may still be recoverable from the directory index "
            "until the filesystem flushes it on its own schedule."
        )
