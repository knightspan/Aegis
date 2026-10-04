"""Linux and macOS backend. One module: they differ only in the extent ioctl.

Everything else - ``statvfs`` for the cluster size, ``os.listxattr``, ``os.open``
semantics, directory fsync - is shared, so splitting them would duplicate four
fifths of the file to isolate one ``if``.
"""

from __future__ import annotations

import ctypes
import os
import struct
import subprocess
import sys
from pathlib import Path

import structlog

from core.erase._platform.base import UNSUPPORTED, Flags, PortableBackend
from core.models import Extent

__all__ = ["PosixBackend", "FS_IOC_FIEMAP", "COW_FILESYSTEMS"]

logger = structlog.get_logger(__name__)

#: ``FS_IOC_FIEMAP``. The extent map ioctl, ext4/xfs/btrfs/f2fs.
FS_IOC_FIEMAP = 0xC020660B

#: ``FS_IOC_GETFLAGS`` / ``FS_IOC_SETFLAGS`` - the chattr attribute word.
FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086602

FS_COMPR_FL = 0x00000004
FS_IMMUTABLE_FL = 0x00000010
FS_ENCRYPT_FL = 0x00000800

#: ``F_LOG2PHYS_EXT`` on macOS: logical-to-physical for one offset at a time.
F_LOG2PHYS_EXT = 49

#: Ask for at most this many extents in one ioctl. A file fragmented past this
#: is reported truncated, with a limitation, rather than looping forever.
FIEMAP_MAX_EXTENTS = 512

#: Sync the file before mapping it. Without this a freshly written file comes
#: back as one delayed-allocation extent with no physical address at all, so
#: the map is empty exactly when it is needed - after a write and before an
#: erase. This is what `filefrag -s` passes, for the same reason.
FIEMAP_FLAG_SYNC = 0x0001

FIEMAP_EXTENT_LAST = 0x0001
FIEMAP_EXTENT_UNKNOWN = 0x0002
FIEMAP_EXTENT_DELALLOC = 0x0004
FIEMAP_EXTENT_ENCODED = 0x0008
FIEMAP_EXTENT_DATA_INLINE = 0x0200

#: Filesystems that redirect a write to newly allocated blocks. On these the
#: pre-erase extent map addresses blocks the overwrite never touched, so a
#: physical read back proves nothing at all.
COW_FILESYSTEMS = frozenset(
    {"btrfs", "zfs", "apfs", "refs", "bcachefs", "nilfs2", "f2fs"}
)

#: Header: fm_start u64, fm_length u64, fm_flags u32, fm_mapped_extents u32,
#: fm_extent_count u32, fm_reserved u32.
_FIEMAP_HEADER = struct.Struct("<QQIIII")
#: Extent: fe_logical u64, fe_physical u64, fe_length u64, fe_reserved64[2],
#: fe_flags u32, fe_reserved[3].
_FIEMAP_EXTENT = struct.Struct("<QQQQQIIII")


class PosixBackend(PortableBackend):
    """Linux and macOS."""

    name = "posix"

    # -- filesystem identity ------------------------------------------------

    def fs_type(self, path: Path) -> tuple[str, list[str]]:
        if sys.platform == "linux":
            return self._fs_type_linux(path)
        return self._fs_type_darwin(path)

    def _fs_type_linux(self, path: Path) -> tuple[str, list[str]]:
        """The longest mount point in /proc/mounts that prefixes the path.

        Longest, not first: ``/`` prefixes everything, so a shorter match would
        report the root filesystem's type for a file on a mounted volume - and
        an ext4 answer for a btrfs file would suppress the copy-on-write
        finding that matters most.
        """
        try:
            resolved = path.resolve()
            mounts = Path("/proc/mounts").read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return "", [f"/proc/mounts could not be read for {path}: {exc}."]

        best_point = ""
        best_type = ""
        for line in mounts.splitlines():
            fields = line.split()
            if len(fields) < 3:
                continue
            point = fields[1].replace("\\040", " ")
            if point == "/" or str(resolved) == point or str(resolved).startswith(
                point.rstrip("/") + "/"
            ):
                if len(point) >= len(best_point):
                    best_point, best_type = point, fields[2]
        if not best_type:
            return "", [f"No mount point in /proc/mounts covers {path}."]
        return best_type, []

    def _fs_type_darwin(self, path: Path) -> tuple[str, list[str]]:
        """``statfs`` via ctypes; ``f_fstypename`` is a 16-byte char array."""
        try:
            libc = ctypes.CDLL("libc.dylib", use_errno=True)
        except OSError as exc:  # pragma: no cover - macOS only
            return "", [f"libc could not be loaded to identify {path}'s type: {exc}."]

        class _Statfs(ctypes.Structure):  # pragma: no cover - macOS only
            _fields_ = [
                ("f_bsize", ctypes.c_uint32),
                ("f_iosize", ctypes.c_int32),
                ("f_blocks", ctypes.c_uint64),
                ("f_bfree", ctypes.c_uint64),
                ("f_bavail", ctypes.c_uint64),
                ("f_files", ctypes.c_uint64),
                ("f_ffree", ctypes.c_uint64),
                ("f_fsid", ctypes.c_int32 * 2),
                ("f_owner", ctypes.c_uint32),
                ("f_type", ctypes.c_uint32),
                ("f_flags", ctypes.c_uint32),
                ("f_fssubtype", ctypes.c_uint32),
                ("f_fstypename", ctypes.c_char * 16),
                ("f_mntonname", ctypes.c_char * 1024),
                ("f_mntfromname", ctypes.c_char * 1024),
                ("f_reserved", ctypes.c_uint32 * 8),
            ]

        buffer = _Statfs()  # pragma: no cover - macOS only
        if libc.statfs(str(path).encode(), ctypes.byref(buffer)) != 0:
            return "", [f"statfs failed for {path}."]
        return buffer.f_fstypename.decode("ascii", "replace"), []

    def cluster_bytes(self, path: Path) -> tuple[int, list[str]]:
        try:
            return int(os.statvfs(path).f_bsize), []
        except OSError as exc:
            return 0, [
                f"statvfs failed for {path} ({exc}), so file slack cannot be "
                "computed."
            ]

    # -- extents ------------------------------------------------------------

    def extents(self, path: Path) -> tuple[list[Extent], list[str]]:
        if sys.platform == "linux":
            return self._extents_fiemap(path)
        return self._extents_log2phys(path)

    def _extents_fiemap(self, path: Path) -> tuple[list[Extent], list[str]]:
        """FIEMAP. The physical map, captured while the file still exists."""
        import fcntl

        try:
            size = path.stat().st_size
        except OSError as exc:
            return [], [f"{path} could not be stat'd for its extent map: {exc}."]
        if size == 0:
            return [], []

        payload = bytearray(
            _FIEMAP_HEADER.size + FIEMAP_MAX_EXTENTS * _FIEMAP_EXTENT.size
        )
        _FIEMAP_HEADER.pack_into(
            payload, 0, 0, size, FIEMAP_FLAG_SYNC, 0, FIEMAP_MAX_EXTENTS, 0
        )

        try:
            fd = os.open(path, os.O_RDONLY)
        except OSError as exc:
            return [], [f"{path} could not be opened for FIEMAP: {exc}."]
        try:
            fcntl.ioctl(fd, FS_IOC_FIEMAP, payload, True)
        except OSError as exc:
            return [], [
                f"FIEMAP is unavailable for {path} ({exc}), so no physical "
                "extent map was captured and the overwrite cannot be verified "
                "by reading the medium."
            ]
        finally:
            os.close(fd)

        _start, _length, _flags, mapped, _count, _reserved = _FIEMAP_HEADER.unpack_from(
            payload, 0
        )
        found: list[Extent] = []
        limitations: list[str] = []
        for index in range(min(mapped, FIEMAP_MAX_EXTENTS)):
            offset = _FIEMAP_HEADER.size + index * _FIEMAP_EXTENT.size
            logical, physical, length, _r1, _r2, flags, _a, _b, _c = (
                _FIEMAP_EXTENT.unpack_from(payload, offset)
            )
            if flags & FIEMAP_EXTENT_DATA_INLINE:
                limitations.append(
                    f"An extent of {path} is stored inline in the inode rather "
                    "than in a data block, so it has no physical address to "
                    "read back."
                )
                continue
            if flags & (FIEMAP_EXTENT_UNKNOWN | FIEMAP_EXTENT_DELALLOC):
                limitations.append(
                    f"An extent of {path} has no assigned physical location "
                    "yet (delayed allocation), so it was not recorded."
                )
                continue
            if flags & FIEMAP_EXTENT_ENCODED:
                limitations.append(
                    f"An extent of {path} is compressed or otherwise encoded on "
                    "disk, so the bytes at its physical address are not the "
                    "file's bytes and a comparison would be meaningless."
                )
                continue
            found.append(
                Extent(
                    logical_offset=int(logical),
                    physical_offset=int(physical),
                    length=int(length),
                )
            )
        if mapped >= FIEMAP_MAX_EXTENTS:
            limitations.append(
                f"{path} has at least {FIEMAP_MAX_EXTENTS} extents; only the "
                "first were captured, so verification covers part of the file."
            )
        return found, limitations

    def _extents_log2phys(self, path: Path) -> tuple[list[Extent], list[str]]:
        """macOS ``F_LOG2PHYS_EXT``, walked one run at a time."""
        import fcntl  # pragma: no cover - macOS only

        try:  # pragma: no cover - macOS only
            size = path.stat().st_size
        except OSError as exc:
            return [], [f"{path} could not be measured for its extent map: {exc}."]
        if size == 0:  # pragma: no cover - macOS only
            return [], []

        found: list[Extent] = []  # pragma: no cover - macOS only
        cursor = 0
        try:
            fd = os.open(path, os.O_RDONLY)
        except OSError as exc:
            return [], [f"{path} could not be opened for F_LOG2PHYS_EXT: {exc}."]
        try:
            while cursor < size and len(found) < FIEMAP_MAX_EXTENTS:
                request = struct.pack("<IIqqq", 0, 0, cursor, size - cursor, 0)
                try:
                    answer = fcntl.fcntl(fd, F_LOG2PHYS_EXT, request)
                except OSError as exc:
                    return [], [
                        f"F_LOG2PHYS_EXT failed for {path} at offset {cursor} "
                        f"({exc}); no usable extent map was captured."
                    ]
                _f1, _f2, _logical, length, physical = struct.unpack("<IIqqq", answer)
                if length <= 0:
                    break
                found.append(
                    Extent(
                        logical_offset=cursor,
                        physical_offset=int(physical),
                        length=int(length),
                    )
                )
                cursor += int(length)
        finally:
            os.close(fd)
        return found, []

    # -- resident data ------------------------------------------------------

    def is_resident(self, path: Path) -> tuple[bool | None, list[str]]:
        """Resident file data is an NTFS concept, with one ext4 analogue.

        ext4 inline_data stores a small file inside the inode, which is the
        same hazard: writing through the file handle does not reach it. FIEMAP
        reports it with ``FIEMAP_EXTENT_DATA_INLINE``, so that is what is
        checked rather than guessed from the size.
        """
        import fcntl

        try:
            size = path.stat().st_size
        except OSError:
            return None, []
        if size == 0:
            return False, []

        payload = bytearray(_FIEMAP_HEADER.size + _FIEMAP_EXTENT.size)
        _FIEMAP_HEADER.pack_into(payload, 0, 0, size, FIEMAP_FLAG_SYNC, 0, 1, 0)
        try:
            fd = os.open(path, os.O_RDONLY)
        except OSError:
            return None, []
        try:
            fcntl.ioctl(fd, FS_IOC_FIEMAP, payload, True)
        except OSError:
            fs_name, _ = self.fs_type(path)
            return None, [
                f"Whether {path} stores its data inside a filesystem metadata "
                f"record could not be determined: {fs_name or 'this filesystem'} "
                "does not answer FIEMAP."
            ]
        finally:
            os.close(fd)

        _s, _l, _fl, mapped, _c, _r = _FIEMAP_HEADER.unpack_from(payload, 0)
        if mapped < 1:
            return None, []
        *_head, flags, _a, _b, _c2 = _FIEMAP_EXTENT.unpack_from(
            payload, _FIEMAP_HEADER.size
        )
        return bool(flags & FIEMAP_EXTENT_DATA_INLINE), []

    # -- flags --------------------------------------------------------------

    def flags(self, path: Path) -> tuple[Flags, list[str]]:
        import fcntl

        limitations: list[str] = []
        sparse: bool | None = None
        try:
            stat = path.stat()
            # A file allocated fewer 512-byte blocks than its length is sparse.
            sparse = stat.st_blocks * 512 < stat.st_size
        except OSError as exc:
            limitations.append(f"{path} could not be stat'd for sparseness: {exc}.")

        compressed: bool | None = None
        encrypted: bool | None = None
        immutable: bool | None = None
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        except OSError as exc:
            limitations.append(
                f"{path} could not be opened to read its filesystem flags: {exc}."
            )
            return Flags(sparse=sparse), limitations
        try:
            raw = fcntl.ioctl(fd, FS_IOC_GETFLAGS, struct.pack("l", 0))
            (word,) = struct.unpack("l", raw)
            compressed = bool(word & FS_COMPR_FL)
            encrypted = bool(word & FS_ENCRYPT_FL)
            immutable = bool(word & FS_IMMUTABLE_FL)
        except OSError as exc:
            limitations.append(
                f"The chattr flag word for {path} could not be read ({exc}), so "
                "compression, encryption and immutability are unknown."
            )
        finally:
            os.close(fd)
        return (
            Flags(
                sparse=sparse,
                compressed=compressed,
                encrypted=encrypted,
                immutable=immutable,
            ),
            limitations,
        )

    def clear_immutable(self, path: Path) -> tuple[bool, str]:
        import fcntl

        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        except OSError as exc:
            return False, f"{path} could not be opened to clear +i: {exc}."
        try:
            raw = fcntl.ioctl(fd, FS_IOC_GETFLAGS, struct.pack("l", 0))
            (word,) = struct.unpack("l", raw)
            if not word & FS_IMMUTABLE_FL:
                return False, ""
            fcntl.ioctl(
                fd, FS_IOC_SETFLAGS, struct.pack("l", word & ~FS_IMMUTABLE_FL)
            )
        except OSError as exc:
            return False, (
                f"The immutable attribute on {path} could not be cleared "
                f"({exc}); erasing it needs CAP_LINUX_IMMUTABLE."
            )
        finally:
            os.close(fd)
        return True, ""

    # -- snapshots and TRIM -------------------------------------------------

    def cow_snapshots(self, path: Path) -> tuple[list[str] | None, list[str]]:
        """Snapshots referencing this file's old extents.

        Returns ``None`` on any failure, never ``[]``. "No snapshots" and
        "could not ask" are different claims and only one of them lets an
        operator stop worrying.
        """
        fs_name, _ = self.fs_type(path)
        family = fs_name.lower()
        if family not in {"btrfs", "zfs", "apfs"}:
            return [], []

        if family == "btrfs":
            command = ["btrfs", "subvolume", "list", "-s", str(path.parent)]
        elif family == "zfs":
            command = ["zfs", "list", "-t", "snapshot", "-H", "-o", "name"]
        else:  # pragma: no cover - macOS only
            command = ["tmutil", "listlocalsnapshots", str(path.parent)]

        try:
            completed = subprocess.run(
                command, capture_output=True, text=True, timeout=15, check=False
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return None, [
                f"Snapshots on this {family} volume could not be listed "
                f"({exc}), so whether any still reference {path}'s old extents "
                "is unknown."
            ]
        if completed.returncode != 0:
            return None, [
                f"`{command[0]}` returned {completed.returncode} when asked for "
                f"snapshots on this {family} volume "
                f"({completed.stderr.strip()[:200]}), so whether any reference "
                f"{path}'s old extents is unknown."
            ]
        names = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
        return names, []

    def trim_likely(self, path: Path) -> tuple[bool | None, list[str]]:
        """Whether the underlying device discards, from sysfs."""
        if sys.platform != "linux":  # pragma: no cover - macOS only
            return None, [
                f"Whether the volume holding {path} issues TRIM was not "
                f"determined. {UNSUPPORTED}"
            ]
        device, limits = self.block_device_for(path)
        if device is None:
            return None, limits
        name = Path(device).name
        # Strip a partition suffix: /dev/sda1 -> sda, /dev/nvme0n1p2 -> nvme0n1.
        queue = Path(f"/sys/block/{name}/queue")
        if not queue.exists():
            stem = name.rstrip("0123456789")
            if stem.endswith("p"):
                stem = stem[:-1]
            queue = Path(f"/sys/block/{stem}/queue")
        try:
            rotational = (queue / "rotational").read_text().strip()
            granularity = (queue / "discard_granularity").read_text().strip()
        except OSError as exc:
            return None, [
                f"sysfs queue attributes for {name} could not be read ({exc}), "
                "so whether this device issues TRIM is unknown."
            ]
        # `rotational == "0"` used to be required here, and a USB bridge does not
        # clear that flag: a flash stick reporting rotational=1 answered False,
        # so ResidualKind.TRIM_REMAP never fired for files on removable flash -
        # the media where an overwrite is least likely to land on the original
        # page. Discard support and a flash device node are each positive
        # evidence on their own; the flag only ever adds to them.
        discards = int(granularity or 0) > 0
        flash_node = name.startswith(("nvme", "mmcblk"))
        return discards or rotational == "0" or flash_node, []

    def block_device_for(self, path: Path) -> tuple[str | None, list[str]]:
        """The block device backing ``path``, from ``/proc/mounts``."""
        if sys.platform != "linux":  # pragma: no cover - macOS only
            return None, [
                f"The block device holding {path} was not identified. "
                f"{UNSUPPORTED}"
            ]
        try:
            resolved = path.resolve()
            mounts = Path("/proc/mounts").read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return None, [f"/proc/mounts could not be read for {path}: {exc}."]

        best_point = ""
        best_device = ""
        for line in mounts.splitlines():
            fields = line.split()
            if len(fields) < 3:
                continue
            source, point = fields[0].replace("\\040", " "), fields[1]
            if point == "/" or str(resolved) == point or str(resolved).startswith(
                point.rstrip("/") + "/"
            ):
                if len(point) >= len(best_point):
                    best_point, best_device = point, source
        if not best_device.startswith("/dev/"):
            return None, [
                f"{path} is on {best_device or 'an unidentified source'}, which "
                "is not a block device, so its physical blocks cannot be read "
                "back."
            ]
        return best_device, []

    # -- writing ------------------------------------------------------------

    def open_unbuffered_write(self, path: Path) -> tuple[int, bool, list[str]]:
        """``O_WRONLY | O_SYNC``. Write-through, so the fsync is a formality."""
        try:
            fd = os.open(path, os.O_WRONLY | os.O_SYNC)
        except OSError:
            fd = os.open(path, os.O_WRONLY)
            return fd, False, [
                f"{path} could not be opened O_SYNC, so writes were buffered "
                "and may not have reached the medium before the call returned."
            ]
        return fd, True, []
