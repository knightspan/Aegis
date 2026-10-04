"""Win32 storage IOCTL codes and structures, packed and parsed without Windows.

Every layout here is the one ``winioctl.h`` / ``ntddscsi.h`` / ``nvme.h``
define for 64-bit Windows. They are built with :mod:`struct` rather than
:mod:`ctypes` structures on purpose: the byte offsets are then written down
once, in this file, where a reader can check them against the header, and a
test on any host can pin them.

Nothing in this module performs I/O.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

__all__ = [
    "ATA_FLAGS_48BIT_COMMAND",
    "ATA_FLAGS_DATA_IN",
    "ATA_FLAGS_DATA_OUT",
    "ATA_FLAGS_DRDY_REQUIRED",
    "ATA_PASS_THROUGH_EX_SIZE",
    "AtaResult",
    "BUS_TYPE_NAMES",
    "DeviceDescriptor",
    "FSCTL_DISMOUNT_VOLUME",
    "FSCTL_LOCK_VOLUME",
    "FSCTL_UNLOCK_VOLUME",
    "IOCTL_ATA_PASS_THROUGH",
    "IOCTL_DISK_GET_DRIVE_GEOMETRY_EX",
    "IOCTL_DISK_GET_LENGTH_INFO",
    "IOCTL_DISK_SET_DISK_ATTRIBUTES",
    "IOCTL_DISK_UPDATE_PROPERTIES",
    "pack_set_disk_attributes",
    "IOCTL_STORAGE_GET_DEVICE_NUMBER",
    "IOCTL_STORAGE_QUERY_PROPERTY",
    "IOCTL_STORAGE_REINITIALIZE_MEDIA",
    "IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS",
    "STORAGE_SANITIZE_BLOCK_ERASE",
    "STORAGE_SANITIZE_CRYPTO_ERASE",
    "ctl_code",
    "pack_ata_pass_through",
    "pack_nvme_identify_query",
    "pack_property_query",
    "pack_reinitialize_media",
    "parse_access_alignment",
    "parse_ata_pass_through",
    "parse_device_descriptor",
    "parse_device_number",
    "parse_geometry_ex",
    "parse_length_info",
    "parse_nvme_identify_result",
    "parse_volume_disk_extents",
]

# -- CreateFileW ---------------------------------------------------------------

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_FLAG_NO_BUFFERING = 0x20000000
FILE_FLAG_WRITE_THROUGH = 0x80000000

# -- Win32 error codes this layer names ---------------------------------------

ERROR_INVALID_FUNCTION = 1
ERROR_FILE_NOT_FOUND = 2
ERROR_PATH_NOT_FOUND = 3
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_HANDLE = 6
ERROR_WRITE_PROTECT = 19
ERROR_NOT_READY = 21
ERROR_CRC = 23
ERROR_SECTOR_NOT_FOUND = 27
ERROR_SHARING_VIOLATION = 32
ERROR_NOT_SUPPORTED = 50
ERROR_INVALID_PARAMETER = 87
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_MORE_DATA = 234
ERROR_NO_SUCH_DEVICE = 433
ERROR_IO_DEVICE = 1117
ERROR_DEVICE_NOT_CONNECTED = 1167

#: Errors that mean "the medium could not be read or written here", which the
#: acquisition salvages sector by sector and the clear records as unwritable,
#: as opposed to errors that mean the device or handle is gone.
MEDIUM_ERRORS = frozenset({ERROR_CRC, ERROR_SECTOR_NOT_FOUND, ERROR_IO_DEVICE})
#: Errors that mean the device went away under the handle.
GONE_ERRORS = frozenset(
    {
        ERROR_FILE_NOT_FOUND,
        ERROR_PATH_NOT_FOUND,
        ERROR_NOT_READY,
        ERROR_NO_SUCH_DEVICE,
        ERROR_DEVICE_NOT_CONNECTED,
        ERROR_INVALID_HANDLE,
    }
)

# -- control codes --------------------------------------------------------------

METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0
FILE_READ_ACCESS = 1
FILE_WRITE_ACCESS = 2


def ctl_code(device_type: int, function: int, method: int, access: int) -> int:
    """``CTL_CODE`` from ``winioctl.h``."""
    return (device_type << 16) | (access << 14) | (function << 2) | method


_DISK = 0x00000007  # IOCTL_DISK_BASE / FILE_DEVICE_DISK
_STORAGE = 0x0000002D  # IOCTL_STORAGE_BASE / FILE_DEVICE_MASS_STORAGE
_CONTROLLER = 0x00000004  # IOCTL_SCSI_BASE / FILE_DEVICE_CONTROLLER
_FILESYSTEM = 0x00000009
_VOLUME = 0x00000056

IOCTL_DISK_GET_LENGTH_INFO = ctl_code(_DISK, 0x0017, METHOD_BUFFERED, FILE_READ_ACCESS)
IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = ctl_code(
    _DISK, 0x0028, METHOD_BUFFERED, FILE_ANY_ACCESS
)
IOCTL_DISK_UPDATE_PROPERTIES = ctl_code(_DISK, 0x0050, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_STORAGE_GET_DEVICE_NUMBER = ctl_code(
    _STORAGE, 0x0420, METHOD_BUFFERED, FILE_ANY_ACCESS
)
IOCTL_STORAGE_QUERY_PROPERTY = ctl_code(
    _STORAGE, 0x0500, METHOD_BUFFERED, FILE_ANY_ACCESS
)
#: Offloads an erase to the device. NVMe only for the sanitize method; see
#: :func:`pack_reinitialize_media`.
IOCTL_STORAGE_REINITIALIZE_MEDIA = ctl_code(
    _STORAGE, 0x0590, METHOD_BUFFERED, FILE_WRITE_ACCESS
)
IOCTL_ATA_PASS_THROUGH = ctl_code(
    _CONTROLLER, 0x040B, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS
)
FSCTL_LOCK_VOLUME = ctl_code(_FILESYSTEM, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
FSCTL_UNLOCK_VOLUME = ctl_code(_FILESYSTEM, 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
FSCTL_DISMOUNT_VOLUME = ctl_code(_FILESYSTEM, 8, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_DISK_SET_DISK_ATTRIBUTES = ctl_code(
    _DISK, 0x003D, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS
)
IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = ctl_code(
    _VOLUME, 0, METHOD_BUFFERED, FILE_ANY_ACCESS
)

# -- simple outputs ---------------------------------------------------------------


def parse_length_info(buf: bytes) -> int:
    """``GET_LENGTH_INFORMATION``: one LARGE_INTEGER, the length in bytes."""
    if len(buf) < 8:
        raise ValueError(f"GET_LENGTH_INFORMATION is 8 bytes, got {len(buf)}")
    (length,) = struct.unpack_from("<q", buf, 0)
    if length < 0:
        raise ValueError(f"negative disk length {length}")
    return int(length)


def parse_device_number(buf: bytes) -> tuple[int, int, int]:
    """``STORAGE_DEVICE_NUMBER``: (DeviceType, DeviceNumber, PartitionNumber)."""
    if len(buf) < 12:
        raise ValueError(f"STORAGE_DEVICE_NUMBER is 12 bytes, got {len(buf)}")
    kind, number, partition = struct.unpack_from("<III", buf, 0)
    return int(kind), int(number), int(partition)


def parse_geometry_ex(buf: bytes) -> tuple[int, int]:
    """``DISK_GEOMETRY_EX``: (BytesPerSector, DiskSize).

    ``DISK_GEOMETRY`` is Cylinders (8), MediaType (4), TracksPerCylinder (4),
    SectorsPerTrack (4), BytesPerSector (4): BytesPerSector at 20. DiskSize, a
    LARGE_INTEGER, follows at 24.
    """
    if len(buf) < 32:
        raise ValueError(f"DISK_GEOMETRY_EX needs 32 bytes, got {len(buf)}")
    (sector,) = struct.unpack_from("<I", buf, 20)
    (size,) = struct.unpack_from("<q", buf, 24)
    return int(sector), int(size)


def parse_volume_disk_extents(buf: bytes) -> list[tuple[int, int, int]]:
    """``VOLUME_DISK_EXTENTS``: [(DiskNumber, StartingOffset, ExtentLength)].

    NumberOfDiskExtents (4) and 4 bytes of padding, then 24-byte
    ``DISK_EXTENT`` records: DiskNumber (4), padding (4), two LARGE_INTEGERs.
    """
    if len(buf) < 8:
        raise ValueError("VOLUME_DISK_EXTENTS is at least 8 bytes")
    (count,) = struct.unpack_from("<I", buf, 0)
    if 8 + 24 * count > len(buf):
        raise ValueError(f"VOLUME_DISK_EXTENTS claims {count} extents, truncated")
    out: list[tuple[int, int, int]] = []
    for index in range(count):
        disk, start, length = struct.unpack_from("<I4xqq", buf, 8 + 24 * index)
        out.append((int(disk), int(start), int(length)))
    return out


DISK_ATTRIBUTE_OFFLINE = 0x0000000000000001


def pack_set_disk_attributes(*, offline: bool, persist: bool) -> bytes:
    """``SET_DISK_ATTRIBUTES`` changing only the offline bit.

    Version (4, = sizeof = 40), Persist (1), Reserved1[3], Attributes (8),
    AttributesMask (8), Reserved2[4] (16).
    """
    return struct.pack(
        "<IB3xQQ16x",
        40,
        1 if persist else 0,
        DISK_ATTRIBUTE_OFFLINE if offline else 0,
        DISK_ATTRIBUTE_OFFLINE,
    )


# -- IOCTL_STORAGE_QUERY_PROPERTY -----------------------------------------------

STORAGE_DEVICE_PROPERTY = 0
STORAGE_ACCESS_ALIGNMENT_PROPERTY = 6
STORAGE_ADAPTER_PROTOCOL_SPECIFIC_PROPERTY = 49
STORAGE_DEVICE_PROTOCOL_SPECIFIC_PROPERTY = 50
PROPERTY_STANDARD_QUERY = 0

#: ``STORAGE_BUS_TYPE``.
BUS_TYPE_NAMES: dict[int, str] = {
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


def pack_property_query(
    property_id: int, query_type: int = PROPERTY_STANDARD_QUERY
) -> bytes:
    """``STORAGE_PROPERTY_QUERY`` with an empty AdditionalParameters."""
    return struct.pack("<II4x", property_id, query_type)


@dataclass(frozen=True)
class DeviceDescriptor:
    """The fields of ``STORAGE_DEVICE_DESCRIPTOR`` identity binding needs."""

    bus_type: int
    removable: bool
    vendor: str
    product: str
    revision: str
    serial: str

    @property
    def bus_name(self) -> str:
        return BUS_TYPE_NAMES.get(self.bus_type, str(self.bus_type))


def _cstring_at(buf: bytes, offset: int) -> str:
    if offset <= 0 or offset >= len(buf):
        return ""
    end = buf.find(b"\x00", offset)
    raw = buf[offset : end if end >= 0 else len(buf)]
    return raw.decode("ascii", errors="replace").strip()


def parse_device_descriptor(buf: bytes) -> DeviceDescriptor:
    """``STORAGE_DEVICE_DESCRIPTOR``.

    Version (4), Size (4), DeviceType (1), DeviceTypeModifier (1),
    RemovableMedia (1), CommandQueueing (1), then the four string offsets
    VendorId, ProductId, ProductRevision, SerialNumber (4 each, from 12), then
    BusType (4) at 28. An offset of zero means the string is absent.
    """
    if len(buf) < 36:
        raise ValueError(f"STORAGE_DEVICE_DESCRIPTOR needs 36 bytes, got {len(buf)}")
    removable = bool(buf[10])
    vendor, product, revision, serial, bus = struct.unpack_from("<IIIII", buf, 12)
    return DeviceDescriptor(
        bus_type=int(bus),
        removable=removable,
        vendor=_cstring_at(buf, vendor),
        product=_cstring_at(buf, product),
        revision=_cstring_at(buf, revision),
        serial=_cstring_at(buf, serial),
    )


def parse_access_alignment(buf: bytes) -> tuple[int, int]:
    """``STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR``: (logical, physical) sector bytes.

    Version, Size, BytesPerCacheLine, BytesOffsetForCacheAlignment,
    BytesPerLogicalSector (16), BytesPerPhysicalSector (20).
    """
    if len(buf) < 24:
        raise ValueError("STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR needs 24 bytes")
    logical, physical = struct.unpack_from("<II", buf, 16)
    return int(logical), int(physical)


# -- NVMe identify through the property query ---------------------------------

PROTOCOL_TYPE_NVME = 3
NVME_DATA_TYPE_IDENTIFY = 1
NVME_IDENTIFY_CNS_CONTROLLER = 1
NVME_IDENTIFY_BYTES = 4096
#: ``STORAGE_PROTOCOL_SPECIFIC_DATA`` is ten ULONGs.
_PROTOCOL_DATA_BYTES = 40


def pack_nvme_identify_query(
    cns: int = NVME_IDENTIFY_CNS_CONTROLLER, nsid: int = 0
) -> bytes:
    """A property query asking the NVMe driver for an Identify data structure.

    ``STORAGE_PROPERTY_QUERY`` (PropertyId, QueryType) followed in its
    AdditionalParameters by ``STORAGE_PROTOCOL_SPECIFIC_DATA`` and room for the
    4096-byte answer, as the Windows NVMe sample builds it.
    """
    header = struct.pack(
        "<II", STORAGE_ADAPTER_PROTOCOL_SPECIFIC_PROPERTY, PROPERTY_STANDARD_QUERY
    )
    specific = struct.pack(
        "<10I",
        PROTOCOL_TYPE_NVME,
        NVME_DATA_TYPE_IDENTIFY,
        cns,
        nsid,
        _PROTOCOL_DATA_BYTES,  # ProtocolDataOffset, from the specific-data start
        NVME_IDENTIFY_BYTES,  # ProtocolDataLength
        0,
        0,
        0,
        0,
    )
    return header + specific + bytes(NVME_IDENTIFY_BYTES)


def parse_nvme_identify_result(buf: bytes) -> bytes:
    """The Identify data out of a ``STORAGE_PROTOCOL_DATA_DESCRIPTOR``.

    Version (4), Size (4), then the ``STORAGE_PROTOCOL_SPECIFIC_DATA`` the driver
    filled in; the data sits at its ProtocolDataOffset from the start of that
    structure, and is ProtocolDataLength long.
    """
    if len(buf) < 8 + _PROTOCOL_DATA_BYTES:
        raise ValueError("protocol data descriptor truncated")
    offset, length = struct.unpack_from("<II", buf, 8 + 16)
    start = 8 + offset
    if length < 512 or start + length > len(buf):
        raise ValueError(
            f"protocol data descriptor names {length} bytes at {start}, "
            f"outside the {len(buf)}-byte answer"
        )
    return bytes(buf[start : start + length])


# -- IOCTL_STORAGE_REINITIALIZE_MEDIA -----------------------------------------------

STORAGE_SANITIZE_DEFAULT = 0
STORAGE_SANITIZE_BLOCK_ERASE = 1
STORAGE_SANITIZE_CRYPTO_ERASE = 2
_REINITIALIZE_BYTES = 16


def pack_reinitialize_media(method: int, timeout_s: int) -> bytes:
    """``STORAGE_REINITIALIZE_MEDIA``: Version, Size, TimeoutInSeconds, options.

    Version and Size are both ``sizeof`` the structure (16). The option word
    carries SanitizeMethod in bits 0-3 and DisallowUnrestrictedSanitizeExit in
    bit 4, which is set: a failed sanitize must leave the drive in the failed
    state, where it reports the failure, rather than let it be exited quietly.
    """
    if method not in {STORAGE_SANITIZE_BLOCK_ERASE, STORAGE_SANITIZE_CRYPTO_ERASE}:
        raise ValueError(f"sanitize method {method} is not one this build issues")
    if timeout_s <= 0:
        raise ValueError("a sanitize needs a positive timeout")
    option = (method & 0xF) | (1 << 4)
    return struct.pack(
        "<IIII", _REINITIALIZE_BYTES, _REINITIALIZE_BYTES, timeout_s, option
    )


# -- IOCTL_ATA_PASS_THROUGH ------------------------------------------------------

ATA_FLAGS_DRDY_REQUIRED = 0x01
ATA_FLAGS_DATA_IN = 0x02
ATA_FLAGS_DATA_OUT = 0x04
ATA_FLAGS_48BIT_COMMAND = 0x08
ATA_FLAGS_NO_MULTIPLE = 0x20

#: ``ATA_PASS_THROUGH_EX`` on 64-bit Windows: Length, AtaFlags (2 each),
#: PathId, TargetId, Lun, ReservedAsUchar (1 each), DataTransferLength,
#: TimeOutValue, ReservedAsUlong (4 each), 4 bytes of alignment padding,
#: DataBufferOffset (ULONG_PTR, 8), PreviousTaskFile[8], CurrentTaskFile[8].
_APT_FORMAT = "<HHBBBBIII4xQ8s8s"
ATA_PASS_THROUGH_EX_SIZE = struct.calcsize(_APT_FORMAT)
assert ATA_PASS_THROUGH_EX_SIZE == 48


def pack_ata_pass_through(
    *,
    command: int,
    features: int = 0,
    count: int = 0,
    lba: int = 0,
    device: int = 0x40,
    data_in: int = 0,
    data_out: bytes = b"",
    ext: bool = False,
    timeout_s: int = 30,
) -> bytes:
    """One ``ATA_PASS_THROUGH_EX`` with its data buffer appended.

    Task-file order is Features, SectorCount, LBA low, LBA mid, LBA high,
    Device, Command, Reserved. For a 48-bit command the high bytes go in
    PreviousTaskFile in the same positions.
    """
    if data_in and data_out:
        raise ValueError("a pass-through moves data in one direction")
    length = data_in or len(data_out)
    flags = ATA_FLAGS_DRDY_REQUIRED
    if data_in:
        flags |= ATA_FLAGS_DATA_IN
    if data_out:
        flags |= ATA_FLAGS_DATA_OUT
    if ext:
        flags |= ATA_FLAGS_48BIT_COMMAND
    current = bytes(
        [
            features & 0xFF,
            count & 0xFF,
            lba & 0xFF,
            (lba >> 8) & 0xFF,
            (lba >> 16) & 0xFF,
            device & 0xFF,
            command & 0xFF,
            0,
        ]
    )
    previous = (
        bytes(
            [
                (features >> 8) & 0xFF,
                (count >> 8) & 0xFF,
                (lba >> 24) & 0xFF,
                (lba >> 32) & 0xFF,
                (lba >> 40) & 0xFF,
                0,
                0,
                0,
            ]
        )
        if ext
        else bytes(8)
    )
    header = struct.pack(
        _APT_FORMAT,
        ATA_PASS_THROUGH_EX_SIZE,
        flags,
        0,
        0,
        0,
        0,
        length,
        timeout_s,
        0,
        ATA_PASS_THROUGH_EX_SIZE,
        previous,
        current,
    )
    return header + (data_out if data_out else bytes(length))


@dataclass(frozen=True)
class AtaResult:
    """What the device answered: registers and the data buffer."""

    status: int
    error: int
    #: SectorCount, 16 bits for a 48-bit command.
    count: int
    #: LBA, 48 bits for a 48-bit command.
    lba: int
    data: bytes

    @property
    def aborted(self) -> bool:
        """ERR set in the status register: the device refused the command."""
        return bool(self.status & 0x01)


def parse_ata_pass_through(buf: bytes, *, ext: bool = False) -> AtaResult:
    """The returned ``ATA_PASS_THROUGH_EX``: output registers and data."""
    if len(buf) < ATA_PASS_THROUGH_EX_SIZE:
        raise ValueError("ATA_PASS_THROUGH_EX truncated")
    (_, _, _, _, _, _, length, _, _, offset, previous, current) = struct.unpack_from(
        _APT_FORMAT, buf, 0
    )
    count = current[1]
    lba = current[2] | (current[3] << 8) | (current[4] << 16)
    if ext:
        count |= previous[1] << 8
        lba |= (previous[2] << 24) | (previous[3] << 32) | (previous[4] << 40)
    data = bytes(buf[offset : offset + length]) if length else b""
    return AtaResult(
        status=current[6], error=current[0], count=count, lba=lba, data=data
    )
