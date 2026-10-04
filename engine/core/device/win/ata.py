"""ATA commands through ``IOCTL_ATA_PASS_THROUGH``: identify, sanitize, HPA/DCO.

Each command is exactly one ATA opcode with the feature and LBA values the
ATA/ATAPI Command Set (ACS-3) assigns it. No command is mapped onto another:
a SANITIZE that the driver refuses is reported refused, never retried as an
overwrite.

A USB bridge or card reader usually does not translate ATA pass-through, and
some that do answer with a buffer they invented. IDENTIFY data carries a
checksum (word 255); when the signature byte is present and the checksum does
not hold, the data is treated as untrustworthy and nothing is inferred from it.
"""

from __future__ import annotations

import struct
import time
from collections.abc import Callable, Generator
from dataclasses import dataclass, field

from core.device.win import ioctl
from core.device.win.disk import WindowsDisk
from core.device.win.native import NativeError
from core.errors import DeviceFrozen, UnsupportedCapability

__all__ = [
    "AtaIdentity",
    "SanitizeStatus",
    "SANITIZE_BLOCK_ERASE",
    "SANITIZE_CRYPTO_SCRAMBLE",
    "SANITIZE_OVERWRITE",
    "dco_identify",
    "identify",
    "parse_dco",
    "parse_identify",
    "read_native_max",
    "sanitize",
    "sanitize_status",
    "set_max_address",
]

CMD_IDENTIFY = 0xEC
CMD_READ_NATIVE_MAX_EXT = 0x27
CMD_SET_MAX_ADDRESS_EXT = 0x37
CMD_DCO = 0xB1
CMD_SANITIZE = 0xB4

DCO_IDENTIFY = 0xC2

#: SANITIZE DEVICE feature codes and the LBA keys each requires (ACS-3 7.36).
SANITIZE_STATUS_EXT = 0x0000
SANITIZE_CRYPTO_SCRAMBLE = 0x0011
SANITIZE_BLOCK_ERASE = 0x0012
SANITIZE_OVERWRITE = 0x0014
_SANITIZE_KEYS = {
    SANITIZE_CRYPTO_SCRAMBLE: 0x43727970,  # "Cryp"
    SANITIZE_BLOCK_ERASE: 0x426B4572,  # "BkEr"
}
SANITIZE_NAMES = {
    SANITIZE_CRYPTO_SCRAMBLE: "CRYPTO SCRAMBLE EXT",
    SANITIZE_BLOCK_ERASE: "BLOCK ERASE EXT",
    SANITIZE_OVERWRITE: "OVERWRITE EXT",
}


def _swap_string(words: bytes) -> str:
    """ATA strings are byte-swapped within each 16-bit word."""
    swapped = bytearray()
    for index in range(0, len(words) - 1, 2):
        swapped += bytes([words[index + 1], words[index]])
    return swapped.decode("ascii", errors="replace").strip(" \x00")


@dataclass(frozen=True)
class AtaIdentity:
    """The IDENTIFY DEVICE fields the resolver and the workflows use."""

    model: str
    serial: str
    checksum_valid: bool | None
    lba48: bool
    #: User-addressable sectors (words 100-103, or 60-61 without 48-bit).
    addressable_sectors: int
    sanitize_supported: bool
    crypto_scramble: bool
    overwrite: bool
    block_erase: bool
    security_supported: bool
    security_enabled: bool
    security_locked: bool
    security_frozen: bool
    enhanced_erase: bool
    hpa_supported: bool
    dco_supported: bool
    raw: bytes = field(repr=False, default=b"")

    @property
    def trustworthy(self) -> bool:
        """False when the checksum says the buffer was not the drive's."""
        return self.checksum_valid is not False


def parse_identify(data: bytes) -> AtaIdentity:
    """Decode a 512-byte IDENTIFY DEVICE buffer. Pure."""
    if len(data) < 512:
        raise ValueError(f"IDENTIFY DEVICE data is 512 bytes, got {len(data)}")
    words = struct.unpack_from("<256H", data, 0)
    checksum: bool | None = None
    if words[255] & 0xFF == 0xA5:
        checksum = sum(data[:512]) & 0xFF == 0
    lba48 = bool(words[83] & (1 << 10))
    lba28 = words[60] | (words[61] << 16)
    lba48_max = (
        words[100] | (words[101] << 16) | (words[102] << 32) | (words[103] << 48)
    )
    security = words[128]
    return AtaIdentity(
        model=_swap_string(data[54:94]),
        serial=_swap_string(data[20:40]),
        checksum_valid=checksum,
        lba48=lba48,
        addressable_sectors=lba48_max if lba48 and lba48_max else lba28,
        sanitize_supported=bool(words[59] & (1 << 12)),
        crypto_scramble=bool(words[59] & (1 << 13)),
        overwrite=bool(words[59] & (1 << 14)),
        block_erase=bool(words[59] & (1 << 15)),
        security_supported=bool(security & 0x01),
        security_enabled=bool(security & 0x02),
        security_locked=bool(security & 0x04),
        security_frozen=bool(security & 0x08),
        enhanced_erase=bool(security & 0x20),
        hpa_supported=bool(words[82] & (1 << 10)),
        dco_supported=bool(words[83] & (1 << 11)),
        raw=bytes(data[:512]),
    )


def _run(
    disk: WindowsDisk,
    *,
    command: int,
    features: int = 0,
    count: int = 0,
    lba: int = 0,
    data_in: int = 0,
    ext: bool = False,
    timeout_s: int = 30,
) -> ioctl.AtaResult:
    request = ioctl.pack_ata_pass_through(
        command=command,
        features=features,
        count=count,
        lba=lba,
        data_in=data_in,
        ext=ext,
        timeout_s=timeout_s,
    )
    try:
        raw = disk.ioctl(ioctl.IOCTL_ATA_PASS_THROUGH, request, len(request))
    except NativeError as exc:
        if exc.winerror in {
            ioctl.ERROR_INVALID_FUNCTION,
            ioctl.ERROR_NOT_SUPPORTED,
            ioctl.ERROR_INVALID_PARAMETER,
        }:
            raise UnsupportedCapability(
                f"The Windows storage stack did not pass ATA command "
                f"0x{command:02X} to {disk.path} (Win32 error {exc.winerror}). "
                "A USB bridge, a RAID or NVMe controller, or the driver refuses "
                "ATA pass-through here.",
                remediation="Attach the drive directly to a SATA port, or use "
                "an overwrite (Clear). Nothing was sent to the drive.",
            ) from exc
        raise
    return ioctl.parse_ata_pass_through(raw, ext=ext)


def identify(disk: WindowsDisk) -> AtaIdentity:
    """IDENTIFY DEVICE."""
    result = _run(disk, command=CMD_IDENTIFY, data_in=512)
    if result.aborted:
        raise UnsupportedCapability(
            f"{disk.path} aborted IDENTIFY DEVICE (error register "
            f"0x{result.error:02X}); it is not an ATA device behind this path."
        )
    return parse_identify(result.data)


def read_native_max(disk: WindowsDisk) -> int:
    """READ NATIVE MAX ADDRESS EXT: the highest native LBA."""
    result = _run(disk, command=CMD_READ_NATIVE_MAX_EXT, ext=True)
    if result.aborted:
        raise UnsupportedCapability(
            f"{disk.path} aborted READ NATIVE MAX ADDRESS EXT (error "
            f"0x{result.error:02X}); the HPA feature set is not available."
        )
    return result.lba


def set_max_address(disk: WindowsDisk, max_lba: int, *, volatile: bool) -> None:
    """SET MAX ADDRESS EXT. Must directly follow :func:`read_native_max`.

    ``volatile`` sets the VV bit (SectorCount bit 0): the new maximum lasts
    until the next power cycle and the drive then returns to its previous
    configuration. The HPA workflow uses the volatile form unless a permanent
    change was approved.
    """
    result = _run(
        disk,
        command=CMD_SET_MAX_ADDRESS_EXT,
        count=1 if volatile else 0,
        lba=max_lba,
        ext=True,
    )
    if result.aborted:
        raise UnsupportedCapability(
            f"{disk.path} aborted SET MAX ADDRESS EXT (error "
            f"0x{result.error:02X}). The accessible maximum is unchanged."
        )


def parse_dco(data: bytes) -> int:
    """The maximum LBA a DEVICE CONFIGURATION IDENTIFY buffer reports (words 3-6)."""
    if len(data) < 512:
        raise ValueError("DCO IDENTIFY data is 512 bytes")
    words = struct.unpack_from("<256H", data, 0)
    return int(words[3] | (words[4] << 16) | (words[5] << 32) | (words[6] << 48))


def dco_identify(disk: WindowsDisk) -> int:
    """DEVICE CONFIGURATION IDENTIFY: the factory maximum LBA."""
    result = _run(disk, command=CMD_DCO, features=DCO_IDENTIFY, data_in=512)
    if result.aborted:
        raise UnsupportedCapability(
            f"{disk.path} aborted DEVICE CONFIGURATION IDENTIFY (error "
            f"0x{result.error:02X}); DCO is not available or is frozen."
        )
    return parse_dco(result.data)


@dataclass(frozen=True)
class SanitizeStatus:
    """SANITIZE STATUS EXT, decoded."""

    completed_ok: bool
    in_progress: bool
    frozen: bool
    progress: int  # 0..65535
    failed: bool


def sanitize_status(disk: WindowsDisk) -> SanitizeStatus:
    """SANITIZE STATUS EXT. The progress indicator is in LBA bits 15:0."""
    result = _run(disk, command=CMD_SANITIZE, features=SANITIZE_STATUS_EXT, ext=True)
    return SanitizeStatus(
        completed_ok=bool(result.count & 0x8000),
        in_progress=bool(result.count & 0x4000),
        frozen=bool(result.count & 0x2000),
        progress=result.lba & 0xFFFF,
        failed=result.aborted,
    )


def sanitize(
    disk: WindowsDisk,
    action: int,
    *,
    poll_s: float = 5.0,
    timeout_s: float = 24 * 3600.0,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> Generator[SanitizeStatus, None, SanitizeStatus]:
    """Issue one SANITIZE DEVICE action and poll it to completion.

    Yields every status read, returns the last. Raises when the drive aborts
    the command, reports the sanitize failed, or does not finish in
    ``timeout_s`` - in which case the drive is still sanitizing and the
    caller's report must say the result is unknown.
    """
    if action not in _SANITIZE_KEYS:
        raise UnsupportedCapability(
            f"SANITIZE action 0x{action:04X} is not issued by this build."
        )
    before = sanitize_status(disk)
    if before.frozen:
        raise DeviceFrozen(
            f"{disk.path} reports SANITIZE FROZEN; the command would be aborted."
        )
    result = _run(
        disk,
        command=CMD_SANITIZE,
        features=action,
        lba=_SANITIZE_KEYS[action],
        ext=True,
        timeout_s=60,
    )
    if result.aborted:
        raise UnsupportedCapability(
            f"{disk.path} aborted SANITIZE {SANITIZE_NAMES[action]} (error "
            f"0x{result.error:02X}). Nothing was sanitized.",
            remediation="The drive refused the command; use an overwrite "
            "(Clear) or the drive vendor's tool.",
        )
    deadline = clock() + timeout_s
    while True:
        status = sanitize_status(disk)
        yield status
        if status.failed:
            raise UnsupportedCapability(
                f"{disk.path} reports that SANITIZE {SANITIZE_NAMES[action]} "
                "failed. The drive stays in the sanitize-failed state until a "
                "successful sanitize completes."
            )
        if not status.in_progress:
            if not status.completed_ok:
                raise UnsupportedCapability(
                    f"{disk.path} stopped sanitizing without reporting success."
                )
            return status
        if clock() > deadline:
            raise UnsupportedCapability(
                f"{disk.path} was still sanitizing after {int(timeout_s)} s. The "
                "outcome is unknown; do not rely on the device until SANITIZE "
                "STATUS reports completion."
            )
        sleep(poll_s)
