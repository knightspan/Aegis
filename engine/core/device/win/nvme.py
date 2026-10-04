"""NVMe on Windows: Identify Controller, and sanitize through the in-box driver.

Windows' NVMe driver (``stornvme``) does not pass Sanitize or Format NVM
through ``IOCTL_STORAGE_PROTOCOL_COMMAND``. What it does offer is
``IOCTL_STORAGE_REINITIALIZE_MEDIA``, which makes the driver issue an NVMe
Sanitize itself; from Windows Server 2022 / Windows 10 build 20348 the caller
chooses block erase or crypto erase through ``STORAGE_REINITIALIZE_MEDIA``.
On an earlier build the structure is ignored and the driver's default action
runs, so :func:`reinitialize_media` records the build it ran on and the report
says which method was *requested*, not assumed.

What Identify Controller says about sanitize (NVMe 1.4, figure 247):

* SANICAP (bytes 328-331): bit 0 crypto erase, bit 1 block erase, bit 2
  overwrite.
* OACS (bytes 256-257): bit 1 Format NVM supported.
* FNA (byte 524): bit 2 crypto erase supported as part of a secure erase.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from core.device.win import ioctl
from core.device.win.disk import WindowsDisk
from core.device.win.native import NativeError
from core.errors import UnsupportedCapability

__all__ = [
    "NvmeIdentity",
    "identify_controller",
    "parse_identify_controller",
    "reinitialize_media",
    "REINITIALIZE_MIN_BUILD",
]

#: The first build whose driver honours the sanitize method in the input.
REINITIALIZE_MIN_BUILD = 20348


@dataclass(frozen=True)
class NvmeIdentity:
    vendor_id: int
    serial: str
    model: str
    firmware: str
    format_supported: bool
    crypto_erase: bool
    block_erase: bool
    overwrite: bool
    format_crypto: bool


def parse_identify_controller(data: bytes) -> NvmeIdentity:
    """Decode the fields of a 4096-byte Identify Controller structure. Pure."""
    if len(data) < 4096:
        raise ValueError(f"Identify Controller is 4096 bytes, got {len(data)}")
    (vid,) = struct.unpack_from("<H", data, 0)
    (oacs,) = struct.unpack_from("<H", data, 256)
    (sanicap,) = struct.unpack_from("<I", data, 328)
    fna = data[524]
    return NvmeIdentity(
        vendor_id=int(vid),
        serial=data[4:24].decode("ascii", errors="replace").strip(),
        model=data[24:64].decode("ascii", errors="replace").strip(),
        firmware=data[64:72].decode("ascii", errors="replace").strip(),
        format_supported=bool(oacs & 0x02),
        crypto_erase=bool(sanicap & 0x01),
        block_erase=bool(sanicap & 0x02),
        overwrite=bool(sanicap & 0x04),
        format_crypto=bool(fna & 0x04),
    )


def identify_controller(disk: WindowsDisk) -> NvmeIdentity:
    """Identify Controller through ``IOCTL_STORAGE_QUERY_PROPERTY``."""
    query = ioctl.pack_nvme_identify_query()
    try:
        raw = disk.ioctl(ioctl.IOCTL_STORAGE_QUERY_PROPERTY, query, len(query))
    except NativeError as exc:
        raise UnsupportedCapability(
            f"The Windows NVMe driver did not return Identify Controller for "
            f"{disk.path} (Win32 error {exc.winerror}); the disk is not on the "
            "in-box NVMe driver, or a bridge hides the controller."
        ) from exc
    return parse_identify_controller(ioctl.parse_nvme_identify_result(raw))


def reinitialize_media(
    disk: WindowsDisk, method: int, *, timeout_s: int, os_build: int
) -> dict[str, object]:
    """Ask the NVMe driver to sanitize the whole device. Blocks until it returns.

    Returns what was requested and on which build, for the report. Raises when
    the driver refuses; the Win32 error is kept.
    """
    payload = ioctl.pack_reinitialize_media(method, timeout_s)
    honoured = os_build >= REINITIALIZE_MIN_BUILD
    try:
        disk.ioctl(
            ioctl.IOCTL_STORAGE_REINITIALIZE_MEDIA, payload if honoured else b"", 0
        )
    except NativeError as exc:
        raise UnsupportedCapability(
            f"IOCTL_STORAGE_REINITIALIZE_MEDIA on {disk.path} failed with Win32 "
            f"error {exc.winerror}. Windows allows it only on a data disk (never "
            "the boot disk outside WinPE) whose NVMe controller supports "
            "Sanitize. Nothing is known to have been erased.",
            remediation="Use an overwrite (Clear), or the drive vendor's tool.",
        ) from exc
    return {
        "ioctl": "IOCTL_STORAGE_REINITIALIZE_MEDIA",
        "requested_method": (
            "crypto erase"
            if method == ioctl.STORAGE_SANITIZE_CRYPTO_ERASE
            else "block erase"
        ),
        "method_honoured": honoured,
        "os_build": os_build,
        "note": (
            "The driver takes the requested sanitize method on this build."
            if honoured
            else f"Build {os_build} predates {REINITIALIZE_MIN_BUILD}: the driver "
            "ignores the requested method and issues its default sanitize "
            "action, which Sanctum cannot observe."
        ),
    }
