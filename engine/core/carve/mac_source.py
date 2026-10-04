"""Read-only acquisition source for a macOS disk or partition (``/dev/rdiskN``).

Opened ``O_RDONLY`` through the raw character device, sized from the kernel,
and bound to the size the operator selected. macOS has no software write
block; the record says so and names a hardware write blocker as the control.

Reads are widened to the device block and sliced back, for the same reason as
on Windows: the raw device refuses anything smaller than a block, and the
acquisition's salvage path asks for 512-byte pieces. A device that disappears
raises :class:`~core.errors.DeviceVanished` rather than ``OSError``, so it is
never salvaged into an image of fill bytes.
"""

from __future__ import annotations

import errno

from core.device.mac.rawdisk import MacIo, MacRawDisk
from core.errors import DeviceVanished, EvidenceIntegrityError

__all__ = ["MacDiskReader", "open_macos_source"]

_GONE = frozenset({errno.ENXIO, errno.ENODEV, errno.ENOENT})


class MacDiskReader:
    """:class:`~core.carve.acquire.SourceReader` over ``/dev/rdiskN``."""

    def __init__(
        self,
        device: str,
        *,
        expected_size: int,
        sector_size: int = 512,
        io: MacIo | None = None,
    ) -> None:
        self._disk = MacRawDisk(device, write=False, io=io).open()
        if expected_size > 0:
            self._disk.bind(size_bytes=expected_size)
        self.path = self._disk.path
        self.size = self._disk.size_bytes
        self.sector_size = max(sector_size, 1)

    def read_at(self, offset: int, length: int) -> bytes:
        length = min(length, self.size - offset)
        if length <= 0:
            return b""
        block = self._disk.logical_sector
        start = (offset // block) * block
        end = min(self.size, -(-(offset + length) // block) * block)
        try:
            data = self._disk.read_at(start, end - start)
        except OSError as exc:
            if exc.errno in _GONE:
                raise DeviceVanished(
                    f"{self.path} disappeared during acquisition at {offset}."
                ) from exc
            raise
        return data[offset - start : offset - start + length]

    def close(self) -> None:
        self._disk.close()


def open_macos_source(
    device: str,
    *,
    expected_size: int = 0,
    sector_size: int = 512,
    io: MacIo | None = None,
) -> MacDiskReader:
    """The raw reader. A whole disk needs the size that was selected."""
    if expected_size <= 0:
        raise EvidenceIntegrityError(
            f"raw acquisition of {device} needs the size of the disk that was "
            "selected, so the handle can be bound to it",
            remediation="Start the acquisition from the Devices screen. Nothing "
            "was opened.",
        )
    return MacDiskReader(
        device, expected_size=expected_size, sector_size=sector_size, io=io
    )
