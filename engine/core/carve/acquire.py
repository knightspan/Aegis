"""Forensic imaging: write-blocked reads, dual hashing, honest bad sectors.

Two rules govern everything here.

**Never modify the evidence.** The source is opened ``O_RDONLY`` and, on Linux,
set read-only at the block layer with ``BLKROSET`` before it is opened at all.
That flag is then read back with ``BLKROGET``: a write block that was requested
but did not take is worse than none, because the operator believes in it.
Windows and macOS have no equivalent software write block. Rather than imply
one, an acquisition on those platforms records
``NO_SOFTWARE_WRITE_BLOCK`` as a limitation on the record and in the report. A
hardware write blocker is the correct answer and the documentation says so.

**Never silently substitute.** A drive with forty thousand bad sectors still
yields evidence, so a read error never aborts the run. What it does is:

1. retry the failing block at sector granularity, so three bad sectors cost
   three sectors rather than the whole 1 MiB block;
2. fill each still-unreadable sector with the substitution byte;
3. record its LBA range on the acquisition, in the ledger and in the report.

An image containing invented bytes and no record of where they are is not
evidence, it is a forgery with good intentions.

Hashing happens **in the read pass**, both algorithms at once. Re-reading a 2 TB
disk to hash it doubles the acquisition, and a per-chunk hash list means a later
integrity failure names a chunk instead of condemning the whole image.
"""

from __future__ import annotations

import errno
import hashlib
import os
import platform
import sys
from collections.abc import Callable, Generator, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

import structlog

from core.carve.evidence import DEFAULT_SECTOR_BYTES, open_evidence
from core.errors import EvidenceIntegrityError, UnsupportedCapability
from core.ledger.chain import Ledger, boot_id
from core.models import (
    AcquisitionRecord,
    BadSectorRange,
    EvidenceSource,
    IntegrityResult,
    Progress,
    SubstitutedRange,
)

__all__ = [
    "SourceReader",
    "FileSourceReader",
    "is_win32_device_path",
    "AcquireOptions",
    "AcquisitionPhase",
    "acquire",
    "verify_image",
    "e01_write_supported",
    "apply_write_block",
    "NO_SOFTWARE_WRITE_BLOCK",
    "WRITE_BLOCK_NOT_VERIFIED",
    "TOOL_VERSION",
]

logger = structlog.get_logger(__name__)

KIB = 1024
MIB = 1024 * KIB

TOOL_VERSION = "sanctum-forensics/0.0.0"

#: ioctl request numbers for the block-layer read-only flag (Linux).
BLKROSET = 0x125D
BLKROGET = 0x125E

NO_SOFTWARE_WRITE_BLOCK = (
    "NO_SOFTWARE_WRITE_BLOCK: {platform} provides no software write block "
    "equivalent to Linux BLKROSET. The source was opened read-only, but nothing "
    "prevents another process on this host from writing to it during "
    "acquisition. Use a hardware write blocker for evidence that will be "
    "presented; this image is suitable for triage only."
)

WRITE_BLOCK_REFUSED = (
    "WRITE_BLOCK_NOT_APPLIED: BLKROSET was issued but BLKROGET read back "
    "writable. The kernel did not honour the request, so no write block is in "
    "force despite one having been asked for."
)

WRITE_BLOCK_NOT_VERIFIED = (
    "WRITE_BLOCK_NOT_VERIFIED: BLKROSET was set and BLKROGET read it back as "
    "applied, which establishes that the kernel holds this device read-only. It "
    "does not establish that a write would be refused - proving that requires "
    "attempting one, and this tool never writes to an evidence device. Qualify "
    "the interface once against scratch media with scripts/probe-write-block.py "
    "and keep the result. Note also that BLKROSET governs the block layer only: "
    "SG_IO and ATA pass-through writes bypass it entirely, as does a partition "
    "node whose own flag was never set."
)

E01_WRITE_UNSUPPORTED = (
    "This build of libewf-python ({version}) cannot write E01. libewf refuses "
    "the write open with 'write access currently not supported - compiled "
    "without zlib': the upstream sdist's setup.py configures with "
    "--disable-shared-libs, and m4/zlib.m4 reads that same switch as 'use the "
    "local deflate implementation', which libewf will not write with. Reading "
    "E01 is fully supported; only acquisition to E01 is unavailable."
)

#: Attached to every E01 acquisition, because it is true of these bindings
#: rather than of a broken build of them. libewf's C API can set the
#: compression method and level; ``pyewf`` binds none of those setters, so the
#: option is accepted, has no effect, and says so.
#:
#: The operationally important half is the second sentence. libewf's default is
#: not "fast", it is **no compression at all**, confirmed with ewfinfo against
#: a container this module wrote: 8 MiB of a single repeated byte produced
#: 8,394,899 bytes, larger than the source. An E01 written here is a container
#: format and an integrity record, never a space saving.
E01_COMPRESSION_NOT_SELECTABLE = (
    "E01_COMPRESSION_NOT_SELECTABLE: libewf-python {version} binds none of "
    "libewf's write-configuration setters - pyewf.handle exposes set_header_"
    "codepage and nothing else, so libewf_handle_set_compression_values cannot "
    "be reached. AcquireOptions.compression={requested!r} had no effect: the "
    "container was written at libewf's default, which ewfinfo reports as "
    "'no compression'. Expect an E01 slightly LARGER than the source, not "
    "smaller. Use ewfacquire -c fast if the container must be compressed."
)

#: pyewf exposes no flush, so a checkpoint cannot make an in-progress E01
#: durable the way an fsync makes a raw image durable.
E01_NO_DURABLE_CHECKPOINT = (
    "E01_NO_DURABLE_CHECKPOINT: pyewf exposes no flush, so checkpoints during "
    "an E01 acquisition are recorded in the ledger but not forced to disk. An "
    "E01 interrupted mid-run is not resumable and must be re-acquired."
)


class AcquisitionPhase:
    """Phase names, so the ledger and the UI cannot drift apart."""

    PREFLIGHT = "preflight"
    WRITE_BLOCK = "write_block"
    READ = "read"
    VERIFY = "verify"
    COMPLETE = "complete"


# --------------------------------------------------------------------------
# Source seam
# --------------------------------------------------------------------------


@runtime_checkable
class SourceReader(Protocol):
    """A read-only byte source being imaged.

    The seam exists so bad sectors can be injected in tests without a failing
    disk: an implementation raises ``OSError(EIO)`` and the salvage path is
    exercised for real.
    """

    size: int
    sector_size: int

    def read_at(self, offset: int, length: int) -> bytes:
        """Return bytes at ``offset``. May raise ``OSError`` on medium error."""
        ...

    def close(self) -> None: ...


#: Win32 device-namespace prefixes: ``\\.\PhysicalDriveN``, ``\\.\E:`` and the
#: ``\\?\`` spellings of a drive or volume. ``\\?\C:\...`` is a long file path,
#: not a device, and is not matched.
_WIN32_DEVICE_PREFIXES = ("\\\\.\\", "//./")
_WIN32_DEVICE_NAMES = ("physicaldrive", "volume{", "globalroot")


def is_win32_device_path(path: Path | str) -> bool:
    """Whether ``path`` names a Win32 raw device rather than a file.

    ``open()`` cannot address the device namespace, so such a path is routed to
    the ``CreateFileW`` reader in :mod:`core.carve.win_source` rather than to
    :class:`FileSourceReader`.
    """
    text = os.fspath(path)
    if text.startswith(_WIN32_DEVICE_PREFIXES):
        return True
    if text.startswith(("\\\\?\\", "//?/")):
        rest = text[4:].lower()
        return rest.startswith(_WIN32_DEVICE_NAMES) or (
            len(rest) == 2 and rest[1] == ":"
        )
    return False


class FileSourceReader:
    """A file or block device opened read-only."""

    def __init__(
        self, path: Path | str, *, sector_size: int = DEFAULT_SECTOR_BYTES
    ) -> None:
        if is_win32_device_path(path):
            raise EvidenceIntegrityError(
                f"{os.fspath(path)} is in the Win32 device namespace; plain file "
                "I/O cannot open it",
                remediation=(
                    "Acquire it through core.carve.acquire.acquire(), which opens "
                    "Win32 devices with the read-only CreateFileW reader. Nothing "
                    "was opened."
                ),
            )
        self.path = Path(path)
        if not self.path.exists():
            raise EvidenceIntegrityError(
                f"acquisition source not found: {self.path}",
                remediation="Check the path. Nothing was created.",
            )
        self._fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        self.sector_size = sector_size
        self.size = self._probe_size()

    def _probe_size(self) -> int:
        stat = os.fstat(self._fd)
        if stat.st_size:
            return int(stat.st_size)
        # A Linux block device reports st_size 0; seek to the end instead.
        end = os.lseek(self._fd, 0, os.SEEK_END)
        os.lseek(self._fd, 0, os.SEEK_SET)
        return int(end)

    def read_at(self, offset: int, length: int) -> bytes:
        pread = getattr(os, "pread", None)
        if pread is not None:
            return bytes(pread(self._fd, length, offset))
        os.lseek(self._fd, offset, os.SEEK_SET)
        return os.read(self._fd, length)

    def close(self) -> None:
        try:
            os.close(self._fd)
        except OSError:
            pass


# --------------------------------------------------------------------------
# Options
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AcquireOptions:
    """Knobs for one acquisition. Defaults are the demo-safe settings."""

    block_bytes: int = MIB
    #: Per-chunk hash granularity. Smaller localises a later failure more
    #: tightly, at the cost of a longer hash list in the record.
    chunk_bytes: int = 4 * MIB
    sector_size: int = DEFAULT_SECTOR_BYTES
    fill_byte: int = 0x00
    #: Retries of a failing block before dropping to sector granularity.
    retries: int = 2
    #: Bad sectors after which the operator is warned. The run continues:
    #: only the operator decides to stop.
    error_ceiling: int = 10_000
    checkpoint_bytes: int = 256 * MIB
    #: Split the raw destination into segments of this size. ``None`` is one file.
    segment_bytes: int | None = None
    compression: Literal["none", "fast", "best"] = "fast"
    operator: str = "sanctum"
    case_number: str = ""
    evidence_number: str = ""
    examiner: str = ""
    description: str = ""
    notes: str = ""
    #: The identity the operator selected, for a raw device on Windows or
    #: macOS. The reader binds its handle to it and refuses a different disk.
    expected_serial: str = ""
    expected_size: int = 0

    def __post_init__(self) -> None:
        if self.block_bytes % self.sector_size:
            raise ValueError(
                f"block_bytes {self.block_bytes} is not a multiple of sector_size "
                f"{self.sector_size}; sector-granularity salvage would misalign."
            )


DEFAULT_OPTIONS = AcquireOptions()


# --------------------------------------------------------------------------
# Write blocking
# --------------------------------------------------------------------------


@dataclass
class WriteBlockOutcome:
    applied: bool
    limitations: list[str] = field(default_factory=list)
    #: ``flag_read_back``, ``attempted_write``, or ``""`` when no block is in
    #: force. See :class:`core.models.AcquisitionRecord.write_block_verified_by`.
    verified_by: str = ""


def apply_write_block(path: Path | str) -> WriteBlockOutcome:
    """Set the block device read-only, then read the flag back to confirm.

    The read-back is the point. ``BLKROSET`` can be issued against something
    that is not a block device, or by a caller without the privilege to make it
    stick, and in both cases the operator would otherwise believe a protection
    that does not exist.

    **The read-back is also not proof that a write would be refused, and this
    function deliberately does not go looking for that proof.** The only way to
    establish it is to attempt a write, and the evidence path never writes to a
    device (CLAUDE.md). The asymmetry is the reason: a write test is safe only
    when the block works, and it is precisely when the block does *not* work
    that the test writes to evidence. A parachute is not tested by jumping.

    So the outcome says how strongly it was established. ``verified_by`` is
    ``flag_read_back`` here, always, and :data:`WRITE_BLOCK_NOT_VERIFIED` says
    so on the record. Verification by attempted write belongs to
    ``scripts/probe-write-block.py``, run once against scratch media to qualify
    an interface, which is how write blockers are qualified in practice.

    Measured on a Toshiba TransMemory behind a USB bridge, 2026-09-05: the flag
    was honoured, and the refusal arrived at ``write()`` with ``EPERM`` while
    ``open(O_WRONLY)`` succeeded. Anything checking only whether the open
    succeeds would have reported a working block on a cosmetic flag.
    """
    if sys.platform != "linux":
        return WriteBlockOutcome(
            applied=False,
            limitations=[NO_SOFTWARE_WRITE_BLOCK.format(platform=platform.system())],
            verified_by="",
        )

    import fcntl
    import struct

    target = Path(path)
    if not target.is_block_device():
        # A file-backed image needs no block-layer flag; opening it O_RDONLY is
        # the whole guarantee available, and claiming more would be false.
        return WriteBlockOutcome(applied=False, limitations=[], verified_by="")

    fd = os.open(target, os.O_RDONLY)
    try:
        fcntl.ioctl(fd, BLKROSET, struct.pack("i", 1))
        raw = fcntl.ioctl(fd, BLKROGET, struct.pack("i", 0))
        (read_only,) = struct.unpack("i", raw)
    except OSError as exc:
        return WriteBlockOutcome(
            applied=False,
            limitations=[
                f"{WRITE_BLOCK_REFUSED} "
                f"({errno.errorcode.get(exc.errno or 0, exc.errno)})"
            ],
            verified_by="",
        )
    finally:
        os.close(fd)

    if not read_only:
        return WriteBlockOutcome(
            applied=False, limitations=[WRITE_BLOCK_REFUSED], verified_by=""
        )
    return WriteBlockOutcome(
        applied=True,
        limitations=[WRITE_BLOCK_NOT_VERIFIED],
        verified_by="flag_read_back",
    )


# --------------------------------------------------------------------------
# EWF capability
# --------------------------------------------------------------------------


#: Memoised result of :func:`_probe_e01_write`. The probe costs a few hundred
#: bytes of temporary I/O, and the answer cannot change inside one process.
_E01_WRITE_PROBE: bool | None = None


def e01_write_supported() -> bool:
    """True only when this libewf build can actually finalise an E01.

    **Probed by writing one**, never inferred from an attribute. An earlier
    version of this function tested ``hasattr(pyewf.handle, "set_media_size")``
    and was wrong in both directions: ``pyewf`` binds no write-configuration
    setters on *any* platform, including builds that write E01 perfectly well,
    so the attribute test reported "unsupported" on a working install. What
    actually decides the answer is whether libewf was compiled against real
    zlib, and that is not visible from Python at all.

    The probe writes a 512-byte container into a temporary directory and checks
    the segment file appeared. It never touches the caller's destination.
    """
    global _E01_WRITE_PROBE
    if _E01_WRITE_PROBE is None:
        _E01_WRITE_PROBE = _probe_e01_write() or _probe_ctypes_e01_write()
    return _E01_WRITE_PROBE


#: Which backend writes E01 in this process: "pyewf", "libewf-ctypes" or "".
_E01_BACKEND: str | None = None


def _e01_backend() -> str:
    """The writer :class:`_EwfWriter` uses. pyewf first; the ctypes libewf second.

    AEGIS integration: the Windows libewf-python wheel cannot write E01 (no real
    zlib). :mod:`core.carve.ewf_ctypes` drives a write-capable libewf build
    instead, and the container it writes is still read back through pyewf.
    """
    global _E01_BACKEND
    if _E01_BACKEND is None:
        if _probe_e01_write():
            _E01_BACKEND = "pyewf"
        elif _probe_ctypes_e01_write():
            _E01_BACKEND = "libewf-ctypes"
        else:
            _E01_BACKEND = ""
    return _E01_BACKEND


def _probe_ctypes_e01_write() -> bool:
    from core.carve import ewf_ctypes

    return ewf_ctypes.probe_write()


def _probe_e01_write() -> bool:
    """Write a throwaway E01 and report whether libewf produced one."""
    try:
        import pyewf
    except ImportError:
        return False

    import tempfile

    with tempfile.TemporaryDirectory(prefix="sanctum-ewf-probe-") as directory:
        base = os.path.join(directory, "probe")
        handle = pyewf.handle()
        try:
            handle.open([base], "w")
            handle.write(b"\x00" * 512)
            handle.close()
        except (OSError, MemoryError, RuntimeError, ValueError) as exc:
            logger.debug("e01.write_probe_failed", error=str(exc))
            return False
        return os.path.exists(base + ".E01")


def _ewf_version() -> str:
    if _E01_BACKEND == "libewf-ctypes":
        from core.carve import ewf_ctypes

        return f"libewf {ewf_ctypes.library_version()} (ctypes writer)"
    try:
        import pyewf

        return str(pyewf.get_version())
    except ImportError:
        return "not installed"


# --------------------------------------------------------------------------
# Destination
# --------------------------------------------------------------------------


class _ImageWriter(Protocol):
    """What the read pass needs from a destination, raw or E01.

    The seam exists so :func:`_read_pass` contains exactly one loop. An image
    format that cannot seek or cannot resume says so by raising from the
    method, rather than by the read pass carrying a branch for every format.
    """

    def open(self, *, append: bool) -> None: ...

    def write(self, data: bytes) -> None: ...

    def seek(self, offset: int) -> None: ...

    def flush_durable(self) -> None: ...

    def close(self) -> None: ...

    @property
    def segments(self) -> list[Path]: ...


class _RawWriter:
    """Writes a raw image, optionally split into fixed-size segments."""

    def __init__(self, dest: Path, *, segment_bytes: int | None) -> None:
        self.dest = dest
        self._segment_bytes = segment_bytes
        self._segments: list[Path] = []
        self._handle: Any = None
        self._in_segment = 0
        self._index = 0

    def _next_path(self) -> Path:
        if self._segment_bytes is None:
            return self.dest
        self._index += 1
        return self.dest.with_name(f"{self.dest.name}.{self._index:03d}")

    def open(self, *, append: bool) -> None:
        path = self._next_path()
        self._handle = open(path, "r+b" if append and path.exists() else "wb")
        if append and path.exists():
            self._handle.seek(0, os.SEEK_END)
            self._in_segment = self._handle.tell()
        self._segments.append(path)

    def write(self, data: bytes) -> None:
        assert self._handle is not None
        if self._segment_bytes is not None and self._in_segment >= self._segment_bytes:
            self._handle.close()
            self.open(append=False)
            self._in_segment = 0
        self._handle.write(data)
        self._in_segment += len(data)

    def seek(self, offset: int) -> None:
        assert self._handle is not None
        self._handle.seek(offset)

    def flush_durable(self) -> None:
        if self._handle is not None:
            self._handle.flush()
            os.fsync(self._handle.fileno())

    def close(self) -> None:
        if self._handle is not None:
            self.flush_durable()
            self._handle.close()
            self._handle = None

    @property
    def segments(self) -> list[Path]:
        return list(self._segments)


class _EwfWriter:
    """Writes an E01 through ``pyewf``.

    Two things about libewf's write side are not obvious and are handled here
    rather than left to the caller:

    **The name is a base, not a filename.** libewf appends the segment
    extension itself, so opening ``case.E01`` for write produces
    ``case.E01.E01``. The extension is stripped before the open, which makes
    the file that appears on disk exactly the destination the caller named.

    **Nothing about the container is configurable from Python.** ``pyewf``
    binds ``set_header_codepage`` and no other setter, so the compression
    method and level, the segment size, the media type and the sectors per
    chunk are all libewf's defaults - and the default compression level is
    *none*, so the E01 comes out marginally larger than the source rather than
    smaller. The acquisition records :data:`E01_COMPRESSION_NOT_SELECTABLE`
    rather than let a caller believe ``AcquireOptions.compression`` reached the
    container.

    Writing is strictly sequential and cannot be resumed: libewf has no append
    mode for an existing segment set, and :func:`acquire` refuses the
    combination rather than silently starting over.
    """

    #: Extensions libewf appends for itself. One is stripped from the
    #: destination to recover the base name libewf actually wants.
    _SEGMENT_SUFFIXES = (".e01", ".ex01", ".s01", ".l01", ".lx01")

    def __init__(
        self,
        dest: Path,
        *,
        media_size: int = 0,
        sector_size: int = DEFAULT_SECTOR_BYTES,
        compression: str = "fast",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.dest = dest
        self._handle: Any = None
        self._media_size = media_size
        self._sector_size = sector_size
        self._compression = compression
        self._headers = headers or {}
        self._base = (
            dest.with_suffix("")
            if dest.suffix.lower() in self._SEGMENT_SUFFIXES
            else dest
        )

    def open(self, *, append: bool) -> None:
        if append:
            raise UnsupportedCapability(
                "an E01 acquisition cannot be resumed",
                remediation=(
                    "libewf has no append mode for an existing segment set. "
                    "Delete the partial container and acquire again, or "
                    "acquire to raw, which does resume."
                ),
            )
        if _e01_backend() == "libewf-ctypes":
            from core.carve.ewf_ctypes import CtypesEwfWriter

            self._handle = CtypesEwfWriter(
                self._base,
                media_size=self._media_size,
                bytes_per_sector=self._sector_size,
                compression=self._compression,
                headers=self._headers,
            )
            return
        import pyewf

        self._handle = pyewf.handle()
        self._handle.open([str(self._base)], "w")

    def write(self, data: bytes) -> None:
        assert self._handle is not None
        self._handle.write(data)

    def seek(self, offset: int) -> None:
        raise UnsupportedCapability(
            "an E01 is written sequentially and cannot be seeked",
            remediation="Acquire to raw if the destination must be seekable.",
        )

    def flush_durable(self) -> None:
        """No-op: ``pyewf`` exposes no flush. See E01_NO_DURABLE_CHECKPOINT."""

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    @property
    def segments(self) -> list[Path]:
        """The segment files libewf actually produced, in address order."""
        if self._handle is not None:
            return []
        import pyewf

        first = self._base.with_name(f"{self._base.name}.E01")
        if not first.exists():
            return []
        try:
            return [Path(name) for name in pyewf.glob(str(first))]
        except (OSError, MemoryError, RuntimeError, ValueError):
            # glob is only used to enumerate what was written; a failure here
            # must not cost the caller an acquisition that already succeeded.
            return [first]


# --------------------------------------------------------------------------
# Acquisition
# --------------------------------------------------------------------------


def _blake3_hasher() -> Any:
    import blake3

    return blake3.blake3()


def _open_source(
    source: SourceReader | Path | str, options: AcquireOptions
) -> tuple[SourceReader, Path | None, bool]:
    if isinstance(source, (str, Path)):
        text = os.fspath(source)
        if is_win32_device_path(text):
            return _open_win32_source(text, options), Path(text), True
        if _is_macos_disk(text):
            from core.carve.mac_source import open_macos_source

            reader: SourceReader = open_macos_source(
                text,
                expected_size=options.expected_size,
                sector_size=options.sector_size,
            )
            return reader, Path(text), True
        # The reader gets the caller's spelling: Path() on POSIX folds the
        # ``//./`` device prefix to ``//``, and the device check must see it.
        reader = FileSourceReader(source, sector_size=options.sector_size)
        return reader, Path(source), True
    return source, None, False


def _bound_identity(reader: SourceReader) -> dict[str, Any] | None:
    """The identity a device reader bound its handle to, for the ledger."""
    identity = getattr(reader, "identity", None)
    if identity is None:
        return None
    from dataclasses import asdict, is_dataclass

    if is_dataclass(identity) and not isinstance(identity, type):
        return asdict(identity)
    return None


def _is_macos_disk(text: str) -> bool:
    return sys.platform == "darwin" and text.startswith(("/dev/disk", "/dev/rdisk"))


def _open_win32_source(text: str, options: AcquireOptions) -> SourceReader:
    """The Windows raw-device reader, or a refusal naming why there is none."""
    from core.carve.win_source import open_windows_source
    from core.device.win.native import NativeError

    if sys.platform != "win32":
        raise EvidenceIntegrityError(
            f"{text} is a Win32 device path, and this host is "
            f"{platform.system()}, not Windows",
            remediation="Acquire the device on the Windows machine it is "
            "attached to. Nothing was opened.",
        )
    try:
        return open_windows_source(
            text,
            expected_serial=options.expected_serial,
            expected_size=options.expected_size,
            sector_size=options.sector_size,
        )
    except NativeError as exc:
        raise EvidenceIntegrityError(
            f"Windows refused to open {text} for reading (Win32 error "
            f"{exc.winerror})",
            remediation="Raw device acquisition needs Sanctum running as "
            "Administrator. Nothing was read.",
        ) from exc


def _salvage_block(
    reader: SourceReader,
    offset: int,
    length: int,
    options: AcquireOptions,
) -> tuple[bytes, list[BadSectorRange], list[SubstitutedRange]]:
    """Re-read a failed block sector by sector, salvaging everything readable.

    This is the difference between losing three sectors and losing a megabyte.
    """
    sector = options.sector_size
    out = bytearray()
    bad_lbas: list[int] = []
    last_errno = errno.EIO
    for position in range(offset, offset + length, sector):
        take = min(sector, offset + length - position)
        recovered: bytes | None = None
        for _ in range(max(options.retries, 1)):
            try:
                recovered = reader.read_at(position, take)
                break
            except OSError as exc:
                last_errno = exc.errno or errno.EIO
        if recovered is None:
            out += bytes([options.fill_byte]) * take
            bad_lbas.append(position // sector)
        else:
            out += recovered.ljust(take, bytes([options.fill_byte]))

    ranges: list[BadSectorRange] = []
    substituted: list[SubstitutedRange] = []
    for lba in bad_lbas:
        if ranges and lba == ranges[-1].last_lba + 1:
            previous = ranges[-1]
            ranges[-1] = previous.model_copy(update={"last_lba": lba})
            span = substituted[-1]
            substituted[-1] = span.model_copy(
                update={"length": span.length + sector}
            )
            continue
        ranges.append(
            BadSectorRange(
                first_lba=lba,
                last_lba=lba,
                sector_size=sector,
                errno=last_errno,
                attempts=max(options.retries, 1),
            )
        )
        substituted.append(
            SubstitutedRange(
                offset=lba * sector,
                length=sector,
                fill_byte=options.fill_byte,
                reason=(
                    f"sector {lba} returned "
                    f"{errno.errorcode.get(last_errno, last_errno)} after "
                    f"{max(options.retries, 1)} attempts"
                ),
            )
        )
    return bytes(out), ranges, substituted


def _merge_adjacent(ranges: list[BadSectorRange]) -> list[BadSectorRange]:
    """Join runs that met across a block boundary into one reported range."""
    merged: list[BadSectorRange] = []
    for item in ranges:
        if merged and item.first_lba == merged[-1].last_lba + 1:
            merged[-1] = merged[-1].model_copy(update={"last_lba": item.last_lba})
            continue
        merged.append(item)
    return merged


def _merge_substituted(spans: list[SubstitutedRange]) -> list[SubstitutedRange]:
    merged: list[SubstitutedRange] = []
    for span in spans:
        if merged and span.offset == merged[-1].offset + merged[-1].length:
            merged[-1] = merged[-1].model_copy(
                update={"length": merged[-1].length + span.length}
            )
            continue
        merged.append(span)
    return merged


def acquire(
    source: SourceReader | Path | str,
    dest: Path | str,
    *,
    fmt: Literal["raw", "e01"] = "raw",
    options: AcquireOptions = DEFAULT_OPTIONS,
    ledger: Ledger | None = None,
    job_id: str = "acquire",
    resume: bool = False,
) -> Generator[Progress, None, AcquisitionRecord]:
    """Image ``source`` to ``dest``, yielding progress, returning the record.

    Both hashes are computed during the single read pass. Bad sectors are
    salvaged at sector granularity, filled, and recorded; they never abort the
    run. The returned :class:`AcquisitionRecord` is the chain of custody and is
    ledgered in full when a ledger is supplied.
    """
    destination = Path(dest)

    if fmt == "e01" and not e01_write_supported():
        raise UnsupportedCapability(
            E01_WRITE_UNSUPPORTED.format(version=_ewf_version()),
            remediation=(
                "Acquire to raw here and convert with ewfacquire on a host with "
                "full libewf, or run the acquisition on Linux. Reading existing "
                "E01 evidence works on this build."
            ),
        )

    if fmt == "e01" and resume:
        # Refused before anything is opened. libewf cannot append to an
        # existing segment set, so the only thing "resume" could mean here is
        # a silent re-image from zero - which looks like a resume in the log,
        # takes as long as the original run, and would let an operator believe
        # the first run's bytes were reused.
        raise UnsupportedCapability(
            "an E01 acquisition cannot be resumed",
            remediation=(
                "libewf has no append mode for an existing segment set. "
                "Delete the partial container and acquire again, or acquire "
                "to raw, which does resume from a chunk boundary."
            ),
        )

    reader, source_path, owns_reader = _open_source(source, options)
    started_at = datetime.now(UTC)
    limitations: list[str] = []

    try:
        block = apply_write_block(source_path) if source_path else WriteBlockOutcome(
            applied=False, limitations=[]
        )
        limitations.extend(block.limitations)
        if source_path is None and sys.platform != "linux":
            limitations.append(
                NO_SOFTWARE_WRITE_BLOCK.format(platform=platform.system())
            )

        if ledger is not None:
            ledger.append(
                actor=options.operator,
                operation="acquire.start",
                params={
                    "job_id": job_id,
                    "source": str(source_path) if source_path else "<reader>",
                    "source_identity": _bound_identity(reader),
                    "dest": str(destination),
                    "fmt": fmt,
                    "size_bytes": reader.size,
                    "sector_size": options.sector_size,
                    "write_blocked": block.applied,
                    "resumed": resume,
                    "tool_version": TOOL_VERSION,
                    "boot_id": boot_id(),
                },
                result={},
            )

        yield Progress(
            job_id=job_id,
            phase=AcquisitionPhase.PREFLIGHT,
            pct_bp=0,
            bytes_done=0,
            bytes_total=reader.size,
            throughput_bytes_per_sec=0,
            eta_seconds=0,
            message=f"imaging {reader.size} bytes to {destination.name}",
        )

        watermark: dict[str, int] = {"bytes_done": 0, "bytes_total": reader.size}
        try:
            record = yield from _read_pass(
                reader,
                destination,
                fmt=fmt,
                options=options,
                job_id=job_id,
                resume=resume,
                started_at=started_at,
                source_path=source_path,
                write_blocked=block.applied,
                write_block_verified_by=block.verified_by,
                limitations=limitations,
                ledger=ledger,
                watermark=watermark,
            )
        except GeneratorExit:
            # The caller closed this generator: an operator pressed Cancel, or
            # the client that asked for the image went away. The read stopped at
            # a yield, so nothing is half-written - but there is now a file on
            # disk that looks like an image and is not one.
            #
            # It goes in the chain before the exception continues, for the same
            # reason a cancelled erase does (core/erase/drive.py): an examiner
            # who finds this file later must be able to tell from the chain that
            # it is a fragment. Without an entry it is indistinguishable from a
            # crash, and a truncated image that nobody knows is truncated is a
            # worse artifact than no image at all.
            #
            # No progress is yielded here and none can be: a generator that
            # yields while closing raises RuntimeError. The ledger is the only
            # channel out, which is the right one anyway.
            _record_cancelled_acquisition(
                ledger,
                job_id=job_id,
                destination=destination,
                fmt=fmt,
                source_path=source_path,
                operator=options.operator,
                watermark=watermark,
            )
            raise
    finally:
        if owns_reader:
            reader.close()

    if ledger is not None:
        ledger.append(
            actor=options.operator,
            operation="acquire.complete",
            params=record.model_dump(mode="json"),
            result={"sha256": record.sha256, "blake3": record.blake3},
        )

    return record


def _record_cancelled_acquisition(
    ledger: Ledger | None,
    *,
    job_id: str,
    destination: Path,
    fmt: str,
    source_path: Path | None,
    operator: str,
    watermark: dict[str, int],
) -> None:
    """Append the entry that says what the file on disk actually is.

    Everything an examiner needs to classify the artifact without opening it:
    that it is a **partial image**, how many bytes of the source reached it, how
    many the source has, and - the part that matters most - that no digest for
    it is on record, because the hashes an acquisition publishes are computed
    over the whole source as it is read and there is no whole source here.

    A truncated ``.dd`` looks exactly like a complete ``.dd``. That is why this
    is written even though nothing was destroyed.
    """
    if ledger is None:
        return
    done = int(watermark.get("bytes_done", 0))
    total = int(watermark.get("bytes_total", 0))
    try:
        on_disk = destination.stat().st_size if destination.exists() else 0
    except OSError:  # pragma: no cover - the stat of a file we just wrote
        on_disk = 0
    try:
        ledger.append(
            actor=operator,
            operation="acquire.cancelled",
            params={
                "job_id": job_id,
                "source": str(source_path) if source_path else "<reader>",
                "destination": str(destination),
                "fmt": fmt,
                "bytes_acquired": done,
                "bytes_expected": total,
                "container_bytes_on_disk": on_disk,
                "note": (
                    "Acquisition cancelled before completion. The file at this "
                    "destination is a PARTIAL IMAGE: it holds the first "
                    f"{done} of {total} source bytes and is NOT a complete copy "
                    "of the source. No sha256 or blake3 is recorded for it - "
                    "the digests an acquisition publishes cover the whole "
                    "source as it was read, and this read did not finish, so "
                    "any hash of this file attests to the fragment only. Do not "
                    "carve it and report the results as coverage of the source. "
                    "Re-acquire, or resume from the last acquire.checkpoint "
                    "entry for this job."
                ),
            },
            result={},
        )
    except (OSError, ValueError, RuntimeError) as exc:  # pragma: no cover
        # Losing the cancellation record is bad; failing to unwind the
        # generator on top of it is worse, and would leave the caller with an
        # exception from a teardown path instead of the cancellation it asked
        # for.
        logger.warning(
            "acquire_cancel_record_failed", job_id=job_id, error=str(exc)
        )


def _read_pass(
    reader: SourceReader,
    destination: Path,
    *,
    fmt: Literal["raw", "e01"],
    options: AcquireOptions,
    job_id: str,
    resume: bool,
    started_at: datetime,
    source_path: Path | None,
    write_blocked: bool,
    write_block_verified_by: str,
    limitations: list[str],
    ledger: Ledger | None,
    watermark: dict[str, int] | None = None,
) -> Generator[Progress, None, AcquisitionRecord]:
    """The single pass that reads, hashes, salvages and writes.

    ``watermark`` is updated in place with how far the read has got, before
    every yield. It exists for one caller and one case: :func:`acquire` closing
    this generator, where the return value never arrives and the only way to say
    how much of the source made it into the image is to have been told as it
    went.
    """
    sha = hashlib.sha256()
    blake = _blake3_hasher()
    chunk_sha = hashlib.sha256()
    chunk_hashes: list[str] = []
    chunk_filled = 0

    bad_sectors: list[BadSectorRange] = []
    substituted: list[SubstitutedRange] = []

    writer: _ImageWriter = (
        _EwfWriter(
            destination,
            media_size=reader.size,
            sector_size=options.sector_size,
            compression=options.compression,
            headers={
                "case_number": options.case_number,
                "evidence_number": options.evidence_number,
                "examiner_name": options.examiner,
                "description": options.description,
                "notes": options.notes,
            },
        )
        if fmt == "e01"
        else _RawWriter(destination, segment_bytes=options.segment_bytes)
    )
    if fmt == "e01":
        if _e01_backend() == "libewf-ctypes":
            limitations.append(
                "E01_WRITER: written by "
                + _ewf_version()
                + f" with compression '{options.compression}', EnCase 6 format; "
                "read back and verified through pyewf, an independent libewf build."
            )
        else:
            limitations.append(
                E01_COMPRESSION_NOT_SELECTABLE.format(
                    version=_ewf_version(), requested=options.compression
                )
            )
        limitations.append(E01_NO_DURABLE_CHECKPOINT)

    start_offset = 0
    prior_bytes = destination.stat().st_size if destination.exists() else 0
    # An E01 is never resumed: libewf cannot append to an existing segment
    # set, so re-reading the source from zero is the only correct behaviour.
    if fmt == "e01":
        prior_bytes = 0
    if resume and prior_bytes:
        # Align down to a chunk boundary: the chunk hash list is built in
        # order, so restarting mid-chunk would produce a hash over a partial
        # chunk and every later index would refer to the wrong bytes. Up to
        # one chunk of completed work is re-read, which is cheap next to
        # getting the list wrong.
        complete_chunks = prior_bytes // options.chunk_bytes
        start_offset = complete_chunks * options.chunk_bytes
        for index in range(complete_chunks):
            piece = _read_file_range(
                destination, index * options.chunk_bytes, options.chunk_bytes
            )
            sha.update(piece)
            blake.update(piece)
            chunk_hashes.append(hashlib.sha256(piece).hexdigest())
    writer.open(append=resume and start_offset > 0)
    if start_offset:
        writer.seek(start_offset)

    offset = start_offset
    next_checkpoint = offset + options.checkpoint_bytes
    monotonic_start = _monotonic_ns()
    warned_ceiling = False

    try:
        while offset < reader.size:
            length = min(options.block_bytes, reader.size - offset)
            try:
                data = reader.read_at(offset, length)
            except OSError:
                data, ranges, spans = _salvage_block(reader, offset, length, options)
                bad_sectors.extend(ranges)
                substituted.extend(spans)
                if len(bad_sectors) > options.error_ceiling and not warned_ceiling:
                    warned_ceiling = True
                    limitations.append(
                        f"ERROR_CEILING_EXCEEDED: more than "
                        f"{options.error_ceiling} bad sector ranges. The run "
                        "continues; cancel it if the media is failing faster "
                        "than it is being read."
                    )
            if len(data) < length:
                data = data.ljust(length, bytes([options.fill_byte]))

            writer.write(data)
            sha.update(data)
            blake.update(data)

            consumed = 0
            while consumed < len(data):
                take = min(options.chunk_bytes - chunk_filled, len(data) - consumed)
                chunk_sha.update(data[consumed : consumed + take])
                chunk_filled += take
                consumed += take
                if chunk_filled == options.chunk_bytes:
                    chunk_hashes.append(chunk_sha.hexdigest())
                    chunk_sha = hashlib.sha256()
                    chunk_filled = 0

            offset += length

            if offset >= next_checkpoint:
                writer.flush_durable()
                next_checkpoint = offset + options.checkpoint_bytes
                if ledger is not None:
                    ledger.append(
                        actor=options.operator,
                        operation="acquire.checkpoint",
                        params={"job_id": job_id, "offset": offset},
                        result={},
                    )

            elapsed_ns = max(_monotonic_ns() - monotonic_start, 1)
            done = offset - start_offset
            rate = int(done * 1_000_000_000 // elapsed_ns)
            if watermark is not None:
                # Before the yield, not after: the yield is where this
                # generator can be closed, and a watermark updated afterwards
                # would be one record behind at exactly the moment it is read.
                watermark["bytes_done"] = offset
                watermark["bytes_total"] = reader.size
            yield Progress(
                job_id=job_id,
                phase=AcquisitionPhase.READ,
                pct_bp=10_000 * offset // reader.size if reader.size else 10_000,
                bytes_done=offset,
                bytes_total=reader.size,
                throughput_bytes_per_sec=rate,
                eta_seconds=(reader.size - offset) // rate if rate else 0,
                message=(
                    f"read {offset}/{reader.size}"
                    + (f", {len(bad_sectors)} bad range(s)" if bad_sectors else "")
                ),
            )
    finally:
        writer.close()

    if chunk_filled:
        chunk_hashes.append(chunk_sha.hexdigest())

    merged_bad = _merge_adjacent(bad_sectors)
    merged_spans = _merge_substituted(substituted)
    if merged_bad:
        total = sum(item.sector_count for item in merged_bad)
        limitations.append(
            f"BAD_SECTORS: {total} sector(s) in {len(merged_bad)} range(s) could "
            f"not be read and were filled with 0x{options.fill_byte:02x}. Those "
            "offsets contain tool-generated bytes, not media contents."
        )

    finished_at = datetime.now(UTC)
    return AcquisitionRecord(
        job_id=job_id,
        source=EvidenceSource(
            path=str(source_path) if source_path else "<reader>",
            fmt="raw",
            size_bytes=reader.size,
            sector_size=options.sector_size,
            sha256=sha.hexdigest(),
            blake3=blake.hexdigest(),
            segments=[str(p) for p in writer.segments],
            substituted_ranges=merged_spans,
            limitations=list(limitations),
        ),
        dest_path=str(destination),
        fmt=fmt,
        started_at=started_at,
        finished_at=finished_at,
        operator=options.operator,
        tool_version=TOOL_VERSION,
        boot_id=boot_id(),
        monotonic_ns=_monotonic_ns() - monotonic_start,
        bytes_read=reader.size,
        sha256=sha.hexdigest(),
        blake3=blake.hexdigest(),
        chunk_bytes=options.chunk_bytes,
        chunk_hashes=chunk_hashes,
        bad_sectors=merged_bad,
        limitations=list(limitations),
        # True whenever this run continued an existing destination, even if the
        # chunk-boundary alignment meant no completed bytes were reusable. The
        # provenance fact a reader needs is that the image was produced across
        # more than one run, not how much of it the second run skipped.
        resumed=resume and prior_bytes > 0,
        write_blocked=write_blocked,
        write_block_verified_by=write_block_verified_by,
    )


def _monotonic_ns() -> int:
    import time

    return time.monotonic_ns()


def _read_file_range(path: Path, offset: int, length: int) -> bytes:
    with open(path, "rb") as handle:
        handle.seek(offset)
        return handle.read(length)


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------


def verify_image(
    path: Path | str,
    record: AcquisitionRecord,
    progress: Callable[[int, int], None] | None = None,
) -> IntegrityResult:
    """Re-read the image and compare both hashes to the acquisition record.

    On a mismatch the per-chunk list localises the damage. "This image no
    longer matches its record" is a fact an operator can act on; "chunk 2 of
    64 differs" is one they can act on quickly.

    AEGIS integration: ``progress(bytes_verified, bytes_total)`` is called after
    each chunk, so a desktop can show a long read-back; it does not change what
    is read, hashed or compared. It may raise to abandon the verification.
    """
    sha = hashlib.sha256()
    blake = _blake3_hasher()
    mismatched: list[int] = []
    verified = 0

    with open_evidence(path) as handle:
        for index in range(len(record.chunk_hashes)):
            offset = index * record.chunk_bytes
            piece = handle.read(offset, record.chunk_bytes)
            if not piece:
                break
            sha.update(piece)
            blake.update(piece)
            verified += len(piece)
            if hashlib.sha256(piece).hexdigest() != record.chunk_hashes[index]:
                mismatched.append(index)
            if progress is not None:
                progress(verified, record.bytes_read)

    actual_sha = sha.hexdigest()
    actual_blake = blake.hexdigest()
    sha_ok = actual_sha == record.sha256
    blake_ok = actual_blake == record.blake3
    return IntegrityResult(
        passed=sha_ok and blake_ok and not mismatched,
        sha256_matches=sha_ok,
        blake3_matches=blake_ok,
        expected_sha256=record.sha256,
        actual_sha256=actual_sha,
        expected_blake3=record.blake3,
        actual_blake3=actual_blake,
        mismatched_chunks=mismatched,
        bytes_verified=verified,
    )


def iter_progress(
    generator: Generator[Progress, None, AcquisitionRecord],
) -> Iterator[Progress]:
    """Yield progress and discard the record, for callers that only display."""
    yield from generator
