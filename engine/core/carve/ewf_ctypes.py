"""E01 writing through a write-capable libewf shared library, via ctypes.

AEGIS integration module (added for the AEGIS desktop bridge, 2026-10-03).
Part of the AEGIS Variant engine; same license and notices as the rest of
this tree (see LICENSE and docs/INTEGRATION_PROVENANCE.md in the AEGIS bundle).

Why this exists
---------------
The ``libewf-python`` wheel that installs on Windows reads E01 and cannot write
one: it is built against libewf's local deflate, which only inflates, so
``pyewf.handle().open(..., "w")`` fails at close with "missing support for
deflate compression". :func:`core.carve.acquire.e01_write_supported` probes for
exactly that and refuses E01 acquisition when it fails.

Autopsy ships a libewf build linked against real zlib (it is what its own
``ewfexport`` tool writes E01 with). This module drives that library's public C
API directly, so an acquisition can produce a genuine, compressed EWF-E01
container on a Windows host where the Python binding cannot.

It is **only** a writer. Reading, verification and every hash comparison still
go through ``pyewf`` (:class:`core.carve.evidence.EwfEvidence`), an independent
build of libewf, so a container this module writes is read back by different
code from the code that wrote it.

The library is located from ``AEGIS_LIBEWF_DIR`` (set by the AEGIS desktop
bridge) and nothing else: no search of PATH, no guess at an install directory.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
from pathlib import Path
from typing import Any

import structlog

__all__ = [
    "LIBEWF_DIR_ENV",
    "CtypesEwfWriter",
    "available",
    "library_version",
    "probe_write",
]

logger = structlog.get_logger(__name__)

#: Directory holding libewf.dll and its zlib.dll.
LIBEWF_DIR_ENV = "AEGIS_LIBEWF_DIR"

_ACCESS_WRITE = 0x02
_FORMAT_ENCASE6 = 0x06
#: libewf compression levels: 0 none, 1 fast, 2 best.
_COMPRESSION = {"none": 0, "fast": 1, "best": 2}

_LIB: Any = None
_LIB_ERROR = ""


def _load() -> Any:
    global _LIB, _LIB_ERROR
    if _LIB is not None or _LIB_ERROR:
        return _LIB
    directory = os.environ.get(LIBEWF_DIR_ENV, "").strip()
    if not directory:
        _LIB_ERROR = f"{LIBEWF_DIR_ENV} is not set"
        return None
    dll = Path(directory) / "libewf.dll"
    if not dll.is_file():
        _LIB_ERROR = f"{dll} does not exist"
        return None
    try:
        if hasattr(os, "add_dll_directory"):
            os.add_dll_directory(str(dll.parent))
        lib = ctypes.CDLL(str(dll))
    except OSError as exc:
        _LIB_ERROR = f"{dll} could not be loaded: {exc}"
        return None
    vp = ctypes.c_void_p
    lib.libewf_get_version.restype = ctypes.c_char_p
    lib.libewf_handle_initialize.argtypes = [ctypes.POINTER(vp), ctypes.POINTER(vp)]
    lib.libewf_handle_open.argtypes = [
        vp, ctypes.POINTER(ctypes.c_char_p), ctypes.c_int, ctypes.c_int,
        ctypes.POINTER(vp),
    ]
    lib.libewf_handle_set_media_size.argtypes = [vp, ctypes.c_uint64, ctypes.POINTER(vp)]
    lib.libewf_handle_set_bytes_per_sector.argtypes = [
        vp, ctypes.c_uint32, ctypes.POINTER(vp)
    ]
    lib.libewf_handle_set_format.argtypes = [vp, ctypes.c_uint8, ctypes.POINTER(vp)]
    lib.libewf_handle_set_compression_values.argtypes = [
        vp, ctypes.c_int8, ctypes.c_uint8, ctypes.POINTER(vp)
    ]
    lib.libewf_handle_set_utf8_header_value.argtypes = [
        vp, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
        ctypes.POINTER(vp),
    ]
    lib.libewf_handle_set_utf8_hash_value.argtypes = [
        vp, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
        ctypes.POINTER(vp),
    ]
    lib.libewf_handle_write_buffer.restype = ctypes.c_ssize_t
    lib.libewf_handle_write_buffer.argtypes = [
        vp, ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(vp)
    ]
    lib.libewf_handle_write_finalize.restype = ctypes.c_ssize_t
    lib.libewf_handle_write_finalize.argtypes = [vp, ctypes.POINTER(vp)]
    lib.libewf_handle_close.argtypes = [vp, ctypes.POINTER(vp)]
    lib.libewf_handle_free.argtypes = [ctypes.POINTER(vp), ctypes.POINTER(vp)]
    lib.libewf_error_sprint.argtypes = [vp, ctypes.c_char_p, ctypes.c_size_t]
    lib.libewf_error_free.argtypes = [ctypes.POINTER(vp)]
    _LIB = lib
    return lib


def available() -> bool:
    """Whether the writer library loaded. Not whether it writes: see probe_write."""
    return _load() is not None


def unavailable_reason() -> str:
    _load()
    return _LIB_ERROR


def library_version() -> str:
    lib = _load()
    if lib is None:
        return ""
    return str(lib.libewf_get_version().decode("ascii", "replace"))


class EwfWriteError(OSError):
    """libewf refused a write-side call. The message is libewf's own."""


class CtypesEwfWriter:
    """Sequential E01 writer. Mirrors the ``pyewf.handle`` calls _EwfWriter makes.

    The media size must be known before the first write: EWF records it in the
    volume section, and a container whose declared size disagrees with the bytes
    written does not finalize.
    """

    def __init__(
        self,
        base: Path,
        *,
        media_size: int,
        bytes_per_sector: int = 512,
        compression: str = "fast",
        headers: dict[str, str] | None = None,
    ) -> None:
        lib = _load()
        if lib is None:
            raise EwfWriteError(f"libewf writer unavailable: {_LIB_ERROR}")
        self._lib = lib
        self._handle = ctypes.c_void_p()
        self._md5 = hashlib.md5()  # noqa: S324 - EWF's own integrity field, not security
        self._sha1 = hashlib.sha1()  # noqa: S324 - EWF's own integrity field
        self._written = 0
        self._media_size = int(media_size)
        self._check(lib.libewf_handle_initialize(ctypes.byref(self._handle), self._err()))
        names = (ctypes.c_char_p * 1)(os.fsencode(str(base)))
        self._check(lib.libewf_handle_open(self._handle, names, 1, _ACCESS_WRITE, self._err()))
        self._check(lib.libewf_handle_set_format(self._handle, _FORMAT_ENCASE6, self._err()))
        self._check(
            lib.libewf_handle_set_bytes_per_sector(
                self._handle, int(bytes_per_sector), self._err()
            )
        )
        self._check(
            lib.libewf_handle_set_media_size(self._handle, self._media_size, self._err())
        )
        level = _COMPRESSION.get(compression, 1)
        self._check(
            lib.libewf_handle_set_compression_values(self._handle, level, 0, self._err())
        )
        for key, value in (headers or {}).items():
            if not value:
                continue
            k = key.encode("utf-8")
            v = str(value).encode("utf-8")
            self._check(
                lib.libewf_handle_set_utf8_header_value(
                    self._handle, k, len(k), v, len(v), self._err()
                )
            )

    # -- error plumbing --------------------------------------------------

    def _err(self) -> Any:
        self._last_error = ctypes.c_void_p()
        return ctypes.byref(self._last_error)

    def _message(self) -> str:
        if not getattr(self, "_last_error", None) or not self._last_error.value:
            return "libewf reported an error without a message"
        buffer = ctypes.create_string_buffer(4096)
        self._lib.libewf_error_sprint(self._last_error, buffer, len(buffer))
        self._lib.libewf_error_free(ctypes.byref(self._last_error))
        return buffer.value.decode("utf-8", "replace").strip()

    def _check(self, code: int) -> None:
        if code != 1:
            raise EwfWriteError(self._message())

    # -- the pyewf-shaped surface -----------------------------------------

    def write(self, data: bytes) -> None:
        view = bytes(data)
        offset = 0
        while offset < len(view):
            piece = view[offset : offset + (8 << 20)]
            wrote = self._lib.libewf_handle_write_buffer(
                self._handle, piece, len(piece), self._err()
            )
            if wrote != len(piece):
                raise EwfWriteError(self._message())
            self._md5.update(piece)
            self._sha1.update(piece)
            offset += wrote
        self._written += len(view)

    def close(self) -> None:
        if not self._handle:
            return
        try:
            if self._written == self._media_size:
                # EWF stores MD5 (and SHA-1 in the EnCase 6 hash section). They
                # are the container's own integrity fields; the acquisition's
                # SHA-256 and BLAKE3 are computed independently over the source.
                for name, digest in (
                    (b"MD5", self._md5.hexdigest()),
                    (b"SHA1", self._sha1.hexdigest()),
                ):
                    value = digest.encode("ascii")
                    self._check(
                        self._lib.libewf_handle_set_utf8_hash_value(
                            self._handle, name, len(name), value, len(value), self._err()
                        )
                    )
            if self._lib.libewf_handle_write_finalize(self._handle, self._err()) < 0:
                raise EwfWriteError(self._message())
            self._lib.libewf_handle_close(self._handle, self._err())
        finally:
            self._lib.libewf_handle_free(ctypes.byref(self._handle), self._err())
            self._handle = ctypes.c_void_p()

    @property
    def md5(self) -> str:
        return self._md5.hexdigest()


def probe_write() -> bool:
    """Write a 64 KiB container to a temporary directory, read it back with pyewf."""
    if not available():
        return False
    import tempfile

    payload = bytes(range(256)) * 256
    with tempfile.TemporaryDirectory(prefix="aegis-ewf-probe-") as directory:
        base = Path(directory) / "probe"
        try:
            writer = CtypesEwfWriter(base, media_size=len(payload))
            writer.write(payload)
            writer.close()
            import pyewf

            handle = pyewf.handle()
            handle.open(pyewf.glob(str(base) + ".E01"))
            try:
                ok = handle.read(len(payload)) == payload
            finally:
                handle.close()
            return ok
        except (OSError, ImportError, RuntimeError, ValueError) as exc:
            logger.debug("e01.ctypes_probe_failed", error=str(exc))
            return False
