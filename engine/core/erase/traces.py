"""Traces the desktop keeps of an erased file: found, reported, and removed.

Overwriting a file's extents does not reach what the desktop made of the file.
A file manager keeps a thumbnail named by the MD5 of the file's URI. The
recent-files list keeps its path. An earlier delete may have left a whole copy
in the Trash or the Recycle Bin, with a record of where it came from. Each of
those is a trace of exactly the file the operator asked to destroy, and
overwriting the file touches none of them.

This module runs after the erase. It finds those traces and, on a real run,
removes the ones it can tie to an erased path **on evidence**:

* a thumbnail whose name is the MD5 of the erased file's URI, or whose
  ``Thumb::URI`` names a file inside an erased folder (the freedesktop
  thumbnail specification);
* an entry in GTK's ``recently-used.xbel`` whose ``href`` decodes to the path,
  and a KDE ``RecentDocuments`` link whose ``URL`` does;
* a Trash item whose ``.trashinfo`` names the path, or names a folder that held
  it (the freedesktop Trash specification), in the home Trash and in the
  ``.Trash-$uid`` or sticky ``.Trash/$uid`` directory of the file's volume;
* a Recycle Bin ``$R`` item whose ``$I`` record names the path;
* a Windows Recent shortcut whose LinkInfo names the path ([MS-SHLLINK] 2.3);
* a Windows jump list (``*.automaticDestinations-ms``) every one of whose
  shortcut streams names an erased path;
* a macOS Trash item whose put-back record (``ptbL`` and ``ptbN`` in the
  Trash's ``.DS_Store``) names the path, or a folder that held it.

Some traces are tied to an erased path on evidence but sit inside a file that
another process owns and rewrites. Those are reported with ``exact=True`` and
``report_only=True``, with the reason, and never edited:

* a macOS recent item (a ``.sfl2``/``.sfl3`` shared file list, which
  ``sharedfilelistd`` owns) whose bookmark names the path;
* a macOS Quick Look cache entry (``index.sqlite``, which the Quick Look daemon
  owns), read through a read-only, immutable SQLite open;
* a jump-list entry in a jump list that also names files nobody asked to
  erase, and any entry of a ``*.customDestinations-ms`` list;
* the put-back record in a macOS Trash's ``.DS_Store``.

Anything weaker is reported with ``exact=False`` and never removed: a macOS
Trash item of the same name with no put-back record, or one whose record names
some other path, is a *possible* copy, left for the operator to judge.

**Removal reuses the erase.** A trace that is a file - a thumbnail, a Trash
copy, a shortcut, a whole jump list - goes through
:func:`core.erase.files.erase_one`, the same steps as a target, so it is
overwritten, renamed and unlinked, and the same residual findings apply to it.
An entry inside a shared list is cut out and the list is overwritten in place,
padded to its old length, so the bytes that named the file are replaced rather
than left behind in a freed block.

**Links are never followed.** A place that is itself a link is recorded as
unreadable and not searched; every file is opened with ``O_NOFOLLOW``; the
erase refuses a link by name.

Every place inspected is returned with its outcome (searched, absent,
unreadable, permission-denied), and every place this platform keeps traces in
that the sweep does not search is named. :func:`find_traces` is the read-only
search; :func:`sweep` searches and removes the exact traces.
"""

from __future__ import annotations

import errno
import hashlib
import html
import io
import ntpath
import os
import plistlib
import posixpath
import re
import sqlite3
import stat as stat_mod
import struct
import xml.etree.ElementTree as ET
from collections.abc import Callable, Generator, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from urllib.parse import quote, unquote

import structlog

from core.erase.sink import LedgerSink
from core.errors import ConfirmationMismatch, SystemDiskRefused
from core.models import (
    FileEraseOptions,
    FileEraseRecord,
    Progress,
    TraceInspection,
    TraceRecord,
    TraceSweepResult,
)
from core.platform.host import family
from core.platform.model import PlatformFamily

__all__ = [
    "PHASE",
    "TraceKind",
    "TraceLocations",
    "bookmark_path",
    "custom_destination_targets",
    "default_locations",
    "ds_store_records",
    "file_uris",
    "find_traces",
    "jump_list_streams",
    "locations_for",
    "path_from_uri",
    "quicklook_entries",
    "shared_file_list_paths",
    "sweep",
    "trash_putback",
]

logger = structlog.get_logger(__name__)

#: The progress phase the sweep reports under.
PHASE = "TRACES"


class TraceKind(StrEnum):
    """What a trace is. The report prints these."""

    THUMBNAIL = "THUMBNAIL"
    #: A failed-thumbnail marker: no image, but it names the file.
    THUMBNAIL_FAILURE = "THUMBNAIL_FAILURE"
    RECENT_ENTRY = "RECENT_ENTRY"
    RECENT_DOCUMENT = "RECENT_DOCUMENT"
    TRASH_COPY = "TRASH_COPY"
    TRASH_RECORD = "TRASH_RECORD"
    RECYCLE_BIN_COPY = "RECYCLE_BIN_COPY"
    RECYCLE_BIN_RECORD = "RECYCLE_BIN_RECORD"
    RECENT_SHORTCUT = "RECENT_SHORTCUT"
    POSSIBLE_COPY = "POSSIBLE_COPY"
    #: A Windows jump list (automatic or custom destinations) naming the file.
    JUMP_LIST_ENTRY = "JUMP_LIST_ENTRY"
    #: A macOS Quick Look thumbnail cache entry for the file.
    QUICKLOOK_THUMBNAIL = "QUICKLOOK_THUMBNAIL"


#: Outcomes of inspecting one place.
SEARCHED = "searched"
ABSENT = "absent"
UNREADABLE = "unreadable"
PERMISSION_DENIED = "permission-denied"

#: Places each platform keeps traces that this sweep does not search. Printed
#: in the report, so its reader knows where the sweep stopped.
NOT_SEARCHED: dict[str, list[str]] = {
    "linux": [
        "Caches and history an application keeps for itself: office suites, "
        "image viewers, editors and browsers.",
        "Desktop search and activity indexes: GNOME's Tracker or LocalSearch "
        "and the KDE activity database.",
        "Backups, filesystem snapshots and sync clients.",
    ],
    "windows": [
        "The thumbnail databases (thumbcache_*.db): cannot be tied to a path on "
        "evidence: entries are keyed by a cache hash, not the file path.",
        "The Windows Search index.",
        "Recent lists an application keeps for itself, such as Office's, and "
        "the RecentDocs registry key.",
        "Volume Shadow Copies, File History, OneDrive and other sync clients.",
    ],
    "macos": [
        "The Spotlight index.",
        "Recent lists an application keeps for itself outside the shared file "
        "lists, and the per-document versions store.",
        "Time Machine and APFS snapshots, iCloud Drive and other sync clients.",
    ],
}

#: Why a trace tied to an erased path on evidence is still only reported.
REPORT_ONLY_REASONS: dict[str, str] = {
    "sfl": (
        "macOS rewrites this list from sharedfilelistd; Sanctum reports it and "
        "does not edit a live daemon-owned file."
    ),
    "quicklook": (
        "The Quick Look cache is a shared database owned by a system daemon; "
        "Sanctum reports the entry and does not edit it. `qlmanage -r cache` "
        "resets the whole cache, which deletes its files but does not "
        "overwrite them."
    ),
    "jump_list": (
        "The jump list also names files nobody asked to erase. Editing a live "
        "compound file the shell owns risks corrupting those entries, so this "
        "one is reported and the file left as it is."
    ),
    "custom_jump_list": (
        "A custom jump list is written by the application it belongs to, as "
        "back-to-back shortcuts; cutting one out in place risks corrupting the "
        "rest, so the entry is reported and the file left as it is."
    ),
    "ds_store": (
        "The put-back record lives in the Trash's .DS_Store, a B-tree Finder "
        "owns and rewrites; Sanctum reports it and does not edit the file. It "
        "names the path, not the content, and stays until Finder rewrites the "
        "file."
    ),
}

#: freedesktop thumbnail size directories.
_THUMBNAIL_SIZES = ("normal", "large", "x-large", "xx-large")

#: Characters left unescaped in a file URI's path by the encoders a thumbnail
#: may have been named under: GLib's ``g_filename_to_uri``, RFC 3986's pchar
#: set (Qt's fully encoded form keeps the same ones), and a strict encoder that
#: escapes everything but ``/``. The MD5 differs with each, so each is tried.
_URI_SAFE = ("!$&'()*+,-./:=@_~", "!$&'()*+,;=:@/-._~", "/")

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

#: A thumbnail's text chunks come before its image data; this much is read.
_PNG_HEAD = 64 * 1024

#: How many cached thumbnails are read, per cache, for thumbnails of files
#: inside an erased folder. The MD5 lookups for the erased files themselves
#: are not bounded by this.
SCAN_LIMIT = 20_000

#: Size bounds for the small files a trace is recorded in.
_RECORD_LIMIT = 64 * 1024
_LIST_LIMIT = 32 * 1024 * 1024

#: Bounds for the structured files parsed below. Each is far above what a
#: desktop writes, and each stops a hostile file from costing more than that.
_DS_STORE_LIMIT = 16 * 1024 * 1024
_DS_MAX_BLOCKS = 65_536
_DS_MAX_DEPTH = 32
_DS_MAX_RECORDS = 1_000_000
_BOOKMARK_MAX_TOCS = 16
_BOOKMARK_MAX_ENTRIES = 4_096
_PLIST_MAX_OBJECTS = 1_000_000
#: Shared file lists under the sharedfilelist folder, and how deep to look.
_SFL_FILE_LIMIT = 2_000
_SFL_DEPTH = 4
_SFL_SUFFIXES = (".sfl", ".sfl2", ".sfl3")
#: Quick Look cache rows read.
_QUICKLOOK_ROW_LIMIT = 500_000
#: Jump list streams read, and shortcuts found in one custom list.
_JUMP_LIST_STREAMS = 10_000
_CUSTOM_LINKS = 4_096

#: A Shell Link header: HeaderSize 0x4C, then CLSID 00021401-0000-0000-C000-
#: 000000000046 in its little-endian GUID form ([MS-SHLLINK] 2.1).
_LNK_HEADER = b"\x4c\x00\x00\x00" + bytes.fromhex("0114020000000000c000000000000046")

_XBEL_BOOKMARK = re.compile(
    rb"""[ \t]*<bookmark\b[^>]*?\bhref=(["'])(.*?)\1[^>]*?"""
    rb"""(?:/>|>.*?</bookmark\s*>)[ \t]*(?:\r?\n)?""",
    re.DOTALL,
)


# --------------------------------------------------------------------------
# Where to look
# --------------------------------------------------------------------------


def _mount_top(path: str) -> Path | None:
    """The mount point of the volume that holds ``path``.

    The path itself is usually gone by now, so the walk starts at its nearest
    surviving ancestor.
    """
    current = Path(os.path.abspath(path))
    while not os.path.lexists(current) and current.parent != current:
        current = current.parent
    while not os.path.ismount(current):
        if current.parent == current:
            return None
        current = current.parent
    return current


def _drive_top(path: str) -> Path | None:
    """The root of the Windows volume ``path`` is on: ``C:\\`` for ``C:\\x``."""
    drive, _ = ntpath.splitdrive(path)
    return Path(drive + "\\") if drive else None


@dataclass(frozen=True)
class TraceLocations:
    """Where one host keeps traces.

    :func:`locations_for` builds it for a platform; a test builds its own.
    """

    family: PlatformFamily
    home: Path | None = None
    #: freedesktop thumbnail caches.
    thumbnail_roots: tuple[Path, ...] = ()
    #: GTK recent-files lists (XBEL).
    recent_lists: tuple[Path, ...] = ()
    #: KDE's one-link-per-document recent list.
    recent_document_dirs: tuple[Path, ...] = ()
    #: The home Trash.
    home_trash: Path | None = None
    #: The user's uid, for per-volume Trash directories. None: not searched.
    uid: int | None = None
    #: Windows Recent shortcuts.
    recent_shortcut_dirs: tuple[Path, ...] = ()
    #: Search ``<volume>\\$Recycle.Bin`` on each erased path's volume.
    recycle_bin: bool = False
    #: The macOS home Trash (``~/.Trash``).
    mac_trash: Path | None = None
    #: The volume the home Trash's put-back locations are relative to: the
    #: boot volume, ``/``.
    mac_trash_volume: Path = Path("/")
    #: Roots walked for macOS shared file lists (``.sfl2``/``.sfl3``).
    shared_file_lists: tuple[Path, ...] = ()
    #: macOS Quick Look thumbnail cache folders (holding ``index.sqlite``).
    quicklook_caches: tuple[Path, ...] = ()
    #: Windows ``AutomaticDestinations`` folders.
    jump_list_dirs: tuple[Path, ...] = ()
    #: Windows ``CustomDestinations`` folders.
    custom_jump_list_dirs: tuple[Path, ...] = ()
    #: Places this platform keeps traces in that could not be located on this
    #: host, each with the reason. Reported as not searched.
    not_located: tuple[str, ...] = ()
    #: Finds the top of the volume that holds a path. Injected, so a test never
    #: walks up the host's own mounts.
    volume_top: Callable[[str], Path | None] = field(default=_mount_top)


def _xdg_dir(env: Mapping[str, str], name: str, fallback: Path) -> Path:
    """An XDG base directory. A relative value is invalid and is ignored."""
    value = env.get(name, "")
    return Path(value) if value and os.path.isabs(value) else fallback


def locations_for(
    platform: PlatformFamily,
    env: Mapping[str, str],
    home: Path,
    *,
    uid: int | None = None,
    volume_top: Callable[[str], Path | None] | None = None,
) -> TraceLocations:
    """The places ``platform`` keeps traces, for the user whose home is ``home``.

    ``env`` supplies ``APPDATA`` on Windows, ``TMPDIR`` on macOS and the XDG
    base directories elsewhere; ``volume_top`` replaces the walk to a path's
    volume root, so a test can build a whole profile, drive root included,
    under a temporary directory.
    """
    if platform == "windows":
        appdata = env.get("APPDATA", "")
        recent = Path(appdata) / "Microsoft" / "Windows" / "Recent" if appdata else None
        return TraceLocations(
            family=platform,
            home=home,
            recent_shortcut_dirs=(recent,) if recent else (),
            jump_list_dirs=(recent / "AutomaticDestinations",) if recent else (),
            custom_jump_list_dirs=(recent / "CustomDestinations",) if recent else (),
            recycle_bin=True,
            volume_top=volume_top or _drive_top,
            not_located=()
            if recent
            else (
                "Recent shortcuts and jump lists: APPDATA is not set, so the "
                "Recent folder could not be located.",
            ),
        )
    if platform == "macos":
        tmpdir = env.get("TMPDIR", "")
        quicklook: tuple[Path, ...] = ()
        if tmpdir and os.path.isabs(tmpdir):
            # $TMPDIR is /var/folders/xx/yyyy/T/; the cache is in its sibling C.
            # A path on this host, so this host's path rules (posixpath on a Mac).
            per_user = Path(os.path.dirname(os.path.normpath(tmpdir)))
            quicklook = (per_user / "C" / "com.apple.QuickLook.thumbnailcache",)
        return TraceLocations(
            family=platform,
            home=home,
            mac_trash=home / ".Trash",
            uid=uid,
            shared_file_lists=(
                home / "Library" / "Application Support" / "com.apple.sharedfilelist",
            ),
            quicklook_caches=quicklook,
            volume_top=volume_top or _mount_top,
            not_located=()
            if quicklook
            else (
                "The Quick Look thumbnail cache: TMPDIR is not set, so its "
                "per-user folder ($TMPDIR/../C/) could not be located.",
            ),
        )
    cache = _xdg_dir(env, "XDG_CACHE_HOME", home / ".cache")
    data = _xdg_dir(env, "XDG_DATA_HOME", home / ".local" / "share")
    return TraceLocations(
        family=platform,
        home=home,
        thumbnail_roots=(cache / "thumbnails", home / ".thumbnails"),
        # GTK 3 and 4 write the first; GTK 2 wrote the second.
        recent_lists=(data / "recently-used.xbel", home / ".recently-used.xbel"),
        recent_document_dirs=(data / "RecentDocuments",),
        home_trash=data / "Trash",
        uid=uid,
        volume_top=volume_top or _mount_top,
    )


def default_locations() -> TraceLocations:
    """This host's places, for the user the process runs as."""
    uid = os.getuid() if hasattr(os, "getuid") else None
    return locations_for(family(), os.environ, Path.home(), uid=uid)


# --------------------------------------------------------------------------
# URIs
# --------------------------------------------------------------------------


def file_uris(path: str) -> list[str]:
    """The ``file://`` URIs a desktop may have written for ``path``, deduplicated."""
    raw = os.fsencode(path)
    uris: list[str] = []
    for safe in _URI_SAFE:
        uri = "file://" + quote(raw, safe=safe)
        if uri not in uris:
            uris.append(uri)
    return uris


def path_from_uri(uri: str) -> str | None:
    """The local path a ``file:`` URI names, or None for any other URI."""
    if not uri.startswith("file://"):
        return None
    rest = uri[len("file://") :]
    if rest.startswith("localhost/"):
        rest = rest[len("localhost") :]
    if not rest.startswith("/"):
        return None  # a host other than this one
    return unquote(rest, errors="surrogateescape")


# --------------------------------------------------------------------------
# Reading the places, safely
# --------------------------------------------------------------------------


def _read(path: Path, limit: int, *, whole: bool) -> bytes | None:
    """Bytes of a regular file, never following a link or blocking on a FIFO.

    ``whole`` returns None for a file larger than ``limit``: a list that is
    rewritten must have been read in full. Otherwise the first ``limit`` bytes.
    """
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat_mod.S_ISREG(info.st_mode):
            return None
        if whole and info.st_size > limit:
            return None
        chunks: list[bytes] = []
        remaining = limit
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    except OSError:
        return None
    finally:
        os.close(fd)


def _listdir(directory: Path) -> list[Path] | None:
    """Entries of a directory, sorted; None when it is absent or unreadable."""
    try:
        return sorted(Path(entry.path) for entry in os.scandir(directory))
    except OSError:
        return None


def _is_link(info: os.stat_result) -> bool:
    """A symbolic link, or on Windows a symlink or junction reparse point."""
    if stat_mod.S_ISLNK(info.st_mode):
        return True
    tag = getattr(info, "st_reparse_tag", 0)
    return tag in (0xA000000C, 0xA0000003)  # IO_REPARSE_TAG_SYMLINK, MOUNT_POINT


def _probe(where: Path, *, directory: bool) -> tuple[str, str]:
    """``(outcome, detail)`` for one place, before anything in it is read.

    A place that is a link is not searched: the sweep never follows one, so a
    link planted where a Trash or cache belongs cannot lead the erase anywhere.
    """
    try:
        info = os.lstat(where)
    except (FileNotFoundError, NotADirectoryError):
        return ABSENT, ""
    except PermissionError as exc:
        return PERMISSION_DENIED, f"It could not be examined: {exc.strerror}."
    except OSError as exc:
        return UNREADABLE, f"It could not be examined: {exc.strerror}."
    if _is_link(info):
        return UNREADABLE, "It is a link, and the sweep never follows one."
    if directory and not stat_mod.S_ISDIR(info.st_mode):
        return UNREADABLE, "It is not a directory."
    if not directory and not stat_mod.S_ISREG(info.st_mode):
        return UNREADABLE, "It is not a regular file."
    try:
        if directory:
            with os.scandir(where):
                pass
        else:
            fd = os.open(
                where,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_BINARY", 0),
            )
            os.close(fd)
    except OSError as exc:
        if isinstance(exc, PermissionError) or exc.errno in (errno.EACCES, errno.EPERM):
            return PERMISSION_DENIED, f"It could not be opened: {exc.strerror}."
        return UNREADABLE, f"It could not be opened: {exc.strerror}."
    return SEARCHED, ""


def _is_real_dir(path: Path) -> bool:
    """A directory, and not a link to one."""
    try:
        return stat_mod.S_ISDIR(os.lstat(path).st_mode)
    except OSError:
        return False


def png_text(data: bytes) -> dict[str, str]:
    """The ``tEXt`` chunks that come before a PNG's image data."""
    found: dict[str, str] = {}
    if not data.startswith(_PNG_SIGNATURE):
        return found
    offset = len(_PNG_SIGNATURE)
    while offset + 8 <= len(data):
        length, kind = struct.unpack_from(">I4s", data, offset)
        if kind in (b"IDAT", b"IEND"):
            break
        body = data[offset + 8 : offset + 8 + length]
        if kind == b"tEXt" and len(body) == length:
            key, _, value = body.partition(b"\x00")
            found[key.decode("latin-1")] = value.decode("latin-1")
        offset += 12 + length
    return found


def _trashinfo_path(data: bytes) -> str | None:
    """The ``Path=`` of a ``.trashinfo`` file's ``[Trash Info]`` group, decoded."""
    in_group = False
    for line in data.decode("utf-8", "surrogateescape").splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_group = stripped == "[Trash Info]"
        elif in_group and stripped.startswith("Path="):
            value = stripped[len("Path=") :]
            return unquote(value, errors="surrogateescape") or None
    return None


def recycle_record(data: bytes) -> tuple[str, int] | None:
    """``(original path, size)`` from a Recycle Bin ``$I`` record.

    Version 1 (Vista to 8.1) holds the path in a fixed 520-byte field; version
    2 (Windows 10 and later) gives its length in characters first.
    """
    if len(data) < 24:
        return None
    version, size, _deleted = struct.unpack_from("<qqq", data, 0)
    if version == 1:
        raw = data[24 : 24 + 520]
    elif version == 2 and len(data) >= 28:
        (chars,) = struct.unpack_from("<i", data, 24)
        if chars <= 0:
            return None
        raw = data[28 : 28 + 2 * chars]
    else:
        return None
    text = raw.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
    return (text, size) if text else None


def _cstring(buffer: bytes, offset: int, *, wide: bool) -> str:
    """A NUL-terminated string at ``offset``; empty when out of range."""
    if offset <= 0 or offset >= len(buffer):
        return ""
    if wide:
        end = offset
        while end + 1 < len(buffer) and buffer[end : end + 2] != b"\x00\x00":
            end += 2
        return buffer[offset:end].decode("utf-16-le", errors="replace")
    end = buffer.find(b"\x00", offset)
    raw = buffer[offset : end if end >= 0 else len(buffer)]
    return raw.decode("mbcs" if os.name == "nt" else "cp1252", errors="replace")


def shortcut_target(data: bytes) -> str | None:
    """The local path a Shell Link (``.lnk``) points at, from its LinkInfo.

    [MS-SHLLINK] 2.3: the path is ``LocalBasePath`` followed by
    ``CommonPathSuffix``, in their Unicode forms when the header carries them.
    """
    if len(data) < 0x4C or data[:4] != b"\x4c\x00\x00\x00":
        return None
    (flags,) = struct.unpack_from("<I", data, 0x14)
    offset = 0x4C
    if flags & 0x1:  # HasLinkTargetIDList
        if offset + 2 > len(data):
            return None
        (id_list_size,) = struct.unpack_from("<H", data, offset)
        offset += 2 + id_list_size
    if not flags & 0x2:  # HasLinkInfo
        return None
    if offset + 0x1C > len(data):
        return None
    (info_size, header_size, info_flags, _volume, base, _network, suffix) = (
        struct.unpack_from("<7I", data, offset)
    )
    info = data[offset : offset + info_size]
    if len(info) < 0x1C:
        return None
    if not info_flags & 0x1:  # VolumeIDAndLocalBasePath
        return None
    if header_size >= 0x24 and len(info) >= 0x24:
        wide_base, wide_suffix = struct.unpack_from("<2I", info, 0x1C)
        if wide_base:
            head = _cstring(info, wide_base, wide=True)
            return (head + _cstring(info, wide_suffix, wide=True)) or None
    head = _cstring(info, base, wide=False)
    return (head + _cstring(info, suffix, wide=False)) or None


class _Malformed(Exception):
    """A structure that does not hold together; the whole file is set aside."""


class _Cursor:
    """Bounded reads from ``data[start:end]``. Every read is checked."""

    def __init__(self, data: bytes, start: int, end: int) -> None:
        if start < 0 or start > end or end > len(data):
            raise _Malformed
        self.data = data
        self.pos = start
        self.end = end

    def take(self, count: int) -> bytes:
        if count < 0 or self.pos + count > self.end:
            raise _Malformed
        chunk = self.data[self.pos : self.pos + count]
        self.pos += count
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u32(self) -> int:
        (value,) = struct.unpack(">I", self.take(4))
        return int(value)


def _ds_value(cursor: _Cursor, kind: bytes) -> str | int | bytes:
    """One record value of a ``.DS_Store``, by its four-byte type code."""
    if kind == b"bool":
        return cursor.u8()
    if kind in (b"long", b"shor"):
        return cursor.u32()
    if kind == b"type":
        return cursor.take(4)
    if kind in (b"comp", b"dutc"):
        return cursor.take(8)
    if kind == b"blob":
        return cursor.take(cursor.u32())
    if kind == b"ustr":
        chars = cursor.u32()
        try:
            return cursor.take(2 * chars).decode("utf-16-be")
        except UnicodeDecodeError as exc:
            raise _Malformed from exc
    # An unknown type has an unknown length: nothing after it can be trusted.
    raise _Malformed


def ds_store_records(
    data: bytes, wanted: frozenset[str] = frozenset({"ptbL", "ptbN"})
) -> dict[str, dict[str, str | int | bytes]] | None:
    """The ``wanted`` records of a Finder ``.DS_Store``, by file name.

    The file is a buddy-allocated store ("Bud1"): a header naming the
    allocator's root block, which lists every block's address and a table of
    contents whose ``DSDB`` entry is the B-tree's master block. Each tree node
    holds records of (file name, four-byte structure id, typed value). Every
    offset and length is checked against the file; a node reached twice, a
    tree deeper than any Finder writes, or a value of a type not known here
    makes the whole file unreadable, and None is returned.
    """
    try:
        return _ds_store_records(data, wanted)
    except _Malformed:
        return None


def _ds_store_records(
    data: bytes, wanted: frozenset[str]
) -> dict[str, dict[str, str | int | bytes]]:
    if len(data) < 36 or data[:8] != b"\x00\x00\x00\x01Bud1":
        raise _Malformed
    root_offset, root_size, root_check = struct.unpack_from(">III", data, 8)
    if root_offset != root_check:
        raise _Malformed
    # Every offset in the file counts from byte 4, after the leading 1.
    root = _Cursor(data, 4 + root_offset, 4 + root_offset + root_size)
    count = root.u32()
    root.u32()
    if count > _DS_MAX_BLOCKS:
        raise _Malformed
    addresses = [root.u32() for _ in range(count)]
    root.take(4 * (-count % 256))  # the address table is padded to 256 slots
    toc: dict[bytes, int] = {}
    for _ in range(root.u32()):
        name = root.take(root.u8())
        toc[name] = root.u32()
    if b"DSDB" not in toc:
        raise _Malformed

    def block(number: int) -> _Cursor:
        if number >= len(addresses):
            raise _Malformed
        address = addresses[number]
        start = 4 + (address & ~0x1F)
        size = 1 << (address & 0x1F)
        if start >= len(data):
            raise _Malformed
        return _Cursor(data, start, min(len(data), start + size))

    master = block(toc[b"DSDB"])
    root_node = master.u32()
    found: dict[str, dict[str, str | int | bytes]] = {}
    visited: set[int] = set()
    records = 0

    def record(cursor: _Cursor) -> None:
        nonlocal records
        records += 1
        if records > _DS_MAX_RECORDS:
            raise _Malformed
        try:
            name = cursor.take(2 * cursor.u32()).decode("utf-16-be")
        except UnicodeDecodeError as exc:
            raise _Malformed from exc
        structure = cursor.take(4).decode("latin-1")
        value = _ds_value(cursor, cursor.take(4))
        if structure in wanted:
            found.setdefault(name, {})[structure] = value

    def walk(number: int, depth: int) -> None:
        if depth > _DS_MAX_DEPTH or number in visited:
            raise _Malformed
        visited.add(number)
        node = block(number)
        right = node.u32()
        entries = node.u32()
        if right == 0:
            for _ in range(entries):
                record(node)
            return
        for _ in range(entries):
            walk(node.u32(), depth + 1)
            record(node)
        walk(right, depth + 1)

    walk(root_node, 0)
    return found


def trash_putback(data: bytes) -> dict[str, tuple[str, str]] | None:
    """``{Trash item name: (ptbL, ptbN)}`` from a Trash's ``.DS_Store``.

    ``ptbL`` is the folder the item was deleted from, relative to its volume's
    root; ``ptbN`` its name there (the Trash renames an item whose name is
    taken, so the two names can differ). None when the file is not a readable
    ``.DS_Store``; an item without both records is left out.
    """
    records = ds_store_records(data)
    if records is None:
        return None
    putback: dict[str, tuple[str, str]] = {}
    for name, fields in records.items():
        location, original = fields.get("ptbL"), fields.get("ptbN")
        if isinstance(location, str) and isinstance(original, str):
            putback[name] = (location, original)
    return putback


def _putback_path(volume: Path, location: str, name: str) -> str | None:
    """The path a put-back record names, or None when it is not a plain path."""
    parts = [part for part in location.split("/") if part]
    if (
        not name
        or name in (".", "..")
        or "/" in name
        or "\x00" in name
        or any(part in (".", "..") or "\x00" in part for part in parts)
    ):
        return None
    return posixpath.join(str(volume), *parts, name)


def _book_item(view: bytes, base: int, offset: int) -> tuple[int, bytes] | None:
    """``(type code, payload)`` of one item in a bookmark's data section."""
    start = base + offset
    if start + 8 > len(view):
        return None
    length, code = struct.unpack_from("<II", view, start)
    if start + 8 + length > len(view):
        return None
    return code, view[start + 8 : start + 8 + length]


def bookmark_path(data: bytes) -> str | None:
    """The absolute path a macOS bookmark (``book``) names, or None.

    The path is the ``0x1004`` entry of the bookmark's table of contents: an
    array of UTF-8 strings, one per path component from the root. Only a path
    decoded in full is returned: a component that is not a UTF-8 string, is
    empty or holds a separator, or any offset that leaves the blob, and there
    is no path - never a partial one.
    """
    if len(data) < 16 or data[:4] != b"book":
        return None
    total, _version, header = struct.unpack_from("<III", data, 4)
    if header < 16 or total < header + 4 or total > len(data):
        return None
    view = data[:total]
    (first,) = struct.unpack_from("<I", view, header)
    toc = header + first
    seen: set[int] = set()
    for _ in range(_BOOKMARK_MAX_TOCS):
        if toc in seen or toc + 20 > len(view):
            return None
        seen.add(toc)
        _size, magic, _ident, next_toc, count = struct.unpack_from("<5I", view, toc)
        if magic != 0xFFFFFFFE or count > _BOOKMARK_MAX_ENTRIES:
            return None
        if toc + 20 + 12 * count > len(view):
            return None
        for number in range(count):
            key, offset, _reserved = struct.unpack_from(
                "<3I", view, toc + 20 + 12 * number
            )
            if key == 0x1004:
                return _book_path(view, header, offset)
        if next_toc == 0:
            return None
        toc = header + next_toc
    return None


def _book_path(view: bytes, base: int, offset: int) -> str | None:
    """The path components array of a bookmark, joined, or None."""
    item = _book_item(view, base, offset)
    if item is None or item[0] != 0x0601 or len(item[1]) % 4:
        return None
    count = len(item[1]) // 4
    if not count or count > _BOOKMARK_MAX_ENTRIES:
        return None
    parts: list[str] = []
    for (element,) in struct.iter_unpack("<I", item[1]):
        component = _book_item(view, base, element)
        if component is None or component[0] != 0x0101:
            return None
        try:
            text = component[1].decode("utf-8")
        except UnicodeDecodeError:
            return None
        if not text or "/" in text or "\x00" in text:
            return None
        parts.append(text)
    return "/" + "/".join(parts)


def _plist_plausible(data: bytes) -> bool:
    """A binary plist whose trailer fits the file, checked before plistlib.

    The trailer gives the object count and offset table; a forged one could
    otherwise make the parser reserve room for billions of objects.
    """
    if len(data) < 40 or not data.startswith(b"bplist00"):
        return False
    trailer: tuple[int, int, int, int, int] = struct.unpack_from(
        ">6xBBQQQ", data, len(data) - 32
    )
    offset_size, _ref_size, objects, _top, table = trailer
    return (
        1 <= offset_size <= 8
        and 0 < objects <= min(_PLIST_MAX_OBJECTS, len(data))
        and 8 <= table
        and table + objects * offset_size <= len(data) - 32
    )


def shared_file_list_paths(data: bytes) -> list[str] | None:
    """Paths named by the bookmarks in a macOS shared file list, or None.

    ``.sfl2`` and ``.sfl3`` files are NSKeyedArchiver binary property lists;
    each item carries its file as bookmark data. The archive's layout differs
    between releases, so rather than walk it, every data object in it that is
    a bookmark is decoded, and only paths decoded in full are returned. An
    XML plist is not parsed: a shared file list is always binary.
    """
    if not _plist_plausible(data):
        return None
    try:
        archive = plistlib.loads(data, fmt=plistlib.FMT_BINARY)
    except (
        plistlib.InvalidFileException,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        OverflowError,
        RecursionError,
        MemoryError,
        struct.error,
    ):
        return None
    objects = archive.get("$objects") if isinstance(archive, dict) else None
    if not isinstance(objects, list):
        return None
    paths: list[str] = []
    for item in objects[:_PLIST_MAX_OBJECTS]:
        blob = item.get("NS.data") if isinstance(item, dict) else item
        if isinstance(blob, bytes) and blob.startswith(b"book"):
            path = bookmark_path(blob)
            if path is not None and path not in paths:
                paths.append(path)
    return paths


def quicklook_entries(
    index_db: Path,
) -> tuple[list[tuple[str, int, int]] | None, str]:
    """``(path, row id, thumbnails)`` per file in a Quick Look ``index.sqlite``.

    The database is opened read-only and immutable, through a URI, in place:
    nothing is copied, locked or written, and no journal is created. Returns
    ``(None, reason)`` when it cannot be opened or its schema is not the one
    known here - a ``files`` table with ``folder`` and ``file_name`` columns.
    """
    uri = index_db.absolute().as_uri() + "?mode=ro&immutable=1"
    try:
        connection = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        return None, f"it could not be opened read-only ({exc})"
    try:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        if "files" not in tables:
            return None, "its schema is not a known one (no files table)"
        columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(files)")
        }
        if not {"folder", "file_name"} <= columns:
            return None, (
                "its schema is not a known one (the files table has no folder "
                "and file_name columns)"
            )
        counts: dict[int, int] = {}
        if "thumbnails" in tables:
            thumb_columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(thumbnails)")
            }
            if "file_id" in thumb_columns:
                counts = {
                    file_id: int(number)
                    for file_id, number in connection.execute(
                        "SELECT file_id, COUNT(*) FROM thumbnails GROUP BY file_id"
                    )
                    if isinstance(file_id, int)
                }
        entries: list[tuple[str, int, int]] = []
        for rowid, folder, name in connection.execute(
            "SELECT rowid, folder, file_name FROM files LIMIT ?",
            (_QUICKLOOK_ROW_LIMIT,),
        ):
            path = _quicklook_path(folder, name)
            if path is not None:
                entries.append((path, int(rowid), counts.get(int(rowid), 0)))
        return entries, ""
    except sqlite3.Error as exc:
        return None, f"it could not be read ({exc})"
    finally:
        connection.close()


def _quicklook_path(folder: object, name: object) -> str | None:
    """The path a Quick Look ``files`` row names: a folder path or URL, and a name."""
    if isinstance(folder, bytes):
        folder = folder.decode("utf-8", "surrogateescape")
    if isinstance(name, bytes):
        name = name.decode("utf-8", "surrogateescape")
    if not isinstance(folder, str) or not isinstance(name, str):
        return None
    name = name.strip("/")
    local = path_from_uri(folder) if folder.startswith("file://") else folder
    if not name or "/" in name or not local or not local.startswith("/"):
        return None
    return posixpath.join(local, name)


def jump_list_streams(data: bytes) -> list[tuple[str, str | None]] | None:
    """``(stream, link target)`` for each entry stream of an automatic jump list.

    An ``*.automaticDestinations-ms`` file is an OLE compound file: a
    ``DestList`` stream indexes numbered streams, each a Shell Link. The target
    is None for a stream that is not a link or names no local path. None when
    the file is not a readable compound file.
    """
    import olefile

    try:
        if not olefile.isOleFile(io.BytesIO(data)):
            return None
        with olefile.OleFileIO(io.BytesIO(data)) as ole:
            found: list[tuple[str, str | None]] = []
            for entry in ole.listdir(streams=True, storages=False):
                name = "/".join(entry)
                if name == "DestList":
                    continue
                if len(found) >= _JUMP_LIST_STREAMS:
                    return None
                blob = ole.openstream(entry).read(_RECORD_LIMIT)
                found.append((name, shortcut_target(blob)))
            return found
    except (OSError, ValueError, TypeError, KeyError, IndexError, struct.error):
        return None


def custom_destination_targets(data: bytes) -> list[str]:
    """Link targets of the shortcuts in a ``*.customDestinations-ms`` list.

    The file is shortcuts back to back between a header and a footer, with no
    index; each Shell Link header is found by its signature and parsed where
    it starts.
    """
    targets: list[str] = []
    start = data.find(_LNK_HEADER)
    while start >= 0 and len(targets) < _CUSTOM_LINKS:
        target = shortcut_target(data[start : start + _RECORD_LIMIT])
        if target and target not in targets:
            targets.append(target)
        start = data.find(_LNK_HEADER, start + len(_LNK_HEADER))
    return targets


# --------------------------------------------------------------------------
# What was erased
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class _Erased:
    """One erased path and its comparison key."""

    path: str
    key: str
    is_directory: bool
    size_bytes: int


class _Index:
    """The erased paths, and which of them another path is or lies inside."""

    def __init__(self, records: Sequence[FileEraseRecord], *, windows: bool) -> None:
        self.windows = windows
        self.sep = "\\" if windows else "/"
        self.erased = [
            _Erased(
                path=record.path,
                key=self.key(record.path),
                is_directory=record.is_directory,
                size_bytes=record.inspection.size_bytes,
            )
            for record in records
            if record.ok and record.unlinked
        ]
        self._exact = {item.key: item for item in self.erased}
        #: Longest first, so the innermost erased folder claims a path.
        self._folders = sorted(
            (item for item in self.erased if item.is_directory),
            key=lambda item: len(item.key),
            reverse=True,
        )
        #: Erased paths that are not inside another erased folder.
        self.roots = [
            item
            for item in self.erased
            if not any(
                item.key.startswith(folder.key + self.sep)
                for folder in self._folders
                if folder is not item
            )
        ]

    def key(self, path: str) -> str:
        if self.windows:
            return ntpath.normcase(ntpath.normpath(path))
        return posixpath.normpath(posixpath.abspath(path))

    def owner(self, path: str) -> _Erased | None:
        """The erased path ``path`` is, or the erased folder it lies inside."""
        key = self.key(path)
        exact = self._exact.get(key)
        if exact is not None:
            return exact
        for folder in self._folders:
            if key.startswith(folder.key + self.sep):
                return folder
        return None

    def inside(self, path: str) -> list[tuple[_Erased, list[str]]]:
        """Erased roots inside the folder ``path``, each with its relative parts."""
        key = self.key(path)
        found: list[tuple[_Erased, list[str]]] = []
        for item in self.roots:
            if item.key.startswith(key + self.sep):
                relative = item.key[len(key) + 1 :]
                found.append(
                    (item, [part for part in relative.split(self.sep) if part])
                )
        return found

    @property
    def names(self) -> dict[str, _Erased]:
        """Erased paths by final component, for a same-name comparison."""
        split = ntpath.basename if self.windows else posixpath.basename
        by_name: dict[str, _Erased] = {}
        for item in self.erased:
            by_name.setdefault(split(item.path.rstrip("/\\")), item)
        return by_name


# --------------------------------------------------------------------------
# Finding
# --------------------------------------------------------------------------


@dataclass
class _Found:
    """A trace, before anything is done to it."""

    kind: TraceKind
    target: str
    location: Path
    evidence: str
    content_copy: bool
    exact: bool = True
    #: How a real run removes it: "erase" puts the file through erase_one,
    #: "list" cuts ``entry`` out of the list at ``location``, "report" leaves
    #: it where it is and says why in ``reason``.
    how: str = "erase"
    entry: str = ""
    #: For a Trash or Recycle Bin record, the copy it describes. The record is
    #: kept when that copy could not be removed, so the copy stays visible.
    pair: Path | None = None
    reason: str = ""


_OUTCOME_WORDS = {
    ABSENT: " (not present)",
    UNREADABLE: " (not read)",
    PERMISSION_DENIED: " (permission denied)",
}


@dataclass
class _Inspected:
    """One place inspected, and what came of it."""

    label: str
    location: Path
    outcome: str
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.outcome == SEARCHED

    def fail(self, outcome: str, detail: str) -> None:
        """A place that was present but could not be searched through."""
        if self.outcome == SEARCHED:
            self.outcome = outcome
            self.detail = detail

    def line(self) -> str:
        return f"{self.label}: {self.location}{_OUTCOME_WORDS.get(self.outcome, '')}"


@dataclass
class _Plan:
    found: list[_Found] = field(default_factory=list)
    inspected: list[_Inspected] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    #: Places found at run time that could not be searched (an unknown
    #: schema, say), added to the platform's fixed list.
    not_searched: list[str] = field(default_factory=list)
    _seen: set[tuple[str, str]] = field(default_factory=set)

    def add(self, trace: _Found) -> None:
        key = (str(trace.location), trace.entry)
        if key not in self._seen:
            self._seen.add(key)
            self.found.append(trace)

    def place(self, label: str, where: Path, *, directory: bool = True) -> _Inspected:
        """Record a place as inspected, probed without following a link."""
        outcome, detail = _probe(where, directory=directory)
        entry = _Inspected(label, where, outcome, detail)
        self.inspected.append(entry)
        if outcome in (UNREADABLE, PERMISSION_DENIED):
            self.notes.append(f"The {label} at {where} was not searched. {detail}")
        return entry

    @property
    def searched(self) -> list[str]:
        return [entry.line() for entry in self.inspected]


def _size_words(copy: Path, erased: _Erased) -> str:
    """How a copy's size compares with the erased file's, for the evidence."""
    if erased.is_directory:
        return ""
    try:
        info = os.lstat(copy)
    except OSError:
        return ""
    if not stat_mod.S_ISREG(info.st_mode):
        return ""
    if info.st_size == erased.size_bytes:
        return f" It is the same size as the erased file ({info.st_size:,} bytes)."
    return (
        f" It is {info.st_size:,} bytes and the erased file was "
        f"{erased.size_bytes:,}: an earlier version."
    )


def _thumbnail_dirs(root: Path) -> list[tuple[Path, bool]]:
    """``(directory, holds failure markers)`` for each cache directory present."""
    found = [(root / size, False) for size in _THUMBNAIL_SIZES]
    failures = _listdir(root / "fail") or []
    found.extend((entry, True) for entry in failures)
    return [
        (directory, failed) for directory, failed in found if _is_real_dir(directory)
    ]


def _thumbnail_kind(failed: bool) -> TraceKind:
    return TraceKind.THUMBNAIL_FAILURE if failed else TraceKind.THUMBNAIL


def _find_thumbnails(root: Path, index: _Index, plan: _Plan) -> None:
    """Thumbnails of erased files, by name, then of files inside erased folders."""
    if not plan.place("thumbnail cache", root).ok:
        return
    directories = _thumbnail_dirs(root)
    if not directories:
        return
    for item in index.erased:
        if item.is_directory:
            continue
        for uri in file_uris(item.path):
            name = hashlib.md5(uri.encode("ascii"), usedforsecurity=False).hexdigest()
            for directory, failed in directories:
                candidate = directory / f"{name}.png"
                if not os.path.lexists(candidate):
                    continue
                recorded = png_text(_read(candidate, _PNG_HEAD, whole=False) or b"")
                named = recorded.get("Thumb::URI")
                named_path = path_from_uri(named) if named else None
                if named is None:
                    evidence = (
                        f"Named by the MD5 of {uri}. It carries no Thumb::URI "
                        "to confirm the match."
                    )
                    exact = True
                elif named_path is not None and index.key(named_path) == item.key:
                    evidence = (
                        f"Named by the MD5 of {uri}, and its Thumb::URI names "
                        "the same file."
                    )
                    exact = True
                else:
                    evidence = (
                        f"Named by the MD5 of {uri}, but its Thumb::URI names "
                        f"{named}. Left in place."
                    )
                    exact = False
                plan.add(
                    _Found(
                        kind=_thumbnail_kind(failed),
                        target=item.path,
                        location=candidate,
                        evidence=evidence,
                        content_copy=not failed,
                        exact=exact,
                    )
                )

    if not any(item.is_directory for item in index.erased):
        return
    read = 0
    for directory, failed in directories:
        for candidate in _listdir(directory) or []:
            if read >= SCAN_LIMIT:
                plan.notes.append(
                    f"The thumbnail cache at {root} holds more than "
                    f"{SCAN_LIMIT:,} files. Only the first {SCAN_LIMIT:,} were "
                    "read for thumbnails of files inside erased folders."
                )
                return
            if candidate.suffix != ".png":
                continue
            read += 1
            named = png_text(_read(candidate, _PNG_HEAD, whole=False) or b"").get(
                "Thumb::URI"
            )
            named_path = path_from_uri(named) if named else None
            owner = index.owner(named_path) if named_path else None
            if owner is None or not owner.is_directory:
                continue
            plan.add(
                _Found(
                    kind=_thumbnail_kind(failed),
                    target=owner.path,
                    location=candidate,
                    evidence=(
                        f"Its Thumb::URI names {named}, inside the erased "
                        f"folder {owner.path}."
                    ),
                    content_copy=not failed,
                )
            )


def _find_recent_list(path: Path, index: _Index, plan: _Plan) -> None:
    """Entries of a GTK recent-files list that name an erased path."""
    entry = plan.place("recent-files list", path, directory=False)
    if not entry.ok:
        return
    data = _read(path, _LIST_LIMIT, whole=True)
    if data is None:
        entry.fail(UNREADABLE, f"It is larger than {_LIST_LIMIT:,} bytes.")
        plan.notes.append(f"{path} could not be read, so it was not searched.")
        return
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        entry.fail(UNREADABLE, "It declares a DTD or entities.")
        plan.notes.append(f"{path} declares a DTD or entities and was not parsed.")
        return
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        entry.fail(UNREADABLE, f"It is not well-formed XML ({exc}).")
        plan.notes.append(
            f"{path} is not well-formed XML ({exc}) and was not searched."
        )
        return
    for bookmark in root.iter("bookmark"):
        href = bookmark.get("href") or ""
        local = path_from_uri(href)
        owner = index.owner(local) if local else None
        if owner is None:
            continue
        plan.add(
            _Found(
                kind=TraceKind.RECENT_ENTRY,
                target=owner.path,
                location=path,
                evidence=f"The list has an entry for {href}.",
                content_copy=False,
                how="list",
                entry=href,
            )
        )


def _desktop_url(line: str, home: Path | None) -> str | None:
    """The local path in a ``URL=`` line of a KDE recent-document link."""
    key, sep, value = line.partition("=")
    if not sep or key.strip().split("[", 1)[0] != "URL":
        return None
    value = value.strip()
    if home is not None:
        value = value.replace("$HOME", str(home))
    if value.startswith("file://"):
        return path_from_uri(value)
    if value.startswith("file:"):
        return unquote(value[len("file:") :], errors="surrogateescape")
    return value if value.startswith("/") else None


def _find_recent_documents(
    directory: Path, index: _Index, plan: _Plan, home: Path | None
) -> None:
    """KDE ``RecentDocuments`` links whose URL names an erased path."""
    if not plan.place("recent documents", directory).ok:
        return
    for link in _listdir(directory) or []:
        if link.suffix != ".desktop":
            continue
        data = _read(link, _RECORD_LIMIT, whole=True)
        if data is None:
            continue
        for line in data.decode("utf-8", "surrogateescape").splitlines():
            local = _desktop_url(line, home)
            owner = index.owner(local) if local else None
            if owner is None:
                continue
            plan.add(
                _Found(
                    kind=TraceKind.RECENT_DOCUMENT,
                    target=owner.path,
                    location=link,
                    evidence=f"Its URL names {local}.",
                    content_copy=False,
                )
            )
            break


def _real_dirs_down(root: Path, parts: list[str]) -> bool:
    """``root`` and each folder below it along ``parts`` is a directory, not a link."""
    current = root
    if not _is_real_dir(current):
        return False
    for part in parts:
        current = current / part
        if not _is_real_dir(current):
            return False
    return True


def _find_bin_items(
    items: list[tuple[str, Path, Path]],
    index: _Index,
    plan: _Plan,
    *,
    copy_kind: TraceKind,
    record_kind: TraceKind,
    record_reason: str = "",
) -> None:
    """Trash or Recycle Bin items whose recorded origin was erased, or held it.

    Each item is ``(original path, content copy, record)``. An item deleted
    from an erased path is a copy of it, and its record names it; both go. A
    folder deleted from above an erased path may hold a copy of it inside; only
    that inner copy goes, because the folder and its record also describe
    files nobody asked to erase.

    ``record_reason`` makes the record report-only: the macOS put-back record
    is one entry of a ``.DS_Store`` that describes the whole Trash.
    """
    for original, copy, record in items:
        owner = index.owner(original)
        if owner is not None:
            where = (
                f"{original}"
                if owner.key == index.key(original)
                else f"{original}, inside the erased folder {owner.path}"
            )
            present = os.path.lexists(copy)
            if present:
                plan.add(
                    _Found(
                        kind=copy_kind,
                        target=owner.path,
                        location=copy,
                        evidence=f"{record.name} records that this was deleted "
                        f"from {where}." + _size_words(copy, owner),
                        content_copy=True,
                    )
                )
            plan.add(
                _Found(
                    kind=record_kind,
                    target=owner.path,
                    location=record,
                    evidence=f"It records the deletion of {where}"
                    + (f" (the entry for {copy.name})." if record_reason else "."),
                    content_copy=False,
                    pair=copy if present else None,
                    how="report" if record_reason else "erase",
                    entry=copy.name if record_reason else "",
                    reason=record_reason,
                )
            )
            continue
        for inner, parts in index.inside(original):
            inner_copy = copy.joinpath(*parts)
            # Every folder on the way down must be a real one. A link inside
            # a trashed folder would lead the erase out of the Trash, onto a
            # file nobody named.
            if not _real_dirs_down(copy, parts[:-1]) or not os.path.lexists(inner_copy):
                continue
            plan.add(
                _Found(
                    kind=copy_kind,
                    target=inner.path,
                    location=inner_copy,
                    evidence=(
                        f"{record.name} records a folder deleted from {original}; "
                        f"this is the copy of {inner.path} inside it."
                    )
                    + _size_words(inner_copy, inner),
                    content_copy=True,
                )
            )


def _trash_items(
    trash: Path, top: Path | None, plan: _Plan
) -> list[tuple[str, Path, Path]]:
    """Items of one freedesktop Trash directory, with their recorded origin.

    Its ``info`` and ``files`` folders must be real directories: a link there
    would point the erase of a "Trash copy" at some other folder entirely.
    """
    items: list[tuple[str, Path, Path]] = []
    if not os.path.lexists(trash / "info"):
        return items
    if not (_is_real_dir(trash / "info") and _is_real_dir(trash / "files")):
        plan.notes.append(
            f"{trash} has an info or files folder that is not a real directory, "
            "so it was not searched."
        )
        return items
    for info in _listdir(trash / "info") or []:
        if not info.name.endswith(".trashinfo"):
            continue
        data = _read(info, _RECORD_LIMIT, whole=True)
        original = _trashinfo_path(data) if data else None
        if not original:
            continue
        if not original.startswith("/"):
            # A per-volume Trash records paths relative to the volume's top.
            if top is None:
                continue
            original = str(top / original)
        name = info.name[: -len(".trashinfo")]
        items.append((original, trash / "files" / name, info))
    return items


def _volume_tops(where: TraceLocations, index: _Index) -> list[Path]:
    """The top of each erased path's volume, once each."""
    tops: list[Path] = []
    for item in index.roots:
        top = where.volume_top(item.path)
        if top is not None and top not in tops:
            tops.append(top)
    return tops


def _volume_trashes(
    where: TraceLocations, index: _Index, plan: _Plan
) -> list[tuple[Path, Path]]:
    """``(trash directory, volume top)`` for each erased path's volume.

    The freedesktop specification: ``$topdir/.Trash/$uid`` is used only when
    ``$topdir/.Trash`` is a real directory (not a link) with the sticky bit
    set; otherwise ``$topdir/.Trash-$uid``. A ``.Trash`` that fails the check
    is named in the notes, as the specification asks.
    """
    if where.uid is None or where.family in ("windows", "macos"):
        return []
    home_trash = os.path.realpath(where.home_trash) if where.home_trash else None
    found: list[tuple[Path, Path]] = []
    for top in _volume_tops(where, index):
        candidates = [top / f".Trash-{where.uid}"]
        shared = top / ".Trash"
        try:
            info = os.lstat(shared)
        except OSError:
            info = None
        if info is not None:
            if stat_mod.S_ISDIR(info.st_mode) and info.st_mode & stat_mod.S_ISVTX:
                candidates.append(shared / str(where.uid))
            else:
                plan.notes.append(
                    f"{shared} is not a real directory with the sticky bit set, "
                    "so by the freedesktop Trash specification it was not used."
                )
        for candidate in candidates:
            if _is_real_dir(candidate) and os.path.realpath(candidate) != home_trash:
                found.append((candidate, top))
    return found


def _recycle_items(bin_root: Path) -> list[tuple[str, Path, Path]]:
    """Recycle Bin items this user can read, with their recorded origin.

    Another user's folder under ``$Recycle.Bin`` is closed by its ACL, and is
    skipped rather than reported: it is not this user's to erase.
    """
    items: list[tuple[str, Path, Path]] = []
    for sid in _listdir(bin_root) or []:
        if not _is_real_dir(sid):
            continue
        for record in _listdir(sid) or []:
            if not record.name.startswith("$I"):
                continue
            data = _read(record, _RECORD_LIMIT, whole=True)
            parsed = recycle_record(data) if data else None
            if parsed is None:
                continue
            original, _size = parsed
            items.append((original, record.with_name("$R" + record.name[2:]), record))
    return items


def _find_shortcuts(directory: Path, index: _Index, plan: _Plan) -> None:
    """Windows Recent shortcuts whose link target was erased."""
    if not plan.place("Recent shortcuts", directory).ok:
        return
    for link in _listdir(directory) or []:
        if link.suffix.lower() != ".lnk":
            continue
        data = _read(link, _RECORD_LIMIT, whole=True)
        target = shortcut_target(data) if data else None
        owner = index.owner(target) if target else None
        if owner is None:
            continue
        plan.add(
            _Found(
                kind=TraceKind.RECENT_SHORTCUT,
                target=owner.path,
                location=link,
                evidence=f"Its link target is {target}.",
                content_copy=False,
            )
        )


def _entries_word(count: int) -> str:
    return f"{count} other entr{'y' if count == 1 else 'ies'}"


def _find_jump_lists(directory: Path, index: _Index, plan: _Plan) -> None:
    """Automatic jump lists with an entry whose shortcut names an erased path.

    A jump list every entry of which names an erased path is a trace as a
    whole and is erased as a file. One that also names other files is only
    reported: cutting a stream out of a compound file the shell holds open is
    an edit that can corrupt the entries around it.
    """
    if not plan.place("jump lists (AutomaticDestinations)", directory).ok:
        return
    for path in _listdir(directory) or []:
        if not path.name.lower().endswith(".automaticdestinations-ms"):
            continue
        data = _read(path, _LIST_LIMIT, whole=True)
        if data is None:
            plan.notes.append(f"{path} could not be read, so it was not searched.")
            continue
        streams = jump_list_streams(data)
        if streams is None:
            plan.notes.append(
                f"{path} is not a compound file this sweep can read, so it was "
                "not searched."
            )
            continue
        owners: dict[str, tuple[_Erased, list[str]]] = {}
        tied = 0
        for name, target in streams:
            owner = index.owner(target) if target else None
            if owner is None:
                continue
            tied += 1
            owners.setdefault(owner.key, (owner, []))[1].append(
                f"stream {name} is a shortcut to {target}"
            )
        whole = bool(streams) and tied == len(streams)
        for owner, links in owners.values():
            evidence = "In this jump list, " + "; ".join(links) + "."
            if whole:
                evidence += (
                    " Every entry in it names an erased path, so the whole file "
                    "is a trace and is erased, its DestList index with it."
                )
            else:
                evidence += f" It also holds {_entries_word(len(streams) - tied)}."
            plan.add(
                _Found(
                    kind=TraceKind.JUMP_LIST_ENTRY,
                    target=owner.path,
                    location=path,
                    evidence=evidence,
                    content_copy=False,
                    how="erase" if whole else "report",
                    entry=owner.key,
                    reason="" if whole else REPORT_ONLY_REASONS["jump_list"],
                )
            )


def _find_custom_jump_lists(directory: Path, index: _Index, plan: _Plan) -> None:
    """Custom jump lists holding a shortcut to an erased path. Report only."""
    if not plan.place("jump lists (CustomDestinations)", directory).ok:
        return
    for path in _listdir(directory) or []:
        if not path.name.lower().endswith(".customdestinations-ms"):
            continue
        data = _read(path, _LIST_LIMIT, whole=True)
        if data is None:
            plan.notes.append(f"{path} could not be read, so it was not searched.")
            continue
        for target in custom_destination_targets(data):
            owner = index.owner(target)
            if owner is None:
                continue
            plan.add(
                _Found(
                    kind=TraceKind.JUMP_LIST_ENTRY,
                    target=owner.path,
                    location=path,
                    evidence=f"This custom jump list holds a shortcut to {target}.",
                    content_copy=False,
                    how="report",
                    entry=owner.key,
                    reason=REPORT_ONLY_REASONS["custom_jump_list"],
                )
            )


def _mac_putback(
    trash: Path, plan: _Plan
) -> tuple[dict[str, tuple[str, str]] | None, str]:
    """The Trash's put-back records, or None and why they are not available."""
    store = trash / ".DS_Store"
    entry = plan.place("Trash put-back records", store, directory=False)
    if entry.outcome == ABSENT:
        return {}, "the Trash has no .DS_Store"
    if not entry.ok:
        return None, f"its .DS_Store was not read ({entry.detail})"
    data = _read(store, _DS_STORE_LIMIT, whole=True)
    putback = trash_putback(data) if data is not None else None
    if putback is None:
        entry.fail(UNREADABLE, "It is not a .DS_Store this sweep can read.")
        plan.notes.append(
            f"{store} is not a .DS_Store this sweep can read, so no put-back "
            "record in it was used."
        )
        return None, "its .DS_Store could not be read"
    return putback, ""


def _find_mac_trash(
    trash: Path, volume: Path, index: _Index, plan: _Plan, *, label: str = "Trash"
) -> None:
    """macOS Trash items, tied to an erased path by their put-back record.

    Finder records where an item came from in the Trash's ``.DS_Store``: the
    folder (``ptbL``, relative to ``volume``) and the name (``ptbN``). An item
    whose record names an erased path, or a folder that held one, is a copy
    and is erased like a freedesktop Trash copy. An item with no record, or
    whose record names another path, is at most a same-name possible copy and
    is never removed.
    """
    entry = plan.place(label, trash)
    if entry.outcome == PERMISSION_DENIED:
        plan.notes.append(
            f"{trash} could not be listed. macOS lets an application read the "
            "Trash only with Full Disk Access."
        )
    if not entry.ok:
        return
    items = _listdir(trash)
    if items is None:
        entry.fail(UNREADABLE, "It could not be listed.")
        return
    putback, why = _mac_putback(trash, plan)
    store = trash / ".DS_Store"
    names = index.names
    tied: list[tuple[str, Path, Path]] = []
    for item in items:
        if item.name == ".DS_Store":
            continue
        record = putback.get(item.name) if putback else None
        original = _putback_path(volume, *record) if record else None
        erased = names.get(item.name)
        if original is not None:
            if index.owner(original) is not None or index.inside(original):
                tied.append((original, item, store))
            elif erased is not None:
                plan.add(
                    _Found(
                        kind=TraceKind.POSSIBLE_COPY,
                        target=erased.path,
                        location=item,
                        evidence=(
                            "An item of the same name is in the Trash, but its "
                            f"put-back record says it was deleted from {original}, "
                            "not from the erased path. Left in place."
                        ),
                        content_copy=True,
                        exact=False,
                    )
                )
            continue
        if erased is None:
            continue
        missing = why or "it has no put-back record in the Trash's .DS_Store"
        plan.add(
            _Found(
                kind=TraceKind.POSSIBLE_COPY,
                target=erased.path,
                location=item,
                evidence=(
                    f"An item of the same name is in the Trash, and {missing}, "
                    "so nothing ties it to the erased file. It is a possible "
                    "copy and was left in place."
                ),
                content_copy=True,
                exact=False,
            )
        )
    _find_bin_items(
        tied,
        index,
        plan,
        copy_kind=TraceKind.TRASH_COPY,
        record_kind=TraceKind.TRASH_RECORD,
        record_reason=REPORT_ONLY_REASONS["ds_store"],
    )


def _mac_volume_trashes(where: TraceLocations, index: _Index, plan: _Plan) -> None:
    """``$volume/.Trashes/$uid`` on each erased path's volume but the boot one."""
    if where.uid is None:
        return
    for top in _volume_tops(where, index):
        if top == where.mac_trash_volume:
            continue
        trashes = top / ".Trashes"
        if not os.path.lexists(trashes):
            continue
        if not _is_real_dir(trashes):
            plan.notes.append(
                f"{trashes} is not a real directory, so it was not searched."
            )
            continue
        _find_mac_trash(
            trashes / str(where.uid), top, index, plan, label="volume Trash"
        )


def _sfl_files(root: Path, plan: _Plan) -> list[Path]:
    """Shared file lists under ``root``, never through a link, bounded."""
    found: list[Path] = []
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError:
            plan.notes.append(
                f"{directory} could not be listed, so it was not searched."
            )
            continue
        for item in entries:
            if item.is_dir(follow_symlinks=False):
                if depth < _SFL_DEPTH:
                    stack.append((Path(item.path), depth + 1))
            elif item.is_file(follow_symlinks=False) and item.name.endswith(
                _SFL_SUFFIXES
            ):
                if len(found) >= _SFL_FILE_LIMIT:
                    plan.notes.append(
                        f"{root} holds more than {_SFL_FILE_LIMIT:,} shared file "
                        "lists; only the first were searched."
                    )
                    return found
                found.append(Path(item.path))
    return found


def _find_shared_file_lists(root: Path, index: _Index, plan: _Plan) -> None:
    """macOS recent items whose bookmark names an erased path. Report only."""
    if not plan.place("recent items (shared file lists)", root).ok:
        return
    for path in _sfl_files(root, plan):
        data = _read(path, _LIST_LIMIT, whole=True)
        if data is None:
            plan.notes.append(f"{path} could not be read, so it was not searched.")
            continue
        named_paths = shared_file_list_paths(data)
        if named_paths is None:
            plan.notes.append(
                f"{path} is not a binary property list this sweep can read, so "
                "it was not searched."
            )
            continue
        for named in named_paths:
            owner = index.owner(named)
            if owner is None:
                continue
            plan.add(
                _Found(
                    kind=TraceKind.RECENT_ENTRY,
                    target=owner.path,
                    location=path,
                    evidence=f"An item's bookmark in this list names {named}.",
                    content_copy=False,
                    how="report",
                    entry=named,
                    reason=REPORT_ONLY_REASONS["sfl"],
                )
            )


def _find_quicklook(cache: Path, index: _Index, plan: _Plan) -> None:
    """Quick Look cache entries for an erased path. Report only."""
    if not plan.place("Quick Look thumbnail cache", cache).ok:
        return
    database = cache / "index.sqlite"
    entry = plan.place("Quick Look index", database, directory=False)
    if not entry.ok:
        return
    rows, why = quicklook_entries(database)
    if rows is None:
        entry.fail(UNREADABLE, f"It was not searched: {why}.")
        plan.not_searched.append(
            f"The Quick Look thumbnail cache at {database}: {why}, so it was "
            "not searched."
        )
        return
    if len(rows) >= _QUICKLOOK_ROW_LIMIT:
        plan.notes.append(
            f"{database} holds more than {_QUICKLOOK_ROW_LIMIT:,} entries; only "
            "the first were searched."
        )
    log = cache / "index.sqlite-wal"
    try:
        pending = os.lstat(log).st_size > 0
    except OSError:
        pending = False
    if pending:
        plan.notes.append(
            f"{log} holds changes not yet written into index.sqlite. The cache "
            "is opened immutable, so an entry only in that log was not read."
        )
    for path, rowid, thumbnails in rows:
        owner = index.owner(path)
        if owner is None:
            continue
        stored = (
            f", and thumbnails.data holds {thumbnails} thumbnail(s) of it."
            if thumbnails
            else ", with no stored thumbnail recorded for it."
        )
        plan.add(
            _Found(
                kind=TraceKind.QUICKLOOK_THUMBNAIL,
                target=owner.path,
                location=database,
                evidence=f"Row {rowid} of the files table names {path}{stored}",
                content_copy=thumbnails > 0,
                how="report",
                entry=str(rowid),
                reason=REPORT_ONLY_REASONS["quicklook"],
            )
        )


def _find(records: Sequence[FileEraseRecord], where: TraceLocations) -> _Plan:
    index = _Index(records, windows=where.family == "windows")
    plan = _Plan()
    for root in where.thumbnail_roots:
        _find_thumbnails(root, index, plan)
    for recent in where.recent_lists:
        _find_recent_list(recent, index, plan)
    for directory in where.recent_document_dirs:
        _find_recent_documents(directory, index, plan, where.home)
    if where.home_trash is not None and plan.place("home Trash", where.home_trash).ok:
        _find_bin_items(
            _trash_items(where.home_trash, None, plan),
            index,
            plan,
            copy_kind=TraceKind.TRASH_COPY,
            record_kind=TraceKind.TRASH_RECORD,
        )
    for trash, top in _volume_trashes(where, index, plan):
        if plan.place("volume Trash", trash).ok:
            _find_bin_items(
                _trash_items(trash, top, plan),
                index,
                plan,
                copy_kind=TraceKind.TRASH_COPY,
                record_kind=TraceKind.TRASH_RECORD,
            )
    if where.recycle_bin:
        bins: list[Path] = []
        for item in index.roots:
            volume = where.volume_top(item.path)
            if volume is not None and volume / "$Recycle.Bin" not in bins:
                bins.append(volume / "$Recycle.Bin")
        for bin_root in bins:
            if plan.place("Recycle Bin", bin_root).ok:
                _find_bin_items(
                    _recycle_items(bin_root),
                    index,
                    plan,
                    copy_kind=TraceKind.RECYCLE_BIN_COPY,
                    record_kind=TraceKind.RECYCLE_BIN_RECORD,
                )
    for directory in where.recent_shortcut_dirs:
        _find_shortcuts(directory, index, plan)
    for directory in where.jump_list_dirs:
        _find_jump_lists(directory, index, plan)
    for directory in where.custom_jump_list_dirs:
        _find_custom_jump_lists(directory, index, plan)
    if where.mac_trash is not None:
        _find_mac_trash(where.mac_trash, where.mac_trash_volume, index, plan)
        _mac_volume_trashes(where, index, plan)
    for root in where.shared_file_lists:
        _find_shared_file_lists(root, index, plan)
    for cache in where.quicklook_caches:
        _find_quicklook(cache, index, plan)
    return plan


def _as_record(found: _Found) -> TraceRecord:
    report_only = found.exact and found.how == "report"
    return TraceRecord(
        kind=found.kind.value,
        target=found.target,
        location=str(found.location),
        evidence=found.evidence,
        content_copy=found.content_copy,
        exact=found.exact,
        report_only=report_only,
        report_only_reason=found.reason if report_only else "",
    )


def _result(
    plan: _Plan, where: TraceLocations, traces: list[TraceRecord]
) -> TraceSweepResult:
    """The sweep's result: what was inspected, what was not, what was found."""
    return TraceSweepResult(
        searched=plan.searched,
        not_searched=list(NOT_SEARCHED.get(where.family, NOT_SEARCHED["linux"]))
        + list(where.not_located)
        + plan.not_searched,
        traces=traces,
        notes=plan.notes,
        inspected=[
            TraceInspection(
                label=entry.label,
                location=str(entry.location),
                outcome=entry.outcome,
                detail=entry.detail,
            )
            for entry in plan.inspected
        ],
    )


def find_traces(
    records: Sequence[FileEraseRecord], locations: TraceLocations | None = None
) -> TraceSweepResult:
    """Every trace of the erased records, found and left untouched.

    Only records that were erased are looked for: a path the erase refused
    keeps its traces, because it keeps its file.
    """
    where = locations if locations is not None else default_locations()
    plan = _find(records, where)
    return _result(plan, where, [_as_record(found) for found in plan.found])


# --------------------------------------------------------------------------
# Removing
# --------------------------------------------------------------------------


def _erase_trace(location: Path, settings: FileEraseOptions) -> tuple[bool, int, str]:
    """Put one trace file or folder through the same steps as a target."""
    # Imported here because core.erase.files imports this module.
    from core.erase.files import erase_one, expand_targets

    options = FileEraseOptions(
        confirm=True,
        cleanse_metadata=False,
        break_hardlinks=settings.break_hardlinks,
        rename_rounds=settings.rename_rounds,
        workers=1,
    )
    written = 0
    error = ""
    for path in expand_targets([location]):
        try:
            record = erase_one(path, options)
        except (ConfirmationMismatch, SystemDiskRefused) as exc:
            error = error or str(exc)
            continue
        written += record.bytes_overwritten
        if not record.ok and not error:
            error = ": ".join(
                part for part in (record.error_kind, record.error) if part
            )
    removed = not os.path.lexists(location)
    if not removed and not error:
        error = f"{location} was still present after the erase."
    return removed, written, error


def _overwrite_in_place(path: Path, content: bytes, *, expected: os.stat_result) -> str:
    """Replace a list's bytes where they lie, padded to its old length.

    Writing a new file and renaming it over the old one would free the old
    blocks with the removed entries still in them. Writing in place, and
    padding with whitespace rather than truncating, puts new bytes over every
    byte that held them. XML allows whitespace after the root element, so the
    list still parses; the desktop drops the padding the next time it saves.
    Returns an error, or an empty string.
    """
    flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        return f"{path} could not be opened for writing: {exc.strerror}."
    try:
        info = os.fstat(fd)
        if (info.st_ino, info.st_size, info.st_mtime_ns) != (
            expected.st_ino,
            expected.st_size,
            expected.st_mtime_ns,
        ):
            return (
                f"{path} changed while the sweep was reading it, so it was left "
                "as it is. Close the applications that use it and erase again."
            )
        padding = info.st_size - len(content)
        body = content + (b" " * (padding - 1) + b"\n" if padding > 0 else b"")
        os.lseek(fd, 0, os.SEEK_SET)
        view = memoryview(body)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
    except OSError as exc:
        return f"{path} could not be rewritten: {exc.strerror}."
    finally:
        os.close(fd)
    return ""


def _remove_entries(path: Path, hrefs: set[str]) -> str:
    """Cut the entries for ``hrefs`` out of a recent-files list. Returns an error."""
    try:
        before_stat = os.lstat(path)
    except OSError as exc:
        return f"{path} could not be read: {exc.strerror}."
    data = _read(path, _LIST_LIMIT, whole=True)
    if data is None:
        return f"{path} could not be read in full."
    removed = 0

    def cut(match: re.Match[bytes]) -> bytes:
        nonlocal removed
        href = html.unescape(match.group(2).decode("utf-8", "surrogateescape"))
        if href in hrefs:
            removed += 1
            return b""
        return match.group(0)

    rewritten = _XBEL_BOOKMARK.sub(cut, data)
    refused = (
        f"The entry could not be cut out of {path} without disturbing the "
        "rest of the list, so the list was left as it is."
    )
    try:
        before = [item.get("href") for item in ET.fromstring(data).iter("bookmark")]
        after = [item.get("href") for item in ET.fromstring(rewritten).iter("bookmark")]
    except ET.ParseError:
        return refused
    wanted = sum(1 for href in before if href in hrefs)
    if (
        not wanted
        or removed != wanted
        or len(after) != len(before) - wanted
        or any(href in hrefs for href in after)
    ):
        return refused
    return _overwrite_in_place(path, rewritten, expected=before_stat)


def _progress(job_id: str, message: str) -> Progress:
    return Progress(
        job_id=job_id,
        phase=PHASE,
        pct_bp=10_000,
        bytes_done=0,
        bytes_total=0,
        throughput_bytes_per_sec=0,
        eta_seconds=0,
        message=message,
    )


def sweep(
    records: Sequence[FileEraseRecord],
    settings: FileEraseOptions,
    *,
    job_id: str,
    ledger: LedgerSink,
    locations: TraceLocations | None = None,
) -> Generator[Progress, None, TraceSweepResult]:
    """Find the traces of the erased records and, on a real run, remove the exact ones.

    Every trace gets an ``erase.file.trace`` entry as it is dealt with, so a
    sweep closed part-way has left a record of each one it reached, and the
    sweep ends with one ``erase.file.traces`` entry naming every place it
    searched - so a sweep that found nothing is distinguishable from one that
    never ran.
    """
    where = locations if locations is not None else default_locations()
    plan = _find(records, where)
    yield _progress(
        job_id,
        f"{len(plan.found)} trace(s) found in {len(plan.searched)} place(s)",
    )

    lists: dict[Path, str] = {}
    kept: set[Path] = set()
    #: Trace files already put through the erase, with the outcome: a jump
    #: list tied to two erased paths is one file, erased once.
    erased: dict[Path, tuple[bool, str]] = {}
    traces: list[TraceRecord] = []
    for found in plan.found:
        trace = _as_record(found)
        if found.exact and found.how != "report":
            if found.pair is not None and found.pair in kept:
                trace.error = (
                    "Kept, because the copy it describes could not be removed; "
                    "without it the copy would be hidden in the Trash."
                )
            elif found.how == "list":
                if found.location not in lists:
                    hrefs = {
                        other.entry
                        for other in plan.found
                        if other.exact
                        and other.how == "list"
                        and other.location == found.location
                    }
                    lists[found.location] = _remove_entries(found.location, hrefs)
                trace.error = lists[found.location]
                trace.removed = not trace.error
                trace.action = "entry removed" if trace.removed else ""
            elif found.location in erased:
                trace.removed, trace.error = erased[found.location]
                trace.action = "erased" if trace.removed else ""
            else:
                removed, written, error = _erase_trace(found.location, settings)
                erased[found.location] = (removed, error)
                trace.removed = removed
                trace.bytes_overwritten = written
                trace.error = error
                trace.action = "erased" if removed else ""
                if not removed:
                    kept.add(found.location)
        ledger.record_file(
            "trace",
            {"job_id": job_id} | trace.model_dump(mode="json"),
        )
        traces.append(trace)
        yield _progress(job_id, f"{trace.kind} {trace.location}")

    result = _result(plan, where, traces)
    ledger.record_file(
        "traces",
        {
            "job_id": job_id,
            "searched": result.searched,
            "inspected": [entry.model_dump(mode="json") for entry in result.inspected],
            "not_searched": result.not_searched,
            "found": len(traces),
            "exact": sum(1 for trace in traces if trace.exact),
            "removed": sum(1 for trace in traces if trace.removed),
            "report_only": sum(1 for trace in traces if trace.report_only),
            "notes": result.notes,
        },
    )
    logger.info(
        "trace_sweep_complete",
        job_id=job_id,
        found=len(traces),
        removed=sum(1 for trace in traces if trace.removed),
    )
    return result
