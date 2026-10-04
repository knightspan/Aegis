"""Synthetic desktop profiles and byte-level trace artifacts for the sweep tests.

Every builder here writes under a directory the test owns (``tmp_path``), and
every artifact is packed from its format's description, byte for byte:

* a Finder ``.DS_Store`` (the "Bud1" buddy allocator and its B-tree);
* a macOS bookmark (``book``) and the NSKeyedArchiver binary plist a
  ``.sfl2``/``.sfl3`` shared file list wraps it in;
* a Quick Look ``index.sqlite``;
* an OLE compound file (CFB v3) holding a Windows jump list's streams, and a
  ``*.customDestinations-ms`` list of back-to-back shortcuts.

The profile builders lay out a home directory as each operating system does -
Windows' ``AppData\\Roaming\\Microsoft\\Windows\\Recent`` with a fake drive root
holding ``$Recycle.Bin``, the macOS ``~/.Trash`` and ``Library/Application
Support``, the XDG directories - and return the locations
:func:`core.erase.traces.locations_for` builds for them. Nothing reads the
home directory of whoever runs the suite.
"""

from __future__ import annotations

import plistlib
import sqlite3
import struct
from dataclasses import dataclass
from pathlib import Path

from core.erase import traces

# --------------------------------------------------------------------------
# .DS_Store
# --------------------------------------------------------------------------

#: One record value: (four-byte type code, value).
DsValue = tuple[bytes, object]


def ds_record(name: str, structure: bytes, kind: bytes, value: object) -> bytes:
    """One B-tree record: name, structure id, type code, typed value."""
    encoded = name.encode("utf-16-be")
    head = struct.pack(">I", len(encoded) // 2) + encoded + structure + kind
    if kind == b"ustr":
        assert isinstance(value, str)
        text = value.encode("utf-16-be")
        return head + struct.pack(">I", len(text) // 2) + text
    if kind in (b"long", b"shor"):
        assert isinstance(value, int)
        return head + struct.pack(">I", value)
    if kind == b"bool":
        assert isinstance(value, int)
        return head + bytes([value])
    if kind == b"blob":
        assert isinstance(value, bytes)
        return head + struct.pack(">I", len(value)) + value
    if kind in (b"type", b"comp", b"dutc"):
        assert isinstance(value, bytes)
        return head + value
    raise ValueError(kind)


def putback_records(name: str, folder: str, original: str) -> list[bytes]:
    """``ptbL`` and ``ptbN`` for one Trash item, and the records Finder adds."""
    return [
        ds_record(name, b"Iloc", b"blob", b"\x00" * 16),
        ds_record(name, b"ptbL", b"ustr", folder),
        ds_record(name, b"ptbN", b"ustr", original),
        ds_record(name, b"modD", b"dutc", b"\x00" * 8),
        ds_record(name, b"vSrn", b"long", 1),
    ]


def _block_size(length: int) -> tuple[int, int]:
    """The smallest power-of-two block (at least 32 bytes) that holds ``length``."""
    exponent = 5
    while (1 << exponent) < length:
        exponent += 1
    return exponent, 1 << exponent


def ds_store(records: list[bytes], *, fanout: int | None = None) -> bytes:
    """A ``.DS_Store``: a buddy allocator whose DSDB tree holds ``records``.

    ``records`` must already be in the tree's order. With ``fanout``, the
    records are split into leaves of that many, joined by one internal node,
    so the walk down a two-level tree is exercised.
    """
    blocks: list[bytes] = []  # block 0 is the allocator's own root block

    def add(body: bytes) -> int:
        blocks.append(body)
        return len(blocks)  # the number it will have once block 0 is prepended

    if fanout is None:
        root_node = add(struct.pack(">II", 0, len(records)) + b"".join(records))
        levels, nodes = 0, 1
    else:
        # Leaves hold ``fanout`` records each; one record separates each pair.
        groups: list[list[bytes]] = []
        separators: list[bytes] = []
        rest = list(records)
        while rest:
            group, rest = rest[:fanout], rest[fanout:]
            if len(rest) > 1:
                separators.append(rest.pop(0))
            else:
                group, rest = group + rest, []
            groups.append(group)
        leaves = [
            add(struct.pack(">II", 0, len(group)) + b"".join(group)) for group in groups
        ]
        body = b""
        for leaf, separator in zip(leaves[:-1], separators, strict=True):
            body += struct.pack(">I", leaf) + separator
        root_node = add(struct.pack(">II", leaves[-1], len(separators)) + body)
        levels, nodes = 1, len(leaves) + 1
    master = add(struct.pack(">5I", root_node, levels, len(records), nodes, 0x1000))

    # Lay the blocks out after the 32-byte header area, each at an offset that
    # is a multiple of its own size, as the buddy allocator places them.
    def layout(root_body_size: int) -> tuple[list[int], int]:
        addresses: list[int] = []
        offset = 0x20
        sizes = [root_body_size] + [len(body) for body in blocks]
        for length in sizes:
            exponent, size = _block_size(length)
            offset = (offset + size - 1) // size * size
            addresses.append(offset | exponent)
            offset += size
        return addresses, offset

    count = len(blocks) + 1
    toc = b"\x04DSDB" + struct.pack(">I", master)
    root_body_size = 8 + 4 * ((count + 255) // 256 * 256) + 4 + len(toc) + 32 * 4
    addresses, end = layout(root_body_size)
    table = [*addresses, *([0] * (-count % 256))]
    root_body = (
        struct.pack(">II", count, 0)
        + struct.pack(f">{len(table)}I", *table)
        + struct.pack(">I", 1)
        + toc
        + struct.pack(">I", 0) * 32  # 32 empty free lists
    )
    assert len(root_body) == root_body_size
    image = bytearray(end + 4)
    root_offset = addresses[0] & ~0x1F
    header = struct.pack(
        ">I4sIII", 1, b"Bud1", root_offset, root_body_size, root_offset
    )
    image[0 : len(header)] = header
    for address, body in zip(addresses, [root_body, *blocks], strict=True):
        start = 4 + (address & ~0x1F)
        image[start : start + len(body)] = body
    return bytes(image)


class MacTrash:
    """A macOS Trash folder whose ``.DS_Store`` records each item's origin."""

    def __init__(self, folder: Path, *, volume: Path = Path("/")) -> None:
        self.folder = folder
        self.volume = volume
        self.putback: dict[str, tuple[str, str]] = {}
        folder.mkdir(parents=True, exist_ok=True)

    def add(
        self,
        name: str,
        deleted_from: Path | str,
        content: bytes | None,
        *,
        original_name: str | None = None,
    ) -> Path:
        """An item, and its put-back record merged into the ``.DS_Store``."""
        copy = self.folder / name
        if content is not None:
            copy.write_bytes(content)
        location = str(Path(deleted_from).relative_to(self.volume)) + "/"
        self.putback[name] = (location, original_name or name)
        self.write()
        return copy

    def write(self, *, fanout: int | None = None) -> Path:
        records: list[bytes] = []
        for name in sorted(self.putback):
            location, original = self.putback[name]
            records.extend(putback_records(name, location, original))
        store = self.folder / ".DS_Store"
        store.write_bytes(ds_store(records, fanout=fanout))
        return store


# --------------------------------------------------------------------------
# Bookmarks and shared file lists
# --------------------------------------------------------------------------


def bookmark(path: str, *, component_type: int = 0x0101) -> bytes:
    """A macOS bookmark whose TOC's 0x1004 entry lists the path's components."""
    parts = [part for part in path.split("/") if part]
    data = bytearray(b"\x00\x00\x00\x00")  # the first TOC's offset, patched below
    offsets: list[int] = []
    for part in parts:
        encoded = part.encode("utf-8")
        offsets.append(len(data))
        data += struct.pack("<II", len(encoded), component_type) + encoded
        data += b"\x00" * (-len(data) % 4)
    array_offset = len(data)
    data += struct.pack("<II", 4 * len(offsets), 0x0601)
    data += struct.pack(f"<{len(offsets)}I", *offsets)
    # A second entry, a volume path string, as Finder writes one.
    volume = b"/"
    volume_offset = len(data)
    data += struct.pack("<II", len(volume), 0x0101) + volume
    data += b"\x00" * (-len(data) % 4)
    toc_offset = len(data)
    entries = [(0x1004, array_offset), (0x2002, volume_offset)]
    data += struct.pack(
        "<5I", 20 + 12 * len(entries) - 8, 0xFFFFFFFE, 1, 0, len(entries)
    )
    for key, offset in entries:
        data += struct.pack("<3I", key, offset, 0)
    struct.pack_into("<I", data, 0, toc_offset)
    header_size = 0x30
    total = header_size + len(data)
    header = struct.pack("<4sIII", b"book", total, 0x10040000, header_size)
    return header + b"\x00" * (header_size - len(header)) + bytes(data)


def shared_file_list(bookmarks: list[bytes], *, wrap_data: bool = False) -> bytes:
    """An NSKeyedArchiver binary plist of shared-file-list items with bookmarks."""
    objects: list[object] = ["$null"]
    root = {"items": plistlib.UID(2), "properties": plistlib.UID(3)}
    objects.append(root)
    item_refs = []
    objects.append({"NS.objects": item_refs, "$class": plistlib.UID(4)})
    objects.append({"NS.keys": [], "NS.objects": [], "$class": plistlib.UID(4)})
    objects.append({"$classname": "NSArray", "$classes": ["NSArray", "NSObject"]})
    for blob in bookmarks:
        objects.append(blob if not wrap_data else {"NS.data": blob})
        blob_ref = plistlib.UID(len(objects) - 1)
        objects.append({"Bookmark": blob_ref, "uuid": plistlib.UID(0)})
        item_refs.append(plistlib.UID(len(objects) - 1))
    archive = {
        "$archiver": "NSKeyedArchiver",
        "$version": 100000,
        "$top": {"root": plistlib.UID(1)},
        "$objects": objects,
    }
    return plistlib.dumps(archive, fmt=plistlib.FMT_BINARY)


# --------------------------------------------------------------------------
# Quick Look
# --------------------------------------------------------------------------


def quicklook_index(
    cache: Path, rows: list[tuple[str, str, int]], *, schema: str = "known"
) -> Path:
    """A Quick Look ``index.sqlite``: ``(folder, file name, thumbnails)`` rows."""
    cache.mkdir(parents=True, exist_ok=True)
    database = cache / "index.sqlite"
    connection = sqlite3.connect(database)
    try:
        if schema == "known":
            connection.execute(
                "CREATE TABLE files (folder TEXT, file_name TEXT, version BLOB)"
            )
            connection.execute(
                "CREATE TABLE thumbnails (file_id INTEGER, size INTEGER, "
                "bitmapdata_location INTEGER, bitmapdata_length INTEGER)"
            )
            for folder, name, count in rows:
                cursor = connection.execute(
                    "INSERT INTO files (folder, file_name, version) VALUES (?, ?, ?)",
                    (folder, name, b"v"),
                )
                for number in range(count):
                    connection.execute(
                        "INSERT INTO thumbnails VALUES (?, ?, ?, ?)",
                        (cursor.lastrowid, 64 << number, 0, 4096),
                    )
        else:
            connection.execute("CREATE TABLE entries (url TEXT, blob BLOB)")
        connection.commit()
    finally:
        connection.close()
    (cache / "thumbnails.data").write_bytes(b"\x00" * 4096)
    return database


# --------------------------------------------------------------------------
# Compound files and jump lists
# --------------------------------------------------------------------------

_SECTOR = 512
_FREESECT = 0xFFFFFFFF
_ENDOFCHAIN = 0xFFFFFFFE
_FATSECT = 0xFFFFFFFD
_NOSTREAM = 0xFFFFFFFF


def _dir_entry(
    name: str,
    kind: int,
    *,
    child: int = _NOSTREAM,
    right: int = _NOSTREAM,
    start: int = _ENDOFCHAIN,
    size: int = 0,
) -> bytes:
    encoded = (name + "\x00").encode("utf-16-le") if name else b""
    return (
        encoded.ljust(64, b"\x00")
        + struct.pack("<HBB", len(encoded), kind, 1)
        + struct.pack("<III", _NOSTREAM, right, child)
        + b"\x00" * 16  # CLSID
        + b"\x00" * 4  # state bits
        + b"\x00" * 16  # creation and modified times
        + struct.pack("<IQ", start, size)
    )


def compound_file(streams: dict[str, bytes]) -> bytes:
    """An OLE compound file (CFB version 3) holding ``streams`` at its root.

    Each stream is padded to the 4,096-byte mini-stream cutoff so it lives in
    regular sectors, which keeps the writer to the FAT alone. The siblings are
    chained through their right pointers in CFB name order (length, then
    upper case), which a reader walks as a valid binary search tree.
    """
    names = sorted(streams, key=lambda name: (len(name), name.upper()))
    bodies = [streams[name].ljust(4096, b"\x00") for name in names]
    stream_sectors = [-(-len(body) // _SECTOR) for body in bodies]
    entries = 1 + len(names)
    dir_sectors = -(-entries // 4)
    data_sectors = dir_sectors + sum(stream_sectors)
    fat_sectors = 1
    while fat_sectors * 128 < fat_sectors + data_sectors:
        fat_sectors += 1
    assert fat_sectors <= 109

    fat: list[int] = [_FATSECT] * fat_sectors
    first_dir = len(fat)
    for number in range(dir_sectors):
        fat.append(first_dir + number + 1 if number < dir_sectors - 1 else _ENDOFCHAIN)
    starts: list[int] = []
    for count in stream_sectors:
        start = len(fat)
        starts.append(start)
        for number in range(count):
            fat.append(start + number + 1 if number < count - 1 else _ENDOFCHAIN)
    fat += [_FREESECT] * (fat_sectors * 128 - len(fat))

    directory = _dir_entry("Root Entry", 5, child=1 if names else _NOSTREAM)
    for number, (name, body) in enumerate(zip(names, bodies, strict=True)):
        right = number + 2 if number + 1 < len(names) else _NOSTREAM
        directory += _dir_entry(
            name, 2, right=right, start=starts[number], size=len(body)
        )
    directory = directory.ljust(dir_sectors * _SECTOR, b"\x00")
    # Unused directory slots are empty entries whose pointers are NOSTREAM.
    for slot in range(entries, dir_sectors * 4):
        empty = _dir_entry("", 0)
        directory = directory[: slot * 128] + empty + directory[(slot + 1) * 128 :]

    difat = list(range(fat_sectors)) + [_FREESECT] * (109 - fat_sectors)
    header = (
        bytes.fromhex("d0cf11e0a1b11ae1")
        + b"\x00" * 16
        + struct.pack("<HHHHH", 0x003E, 0x0003, 0xFFFE, 9, 6)
        + b"\x00" * 6
        + struct.pack(
            "<IIIIIIIII",
            0,
            fat_sectors,
            first_dir,
            0,
            0x1000,
            _ENDOFCHAIN,
            0,
            _ENDOFCHAIN,
            0,
        )
        + struct.pack("<109I", *difat)
    )
    assert len(header) == _SECTOR
    body = struct.pack(f"<{len(fat)}I", *fat) + directory
    for data, count in zip(bodies, stream_sectors, strict=True):
        body += data.ljust(count * _SECTOR, b"\x00")
    return header + body


def automatic_destinations(links: list[bytes]) -> bytes:
    """A jump list: numbered hex streams of shortcuts, and a DestList index."""
    streams = {f"{number + 1:x}": link for number, link in enumerate(links)}
    streams["DestList"] = struct.pack("<IIII", 4, len(links), 0, 0)
    return compound_file(streams)


def custom_destinations(links: list[bytes]) -> bytes:
    """A custom jump list: a header, the shortcuts back to back, a footer."""
    header = struct.pack("<III", 2, 1, 0) + struct.pack("<I", len(links))
    return header + b"".join(links) + b"\xab\xfb\xbf\xba"


# --------------------------------------------------------------------------
# Profiles
# --------------------------------------------------------------------------


@dataclass
class WindowsProfile:
    drive: Path
    home: Path
    appdata: Path
    recent: Path
    automatic: Path
    custom: Path
    recycle_bin: Path
    locations: traces.TraceLocations


def windows_profile(root: Path, user: str = "Asha") -> WindowsProfile:
    """A ``C:`` drive under ``root``: the user's profile and ``$Recycle.Bin``."""
    drive = root / "C"
    home = drive / "Users" / user
    appdata = home / "AppData" / "Roaming"
    recent = appdata / "Microsoft" / "Windows" / "Recent"
    automatic = recent / "AutomaticDestinations"
    custom = recent / "CustomDestinations"
    recycle_bin = drive / "$Recycle.Bin" / "S-1-5-21-1111-2222-3333-1001"
    for folder in (automatic, custom, recycle_bin):
        folder.mkdir(parents=True)
    (home / "AppData" / "Local" / "Microsoft" / "Windows" / "Explorer").mkdir(
        parents=True
    )
    locations = traces.locations_for(
        "windows",
        {"APPDATA": str(appdata), "LOCALAPPDATA": str(home / "AppData" / "Local")},
        home,
        volume_top=lambda _path: drive,
    )
    return WindowsProfile(
        drive, home, appdata, recent, automatic, custom, recycle_bin, locations
    )


@dataclass
class MacProfile:
    home: Path
    trash: Path
    sharedfilelist: Path
    tmpdir: Path
    quicklook: Path
    locations: traces.TraceLocations


def mac_profile(root: Path, user: str = "asha", *, uid: int = 501) -> MacProfile:
    """A macOS home under ``root``, and the per-user ``/var/folders`` tree."""
    home = root / "Users" / user
    trash = home / ".Trash"
    sharedfilelist = (
        home / "Library" / "Application Support" / "com.apple.sharedfilelist"
    )
    tmpdir = root / "var" / "folders" / "xy" / "abc123" / "T"
    quicklook = tmpdir.parent / "C" / "com.apple.QuickLook.thumbnailcache"
    for folder in (trash, sharedfilelist, tmpdir):
        folder.mkdir(parents=True)
    locations = traces.locations_for(
        "macos",
        {"TMPDIR": str(tmpdir) + "/"},
        home,
        uid=uid,
        volume_top=lambda _path: Path("/"),
    )
    return MacProfile(home, trash, sharedfilelist, tmpdir, quicklook, locations)


@dataclass
class LinuxProfile:
    home: Path
    data: Path
    cache: Path
    locations: traces.TraceLocations


def linux_profile(
    root: Path, *, uid: int = 1000, volume: Path | None = None
) -> LinuxProfile:
    """An XDG home under ``root``, with XDG_DATA_HOME and XDG_CACHE_HOME set."""
    home = root / "home" / "asha"
    data = root / "xdg-data"
    cache = root / "xdg-cache"
    for folder in (home, data, cache):
        folder.mkdir(parents=True)
    locations = traces.locations_for(
        "linux",
        {"XDG_DATA_HOME": str(data), "XDG_CACHE_HOME": str(cache)},
        home,
        uid=uid,
        # No volume unless the test names one: the host's mounts are never walked.
        volume_top=lambda _path: volume,
    )
    return LinuxProfile(home, data, cache, locations)
