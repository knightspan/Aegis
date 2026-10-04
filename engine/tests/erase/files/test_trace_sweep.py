"""The trace sweep finds what the desktop kept of an erased file, and removes it.

Every home, cache, Trash and Recycle Bin here is synthetic and built under
``tmp_path``: thumbnails are real PNGs carrying ``Thumb::URI``, the recent list
is XBEL as GTK writes it, and the ``$I`` records and ``.lnk`` shortcuts are
packed byte for byte from their specifications. Nothing reads the home
directory of whoever runs the suite.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import struct
import sys
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from core.erase import traces
from core.erase.files import erase_paths
from core.models import FileEraseRecord, FileInspection, TraceSweepResult

from .conftest import drain, posix_only, real_erase

# --------------------------------------------------------------------------
# Synthetic desktop artifacts
# --------------------------------------------------------------------------


def _chunk(kind: bytes, body: bytes) -> bytes:
    return (
        struct.pack(">I", len(body))
        + kind
        + body
        + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)
    )


def png(uri: str | None) -> bytes:
    """A 1x1 greyscale PNG, with ``Thumb::URI`` when ``uri`` is given."""
    parts = [
        b"\x89PNG\r\n\x1a\n",
        _chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)),
    ]
    if uri is not None:
        parts.append(_chunk(b"tEXt", b"Thumb::URI\x00" + uri.encode("latin-1")))
        parts.append(_chunk(b"tEXt", b"Thumb::MTime\x001790000000"))
    parts.append(_chunk(b"IDAT", zlib.compress(b"\x00\x7f")))
    parts.append(_chunk(b"IEND", b""))
    return b"".join(parts)


def glib_uri(path: Path | str) -> str:
    return traces.file_uris(str(path))[0]


def thumbnail(
    home: Path, path: Path | str, *, size: str = "normal", uri: str | None = None
) -> Path:
    """A thumbnail for ``path``, named by the MD5 of its URI as the spec says."""
    named = uri or glib_uri(path)
    directory = home / ".cache" / "thumbnails" / size
    directory.mkdir(parents=True, exist_ok=True)
    name = hashlib.md5(named.encode("ascii"), usedforsecurity=False).hexdigest()
    target = directory / f"{name}.png"
    target.write_bytes(png(named))
    return target


XBEL_HEAD = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<xbel version="1.0"\n'
    '      xmlns:bookmark="http://www.freedesktop.org/standards/desktop-bookmarks"\n'
    '      xmlns:mime="http://www.freedesktop.org/standards/shared-mime-info"\n'
    ">\n"
)


def xbel_entry(href: str) -> str:
    return (
        f'  <bookmark href="{href}" added="2026-09-01T10:00:00.000000Z" '
        'modified="2026-09-01T10:00:00.000000Z" '
        'visited="2026-09-01T10:00:00.000000Z">\n'
        "    <info>\n"
        '      <metadata owner="http://freedesktop.org">\n'
        '        <mime:mime-type type="image/jpeg"/>\n'
        "        <bookmark:applications>\n"
        '          <bookmark:application name="Image Viewer" exec="&apos;eog %u&apos;" '
        'modified="2026-09-01T10:00:00.000000Z" count="1"/>\n'
        "        </bookmark:applications>\n"
        "      </metadata>\n"
        "    </info>\n"
        "  </bookmark>\n"
    )


def recent_list(home: Path, hrefs: list[str]) -> Path:
    target = home / ".local" / "share" / "recently-used.xbel"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        XBEL_HEAD + "".join(xbel_entry(href) for href in hrefs) + "</xbel>",
        encoding="utf-8",
    )
    return target


def trash_item(
    trash: Path, name: str, recorded_path: str, content: bytes | None
) -> tuple[Path, Path]:
    """A freedesktop Trash item: the copy under files/, the record under info/."""
    (trash / "files").mkdir(parents=True, exist_ok=True)
    (trash / "info").mkdir(parents=True, exist_ok=True)
    copy = trash / "files" / name
    if content is not None:
        copy.write_bytes(content)
    info = trash / "info" / f"{name}.trashinfo"
    info.write_text(
        "[Trash Info]\n"
        f"Path={quote(recorded_path)}\n"
        "DeletionDate=2026-09-20T11:22:33\n",
        encoding="utf-8",
    )
    return copy, info


def recycle_i_record(path: str, size: int, *, version: int = 2) -> bytes:
    """A ``$I`` record as Windows writes it."""
    head = struct.pack("<qqq", version, size, 133_000_000_000_000_000)
    encoded = (path + "\x00").encode("utf-16-le")
    if version == 1:
        return head + encoded.ljust(520, b"\x00")
    return head + struct.pack("<i", len(path) + 1) + encoded


def shell_link(target: str, *, wide: bool = False) -> bytes:
    """A minimal [MS-SHLLINK] file: header, then a LinkInfo naming ``target``."""
    header = bytearray(0x4C)
    struct.pack_into("<I", header, 0, 0x4C)
    header[4:20] = bytes.fromhex("0114020000000000c000000000000046")
    struct.pack_into("<I", header, 0x14, 0x2)  # HasLinkInfo only
    volume = struct.pack("<IIII", 0x10, 3, 0x1234, 0x10)
    header_size = 0x24 if wide else 0x1C
    base_offset = header_size + len(volume)
    ansi = target.encode("cp1252", errors="replace") + b"\x00"
    suffix_offset = base_offset + len(ansi)
    tail = ansi + b"\x00"
    wide_base = wide_suffix = 0
    if wide:
        wide_base = suffix_offset + 1
        encoded = (target + "\x00").encode("utf-16-le")
        wide_suffix = wide_base + len(encoded)
        tail += encoded + b"\x00\x00"
    fields = struct.pack(
        "<IIIIIII",
        0,  # size, patched below
        header_size,
        0x1,  # VolumeIDAndLocalBasePath
        header_size,  # VolumeIDOffset
        base_offset,
        0,
        suffix_offset,
    )
    if wide:
        fields += struct.pack("<II", wide_base, wide_suffix)
    info = bytearray(fields + volume + tail)
    struct.pack_into("<I", info, 0, len(info))
    return bytes(header) + bytes(info)


class Recorder:
    """A ledger sink that keeps what it is given."""

    def __init__(self) -> None:
        self.entries: list[tuple[str, dict[str, Any]]] = []

    def record(self, phase: Any, operation: str, payload: dict[str, Any]) -> None:
        self.entries.append((operation, payload))

    def last_checkpoint(self, job_id: str) -> None:
        return None

    def record_file(self, operation: str, payload: dict[str, Any]) -> None:
        self.entries.append((operation, payload))


@pytest.fixture
def home(tmp_path: Path) -> Path:
    made = tmp_path / "home"
    made.mkdir()
    return made


@pytest.fixture
def where(home: Path, monkeypatch: pytest.MonkeyPatch) -> traces.TraceLocations:
    """Linux locations under the synthetic home, with no volume Trash walk.

    The freedesktop places record ``file://`` URIs of POSIX paths. On Windows
    the host selects the Recycle Bin and shortcut places instead, so a Linux
    sweep over NT paths is a pairing no run can reach.
    """
    if sys.platform == "win32":
        pytest.skip("freedesktop places name POSIX paths; this host is Windows")
    locations = traces.locations_for("linux", {}, home)
    monkeypatch.setattr(traces, "default_locations", lambda: locations)
    return locations


@pytest.fixture
def photo(tmp_path: Path) -> Path:
    """The file being erased. Its name needs escaping in a URI."""
    folder = tmp_path / "work"
    folder.mkdir()
    target = folder / "Q3 plan (draft) é.jpg"
    target.write_bytes(b"\xff\xd8\xff" + b"J" * 4093)
    return target


def erase(
    paths: list[Path], *, find_only: bool = False, ledger: Recorder | None = None
) -> TraceSweepResult:
    """Erase ``paths`` and sweep, or - ``find_only`` - only search, read-only.

    ``find_only`` goes through :func:`core.erase.traces.find_traces`, the
    read-only search, with records that say each path was erased. Nothing is
    erased and no trace is removed; it is not a mode of the erase.
    """
    if find_only:
        from core.erase.inspect import inspect_path

        return traces.find_traces(
            [
                FileEraseRecord(
                    path=str(path),
                    ok=True,
                    unlinked=True,
                    inspection=inspect_path(path),
                )
                for path in paths
            ]
        )
    options = real_erase(workers=1, sweep_traces=True)
    _, result = drain(
        erase_paths(paths, options, job_id="sweep-1", ledger=ledger or Recorder())
    )
    assert result.trace_sweep is not None
    return result.trace_sweep


def only(sweep: TraceSweepResult, kind: traces.TraceKind) -> list[Any]:
    return [trace for trace in sweep.traces if trace.kind == kind.value]


# --------------------------------------------------------------------------
# Thumbnails
# --------------------------------------------------------------------------


def test_a_thumbnail_named_by_the_md5_of_the_uri_is_found_and_erased(
    home: Path, where: traces.TraceLocations, photo: Path
) -> None:
    cached = thumbnail(home, photo, size="large")

    sweep = erase([photo])

    (trace,) = only(sweep, traces.TraceKind.THUMBNAIL)
    assert trace.target == str(photo)
    assert trace.location == str(cached)
    assert trace.exact and trace.content_copy
    assert "Thumb::URI names the same file" in trace.evidence
    assert trace.removed and trace.action == "erased"
    assert trace.bytes_overwritten > 0
    assert not cached.exists(), "the thumbnail is a copy of the picture"


@pytest.mark.parametrize(
    "safe",
    ["!$&'()*+,-./:=@_~", "!$&'()*+,;=:@/-._~", "/"],
    ids=["glib", "rfc3986-pchar", "strict"],
)
def test_each_uri_encoding_a_desktop_may_have_hashed_is_tried(
    home: Path, where: traces.TraceLocations, tmp_path: Path, safe: str
) -> None:
    """The MD5 changes with the encoding, so each encoder's form is looked up."""
    target = tmp_path / "work" / "a;b=c,d@e (1).png"
    target.parent.mkdir()
    target.write_bytes(b"\x89PNG" + b"x" * 60)
    uri = "file://" + quote(os.fsencode(str(target)), safe=safe)
    cached = thumbnail(home, target, uri=uri)

    sweep = erase([target], find_only=True)

    assert [trace.location for trace in only(sweep, traces.TraceKind.THUMBNAIL)] == [
        str(cached)
    ]


def test_a_failed_thumbnail_marker_is_a_mention_not_a_copy(
    home: Path, where: traces.TraceLocations, photo: Path
) -> None:
    uri = glib_uri(photo)
    marker_dir = home / ".cache" / "thumbnails" / "fail" / "gnome-thumbnail-factory"
    marker_dir.mkdir(parents=True)
    name = hashlib.md5(uri.encode("ascii"), usedforsecurity=False).hexdigest()
    (marker_dir / f"{name}.png").write_bytes(png(uri))

    sweep = erase([photo])

    (trace,) = only(sweep, traces.TraceKind.THUMBNAIL_FAILURE)
    assert trace.content_copy is False
    assert trace.removed


def test_a_thumbnail_whose_uri_names_another_file_is_left_in_place(
    home: Path, where: traces.TraceLocations, photo: Path
) -> None:
    """A name match contradicted by the file's own Thumb::URI is not evidence."""
    directory = home / ".cache" / "thumbnails" / "normal"
    directory.mkdir(parents=True)
    name = hashlib.md5(glib_uri(photo).encode(), usedforsecurity=False).hexdigest()
    cached = directory / f"{name}.png"
    cached.write_bytes(png("file:///somewhere/else.jpg"))

    sweep = erase([photo])

    (trace,) = only(sweep, traces.TraceKind.THUMBNAIL)
    assert trace.exact is False
    assert trace.removed is False and trace.action == ""
    assert cached.exists()


def test_a_folder_erase_finds_thumbnails_of_files_it_used_to_hold(
    home: Path, where: traces.TraceLocations, tmp_path: Path
) -> None:
    """A file deleted from the folder long ago left a thumbnail naming it."""
    folder = tmp_path / "album"
    folder.mkdir()
    (folder / "kept.jpg").write_bytes(b"\xff\xd8" + b"k" * 100)
    gone = thumbnail(home, folder / "deleted-last-year.jpg")
    unrelated = thumbnail(home, tmp_path / "elsewhere.jpg")

    sweep = erase([folder])

    found = only(sweep, traces.TraceKind.THUMBNAIL)
    assert [trace.location for trace in found] == [str(gone)]
    assert found[0].target == str(folder)
    assert "inside the erased folder" in found[0].evidence
    assert not gone.exists()
    assert unrelated.exists(), "a thumbnail of a file outside the folder stays"


@posix_only
def test_a_thumbnail_that_is_a_link_is_not_followed(
    home: Path, where: traces.TraceLocations, photo: Path, tmp_path: Path
) -> None:
    """The erase refuses a link by name. Following it would erase what it points at."""
    outside = tmp_path / "precious.txt"
    outside.write_bytes(b"not a thumbnail")
    directory = home / ".cache" / "thumbnails" / "normal"
    directory.mkdir(parents=True)
    name = hashlib.md5(glib_uri(photo).encode(), usedforsecurity=False).hexdigest()
    (directory / f"{name}.png").symlink_to(outside)

    sweep = erase([photo])

    (trace,) = only(sweep, traces.TraceKind.THUMBNAIL)
    assert trace.removed is False
    assert "REPARSE_POINT_REFUSED" in trace.error
    assert outside.read_bytes() == b"not a thumbnail"


# --------------------------------------------------------------------------
# Recent files
# --------------------------------------------------------------------------


def test_a_recent_files_entry_is_cut_out_and_the_rest_of_the_list_kept(
    home: Path, where: traces.TraceLocations, photo: Path
) -> None:
    others = ["file:///home/someone/Documents/minutes.odt", "file:///srv/share/a.pdf"]
    listed = recent_list(home, [others[0], glib_uri(photo), others[1]])
    before = listed.stat()

    sweep = erase([photo])

    (trace,) = only(sweep, traces.TraceKind.RECENT_ENTRY)
    assert trace.removed and trace.action == "entry removed"
    assert trace.content_copy is False
    root = ET.fromstring(listed.read_bytes())
    assert [item.get("href") for item in root.iter("bookmark")] == others
    after = listed.stat()
    assert (after.st_ino, after.st_size) == (before.st_ino, before.st_size), (
        "the list is overwritten in place, padded to its old length, so the "
        "bytes that named the file are replaced rather than freed"
    )
    assert glib_uri(photo).encode() not in listed.read_bytes()


def test_an_entry_that_cannot_be_cut_cleanly_leaves_the_list_as_it_is(
    home: Path, where: traces.TraceLocations, photo: Path
) -> None:
    """A form the cutter does not recognise is refused, never guessed at."""
    listed = recent_list(home, [])
    odd = XBEL_HEAD + f'  <bookmark href = "{glib_uri(photo)}"/>\n</xbel>'
    listed.write_text(odd, encoding="utf-8")

    sweep = erase([photo])

    (trace,) = only(sweep, traces.TraceKind.RECENT_ENTRY)
    assert trace.removed is False
    assert "left as it is" in trace.error
    assert listed.read_text(encoding="utf-8") == odd


def test_a_list_changed_while_it_was_read_is_not_overwritten(tmp_path: Path) -> None:
    listed = tmp_path / "recently-used.xbel"
    listed.write_bytes(b"<xbel/>")
    stale = listed.stat()
    listed.write_bytes(b"<xbel version='1.0'/>")

    error = traces._overwrite_in_place(listed, b"<xbel/>", expected=stale)

    assert "changed while the sweep was reading it" in error
    assert listed.read_bytes() == b"<xbel version='1.0'/>"


def test_a_kde_recent_document_link_is_erased(
    home: Path, where: traces.TraceLocations, photo: Path
) -> None:
    folder = home / ".local" / "share" / "RecentDocuments"
    folder.mkdir(parents=True)
    link = folder / "plan.jpg.desktop"
    link.write_text(
        f"[Desktop Entry]\nName=plan\nType=Link\nURL[$e]={glib_uri(photo)}\n",
        encoding="utf-8",
    )

    sweep = erase([photo])

    (trace,) = only(sweep, traces.TraceKind.RECENT_DOCUMENT)
    assert trace.removed
    assert not link.exists()


# --------------------------------------------------------------------------
# Trash
# --------------------------------------------------------------------------


def test_a_trash_copy_and_its_record_are_erased(
    home: Path, where: traces.TraceLocations, photo: Path
) -> None:
    trash = home / ".local" / "share" / "Trash"
    copy, info = trash_item(trash, photo.name, str(photo), photo.read_bytes())

    sweep = erase([photo])

    (kept,) = only(sweep, traces.TraceKind.TRASH_COPY)
    (record,) = only(sweep, traces.TraceKind.TRASH_RECORD)
    assert kept.content_copy and kept.removed
    assert "same size as the erased file (4,096 bytes)" in kept.evidence
    assert record.removed and not record.content_copy
    assert not copy.exists() and not info.exists()


def test_an_earlier_version_in_the_trash_is_named_as_one(
    home: Path, where: traces.TraceLocations, photo: Path
) -> None:
    trash = home / ".local" / "share" / "Trash"
    trash_item(trash, photo.name, str(photo), b"older and shorter")

    sweep = erase([photo], find_only=True)

    (kept,) = only(sweep, traces.TraceKind.TRASH_COPY)
    assert "an earlier version" in kept.evidence


def test_a_trashed_folder_that_held_the_file_loses_only_that_copy(
    home: Path, where: traces.TraceLocations, photo: Path
) -> None:
    """The folder and its record describe other files too, so they stay."""
    trash = home / ".local" / "share" / "Trash"
    copy, info = trash_item(trash, "work", str(photo.parent), None)
    copy.mkdir()
    inner = copy / photo.name
    inner.write_bytes(b"old copy")
    sibling = copy / "unrelated.txt"
    sibling.write_bytes(b"not asked about")

    sweep = erase([photo])

    (trace,) = only(sweep, traces.TraceKind.TRASH_COPY)
    assert trace.location == str(inner) and trace.removed
    assert not only(sweep, traces.TraceKind.TRASH_RECORD)
    assert not inner.exists()
    assert sibling.read_bytes() == b"not asked about" and info.exists()


@posix_only
def test_a_link_inside_a_trashed_folder_is_never_followed(
    home: Path, where: traces.TraceLocations, tmp_path: Path
) -> None:
    """The copy's path runs through a link out of the Trash: nothing is found."""
    target = tmp_path / "work" / "sub" / "notes.txt"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"to erase")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "notes.txt").write_bytes(b"someone else's notes")
    trash = home / ".local" / "share" / "Trash"
    copy, _ = trash_item(trash, "work", str(tmp_path / "work"), None)
    copy.mkdir()
    (copy / "sub").symlink_to(outside)

    sweep = erase([target])

    assert not only(sweep, traces.TraceKind.TRASH_COPY)
    assert (outside / "notes.txt").read_bytes() == b"someone else's notes"


@posix_only
def test_a_trash_copy_that_cannot_be_removed_keeps_its_record(
    home: Path, where: traces.TraceLocations, photo: Path, tmp_path: Path
) -> None:
    """Without its record, a copy left behind would be invisible in the Trash."""
    trash = home / ".local" / "share" / "Trash"
    copy, info = trash_item(trash, photo.name, str(photo), None)
    copy.symlink_to(tmp_path / "anything")

    sweep = erase([photo])

    (kept,) = only(sweep, traces.TraceKind.TRASH_COPY)
    (record,) = only(sweep, traces.TraceKind.TRASH_RECORD)
    assert kept.removed is False
    assert record.removed is False and "Kept, because" in record.error
    assert info.exists()


def test_a_volume_trash_records_paths_relative_to_the_volume_top(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    volume = tmp_path / "volume"
    target = volume / "cases" / "evidence.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"e" * 512)
    copy, info = trash_item(
        volume / ".Trash-1000", "evidence.bin", "cases/evidence.bin", b"e" * 512
    )
    locations = dataclasses.replace(
        traces.locations_for("linux", {}, home, uid=1000),
        volume_top=lambda _path: volume,
    )
    monkeypatch.setattr(traces, "default_locations", lambda: locations)

    sweep = erase([target])

    assert {trace.kind for trace in sweep.traces} == {"TRASH_COPY", "TRASH_RECORD"}
    assert all(trace.removed for trace in sweep.traces)
    assert not copy.exists() and not info.exists()
    assert any(place.startswith("volume Trash") for place in sweep.searched)


# --------------------------------------------------------------------------
# Windows and macOS, from synthetic volumes
# --------------------------------------------------------------------------


def _record(path: str, *, size: int = 11, directory: bool = False) -> FileEraseRecord:
    return FileEraseRecord(
        path=path,
        ok=True,
        unlinked=True,
        is_directory=directory,
        inspection=FileInspection(path=path, size_bytes=size),
    )


@pytest.mark.parametrize("version", [1, 2])
def test_a_recycle_bin_copy_is_found_from_its_i_record(
    tmp_path: Path, version: int
) -> None:
    """``$I`` names the origin; ``$R`` is the copy. Matched case-insensitively."""
    volume = tmp_path / "C"
    bin_dir = volume / "$Recycle.Bin" / "S-1-5-21-1111-2222-3333-1001"
    bin_dir.mkdir(parents=True)
    (bin_dir / "$IK3J9Q2.docx").write_bytes(
        recycle_i_record("C:\\Users\\Asha\\Documents\\Salary.docx", 11, version=version)
    )
    (bin_dir / "$RK3J9Q2.docx").write_bytes(b"old content")
    (bin_dir / "$IZZZZZZ.txt").write_bytes(recycle_i_record("C:\\other.txt", 3))
    locations = traces.TraceLocations(
        family="windows", recycle_bin=True, volume_top=lambda _path: volume
    )

    sweep = traces.find_traces(
        [_record("c:\\users\\asha\\documents\\SALARY.DOCX")], locations
    )

    kinds = sorted(trace.kind for trace in sweep.traces)
    assert kinds == ["RECYCLE_BIN_COPY", "RECYCLE_BIN_RECORD"]
    (copy,) = only(sweep, traces.TraceKind.RECYCLE_BIN_COPY)
    assert copy.location.endswith("$RK3J9Q2.docx")
    assert "same size as the erased file" in copy.evidence


@pytest.mark.parametrize("wide", [False, True], ids=["ansi", "unicode"])
def test_a_windows_recent_shortcut_is_matched_by_its_link_target(
    tmp_path: Path, wide: bool
) -> None:
    recent = tmp_path / "Recent"
    recent.mkdir()
    (recent / "Salary.docx.lnk").write_bytes(
        shell_link("C:\\Users\\Asha\\Documents\\Salary.docx", wide=wide)
    )
    (recent / "Other.lnk").write_bytes(shell_link("D:\\elsewhere.txt", wide=wide))
    locations = traces.TraceLocations(family="windows", recent_shortcut_dirs=(recent,))

    sweep = traces.find_traces(
        [_record("C:\\Users\\Asha\\Documents\\Salary.docx")], locations
    )

    (trace,) = sweep.traces
    assert trace.kind == "RECENT_SHORTCUT" and trace.exact
    assert trace.location.endswith("Salary.docx.lnk")


@posix_only
def test_the_macos_trash_is_reported_and_never_removed(
    tmp_path: Path, photo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no put-back record in a .DS_Store, a name match is only a maybe."""
    trash = tmp_path / "mac-home" / ".Trash"
    trash.mkdir(parents=True)
    same_name = trash / photo.name
    same_name.write_bytes(b"maybe the same picture")
    locations = traces.TraceLocations(family="macos", mac_trash=trash)
    monkeypatch.setattr(traces, "default_locations", lambda: locations)

    sweep = erase([photo])

    (trace,) = sweep.traces
    assert trace.kind == "POSSIBLE_COPY"
    assert trace.exact is False and trace.removed is False
    assert "no put-back record" not in trace.evidence
    assert "the Trash has no .DS_Store" in trace.evidence
    assert same_name.exists()
    assert any("Spotlight" in line for line in sweep.not_searched)


# --------------------------------------------------------------------------
# Scope, the read-only search and the chain
# --------------------------------------------------------------------------


def test_the_read_only_search_reports_every_trace_and_removes_none(
    home: Path, where: traces.TraceLocations, photo: Path
) -> None:
    cached = thumbnail(home, photo)
    listed = recent_list(home, [glib_uri(photo)])
    trash_item(home / ".local" / "share" / "Trash", photo.name, str(photo), b"x")
    listed_bytes = listed.read_bytes()

    sweep = erase([photo], find_only=True)

    assert {trace.kind for trace in sweep.traces} == {
        "THUMBNAIL",
        "RECENT_ENTRY",
        "TRASH_COPY",
        "TRASH_RECORD",
    }
    assert not any(trace.removed or trace.action for trace in sweep.traces)
    assert cached.exists() and listed.read_bytes() == listed_bytes
    assert photo.exists()


@posix_only
def test_a_refused_target_keeps_its_traces(
    home: Path, where: traces.TraceLocations, photo: Path, tmp_path: Path
) -> None:
    """The erase refused the link, so the file is still there, and so are its traces."""
    link = tmp_path / "link.jpg"
    link.symlink_to(photo)
    cached = thumbnail(home, link)

    sweep = erase([link])

    assert sweep.traces == []
    assert cached.exists()


def test_the_chain_records_each_trace_and_every_place_searched(
    home: Path, where: traces.TraceLocations, photo: Path
) -> None:
    thumbnail(home, photo)
    ledger = Recorder()

    sweep = erase([photo], ledger=ledger)

    operations = [operation for operation, _ in ledger.entries]
    assert operations.count("trace") == 1
    assert operations[-1] == "traces", "the summary closes the sweep"
    (entry,) = [
        payload for operation, payload in ledger.entries if operation == "trace"
    ]
    assert entry["kind"] == "THUMBNAIL" and entry["removed"] is True
    summary = ledger.entries[-1][1]
    assert summary["searched"] == sweep.searched
    assert summary["found"] == 1 and summary["removed"] == 1
    assert any("(not present)" in place for place in sweep.searched), (
        "a place that is absent is still named, so its absence is on record"
    )


def test_a_sweep_that_finds_nothing_still_says_where_it_looked(
    where: traces.TraceLocations, photo: Path
) -> None:
    ledger = Recorder()

    sweep = erase([photo], ledger=ledger)

    assert sweep.traces == []
    assert sweep.searched and sweep.not_searched
    assert ledger.entries[-1][0] == "traces"


def test_the_sweep_runs_only_when_asked(
    where: traces.TraceLocations, photo: Path
) -> None:
    _, result = drain(
        erase_paths(
            [photo], real_erase(workers=1), job_id="no-sweep", ledger=Recorder()
        )
    )
    assert result.trace_sweep is None


# --------------------------------------------------------------------------
# Locations and parsers
# --------------------------------------------------------------------------


def test_locations_follow_the_xdg_base_directories() -> None:
    env = {"XDG_CACHE_HOME": "/fast/cache", "XDG_DATA_HOME": "/data"}
    where = traces.locations_for("linux", env, Path("/home/asha"), uid=1000)
    assert where.thumbnail_roots[0] == Path("/fast/cache/thumbnails")
    assert where.recent_lists == (
        Path("/data/recently-used.xbel"),
        Path("/home/asha/.recently-used.xbel"),
    ), "GTK 3 and 4 write the first; GTK 2 wrote the second"
    assert where.home_trash == Path("/data/Trash")

    relative = traces.locations_for("linux", {"XDG_DATA_HOME": "rel"}, Path("/h"))
    assert relative.home_trash == Path("/h/.local/share/Trash"), (
        "a relative XDG value is invalid by the specification and is ignored"
    )


def test_each_platform_names_its_own_places() -> None:
    windows = traces.locations_for(
        "windows",
        {"APPDATA": "C:\\Users\\Asha\\AppData\\Roaming"},
        Path("C:/Users/Asha"),
    )
    assert windows.recycle_bin
    assert windows.recent_shortcut_dirs[0].name == "Recent"
    mac = traces.locations_for("macos", {}, Path("/Users/asha"))
    assert mac.mac_trash == Path("/Users/asha/.Trash")
    assert not mac.thumbnail_roots


def test_the_parsers_answer_none_for_anything_else() -> None:
    assert traces.png_text(b"GIF89a") == {}
    assert traces.recycle_record(b"\x03" + b"\x00" * 40) is None
    assert traces.recycle_record(b"short") is None
    assert traces.shortcut_target(b"MZ" + b"\x00" * 100) is None
    assert traces.path_from_uri("https://example.org/a") is None
    assert traces.path_from_uri("file://server/share/a") is None
    assert traces.path_from_uri("file://localhost/tmp/a%20b") == "/tmp/a b"
