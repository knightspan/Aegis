"""The OS-specific trace adapters: macOS, Windows and Linux, run on any host.

Each operating system's profile is laid out under ``tmp_path`` by
:mod:`.trace_profiles`, and every artifact in it - a Finder ``.DS_Store``, a
bookmark inside a ``.sfl3`` shared file list, a Quick Look ``index.sqlite``,
a jump list compound file - is packed byte for byte in the test. The parsers
are pure, so the Windows and macOS tests run on Linux. Nothing reads the home
directory of whoever runs the suite.

The rules each adapter is held to:

* only a record that ties an artifact to an erased path makes it exact;
* a same-name file with no such record, or a record naming another path, is
  never removed;
* no link is followed;
* the read-only search (``find_traces``) removes nothing;
* a trace inside a file another process owns is reported, with the reason,
  and the file is left byte for byte as it was.
"""

from __future__ import annotations

import dataclasses
import os
import sqlite3
import struct
import sys
from pathlib import Path
from typing import Any

import pytest
from core.erase import traces
from core.models import FileEraseRecord, FileInspection, TraceSweepResult
from core.report.render import (
    NONE_RECORDED,
    build_file_erase_report,
    render_pdf,
    trace_section,
)

from tests.report.test_module_reports import file_inputs

from .conftest import drain, posix_only, real_erase
from .test_trace_sweep import Recorder, erase, glib_uri, only, recent_list, shell_link
from .trace_profiles import (
    MacTrash,
    automatic_destinations,
    bookmark,
    compound_file,
    custom_destinations,
    ds_record,
    ds_store,
    linux_profile,
    mac_profile,
    putback_records,
    quicklook_index,
    shared_file_list,
    windows_profile,
)

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def erased(path: str, *, size: int = 11, directory: bool = False) -> FileEraseRecord:
    """A record of a path the erase removed, for a sweep run on its own."""
    return FileEraseRecord(
        path=path,
        ok=True,
        unlinked=True,
        is_directory=directory,
        inspection=FileInspection(path=path, size_bytes=size),
    )


def run_sweep(
    records: list[FileEraseRecord],
    locations: traces.TraceLocations,
    *,
    find_only: bool = False,
) -> TraceSweepResult:
    if find_only:
        return traces.find_traces(records, locations)
    settings = real_erase(workers=1)
    _, result = drain(
        traces.sweep(
            records, settings, job_id="adapters", ledger=Recorder(), locations=locations
        )
    )
    assert isinstance(result, TraceSweepResult)
    return result


def outcome_of(sweep: TraceSweepResult, label: str) -> str:
    (entry,) = [item for item in sweep.inspected if item.label == label]
    return entry.outcome


@pytest.fixture
def photo(tmp_path: Path) -> Path:
    folder = tmp_path / "work"
    folder.mkdir()
    target = folder / "Q3 plan (draft) é.jpg"
    target.write_bytes(b"\xff\xd8\xff" + b"J" * 4093)
    return target


SALARY = "C:\\Users\\Asha\\Documents\\Salary.docx"
MINUTES = "C:\\Users\\Asha\\Documents\\Minutes.docx"


# --------------------------------------------------------------------------
# .DS_Store parser
# --------------------------------------------------------------------------


def test_the_ds_store_parser_reads_put_back_records_and_skips_the_rest() -> None:
    records = [
        ds_record("a.jpg", b"BKGD", b"blob", b"\x00" * 12),
        ds_record("a.jpg", b"dilc", b"blob", b"\x01" * 32),
        ds_record("a.jpg", b"ICVO", b"bool", 1),
        ds_record("a.jpg", b"fwvh", b"shor", 400),
        ds_record("a.jpg", b"vstl", b"type", b"icnv"),
        ds_record("a.jpg", b"lg1S", b"comp", b"\x00" * 8),
        *putback_records("a.jpg", "Users/asha/Desktop/", "a.jpg"),
        *putback_records("b 2.jpg", "Users/asha/Pictures/", "b.jpg"),
    ]

    parsed = traces.trash_putback(ds_store(records))

    assert parsed == {
        "a.jpg": ("Users/asha/Desktop/", "a.jpg"),
        "b 2.jpg": ("Users/asha/Pictures/", "b.jpg"),
    }


def test_the_ds_store_parser_walks_an_internal_node() -> None:
    records: list[bytes] = []
    for number in range(40):
        records += putback_records(f"item-{number:02}", "Users/asha/", f"o-{number}")

    parsed = traces.trash_putback(ds_store(records, fanout=7))

    assert parsed is not None and len(parsed) == 40
    assert parsed["item-39"] == ("Users/asha/", "o-39")


def _node_pointing_at_itself() -> bytes:
    good = bytearray(ds_store(putback_records("a", "x/", "a")))
    # The allocator lists: root(0), leaf(1), master(2). Point the master at a
    # node whose rightmost child is the node itself.
    count = struct.unpack_from(">I", good, 4 + struct.unpack_from(">I", good, 8)[0])[0]
    assert count == 3
    root = 4 + struct.unpack_from(">I", good, 8)[0]
    leaf_address = struct.unpack_from(">I", good, root + 8 + 4)[0]
    leaf = 4 + (leaf_address & ~0x1F)
    struct.pack_into(">II", good, leaf, 1, 0)  # right child = block 1, itself
    return bytes(good)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x00\x00\x00\x01Bud2" + b"\x00" * 64,
        b"\x00\x00\x00\x01Bud1" + struct.pack(">III", 0x20, 0x800, 0x40) + b"\x00" * 64,
        b"\x00\x00\x00\x01Bud1" + struct.pack(">III", 0x7FFF0000, 64, 0x7FFF0000),
        pytest.param(_node_pointing_at_itself(), id="cycle"),
        pytest.param(
            # A string that claims 1,000 characters and holds two.
            ds_store(
                [ds_record("a", b"ptbL", b"ustr", "x/")[:-8] + b"\x00\x00\x03\xe8x/"]
            ),
            id="value-cut",
        ),
        pytest.param(
            ds_store(
                [ds_record("a", b"ptbL", b"blob", b"x")[:-5] + b"weird" + b"\x00"]
            ),
            id="unknown-type",
        ),
    ],
)
def test_the_ds_store_parser_refuses_what_does_not_hold_together(data: bytes) -> None:
    assert traces.ds_store_records(data) is None
    assert traces.trash_putback(data) is None


def test_every_truncation_of_a_ds_store_is_refused_or_read_but_never_raises() -> None:
    whole = ds_store(
        putback_records("a.jpg", "Users/asha/", "a.jpg")
        + putback_records("b.jpg", "Users/asha/", "b.jpg"),
        fanout=3,
    )
    for end in range(0, len(whole), 7):
        parsed = traces.ds_store_records(whole[:end])
        assert parsed is None or isinstance(parsed, dict)


def test_a_block_count_beyond_the_bound_is_refused() -> None:
    data = bytearray(ds_store(putback_records("a", "x/", "a")))
    root = 4 + struct.unpack_from(">I", data, 8)[0]
    struct.pack_into(">I", data, root, 0x7FFFFFFF)
    assert traces.ds_store_records(bytes(data)) is None


# --------------------------------------------------------------------------
# macOS Trash: put-back evidence
# --------------------------------------------------------------------------


@posix_only
def test_a_mac_trash_item_whose_put_back_names_the_file_is_erased(
    tmp_path: Path, photo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = mac_profile(tmp_path / "mac")
    trash = MacTrash(profile.trash)
    copy = trash.add(photo.name, photo.parent, photo.read_bytes())
    store_before = (profile.trash / ".DS_Store").read_bytes()
    monkeypatch.setattr(traces, "default_locations", lambda: profile.locations)

    sweep = erase([photo])

    (kept,) = only(sweep, traces.TraceKind.TRASH_COPY)
    assert kept.exact and kept.removed and kept.action == "erased"
    assert ".DS_Store records that this was deleted from" in kept.evidence
    assert "same size as the erased file" in kept.evidence
    assert not copy.exists()
    (record,) = only(sweep, traces.TraceKind.TRASH_RECORD)
    assert record.exact and record.report_only and not record.removed
    assert "Finder owns and rewrites" in record.report_only_reason
    assert (profile.trash / ".DS_Store").read_bytes() == store_before
    assert outcome_of(sweep, "Trash") == "searched"
    assert outcome_of(sweep, "Trash put-back records") == "searched"


@posix_only
def test_a_renamed_trash_item_is_tied_by_its_put_back_name(
    tmp_path: Path, photo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The Trash renamed the copy; ptbN still holds the name it had."""
    profile = mac_profile(tmp_path / "mac")
    copy = MacTrash(profile.trash).add(
        "renamed 2.jpg", photo.parent, b"older", original_name=photo.name
    )
    monkeypatch.setattr(traces, "default_locations", lambda: profile.locations)

    sweep = erase([photo])

    (kept,) = only(sweep, traces.TraceKind.TRASH_COPY)
    assert kept.location == str(copy) and kept.removed
    assert "an earlier version" in kept.evidence
    assert not copy.exists()


@posix_only
def test_a_same_name_item_deleted_from_elsewhere_is_never_removed(
    tmp_path: Path, photo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A record that ties the item to a different path is evidence against it."""
    profile = mac_profile(tmp_path / "mac")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    same_name = MacTrash(profile.trash).add(
        photo.name, elsewhere, b"someone else's picture"
    )
    monkeypatch.setattr(traces, "default_locations", lambda: profile.locations)

    sweep = erase([photo])

    (trace,) = sweep.traces
    assert trace.kind == "POSSIBLE_COPY"
    assert trace.exact is False and trace.removed is False
    assert f"deleted from {elsewhere}/{photo.name}" in trace.evidence
    assert same_name.read_bytes() == b"someone else's picture"


@posix_only
def test_a_same_name_item_with_no_record_is_left_alone(
    tmp_path: Path, photo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = mac_profile(tmp_path / "mac")
    trash = MacTrash(profile.trash)
    trash.add("other.txt", tmp_path, b"unrelated")
    same_name = profile.trash / photo.name
    same_name.write_bytes(b"no record says where this came from")
    monkeypatch.setattr(traces, "default_locations", lambda: profile.locations)

    sweep = erase([photo])

    (trace,) = sweep.traces
    assert trace.kind == "POSSIBLE_COPY" and not trace.exact
    assert "no put-back record" in trace.evidence
    assert same_name.exists()


@posix_only
def test_an_unreadable_ds_store_falls_back_to_a_possible_copy(
    tmp_path: Path, photo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = mac_profile(tmp_path / "mac")
    (profile.trash / ".DS_Store").write_bytes(b"\x00\x00\x00\x01Bud1garbage" * 4)
    same_name = profile.trash / photo.name
    same_name.write_bytes(b"x")
    monkeypatch.setattr(traces, "default_locations", lambda: profile.locations)

    sweep = erase([photo])

    (trace,) = sweep.traces
    assert trace.kind == "POSSIBLE_COPY" and not trace.exact
    assert "could not be read" in trace.evidence
    assert outcome_of(sweep, "Trash put-back records") == "unreadable"
    assert same_name.exists()


@posix_only
def test_a_trashed_folder_that_held_the_file_loses_only_that_copy(
    tmp_path: Path, photo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = mac_profile(tmp_path / "mac")
    folder = MacTrash(profile.trash).add("work", photo.parent.parent, None)
    folder.mkdir()
    inner = folder / photo.name
    inner.write_bytes(b"old copy")
    sibling = folder / "unrelated.txt"
    sibling.write_bytes(b"not asked about")
    monkeypatch.setattr(traces, "default_locations", lambda: profile.locations)

    sweep = erase([photo])

    (trace,) = only(sweep, traces.TraceKind.TRASH_COPY)
    assert trace.location == str(inner) and trace.removed
    assert not only(sweep, traces.TraceKind.TRASH_RECORD)
    assert sibling.read_bytes() == b"not asked about"


@posix_only
def test_a_trash_item_that_is_a_link_is_never_followed(
    tmp_path: Path, photo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Its put-back record names the file, but the item points out of the Trash."""
    profile = mac_profile(tmp_path / "mac")
    outside = tmp_path / "precious.jpg"
    outside.write_bytes(b"not a Trash copy")
    MacTrash(profile.trash).add(photo.name, photo.parent, None)
    (profile.trash / photo.name).symlink_to(outside)
    monkeypatch.setattr(traces, "default_locations", lambda: profile.locations)

    sweep = erase([photo])

    (kept,) = only(sweep, traces.TraceKind.TRASH_COPY)
    assert kept.removed is False and "REPARSE_POINT_REFUSED" in kept.error
    assert outside.read_bytes() == b"not a Trash copy"


@posix_only
def test_a_trash_that_is_a_link_is_not_searched(
    tmp_path: Path, photo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = mac_profile(tmp_path / "mac")
    real = tmp_path / "somewhere-else"
    MacTrash(real).add(photo.name, photo.parent, b"copy")
    profile.trash.rmdir()
    profile.trash.symlink_to(real)
    monkeypatch.setattr(traces, "default_locations", lambda: profile.locations)

    sweep = erase([photo])

    assert sweep.traces == []
    assert outcome_of(sweep, "Trash") == "unreadable"
    assert (real / photo.name).read_bytes() == b"copy"
    assert any("never follows" in note for note in sweep.notes)


@posix_only
def test_the_read_only_search_on_a_mac_profile_removes_nothing(
    tmp_path: Path, photo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = mac_profile(tmp_path / "mac")
    copy = MacTrash(profile.trash).add(photo.name, photo.parent, b"copy")
    listing = profile.sharedfilelist / "com.apple.LSSharedFileList.RecentDocuments.sfl3"
    listing.write_bytes(shared_file_list([bookmark(str(photo))]))
    monkeypatch.setattr(traces, "default_locations", lambda: profile.locations)

    sweep = erase([photo], find_only=True)

    kinds = {trace.kind for trace in sweep.traces}
    assert kinds == {"TRASH_COPY", "TRASH_RECORD", "RECENT_ENTRY"}
    assert not any(trace.removed or trace.action for trace in sweep.traces)
    assert copy.exists() and photo.exists()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="a macOS volume path is POSIX; a Windows temporary directory cannot "
    "stand in for one under /Volumes",
)
def test_a_trash_on_another_volume_is_read_relative_to_that_volume(
    tmp_path: Path,
) -> None:
    profile = mac_profile(tmp_path / "mac")
    volume = tmp_path / "Volumes" / "USB"
    trash = MacTrash(volume / ".Trashes" / "501", volume=volume)
    copy = trash.add("report.pdf", volume / "cases", b"%PDF-")
    locations = dataclasses.replace(profile.locations, volume_top=lambda _path: volume)

    sweep = traces.find_traces(
        [erased(str(volume / "cases" / "report.pdf"))], locations
    )

    (found,) = only(sweep, traces.TraceKind.TRASH_COPY)
    assert found.location == str(copy) and found.exact
    assert any(entry.label == "volume Trash" for entry in sweep.inspected)


def test_a_put_back_record_with_dot_dot_ties_nothing(tmp_path: Path) -> None:
    profile = mac_profile(tmp_path / "mac")
    trash = MacTrash(profile.trash)
    (profile.trash / "a.txt").write_bytes(b"x")
    trash.putback["a.txt"] = ("tmp/../etc/", "a.txt")
    trash.write()
    locations = dataclasses.replace(profile.locations, mac_trash_volume=Path("/"))

    sweep = traces.find_traces([erased("/etc/a.txt")], locations)

    (trace,) = sweep.traces
    assert trace.kind == "POSSIBLE_COPY" and not trace.exact


# --------------------------------------------------------------------------
# macOS recent items (shared file lists)
# --------------------------------------------------------------------------


def test_the_bookmark_parser_returns_only_a_fully_decoded_path() -> None:
    assert traces.bookmark_path(bookmark("/Users/asha/a b/é.txt")) == (
        "/Users/asha/a b/é.txt"
    )
    # A component that is not a UTF-8 string: no path, not a partial one.
    assert (
        traces.bookmark_path(bookmark("/Users/asha/x", component_type=0x0201)) is None
    )
    whole = bookmark("/Users/asha/x.txt")
    for end in range(0, len(whole) - 1):
        assert traces.bookmark_path(whole[:end]) is None
    assert traces.bookmark_path(b"alis" + whole[4:]) is None
    broken = bytearray(whole)
    struct.pack_into("<I", broken, 0x30, 0xFFFFFF00)  # first TOC far outside
    assert traces.bookmark_path(bytes(broken)) is None


def test_the_shared_file_list_parser_reads_bookmarks_in_either_form() -> None:
    blobs = [bookmark("/Users/asha/a.txt"), bookmark("/Volumes/USB/b.txt")]
    assert traces.shared_file_list_paths(shared_file_list(blobs)) == [
        "/Users/asha/a.txt",
        "/Volumes/USB/b.txt",
    ]
    assert traces.shared_file_list_paths(
        shared_file_list(blobs[:1], wrap_data=True)
    ) == ["/Users/asha/a.txt"]


def test_the_shared_file_list_parser_refuses_xml_and_forged_trailers() -> None:
    import plistlib

    assert traces.shared_file_list_paths(plistlib.dumps({"$objects": []})) is None
    good = bytearray(shared_file_list([bookmark("/a")]))
    struct.pack_into(">Q", good, len(good) - 24, 2**40)  # object count
    assert traces.shared_file_list_paths(bytes(good)) is None
    assert traces.shared_file_list_paths(b"bplist00" + b"\x00" * 10) is None


def test_a_recent_item_naming_the_file_is_reported_and_the_list_left_alone(
    tmp_path: Path,
) -> None:
    profile = mac_profile(tmp_path / "mac")
    app = (
        profile.sharedfilelist / "com.apple.LSSharedFileList.ApplicationRecentDocuments"
    )
    app.mkdir()
    listing = app / "com.apple.textedit.sfl3"
    target = "/Users/asha/Documents/Salary.rtf"
    listing.write_bytes(
        shared_file_list(
            [bookmark("/Users/asha/Documents/Minutes.rtf"), bookmark(target)]
        )
    )
    before = listing.read_bytes()

    sweep = run_sweep([erased(target)], profile.locations)

    (trace,) = only(sweep, traces.TraceKind.RECENT_ENTRY)
    assert trace.location == str(listing)
    assert trace.exact and trace.report_only and not trace.removed
    assert trace.report_only_reason == (
        "macOS rewrites this list from sharedfilelistd; Sanctum reports it and "
        "does not edit a live daemon-owned file."
    )
    assert listing.read_bytes() == before


def test_a_recent_item_naming_a_different_path_is_not_a_trace(tmp_path: Path) -> None:
    profile = mac_profile(tmp_path / "mac")
    listing = profile.sharedfilelist / "com.apple.LSSharedFileList.RecentDocuments.sfl2"
    listing.write_bytes(shared_file_list([bookmark("/Users/asha/Salary.rtf.bak")]))

    sweep = run_sweep([erased("/Users/asha/Salary.rtf")], profile.locations)

    assert sweep.traces == []
    assert outcome_of(sweep, "recent items (shared file lists)") == "searched"


@posix_only
def test_a_linked_folder_of_shared_file_lists_is_not_followed(tmp_path: Path) -> None:
    profile = mac_profile(tmp_path / "mac")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x.sfl3").write_bytes(shared_file_list([bookmark("/Users/asha/a.txt")]))
    (profile.sharedfilelist / "linked").symlink_to(outside)

    sweep = run_sweep([erased("/Users/asha/a.txt")], profile.locations)

    assert sweep.traces == []


# --------------------------------------------------------------------------
# macOS Quick Look
# --------------------------------------------------------------------------


def test_the_quick_look_path_comes_from_tmpdir() -> None:
    where = traces.locations_for(
        "macos", {"TMPDIR": "/var/folders/xy/abc123/T/"}, Path("/Users/asha")
    )
    assert where.quicklook_caches == (
        Path("/var/folders/xy/abc123/C/com.apple.QuickLook.thumbnailcache"),
    )
    unset = traces.locations_for("macos", {}, Path("/Users/asha"))
    assert unset.quicklook_caches == ()
    assert any("TMPDIR is not set" in line for line in unset.not_located)


def test_quick_look_entries_are_read_without_touching_the_database(
    tmp_path: Path,
) -> None:
    database = quicklook_index(
        tmp_path / "ql",
        [
            ("/Users/asha/Documents", "Salary.pdf", 2),
            ("file:///Users/asha/Pictures/", "a%20b.png", 0),
            ("relative/folder", "x", 1),
        ],
    )
    before = (database.read_bytes(), database.stat().st_mtime_ns)
    listed_before = sorted(os.listdir(tmp_path / "ql"))

    rows, why = traces.quicklook_entries(database)

    assert why == ""
    assert rows == [
        ("/Users/asha/Documents/Salary.pdf", 1, 2),
        ("/Users/asha/Pictures/a%20b.png", 2, 0),
    ]
    assert (database.read_bytes(), database.stat().st_mtime_ns) == before
    assert sorted(os.listdir(tmp_path / "ql")) == listed_before, (
        "a read-only, immutable open creates no journal or WAL"
    )


def test_a_quick_look_entry_is_reported_and_the_cache_left_alone(
    tmp_path: Path,
) -> None:
    profile = mac_profile(tmp_path / "mac")
    database = quicklook_index(
        profile.quicklook,
        [("/Users/asha/Documents", "Salary.pdf", 3), ("/Users/asha", "keep.pdf", 1)],
    )
    before = database.read_bytes()

    sweep = run_sweep([erased("/Users/asha/Documents/Salary.pdf")], profile.locations)

    (trace,) = only(sweep, traces.TraceKind.QUICKLOOK_THUMBNAIL)
    assert trace.exact and trace.report_only and not trace.removed
    assert trace.content_copy, "thumbnails.data holds images of it"
    assert "3 thumbnail(s)" in trace.evidence
    assert "shared database owned by a system daemon" in trace.report_only_reason
    assert database.read_bytes() == before
    assert outcome_of(sweep, "Quick Look index") == "searched"


def test_a_quick_look_cache_of_unknown_schema_is_named_as_not_searched(
    tmp_path: Path,
) -> None:
    profile = mac_profile(tmp_path / "mac")
    quicklook_index(profile.quicklook, [], schema="other")

    sweep = run_sweep([erased("/Users/asha/a.pdf")], profile.locations)

    assert sweep.traces == []
    assert outcome_of(sweep, "Quick Look index") == "unreadable"
    assert any(
        "Quick Look" in line and "schema is not a known one" in line
        for line in sweep.not_searched
    )


def test_a_quick_look_file_that_is_not_a_database_is_not_searched(
    tmp_path: Path,
) -> None:
    profile = mac_profile(tmp_path / "mac")
    profile.quicklook.mkdir(parents=True)
    (profile.quicklook / "index.sqlite").write_bytes(b"not sqlite at all" * 100)

    sweep = run_sweep([erased("/Users/asha/a.pdf")], profile.locations)

    assert outcome_of(sweep, "Quick Look index") == "unreadable"
    assert any("Quick Look" in line for line in sweep.not_searched)


# --------------------------------------------------------------------------
# Windows jump lists
# --------------------------------------------------------------------------


def test_the_jump_list_parser_reads_each_entry_stream() -> None:
    data = automatic_destinations(
        [shell_link(SALARY), shell_link(MINUTES, wide=True), b"not a link"]
    )
    assert traces.jump_list_streams(data) == [
        ("1", SALARY),
        ("2", MINUTES),
        ("3", None),
    ]
    assert traces.jump_list_streams(b"\x4c\x00\x00\x00" + b"\x00" * 600) is None
    assert traces.jump_list_streams(data[:700]) is None


def test_a_jump_list_of_only_erased_entries_is_erased_whole(tmp_path: Path) -> None:
    profile = windows_profile(tmp_path / "win")
    jump = profile.automatic / "5f7b5f1e01b83767.automaticDestinations-ms"
    jump.write_bytes(automatic_destinations([shell_link(SALARY), shell_link(MINUTES)]))

    sweep = run_sweep([erased(SALARY), erased(MINUTES)], profile.locations)

    found = only(sweep, traces.TraceKind.JUMP_LIST_ENTRY)
    assert {trace.target for trace in found} == {SALARY, MINUTES}
    assert all(
        trace.exact and trace.removed and not trace.report_only for trace in found
    )
    assert sum(trace.bytes_overwritten for trace in found) > 0
    assert "Every entry in it names an erased path" in found[0].evidence
    assert not jump.exists()


def test_a_jump_list_that_also_names_other_files_is_reported_only(
    tmp_path: Path,
) -> None:
    profile = windows_profile(tmp_path / "win")
    jump = profile.automatic / "9b9cdc69c1c24e2b.automaticDestinations-ms"
    jump.write_bytes(automatic_destinations([shell_link(SALARY), shell_link(MINUTES)]))
    before = jump.read_bytes()

    sweep = run_sweep([erased(SALARY)], profile.locations)

    (trace,) = only(sweep, traces.TraceKind.JUMP_LIST_ENTRY)
    assert trace.exact and trace.report_only and not trace.removed
    assert "It also holds 1 other entry." in trace.evidence
    assert "risks corrupting" in trace.report_only_reason
    assert jump.read_bytes() == before


def test_a_jump_list_naming_another_path_is_not_a_trace(tmp_path: Path) -> None:
    profile = windows_profile(tmp_path / "win")
    jump = profile.automatic / "a.automaticDestinations-ms"
    jump.write_bytes(automatic_destinations([shell_link(SALARY + ".bak")]))

    sweep = run_sweep([erased(SALARY)], profile.locations)

    assert sweep.traces == [] and jump.exists()


def test_the_read_only_search_leaves_a_whole_file_jump_list_in_place(
    tmp_path: Path,
) -> None:
    profile = windows_profile(tmp_path / "win")
    jump = profile.automatic / "b.automaticDestinations-ms"
    jump.write_bytes(automatic_destinations([shell_link(SALARY)]))

    sweep = run_sweep([erased(SALARY)], profile.locations, find_only=True)

    (trace,) = sweep.traces
    assert trace.exact and not trace.removed and trace.action == ""
    assert jump.exists()


@posix_only
def test_a_jump_list_that_is_a_link_is_not_read(tmp_path: Path) -> None:
    profile = windows_profile(tmp_path / "win")
    outside = tmp_path / "precious.bin"
    outside.write_bytes(automatic_destinations([shell_link(SALARY)]))
    (profile.automatic / "c.automaticDestinations-ms").symlink_to(outside)

    sweep = run_sweep([erased(SALARY)], profile.locations)

    assert sweep.traces == []
    assert outside.exists()
    assert any("could not be read" in note for note in sweep.notes)


def test_a_custom_jump_list_entry_is_reported_only(tmp_path: Path) -> None:
    profile = windows_profile(tmp_path / "win")
    custom = profile.custom / "7e4dca80246863e3.customDestinations-ms"
    custom.write_bytes(custom_destinations([shell_link(MINUTES), shell_link(SALARY)]))
    before = custom.read_bytes()

    sweep = run_sweep([erased(SALARY)], profile.locations)

    (trace,) = only(sweep, traces.TraceKind.JUMP_LIST_ENTRY)
    assert trace.location == str(custom)
    assert trace.exact and trace.report_only and not trace.removed
    assert custom.read_bytes() == before


def test_the_windows_profile_is_searched_in_every_place(tmp_path: Path) -> None:
    profile = windows_profile(tmp_path / "win")
    (profile.recent / "Salary.docx.lnk").write_bytes(shell_link(SALARY))
    (profile.recycle_bin / "$IABC123.docx").write_bytes(
        struct.pack("<qqq", 2, 11, 0)
        + struct.pack("<i", len(SALARY) + 1)
        + (SALARY + "\x00").encode("utf-16-le")
    )
    (profile.recycle_bin / "$RABC123.docx").write_bytes(b"old content")

    sweep = run_sweep([erased(SALARY)], profile.locations, find_only=True)

    assert {trace.kind for trace in sweep.traces} == {
        "RECENT_SHORTCUT",
        "RECYCLE_BIN_COPY",
        "RECYCLE_BIN_RECORD",
    }
    assert {entry.label: entry.outcome for entry in sweep.inspected} == {
        "Recycle Bin": "searched",
        "Recent shortcuts": "searched",
        "jump lists (AutomaticDestinations)": "searched",
        "jump lists (CustomDestinations)": "searched",
    }


def test_the_thumbcache_is_named_as_not_searched_with_the_reason(
    tmp_path: Path,
) -> None:
    profile = windows_profile(tmp_path / "win")

    sweep = run_sweep([erased(SALARY)], profile.locations)

    assert (
        "The thumbnail databases (thumbcache_*.db): cannot be tied to a path on "
        "evidence: entries are keyed by a cache hash, not the file path."
    ) in sweep.not_searched
    assert not any("Jump lists" in line for line in sweep.not_searched)


def test_windows_without_appdata_says_what_it_could_not_locate() -> None:
    where = traces.locations_for("windows", {}, Path("C:/Users/Asha"))
    assert where.jump_list_dirs == () and where.recent_shortcut_dirs == ()
    sweep = traces.find_traces([erased(SALARY)], where)
    assert any("APPDATA is not set" in line for line in sweep.not_searched)


# --------------------------------------------------------------------------
# Linux
# --------------------------------------------------------------------------


@posix_only
def test_a_sticky_shared_trash_is_searched_for_this_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    volume = tmp_path / "volume"
    target = volume / "cases" / "evidence.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"e" * 512)
    shared = volume / ".Trash"
    (shared / "1000" / "files").mkdir(parents=True)
    (shared / "1000" / "info").mkdir()
    shared.chmod(0o1777)
    (shared / "1000" / "files" / "evidence.bin").write_bytes(b"e" * 512)
    (shared / "1000" / "info" / "evidence.bin.trashinfo").write_text(
        "[Trash Info]\nPath=cases/evidence.bin\nDeletionDate=2026-09-20T11:22:33\n"
    )
    profile = linux_profile(tmp_path / "linux", volume=volume)
    monkeypatch.setattr(traces, "default_locations", lambda: profile.locations)

    sweep = erase([target])

    assert {trace.kind for trace in sweep.traces} == {"TRASH_COPY", "TRASH_RECORD"}
    assert all(trace.removed for trace in sweep.traces)
    assert any(line.startswith("volume Trash") for line in sweep.searched)


@posix_only
@pytest.mark.parametrize("flaw", ["not-sticky", "link"])
def test_a_shared_trash_that_fails_the_specification_is_not_used(
    tmp_path: Path, flaw: str
) -> None:
    volume = tmp_path / "volume"
    volume.mkdir()
    real = tmp_path / "real-trash"
    (real / "1000" / "files").mkdir(parents=True)
    (real / "1000" / "info").mkdir()
    (real / "1000" / "files" / "evidence.bin").write_bytes(b"e")
    (real / "1000" / "info" / "evidence.bin.trashinfo").write_text(
        "[Trash Info]\nPath=cases/evidence.bin\n"
    )
    if flaw == "link":
        real.chmod(0o1777)
        (volume / ".Trash").symlink_to(real)
    else:
        real.rename(volume / ".Trash")
        (volume / ".Trash").chmod(0o755)
    profile = linux_profile(tmp_path / "linux", volume=volume)

    sweep = traces.find_traces(
        [erased(str(volume / "cases" / "evidence.bin"))], profile.locations
    )

    assert sweep.traces == []
    assert any("freedesktop Trash specification" in note for note in sweep.notes)


def test_the_gtk2_recent_list_is_searched_too(tmp_path: Path) -> None:
    if sys.platform == "win32":
        pytest.skip("freedesktop places name POSIX paths")
    profile = linux_profile(tmp_path / "linux")
    target = "/home/asha/Documents/minutes.odt"
    legacy = recent_list(profile.home, [glib_uri(target)])
    legacy = legacy.rename(profile.home / ".recently-used.xbel")

    sweep = traces.find_traces([erased(target)], profile.locations)

    (trace,) = sweep.traces
    assert trace.kind == "RECENT_ENTRY" and trace.location == str(legacy)


@posix_only
def test_each_place_is_inspected_with_its_outcome(tmp_path: Path) -> None:
    profile = linux_profile(tmp_path / "linux")
    (profile.cache / "thumbnails").mkdir()
    (profile.home / ".thumbnails").symlink_to(profile.cache / "thumbnails")
    locked = profile.data / "RecentDocuments"
    locked.mkdir()
    locked.chmod(0)
    try:
        sweep = traces.find_traces([erased("/home/asha/a.txt")], profile.locations)
    finally:
        locked.chmod(0o755)

    outcomes = {
        (entry.label, entry.location): entry.outcome for entry in sweep.inspected
    }
    assert (
        outcomes[("thumbnail cache", str(profile.cache / "thumbnails"))] == "searched"
    )
    assert outcomes[("thumbnail cache", str(profile.home / ".thumbnails"))] == (
        "unreadable"
    ), "a link is never followed"
    assert outcomes[("home Trash", str(profile.data / "Trash"))] == "absent"
    expected = "searched" if os.geteuid() == 0 else "permission-denied"
    assert outcomes[("recent documents", str(locked))] == expected
    assert any("(not present)" in line for line in sweep.searched)


def test_the_macos_and_windows_sweeps_never_touch_a_freedesktop_volume_trash(
    tmp_path: Path,
) -> None:
    volume = tmp_path / "volume"
    (volume / ".Trash-501" / "info").mkdir(parents=True)
    (volume / ".Trash-501" / "files").mkdir()
    profile = mac_profile(tmp_path / "mac")
    locations = dataclasses.replace(profile.locations, volume_top=lambda _p: volume)

    sweep = traces.find_traces([erased(str(volume / "a.txt"))], locations)

    assert not any(".Trash-501" in line for line in sweep.searched)


# --------------------------------------------------------------------------
# The report
# --------------------------------------------------------------------------


def _sweep_dict(tmp_path: Path) -> dict[str, Any]:
    profile = windows_profile(tmp_path / "win")
    jump = profile.automatic / "d.automaticDestinations-ms"
    jump.write_bytes(automatic_destinations([shell_link(SALARY), shell_link(MINUTES)]))
    return run_sweep([erased(SALARY)], profile.locations).model_dump(mode="json")


def test_the_report_lists_each_place_inspected_and_each_report_only_trace(
    tmp_path: Path,
) -> None:
    section = trace_section(_sweep_dict(tmp_path))

    assert section["report_only"] == 1
    places = {row["place"]: row["outcome"] for row in section["inspected"]}
    assert places["jump lists (AutomaticDestinations)"] == "searched"
    (item,) = section["items"]
    assert item["action"] == "reported only"
    assert "risks corrupting" in item["report_only_reason"]


def test_the_certificate_counts_report_only_traces(tmp_path: Path) -> None:
    report = build_file_erase_report(**file_inputs(trace_sweep=_sweep_dict(tmp_path)))
    blob = render_pdf(report)
    # The value wraps onto a second line, and a PDF string escapes parentheses.
    assert b"(1 found, 0 removed, 1 left \\(1) Tj" in blob
    assert b"report-only\\)" in blob
    # The section pages print each place inspected, with its outcome.
    assert b"jump lists \\(AutomaticDestinations\\)" in blob


def test_a_sweep_saved_before_inspection_was_recorded_still_renders() -> None:
    old = {"searched": ["x: /y"], "not_searched": [], "traces": [], "notes": []}
    section = trace_section(old)
    assert section["inspected"] == [NONE_RECORDED]
    assert TraceSweepResult.model_validate(old).inspected == []


def test_a_jump_list_holding_only_its_index_names_nothing() -> None:
    data = compound_file({"DestList": b"\x00" * 32})
    assert traces.jump_list_streams(data) == []


def test_the_quick_look_database_is_opened_read_only(tmp_path: Path) -> None:
    database = quicklook_index(tmp_path / "ql", [("/a", "b", 0)])
    database.chmod(0o444)
    try:
        rows, _ = traces.quicklook_entries(database)
    finally:
        database.chmod(0o644)
    assert rows == [("/a/b", 1, 0)]
    with sqlite3.connect(database) as check:
        assert check.execute("SELECT COUNT(*) FROM files").fetchone() == (1,)
