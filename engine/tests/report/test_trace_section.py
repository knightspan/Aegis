"""The file report and its certificate say what the trace sweep did.

The section is present whether or not the sweep ran, so a report of a job that
did not sweep says so instead of falling silent about thumbnails and Trash
copies. The PDF streams are uncompressed, so the certificate's words are
checked in its bytes.
"""

from __future__ import annotations

from typing import Any

from core.report.render import (
    NONE_RECORDED,
    build_file_erase_report,
    render_pdf,
    trace_section,
)

from .test_module_reports import file_inputs


def sweep(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "searched": [
            "thumbnail cache: /home/asha/.cache/thumbnails",
            "home Trash: /home/asha/.local/share/Trash",
        ],
        "not_searched": ["Backups, filesystem snapshots and sync clients."],
        "traces": [
            {
                "kind": "THUMBNAIL",
                "target": "/home/asha/case-2149/notes.docx",
                "location": "/home/asha/.cache/thumbnails/large/0f3a.png",
                "evidence": "Named by the MD5 of file:///home/asha/case-2149/notes.docx.",
                "content_copy": True,
                "exact": True,
                "action": "erased",
                "removed": True,
                "bytes_overwritten": 18_211,
                "error": "",
            },
            {
                "kind": "POSSIBLE_COPY",
                "target": "/home/asha/case-2149/notes.docx",
                "location": "/Users/asha/.Trash/notes.docx",
                "evidence": "An item of the same name is in the Trash.",
                "content_copy": True,
                "exact": False,
                "action": "",
                "removed": False,
                "bytes_overwritten": 0,
                "error": "",
            },
        ],
        "notes": [],
    }
    base.update(overrides)
    return base


def test_the_section_sits_between_verification_and_limitations() -> None:
    names = list(build_file_erase_report(**file_inputs())["sections"])
    assert names.index("traces") == names.index("erase_verification") + 1
    assert names.index("limitations") == names.index("traces") + 1


def test_a_job_that_did_not_sweep_says_so() -> None:
    section = build_file_erase_report(**file_inputs())["sections"]["traces"]
    assert section["swept"] is False
    assert "neither searched for nor removed" in section["note"]
    assert section["items"] == [NONE_RECORDED]


def test_every_trace_is_listed_with_its_evidence_and_what_became_of_it() -> None:
    section = trace_section(sweep())
    assert (section["found"], section["exact"], section["removed"]) == (2, 1, 1)
    assert section["content_copies"] == 2
    first, second = section["items"]
    assert first["path"].endswith("0f3a.png") and first["action"] == "erased"
    assert second["exact"] is False and second["action"] == "none"
    assert section["searched"][0].startswith("thumbnail cache")
    assert section["not_searched"] == [
        "Backups, filesystem snapshots and sync clients."
    ]
    assert section["unreadable"] == [NONE_RECORDED]


def test_the_note_says_a_removed_trace_carries_the_same_residual_limits() -> None:
    note = trace_section(sweep())["note"]
    assert "same steps as a target" in note
    assert "can write an entry back" in note


def test_the_certificate_counts_what_was_found_and_what_was_left() -> None:
    report = build_file_erase_report(**file_inputs(trace_sweep=sweep()))
    blob = render_pdf(report)
    assert b"Desktop traces" in blob
    assert b"2 found, 1 removed, 1 left" in blob


def test_the_certificate_says_when_nothing_was_searched_for() -> None:
    blob = render_pdf(build_file_erase_report(**file_inputs()))
    assert b"not searched for" in blob
