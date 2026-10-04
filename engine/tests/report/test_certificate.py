"""The certificate page says what the record supports, and nothing more.

The headline in the coloured band is the line a reader takes away, so each
case that must not read as a sanitized medium is pinned here: a failed
read-back, a run with no read-back, a job that did not complete, and - for
reports signed by earlier builds, which are historical evidence and must stay
readable - a rehearsal recorded as "dry run" or "SIMULATION". The PDF streams
are uncompressed, so the words are checked in the bytes.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from core.report.render import build_report, render_json, render_pdf

from .test_render import sample_inputs


def _pdf(**overrides: Any) -> bytes:
    return render_pdf(build_report(**sample_inputs(**overrides)))


def test_a_verified_purge_is_certified_as_such() -> None:
    blob = _pdf()
    assert b"Certificate of Sanitization" in blob
    assert b"PURGE achieved and verified" in blob


def test_the_page_carries_the_sha256_of_the_signed_file() -> None:
    report = build_report(**sample_inputs())
    digest = hashlib.sha256(render_json(report)).hexdigest()
    blob = render_pdf(report)
    assert digest.encode() in blob
    assert b"CASE-0001.forensic.json" in blob


@pytest.mark.parametrize(
    ("overrides", "headline"),
    [
        (
            {
                "method": {
                    "method": "SINGLE_PASS_OVERWRITE",
                    "level_requested": "CLEAR",
                    "level_achieved": "NONE (dry run: nothing was written)",
                },
                "verification": {},
            },
            b"Rehearsal record: nothing was written",
        ),
        (
            {
                "verification": {
                    "strategy": "sampled",
                    "passed": False,
                    "bytes_checked": 4096,
                    "failed_offsets": [0, 512],
                },
            },
            b"Verification failed: not proven sanitized",
        ),
        (
            {"verification": {}},
            b"No read-back verification recorded",
        ),
        (
            {"job_state": "failed"},
            b"Not a certificate: the job failed",
        ),
        (
            {"limitations": ["DRY RUN / NO PHYSICAL DEVICE MODIFIED: host file."]},
            b"Rehearsal record: no device was sanitized",
        ),
        (
            {"limitations": ["SIMULATION / NO PHYSICAL DEVICE MODIFIED: host file."]},
            b"Rehearsal record: no device was sanitized",
        ),
    ],
    ids=[
        "legacy-dry-run",
        "failed-read-back",
        "no-read-back",
        "job-failed",
        "legacy-dry-run-host-file",
        "legacy-simulation-host-file",
    ],
)
def test_nothing_short_of_a_verified_run_is_headlined_as_one(
    overrides: dict[str, Any], headline: bytes
) -> None:
    blob = _pdf(**overrides)
    assert headline in blob
    assert b"achieved and verified" not in blob


def test_an_unsigned_record_says_so_where_the_signature_would_be() -> None:
    assert b"UNSIGNED: this record carries no signature" in _pdf()
