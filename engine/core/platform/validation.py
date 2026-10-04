"""Which platform test suites have actually passed, for this build.

A capability that exists in code but has never run on its platform is
UNVERIFIED, not SUPPORTED. The difference is evidence, and this module is
where the evidence lives: ``validation_record.json`` beside it, written by
``scripts/record_platform_validation.py`` from a real pytest run on that
platform (a developer machine or a CI runner) and never edited by hand.

The record is per *suite*, not per feature: ``file_erase`` is the set of tests
under ``tests/erase/files`` plus ``tests/platform``, run on the platform named.
A suite with no entry, or an entry that is not ``PASS``, leaves every
capability it backs at UNVERIFIED with the recorded state in the reason.

Hardware results are separate (``hardware`` in the record): an automated suite
passing on a CI runner says the code works on that OS, not that a USB stick
from a particular vendor was sanitized. Those entries are only ever added from
a run on designated test media, and ``NOT RUN`` is the default.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

__all__ = [
    "RECORD_PATH",
    "load_record",
    "suite_state",
    "suite_passed",
    "hardware_passed",
]

RECORD_PATH = Path(__file__).with_name("validation_record.json")


def load_record(path: Path | None = None) -> dict[str, Any]:
    """The record, or an empty one if it is missing or unreadable."""
    target = path or RECORD_PATH
    try:
        loaded = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def suite_state(
    platform: str, suite: str, record: dict[str, Any] | None = None
) -> dict[str, Any]:
    """``{"state": "PASS"|"FAIL"|"NOT RUN", ...}`` for one suite on one platform."""
    data = load_record() if record is None else record
    entry = (data.get("suites") or {}).get(platform, {}).get(suite)
    if not isinstance(entry, dict) or "state" not in entry:
        return {"state": "NOT RUN"}
    return entry


def suite_passed(
    platform: str, suite: str, record: dict[str, Any] | None = None
) -> bool:
    return suite_state(platform, suite, record).get("state") == "PASS"


def hardware_passed(
    platform: str, feature: str, record: dict[str, Any] | None = None
) -> bool:
    """Whether ``hardware`` records a PASS for ``feature`` on real media.

    Same shape as ``suites``: ``{"hardware": {platform: {feature: {"state":
    ...}}}}``. A missing entry is NOT RUN, so a feature whose code is present
    and whose suites pass still reads as unexercised on hardware until a run
    on designated test media is recorded.
    """
    data = load_record() if record is None else record
    entry = (data.get("hardware") or {}).get(platform, {}).get(feature)
    return isinstance(entry, dict) and entry.get("state") == "PASS"


def describe(platform: str, suite: str, record: dict[str, Any] | None = None) -> str:
    """One sentence for a capability row's source."""
    entry = suite_state(platform, suite, record)
    state = entry.get("state", "NOT RUN")
    if state == "NOT RUN":
        return f"validation record: {suite} suite on {platform} NOT RUN"
    where = entry.get("runner") or "unknown runner"
    when = entry.get("date") or "unknown date"
    counts = entry.get("counts") or {}
    tally = ", ".join(f"{key} {value}" for key, value in sorted(counts.items()))
    return (
        f"validation record: {suite} suite on {platform} {state} "
        f"({tally or 'no counts'}; {where}; {when})"
    )
