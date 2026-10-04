"""No screen may render a carve evidence score as a percentage.

``confidence_bp`` on a carve candidate is a clamped sum of evidence
components. Formatting it with ``percent()`` produced "100.00%" beside the word
HIGH, which reads as a probability of correctness that no calibration in this
repository establishes. The fix is a rendering, and a rendering is exactly the
kind of thing that gets quietly reverted by someone reaching for the nearest
formatter, so this reads the source and fails if it comes back.

``percent()`` itself stays: the post-erase detection probability and the share
of high-entropy windows really are proportions.
"""

from __future__ import annotations

import re
from pathlib import Path

UI_SRC = Path(__file__).resolve().parents[2] / "ui" / "src"

#: ``percent(<anything>confidence_bp…)``. Matches the candidate and the table
#: row alike, because both went through the same helper.
_PERCENT_OF_CONFIDENCE = re.compile(r"percent\(\s*[A-Za-z_.]*confidence_bp")


def test_no_tsx_source_formats_a_carve_confidence_as_a_percentage() -> None:
    offenders: list[str] = []
    for path in sorted(UI_SRC.rglob("*.ts*")):
        text = path.read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), start=1):
            if _PERCENT_OF_CONFIDENCE.search(line):
                # The Sanitize screen's verification confidence is a real
                # probability and is allowed to be a percentage.
                if "verification" in line:
                    continue
                offenders.append(f"{path.relative_to(UI_SRC)}:{number}: {line.strip()}")
    assert not offenders, (
        "a carve evidence score is being rendered as a percentage, which reads "
        "as a probability of correctness:\n  " + "\n  ".join(offenders)
    )


def test_the_recovery_screen_uses_the_evidence_score_formatter() -> None:
    recovery = (UI_SRC / "screens" / "Recovery.tsx").read_text(encoding="utf-8")
    assert "evidenceScore(" in recovery
    # And says the thing the number is not, where the breakdown is shown.
    assert "not a" in recovery and "probability" in recovery


def test_the_table_column_is_not_headed_confidence_alone() -> None:
    """A column headed "Confidence" over a bounded number invites the reading."""
    recovery = (UI_SRC / "screens" / "Recovery.tsx").read_text(encoding="utf-8")
    assert "<th>Confidence</th>" not in recovery
    assert "Evidence score" in recovery


def test_the_formatter_documents_why_the_two_numbers_differ() -> None:
    fmt = (UI_SRC / "lib" / "format.ts").read_text(encoding="utf-8")
    assert "evidenceScore" in fmt
    assert "10500" in fmt or "10,500" in fmt
