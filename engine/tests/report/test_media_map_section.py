"""The recovery report carries the media map's totals and how they were reached."""

from __future__ import annotations

from core.report.render import build_carve_report, media_map_summary

from .test_module_reports import carve_inputs

MAPPED = {
    "size_bytes": 1_048_576,
    "region_bytes": 65_536,
    "block_bytes": 4096,
    "sampled": True,
    "bytes_read": 262_144,
    "regions": [{"offset": 0}] * 16,
    "by_kind": {"ZERO": 786_432, "HIGH_ENTROPY": 262_144},
    "headers": {"jpg": 3},
    "limitations": ["SAMPLED: ..."],
}


def test_the_evidence_section_says_how_the_image_was_mapped() -> None:
    report = build_carve_report(**carve_inputs(), media_map=MAPPED)
    summary = report["sections"]["evidence"]["media_map"]
    assert summary["mapped"] is True and summary["sampled"] is True
    assert summary["regions"] == 16
    assert summary["bytes_by_class"]["ZERO"] == 786_432
    assert summary["headers_on_sector_boundaries"] == {"jpg": 3}


def test_a_run_without_a_map_says_so() -> None:
    assert media_map_summary(None)["mapped"] is False
    report = build_carve_report(**carve_inputs())
    assert report["sections"]["evidence"]["media_map"]["mapped"] is False
