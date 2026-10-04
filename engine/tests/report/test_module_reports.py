"""Reports for the file eraser and the recovery engine.

Both used to go through the drive-erase builder, which reads its device, method,
hidden-area and verification sections out of a result that a file erasure and a
carve simply do not have. The output was a report whose every substantive
section was empty — a document that reads as a tool that examined something and
found nothing to say about it, which is worse than no report at all.

What these tests hold down is that each shape carries its own subject matter, and
that all three shapes still carry the *same* audit trail and signature block,
because that is the half a third party checks and it must not vary by kind.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from core.ledger.chain import ChainStatus, ChainVerification
from core.report.render import (
    NONE_RECORDED,
    build_carve_report,
    build_file_erase_report,
    build_report,
    render_json,
    render_pdf,
    write_report,
)

CHAIN = ChainVerification(
    status=ChainStatus.VALID,
    explanation="All 12 entries verify, 0..11.",
    verified_through=11,
    entry_count=12,
)

COMMON: dict[str, Any] = {
    "case_id": "CASE-0001",
    "operator": "A. Operator",
    "generated_at": datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC),
    "tool_version": "0.1.0",
    "ledger_excerpt": [],
    "chain_verification": CHAIN,
    "pubkey_fingerprint": "AA:BB:CC:DD",
}


def file_records() -> list[dict[str, Any]]:
    return [
        {
            "path": "/home/analyst/case-2149/notes.docx",
            "ok": True,
            "bytes_overwritten": 41984,
            "unlinked": True,
            "streams_removed": [],
            "xattrs_removed": ["user.xdg.origin.url"],
            "error": None,
            "error_kind": None,
            "findings": [
                {
                    "kind": "FS_JOURNAL",
                    "severity": "MEDIUM",
                    "addressable": False,
                    "explanation": "ext4 journals metadata and sometimes data.",
                }
            ],
            "verification": {
                "passed": None,
                "strategy": "none",
                "reason": "copy-on-write filesystem; extents cannot be re-read",
            },
        },
        {
            "path": "/var/log/journal/sanctum",
            "ok": False,
            "bytes_overwritten": 0,
            "unlinked": False,
            "streams_removed": [],
            "xattrs_removed": [],
            "error": "refused: path is under a protected prefix",
            "error_kind": "PathRefused",
            "findings": [],
            "verification": None,
        },
    ]


def carve_inputs(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = dict(COMMON)
    base.update(
        {
            "evidence": {
                "path": "/evidence/case-2149/recovery-fat32.dd",
                "size_bytes": 7759462400,
                "format": "RawEvidence",
                "identity": {
                    "sha256": "a" * 64,
                    "covers": "first and last 1048576 bytes, and the length",
                    "is_whole_image_hash": False,
                },
            },
            "candidates": [
                {
                    "offset": 1048576,
                    "length": 24030,
                    "ext": "jpg",
                    "mime": "image/jpeg",
                    "source": "signature",
                    "validation": "DECODED",
                    "bucket": "HIGH",
                    "confidence_bp": 8300,
                    "sha256": "b" * 64,
                    "original_name": None,
                    "category": "image",
                    "contiguity_assumed": False,
                    "contiguity_contradicted": False,
                },
                {
                    "offset": 2097152,
                    "length": 8192,
                    "ext": "pdf",
                    "mime": "application/pdf",
                    "source": "fs_metadata",
                    "validation": "HEADER_ONLY",
                    "bucket": "LOW",
                    "confidence_bp": 4500,
                    "sha256": "c" * 64,
                    "original_name": "report.pdf",
                    "category": "document",
                    "contiguity_assumed": True,
                    "contiguity_contradicted": True,
                },
            ],
            "partitions": [
                {
                    "index": 0,
                    "offset": 1048576,
                    "length": 7758413824,
                    "fs_type": "FAT32",
                }
            ],
            "unallocated_bytes": 6000000000,
            "written": ["/out/000001.jpg"],
            "limitations": ["41% of the span had no filesystem to corroborate."],
        }
    )
    base.update(overrides)
    return base


def file_inputs(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = dict(COMMON)
    base.update(
        {
            "records": file_records(),
            "limitations": ["Directory fsync is not available on Windows."],
        }
    )
    base.update(overrides)
    return base


# --------------------------------------------------------------------------
# What every shape must share
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "report",
    [
        build_file_erase_report(**file_inputs()),
        build_carve_report(**carve_inputs()),
    ],
    ids=["file-erase", "carve"],
)
def test_every_shape_carries_the_sections_a_verifier_checks(
    report: dict[str, Any],
) -> None:
    """`verify_report` must not need to know which kind it was handed."""
    sections = report["sections"]
    assert set(sections).issuperset({"case_identity", "audit_trail", "signature"})
    assert sections["audit_trail"]["chain_status"] == "VALID"
    assert sections["audit_trail"]["entry_count"] == 12
    assert report["authoritative"] is True
    assert report["authoritative_artifact"] == "CASE-0001.forensic.json"


@pytest.mark.parametrize(
    "report",
    [
        build_file_erase_report(**file_inputs()),
        build_carve_report(**carve_inputs()),
    ],
    ids=["file-erase", "carve"],
)
def test_every_shape_opens_with_case_identity_and_closes_with_the_signature(
    report: dict[str, Any],
) -> None:
    names = list(report["sections"])
    assert names[0] == "case_identity"
    assert names[-1] == "signature"
    assert names[-2] == "audit_trail"
    assert names[-3] == "limitations"


@pytest.mark.parametrize(
    "report",
    [
        build_report(
            **COMMON,
            device={},
            method={},
            hidden_areas={},
            verification={},
            residual_risk={},
            limitations=[],
        ),
        build_file_erase_report(**file_inputs()),
        build_carve_report(**carve_inputs()),
    ],
    ids=["drive", "file-erase", "carve"],
)
def test_every_shape_renders_to_both_artifacts(
    report: dict[str, Any], tmp_path: Path
) -> None:
    """The PDF renderer walks the report's own sections, not a fixed list."""
    assert render_json(report).startswith(b"{")
    pdf = render_pdf(report)
    assert pdf.startswith(b"%PDF")
    json_path, pdf_path = write_report(report, tmp_path)
    assert json_path.exists() and pdf_path.exists()


# --------------------------------------------------------------------------
# File erasure
# --------------------------------------------------------------------------


def test_the_file_report_names_every_residual_finding_not_a_count() -> None:
    """The findings are the deliverable. A count is not one."""
    sections = build_file_erase_report(**file_inputs())["sections"]
    findings = sections["residual_findings"]
    assert findings["count"] == 1
    assert findings["by_severity"] == {"MEDIUM": 1}
    assert findings["items"][0]["kind"] == "FS_JOURNAL"
    assert findings["items"][0]["path"] == "/home/analyst/case-2149/notes.docx"
    assert "journals metadata" in findings["items"][0]["explanation"]


def test_the_file_report_counts_a_refused_path_as_failed() -> None:
    sections = build_file_erase_report(**file_inputs())["sections"]
    assert sections["results"]["failed"] == 1
    assert sections["results"]["erased"] == 1
    assert sections["scope"]["paths_requested"] == 2


def test_an_unverifiable_erasure_is_never_counted_as_verified() -> None:
    """`passed: None` means nobody could check, which is not a pass."""
    sections = build_file_erase_report(**file_inputs())["sections"]
    verification = sections["erase_verification"]
    assert verification["files_not_verifiable"] == 2
    assert verification["files_verified_by_physical_read"] == 0
    assert "not verified" in verification["note"]


def test_the_file_report_claims_no_sanitization_method_for_a_file_overwrite() -> None:
    """NIST SP 800-88r2 defines clear over every user-addressable location of a
    medium. A file erasure reaches the file's extents, so it is not one."""
    scope = build_file_erase_report(**file_inputs())["sections"]["scope"]
    standards = scope["standards"]
    assert standards["method_vocabulary"].startswith("No NIST SP 800-88r2")
    assert "no conformance is claimed" in standards["technique_standard"]
    (dpdp,) = scope["regulatory_references"]
    assert dpdp["instrument"].startswith("Digital Personal Data Protection Act")


def test_a_new_file_report_carries_no_rehearsal_flag() -> None:
    """Current code reports real erasures only: no dry-run scope or item flag."""
    sections = build_file_erase_report(**file_inputs())["sections"]
    assert "dry_run" not in sections["scope"]
    assert all("dry_run" not in item for item in sections["results"]["items"])


def test_the_file_report_builder_refuses_a_dry_run_argument() -> None:
    with pytest.raises(TypeError):
        build_file_erase_report(**file_inputs(dry_run=True))


def test_a_file_report_with_no_records_still_produces_every_section() -> None:
    report = build_file_erase_report(**file_inputs(records=[], limitations=[]))
    sections = report["sections"]
    assert sections["results"]["items"] == [NONE_RECORDED]
    assert sections["residual_findings"]["items"] == [NONE_RECORDED]
    assert sections["limitations"]["items"] == [NONE_RECORDED]


# --------------------------------------------------------------------------
# Recovery
# --------------------------------------------------------------------------


def test_the_carve_report_identifies_the_evidence_it_read() -> None:
    sections = build_carve_report(**carve_inputs())["sections"]
    evidence = sections["evidence"]
    assert evidence["path"] == "/evidence/case-2149/recovery-fat32.dd"
    assert evidence["size_bytes"] == 7759462400
    assert evidence["identity"]["is_whole_image_hash"] is False


def test_the_carve_report_states_the_evidence_was_never_opened_for_writing() -> None:
    """Evidential integrity is a claim, so the report has to make it explicitly."""
    sections = build_carve_report(**carve_inputs())["sections"]
    integrity = sections["acquisition_integrity"]
    assert integrity["opened_read_only"] is True
    assert "O_RDONLY" in integrity["note"]
    assert integrity["objects_written"] == 1


def test_the_carve_report_buckets_candidates_and_keeps_every_one() -> None:
    sections = build_carve_report(**carve_inputs())["sections"]
    assert sections["confidence"]["by_bucket"] == {"HIGH": 1, "LOW": 1}
    assert sections["recovery"]["candidates"] == 2
    assert sections["recovery"]["by_source"] == {"signature": 1, "fs_metadata": 1}
    assert len(sections["recovery"]["items"]) == 2


def test_the_carve_report_counts_candidates_whose_layout_was_inferred() -> None:
    """A file the tool did not reassemble must be marked, not reported as whole."""
    sections = build_carve_report(**carve_inputs())["sections"]
    assert sections["recovery"]["contiguity_assumed"] == 1
    assert sections["recovery"]["contiguity_contradicted"] == 1


def test_the_carve_report_carries_what_the_decoder_said() -> None:
    """A verdict without its reason is half a finding.

    A phone photo carved from a medium is ``valid`` while its MPF index declares
    a gain map the object does not hold. That second image, and where it was
    declared, is visible only in the detail - so the report has to carry it.
    """
    detail = (
        "MPO 4032x3024: this object holds 1 of the 2 images its MPF index "
        "declares, fully decoded. Not in this object (1921938 bytes): image 2, "
        "declared at byte 1921938, at or past its end."
    )
    inputs = carve_inputs()
    inputs["candidates"][0]["validation_detail"] = detail

    items = build_carve_report(**inputs)["sections"]["recovery"]["items"]

    assert items[0]["validation_detail"] == detail
    assert items[1]["validation_detail"] == ""


def test_the_confidence_section_carries_the_arithmetic_not_only_the_bucket() -> None:
    sections = build_carve_report(**carve_inputs())["sections"]
    confidence = sections["confidence"]
    assert confidence["thresholds"] == {"HIGH": 8000, "MEDIUM": 5000}
    # Six measured components plus the reassembly ceiling (Batch 7).
    assert len(confidence["components"]) == 7
    assert confidence["components"][-1] == "reassembly"
    assert "calibrated" in confidence["note"]


def test_a_carve_report_with_no_candidates_still_produces_every_section() -> None:
    report = build_carve_report(
        **carve_inputs(candidates=[], written=[], partitions=[], limitations=[])
    )
    sections = report["sections"]
    assert sections["recovery"]["candidates"] == 0
    assert sections["recovery"]["items"] == [NONE_RECORDED]
    assert sections["acquisition_integrity"]["output_paths"] == [NONE_RECORDED]
    assert sections["evidence"]["partitions"] == [NONE_RECORDED]
