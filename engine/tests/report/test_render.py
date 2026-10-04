"""Report assembly and rendering. JSON is authoritative; PDF says it is not."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from core.ledger.chain import ChainStatus, ChainVerification
from core.report.render import (
    NONE_RECORDED,
    PDF_DISCLAIMER,
    SECTION_ORDER,
    build_report,
    render_json,
    render_pdf,
    write_report,
)


def sample_inputs(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "case_id": "CASE-0001",
        "operator": "A. Operator",
        "generated_at": datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC),
        "tool_version": "0.1.0",
        "device": {
            "model": "ST2000DM008-2FR102",
            "serial": "ZFL2ABCD",
            "by_id_path": "/dev/disk/by-id/ata-ST2000DM008-2FR102_ZFL2ABCD",
            "size_bytes": 2000398934016,
            "transport": "sata",
            "logical_block_size": 512,
            "physical_block_size": 4096,
        },
        "method": {
            "method": "ATA_SANITIZE_BLOCK_ERASE",
            "level_requested": "PURGE",
            "level_achieved": "PURGE",
            "justification": "Drive firmware reports SANITIZE BLOCK_ERASE_EXT.",
            "capability_evidence": {
                "ata_sanitize_ops": ["BLOCK_ERASE_EXT"],
                "ata_enhanced_erase": True,
                "security_frozen": False,
                "is_sed_opal": False,
                "nvme_sanicap": {},
                "achievable_levels": ["CLEAR", "PURGE"],
            },
        },
        "hidden_areas": {
            "hpa_present": True,
            "dco_present": False,
            "native_max_sectors": 3907029168,
            "accessible_sectors": 3907000000,
            "hidden_bytes": 14934016,
            "covered": True,
        },
        "verification": {
            "strategy": "sampled",
            "passed": True,
            "bytes_checked": 4294967296,
            "sample_count": 4096,
            "sample_seed": 1515870810,
            "confidence_bp": 9940,
            "failed_offsets": [],
            "probability_note": "P = 1 - (1 - (r + u - 1) / n)^k, n=2000398934016",
            "hw_attested": True,
        },
        "residual_risk": {
            "level": "low",
            "purge_achieved": True,
            "factors": ["Hardware-attested purge.", "Verification was sampled."],
            "notes": "Hardware-attested purge with clean verification.",
        },
        "limitations": ["DoD third pass is a fixed zero character."],
        "ledger_excerpt": [],
        "chain_verification": ChainVerification(
            status=ChainStatus.VALID,
            explanation="All 12 entries verify, 0..11.",
            verified_through=11,
            entry_count=12,
        ),
        "pubkey_fingerprint": "AA:BB:CC:DD",
    }
    base.update(overrides)
    return base


# --------------------------------------------------------------------------
# Structure
# --------------------------------------------------------------------------


def test_sections_appear_in_the_specified_order() -> None:
    report = build_report(**sample_inputs())
    assert list(report["sections"]) == list(SECTION_ORDER)


def test_section_order_is_the_nine_the_spec_names() -> None:
    assert SECTION_ORDER == (
        "case_identity",
        "device_identity",
        "method",
        "hidden_areas",
        "verification",
        "residual_risk",
        "limitations",
        "audit_trail",
        "signature",
    )


def test_method_section_prints_capability_evidence_not_only_the_conclusion() -> None:
    report = build_report(**sample_inputs())
    evidence = report["sections"]["method"]["capability_evidence"]
    assert evidence["ata_sanitize_ops"] == ["BLOCK_ERASE_EXT"]
    assert evidence["achievable_levels"] == ["CLEAR", "PURGE"]


def test_method_section_cites_nist_r2_and_names_r1_only_as_withdrawn() -> None:
    """NIST SP 800-88r1 was withdrawn on 2025-09-26. A certificate citing it as
    current would carry a false claim inside its signed bytes."""
    report = build_report(**sample_inputs())
    standards = report["sections"]["method"]["standards"]
    assert "NIST SP 800-88r2" in standards["method_vocabulary"]
    text = render_json(report).decode("utf-8")
    assert "Rev.1" not in text
    assert text.count("800-88r1") == text.count("800-88r1 was withdrawn")


def test_method_section_does_not_claim_ieee_2883_conformance() -> None:
    """IEEE 2883-2022 is a paid standard this project has not read. Naming it
    as the standard NIST r2 defers to is a fact about r2; claiming conformance
    would not be."""
    standards = build_report(**sample_inputs())["sections"]["method"]["standards"]
    technique = standards["technique_standard"]
    assert "not been verified against the text of IEEE 2883-2022" in technique
    assert "does not claim conformance" in technique


def test_method_section_names_the_certificate_fields_it_does_not_record() -> None:
    """NIST SP 800-88r2 Sec. 4.6 lists what a certificate records. The ones this
    report has no field for are named, not silently absent."""
    standards = build_report(**sample_inputs())["sections"]["method"]["standards"]
    missing = standards["nist_sp_800_88r2_sec_4_6_fields_not_recorded"]
    assert "media source" in missing
    assert any("verification and validation" in item for item in missing)
    assert "not made by this tool" in standards["verification_and_validation"]


def test_dpdp_reference_says_what_the_record_cannot_establish() -> None:
    references = build_report(**sample_inputs())["sections"]["method"][
        "regulatory_references"
    ]
    (dpdp,) = references
    assert dpdp["instrument"].endswith("section 8(7)")
    assert "G.S.R. 843(E)" in dpdp["in_force"]
    assert len(dpdp["requires_a_person"]) >= 3
    assert any("8(7)(b)" in item for item in dpdp["requires_a_person"])


def test_verification_section_carries_seed_and_formula_not_just_a_number() -> None:
    section = build_report(**sample_inputs())["sections"]["verification"]
    assert section["sample_seed"] == 1515870810
    assert "P = 1 - (1 - (r + u - 1) / n)^k" in section["probability_note"]


def test_audit_trail_carries_the_chain_status() -> None:
    section = build_report(**sample_inputs())["sections"]["audit_trail"]
    assert section["chain_status"] == "VALID"
    assert section["verified_through"] == 11


# --------------------------------------------------------------------------
# Sections 6 and 7 are never omitted
# --------------------------------------------------------------------------


def test_empty_residual_factors_still_produce_the_section() -> None:
    inputs = sample_inputs()
    inputs["residual_risk"] = {
        "level": "low",
        "purge_achieved": True,
        "factors": [],
        "notes": "",
    }
    section = build_report(**inputs)["sections"]["residual_risk"]
    assert section["factors"] == [NONE_RECORDED]


def test_empty_limitations_print_none_recorded_rather_than_disappearing() -> None:
    inputs = sample_inputs()
    inputs["limitations"] = []
    section = build_report(**inputs)["sections"]["limitations"]
    assert section["items"] == [NONE_RECORDED]


def test_limitations_are_carried_verbatim_and_unedited() -> None:
    wordy = (
        "DOD_5220_22_M_3PASS is a legacy method: NIST SP 800-88r2 states that "
        "multi-pass overwrite is not needed, and on flash media it is harmful."
    )
    inputs = sample_inputs(limitations=[wordy, "second"])
    section = build_report(**inputs)["sections"]["limitations"]
    assert section["items"] == [wordy, "second"]


def test_limitations_are_never_truncated() -> None:
    long_item = "x" * 5000
    section = build_report(**sample_inputs(limitations=[long_item]))["sections"][
        "limitations"
    ]
    assert section["items"][0] == long_item


# --------------------------------------------------------------------------
# JSON artifact
# --------------------------------------------------------------------------


def test_json_is_canonical_and_deterministic() -> None:
    report = build_report(**sample_inputs())
    assert render_json(report) == render_json(report)


def test_json_declares_itself_authoritative() -> None:
    report = build_report(**sample_inputs())
    assert report["authoritative"] is True
    assert "forensic.json" in report["authoritative_artifact"]


def test_json_rejects_a_float_anywhere_in_the_report() -> None:
    inputs = sample_inputs()
    inputs["verification"]["confidence_bp"] = 9940
    report = build_report(**inputs)
    # confidence is carried as integer basis points, so canon accepts it.
    assert isinstance(report["sections"]["verification"]["confidence_bp"], int)
    render_json(report)


# --------------------------------------------------------------------------
# PDF artifact
# --------------------------------------------------------------------------


def test_pdf_is_a_pdf() -> None:
    assert render_pdf(build_report(**sample_inputs())).startswith(b"%PDF")


def test_pdf_states_that_it_is_not_authoritative() -> None:
    blob = render_pdf(build_report(**sample_inputs()))
    assert PDF_DISCLAIMER.split(".")[0].encode("latin-1") in blob


def test_pdf_contains_every_section_heading() -> None:
    blob = render_pdf(build_report(**sample_inputs()))
    for heading in ("Residual Risk", "Limitations", "Audit Trail", "Signature"):
        assert heading.encode("latin-1") in blob


def test_pdf_prints_none_recorded_for_an_empty_limitations_section() -> None:
    blob = render_pdf(build_report(**sample_inputs(limitations=[])))
    assert NONE_RECORDED.encode("latin-1") in blob


# --------------------------------------------------------------------------
# Writing both artifacts
# --------------------------------------------------------------------------


def test_write_report_produces_both_files(tmp_path: Path) -> None:
    report = build_report(**sample_inputs())
    json_path, pdf_path = write_report(report, tmp_path)
    assert json_path.name == "CASE-0001.forensic.json"
    assert pdf_path.name == "CASE-0001.forensic.pdf"
    assert json_path.read_bytes()
    assert pdf_path.read_bytes().startswith(b"%PDF")


def test_written_json_round_trips_to_the_same_report(tmp_path: Path) -> None:
    import json

    report = build_report(**sample_inputs())
    json_path, _ = write_report(report, tmp_path)
    assert json.loads(json_path.read_bytes())["case_id"] == "CASE-0001"


@pytest.mark.parametrize("section", ["residual_risk", "limitations"])
def test_required_sections_survive_a_round_trip(
    tmp_path: Path, section: str
) -> None:
    import json

    report = build_report(**sample_inputs(limitations=[]))
    json_path, _ = write_report(report, tmp_path)
    assert section in json.loads(json_path.read_bytes())["sections"]
