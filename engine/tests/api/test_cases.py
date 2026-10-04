"""Cases group evidence, operations and reports, and the chain is the record.

Two properties are worth stating in tests rather than only in a docstring:

* the case document is an **index** - deleting it loses grouping and no
  evidence, and the integrity verdict on the case screen is always the chain's;
* a case id becomes a filename, so it is validated against a whitelist rather
  than escaped, and the refusals are tested by the attack they close.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from api.deps import AppServices
from core.cases import CaseError, create_case, list_cases, load_case, valid_case_id
from fastapi.testclient import TestClient

from .conftest import settle


def _open_case(client: TestClient, case_id: str = "CASE-2026-001") -> dict[str, object]:
    answer = client.post(
        "/cases",
        json={"case_id": case_id, "title": "Seized laptop", "description": "NTRO"},
    )
    assert answer.status_code == 200, answer.text
    body: dict[str, object] = answer.json()["case"]
    return body


# --------------------------------------------------------------------------
# Identifiers
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "../escape",
        "a/b",
        "a\\b",
        ".hidden",
        "..",
        "case..2026",
        "x" * 65,
    ],
)
def test_an_illegal_case_id_is_refused_because_it_becomes_a_filename(
    bad: str,
) -> None:
    with pytest.raises(CaseError):
        valid_case_id(bad)


def test_a_traversing_case_id_is_refused_by_the_api(client: TestClient) -> None:
    answer = client.post("/cases", json={"case_id": "../../etc/passwd"})

    # 409: the body is well formed and the id is what makes it unacceptable.
    assert answer.status_code == 409, answer.text
    assert answer.json()["detail"]["kind"] == "CaseRefused"
    assert not list(Path("/etc").glob("passwd.json"))


# --------------------------------------------------------------------------
# Lifecycle
# --------------------------------------------------------------------------


def test_a_case_is_created_listed_and_retrieved(client: TestClient) -> None:
    _open_case(client)

    listing = client.get("/cases").json()["cases"]
    assert [item["case_id"] for item in listing] == ["CASE-2026-001"]

    detail = client.get("/cases/CASE-2026-001").json()
    assert detail["case"]["title"] == "Seized laptop"
    assert detail["case"]["evidence_count"] == 0
    assert detail["case"]["operation_count"] == 0


def test_a_duplicate_case_is_refused_rather_than_merged_into(
    client: TestClient,
) -> None:
    """Silently merging into somebody else's case is the mistake this prevents."""
    _open_case(client)

    answer = client.post("/cases", json={"case_id": "CASE-2026-001"})

    assert answer.status_code in {400, 409}
    assert answer.json()["detail"]["remediation"]


def test_a_missing_case_is_a_404_with_a_remediation(client: TestClient) -> None:
    answer = client.get("/cases/CASE-DOES-NOT-EXIST")

    assert answer.status_code == 404
    assert answer.json()["detail"]["kind"] == "CaseNotFound"


def test_the_creator_is_the_trusted_identity_and_not_a_body_field(
    client: TestClient, services: AppServices
) -> None:
    """There is no ``created_by`` in the request model, and this proves it.

    A body that names one is ignored by pydantic, and the value that lands in
    the document is the one :mod:`api.identity` resolved.
    """
    from api.identity import resolve

    client.post(
        "/cases",
        json={"case_id": "CASE-ID-1", "created_by": "Chief Examiner"},
    )
    case = load_case(services.cases_dir, "CASE-ID-1")

    assert case.created_by == resolve(services).actor
    assert "Chief Examiner" not in case.created_by


# --------------------------------------------------------------------------
# Attachment
# --------------------------------------------------------------------------


def test_evidence_is_registered_against_a_case(client: TestClient) -> None:
    _open_case(client)

    answer = client.post(
        "/cases/CASE-2026-001/evidence",
        json={
            "evidence_id": "EX-1",
            "source": "/dev/sdz",
            "media_type": "raw image",
            "source_hash": "a" * 64,
        },
    )

    assert answer.status_code == 200, answer.text
    detail = client.get("/cases/CASE-2026-001").json()
    assert detail["case"]["evidence_count"] == 1
    assert detail["evidence"][0]["evidence_id"] == "EX-1"
    assert detail["evidence"][0]["source_hash"] == "a" * 64


def test_a_job_started_under_a_case_appears_in_its_operations_and_timeline(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    _open_case(client)
    source = tmp_path / "exhibit.bin"
    source.write_bytes(b"\x00" * 4096)

    accepted = client.post(
        "/jobs/acquire",
        json={
            "source": str(source),
            "dest": "case.dd",
            "case_id": "CASE-2026-001",
            "operator": "tester",
        },
    )
    assert accepted.status_code == 200, accepted.text
    job_id = accepted.json()["job_id"]
    assert settle(services, job_id) == "complete"

    detail = client.get("/cases/CASE-2026-001").json()
    assert [item["operation_id"] for item in detail["operations"]] == [job_id]
    # The engine's own entries are keyed by job_id and know nothing about
    # cases; the timeline finds them through the operation id.
    events = {item["event"] for item in detail["audit"]["events"]}
    assert "case.opened" in events
    assert any(event.startswith("acquire") for event in events)


def test_a_job_naming_an_unknown_case_still_runs(
    client: TestClient, tmp_path: Path
) -> None:
    """A typo in an optional field must not block an authorised operation.

    The chain records the run regardless; the case screen shows only what it
    was told about.
    """
    source = tmp_path / "exhibit.bin"
    source.write_bytes(b"\x00" * 1024)

    accepted = client.post(
        "/jobs/acquire",
        json={"source": str(source), "dest": "x.dd", "case_id": "CASE-TYPO"},
    )

    assert accepted.status_code == 200, accepted.text


# --------------------------------------------------------------------------
# The document is an index, not the record
# --------------------------------------------------------------------------


def test_an_unreadable_case_document_does_not_break_the_listing(
    services: AppServices,
) -> None:
    create_case(services.cases_dir, case_id="GOOD-1")
    (services.cases_dir / "broken.json").write_text("{not json", encoding="utf-8")

    listing = list_cases(services.cases_dir)

    assert [item["case_id"] for item in listing] == ["GOOD-1"]


def test_the_case_screen_reports_the_chains_integrity_and_not_the_documents(
    client: TestClient,
) -> None:
    _open_case(client)

    detail = client.get("/cases/CASE-2026-001").json()

    assert detail["case"]["integrity"] == detail["audit"]["chain_status"]
    assert detail["audit"]["chain_status"] in {"VALID", "EMPTY", "INCOMPLETE_TAIL"}


# --------------------------------------------------------------------------
# Closing
# --------------------------------------------------------------------------


def test_a_case_is_closed_chained_and_then_refuses_new_evidence(
    client: TestClient,
) -> None:
    _open_case(client, "CASE-CLOSE-1")
    closed = client.post("/cases/CASE-CLOSE-1/close")
    assert closed.status_code == 200, closed.text
    summary = closed.json()["case"]
    assert summary["status"] == "closed"
    assert summary["closed_at"]

    events = client.get("/cases/CASE-CLOSE-1").json()["audit"]["events"]
    assert any(item["event"] == "case.closed" for item in events)

    late = client.post(
        "/cases/CASE-CLOSE-1/evidence",
        json={"evidence_id": "EV-1", "source": "/dev/sdx", "media_type": "usb"},
    )
    assert late.status_code >= 400


def test_closing_twice_and_closing_a_missing_case_are_refused(
    client: TestClient,
) -> None:
    _open_case(client, "CASE-CLOSE-2")
    assert client.post("/cases/CASE-CLOSE-2/close").status_code == 200
    assert client.post("/cases/CASE-CLOSE-2/close").status_code >= 400
    assert client.post("/cases/NO-SUCH-CASE/close").status_code == 404
