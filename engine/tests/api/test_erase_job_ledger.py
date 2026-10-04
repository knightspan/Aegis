"""A drive erasure is ledgered under the id the caller was given, or not at all.

The erase route used to hand the helper the literal string ``"pending"`` while
returning a real ``erase-drive-<hex>`` id to the browser. The helper put that
placeholder into the ``EraseJob``, and :mod:`core.erase.drive` wrote it into
every ledger entry across all six phases. Both consumers filter on the real id:

* ``GET /jobs/{id}`` (:func:`api.routes.jobs._ledger_entries_for`)
* the report excerpt (:func:`api.routes.audit.generate_report`)

So the chain was intact, every phase was recorded, and no report or job lookup
could ever find one of them again. A wipe's certificate carried nothing but the
genesis entry. That is the failure mode that looks like working software right
up to the moment somebody asks for the audit trail - the same one
``tests/api/test_carve_ledger.py`` pins for the recovery pipeline.

These tests pin the binding itself rather than any one consumer, because the id
is the only thing that ties the six phase entries to the job that produced them.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from api.deps import AppServices
from api.routes import jobs as jobs_route
from fastapi.testclient import TestClient

from tests.api.conftest import RecordingHelper, authorize


@pytest.fixture
def erase(client: TestClient, services: AppServices) -> Any:
    """Start one authorized erase of the synthetic device; return the answer."""

    def start() -> dict[str, Any]:
        answer = client.post(
            "/jobs/erase-drive",
            json={
                "path": "/dev/sdz",
                "typed_serial": "SYN-PURGE-1",
                "authorization_id": authorize(client, services),
            },
        )
        assert answer.status_code == 200, answer.text
        return dict(answer.json())

    return start


def _run_erase_params(helper: RecordingHelper) -> dict[str, object]:
    """The parameters the single ``run_erase`` call was made with."""
    calls = [params for method, params in helper.calls if method == "run_erase"]
    assert len(calls) == 1, f"expected one run_erase call, got {len(calls)}"
    return calls[0]


def test_the_helper_receives_the_job_id_the_caller_was_given(
    client: TestClient, helper: RecordingHelper, erase: Any
) -> None:
    """The one property every consumer of the chain depends on."""
    accepted = erase()
    client.get(f"/jobs/{accepted['job_id']}/stream")

    assert _run_erase_params(helper)["job_id"] == accepted["job_id"]


def test_the_helper_is_never_handed_a_placeholder_id(
    client: TestClient, helper: RecordingHelper, erase: Any
) -> None:
    """``"pending"`` is a JobState, not an identifier. It must not reach a ledger."""
    accepted = erase()
    client.get(f"/jobs/{accepted['job_id']}/stream")

    assert _run_erase_params(helper)["job_id"] != "pending"


def test_the_returned_id_keeps_the_registry_s_own_shape(erase: Any) -> None:
    """Minting it in the route must not change the id format callers already see."""
    accepted = erase()

    job_id = accepted["job_id"]
    assert job_id.startswith("erase-drive-")
    assert len(job_id.removeprefix("erase-drive-")) == 12


def test_the_job_is_filed_in_the_registry_under_that_same_id(
    client: TestClient, erase: Any
) -> None:
    """A job the route named and the registry filed differently is unreachable."""
    accepted = erase()

    status = client.get(f"/jobs/{accepted['job_id']}")
    assert status.status_code == 200
    assert status.json()["job_id"] == accepted["job_id"]


def test_progress_records_carry_the_job_id_the_caller_can_stream(
    client: TestClient, erase: Any
) -> None:
    """The helper echoes the id back into every Progress record it returns."""
    accepted = erase()
    client.get(f"/jobs/{accepted['job_id']}/stream")

    latest = client.get(f"/jobs/{accepted['job_id']}").json()["latest"]
    assert latest is not None
    assert latest["job_id"] == accepted["job_id"]


def test_no_placeholder_job_id_literal_survives_in_the_route() -> None:
    """Static guard, in the shape ``tests/test_stubs_raise.py`` uses.

    The behavioural tests above only see the erase route. A placeholder id
    reintroduced on any other helper-backed route would write the same
    unfindable entries, and this reads the source rather than waiting for a
    test to be written for that route.
    """
    source = Path(jobs_route.__file__).read_text(encoding="utf-8")
    offenders = [
        line.strip()
        for line in source.splitlines()
        if '"job_id": "' in line or "'job_id': '" in line
    ]
    assert not offenders, (
        "a literal job id is being sent to the helper; it must be the id the "
        f"registry filed the job under: {offenders}"
    )
