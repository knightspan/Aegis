"""A client cannot tell the ledger who it is.

The gap this closes: ``operator`` was a string in a request body, the Audit
screen had a text box for it, and whatever was typed became the ``actor`` of
every chain entry. A chain of custody whose custody field is a free-text box is
a chain of custody in name only.

The identity now comes from the privileged helper, which answers ``whoami``
from the uid it was started with and never from anything in the request. What
an examiner types is kept - it is useful - but it is kept as a *label*, marked
as one, and never merged into the trusted half of the string.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from api.deps import AppServices
from api.identity import Identity, resolve, sanitise_label
from core.ledger.chain import Ledger
from fastapi.testclient import TestClient
from helper.daemon import HelperDaemon, InProcessHelper

from .conftest import settle


def _actors(services: AppServices) -> list[str]:
    chain = Ledger(services.ledger_root, tool_version="t", pubkey_fingerprint="")
    return [entry.actor for entry in chain.entries()]


def _run_acquire(
    client: TestClient, services: AppServices, tmp_path: Path, operator: str
) -> str:
    source = tmp_path / "exhibit.bin"
    source.write_bytes(b"\x00" * 2048)
    accepted = client.post(
        "/jobs/acquire",
        json={"source": str(source), "dest": "id.dd", "operator": operator},
    )
    assert accepted.status_code == 200, accepted.text
    job_id: str = accepted.json()["job_id"]
    assert settle(services, job_id) == "complete"
    return job_id


# --------------------------------------------------------------------------
# The helper is the source
# --------------------------------------------------------------------------


def _own_uid() -> int:
    """This process's uid, or ``-1`` on Windows, which has no such number."""
    getuid = getattr(os, "getuid", None)
    return int(getuid()) if getuid is not None else -1


def test_the_helper_answers_whoami_from_its_own_uid_not_the_request() -> None:
    """A caller that names a uid, a username or a basis does not get it back."""
    helper = InProcessHelper()

    answer = helper.call(
        "whoami",
        {
            "uid": 0,
            "username": "root",
            "owner_uid": 0,
            "identity_basis": "trust me",
        },
    )

    assert answer["uid"] == _own_uid()
    assert answer["username"] != "root" or _own_uid() == 0
    assert answer["basis"] != "trust me"


def test_whoami_is_in_the_allowlist_and_not_a_side_door() -> None:
    """It goes through the same static table every other operation does."""
    from helper.daemon import OPERATIONS

    assert "whoami" in OPERATIONS


def test_a_confined_daemon_reports_the_stronger_basis(tmp_path: Path) -> None:
    """The basis sentence distinguishes the two deployments and never overstates.

    A socket daemon was started with a fixed operator uid and SO_PEERCRED
    admits nothing else. The in-process helper holds no privilege and its basis
    says so.
    """
    confined = HelperDaemon(operator_uid=4242, state_dir=tmp_path)
    unconfined = HelperDaemon(operator_uid=4242)

    assert "SO_PEERCRED" in confined.identity_basis
    assert "4242" in confined.identity_basis
    assert "in-process" in unconfined.identity_basis
    assert "no more" in unconfined.identity_basis


# --------------------------------------------------------------------------
# A client cannot spoof the actor
# --------------------------------------------------------------------------


def test_a_client_supplied_operator_never_becomes_the_ledger_actor(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    _run_acquire(client, services, tmp_path, "Chief Examiner")

    identity = resolve(services)
    actors = _actors(services)

    assert actors, "the run should have written entries"
    for actor in actors:
        if actor == "sanctum":
            continue  # the genesis entry's fixed actor
        # The trusted identity is present in every actor string...
        assert identity.actor in actor
        # ... and the claimed name is never there on its own.
        assert not actor.startswith("Chief Examiner")


def test_a_claimed_name_is_kept_as_a_label_and_marked_as_one(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    """The label is not discarded - it is useful - but it is never the identity."""
    _run_acquire(client, services, tmp_path, "Chief Examiner")

    identity = resolve(services)
    labelled = [a for a in _actors(services) if "label:" in a]

    assert labelled, "the examiner's own label should be recorded"
    for actor in labelled:
        assert actor == f"{identity.actor} [label: Chief Examiner]"


def test_a_label_cannot_impersonate_the_trusted_half_of_the_string() -> None:
    """``alice (uid 0)`` typed into the box must not render like the real thing."""
    cleaned = sanitise_label("alice (uid 0)")

    assert "(" not in cleaned
    assert ")" not in cleaned


def test_a_label_cannot_smuggle_a_newline_into_the_chain() -> None:
    assert "\n" not in sanitise_label("a\nb")
    assert "\r" not in sanitise_label("a\rb")


def test_the_default_placeholder_is_not_recorded_as_a_label() -> None:
    """``sanctum`` is the request model's default, not something anyone typed."""
    assert sanitise_label("sanctum") == ""
    assert sanitise_label("") == ""


def test_a_label_is_bounded(client: TestClient, services: AppServices) -> None:
    assert len(sanitise_label("x" * 500)) <= 96


# --------------------------------------------------------------------------
# Honesty about what it establishes
# --------------------------------------------------------------------------


def test_the_identity_claims_an_account_and_not_a_person(
    services: AppServices,
) -> None:
    identity = resolve(services)

    # Windows has no numeric uid and the helper reports -1 rather than
    # inventing one, so the actor names the account instead of printing a uid
    # that does not exist. Either way the string says it is an account.
    if identity.uid < 0:
        assert identity.actor.endswith("(Windows account)")
    else:
        assert f"uid {identity.uid}" in identity.actor
    assert "LOCAL ACCOUNT, NOT A PERSON" in identity.as_dict()["limitation"]


def test_an_unreachable_helper_degrades_and_says_so_rather_than_trusting_input(
    services: AppServices,
) -> None:
    """The fallback is this process's uid. It is never anything a client sent."""

    class Dead:
        def call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
            raise OSError("no helper here")

        def call_stream(self, method: str, params: dict[str, Any]) -> Any:
            raise OSError("no helper here")

    services.helper = Dead()  # type: ignore[assignment]
    services._identity = None  # type: ignore[attr-defined]

    identity = resolve(services)

    assert isinstance(identity, Identity)
    assert identity.trusted is False
    assert identity.uid == _own_uid()
    assert "not confirmed by a privileged process" in identity.basis


def test_a_report_carries_the_identity_limitation(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    import json

    job_id = _run_acquire(client, services, tmp_path, "tester")
    answer = client.post(f"/reports/{job_id}", json={"case_id": "C", "operator": "t"})
    assert answer.status_code == 200, answer.text

    document = json.loads(Path(answer.json()["json_path"]).read_text())
    limitations = " ".join(document["sections"]["limitations"]["items"])

    assert "LOCAL ACCOUNT, NOT A PERSON" in limitations
