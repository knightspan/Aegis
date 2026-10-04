"""``/health`` says when the most important report check is going to be skipped.

MANUAL_REPORT §3 Break 1. A chain started before any signing key existed
records ``NO_SIGNING_KEY_AT_CHAIN_CREATION`` in genesis, and
``fingerprint_matches_genesis`` is then SKIP on every report that chain will
ever carry. The job routes deliberately do not mint a key, so the fix is
operational - keygen first - and this is what tells an operator who did not
read the manual, at the one endpoint the runbook already makes them check.
"""

from __future__ import annotations

from pathlib import Path

from api.deps import AppServices
from core.ledger.chain import Ledger
from core.report.sign import fingerprint, load_or_create_key, public_key_of
from fastapi.testclient import TestClient


def _limitations(client: TestClient) -> list[str]:
    body = client.get("/health").json()
    items: list[str] = body["limitations"]
    return items


def _mint_key(services: AppServices) -> str:
    key = load_or_create_key(services.key_dir or services.state_dir / "keys")
    return fingerprint(public_key_of(key))


def _start_chain(services: AppServices, finger: str) -> None:
    Ledger(
        services.ledger_root, tool_version="t", pubkey_fingerprint=finger
    ).append(actor="t", operation="op", params={}, result={})


def test_no_key_and_no_chain_warns_before_the_first_job(client: TestClient) -> None:
    items = _limitations(client)
    assert any(item.startswith("NO_SIGNING_KEY:") for item in items), items
    assert not any(item.startswith("CHAIN_WITHOUT_KEY_FINGERPRINT") for item in items)


def test_a_chain_started_without_a_key_is_reported_even_after_a_key_exists(
    client: TestClient, services: AppServices
) -> None:
    """Minting the key later does not repair the chain, so the warning stays."""
    _start_chain(services, "")
    _mint_key(services)

    items = _limitations(client)
    assert any(
        item.startswith("CHAIN_WITHOUT_KEY_FINGERPRINT:") for item in items
    ), items
    assert not any(item.startswith("NO_SIGNING_KEY:") for item in items)


def test_a_key_minted_before_the_chain_raises_nothing(
    client: TestClient, services: AppServices
) -> None:
    _start_chain(services, _mint_key(services))

    items = _limitations(client)
    assert not any("SIGNING_KEY" in item or "KEY_FINGERPRINT" in item for item in items)


def test_the_check_never_creates_a_key(
    client: TestClient, services: AppServices, tmp_path: Path
) -> None:
    client.get("/health")
    key_dir = services.key_dir or services.state_dir / "keys"
    assert not key_dir.exists() or not any(key_dir.iterdir())
