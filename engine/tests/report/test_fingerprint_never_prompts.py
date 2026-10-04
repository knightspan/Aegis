"""Looking up a key's fingerprint must never wait for a person to type.

``services.ledger()`` looks the fingerprint up on every ledger access. The
desktop launcher runs the API from a terminal, so stdin is a tty, and a lookup
that prompted blocked the request thread on a passphrase prompt in that
terminal: the browser saw a request that never returned, and nothing in the
window said why.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from core.report import sign
from core.report.sign import (
    PASSPHRASE_ENV,
    fingerprint,
    fingerprint_of_existing_key,
    load_or_create_key,
    public_key_of,
)


@pytest.fixture
def key_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv(PASSPHRASE_ENV, "a-test-passphrase-123")
    load_or_create_key(tmp_path / "keys")
    monkeypatch.delenv(PASSPHRASE_ENV)
    return tmp_path / "keys"


def test_the_lookup_does_not_prompt_when_no_passphrase_is_in_the_environment(
    key_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def prompt(_path: Path) -> str:
        raise AssertionError("the fingerprint lookup asked for a passphrase")

    monkeypatch.setattr(sign, "_prompt_passphrase", prompt)
    assert fingerprint_of_existing_key(key_dir) == ""


def test_the_lookup_still_reads_the_fingerprint_when_the_environment_has_the_passphrase(
    key_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(PASSPHRASE_ENV, "a-test-passphrase-123")
    expected = fingerprint(public_key_of(load_or_create_key(key_dir)))
    assert fingerprint_of_existing_key(key_dir) == expected


def test_an_explicit_signing_still_prompts_interactively(
    key_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the lookup is silent; signing a report may still ask."""
    monkeypatch.setattr(sign, "_prompt_passphrase", lambda _p: "a-test-passphrase-123")
    assert load_or_create_key(key_dir) is not None
