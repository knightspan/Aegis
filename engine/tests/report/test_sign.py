"""Ed25519 signing, key-at-rest handling, and signature verification."""

from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

import pytest
from core.report.sign import (
    KEY_FILENAME,
    PASSPHRASE_ENV,
    SIGNATURE_ALG,
    KeyPassphraseMissing,
    KeyPathUnusable,
    KeyPermissionsUnsafe,
    fingerprint,
    key_file_for,
    load_or_create_key,
    public_key_of,
    sign_report,
    verify_signature,
)

PASSPHRASE = "correct horse battery staple"

REPORT: dict[str, Any] = {
    "case_id": "CASE-0001",
    "operator": "tester",
    "device": {"serial": "SYN-0001", "size_bytes": 1024},
    "residual_risk": {"level": "low", "factors": []},
}


@pytest.fixture
def key_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv(PASSPHRASE_ENV, PASSPHRASE)
    return tmp_path / "sanctum.key.pem"


# --------------------------------------------------------------------------
# Key at rest
# --------------------------------------------------------------------------


def test_key_is_generated_on_first_use(key_path: Path) -> None:
    load_or_create_key(key_path)
    assert key_path.exists()


def test_generated_key_is_encrypted_at_rest(key_path: Path) -> None:
    load_or_create_key(key_path)
    pem = key_path.read_bytes()
    assert b"ENCRYPTED" in pem


def test_the_same_key_is_returned_on_reload(key_path: Path) -> None:
    first = public_key_of(load_or_create_key(key_path))
    second = public_key_of(load_or_create_key(key_path))
    assert fingerprint(first) == fingerprint(second)


def test_wrong_passphrase_raises(
    key_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    load_or_create_key(key_path)
    monkeypatch.setenv(PASSPHRASE_ENV, "wrong passphrase")
    with pytest.raises(ValueError):
        load_or_create_key(key_path)


def test_missing_passphrase_is_refused_rather_than_defaulted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(PASSPHRASE_ENV, raising=False)
    monkeypatch.setattr("core.report.sign._prompt_passphrase", lambda _p: "")
    with pytest.raises(KeyPassphraseMissing) as excinfo:
        load_or_create_key(tmp_path / "k.pem")
    assert PASSPHRASE_ENV in str(excinfo.value)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX file mode bits are not enforced on Windows; NTFS ACLs are a "
    "different model and this check does not apply",
)
def test_key_file_is_created_with_mode_0600(key_path: Path) -> None:
    load_or_create_key(key_path)
    mode = stat.S_IMODE(os.stat(key_path).st_mode)
    assert mode == 0o600


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX file mode bits are not enforced on Windows; NTFS ACLs are a "
    "different model and this check does not apply",
)
def test_group_or_world_readable_key_is_refused(key_path: Path) -> None:
    load_or_create_key(key_path)
    os.chmod(key_path, 0o644)
    with pytest.raises(KeyPermissionsUnsafe) as excinfo:
        load_or_create_key(key_path)
    assert "0600" in str(excinfo.value)


# --------------------------------------------------------------------------
# Fingerprint
# --------------------------------------------------------------------------


def test_fingerprint_is_colon_separated_uppercase_hex(key_path: Path) -> None:
    value = fingerprint(public_key_of(load_or_create_key(key_path)))
    assert re.fullmatch(r"(?:[0-9A-F]{2}:){31}[0-9A-F]{2}", value)


def test_fingerprint_is_over_the_raw_thirty_two_public_key_bytes(
    key_path: Path,
) -> None:
    import hashlib

    from cryptography.hazmat.primitives import serialization

    public = public_key_of(load_or_create_key(key_path))
    raw = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    assert len(raw) == 32
    expected = hashlib.sha256(raw).hexdigest().upper()
    assert fingerprint(public).replace(":", "") == expected


# --------------------------------------------------------------------------
# Signing
# --------------------------------------------------------------------------


def test_sign_then_verify_is_true(key_path: Path) -> None:
    key = load_or_create_key(key_path)
    signature = sign_report(REPORT, key)
    assert verify_signature(REPORT, signature) is True


def test_signature_records_algorithm_and_canon_version(key_path: Path) -> None:
    signature = sign_report(REPORT, load_or_create_key(key_path))
    assert signature.alg == SIGNATURE_ALG
    assert signature.canon_version
    assert signature.signed_at.endswith("Z")


def test_signature_fingerprint_matches_the_embedded_public_key(
    key_path: Path,
) -> None:
    key = load_or_create_key(key_path)
    signature = sign_report(REPORT, key)
    assert signature.pubkey_fingerprint == fingerprint(public_key_of(key))


@pytest.mark.parametrize(
    "mutation",
    [
        {"case_id": "CASE-0002"},
        {"operator": "someone else"},
        {"device": {"serial": "OTHER", "size_bytes": 1024}},
        {"residual_risk": {"level": "high", "factors": []}},
    ],
)
def test_any_altered_field_fails_verification(
    key_path: Path, mutation: dict[str, Any]
) -> None:
    signature = sign_report(REPORT, load_or_create_key(key_path))
    tampered = {**REPORT, **mutation}
    assert verify_signature(tampered, signature) is False


def test_an_added_field_fails_verification(key_path: Path) -> None:
    signature = sign_report(REPORT, load_or_create_key(key_path))
    assert verify_signature({**REPORT, "extra": 1}, signature) is False


def test_a_flipped_signature_byte_fails_verification(key_path: Path) -> None:
    signature = sign_report(REPORT, load_or_create_key(key_path))
    flipped = signature.model_copy(
        update={
            "sig_b64": ("A" if signature.sig_b64[0] != "A" else "B")
            + signature.sig_b64[1:]
        }
    )
    assert verify_signature(REPORT, flipped) is False


def test_a_signature_from_a_different_key_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(PASSPHRASE_ENV, PASSPHRASE)
    first = load_or_create_key(tmp_path / "a.pem")
    second = load_or_create_key(tmp_path / "b.pem")
    signature = sign_report(REPORT, first)
    swapped = signature.model_copy(
        update={
            "pubkey_b64": sign_report(REPORT, second).pubkey_b64,
            "pubkey_fingerprint": fingerprint(public_key_of(second)),
        }
    )
    assert verify_signature(REPORT, swapped) is False


def test_the_signature_field_itself_is_excluded_from_the_signed_bytes(
    key_path: Path,
) -> None:
    key = load_or_create_key(key_path)
    signature = sign_report(REPORT, key)
    with_signature = {**REPORT, "signature": signature.model_dump()}
    assert verify_signature(with_signature, signature) is True


def test_a_report_built_with_its_signature_still_verifies(key_path: Path) -> None:
    """The signature must not cover itself, in either place it appears.

    ``build_report`` mirrors the signature into ``sections.signature`` because
    the report renders nine sections in a fixed order and the signature is the
    ninth. Excluding only the top-level key made
    ``build_report(..., signature=...)`` produce a document whose signature
    could never verify: the sections copy was empty when the bytes were signed
    and populated when they were checked.

    Every test in this file passed while that was broken, because they all sign
    a report and attach the signature to the top level themselves. The API's
    end-to-end run is what surfaced it.
    """
    from datetime import UTC, datetime

    from core.ledger.chain import Ledger
    from core.report.render import build_report

    ledger = Ledger(
        key_path.parent / "ledger", tool_version="0.0.0", pubkey_fingerprint="AA:BB"
    )
    fields: dict[str, Any] = {
        "case_id": "CASE-SIGNED",
        "operator": "tester",
        "generated_at": datetime.now(UTC),
        "tool_version": "0.0.0",
        "device": {},
        "method": {},
        "hidden_areas": {},
        "verification": {},
        "residual_risk": {},
        "limitations": [],
        "ledger_excerpt": [],
        "chain_verification": ledger.verify(),
        "pubkey_fingerprint": "AA:BB",
    }

    key = load_or_create_key(key_path)
    unsigned = build_report(**fields)
    signature = sign_report(unsigned, key)

    signed = build_report(**fields, signature=signature)
    assert signed["sections"]["signature"], "the section must be populated"
    assert verify_signature(signed, signature) is True


def test_tampering_is_still_caught_inside_a_section(key_path: Path) -> None:
    """The exclusion must be narrow: only the signature blocks, nothing else."""
    from datetime import UTC, datetime

    from core.ledger.chain import Ledger
    from core.report.render import build_report

    ledger = Ledger(
        key_path.parent / "ledger2", tool_version="0.0.0", pubkey_fingerprint="AA:BB"
    )
    fields: dict[str, Any] = {
        "case_id": "CASE-TAMPER",
        "operator": "tester",
        "generated_at": datetime.now(UTC),
        "tool_version": "0.0.0",
        "device": {"serial": "SYN-1"},
        "method": {},
        "hidden_areas": {},
        "verification": {},
        "residual_risk": {},
        "limitations": [],
        "ledger_excerpt": [],
        "chain_verification": ledger.verify(),
        "pubkey_fingerprint": "AA:BB",
    }
    key = load_or_create_key(key_path)
    signature = sign_report(build_report(**fields), key)
    signed = build_report(**fields, signature=signature)

    assert verify_signature(signed, signature) is True

    signed["sections"]["device_identity"]["serial"] = "SOMEONE-ELSES-DISK"
    assert verify_signature(signed, signature) is False


# --------------------------------------------------------------------------
# A directory is a legal thing to be handed
# --------------------------------------------------------------------------


def test_a_key_directory_holds_the_key_file_inside_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """What both real callers pass. Taking it literally killed the A.7 step.

    The API's ``key_dir`` and the hardware harness's ``--key-dir`` are both
    directories created by whoever runs the tool - 0755 under any normal umask.
    ``load_or_create_key`` stat-ed that directory looking for 0600 and raised
    ``KeyPermissionsUnsafe``; past that check it would have called
    ``read_bytes()`` on a directory and raised ``IsADirectoryError``.
    """
    monkeypatch.setenv(PASSPHRASE_ENV, PASSPHRASE)
    key_dir = tmp_path / "keys"
    key_dir.mkdir(mode=0o755)

    load_or_create_key(key_dir)

    key_file = key_dir / KEY_FILENAME
    assert key_file.is_file()
    if sys.platform == "win32":
        # NTFS ACLs, not mode bits: core.report.sign._assert_safe_permissions
        # returns early on Windows rather than give a false assurance, and
        # chmod there cannot express 0600.
        return
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(key_dir.stat().st_mode) == 0o755, (
        "the directory's own mode is not the key's mode and must not be touched"
    )


def test_a_0755_key_directory_is_not_a_permissions_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The exact failure from results-20260904T163645Z/a7-report.err."""
    monkeypatch.setenv(PASSPHRASE_ENV, PASSPHRASE)
    key_dir = tmp_path / "keys"
    key_dir.mkdir(mode=0o755)

    first = load_or_create_key(key_dir)
    second = load_or_create_key(key_dir)

    assert fingerprint(public_key_of(first)) == fingerprint(public_key_of(second)), (
        "the second call must reload the same key, not mint a new one"
    )


def test_a_directory_that_does_not_exist_yet_is_still_a_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A suffix-less path is a directory even before anything creates it."""
    monkeypatch.setenv(PASSPHRASE_ENV, PASSPHRASE)
    key_dir = tmp_path / "state" / "keys"

    load_or_create_key(key_dir)

    assert (key_dir / KEY_FILENAME).is_file()


def test_a_file_path_is_still_used_verbatim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(PASSPHRASE_ENV, PASSPHRASE)
    explicit = tmp_path / "sanctum.key.pem"

    load_or_create_key(explicit)

    assert explicit.is_file()
    assert not (tmp_path / KEY_FILENAME).exists()


def test_a_key_path_occupied_by_a_directory_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A clear error, not IsADirectoryError from deep inside a PEM parser."""
    monkeypatch.setenv(PASSPHRASE_ENV, PASSPHRASE)
    key_dir = tmp_path / "keys"
    (key_dir / KEY_FILENAME).mkdir(parents=True)

    with pytest.raises(KeyPathUnusable) as caught:
        load_or_create_key(key_dir)

    assert "not a regular file" in caught.value.message
    assert caught.value.remediation


def test_key_file_for_resolves_both_shapes(tmp_path: Path) -> None:
    existing = tmp_path / "keys"
    existing.mkdir()

    assert key_file_for(existing) == existing / KEY_FILENAME
    assert key_file_for(tmp_path / "missing-dir") == (
        tmp_path / "missing-dir" / KEY_FILENAME
    )
    assert key_file_for(tmp_path / "k.pem") == tmp_path / "k.pem"
