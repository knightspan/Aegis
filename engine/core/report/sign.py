"""Ed25519 detached signing of reports.

The signature is over :func:`core.ledger.canon.canonical_bytes` of the report
dict with the ``signature`` field removed, so a signed report can carry its own
signature without the classic chicken-and-egg problem, and so a verifier
reconstructs exactly the same bytes by applying the same exclusion.

Key handling is deliberately unforgiving:

* The private key is stored as an encrypted PEM using
  ``BestAvailableEncryption``. The passphrase comes from the
  ``SANCTUM_KEY_PASSPHRASE`` environment variable or an interactive prompt.
  There is no default and no hardcoded fallback: a signing key that anyone can
  load is not a signing key.
* The key file is created ``0600`` and a key file readable by group or others is
  **refused**, not warned about. On Windows the POSIX mode bits are not
  meaningful and that check is skipped.

What a signature proves is narrower than it looks. It proves that whoever held
this private key signed these exact bytes. It does not, on its own, prove *who*
that was: an embedded public key is only as trustworthy as the channel the
verifier got the fingerprint from. See :mod:`core.report.verify_report`.
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import os
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from core.errors import SanctumError
from core.ledger.canon import CANON_VERSION, canonical_bytes
from core.models import Signature

__all__ = [
    "PASSPHRASE_ENV",
    "SIGNATURE_ALG",
    "SIGNATURE_FIELD",
    "KEY_FILENAME",
    "KeyPassphraseMissing",
    "KeyPermissionsUnsafe",
    "KeyPathUnusable",
    "key_file_for",
    "fingerprint_of_existing_key",
    "load_or_create_key",
    "public_key_of",
    "fingerprint",
    "sign_report",
    "verify_signature",
]

logger = structlog.get_logger(__name__)

PASSPHRASE_ENV = "SANCTUM_KEY_PASSPHRASE"
SIGNATURE_ALG = "Ed25519"
SIGNATURE_FIELD = "signature"

_UNSAFE_MODE_BITS = stat.S_IRWXG | stat.S_IRWXO

#: The key file's name inside a key *directory*. Callers that manage a directory
#: rather than a file - the API's ``key_dir`` and the hardware harness's
#: ``--key-dir`` - both land here.
KEY_FILENAME = "sanctum-signing.key.pem"


class KeyPathUnusable(SanctumError):
    """The path given for the signing key cannot hold a key."""

    default_remediation = (
        "Pass either a key file path or a directory to hold one. If a directory "
        "was intended, remove whatever occupies "
        f"<directory>/{KEY_FILENAME} and retry."
    )


class KeyPassphraseMissing(SanctumError):
    """No passphrase was supplied for the signing key."""

    default_remediation = (
        f"Set {PASSPHRASE_ENV} in the environment, or run interactively so the "
        "passphrase can be prompted for. There is deliberately no default."
    )


class KeyPermissionsUnsafe(SanctumError):
    """The private key file is readable by more than its owner."""

    default_remediation = (
        "Restore owner-only access with `chmod 0600 <keyfile>` and confirm no "
        "copy was made while it was exposed. Rotate the key if in doubt."
    )


def _prompt_passphrase(path: Path) -> str:
    """Ask for the passphrase interactively. Separated so tests can replace it."""
    if not sys.stdin or not sys.stdin.isatty():
        return ""
    return getpass.getpass(f"Passphrase for signing key {path}: ")


def _passphrase(path: Path, explicit: str | None = None) -> bytes:
    value = explicit or os.environ.get(PASSPHRASE_ENV) or _prompt_passphrase(path)
    if not value:
        raise KeyPassphraseMissing(
            f"No passphrase available for {path} ({PASSPHRASE_ENV} is unset and "
            "no interactive prompt was possible); refusing to write or read an "
            "unprotected signing key."
        )
    return value.encode("utf-8")


def _assert_safe_permissions(path: Path) -> None:
    if sys.platform == "win32":
        # POSIX mode bits are not enforced here; NTFS ACLs are a different model
        # and checking st_mode would give a false assurance.
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & _UNSAFE_MODE_BITS:
        raise KeyPermissionsUnsafe(
            f"{path} has mode {mode:04o}; a signing key must be 0600 so only "
            "its owner can read it."
        )


def key_file_for(path: Path | str) -> Path:
    """Resolve ``path`` to the key *file*, whether a file or a directory was given.

    Both callers in this repository hand over a directory - the API's
    ``key_dir`` and the hardware harness's ``--key-dir`` - while the tests hand
    over a file. Taking the argument literally meant stat-ing a directory for
    0600 permissions, which no directory has: the harness's Phase A report step
    died on ``.../keys has mode 0755``, and past that check it would have died
    again reading a directory as PEM.

    The rule, so that neither side has to guess:

    * an existing directory, or a path with no filename suffix, is a directory
      and the key lives at ``<directory>/sanctum-signing.key.pem``;
    * anything else is the key file itself.
    """
    candidate = Path(path)
    if candidate.is_dir() or not candidate.suffix:
        return candidate / KEY_FILENAME
    return candidate


def load_or_create_key(
    path: Path | str, passphrase: str | None = None
) -> Ed25519PrivateKey:
    """Load the Ed25519 private key at ``path``, generating it on first use.

    Args:
        path: The key file, or a directory to hold it. See :func:`key_file_for`.
        passphrase: Typed by the operator in the desktop app, which has no
            terminal to prompt on and no environment the operator set. Used
            for this call only and never stored. When omitted, the
            environment and then an interactive prompt are tried, as before.

    Raises:
        KeyPathUnusable: The resolved key path is not a regular file.
        KeyPassphraseMissing: No passphrase was available.
        KeyPermissionsUnsafe: The existing key file is group- or world-readable.
        ValueError: The passphrase does not decrypt the key.
    """
    key_path = key_file_for(path)
    if key_path.exists() and not key_path.is_file():
        raise KeyPathUnusable(
            f"{key_path} is not a regular file, so it cannot hold a signing key."
        )
    passphrase_bytes = _passphrase(key_path, passphrase)

    if key_path.exists():
        _assert_safe_permissions(key_path)
        loaded = serialization.load_pem_private_key(
            key_path.read_bytes(), password=passphrase_bytes
        )
        if not isinstance(loaded, Ed25519PrivateKey):
            raise ValueError(f"{key_path} does not hold an Ed25519 private key")
        return loaded

    private = Ed25519PrivateKey.generate()
    pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase_bytes),
    )
    key_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, pem)
        os.fsync(fd)
    finally:
        os.close(fd)
    logger.info("signing_key_created", path=str(key_path))
    return private


def fingerprint_of_existing_key(path: Path | str) -> str:
    """The fingerprint of the key at ``path``, or ``""`` if there is not one.

    Never creates a key. A ledger's genesis entry should record the fingerprint
    of the key its reports will be signed with, which means the key has to exist
    before the first append - but a caller that has no key yet, or no passphrase
    to unlock one, must still be able to start a chain. It gets ``""``, and
    :data:`core.ledger.chain.NO_SIGNING_KEY` is recorded in genesis so the
    absence is stated rather than left as an empty field.

    Never prompts, and never blocks: without the passphrase in the environment
    the fingerprint is not read and the answer is ``""``.
    """
    key_path = key_file_for(path)
    if not key_path.is_file():
        return ""
    # Never prompt. This is a lookup made on every ledger access, from request
    # threads, and the desktop launcher runs the API from a terminal: a prompt
    # here blocks the request forever, with nothing in the window to say why. Only
    # the environment can unlock the key for a lookup; without it the answer is
    # "" and a chain that has to be started records NO_SIGNING_KEY. Signing a
    # report is a separate call and may still ask.
    passphrase = os.environ.get(PASSPHRASE_ENV)
    if not passphrase:
        return ""
    try:
        private = load_or_create_key(key_path, passphrase)
    except (SanctumError, ValueError, OSError):
        return ""
    return fingerprint(public_key_of(private))


def public_key_of(private: Ed25519PrivateKey) -> Ed25519PublicKey:
    """The public half of ``private``."""
    return private.public_key()


def _raw_public_bytes(public: Ed25519PublicKey) -> bytes:
    return public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def fingerprint(public: Ed25519PublicKey) -> str:
    """SHA-256 of the raw 32 public key bytes, as uppercase hex pairs."""
    digest = hashlib.sha256(_raw_public_bytes(public)).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def _signable_bytes(report: dict[str, Any]) -> bytes:
    """Canonical bytes of ``report`` with every signature block removed.

    Two blocks, not one. The signature lives at the top level *and* is mirrored
    into ``sections.signature``, because the report renders nine sections in a
    fixed order and the signature is the ninth. Both must be excluded from what
    is signed, for the obvious reason: a signature cannot cover itself.

    Stripping only the top-level key - which this function did until it was
    caught by the API's end-to-end test - made
    ``build_report(..., signature=...)`` produce a document whose signature
    could never verify, because the sections copy was empty when the bytes were
    signed and populated when they were checked. Signing and then attaching to
    the top level alone happened to work, so every existing test passed.
    """
    without = {k: v for k, v in report.items() if k != SIGNATURE_FIELD}
    sections = without.get("sections")
    if isinstance(sections, dict) and SIGNATURE_FIELD in sections:
        without["sections"] = {
            k: v for k, v in sections.items() if k != SIGNATURE_FIELD
        }
    return canonical_bytes(without)


def _now() -> str:
    stamp = datetime.now(UTC)
    return (
        f"{stamp.year:04d}-{stamp.month:02d}-{stamp.day:02d}"
        f"T{stamp.hour:02d}:{stamp.minute:02d}:{stamp.second:02d}"
        f".{stamp.microsecond:06d}Z"
    )


def sign_report(report: dict[str, Any], private: Ed25519PrivateKey) -> Signature:
    """Sign ``report``'s canonical bytes, excluding any existing signature."""
    public = public_key_of(private)
    payload = _signable_bytes(report)
    return Signature(
        alg=SIGNATURE_ALG,
        pubkey_fingerprint=fingerprint(public),
        pubkey_b64=base64.b64encode(_raw_public_bytes(public)).decode("ascii"),
        sig_b64=base64.b64encode(private.sign(payload)).decode("ascii"),
        signed_at=_now(),
        canon_version=CANON_VERSION,
    )


def verify_signature(report: dict[str, Any], signature: Signature) -> bool:
    """Whether ``signature`` is valid for ``report`` under its embedded key.

    Reconstructs the signed bytes with the same exclusion :func:`sign_report`
    used. Returns ``False`` rather than raising for any failure, so a caller can
    report every check independently.
    """
    if signature.alg != SIGNATURE_ALG:
        logger.warning("signature_alg_unknown", alg=signature.alg)
        return False
    try:
        public = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(signature.pubkey_b64, validate=True)
        )
        public.verify(
            base64.b64decode(signature.sig_b64, validate=True),
            _signable_bytes(report),
        )
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True
