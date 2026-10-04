"""What a report may claim, by what was actually done.

Five categories, never merged, never described with the undifferentiated
words "secure erase":

1. **FILE ERASE** - a file's current blocks overwritten through the
   filesystem. Says nothing about the rest of the medium.
2. **ADDRESSABLE WHOLE-DRIVE CLEAR** - every LBA the operating system exposes,
   overwritten by the host and read back. NIST SP 800-88 Rev. 2 Clear. Not a
   Purge, not NAND-level destruction.
3. **DEVICE SANITIZE** - the drive's own firmware command (ATA SANITIZE,
   ATA SECURITY ERASE, NVMe Sanitize, NVMe Format). Purge when the firmware
   implements it as specified; the report prints whose claim completion is.
4. **CRYPTO ERASE** - the media encryption key replaced. The ciphertext stays;
   the guarantee rests on key management the host cannot inspect.
5. **PHYSICAL DESTRUCTION ATTESTATION** - a person's signed statement about a
   destruction this tool did not observe.

:func:`describe` maps a recorded method to its category and the exact
METHOD / PROTOCOL / SCOPE / VERIFICATION / ASSURANCE / LIMITATIONS words a
certificate prints. The word "unrecoverable" is never produced here.
"""

from __future__ import annotations

from typing import Any

__all__ = ["CATEGORIES", "describe", "describe_kind"]

FILE_ERASE = "FILE ERASE"
ADDRESSABLE_CLEAR = "ADDRESSABLE WHOLE-DRIVE CLEAR"
DEVICE_SANITIZE = "DEVICE SANITIZE"
CRYPTO_ERASE = "CRYPTO ERASE"
DESTRUCTION = "PHYSICAL DESTRUCTION ATTESTATION"

CATEGORIES = (FILE_ERASE, ADDRESSABLE_CLEAR, DEVICE_SANITIZE, CRYPTO_ERASE, DESTRUCTION)

_METHODS: dict[str, tuple[str, str, str]] = {
    # method -> (category, protocol, command)
    "SINGLE_PASS_OVERWRITE": (ADDRESSABLE_CLEAR, "block", "host overwrite, one pass"),
    "DOD_5220_22_M_3PASS": (ADDRESSABLE_CLEAR, "block", "host overwrite, three passes"),
    "ATA_SANITIZE_BLOCK_ERASE": (DEVICE_SANITIZE, "ATA", "SANITIZE BLOCK ERASE EXT"),
    "ATA_SANITIZE_OVERWRITE": (DEVICE_SANITIZE, "ATA", "SANITIZE OVERWRITE EXT"),
    "ATA_SECURITY_ERASE_ENHANCED": (
        DEVICE_SANITIZE,
        "ATA",
        "SECURITY ERASE UNIT (enhanced)",
    ),
    "NVME_SANITIZE_BLOCK": (DEVICE_SANITIZE, "NVMe", "Sanitize, block erase"),
    "NVME_FORMAT_SES1": (DEVICE_SANITIZE, "NVMe", "Format NVM, user-data erase"),
    "ATA_SANITIZE_CRYPTO_SCRAMBLE": (
        CRYPTO_ERASE,
        "ATA",
        "SANITIZE CRYPTO SCRAMBLE EXT",
    ),
    "NVME_SANITIZE_CRYPTO": (CRYPTO_ERASE, "NVMe", "Sanitize, crypto erase"),
    "SED_CRYPTO_ERASE": (CRYPTO_ERASE, "TCG Opal", "Opal revert (key replacement)"),
}

_ASSURANCE = {
    FILE_ERASE: (
        "The file's current blocks were overwritten through the filesystem. "
        "Copies the filesystem, a snapshot, a journal or the flash controller "
        "kept elsewhere are not reached; the residual findings list them."
    ),
    ADDRESSABLE_CLEAR: (
        "NIST SP 800-88 Rev. 2 Clear of the addressable storage: every LBA the "
        "operating system exposed was overwritten and read back. Not a Purge. "
        "Not NAND-level destruction: flash remapped and spare blocks are not "
        "addressable and were not written."
    ),
    DEVICE_SANITIZE: (
        "NIST SP 800-88 Rev. 2 Purge when the drive's firmware implements the "
        "command as its specification requires. Completion is the drive's or "
        "driver's own claim; the medium was also read back, and both are "
        "recorded."
    ),
    CRYPTO_ERASE: (
        "Cryptographic erase: the media encryption key was replaced. The "
        "ciphertext remains on the medium. Whether the old key is "
        "irrecoverable rests on the drive's key management, which this tool "
        "cannot inspect."
    ),
    DESTRUCTION: (
        "A signed human attestation. This tool did not observe the destruction "
        "and cannot verify it."
    ),
}

_SCOPE = {
    FILE_ERASE: "The named files' current blocks only.",
    ADDRESSABLE_CLEAR: (
        "LBA 0 to the last LBA the operating system exposed. An HPA/DCO region "
        "is outside this range unless it was restored through the HPA/DCO "
        "workflow first."
    ),
    DEVICE_SANITIZE: "The whole medium as the drive's firmware defines it.",
    CRYPTO_ERASE: "Every block encrypted under the replaced key.",
    DESTRUCTION: "The physical device named in the attestation.",
}


def describe(
    method: str,
    *,
    verification: dict[str, Any] | None = None,
    limitations: list[str] | None = None,
    transport: str = "",
) -> dict[str, Any]:
    """The certificate words for a drive-level method."""
    category, protocol, command = _METHODS.get(
        method, (ADDRESSABLE_CLEAR, "block", method or "not recorded")
    )
    check = verification or {}
    strategy = str(check.get("strategy") or "")
    if not check:
        verified = "not verified (no read-back recorded)"
    elif category == CRYPTO_ERASE:
        verified = (
            "sampled windows hashed before and after the command; every one "
            "must have changed"
        )
    elif strategy == "full_read":
        verified = "every addressable byte read back and compared"
    elif strategy == "sampled":
        verified = "edges plus seeded random windows read back; probability stated"
    else:
        verified = "device completion status plus a sampled read-back"
    return {
        "category": category,
        "method": command,
        "protocol": protocol,
        "transport": transport or "not recorded",
        "scope": _SCOPE[category],
        "verification": verified,
        "assurance": _ASSURANCE[category],
        "limitations": list(limitations or []),
    }


def describe_kind(kind: str) -> dict[str, Any]:
    """The certificate words for a non-drive report kind."""
    category = {
        "files": FILE_ERASE,
        "destroy": DESTRUCTION,
    }.get(kind)
    if category is None:
        return {}
    return {
        "category": category,
        "scope": _SCOPE[category],
        "assurance": _ASSURANCE[category],
    }
