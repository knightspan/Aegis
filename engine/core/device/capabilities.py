"""Probe a device's sanitization capabilities. Read-only.

Method selection is driven by what is probed here, never by user preference
alone (CLAUDE.md non-negotiable). Two rules follow from that and are enforced
throughout this module:

1. A capability that was not *observed* is not claimed. An absent tool, a
   bridge that swallows pass-through, or an unparseable field all yield "not
   supported" plus a recorded limitation — never a silent assumption.
2. A privilege failure is not "unsupported". ``hdparm -I`` returning permission
   denied raises :class:`UnsupportedCapability` with remediation, because
   reporting it as an empty capability set would understate the hardware and
   push the operator toward a weaker method than the drive can honour.

Scope note for the erase module: NVMe *sanitize* acts at controller scope and
affects every namespace, while *format* acts per namespace. A multi-namespace
controller therefore needs a sanitize, not a format, to guarantee the whole
device is covered.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

import structlog

from core.device import media
from core.device._sysio import SystemProbe
from core.errors import UnsupportedCapability
from core.models import (
    Device,
    DeviceCapabilities,
    EraseMethod,
    SanitizationLevel,
)

__all__ = [
    "MAGNETIC_ONLY_PURGE_METHODS",
    "R1_TABLE_A8_SECURE_ERASE_NOTE",
    "probe",
    "purge_mechanisms",
    "recommend_method",
]

logger = structlog.get_logger(__name__)

#: ATA SANITIZE operations we look for in the hdparm feature table.
ATA_SANITIZE_OPS = ("BLOCK_ERASE_EXT", "OVERWRITE_EXT", "CRYPTO_SCRAMBLE_EXT")

#: NVMe Identify Controller SANICAP bit positions (NVMe base spec, Figure 275).
_SANICAP_CRYPTO_ERASE = 0
_SANICAP_BLOCK_ERASE = 1
_SANICAP_OVERWRITE = 2
#: NVMe FNA bit 2: cryptographic erase supported by Format NVM.
_FNA_CRYPTO_FORMAT = 2

#: sedutil-cli --scan second column values that mean a real Opal SSC.
_OPAL_CODES = frozenset({"1", "2", "L"})
#: ...and the ones that mean Pyrite, which has no crypto-erase of user data.
_PYRITE_CODES = frozenset({"p", "P"})

_ERASE_TIME = re.compile(r">?\s*(\d+)\s*min for SECURITY ERASE UNIT", re.IGNORECASE)
_ENHANCED_TIME = re.compile(
    r">?\s*(\d+)\s*min for ENHANCED SECURITY ERASE UNIT", re.IGNORECASE
)


# --------------------------------------------------------------------------
# hdparm parsing
# --------------------------------------------------------------------------


def _security_flag(security_block: list[str], keyword: str) -> bool:
    """Read one hdparm security flag.

    hdparm prints ``\\tnot\\tfrozen`` when clear and ``\\t\\tfrozen`` when set,
    so the flag is true when the line ends in the keyword *without* a preceding
    ``not``.
    """
    for line in security_block:
        stripped = line.strip()
        if not stripped.endswith(keyword):
            continue
        return not stripped.startswith("not")
    return False


def _security_block(text: str) -> list[str]:
    """Return the lines of the ``Security:`` section of ``hdparm -I`` output."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip().rstrip(":").lower() == "security":
            return lines[index + 1 :]
    return []


def _sanitize_ops(text: str) -> list[str]:
    """Collect SANITIZE operations marked supported (``*``) by hdparm."""
    found: list[str] = []
    for line in text.splitlines():
        for op in ATA_SANITIZE_OPS:
            if op in line and "*" in line.split(op, 1)[0]:
                found.append(op)
    return sorted(set(found))


def _erase_seconds(security_block: list[str], *, enhanced: bool) -> int:
    """Read the erase-time estimate hdparm reports, preferring the enhanced one.

    hdparm prints minutes. The conversion happens here, at the parse site, so
    every consumer downstream handles one unit and the field name matches what
    it holds.
    """
    blob = "\n".join(security_block)
    if enhanced and (match := _ENHANCED_TIME.search(blob)):
        return int(match.group(1)) * 60
    if match := _ERASE_TIME.search(blob):
        return int(match.group(1)) * 60
    return 0


def _probe_ata(
    device: Device, io: SystemProbe, limitations: list[str]
) -> dict[str, Any]:
    """Run and parse ``hdparm -I``. Raises on a privilege failure."""
    result = io.run("hdparm", "-I", device.path)
    if result.permission_denied:
        raise UnsupportedCapability(
            f"hdparm could not read {device.path}: permission denied.",
            remediation=(
                "Capability probing needs raw device access. Run the privileged "
                "helper as root (see helper/daemon.py) and retry; do not treat "
                "this as an unsupported device."
            ),
        )
    if not result.ok:
        reason = "hdparm is not installed" if result.missing else "hdparm failed"
        if device.transport in {"usb", "mmc"}:
            limitations.append(
                f"ATA pass-through is unavailable through this {device.transport} "
                "bridge, so firmware sanitize and secure erase cannot be verified "
                "or issued. Only overwrite-based CLEAR can be assured."
            )
        else:
            limitations.append(
                f"{reason} for {device.path}; ATA security and SANITIZE support "
                "could not be established."
            )
        logger.info(
            "hdparm_unavailable", path=device.path, returncode=result.returncode
        )
        return {}

    text = result.stdout
    block = _security_block(text)
    enhanced = _security_flag(block, "supported: enhanced erase")
    return {
        "ata_security_erase": _security_flag(block, "supported"),
        "ata_enhanced_erase": enhanced,
        "security_frozen": _security_flag(block, "frozen"),
        "ata_sanitize_ops": _sanitize_ops(text),
        "est_erase_seconds": _erase_seconds(block, enhanced=enhanced),
    }


# --------------------------------------------------------------------------
# NVMe parsing
# --------------------------------------------------------------------------


def _probe_nvme(
    device: Device, io: SystemProbe, limitations: list[str]
) -> dict[str, Any]:
    """Run and parse ``nvme id-ctrl -o json``."""
    result = io.run("nvme", "id-ctrl", device.path, "-o", "json")
    if result.permission_denied:
        raise UnsupportedCapability(
            f"nvme id-ctrl could not read {device.path}: permission denied.",
            remediation=(
                "Capability probing needs raw device access. Run the privileged "
                "helper as root and retry."
            ),
        )
    if not result.ok:
        limitations.append(
            "nvme-cli is unavailable, so controller sanitize capability could "
            "not be established for this device."
        )
        return {}
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        limitations.append("nvme id-ctrl output could not be parsed.")
        return {}

    sanicap = int(payload.get("sanicap") or 0)
    fna = int(payload.get("fna") or 0)
    namespaces = int(payload.get("nn") or 0)
    if namespaces > 1:
        limitations.append(
            f"Controller exposes {namespaces} namespaces. Format NVM acts per "
            "namespace; only a controller-scope sanitize covers the whole device."
        )
    return {
        "nvme_sanicap": {
            "crypto_erase": bool(sanicap >> _SANICAP_CRYPTO_ERASE & 1),
            "block_erase": bool(sanicap >> _SANICAP_BLOCK_ERASE & 1),
            "overwrite": bool(sanicap >> _SANICAP_OVERWRITE & 1),
            "fna_crypto_format": bool(fna >> _FNA_CRYPTO_FORMAT & 1),
            "namespace_count": namespaces,
            "raw_sanicap": sanicap,
            "raw_fna": fna,
        }
    }


# --------------------------------------------------------------------------
# SED
# --------------------------------------------------------------------------


def _probe_sed(device: Device, io: SystemProbe, limitations: list[str]) -> bool:
    """Detect a true Opal SSC. Pyrite is deliberately not counted as Opal.

    Pyrite implements the Opal command set but provides no cryptographic erase
    of user data, so treating it as Opal would promise a PURGE the drive cannot
    deliver.
    """
    result = io.run("sedutil-cli", "--scan")
    if not result.ok:
        return False
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[0] != device.path:
            continue
        code = fields[1]
        if code in _OPAL_CODES:
            return True
        if code in _PYRITE_CODES or "pyrite" in line.lower():
            limitations.append(
                "Drive reports Pyrite, not Opal. Pyrite has no cryptographic "
                "erase of user data, so crypto-erase cannot be used for PURGE."
            )
        return False
    return False


# --------------------------------------------------------------------------
# achievable_levels
# --------------------------------------------------------------------------


#: Verbatim from NIST SP 800-88r1 (withdrawn 2025-09-26), Table A-8, "ATA
#: Solid State Drives (SSDs)", Notes, printed page 37.
R1_TABLE_A8_SECURE_ERASE_NOTE = (
    "Whereas ATA Secure Erase was a Purge mechanism for magnetic media, it is "
    "only a Clear mechanism for flash memory due to variability in "
    "implementation and the possibility that sensitive data may remain in areas "
    "such as spare cells that have been rotated out of use."
)

#: Methods that are Purge mechanisms on magnetic media only. On flash neither
#: counts toward Purge: r1 Table A-8 lists SECURITY ERASE UNIT under Clear for
#: ATA SSDs, and its ATA SSD Purge options are SANITIZE block erase, SANITIZE
#: crypto scramble and TCG Opal/Enterprise cryptographic erase - SANITIZE
#: overwrite is not among them.
MAGNETIC_ONLY_PURGE_METHODS = frozenset(
    {EraseMethod.ATA_SECURITY_ERASE_ENHANCED, EraseMethod.ATA_SANITIZE_OVERWRITE}
)


def _purge_candidates(
    *,
    ata_sanitize_ops: Sequence[str],
    ata_enhanced_erase: bool,
    security_frozen: bool,
    nvme_sanicap: Mapping[str, Any],
    is_sed_opal: bool,
    flash: bool,
) -> list[EraseMethod]:
    """Every PURGE mechanism the device offers, strongest and most attested first.

    The one place the Clear/Purge decision is made. The methods are clear, purge
    and destroy as NIST SP 800-88r2 (September 2025) Sec. 3.1 defines them. r2
    removed r1's per-media technique tables and defers technique acceptability
    to IEEE 2883 (Sec. 3.1.2, Sec. 4.4, Appendix D), whose text has not been
    read. The per-media rule below therefore rests on the withdrawn SP 800-88r1
    Appendix A tables, adopted here as the organisation's standard until IEEE
    2883 is checked:

    * Magnetic ATA (r1 Table A-5): SANITIZE overwrite, SANITIZE crypto scramble,
      SECURITY ERASE UNIT in enhanced mode (not while frozen), Opal/Enterprise
      cryptographic erase. Table A-5 does not list SANITIZE block erase; it is
      counted wherever a drive reports it, which a magnetic drive would not
      normally do.
    * Flash ATA (r1 Table A-8): SANITIZE block erase, SANITIZE crypto scramble,
      Opal/Enterprise cryptographic erase. **Not** SECURITY ERASE UNIT, which
      that table lists under Clear, and not SANITIZE overwrite.
    * NVMe (r1 Table A-8): Format NVM with cryptographic erase, Opal
      cryptographic erase; plus NVMe sanitize block and crypto erase, which r1
      predates and r2 Sec. 3.1.2 names in general terms. NVMe sanitize overwrite
      has no executable method here and is not counted.

    CLEAR is always reachable (r2 Sec. 3.1.1) and DESTROY never is in software.
    """
    nvme = nvme_sanicap
    available = (
        ("BLOCK_ERASE_EXT" in ata_sanitize_ops, EraseMethod.ATA_SANITIZE_BLOCK_ERASE),
        (
            "CRYPTO_SCRAMBLE_EXT" in ata_sanitize_ops,
            EraseMethod.ATA_SANITIZE_CRYPTO_SCRAMBLE,
        ),
        ("OVERWRITE_EXT" in ata_sanitize_ops, EraseMethod.ATA_SANITIZE_OVERWRITE),
        (
            bool(nvme.get("block_erase")) or bool(nvme.get("crypto_erase")),
            EraseMethod.NVME_SANITIZE_BLOCK,
        ),
        (is_sed_opal, EraseMethod.SED_CRYPTO_ERASE),
        (bool(nvme.get("fna_crypto_format")), EraseMethod.NVME_FORMAT_SES1),
        (
            ata_enhanced_erase and not security_frozen,
            EraseMethod.ATA_SECURITY_ERASE_ENHANCED,
        ),
    )
    return [
        method
        for present, method in available
        if present and not (flash and method in MAGNETIC_ONLY_PURGE_METHODS)
    ]


def purge_mechanisms(
    capabilities: DeviceCapabilities, device: Device
) -> list[EraseMethod]:
    """The PURGE mechanisms ``device`` offers, strongest first.

    See ``_purge_candidates`` for the rule and its authority.
    """
    return _purge_candidates(
        ata_sanitize_ops=capabilities.ata_sanitize_ops,
        ata_enhanced_erase=capabilities.ata_enhanced_erase,
        security_frozen=capabilities.security_frozen,
        nvme_sanicap=capabilities.nvme_sanicap,
        is_sed_opal=capabilities.is_sed_opal,
        flash=media.is_flash(device)[0],
    )


def _purge_basis_limitations(
    found: Mapping[str, Any],
    flash: bool,
    flash_reason: str,
    candidates: list[EraseMethod],
) -> list[str]:
    """Say, in the capability record, what the Purge decision rested on."""
    notes: list[str] = []
    enhanced = bool(found.get("ata_enhanced_erase"))
    overwrite = "OVERWRITE_EXT" in (found.get("ata_sanitize_ops") or [])
    if flash and enhanced:
        notes.append(
            "The drive supports ATA enhanced SECURITY ERASE, but this device was "
            f"determined to be flash because {flash_reason}, and on flash that "
            "command is counted as Clear only, never Purge. Authority: NIST SP "
            "800-88r1 Table A-8 (ATA SSDs), which lists SECURITY ERASE UNIT under "
            f'Clear and states: "{R1_TABLE_A8_SECURE_ERASE_NOTE}" r1 was withdrawn '
            "on 2025-09-26; SP 800-88r2 defers technique acceptability to IEEE "
            "2883, whose text has not been checked. Purge on this device needs "
            "ATA SANITIZE block erase or crypto scramble, or an Opal "
            "cryptographic erase."
        )
    if flash and overwrite:
        notes.append(
            "The drive reports ATA SANITIZE OVERWRITE_EXT, but this device was "
            f"determined to be flash because {flash_reason}, and on flash that "
            "operation is not counted as Purge: NIST SP 800-88r1 Table A-8 gives "
            "block erase and crypto scramble as the ATA SSD sanitize Purge options, "
            "not overwrite. r1 is withdrawn and IEEE 2883 has not been checked."
        )
    if candidates and candidates[0] is EraseMethod.ATA_SECURITY_ERASE_ENHANCED:
        notes.append(
            "Purge on this device would be ATA enhanced SECURITY ERASE, counted as "
            "Purge because the device was not determined to be flash "
            f"({flash_reason}). "
            "The basis is NIST SP 800-88r1 Table A-5 (ATA hard disk drives), which "
            "was withdrawn on 2025-09-26, applies to legacy magnetic media only, and "
            "warns that hybrid drives may not be identifiable by the label. SP "
            "800-88r2 does not name the command, and IEEE 2883 has not been checked. "
            "r1 also recommends consulting the manufacturer before relying on it."
        )
    return notes


def _achievable_levels(candidates: list[EraseMethod]) -> set[SanitizationLevel]:
    """Compute, never store, the sanitization methods this device can reach."""
    levels = {SanitizationLevel.CLEAR}
    if candidates:
        levels.add(SanitizationLevel.PURGE)
    return levels


def probe(device: Device, io: SystemProbe | None = None) -> DeviceCapabilities:
    """Probe ATA/NVMe/SED capability for ``device`` without altering it.

    Args:
        device: The device to interrogate.
        io: Host access seam. Defaults to the real system.

    Raises:
        UnsupportedCapability: A probe failed for lack of privilege. This is
            never reported as an absent capability.
    """
    io = io or SystemProbe()
    limitations: list[str] = []
    found: dict[str, Any] = {}

    if device.transport == "nvme":
        found.update(_probe_nvme(device, io, limitations))
    else:
        found.update(_probe_ata(device, io, limitations))

    found["is_sed_opal"] = _probe_sed(device, io, limitations)

    flash, flash_reason = media.is_flash(device)
    candidates = _purge_candidates(
        ata_sanitize_ops=list(found.get("ata_sanitize_ops") or []),
        ata_enhanced_erase=bool(found.get("ata_enhanced_erase")),
        security_frozen=bool(found.get("security_frozen")),
        nvme_sanicap=dict(found.get("nvme_sanicap") or {}),
        is_sed_opal=bool(found.get("is_sed_opal")),
        flash=flash,
    )
    limitations.extend(
        _purge_basis_limitations(found, flash, flash_reason, candidates)
    )

    caps = DeviceCapabilities(
        ata_security_erase=bool(found.get("ata_security_erase")),
        ata_enhanced_erase=bool(found.get("ata_enhanced_erase")),
        ata_sanitize_ops=list(found.get("ata_sanitize_ops") or []),
        nvme_sanicap=dict(found.get("nvme_sanicap") or {}),
        is_sed_opal=bool(found.get("is_sed_opal")),
        security_frozen=bool(found.get("security_frozen")),
        est_erase_seconds=int(found.get("est_erase_seconds") or 0),
        achievable_levels=_achievable_levels(candidates),
        limitations=limitations,
    )
    logger.info(
        "capabilities_probed",
        path=device.path,
        transport=device.transport,
        levels=sorted(level.value for level in caps.achievable_levels),
        limitation_count=len(caps.limitations),
    )
    return caps


def recommend_method(
    capabilities: DeviceCapabilities,
    target_level: SanitizationLevel,
    *,
    device: Device,
) -> EraseMethod:
    """Pick the strongest achievable method for ``target_level``.

    ``device`` is required, not defaulted: whether a mechanism counts as Purge
    depends on whether the medium is flash, and a default would silently mean
    "magnetic".

    Raises:
        UnsupportedCapability: ``target_level`` is not in
            ``capabilities.achievable_levels``.
    """
    if target_level not in capabilities.achievable_levels:
        reachable = ", ".join(
            sorted(level.value for level in capabilities.achievable_levels)
        )
        detail = " ".join(capabilities.limitations) or "No mechanism was observed."
        raise UnsupportedCapability(
            f"{target_level.value} is not achievable on this device. {detail}",
            remediation=(
                f"Choose one of: {reachable}. To reach "
                f"{target_level.value} on this media, physical destruction is "
                "the remaining option."
            ),
        )

    if target_level is SanitizationLevel.CLEAR:
        return EraseMethod.SINGLE_PASS_OVERWRITE

    candidates = purge_mechanisms(capabilities, device)
    if candidates:
        return candidates[0]
    raise UnsupportedCapability(
        f"{target_level.value} was reported achievable but no mechanism matched.",
        remediation="Re-probe the device; the capability set is inconsistent.",
    )
