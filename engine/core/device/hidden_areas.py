"""Detect HPA/DCO hidden areas. Read-only.

A Host Protected Area or Device Configuration Overlay shrinks the sector range
the OS can address. Anything hidden there is invisible to an overwrite pass, so
a CLEAR that ignores it is not a CLEAR of the whole medium. Detection here is
strictly read-only: ``hdparm -N`` and ``hdparm --dco-identify`` report, they do
not set. Restoring a native max is a destructive configuration change and is
deliberately not implemented in this module.

As with capability probing, a privilege failure raises rather than reporting
"no hidden area" — a false negative here silently understates what survives an
erase.
"""

from __future__ import annotations

import re

import structlog

from core.device._sysio import SystemProbe
from core.errors import UnsupportedCapability
from core.models import Device, HiddenAreaReport

__all__ = ["detect_hidden_areas"]

logger = structlog.get_logger(__name__)

SECTOR_BYTES = 512

#: ``hdparm -N`` prints ``max sectors = <accessible>/<native>``.
_MAX_SECTORS = re.compile(r"max sectors\s*=\s*(\d+)\s*/\s*(\d+)", re.IGNORECASE)
#: ``hdparm --dco-identify`` prints ``Real max sectors: <native>``.
_DCO_REAL_MAX = re.compile(r"Real max sectors:\s*(\d+)", re.IGNORECASE)
#: hdparm prints this and still exits 0 when the SET_MAX reading is nonsense,
#: which is what a USB bridge produces. Observed on a TransMemory stick behind a
#: usb bridge: ``max sectors = 0/1, HPA setting seems invalid``. Trusting the
#: exit code there yielded a native max of one sector and an erase that covered
#: 512 bytes of a 7.76 GB device.
_INVALID_HPA = re.compile(r"HPA setting seems invalid", re.IGNORECASE)

#: Transports where ATA pass-through is not dependable enough to act on. A USB
#: or MMC bridge may answer the SET_MAX command, refuse it, or invent a reply,
#: and nothing in the answer distinguishes those cases. The probe is skipped
#: rather than guessed, and the report says the drive was not probed.
_NO_ATA_PASSTHROUGH = frozenset({"usb", "mmc"})

#: How far a parsed sector count may sit from the kernel-reported size before it
#: is rejected. An HPA hides a slice of a drive, not 90% of it, so a reading an
#: order of magnitude away is a parse or a bridge fault rather than a finding.
_SANITY_FACTOR = 10


def _require_privilege(device: Device, tool: str, denied: bool) -> None:
    if not denied:
        return
    raise UnsupportedCapability(
        f"{tool} could not read {device.path}: permission denied.",
        remediation=(
            "HPA/DCO detection needs raw device access. Run the privileged "
            "helper as root and retry; a permission failure must not be read "
            "as 'no hidden area'."
        ),
    )


def _unprobed(device: Device, reason: str) -> HiddenAreaReport:
    """A report that says "not measured", using the kernel size as the sector count.

    The sector counts here are the kernel's, not the drive's answer to a
    SET_MAX query - there was no usable answer. They are filled in so callers
    have a size to work with; ``probe_failed`` is what says they carry no
    information about hidden sectors.
    """
    sectors = device.size_bytes // SECTOR_BYTES
    logger.info("hidden_area_probe_failed", path=device.path, reason=reason)
    return HiddenAreaReport(
        hpa_present=False,
        dco_present=False,
        native_max_sectors=sectors,
        accessible_sectors=sectors,
        hidden_bytes=0,
        probe_failed=True,
        limitations=[reason],
    )


def _implausible(value: int, kernel_sectors: int) -> bool:
    """True when a parsed sector count is too far from the kernel's to be real."""
    if value <= 0:
        return True
    return not (
        kernel_sectors // _SANITY_FACTOR <= value <= kernel_sectors * _SANITY_FACTOR
    )


def _reject_reason(
    device: Device, accessible: int, native: int, kernel_sectors: int
) -> str | None:
    """Why this ``hdparm -N`` reading must not be trusted, or ``None`` if it may be."""
    if accessible <= 0 or native <= 0:
        return (
            f"hdparm -N reported max sectors = {accessible}/{native} for "
            f"{device.path}; a zero sector count is not a measurement, so no "
            "HPA/DCO determination was made."
        )
    if _implausible(accessible, kernel_sectors) or _implausible(native, kernel_sectors):
        return (
            f"hdparm -N reported max sectors = {accessible}/{native} for "
            f"{device.path}, which is more than {_SANITY_FACTOR}x away from the "
            f"{kernel_sectors} sectors the kernel reports; the reading was "
            "rejected and no HPA/DCO determination was made."
        )
    return None


def detect_hidden_areas(
    device: Device, io: SystemProbe | None = None
) -> HiddenAreaReport:
    """Report HPA/DCO presence and the byte count they hide from normal I/O.

    A reading is trusted only when the tool succeeded *and* the numbers it
    returned survive sanity checks against the kernel-reported size. hdparm
    exits 0 on a bridge that answers the SET_MAX query with nonsense, so the
    exit code alone decides nothing.

    When the probe cannot be trusted the result carries ``probe_failed`` and a
    limitation naming the reason. It never reports "no hidden area", because a
    failed probe and a clean drive support opposite conclusions about what
    survives an erase.

    Args:
        device: The device to interrogate.
        io: Host access seam. Defaults to the real system.

    Raises:
        UnsupportedCapability: A probe failed for lack of privilege.
    """
    io = io or SystemProbe()
    kernel_sectors = device.size_bytes // SECTOR_BYTES

    if device.transport == "nvme":
        # HPA and DCO are ATA features. NVMe namespaces have neither, so the
        # whole namespace is addressable by definition. This is a determination,
        # not a failed probe.
        return HiddenAreaReport(
            hpa_present=False,
            dco_present=False,
            native_max_sectors=kernel_sectors,
            accessible_sectors=kernel_sectors,
            hidden_bytes=0,
        )

    if device.transport in _NO_ATA_PASSTHROUGH:
        # Not attempted rather than attempted and disbelieved: the command would
        # go to a bridge, and a bridge's answer says nothing about the medium
        # behind it. Skipping it also keeps a SET_MAX command off a device whose
        # firmware may mishandle it.
        return _unprobed(
            device,
            f"{device.path} is behind a {device.transport} bridge, where ATA "
            "pass-through is not dependable; HPA/DCO was not probed and hidden "
            "sectors, if any, were neither detected nor erased.",
        )

    hpa_result = io.run("hdparm", "-N", device.path)
    _require_privilege(device, "hdparm -N", hpa_result.permission_denied)

    if not hpa_result.ok:
        return _unprobed(
            device,
            f"hdparm -N exited {hpa_result.returncode} for {device.path}; no "
            "HPA/DCO determination was made.",
        )
    if _INVALID_HPA.search(hpa_result.stdout):
        return _unprobed(
            device,
            f"hdparm -N reported the HPA setting as invalid for {device.path} "
            "and still exited 0; the reading was discarded and no HPA/DCO "
            "determination was made.",
        )

    match = _MAX_SECTORS.search(hpa_result.stdout)
    if match is None:
        return _unprobed(
            device,
            f"hdparm -N printed no 'max sectors' line for {device.path}; no "
            "HPA/DCO determination was made.",
        )

    accessible = int(match.group(1))
    hpa_native = int(match.group(2))
    rejected = _reject_reason(device, accessible, hpa_native, kernel_sectors)
    if rejected is not None:
        return _unprobed(device, rejected)

    dco_result = io.run("hdparm", "--dco-identify", device.path)
    _require_privilege(device, "hdparm --dco-identify", dco_result.permission_denied)

    limitations: list[str] = []
    dco_native = 0
    if dco_result.ok and (dco_match := _DCO_REAL_MAX.search(dco_result.stdout)):
        candidate = int(dco_match.group(1))
        if _implausible(candidate, kernel_sectors):
            # The HPA reading passed its checks, so the drive is not wholly
            # unreachable; only this one number is unusable. Dropping it and
            # saying so beats letting it set the native max.
            limitations.append(
                f"hdparm --dco-identify reported a real max of {candidate} "
                f"sectors for {device.path}, which is implausible against the "
                f"{kernel_sectors} sectors the kernel reports; the DCO reading "
                "was discarded."
            )
        else:
            dco_native = candidate

    native_max = max(hpa_native, dco_native)
    hidden_sectors = max(native_max - accessible, 0)
    report = HiddenAreaReport(
        hpa_present=accessible < hpa_native,
        dco_present=dco_native > hpa_native,
        native_max_sectors=native_max,
        accessible_sectors=accessible,
        hidden_bytes=hidden_sectors * SECTOR_BYTES,
        probe_failed=False,
        limitations=limitations,
    )
    logger.info(
        "hidden_areas_probed",
        path=device.path,
        hpa=report.hpa_present,
        dco=report.dco_present,
        hidden_bytes=report.hidden_bytes,
    )
    return report
