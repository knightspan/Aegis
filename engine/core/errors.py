"""Exception hierarchy for Sanctum Forensics.

Every error carries a ``remediation`` string: a concrete next step for the
operator. Layers raise these instead of bare exceptions so the API and CLI can
present an honest, actionable message.
"""

from __future__ import annotations

__all__ = [
    "SanctumError",
    "DeviceVanished",
    "DeviceFrozen",
    "SystemDiskRefused",
    "MountedRefused",
    "ConfirmationMismatch",
    "GeometryRefused",
    "OverwriteIncomplete",
    "UnsupportedCapability",
    "EvidenceIntegrityError",
    "LedgerChainBroken",
    "LedgerBusy",
    "SignatureInvalid",
    "PlatformUnsupported",
    "WorkflowGateRefused",
    "FormatFailed",
]


class SanctumError(Exception):
    """Base class for every Sanctum error.

    Args:
        message: Human-readable description of what went wrong.
        remediation: Concrete next step. Defaults to the subclass default.
    """

    default_remediation: str = "No automated remediation is available."

    def __init__(self, message: str, *, remediation: str | None = None) -> None:
        super().__init__(message)
        self.message: str = message
        self.remediation: str = remediation or self.default_remediation


class DeviceVanished(SanctumError):
    """The target device disappeared mid-operation (unplugged or reset)."""

    default_remediation = (
        "Re-enumerate devices and confirm the target is still connected before retry."
    )


class DeviceFrozen(SanctumError):
    """ATA security is frozen by firmware/BIOS; security-erase cannot start."""

    default_remediation = (
        "Issue an S3 sleep/wake cycle or power-cycle the drive to clear the frozen "
        "state, then re-probe capabilities."
    )


class SystemDiskRefused(SanctumError):
    """Refused: the target hosts the running root filesystem."""

    default_remediation = (
        "Boot from separate media and run the erase against the drive as a non-system "
        "disk."
    )


class MountedRefused(SanctumError):
    """Refused: the target has one or more mounted filesystems."""

    default_remediation = "Unmount every filesystem on the device and retry."


class ConfirmationMismatch(SanctumError):
    """The serial typed by the operator does not match the target device."""

    default_remediation = (
        "Re-read the device serial from the capability report and type it exactly."
    )


class GeometryRefused(SanctumError):
    """The erase geometry does not cover the whole medium the kernel reports.

    Raised rather than wiping what the smaller number describes. An erase that
    silently covers a fraction of a device is the one failure this tool must
    never produce: it ends with a report saying the medium was sanitized.
    """

    default_remediation = (
        "Re-run enumeration and HPA/DCO detection for the device. If the hidden "
        "area probe cannot produce a trustworthy native max, erase using the "
        "kernel-reported size and record that hidden sectors were not covered."
    )


class OverwriteIncomplete(SanctumError):
    """The overwrite did not account for every byte it set out to write.

    Sibling of :class:`GeometryRefused`, and raised for the same reason. That
    one catches an erase planned over the wrong extent; this one catches an
    erase that planned the right extent and then did not cover it - a short
    ``os.write`` the loop failed to finish, or a write that stopped making
    progress without raising.

    Every byte in the plan must end up either written or recorded in
    ``unwritable``. A byte that is neither is a hole, and a run that reports
    success over a hole is the one result this tool must never produce.
    """

    default_remediation = (
        "Do not treat the medium as sanitized. Re-run the erase; if it stops at "
        "the same offset again, the device is failing writes without reporting "
        "an error and should be physically destroyed rather than reused."
    )


class UnsupportedCapability(SanctumError):
    """The requested erase method is not achievable on this device."""

    default_remediation = (
        "Select a method from the device's probed achievable_levels, or physically "
        "destroy the media."
    )


class EvidenceIntegrityError(SanctumError):
    """An evidence image or path failed a read-only integrity check."""

    default_remediation = (
        "Re-acquire the evidence from the original source and compare acquisition "
        "hashes before carving."
    )


class LedgerChainBroken(SanctumError):
    """A ledger entry's prev_entry_hash does not match the prior entry."""

    default_remediation = (
        "Treat the ledger as compromised. Preserve the raw store and investigate from "
        "the last verified entry."
    )


class LedgerBusy(SanctumError):
    """Another writer held the ledger lock for longer than an append will wait.

    Raised instead of silently dropping the entry. A ledger entry that was not
    written is a gap nobody can see; a failed operation is a failure everybody
    can.
    """

    default_remediation = (
        "Another process is holding the ledger lock. Check for a hung Sanctum "
        "process (the API, the helper, or a harness script) with the same state "
        "directory, stop it, and retry. Do not delete the lock file while a "
        "writer may still be running."
    )


class SignatureInvalid(SanctumError):
    """A report or payload signature failed verification."""

    default_remediation = (
        "Confirm the correct public key and that the payload was not modified after "
        "signing."
    )


class PlatformUnsupported(SanctumError):
    """The operation has no path on this host's platform in this build.

    Raised with the platform's own reason (the capability resolver's, or the
    adapter's). Each platform's backend is its own code: Linux block-device
    semantics in core.erase.drive, the Win32 and raw-device layers in
    core.device.win and core.device.mac; nothing is shimmed across them.
    """

    default_remediation = (
        "Open the Platform screen: it names, per capability, the platforms and "
        "device classes where this runs and why it does not run here. Nothing "
        "was done."
    )


class WorkflowGateRefused(SanctumError):
    """A destructive request did not carry a valid, current authorization.

    Raised at the write seam, in the process that would write, after that
    process re-read the device and the backup itself. ``why_blocked`` lists every
    reason found, in words an operator can act on.
    """

    default_remediation = (
        "Open a new workflow (POST /workflow/erase-drive), approve it, and "
        "execute with the authorization it returns. Nothing was erased."
    )

    def __init__(
        self,
        message: str,
        *,
        why_blocked: list[str] | None = None,
        remediation: str | None = None,
    ) -> None:
        super().__init__(message, remediation=remediation)
        self.why_blocked: list[str] = list(why_blocked or [])


class FormatFailed(SanctumError):
    """A format was refused by its own checks, or one of its steps failed.

    A step that fails after the first write can leave the device without a
    partition table or filesystem. The message names the step and says so.
    """

    default_remediation = (
        "Read the ledger entry for this job, then open a new format workflow. "
        "The device holds no data from before the erase; it may hold no "
        "partition table either."
    )
