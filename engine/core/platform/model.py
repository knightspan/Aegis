"""The normalized platform model every adapter populates and the UI consumes.

The UI never learns how a device was discovered. A Windows ``Get-Disk`` row, a
macOS ``diskutil`` plist and a Linux ``lsblk`` node all become the same
:class:`NormalizedDevice`, and every statement about what can be done to it
becomes an :class:`OperationCapability` with a status, a reason and the source
the status was read from.

Two rules shape the model:

* **No status without a reason and a source.** A capability row that says
  SUPPORTED without saying which probe established it is a hardcoded
  checkmark, and the report would be repeating a claim nobody measured.
* **Support is per operation, never per platform.** "Windows is supported"
  means nothing. "Folder erase on this NTFS volume is supported with
  limitations, because NTFS may keep a small file resident in its MFT record"
  is a statement a reader can check.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field

__all__ = [
    "Capability",
    "CAPABILITY_LABELS",
    "CapabilityState",
    "ResolvedCapability",
    "RUNNABLE_STATES",
    "STATE_LABELS",
    "CapabilityStatus",
    "OperationStatus",
    "Operation",
    "OPERATION_LABELS",
    "PlatformFamily",
    "PlatformInfo",
    "PrivilegeState",
    "OperationCapability",
    "PartitionInfo",
    "SafetyCheck",
    "NormalizedDevice",
    "SanitizeOption",
    "DeviceAssessment",
    "FilesystemCapability",
    "FilesystemSupport",
    "MediaClassSupport",
    "PlatformStatus",
    "Interface",
    "MediaType",
]


class CapabilityStatus(StrEnum):
    """What the application can do, established *before* anything runs."""

    #: A real backend exists, it runs on this host, and it has a verification
    #: path. Limitations may still apply and are listed.
    SUPPORTED = "SUPPORTED"
    #: A real backend exists and runs, but part of the claim cannot be made
    #: (flash remapping, copy-on-write, resident data). The limits are listed.
    SUPPORTED_WITH_LIMITATIONS = "SUPPORTED_WITH_LIMITATIONS"
    #: A backend exists but this process lacks the privilege it needs.
    NOT_AUTHORIZED = "NOT_AUTHORIZED"
    #: The operation can run but nothing on this host can check its result.
    NOT_VERIFIABLE = "NOT_VERIFIABLE"
    #: Code exists but has never been exercised on real hardware of this kind.
    UNVERIFIED = "UNVERIFIED"
    #: A probe ran and could not settle the question.
    INCONCLUSIVE = "INCONCLUSIVE"
    #: No backend exists on this platform, or the target is refused outright.
    UNSUPPORTED = "UNSUPPORTED"


class CapabilityState(StrEnum):
    """Where one capability stands for one device (or one platform)."""

    #: Runnable here, and a run on real hardware of this device class is
    #: recorded in the validation record.
    VALIDATED_PHYSICAL = "VALIDATED_PHYSICAL"
    #: Runnable here; synthetic and adapter-double tests only.
    IMPLEMENTED_NOT_PHYSICALLY_VALIDATED = "IMPLEMENTED_NOT_PHYSICALLY_VALIDATED"
    #: Implemented; whether it runs depends on what the device reports, and
    #: there is no device (platform matrix) or its probe did not settle it.
    IMPLEMENTED_DEVICE_DEPENDENT = "IMPLEMENTED_DEVICE_DEPENDENT"
    #: Implemented and exposed, but this process lacks the OS privilege.
    AVAILABLE_BUT_REQUIRES_PRIVILEGE = "AVAILABLE_BUT_REQUIRES_PRIVILEGE"
    #: Implemented; this device (or the bridge in front of it) does not expose
    #: the mechanism.
    UNSUPPORTED_BY_DEVICE = "UNSUPPORTED_BY_DEVICE"
    #: The operating system offers no path to the mechanism at all.
    UNSUPPORTED_BY_PLATFORM = "UNSUPPORTED_BY_PLATFORM"
    #: The OS could do it; this build has no code for it.
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    #: Exposed and implemented, refused by a safety rule for this device.
    BLOCKED_BY_SAFETY_POLICY = "BLOCKED_BY_SAFETY_POLICY"


#: The words the interface shows. Two device states share one word because to
#: an operator they are the same answer ("depends on the device"); the reason
#: sentence says which.
STATE_LABELS: dict[CapabilityState, str] = {
    CapabilityState.VALIDATED_PHYSICAL: "SUPPORTED",
    CapabilityState.IMPLEMENTED_NOT_PHYSICALLY_VALIDATED: "IMPLEMENTED / UNVALIDATED",
    CapabilityState.IMPLEMENTED_DEVICE_DEPENDENT: "DEVICE-DEPENDENT",
    CapabilityState.AVAILABLE_BUT_REQUIRES_PRIVILEGE: "REQUIRES PRIVILEGE",
    CapabilityState.UNSUPPORTED_BY_DEVICE: "DEVICE-DEPENDENT",
    CapabilityState.UNSUPPORTED_BY_PLATFORM: "PLATFORM-LIMITED",
    CapabilityState.NOT_IMPLEMENTED: "NOT IMPLEMENTED",
    CapabilityState.BLOCKED_BY_SAFETY_POLICY: "BLOCKED FOR SAFETY",
}

#: States in which the operation may be started (after the workflow gates).
RUNNABLE_STATES = frozenset(
    {
        CapabilityState.VALIDATED_PHYSICAL,
        CapabilityState.IMPLEMENTED_NOT_PHYSICALLY_VALIDATED,
    }
)


class Capability(StrEnum):
    """Every capability the resolver answers for."""

    DEVICE_DISCOVERY = "device_discovery"
    FILE_ERASE = "file_erase"
    FREE_SPACE_WIPE = "free_space_wipe"
    WHOLE_DRIVE_CLEAR = "whole_drive_clear"
    ATA_SANITIZE = "ata_sanitize"
    ATA_SECURITY_ERASE = "ata_security_erase"
    NVME_SANITIZE = "nvme_sanitize"
    NVME_FORMAT = "nvme_format"
    CRYPTO_ERASE = "crypto_erase"
    RAW_ACQUISITION = "raw_acquisition"
    VOLUME_ACQUISITION = "volume_acquisition"
    HPA_DCO_DISCOVERY = "hpa_dco_discovery"
    HPA_DCO_MODIFY = "hpa_dco_modify"
    BACKUP_RESTORE = "backup_restore"
    TRACE_SWEEP = "trace_sweep"


CAPABILITY_LABELS: dict[Capability, str] = {
    Capability.DEVICE_DISCOVERY: "Device discovery",
    Capability.FILE_ERASE: "File erase",
    Capability.FREE_SPACE_WIPE: "Free-space wipe",
    Capability.WHOLE_DRIVE_CLEAR: "Whole-drive clear (addressable overwrite)",
    Capability.ATA_SANITIZE: "ATA SANITIZE (device sanitize)",
    Capability.ATA_SECURITY_ERASE: "ATA SECURITY ERASE UNIT (device sanitize)",
    Capability.NVME_SANITIZE: "NVMe Sanitize (device sanitize)",
    Capability.NVME_FORMAT: "NVMe Format NVM, user-data erase (device sanitize)",
    Capability.CRYPTO_ERASE: "Cryptographic erase",
    Capability.RAW_ACQUISITION: "Raw physical-device acquisition",
    Capability.VOLUME_ACQUISITION: "Logical volume acquisition",
    Capability.HPA_DCO_DISCOVERY: "HPA / DCO discovery",
    Capability.HPA_DCO_MODIFY: "HPA / DCO modification",
    Capability.BACKUP_RESTORE: "Backup restore",
    Capability.TRACE_SWEEP: "Live-desktop trace sweep",
}

class OperationStatus(StrEnum):
    """What happened, established *after* an operation ran (reports only)."""

    SUCCESS = "SUCCESS"
    VERIFIED = "VERIFIED"
    INCONCLUSIVE = "INCONCLUSIVE"
    FAILED = "FAILED"
    NOT_AUTHORIZED = "NOT_AUTHORIZED"
    NOT_PERFORMED = "NOT_PERFORMED"


class Operation(StrEnum):
    """Every operation a capability row can describe."""

    DEVICE_DISCOVERY = "device_discovery"
    FILE_ERASE = "file_erase"
    FOLDER_ERASE = "folder_erase"
    BATCH_ERASE = "batch_erase"
    METADATA_CLEANSE = "metadata_cleanse"
    FREE_SPACE_WIPE = "free_space_wipe"
    WHOLE_DRIVE_CLEAR = "whole_drive_clear"
    WHOLE_DRIVE_PURGE = "whole_drive_purge"
    FILE_VERIFICATION = "file_verification"
    DRIVE_VERIFICATION = "drive_verification"
    RESUME = "resume"


#: Plain-language names. The UI shows these; the enum value is for machines.
OPERATION_LABELS: dict[Operation, str] = {
    Operation.DEVICE_DISCOVERY: "Device discovery",
    Operation.FILE_ERASE: "File erase",
    Operation.FOLDER_ERASE: "Folder erase",
    Operation.BATCH_ERASE: "Batch erase",
    Operation.METADATA_CLEANSE: "Metadata cleansing",
    Operation.FREE_SPACE_WIPE: "Free-space wipe",
    Operation.WHOLE_DRIVE_CLEAR: "Whole-drive Clear",
    Operation.WHOLE_DRIVE_PURGE: "Whole-drive hardware Purge",
    Operation.FILE_VERIFICATION: "File erase verification",
    Operation.DRIVE_VERIFICATION: "Whole-drive verification",
    Operation.RESUME: "Resume an interrupted wipe",
}

PlatformFamily = Literal["linux", "windows", "macos", "other"]

#: The bus a device is attached through. A superset of the Linux
#: :data:`core.models.Transport`, because Windows and macOS report buses Linux
#: folds into others (SAS, Thunderbolt, SD readers, virtual disks).
Interface = Literal[
    "sata", "nvme", "usb", "mmc", "sas", "scsi", "thunderbolt", "virtual", "unknown"
]

#: ``flash`` is used when the medium is known to be NAND but not whether it is
#: packaged as an SSD, a stick or a card; the distinction does not change what
#: an overwrite can reach.
MediaType = Literal["hdd", "ssd", "flash", "unknown"]


class PlatformInfo(BaseModel):
    """Which host this is, as the OS itself reports it."""

    family: PlatformFamily
    #: Human name, e.g. ``Windows 11``, ``macOS 15.3``, ``Fedora Linux 44``.
    os_name: str
    os_version: str
    #: Kernel or build string, e.g. ``10.0.26100`` or ``6.19.10-300.fc44``.
    os_build: str = ""
    machine: str = ""
    app_version: str
    #: True inside a packaged build (PyInstaller); False from a source checkout.
    packaged: bool = False
    #: What this build is, from ``build_info.json`` written at package time.
    #: Empty from a source checkout, where there is no build to identify.
    build: dict[str, str] = Field(default_factory=dict)
    #: ``sys.platform`` verbatim, so a reader can check the mapping.
    sys_platform: str


class PrivilegeState(BaseModel):
    """What this process, and whatever does its privileged work, may do."""

    #: ``root`` / ``administrator`` when elevated, ``standard`` when not.
    level: Literal["root", "administrator", "standard", "unknown"]
    elevated: bool | None
    #: Sentence naming the call that established ``level``.
    basis: str
    #: How privileged operations are reached: a separate root helper over an
    #: authenticated socket, in this process, or not at all on this platform.
    helper: Literal["socket", "in-process", "none"] = "in-process"
    helper_basis: str = ""


class OperationCapability(BaseModel):
    """One row of the capability matrix."""

    operation: Operation
    label: str
    status: CapabilityStatus
    #: Plain-language sentence a non-specialist can act on.
    reason: str
    #: Which probe, file or code path established the status. Never empty.
    source: str
    verification: str = ""
    limitations: list[str] = Field(default_factory=list)
    requires_privilege: bool = False
    #: The resolver's precise state (:mod:`core.platform.capability`). ``status``
    #: is derived from it for clients that still read the older word.
    state: CapabilityState | None = None
    state_label: str = ""
    mechanism: str = ""
    assurance: str = ""
    #: Device classes with a recorded physical run backing ``state``.
    validated_classes: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class ResolvedCapability(BaseModel):
    """One capability, resolved for one device or one platform."""

    capability: Capability
    label: str
    state: CapabilityState
    #: The word the UI shows (``STATE_LABELS``).
    state_label: str
    #: Plain-language reason. Never empty.
    reason: str
    #: What established the state: table entry, probe, record.
    source: str
    mechanism: str = ""
    protocol: str = ""
    required_privilege: str = "none"
    safety_restrictions: list[str] = Field(default_factory=list)
    verification: str = ""
    assurance: str = ""
    limitations: list[str] = Field(default_factory=list)
    #: The device class physical evidence was matched against ("" for a
    #: device-free capability or the platform matrix).
    device_class: str = ""
    #: Recorded physical runs this state rests on.
    evidence: list[str] = Field(default_factory=list)
    #: Device classes with recorded physical runs (platform matrix only).
    validated_classes: list[str] = Field(default_factory=list)
    module: str = ""

    @property
    def runnable(self) -> bool:
        return self.state in RUNNABLE_STATES


class PartitionInfo(BaseModel):
    """One partition or volume on a device."""

    id: str
    size_bytes: int = 0
    filesystem: str = ""
    label: str = ""
    mount_points: list[str] = Field(default_factory=list)


class SafetyCheck(BaseModel):
    """One pre-flight check, rendered as a line the operator can read."""

    key: str
    label: str
    #: ``True`` passed, ``False`` failed (blocks), ``None`` could not be decided.
    passed: bool | None
    detail: str


class NormalizedDevice(BaseModel):
    """A storage device, the same shape on every platform."""

    #: Stable identifier the privileged layer re-resolves: ``/dev/sdb`` on
    #: Linux, ``PhysicalDrive2`` on Windows, ``disk4`` on macOS.
    id: str
    platform: PlatformFamily
    #: The path an OS tool accepts for this device.
    path: str
    vendor: str = ""
    model: str = ""
    serial: str = ""
    capacity_bytes: int = 0
    interface: Interface = "unknown"
    media_type: MediaType = "unknown"
    #: Sentence naming the signal that decided ``media_type``.
    media_basis: str = ""
    removable: bool | None = None
    #: The OS reports the disk as internal to the machine (macOS ``Internal``).
    #: ``None`` when the OS does not say.
    internal: bool | None = None
    mounted: bool = False
    mount_points: list[str] = Field(default_factory=list)
    system_device: bool = False
    #: Why ``system_device`` is true, one sentence each. Empty when it is not.
    system_reasons: list[str] = Field(default_factory=list)
    filesystems: list[str] = Field(default_factory=list)
    partitions: list[PartitionInfo] = Field(default_factory=list)
    #: A second identifier stable across replug (by-id link, UniqueId, UUID).
    stable_id: str = ""
    #: What the discovery could not establish, as sentences.
    limitations: list[str] = Field(default_factory=list)


class SanitizeOption(BaseModel):
    """One way the device could be sanitized, or why it cannot."""

    level: Literal["CLEAR", "PURGE"]
    #: Plain-language title, e.g. ``Hardware purge`` or ``Overwrite (Clear)``.
    title: str
    status: CapabilityStatus
    #: The engine's method name when one would run.
    method: str | None = None
    #: One sentence a non-specialist can read: why this is or is not offered.
    why: str
    #: The engine's justification and evidence, for "technical details".
    technical: list[str] = Field(default_factory=list)
    verification: str = ""
    remediation: str = ""
    #: The resolver's state for the capability this option would run.
    state: CapabilityState | None = None
    state_label: str = ""
    capability: Capability | None = None
    mechanism: str = ""
    protocol: str = ""
    assurance: str = ""
    limitations: list[str] = Field(default_factory=list)


class DeviceAssessment(BaseModel):
    """Everything the Sanitize screen needs to answer its three questions.

    1. What device am I about to operate on? - the device and its checks.
    2. What will happen? - ``recommended`` and ``headline``.
    3. Can the application verify it? - ``verification``.
    """

    device_id: str
    platform: PlatformFamily
    #: Overall whole-drive status for this device on this host.
    status: CapabilityStatus
    #: ``READY``, ``NOT AVAILABLE`` or ``NOT AUTHORIZED``: one word for a judge.
    headline: str
    #: Why, in one or two plain sentences.
    reason: str
    recommended_action: str = ""
    recommended: SanitizeOption | None = None
    alternatives: list[SanitizeOption] = Field(default_factory=list)
    unavailable: list[SanitizeOption] = Field(default_factory=list)
    verification: str = ""
    safety_checks: list[SafetyCheck] = Field(default_factory=list)
    flash_limitation: str = ""
    #: The evidence bucket this device falls in (``usb-flash``, ``nvme``, ...).
    device_class: str = ""
    #: Every device capability as the resolver answers it, each with a reason.
    capabilities: list[ResolvedCapability] = Field(default_factory=list)


FilesystemCapability = Literal[
    "detect", "read", "erase_files", "metadata", "free_space", "whole_drive"
]


class FilesystemSupport(BaseModel):
    """One filesystem, one row per capability, one cell per platform."""

    filesystem: str
    #: capability -> platform -> status
    cells: dict[str, dict[str, CapabilityStatus]]
    #: capability -> sentence explaining the row
    notes: dict[str, str] = Field(default_factory=dict)


class MediaClassSupport(BaseModel):
    """Storage-class row for the platform screen (Internal SSD, USB HDD, ...)."""

    media_class: str
    discovery: CapabilityStatus
    file_erase: CapabilityStatus
    whole_drive: CapabilityStatus
    reason: str
    #: How many devices of this class discovery found on this host right now.
    detected_now: int = 0


class PlatformStatus(BaseModel):
    """The whole ``/platform`` answer."""

    platform: PlatformInfo
    privilege: PrivilegeState
    operations: list[OperationCapability]
    media_classes: list[MediaClassSupport]
    filesystems: list[FilesystemSupport]
    restrictions: list[str]
    #: Which adapter produced this (``linux``, ``windows``, ``macos``).
    adapter: str
    #: The resolver's platform matrix: every capability with its precise state.
    capabilities: list[ResolvedCapability] = Field(default_factory=list)
