"""The capability resolver: one authoritative answer per capability, per device.

Every screen, report and API answer that says whether something can be done
asks this module. Nothing else decides a capability state.

Three things are kept apart, because merging any two of them is how a tool
ends up claiming what it never did:

* **Implementation** - whether this build has code that performs the
  capability on this operating system. :data:`IMPLEMENTATIONS` is the table,
  and a package test asserts every module it names ships.
* **Availability** - whether that code can run *here, now, against this
  device*: the device must expose the mechanism (a USB bridge usually hides
  ATA and NVMe commands), the safety policy must allow it (never a system
  disk, never a mounted filesystem), and this process must hold the privilege
  the OS demands.
* **Evidence** - whether a run on real hardware *of this device class* is
  recorded. :func:`physical_evidence` reads ``physical_validations`` in the
  validation record. An ATA SANITIZE run on a SATA SSD says nothing about NVMe
  sanitize, and a clear of a USB stick says nothing about an internal disk, so
  evidence is matched on (platform, capability, device class) exactly.

The states, in the order the resolver tests for them::

    NOT_IMPLEMENTED / UNSUPPORTED_BY_PLATFORM    - no code, or the OS has no path
    UNSUPPORTED_BY_DEVICE / IMPLEMENTED_DEVICE_DEPENDENT
                                                 - the device hides it, or the
                                                   probe could not settle it
    BLOCKED_BY_SAFETY_POLICY                     - system disk, mounted, frozen
    AVAILABLE_BUT_REQUIRES_PRIVILEGE             - needs root / Administrator
    VALIDATED_PHYSICAL / IMPLEMENTED_NOT_PHYSICALLY_VALIDATED
                                                 - runnable; evidence decides

Every result carries a reason a non-specialist can read and the source that
established it. A state without a reason is a checkmark nobody measured.
"""

from __future__ import annotations

import functools
import importlib.util
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, Field

from core.platform.model import (
    CAPABILITY_LABELS,
    RUNNABLE_STATES,
    STATE_LABELS,
    Capability,
    CapabilityState,
    CapabilityStatus,
    Interface,
    MediaType,
    NormalizedDevice,
    PlatformFamily,
    ResolvedCapability,
)

__all__ = [
    "Capability",
    "CapabilityState",
    "CAPABILITY_LABELS",
    "DESTRUCTIVE",
    "DeviceClass",
    "DeviceProfile",
    "Implementation",
    "IMPLEMENTATIONS",
    "MechanismProbe",
    "PhysicalEvidence",
    "ResolvedCapability",
    "STATE_LABELS",
    "StrategyResolution",
    "device_class",
    "implementation",
    "legacy_status",
    "module_present",
    "physical_evidence",
    "profile_from_device",
    "resolve_device",
    "resolve_platform",
    "RUNNABLE_STATES",
]




#: Capabilities that write to the medium. The safety policy applies to these.
DESTRUCTIVE = frozenset(
    {
        Capability.WHOLE_DRIVE_CLEAR,
        Capability.ATA_SANITIZE,
        Capability.ATA_SECURITY_ERASE,
        Capability.NVME_SANITIZE,
        Capability.NVME_FORMAT,
        Capability.CRYPTO_ERASE,
        Capability.HPA_DCO_MODIFY,
        Capability.BACKUP_RESTORE,
    }
)

#: Capabilities that only work when the device's controller answers a probe.
#: ``probe`` in a :class:`DeviceProfile` is keyed by these values.
DEVICE_MECHANISMS = frozenset(
    {
        Capability.ATA_SANITIZE,
        Capability.ATA_SECURITY_ERASE,
        Capability.NVME_SANITIZE,
        Capability.NVME_FORMAT,
        Capability.CRYPTO_ERASE,
        Capability.HPA_DCO_DISCOVERY,
        Capability.HPA_DCO_MODIFY,
    }
)

#: Device-free capabilities: they act on files, not on a device.
_DEVICE_FREE = frozenset(
    {
        Capability.DEVICE_DISCOVERY,
        Capability.FILE_ERASE,
        Capability.FREE_SPACE_WIPE,
        Capability.TRACE_SWEEP,
    }
)

DeviceClass = Literal[
    "usb-flash",
    "usb-ssd",
    "usb-hdd",
    "sata-hdd",
    "sata-ssd",
    "nvme",
    "sas",
    "mmc",
    "thunderbolt",
    "apple-internal",
    "virtual",
    "unknown",
]

Protocol = Literal["filesystem", "block", "ATA", "NVMe", "TCG Opal", "Apple", "n/a"]
Privilege = Literal["none", "root", "administrator", "root or administrator"]


# --------------------------------------------------------------------------
# Implementation table
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Implementation:
    """What this build does for one (platform, capability), or why it does not.

    ``state`` is ``None`` when code exists. Otherwise it is
    :attr:`CapabilityState.NOT_IMPLEMENTED` or
    :attr:`CapabilityState.UNSUPPORTED_BY_PLATFORM` and ``reason`` says why.
    """

    module: str
    mechanism: str
    protocol: Protocol
    privilege: Privilege
    verification: str
    assurance: str
    limitations: tuple[str, ...] = ()
    #: Device classes on which the policy refuses this capability outright,
    #: each with its reason.
    refused_classes: Mapping[str, str] = field(default_factory=dict)
    state: CapabilityState | None = None
    reason: str = ""


def _absent(state: CapabilityState, reason: str) -> Implementation:
    return Implementation(
        module="",
        mechanism="",
        protocol="n/a",
        privilege="none",
        verification="",
        assurance="",
        state=state,
        reason=reason,
    )


_FLASH = (
    "On flash media an overwrite cannot reach blocks the controller has "
    "remapped or holds in over-provisioning. This is a Clear of the addressable "
    "storage, not NAND-level destruction."
)
_ADDRESSABLE = (
    "NIST SP 800-88 Rev. 2 Clear of the addressable LBA range the OS reports. "
    "Not a Purge, not NAND-level destruction, and it does not reach an HPA/DCO "
    "hidden region unless that region was first restored through the HPA/DCO "
    "workflow."
)
_FW_ASSURANCE = (
    "NIST SP 800-88 Rev. 2 Purge when the drive executes the command as its "
    "specification requires. Completion is the drive's own claim; Sanctum reads "
    "the medium back as well and reports both."
)
_CRYPTO_ASSURANCE = (
    "Cryptographic erase: the media encryption key is replaced. The ciphertext "
    "remains on the medium; the guarantee is only as good as the drive's key "
    "management, which Sanctum cannot inspect."
)
_VERIFY_CLEAR = (
    "Read-back of every addressable block up to 64 GiB; above that the first "
    "and last GiB plus seeded random windows, with the detection probability "
    "stated."
)
_VERIFY_FW = (
    "The drive's completion status, then a sampled read-back of the medium. "
    "Attestation is evidence, not proof."
)
_ACQ = (
    "Read-only, sector-aligned chunked reads; SHA-256 and BLAKE3 computed in "
    "the same pass; unreadable sectors are filled, recorded by LBA and never "
    "abort the run."
)
_BRIDGE = (
    "A USB or card-reader bridge usually translates only reads and writes; "
    "ATA and NVMe sanitize commands do not reach the controller behind it."
)
_APPLE_INTERNAL_RAW = (
    "Apple-managed internal storage is never raw-written: on Apple silicon and "
    "T2 Macs the Secure Enclave encrypts it, and the purge-capable path is "
    "macOS's own Erase All Content and Settings."
)

_L: PlatformFamily = "linux"
_W: PlatformFamily = "windows"
_M: PlatformFamily = "macos"
C = Capability

IMPLEMENTATIONS: dict[tuple[PlatformFamily, Capability], Implementation] = {
    # ------------------------------------------------------------ discovery
    (_L, C.DEVICE_DISCOVERY): Implementation(
        module="core.platform.linux",
        mechanism="lsblk JSON and sysfs, re-read before every destructive step",
        protocol="n/a",
        privilege="none",
        verification="Serial, model and size are read from two sources and "
        "compared.",
        assurance="Read-only.",
    ),
    (_W, C.DEVICE_DISCOVERY): Implementation(
        module="core.platform.windows",
        mechanism="Storage module (Get-Disk, Get-PhysicalDisk, Get-Partition, "
        "Get-Volume), re-read before every destructive step",
        protocol="n/a",
        privilege="none",
        verification="The disk number and serial are read again from the open "
        "handle before any write.",
        assurance="Read-only.",
    ),
    (_M, C.DEVICE_DISCOVERY): Implementation(
        module="core.platform.macos",
        mechanism="diskutil list / apfs list / info (-plist), re-read before "
        "every destructive step",
        protocol="n/a",
        privilege="none",
        verification="Size and media identity are read again from the device "
        "node before any write.",
        assurance="Read-only.",
    ),
    # ---------------------------------------------------------------- files
    (_L, C.FILE_ERASE): Implementation(
        module="core.erase.files",
        mechanism="In-place overwrite through the file handle, rename, "
        "truncate, unlink",
        protocol="filesystem",
        privilege="none",
        verification="Physical read-back of the file's mapped extents (needs root).",
        assurance="Clear of the file's current blocks. Journals, snapshots and "
        "flash remapping are reported, never claimed.",
    ),
    (_W, C.FILE_ERASE): Implementation(
        module="core.erase._platform.win",
        mechanism="In-place overwrite through the file handle with NTFS extent "
        "mapping (FSCTL_GET_RETRIEVAL_POINTERS), rename, truncate, delete",
        protocol="filesystem",
        privilege="none",
        verification="Raw volume read-back of the mapped clusters (needs "
        "Administrator).",
        assurance="Clear of the file's current clusters. MFT-resident data, "
        "Volume Shadow Copies and flash remapping are reported, never claimed.",
    ),
    (_M, C.FILE_ERASE): Implementation(
        module="core.erase.files",
        mechanism="In-place overwrite through the file handle, rename, "
        "truncate, unlink",
        protocol="filesystem",
        privilege="none",
        verification="Not possible on APFS (copy-on-write); HFS+ and FAT are "
        "read back when the extents can be mapped.",
        assurance="On APFS this is removal plus a residual report, never a "
        "verified destruction.",
        limitations=(
            "APFS is copy-on-write: the overwrite lands in new blocks and the "
            "old ones are only released.",
        ),
    ),
    (_L, C.FREE_SPACE_WIPE): Implementation(
        module="core.erase.freespace",
        mechanism="Fill the volume's free space with a file, read the fill back, "
        "release it",
        protocol="filesystem",
        privilege="none",
        verification="The fill is read back before release.",
        assurance="Clear of free blocks the filesystem hands out. Slack space "
        "and deleted directory entries are not reached.",
    ),
    (_W, C.FREE_SPACE_WIPE): _absent(
        CapabilityState.NOT_IMPLEMENTED,
        "Not implemented on Windows: how NTFS allocates a filling file "
        "(MFT zone, reserved clusters) has not been measured, so the fill "
        "could not be described honestly.",
    ),
    (_M, C.FREE_SPACE_WIPE): _absent(
        CapabilityState.NOT_IMPLEMENTED,
        "Not implemented on macOS: APFS is copy-on-write and shares free space "
        "across a container's volumes, so a fill does not map to released "
        "blocks in a way that could be verified.",
    ),
    # ---------------------------------------------------------- whole drive
    (_L, C.WHOLE_DRIVE_CLEAR): Implementation(
        module="core.erase.drive",
        mechanism="O_DIRECT sequential overwrite of every LBA of the block device",
        protocol="block",
        privilege="root",
        verification=_VERIFY_CLEAR,
        assurance=_ADDRESSABLE,
        limitations=(_FLASH,),
    ),
    (_W, C.WHOLE_DRIVE_CLEAR): Implementation(
        module="core.erase.blockclear",
        mechanism="WriteFile to \\\\.\\PhysicalDriveN opened with "
        "FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH; the handle is bound "
        "to the disk number and serial before the first write",
        protocol="block",
        privilege="administrator",
        verification=_VERIFY_CLEAR,
        assurance=_ADDRESSABLE,
        limitations=(_FLASH,),
        refused_classes={
            "virtual": "A Storage Spaces or virtual disk is not a physical "
            "medium; clearing it does not clear the disks behind it.",
        },
    ),
    (_M, C.WHOLE_DRIVE_CLEAR): Implementation(
        module="core.erase.blockclear",
        mechanism="pwrite to /dev/rdiskN (raw character device, sector-aligned)",
        protocol="block",
        privilege="root",
        verification=_VERIFY_CLEAR,
        assurance=_ADDRESSABLE,
        limitations=(_FLASH,),
        refused_classes={
            "apple-internal": _APPLE_INTERNAL_RAW,
            "virtual": "A disk image or synthesized APFS container is not a "
            "physical medium.",
        },
    ),
    # ------------------------------------------------------------- firmware
    (_L, C.ATA_SANITIZE): Implementation(
        module="core.erase.drive",
        mechanism="ATA SANITIZE DEVICE (B4h) BLOCK ERASE EXT or OVERWRITE EXT "
        "through SG_IO (hdparm --sanitize-*)",
        protocol="ATA",
        privilege="root",
        verification=_VERIFY_FW,
        assurance=_FW_ASSURANCE,
        refused_classes={"usb-flash": _BRIDGE, "mmc": _BRIDGE},
    ),
    (_W, C.ATA_SANITIZE): Implementation(
        module="core.device.win.ata",
        mechanism="ATA SANITIZE DEVICE (B4h) BLOCK ERASE EXT / OVERWRITE EXT "
        "through IOCTL_ATA_PASS_THROUGH, status polled with SANITIZE STATUS EXT",
        protocol="ATA",
        privilege="administrator",
        verification=_VERIFY_FW,
        assurance=_FW_ASSURANCE,
        limitations=(
            "The Windows storage driver may refuse the pass-through; the "
            "refusal is reported and nothing is retried another way.",
        ),
        refused_classes={"usb-flash": _BRIDGE, "mmc": _BRIDGE},
    ),
    (_M, C.ATA_SANITIZE): _absent(
        CapabilityState.UNSUPPORTED_BY_PLATFORM,
        "macOS exposes no public ATA pass-through to applications, so no ATA "
        "sanitize command can be issued from macOS.",
    ),
    (_L, C.ATA_SECURITY_ERASE): Implementation(
        module="core.erase.drive",
        mechanism="ATA SECURITY SET PASSWORD, ERASE PREPARE, ERASE UNIT "
        "(enhanced where supported) through SG_IO (hdparm)",
        protocol="ATA",
        privilege="root",
        verification=_VERIFY_FW,
        assurance=_FW_ASSURANCE
        + " NIST SP 800-88 Rev. 2 notes that some drives implement it poorly "
        "on flash; it is ranked below SANITIZE.",
        refused_classes={"usb-flash": _BRIDGE, "mmc": _BRIDGE},
    ),
    (_W, C.ATA_SECURITY_ERASE): _absent(
        CapabilityState.NOT_IMPLEMENTED,
        "Not implemented on Windows. The sequence sets a drive password first; "
        "if the erase is then refused or interrupted the drive stays locked, "
        "and no recovery path for that has been built and tested on Windows. "
        "ATA SANITIZE is offered instead where the drive supports it.",
    ),
    (_M, C.ATA_SECURITY_ERASE): _absent(
        CapabilityState.UNSUPPORTED_BY_PLATFORM,
        "macOS exposes no public ATA pass-through to applications.",
    ),
    (_L, C.NVME_SANITIZE): Implementation(
        module="core.erase.drive",
        mechanism="NVMe Sanitize (84h), block-erase action, through the NVMe "
        "admin ioctl (nvme sanitize)",
        protocol="NVMe",
        privilege="root",
        verification=_VERIFY_FW,
        assurance=_FW_ASSURANCE,
    ),
    (_W, C.NVME_SANITIZE): Implementation(
        module="core.device.win.nvme",
        mechanism="IOCTL_STORAGE_REINITIALIZE_MEDIA with the block-erase "
        "sanitize method (the in-box NVMe driver issues NVMe Sanitize)",
        protocol="NVMe",
        privilege="administrator",
        verification=_VERIFY_FW,
        assurance=_FW_ASSURANCE,
        limitations=(
            "Windows gives no progress for the sanitize; the call returns when "
            "the driver reports completion or the timeout expires.",
        ),
    ),
    (_M, C.NVME_SANITIZE): _absent(
        CapabilityState.UNSUPPORTED_BY_PLATFORM,
        "macOS exposes no public NVMe admin-command interface to applications.",
    ),
    (_L, C.NVME_FORMAT): Implementation(
        module="core.erase.drive",
        mechanism="NVMe Format NVM (80h) with Secure Erase Settings = 1 "
        "(user-data erase) through the NVMe admin ioctl (nvme format --ses=1)",
        protocol="NVMe",
        privilege="root",
        verification=_VERIFY_FW,
        assurance=_FW_ASSURANCE,
    ),
    (_W, C.NVME_FORMAT): _absent(
        CapabilityState.UNSUPPORTED_BY_PLATFORM,
        "Windows' in-box NVMe driver does not pass Format NVM through "
        "IOCTL_STORAGE_PROTOCOL_COMMAND, so it cannot be issued from Windows. "
        "NVMe Sanitize is used instead where the drive supports it.",
    ),
    (_M, C.NVME_FORMAT): _absent(
        CapabilityState.UNSUPPORTED_BY_PLATFORM,
        "macOS exposes no public NVMe admin-command interface to applications.",
    ),
    (_L, C.CRYPTO_ERASE): Implementation(
        module="core.erase.drive",
        mechanism="ATA SANITIZE CRYPTO SCRAMBLE EXT where the drive reports it. "
        "A TCG Opal drive is recognised (sedutil-cli) but not reverted: this "
        "build cannot accept the PSID",
        protocol="ATA",
        privilege="root",
        verification=_VERIFY_FW,
        assurance=_CRYPTO_ASSURANCE,
        refused_classes={"usb-flash": _BRIDGE, "mmc": _BRIDGE},
    ),
    (_W, C.CRYPTO_ERASE): Implementation(
        module="core.device.win.nvme",
        mechanism="IOCTL_STORAGE_REINITIALIZE_MEDIA with the crypto-erase "
        "sanitize method (NVMe), or ATA SANITIZE CRYPTO SCRAMBLE EXT through "
        "IOCTL_ATA_PASS_THROUGH",
        protocol="NVMe",
        privilege="administrator",
        verification=_VERIFY_FW,
        assurance=_CRYPTO_ASSURANCE,
        refused_classes={"usb-flash": _BRIDGE, "mmc": _BRIDGE},
    ),
    (_M, C.CRYPTO_ERASE): _absent(
        CapabilityState.UNSUPPORTED_BY_PLATFORM,
        "macOS exposes no crypto-erase command to applications. On Apple "
        "silicon and T2 Macs the equivalent is Erase All Content and Settings, "
        "which destroys the Secure Enclave keys; Sanctum cannot perform or "
        "verify it and names it as the recommended action instead.",
    ),
    # ---------------------------------------------------------- acquisition
    (_L, C.RAW_ACQUISITION): Implementation(
        module="core.carve.acquire",
        mechanism="O_RDONLY block-device read after BLKROSET, with the "
        "read-only flag read back (BLKROGET)",
        protocol="block",
        privilege="root",
        verification=_ACQ,
        assurance="Forensic image of the addressable LBA range; software write "
        "block applied and verified at the block layer.",
    ),
    (_W, C.RAW_ACQUISITION): Implementation(
        module="core.carve.win_source",
        mechanism="CreateFileW(\\\\.\\PhysicalDriveN, GENERIC_READ, "
        "FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_FLAG_NO_BUFFERING) with the "
        "size from IOCTL_DISK_GET_LENGTH_INFO; the handle is bound to the "
        "selected disk number and serial",
        protocol="block",
        privilege="administrator",
        verification=_ACQ,
        assurance="Forensic image of the addressable LBA range. Windows has no "
        "software write block: the handle is opened without write access, and "
        "a hardware write blocker is still the correct control.",
        limitations=(
            "No software write block exists on Windows; the report says so.",
        ),
    ),
    (_M, C.RAW_ACQUISITION): Implementation(
        module="core.carve.mac_source",
        mechanism="O_RDONLY read of /dev/rdiskN with the size from "
        "DKIOCGETBLOCKCOUNT x DKIOCGETBLOCKSIZE",
        protocol="block",
        privilege="root",
        verification=_ACQ,
        assurance="Forensic image of the addressable LBA range. macOS has no "
        "software write block; the device is opened read-only and a hardware "
        "write blocker is still the correct control.",
        limitations=(
            "No software write block exists on macOS; the report says so.",
        ),
        refused_classes={
            "apple-internal": "Internal Apple storage is encrypted by the "
            "Secure Enclave; a raw image of it is ciphertext that cannot be "
            "decrypted off the machine, so it is not offered.",
        },
    ),
    (_L, C.VOLUME_ACQUISITION): Implementation(
        module="core.carve.acquire",
        mechanism="O_RDONLY read of the partition block device after BLKROSET",
        protocol="block",
        privilege="root",
        verification=_ACQ,
        assurance="Image of one partition; unallocated space outside it is not "
        "included.",
    ),
    (_W, C.VOLUME_ACQUISITION): Implementation(
        module="core.carve.win_source",
        mechanism="CreateFileW(\\\\.\\X:, GENERIC_READ) with the size from "
        "IOCTL_DISK_GET_LENGTH_INFO",
        protocol="block",
        privilege="administrator",
        verification=_ACQ,
        assurance="Image of one volume as the volume manager presents it. A "
        "mounted volume may change while it is read; the report says so.",
    ),
    (_M, C.VOLUME_ACQUISITION): Implementation(
        module="core.carve.mac_source",
        mechanism="O_RDONLY read of /dev/rdiskNsM",
        protocol="block",
        privilege="root",
        verification=_ACQ,
        assurance="Image of one partition. An APFS volume inside a container "
        "is not a partition and is imaged through its container's store.",
        refused_classes={
            "apple-internal": "Internal Apple storage is encrypted by the "
            "Secure Enclave; a raw image of it is ciphertext.",
        },
    ),
    # --------------------------------------------------------------- HPA/DCO
    (_L, C.HPA_DCO_DISCOVERY): Implementation(
        module="core.device.hidden_areas",
        mechanism="READ NATIVE MAX ADDRESS and DEVICE CONFIGURATION IDENTIFY "
        "(hdparm -N, hdparm --dco-identify)",
        protocol="ATA",
        privilege="root",
        verification="Read-only; the reported native maximum is checked for "
        "plausibility against the kernel size.",
        assurance="Discovery only. A bridge's answer is rejected rather than "
        "believed.",
        refused_classes={"usb-flash": _BRIDGE, "mmc": _BRIDGE},
    ),
    (_W, C.HPA_DCO_DISCOVERY): Implementation(
        module="core.device.hidden_area_workflow",
        mechanism="IDENTIFY DEVICE (ECh), READ NATIVE MAX ADDRESS EXT (27h) and "
        "DEVICE CONFIGURATION IDENTIFY (B1h/C2h) through IOCTL_ATA_PASS_THROUGH "
        "(core.device.win.ata), on a handle bound to the disk's serial and size",
        protocol="ATA",
        privilege="administrator",
        verification="Read-only; the reported native maximum is checked for "
        "plausibility against the Windows disk length, and an IDENTIFY buffer "
        "whose checksum fails is not believed.",
        assurance="Discovery only.",
        refused_classes={"usb-flash": _BRIDGE, "mmc": _BRIDGE},
    ),
    (_M, C.HPA_DCO_DISCOVERY): _absent(
        CapabilityState.UNSUPPORTED_BY_PLATFORM,
        "macOS exposes no public ATA pass-through, so the native maximum "
        "address cannot be read from macOS.",
    ),
    (_L, C.HPA_DCO_MODIFY): Implementation(
        module="core.device.hidden_area_workflow",
        mechanism="SET MAX ADDRESS to the native maximum: hdparm -N <native> "
        "(volatile, the default) or hdparm -N p<native> (permanent, only when "
        "explicitly requested and approved), only through the guarded HPA/DCO "
        "workflow; DCO RESTORE and DCO SET are never issued",
        protocol="ATA",
        privilege="root",
        verification="hdparm -N is read again immediately before the change "
        "(a drifted plan is refused) and after it: the accessible maximum must "
        "equal the requested value and the native maximum must be unchanged.",
        assurance="Changes the drive's configuration. Never done implicitly by "
        "an erase: an ordinary erase covers the accessible range only and "
        "reports the hidden bytes it did not reach.",
        limitations=(
            "Only the HPA is changed. DCO RESTORE can make a drive report a "
            "different model's geometry and is not issued by this build.",
            "A volatile change is lost at the next power cycle.",
            "The kernel keeps the size it read at attach time; the device must "
            "be rescanned or re-attached before an erase sees the new size.",
        ),
        refused_classes={"usb-flash": _BRIDGE, "mmc": _BRIDGE},
    ),
    (_W, C.HPA_DCO_MODIFY): Implementation(
        module="core.device.hidden_area_workflow",
        mechanism="SET MAX ADDRESS EXT (37h) to the native maximum with VV=1 "
        "(volatile, the default; VV=0 only when a permanent change is "
        "explicitly requested and approved), immediately after READ NATIVE MAX "
        "ADDRESS EXT (27h), through IOCTL_ATA_PASS_THROUGH, only through the "
        "guarded HPA/DCO workflow; DCO RESTORE and DCO SET are never issued",
        protocol="ATA",
        privilege="administrator",
        verification="IDENTIFY DEVICE and READ NATIVE MAX ADDRESS EXT are read "
        "again immediately before the change (a drifted plan is refused) and "
        "after it: the accessible maximum must equal the requested value and "
        "the native maximum must be unchanged.",
        assurance="Changes the drive's configuration. Never done implicitly by "
        "an erase: an ordinary erase covers the accessible range only and "
        "reports the hidden bytes it did not reach.",
        limitations=(
            "Only the HPA is changed. DCO RESTORE is not issued by this build.",
            "A volatile change is lost at the next power cycle.",
        ),
        refused_classes={"usb-flash": _BRIDGE, "mmc": _BRIDGE},
    ),
    (_M, C.HPA_DCO_MODIFY): _absent(
        CapabilityState.UNSUPPORTED_BY_PLATFORM,
        "macOS exposes no public ATA pass-through, so SET MAX ADDRESS cannot be "
        "issued from macOS.",
    ),
    # --------------------------------------------------------------- restore
    (_L, C.BACKUP_RESTORE): Implementation(
        module="core.restore",
        mechanism="Sector-aligned O_SYNC writes of the verified image to the "
        "block device, then a hash of the written range",
        protocol="block",
        privilege="root",
        verification="SHA-256 of the written range must equal the image's.",
        assurance="The target holds the image's bytes over the restored range. "
        "A backup is not proof of where its bytes came from.",
    ),
    (_W, C.BACKUP_RESTORE): Implementation(
        module="core.restore",
        mechanism="WriteFile of the verified image to \\\\.\\PhysicalDriveN "
        "through the same bound, unbuffered handle the clear uses",
        protocol="block",
        privilege="administrator",
        verification="SHA-256 of the written range must equal the image's.",
        assurance="The target holds the image's bytes over the restored range.",
        refused_classes={"virtual": "Not a physical medium."},
    ),
    (_M, C.BACKUP_RESTORE): Implementation(
        module="core.restore",
        mechanism="pwrite of the verified image to /dev/rdiskN",
        protocol="block",
        privilege="root",
        verification="SHA-256 of the written range must equal the image's.",
        assurance="The target holds the image's bytes over the restored range.",
        refused_classes={"apple-internal": _APPLE_INTERNAL_RAW},
    ),
    # --------------------------------------------------------------- traces
    (_L, C.TRACE_SWEEP): Implementation(
        module="core.erase.traces",
        mechanism="Evidence-tied search of thumbnails, recent-files lists and "
        "Trash; removal reuses the file erase",
        protocol="filesystem",
        privilege="none",
        verification="Every location inspected and every one not searched is "
        "listed in the report.",
        assurance="Removes only traces tied to an erased path on evidence.",
    ),
    (_W, C.TRACE_SWEEP): Implementation(
        module="core.erase.traces",
        mechanism="Evidence-tied search of the Recycle Bin ($I records), Recent "
        "shortcuts and jump lists",
        protocol="filesystem",
        privilege="none",
        verification="Every location inspected and every one not searched is "
        "listed in the report.",
        assurance="Removes only traces tied to an erased path on evidence.",
    ),
    (_M, C.TRACE_SWEEP): Implementation(
        module="core.erase.traces",
        mechanism="Evidence-tied search of the Trash (put-back records), recent "
        "items and the Quick Look cache",
        protocol="filesystem",
        privilege="none",
        verification="Every location inspected and every one not searched is "
        "listed in the report.",
        assurance="Removes only traces tied to an erased path on evidence.",
    ),
}
del C


@functools.cache
def module_present(name: str) -> bool:
    """Whether ``name`` can be imported in this build (source or packaged).

    A package that lost a backend module would otherwise still report the
    capability from this table; checking the module is what keeps the table
    honest about the build it is running in.
    """
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def implementation(platform: PlatformFamily, capability: Capability) -> Implementation:
    """The table entry, or a NOT_IMPLEMENTED entry for an unknown platform.

    An entry whose module is missing from this build becomes NOT_IMPLEMENTED
    with that reason.
    """
    found = IMPLEMENTATIONS.get((platform, capability))
    if found is not None and found.state is None and not module_present(found.module):
        return _absent(
            CapabilityState.NOT_IMPLEMENTED,
            f"This build is missing {found.module}, which performs "
            f"{CAPABILITY_LABELS[capability].lower()}; the package is incomplete.",
        )
    if found is not None:
        return found
    return _absent(
        CapabilityState.NOT_IMPLEMENTED,
        f"This build has no {CAPABILITY_LABELS[capability].lower()} for "
        f"the '{platform}' platform.",
    )


# --------------------------------------------------------------------------
# Device profile
# --------------------------------------------------------------------------


class MechanismProbe(BaseModel):
    """What a device reported about one mechanism.

    ``exposed`` is ``True`` when the controller reported support, ``False``
    when it reported none or a bridge hides the command set, ``None`` when the
    probe could not settle the question (not run, refused, unreadable).
    """

    exposed: bool | None
    basis: str
    #: Exposed, but a device state refuses it now (security frozen, a sanitize
    #: already in progress). The reason is in ``basis``.
    blocked: bool = False
    #: The exact command or IOCTL the probe issued, for the report.
    command: str = ""


class DeviceProfile(BaseModel):
    """Everything the resolver needs about one device, and nothing it doesn't."""

    platform: PlatformFamily
    architecture: str = ""
    device_id: str
    path: str = ""
    model: str = ""
    serial: str = ""
    size_bytes: int = 0
    interface: Interface = "unknown"
    media_type: MediaType = "unknown"
    removable: bool | None = None
    #: Internal storage Apple manages (Apple silicon fabric, T2 NVMe).
    apple_managed: bool = False
    system_device: bool = False
    system_reasons: list[str] = Field(default_factory=list)
    mounted: bool = False
    mount_points: list[str] = Field(default_factory=list)
    filesystems: list[str] = Field(default_factory=list)
    #: ``True`` elevated, ``False`` not, ``None`` unknown.
    privileged: bool | None = None
    privilege_basis: str = ""
    #: Keyed by :class:`Capability` value.
    probes: dict[str, MechanismProbe] = Field(default_factory=dict)


def device_class(
    interface: str, media_type: str, *, apple_managed: bool = False
) -> DeviceClass:
    """The evidence bucket a device falls in. Pure."""
    if apple_managed:
        return "apple-internal"
    if interface == "usb":
        if media_type == "hdd":
            return "usb-hdd"
        if media_type == "ssd":
            return "usb-ssd"
        return "usb-flash"
    if interface in {"sata", "scsi"}:
        if media_type == "hdd":
            return "sata-hdd"
        if media_type in {"ssd", "flash"}:
            return "sata-ssd"
        return "unknown"
    if interface == "nvme":
        return "nvme"
    if interface == "sas":
        return "sas"
    if interface == "mmc":
        return "mmc"
    if interface == "thunderbolt":
        return "thunderbolt"
    if interface == "virtual":
        return "virtual"
    return "unknown"


def profile_from_device(
    device: NormalizedDevice,
    *,
    privileged: bool | None,
    privilege_basis: str = "",
    probes: Mapping[str, MechanismProbe] | None = None,
    architecture: str = "",
    apple_managed: bool = False,
) -> DeviceProfile:
    """A :class:`DeviceProfile` from a discovery row plus probe results."""
    return DeviceProfile(
        platform=device.platform,
        architecture=architecture,
        device_id=device.id,
        path=device.path,
        model=device.model,
        serial=device.serial,
        size_bytes=device.capacity_bytes,
        interface=device.interface,
        media_type=device.media_type,
        removable=device.removable,
        apple_managed=apple_managed,
        system_device=device.system_device,
        system_reasons=list(device.system_reasons),
        mounted=device.mounted,
        mount_points=list(device.mount_points),
        filesystems=list(device.filesystems),
        privileged=privileged,
        privilege_basis=privilege_basis,
        probes=dict(probes or {}),
    )


# --------------------------------------------------------------------------
# Evidence
# --------------------------------------------------------------------------


class PhysicalEvidence(BaseModel):
    """One recorded run on real hardware, as the validation record holds it."""

    platform: str
    capability: str
    device_class: str
    model: str = ""
    serial: str = ""
    interface: str = ""
    os: str = ""
    date: str = ""
    commit: str = ""
    method: str = ""
    preflight: str = ""
    operation: str = ""
    verification: str = ""
    artifacts: list[str] = Field(default_factory=list)
    report_hash: str = ""
    ledger_entry: str = ""
    result: str = ""


def physical_evidence(
    platform: str,
    capability: Capability,
    *,
    device_class: str | None = None,
    record: Mapping[str, Any] | None = None,
) -> list[PhysicalEvidence]:
    """Recorded PASS runs for (platform, capability[, device class]).

    ``device_class=None`` returns every class, for the platform matrix, where
    the scope is then printed rather than generalised.
    """
    if record is None:
        from core.platform.validation import load_record

        record = load_record()
    found: list[PhysicalEvidence] = []
    for raw in record.get("physical_validations") or []:
        if not isinstance(raw, dict):
            continue
        try:
            entry = PhysicalEvidence.model_validate(raw)
        except ValueError:
            continue
        if entry.result != "PASS":
            continue
        if entry.platform != platform or entry.capability != capability.value:
            continue
        if device_class is not None and entry.device_class != device_class:
            continue
        found.append(entry)
    return found


def _evidence_refs(items: Iterable[PhysicalEvidence]) -> list[str]:
    return [
        f"{item.date} {item.model or 'device'} ({item.device_class}, "
        f"{item.interface or 'interface not recorded'}) at "
        f"{item.commit or 'commit not recorded'}"
        for item in items
    ]


# --------------------------------------------------------------------------
# Resolution
# --------------------------------------------------------------------------


class StrategyResolution(BaseModel):
    """The resolver's whole answer for one device."""

    device_id: str
    platform: PlatformFamily
    device_class: str
    capabilities: list[ResolvedCapability]
    #: Runnable device-sanitize capabilities, strongest first.
    sanitize_order: list[Capability] = Field(default_factory=list)

    def get(self, capability: Capability) -> ResolvedCapability:
        for item in self.capabilities:
            if item.capability is capability:
                return item
        raise KeyError(capability)


def _result(
    capability: Capability,
    state: CapabilityState,
    reason: str,
    source: str,
    impl: Implementation | None,
    *,
    klass: str = "",
    restrictions: list[str] | None = None,
    extra_limits: Iterable[str] = (),
    evidence: list[str] | None = None,
    validated_classes: list[str] | None = None,
) -> ResolvedCapability:
    limits = list(impl.limitations) if impl else []
    limits.extend(item for item in extra_limits if item not in limits)
    return ResolvedCapability(
        capability=capability,
        label=CAPABILITY_LABELS[capability],
        state=state,
        state_label=STATE_LABELS[state],
        reason=reason,
        source=source,
        mechanism=impl.mechanism if impl else "",
        protocol=impl.protocol if impl else "",
        required_privilege=impl.privilege if impl else "none",
        safety_restrictions=list(restrictions or []),
        verification=impl.verification if impl else "",
        assurance=impl.assurance if impl else "",
        limitations=limits,
        device_class=klass,
        evidence=list(evidence or []),
        validated_classes=list(validated_classes or []),
        module=impl.module if impl else "",
    )


def _table_ref(platform: str, capability: Capability) -> str:
    return f"core.platform.capability.IMPLEMENTATIONS[{platform}, {capability.value}]"


def _safety_reasons(profile: DeviceProfile) -> list[str]:
    reasons: list[str] = []
    if profile.system_device:
        reasons.append(
            "This is the system or boot disk"
            + (
                ": " + " ".join(profile.system_reasons)
                if profile.system_reasons
                else "."
            )
        )
    if profile.mounted:
        reasons.append(
            "A filesystem on this device is mounted ("
            + (", ".join(profile.mount_points) or "mount point not reported")
            + "); unmount or take the disk offline, then rescan."
        )
    if not profile.serial.strip():
        reasons.append(
            "The device reports no serial number, so its identity cannot be "
            "bound between planning and the write; destructive work is refused."
        )
    return reasons


def _resolve_one(
    profile: DeviceProfile,
    capability: Capability,
    klass: DeviceClass,
    record: Mapping[str, Any] | None,
) -> ResolvedCapability:
    impl = implementation(profile.platform, capability)
    table = _table_ref(profile.platform, capability)
    if impl.state is not None:
        return _result(capability, impl.state, impl.reason, table, None, klass=klass)

    refused = impl.refused_classes.get(klass)
    if refused:
        state = (
            CapabilityState.UNSUPPORTED_BY_DEVICE
            if capability in DEVICE_MECHANISMS
            else CapabilityState.BLOCKED_BY_SAFETY_POLICY
        )
        return _result(
            capability, state, refused, table + " refused_classes", impl, klass=klass
        )

    extra: list[str] = []
    source = table
    if capability in DEVICE_MECHANISMS:
        probe = profile.probes.get(capability.value)
        if probe is None or probe.exposed is None:
            why = (
                probe.basis
                if probe is not None
                else "The device was not probed for this command"
            )
            return _result(
                capability,
                CapabilityState.IMPLEMENTED_DEVICE_DEPENDENT,
                f"Implemented; whether this device supports it is unknown. {why}",
                table + "; probe: " + (probe.command if probe else "not run"),
                impl,
                klass=klass,
            )
        source += "; probe: " + (probe.command or "device report") + f" ({probe.basis})"
        if probe.exposed is False:
            return _result(
                capability,
                CapabilityState.UNSUPPORTED_BY_DEVICE,
                probe.basis,
                source,
                impl,
                klass=klass,
            )
        if probe.blocked:
            return _result(
                capability,
                CapabilityState.BLOCKED_BY_SAFETY_POLICY,
                probe.basis,
                source,
                impl,
                klass=klass,
                restrictions=[probe.basis],
            )

    if capability in DESTRUCTIVE:
        reasons = _safety_reasons(profile)
        if reasons:
            return _result(
                capability,
                CapabilityState.BLOCKED_BY_SAFETY_POLICY,
                " ".join(reasons),
                source + "; safety policy (system disk, mounted filesystem, identity)",
                impl,
                klass=klass,
                restrictions=reasons,
            )
    elif capability in {Capability.RAW_ACQUISITION, Capability.VOLUME_ACQUISITION}:
        if profile.mounted:
            extra.append(
                "A filesystem on this device is mounted, so its contents may "
                "change while it is read; the image is of a live device."
            )

    if impl.privilege != "none" and profile.privileged is not True:
        basis = profile.privilege_basis or "privilege state unknown"
        return _result(
            capability,
            CapabilityState.AVAILABLE_BUT_REQUIRES_PRIVILEGE,
            f"Available ({impl.mechanism.split(';')[0]}), but it needs "
            f"{impl.privilege} and this process does not hold it ({basis}).",
            source + "; " + basis,
            impl,
            klass=klass,
            extra_limits=extra,
        )

    evidence = physical_evidence(
        profile.platform, capability, device_class=klass, record=record
    )
    if evidence:
        return _result(
            capability,
            CapabilityState.VALIDATED_PHYSICAL,
            f"Available - {impl.mechanism.split(';')[0]}. Physically validated "
            f"on this device class ({klass}).",
            source + "; validation record physical_validations",
            impl,
            klass=klass,
            extra_limits=extra,
            evidence=_evidence_refs(evidence),
        )
    return _result(
        capability,
        CapabilityState.IMPLEMENTED_NOT_PHYSICALLY_VALIDATED,
        f"Available - {impl.mechanism.split(';')[0]}. No run on a physical "
        f"{klass} device is recorded, so it is implemented, not physically "
        "validated.",
        source + "; validation record: no physical run for this class",
        impl,
        klass=klass,
        extra_limits=extra,
    )


#: Device sanitize preference: strongest mechanism first. Crypto erase is not
#: first because its guarantee rests on key management nobody can inspect.
_SANITIZE_ORDER = (
    Capability.NVME_SANITIZE,
    Capability.ATA_SANITIZE,
    Capability.CRYPTO_ERASE,
    Capability.NVME_FORMAT,
    Capability.ATA_SECURITY_ERASE,
)


def resolve_device(
    profile: DeviceProfile,
    *,
    capabilities: Iterable[Capability] | None = None,
    record: Mapping[str, Any] | None = None,
) -> StrategyResolution:
    """Resolve every device capability for one device. Pure given ``record``."""
    klass = device_class(
        profile.interface, profile.media_type, apple_managed=profile.apple_managed
    )
    wanted = [
        item
        for item in (capabilities or list(Capability))
        if item not in _DEVICE_FREE
    ]
    rows = [_resolve_one(profile, item, klass, record) for item in wanted]
    by_cap = {row.capability: row for row in rows}
    order = [
        item
        for item in _SANITIZE_ORDER
        if item in by_cap and by_cap[item].runnable
    ]
    return StrategyResolution(
        device_id=profile.device_id,
        platform=profile.platform,
        device_class=klass,
        capabilities=rows,
        sanitize_order=order,
    )


def resolve_platform(
    platform: PlatformFamily,
    *,
    privileged: bool | None,
    privilege_basis: str = "",
    record: Mapping[str, Any] | None = None,
) -> list[ResolvedCapability]:
    """The platform matrix: every capability, no particular device.

    A device mechanism resolves to IMPLEMENTED_DEVICE_DEPENDENT here, because
    without a device there is nothing to probe. A runnable capability with
    physical evidence on *some* device class is VALIDATED_PHYSICAL with that
    scope listed in ``validated_classes`` and in the reason; it is never
    generalised to classes nobody ran.
    """
    out: list[ResolvedCapability] = []
    for capability in Capability:
        impl = implementation(platform, capability)
        table = _table_ref(platform, capability)
        if impl.state is not None:
            out.append(_result(capability, impl.state, impl.reason, table, None))
            continue
        evidence = physical_evidence(platform, capability, record=record)
        classes = sorted({item.device_class for item in evidence})
        refused = [
            f"{name}: {why}" for name, why in sorted(impl.refused_classes.items())
        ]
        if capability in DEVICE_MECHANISMS:
            out.append(
                _result(
                    capability,
                    CapabilityState.IMPLEMENTED_DEVICE_DEPENDENT,
                    f"Implemented ({impl.mechanism.split(';')[0]}). Offered per "
                    "device, only when the device's controller reports the "
                    "command and no bridge hides it.",
                    table,
                    impl,
                    restrictions=refused,
                    evidence=_evidence_refs(evidence),
                    validated_classes=classes,
                )
            )
            continue
        if impl.privilege != "none" and privileged is not True:
            out.append(
                _result(
                    capability,
                    CapabilityState.AVAILABLE_BUT_REQUIRES_PRIVILEGE,
                    f"Available ({impl.mechanism.split(';')[0]}), but it needs "
                    f"{impl.privilege} and this process does not hold it "
                    f"({privilege_basis or 'privilege state unknown'}).",
                    table + "; " + (privilege_basis or "privilege unknown"),
                    impl,
                    restrictions=refused,
                    evidence=_evidence_refs(evidence),
                    validated_classes=classes,
                )
            )
            continue
        if evidence:
            out.append(
                _result(
                    capability,
                    CapabilityState.VALIDATED_PHYSICAL,
                    f"Available - {impl.mechanism.split(';')[0]}. Physically "
                    f"validated on: {', '.join(classes)} only; every other device "
                    "class is implemented, not physically validated.",
                    table + "; validation record physical_validations",
                    impl,
                    restrictions=refused,
                    evidence=_evidence_refs(evidence),
                    validated_classes=classes,
                )
            )
            continue
        out.append(
            _result(
                capability,
                CapabilityState.IMPLEMENTED_NOT_PHYSICALLY_VALIDATED,
                f"Available - {impl.mechanism.split(';')[0]}. No run on physical "
                "hardware is recorded for this platform.",
                table + "; validation record: no physical run",
                impl,
                restrictions=refused,
            )
        )
    return out


def legacy_status(
    state: CapabilityState, *, has_limits: bool = True
) -> CapabilityStatus:
    """The pre-resolver status word, for clients that still read ``status``."""
    if state is CapabilityState.VALIDATED_PHYSICAL:
        return (
            CapabilityStatus.SUPPORTED_WITH_LIMITATIONS
            if has_limits
            else CapabilityStatus.SUPPORTED
        )
    if state is CapabilityState.IMPLEMENTED_NOT_PHYSICALLY_VALIDATED:
        return CapabilityStatus.UNVERIFIED
    if state is CapabilityState.IMPLEMENTED_DEVICE_DEPENDENT:
        return CapabilityStatus.INCONCLUSIVE
    if state is CapabilityState.AVAILABLE_BUT_REQUIRES_PRIVILEGE:
        return CapabilityStatus.NOT_AUTHORIZED
    return CapabilityStatus.UNSUPPORTED
