"""The platform adapter contract, and the logic every adapter shares.

An adapter answers four kinds of question for one operating system:

* **Discovery** - :meth:`PlatformAdapter.enumerate_devices` and
  :meth:`PlatformAdapter.inspect_device` return :class:`NormalizedDevice`
  rows; the second re-reads one device from the OS, and is what the
  privileged layer calls immediately before a destructive operation so it
  never trusts a value the UI sent.
* **Capability** - :meth:`PlatformAdapter.operation_capabilities` is the
  platform matrix; :meth:`PlatformAdapter.assess_device` is the per-device
  answer the Sanitize screen renders.
* **Execution** - :meth:`PlatformAdapter.execute_drive_sanitization` either
  runs the platform's real whole-drive engine or raises
  :class:`~core.errors.PlatformUnsupported` naming why. File erasure is not an
  adapter method: :mod:`core.erase.files` is one cross-platform engine and the
  per-OS differences live in :mod:`core.erase._platform`, which the adapter
  reports on rather than duplicates.
* **Restrictions** - :meth:`PlatformAdapter.restrictions` and
  :meth:`PlatformAdapter.protected_paths`.

What is shared lives in :class:`BaseAdapter`: the safety checks (the same
checks on every OS, so Windows cannot quietly skip one Linux enforces), the
file-erase capability rows derived from the file backend, and the assessment
shape. An adapter supplies facts; it does not get to supply its own rules.
"""

from __future__ import annotations

import sys
from collections.abc import Generator
from typing import TYPE_CHECKING, Any, Protocol

from core.errors import (
    ConfirmationMismatch,
    MountedRefused,
    PlatformUnsupported,
    SystemDiskRefused,
    UnsupportedCapability,
)
from core.platform.model import (
    OPERATION_LABELS,
    RUNNABLE_STATES,
    STATE_LABELS,
    Capability,
    CapabilityState,
    CapabilityStatus,
    DeviceAssessment,
    MediaClassSupport,
    NormalizedDevice,
    Operation,
    OperationCapability,
    PlatformFamily,
    PlatformInfo,
    PrivilegeState,
    ResolvedCapability,
    SafetyCheck,
    SanitizeOption,
)

if TYPE_CHECKING:  # pragma: no cover
    from core.platform.capability import MechanismProbe, StrategyResolution

__all__ = [
    "PlatformAdapter",
    "BaseAdapter",
    "FLASH_LIMITATION",
    "DiscoveryOutcome",
    "row",
    "legacy_row",
]

#: The same sentence on every platform. Overwrite never reaches what the flash
#: translation layer has remapped or held back, and no OS changes that.
FLASH_LIMITATION = (
    "SSD / flash limitation: an overwrite cannot address blocks the flash "
    "controller has remapped or held in over-provisioned space. Only a "
    "firmware sanitize or cryptographic erase reaches them, so an overwrite of "
    "flash is reported as Clear, never as Purge."
)

#: Status values that mean "this can run on this host".
_RUNNABLE = frozenset(
    {CapabilityStatus.SUPPORTED, CapabilityStatus.SUPPORTED_WITH_LIMITATIONS}
)


def _offerable(option: SanitizeOption) -> bool:
    """Whether a drive option is offered to the operator.

    The resolver's state decides when it is set: only a runnable state is
    offered, and IMPLEMENTED / UNVALIDATED is offered under that word, never as
    supported. Without a state (an option built before resolution) the older
    rule applies: a runnable status, or UNVERIFIED with a method.
    """
    if option.state is not None:
        available = option.state in RUNNABLE_STATES or (
            option.state is CapabilityState.AVAILABLE_BUT_REQUIRES_PRIVILEGE
        )
        return available and (option.method is not None or option.level == "CLEAR")
    if option.status in _RUNNABLE:
        return True
    return option.status is CapabilityStatus.UNVERIFIED and option.method is not None


#: Which resolver capability backs each platform-matrix row. Rows whose
#: operation is not here (none today) keep the adapter's own status.
_OPERATION_CAPABILITY: dict[Operation, Capability] = {
    Operation.DEVICE_DISCOVERY: Capability.DEVICE_DISCOVERY,
    Operation.FILE_ERASE: Capability.FILE_ERASE,
    Operation.FOLDER_ERASE: Capability.FILE_ERASE,
    Operation.BATCH_ERASE: Capability.FILE_ERASE,
    Operation.METADATA_CLEANSE: Capability.FILE_ERASE,
    Operation.FILE_VERIFICATION: Capability.FILE_ERASE,
    Operation.FREE_SPACE_WIPE: Capability.FREE_SPACE_WIPE,
    Operation.WHOLE_DRIVE_CLEAR: Capability.WHOLE_DRIVE_CLEAR,
    Operation.DRIVE_VERIFICATION: Capability.WHOLE_DRIVE_CLEAR,
    Operation.RESUME: Capability.WHOLE_DRIVE_CLEAR,
}

#: Device-sanitize capabilities, the ones a "Purge" row summarises.
FIRMWARE_CAPABILITIES: tuple[Capability, ...] = (
    Capability.NVME_SANITIZE,
    Capability.ATA_SANITIZE,
    Capability.CRYPTO_ERASE,
    Capability.NVME_FORMAT,
    Capability.ATA_SECURITY_ERASE,
)

#: ``core.models.EraseMethod`` value -> the capability that performs it.
METHOD_CAPABILITY: dict[str, Capability] = {
    "SINGLE_PASS_OVERWRITE": Capability.WHOLE_DRIVE_CLEAR,
    "DOD_5220_22_M_3PASS": Capability.WHOLE_DRIVE_CLEAR,
    "ATA_SECURITY_ERASE_ENHANCED": Capability.ATA_SECURITY_ERASE,
    "ATA_SANITIZE_BLOCK_ERASE": Capability.ATA_SANITIZE,
    "ATA_SANITIZE_OVERWRITE": Capability.ATA_SANITIZE,
    "NVME_SANITIZE_BLOCK": Capability.NVME_SANITIZE,
    "NVME_SANITIZE_CRYPTO": Capability.CRYPTO_ERASE,
    "NVME_FORMAT_SES1": Capability.NVME_FORMAT,
    "ATA_SANITIZE_CRYPTO_SCRAMBLE": Capability.CRYPTO_ERASE,
    "SED_CRYPTO_ERASE": Capability.CRYPTO_ERASE,
}

#: How restrictive each state is. Merging two answers keeps the higher.
_RANK: dict[CapabilityState, int] = {
    CapabilityState.VALIDATED_PHYSICAL: 0,
    CapabilityState.IMPLEMENTED_NOT_PHYSICALLY_VALIDATED: 1,
    CapabilityState.IMPLEMENTED_DEVICE_DEPENDENT: 2,
    CapabilityState.AVAILABLE_BUT_REQUIRES_PRIVILEGE: 3,
    CapabilityState.UNSUPPORTED_BY_DEVICE: 4,
    CapabilityState.BLOCKED_BY_SAFETY_POLICY: 5,
    CapabilityState.NOT_IMPLEMENTED: 6,
    CapabilityState.UNSUPPORTED_BY_PLATFORM: 6,
}


def implied_state(status: CapabilityStatus) -> CapabilityState | None:
    """The state an adapter's own status word implies, or None if it implies none.

    Used only to *restrict*: an adapter that refused something for a reason the
    resolver cannot see (a container, a missing tool) wins over the table.
    """
    privileged = CapabilityState.AVAILABLE_BUT_REQUIRES_PRIVILEGE
    return {
        CapabilityStatus.NOT_AUTHORIZED: privileged,
        CapabilityStatus.INCONCLUSIVE: CapabilityState.IMPLEMENTED_DEVICE_DEPENDENT,
        CapabilityStatus.NOT_VERIFIABLE: CapabilityState.UNSUPPORTED_BY_PLATFORM,
        CapabilityStatus.UNSUPPORTED: CapabilityState.BLOCKED_BY_SAFETY_POLICY,
    }.get(status)


def more_restrictive(
    first: CapabilityState, second: CapabilityState | None
) -> CapabilityState:
    if second is None:
        return first
    return second if _RANK[second] > _RANK[first] else first


def purge_summary(
    resolved: dict[Capability, ResolvedCapability],
) -> ResolvedCapability | None:
    """One answer for "hardware purge" from the per-protocol answers.

    The least restrictive firmware capability wins, because the row asks
    whether *any* device-sanitize path exists here; each path keeps its own
    row in the resolver's list.
    """
    candidates = [resolved[item] for item in FIRMWARE_CAPABILITIES if item in resolved]
    if not candidates:
        return None
    best = min(candidates, key=lambda item: _RANK[item.state])
    names = [
        f"{item.label}: {item.state_label.lower()}"
        for item in candidates
    ]
    return best.model_copy(
        update={"reason": best.reason + " Per protocol - " + "; ".join(names) + "."}
    )


def row(
    operation: Operation,
    status: CapabilityStatus,
    reason: str,
    source: str,
    *,
    verification: str = "",
    limitations: list[str] | None = None,
    requires_privilege: bool = False,
    state: CapabilityState | None = None,
) -> OperationCapability:
    """Build one capability row. ``source`` is mandatory by construction.

    ``state`` is set only when the adapter knows a precise reason the resolver
    cannot see (a container, a missing tool); it then restricts the resolver's
    answer rather than being replaced by it.
    """
    if not source:
        raise ValueError(f"capability row {operation} has no source")
    return OperationCapability(
        operation=operation,
        label=OPERATION_LABELS[operation],
        status=status,
        reason=reason,
        source=source,
        verification=verification,
        limitations=list(limitations or []),
        requires_privilege=requires_privilege,
        state=state,
        state_label=STATE_LABELS[state] if state else "",
    )


class DiscoveryOutcome:
    """What the last device discovery on this adapter established."""

    def __init__(self) -> None:
        self.ran = False
        self.ok = False
        self.tool = ""
        self.detail = ""
        self.devices: list[NormalizedDevice] = []

    def record(
        self, *, ok: bool, tool: str, detail: str, devices: list[NormalizedDevice]
    ) -> None:
        self.ran = True
        self.ok = ok
        self.tool = tool
        self.detail = detail
        self.devices = devices


class PlatformAdapter(Protocol):
    """What the sanitization service needs from an operating system."""

    name: str
    family: PlatformFamily

    def platform_info(self) -> PlatformInfo: ...

    def privilege_state(self) -> PrivilegeState: ...

    def enumerate_devices(
        self, *, include_virtual: bool = False
    ) -> list[NormalizedDevice]: ...

    def inspect_device(self, device_id: str) -> NormalizedDevice: ...

    def assess_device(self, device: NormalizedDevice) -> DeviceAssessment: ...

    def operation_capabilities(self) -> list[OperationCapability]: ...

    def media_classes(self) -> list[MediaClassSupport]: ...

    def restrictions(self) -> list[str]: ...

    def protected_paths(self) -> list[str]: ...

    def execute_drive_sanitization(
        self, params: dict[str, Any]
    ) -> Generator[dict[str, Any], None, dict[str, Any]]: ...

    def resume_drive_sanitization(
        self, params: dict[str, Any]
    ) -> Generator[dict[str, Any], None, dict[str, Any]]: ...


class BaseAdapter:
    """Shared behaviour. Subclasses supply OS facts, never their own rules."""

    name = "base"
    family: PlatformFamily = "other"

    def __init__(
        self,
        *,
        helper: str = "in-process",
        helper_basis: str = "",
        privilege: PrivilegeState | None = None,
    ) -> None:
        self._helper = helper
        self._helper_basis = helper_basis
        #: Tests only: the privilege this adapter reports instead of the host's.
        self._privilege_override = privilege
        self.discovery = DiscoveryOutcome()

    # -- host ---------------------------------------------------------------

    def platform_info(self) -> PlatformInfo:
        from core.platform.host import platform_info

        return platform_info()

    def privilege_state(self) -> PrivilegeState:
        if self._privilege_override is not None:
            return self._privilege_override
        from core.platform.host import privilege_state

        return privilege_state(helper=self._helper, helper_basis=self._helper_basis)

    # -- discovery (subclass) -----------------------------------------------

    def enumerate_devices(
        self, *, include_virtual: bool = False
    ) -> list[NormalizedDevice]:
        raise NotImplementedError

    def inspect_device(self, device_id: str) -> NormalizedDevice:
        """Re-read one device from the OS. Never served from a cache."""
        from core.errors import DeviceVanished

        needle = device_id.strip()
        for device in self.enumerate_devices(include_virtual=True):
            if needle in {device.id, device.path, device.serial, device.stable_id}:
                return device
        raise DeviceVanished(f"No storage device matches {device_id!r}.")

    def device_rows(self, *, include_virtual: bool = False) -> list[dict[str, Any]]:
        """The helper's ``enumerate_devices`` answer.

        ``device`` keeps the legacy field names so the device screens still
        render; a platform with no Linux capability probe or erase preview
        leaves those keys null with the reason in ``capability_error``.
        :class:`~core.platform.linux.LinuxAdapter` overrides this with the
        real probe.
        """
        rows: list[dict[str, Any]] = []
        reason = self.whole_drive_unavailable_reason()
        for device in self.enumerate_devices(include_virtual=include_virtual):
            entry = legacy_row(device, reason)
            entry["assessment"] = self.assess_device(device).model_dump(mode="json")
            rows.append(entry)
        return rows

    # -- whole-drive (subclass) ---------------------------------------------

    def whole_drive_unavailable_reason(self) -> str:
        """Why this platform has no whole-drive engine, or ``""`` if it has one."""
        return (
            f"This build has no whole-drive sanitization engine for "
            f"{self.family}. Nothing is offered rather than something unverified."
        )

    def whole_drive_recommended_action(self) -> str:
        return (
            "Sanitize this device with the Sanctum Linux build (AppImage) on "
            "any Linux host or live USB, where the validated whole-drive engine "
            "runs, or use the drive vendor's own sanitize tool."
        )

    def execute_drive_sanitization(
        self, params: dict[str, Any]
    ) -> Generator[dict[str, Any], None, dict[str, Any]]:
        raise PlatformUnsupported(
            self.whole_drive_unavailable_reason()
            + " No operation was performed on the device.",
            remediation=self.whole_drive_recommended_action(),
        )
        yield {}  # pragma: no cover - makes this a generator

    def resume_drive_sanitization(
        self, params: dict[str, Any]
    ) -> Generator[dict[str, Any], None, dict[str, Any]]:
        raise PlatformUnsupported(
            self.whole_drive_unavailable_reason()
            + " There is nothing to resume on this platform.",
            remediation=self.whole_drive_recommended_action(),
        )
        yield {}  # pragma: no cover - makes this a generator

    def authorization_probe(self, path: str) -> dict[str, Any]:
        """The fresh read the erase workflow binds and the write seam re-checks.

        ``{"device": {path, serial, model, size_bytes, is_system_disk,
        mounted_at, ...}, "capabilities": {achievable_levels,
        est_erase_seconds, limitations}}``. The default refuses: a platform
        without an engine has nothing to authorize.
        """
        raise PlatformUnsupported(
            self.whole_drive_unavailable_reason()
            + " No operation was performed on the device.",
            remediation=self.whole_drive_recommended_action(),
        )

    def prepare_device(self, params: dict[str, Any]) -> dict[str, Any]:
        """Unmount or take offline, as a separate explicit step. Default: none."""
        raise PlatformUnsupported(
            f"This build has no device preparation step for {self.family}; "
            "unmount the device with the operating system's own tools.",
        )

    #: Device-sanitize capabilities this adapter can execute, strongest first.
    sanitize_capabilities: tuple[Capability, ...] = ()

    def _revalidated(self, params: dict[str, Any]) -> NormalizedDevice:
        """Re-read the device now and apply every refusal before anything opens."""
        from core.device.guard import refuse_removed_mode_keys

        refuse_removed_mode_keys(params)
        wanted = str(params["path"])
        device = self.inspect_device(wanted)
        if device.system_device:
            raise SystemDiskRefused(
                f"Refusing {device.path}: it is the system or boot disk. "
                + " ".join(device.system_reasons)
            )
        if device.mounted:
            raise MountedRefused(
                f"Refusing {device.path}: volumes on it are mounted at "
                + ", ".join(device.mount_points)
                + ". Nothing was written.",
                remediation=self.whole_drive_recommended_action(),
            )
        serial = normalized_serial(device.serial)
        if not serial:
            raise ConfirmationMismatch(
                f"{device.path} reports no serial number, so its identity cannot "
                "be bound. Nothing was written.",
                remediation="Use a device that reports a serial, or clear it on "
                "Linux where the by-id path is available.",
            )
        twins = [
            item.id
            for item in self.discovery.devices
            if item.id != device.id and normalized_serial(item.serial) == serial
        ]
        if twins:
            raise ConfirmationMismatch(
                f"{device.path} and {', '.join(twins)} report the same serial "
                f"{device.serial!r}; the identity is ambiguous. Nothing was written.",
                remediation="Detach the other device, rescan and try again.",
            )
        typed = normalized_serial(str(params.get("typed_serial") or ""))
        if typed != serial:
            raise ConfirmationMismatch(
                f"The typed serial does not match {device.path}, whose serial "
                f"is {device.serial!r}. Nothing was written."
            )
        return device

    def _choose(self, device: NormalizedDevice, level: str) -> tuple[Capability, Any]:
        resolution = self.device_resolution(device)
        allowed = set(RUNNABLE_STATES)
        if level == "CLEAR":
            row = resolution.get(Capability.WHOLE_DRIVE_CLEAR)
            if row.state not in allowed:
                raise UnsupportedCapability(
                    f"Whole-drive clear of {device.path} is {row.state_label}: "
                    f"{row.reason}",
                    remediation=self.whole_drive_recommended_action(),
                )
            return Capability.WHOLE_DRIVE_CLEAR, resolution
        for capability in (
            Capability.NVME_SANITIZE,
            Capability.ATA_SANITIZE,
            Capability.CRYPTO_ERASE,
        ):
            if resolution.get(capability).state in allowed and (
                capability in self.sanitize_capabilities
            ):
                return capability, resolution
        reasons = "; ".join(
            f"{row.label}: {row.state_label} ({row.reason})"
            for row in resolution.capabilities
            if row.capability
            in {
                Capability.NVME_SANITIZE,
                Capability.ATA_SANITIZE,
                Capability.CRYPTO_ERASE,
                Capability.NVME_FORMAT,
                Capability.ATA_SECURITY_ERASE,
            }
        )
        raise UnsupportedCapability(
            f"No device sanitize is available for {device.path}. It is never "
            f"replaced by an overwrite. {reasons}",
            remediation="Choose Clear, or attach the drive where its controller "
            "is reachable (a direct SATA or NVMe connection).",
        )

    def _block_engine_rows(
        self, privilege: PrivilegeState
    ) -> list[OperationCapability]:
        """Whole-drive rows for a platform whose engine is ``core.erase.blockclear``.

        The resolver decides the final state; these rows carry only what the
        adapter knows (privilege) and the verification wording.
        """
        privileged = self._privileged_enough(privilege)
        status = (
            CapabilityStatus.NOT_AUTHORIZED
            if privileged is False
            else CapabilityStatus.UNVERIFIED
        )
        src = "core.erase.blockclear; " + privilege.basis
        return [
            row(
                Operation.FREE_SPACE_WIPE,
                CapabilityStatus.UNSUPPORTED,
                "Free-space wipe is not implemented on this platform.",
                "core.erase.freespace.FREE_SPACE_PLATFORMS",
                verification="Nothing runs here, so there is nothing to verify.",
                state=CapabilityState.NOT_IMPLEMENTED,
            ),
            row(
                Operation.WHOLE_DRIVE_CLEAR,
                status,
                "Every addressable LBA is overwritten through a handle bound to "
                "the planned disk, then read back.",
                src,
                verification="Full read-back up to 64 GiB, seeded sampling "
                "above it with the detection probability stated.",
                limitations=[FLASH_LIMITATION],
                requires_privilege=True,
            ),
            row(
                Operation.WHOLE_DRIVE_PURGE,
                status,
                "Decided per device from the controller's own report.",
                "core.erase.devicesanitize; " + privilege.basis,
                verification="The device's or driver's completion status, then a "
                "sampled read-back of the medium.",
                requires_privilege=True,
            ),
            row(
                Operation.DRIVE_VERIFICATION,
                status,
                "Overwrites are read back; device sanitize is sampled after the "
                "command completes.",
                "core.erase.blockclear.verify_target",
                verification="A sampled verification states its seed and "
                "detection probability; uncertainty is never reported as a pass.",
                requires_privilege=True,
            ),
            row(
                Operation.RESUME,
                status,
                "An interrupted clear continues from its last ledgered "
                "checkpoint, through a handle bound to the same disk.",
                "core.erase.blockclear.clear(resume_from=...)",
                verification="The resumed run is verified over the whole "
                "device, exactly as an uninterrupted one.",
                requires_privilege=True,
            ),
        ]

    # -- restrictions -------------------------------------------------------

    def restrictions(self) -> list[str]:
        return []

    def protected_paths(self) -> list[str]:
        from core.platform.paths import protected_prefixes

        return protected_prefixes(self.family)

    # -- safety: identical on every platform --------------------------------

    def safety_checks(
        self, device: NormalizedDevice, privilege: PrivilegeState
    ) -> list[SafetyCheck]:
        """The pre-flight checks, in the order an operator reads them.

        One implementation for every OS. ``passed=None`` is used when a fact
        could not be established, and a check that could not be established
        is never rendered as a pass.
        """
        checks: list[SafetyCheck] = [
            SafetyCheck(
                key="detected",
                label="Device detected",
                passed=True,
                detail=f"{device.path} was read from the OS by {self.name} discovery.",
            ),
            SafetyCheck(
                key="identity",
                label="Identity readable",
                passed=True if (device.serial or device.stable_id) else None,
                detail=(
                    f"Serial {device.serial}."
                    if device.serial
                    else f"No serial reported; stable id {device.stable_id}."
                    if device.stable_id
                    else "Neither a serial nor a stable identifier was reported."
                ),
            ),
            SafetyCheck(
                key="capacity",
                label="Capacity known",
                passed=device.capacity_bytes > 0,
                detail=(
                    f"{device.capacity_bytes} bytes."
                    if device.capacity_bytes > 0
                    else "The OS reported no capacity for this device."
                ),
            ),
            SafetyCheck(
                key="not_system",
                label="Not the system or boot disk",
                passed=not device.system_device,
                detail=(
                    " ".join(device.system_reasons)
                    if device.system_device
                    else "Holds no running system, boot, swap or page file."
                ),
            ),
            SafetyCheck(
                key="not_mounted",
                label="No mounted filesystem",
                passed=not device.mounted,
                detail=(
                    "Mounted at " + ", ".join(device.mount_points) + "."
                    if device.mounted
                    else "Nothing on this device is mounted."
                ),
            ),
            SafetyCheck(
                key="media_type",
                label="Media type identified",
                passed=True if device.media_type != "unknown" else None,
                detail=device.media_basis or "The medium type was not determined.",
            ),
            SafetyCheck(
                key="privilege",
                label="Privilege available",
                passed=self._privileged_enough(privilege),
                detail=self._privilege_detail(privilege),
            ),
        ]
        return checks

    def _privileged_enough(self, privilege: PrivilegeState) -> bool | None:
        if privilege.helper == "socket":
            return True
        return privilege.elevated

    def _privilege_detail(self, privilege: PrivilegeState) -> str:
        if privilege.helper == "socket":
            return (
                "Privileged work runs in the separate helper process over its "
                "authenticated socket; this interface stays unprivileged."
            )
        if privilege.elevated:
            return f"This process is elevated ({privilege.basis})."
        if privilege.elevated is False:
            return (
                f"This process is not elevated ({privilege.basis}). Raw device "
                "access is refused by the OS."
            )
        return f"Elevation could not be determined ({privilege.basis})."

    # -- assessment ---------------------------------------------------------

    def drive_options(
        self, device: NormalizedDevice
    ) -> tuple[list[SanitizeOption], str]:
        """Every level for ``device`` and the verification sentence.

        The default is the honest one for a platform with no engine: both
        levels unavailable, with the platform's reason.
        """
        reason = self.whole_drive_unavailable_reason()
        options = [
            SanitizeOption(
                level=level,
                title=title,
                status=CapabilityStatus.UNSUPPORTED,
                why=reason,
                remediation=self.whole_drive_recommended_action(),
            )
            for level, title in (
                ("PURGE", "Hardware purge"),
                ("CLEAR", "Overwrite (Clear)"),
            )
        ]
        return options, "No verification: no whole-drive operation is offered here."

    def assess_device(self, device: NormalizedDevice) -> DeviceAssessment:
        """Recommended method, alternatives, and why anything is unavailable."""
        privilege = self.privilege_state()
        checks = self.safety_checks(device, privilege)
        options, verification = self.drive_options(device)
        resolution = self.device_resolution(
            device, privilege, planned=_planned_probes(options)
        )
        options = [self._annotate_option(item, resolution) for item in options]
        runnable = [item for item in options if _offerable(item)]
        unavailable = [item for item in options if not _offerable(item)]
        recommended = runnable[0] if runnable else None
        flash_note = FLASH_LIMITATION if device.media_type in {"ssd", "flash"} else ""

        base = {
            "device_id": device.id,
            "platform": self.family,
            "safety_checks": checks,
            "flash_limitation": flash_note,
            "verification": verification,
            "device_class": resolution.device_class,
            "capabilities": resolution.capabilities,
        }

        if device.system_device:
            return DeviceAssessment(
                **base,
                status=CapabilityStatus.UNSUPPORTED,
                headline="NOT AVAILABLE",
                reason=(
                    "This is the system or boot disk, or holds a protected "
                    "operating-system volume. " + " ".join(device.system_reasons)
                ).strip(),
                recommended_action=self._system_disk_advice(device),
                unavailable=options,
            )
        if device.mounted:
            return DeviceAssessment(
                **base,
                status=CapabilityStatus.UNSUPPORTED,
                headline="NOT AVAILABLE",
                reason=(
                    "A filesystem on this device is in use ("
                    + ", ".join(device.mount_points)
                    + "). Erasing a mounted device would corrupt it under a "
                    "running program and could not be verified."
                ),
                recommended_action=(
                    "Unmount or eject every volume on this device, then rescan."
                ),
                unavailable=options,
            )
        if recommended is None:
            # The Clear option's reason when there is one: it is the path every
            # device has, so why *it* is unavailable is the answer an operator
            # needs; why a firmware path is also absent is secondary.
            clears = [item for item in options if item.level == "CLEAR"]
            first = clears[0] if clears else options[0] if options else None
            return DeviceAssessment(
                **base,
                status=CapabilityStatus.UNSUPPORTED,
                headline="NOT AVAILABLE",
                reason=first.why if first else "No sanitization method is available.",
                recommended_action=(first.remediation if first else "")
                or self.whole_drive_recommended_action(),
                unavailable=unavailable,
            )
        privileged = self._privileged_enough(privilege)
        if privileged is False:
            return DeviceAssessment(
                **base,
                status=CapabilityStatus.NOT_AUTHORIZED,
                headline="NOT AUTHORIZED",
                reason=(
                    "The method is available but this process does not have the "
                    "privilege the OS requires for raw device access. The erase "
                    "is refused until the helper runs with that privilege."
                ),
                recommended_action=self._elevation_advice(),
                recommended=recommended,
                alternatives=runnable[1:],
                unavailable=unavailable,
            )
        return DeviceAssessment(
            **base,
            status=recommended.status,
            headline="READY",
            reason=recommended.why,
            recommended=recommended,
            alternatives=runnable[1:],
            unavailable=unavailable,
        )

    def _elevation_advice(self) -> str:
        return "Start the privileged helper, then rescan."

    def _system_disk_advice(self, device: NormalizedDevice) -> str:
        return (
            "Boot the machine from external media (for example the Sanctum "
            "Linux build on a USB stick) and sanitize the internal disk from "
            "there, or use the OS's own reset flow."
        )

    # -- file-side capability rows, shared -----------------------------------

    def _file_backend_rows(
        self, privilege: PrivilegeState
    ) -> list[OperationCapability]:
        """File, folder, batch, metadata and file-verification rows.

        Derived from the file backend this host actually selected
        (:func:`core.erase._platform.backend`), by checking which capability
        methods it implements rather than inheriting the honest unknown.
        """
        from core.erase._platform import backend
        from core.erase._platform.base import PortableBackend

        chosen = backend()
        cls = type(chosen)
        implemented = {
            name
            for name in (
                "extents",
                "fs_type",
                "alt_data_streams",
                "vss_shadows",
                "cow_snapshots",
            )
            if getattr(cls, name) is not getattr(PortableBackend, name)
        }
        source = (
            f"core.erase.files with the '{chosen.name}' file backend "
            f"({cls.__module__}.{cls.__name__}); implements "
            + (", ".join(sorted(implemented)) or "no platform-specific probes")
        )
        from core.platform.validation import describe, suite_passed

        limits = self._file_limitations()
        validated = suite_passed(self.family, "file_erase")
        source += "; " + describe(self.family, "file_erase")
        file_status = (
            CapabilityStatus.SUPPORTED_WITH_LIMITATIONS
            if chosen.name != "portable" and validated
            else CapabilityStatus.UNVERIFIED
        )
        erase_reason = (
            "Overwrites the file's data in place, renames it to random names of "
            "the same length, truncates and deletes it, then lists every copy "
            "it could not reach (journal, snapshots, SSD remapping)."
        )
        if not validated:
            erase_reason += (
                " The file-erase test suite has not been recorded as passing on "
                "this platform for this build, so this is UNVERIFIED rather "
                "than supported."
            )
        rows = [
            row(
                Operation.FILE_ERASE,
                file_status,
                erase_reason,
                source,
                verification="Physical read-back of the original extents when "
                "they could be mapped and the volume can be read raw.",
                limitations=limits,
            ),
            row(
                Operation.FOLDER_ERASE,
                file_status,
                "Every file in the folder, deepest first, then the folders "
                "themselves, each with the same file erase.",
                source + "; core.erase.files.expand_targets walks depth-first "
                "and never follows symlinks or junctions",
                verification=(
                    "Per file, as above; a link or reparse point is reported "
                    "refused rather than erased."
                ),
                limitations=limits,
            ),
            row(
                Operation.BATCH_ERASE,
                file_status,
                "Many files and folders in one job, one ledger entry per file "
                "per phase, cancellable between files.",
                source,
                verification=(
                    "Per file, as above; a cancelled batch records which files "
                    "it had reached."
                ),
                limitations=limits,
            ),
        ]
        from core.erase import metadata as metadata_mod

        handlers = sorted(
            name.removeprefix("cleanse_").upper()
            for name in dir(metadata_mod)
            if name.startswith("cleanse_") and name != "cleanse_only"
        )
        rows.append(
            row(
                Operation.METADATA_CLEANSE,
                CapabilityStatus.SUPPORTED_WITH_LIMITATIONS,
                "Removes embedded document metadata (EXIF, author fields, "
                "document properties) before the file is erased. Formats not "
                "listed are reported as not cleansed, never as clean.",
                "core.erase.metadata handlers: " + ", ".join(handlers),
                verification="The cleansed file is re-parsed and every field "
                "that survived is named in the record.",
                limitations=[
                    "Filesystem metadata (directory entries, MFT records, "
                    "journal) is renamed and truncated, not cleansed in place."
                ],
            )
        )
        maps_extents = "extents" in implemented
        if not maps_extents:
            verify_status = CapabilityStatus.NOT_VERIFIABLE
            verify_reason = (
                "This platform's file backend cannot map a file to physical "
                "blocks, so there is nothing to read back."
            )
        elif self._privileged_enough(privilege):
            verify_status = CapabilityStatus.SUPPORTED_WITH_LIMITATIONS
            verify_reason = (
                "The original physical blocks are mapped before the erase and "
                "read back from the raw volume afterwards."
            )
        else:
            verify_status = CapabilityStatus.NOT_AUTHORIZED
            verify_reason = (
                "The erase runs, but reading the raw volume back needs "
                "elevation this process does not have, so the result is "
                "reported as not verified rather than as passed."
            )
        rows.append(
            row(
                Operation.FILE_VERIFICATION,
                verify_status,
                verify_reason,
                source + "; core.erase.verify.verify_file_erase",
                verification=(
                    "This row *is* the verification path: a result is passed, "
                    "failed or not possible, and is never inferred from the "
                    "file having disappeared."
                ),
                limitations=[
                    "On copy-on-write filesystems (APFS, Btrfs, ReFS, ZFS) the "
                    "overwrite lands in new blocks, so a read-back of the old "
                    "ones is reported as not verifiable.",
                ],
                requires_privilege=True,
            )
        )
        return rows

    def _file_limitations(self) -> list[str]:
        return [FLASH_LIMITATION]

    # -- platform matrix ----------------------------------------------------

    def operation_capabilities(self) -> list[OperationCapability]:
        privilege = self.privilege_state()
        rows = [self._discovery_row()]
        rows += self._file_backend_rows(privilege)
        rows += self._platform_rows(privilege)
        resolved = {
            item.capability: item for item in self.platform_capabilities(privilege)
        }
        return [self._with_state(item, resolved) for item in rows]

    # -- resolver ----------------------------------------------------------

    def platform_capabilities(
        self, privilege: PrivilegeState | None = None
    ) -> list[ResolvedCapability]:
        """The resolver's platform matrix for this host, adapter facts applied."""
        from core.platform.capability import resolve_platform

        privilege = privilege or self.privilege_state()
        resolved = resolve_platform(
            self.family,
            privileged=self._privileged_enough(privilege),
            privilege_basis=privilege.basis,
        )
        return [self._adjust_capability(item) for item in resolved]

    def _adjust_capability(self, item: ResolvedCapability) -> ResolvedCapability:
        """Restrict one resolved capability with a fact only the adapter knows.

        The default is no adjustment. Linux uses it for a container (the host's
        system disk is invisible) and for a missing firmware tool.
        """
        return item

    def _with_state(
        self,
        item: OperationCapability,
        resolved: dict[Capability, ResolvedCapability],
    ) -> OperationCapability:
        """One matrix row with the resolver's state merged in.

        The more restrictive of the resolver's answer and the adapter's own
        wins, and its reason travels with it. ``status`` is re-derived from the
        merged state, except NOT_VERIFIABLE, which says something no state does.
        """
        from core.platform.capability import legacy_status

        if item.operation is Operation.WHOLE_DRIVE_PURGE:
            answer = purge_summary(resolved)
        else:
            capability = _OPERATION_CAPABILITY.get(item.operation)
            answer = resolved.get(capability) if capability else None
        if answer is None:
            return item
        own = item.state or implied_state(item.status)
        state = more_restrictive(answer.state, own)
        adapter_wins = state is not answer.state
        reason = item.reason if adapter_wins else answer.reason
        if not adapter_wins and item.reason and item.reason not in reason:
            reason = reason + " " + item.reason
        limits = list(item.limitations)
        limits += [text for text in answer.limitations if text not in limits]
        status = (
            item.status
            if item.status is CapabilityStatus.NOT_VERIFIABLE
            else legacy_status(state, has_limits=bool(limits))
        )
        return item.model_copy(
            update={
                "state": state,
                "state_label": STATE_LABELS[state],
                "status": status,
                "reason": reason,
                "mechanism": answer.mechanism,
                "assurance": answer.assurance,
                "limitations": limits,
                "validated_classes": list(answer.validated_classes),
                "evidence": list(answer.evidence),
                "source": item.source
                + ("" if answer.source in item.source else "; " + answer.source),
            }
        )

    def device_probes(self, device: NormalizedDevice) -> dict[str, MechanismProbe]:
        """What the device reported about each firmware mechanism.

        The default knows nothing, so every device mechanism resolves to
        DEVICE-DEPENDENT with "not probed". Adapters with a probe override it.
        """
        return {}

    def device_resolution(
        self,
        device: NormalizedDevice,
        privilege: PrivilegeState | None = None,
        *,
        planned: dict[str, MechanismProbe] | None = None,
    ) -> StrategyResolution:
        """The resolver's answer for one device on this host.

        ``planned`` carries mechanisms an engine already planned for this
        device from its own probe; an explicit probe from
        :meth:`device_probes` overrides them.
        """
        from core.platform.capability import (
            profile_from_device,
            resolve_device,
        )

        privilege = privilege or self.privilege_state()
        probes = dict(planned or {})
        probes.update(self.device_probes(device))
        profile = profile_from_device(
            device,
            privileged=self._privileged_enough(privilege),
            privilege_basis=privilege.basis,
            probes=probes,
            apple_managed=self.apple_managed(device),
        )
        resolution = resolve_device(profile)
        adjusted = [self._adjust_capability(item) for item in resolution.capabilities]
        return resolution.model_copy(update={"capabilities": adjusted})

    def apple_managed(self, device: NormalizedDevice) -> bool:
        """Whether ``device`` is internal storage Apple manages. macOS only."""
        return False

    def _annotate_option(
        self, option: SanitizeOption, resolution: StrategyResolution
    ) -> SanitizeOption:
        """An option with the resolver's state for the capability it would run."""
        from core.platform.capability import legacy_status

        if option.method and option.method in METHOD_CAPABILITY:
            capability = METHOD_CAPABILITY[option.method]
        elif option.level == "CLEAR":
            capability = Capability.WHOLE_DRIVE_CLEAR
        else:
            by_cap = {item.capability: item for item in resolution.capabilities}
            summary = purge_summary(by_cap)
            capability = summary.capability if summary else Capability.NVME_SANITIZE
        try:
            answer = resolution.get(capability)
        except KeyError:
            return option
        own = option.state or implied_state(option.status)
        state = more_restrictive(answer.state, own)
        adapter_wins = state is not answer.state
        why = option.why if adapter_wins or not answer.reason else option.why
        if not adapter_wins and answer.reason and answer.reason not in why:
            why = (why + " " + answer.reason).strip()
        limits = list(option.limitations)
        limits += [text for text in answer.limitations if text not in limits]
        return option.model_copy(
            update={
                "state": state,
                "state_label": STATE_LABELS[state],
                "status": legacy_status(state, has_limits=bool(limits)),
                "capability": capability,
                "why": why,
                "mechanism": answer.mechanism,
                "protocol": answer.protocol,
                "assurance": answer.assurance,
                "limitations": limits,
                "verification": option.verification or answer.verification,
            }
        )

    def _discovery_row(self) -> OperationCapability:
        if not self.discovery.ran:
            try:
                self.enumerate_devices()
            except Exception as exc:  # noqa: BLE001 - reported, not raised
                self.discovery.record(
                    ok=False, tool=self.name, detail=str(exc), devices=[]
                )
        outcome = self.discovery
        if outcome.ok:
            return row(
                Operation.DEVICE_DISCOVERY,
                CapabilityStatus.SUPPORTED,
                f"{len(outcome.devices)} storage device(s) found.",
                f"{outcome.tool}: {outcome.detail}".strip(": "),
                verification=(
                    "Every list is read from the OS, never cached; the "
                    "privileged layer re-reads the device again immediately "
                    "before any destructive operation."
                ),
            )
        return row(
            Operation.DEVICE_DISCOVERY,
            CapabilityStatus.INCONCLUSIVE,
            "Device discovery did not complete: " + (outcome.detail or "unknown"),
            outcome.tool or self.name,
        )

    def _platform_rows(self, privilege: PrivilegeState) -> list[OperationCapability]:
        """Free space, whole-drive and resume. Default: none on this platform."""
        reason = self.whole_drive_unavailable_reason()
        src = f"{type(self).__module__}.{type(self).__name__}"
        return [
            row(
                Operation.FREE_SPACE_WIPE,
                CapabilityStatus.UNSUPPORTED,
                "Free-space wipe is implemented for Linux only; its fill "
                "behaviour has not been measured on this platform's filesystems.",
                "core.erase.freespace.FREE_SPACE_PLATFORMS",
                verification="Nothing runs here, so there is nothing to verify.",
            ),
            row(
                Operation.WHOLE_DRIVE_CLEAR,
                CapabilityStatus.UNSUPPORTED,
                reason,
                src,
                verification="Nothing runs here, so there is nothing to verify.",
            ),
            row(
                Operation.WHOLE_DRIVE_PURGE,
                CapabilityStatus.UNSUPPORTED,
                reason,
                src,
                verification="Nothing runs here, so there is nothing to verify.",
            ),
            row(
                Operation.DRIVE_VERIFICATION,
                CapabilityStatus.UNSUPPORTED,
                "No whole-drive operation runs here, so there is none to verify.",
                src,
                verification="Nothing runs here, so there is nothing to verify.",
            ),
            row(
                Operation.RESUME,
                CapabilityStatus.UNSUPPORTED,
                "Only a whole-drive overwrite can resume, and none runs here. A "
                "cancelled file batch records which files it reached.",
                src,
                verification="Nothing runs here, so there is nothing to verify.",
            ),
        ]

    # -- media classes ------------------------------------------------------

    def media_classes(self) -> list[MediaClassSupport]:
        """Storage-class rows, counted from the devices discovery found."""
        caps = {item.operation: item for item in self.operation_capabilities()}
        devices = self.discovery.devices
        file_status = caps[Operation.FILE_ERASE].status
        discovery_status = caps[Operation.DEVICE_DISCOVERY].status
        clear = caps[Operation.WHOLE_DRIVE_CLEAR]

        def count(predicate: Any) -> int:
            return sum(1 for item in devices if predicate(item))

        classes: list[tuple[str, Any, str]] = [
            (
                "Internal HDD",
                lambda d: d.media_type == "hdd" and d.removable is not True,
                "",
            ),
            (
                "Internal SSD",
                lambda d: (
                    d.media_type in {"ssd", "flash"}
                    and d.interface in {"sata", "nvme", "sas", "scsi"}
                    and d.removable is not True
                ),
                FLASH_LIMITATION,
            ),
            (
                "USB HDD",
                lambda d: d.interface == "usb" and d.media_type == "hdd",
                "USB bridges usually block the pass-through a firmware purge needs.",
            ),
            (
                "USB SSD / flash drive",
                lambda d: d.interface == "usb" and d.media_type != "hdd",
                FLASH_LIMITATION,
            ),
            (
                "SD / memory card",
                lambda d: d.interface == "mmc",
                FLASH_LIMITATION + " Card readers expose no sanitize command at all.",
            ),
        ]
        result: list[MediaClassSupport] = []
        for label, predicate, note in classes:
            whole = clear.status
            reason = clear.reason if whole not in _RUNNABLE else note or clear.reason
            if whole in _RUNNABLE and note:
                whole = CapabilityStatus.SUPPORTED_WITH_LIMITATIONS
            result.append(
                MediaClassSupport(
                    media_class=label,
                    discovery=discovery_status,
                    file_erase=file_status,
                    whole_drive=whole,
                    reason=reason,
                    detected_now=count(predicate),
                )
            )
        return result


def _planned_probes(options: list[SanitizeOption]) -> dict[str, MechanismProbe]:
    """Mechanisms an engine planned for a device, as probe results.

    An engine that planned a firmware method did so because the device's own
    capability probe reported the command. That is the probe result; it is
    recorded as such rather than probed a second time.
    """
    from core.platform.capability import MechanismProbe

    out: dict[str, MechanismProbe] = {}
    for option in options:
        if not option.method or option.method not in METHOD_CAPABILITY:
            continue
        capability = METHOD_CAPABILITY[option.method]
        if capability is Capability.WHOLE_DRIVE_CLEAR:
            continue
        planned = option.status in _RUNNABLE or option.status in {
            CapabilityStatus.UNVERIFIED
        }
        if planned:
            out[capability.value] = MechanismProbe(
                exposed=True,
                basis=f"The device's capability probe reported {option.method}.",
                command="engine capability probe",
            )
    return out


def json_records(
    generator: Generator[Any, None, Any],
) -> Generator[dict[str, Any], None, dict[str, Any]]:
    """Yield each engine record as JSON; return the result as JSON.

    Closing this generator closes the engine's at its next yield, which is how
    a cancel reaches a running wipe.
    """
    try:
        while True:
            try:
                record = next(generator)
            except StopIteration as stop:
                return {"result": stop.value.model_dump(mode="json")}
            yield record.model_dump(mode="json")
    finally:
        generator.close()


def ledger_sink(params: dict[str, Any]) -> Any:
    """The hash-chained ledger a helper request names, as an erase sink."""
    from pathlib import Path

    from core.erase.sink import ChainLedgerSink
    from core.ledger.chain import Ledger

    owner = params.get("owner_uid")
    return ChainLedgerSink(
        Ledger(
            Path(str(params["ledger_root"])),
            tool_version=str(params.get("tool_version", "sanctum-forensics/0.0.0")),
            pubkey_fingerprint=str(params.get("pubkey_fingerprint", "")),
            owner_uid=int(owner) if isinstance(owner, int) else None,
        )
    )


def core_device(device: NormalizedDevice) -> Any:
    """A normalized device as the erase engines' :class:`core.models.Device`."""
    from core.models import Device

    transport = (
        device.interface
        if device.interface in {"sata", "nvme", "usb", "mmc"}
        else "unknown"
    )
    return Device(
        path=device.path,
        model=device.model,
        serial=device.serial,
        size_bytes=device.capacity_bytes,
        rotational=device.media_type == "hdd",
        transport=transport,
        is_system_disk=device.system_device,
        mounted_at=list(device.mount_points),
        pt_type=None,
        by_id_path=device.stable_id or None,
    )


def normalized_serial(serial: str) -> str:
    return "".join(serial.split()).upper()


def running_on(family: PlatformFamily) -> bool:
    """True when this process runs on ``family``."""
    from core.platform.host import family as host_family

    return host_family(sys.platform) == family


def legacy_row(device: NormalizedDevice, reason: str) -> dict[str, Any]:
    """A normalized device in the helper's pre-adapter row shape.

    For platforms with no Linux capability probe: the legacy keys the device
    screens read are filled from the normalized device, and the probe fields
    are null with ``reason`` saying why.
    """
    transport = (
        device.interface
        if device.interface in {"sata", "nvme", "usb", "mmc"}
        else "unknown"
    )
    return {
        "device": {
            "path": device.path,
            "model": device.model,
            "serial": device.serial,
            "size_bytes": device.capacity_bytes,
            "rotational": device.media_type == "hdd",
            "transport": transport,
            "is_system_disk": device.system_device,
            "mounted_at": device.mount_points,
            "pt_type": None,
            "by_id_path": device.stable_id or None,
        },
        "media": {
            "flash": device.media_type in {"ssd", "flash"}
            if device.media_type != "unknown"
            else None,
            "reason": device.media_basis,
        },
        "capabilities": None,
        "erase_preview": None,
        "capability_error": reason,
        "hidden_areas": None,
        "hidden_area_error": (
            "Hidden-area (HPA/DCO) state is in the assessment's resolved "
            "capabilities for this platform."
        ),
        "normalized": device.model_dump(mode="json"),
    }
