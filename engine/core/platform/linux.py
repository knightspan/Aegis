"""Linux adapter: the existing, validated engine, behind the platform seam.

Nothing here reimplements the Linux path. Discovery is
:func:`core.device.enumerate.enumerate_devices` (``lsblk`` with a ``/sys/block``
fallback), capability is :func:`core.device.capabilities.probe`, the plan is
:func:`core.erase.drive.preview`, and execution is
:func:`core.erase.drive.execute` - the same calls the privileged helper made
before this module existed. The adapter's job is translation: a
:class:`~core.models.Device` becomes a :class:`NormalizedDevice`, and an
:class:`~core.models.ErasePreview` becomes the plain-language options the
Sanitize screen shows.

Every ``core.device`` and ``core.erase.drive`` import is inside a function.
``core.erase.drive`` refuses to import off Linux, and this module is imported
on every platform so the adapter table can be tested anywhere.
"""

from __future__ import annotations

import shutil
from collections.abc import Generator
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from core.errors import PlatformUnsupported, SanctumError
from core.platform.base import FLASH_LIMITATION, BaseAdapter, json_records, row
from core.platform.model import (
    CapabilityStatus,
    Interface,
    MediaType,
    NormalizedDevice,
    Operation,
    OperationCapability,
    PartitionInfo,
    PrivilegeState,
    SafetyCheck,
    SanitizeOption,
)
from core.platform.validation import hardware_passed

if TYPE_CHECKING:  # pragma: no cover
    from core.device._sysio import SystemProbe
    from core.models import Device, ErasePreview, PlannedErase

__all__ = ["LinuxAdapter", "normalize_device", "options_from_preview"]

logger = structlog.get_logger(__name__)

#: Files a container runtime creates. Inside a container the host's root
#: filesystem, mounts and swap are invisible, so the system disk cannot be
#: identified - while /sys still lists every host disk.
CONTAINER_MARKERS = (Path("/run/.containerenv"), Path("/.dockerenv"))

#: Set to 1 only when the container was given exactly the device to erase and
#: nothing else (``--device /dev/sdX``). It is read in the privileged process.
CONTAINER_OVERRIDE_ENV = "SANCTUM_ALLOW_CONTAINER_DEVICES"


def in_container(markers: tuple[Path, ...] | None = None) -> bool:
    """Whether this process runs inside a container runtime."""
    found = CONTAINER_MARKERS if markers is None else markers
    return any(marker.exists() for marker in found)


def _container_refusal() -> str:
    """Why whole-drive work is refused in a container, or ``""``."""
    import os

    if not in_container() or os.environ.get(CONTAINER_OVERRIDE_ENV) == "1":
        return ""
    return (
        "This process runs inside a container, where the host's root "
        "filesystem, mounts and swap are not visible, so the host's system "
        "disk cannot be identified - and /sys still lists every host disk. "
        "Whole-drive sanitization is refused rather than guessed."
    )


#: Pass-through tools a firmware purge is issued with. Whether any exists on
#: this host is the platform-level source for the Purge row; whether the
#: *device* accepts one is decided per device by the capability probe.
PURGE_TOOLS = ("hdparm", "nvme", "sedutil-cli")

_SOFTWARE_METHODS = frozenset({"SINGLE_PASS_OVERWRITE", "DOD_5220_22_M_3PASS"})
_CRYPTO_METHODS = frozenset({"ATA_SANITIZE_CRYPTO_SCRAMBLE", "SED_CRYPTO_ERASE"})


def _media_type(device: Device, flash: bool) -> MediaType:
    if not flash:
        return "hdd"
    if device.transport in {"sata", "nvme"}:
        return "ssd"
    return "flash"


def normalize_device(
    device: Device,
    *,
    flash: bool,
    flash_reason: str,
    removable: bool | None = None,
    partitions: list[PartitionInfo] | None = None,
) -> NormalizedDevice:
    """A Linux :class:`~core.models.Device` in the cross-platform shape."""
    reasons: list[str] = []
    if device.is_system_disk:
        reasons.append(
            "Holds the running root filesystem, /boot or an active swap area."
        )
    parts = partitions or []
    interface: Interface = device.transport
    return NormalizedDevice(
        id=device.path,
        platform="linux",
        path=device.path,
        model=device.model,
        serial=device.serial,
        capacity_bytes=device.size_bytes,
        interface=interface,
        media_type=_media_type(device, flash),
        media_basis=f"Decided because {flash_reason}.",
        removable=removable,
        mounted=bool(device.mounted_at),
        mount_points=list(device.mounted_at),
        system_device=device.is_system_disk,
        system_reasons=reasons,
        filesystems=sorted({item.filesystem for item in parts if item.filesystem}),
        partitions=parts,
        stable_id=device.by_id_path or "",
    )


def _option_title(level: str, method: str | None) -> str:
    if level == "CLEAR":
        return "Overwrite (Clear)"
    if method in _CRYPTO_METHODS:
        return "Cryptographic erase (Purge)"
    return "Hardware purge"


def _option_why(plan: PlannedErase, flash: bool) -> str:
    method = str(plan.method or "")
    if plan.level == "CLEAR":
        text = "Every addressable block is overwritten from this computer."
        if flash:
            text += (
                " On flash this cannot reach remapped or spare blocks, so the "
                "result is recorded as Clear."
            )
        return text
    if method in _CRYPTO_METHODS:
        return (
            "The drive destroys the key that encrypts everything on it, which "
            "makes every stored block unreadable at once."
        )
    return (
        "The drive's own firmware erases every block, including spare and "
        "remapped areas an overwrite from this computer cannot reach."
    )


def _verification_sentence(plan: PlannedErase, size_bytes: int) -> str:
    from core.erase.verify import choose_strategy
    from core.models import EraseMethod

    if not plan.method:
        return ""
    strategy = choose_strategy(size_bytes, EraseMethod(plan.method))
    if strategy == "hw_attested":
        return (
            "The drive reports its own completion status (hardware-attested). "
            "The host cannot read the spare areas firmware erased, and the "
            "report says so."
        )
    if strategy == "full_read":
        return "Every byte is read back after the overwrite and checked."
    return (
        "A seeded random sample is read back after the overwrite; the report "
        "states the probability that a residual region would have been found."
    )


def options_from_preview(
    preview: ErasePreview, size_bytes: int
) -> tuple[list[SanitizeOption], str]:
    """The engine's own plans, PURGE first, as plain-language options.

    The order is the recommendation: Purge is offered first when the drive can
    do it, and a Clear that follows it is an alternative, never a substitute.
    When Purge is not reachable its refusal travels verbatim, which is what
    stops the screen from quietly presenting a Clear as the best available.
    """
    by_level = {plan.level.value: plan for plan in preview.plans}
    options: list[SanitizeOption] = []
    verification = ""
    for level in ("PURGE", "CLEAR"):
        plan = by_level.get(level)
        if plan is None:
            continue
        method = plan.method.value if plan.method else None
        technical: list[str] = []
        if method:
            technical.append(f"Method: {method}")
        if plan.justification:
            technical.append(plan.justification)
        technical += [*plan.evidence, *plan.limitations]
        if not plan.reachable:
            options.append(
                SanitizeOption(
                    level=level,
                    title=_option_title(level, None),
                    status=CapabilityStatus.UNSUPPORTED,
                    why=plan.refusal or "Not reachable on this device.",
                    technical=technical,
                    remediation=plan.remediation or preview.purge_requires,
                )
            )
            continue
        if not plan.executable:
            options.append(
                SanitizeOption(
                    level=level,
                    title=_option_title(level, method),
                    status=CapabilityStatus.UNSUPPORTED,
                    method=method,
                    why=plan.not_executable_reason,
                    technical=technical,
                )
            )
            continue
        limited = bool(plan.limitations) or (level == "CLEAR" and preview.flash)
        sentence = _verification_sentence(plan, size_bytes)
        verification = verification or sentence
        why = _option_why(plan, preview.flash)
        status = (
            CapabilityStatus.SUPPORTED_WITH_LIMITATIONS
            if limited
            else CapabilityStatus.SUPPORTED
        )
        if level == "PURGE" and not hardware_passed("linux", "whole_drive_purge"):
            # The drive reported the command and the engine can issue it, but
            # no firmware sanitize has been recorded on a physical drive. The
            # option stays offered, and says it is unverified rather than
            # supported: the status is a claim about evidence.
            status = CapabilityStatus.UNVERIFIED
            why += (
                " UNVERIFIED: the drive reports this command, but no firmware "
                "sanitize has been run on a physical drive by this project; "
                "the path is fixture-tested only."
            )
        options.append(
            SanitizeOption(
                level=level,
                title=_option_title(level, method),
                status=status,
                method=method,
                why=why,
                technical=technical,
                verification=sentence,
            )
        )
    return options, verification


def _inconclusive_options(exc: SanctumError) -> tuple[list[SanitizeOption], str]:
    """What a device whose capability probe failed can be offered: nothing.

    A probe that did not complete establishes nothing, so no method is
    predicted and the failure travels as the reason. This is what an
    unprivileged process sees for every device, because ATA and NVMe
    pass-through need the privileged helper.
    """
    return (
        [
            SanitizeOption(
                level=level,
                title=_option_title(level, None),
                status=CapabilityStatus.INCONCLUSIVE,
                why=(
                    "The capability probe did not complete, so no method is "
                    f"predicted: {exc.message}"
                ),
                remediation=exc.remediation,
            )
            for level in ("PURGE", "CLEAR")
        ],
        "",
    )


class LinuxAdapter(BaseAdapter):
    """Linux: lsblk/sysfs discovery, the validated whole-drive engine."""

    name = "linux"
    family = "linux"

    def __init__(
        self,
        *,
        helper: str = "in-process",
        helper_basis: str = "",
        probe: SystemProbe | None = None,
    ) -> None:
        super().__init__(helper=helper, helper_basis=helper_basis)
        self._probe = probe
        self._core: dict[str, Device] = {}

    # -- discovery ----------------------------------------------------------

    def _system_probe(self) -> SystemProbe:
        from core.device._sysio import SystemProbe

        return self._probe or SystemProbe()

    def core_devices(self, *, include_virtual: bool = False) -> list[Device]:
        """The engine's own device records, exactly as the helper used them."""
        from core.device.enumerate import enumerate_devices

        if self._probe is None:
            # The exact call the helper made before the adapter existed.
            return enumerate_devices(include_virtual=include_virtual)
        return enumerate_devices(self._probe, include_virtual=include_virtual)

    def _partitions(self, probe: SystemProbe) -> dict[str, list[PartitionInfo]]:
        """Partitions per top-level kernel name, from the same lsblk payload."""
        from core.device.enumerate import _lsblk_payload, _mountpoints_of, _walk

        payload = _lsblk_payload(probe)
        if payload is None:
            return {}
        found: dict[str, list[PartitionInfo]] = {}
        for top in payload.get("blockdevices") or []:
            name = str(top.get("name") or "")
            items: list[PartitionInfo] = []
            for node in _walk(top)[1:]:
                items.append(
                    PartitionInfo(
                        id=str(node.get("path") or node.get("name") or ""),
                        size_bytes=int(node.get("size") or 0),
                        filesystem=str(node.get("fstype") or ""),
                        label=str(node.get("label") or ""),
                        mount_points=_mountpoints_of(node),
                    )
                )
            found[name] = items
        return found

    def _removable(self, probe: SystemProbe, device: Device) -> bool | None:
        text = probe.read_text(
            probe.sysfs_root / "block" / Path(device.path).name / "removable"
        )
        if text is None:
            return None
        return text.strip() == "1"

    def normalize(
        self,
        device: Device,
        probe: SystemProbe | None = None,
        partitions: dict[str, list[PartitionInfo]] | None = None,
    ) -> NormalizedDevice:
        from core.device import media

        source = probe or self._system_probe()
        flash, reason = media.is_flash(device)
        return normalize_device(
            device,
            flash=flash,
            flash_reason=reason,
            removable=self._removable(source, device),
            partitions=(partitions or {}).get(Path(device.path).name, []),
        )

    def enumerate_devices(
        self, *, include_virtual: bool = False
    ) -> list[NormalizedDevice]:
        probe = self._system_probe()
        try:
            devices = self.core_devices(include_virtual=include_virtual)
        except (OSError, SanctumError) as exc:
            self.discovery.record(ok=False, tool="lsblk", detail=str(exc), devices=[])
            raise
        partitions = self._partitions(probe)
        normalized = [self.normalize(item, probe, partitions) for item in devices]
        self._core = {item.path: item for item in devices}
        self.discovery.record(
            ok=True,
            tool="lsblk -J -O -b (sysfs fallback)",
            detail="block devices read from the kernel",
            devices=normalized,
        )
        return normalized

    # -- rows the helper serves ----------------------------------------------

    def device_rows(self, *, include_virtual: bool = False) -> list[dict[str, Any]]:
        """The ``enumerate_devices`` helper answer: legacy fields plus the new.

        The legacy keys (``device``, ``media``, ``capabilities``,
        ``erase_preview``, ``hidden_areas`` and their ``*_error`` siblings) are
        produced exactly as the helper produced them before the adapter
        existed, so nothing that reads them changes. ``normalized`` and
        ``assessment`` are added beside them.
        """
        from core.device import capabilities, hidden_areas, media
        from core.erase import drive

        probe = self._system_probe()
        devices = self.core_devices(include_virtual=include_virtual)
        partitions = self._partitions(probe)
        rows: list[dict[str, Any]] = []
        normalized_all: list[NormalizedDevice] = []
        for device in devices:
            entry: dict[str, Any] = {"device": device.model_dump(mode="json")}
            flash, flash_reason = media.is_flash(device)
            entry["media"] = {"flash": flash, "reason": flash_reason}
            normalized = self.normalize(device, probe, partitions)
            normalized_all.append(normalized)
            options: tuple[list[SanitizeOption], str] | None = None
            try:
                probed = capabilities.probe(device)
                entry["capabilities"] = probed.model_dump(mode="json")
                preview = drive.preview(device, probed)
                entry["erase_preview"] = preview.model_dump(mode="json")
                options = options_from_preview(preview, device.size_bytes)
            except SanctumError as exc:
                entry["capabilities"] = None
                entry["erase_preview"] = None
                entry["capability_error"] = exc.message
                options = (
                    [
                        SanitizeOption(
                            level=level,
                            title=_option_title(level, None),
                            status=CapabilityStatus.INCONCLUSIVE,
                            why=(
                                "The capability probe did not complete, so no "
                                f"method is predicted: {exc.message}"
                            ),
                            remediation=exc.remediation,
                        )
                        for level in ("PURGE", "CLEAR")
                    ],
                    "",
                )
            try:
                hidden = hidden_areas.detect_hidden_areas(device)
                entry["hidden_areas"] = hidden.model_dump(mode="json")
            except SanctumError as exc:
                entry["hidden_areas"] = None
                entry["hidden_area_error"] = exc.message
            entry["normalized"] = normalized.model_dump(mode="json")
            entry["assessment"] = self.assess_with(normalized, options).model_dump(
                mode="json"
            )
            rows.append(entry)
        self._core = {item.path: item for item in devices}
        self.discovery.record(
            ok=True,
            tool="lsblk -J -O -b (sysfs fallback)",
            detail="block devices read from the kernel",
            devices=normalized_all,
        )
        return rows

    def assess_with(
        self,
        device: NormalizedDevice,
        options: tuple[list[SanitizeOption], str] | None,
    ) -> Any:
        self._pending_options = options
        try:
            return self.assess_device(device)
        finally:
            self._pending_options = None

    def _engine_options(
        self, device: NormalizedDevice
    ) -> tuple[list[SanitizeOption], str]:
        pending: tuple[list[SanitizeOption], str] | None = getattr(
            self, "_pending_options", None
        )
        if pending is not None:
            return pending
        from core.device import capabilities
        from core.erase import drive

        core_device = self._core.get(device.id)
        if core_device is None:
            from core.device.enumerate import get_device

            core_device = get_device(device.id, self._system_probe())
        try:
            probed = capabilities.probe(core_device)
        except SanctumError as exc:
            # Routine, not exceptional: an unprivileged process cannot issue
            # ATA or NVMe pass-through, so every device probes this way until
            # the helper is running. The assessment says INCONCLUSIVE rather
            # than failing the request that asked for it.
            return _inconclusive_options(exc)
        return options_from_preview(
            drive.preview(core_device, probed), core_device.size_bytes
        )

    def authorization_probe(self, path: str) -> dict[str, Any]:
        """``lsblk``/sysfs identity and the hdparm/nvme capability probe, now."""
        from core.device import capabilities
        from core.device.enumerate import get_device

        device = get_device(path)
        return {
            "device": device.model_dump(mode="json"),
            "capabilities": capabilities.probe(device).model_dump(mode="json"),
        }

    def whole_drive_unavailable_reason(self) -> str:
        try:
            import core.erase.drive  # noqa: F401
        except PlatformUnsupported as exc:
            return exc.message
        return _container_refusal()

    def whole_drive_recommended_action(self) -> str:
        if _container_refusal():
            return (
                "Run Sanctum on the host, or pass exactly the target device "
                f"into the container (--device /dev/sdX) and set "
                f"{CONTAINER_OVERRIDE_ENV}=1 for the helper."
            )
        return super().whole_drive_recommended_action()

    def safety_checks(
        self, device: NormalizedDevice, privilege: PrivilegeState
    ) -> list[SafetyCheck]:
        checks = super().safety_checks(device, privilege)
        if in_container():
            checks.append(
                SafetyCheck(
                    key="host_view",
                    label="Host system disk identifiable",
                    passed=None,
                    detail=(
                        "Running in a container: the host's root, mounts and "
                        "swap are not visible from here."
                    ),
                )
            )
        return checks

    def drive_options(
        self, device: NormalizedDevice
    ) -> tuple[list[SanitizeOption], str]:
        refusal = _container_refusal()
        if refusal:
            return BaseAdapter.drive_options(self, device)
        return self._engine_options(device)

    def _elevation_advice(self) -> str:
        return (
            "Start the privileged helper (sudo python -m helper --operator-uid "
            "<your uid> --state-dir <state dir>) and set SANCTUM_HELPER_SOCKET, "
            "then rescan. The interface itself never runs as root."
        )

    # -- platform rows ------------------------------------------------------

    def _platform_rows(self, privilege: PrivilegeState) -> list[OperationCapability]:
        from core.erase.freespace import FREE_SPACE_PLATFORMS, SUPPORTED

        rows: list[OperationCapability] = []
        if "linux" in FREE_SPACE_PLATFORMS:
            rows.append(
                row(
                    Operation.FREE_SPACE_WIPE,
                    CapabilityStatus.SUPPORTED_WITH_LIMITATIONS,
                    "Fills a data volume's free space and checks the fill, on "
                    + ", ".join(SUPPORTED.values())
                    + " only. Slack space and deleted directory entries are "
                    "not reached, and the report says so.",
                    "core.erase.freespace.SUPPORTED, FREE_SPACE_PLATFORMS",
                    verification="The fill is read back before release.",
                )
            )
        engine_reason = self.whole_drive_unavailable_reason()
        privileged = self._privileged_enough(privilege)
        source = "core.erase.drive imports on this host (Linux block-device semantics)"
        if engine_reason:
            clear = row(
                Operation.WHOLE_DRIVE_CLEAR,
                CapabilityStatus.UNSUPPORTED,
                engine_reason,
                "core.erase.drive import guard",
                verification=(
                    "Nothing runs here: the engine does not load on this "
                    "host, so there is nothing to verify."
                ),
            )
        elif privileged is False:
            clear = row(
                Operation.WHOLE_DRIVE_CLEAR,
                CapabilityStatus.NOT_AUTHORIZED,
                "The overwrite engine is available, but raw device writes need "
                "the privileged helper, which is not running.",
                source + "; " + privilege.basis,
                verification=(
                    "Would be a full read-back up to 64 GiB, and seeded "
                    "sampling above it, once the helper is running."
                ),
                requires_privilege=True,
            )
        else:
            clear_limits = [FLASH_LIMITATION]
            if not hardware_passed("linux", "hidden_area_unlock"):
                clear_limits.append(
                    "HPA/DCO unlock has not been run on a physical drive: no "
                    "hardware result is recorded for the HPA/DCO workflow, and "
                    "the case where sectors really are hidden is tested against "
                    "a faked probe and a fake hdparm."
                )
            clear = row(
                Operation.WHOLE_DRIVE_CLEAR,
                CapabilityStatus.SUPPORTED_WITH_LIMITATIONS,
                "Every addressable block is overwritten with O_DIRECT writes. "
                "An HPA/DCO hidden area is reported as not covered and never "
                "unlocked by the erase; exposing it is the separate, approved "
                "HPA/DCO workflow.",
                source,
                verification="Full read-back up to 64 GiB, seeded "
                "sampling above it with a stated detection probability.",
                limitations=clear_limits,
                requires_privilege=True,
            )
        rows.append(clear)

        tools = [name for name in PURGE_TOOLS if shutil.which(name)]
        if engine_reason:
            purge = row(
                Operation.WHOLE_DRIVE_PURGE,
                CapabilityStatus.UNSUPPORTED,
                engine_reason,
                "core.erase.drive import guard",
                verification=(
                    "Nothing runs here: the engine does not load on this "
                    "host, so there is nothing to verify."
                ),
            )
        elif not tools:
            purge = row(
                Operation.WHOLE_DRIVE_PURGE,
                CapabilityStatus.UNSUPPORTED,
                "None of " + ", ".join(PURGE_TOOLS) + " is installed, so no "
                "firmware sanitize command can be issued. Overwrite (Clear) "
                "remains available; it is never presented as a Purge.",
                "shutil.which over " + ", ".join(PURGE_TOOLS),
                verification=(
                    "No firmware command is issued here, so there is no "
                    "drive attestation to read."
                ),
            )
        elif privileged is False:
            purge = row(
                Operation.WHOLE_DRIVE_PURGE,
                CapabilityStatus.NOT_AUTHORIZED,
                "Firmware sanitize tools are installed but need the privileged "
                "helper, which is not running.",
                "found " + ", ".join(tools) + "; " + privilege.basis,
                verification=(
                    "Would be the drive's own completion status "
                    "(hardware-attested), once the helper is running."
                ),
                requires_privilege=True,
            )
        else:
            # The tools and the dispatch exist, but a status is a claim about
            # evidence: until a firmware sanitize has been recorded on real
            # media, this row is UNVERIFIED rather than supported.
            exercised = hardware_passed("linux", "whole_drive_purge")
            purge = row(
                Operation.WHOLE_DRIVE_PURGE,
                CapabilityStatus.SUPPORTED_WITH_LIMITATIONS
                if exercised
                else CapabilityStatus.UNVERIFIED,
                "Decided per device: the drive must report ATA SANITIZE, "
                "SECURITY ERASE, NVMe sanitize/format or Opal crypto erase. USB "
                "bridges usually block the pass-through, and the device screen "
                "says so for each device."
                + (
                    ""
                    if exercised
                    else " No firmware sanitize has been recorded on a physical "
                    "drive, so the path is UNVERIFIED: the commands are "
                    "fixture-tested, never run on hardware."
                ),
                "found "
                + ", ".join(tools)
                + "; per-device capability probe; validation record: "
                + ("hardware PASS" if exercised else "hardware NOT RUN"),
                verification="Drive-reported completion (hardware-attested).",
                requires_privilege=True,
            )
        rows.append(purge)
        rows.append(
            row(
                Operation.DRIVE_VERIFICATION,
                clear.status,
                "Overwrites are read back (full up to 64 GiB, sampled above); "
                "firmware methods are attested by the drive."
                if clear.status is not CapabilityStatus.UNSUPPORTED
                else clear.reason,
                "core.erase.verify.choose_strategy",
                verification="A sampled verification reports its seed and the "
                "probability that a residual region would have been found; "
                "uncertainty is never reported as a pass.",
                requires_privilege=True,
            )
        )
        rows.append(
            row(
                Operation.RESUME,
                clear.status,
                "An interrupted overwrite continues from its last ledgered "
                "checkpoint. A firmware sanitize cannot be resumed; it is "
                "issued again from the start.",
                "core.erase.drive.resume, CHECKPOINT_INTERVAL_BYTES",
                verification="The resumed run is verified exactly as an "
                "uninterrupted one, over the whole device.",
                requires_privilege=True,
            )
        )
        return rows

    def restrictions(self) -> list[str]:
        return [
            "Whole-drive sanitization, hidden-area (HPA/DCO) handling, "
            "checkpoint resume and free-space wipe are Linux-only in this "
            "release.",
            "Firmware purge needs ATA or NVMe pass-through; most USB bridges "
            "and card readers block it, and such devices are offered Clear "
            "only.",
            "The UI and API never run as root. Raw device work happens in the "
            "separate helper, authenticated by SO_PEERCRED.",
        ]

    # -- execution ----------------------------------------------------------

    def _job_and_ledger(self, params: dict[str, Any]) -> tuple[Any, Any, Any]:
        """Re-read the device, re-check the confirmation, build the job.

        The device is read from the host here, in the privileged process, and
        never taken from the request: a stale UI cannot authorise a wipe of a
        device swapped since the page loaded. The confirmation rule is
        :func:`core.device.guard.assert_serial_confirmed` - one
        implementation, called from both sides of the boundary.
        """
        from core.device import capabilities, guard
        from core.device.enumerate import get_device
        from core.ledger.chain import Ledger
        from core.models import EraseJob, SanitizationLevel

        guard.refuse_removed_mode_keys(params)
        refusal = _container_refusal()
        if refusal:
            raise PlatformUnsupported(
                refusal + " No operation was performed on the device.",
                remediation=self.whole_drive_recommended_action(),
            )
        device = get_device(str(params["path"]))
        typed_serial = str(params.get("typed_serial") or "")
        guard.assert_serial_confirmed(device, typed_serial)

        owner = params.get("owner_uid")
        ledger = Ledger(
            Path(str(params["ledger_root"])),
            tool_version=str(params.get("tool_version", "sanctum-forensics/0.0.0")),
            pubkey_fingerprint=str(params.get("pubkey_fingerprint", "")),
            owner_uid=int(owner) if isinstance(owner, int) else None,
        )
        job = EraseJob(
            job_id=str(params["job_id"]),
            device=device,
            level=SanitizationLevel(str(params.get("level", "CLEAR"))),
            confirmed_serial=typed_serial,
            method=None,
        )
        return job, capabilities.probe(device), ledger

    def execute_drive_sanitization(
        self, params: dict[str, Any]
    ) -> Generator[dict[str, Any], None, dict[str, Any]]:
        from core.erase.drive import ChainLedgerSink, execute

        job, probed, ledger = self._job_and_ledger(params)
        generator = execute(job, probed, ledger=ChainLedgerSink(ledger))
        return (yield from json_records(generator))

    def resume_drive_sanitization(
        self, params: dict[str, Any]
    ) -> Generator[dict[str, Any], None, dict[str, Any]]:
        from core.erase.drive import ChainLedgerSink, resume

        job, probed, ledger = self._job_and_ledger(params)
        generator = resume(job, probed, ledger=ChainLedgerSink(ledger))
        return (yield from json_records(generator))

