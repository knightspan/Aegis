"""The capability resolver: precise states, reasons, and class-scoped evidence.

Pure tests. Every device here is a :class:`DeviceProfile` built in the test;
nothing is discovered and nothing is opened.
"""

from __future__ import annotations

from typing import Any

import pytest
from core.platform.capability import (
    DESTRUCTIVE,
    DEVICE_MECHANISMS,
    IMPLEMENTATIONS,
    Capability,
    CapabilityState,
    DeviceProfile,
    MechanismProbe,
    device_class,
    legacy_status,
    resolve_device,
    resolve_platform,
)
from core.platform.model import STATE_LABELS, CapabilityStatus

S = CapabilityState
EMPTY: dict[str, Any] = {"physical_validations": []}


def _profile(**over: Any) -> DeviceProfile:
    base: dict[str, Any] = {
        "platform": "windows",
        "device_id": "PhysicalDrive2",
        "path": "\\\\.\\PhysicalDrive2",
        "model": "Test Disk",
        "serial": "SER123",
        "size_bytes": 8 << 30,
        "interface": "usb",
        "media_type": "flash",
        "removable": True,
        "privileged": True,
        "privilege_basis": "IsUserAnAdmin() returned 1",
    }
    base.update(over)
    return DeviceProfile.model_validate(base)


def _state(profile: DeviceProfile, capability: Capability, record: Any = None) -> Any:
    return resolve_device(profile, record=record or EMPTY).get(capability)


# -- the table ---------------------------------------------------------------


@pytest.mark.parametrize("platform", ["linux", "windows", "macos"])
def test_every_capability_has_an_entry_on_every_platform(platform: str) -> None:
    for capability in Capability:
        entry = IMPLEMENTATIONS.get((platform, capability))  # type: ignore[arg-type]
        assert entry is not None, (platform, capability)
        if entry.state is None:
            assert entry.module and entry.mechanism and entry.assurance
            assert entry.verification
        else:
            assert entry.state in {S.NOT_IMPLEMENTED, S.UNSUPPORTED_BY_PLATFORM}
            assert len(entry.reason) > 40


def _implemented_modules() -> list[str]:
    return sorted({entry.module for entry in IMPLEMENTATIONS.values() if entry.module})


@pytest.mark.parametrize("module", _implemented_modules())
def test_every_module_the_resolver_names_imports(module: str) -> None:
    """A table entry naming code that does not exist is a claim, not a capability.

    ``core.erase.drive`` refuses to import off Linux by design; that refusal is
    the platform saying so, not a missing module.
    """
    import importlib
    import sys

    from core.errors import PlatformUnsupported

    try:
        importlib.import_module(module)
    except PlatformUnsupported:
        if sys.platform.startswith("linux"):
            raise
        pytest.skip(f"{module} is Linux-only by design")


def test_the_hpa_modify_entries_name_the_guarded_workflow() -> None:
    for platform in ("linux", "windows"):
        entry = IMPLEMENTATIONS[(platform, Capability.HPA_DCO_MODIFY)]  # type: ignore[index]
        assert entry.module == "core.device.hidden_area_workflow"
        assert "volatile" in entry.mechanism
        assert "DCO RESTORE and DCO SET are never issued" in entry.mechanism
        assert "Never done implicitly by an erase" in entry.assurance
    linux = IMPLEMENTATIONS[("linux", Capability.HPA_DCO_MODIFY)]
    assert "hdparm -N <native>" in linux.mechanism
    assert "hdparm -N p<native>" in linux.mechanism
    windows = IMPLEMENTATIONS[("windows", Capability.HPA_DCO_MODIFY)]
    assert "VV=1" in windows.mechanism and "27h" in windows.mechanism
    macos = IMPLEMENTATIONS[("macos", Capability.HPA_DCO_MODIFY)]
    assert macos.state is S.UNSUPPORTED_BY_PLATFORM


def test_every_state_has_a_label_and_the_labels_are_the_interface_words() -> None:
    assert set(STATE_LABELS) == set(S)
    assert set(STATE_LABELS.values()) == {
        "SUPPORTED",
        "IMPLEMENTED / UNVALIDATED",
        "DEVICE-DEPENDENT",
        "PLATFORM-LIMITED",
        "REQUIRES PRIVILEGE",
        "BLOCKED FOR SAFETY",
        "NOT IMPLEMENTED",
    }


def test_overwrite_is_never_mapped_to_a_firmware_capability() -> None:
    for (platform, capability), entry in IMPLEMENTATIONS.items():
        if capability in DEVICE_MECHANISMS - {
            Capability.HPA_DCO_DISCOVERY,
            Capability.HPA_DCO_MODIFY,
        } and entry.state is None:
            assert entry.protocol in {"ATA", "NVMe", "TCG Opal"}, (platform, capability)
            assert "overwrite of every" not in entry.mechanism.lower()
            assert "Purge" in entry.assurance or "Cryptographic" in entry.assurance


def test_clear_never_claims_purge_or_nand_destruction() -> None:
    for platform in ("linux", "windows", "macos"):
        entry = IMPLEMENTATIONS[(platform, Capability.WHOLE_DRIVE_CLEAR)]  # type: ignore[index]
        assert "Not a Purge" in entry.assurance
        assert "not NAND-level destruction" in entry.assurance


# -- device classes ------------------------------------------------------------


@pytest.mark.parametrize(
    ("interface", "media", "apple", "expected"),
    [
        ("usb", "flash", False, "usb-flash"),
        ("usb", "unknown", False, "usb-flash"),
        ("usb", "hdd", False, "usb-hdd"),
        ("usb", "ssd", False, "usb-ssd"),
        ("sata", "hdd", False, "sata-hdd"),
        ("sata", "ssd", False, "sata-ssd"),
        ("nvme", "ssd", False, "nvme"),
        ("nvme", "ssd", True, "apple-internal"),
        ("mmc", "flash", False, "mmc"),
        ("virtual", "unknown", False, "virtual"),
        ("unknown", "unknown", False, "unknown"),
    ],
)
def test_device_class(interface: str, media: str, apple: bool, expected: str) -> None:
    assert device_class(interface, media, apple_managed=apple) == expected


# -- each state is reachable for the right reason -----------------------------


def test_runnable_clear_without_evidence_is_implemented_not_validated() -> None:
    row = _state(_profile(), Capability.WHOLE_DRIVE_CLEAR)
    assert row.state is S.IMPLEMENTED_NOT_PHYSICALLY_VALIDATED
    assert row.state_label == "IMPLEMENTED / UNVALIDATED"
    assert "PhysicalDrive" in row.mechanism
    assert row.reason.startswith("Available")


def test_evidence_is_matched_on_the_device_class_only() -> None:
    record = {
        "physical_validations": [
            {
                "platform": "windows",
                "capability": "whole_drive_clear",
                "device_class": "usb-flash",
                "model": "Stick",
                "date": "2026-09-28",
                "commit": "abc",
                "result": "PASS",
            }
        ]
    }
    stick = _state(_profile(), Capability.WHOLE_DRIVE_CLEAR, record)
    assert stick.state is S.VALIDATED_PHYSICAL
    assert stick.evidence
    internal = _state(
        _profile(interface="sata", media_type="ssd", removable=False),
        Capability.WHOLE_DRIVE_CLEAR,
        record,
    )
    assert internal.state is S.IMPLEMENTED_NOT_PHYSICALLY_VALIDATED
    linux = _state(_profile(platform="linux"), Capability.WHOLE_DRIVE_CLEAR, record)
    assert linux.state is S.IMPLEMENTED_NOT_PHYSICALLY_VALIDATED


def test_a_failed_physical_run_is_not_evidence_of_support() -> None:
    record = {
        "physical_validations": [
            {
                "platform": "windows",
                "capability": "whole_drive_clear",
                "device_class": "usb-flash",
                "result": "FAIL",
            }
        ]
    }
    row = _state(_profile(), Capability.WHOLE_DRIVE_CLEAR, record)
    assert row.state is S.IMPLEMENTED_NOT_PHYSICALLY_VALIDATED


def test_a_usb_bridge_hides_ata_sanitize() -> None:
    row = _state(_profile(), Capability.ATA_SANITIZE)
    assert row.state is S.UNSUPPORTED_BY_DEVICE
    assert "bridge" in row.reason


def test_an_unprobed_device_is_device_dependent() -> None:
    row = _state(_profile(interface="nvme", media_type="ssd"), Capability.NVME_SANITIZE)
    assert row.state is S.IMPLEMENTED_DEVICE_DEPENDENT
    assert row.state_label == "DEVICE-DEPENDENT"
    assert "not probed" in row.reason


def test_a_probe_that_found_no_support_is_unsupported_by_device() -> None:
    profile = _profile(
        interface="nvme",
        media_type="ssd",
        probes={
            "nvme_sanitize": MechanismProbe(
                exposed=False,
                basis="SANICAP reports no sanitize action.",
                command="IOCTL_STORAGE_QUERY_PROPERTY identify controller",
            )
        },
    )
    row = _state(profile, Capability.NVME_SANITIZE)
    assert row.state is S.UNSUPPORTED_BY_DEVICE
    assert "SANICAP" in row.reason
    assert "IOCTL_STORAGE_QUERY_PROPERTY" in row.source


def test_an_exposed_but_frozen_command_is_blocked_for_safety() -> None:
    profile = _profile(
        interface="sata",
        media_type="ssd",
        probes={
            "ata_sanitize": MechanismProbe(
                exposed=True, blocked=True, basis="The drive is security-frozen."
            )
        },
    )
    row = _state(profile, Capability.ATA_SANITIZE)
    assert row.state is S.BLOCKED_BY_SAFETY_POLICY
    assert "frozen" in row.reason


def test_an_exposed_command_resolves_to_implemented() -> None:
    profile = _profile(
        interface="nvme",
        media_type="ssd",
        probes={"nvme_sanitize": MechanismProbe(exposed=True, basis="SANICAP BES=1")},
    )
    row = _state(profile, Capability.NVME_SANITIZE)
    assert row.state is S.IMPLEMENTED_NOT_PHYSICALLY_VALIDATED
    assert "REINITIALIZE_MEDIA" in row.mechanism


@pytest.mark.parametrize(
    "over",
    [
        {"system_device": True, "system_reasons": ["IsBoot."]},
        {"mounted": True, "mount_points": ["E:\\"]},
    ],
)
def test_system_and_mounted_block_every_destructive_capability(
    over: dict[str, Any],
) -> None:
    profile = _profile(
        interface="nvme",
        media_type="ssd",
        probes={
            key: MechanismProbe(exposed=True, basis="reported")
            for key in (item.value for item in DEVICE_MECHANISMS)
        },
        **over,
    )
    resolution = resolve_device(profile, record=EMPTY)
    for row in resolution.capabilities:
        if row.capability in DESTRUCTIVE and row.state not in {
            S.NOT_IMPLEMENTED,
            S.UNSUPPORTED_BY_PLATFORM,
        }:
            assert row.state is S.BLOCKED_BY_SAFETY_POLICY, row.capability
            assert row.safety_restrictions


def test_acquisition_of_a_mounted_device_is_allowed_and_says_so() -> None:
    profile = _profile(mounted=True, mount_points=["E:\\"])
    row = _state(profile, Capability.RAW_ACQUISITION)
    assert row.state is S.IMPLEMENTED_NOT_PHYSICALLY_VALIDATED
    assert any("mounted" in text for text in row.limitations)


def test_an_unelevated_process_is_told_it_needs_privilege() -> None:
    row = _state(
        _profile(privileged=False, privilege_basis="IsUserAnAdmin() returned 0"),
        Capability.WHOLE_DRIVE_CLEAR,
    )
    assert row.state is S.AVAILABLE_BUT_REQUIRES_PRIVILEGE
    assert "administrator" in row.reason
    assert "IsUserAnAdmin" in row.reason


def test_windows_security_erase_is_not_implemented_and_says_why() -> None:
    row = _state(
        _profile(interface="sata", media_type="ssd"), Capability.ATA_SECURITY_ERASE
    )
    assert row.state is S.NOT_IMPLEMENTED
    assert "password" in row.reason


def test_windows_nvme_format_is_platform_limited() -> None:
    row = _state(_profile(interface="nvme", media_type="ssd"), Capability.NVME_FORMAT)
    assert row.state is S.UNSUPPORTED_BY_PLATFORM
    assert row.state_label == "PLATFORM-LIMITED"


def test_macos_internal_apple_storage_is_never_raw_written() -> None:
    profile = _profile(
        platform="macos",
        device_id="disk0",
        path="/dev/disk0",
        interface="nvme",
        media_type="ssd",
        removable=False,
        apple_managed=True,
        privileged=True,
    )
    resolution = resolve_device(profile, record=EMPTY)
    assert resolution.device_class == "apple-internal"
    clear = resolution.get(Capability.WHOLE_DRIVE_CLEAR)
    assert clear.state is S.BLOCKED_BY_SAFETY_POLICY
    assert "Erase All Content and Settings" in clear.reason
    assert resolution.get(Capability.CRYPTO_ERASE).state is S.UNSUPPORTED_BY_PLATFORM
    acquisition = resolution.get(Capability.RAW_ACQUISITION)
    assert acquisition.state is S.BLOCKED_BY_SAFETY_POLICY


def test_macos_external_usb_clear_is_available() -> None:
    profile = _profile(
        platform="macos",
        device_id="disk4",
        path="/dev/disk4",
        privileged=True,
        privilege_basis="geteuid() == 0",
    )
    row = _state(profile, Capability.WHOLE_DRIVE_CLEAR)
    assert row.state is S.IMPLEMENTED_NOT_PHYSICALLY_VALIDATED
    assert "/dev/rdisk" in row.mechanism
    firmware = _state(profile, Capability.ATA_SANITIZE)
    assert firmware.state is S.UNSUPPORTED_BY_PLATFORM


def test_sanitize_order_lists_only_runnable_mechanisms_strongest_first() -> None:
    profile = _profile(
        platform="linux",
        interface="nvme",
        media_type="ssd",
        probes={
            "nvme_sanitize": MechanismProbe(exposed=True, basis="SANICAP"),
            "nvme_format": MechanismProbe(exposed=True, basis="OACS"),
            "crypto_erase": MechanismProbe(exposed=False, basis="no crypto"),
        },
    )
    resolution = resolve_device(profile, record=EMPTY)
    assert resolution.sanitize_order == [
        Capability.NVME_SANITIZE,
        Capability.NVME_FORMAT,
    ]


def test_every_resolved_row_has_a_reason_a_source_and_a_label() -> None:
    for platform in ("linux", "windows", "macos"):
        for privileged in (True, False, None):
            rows = resolve_platform(
                platform,  # type: ignore[arg-type]
                privileged=privileged,
                record=EMPTY,
            )
            assert {row.capability for row in rows} == set(Capability)
            for row in rows:
                assert row.reason and row.source and row.state_label


def test_the_platform_matrix_scopes_evidence_and_never_generalises() -> None:
    record = {
        "physical_validations": [
            {
                "platform": "linux",
                "capability": "whole_drive_clear",
                "device_class": "usb-flash",
                "result": "PASS",
            }
        ]
    }
    rows = {
        row.capability: row
        for row in resolve_platform("linux", privileged=True, record=record)
    }
    clear = rows[Capability.WHOLE_DRIVE_CLEAR]
    assert clear.state is S.VALIDATED_PHYSICAL
    assert clear.validated_classes == ["usb-flash"]
    assert "usb-flash only" in clear.reason
    purge = rows[Capability.NVME_SANITIZE]
    assert purge.state is S.IMPLEMENTED_DEVICE_DEPENDENT


def test_legacy_status_never_upgrades_an_unvalidated_state() -> None:
    assert (
        legacy_status(S.IMPLEMENTED_NOT_PHYSICALLY_VALIDATED)
        is CapabilityStatus.UNVERIFIED
    )
    for state in (
        S.UNSUPPORTED_BY_DEVICE,
        S.UNSUPPORTED_BY_PLATFORM,
        S.NOT_IMPLEMENTED,
        S.BLOCKED_BY_SAFETY_POLICY,
    ):
        assert legacy_status(state) is CapabilityStatus.UNSUPPORTED
    assert (
        legacy_status(S.AVAILABLE_BUT_REQUIRES_PRIVILEGE)
        is CapabilityStatus.NOT_AUTHORIZED
    )


def test_the_committed_record_holds_only_complete_physical_entries() -> None:
    from core.platform.validation import load_record

    for entry in load_record().get("physical_validations", []):
        for key in (
            "platform",
            "capability",
            "device_class",
            "model",
            "serial",
            "date",
            "commit",
            "method",
            "verification",
            "artifacts",
            "result",
        ):
            assert entry.get(key), (entry.get("capability"), key)
