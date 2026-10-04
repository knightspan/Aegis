"""The Clear/Purge mapping, for every device class, stated as a table.

No SATA SSD has been available to this project, so these tests are the only
evidence for the flash half of the mapping. Each row names a device class, a
probed capability profile, and the mechanism the engine must choose for a
Purge - or ``None`` where Purge must not be reachable at all.

The authority for the flash rows is NIST SP 800-88r1 Table A-8 (ATA SSDs),
which lists SECURITY ERASE UNIT under Clear and says "Whereas ATA Secure Erase
was a Purge mechanism for magnetic media, it is only a Clear mechanism for
flash memory". Its Purge options for ATA SSDs are SANITIZE block erase, SANITIZE
crypto scramble, and TCG Opal/Enterprise cryptographic erase; SANITIZE
overwrite is not among them. The magnetic rows rest on r1 Table A-5 (ATA hard
disk drives). r1 is withdrawn, and SP 800-88r2 defers technique acceptability
to IEEE 2883, whose text has not been read; see docs/compliance.md.
"""

from __future__ import annotations

import json

import pytest
from core.device._sysio import SystemProbe
from core.device.capabilities import probe, purge_mechanisms, recommend_method
from core.errors import UnsupportedCapability
from core.models import Device, EraseMethod, SanitizationLevel

from .conftest import FakeRunner, ok

# --------------------------------------------------------------------------
# Device classes
# --------------------------------------------------------------------------

#: name -> (Device overrides, expected is-flash). The expected flag is asserted,
#: so a change to core.device.media.is_flash that moves a class shows up here
#: as a failure in this table and not as a silent change of certificate.
DEVICE_CLASSES: dict[str, tuple[dict[str, object], bool]] = {
    "ata_hdd": (
        {"transport": "sata", "rotational": True, "model": "ST2000DM008-2FR102"},
        False,
    ),
    "ata_ssd": (
        {"transport": "sata", "rotational": False, "model": "Samsung SSD 870 EVO"},
        True,
    ),
    "ata_ssd_rotational_flag_wrong": (
        {"transport": "sata", "rotational": True, "model": "Samsung SSD 870 EVO"},
        True,
    ),
    "ata_ssd_unnamed_nonrotational": (
        {"transport": "sata", "rotational": False, "model": "GENERIC-DISK"},
        True,
    ),
    "unknown_transport_rotational": (
        {"transport": "unknown", "rotational": True, "model": "GENERIC-DISK"},
        False,
    ),
    "usb_bridge_with_passthrough": (
        {"transport": "usb", "rotational": True, "model": "GENERIC-DISK"},
        True,
    ),
    "mmc": (
        {"transport": "mmc", "rotational": False, "model": "GENERIC-DISK"},
        True,
    ),
}

ATA_CLASSES = tuple(DEVICE_CLASSES)


def make_device(overrides: dict[str, object], path: str = "/dev/sdb") -> Device:
    base: dict[str, object] = {
        "path": path,
        "model": "GENERIC-DISK",
        "serial": "SYN-0001",
        "size_bytes": 1 << 34,
        "rotational": True,
        "transport": "sata",
        "is_system_disk": False,
        "mounted_at": [],
        "pt_type": None,
    }
    base.update(overrides)
    return Device.model_validate(base)


# --------------------------------------------------------------------------
# Capability profiles
# --------------------------------------------------------------------------


def hdparm(
    *, ops: tuple[str, ...] = (), enhanced: bool = False, frozen: bool = False
) -> str:
    """Build ``hdparm -I`` output in the layout the parser reads."""
    lines = [
        "/dev/sdb:",
        "",
        "ATA device, with non-removable media",
        "Commands/features:",
        "\tEnabled\tSupported:",
        "\t   *\tSecurity Mode feature set",
    ]
    if ops:
        lines.append("\t   *\tSANITIZE feature set")
        lines.extend(f"\t   *\t   {op} command" for op in ops)
    lines += [
        "Security:",
        "\t\tsupported",
        "\tnot\tenabled",
        "\tnot\tlocked",
        "\t\tfrozen" if frozen else "\tnot\tfrozen",
        "\t\tsupported: enhanced erase"
        if enhanced
        else "\tnot\tsupported: enhanced erase",
        "\t2min for SECURITY ERASE UNIT. 2min for ENHANCED SECURITY ERASE UNIT.",
    ]
    return "\n".join(lines) + "\n"


def sedutil(path: str, opal: bool) -> str:
    code = "2" if opal else "No"
    return f"Scanning for Opal compliant disks\n{path}  {code}  MODEL  1.0\n"


def ata_io(text: str, *, opal: bool = False) -> SystemProbe:
    return SystemProbe(
        runner=FakeRunner(  # type: ignore[arg-type]
            {
                ("hdparm", "-I", "/dev/sdb"): ok(text),
                ("sedutil-cli", "--scan"): ok(sedutil("/dev/sdb", opal)),
            }
        )
    )


B, C, OV = "BLOCK_ERASE_EXT", "CRYPTO_SCRAMBLE_EXT", "OVERWRITE_EXT"
M = EraseMethod

#: profile -> (hdparm kwargs, opal, Purge mechanism on magnetic, on flash).
ATA_PROFILES: dict[str, tuple[dict[str, object], bool, M | None, M | None]] = {
    "nothing": ({}, False, None, None),
    "enhanced_only": ({"enhanced": True}, False, M.ATA_SECURITY_ERASE_ENHANCED, None),
    "enhanced_frozen": ({"enhanced": True, "frozen": True}, False, None, None),
    "sanitize_block": (
        {"ops": (B,)},
        False,
        M.ATA_SANITIZE_BLOCK_ERASE,
        M.ATA_SANITIZE_BLOCK_ERASE,
    ),
    "sanitize_crypto": (
        {"ops": (C,)},
        False,
        M.ATA_SANITIZE_CRYPTO_SCRAMBLE,
        M.ATA_SANITIZE_CRYPTO_SCRAMBLE,
    ),
    "sanitize_overwrite_only": ({"ops": (OV,)}, False, M.ATA_SANITIZE_OVERWRITE, None),
    "sanitize_overwrite_and_enhanced": (
        {"ops": (OV,), "enhanced": True},
        False,
        M.ATA_SANITIZE_OVERWRITE,
        None,
    ),
    "sanitize_all_and_enhanced": (
        {"ops": (B, C, OV), "enhanced": True},
        False,
        M.ATA_SANITIZE_BLOCK_ERASE,
        M.ATA_SANITIZE_BLOCK_ERASE,
    ),
    "opal_only": ({}, True, M.SED_CRYPTO_ERASE, M.SED_CRYPTO_ERASE),
    "opal_and_enhanced": (
        {"enhanced": True},
        True,
        M.SED_CRYPTO_ERASE,
        M.SED_CRYPTO_ERASE,
    ),
    "opal_and_sanitize_overwrite": (
        {"ops": (OV,)},
        True,
        M.ATA_SANITIZE_OVERWRITE,
        M.SED_CRYPTO_ERASE,
    ),
}


def ata_rows() -> list[object]:
    rows: list[object] = []
    for cls in ATA_CLASSES:
        overrides, flash = DEVICE_CLASSES[cls]
        for name, (kwargs, opal, magnetic, on_flash) in ATA_PROFILES.items():
            expected = on_flash if flash else magnetic
            rows.append(
                pytest.param(
                    cls, overrides, flash, kwargs, opal, expected, id=f"{cls}-{name}"
                )
            )
    return rows


@pytest.mark.parametrize(
    ("cls", "overrides", "flash", "hdparm_kwargs", "opal", "expected"), ata_rows()
)
def test_ata_purge_mapping_by_device_class(
    cls: str,
    overrides: dict[str, object],
    flash: bool,
    hdparm_kwargs: dict[str, object],
    opal: bool,
    expected: EraseMethod | None,
) -> None:
    from core.device.media import is_flash

    device = make_device(overrides)
    assert is_flash(device)[0] is flash, f"{cls} changed flash classification"
    caps = probe(device, ata_io(hdparm(**hdparm_kwargs), opal=opal))  # type: ignore[arg-type]

    assert SanitizationLevel.CLEAR in caps.achievable_levels
    assert SanitizationLevel.DESTROY not in caps.achievable_levels
    assert recommend_method(caps, SanitizationLevel.CLEAR, device=device) is (
        EraseMethod.SINGLE_PASS_OVERWRITE
    )
    if expected is None:
        assert SanitizationLevel.PURGE not in caps.achievable_levels
        with pytest.raises(UnsupportedCapability):
            recommend_method(caps, SanitizationLevel.PURGE, device=device)
    else:
        assert SanitizationLevel.PURGE in caps.achievable_levels
        assert (
            recommend_method(caps, SanitizationLevel.PURGE, device=device) is expected
        )
    if flash:
        assert EraseMethod.ATA_SECURITY_ERASE_ENHANCED not in purge_mechanisms(
            caps, device
        )
        assert EraseMethod.ATA_SANITIZE_OVERWRITE not in purge_mechanisms(caps, device)


# --------------------------------------------------------------------------
# NVMe: always flash
# --------------------------------------------------------------------------

#: name -> (sanicap, fna, opal, Purge mechanism). SANICAP bit 0 crypto erase,
#: bit 1 block erase, bit 2 overwrite; FNA bit 2 crypto erase by Format NVM.
NVME_PROFILES: dict[str, tuple[int, int, bool, M | None]] = {
    "nothing": (0, 0, False, None),
    "sanitize_crypto": (0b001, 0, False, M.NVME_SANITIZE_BLOCK),
    "sanitize_block": (0b010, 0, False, M.NVME_SANITIZE_BLOCK),
    "sanitize_overwrite_only": (0b100, 0, False, None),
    "format_crypto": (0, 0b100, False, M.NVME_FORMAT_SES1),
    "opal_only": (0, 0, True, M.SED_CRYPTO_ERASE),
    "everything": (0b111, 0b100, True, M.NVME_SANITIZE_BLOCK),
}


@pytest.mark.parametrize(
    ("sanicap", "fna", "opal", "expected"),
    [pytest.param(*row, id=name) for name, row in NVME_PROFILES.items()],
)
def test_nvme_purge_mapping(
    sanicap: int, fna: int, opal: bool, expected: EraseMethod | None
) -> None:
    device = make_device(
        {"transport": "nvme", "rotational": False, "model": "GENERIC NVME"},
        path="/dev/nvme0n1",
    )
    io = SystemProbe(
        runner=FakeRunner(  # type: ignore[arg-type]
            {
                ("nvme", "id-ctrl", "/dev/nvme0n1", "-o", "json"): ok(
                    json.dumps({"nn": 1, "sanicap": sanicap, "fna": fna})
                ),
                ("sedutil-cli", "--scan"): ok(sedutil("/dev/nvme0n1", opal)),
            }
        )
    )
    caps = probe(device, io)
    if expected is None:
        assert SanitizationLevel.PURGE not in caps.achievable_levels
        with pytest.raises(UnsupportedCapability):
            recommend_method(caps, SanitizationLevel.PURGE, device=device)
    else:
        assert SanitizationLevel.PURGE in caps.achievable_levels
        assert (
            recommend_method(caps, SanitizationLevel.PURGE, device=device) is expected
        )


# --------------------------------------------------------------------------
# What the capability record says about the enhanced erase decision
# --------------------------------------------------------------------------


def test_flash_with_enhanced_erase_records_why_it_is_clear_only() -> None:
    device = make_device(DEVICE_CLASSES["ata_ssd"][0])
    caps = probe(device, ata_io(hdparm(enhanced=True)))
    blob = " ".join(caps.limitations)
    assert "Table A-8" in blob
    assert "Clear" in blob
    assert "IEEE 2883" in blob
    assert "queue/rotational=0" in blob


def test_flash_with_sanitize_overwrite_records_why_it_is_not_purge() -> None:
    device = make_device(DEVICE_CLASSES["ata_ssd"][0])
    caps = probe(device, ata_io(hdparm(ops=(OV,))))
    assert any(
        "OVERWRITE_EXT" in item and "Table A-8" in item for item in caps.limitations
    )


def test_magnetic_enhanced_erase_purge_names_its_withdrawn_basis() -> None:
    device = make_device(DEVICE_CLASSES["ata_hdd"][0])
    caps = probe(device, ata_io(hdparm(enhanced=True)))
    blob = " ".join(caps.limitations)
    assert "Table A-5" in blob
    assert "withdrawn" in blob
    assert "IEEE 2883" in blob


def test_magnetic_enhanced_erase_not_chosen_carries_no_basis_note() -> None:
    device = make_device(DEVICE_CLASSES["ata_hdd"][0])
    caps = probe(device, ata_io(hdparm(ops=(B,), enhanced=True)))
    assert not any("Table A-5" in item for item in caps.limitations)
