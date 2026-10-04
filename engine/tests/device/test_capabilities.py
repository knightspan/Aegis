"""Capability probing: never claim a capability that was not observed."""

from __future__ import annotations

import json

import pytest
from core.device._sysio import SystemProbe
from core.device.capabilities import probe, recommend_method
from core.errors import UnsupportedCapability
from core.models import Device, EraseMethod, SanitizationLevel

from .conftest import FakeRunner, fail, ok

# --------------------------------------------------------------------------
# Captured tool output
# --------------------------------------------------------------------------

HDPARM_SATA_FULL = """
/dev/sdb:

ATA device, with non-removable media
\tModel Number:       ST2000DM008-2FR102
\tSerial Number:      ZFL2ABCD
Commands/features:
\tEnabled\tSupported:
\t   *\tSMART feature set
\t   *\tSecurity Mode feature set
\t   *\tSANITIZE feature set
\t   *\t   BLOCK_ERASE_EXT command
\t   *\t   OVERWRITE_EXT command
\t   *\t   CRYPTO_SCRAMBLE_EXT command
Security:
\tMaster password revision code = 65534
\t\tsupported
\tnot\tenabled
\tnot\tlocked
\tnot\tfrozen
\tnot\texpired: security count
\t\tsupported: enhanced erase
\t226min for SECURITY ERASE UNIT. 226min for ENHANCED SECURITY ERASE UNIT.
"""

HDPARM_SATA_FROZEN_NO_ENHANCED = """
/dev/sdc:

ATA device, with non-removable media
Commands/features:
\tEnabled\tSupported:
\t   *\tSecurity Mode feature set
\t    \tSANITIZE feature set
\t    \t   BLOCK_ERASE_EXT command
Security:
\t\tsupported
\tnot\tenabled
\tnot\tlocked
\t\tfrozen
\tnot\tsupported: enhanced erase
\t\t2min for SECURITY ERASE UNIT.
"""

HDPARM_PERMISSION = "/dev/sdb: Permission denied\n"

NVME_ID_CTRL = json.dumps(
    {
        "mn": "Samsung SSD 980 PRO 1TB",
        "sn": "S5GXNX0R123456",
        "nn": 1,
        "fna": 4,
        "sanicap": 2,
    }
)

NVME_ID_CTRL_ALL_SANITIZE = json.dumps({"nn": 2, "fna": 0, "sanicap": 7})
NVME_ID_CTRL_NONE = json.dumps({"nn": 1, "fna": 0, "sanicap": 0})

SEDUTIL_OPAL2 = """Scanning for Opal compliant disks
/dev/nvme0n1     2  Samsung SSD 980 PRO 1TB                  5B2QGXA7
/dev/sdb        No
No more disks present ending scan
"""

SEDUTIL_PYRITE = """Scanning for Opal compliant disks
/dev/sdb         p  Cheap Pyrite Drive                       1.0
No more disks present ending scan
"""

SEDUTIL_NONE = """Scanning for Opal compliant disks
/dev/sdb        No
No more disks present ending scan
"""


def make_device(**overrides: object) -> Device:
    base: dict[str, object] = {
        "path": "/dev/sdb",
        "model": "ST2000DM008-2FR102",
        "serial": "ZFL2ABCD",
        "size_bytes": 2000398934016,
        "rotational": True,
        "transport": "sata",
        "is_system_disk": False,
        "mounted_at": [],
        "pt_type": "gpt",
    }
    base.update(overrides)
    return Device.model_validate(base)


def io(**responses: object) -> SystemProbe:
    table = {
        ("hdparm", "-I", "/dev/sdb"): ok(HDPARM_SATA_FULL),
        ("sedutil-cli", "--scan"): ok(SEDUTIL_NONE),
    }
    for key, value in responses.items():
        table[tuple(key.split("|"))] = value  # type: ignore[index]
    return SystemProbe(runner=FakeRunner(table))  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# SATA / ATA
# --------------------------------------------------------------------------


def test_parses_ata_security_and_enhanced_erase() -> None:
    caps = probe(make_device(), io())
    assert caps.ata_security_erase is True
    assert caps.ata_enhanced_erase is True
    assert caps.security_frozen is False


def test_parses_frozen_security_state() -> None:
    probe_io = io(**{"hdparm|-I|/dev/sdb": ok(HDPARM_SATA_FROZEN_NO_ENHANCED)})
    caps = probe(make_device(), probe_io)
    assert caps.security_frozen is True
    assert caps.ata_enhanced_erase is False


def test_collects_supported_sanitize_ops_only() -> None:
    caps = probe(make_device(), io())
    assert sorted(caps.ata_sanitize_ops) == [
        "BLOCK_ERASE_EXT",
        "CRYPTO_SCRAMBLE_EXT",
        "OVERWRITE_EXT",
    ]


def test_ignores_sanitize_ops_that_are_not_starred() -> None:
    probe_io = io(**{"hdparm|-I|/dev/sdb": ok(HDPARM_SATA_FROZEN_NO_ENHANCED)})
    caps = probe(make_device(), probe_io)
    assert caps.ata_sanitize_ops == []


def test_reads_enhanced_erase_time_estimate() -> None:
    caps = probe(make_device(), io())
    assert caps.est_erase_seconds == 226 * 60


def test_falls_back_to_plain_erase_time_when_no_enhanced() -> None:
    probe_io = io(**{"hdparm|-I|/dev/sdb": ok(HDPARM_SATA_FROZEN_NO_ENHANCED)})
    caps = probe(make_device(), probe_io)
    assert caps.est_erase_seconds == 2 * 60


def test_permission_error_raises_rather_than_reporting_unsupported() -> None:
    probe_io = io(
        **{"hdparm|-I|/dev/sdb": fail(1, stderr=HDPARM_PERMISSION)},
    )
    with pytest.raises(UnsupportedCapability) as excinfo:
        probe(make_device(), probe_io)
    assert "root" in excinfo.value.remediation.lower()


# --------------------------------------------------------------------------
# NVMe
# --------------------------------------------------------------------------


def nvme_io(id_ctrl: str = NVME_ID_CTRL, sed: str = SEDUTIL_NONE) -> SystemProbe:
    return SystemProbe(
        runner=FakeRunner(  # type: ignore[arg-type]
            {
                ("nvme", "id-ctrl", "/dev/nvme0n1", "-o", "json"): ok(id_ctrl),
                ("sedutil-cli", "--scan"): ok(sed),
            }
        )
    )


def nvme_device() -> Device:
    return make_device(
        path="/dev/nvme0n1", transport="nvme", rotational=False, serial="S5GXNX0R123456"
    )


def test_decodes_nvme_sanicap_bits() -> None:
    caps = probe(nvme_device(), nvme_io(NVME_ID_CTRL_ALL_SANITIZE))
    assert caps.nvme_sanicap["crypto_erase"] is True
    assert caps.nvme_sanicap["block_erase"] is True
    assert caps.nvme_sanicap["overwrite"] is True


def test_decodes_single_nvme_sanicap_bit() -> None:
    caps = probe(nvme_device(), nvme_io())
    assert caps.nvme_sanicap["crypto_erase"] is False
    assert caps.nvme_sanicap["block_erase"] is True
    assert caps.nvme_sanicap["overwrite"] is False


def test_decodes_fna_crypto_erase_bit() -> None:
    caps = probe(nvme_device(), nvme_io())
    assert caps.nvme_sanicap["fna_crypto_format"] is True


def test_records_nvme_namespace_count() -> None:
    caps = probe(nvme_device(), nvme_io(NVME_ID_CTRL_ALL_SANITIZE))
    assert caps.nvme_sanicap["namespace_count"] == 2


def test_nvme_without_sanitize_support_is_clear_only() -> None:
    caps = probe(nvme_device(), nvme_io(NVME_ID_CTRL_NONE))
    assert caps.achievable_levels == {SanitizationLevel.CLEAR}


# --------------------------------------------------------------------------
# SED
# --------------------------------------------------------------------------


def test_detects_opal_two() -> None:
    caps = probe(nvme_device(), nvme_io(NVME_ID_CTRL_NONE, sed=SEDUTIL_OPAL2))
    assert caps.is_sed_opal is True


def test_pyrite_is_not_treated_as_opal() -> None:
    probe_io = io(**{"sedutil-cli|--scan": ok(SEDUTIL_PYRITE)})
    caps = probe(make_device(), probe_io)
    assert caps.is_sed_opal is False


def test_pyrite_records_a_limitation() -> None:
    probe_io = io(**{"sedutil-cli|--scan": ok(SEDUTIL_PYRITE)})
    caps = probe(make_device(), probe_io)
    assert any("pyrite" in factor.lower() for factor in caps.limitations)


# --------------------------------------------------------------------------
# USB / MMC bridges
# --------------------------------------------------------------------------


def test_usb_bridge_without_passthrough_is_clear_only() -> None:
    probe_io = SystemProbe(
        runner=FakeRunner(  # type: ignore[arg-type]
            {
                ("hdparm", "-I", "/dev/sda"): fail(
                    1, stderr="SG_IO: bad/missing sense data\n"
                ),
                ("sedutil-cli", "--scan"): ok(SEDUTIL_NONE),
            }
        )
    )
    caps = probe(make_device(path="/dev/sda", transport="usb"), probe_io)
    assert caps.achievable_levels == {SanitizationLevel.CLEAR}
    assert any("bridge" in factor.lower() for factor in caps.limitations)


def test_usb_bridge_permission_error_still_raises() -> None:
    probe_io = SystemProbe(
        runner=FakeRunner(  # type: ignore[arg-type]
            {("hdparm", "-I", "/dev/sda"): fail(1, stderr=HDPARM_PERMISSION)}
        )
    )
    with pytest.raises(UnsupportedCapability):
        probe(make_device(path="/dev/sda", transport="usb"), probe_io)


# --------------------------------------------------------------------------
# achievable_levels
# --------------------------------------------------------------------------


def test_clear_is_always_achievable() -> None:
    caps = probe(make_device(), io())
    assert SanitizationLevel.CLEAR in caps.achievable_levels


def test_destroy_is_never_achievable_in_software() -> None:
    caps = probe(make_device(), io())
    assert SanitizationLevel.DESTROY not in caps.achievable_levels


def test_purge_from_ata_sanitize_ops() -> None:
    caps = probe(make_device(), io())
    assert SanitizationLevel.PURGE in caps.achievable_levels


def test_purge_from_enhanced_erase_requires_not_frozen() -> None:
    probe_io = io(**{"hdparm|-I|/dev/sdb": ok(HDPARM_SATA_FROZEN_NO_ENHANCED)})
    caps = probe(make_device(), probe_io)
    assert caps.security_frozen is True
    assert SanitizationLevel.PURGE not in caps.achievable_levels


def test_purge_from_sed_opal_crypto_erase() -> None:
    caps = probe(nvme_device(), nvme_io(NVME_ID_CTRL_NONE, sed=SEDUTIL_OPAL2))
    assert SanitizationLevel.PURGE in caps.achievable_levels


# --------------------------------------------------------------------------
# recommend_method
# --------------------------------------------------------------------------


def test_recommends_sanitize_block_erase_for_purge_on_ata() -> None:
    caps = probe(make_device(), io())
    assert (
        recommend_method(caps, SanitizationLevel.PURGE, device=make_device())
        == EraseMethod.ATA_SANITIZE_BLOCK_ERASE
    )


def test_recommends_overwrite_for_clear() -> None:
    caps = probe(make_device(), io())
    assert (
        recommend_method(caps, SanitizationLevel.CLEAR, device=make_device())
        == EraseMethod.SINGLE_PASS_OVERWRITE
    )


def test_recommend_refuses_unachievable_level() -> None:
    caps = probe(nvme_device(), nvme_io(NVME_ID_CTRL_NONE))
    with pytest.raises(UnsupportedCapability):
        recommend_method(caps, SanitizationLevel.PURGE, device=nvme_device())


def test_recommend_never_returns_destroy() -> None:
    caps = probe(make_device(), io())
    with pytest.raises(UnsupportedCapability):
        recommend_method(caps, SanitizationLevel.DESTROY, device=make_device())


def test_ata_crypto_scramble_is_distinct_from_sed_crypto_erase() -> None:
    caps = probe(make_device(), io())
    assert caps.is_sed_opal is False
    assert (
        recommend_method(caps, SanitizationLevel.PURGE, device=make_device())
        != EraseMethod.SED_CRYPTO_ERASE
    )


def test_sed_only_device_recommends_sed_crypto_erase() -> None:
    caps = probe(nvme_device(), nvme_io(NVME_ID_CTRL_NONE, sed=SEDUTIL_OPAL2))
    assert (
        recommend_method(caps, SanitizationLevel.PURGE, device=nvme_device())
        == EraseMethod.SED_CRYPTO_ERASE
    )


def test_ata_crypto_scramble_only_device_recommends_that_method() -> None:
    hdparm_crypto_only = HDPARM_SATA_FULL
    for op in ("BLOCK_ERASE_EXT", "OVERWRITE_EXT"):
        hdparm_crypto_only = hdparm_crypto_only.replace(
            f"\t   *\t   {op} command\n", f"\t    \t   {op} command\n"
        )
    caps = probe(make_device(), io(**{"hdparm|-I|/dev/sdb": ok(hdparm_crypto_only)}))
    assert caps.ata_sanitize_ops == ["CRYPTO_SCRAMBLE_EXT"]
    assert (
        recommend_method(caps, SanitizationLevel.PURGE, device=make_device())
        == EraseMethod.ATA_SANITIZE_CRYPTO_SCRAMBLE
    )
