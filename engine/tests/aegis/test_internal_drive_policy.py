"""AEGIS policy: device sanitization only on removable USB/SD media, never an internal drive."""

from types import SimpleNamespace

import aegis_engine_cli as cli


def dev(interface="usb", internal=None, system=False):
    return SimpleNamespace(interface=interface, internal=internal, system_device=system, system_reasons=["IsBoot"])


def test_usb_removable_is_allowed():
    assert cli.sanitize_policy_refusal(dev("usb"), "USB") == ""


def test_sd_card_is_allowed():
    assert cli.sanitize_policy_refusal(dev("mmc"), "SD") == ""


def test_internal_nvme_non_system_is_refused():
    assert "Internal" in cli.sanitize_policy_refusal(dev("nvme"), "NVMe")


def test_internal_sata_ssd_and_hdd_are_refused():
    assert cli.sanitize_policy_refusal(dev("sata"), "SATA")
    assert cli.sanitize_policy_refusal(dev("sas"), "SAS")
    assert cli.sanitize_policy_refusal(dev("scsi"), "RAID")


def test_unknown_bus_fails_closed():
    assert cli.sanitize_policy_refusal(dev("unknown"), "")
    assert cli.sanitize_policy_refusal(dev("unknown"), "Unknown")


def test_internal_flag_wins_over_usb_interface():
    assert cli.sanitize_policy_refusal(dev("usb", internal=True), "USB")


def test_disagreeing_sources_fail_closed():
    assert cli.sanitize_policy_refusal(dev("usb"), "NVMe")


def test_system_disk_is_refused_even_on_usb():
    assert "System" in cli.sanitize_policy_refusal(dev("usb", system=True), "USB")
