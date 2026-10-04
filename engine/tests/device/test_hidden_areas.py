"""HPA/DCO detection. Read-only: detection never changes a device's native max."""

from __future__ import annotations

import pytest
from core.device._sysio import SystemProbe
from core.device.hidden_areas import detect_hidden_areas
from core.errors import UnsupportedCapability
from core.models import Device

from .conftest import FakeRunner, fail, ok

HDPARM_N_NO_HPA = """
/dev/sdb:
 max sectors   = 3907029168/3907029168, HPA is disabled
"""

HDPARM_N_HPA_ENABLED = """
/dev/sdb:
 max sectors   = 3907000000/3907029168, HPA is enabled
"""

DCO_NO_EXTRA = """
/dev/sdb:
DCO Revision: 0x0002
The following features can be selectively disabled via DCO:
\tReal max sectors: 3907029168
\tATA command/feature sets:
\t\t SMART security HPA 48_bit SET_MAX
"""

DCO_HIDES_SECTORS = """
/dev/sdb:
DCO Revision: 0x0002
The following features can be selectively disabled via DCO:
\tReal max sectors: 3907100000
\tATA command/feature sets:
\t\t SMART security HPA 48_bit SET_MAX
"""

DCO_UNSUPPORTED = "/dev/sdb:\n SG_IO: bad/missing sense data\n"

SECTOR = 512


def device(**overrides: object) -> Device:
    base: dict[str, object] = {
        "path": "/dev/sdb",
        "model": "ST2000DM008",
        "serial": "ZFL2ABCD",
        "size_bytes": 3907029168 * SECTOR,
        "rotational": True,
        "transport": "sata",
        "is_system_disk": False,
        "mounted_at": [],
        "pt_type": "gpt",
    }
    base.update(overrides)
    return Device.model_validate(base)


def io(hdparm_n: object, dco: object) -> SystemProbe:
    return SystemProbe(
        runner=FakeRunner(  # type: ignore[arg-type]
            {
                ("hdparm", "-N", "/dev/sdb"): hdparm_n,
                ("hdparm", "--dco-identify", "/dev/sdb"): dco,
            }
        )
    )


def test_reports_no_hidden_area_on_a_clean_disk() -> None:
    report = detect_hidden_areas(device(), io(ok(HDPARM_N_NO_HPA), ok(DCO_NO_EXTRA)))
    assert report.hpa_present is False
    assert report.dco_present is False
    assert report.hidden_bytes == 0
    assert report.accessible_sectors == 3907029168
    assert report.native_max_sectors == 3907029168


def test_detects_hpa_and_counts_hidden_bytes() -> None:
    report = detect_hidden_areas(
        device(), io(ok(HDPARM_N_HPA_ENABLED), ok(DCO_NO_EXTRA))
    )
    assert report.hpa_present is True
    assert report.accessible_sectors == 3907000000
    assert report.native_max_sectors == 3907029168
    assert report.hidden_bytes == (3907029168 - 3907000000) * SECTOR


def test_detects_dco_hiding_sectors_beyond_the_hpa_native_max() -> None:
    report = detect_hidden_areas(
        device(), io(ok(HDPARM_N_NO_HPA), ok(DCO_HIDES_SECTORS))
    )
    assert report.dco_present is True
    assert report.native_max_sectors == 3907100000
    assert report.hidden_bytes == (3907100000 - 3907029168) * SECTOR


def test_counts_hpa_and_dco_together() -> None:
    report = detect_hidden_areas(
        device(), io(ok(HDPARM_N_HPA_ENABLED), ok(DCO_HIDES_SECTORS))
    )
    assert report.hpa_present is True
    assert report.dco_present is True
    assert report.hidden_bytes == (3907100000 - 3907000000) * SECTOR


def test_degrades_when_dco_identify_is_unsupported() -> None:
    report = detect_hidden_areas(
        device(), io(ok(HDPARM_N_HPA_ENABLED), fail(1, stderr=DCO_UNSUPPORTED))
    )
    assert report.hpa_present is True
    assert report.dco_present is False


def test_permission_error_raises_instead_of_reporting_no_hidden_area() -> None:
    probe_io = io(fail(1, stderr="/dev/sdb: Permission denied\n"), ok(DCO_NO_EXTRA))
    with pytest.raises(UnsupportedCapability):
        detect_hidden_areas(device(), probe_io)


def test_nvme_has_no_hpa_or_dco_and_reports_full_size() -> None:
    nvme = device(path="/dev/nvme0n1", transport="nvme", rotational=False)
    report = detect_hidden_areas(nvme, io(ok(""), ok("")))
    assert report.hpa_present is False
    assert report.dco_present is False
    assert report.hidden_bytes == 0
    assert report.accessible_sectors == nvme.size_bytes // SECTOR


# --------------------------------------------------------------------------
# A successful exit is not a successful probe
# --------------------------------------------------------------------------

#: What a USB bridge produced on the TransMemory stick used for hardware
#: validation. hdparm exits 0. Trusting it gave native_max_sectors=1 and an
#: erase that covered 512 bytes of a 7.76 GB device.
HDPARM_N_INVALID = """
/dev/sdb:
 max sectors   = 0/1, HPA setting seems invalid (buggy kernel device driver?)
"""

HDPARM_N_ZEROES = """
/dev/sdb:
 max sectors   = 0/0, HPA is disabled
"""

HDPARM_N_ABSURD = """
/dev/sdb:
 max sectors   = 3907029168/93768700032, HPA is enabled
"""

FULL_SECTORS = 3907029168


def test_invalid_hpa_warning_is_not_trusted_despite_a_zero_exit() -> None:
    """The defect that let a 7.76 GB wipe cover 512 bytes.

    hdparm exited 0 and printed a parsable ``max sectors`` line, so exit code
    and regex match both said "good reading". The numbers were 0/1.
    """
    report = detect_hidden_areas(
        device(), io(ok(HDPARM_N_INVALID), ok(DCO_NO_EXTRA))
    )

    assert report.probe_failed is True
    assert report.hpa_present is False
    assert report.hidden_bytes == 0
    assert report.native_max_sectors == FULL_SECTORS
    assert report.accessible_sectors == FULL_SECTORS
    assert report.limitations, "a failed probe must say why"
    assert "invalid" in report.limitations[0]


def test_zero_sector_counts_are_rejected() -> None:
    report = detect_hidden_areas(device(), io(ok(HDPARM_N_ZEROES), ok(DCO_NO_EXTRA)))

    assert report.probe_failed is True
    assert report.accessible_sectors == FULL_SECTORS
    assert "zero sector count" in report.limitations[0]


def test_sector_counts_far_from_the_kernel_size_are_rejected() -> None:
    """A native max 24x the kernel size is a parse fault, not a 90% HPA."""
    report = detect_hidden_areas(device(), io(ok(HDPARM_N_ABSURD), ok(DCO_NO_EXTRA)))

    assert report.probe_failed is True
    assert report.hidden_bytes == 0
    assert report.native_max_sectors == FULL_SECTORS


def test_a_failed_hdparm_does_not_report_no_hidden_area() -> None:
    report = detect_hidden_areas(device(), io(fail(5), ok(DCO_NO_EXTRA)))

    assert report.probe_failed is True
    assert "exited 5" in report.limitations[0]


def test_an_implausible_dco_reading_is_dropped_without_failing_the_probe() -> None:
    """The HPA reading passed; only the DCO number is unusable."""
    report = detect_hidden_areas(
        device(),
        io(ok(HDPARM_N_HPA_ENABLED), ok("\tReal max sectors: 99999999999999\n")),
    )

    assert report.probe_failed is False
    assert report.dco_present is False
    assert report.native_max_sectors == FULL_SECTORS
    assert any("DCO reading was discarded" in item for item in report.limitations)


def test_a_good_reading_still_reports_no_limitations() -> None:
    report = detect_hidden_areas(device(), io(ok(HDPARM_N_NO_HPA), ok(DCO_NO_EXTRA)))

    assert report.probe_failed is False
    assert report.limitations == []


# --------------------------------------------------------------------------
# Transports where ATA pass-through is not dependable
# --------------------------------------------------------------------------


@pytest.mark.parametrize("transport", ["usb", "mmc"])
def test_bridged_transports_are_not_probed_at_all(transport: str) -> None:
    """Not attempted, not attempted-and-disbelieved.

    A bridge's answer describes the bridge, not the medium behind it, and no
    part of the answer says which. The command is also a SET_MAX query, which
    is not something to send blind to firmware that may mishandle it.
    """
    probe_io = io(ok(HDPARM_N_INVALID), ok(DCO_NO_EXTRA))
    report = detect_hidden_areas(device(transport=transport), probe_io)

    assert probe_io.runner.calls == [], "the probe must not run on a bridge"  # type: ignore[attr-defined]
    assert report.probe_failed is True
    assert report.hpa_present is False
    assert report.accessible_sectors == FULL_SECTORS
    assert transport in report.limitations[0]


def test_nvme_is_a_determination_not_a_failed_probe() -> None:
    nvme = device(path="/dev/nvme0n1", transport="nvme", rotational=False)
    report = detect_hidden_areas(nvme, io(ok(""), ok("")))

    assert report.probe_failed is False
    assert report.limitations == []
