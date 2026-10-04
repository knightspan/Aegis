"""Shared fixtures. No real device or image access anywhere in the suite."""

from __future__ import annotations

import errno
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from tempfile import gettempdir
from typing import Any

import pytest
import structlog
from core.models import (
    CarveCandidate,
    Device,
    DeviceCapabilities,
    EraseJob,
    EraseMethod,
    ErasePlan,
    ForensicReport,
    LedgerEntry,
    SanitizationLevel,
    VerificationResult,
)

from tests import _host_device_guard


@pytest.fixture
def sample_device() -> Device:
    return Device(
        path="/dev/sdz",
        model="SYNTHETIC-TEST-DISK",
        serial="SYN-0001",
        size_bytes=512 * 1024 * 1024,
        rotational=False,
        transport="usb",
        is_system_disk=False,
        mounted_at=[],
        pt_type="gpt",
    )


@pytest.fixture
def sample_capabilities() -> DeviceCapabilities:
    return DeviceCapabilities(
        ata_security_erase=False,
        ata_enhanced_erase=False,
        ata_sanitize_ops=[],
        nvme_sanicap={},
        is_sed_opal=False,
        security_frozen=False,
        est_erase_seconds=60,
        achievable_levels={SanitizationLevel.CLEAR},
    )


@pytest.fixture
def sample_plan() -> ErasePlan:
    return ErasePlan(
        method=EraseMethod.SINGLE_PASS_OVERWRITE,
        level=SanitizationLevel.CLEAR,
        justification="synthetic fixture",
        est_seconds=750,
    )


@pytest.fixture
def sample_erase_job(sample_device: Device) -> EraseJob:
    return EraseJob(
        job_id="job-0001",
        device=sample_device,
        method=EraseMethod.SINGLE_PASS_OVERWRITE,
        level=SanitizationLevel.CLEAR,
        confirmed_serial=None,
    )


@pytest.fixture
def sample_verification() -> VerificationResult:
    return VerificationResult(
        passed=False,
        strategy="sampled",
        bytes_checked=0,
        sample_count=0,
        confidence_bp=0,
        failed_offsets=[],
    )


@pytest.fixture
def sample_candidate() -> CarveCandidate:
    return CarveCandidate(
        offset=0,
        length=0,
        ext="bin",
        mime="application/octet-stream",
        source="signature",
        validation="corrupt",
        confidence_bp=0,
        bucket="LOW",
        sha256="0" * 64,
        original_name=None,
        possibly_fragmented=False,
    )


@pytest.fixture
def sample_ledger_entry() -> LedgerEntry:
    return LedgerEntry(
        seq=0,
        ts_utc=datetime(2026, 1, 1, tzinfo=UTC),
        monotonic_ns=0,
        boot_id="00000000-0000-0000-0000-000000000000",
        actor="test",
        operation="noop",
        params_hash="0" * 64,
        result_hash="0" * 64,
        prev_entry_hash="0" * 64,
        entry_hash="0" * 64,
    )


@pytest.fixture
def sample_report(sample_ledger_entry: LedgerEntry) -> ForensicReport:
    return ForensicReport(
        case_id="CASE-0001",
        operator="test",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        tool_version="0.0.0",
        pubkey_fingerprint="AA:BB",
        sections={},
        ledger_excerpt=[sample_ledger_entry],
        signature=None,
    )


@pytest.fixture(autouse=True)
def _host_disk_reads_get_eacces(monkeypatch: pytest.MonkeyPatch) -> None:
    """A file erase's read-back of the host disk gets EACCES, on every host.

    The file eraser verifies an overwrite by reading the file's old physical
    extents from the block device beneath it. In the suite that is the machine's
    own disk: an unprivileged run is refused by the kernel, and a root run - a
    CI container - would read it. Both get the unprivileged answer here, before
    any open, so the result is the same everywhere and no test reads a host
    disk. A test that verifies against an image passes a regular file as the
    device and still gets the real read; a path that does not exist still gets
    the kernel's ENOENT.
    """
    from core.erase import verify

    real = verify._read_physical_extents

    def read(device: str, extents: Any, expected_byte: int) -> Any:
        if os.path.exists(device) and not os.path.isfile(device):
            raise PermissionError(
                errno.EACCES,
                "raw host-disk reads are not taken in the test suite",
                device,
            )
        return real(device, extents, expected_byte)

    monkeypatch.setattr(verify, "_read_physical_extents", read)


@pytest.fixture(autouse=True)
def _host_uuid_directory_is_not_listed(monkeypatch: pytest.MonkeyPatch) -> None:
    """The host's ``/dev/disk/by-uuid`` is never listed; a UUID from it is unknown.

    ``resolve_volume`` names a volume's filesystem UUID by listing that
    directory, which lists every volume on the machine, removable media
    included. No test asserts the UUID of a real volume - the udisks loop tests
    do not, and the unit tests pass a directory of their own - so in the suite
    the host's directory answers "unknown" without being read.
    """
    from core.erase import freespace

    real = freespace._uuid_for
    host = Path("/dev/disk/by-uuid")

    def uuid_for(source: str, by_uuid: Path) -> str | None:
        return None if Path(by_uuid) == host else real(source, by_uuid)

    monkeypatch.setattr(freespace, "_uuid_for", uuid_for)


@pytest.fixture(autouse=True)
def _trace_sweep_searches_a_synthetic_home(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """The trace sweep reads a home made for the test, never the runner's own.

    A file erase submitted through the API sweeps the desktop's thumbnails,
    recent-files list and Trash for traces of the erased files. Left alone, the
    suite would read - and on a real run, erase from - the home directory of
    whoever runs it. The synthetic home is created on first use, and no volume
    Trash is searched, so the sweep never walks up the host's mounts either.
    Tests of the sweep itself pass locations of their own.
    """
    from core.erase import traces

    made: list[Path] = []

    def synthetic() -> traces.TraceLocations:
        if not made:
            made.append(tmp_path_factory.mktemp("home"))
        return traces.locations_for("linux", {}, made[0])

    monkeypatch.setattr(traces, "default_locations", synthetic)


def pytest_configure() -> None:
    """Silence structlog below WARNING, and refuse host block-device access."""
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING),
        cache_logger_on_first_use=True,
    )
    _host_device_guard.install([str(Path(__file__).resolve().parents[1]), gettempdir()])


def pytest_terminal_summary(terminalreporter: pytest.TerminalReporter) -> None:
    """Name the guard's rule set, what the suite may inspect, and every refusal.

    The first line says which host's rules the hook applied ("Linux rules
    active", "macOS rules active", "Windows rules active", or "no rules
    active"), never that the guard "passed": a rule set matches only its own
    host's devices.
    """
    for line in _host_device_guard.summary_lines():
        terminalreporter.write_line(line)
    if _host_device_guard.BLOCKED:
        terminalreporter.section("host block-device access refused", red=True)
        for line in _host_device_guard.BLOCKED:
            terminalreporter.line(line)


def pytest_sessionfinish(session: pytest.Session) -> None:
    """A refusal fails the run, even one a worker thread or handler swallowed."""
    if _host_device_guard.BLOCKED:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
