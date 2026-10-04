"""NTFS behaviour that can only be tested on Windows. Skipped elsewhere.

These run on the `windows-latest` CI runner, against its real NTFS volume.
The junction test is the regression test for the worst defect this work
found: a recursive erase that followed a directory junction out of the folder
it was given and erased whatever it pointed at.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "win32", reason="NTFS/Win32 behaviour; this host is not Windows"
)


def _erase_options(**over: object) -> object:
    from core.models import FileEraseOptions

    base: dict[str, object] = {"confirm": True}
    base.update(over)
    return FileEraseOptions.model_validate(base)


def _make_junction(link: Path, target: Path) -> None:
    """A real NTFS junction: a directory, a reparse point, not a symlink."""
    import _winapi

    create = getattr(_winapi, "CreateJunction", None)
    if create is None:  # pragma: no cover - CPython always has it on Windows
        pytest.skip("_winapi.CreateJunction is unavailable")
    create(str(target), str(link))


def test_a_junction_cannot_redirect_a_recursive_erase_out_of_the_root(
    tmp_path: Path,
) -> None:
    from core.erase.files import erase_paths, expand_targets
    from core.erase.sink import LedgerSink

    root = tmp_path / "test-root"
    safe = root / "safe"
    outside = tmp_path / "outside"
    safe.mkdir(parents=True)
    outside.mkdir()
    (safe / "mine.txt").write_text("erase me")
    (outside / "someone-elses.txt").write_text("this must survive")
    _make_junction(root / "junction", outside)

    targets = expand_targets([root])

    assert outside / "someone-elses.txt" not in targets
    assert root / "junction" / "someone-elses.txt" not in targets
    assert root / "safe" / "mine.txt" in targets
    assert root / "junction" in targets, "the junction itself is reported"

    class _Sink(LedgerSink):
        def record(self, phase: object, event: str, detail: dict[str, object]) -> None:
            return None

    generator = erase_paths([root], _erase_options(), job_id="junction", ledger=_Sink())
    try:
        while True:
            next(generator)
    except StopIteration as stop:
        result = stop.value

    assert (outside / "someone-elses.txt").read_text() == "this must survive"
    assert not (safe / "mine.txt").exists()
    junction_record = next(
        record for record in result.records if record.path.endswith("junction")
    )
    assert junction_record.error_kind == "REPARSE_POINT_REFUSED"
    assert junction_record.unlinked is False


def test_a_directory_symlink_is_refused_the_same_way(tmp_path: Path) -> None:
    from core.erase.files import expand_targets

    outside = tmp_path / "target"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep")
    root = tmp_path / "root"
    root.mkdir()
    try:
        (root / "link").symlink_to(outside, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - needs Developer Mode or admin
        pytest.skip(f"symlink creation is not permitted here: {exc}")

    targets = expand_targets([root])

    assert outside / "keep.txt" not in targets
    assert (outside / "keep.txt").is_file()


@pytest.mark.parametrize(
    "relative",
    ["System32", "System32\\drivers\\etc\\hosts", "explorer.exe"],
)
def test_protected_windows_locations_are_refused_before_any_write(
    relative: str,
) -> None:
    from core.erase.files import erase_one
    from core.errors import SystemDiskRefused
    from core.models import FileEraseOptions

    target = Path(os.environ.get("SystemRoot", "C:\\Windows")) / relative
    if not target.exists():  # pragma: no cover - unusual Windows install
        pytest.skip(f"{target} does not exist on this runner")

    # Confirmed, and still refused before anything is opened, let alone written.
    with pytest.raises(SystemDiskRefused):
        erase_one(target, FileEraseOptions(confirm=True))


def test_a_traversing_path_lands_in_the_protected_tree_and_is_refused(
    tmp_path: Path,
) -> None:
    from core.erase.files import erase_one
    from core.errors import SystemDiskRefused
    from core.models import FileEraseOptions

    system_root = Path(os.environ.get("SystemRoot", "C:\\Windows"))
    traversing = tmp_path / ".." / ".." / ".." / ".." / ".." / ".." / ".." / ".."
    candidate = traversing / system_root.relative_to(system_root.anchor) / "System32"
    if not candidate.resolve().exists():  # pragma: no cover
        pytest.skip("the traversal did not land in the Windows directory")

    # Confirmed, and still refused before anything is opened, let alone written.
    with pytest.raises(SystemDiskRefused):
        erase_one(candidate, FileEraseOptions(confirm=True))


def test_an_alternate_data_stream_is_seen_and_erased(tmp_path: Path) -> None:
    from core.erase.files import erase_one
    from core.erase.inspect import inspect_path

    target = tmp_path / "carrier.txt"
    target.write_text("visible content")
    with open(f"{target}:hidden", "w", encoding="utf-8") as stream:
        stream.write("the interesting part")

    inspection = inspect_path(target)
    assert any("hidden" in name for name in inspection.alt_data_streams), (
        f"the stream was not enumerated: {inspection.alt_data_streams}"
    )

    record = erase_one(target, _erase_options())

    assert record.ok, record.error
    assert record.unlinked
    assert any("hidden" in name for name in record.streams_removed)
    assert not target.exists()


def test_a_small_file_is_reported_resident_rather_than_guessed(tmp_path: Path) -> None:
    """NTFS keeps a tiny file inside its MFT record; the erase must say so."""
    from core.erase.files import erase_one
    from core.erase.inspect import inspect_path

    target = tmp_path / "tiny.txt"
    target.write_text("x" * 64)

    inspection = inspect_path(target)

    assert inspection.is_resident is not None, (
        "residency must be established on NTFS, not left unknown: "
        f"{inspection.limitations}"
    )
    if inspection.is_resident:
        record = erase_one(target, _erase_options())
        assert any("resident" in item.lower() for item in record.limitations), (
            f"a resident file must say its bytes survive: {record.limitations}"
        )


def test_the_windows_backend_is_the_one_that_was_selected() -> None:
    from core.erase._platform import backend

    assert backend().name == "windows"


def test_discovery_inside_the_suite_is_stopped_before_powershell_starts() -> None:
    """The real adapter, with its real runner, never reaches this machine's disks.

    Until 2026-09-27 this test ran PowerShell's ``Get-Disk`` against the
    runner's disks and checked that the system disk was protected. The suite
    does not reach host devices (``tests/_host_device_guard.py``), so that check
    is made by ``scripts/platform_smoke.py``, which CI runs on this runner
    before the suite and uploads as evidence. What is checked here: discovery
    fails as it would with PowerShell blocked, and the guard refused the
    encoded ``Get-Disk`` script before PowerShell ran.
    """
    from core.errors import PlatformUnsupported
    from core.platform import current_adapter

    from tests._host_device_guard import expect_refusal, launch_barrier

    adapter = current_adapter()
    with (
        expect_refusal() as refusals,
        launch_barrier(),
        pytest.raises(PlatformUnsupported, match="Get-Disk"),
    ):
        adapter.enumerate_devices()

    assert all("get-disk" in refusal for refusal in refusals), refusals


def test_vss_shadows_and_trim_likely_ask_for_a_hidden_console(
    tmp_path: Path,
) -> None:
    """vssadmin and fsutil are console-subsystem tools; this packaged
    (console=False) app has no console of its own to give them. Same defect,
    same fix as core.device._sysio.SubprocessRunner - found in the same
    audit, 2026-09-27."""
    import subprocess
    from unittest.mock import patch

    from core.erase._platform.win import WindowsBackend

    target = tmp_path / "file.txt"
    target.write_text("x")
    backend = WindowsBackend()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess([], 0, "", "")
        backend.vss_shadows(target)
    assert mock_run.call_args.kwargs["creationflags"] != 0

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess([], 0, "0\n", "")
        backend.trim_likely(target)
    assert mock_run.call_args.kwargs["creationflags"] != 0
