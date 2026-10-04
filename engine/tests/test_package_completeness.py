"""Every platform backend and data file the capability table names ships.

The carve signature table once shipped in no packaged build at all, and
nothing noticed until a real Windows install was driven by hand. These tests
pin the same class of mistake for everything added since: every module the
capability resolver names is importable, is inside a package PyInstaller's
``collect_submodules("core")`` walks, imports nothing the spec excludes, and
every data file it reads is bundled by the spec.
"""

from __future__ import annotations

import ast
import importlib
import importlib.util
import pkgutil
import re
from pathlib import Path

import core
import pytest
from core.platform.capability import IMPLEMENTATIONS, module_present

ROOT = Path(__file__).resolve().parents[1]
SPEC = (ROOT / "packaging" / "sanctum.spec").read_text(encoding="utf-8")

#: Platform backends added by the capability-completion work. Each must ship on
#: every platform: the adapters import them lazily, and a missing one would
#: surface only when the screen that needs it is opened.
BACKENDS = (
    "core.platform.capability",
    "core.device.win.ioctl",
    "core.device.win.native",
    "core.device.win.disk",
    "core.device.win.ata",
    "core.device.win.nvme",
    "core.device.mac.rawdisk",
    "core.carve.win_source",
    "core.carve.mac_source",
    "core.erase.blockclear",
    "core.erase.devicesanitize",
    "core.report.semantics",
    "core.backup",
    "core.restore",
    "core.benchmark",
)


def _walked() -> set[str]:
    """What ``collect_submodules("core")`` finds: every importable submodule."""
    found = {"core"}
    for info in pkgutil.walk_packages(core.__path__, prefix="core."):
        found.add(info.name)
    return found


def _excluded() -> list[str]:
    match = re.search(r"excludes=\[([^\]]*)\]", SPEC)
    assert match, "the spec's excludes list moved"
    return re.findall(r'"([^"]+)"', match.group(1))


@pytest.mark.parametrize("name", BACKENDS)
def test_each_backend_is_collected_by_the_spec(name: str) -> None:
    assert name in _walked(), f"{name} is not under a package collect_submodules walks"
    assert 'collect_submodules("core")' in SPEC


def test_every_module_the_capability_table_names_exists() -> None:
    missing = sorted(
        {
            entry.module
            for entry in IMPLEMENTATIONS.values()
            if entry.state is None and not module_present(entry.module)
        }
    )
    assert not missing, (
        f"the capability table names modules this build lacks: {missing}"
    )


def test_every_capability_module_imports_on_this_host() -> None:
    for entry in IMPLEMENTATIONS.values():
        if entry.state is None and entry.module != "core.erase.drive":
            # core.erase.drive refuses to import off Linux by design.
            importlib.import_module(entry.module)


def test_no_shipped_module_imports_what_the_spec_excludes() -> None:
    excluded = set(_excluded())
    offenders: list[str] = []
    for package in ("core", "api", "helper"):
        for path in (ROOT / package).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                for name in names:
                    if name.split(".")[0] in excluded:
                        offenders.append(f"{path.relative_to(ROOT)} imports {name}")
    assert not offenders, offenders


def test_the_spec_never_excludes_an_application_package() -> None:
    for name in _excluded():
        assert name.split(".")[0] not in {"core", "api", "helper"}, name


def test_the_validation_record_with_physical_runs_is_bundled() -> None:
    assert '"validation_record.json"' in SPEC
    record = ROOT / "core" / "platform" / "validation_record.json"
    import json

    data = json.loads(record.read_text(encoding="utf-8"))
    assert isinstance(data.get("physical_validations"), list)


def test_the_firmware_command_tables_are_plain_constants() -> None:
    """The IOCTL and ATA opcode tables need no data file and no generated code."""
    from core.device.win import ata, ioctl

    assert ioctl.IOCTL_ATA_PASS_THROUGH == 0x0004D02C
    assert ioctl.IOCTL_STORAGE_REINITIALIZE_MEDIA == 0x002D9640
    assert ata.CMD_SANITIZE == 0xB4
    assert set(ata.SANITIZE_NAMES) == {0x0011, 0x0012, 0x0014}


def test_testkit_doubles_are_test_only() -> None:
    """The adapter doubles live in testkit, which the spec excludes."""
    assert "testkit" in _excluded()
    for name in ("testkit.fake_windows", "testkit.fake_macos"):
        assert importlib.util.find_spec(name) is not None
