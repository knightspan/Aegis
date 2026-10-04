"""The recorder must not file a Windows 11 run under Windows 10."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "record_platform_validation", ROOT / "scripts" / "record_platform_validation.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_fallback_name_reads_the_build_number_on_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Windows 11 reports release "10"; only the build tells them apart.

    This is the path taken when the project cannot be imported - the package
    job records without installing it - so it must not be the path that files
    a real Windows 11 result under the wrong operating system.
    """
    module = _module()
    monkeypatch.setattr(module.sys, "platform", "win32")
    monkeypatch.setattr(
        module.platform, "win32_ver", lambda: ("10", "10.0.26100", "", "")
    )
    assert module._os_string() == "Windows 11"

    monkeypatch.setattr(
        module.platform, "win32_ver", lambda: ("10", "10.0.19045", "", "")
    )
    assert module._os_string() == "Windows 10"


def test_the_fallback_names_macos_and_linux_the_way_they_name_themselves(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A row that says Darwin names the kernel, not the product."""
    module = _module()
    monkeypatch.setattr(module.sys, "platform", "darwin")
    monkeypatch.setattr(
        module.platform, "mac_ver", lambda: ("14.8.9", ("", "", ""), "")
    )
    assert module._os_string() == "macOS 14.8.9"

    release = tmp_path / "os-release"
    release.write_text('PRETTY_NAME="Ubuntu 24.04.5 LTS"\n', encoding="utf-8")
    monkeypatch.setattr(module.sys, "platform", "linux")
    monkeypatch.setattr(module, "Path", lambda _: release)
    assert module._os_string() == "Ubuntu 24.04.5 LTS"
