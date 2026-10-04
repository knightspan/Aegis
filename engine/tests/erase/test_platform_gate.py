"""The Linux-only import guard. This module runs on every platform."""

from __future__ import annotations

import importlib
import sys

import pytest
from core.errors import PlatformUnsupported, SanctumError


def test_importing_drive_off_linux_raises_platform_unsupported() -> None:
    if sys.platform == "linux":
        module = importlib.import_module("core.erase.drive")
        assert module.execute is not None
        return

    sys.modules.pop("core.erase.drive", None)
    with pytest.raises(PlatformUnsupported) as excinfo:
        importlib.import_module("core.erase.drive")
    assert sys.platform in str(excinfo.value)


def test_platform_error_is_a_sanctum_error_with_remediation() -> None:
    err = PlatformUnsupported("nope")
    assert isinstance(err, SanctumError)
    assert err.remediation.strip()
    assert "Platform screen" in err.remediation


def test_file_erasure_stays_importable_on_every_platform() -> None:
    module = importlib.import_module("core.erase.files")
    assert module.erase_paths is not None


def test_patterns_and_verify_stay_importable_on_every_platform() -> None:
    assert importlib.import_module("core.erase.patterns").pattern_passes is not None
    assert importlib.import_module("core.erase.verify").verify is not None
