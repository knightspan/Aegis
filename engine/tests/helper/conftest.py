"""Fixtures for the helper suite.

``short_socket_dir`` exists because an ``AF_UNIX`` path is capped at about
104 bytes on macOS and 108 on Linux, and pytest's ``tmp_path`` under
``/Users/runner/work/...`` or ``/private/var/folders/...`` is longer than that.
A test that binds a socket under ``tmp_path`` therefore fails on the macOS
runner with ``OSError: AF_UNIX path too long`` - which says nothing about the
helper. The directory here is short, per-test and cleaned up.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture
def short_socket_dir() -> Iterator[Path]:
    if sys.platform == "win32":  # pragma: no cover - no AF_UNIX helper there
        pytest.skip("the helper daemon and its Unix socket are POSIX-only")
    directory = Path(tempfile.mkdtemp(prefix="snc-"))
    try:
        yield directory
    finally:
        shutil.rmtree(directory, ignore_errors=True)
