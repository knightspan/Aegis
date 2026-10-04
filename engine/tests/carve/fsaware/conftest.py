"""Fixtures for filesystem-aware recovery.

Two gates, and they are deliberately separate so a skip says which one bit:

* **Linux.** ``pytsk3`` runs anywhere, but the filesystem *builders* are
  ``mkfs.ntfs``, ``mtools``, ``debugfs`` and ``mkfs.exfat``, and those are
  Linux userland. There is nothing to test without them.
* **Tooling.** Each filesystem names the tools it needs, so a host missing only
  ``mtools`` skips the FAT32 tests and runs the rest, and the skip reason names
  the tool rather than saying "unavailable".

There is deliberately **no root gate**. Every image is built unprivileged, and
``test_corpus_needs_no_root.py`` exists to make that fail loudly rather than
quietly if it ever stops being true.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from testkit.fsimage import probe_tools
from testkit.generate_corpus import (
    FilesystemCorpus,
    generate_filesystem_corpus,
)

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="the filesystem builders are mkfs.ntfs/mtools/debugfs, which are Linux",
)


def requires(*filesystems: str) -> pytest.MarkDecorator:
    """Skip unless every named filesystem's tooling is installed."""
    report = probe_tools()
    absent = {
        name: report.missing[name] for name in filesystems if name in report.missing
    }
    return pytest.mark.skipif(
        bool(absent),
        reason="; ".join(
            f"{name} needs {', '.join(tools)}" for name, tools in sorted(absent.items())
        )
        or "",
    )


@pytest.fixture(scope="session")
def corpus_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Where the filesystem corpus is built. Once per session; it is not cheap."""
    return tmp_path_factory.mktemp("fs-corpus")


@pytest.fixture(scope="session")
def corpus(corpus_dir: Path) -> FilesystemCorpus:
    """The built corpus and its manifest.

    Session-scoped because building twelve real filesystem images per test
    would dominate the run, and every test here reads them without writing.
    """
    if sys.platform != "linux":  # pragma: no cover - the module is skipped first
        pytest.skip("filesystem builders are Linux-only")
    report = probe_tools()
    if report.missing:
        pytest.skip(f"filesystem tooling missing: {report.reason()}")
    return generate_filesystem_corpus(corpus_dir, seed=0)
