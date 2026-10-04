"""Prove the corpus builds unprivileged, and name the filesystem if it stops.

A corpus that only builds under ``sudo`` is a corpus that quietly stops being
built. Every developer's run skips it, CI skips it, and the gap is discovered on
the day somebody needs the numbers. So rather than gating these tests on
``euid == 0``, the build runs as whoever is running the suite and this test
fails loudly - naming the filesystem and the error - if any part of it turns out
to need privileges.

This is why :mod:`testkit.fsimage` writes NTFS deletion and the exFAT directory
entries by hand instead of mounting anything: mounting a filesystem needs
``CAP_SYS_ADMIN`` in the initial user namespace, and there is no unprivileged
way around that on Linux.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from testkit.fsimage import (
    PlantedFile,
    build_exfat,
    build_ext,
    build_fat32,
    build_ntfs,
    probe_tools,
)

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="the filesystem builders are mkfs.ntfs/mtools/debugfs, which are Linux",
)

#: Small, so this test stays a privilege check rather than a second corpus run.
_PAYLOAD = bytes(range(256)) * 64


def test_every_filesystem_image_builds_as_an_unprivileged_user(
    tmp_path: Path,
) -> None:
    """Build one image per filesystem and report every one that needed root.

    The assertion is on the *set* of failures, not the first: a run that names
    all three broken filesystems is worth more than one that stops at the first
    and hides the other two.
    """
    if os.geteuid() == 0:
        pytest.skip(
            "running as root, so this test cannot demonstrate anything: it "
            "exists to prove the build needs no privileges, and as root every "
            "build succeeds whether it needs them or not. Re-run as a normal "
            "user."
        )

    report = probe_tools()
    if report.missing:
        pytest.skip(f"filesystem tooling missing: {report.reason()}")

    files = [
        PlantedFile("keep.bin", _PAYLOAD),
        PlantedFile("gone.bin", _PAYLOAD[::-1], deleted=True),
    ]
    builders = {
        "ntfs": lambda path: build_ntfs(path, files),
        "fat32": lambda path: build_fat32(path, files),
        "exfat": lambda path: build_exfat(path, files, contiguous=["gone.bin"]),
        "ext2": lambda path: build_ext(path, files, kind="ext2"),
        "ext3": lambda path: build_ext(path, files, kind="ext3"),
        "ext4": lambda path: build_ext(path, files, kind="ext4"),
    }

    failures: dict[str, str] = {}
    built: list[str] = []
    for filesystem, build in builders.items():
        image = tmp_path / f"{filesystem}.img"
        try:
            build(image)
        except (RuntimeError, OSError, ValueError) as exc:
            failures[filesystem] = f"{type(exc).__name__}: {exc}"
            continue
        if not image.exists() or image.stat().st_size == 0:
            failures[filesystem] = "the builder returned but produced no image"
            continue
        built.append(filesystem)

    assert not failures, (
        "these filesystem images could not be built without root, so the corpus "
        "is not reproducible on a developer machine: "
        + "; ".join(f"{name} ({why})" for name, why in sorted(failures.items()))
    )
    assert set(built) == set(builders), "every filesystem must have been built"


def test_the_full_corpus_fixture_itself_was_built_unprivileged(
    corpus: object, corpus_dir: Path
) -> None:
    """The real corpus, not a reduced stand-in, and every image present.

    The test above builds one small image per filesystem. This one asserts that
    the corpus the other tests actually measure against - damaged variants,
    multi-partition image and all - came out of the same unprivileged run.
    """
    if os.geteuid() == 0:
        pytest.skip("running as root; this test cannot demonstrate anything")

    from testkit.generate_corpus import FilesystemCorpus

    assert isinstance(corpus, FilesystemCorpus)
    missing = [name for name in corpus.images if not (corpus_dir / name).exists()]
    assert not missing, f"the corpus is incomplete: {', '.join(missing)}"
    assert len(corpus.images) >= 12
    for name in corpus.images:
        assert (corpus_dir / name).stat().st_size > 0, f"{name} is empty"
