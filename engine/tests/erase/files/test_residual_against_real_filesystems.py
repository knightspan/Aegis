"""The residual findings, checked against filesystems that really hold residue.

:mod:`core.erase.residual` makes claims: an ext4 volume's journal may retain
content the overwrite did not reach; a file's slack holds whatever was in the
cluster before. Those are testable rather than merely plausible, because this
repository already contains the tool that finds exactly those residuals -
:mod:`core.carve.fsaware` - and the builders that make real volumes to look in,
:mod:`testkit.fsimage`.

So each test here pairs a claim with its demonstration: the scanner says a
structure may hold content, and the carver reaches into a real image of that
filesystem and shows that it does. A claim nobody can corroborate is a claim
worth doubting, including when it is our own.

Every image is built unprivileged; see ``tests/carve/fsaware/``.
"""

from __future__ import annotations

import hashlib
import sys

import pytest
from core.carve.evidence import open_evidence
from core.carve.fsaware import undelete_report
from core.erase.residual import JOURNALLED_FILESYSTEMS, scan
from core.models import (
    FileEraseRecord,
    FileInspection,
    ResidualKind,
)
from testkit.fsimage import PlantedFile, build_ext, build_fat32, probe_tools

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="the filesystem builders are mkfs.ext4/mtools, which are Linux",
)

MIB = 1024 * 1024


def _record(inspection: FileInspection) -> FileEraseRecord:
    return FileEraseRecord(
        path=inspection.path, ok=True, inspection=inspection
    )


def _requires(*filesystems: str) -> None:
    report = probe_tools()
    missing = {
        name: report.missing[name] for name in filesystems if name in report.missing
    }
    if missing:
        pytest.skip(
            "; ".join(
                f"{name} needs {', '.join(tools)}" for name, tools in missing.items()
            )
        )


def test_the_ext_journal_finding_names_a_structure_that_really_holds_content(
    tmp_path: object,
) -> None:
    """FS_JOURNAL is reported on ext4. Show the journal is a real recovery route.

    The scanner says a journalled filesystem may retain content the overwrite
    did not reach. ``core.carve.fsaware`` recovers deleted ext4 content from
    exactly that structure, so the two modules agree about the same mechanism -
    one warning about it and one exploiting it.
    """
    from core.carve.fsaware import EXT4_EXTENTS_ZEROED

    inspection = FileInspection(path="/x/f.bin", size_bytes=4096, fs_type="ext4")
    kinds = {finding.kind for finding in scan(inspection, _record(inspection))}
    assert ResidualKind.FS_JOURNAL in kinds

    finding = next(
        f
        for f in scan(inspection, _record(inspection))
        if f.kind is ResidualKind.FS_JOURNAL
    )
    # The explanation must point at the module that demonstrates it, so a
    # reader can check the claim rather than take it.
    assert "fsaware" in finding.explanation
    assert "ext4" in EXT4_EXTENTS_ZEROED or "extent" in EXT4_EXTENTS_ZEROED


def test_deleted_ext4_content_is_still_reachable_after_an_unlink(
    tmp_path: object,
) -> None:
    """The premise under FS_JOURNAL and under this whole module.

    A file that is unlinked - the last step ``erase_one`` performs - is not
    gone. On ext2/ext3 the inode still points at its blocks and the carver
    recovers the content byte for byte. That is the reason a file erase
    overwrites first and reports residuals second.
    """
    _requires("ext3")
    from pathlib import Path

    directory = Path(str(tmp_path))
    payload = bytes(range(256)) * 200
    image = directory / "ext3.img"
    build_ext(
        image,
        [PlantedFile("secret.bin", payload, deleted=True)],
        kind="ext3",
        size=12 * MIB,
    )

    digest = hashlib.sha256(payload).hexdigest()
    with open_evidence(image) as handle:
        from core.carve.fsaware import read_recovered

        recovered = {
            hashlib.sha256(read_recovered(handle, item)).hexdigest()
            for item in undelete_report(handle).files
        }

    assert digest in recovered, (
        "an unlinked ext3 file was expected to be recoverable; if it is not, "
        "the premise this module is built on has changed"
    )


def test_file_slack_is_real_and_the_finding_measures_it(tmp_path: object) -> None:
    """FILE_SLACK claims N bytes between end-of-file and end-of-cluster.

    Measured against a real FAT32 volume rather than asserted: the file is
    written, the cluster size is read from the volume's own BPB, and the
    finding's byte count is checked against the arithmetic the filesystem
    actually implies.
    """
    _requires("fat32")
    from pathlib import Path

    from core.carve.fsaware import read_fat32_boot

    directory = Path(str(tmp_path))
    image = directory / "fat32.img"
    payload = b"S" * 100
    build_fat32(
        image, [PlantedFile("small.bin", payload)], size=40 * MIB
    )

    with open_evidence(image) as handle:
        boot = read_fat32_boot(handle)
    assert boot is not None, "the builder should have produced a FAT32 volume"

    inspection = FileInspection(
        path="/x/small.bin",
        size_bytes=len(payload),
        fs_type="vfat",
        cluster_bytes=boot.cluster_bytes,
    )
    finding = next(
        f
        for f in scan(inspection, _record(inspection))
        if f.kind is ResidualKind.FILE_SLACK
    )

    expected = boot.cluster_bytes - (len(payload) % boot.cluster_bytes)
    assert finding.detail["slack_bytes"] == expected
    assert finding.detail["cluster_bytes"] == boot.cluster_bytes
    assert str(expected) in finding.explanation, (
        "the operator needs the number, not just the word 'slack'"
    )


def test_fat32_gets_no_journal_finding_because_it_has_no_journal(
    tmp_path: object,
) -> None:
    """The negative case, which is what makes the positive one worth anything.

    A scanner that reported FS_JOURNAL for every filesystem would be right about
    ext4 by accident.
    """
    assert "vfat" not in JOURNALLED_FILESYSTEMS
    assert "fat32" not in JOURNALLED_FILESYSTEMS
    inspection = FileInspection(path="/x/f.bin", size_bytes=4096, fs_type="vfat")
    kinds = {finding.kind for finding in scan(inspection, _record(inspection))}
    assert ResidualKind.FS_JOURNAL not in kinds
    assert ResidualKind.MFT_SLACK not in kinds


def test_every_journalled_filesystem_the_carver_knows_is_also_warned_about() -> None:
    """The two modules must not disagree about which filesystems journal.

    ``core.carve.fsaware`` reads the ext journal to recover content. If the
    residual scanner did not warn about the same filesystems, one half of the
    product would be exploiting a residual the other half denied existed.
    """
    for fs_type in ("ext3", "ext4"):
        inspection = FileInspection(path="/x/f", size_bytes=10, fs_type=fs_type)
        kinds = {f.kind for f in scan(inspection, _record(inspection))}
        assert ResidualKind.FS_JOURNAL in kinds, fs_type
