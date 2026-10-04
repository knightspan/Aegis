"""The residual scanner is the deliverable. Test every kind it claims to detect.

Pure-function tests: no filesystem, no clock. That is the payoff of
:func:`core.erase.residual.scan` taking only an inspection and a record - every
branch is reachable from a constructed model, including the ones that need a
btrfs volume with snapshots or an SSD that reports discard.
"""

from __future__ import annotations

from pathlib import Path

from core.erase.residual import IMPLEMENTED_KINDS, scan
from core.models import (
    FILE_PATH_KINDS,
    FileEraseRecord,
    FileInspection,
    ResidualKind,
    Severity,
)


def _record(inspection: FileInspection, **overrides: object) -> FileEraseRecord:
    base: dict[str, object] = {
        "path": inspection.path,
        "ok": True,
        "inspection": inspection,
    }
    base.update(overrides)
    return FileEraseRecord.model_validate(base)


def _kinds(inspection: FileInspection, **overrides: object) -> set[ResidualKind]:
    return {f.kind for f in scan(inspection, _record(inspection, **overrides))}


def _find(
    inspection: FileInspection, kind: ResidualKind, **overrides: object
) -> object:
    return next(
        f
        for f in scan(inspection, _record(inspection, **overrides))
        if f.kind is kind
    )


# --------------------------------------------------------------------------
# Full-content survival: HIGH
# --------------------------------------------------------------------------


def test_resident_data_is_high_and_not_addressable() -> None:
    inspection = FileInspection(
        path="x", size_bytes=200, is_resident=True, fs_type="NTFS"
    )
    resident = _find(inspection, ResidualKind.RESIDENT_MFT_DATA)
    assert resident.severity is Severity.HIGH  # type: ignore[attr-defined]
    assert resident.addressable is False  # type: ignore[attr-defined]
    assert "$MFT" in resident.explanation  # type: ignore[attr-defined]


def test_hardlink_is_high_addressable_and_counts_the_other_names() -> None:
    inspection = FileInspection(path="x", size_bytes=10, hardlink_count=3)
    finding = _find(inspection, ResidualKind.HARDLINK_SURVIVES)
    assert finding.severity is Severity.HIGH  # type: ignore[attr-defined]
    assert finding.addressable is True  # type: ignore[attr-defined]
    assert finding.detail["hardlink_count"] == 3  # type: ignore[attr-defined]
    assert finding.detail["other_names"] == 2  # type: ignore[attr-defined]


def test_breaking_a_hardlink_still_reports_it_and_says_it_was_broken() -> None:
    """Destroying the other names' data does not excuse not saying so."""
    inspection = FileInspection(path="x", size_bytes=10, hardlink_count=2)
    finding = _find(
        inspection, ResidualKind.HARDLINK_SURVIVES, bytes_overwritten=4096
    )
    assert finding.severity is Severity.HIGH  # type: ignore[attr-defined]
    assert finding.detail["overwritten"] is True  # type: ignore[attr-defined]
    assert "break_hardlinks" in finding.explanation  # type: ignore[attr-defined]


def test_snapshots_are_named_not_counted() -> None:
    """An operator has to delete them, so the report has to say which."""
    inspection = FileInspection(
        path="x", size_bytes=10, fs_type="btrfs", cow_snapshots=["snap-1", "snap-2"]
    )
    finding = _find(inspection, ResidualKind.COW_SNAPSHOT)
    assert "snap-1" in finding.explanation  # type: ignore[attr-defined]
    assert "snap-2" in finding.explanation  # type: ignore[attr-defined]
    assert finding.severity is Severity.HIGH  # type: ignore[attr-defined]
    assert finding.addressable is True  # type: ignore[attr-defined]


def test_shadow_copies_are_named_too() -> None:
    inspection = FileInspection(
        path="x", size_bytes=10, fs_type="NTFS", vss_shadow_ids=["{abc-123}"]
    )
    finding = _find(inspection, ResidualKind.VSS_SHADOW_COPY)
    assert "{abc-123}" in finding.explanation  # type: ignore[attr-defined]
    assert finding.addressable is True  # type: ignore[attr-defined]


def test_trim_is_high_because_the_whole_content_may_survive() -> None:
    """Not MEDIUM. On flash the overwrite may have missed the page entirely."""
    finding = _find(
        FileInspection(path="x", size_bytes=10, trim_likely=True),
        ResidualKind.TRIM_REMAP,
    )
    assert finding.severity is Severity.HIGH  # type: ignore[attr-defined]
    assert finding.addressable is False  # type: ignore[attr-defined]


def test_sync_directory_is_flagged_and_is_addressable() -> None:
    inspection = FileInspection(
        path="/home/x/OneDrive/secret.txt", size_bytes=10, in_sync_directory=True
    )
    finding = _find(inspection, ResidualKind.BACKUP_COPY_LIKELY)
    assert finding.addressable is True  # type: ignore[attr-defined]
    assert finding.severity is Severity.HIGH  # type: ignore[attr-defined]


# --------------------------------------------------------------------------
# Unknown is not clean
# --------------------------------------------------------------------------


def test_unknown_snapshot_state_produces_no_finding() -> None:
    """``None`` is not ``[]``. An unknown must not be scored as clean.

    It must not be scored as *dirty* either - inventing a snapshot finding for
    every volume nobody could query would train an operator to ignore the row.
    The unknown travels as a limitation on the inspection instead.
    """
    assert ResidualKind.COW_SNAPSHOT not in _kinds(
        FileInspection(path="x", size_bytes=10, cow_snapshots=None)
    )
    assert ResidualKind.VSS_SHADOW_COPY not in _kinds(
        FileInspection(path="x", size_bytes=10, vss_shadow_ids=None)
    )
    assert ResidualKind.TRIM_REMAP not in _kinds(
        FileInspection(path="x", size_bytes=10, trim_likely=None)
    )
    assert ResidualKind.RESIDENT_MFT_DATA not in _kinds(
        FileInspection(path="x", size_bytes=10, is_resident=None)
    )


def test_an_explicit_negative_produces_no_finding_either() -> None:
    assert ResidualKind.COW_SNAPSHOT not in _kinds(
        FileInspection(path="x", size_bytes=10, cow_snapshots=[])
    )
    assert ResidualKind.TRIM_REMAP not in _kinds(
        FileInspection(path="x", size_bytes=10, trim_likely=False)
    )


# --------------------------------------------------------------------------
# Streams
# --------------------------------------------------------------------------


def test_an_overwritten_stream_is_medium_and_an_untouched_one_is_high() -> None:
    inspection = FileInspection(
        path="x", size_bytes=10, alt_data_streams=[":hidden:$DATA"], fs_type="NTFS"
    )
    untouched = _find(inspection, ResidualKind.ALT_DATA_STREAM)
    assert untouched.severity is Severity.HIGH  # type: ignore[attr-defined]
    assert untouched.addressable is True  # type: ignore[attr-defined]

    cleared = _find(
        inspection,
        ResidualKind.ALT_DATA_STREAM,
        streams_removed=[":hidden:$DATA"],
    )
    assert cleared.severity is Severity.MEDIUM  # type: ignore[attr-defined]


# --------------------------------------------------------------------------
# Per-filesystem structures
# --------------------------------------------------------------------------


def test_ntfs_always_reports_journal_index_and_mft_slack() -> None:
    kinds = _kinds(FileInspection(path="x", size_bytes=4096, fs_type="NTFS"))
    assert ResidualKind.FS_JOURNAL in kinds
    assert ResidualKind.USN_JOURNAL in kinds
    assert ResidualKind.MFT_SLACK in kinds
    assert ResidualKind.INDEX_SLACK in kinds


def test_ext4_reports_the_journal_but_not_the_ntfs_structures() -> None:
    kinds = _kinds(FileInspection(path="x", size_bytes=4096, fs_type="ext4"))
    assert ResidualKind.FS_JOURNAL in kinds
    assert ResidualKind.USN_JOURNAL not in kinds
    assert ResidualKind.MFT_SLACK not in kinds
    assert ResidualKind.INDEX_SLACK not in kinds


def test_fat32_has_no_journal_at_all() -> None:
    """FAT keeps no journal, so claiming one would be inventing a residual."""
    kinds = _kinds(FileInspection(path="x", size_bytes=4096, fs_type="vfat"))
    assert ResidualKind.FS_JOURNAL not in kinds


def test_sparse_compressed_and_encrypted() -> None:
    assert ResidualKind.SPARSE_UNWRITTEN in _kinds(
        FileInspection(path="x", size_bytes=10, is_sparse=True)
    )
    assert ResidualKind.COMPRESSED_REALLOC in _kinds(
        FileInspection(path="x", size_bytes=10, is_compressed=True)
    )
    assert ResidualKind.ENCRYPTED_EFS in _kinds(
        FileInspection(path="x", size_bytes=10, is_encrypted=True)
    )


def test_file_slack_only_when_there_is_slack() -> None:
    assert ResidualKind.FILE_SLACK in _kinds(
        FileInspection(path="x", size_bytes=100, cluster_bytes=4096)
    )
    assert ResidualKind.FILE_SLACK not in _kinds(
        FileInspection(path="x", size_bytes=8192, cluster_bytes=4096)
    )
    # Unknown cluster size: no finding, because there is nothing to report.
    assert ResidualKind.FILE_SLACK not in _kinds(
        FileInspection(path="x", size_bytes=100, cluster_bytes=0)
    )


def test_the_slack_finding_carries_the_byte_count() -> None:
    finding = _find(
        FileInspection(path="x", size_bytes=100, cluster_bytes=4096),
        ResidualKind.FILE_SLACK,
    )
    assert finding.detail["slack_bytes"] == 3996  # type: ignore[attr-defined]


# --------------------------------------------------------------------------
# Ordering and honesty of the kind list
# --------------------------------------------------------------------------


def test_findings_come_back_worst_first() -> None:
    """An operator reads the top of the list. HIGH belongs there."""
    inspection = FileInspection(
        path="x",
        size_bytes=100,
        fs_type="NTFS",
        cluster_bytes=4096,
        hardlink_count=2,
        is_resident=True,
    )
    severities = [f.severity for f in scan(inspection, _record(inspection))]
    order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
    assert severities == sorted(severities, key=lambda item: order[item])
    assert severities[0] is Severity.HIGH


def test_scan_is_pure_and_deterministic() -> None:
    """Same inputs, same findings - so a report can be re-derived from a ledger."""
    inspection = FileInspection(
        path="x", size_bytes=100, fs_type="NTFS", cluster_bytes=4096, hardlink_count=2
    )
    first = scan(inspection, _record(inspection))
    second = scan(inspection, _record(inspection))
    assert [f.model_dump() for f in first] == [f.model_dump() for f in second]


def test_every_implemented_kind_is_reachable_from_the_source() -> None:
    """IMPLEMENTED_KINDS must be the truth, not an aspiration.

    The commit message lists what is not detected. This makes that list
    verifiable rather than a claim: a kind named in IMPLEMENTED_KINDS but never
    constructed in the module fails here.
    """
    source = Path("core/erase/residual.py").read_text(encoding="utf-8")
    for kind in IMPLEMENTED_KINDS:
        assert f"ResidualKind.{kind.value}" in source, (
            f"{kind.value} is claimed as implemented but never constructed"
        )
    for kind in set(ResidualKind) - IMPLEMENTED_KINDS:
        assert f"ResidualKind.{kind.value}" not in source, (
            f"{kind.value} is constructed but not claimed as implemented"
        )


def test_every_kind_is_reachable_from_some_inspection() -> None:
    """Stronger than reading the source: each kind is actually produced.

    A detector guarded by a condition that can never be true would satisfy the
    source-text test above and still never fire.
    """
    cases: dict[ResidualKind, FileInspection] = {
        ResidualKind.RESIDENT_MFT_DATA: FileInspection(
            path="x", size_bytes=200, is_resident=True
        ),
        ResidualKind.ALT_DATA_STREAM: FileInspection(
            path="x", size_bytes=10, alt_data_streams=[":s:$DATA"]
        ),
        ResidualKind.HARDLINK_SURVIVES: FileInspection(
            path="x", size_bytes=10, hardlink_count=2
        ),
        ResidualKind.COW_SNAPSHOT: FileInspection(
            path="x", size_bytes=10, fs_type="btrfs", cow_snapshots=["s"]
        ),
        ResidualKind.VSS_SHADOW_COPY: FileInspection(
            path="x", size_bytes=10, vss_shadow_ids=["{id}"]
        ),
        ResidualKind.ENCRYPTED_EFS: FileInspection(
            path="x", size_bytes=10, is_encrypted=True
        ),
        ResidualKind.COMPRESSED_REALLOC: FileInspection(
            path="x", size_bytes=10, is_compressed=True
        ),
        ResidualKind.SPARSE_UNWRITTEN: FileInspection(
            path="x", size_bytes=10, is_sparse=True
        ),
        ResidualKind.TRIM_REMAP: FileInspection(
            path="x", size_bytes=10, trim_likely=True
        ),
        ResidualKind.BACKUP_COPY_LIKELY: FileInspection(
            path="/x/Dropbox/f", size_bytes=10, in_sync_directory=True
        ),
        ResidualKind.FS_JOURNAL: FileInspection(
            path="x", size_bytes=10, fs_type="ext4"
        ),
        ResidualKind.FILE_SLACK: FileInspection(
            path="x", size_bytes=100, cluster_bytes=4096
        ),
        ResidualKind.MFT_SLACK: FileInspection(
            path="x", size_bytes=10, fs_type="NTFS"
        ),
        ResidualKind.USN_JOURNAL: FileInspection(
            path="x", size_bytes=10, fs_type="NTFS"
        ),
        ResidualKind.INDEX_SLACK: FileInspection(
            path="x", size_bytes=10, fs_type="NTFS"
        ),
    }
    assert set(cases) == FILE_PATH_KINDS, "a file-path kind has no reachability case"
    for kind, inspection in cases.items():
        assert kind in _kinds(inspection), f"{kind.value} was never produced"


def test_every_explanation_is_a_sentence_not_a_label() -> None:
    """The explanation is what an operator acts on, so it has to be prose."""
    inspection = FileInspection(
        path="x",
        size_bytes=100,
        fs_type="NTFS",
        cluster_bytes=4096,
        hardlink_count=2,
        is_resident=True,
        trim_likely=True,
    )
    for finding in scan(inspection, _record(inspection)):
        assert finding.explanation.endswith("."), finding.kind
        assert len(finding.explanation.split()) >= 12, finding.kind
