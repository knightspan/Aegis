"""What this erase could not guarantee, enumerated.

**This module is the deliverable.** Overwriting a file through the filesystem
does not reliably destroy it: journals, copy-on-write, resident data, slack,
snapshots and TRIM all keep copies the OS will not hand back. A tool that
reports "shredded, unrecoverable" is lying. A tool that reports "overwrote 3
extents, the ext4 journal may retain content, and 2 snapshots still reference
the old extents" is evidence.

:func:`scan` is a **pure function** of the inspection and the erase record. No
I/O, no clock, no randomness. Three things follow from that, and all three
matter:

* every branch is directly testable without a filesystem;
* the findings in a report can be reproduced from the ledgered inputs alone, by
  someone who was not there;
* it runs identically in a pool worker and in the parent.

Severity is derived, never guessed:

* ``HIGH``   -- the full content plausibly survives.
* ``MEDIUM`` -- fragments or metadata survive.
* ``LOW``    -- only filenames survive.

**Unknown is not clean.** Every condition below tests for an explicit positive.
``cow_snapshots is None`` means nobody could enumerate snapshots, and it
produces no finding here - the *limitation* carries it instead. Treating an
unknown as absent is how a report ends up quietly reassuring.
"""

from __future__ import annotations

from core.models import (
    FILE_PATH_KINDS,
    FileEraseRecord,
    FileInspection,
    ResidualFinding,
    ResidualKind,
    Severity,
)

__all__ = [
    "scan",
    "IMPLEMENTED_KINDS",
    "JOURNALLED_FILESYSTEMS",
    "COW_FILESYSTEMS",
    "severity_rank",
]

#: Filesystems that write metadata, and sometimes data, to a journal before the
#: main structures. Content that passed through the journal can outlive an
#: overwrite of the file's own blocks - which is measurable: the ext4 journal
#: scan in ``core.carve.fsaware`` recovers exactly this.
JOURNALLED_FILESYSTEMS = frozenset(
    {"ntfs", "ext3", "ext4", "xfs", "jfs", "reiserfs", "ocfs2"}
)

#: Filesystems that redirect a write to newly allocated blocks rather than
#: overwriting in place. On these the overwrite never touched the original
#: blocks at all, whatever the write call returned.
COW_FILESYSTEMS = frozenset({"btrfs", "zfs", "apfs", "refs", "bcachefs", "nilfs2"})

_SEVERITY_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}


def severity_rank(severity: Severity) -> int:
    """Sort key: HIGH first, because that is what an operator must read first."""
    return _SEVERITY_ORDER[severity]


# --------------------------------------------------------------------------
# One detector per kind. Each returns a finding or None.
# --------------------------------------------------------------------------


def _resident(
    inspection: FileInspection, record: FileEraseRecord
) -> ResidualFinding | None:
    if inspection.is_resident is not True:
        return None
    return ResidualFinding(
        kind=ResidualKind.RESIDENT_MFT_DATA,
        severity=Severity.HIGH,
        explanation=(
            f"{inspection.path} stored its {inspection.size_bytes} bytes of "
            "content resident inside a filesystem metadata record - the $MFT "
            "record on NTFS, the inode on an ext4 volume with inline_data. "
            "Writing through the file handle reaches data blocks, and this "
            "file had none, so the original bytes are still in that record. "
            "Nothing short of overwriting the metadata record itself removes "
            "them, and no unprivileged interface exposes it."
        ),
        addressable=False,
        detail={"size_bytes": inspection.size_bytes, "fs_type": inspection.fs_type},
    )


def _alt_streams(
    inspection: FileInspection, record: FileEraseRecord
) -> ResidualFinding | None:
    if not inspection.alt_data_streams:
        return None
    untouched = [
        name
        for name in inspection.alt_data_streams
        if name not in record.streams_removed
    ]
    if untouched:
        return ResidualFinding(
            kind=ResidualKind.ALT_DATA_STREAM,
            severity=Severity.HIGH,
            explanation=(
                f"{inspection.path} carries {len(inspection.alt_data_streams)} "
                f"alternate data stream(s), and {len(untouched)} of them were "
                f"not overwritten: {', '.join(untouched)}. An alternate stream "
                "holds arbitrary content and is invisible to ordinary tools, so "
                "the file's real payload may be there rather than in the main "
                "stream."
            ),
            addressable=True,
            detail={
                "streams": list(inspection.alt_data_streams),
                "untouched": untouched,
            },
        )
    return ResidualFinding(
        kind=ResidualKind.ALT_DATA_STREAM,
        severity=Severity.MEDIUM,
        explanation=(
            f"{inspection.path} carried "
            f"{len(inspection.alt_data_streams)} alternate data stream(s) "
            f"({', '.join(inspection.alt_data_streams)}); each was overwritten "
            "and removed. What survives is the same as for the main stream: "
            "whatever the journal and the slack retained."
        ),
        addressable=False,
        detail={"streams": list(inspection.alt_data_streams)},
    )


def _hardlink(
    inspection: FileInspection, record: FileEraseRecord
) -> ResidualFinding | None:
    if inspection.hardlink_count <= 1:
        return None
    others = inspection.hardlink_count - 1
    overwritten = record.bytes_overwritten > 0
    return ResidualFinding(
        kind=ResidualKind.HARDLINK_SURVIVES,
        severity=Severity.HIGH,
        explanation=(
            f"{inspection.path} had {inspection.hardlink_count} hard links, so "
            f"the same inode is reachable under {others} other name(s) this "
            "erase was not given. "
            + (
                "The data was overwritten anyway because break_hardlinks was "
                "set, which destroyed the content under those other names too."
                if overwritten
                else "Only this name was unlinked; the content is intact and "
                "readable under the other name(s). Find them with `find "
                "-samefile` or `fsutil hardlink list` and erase each one."
            )
        ),
        addressable=True,
        detail={
            "hardlink_count": inspection.hardlink_count,
            "other_names": others,
            "overwritten": overwritten,
        },
    )


def _cow_snapshot(
    inspection: FileInspection, record: FileEraseRecord
) -> ResidualFinding | None:
    # `is None` is unknown and must not be scored. Only a non-empty list is a
    # positive observation.
    if not inspection.cow_snapshots:
        return None
    names = ", ".join(inspection.cow_snapshots)
    return ResidualFinding(
        kind=ResidualKind.COW_SNAPSHOT,
        severity=Severity.HIGH,
        explanation=(
            f"{inspection.fs_type or 'This filesystem'} is copy-on-write and "
            f"{len(inspection.cow_snapshots)} snapshot(s) exist: {names}. A "
            "copy-on-write overwrite is written to newly allocated blocks, so "
            "the original blocks were never touched and each snapshot still "
            "references them in full. Delete the snapshots to address this; "
            "until then the file's entire content survives."
        ),
        addressable=True,
        detail={"snapshots": list(inspection.cow_snapshots)},
    )


def _vss(
    inspection: FileInspection, record: FileEraseRecord
) -> ResidualFinding | None:
    if not inspection.vss_shadow_ids:
        return None
    ids = ", ".join(inspection.vss_shadow_ids)
    return ResidualFinding(
        kind=ResidualKind.VSS_SHADOW_COPY,
        severity=Severity.HIGH,
        explanation=(
            f"This volume holds {len(inspection.vss_shadow_ids)} Volume Shadow "
            f"Copy snapshot(s): {ids}. Each preserves the blocks this file "
            "occupied at the time it was taken, so the full content is "
            "recoverable from any of them. Remove them with `vssadmin delete "
            "shadows` from an elevated prompt."
        ),
        addressable=True,
        detail={"shadow_ids": list(inspection.vss_shadow_ids)},
    )


def _encrypted(
    inspection: FileInspection, record: FileEraseRecord
) -> ResidualFinding | None:
    if inspection.is_encrypted is not True:
        return None
    return ResidualFinding(
        kind=ResidualKind.ENCRYPTED_EFS,
        severity=Severity.HIGH,
        explanation=(
            f"{inspection.path} was encrypted at the filesystem level (EFS on "
            "NTFS, fscrypt on ext4). Writing through the handle re-encrypts the "
            "overwrite pattern and stores it somewhere the driver chooses, "
            "which need not be where the original ciphertext sits. The "
            "original ciphertext blocks may therefore be intact, and they are "
            "readable by anyone holding the key."
        ),
        addressable=False,
        detail={"fs_type": inspection.fs_type},
    )


def _compressed(
    inspection: FileInspection, record: FileEraseRecord
) -> ResidualFinding | None:
    if inspection.is_compressed is not True:
        return None
    return ResidualFinding(
        kind=ResidualKind.COMPRESSED_REALLOC,
        severity=Severity.HIGH,
        explanation=(
            f"{inspection.path} was stored compressed. The overwrite pattern "
            "compresses to a different size than the original content, so the "
            "filesystem reallocated the file's clusters rather than writing "
            "over them in place. The clusters holding the original compressed "
            "data were released without being overwritten."
        ),
        addressable=False,
        detail={"fs_type": inspection.fs_type},
    )


def _sparse(
    inspection: FileInspection, record: FileEraseRecord
) -> ResidualFinding | None:
    if inspection.is_sparse is not True:
        return None
    return ResidualFinding(
        kind=ResidualKind.SPARSE_UNWRITTEN,
        severity=Severity.MEDIUM,
        explanation=(
            f"{inspection.path} is sparse: parts of its logical length were "
            "never allocated on the volume. Writing the overwrite pattern "
            "across the whole logical length allocates fresh blocks for those "
            "holes rather than overwriting anything, so those regions destroy "
            "nothing - while the blocks the file did once own, if it shrank, "
            "were released unwritten."
        ),
        addressable=False,
        detail={"size_bytes": inspection.size_bytes},
    )


def _trim(
    inspection: FileInspection, record: FileEraseRecord
) -> ResidualFinding | None:
    if inspection.trim_likely is not True:
        return None
    return ResidualFinding(
        kind=ResidualKind.TRIM_REMAP,
        # HIGH, not MEDIUM: on flash the overwrite may have landed on a
        # different physical page entirely, leaving the *entire* original
        # content readable by firmware or a chip-off. That is full-content
        # survival, which is what HIGH means.
        severity=Severity.HIGH,
        explanation=(
            "The volume holding this file is on flash media that reports "
            "discard support. A flash translation layer writes to a freshly "
            "erased page and remaps the logical address, so the overwrite very "
            "likely did not land on the physical page holding the original "
            "content. That page is not host-addressable but remains readable by "
            "the controller or by a chip-off. Only a firmware sanitize or a "
            "cryptographic erase of the whole device reaches it - see "
            "core.erase.drive."
        ),
        addressable=False,
        detail={"fs_type": inspection.fs_type},
    )


def _backup_copy(
    inspection: FileInspection, record: FileEraseRecord
) -> ResidualFinding | None:
    if not inspection.in_sync_directory:
        return None
    return ResidualFinding(
        kind=ResidualKind.BACKUP_COPY_LIKELY,
        severity=Severity.HIGH,
        explanation=(
            f"{inspection.path} lies under a directory a cloud-sync client "
            "mirrors. The provider holds at least one copy and its version "
            "history may hold several earlier ones. Erasing the local file "
            "removes none of them, and on most providers the deletion itself "
            "syncs as a new version rather than as a destruction. Delete the "
            "file and its version history through the provider."
        ),
        addressable=True,
        detail={"path": inspection.path},
    )


def _fs_journal(
    inspection: FileInspection, record: FileEraseRecord
) -> ResidualFinding | None:
    if inspection.fs_type.lower() not in JOURNALLED_FILESYSTEMS:
        return None
    return ResidualFinding(
        kind=ResidualKind.FS_JOURNAL,
        severity=Severity.MEDIUM,
        explanation=(
            f"{inspection.fs_type} journals its metadata, and in data=journal "
            "mode its data too. Blocks that passed through the journal are not "
            "reached by writing through the file handle, and the journal is a "
            "circular buffer that keeps them until it wraps. Sanctum's own "
            "carver recovers deleted ext4 content from exactly this structure "
            "(core.carve.fsaware), so this is a demonstrated recovery route "
            "rather than a theoretical one."
        ),
        addressable=False,
        detail={"fs_type": inspection.fs_type},
    )


def _file_slack(
    inspection: FileInspection, record: FileEraseRecord
) -> ResidualFinding | None:
    if inspection.slack_bytes <= 0:
        return None
    return ResidualFinding(
        kind=ResidualKind.FILE_SLACK,
        severity=Severity.MEDIUM,
        explanation=(
            f"{inspection.size_bytes} bytes occupy whole "
            f"{inspection.cluster_bytes}-byte clusters, leaving "
            f"{inspection.slack_bytes} bytes of slack between end-of-file and "
            "end-of-cluster. A write through the file handle stops at the file "
            "length and cannot reach slack, which still holds whatever "
            "occupied those clusters before."
        ),
        addressable=False,
        detail={
            "slack_bytes": inspection.slack_bytes,
            "cluster_bytes": inspection.cluster_bytes,
        },
    )


def _mft_slack(
    inspection: FileInspection, record: FileEraseRecord
) -> ResidualFinding | None:
    if inspection.fs_type.lower() != "ntfs":
        return None
    return ResidualFinding(
        kind=ResidualKind.MFT_SLACK,
        severity=Severity.MEDIUM,
        explanation=(
            "The file's $MFT record is 1024 bytes and is not zeroed when the "
            "record is freed; it is marked unused and reused later. Until then "
            "the record retains the file's attributes, and for a file that was "
            "once small enough, its resident content."
        ),
        addressable=False,
        detail={"fs_type": inspection.fs_type},
    )


def _usn_journal(
    inspection: FileInspection, record: FileEraseRecord
) -> ResidualFinding | None:
    if inspection.fs_type.lower() != "ntfs":
        return None
    return ResidualFinding(
        kind=ResidualKind.USN_JOURNAL,
        # LOW: the USN journal records that a file changed and what it was
        # called. It does not record content.
        severity=Severity.LOW,
        explanation=(
            "NTFS records every change to this file in the $UsnJrnl change "
            "journal, including its name and the fact of its deletion. No "
            "content is stored there, but the filename and the timeline "
            "survive. Delete the journal with `fsutil usn deletejournal` if "
            "the name itself is sensitive."
        ),
        addressable=True,
        detail={"fs_type": inspection.fs_type},
    )


def _index_slack(
    inspection: FileInspection, record: FileEraseRecord
) -> ResidualFinding | None:
    if inspection.fs_type.lower() != "ntfs":
        return None
    return ResidualFinding(
        kind=ResidualKind.INDEX_SLACK,
        severity=Severity.LOW,
        explanation=(
            "Removing this file's entry from its parent directory's $I30 index "
            "shrinks the index's used length and leaves the old entry bytes in "
            "the slack beyond it. The filename, its recorded size and its MAC "
            "timestamps survive there. Sanctum's own carver reads exactly this "
            "(core.carve.fsaware), which is why the rename chain runs first: "
            "the name left in slack is then a random one."
        ),
        addressable=False,
        detail={"fs_type": inspection.fs_type},
    )


#: Every detector, in a fixed order so the output is deterministic.
_DETECTORS = (
    _resident,
    _alt_streams,
    _hardlink,
    _cow_snapshot,
    _vss,
    _encrypted,
    _compressed,
    _sparse,
    _trim,
    _backup_copy,
    _fs_journal,
    _file_slack,
    _mft_slack,
    _usn_journal,
    _index_slack,
)

#: The kinds this module actually detects. Asserted against the source by a
#: test, so it is the truth rather than an aspiration. Drive-path kinds are
#: excluded: this module inspects a filesystem, and what a disk controller did
#: is not visible from one.
IMPLEMENTED_KINDS: frozenset[ResidualKind] = FILE_PATH_KINDS


def scan(
    inspection: FileInspection, record: FileEraseRecord
) -> list[ResidualFinding]:
    """Every residual this erase left, highest severity first.

    Pure: the same inputs always give the same findings, so a report's
    conclusions can be re-derived from the ledgered inspection and record by
    someone who was not present for the erase.
    """
    found = [
        finding
        for detect in _DETECTORS
        if (finding := detect(inspection, record)) is not None
    ]
    return sorted(found, key=lambda item: severity_rank(item.severity))
