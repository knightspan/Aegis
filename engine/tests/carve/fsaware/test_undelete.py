"""Filesystem-aware recovery, measured against a corpus with known contents.

Each test states what its filesystem is actually capable of, which is not the
same thing on any two of them. The ext4 test asserts that recovery is *poor*,
and that is not a lowered bar: it is the finding, and a test that let ext4 look
like NTFS would be hiding it.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from core.carve.evidence import open_evidence
from core.carve.fsaware import (
    EXFAT_NO_FAT_CHAIN,
    EXT4_EXTENTS_ZEROED,
    FAT_CHAIN_LOST,
    NTFS_NAME_ONLY,
    RecoveredFile,
    UndeleteReport,
    read_recovered,
    undelete_report,
)
from core.carve.score import HIGH_BUCKET_FLOOR_BP, score_candidate
from testkit.generate_corpus import FilesystemCorpus

from .conftest import requires


def _report(corpus_dir: Path, image: str) -> tuple[UndeleteReport, dict[str, bytes]]:
    """Run undelete over one image and return the report plus recovered bytes."""
    with open_evidence(corpus_dir / image) as handle:
        report = undelete_report(handle)
        content = {
            f"{item.candidate.original_name}@{item.candidate.offset}": read_recovered(
                handle, item
            )
            for item in report.files
        }
    return report, content


def _digests(corpus_dir: Path, image: str) -> set[str]:
    with open_evidence(corpus_dir / image) as handle:
        return {
            hashlib.sha256(read_recovered(handle, item)).hexdigest()
            for item in undelete_report(handle).files
        }


def _named(report: UndeleteReport, name: str) -> RecoveredFile:
    matches = [item for item in report.files if item.candidate.original_name == name]
    assert matches, f"{name} was not recovered at all; got {_names(report)}"
    return matches[0]


def _names(report: UndeleteReport) -> list[str | None]:
    return [item.candidate.original_name for item in report.files]


# --------------------------------------------------------------------------
# 1. NTFS
# --------------------------------------------------------------------------


@requires("ntfs")
def test_ntfs_recovers_every_deleted_file_byte_identical(
    corpus: FilesystemCorpus, corpus_dir: Path
) -> None:
    """The demo case. NTFS keeps the run list, so recovery is exact, not close.

    Eight of twenty files are deleted and all eight must come back byte for
    byte. Anything less than byte-identical is a file that does not open, so
    the assertion is on SHA-256 and nothing softer.
    """
    expected = {
        item.sha256
        for item in corpus.for_filesystem("ntfs")
        if item.image == "ntfs.img" and item.recoverable
    }
    assert len(expected) == 8, "the corpus should delete eight distinct NTFS files"
    assert expected <= _digests(corpus_dir, "ntfs.img")


@requires("ntfs")
def test_ntfs_recovers_the_original_names_not_just_the_bytes(
    corpus: FilesystemCorpus, corpus_dir: Path
) -> None:
    """A name is most of what makes undelete better than carving.

    NTFS removes the directory entry on unlink, so the name has to come from
    the record's own ``$FILE_NAME`` attribute. Recovering content without it
    would leave the pipeline no better off than the signature carver.
    """
    report, _ = _report(corpus_dir, "ntfs.img")
    deleted = {
        item.name
        for item in corpus.for_filesystem("ntfs")
        if item.image == "ntfs.img" and item.deleted
    }
    assert deleted <= set(_names(report))
    for item in report.files:
        assert item.candidate.source == "fs_metadata"
        assert item.candidate.fs_type == "ntfs"


# --------------------------------------------------------------------------
# 2. NTFS $I30 index slack
# --------------------------------------------------------------------------


@requires("ntfs")
def test_a_reused_mft_record_yields_a_name_from_index_slack_and_no_content(
    corpus: FilesystemCorpus, corpus_dir: Path
) -> None:
    """A name with nothing behind it is still evidence - and must not score HIGH.

    When an MFT record is reused, the deleted file's name can survive in the
    parent directory's ``$I30`` slack while its content is gone. Reporting the
    name is right. Reporting it confidently would be wrong: nothing about the
    content was recovered, so the candidate has to land below HIGH on its own
    merits rather than by being filtered out later.
    """
    reused = next(
        item
        for item in corpus.for_filesystem("ntfs")
        if item.image == "ntfs-reused.img" and "reused" in item.note
    )
    report, content = _report(corpus_dir, "ntfs-reused.img")
    recovered = _named(report, reused.name)

    assert recovered.extents == (), "a reused record can yield no content"
    assert content[f"{reused.name}@{recovered.candidate.offset}"] == b""
    assert NTFS_NAME_ONLY in recovered.candidate.validation_detail
    assert recovered.candidate.length == reused.size, (
        "the recorded size survives in the index entry even when the bytes do not"
    )

    scored = score_candidate(recovered.candidate, data=b"")
    assert scored.confidence_bp < HIGH_BUCKET_FLOOR_BP, (
        f"a name with no content scored {scored.confidence_bp} bp, at or above "
        f"the HIGH floor of {HIGH_BUCKET_FLOOR_BP}"
    )
    assert scored.bucket != "HIGH"


# --------------------------------------------------------------------------
# 3 and 4. FAT32
# --------------------------------------------------------------------------


@requires("fat32")
def test_fat32_recovers_a_contiguous_deleted_file_and_says_it_assumed_contiguity(
    corpus: FilesystemCorpus, corpus_dir: Path
) -> None:
    """Exact bytes, and an honest label on how they were obtained.

    FAT deletion destroys the cluster chain, so even a perfect recovery rests
    on an assumption about the layout. The bytes being right does not make the
    assumption disappear, and the candidate says so either way.
    """
    report, content = _report(corpus_dir, "fat32.img")
    # The two named plants, not the filler files. The fillers are scaffolding
    # for the fragmentation case; a handful of them lose clusters to the
    # fragmented file that was threaded between them, and folding that into
    # this assertion would make a test about contiguous recovery fail for a
    # reason that has nothing to do with contiguous recovery.
    truth = {
        item.sha256: item.name
        for item in corpus.for_filesystem("fat32")
        if item.image == "fat32.img"
        and item.deleted
        and not item.fragmented
        and not item.name.startswith("fill")
    }
    assert len(truth) == 2, "the corpus should plant two contiguous deleted files"

    hits = [
        item
        for key, item in zip(content, report.files, strict=True)
        if hashlib.sha256(content[key]).hexdigest() in truth
    ]
    assert len(hits) == len(truth), (
        f"recovered {len(hits)} of {len(truth)} contiguous deleted files"
    )
    for item in hits:
        assert item.candidate.contiguity_assumed is True
        assert FAT_CHAIN_LOST in item.candidate.validation_detail
        assert item.candidate.possibly_fragmented is True


@requires("fat32")
def test_fat32_says_a_fragmented_recovery_is_partial_rather_than_reporting_success(
    corpus: FilesystemCorpus, corpus_dir: Path
) -> None:
    """The case FAT cannot win, and must not pretend to.

    ``split.bin`` was written into holes between filler files and those fillers
    were then deleted too. The reconstruction walks free clusters and pulls in
    the fillers' bytes, so the result is the right length and the wrong
    content. Nothing on the volume can detect that, which is exactly why the
    candidate must carry the caveat unconditionally instead of only when
    something contradicts it.
    """
    planted = next(
        item
        for item in corpus.for_filesystem("fat32")
        if item.image == "fat32.img" and item.fragmented
    )
    assert planted.recoverable is False, "the corpus expects this one to be a miss"

    report, content = _report(corpus_dir, "fat32.img")
    recovered = _named(report, "_plit.bin")  # FAT replaces the first byte with 0xE5
    payload = content[f"_plit.bin@{recovered.candidate.offset}"]

    assert len(payload) == planted.size, "the recorded size is still correct"
    assert hashlib.sha256(payload).hexdigest() != planted.sha256, (
        "this file was fragmented around files that were then deleted; an exact "
        "recovery here would mean the corpus stopped fragmenting it"
    )
    assert recovered.candidate.contiguity_assumed is True
    assert recovered.candidate.validation != "valid"
    assert FAT_CHAIN_LOST in recovered.candidate.validation_detail
    assert "no check on this volume can say so" in recovered.candidate.validation_detail


@requires("fat32")
def test_fat32_proves_fragmentation_when_a_live_file_sits_inside_the_span(
    corpus: FilesystemCorpus, corpus_dir: Path
) -> None:
    """The one case where the volume itself contradicts the reconstruction.

    While the neighbouring files still exist, a cluster between this file's
    first and last belongs to something live. That is proof of fragmentation
    rather than a suspicion, and it is worth reporting differently from the
    silent case above.
    """
    report, _ = _report(corpus_dir, "fat32-neighbours.img")
    recovered = _named(report, "_plit.bin")
    assert recovered.candidate.contiguity_contradicted is True
    assert "FRAGMENTATION_PROVEN" in recovered.candidate.validation_detail
    assert len(recovered.extents) > 1, (
        "the reconstruction had to route around the live clusters"
    )


# --------------------------------------------------------------------------
# 5. exFAT
# --------------------------------------------------------------------------


@requires("exfat")
def test_exfat_with_nofatchain_recovers_exactly_and_says_it_was_really_contiguous(
    corpus: FilesystemCorpus, corpus_dir: Path
) -> None:
    """The difference between a fact and a guess, which exFAT records for us.

    ``NoFatChain`` set means exFAT stored the file as one run and kept no chain
    for it *while it was live*. The contiguous read is then a recorded fact
    about the layout, and the candidate must not be marked as having assumed
    anything. The chained file beside it is the control.
    """
    planted = next(
        item
        for item in corpus.for_filesystem("exfat")
        if item.name == "contiguous.jpg"
    )
    report, content = _report(corpus_dir, "exfat.img")

    recovered = _named(report, "contiguous.jpg")
    payload = content[f"contiguous.jpg@{recovered.candidate.offset}"]
    assert hashlib.sha256(payload).hexdigest() == planted.sha256
    assert recovered.candidate.contiguity_assumed is False
    assert recovered.candidate.contiguity_contradicted is False
    assert EXFAT_NO_FAT_CHAIN in recovered.candidate.validation_detail

    chained = _named(report, "chained.png")
    assert chained.candidate.contiguity_assumed is True, (
        "the control file used a FAT chain, so its layout can only be assumed"
    )
    assert EXFAT_NO_FAT_CHAIN not in chained.candidate.validation_detail


# --------------------------------------------------------------------------
# 6 and 7. ext
# --------------------------------------------------------------------------


@requires("ext3")
def test_ext3_inode_undelete_returns_the_original_bytes(
    corpus: FilesystemCorpus, corpus_dir: Path
) -> None:
    """The block pointers survive the unlink, so the content does."""
    expected = {
        item.sha256
        for item in corpus.for_filesystem("ext3")
        if item.recoverable
    }
    assert expected, "the corpus should delete ext3 files"
    assert expected <= _digests(corpus_dir, "ext3.img")


@requires("ext2")
def test_ext2_inode_undelete_returns_the_original_bytes(
    corpus: FilesystemCorpus, corpus_dir: Path
) -> None:
    """Same mechanism as ext3, and the one where it is unconditionally true."""
    expected = {
        item.sha256 for item in corpus.for_filesystem("ext2") if item.recoverable
    }
    assert expected <= _digests(corpus_dir, "ext2.img")


@requires("ext4")
def test_ext4_recovery_is_poor_and_the_limitation_is_stated(
    corpus: FilesystemCorpus, corpus_dir: Path
) -> None:
    """This test documents a weakness rather than hiding one.

    ``ext4_ext_remove_space`` zeroes the inode's extent tree on unlink, so a
    surviving inode names a file and points at no blocks. If this test ever
    starts failing because recovery *improved*, that is worth investigating
    before celebrating: the likely cause is a corpus that stopped modelling
    ext4 deletion correctly.
    """
    deleted = [item for item in corpus.for_filesystem("ext4") if item.deleted]
    assert deleted, "the corpus should delete ext4 files"
    assert all(not item.recoverable for item in deleted)

    report, content = _report(corpus_dir, "ext4.img")
    recovered_bytes = sum(len(payload) for payload in content.values())
    assert recovered_bytes == 0, (
        "ext4 undelete recovered content; the extent tree should be gone"
    )

    assert any(EXT4_EXTENTS_ZEROED in limit for limit in report.limitations), (
        "the report must carry the ext4 limitation, not leave it to the reader"
    )
    assert all(
        EXT4_EXTENTS_ZEROED in item.candidate.validation_detail
        for item in report.files
    )


# --------------------------------------------------------------------------
# 8. Partition offsets
# --------------------------------------------------------------------------


@requires("ntfs", "fat32")
def test_offsets_are_image_absolute_not_partition_relative(
    corpus: FilesystemCorpus, corpus_dir: Path
) -> None:
    """The mistake that leaves every offset in a report quietly wrong.

    A partition-relative offset still hashes correctly, still opens, and still
    looks right in every column but one. It is only wrong when somebody goes
    back to the image to find the bytes, which is precisely when it matters.
    Checked against the known plant offsets, and against the standalone image
    the partition was built from.
    """
    first_offset, second_offset = corpus.partition_offsets
    assert first_offset > 0

    report, _ = _report(corpus_dir, "two-partitions.img")
    assert [item.fs_type for item in report.partitions if item.fs_type] == [
        "ntfs",
        "fat32",
    ]

    standalone, _ = _report(corpus_dir, "ntfs.img")
    inside = {
        item.candidate.original_name: item.candidate.offset
        for item in standalone.files
        if item.extents
    }
    combined = {
        item.candidate.original_name: item.candidate.offset
        for item in report.files
        if item.extents and item.candidate.fs_type == "ntfs"
    }
    shared = set(inside) & set(combined)
    assert shared, "the same NTFS files should be found in both images"
    for name in shared:
        assert combined[name] == inside[name] + first_offset, (
            f"{name} was reported at {combined[name]}; the partition starts at "
            f"{first_offset} and the file sits at {inside[name]} inside it"
        )

    fat_offsets = [
        item.candidate.offset
        for item in report.files
        if item.candidate.fs_type == "fat32" and item.extents
    ]
    assert fat_offsets, "the second partition should yield candidates too"
    assert min(fat_offsets) >= second_offset, (
        "a file in the second partition was reported before that partition begins"
    )


# --------------------------------------------------------------------------
# 9. Damage
# --------------------------------------------------------------------------


@requires("ntfs", "fat32")
def test_a_corrupted_partition_table_degrades_to_whole_image_carving(
    corpus: FilesystemCorpus, corpus_dir: Path
) -> None:
    """Damaged evidence is the normal case, so this must not raise.

    The right behaviour is to say what could not be read, report the whole
    image as unallocated so the signature carver still covers every byte, and
    return - not to raise and leave the examiner with nothing.
    """
    report, _ = _report(corpus_dir, "damaged-parttable.img")

    assert report.degraded_to_whole_image is True
    assert report.limitations, "a degraded run must say why"
    assert any(
        "PARTITION_TABLE_UNREADABLE" in limit or "NO_PARTITION_TABLE" in limit
        for limit in report.limitations
    )

    size = (corpus_dir / "damaged-parttable.img").stat().st_size
    assert sum(item.length for item in report.unallocated) == size, (
        "nothing was recovered, so every byte must be offered to the carver"
    )


@requires("ntfs")
def test_a_zeroed_boot_sector_degrades_without_raising(
    corpus: FilesystemCorpus, corpus_dir: Path
) -> None:
    """No filesystem, no crash, and the whole volume handed on for carving."""
    report, _ = _report(corpus_dir, "damaged-boot.img")
    assert report.files == []
    assert report.degraded_to_whole_image is True
    size = (corpus_dir / "damaged-boot.img").stat().st_size
    assert sum(item.length for item in report.unallocated) == size


@requires("fat32")
def test_a_quick_format_leaves_content_for_the_carver_and_nothing_for_undelete(
    corpus: FilesystemCorpus, corpus_dir: Path
) -> None:
    """The case that separates the two recovery strategies most sharply.

    A quick format writes new metadata over old and touches no data block. The
    records undelete depends on are gone; the content signature carving depends
    on is entirely intact. So: no candidates, and an unallocated map covering
    nearly the whole volume.
    """
    report, _ = _report(corpus_dir, "quick-formatted.img")
    assert report.files == []
    size = (corpus_dir / "quick-formatted.img").stat().st_size
    unallocated = sum(item.length for item in report.unallocated)
    assert unallocated > size * 0.9, (
        "a quick-formatted volume holds no live files, so almost all of it is "
        "unallocated and every byte of it should reach the carver"
    )


# --------------------------------------------------------------------------
# 10. The evidence path
# --------------------------------------------------------------------------


@requires("ntfs")
def test_pytsk3_never_opens_the_image_itself(
    corpus: FilesystemCorpus, corpus_dir: Path, tmp_path: Path
) -> None:
    """Structural proof, not a convention: the path is deleted before the walk.

    ``EvidenceHandle`` holds an open descriptor, so reads through it keep
    working after the directory entry is unlinked. ``pytsk3`` was given no
    path and cannot open one. If a future change let TSK open the image by
    name - which it will do perfectly happily - this test fails immediately,
    and the block cache, the read-only open and, most importantly, the
    substituted-range record would otherwise have been quietly bypassed inside
    filesystem parsing.
    """
    copy = tmp_path / "unlinked.img"
    copy.write_bytes((corpus_dir / "ntfs.img").read_bytes())

    with open_evidence(copy) as handle:
        copy.unlink()
        assert not copy.exists()

        report = undelete_report(handle)
        payloads = [read_recovered(handle, item) for item in report.files]

    assert report.files, "recovery must still work through the open handle"
    assert any(payloads), "and must still return content"
    assert report.image_reads > 0, (
        "every byte TSK read should have come through EvidenceImgInfo"
    )


@requires("ntfs")
def test_the_unallocated_map_is_returned_rather_than_left_to_be_recomputed(
    corpus: FilesystemCorpus, corpus_dir: Path
) -> None:
    """The carver's input, produced once by the pass that already knows it.

    Allocated and unallocated must partition the image exactly: a gap would be
    bytes no stage looks at, and an overlap would be bytes carved twice.
    """
    report, _ = _report(corpus_dir, "ntfs.img")
    size = (corpus_dir / "ntfs.img").stat().st_size

    allocated = sum(item.length for item in report.allocated)
    unallocated = sum(item.length for item in report.unallocated)
    assert allocated + unallocated == size
    assert allocated > 0, "a volume with twelve live files has allocated space"

    ranges = sorted(report.allocated + report.unallocated, key=lambda x: x.offset)
    for earlier, later in zip(ranges, ranges[1:], strict=False):
        assert earlier.end == later.offset, "the map must have no gap and no overlap"


@requires("ntfs")
def test_recovered_content_matches_the_hash_the_candidate_claims(
    corpus: FilesystemCorpus, corpus_dir: Path
) -> None:
    """``candidate.sha256`` must be checkable by the caller, not taken on trust.

    It is computed over the same extents :func:`read_recovered` reads, so the
    two cannot drift. This matters most for the resident-``$DATA`` case, where
    the content is spliced back together around the record's update sequence.
    """
    with open_evidence(corpus_dir / "ntfs.img") as handle:
        for item in undelete_report(handle).files:
            payload = read_recovered(handle, item)
            assert hashlib.sha256(payload).hexdigest() == item.candidate.sha256
