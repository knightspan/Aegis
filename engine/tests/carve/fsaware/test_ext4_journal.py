"""The jbd2 scan, tested against a journal built byte by byte.

ext4 zeroes an inode's extent tree on unlink, so the only place a deleted
file's block pointers survive is a stale copy of the inode-table block still
sitting in the journal. That path cannot be exercised from the corpus: the
corpus is built with ``debugfs``, which edits the filesystem offline and writes
no journal at all, and the only way to get real journal contents is to mount the
volume with the kernel driver - which needs root, which the corpus deliberately
does not use.

So the journal is constructed here instead, to the format's own layout, and the
scan is measured against it. That is the honest division: the corpus measures
what recovery achieves on real volumes, and this measures the parser that fires
when a real volume does have journal contents to offer.
"""

from __future__ import annotations

import struct

from core.carve.fsaware import (
    EXT4_EXTENT_MAGIC,
    JBD2_MAGIC,
    ExtSuperblock,
    _parse_ext4_inode,
    _scan_journal_for_inodes,
)

BLOCK = 1024
INODE = 256
SUPERBLOCK = ExtSuperblock(
    block_size=BLOCK, inode_size=INODE, inodes_per_group=2048, blocks_count=8192
)

#: A believable time, so the timestamps in the recovered inode are real.
_WHEN = 1_780_000_000


def make_inode(
    *,
    size: int,
    start_block: int,
    length: int,
    links: int = 0,
    dtime: int = _WHEN,
    mode: int = 0x81A4,
    extents: int = 1,
) -> bytes:
    """One ext4 inode, with an extent tree in ``i_block``."""
    raw = bytearray(INODE)
    struct.pack_into("<H", raw, 0x00, mode)
    struct.pack_into("<I", raw, 0x04, size & 0xFFFF_FFFF)
    struct.pack_into("<IIII", raw, 0x08, _WHEN, _WHEN, _WHEN, dtime)
    struct.pack_into("<H", raw, 0x1A, links)
    struct.pack_into("<I", raw, 0x20, 0x0008_0000)  # EXT4_EXTENTS_FL
    struct.pack_into("<HHHHI", raw, 0x28, EXT4_EXTENT_MAGIC, extents, 4, 0, 0)
    struct.pack_into(
        "<IHHI", raw, 0x28 + 12, 0, length, start_block >> 16, start_block & 0xFFFF
    )
    struct.pack_into("<I", raw, 0x6C, size >> 32)
    return bytes(raw)


def jbd2_block(block_type: int) -> bytes:
    """A jbd2 bookkeeping block: superblock, descriptor, commit or revoke."""
    raw = bytearray(BLOCK)
    struct.pack_into(">III", raw, 0, JBD2_MAGIC, block_type, 1)
    return bytes(raw)


def inode_table_block(*inodes: bytes) -> bytes:
    """A copy of an inode-table block, as the journal would hold one."""
    raw = bytearray(BLOCK)
    for index, inode in enumerate(inodes):
        raw[index * INODE : (index + 1) * INODE] = inode
    return bytes(raw)


def test_a_deleted_inode_with_an_intact_extent_tree_is_recovered() -> None:
    """The whole point: a stale copy predating the tree being zeroed."""
    journal = b"".join(
        [
            jbd2_block(4),  # journal superblock
            jbd2_block(1),  # descriptor
            inode_table_block(make_inode(size=3000, start_block=100, length=3)),
            jbd2_block(2),  # commit
        ]
    )

    found = _scan_journal_for_inodes(journal, SUPERBLOCK, base=0)

    assert len(found) == 1
    recovered = found[0]
    assert recovered.size == 3000
    assert recovered.extents[0].offset == 100 * BLOCK
    # The extent covers three blocks but the file is 3000 bytes; the run is
    # clamped to the size, because returning the tail padding as recovered
    # content would change the file's hash.
    assert recovered.extents[0].length == 3000
    assert recovered.mac.modified is not None
    assert recovered.mac.created is None, "ext has no creation time to report"


def test_the_partition_offset_is_added_to_every_recovered_extent() -> None:
    """A journal inside a partition still yields image-absolute offsets."""
    journal = jbd2_block(4) + inode_table_block(
        make_inode(size=BLOCK, start_block=7, length=1)
    )
    base = 1 << 20
    found = _scan_journal_for_inodes(journal, SUPERBLOCK, base=base)
    assert found[0].extents[0].offset == base + 7 * BLOCK


def test_jbd2_bookkeeping_blocks_are_never_read_as_inode_tables() -> None:
    """Descriptor, commit and revoke blocks are the journal's own, not copies."""
    journal = b"".join(jbd2_block(kind) for kind in (4, 1, 2, 5))
    assert _scan_journal_for_inodes(journal, SUPERBLOCK, base=0) == []


def test_a_live_inode_is_not_reported_as_deleted() -> None:
    """Links still held, or no deletion time: the file was never unlinked."""
    still_linked = inode_table_block(
        make_inode(size=2048, start_block=50, length=2, links=1)
    )
    never_deleted = inode_table_block(
        make_inode(size=2048, start_block=50, length=2, dtime=0)
    )
    assert _scan_journal_for_inodes(still_linked, SUPERBLOCK, base=0) == []
    assert _scan_journal_for_inodes(never_deleted, SUPERBLOCK, base=0) == []


def test_a_deleted_directory_is_not_recovered_as_a_file() -> None:
    """Only regular files carry content worth returning."""
    directory = inode_table_block(
        make_inode(size=BLOCK, start_block=9, length=1, mode=0x41ED)
    )
    assert _scan_journal_for_inodes(directory, SUPERBLOCK, base=0) == []


def test_an_inode_whose_extent_tree_was_zeroed_yields_nothing() -> None:
    """The live ext4 case, and the reason this whole path exists.

    Once ``ext4_ext_remove_space`` has run there is no extent header left, so
    the inode is skipped rather than turned into a candidate pointing at block
    zero.
    """
    raw = bytearray(make_inode(size=4096, start_block=11, length=4))
    raw[0x28:0x28 + 60] = bytes(60)
    assert _parse_ext4_inode(bytes(raw), BLOCK, 0) is None
    assert _scan_journal_for_inodes(inode_table_block(bytes(raw)), SUPERBLOCK, 0) == []


def test_random_bytes_do_not_become_recovered_files() -> None:
    """The scan is structural, so it has to reject data that is not an inode.

    A journal holds copies of every kind of metadata block, not only inode
    tables. Every one of them is offered to this parser, so a loose check would
    fill a report with files that never existed.
    """
    import random

    rng = random.Random(0)
    noise = bytes(rng.randbytes(BLOCK * 32))
    assert _scan_journal_for_inodes(noise, SUPERBLOCK, base=0) == []


def test_the_same_inode_seen_in_several_transactions_is_reported_once() -> None:
    """A journal holds many copies of a hot inode-table block."""
    inode = make_inode(size=1500, start_block=64, length=2)
    journal = b"".join(inode_table_block(inode) for _ in range(5))
    assert len(_scan_journal_for_inodes(journal, SUPERBLOCK, base=0)) == 1
