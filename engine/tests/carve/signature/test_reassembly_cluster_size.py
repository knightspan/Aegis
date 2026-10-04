"""The volume's real cluster size reaches the reassembler (BATCH3 FINDINGS 4).

``carve_structures`` has no filesystem context of its own; the undelete pass
does, because it opened the volume. These tests pin the three links between
them: the undelete report records each volume's cluster size from its boot
sector, ``carve_structures`` hands the size for a header's offset to the search,
and ``api.carve_job`` threads one into the other.

The observable is the physical-layout rule. A split 2048 bytes into a file is a
layout no 4096-byte-cluster allocator produces, so on such a volume it is
refused. With no cluster size - a raw image - the search walks 512-byte sectors
and the same split is recovered byte for byte. A test that saw the same result
either way would not be testing the plumbing.

Images are formatted with ``mkfs.vfat`` and ``mkfs.exfat`` unprivileged, and the
JPEG is written straight into the data area with no directory entry, which is
what a quick format leaves: carving is the only route to it.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from core.carve.evidence import BytesEvidence, open_evidence
from core.carve.fsaware import read_exfat_boot, read_fat32_boot, undelete_report
from core.carve.structure import carve_structures

from tests.carve.signature.conftest import make_noisy_jpeg

MIB = 1024 * 1024
GAP_BYTES = 32 * 1024
SPLIT = 2048


def _filler(size: int) -> bytes:
    return bytes((index * 7 + 3) & 0xFF for index in range(size))


def _split(payload: bytes, head: int, gap: int) -> bytes:
    return payload[:head] + _filler(gap) + payload[head:]


def _format(kind: str, path: Path, cluster: int) -> None:
    tool = {"fat32": "mkfs.vfat", "exfat": "mkfs.exfat"}[kind]
    if shutil.which(tool) is None:
        pytest.skip(f"{tool} is not installed")
    with open(path, "wb") as handle:
        # FAT32 needs at least 65,525 clusters or TSK will not open it as FAT32.
        handle.truncate(max(64 * MIB, 80_000 * cluster))
    if kind == "fat32":
        command = [tool, "-F", "32", "-S", "512", "-s", str(cluster // 512), str(path)]
    else:
        command = [tool, "-c", str(cluster), str(path)]
    subprocess.run(command, check=True, capture_output=True)


def _data_offset(kind: str, image: bytes, cluster_number: int) -> tuple[int, int]:
    """Image offset of a data cluster, and the volume's cluster size."""
    evidence = BytesEvidence(image)
    if kind == "fat32":
        fat = read_fat32_boot(evidence)
        assert fat is not None
        at = fat.data_offset + (cluster_number - 2) * fat.cluster_bytes
        return at, fat.cluster_bytes
    exfat = read_exfat_boot(evidence)
    assert exfat is not None
    return exfat.cluster_offset(cluster_number), exfat.cluster_bytes


def _drain(path: Path) -> dict[str, Any]:
    from api.carve_job import carve_generator

    pipeline = carve_generator(path)
    try:
        while True:
            next(pipeline)
    except StopIteration as finished:
        result: dict[str, Any] = finished.value
    return result


@pytest.fixture(scope="module")
def original() -> bytes:
    return make_noisy_jpeg(seed=99)


# --------------------------------------------------------------------------
# The undelete report records it
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "cluster"), [("fat32", 512), ("fat32", 1024), ("exfat", 4096)]
)
def test_undelete_records_each_volumes_cluster_size(
    tmp_path: Path, kind: str, cluster: int
) -> None:
    path = tmp_path / f"{kind}-{cluster}.img"
    _format(kind, path, cluster)

    with open_evidence(path) as handle:
        report = undelete_report(handle)

    opened = [item for item in report.partitions if item.fs_type]
    assert opened, report.limitations
    assert [item.cluster_bytes for item in opened] == [cluster]


def test_a_volume_with_no_filesystem_has_no_cluster_size(tmp_path: Path) -> None:
    path = tmp_path / "raw.dd"
    path.write_bytes(_filler(4 * MIB))

    with open_evidence(path) as handle:
        report = undelete_report(handle)

    assert all(item.cluster_bytes == 0 for item in report.partitions)


# --------------------------------------------------------------------------
# carve_structures uses the size it is given
# --------------------------------------------------------------------------


def test_carve_structures_hands_the_cluster_size_to_the_search(original: bytes) -> None:
    image = _split(original, SPLIT, GAP_BYTES) + bytes(8192)
    want = hashlib.sha256(original).hexdigest()

    def recovered(sizes: dict[str, int] | None) -> bool:
        lookup = None if sizes is None else (lambda offset: sizes["cluster"])
        return any(
            item.sha256 == want and item.fragments
            for item in carve_structures(BytesEvidence(image), cluster_bytes_at=lookup)
        )

    assert recovered(None), "with no cluster size the 512-byte grid finds the split"
    assert not recovered({"cluster": 4096}), (
        "a 4096-byte-cluster volume cannot hold a 2048-byte head, so the join "
        "must not be enumerated"
    )


# --------------------------------------------------------------------------
# The pipeline threads one into the other
# --------------------------------------------------------------------------


def test_the_pipeline_refuses_a_split_the_volume_cannot_hold(
    tmp_path: Path, original: bytes
) -> None:
    """exFAT, 4096-byte clusters, a JPEG split 2048 bytes in: refused, not guessed."""
    path = tmp_path / "exfat-4096.img"
    _format("exfat", path, 4096)
    image = bytearray(path.read_bytes())
    at, cluster = _data_offset("exfat", bytes(image), 1000)
    assert cluster == 4096
    laid = _split(original, SPLIT, GAP_BYTES)
    image[at : at + len(laid)] = laid
    path.write_bytes(bytes(image))

    result = _drain(path)

    opened = [item for item in result["partitions"] if item["fs_type"]]
    assert [item["cluster_bytes"] for item in opened] == [4096]
    header = [item for item in result["candidates"] if item["offset"] == at]
    assert header, "the JPEG header should still be reported"
    assert not [item for item in result["candidates"] if item["fragments"]], (
        "the pipeline reassembled a split that a 4096-byte-cluster volume cannot "
        "produce, so the cluster size did not reach the search"
    )


def test_the_pipeline_recovers_finding_1_on_a_512_byte_fat32_volume(
    tmp_path: Path, original: bytes
) -> None:
    """PREFLIGHT2 FINDING 1's geometry on a real FAT32 boot sector, byte for byte.

    Head 65,536, a 512-byte gap cluster of directory entries then 64 KiB of
    another file, then the tail: the layout that produced a HIGH object matching
    nothing. On a volume whose cluster size is known it comes back exactly.
    """
    path = tmp_path / "fat32-512.img"
    _format("fat32", path, 512)
    image = bytearray(path.read_bytes())
    at, cluster = _data_offset("fat32", bytes(image), 4000)
    assert cluster == 512
    entry = b"FRAGPAD0BIN\x20" + bytes(20)
    gap = (entry * 16)[:512] + hashlib.shake_256(b"pad").digest(64 * 1024)
    head = 65_536
    laid = original[:head] + gap + original[head:]
    image[at : at + len(laid)] = laid
    path.write_bytes(bytes(image))

    result = _drain(path)

    want = hashlib.sha256(original).hexdigest()
    rebuilt = [item for item in result["candidates"] if item["fragments"]]
    assert [item["sha256"] for item in rebuilt] == [want], rebuilt
    assert [(run["offset"], run["length"]) for run in rebuilt[0]["fragments"]] == [
        (at, head),
        (at + head + len(gap), len(original) - head),
    ]
