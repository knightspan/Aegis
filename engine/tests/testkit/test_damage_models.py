"""Damage models: each does what it says, and FULL / PARTIAL / GONE is computed.

A recall figure against objects no longer on the medium is meaningless, so the
statuses these tests pin are the thing the benchmark rests on. The metadata
model is checked against each filesystem's own reader (The Sleuth Kit) and
against structures found independently of the code under test.
"""

from __future__ import annotations

import hashlib
import random
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from testkit.damage import (
    Overwrite,
    Truth,
    TruthObject,
    apply_interleaved_overwrite,
    apply_metadata_destruction,
    apply_truncation,
    apply_zeroed_regions,
    load_truth,
    locate,
    status_of,
    write_truth,
)
from testkit.fsimage import (
    PlantedFile,
    build_exfat,
    build_ext,
    build_fat32,
    build_ntfs,
    probe_tools,
)

KIB = 1024
MIB = 1024 * KIB


def test_status_is_the_overlap_of_extents_and_damage() -> None:
    assert status_of(((0, 1000),), 1000, []) == ("FULL", 1000)
    assert status_of(((0, 1000),), 1000, [(500, 100)]) == ("PARTIAL", 900)
    assert status_of(((0, 1000),), 1000, [(0, 400), (300, 800)]) == ("GONE", 0)
    assert status_of(((0, 500), (4096, 500)), 1000, [(4096, 4096)]) == (
        "PARTIAL",
        500,
    )
    # A plant that was written already short is PARTIAL with no damage at all.
    assert status_of(((0, 600),), 1000, []) == ("PARTIAL", 600)


def test_locate_places_a_zero_block_by_the_run_it_belongs_to() -> None:
    """Regression: a zero block after a run break was placed at image offset 0.

    The probe limit counted every byte-offset hit of an all-zero block, so on a
    volume starting with a megabyte of zeros only offset 0 was ever tried, and
    it matched. The ext4 benchmark volume showed it as a run at offset 0.
    """
    rng = random.Random(1)
    medium = bytearray(bytes(MIB) + rng.randbytes(3 * MIB))
    head, tail = rng.randbytes(512), rng.randbytes(700)
    data = head + bytes(1024) + tail
    medium[2 * MIB : 2 * MIB + 512] = head
    medium[3 * MIB : 3 * MIB + 1024 + 700] = bytes(1024) + tail
    assert locate(bytes(medium), data, grid=512) == ((2 * MIB, 512), (3 * MIB, 1724))
    assert locate(bytes(medium), rng.randbytes(2048), grid=512) is None
    # A sparse file: zero blocks that were never stored are holes, not guesses.
    sparse = head + bytes(1024) + tail[:512] + bytes(1024)
    stored = bytearray(bytes(MIB) + rng.randbytes(3 * MIB))
    stored[2 * MIB : 2 * MIB + 512] = head
    stored[2 * MIB + 512 : 2 * MIB + 1024] = tail[:512]
    assert locate(bytes(stored), sparse, grid=512) is None
    assert locate(bytes(stored), sparse, grid=512, holes=True) == ((2 * MIB, 1024),)
    contiguous = rng.randbytes(3000)
    medium[3 * MIB + 8192 : 3 * MIB + 11192] = contiguous
    assert locate(bytes(medium), contiguous, grid=512) == ((3 * MIB + 8192, 3000),)


def _flat(tmp_path: Path) -> tuple[Truth, Path]:
    rng = random.Random(3)
    size = 4 * MIB
    medium = bytearray(rng.randbytes(size))
    objects = []
    for index in range(7):
        at = (index + 1) * 512 * KIB
        data = b"\xff\xd8\xff\xe0" + rng.randbytes(20 * KIB + index * 4 * KIB)
        medium[at : at + len(data)] = data
        objects.append(
            TruthObject(
                name=f"o{index}.jpg",
                format="JPEG",
                role="file",
                sha256=hashlib.sha256(data).hexdigest(),
                size=len(data),
                extents=((at, len(data)),),
                status="FULL",
                surviving_bytes=len(data),
            )
        )
    path = tmp_path / "base.img"
    path.write_bytes(bytes(medium))
    truth = Truth(
        image=path.name,
        corpus="test",
        model="none",
        description="flat",
        size_bytes=size,
        filesystem="none",
        cluster_bytes=4096,
        objects=tuple(objects),
    )
    return truth, path


def _statuses(truth: Truth) -> dict[str, str]:
    return {item.name: item.status for item in truth.objects}


def test_truncation_cuts_through_the_median_file(tmp_path: Path) -> None:
    base, path = _flat(tmp_path)
    out = tmp_path / "cut.img"
    truth = apply_truncation(base, path, out)
    assert _statuses(truth) == {
        "o0.jpg": "FULL",
        "o1.jpg": "FULL",
        "o2.jpg": "FULL",
        "o3.jpg": "PARTIAL",
        "o4.jpg": "GONE",
        "o5.jpg": "GONE",
        "o6.jpg": "GONE",
    }
    assert out.stat().st_size == truth.size_bytes == truth.parameters["kept_bytes"]
    assert path.read_bytes()[: truth.size_bytes] == out.read_bytes()


def test_zeroed_regions_are_zeros_and_statuses_follow_them(tmp_path: Path) -> None:
    base, path = _flat(tmp_path)
    out = tmp_path / "zeroed.img"
    truth = apply_zeroed_regions(base, path, out, seed=5)
    damaged = out.read_bytes()
    for offset, length, _what in truth.damaged:
        assert damaged[offset : offset + length] == bytes(length)
    statuses = _statuses(truth)
    assert statuses["o3.jpg"] == "GONE"  # the median file, covered whole
    assert statuses["o6.jpg"] == "PARTIAL"  # the largest, middle third zeroed
    for item in truth.objects:
        ranges = [(offset, length) for offset, length, _what in truth.damaged]
        assert (item.status, item.surviving_bytes) == status_of(
            item.extents, item.size, ranges
        )


def test_interleaved_overwrite_damages_the_victim_and_plants_the_later_file(
    tmp_path: Path,
) -> None:
    base, path = _flat(tmp_path)
    rng = random.Random(9)
    head, tail = rng.randbytes(8 * KIB), rng.randbytes(8 * KIB)
    out = tmp_path / "interleave.img"
    truth = apply_interleaved_overwrite(
        base,
        path,
        out,
        [
            Overwrite("o1.jpg", "later-head.bin", "random", head, 0.0),
            Overwrite("o5.jpg", "later-tail.bin", "random", tail, 0.5),
        ],
    )
    statuses = _statuses(truth)
    assert statuses["o1.jpg"] == statuses["o5.jpg"] == "PARTIAL"
    assert statuses["later-head.bin"] == statuses["later-tail.bin"] == "FULL"
    written = out.read_bytes()
    for later, blob in (("later-head.bin", head), ("later-tail.bin", tail)):
        ((at, length),) = truth.by_name(later).extents
        assert written[at : at + length] == blob
        assert at % 4096 == 0
    victim_at = truth.by_name("o1.jpg").extents[0][0]
    assert truth.by_name("later-head.bin").extents[0][0] == victim_at - victim_at % 4096


def test_a_manifest_round_trips(tmp_path: Path) -> None:
    base, path = _flat(tmp_path)
    truth = apply_zeroed_regions(base, path, tmp_path / "z.img")
    written = write_truth(truth, tmp_path / "z.truth.json")
    assert load_truth(written) == truth


# --------------------------------------------------------------------------
# Metadata destruction, per filesystem
# --------------------------------------------------------------------------


def _tsk_opens(path: Path) -> bool:
    import pytsk3

    try:
        pytsk3.FS_Info(pytsk3.Img_Info(str(path)))
    except OSError:
        return False
    return True


def _volume(tmp_path: Path, filesystem: str) -> tuple[Truth, Path]:
    from testkit.generate_corpus import make_jpeg

    rng = random.Random(11)
    photo = make_jpeg(rng, 160)
    blob = rng.randbytes(200 * KIB)
    files = [PlantedFile("a.jpg", photo), PlantedFile("b.bin", blob, deleted=True)]
    path = tmp_path / f"{filesystem}.img"
    if filesystem == "fat32":
        build_fat32(path, files, size=40 * MIB)
    elif filesystem == "exfat":
        build_exfat(path, files, size=12 * MIB, contiguous=["a.jpg", "b.bin"])
    elif filesystem == "ntfs":
        build_ntfs(path, files, size=24 * MIB)
    else:
        build_ext(path, files, kind="ext4", size=12 * MIB)
    medium = path.read_bytes()
    objects = []
    for planted in files:
        extents = locate(medium, planted.data, grid=512)
        assert extents is not None, planted.name
        objects.append(
            TruthObject(
                name=planted.name,
                format="JPEG" if planted.name.endswith(".jpg") else "random",
                role="file",
                sha256=hashlib.sha256(planted.data).hexdigest(),
                size=len(planted.data),
                extents=extents,
                status="FULL",
                surviving_bytes=len(planted.data),
            )
        )
    truth = Truth(
        image=path.name,
        corpus="test",
        model="delete",
        description=filesystem,
        size_bytes=len(medium),
        filesystem=filesystem,
        cluster_bytes=512,
        objects=tuple(objects),
    )
    return truth, path


@pytest.mark.parametrize("filesystem", ["fat32", "exfat", "ntfs", "ext4"])
def test_metadata_destruction_blinds_the_filesystem_and_spares_the_data(
    tmp_path: Path, filesystem: str
) -> None:
    missing = probe_tools().missing.get(filesystem)
    if missing:
        pytest.skip(f"{filesystem} needs {', '.join(missing)}")
    base, path = _volume(tmp_path, filesystem)
    assert _tsk_opens(path), (
        "the undamaged volume must open, or the test proves nothing"
    )
    out = tmp_path / f"{filesystem}-meta.img"

    truth = apply_metadata_destruction(base, path, out)

    assert not _tsk_opens(out)
    assert _statuses(truth) == {"a.jpg": "FULL", "b.bin": "FULL"}
    before, after = path.read_bytes(), out.read_bytes()
    for item in truth.objects:
        for offset, length in item.extents:
            assert after[offset : offset + length] == before[offset : offset + length]
    for offset, length, _what in truth.damaged:
        assert after[offset : offset + length] == bytes(length)

    # Independent of the parser under test: structures found some other way
    # are gone too.
    if filesystem == "fat32":
        signature = b"\xf8\xff\xff\x0f"
        copies = [
            at for at in range(0, 4 * MIB, 512) if before[at : at + 4] == signature
        ]
        assert len(copies) == 2, "both FAT copies start with the media byte"
        assert all(after[at : at + 4] == bytes(4) for at in copies)
    elif filesystem == "ntfs":
        records = [
            at for at in range(0, len(before), 512) if before[at : at + 4] == b"FILE"
        ]
        assert len(records) > 16
        assert not [at for at in records if after[at : at + 4] == b"FILE"]
    elif filesystem == "exfat":
        checked = subprocess.run(["fsck.exfat", "-n", str(out)], capture_output=True)
        assert checked.returncode != 0
    elif shutil.which("dumpe2fs"):
        listing = subprocess.run(
            ["dumpe2fs", str(path)], capture_output=True, text=True, check=True
        ).stdout
        block = int(re.search(r"Block size:\s+(\d+)", listing).group(1))  # type: ignore[union-attr]
        tables = [
            (int(first) * block, (int(last) - int(first) + 1) * block)
            for first, last in re.findall(r"Inode table at (\d+)-(\d+)", listing)
        ]
        supers = [
            int(number) * block
            for number in re.findall(r"superblock at (\d+)", listing)
        ]
        assert tables and supers
        for offset, length in tables:
            assert after[offset : offset + length] == bytes(length)
        for offset in supers:
            at = max(offset, 1024)
            assert after[at : at + 1024] == bytes(1024)
