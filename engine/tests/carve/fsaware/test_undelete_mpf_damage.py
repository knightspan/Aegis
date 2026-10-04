"""A deleted phone photo with one reused cluster is not a whole photo.

FAT undelete reads a deleted file's clusters as one contiguous run, because the
chain is gone. When a later file has reused one of those clusters, the bytes
recovered are the photo with a cluster of somebody else's data in the middle,
at exactly the recorded length, still ending at the real EOI. A decoder reports
that as a warning and returns an image. For a plain JPEG, exact scan accounting
in the validator catches it; nothing else on this path can, since undelete
candidates never pass through the structure carver's trigger.

A phone photo with an MPF index (an iPhone's HDR gain map) opens in Pillow as
``MPO``, not ``JPEG``, and the validator's accounting used to be gated on
``JPEG``. Measured before the fix: the MPF photo came back ``valid`` at HIGH
10000 with a digest of bytes that were never the file; the plain JPEG came back
``corrupt``. Both must be refused.
"""

from __future__ import annotations

import io
import random
import struct
from pathlib import Path
from typing import Any

import pytest
from api.carve_job import carve_generator
from core.carve.evidence import BytesEvidence
from core.carve.structure import parse_jpeg
from PIL import Image
from testkit.fsimage import PlantedFile, build_fat32

from .conftest import requires


def _noisy(width: int, height: int, seed: int) -> Image.Image:
    rng = random.Random(seed)
    image = Image.new("RGB", (width, height))
    image.putdata(
        [
            (rng.randrange(256), rng.randrange(256), rng.randrange(256))
            for _ in range(width * height)
        ]
    )
    return image


def _photo(kind: str) -> bytes:
    buffer = io.BytesIO()
    if kind == "mpo":
        _noisy(512, 512, 1).save(
            buffer,
            "MPO",
            save_all=True,
            append_images=[_noisy(256, 192, 4)],
            quality=90,
        )
    else:
        _noisy(512, 512, 1).save(buffer, "JPEG", quality=90)
    return buffer.getvalue()


def _carve(image: Path) -> dict[str, Any]:
    generator = carve_generator(image, job_id="mpf-undelete", ledger=None)
    try:
        while True:
            next(generator)
    except StopIteration as stop:
        result: dict[str, Any] = stop.value
        return result


@requires("fat32")
@pytest.mark.parametrize("kind", ["mpo", "jpeg"])
def test_a_reused_cluster_in_a_deleted_photo_is_not_called_valid(
    tmp_path: Path, kind: str
) -> None:
    photo = _photo(kind)
    image = tmp_path / f"{kind}.img"
    build_fat32(image, [PlantedFile("PHOTO.JPG", photo, deleted=True)])

    raw = bytearray(image.read_bytes())
    start = raw.find(photo[:4096])
    assert start >= 0, "mtools must have written the photo contiguously"
    cluster = struct.unpack_from("<H", raw, 11)[0] * raw[13]
    first = parse_jpeg(BytesEvidence(photo), 0, max_size=len(photo))
    assert first is not None
    # A cluster inside the first image's scan, as a later file would leave it.
    reused = start + (first.length // 2) // cluster * cluster
    raw[reused : reused + cluster] = (b"a later file's contents. " * 1024)[:cluster]
    image.write_bytes(bytes(raw))

    undeleted = [
        item
        for item in _carve(image)["candidates"]
        if item["source"] == "fs_metadata" and item["offset"] == start
    ]

    assert undeleted, "undelete must find the deleted photo"
    for item in undeleted:
        assert item["validation"] != "valid", item["validation_detail"]
        assert item["bucket"] != "HIGH", item["score_components"]
