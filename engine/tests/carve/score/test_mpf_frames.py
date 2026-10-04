"""A JPEG's MPF index can declare images the carved object does not hold.

A phone writes an HDR gain map (Apple) or a second view (a stereo camera) as a
second JPEG after the first one's EOI, and indexes both in an APP2 MPF segment
inside the first. The carver ends a JPEG object at the EOI its scan reaches, so
the object it hands the validator holds the first image and an index pointing
past its own end. Pillow opens anything whose index lists more than one image
as an MPO, and decoding frame 1 of that object raises "No data found for
frame".

Measured on seven of seven real iPhone photos before the fix: every one came
out ``corrupt`` and LOW 3000 while its own thumbnail and gain map were HIGH.
These tests use Pillow's MPO writer instead - the same defect with no camera
involved, and nothing binary committed.

A declared frame the object does not contain is information about the object,
not a failed decode. A frame the object *does* contain still has to decode, and
the last two tests exist so this change can never turn a real failure into a
pass.
"""

from __future__ import annotations

import hashlib
import io
import random
from pathlib import Path
from typing import Any

import pytest
from api.carve_job import carve_generator
from core.carve.evidence import BytesEvidence
from core.carve.structure import parse_jpeg
from core.carve.validate import validate_bytes
from PIL import Image

from tests.carve.signature.conftest import Embedded, lay_out

LEAD = 37 * 4096


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


@pytest.fixture(scope="module")
def mpo() -> bytes:
    """Two images, the second after the first one's EOI, indexed by MPF."""
    buffer = io.BytesIO()
    _noisy(256, 256, 1).save(
        buffer, "MPO", save_all=True, append_images=[_noisy(128, 96, 4)], quality=90
    )
    return buffer.getvalue()


@pytest.fixture(scope="module")
def first_image(mpo: bytes) -> bytes:
    """What the carver hands the validator: SOI to the first EOI."""
    parsed = parse_jpeg(BytesEvidence(mpo), 0, max_size=len(mpo))
    assert parsed is not None and parsed.validation == "valid"
    assert parsed.length < len(mpo), "the fixture must have bytes after the EOI"
    return mpo[: parsed.length]


def _carve(image: Path) -> dict[str, Any]:
    generator = carve_generator(image, job_id="mpf", ledger=None)
    try:
        while True:
            next(generator)
    except StopIteration as stop:
        result: dict[str, Any] = stop.value
        return result


def test_a_carved_mpf_photo_without_its_second_image_is_valid(
    first_image: bytes,
) -> None:
    report = validate_bytes(first_image, "jpg")

    assert report.verdict == "valid", report
    # How many frames the index declares, how many are here, and where the
    # absent one was declared to be.
    assert "1 of the 2 images its MPF index declares" in report.detail
    assert f"declared at byte {len(first_image)}" in report.detail


def test_the_pipeline_scores_a_carved_mpf_photo_like_any_whole_jpeg(
    tmp_path: Path, mpo: bytes, first_image: bytes
) -> None:
    image = tmp_path / "mpo.dd"
    image.write_bytes(
        lay_out([Embedded(ext="jpg", offset=LEAD, data=mpo)], LEAD + len(mpo) + 65536)
    )

    by_offset = {item["offset"]: item for item in _carve(image)["candidates"]}

    photo = by_offset[LEAD]
    assert photo["sha256"] == hashlib.sha256(first_image).hexdigest()
    assert photo["validation"] == "valid", photo["validation_detail"]
    assert photo["bucket"] == "HIGH", photo["score_components"]
    # The medium offset of the image the index declares, for a contiguous object.
    assert f"offset {LEAD + len(first_image)}" in photo["validation_detail"]

    # And the declared image is on the medium as an object of its own.
    second = by_offset[LEAD + len(first_image)]
    assert second["sha256"] == hashlib.sha256(mpo[len(first_image) :]).hexdigest()
    assert second["validation"] == "valid"


def test_an_mpo_holding_every_frame_still_decodes_every_frame(mpo: bytes) -> None:
    report = validate_bytes(mpo, "jpg")

    assert report.verdict == "valid", report
    assert "2 frame(s) fully decoded" in report.detail
    assert "declared at" not in report.detail


def test_a_frame_inside_the_object_that_fails_to_decode_is_still_corrupt(
    mpo: bytes, first_image: bytes
) -> None:
    """The one way this fix could do harm: a real failure read as absence."""
    at = len(first_image)
    broken = mpo[:at] + b"\x00\x00" + mpo[at + 2 :]  # frame 1 loses its SOI

    report = validate_bytes(broken, "jpg")

    assert report.verdict == "corrupt", report


@pytest.mark.parametrize(
    "filler",
    [bytes(512), (b"a directory entry? " * 27)[:512]],
    ids=["zeros", "text"],
)
def test_foreign_bytes_in_the_first_image_of_an_mpo_are_corrupt(
    mpo: bytes, filler: bytes
) -> None:
    """Exact accounting applies to an MPO's first image as to any JPEG.

    Before this, Pillow's ``MPO`` format skipped the check entirely: one reused
    512-byte cluster in a deleted two-image JPEG, recovered by FAT undelete,
    came back ``valid`` at HIGH 10000, while the same damage to a plain JPEG
    came back ``corrupt``.
    """
    at = 16384
    damaged = mpo[:at] + filler + mpo[at + len(filler) :]

    report = validate_bytes(damaged, "jpg")

    assert report.verdict == "corrupt", report
    assert "does not account" in report.detail


def test_a_frame_cut_off_inside_the_object_is_not_valid(
    mpo: bytes, first_image: bytes
) -> None:
    """Frame 1 starts inside the object, so it is held, and it is short."""
    report = validate_bytes(mpo[: len(first_image) + 2048], "jpg")

    assert report.verdict != "valid", report
