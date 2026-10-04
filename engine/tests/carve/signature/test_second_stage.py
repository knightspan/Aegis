"""Short magics, and the few bytes that make each one credible.

Three of the signatures added in Batch 8 are too short or too shared to stand on
their own: ``BM`` is two bytes, ``RIFF`` belongs to WebP and WAV alike, and
``ustar`` is five bytes sitting 257 bytes into a block. Each has a second-stage
check, and this file holds them to two things: the check rejects noise, and it
does not reject the real thing.
"""

from __future__ import annotations

import io
import random
import tarfile

from core.carve.evidence import BytesEvidence
from core.carve.signature import (
    build_automaton,
    load_signatures,
    scan,
    tar_header_is_valid,
)


def test_two_signatures_sharing_a_header_both_survive_the_automaton() -> None:
    """WebP and WAV are both ``RIFF``.

    One signature per pattern let the second overwrite the first, and the
    overwritten format then matched nothing on any image ever scanned.
    """
    table = load_signatures()
    riff = [entry for entry in table if entry.header == b"RIFF"]
    assert {entry.name for entry in riff} == {"WebP", "WAV"}

    automaton = build_automaton(table)
    hits = list(automaton.iter("RIFF...."))
    assert hits, "the shared pattern was not in the automaton"
    names = {signature.name for _, sharing in hits for signature in sharing}
    assert {"WebP", "WAV"} <= names, f"a sharing signature was dropped: {names}"


def test_riff_bytes_with_no_form_type_make_no_candidate() -> None:
    """``RIFF`` followed by nothing recognisable is not a file of either format."""
    rng = random.Random(4)
    image = bytes(1024) + b"RIFF" + (64).to_bytes(4, "little") + rng.randbytes(4096)

    report = scan(BytesEvidence(image))

    assert not [item for item in report.candidates if item.ext in {"webp", "wav"}]
    assert report.suppressed_uncorroborated >= 1


def test_bm_over_random_bytes_makes_no_candidate() -> None:
    """Two bytes match about once per 64 KiB, so the size fields decide."""
    rng = random.Random(9)
    body = bytearray(rng.randbytes(512 * 1024))
    planted = 0
    for offset in range(1024, len(body) - 64, 4096):
        body[offset : offset + 2] = b"BM"
        planted += 1

    report = scan(BytesEvidence(bytes(body)))

    bitmaps = [item for item in report.candidates if item.ext == "bmp"]
    assert not bitmaps, f"{len(bitmaps)} of {planted} random 'BM' pairs became files"


def test_a_real_tar_header_verifies_and_a_damaged_one_does_not() -> None:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as out:
        info = tarfile.TarInfo("notes.txt")
        body = b"evidence\n" * 40
        info.size = len(body)
        info.mtime = 1_700_000_000
        out.addfile(info, io.BytesIO(body))
    archive = buffer.getvalue()

    header = archive[:512]
    assert tar_header_is_valid(header)

    damaged = bytearray(header)
    damaged[0] ^= 0xFF  # one byte of the name, which the checksum covers
    assert not tar_header_is_valid(bytes(damaged))


def test_ustar_over_random_bytes_makes_no_candidate() -> None:
    """The magic is five bytes; the header's own checksum is what settles it."""
    rng = random.Random(11)
    body = bytearray(rng.randbytes(512 * 1024))
    for offset in range(4096, len(body) - 1024, 8192):
        body[offset + 257 : offset + 262] = b"ustar"

    report = scan(BytesEvidence(bytes(body)))

    assert not [item for item in report.candidates if item.ext == "tar"]
