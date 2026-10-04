"""The media map classes each region by its bytes, and says how it knows.

Images are built in memory from known parts - zeros, a 0xFF fill, text,
random bytes, a JPEG header on a sector boundary - so every class the map
reports can be checked against what was put there.
"""

from __future__ import annotations

import os
import random
from typing import Any

import pytest
from core.carve.evidence import BytesEvidence
from core.carve.mediamap import BLOCK_BYTES, KINDS, classify_block, map_media
from core.models import MediaMap

REGION = 64 * 1024


def run(data: bytes, **options: Any) -> MediaMap:
    generator = map_media(BytesEvidence(data), **options)
    try:
        while True:
            next(generator)
    except StopIteration as stop:
        result: MediaMap = stop.value
        return result


def text(length: int) -> bytes:
    line = b"Minutes of the meeting held on 12 March. Budget approved.\n"
    return (line * (length // len(line) + 1))[:length]


def noise(length: int, seed: int = 7) -> bytes:
    return random.Random(seed).randbytes(length)


def structured(length: int) -> bytes:
    """Binary with structure: small integers in fixed-width records."""
    record = bytes(range(0, 64)) + b"\x00" * 32 + b"\x01\x00\x00\x00" * 8
    return (record * (length // len(record) + 1))[:length]


def test_each_kind_of_block_is_classed_by_its_bytes() -> None:
    assert classify_block(b"\x00" * BLOCK_BYTES) == ("ZERO", 0, None)
    assert classify_block(b"\xff" * BLOCK_BYTES) == ("FILL", 0, 0xFF)
    assert classify_block(b"\xa5" * BLOCK_BYTES)[2] == 0xA5
    assert classify_block(text(BLOCK_BYTES))[0] == "TEXT"
    kind, entropy, _ = classify_block(noise(BLOCK_BYTES))
    assert kind == "HIGH_ENTROPY" and entropy > 7_900
    assert classify_block(structured(BLOCK_BYTES))[0] == "STRUCTURED"


def test_a_small_image_is_read_in_full_and_mapped_region_by_region() -> None:
    parts = [
        b"\x00" * REGION,
        b"\xff" * REGION,
        text(REGION),
        noise(REGION),
        structured(REGION),
    ]
    result = run(b"".join(parts), regions=5)

    assert result.sampled is False
    assert result.bytes_read == result.size_bytes == 5 * REGION
    assert [region.kind for region in result.regions] == [
        "ZERO",
        "FILL",
        "TEXT",
        "HIGH_ENTROPY",
        "STRUCTURED",
    ]
    assert result.regions[1].fill_byte == 0xFF
    assert all(region.share_bp == 10_000 for region in result.regions)


def test_the_classes_add_up_to_the_image() -> None:
    data = b"\x00" * (3 * REGION) + noise(REGION) + text(REGION // 2)
    result = run(data, regions=4)
    assert set(result.by_kind) == set(KINDS)
    assert sum(result.by_kind.values()) == len(data)
    assert result.by_kind["ZERO"] >= 2 * REGION


def test_headers_on_sector_boundaries_are_counted_by_type() -> None:
    body = bytearray(b"\x00" * (4 * REGION))
    body[2048 : 2048 + 4] = b"\xff\xd8\xff\xe0"  # JPEG, on a sector boundary
    body[REGION + 512 : REGION + 520] = b"%PDF-1.7"
    body[REGION + 700 : REGION + 704] = b"\xff\xd8\xff\xe0"  # off the boundary
    result = run(bytes(body), regions=4)
    assert result.headers == {"jpg": 1, "pdf": 1}
    assert result.regions[0].headers == {"jpg": 1}


def test_a_large_image_is_sampled_within_the_budget_and_says_so() -> None:
    data = noise(4 * 1024 * 1024)
    result = run(data, regions=16, read_budget=256 * 1024)
    assert result.sampled is True
    assert result.bytes_read <= 256 * 1024
    assert all(region.kind == "HIGH_ENTROPY" for region in result.regions)
    assert any(line.startswith("SAMPLED:") for line in result.limitations)


def test_the_same_image_gives_the_same_map() -> None:
    data = noise(2 * 1024 * 1024) + b"\x00" * (2 * 1024 * 1024)
    first = run(data, regions=32, read_budget=128 * 1024)
    second = run(data, regions=32, read_budget=128 * 1024)
    assert first == second


def test_substituted_bytes_are_marked_and_not_passed_off_as_media() -> None:
    data = noise(2 * REGION)
    result = map_media(BytesEvidence(data, unreadable=[(REGION, REGION)]), regions=2)
    try:
        while True:
            next(result)
    except StopIteration as stop:
        mapped: MediaMap = stop.value
    assert mapped.regions[0].substituted is False
    assert mapped.regions[1].substituted is True
    assert any("substituted" in line for line in mapped.limitations)


def test_what_statistics_cannot_say_is_in_the_result() -> None:
    result = run(noise(REGION), regions=1)
    joined = " ".join(result.limitations)
    assert "compressed, encrypted or random" in joined
    assert "not of files" in joined


def test_an_empty_image_maps_to_nothing() -> None:
    result = run(b"")
    assert result.regions == [] and result.size_bytes == 0


@pytest.mark.parametrize("size", [1, 511, BLOCK_BYTES + 1])
def test_an_image_that_is_not_a_whole_number_of_blocks_is_covered(size: int) -> None:
    data = os.urandom(size)
    result = run(data, regions=3)
    assert sum(region.length for region in result.regions) == size
    assert sum(result.by_kind.values()) == size
