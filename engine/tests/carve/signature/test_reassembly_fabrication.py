"""No reassembled object may be something that was never on the medium.

This is the acceptance gate for Batch 7. It asserts on *fabrication*, not on
the bucket: a candidate whose digest is neither the digest of an object that was
planted nor the digest of the contiguous span it names is an object the tool
invented, and demoting it to LOW does not make it evidence.

The layouts are the ones measured to fabricate at ``hwval-run4``:

* ``finding1-fat32-512`` is PREFLIGHT2 FINDING 1, geometry for geometry. FAT32 at
  255 MiB has 512-byte clusters; the planted 73,870-byte JPEG's head is 65,536
  bytes, a 512-byte directory cluster and a live 64 KiB pad follow it, and the
  tail starts 66,048 bytes after the head ends. The header offset is on the
  512-byte grid of the image and off the 4096-byte one, as it was on the volume.
  The search joined the real head to the real tail read 3,584 bytes late: a
  JPEG that decodes, scored HIGH, and matched nothing.
* the other five are the same class reached without an off-grid gap. A benign
  directory cluster next to either edge of the gap lets the join absorb it,
  and another JPEG in the gap lets the head be joined to that JPEG's scan data.
  None of them needs a wrong cluster size, and the gap in each is a whole
  multiple of the volume's real cluster size.

A candidate over a contiguous span that reads back to its own digest is not
fabricated here, whatever its verdict: those bytes are on the medium as one run.
"""

from __future__ import annotations

import hashlib
import importlib.util
import random
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from core.carve.evidence import BytesEvidence
from core.carve.structure import carve_structures

from tests.carve.signature.conftest import make_noisy_jpeg

REPO = Path(__file__).resolve().parents[3]
PAD_BYTES = 64 * 1024


@pytest.fixture(scope="module")
def planted_jpeg() -> bytes:
    """The harness's own fragment-plant JPEG, the object FINDING 1 was measured on."""
    spec = importlib.util.spec_from_file_location(
        "hardware_validation_fabrication", REPO / "scripts" / "hardware_validation.py"
    )
    assert spec and spec.loader
    module: ModuleType = importlib.util.module_from_spec(spec)
    sys.modules["hardware_validation_fabrication"] = module
    spec.loader.exec_module(module)
    payload: bytes = module.fragment_jpeg_bytes()
    assert len(payload) == 73_870, "FINDING 1 was measured on the 73,870-byte plant"
    return payload


@pytest.fixture(scope="module")
def neighbour_jpeg() -> bytes:
    return make_noisy_jpeg(size=160, seed=4242)


def _directory_cluster(cluster: int) -> bytes:
    """A cluster of 8.3 directory entries: short names, an archive attribute, zeros."""
    entry = b"FRAGPAD0BIN\x20" + bytes(20)
    return (entry * (cluster // len(entry) + 1))[:cluster]


@dataclass(frozen=True)
class Layout:
    cluster: int
    head: int
    #: What lies between the runs, in order; ``"dir"``, ``"pad"`` or ``"jpeg"``.
    gap: tuple[str, ...]
    #: Seeds the lead-in and the pad bytes, which decide which wrong join the
    #: code at ``hwval-run4`` produced. Recorded per layout so each one keeps
    #: reproducing the join it was chosen for.
    seed: int = 0


LAYOUTS = {
    # Seed 0: head 65,536 joined to the tail read 3,584 bytes late, 4,750 bytes
    # of it - exactly the object PREFLIGHT2 measured on the loopback volume.
    "finding1-fat32-512": Layout(512, 65_536, ("dir", "pad"), seed=0),
    # Seed 5: the pad's last sector happens to hold no reserved marker code, so
    # the tail was read 512 bytes early instead, with that sector in it.
    "pad-sector-before-tail-512": Layout(512, 65_536, ("dir", "pad"), seed=5),
    "dir-cluster-before-tail-512": Layout(512, 65_536, ("pad", "dir")),
    "dir-cluster-after-head-4096": Layout(4096, 65_536, ("dir", "pad")),
    "dir-cluster-before-tail-4096": Layout(4096, 65_536, ("pad", "dir")),
    "another-jpeg-in-gap-4096": Layout(4096, 4096, ("jpeg",)),
    "another-jpeg-in-gap-512": Layout(512, 65_536, ("jpeg",)),
    # A gap holding no byte a JPEG scan cannot contain, and no EOI: the parser
    # walks straight through it, so head + gap + tail is one contiguous span
    # that decodes. Found during Batch 7, and HIGH at hwval-run4 as well.
    "directory-cluster-inside-a-span-512": Layout(512, 65_536, ("dir",)),
    "zeros-inside-a-span-4096": Layout(4096, 65_536, ("zeros", "zeros")),
    "text-inside-a-span-4096": Layout(4096, 65_536, ("text", "text")),
}

_TEXT = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. "


def _lay_out(
    layout: Layout, jpeg: bytes, neighbour: bytes
) -> tuple[bytes, set[str]]:
    """The image and the digests of every object planted in it."""
    rng = random.Random(layout.seed)
    cluster = layout.cluster
    # 37 clusters of lead-in puts the header on the image's 512-byte grid and,
    # for 512-byte clusters, off its 4096-byte one - where FINDING 1's was.
    lead = rng.randbytes(37 * cluster)
    planted = {hashlib.sha256(jpeg).hexdigest()}
    gap = b""
    for piece in layout.gap:
        if piece == "dir":
            gap += _directory_cluster(cluster)
        elif piece == "pad":
            gap += rng.randbytes(PAD_BYTES)
        elif piece == "zeros":
            gap += bytes(cluster)
        elif piece == "text":
            gap += (_TEXT * (cluster // len(_TEXT) + 1))[:cluster]
        else:
            gap += neighbour + bytes(-len(neighbour) % cluster)
            planted.add(hashlib.sha256(neighbour).hexdigest())
    assert len(gap) % cluster == 0, "the gap must be a layout an allocator can produce"
    tail = jpeg[layout.head :]
    image = (
        lead
        + jpeg[: layout.head]
        + gap
        + tail
        + bytes(-len(tail) % cluster)
        + rng.randbytes(16 * cluster)
    )
    return image, planted


def _fabricated(
    image: bytes, candidates: Iterable[dict[str, Any]], planted: set[str]
) -> list[str]:
    evidence = BytesEvidence(image)
    invented: list[str] = []
    for item in candidates:
        if item["sha256"] in planted:
            continue
        span = hashlib.sha256(evidence.read(item["offset"], item["length"])).hexdigest()
        if not item["fragments"] and item["sha256"] == span:
            continue
        runs = [(run["offset"], run["length"]) for run in item["fragments"]]
        invented.append(
            f"{item['ext']} @{item['offset']} length={item['length']} "
            f"bucket={item['bucket']} validation={item['validation']} runs={runs}"
        )
    return invented


@pytest.mark.parametrize("name", sorted(LAYOUTS))
def test_carve_structures_emits_no_fabricated_object(
    name: str, planted_jpeg: bytes, neighbour_jpeg: bytes
) -> None:
    image, planted = _lay_out(LAYOUTS[name], planted_jpeg, neighbour_jpeg)

    candidates = [
        item.model_dump() for item in carve_structures(BytesEvidence(image))
    ]

    invented = _fabricated(image, candidates, planted)
    assert not invented, (
        f"{name}: the carver emitted objects that were never on the medium: "
        f"{invented}"
    )


@pytest.mark.parametrize("name", sorted(LAYOUTS))
def test_the_carve_pipeline_emits_no_fabricated_object(
    name: str, planted_jpeg: bytes, neighbour_jpeg: bytes, tmp_path: Path
) -> None:
    """The same, through the generator the API runs, scoring and all."""
    from api.carve_job import carve_generator

    image, planted = _lay_out(LAYOUTS[name], planted_jpeg, neighbour_jpeg)
    path = tmp_path / f"{name}.dd"
    path.write_bytes(image)

    pipeline = carve_generator(path)
    try:
        while True:
            next(pipeline)
    except StopIteration as finished:
        result: dict[str, Any] = finished.value

    invented = _fabricated(image, result["candidates"], planted)
    assert not invented, (
        f"{name}: the pipeline emitted objects that were never on the medium: "
        f"{invented}"
    )


@pytest.mark.parametrize("name", sorted(LAYOUTS))
def test_nothing_that_was_never_a_file_is_called_a_whole_object(
    name: str, planted_jpeg: bytes, neighbour_jpeg: bytes, tmp_path: Path
) -> None:
    """The claim, not only the bytes.

    A contiguous span of head + foreign bytes + tail reads back to its own
    digest, so the test above does not count it. It is still an object that
    was never on the medium as a file, and ``validation: valid`` says it was a
    whole one. Every JPEG candidate whose digest matches nothing planted must
    say something else - whatever bucket it lands in.
    """
    from api.carve_job import carve_generator

    image, planted = _lay_out(LAYOUTS[name], planted_jpeg, neighbour_jpeg)
    path = tmp_path / f"{name}.dd"
    path.write_bytes(image)

    pipeline = carve_generator(path)
    try:
        while True:
            next(pipeline)
    except StopIteration as finished:
        result: dict[str, Any] = finished.value

    called_whole = [
        f"@{item['offset']} length={item['length']} bucket={item['bucket']} "
        f"detail={item['validation_detail']!r}"
        for item in result["candidates"]
        if item["ext"] == "jpg"
        and item["sha256"] not in planted
        and item["validation"] == "valid"
    ]
    assert not called_whole, (
        f"{name}: JPEGs that were never a file were reported valid: {called_whole}"
    )
