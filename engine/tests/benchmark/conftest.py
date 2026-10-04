"""A tiny hand-built corpus, so every count in these tests is known in advance.

Everything lives in ``tmp_path``: a 64 KiB image file with objects planted at
fixed offsets (two of them in two runs each), its ``.truth.json`` in the shape
the testkit builders write, a payload store keyed by SHA-256, and an output
directory a test fills with whatever a "tool" returned. No device is involved.
"""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

KIB = 1024
IMAGE_NAME = "media-fat32-255m.img"


@dataclass
class Plant:
    name: str
    fmt: str
    data: bytes
    runs: list[tuple[int, int]]
    role: str = "file"
    status: str = "FULL"


@dataclass
class Corpus:
    root: Path
    image: Path
    truth: Path
    payloads: Path
    outputs: Path
    plants: dict[str, Plant] = field(default_factory=dict)

    def data(self, name: str) -> bytes:
        return self.plants[name].data

    def put(self, relative: str, blob: bytes) -> Path:
        path = self.outputs / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)
        return path


def _plants() -> list[Plant]:
    rng = random.Random(26149)
    jpeg = b"\xff\xd8\xff\xe0" + rng.randbytes(4000)
    pdf = b"%PDF-1.4\n" + rng.randbytes(4000)
    zipf = b"PK\x03\x04" + rng.randbytes(4000)
    png = b"\x89PNG\r\n\x1a\n" + rng.randbytes(6000)
    gif = b"GIF89a" + rng.randbytes(6000)
    partial = b"II*\x00" + rng.randbytes(3000)
    decoy = b"\xff\xd8\xff\xdb" + b"The examiner opened the image. " * 60
    filler = b"\x07" * 2048
    return [
        Plant("exact.jpg", "JPEG", jpeg, [(0, len(jpeg))]),
        Plant("corrupt.pdf", "PDF", pdf, [(8 * KIB, len(pdf))]),
        Plant("missed.zip", "ZIP", zipf, [(16 * KIB, len(zipf))]),
        # Two runs each, with other bytes between: the fragmented cases.
        Plant("frag.png", "PNG", png, [(24 * KIB, 3000), (40 * KIB, len(png) - 3000)]),
        Plant("frag.gif", "GIF", gif, [(28 * KIB, 3000), (48 * KIB, len(gif) - 3000)]),
        Plant(
            "partial.tif", "TIFF", partial, [(32 * KIB, len(partial))], status="PARTIAL"
        ),
        Plant("decoy.txt", "JPEG", decoy, [(56 * KIB, len(decoy))], role="decoy"),
        Plant(
            "fill.pad", "filler", filler, [(62 * KIB, len(filler))], role="unformatted"
        ),
    ]


def build_corpus(root: Path, image_name: str = IMAGE_NAME) -> Corpus:
    """Write the image, its truth and its payloads under ``root``."""
    images = root / "images"
    payloads = root / "payloads"
    outputs = root / "outputs"
    for folder in (images, payloads, outputs):
        folder.mkdir(parents=True, exist_ok=True)
    medium = bytearray(random.Random(7).randbytes(64 * KIB))
    objects: list[dict[str, Any]] = []
    corpus = Corpus(
        root=root,
        image=images / image_name,
        truth=images / f"{image_name.removesuffix('.img')}.truth.json",
        payloads=payloads,
        outputs=outputs,
    )
    for plant in _plants():
        corpus.plants[plant.name] = plant
        position = 0
        for offset, length in plant.runs:
            medium[offset : offset + length] = plant.data[position : position + length]
            position += length
        digest = hashlib.sha256(plant.data).hexdigest()
        (payloads / digest).write_bytes(plant.data)
        objects.append(
            {
                "name": plant.name,
                "format": plant.fmt,
                "role": plant.role,
                "sha256": digest,
                "size": len(plant.data),
                "extents": [list(run) for run in plant.runs],
                "status": plant.status,
                "surviving_bytes": len(plant.data)
                if plant.status == "FULL"
                else len(plant.data) // 2,
                "deleted": True,
                "note": "",
                "hole_bytes": 0,
            }
        )
    corpus.image.write_bytes(bytes(medium))
    truth = {
        "image": image_name,
        "corpus": "test",
        "model": "delete",
        "description": "hand-built",
        "size_bytes": len(medium),
        "filesystem": "none",
        "cluster_bytes": 512,
        "base_image": "",
        "parameters": {},
        "damaged": [],
        "objects": objects,
        "version": 1,
    }
    corpus.truth.write_text(json.dumps(truth, indent=1), encoding="utf-8")
    return corpus


def fill_outputs(corpus: Corpus) -> None:
    """One output of every kind the scorer distinguishes."""
    rng = random.Random(8)
    corpus.put("a/exact.jpg", corpus.data("exact.jpg"))
    corpus.put("b/exact-again.jpg", corpus.data("exact.jpg"))  # duplicate
    pdf = corpus.data("corrupt.pdf")
    # First 3000 bytes right, every later byte inverted: agreement is exact.
    corpus.put("c/corrupt.pdf", pdf[:3000] + bytes(b ^ 0xFF for b in pdf[3000:]))
    corpus.put("d/frag.png", corpus.data("frag.png"))  # fragmented, byte-identical
    corpus.put("e/partial.tif", corpus.data("partial.tif")[:1500])  # PARTIAL, returned
    corpus.put("f/inner.bin", corpus.data("missed.zip")[1000:2000])  # fp fragment
    corpus.put("g/noise.bin", rng.randbytes(2048))  # fp unrelated
    corpus.put("h/decoy.jpg", corpus.data("decoy.txt")[:1500])  # fp decoy
    corpus.put("i/fill.pad", corpus.data("fill.pad"))  # unformatted, exact
    corpus.put("audit.txt", corpus.data("missed.zip"))  # a tool report: never scored


@pytest.fixture
def corpus(tmp_path: Path) -> Corpus:
    return build_corpus(tmp_path / "corpus")


@pytest.fixture
def filled(corpus: Corpus) -> Corpus:
    fill_outputs(corpus)
    return corpus
