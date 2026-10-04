"""Deterministic recovery demo: difficult objects, real carver, ground truth.

    .venv/bin/python scripts/demo_fragmented.py [--json OUT.json]

Builds one synthetic image on host storage (a temporary directory, removed
afterwards), runs the real recovery pipeline over it (``carve_generator``, the
same one the API runs, undelete off because the image has no filesystem), and
prints every candidate against the ground truth the builder recorded:

* a PNG split into two runs by a 32 KiB gap;
* a baseline JPEG split into two runs by a 32 KiB gap;
* an intact PNG, and an exact duplicate of it;
* a PNG whose tail's first cluster was overwritten, which must not be rebuilt;
* a decoy: a PNG signature followed by noise, which must not reach HIGH.

Population label: SYNTHETIC. No device is opened. The image, the seed and the
layout are fixed, so two runs print the same candidates and the same digests.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import random
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:  # pragma: no cover - import bootstrap
    sys.path.insert(0, str(ROOT))

from PIL import Image  # noqa: E402

CLUSTER = 4096
SEED = 26149


def _noise_image(size: int, seed: int) -> Image.Image:
    rng = random.Random(seed)
    image = Image.new("RGB", (size, size))
    image.putdata(
        [
            (rng.randrange(256), rng.randrange(256), rng.randrange(256))
            for _ in range(size * size)
        ]
    )
    return image


def _png(seed: int) -> bytes:
    buffer = io.BytesIO()
    _noise_image(192, seed).save(buffer, "PNG")
    return buffer.getvalue()


def _jpeg(seed: int) -> bytes:
    buffer = io.BytesIO()
    _noise_image(192, seed).save(buffer, "JPEG", quality=90)
    return buffer.getvalue()


def _pad(data: bytes) -> bytes:
    return data + bytes(-len(data) % CLUSTER)


def build(rng: random.Random) -> tuple[bytes, list[dict[str, Any]]]:
    """The image and its ground truth. Every object starts on a cluster."""
    out = bytearray(rng.randbytes(4 * CLUSTER))
    truth: list[dict[str, Any]] = []

    def place(label: str, data: bytes, expect: str, original: bytes | None) -> None:
        truth.append(
            {
                "label": label,
                "offset": len(out),
                "expect": expect,
                "sha256": hashlib.sha256(original).hexdigest() if original else None,
            }
        )
        out.extend(_pad(data))
        out.extend(rng.randbytes(2 * CLUSTER))

    png = _png(SEED)
    place(
        "png split by a 32 KiB gap",
        png[: 3 * CLUSTER] + rng.randbytes(8 * CLUSTER) + png[3 * CLUSTER :],
        "reassembled from two runs, below HIGH",
        png,
    )
    jpeg = _jpeg(SEED + 1)
    place(
        "jpeg split by a 32 KiB gap",
        jpeg[: 2 * CLUSTER] + rng.randbytes(8 * CLUSTER) + jpeg[2 * CLUSTER :],
        "reassembled from two runs, below HIGH",
        jpeg,
    )
    intact = _png(SEED + 2)
    place("intact png", intact, "recovered whole, HIGH", intact)
    place(
        "duplicate of the intact png", intact, "same digest as the intact png", intact
    )
    lost = _png(SEED + 3)
    damaged = bytearray(
        lost[: 3 * CLUSTER] + rng.randbytes(8 * CLUSTER) + lost[3 * CLUSTER :]
    )
    tail = 3 * CLUSTER + 8 * CLUSTER
    damaged[tail : tail + CLUSTER] = rng.randbytes(CLUSTER)
    place(
        "png whose tail was overwritten", bytes(damaged), "not rebuilt, not valid", None
    )
    place(
        "decoy png signature",
        b"\x89PNG\r\n\x1a\n" + rng.randbytes(3 * CLUSTER),
        "never HIGH",
        None,
    )
    return bytes(out), truth


def run(work: Path) -> dict[str, Any]:
    # Local: build() needs only PIL, and importing api.carve_job pulls in the
    # whole application dependency stack (structlog, fastapi, pydantic, ...).
    # scripts/package_carve_smoke.py imports this module for build() alone,
    # in an environment that deliberately has none of that installed.
    from api.carve_job import carve_generator

    image_bytes, truth = build(random.Random(SEED))
    image = work / "demo-fragmented.img"
    image.write_bytes(image_bytes)
    generator = carve_generator(image, undelete=False, out_dir=work / "recovered")
    try:
        while True:
            next(generator)
    except StopIteration as done:
        result: dict[str, Any] = done.value
    rows = []
    for item in truth:
        found = [
            c
            for c in result["candidates"]
            if int(c.get("offset", -1)) == item["offset"]
        ]
        best = max(found, key=lambda c: int(c.get("confidence_bp") or 0), default=None)
        folded_into = next(
            (
                int(c["offset"])
                for c in result["candidates"]
                if item["offset"] in (c.get("duplicate_offsets") or [])
            ),
            None,
        )
        rows.append(
            {
                **item,
                "found": best is not None,
                "duplicate_of": folded_into,
                "validation": best.get("validation") if best else None,
                "bucket": best.get("bucket") if best else None,
                "evidence_score": best.get("confidence_bp") if best else None,
                "runs": [
                    [run["offset"], run["length"]]
                    for run in (best or {}).get("fragments") or []
                ],
                "digest_matches_ground_truth": (
                    bool(
                        best and item["sha256"] and best.get("sha256") == item["sha256"]
                    )
                ),
                "score_components": (best or {}).get("score_components") or {},
            }
        )
    return {
        "population": "SYNTHETIC",
        "seed": SEED,
        "image_bytes": len(image_bytes),
        "image_sha256": hashlib.sha256(image_bytes).hexdigest(),
        "candidates_total": len(result["candidates"]),
        "rows": rows,
    }


def render(report: dict[str, Any]) -> str:
    lines = [
        "SYNTHETIC IMAGE / NO PHYSICAL DEVICE OPENED",
        f"image {report['image_bytes']} bytes, sha256 {report['image_sha256']}",
        f"seed {report['seed']}, {report['candidates_total']} candidates in total",
        "",
    ]
    for row in report["rows"]:
        lines.append(f"{row['label']}  (offset {row['offset']})")
        lines.append(f"  expected   {row['expect']}")
        if not row["found"] and row["duplicate_of"] is not None:
            lines.append(
                "  result     deduplicated: identical SHA-256 to the candidate at "
                f"offset {row['duplicate_of']}, which lists this offset"
            )
        elif not row["found"]:
            lines.append("  result     no candidate at this offset")
        else:
            lines.append(
                f"  result     {row['validation']}, {row['bucket']}, "
                f"evidence score {row['evidence_score']} / 10000"
            )
            if row["runs"]:
                lines.append(f"  runs       {row['runs']}")
            if row["sha256"]:
                lines.append(
                    "  digest     "
                    + (
                        "matches ground truth"
                        if row["digest_matches_ground_truth"]
                        else "DOES NOT match ground truth"
                    )
                )
            components = ", ".join(
                f"{name} {value}" for name, value in row["score_components"].items()
            )
            lines.append(f"  why        {components}")
        lines.append("")
    lines.append(
        "The evidence score is a sum of evidence components, not a probability."
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", type=Path, help="also write the rows as JSON")
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="sanctum-demo-") as scratch:
        report = run(Path(scratch))
    sys.stdout.write(render(report) + "\n")
    if args.json:
        args.json.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":  # pragma: no cover - process entry point
    raise SystemExit(main())
