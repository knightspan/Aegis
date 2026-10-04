"""The benchmark scorer: one piece of code, and it must not favour any tool.

Every case here is an output directory built by hand against a hand-built ground
truth, so each count is known before the scorer runs.
"""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import asdict
from pathlib import Path

from testkit.benchmark import index_outputs, score_run
from testkit.damage import Truth, TruthObject


def _obj(
    name: str,
    data: bytes,
    at: int,
    *,
    fmt: str = "JPEG",
    role: str = "file",
    status: str = "FULL",
) -> TruthObject:
    return TruthObject(
        name=name,
        format=fmt,
        role=role,  # type: ignore[arg-type]
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        extents=((at, len(data)),),
        status=status,  # type: ignore[arg-type]
        surviving_bytes=len(data) if status == "FULL" else len(data) // 2,
    )


def _case(tmp_path: Path) -> tuple[Truth, Path, Path, dict[str, bytes]]:
    rng = random.Random(7)
    header = b"\xff\xd8\xff\xe0" + rng.randbytes(300)
    data = {
        "exact": header + rng.randbytes(4000),
        "corrupt": b"%PDF-1.4\n" + rng.randbytes(4000),
        "missed": b"PK\x03\x04" + rng.randbytes(4000),
        # Shares 304 leading bytes with "exact", then differs.
        "twin": header + rng.randbytes(4000),
        "partial": b"\x89PNG\r\n\x1a\n" + rng.randbytes(4000),
        "decoy": b"\xff\xd8\xff\xe0" + b"The examiner opened the image. " * 60,
        "filler": b"\x07" * 4096,
    }
    objects = (
        _obj("exact.jpg", data["exact"], 0),
        _obj("corrupt.pdf", data["corrupt"], 8192, fmt="PDF"),
        _obj("missed.zip", data["missed"], 16384, fmt="ZIP"),
        _obj("twin.jpg", data["twin"], 24576),
        _obj("partial.png", data["partial"], 32768, fmt="PNG", status="PARTIAL"),
        _obj("decoy.txt", data["decoy"], 40960, fmt="JPEG", role="decoy"),
        _obj("fill.pad", data["filler"], 49152, fmt="filler", role="unformatted"),
    )
    truth = Truth(
        image="case.img",
        corpus="test",
        model="none",
        description="hand-built",
        size_bytes=65536,
        filesystem="none",
        cluster_bytes=512,
        objects=objects,
    )
    payloads = tmp_path / "payloads"
    payloads.mkdir()
    for blob in data.values():
        (payloads / hashlib.sha256(blob).hexdigest()).write_bytes(blob)
    files = tmp_path / "files"
    (files / "nested").mkdir(parents=True)
    return truth, files, payloads, data


def test_every_output_class_is_counted_once(tmp_path: Path) -> None:
    truth, files, payloads, data = _case(tmp_path)
    rng = random.Random(8)
    (files / "a.jpg").write_bytes(data["exact"])
    (files / "nested" / "a-again.jpg").write_bytes(data["exact"])  # duplicate
    (files / "b.pdf").write_bytes(data["corrupt"][:3000] + rng.randbytes(900))
    (files / "p.png").write_bytes(data["partial"][:2000])  # PARTIAL, returned
    (files / "inner.bin").write_bytes(data["missed"][1000:2000])  # fragment
    (files / "decoy.jpg").write_bytes(data["decoy"][:1500])
    (files / "noise.bin").write_bytes(rng.randbytes(2048))  # unrelated
    # Agrees with "exact" and "twin" for all 304 bytes it has: ambiguous.
    (files / "header-only.jpg").write_bytes(data["exact"][:304])
    (files / "fill.pad").write_bytes(data["filler"])  # unformatted, exact
    # A tool's own report is never scored, whatever it contains.
    (files / "audit.txt").write_bytes(data["twin"])

    result = score_run(truth, files, payloads, tool="any")

    assert (result.full, result.exact, result.corrupt, result.missed) == (4, 1, 1, 2)
    assert result.outcomes["exact.jpg"] == "exact"
    assert result.outcomes["corrupt.pdf"] == "corrupt"
    assert result.outcomes["missed.zip"] == "missed"
    assert result.outcomes["twin.jpg"] == "missed"
    assert (result.partial, result.partial_returned, result.partial_exact) == (1, 1, 0)
    assert (result.unformatted_full, result.unformatted_exact) == (1, 1)
    assert result.duplicate_outputs == 1
    assert (result.fp_fragment, result.fp_decoy) == (1, 1)
    assert (result.fp_ambiguous, result.fp_unrelated) == (1, 1)
    assert result.fp_total == 4
    assert result.outputs == 9
    assert result.formats["JPEG"] == {"full": 2, "exact": 1, "corrupt": 0, "missed": 1}


def test_the_score_does_not_depend_on_the_tool_or_file_names(tmp_path: Path) -> None:
    truth, files, payloads, data = _case(tmp_path)
    (files / "f0001234.jpg").write_bytes(data["exact"])
    (files / "00000017.pdf").write_bytes(data["corrupt"][:2000])
    first = asdict(score_run(truth, files, payloads, tool="photorec"))
    for path in list(files.iterdir()):
        if path.is_file():
            path.rename(path.with_name("renamed-" + path.name + ".out"))
    second = asdict(score_run(truth, files, payloads, tool="sanctum-carve"))
    first.pop("tool")
    second.pop("tool")
    assert first == second


def test_only_restricts_the_outputs_scored(tmp_path: Path) -> None:
    truth, files, payloads, data = _case(tmp_path)
    (files / "keep.jpg").write_bytes(data["exact"])
    (files / "drop.pdf").write_bytes(data["corrupt"])
    result = score_run(truth, files, payloads, tool="x", only={"keep.jpg"})
    assert (result.outputs, result.exact) == (1, 1)
    assert result.outcomes["corrupt.pdf"] == "missed"


def test_scoring_the_output_index_equals_scoring_the_files(tmp_path: Path) -> None:
    truth, files, payloads, data = _case(tmp_path)
    (files / "a.jpg").write_bytes(data["exact"])
    (files / "b.pdf").write_bytes(data["corrupt"][:3000] + b"x" * 90_000)
    (files / "nested" / "inner.bin").write_bytes(data["missed"][1000:2000])
    (files / "audit.txt").write_bytes(data["twin"])
    index = tmp_path / "outputs.json"
    index.write_text(json.dumps(index_outputs(files)))
    from_files = asdict(score_run(truth, files, payloads, tool="t"))
    from_index = asdict(score_run(truth, index, payloads, tool="t"))
    assert from_files == from_index
    assert from_index["exact"] == 1 and from_index["corrupt"] == 1
