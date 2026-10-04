"""What a cancelled carve leaves behind, and what the chain says about it.

MANUAL_REPORT FINDING 3. ``core/erase/drive.py`` and ``core/carve/acquire.py``
catch ``GeneratorExit`` and record what the cancelled operation left. The carve
pipeline did not: a cancelled carve left ``carve.start`` alone in the chain,
with recovered objects already in ``out_dir`` and nothing enumerating them.

The same discipline as ``acquire.cancelled``: say what is on disk, and publish
nothing that attests to more than was done. ``carve.complete`` carries a
``findings_sha256`` over the final candidate list; a cancelled run has no final
candidate list, so it has no such digest.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import pytest
from api.carve_job import carve_generator
from core.ledger.chain import ChainStatus, Ledger
from PIL import Image

MIB = 1024 * 1024


def _jpeg(colour: tuple[int, int, int]) -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", (64, 64), colour).save(buffer, "JPEG", quality=90)
    return buffer.getvalue()


@pytest.fixture
def image(tmp_path: Path) -> Path:
    total = 2 * MIB
    canvas = bytearray()
    seed = 0x13579BDF
    while len(canvas) < total:
        seed = (seed * 1103515245 + 12345) & 0xFFFFFFFF
        canvas += seed.to_bytes(4, "little")
    canvas = canvas[:total]
    for index, colour in enumerate([(200, 30, 30), (30, 200, 90)]):
        payload = _jpeg(colour)
        at = index * (total // 2) + 1337
        canvas[at : at + len(payload)] = payload
    path = tmp_path / "case.dd"
    path.write_bytes(bytes(canvas))
    return path


def _ledger(tmp_path: Path) -> Ledger:
    return Ledger(tmp_path / "ledger", tool_version="t", pubkey_fingerprint="AA:BB")


def _cancel_after(
    image: Path, chain: Ledger | None, phase: str, out_dir: Path | None
) -> None:
    """Run the carve until it yields ``phase``, then close it as the registry does."""
    generator = carve_generator(
        image, undelete=False, out_dir=out_dir, job_id="carve-cancel", ledger=chain
    )
    for record in generator:
        if record.phase == phase:
            break
    else:  # pragma: no cover - the fixture always reaches every phase
        raise AssertionError(f"never reached {phase}")
    generator.close()


def _operations(chain: Ledger) -> list[str]:
    return [entry.operation for entry in chain.entries()]


def _payload(chain: Ledger) -> dict[str, Any]:
    entry = next(e for e in chain.entries() if e.operation == "carve.cancelled")
    return chain.params_of(entry)


def test_a_carve_cancelled_after_writing_enumerates_the_objects_on_disk(
    image: Path, tmp_path: Path
) -> None:
    chain = _ledger(tmp_path)
    out_dir = tmp_path / "recovered"

    _cancel_after(image, chain, "write", out_dir)

    assert "carve.cancelled" in _operations(chain)
    assert "carve.complete" not in _operations(chain)

    payload = _payload(chain)
    on_disk = sorted(str(path) for path in out_dir.iterdir())
    assert on_disk, "the fixture must have written something for this to mean anything"
    assert sorted(payload["objects_written"]) == on_disk
    assert payload["objects_written_count"] == len(on_disk)
    assert payload["job_id"] == "carve-cancel"
    assert payload["phase_reached"] == "write"
    assert payload["evidence"]["path"] == str(image)
    assert payload["bytes_scanned"] == image.stat().st_size
    assert payload["out_dir"] == str(out_dir)
    assert "CANCELLED" in payload["note"]


def test_a_carve_cancelled_before_the_scan_says_nothing_was_scanned(
    image: Path, tmp_path: Path
) -> None:
    chain = _ledger(tmp_path)
    out_dir = tmp_path / "recovered"

    _cancel_after(image, chain, "open", out_dir)

    payload = _payload(chain)
    assert payload["phase_reached"] == "open"
    assert payload["bytes_scanned"] == 0
    assert payload["objects_written"] == []
    assert not out_dir.exists() or not any(out_dir.iterdir())


def test_the_entry_refuses_to_publish_a_findings_digest(
    image: Path, tmp_path: Path
) -> None:
    """``findings_sha256`` means "this is the list". A cancelled run has no list."""
    chain = _ledger(tmp_path)

    _cancel_after(image, chain, "write", tmp_path / "recovered")

    entry = next(e for e in chain.entries() if e.operation == "carve.cancelled")
    assert "findings_sha256" not in chain.params_of(entry)
    assert "findings_sha256" not in chain.result_of(entry)
    assert "No findings_sha256 is recorded" in _payload(chain)["note"]


def test_the_chain_is_still_valid_after_a_cancelled_carve(
    image: Path, tmp_path: Path
) -> None:
    chain = _ledger(tmp_path)

    _cancel_after(image, chain, "signatures", tmp_path / "recovered")

    verification = chain.verify(check_blobs=True)
    assert verification.status is ChainStatus.VALID, verification.explanation


def test_a_completed_carve_records_no_cancellation(image: Path, tmp_path: Path) -> None:
    chain = _ledger(tmp_path)
    generator = carve_generator(
        image, undelete=False, out_dir=tmp_path / "recovered",
        job_id="carve-whole", ledger=chain,
    )
    for _ in generator:
        pass

    assert "carve.cancelled" not in _operations(chain)
    assert "carve.complete" in _operations(chain)


def test_cancelling_an_unledgered_carve_does_not_raise(
    image: Path, tmp_path: Path
) -> None:
    _cancel_after(image, None, "signatures", tmp_path / "recovered")
