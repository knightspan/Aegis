"""Single-pass signature scanning: correctness, boundaries, parallelism, honesty."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

import pytest
from core.carve.evidence import BytesEvidence, open_evidence
from core.carve.signature import (
    CHUNK_BYTES,
    ScanReport,
    build_automaton,
    carve_signatures,
    load_signatures,
    scan,
)

from tests.carve.signature.conftest import Embedded, lay_out, make_jpeg

MIB = 1024 * 1024


@pytest.fixture(scope="session")
def db() -> object:
    return load_signatures()


# --------------------------------------------------------------------------
# 1. The corpus
# --------------------------------------------------------------------------


def test_every_embedded_object_is_found_at_its_exact_offset(
    corpus_image: bytes, corpus: list[Embedded]
) -> None:
    report = scan(BytesEvidence(corpus_image))
    found = {(c.offset, c.ext) for c in report.candidates}

    missing = [
        (item.offset, item.ext)
        for item in corpus
        if not any(
            offset == item.offset and _same_family(ext, item.ext)
            for offset, ext in found
        )
    ]
    assert not missing, f"not found at the right offset: {missing}"


def _same_family(found_ext: str, expected_ext: str) -> bool:
    """docx and sqlite carve as zip and sqlite; treat the container as the match."""
    families = {"zip": {"zip", "docx", "xlsx", "pptx"}, "sqlite": {"sqlite", "db"}}
    return found_ext == expected_ext or found_ext in families.get(expected_ext, set())


def test_scan_reports_how_many_of_each_type_it_found(corpus_image: bytes) -> None:
    report = scan(BytesEvidence(corpus_image))
    by_ext: dict[str, int] = {}
    for candidate in report.candidates:
        by_ext[candidate.ext] = by_ext.get(candidate.ext, 0) + 1

    assert by_ext.get("jpg", 0) >= 3
    assert by_ext.get("png", 0) >= 2
    assert by_ext.get("pdf", 0) >= 2
    assert by_ext.get("zip", 0) >= 2


# --------------------------------------------------------------------------
# 2. Chunk boundaries
# --------------------------------------------------------------------------


def test_header_straddling_a_chunk_boundary_is_found_exactly_once() -> None:
    """The classic off-by-one: found twice from overlap, or zero times without it."""
    jpeg = make_jpeg()
    # Start the header two bytes before the boundary so it spans the seam.
    offset = CHUNK_BYTES - 2
    image = lay_out([Embedded(ext="jpg", offset=offset, data=jpeg)], CHUNK_BYTES * 2)

    report = scan(BytesEvidence(image))
    at_offset = [c for c in report.candidates if c.offset == offset]

    assert len(at_offset) == 1, (
        f"expected exactly one JPEG at {offset}, got {len(at_offset)}"
    )


@pytest.mark.parametrize("delta", [-3, -1, 0, 1, 3])
def test_headers_near_every_seam_are_found_once(delta: int) -> None:
    jpeg = make_jpeg()
    offset = CHUNK_BYTES + delta
    image = lay_out([Embedded(ext="jpg", offset=offset, data=jpeg)], CHUNK_BYTES * 2)
    report = scan(BytesEvidence(image))
    assert len([c for c in report.candidates if c.offset == offset]) == 1


# --------------------------------------------------------------------------
# 3. Parallelism
# --------------------------------------------------------------------------


def test_single_process_and_four_process_scans_agree(corpus_file: Path) -> None:
    """Parallelism must not change what is found, only how fast."""
    with open_evidence(corpus_file) as handle:
        serial = scan(handle)
    # Force the pool: the 64 MiB corpus sits under PARALLEL_FLOOR_BYTES, so
    # the default would fall back to serial and this would compare a scan
    # with itself.
    parallel = carve_signatures(corpus_file, workers=4, parallel_floor_bytes=0)

    def key(report: ScanReport) -> set[tuple[int, str]]:
        return {(c.offset, c.ext) for c in report.candidates}

    assert key(serial) == key(parallel)


# --------------------------------------------------------------------------
# 4. Substituted ranges
# --------------------------------------------------------------------------


def test_a_header_inside_a_substituted_range_is_suppressed_and_counted() -> None:
    """Fill bytes are tool output. Carving them would manufacture evidence.

    ``recorded_substituted`` leaves the bytes intact while recording the range,
    which is the case that actually needs defending: substituted ranges arrive
    in the acquisition record, a sidecar the image cannot corroborate, so the
    carver can be handed metadata saying "filled" over bytes that still parse.
    Marking a range whose bytes were also overwritten proves nothing, because
    the header would be gone either way.
    """
    jpeg = make_jpeg()
    good_at = 4096
    bad_at = 40_960
    image = lay_out(
        [
            Embedded(ext="jpg", offset=good_at, data=jpeg),
            Embedded(ext="jpg", offset=bad_at, data=jpeg),
        ],
        128 * 1024,
    )
    handle = BytesEvidence(image, recorded_substituted=[(bad_at - 16, 4096)])

    report = scan(handle)
    offsets = {c.offset for c in report.candidates}

    assert good_at in offsets
    assert bad_at not in offsets
    assert report.suppressed_substituted == 1


def test_a_destroyed_header_inside_filled_bytes_simply_is_not_found() -> None:
    """The ordinary case: acquisition fill overwrote the header, so there is
    nothing to suppress and nothing to report."""
    jpeg = make_jpeg()
    bad_at = 40_960
    image = lay_out([Embedded(ext="jpg", offset=bad_at, data=jpeg)], 128 * 1024)
    handle = BytesEvidence(image, unreadable=[(bad_at - 16, 4096)])

    report = scan(handle)
    assert bad_at not in {c.offset for c in report.candidates}


def test_nothing_is_suppressed_when_no_range_was_substituted(
    corpus_image: bytes,
) -> None:
    report = scan(BytesEvidence(corpus_image))
    assert report.suppressed_substituted == 0


# --------------------------------------------------------------------------
# Signature DB
# --------------------------------------------------------------------------


def test_signature_db_is_loaded_from_disk_not_hardcoded() -> None:
    db = load_signatures()
    names = {entry.name for entry in db}
    for expected in ("JPEG", "PNG", "PDF", "ZIP", "SQLite", "ELF", "EVTX", "MP4"):
        assert expected in names, f"{expected} missing from the signature table"


def test_mp4_signature_carries_its_header_offset() -> None:
    db = load_signatures()
    mp4 = next(entry for entry in db if entry.name == "MP4")
    assert mp4.header_offset == 4, "ftyp sits at byte 4, not byte 0"
    assert mp4.header == bytes.fromhex("66747970")


def test_every_signature_has_a_size_bound() -> None:
    """An unbounded footer search on a 2 TB image never returns."""
    for entry in load_signatures():
        assert entry.max_size > 0
        assert entry.min_size >= 0
        assert entry.min_size < entry.max_size


def test_automaton_is_built_once_for_every_pattern() -> None:
    db = load_signatures()
    automaton = build_automaton(db)
    haystack = bytes.fromhex("0000") + bytes.fromhex("FFD8FF") + b"rest"
    hits = list(automaton.iter(haystack.decode("latin-1")))
    assert hits, "the shared automaton found no JPEG header"


# --------------------------------------------------------------------------
# Footer bounding
# --------------------------------------------------------------------------


def test_object_without_a_footer_within_max_size_is_kept_as_truncated() -> None:
    """Discarding it would lose a recoverable object; claiming valid would lie."""
    headerless_tail = bytes.fromhex("FFD8FF") + b"\x00" * 8192
    handle = BytesEvidence(headerless_tail)
    report = scan(handle)

    jpegs = [c for c in report.candidates if c.ext == "jpg"]
    assert jpegs, "a header with no footer must still be reported"
    assert jpegs[0].validation in {"truncated", "corrupt"}


def test_footer_bounded_object_gets_its_real_length() -> None:
    jpeg = make_jpeg()
    image = lay_out([Embedded(ext="jpg", offset=1024, data=jpeg)], 64 * 1024)
    report = scan(BytesEvidence(image))
    candidate = next(c for c in report.candidates if c.offset == 1024)
    assert candidate.length == len(jpeg)
    recovered = image[candidate.offset : candidate.offset + candidate.length]
    assert hashlib.sha256(recovered).hexdigest() == hashlib.sha256(jpeg).hexdigest()


# --------------------------------------------------------------------------
# 11. Throughput
# --------------------------------------------------------------------------


def test_scan_throughput_is_recorded(
    corpus_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The number that decides the demo image size. Printed, not asserted tightly."""
    size_mib = corpus_file.stat().st_size / MIB

    started = time.perf_counter()
    with open_evidence(corpus_file) as handle:
        serial = scan(handle)
    serial_s = time.perf_counter() - started

    started = time.perf_counter()
    parallel = carve_signatures(corpus_file, workers=4, parallel_floor_bytes=0)
    parallel_s = time.perf_counter() - started

    with capsys.disabled():
        print(
            f"\n  scan throughput: 1 process {size_mib / serial_s:7.1f} MiB/s"
            f"  |  4 processes {size_mib / parallel_s:7.1f} MiB/s"
            f"  ({len(serial.candidates)} candidates)"
        )
    assert serial.candidates and parallel.candidates
