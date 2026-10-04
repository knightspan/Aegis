"""The read-only evidence surface. Contract tests, no real device access.

The single rule this module exists to enforce: nothing downstream can write
to evidence, and nothing downstream can mistake a substituted byte for a byte
that was actually read. Every test here defends one of those two.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from core.carve.evidence import (
    BytesEvidence,
    EvidenceHandle,
    RawEvidence,
    SplitRawEvidence,
    WindowedEvidence,
    open_evidence,
)
from core.errors import EvidenceIntegrityError

PATTERN = bytes(range(256))


def _blob(n_blocks: int = 16) -> bytes:
    return PATTERN * n_blocks


@pytest.fixture
def raw_image(tmp_path: Path) -> Path:
    path = tmp_path / "disk.dd"
    path.write_bytes(_blob())
    return path


# --------------------------------------------------------------------------
# The no-write guarantee
# --------------------------------------------------------------------------


def _handles(tmp_path: Path) -> list[EvidenceHandle]:
    raw = tmp_path / "h.dd"
    raw.write_bytes(_blob())
    seg = tmp_path / "s.001"
    seg.write_bytes(_blob(8))
    (tmp_path / "s.002").write_bytes(_blob(8))
    return [
        BytesEvidence(_blob()),
        RawEvidence(raw),
        SplitRawEvidence([seg, tmp_path / "s.002"]),
        WindowedEvidence(BytesEvidence(_blob()), base_offset=256, length=512),
    ]


@pytest.mark.parametrize("index", range(4))
def test_no_implementation_exposes_a_write_method(tmp_path: Path, index: int) -> None:
    """Not 'raises on write' - the method must not exist to be called.

    A method that raises can still be reached by a caller who catches broadly.
    An attribute that is absent cannot.
    """
    handle = _handles(tmp_path)[index]
    for name in ("write", "write_at", "writable", "truncate", "seek_write"):
        assert not hasattr(handle, name), f"{type(handle).__name__} exposes {name}"
    assert "write" not in dir(handle)


def test_opening_evidence_never_requests_write_access(
    raw_image: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Guards the CLAUDE.md non-negotiable at the syscall, not by convention."""
    seen: list[int] = []
    real_open = os.open

    def spy(path: object, flags: int, *args: object, **kwargs: object) -> int:
        seen.append(flags)
        return real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", spy)
    with RawEvidence(raw_image) as handle:
        handle.read(0, 16)

    assert seen, "expected at least one os.open call"
    for flags in seen:
        assert flags & os.O_WRONLY == 0
        assert flags & os.O_RDWR == 0


# --------------------------------------------------------------------------
# read() contract
# --------------------------------------------------------------------------


def test_read_past_end_returns_short_rather_than_raising() -> None:
    handle = BytesEvidence(b"abcd")
    assert handle.read(2, 100) == b"cd"
    assert handle.read(4, 10) == b""
    assert handle.read(99, 10) == b""


def test_read_rejects_a_negative_offset() -> None:
    with pytest.raises(ValueError):
        BytesEvidence(b"abcd").read(-1, 4)


def test_substituted_bytes_are_distinguishable_from_real_ones() -> None:
    """A real zero and a filled-in zero must never look alike to a caller."""
    handle = BytesEvidence(b"\x00" * 64, unreadable=[(16, 16)])

    assert handle.read(0, 64) == b"\x00" * 64
    assert handle.was_substituted(16, 16) is True
    assert handle.was_substituted(0, 16) is False
    assert handle.was_substituted(32, 32) is False
    assert [(r.offset, r.length) for r in handle.source.substituted_ranges] == [
        (16, 16)
    ]


def test_was_substituted_is_true_when_any_byte_in_the_range_was_filled() -> None:
    """Over-flags rather than under-flags: partial contamination is contamination."""
    handle = BytesEvidence(b"\x00" * 64, unreadable=[(32, 8)])

    assert handle.was_substituted(0, 64) is True
    assert handle.was_substituted(31, 2) is True
    assert handle.was_substituted(39, 2) is True
    assert handle.was_substituted(0, 32) is False
    assert handle.was_substituted(40, 24) is False


def test_substituted_in_reports_the_overlapping_ranges() -> None:
    handle = BytesEvidence(b"\x00" * 128, unreadable=[(16, 16), (96, 8)])
    overlapping = handle.substituted_in(0, 64)
    assert [(r.offset, r.length) for r in overlapping] == [(16, 16)]
    assert handle.substituted_in(48, 8) == []


# --------------------------------------------------------------------------
# Split sets
# --------------------------------------------------------------------------


def test_split_set_reads_across_every_segment_boundary(tmp_path: Path) -> None:
    segments = []
    for index in range(5):
        path = tmp_path / f"img.00{index + 1}"
        path.write_bytes(bytes([index]) * 100)
        segments.append(path)

    handle = SplitRawEvidence(segments)
    assert handle.size == 500
    # A read spanning three segments in one call.
    assert handle.read(50, 200) == b"\x00" * 50 + b"\x01" * 100 + b"\x02" * 50
    # Exactly on a boundary.
    assert handle.read(100, 1) == b"\x01"
    assert handle.read(99, 2) == b"\x00\x01"


def test_missing_middle_segment_names_the_file_it_could_not_find(
    tmp_path: Path,
) -> None:
    for index in (1, 2, 4):
        (tmp_path / f"img.00{index}").write_bytes(b"x" * 10)

    with pytest.raises(EvidenceIntegrityError) as excinfo:
        open_evidence(tmp_path / "img.001")

    assert "img.003" in str(excinfo.value)


# --------------------------------------------------------------------------
# Windowing
# --------------------------------------------------------------------------


def test_window_translates_offsets_against_its_parent() -> None:
    parent = BytesEvidence(bytes(range(256)))
    window = WindowedEvidence(parent, base_offset=64, length=32)

    assert window.size == 32
    assert window.read(0, 4) == bytes([64, 65, 66, 67])
    assert window.read(31, 1) == bytes([95])
    # Past the window end is short, and never leaks the parent's bytes.
    assert window.read(31, 8) == bytes([95])
    assert window.read(32, 8) == b""


def test_window_refuses_to_extend_past_its_parent() -> None:
    with pytest.raises(ValueError):
        WindowedEvidence(BytesEvidence(b"abcd"), base_offset=2, length=99)


def test_window_reports_substitution_from_its_parent() -> None:
    parent = BytesEvidence(b"\x00" * 128, unreadable=[(64, 16)])
    window = WindowedEvidence(parent, base_offset=60, length=32)
    assert window.was_substituted(4, 16) is True
    assert window.was_substituted(0, 4) is False


# --------------------------------------------------------------------------
# Format detection
# --------------------------------------------------------------------------


def test_format_is_detected_by_magic_not_extension(tmp_path: Path) -> None:
    """A raw image named .E01 is still raw. Filenames are not evidence."""
    liar = tmp_path / "actually_raw.E01"
    liar.write_bytes(_blob())
    with open_evidence(liar) as handle:
        assert handle.read(0, 4) == PATTERN[:4]
        assert handle.source.fmt == "raw"


def test_aff4_is_refused_with_a_message_naming_the_format(tmp_path: Path) -> None:
    path = tmp_path / "case.aff4"
    path.write_bytes(b"AFF4" + b"\x00" * 512)
    with pytest.raises(EvidenceIntegrityError, match="AFF4"):
        open_evidence(path)


# --------------------------------------------------------------------------
# Concurrency
# --------------------------------------------------------------------------


def test_eight_threads_reading_one_handle_all_get_correct_bytes(
    raw_image: Path,
) -> None:
    """The carver reads randomly from many workers; a shared file position
    would hand one thread another thread's bytes."""
    expected = _blob()

    with RawEvidence(raw_image) as handle:

        def read_chunk(offset: int) -> tuple[int, bytes]:
            return offset, handle.read(offset, 256)

        offsets = [i * 256 for i in range(16)] * 8
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(read_chunk, offsets))

    for offset, chunk in results:
        assert chunk == expected[offset : offset + 256]


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------


def test_repeated_reads_raise_the_cache_hit_rate(raw_image: Path) -> None:
    with RawEvidence(raw_image, cache_bytes=1 << 20) as handle:
        assert handle.cache_stats().hit_rate_bp == 0
        for _ in range(10):
            handle.read(0, 128)
        stats = handle.cache_stats()

    assert stats.hits > 0
    assert stats.hit_rate_bp > 0
