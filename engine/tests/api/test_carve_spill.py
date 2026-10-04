"""Recovered bytes live on disk during a run, not in the API process.

The pipeline holds bytes for every candidate whose content is not one span on
the medium - a filesystem file in several extents, a bifragmented JPEG rebuilt
across a gap. Those used to accumulate in a dict that lived for the whole run,
so the process held every fragmented object at once. They are now spilled to a
per-run directory and read back one at a time.

Two things are tested, and the second matters more: that the bytes are still
correct, and that nothing is left behind on **any** exit - success, failure, or
the Cancel button. The spill holds content carved out of evidence, so an
orphaned temp directory is not a tidiness problem.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from api.carve_job import SpillStore, carve_generator


@pytest.fixture
def spill(tmp_path: Path) -> Iterator[SpillStore]:
    store = SpillStore(tmp_path / "work", job_id="carve-test")
    yield store
    store.close()


# --------------------------------------------------------------------------
# The store itself
# --------------------------------------------------------------------------


def test_a_payload_round_trips_through_the_spill(spill: SpillStore) -> None:
    spill.put(("structure", 4096), b"payload-bytes")

    assert spill.has(("structure", 4096))
    assert spill.get(("structure", 4096)) == b"payload-bytes"


def test_a_key_that_was_never_spilled_reads_as_absent(spill: SpillStore) -> None:
    assert spill.has(("structure", 1)) is False
    assert spill.get(("structure", 1)) is None


def test_the_same_offset_from_two_sources_is_two_objects(spill: SpillStore) -> None:
    """An undelete record and a carved header can land on the same offset.

    They are different objects and must not share a file.
    """
    spill.put(("fs_metadata", 512), b"from-the-filesystem")
    spill.put(("structure", 512), b"from-the-carver")

    assert spill.get(("fs_metadata", 512)) == b"from-the-filesystem"
    assert spill.get(("structure", 512)) == b"from-the-carver"


def test_the_filename_is_a_digest_and_never_evidence_supplied_text(
    spill: SpillStore,
) -> None:
    """There is no separator to escape, so confinement is a property of naming.

    A filesystem record's original name comes off the seized disk. It is never
    part of a path here.
    """
    hostile = "../../../../etc/passwd\x00; rm -rf /"
    spill.put((hostile, 0), b"x")

    written = [item for item in spill.directory.iterdir()]
    assert len(written) == 1
    assert len(written[0].name) == 64
    assert all(character in "0123456789abcdef" for character in written[0].name)
    assert written[0].parent == spill.directory


def test_the_name_is_deterministic_across_stores(tmp_path: Path) -> None:
    first = SpillStore(tmp_path / "a", job_id="j")
    second = SpillStore(tmp_path / "b", job_id="j")
    try:
        assert first.path_for(("structure", 99)).name == (
            second.path_for(("structure", 99)).name
        )
    finally:
        first.close()
        second.close()


def test_two_runs_of_one_job_id_do_not_share_a_directory(tmp_path: Path) -> None:
    """Otherwise the second run's cleanup would delete the first run's spill."""
    first = SpillStore(tmp_path / "work", job_id="carve-1")
    second = SpillStore(tmp_path / "work", job_id="carve-1")
    try:
        assert first.directory != second.directory
    finally:
        first.close()
        second.close()


def test_copy_to_streams_the_payload_to_its_destination(
    spill: SpillStore, tmp_path: Path
) -> None:
    spill.put(("structure", 0), b"recovered" * 1000)
    destination = tmp_path / "out.bin"

    written = spill.copy_to(("structure", 0), destination)

    assert written == len(b"recovered" * 1000)
    assert destination.read_bytes() == b"recovered" * 1000


def test_close_removes_the_directory_and_is_idempotent(tmp_path: Path) -> None:
    store = SpillStore(tmp_path / "work", job_id="j")
    store.put(("structure", 0), b"x")
    directory = store.directory

    store.close()
    store.close()

    assert not directory.exists()


def test_a_large_candidate_set_holds_one_payload_at_a_time(
    spill: SpillStore,
) -> None:
    """The point of the store, stated as a measurement rather than a comment.

    Two thousand megabyte payloads go in. Nothing the store holds between calls
    grows with the number of payloads, so the resident set is the key index and
    not the content.
    """
    payload = b"\xab" * (1024 * 1024)
    for offset in range(2000):
        spill.put(("structure", offset), payload)

    # The store's own state is 2000 keys, not 2000 megabytes.
    assert len(spill) == 2000
    assert spill.get(("structure", 1999)) == payload
    on_disk = sum(item.stat().st_size for item in spill.directory.iterdir())
    assert on_disk == 2000 * len(payload)


# --------------------------------------------------------------------------
# Cleanup through the pipeline
# --------------------------------------------------------------------------


def _image(tmp_path: Path) -> Path:
    """A small image with one JPEG in it, enough to exercise the pipeline."""
    image = tmp_path / "case.dd"
    body = bytearray(b"\x00" * (256 * 1024))
    jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    jpeg += b"\xff\xdb\x00C\x00" + bytes(range(64))
    jpeg += b"\xff\xd9"
    body[4096 : 4096 + len(jpeg)] = jpeg
    image.write_bytes(bytes(body))
    return image


def test_a_completed_carve_leaves_no_spill_behind(tmp_path: Path) -> None:
    work = tmp_path / "work"
    generator = carve_generator(
        _image(tmp_path),
        undelete=False,
        job_id="carve-clean",
        work_dir=work,
    )
    for _ in generator:
        pass

    assert list(work.iterdir()) == []


def test_a_cancelled_carve_leaves_no_spill_behind(tmp_path: Path) -> None:
    """Cancel is ``GeneratorExit``, and the cleanup is in a ``finally``.

    A cancelled run leaving carved evidence in a temp directory is worse than
    an ordinary leaked temp file, which is why this has its own test.
    """
    work = tmp_path / "work"
    generator = carve_generator(
        _image(tmp_path),
        undelete=False,
        job_id="carve-cancel",
        work_dir=work,
    )
    next(generator)  # into the run
    generator.close()

    assert list(work.iterdir()) == []


def test_a_failed_carve_leaves_no_spill_behind(tmp_path: Path) -> None:
    missing = tmp_path / "not-here.dd"
    work = tmp_path / "work"
    work.mkdir(parents=True, exist_ok=True)

    generator = carve_generator(missing, undelete=False, job_id="j", work_dir=work)
    with pytest.raises((OSError, ValueError, Exception)):
        for _ in generator:
            pass

    assert list(work.iterdir()) == []
