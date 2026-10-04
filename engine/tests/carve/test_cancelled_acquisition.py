"""What a cancelled acquisition leaves behind, and what the chain says about it.

BATCH4 FINDING 8. The cancellation work went into the erase engine only:
``core/erase/drive.py`` catches ``GeneratorExit``, records that the device is
partially sanitized, and re-raises. The acquisition path had ``finally`` blocks
that closed handles and nothing that said what had happened, so a cancelled
image ended as a truncated ``.dd`` or ``.E01`` on disk with nothing in the chain
distinguishing it from a crash.

Nothing is destroyed here, which is why it is the lower-severity half of the
same defect - and also why it is easy to under-rate. **A truncated image looks
exactly like a complete one.** An examiner who carves a fragment believing it is
the whole source will report the absence of evidence that is simply outside the
bytes they have. The entry exists so that conclusion cannot be reached by
accident.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest
from core.carve.acquire import AcquireOptions, acquire
from core.ledger.chain import ChainStatus, Ledger

MIB = 1024 * 1024


#: One progress record is emitted per ``block_bytes`` read, so the source has to
#: be several blocks long for there to be a "partway" to cancel at. Eight blocks
#: of 64 KiB: small enough to stay a unit test, long enough that cancelling
#: after two records leaves a genuinely truncated image.
BLOCK = 64 * 1024
BLOCKS = 8


@pytest.fixture
def source(tmp_path: Path) -> Path:
    """A source big enough that the read yields several times before the end."""
    path = tmp_path / "source.dd"
    path.write_bytes(bytes(range(256)) * (BLOCK * BLOCKS // 256))
    return path


def make_ledger(tmp_path: Path) -> Ledger:
    return Ledger(
        tmp_path / "ledger", tool_version="0.0.0-test", pubkey_fingerprint="AA:BB"
    )


def cancel_partway(
    source: Path, dest: Path, chain: Ledger, *, after: int = 1
) -> int:
    """Acquire, close the generator after ``after`` progress records, return them."""
    generator = acquire(
        source,
        dest,
        fmt="raw",
        options=AcquireOptions(
            operator="tester", block_bytes=BLOCK, chunk_bytes=BLOCK
        ),
        ledger=chain,
        job_id="acq-cancel",
    )
    seen = 0
    for _record in generator:
        seen += 1
        if seen >= after:
            break
    # Exactly what api.jobs.JobRegistry.cancel does to a running job.
    generator.close()
    return seen


def operations(chain: Ledger) -> list[str]:
    return [entry.operation for entry in chain.entries()]


def cancellation_payload(chain: Ledger) -> dict[str, Any]:
    entry = next(
        item for item in chain.entries() if item.operation == "acquire.cancelled"
    )
    return chain.params_of(entry)


def test_a_cancelled_acquisition_records_that_the_image_is_partial(
    source: Path, tmp_path: Path
) -> None:
    """The entry a later reader needs, written before the exception continues."""
    chain = make_ledger(tmp_path)
    dest = tmp_path / "partial.dd"

    cancel_partway(source, dest, chain, after=2)

    assert "acquire.cancelled" in operations(chain), operations(chain)
    assert "acquire.complete" not in operations(chain), (
        "a cancelled acquisition must never record completion"
    )

    payload = cancellation_payload(chain)
    note = str(payload["note"])
    assert "PARTIAL IMAGE" in note
    assert "NOT a complete copy" in note
    assert payload["job_id"] == "acq-cancel"
    assert payload["destination"] == str(dest)


def test_the_entry_says_how_much_of_the_source_was_acquired(
    source: Path, tmp_path: Path
) -> None:
    """"Partial" is not useful without a number. Both numbers, in fact."""
    chain = make_ledger(tmp_path)
    dest = tmp_path / "partial.dd"

    cancel_partway(source, dest, chain, after=2)

    payload = cancellation_payload(chain)
    acquired = int(payload["bytes_acquired"])
    expected = int(payload["bytes_expected"])

    assert expected == source.stat().st_size
    assert 0 < acquired < expected, (acquired, expected)
    assert str(acquired) in str(payload["note"])
    assert str(expected) in str(payload["note"])


def test_the_entry_refuses_to_publish_a_digest_for_the_fragment(
    source: Path, tmp_path: Path
) -> None:
    """The most important line in the entry.

    An acquisition's ``sha256``/``blake3`` are computed over the whole source as
    it is read, and are what an examiner treats as the evidential digest. A hash
    of a truncated container is not that digest, and recording one under the
    same field name would be the tool asserting something it cannot support.
    """
    chain = make_ledger(tmp_path)
    dest = tmp_path / "partial.dd"

    cancel_partway(source, dest, chain, after=2)

    payload = cancellation_payload(chain)
    assert "sha256" not in payload
    assert "blake3" not in payload
    assert "No sha256 or blake3 is recorded" in str(payload["note"])


def test_the_fragment_really_is_shorter_than_the_source(
    source: Path, tmp_path: Path
) -> None:
    """The premise: there is a file, it looks like an image, and it is not one."""
    chain = make_ledger(tmp_path)
    dest = tmp_path / "partial.dd"

    cancel_partway(source, dest, chain, after=2)

    assert dest.exists()
    assert dest.stat().st_size < source.stat().st_size
    assert (
        hashlib.sha256(dest.read_bytes()).hexdigest()
        != hashlib.sha256(source.read_bytes()).hexdigest()
    )
    # And the chain says so, which is the whole point.
    payload = cancellation_payload(chain)
    assert int(payload["container_bytes_on_disk"]) == dest.stat().st_size


def test_the_chain_is_still_valid_after_a_cancellation(
    source: Path, tmp_path: Path
) -> None:
    """Writing the entry during generator teardown must not break the chain."""
    chain = make_ledger(tmp_path)

    cancel_partway(source, tmp_path / "partial.dd", chain, after=2)

    verification = chain.verify(check_blobs=True)
    assert verification.status is ChainStatus.VALID, verification.explanation


def test_a_completed_acquisition_records_no_cancellation(
    source: Path, tmp_path: Path
) -> None:
    """The negative: the entry must not appear on the ordinary path."""
    chain = make_ledger(tmp_path)
    dest = tmp_path / "whole.dd"

    generator = acquire(
        source,
        dest,
        fmt="raw",
        options=AcquireOptions(operator="tester"),
        ledger=chain,
        job_id="acq-whole",
    )
    while True:
        try:
            next(generator)
        except StopIteration as stop:
            record = stop.value
            break

    assert "acquire.cancelled" not in operations(chain)
    assert "acquire.complete" in operations(chain)
    assert record.sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert dest.read_bytes() == source.read_bytes()


def test_cancelling_without_a_ledger_does_not_raise(
    source: Path, tmp_path: Path
) -> None:
    """``ledger`` is optional on this path, and teardown must respect that.

    An exception from the cancellation handler would replace the cancellation
    the caller asked for with a failure from a teardown path.
    """
    generator = acquire(
        source,
        tmp_path / "no-ledger.dd",
        fmt="raw",
        options=AcquireOptions(operator="tester"),
        ledger=None,
        job_id="acq-noledger",
    )
    next(generator)
    generator.close()  # must not raise
