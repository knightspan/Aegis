"""What exact scan accounting says about a contiguous JPEG, and what it declines to say.

:func:`core.carve.fragmentation.accounts_for_scan` is used beyond reassembly: the
structure carver's trigger and the JPEG validator both ask it whether a decoded
span really is one whole image. That makes its *declines* as important as its
answers. A real file can legitimately carry bytes after its EOI (a motion photo
appends a video there), fill bytes before a marker, or a scan structure this
module does not walk; none of those may be turned into a verdict of "corrupt".
"""

from __future__ import annotations

import io
import random

import pytest
from core.carve.fragmentation import accounts_for_scan
from PIL import Image

from tests.carve.signature.conftest import make_noisy_jpeg


def _jpeg(**options: object) -> bytes:
    rng = random.Random(5)
    image = Image.new("RGB", (96, 96))
    image.putdata(
        [
            (rng.randrange(256), rng.randrange(256), rng.randrange(256))
            for _ in range(96 * 96)
        ]
    )
    buffer = io.BytesIO()
    image.save(buffer, "JPEG", **options)
    return buffer.getvalue()


def test_a_whole_baseline_jpeg_accounts_for_its_scan() -> None:
    assert accounts_for_scan(make_noisy_jpeg(seed=99)) is True


def test_bytes_after_the_eoi_are_not_the_scans_business() -> None:
    """A motion photo is a JPEG with a video after its EOI. It is still whole."""
    trailer = b"\x00\x00\x00\x18ftypmp42" * 50
    assert accounts_for_scan(make_noisy_jpeg(seed=99) + trailer) is True


def test_fill_bytes_before_the_eoi_are_legal() -> None:
    original = make_noisy_jpeg(seed=99)
    assert accounts_for_scan(original[:-2] + b"\xff\xff\xff" + original[-2:]) is True


def test_foreign_bytes_inside_a_decodable_span_are_caught() -> None:
    """The contiguous case Pillow calls valid: head, 8 KiB of zeros, tail."""
    original = make_noisy_jpeg(seed=99)
    spliced = original[:65536] + bytes(8192) + original[65536:]

    assert accounts_for_scan(spliced) is False


def test_a_reserved_marker_code_in_the_scan_is_corrupt() -> None:
    original = make_noisy_jpeg(seed=99)
    assert accounts_for_scan(original[:40000] + b"\xff\x42" + original[40000:]) is False


@pytest.mark.parametrize(
    "options", [{"progressive": True}, {"quality": 90, "progressive": True}]
)
def test_a_progressive_jpeg_is_declined_not_condemned(
    options: dict[str, object],
) -> None:
    assert accounts_for_scan(_jpeg(**options)) is None


def test_something_that_is_not_a_jpeg_is_declined() -> None:
    assert accounts_for_scan(b"\x89PNG\r\n\x1a\n" + bytes(64)) is None


# --------------------------------------------------------------------------
# The validator's verdict
# --------------------------------------------------------------------------


def test_the_jpeg_validator_does_not_call_a_spliced_span_valid() -> None:
    """Pillow decodes it fully; the verdict must not stop there."""
    from core.carve.validate import validate_bytes

    original = make_noisy_jpeg(seed=99)
    report = validate_bytes(original[:65536] + bytes(8192) + original[65536:], "jpg")

    assert report.verdict == "corrupt", report
    assert "does not account" in report.detail


@pytest.mark.parametrize(
    "label", ["whole", "motion-photo", "fill-bytes", "progressive"]
)
def test_the_jpeg_validator_still_calls_real_files_valid(label: str) -> None:
    from core.carve.validate import validate_bytes

    original = make_noisy_jpeg(seed=99)
    data = {
        "whole": original,
        "motion-photo": original + b"\x00\x00\x00\x18ftypmp42" * 50,
        "fill-bytes": original[:-2] + b"\xff\xff" + original[-2:],
        "progressive": _jpeg(progressive=True),
    }[label]

    assert validate_bytes(data, "jpg").verdict == "valid"
