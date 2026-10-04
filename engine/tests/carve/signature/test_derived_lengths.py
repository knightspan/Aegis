"""Every candidate's end is derived, and no candidate runs to the end of the image.

This is the acceptance gate for the runaway-length defect (BENCHMARK_REPORT B2)
and for the seven formats that had no signature at all (B5).

The defect had three separate causes and one symptom. A ZIP member header
started a candidate whose parse could not read the archive's end record, because
the record's offsets are counted from the archive's first byte and the parse
began at the member's. An MP4 read the zeros of its own cluster slack as a box
of size 0, which the format defines as "to the end of the file". A TIFF had a
signature and no parser at all. Each produced a candidate covering most of the
medium, and the general rule they all broke is at the bottom of this file: a
parser that derives nothing must not claim more than the scan already bounded.

Every fixture is produced by a real encoder, for the reason
``tests/carve/signature/conftest.py`` gives: a hand-built fake proves the
test's idea of a format rather than the format.
"""

from __future__ import annotations

import gzip
import io
import random
import tarfile
import wave
import zipfile

import pytest
from core.carve.evidence import BytesEvidence
from core.carve.structure import (
    carve_structures,
    parse_bmp,
    parse_gzip,
    parse_html,
    parse_riff,
    parse_rtf,
    parse_tar,
    parse_tiff,
    parse_zip,
)
from PIL import Image

CLUSTER = 4096


def _noise(rng: random.Random, size: int, mode: str = "RGB") -> Image.Image:
    image = Image.new(mode, (size, size))
    image.frombytes(rng.randbytes(size * size * len(mode)))
    return image


def _encode(image: Image.Image, fmt: str, **options: object) -> bytes:
    buffer = io.BytesIO()
    image.save(buffer, fmt, **options)
    return buffer.getvalue()


def _wav(rng: random.Random, seconds: float = 1.0, rate: int = 8000) -> bytes:
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as out:
        out.setnchannels(1)
        out.setsampwidth(2)
        out.setframerate(rate)
        out.writeframes(rng.randbytes(int(seconds * rate) * 2))
    return buffer.getvalue()


def _tar(members: int = 3) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as out:
        for index in range(members):
            body = (f"member {index} " * 200).encode()
            info = tarfile.TarInfo(f"notes{index}.txt")
            info.size = len(body)
            info.mtime = 1_700_000_000
            out.addfile(info, io.BytesIO(body))
    return buffer.getvalue()


def _zip(entries: int = 6) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for index in range(entries):
            archive.writestr(f"file{index}.txt", f"payload {index}\n" * 80)
    return buffer.getvalue()


def _mp4() -> bytes:
    def box(kind: bytes, payload: bytes) -> bytes:
        return (len(payload) + 8).to_bytes(4, "big") + kind + payload

    ftyp = box(b"ftyp", b"isom" + (512).to_bytes(4, "big") + b"isomiso2mp41")
    return ftyp + box(b"mdat", bytes(range(256)) * 4)


def _html(words: int = 500) -> bytes:
    return (
        "<!DOCTYPE html>\n<html><head><title>case notes</title></head><body><p>"
        + "evidence " * words
        + "</p></body></html>\n"
    ).encode()


def _rtf(words: int = 400) -> bytes:
    body = "note " * words
    return ("{\\rtf1\\ansi\\deff0 {\\fonttbl {\\f0 Times;}}\\f0 " + body + "}").encode()


@pytest.fixture(scope="module")
def rng() -> random.Random:
    return random.Random(20260916)


@pytest.fixture(scope="module")
def objects(rng: random.Random) -> list[tuple[str, bytes]]:
    """One object of every format this file covers, in layout order."""
    return [
        ("bmp", _encode(_noise(rng, 64), "BMP")),
        ("webp", _encode(_noise(rng, 96), "WEBP", quality=90)),
        ("wav", _wav(rng)),
        ("gz", gzip.compress(("case notes " * 3000).encode(), mtime=0)),
        ("tar", _tar()),
        ("rtf", _rtf()),
        ("html", _html()),
        ("tiff", _encode(_noise(rng, 128), "TIFF")),
        ("mp4", _mp4()),
        ("zip", _zip()),
    ]


@pytest.fixture(scope="module")
def volume(
    rng: random.Random, objects: list[tuple[str, bytes]]
) -> tuple[bytes, dict[int, tuple[str, int]]]:
    """The objects on a 4096-byte cluster grid, each followed by zero slack.

    The slack is the point. A file does not end on a cluster boundary, so the
    bytes between its last byte and the next cluster are zeros - and those
    zeros are what an MP4 box walk read as a box meaning "to end of file".
    """
    image = bytearray(rng.randbytes(CLUSTER))
    planted: dict[int, tuple[str, int]] = {}
    for ext, data in objects:
        planted[len(image)] = (ext, len(data))
        image += data
        image += bytes(-len(data) % CLUSTER)  # cluster slack
        image += rng.randbytes(CLUSTER)  # a live neighbour
    return bytes(image), planted


# --------------------------------------------------------------------------
# The gate
# --------------------------------------------------------------------------


def test_no_candidate_runs_past_the_object_it_started_in(
    volume: tuple[bytes, dict[int, tuple[str, int]]],
) -> None:
    """The symptom every part of B2 produced, on one image holding all of them.

    A 255 MiB volume wrote 2,750 MiB of recovered objects in 25 files because
    of this, and each of those candidates ran from its header to the last byte
    of the image. The bound asserted here is the end of the planted object's
    own cluster: a candidate may claim its object and the slack it sits in, and
    nothing beyond that is bytes it can account for.
    """
    image, planted = volume
    candidates = list(carve_structures(BytesEvidence(image)))
    assert candidates, "the image holds ten objects and the scan found none"

    runaway: list[str] = []
    for item in candidates:
        start, length = planted[item.offset]
        cluster_end = item.offset + length + (-length % CLUSTER)
        if item.offset + item.length > cluster_end:
            runaway.append(
                f"{item.ext} @{item.offset} length={item.length} reaches "
                f"{item.offset + item.length}, past {cluster_end}"
            )
    assert not runaway, f"candidates claiming bytes they cannot account for: {runaway}"
    assert max(item.offset + item.length for item in candidates) < len(image), (
        "a candidate still reaches the end of the image"
    )


def test_every_planted_object_is_found_at_its_exact_length(
    volume: tuple[bytes, dict[int, tuple[str, int]]],
) -> None:
    """A length that is close is a file that does not open.

    ``backup.tar`` is the one exception and it is asserted separately below:
    the padding its writer adds after the end-of-archive marker cannot be told
    from cluster slack, so it is not claimed.
    """
    image, planted = volume
    found = {item.offset: item for item in carve_structures(BytesEvidence(image))}

    wrong: list[str] = []
    for offset, (ext, length) in planted.items():
        item = found.get(offset)
        if item is None:
            wrong.append(f"{ext} @{offset} was not found")
        elif ext == "tar":
            continue
        elif item.length != length:
            wrong.append(f"{ext} @{offset} length {item.length}, planted {length}")
    assert not wrong, wrong


# --------------------------------------------------------------------------
# B2 (a): ZIP members
# --------------------------------------------------------------------------


def test_a_zip_member_header_is_not_an_archive() -> None:
    """Every member carries ``PK\\x03\\x04``, and none of them is a file.

    The archive's end record counts its offsets from the archive's first byte.
    A parse beginning at a member measured them from the member instead, found
    them inconsistent, and fell back to claiming the rest of the image - one
    such candidate per member, which is where 235 of the 252 false positives
    came from.
    """
    archive = _zip(entries=6)
    image = bytes(2048) + archive + bytes(4096)

    members = [
        offset
        for offset in range(2048, 2048 + len(archive))
        if image[offset : offset + 4] == b"PK\x03\x04"
    ]
    assert len(members) > 1, "this fixture needs an archive with several members"

    parsed = parse_zip(BytesEvidence(image), members[1], max_size=1 << 30)
    assert parsed is not None
    assert parsed.member_of == 2048, "the member did not resolve to its archive"

    candidates = list(carve_structures(BytesEvidence(image)))
    zips = [item for item in candidates if item.ext == "zip"]
    assert len(zips) == 1, f"one archive, {len(zips)} candidates: {zips}"
    assert zips[0].offset == 2048
    assert zips[0].length == len(archive)


def test_zip_with_no_end_record_keeps_the_bound_the_scan_derived() -> None:
    """Declining beats claiming: the scan's neighbour bound is always tighter."""
    archive = _zip(entries=3)
    cut = archive[: len(archive) // 2]
    image = bytes(2048) + cut + bytes(8 * 1024 * 1024)

    parsed = parse_zip(BytesEvidence(image), 2048, max_size=1 << 30)
    assert parsed is None, "a parse that derived nothing returned a length"


# --------------------------------------------------------------------------
# B2 (b): MP4 cluster slack
# --------------------------------------------------------------------------


def test_mp4_zero_slack_after_the_last_box_is_not_a_box() -> None:
    """Eight zero bytes are a box of size 0 named ``\\0\\0\\0\\0``, which is nothing.

    Read as a box, ``size == 0`` means "to the end of the file", and every MP4
    on a volume became a candidate covering the rest of the image. It cost all
    20 MP4 recoveries in the benchmark.
    """
    from core.carve.structure import parse_mp4

    clip = _mp4()
    image = clip + bytes(CLUSTER - len(clip) % CLUSTER) + bytes(64 * 1024 * 1024)

    parsed = parse_mp4(BytesEvidence(image), 0, max_size=1 << 32)

    assert parsed is not None
    assert parsed.length == len(clip), "the slack was read as part of the object"
    assert parsed.validation == "valid"
    assert "zero fill, not a box" in parsed.detail


def test_mp4_box_declaring_size_zero_bounds_itself_by_what_parsed() -> None:
    """A real size-0 box is legal, and still cannot say where the object ends."""
    from core.carve.structure import parse_mp4

    def box(kind: bytes, payload: bytes) -> bytes:
        return (len(payload) + 8).to_bytes(4, "big") + kind + payload

    ftyp = box(b"ftyp", b"isom" + (512).to_bytes(4, "big") + b"isomiso2mp41")
    body = ftyp + (0).to_bytes(4, "big") + b"mdat" + bytes(4096)
    image = body + bytes(8 * 1024 * 1024)

    parsed = parse_mp4(BytesEvidence(image), 0, max_size=1 << 32)

    assert parsed is not None
    assert parsed.length == len(ftyp)
    assert parsed.validation == "truncated"


# --------------------------------------------------------------------------
# B2 (c): TIFF
# --------------------------------------------------------------------------


def test_tiff_length_comes_from_the_ifd_chain(rng: random.Random) -> None:
    """A TIFF has no footer and no length field; its IFDs say where it reaches."""
    scan = _encode(_noise(rng, 128), "TIFF")
    image = bytes(1024) + scan + bytes(32 * 1024 * 1024)

    parsed = parse_tiff(BytesEvidence(image), 1024, max_size=1 << 28)

    assert parsed is not None
    assert parsed.validation == "valid"
    assert parsed.length == len(scan)


def test_big_endian_tiff_is_read_the_same_way(rng: random.Random) -> None:
    scan = _encode(_noise(rng, 64), "TIFF")
    if scan[:2] != b"MM":
        pytest.skip("Pillow wrote a little-endian TIFF on this platform")
    parsed = parse_tiff(BytesEvidence(scan), 0, max_size=1 << 28)
    assert parsed is not None
    assert parsed.length == len(scan)


# --------------------------------------------------------------------------
# B5: the formats that had no signature
# --------------------------------------------------------------------------


def test_bmp_length_is_the_file_size_field(rng: random.Random) -> None:
    bitmap = _encode(_noise(rng, 64), "BMP")
    parsed = parse_bmp(BytesEvidence(bitmap + bytes(CLUSTER)), 0, max_size=1 << 28)
    assert parsed is not None
    assert parsed.validation == "valid"
    assert parsed.length == len(bitmap)


def test_webp_and_wav_share_a_header_and_both_are_still_found(
    rng: random.Random,
) -> None:
    """``RIFF`` belongs to both, and the form type at byte 8 is what separates them.

    One signature per pattern in the automaton silently dropped whichever was
    loaded second, and that format was then unfindable on any image.
    """
    picture = _encode(_noise(rng, 96), "WEBP", quality=90)
    sound = _wav(rng)
    image = (
        bytes(CLUSTER)
        + picture
        + bytes(-len(picture) % CLUSTER)
        + sound
        + bytes(CLUSTER)
    )

    found = {item.ext: item for item in carve_structures(BytesEvidence(image))}

    assert "webp" in found, "the WebP was lost to the WAV signature"
    assert "wav" in found, "the WAV was lost to the WebP signature"
    assert found["webp"].length == len(picture)
    assert found["wav"].length == len(sound)


def test_riff_length_is_the_size_field_plus_its_own_header(rng: random.Random) -> None:
    sound = _wav(rng)
    parsed = parse_riff(BytesEvidence(sound + bytes(CLUSTER)), 0, max_size=1 << 32)
    assert parsed is not None
    assert parsed.length == len(sound)
    assert parsed.length == int.from_bytes(sound[4:8], "little") + 8


def test_gzip_length_comes_from_inflating_the_member() -> None:
    """No footer exists to search for: the trailer is a CRC and a length."""
    member = gzip.compress(("case notes " * 3000).encode(), mtime=0)
    image = member + bytes(CLUSTER) + b"\x1f\x8b\x08" + bytes(64)

    parsed = parse_gzip(BytesEvidence(image), 0, max_size=1 << 32)

    assert parsed is not None
    assert parsed.validation == "valid"
    assert parsed.length == len(member)


def test_gzip_bomb_is_declined_rather_than_inflated() -> None:
    """A small member that inflates to gigabytes is not worth a length."""
    from core.carve.structure import MAX_INFLATE_BYTES

    bomb = gzip.compress(bytes(MAX_INFLATE_BYTES + 1), mtime=0)
    assert len(bomb) < 2 * 1024 * 1024, "the bomb should be small on disk"

    parsed = parse_gzip(BytesEvidence(bomb), 0, max_size=1 << 32)

    assert parsed is None


def test_one_tar_candidate_covers_every_member() -> None:
    """A member header is a record inside a file, not a file."""
    archive = _tar(members=3)
    image = bytes(CLUSTER) + archive + bytes(CLUSTER)

    candidates = [
        item for item in carve_structures(BytesEvidence(image)) if item.ext == "tar"
    ]

    assert len(candidates) == 1, f"3 members produced {len(candidates)} candidates"
    assert candidates[0].offset == CLUSTER


def test_tar_stops_at_the_end_of_archive_marker_and_claims_no_padding() -> None:
    """The limit this parser accepts, asserted so it cannot drift into a guess.

    GNU tar pads an archive to its blocking factor - 10,240 bytes by default -
    and that padding is zeros, which is exactly what the last cluster's slack
    is. Rounding the length up to a blocking factor would recover this file
    byte for byte and would be an assumption about the writer, so the archive
    ends where the format says it does and the shortfall is reported here.
    """
    archive = _tar(members=3)
    parsed = parse_tar(BytesEvidence(archive), 0, max_size=1 << 32)

    assert parsed is not None
    assert parsed.validation == "valid"
    assert "end-of-archive marker" in parsed.detail
    assert parsed.length <= len(archive)
    assert len(archive) % 10_240 == 0, "tarfile pads to its record size"
    assert parsed.length < len(archive), (
        "this archive is padded, so the derived length is deliberately short of "
        "the file as written; see the docstring"
    )


def test_rtf_length_is_the_brace_that_closes_the_document() -> None:
    document = _rtf()
    image = document + b" trailing bytes that are not the document " * 64

    parsed = parse_rtf(BytesEvidence(image), 0, max_size=1 << 28)

    assert parsed is not None
    assert parsed.validation == "valid"
    assert parsed.length == len(document)


def test_rtf_escaped_braces_do_not_close_the_document() -> None:
    r"""``\{`` is a literal brace in the text, and counting it would end early."""
    document = (
        "{\\rtf1\\ansi " + "\\{ literal \\} " * 40 + "{\\b bold}" + "}"
    ).encode()
    parsed = parse_rtf(BytesEvidence(document + bytes(256)), 0, max_size=1 << 28)

    assert parsed is not None
    assert parsed.length == len(document)


def test_html_length_includes_the_line_ending_after_the_closing_tag() -> None:
    """The same reason ``parse_pdf`` consumes one: a text file ends with it."""
    page = _html()
    assert page.endswith(b"</html>\n")
    image = page + bytes(CLUSTER)

    parsed = parse_html(BytesEvidence(image), 0, max_size=1 << 26)

    assert parsed is not None
    assert parsed.length == len(page)


def test_html_without_a_closing_tag_declines_rather_than_guessing() -> None:
    """Nothing bounds it, so the scan's bound stands and the report says so."""
    page = b"<!DOCTYPE html>\n<html><body><p>" + b"unterminated " * 200

    parsed = parse_html(BytesEvidence(page + bytes(4096)), 0, max_size=1 << 26)

    assert parsed is None


def test_a_doctype_and_an_html_tag_are_one_document() -> None:
    """``<html>`` sits inside a document that began at ``<!DOCTYPE html>``."""
    page = _html()
    image = bytes(CLUSTER) + page + bytes(CLUSTER)

    pages = [
        item for item in carve_structures(BytesEvidence(image)) if item.ext == "html"
    ]

    assert len(pages) == 1, f"one document produced {len(pages)} candidates"
    assert pages[0].length == len(page)
