"""PDF streams are inflated under a bound, because a recovered PDF is untrusted.

Before this, ``pikepdf``'s ``read_bytes`` decoded each content stream whole and
the extraction budget was applied to the result. A 512 MiB Flate stream
stored in 522 KiB cost +1,025.5 MiB of peak RSS in triage, measured as below.
Separately, qpdf inflates object streams while it *opens* a file, so a bomb
there costs its full size before any stream is read.

**How memory is measured.** qpdf allocates outside Python, so ``tracemalloc``
cannot see it. ``ru_maxrss`` read by a process about itself is not reliable
either: Linux updates the high-water mark lazily, and a transient peak that was
freed again can be missing from it. The kernel's figure for a process that has
*exited* is exact, so each measurement runs in a grandchild and the child
reports ``RUSAGE_CHILDREN`` for it. Growth is the scan's peak minus the peak of
a baseline process that imports the same modules and reads the same file.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
import zlib
from pathlib import Path

import pytest
from core.carve import pii

REPO = Path(__file__).resolve().parents[2]
MIB = 1024 * 1024

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="the memory bound is measured with resource.getrusage; POSIX-only",
)


def _verhoeff_complete(stem: str) -> str:
    for digit in "0123456789":
        if pii.verhoeff_valid(stem + digit):
            return stem + digit
    raise AssertionError("Verhoeff always has exactly one check digit")


AADHAAR = _verhoeff_complete("49731862054")
PAN = "ABCPE1234F"

_PRELUDE = """
import io, json, sys
import pikepdf
from core.carve import pii
data = open(sys.argv[1], "rb").read()
"""

_BASELINE = _PRELUDE

_SCAN = (
    _PRELUDE
    + """
scan = pii.scan_content(data, ext="pdf", category="document", length=len(data))
print(json.dumps({"inspected": scan.inspected, "basis": scan.basis,
                  "counts": scan.counts}))
"""
)

#: The control: what opening the same bytes costs with no guard in front.
_OPEN = (
    _PRELUDE
    + """
with pikepdf.open(io.BytesIO(data)):
    pass
print("{}")
"""
)

_MEASURE = """
import json, resource, subprocess, sys
done = subprocess.run([sys.executable, "-c", sys.argv[1], sys.argv[2]],
                      capture_output=True, text=True)
print(json.dumps({
    # ru_maxrss is KiB on Linux and *bytes* on macOS/BSD. Multiplying
    # unconditionally reported a 21 GiB peak on the macOS runner for a scan
    # that used 20 MiB.
    "maxrss": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
              * (1 if sys.platform == "darwin" else 1024),
    "returncode": done.returncode,
    "stdout": done.stdout,
    "stderr": done.stderr[-2000:],
}))
"""


def _peak(code: str, path: Path) -> tuple[int, dict[str, object]]:
    """Exact peak RSS of ``code`` run over ``path``, and what it printed."""
    completed = subprocess.run(
        [sys.executable, "-c", _MEASURE, code, str(path)],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    )
    measured = json.loads(completed.stdout)
    assert measured["returncode"] == 0, measured["stderr"]
    lines = str(measured["stdout"]).strip().splitlines()
    printed: dict[str, object] = json.loads(lines[-1]) if lines else {}
    return int(measured["maxrss"]), printed


def _growth(code: str, path: Path) -> tuple[int, dict[str, object]]:
    baseline, _ = _peak(_BASELINE, path)
    peak, printed = _peak(code, path)
    return peak - baseline, printed


def _pdf(streams: list[tuple[bytes, bytes]]) -> bytes:
    """A one-page PDF whose /Contents are ``streams``, as (dictionary, raw bytes)."""
    first = 4
    refs = b" ".join(b"%d 0 R" % (first + index) for index in range(len(streams)))
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents ["
        + refs
        + b"] >>",
    ]
    for dictionary, raw in streams:
        objects.append(
            b"<< /Length %d " % len(raw)
            + dictionary
            + b" >>\nstream\n"
            + raw
            + b"\nendstream"
        )
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % offset for offset in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\n" % (len(objects) + 1)
    out += b"startxref\n%d\n%%%%EOF\n" % xref
    return bytes(out)


def _flate_bomb(prefix: bytes, inflated_bytes: int) -> bytes:
    """``prefix`` followed by spaces up to ``inflated_bytes``, deflated."""
    deflate = zlib.compressobj(9)
    parts = [deflate.compress(prefix)]
    chunk = b" " * MIB
    for _ in range(inflated_bytes // MIB):
        parts.append(deflate.compress(chunk))
    parts.append(deflate.flush())
    return b"".join(parts)


def test_a_flate_bomb_in_a_content_stream_is_never_held_whole(tmp_path: Path) -> None:
    inflated = 1024 * MIB
    raw = _flate_bomb(b"BT (Aadhaar " + AADHAAR.encode() + b") Tj ET\n", inflated)
    document = _pdf([(b"/Filter /FlateDecode", raw)])
    # The point of the test: the stream inflates to far more than the object.
    assert inflated > 500 * len(document), (inflated, len(document))
    path = tmp_path / "bomb.pdf"
    path.write_bytes(document)

    growth, result = _growth(_SCAN, path)

    assert result["inspected"] is True
    # Positive control: the stream was really read, from its start.
    assert result["counts"] == {"aadhaar": 1}, result
    assert "stopped at the 64 MiB extraction budget" in str(result["basis"])
    # Before the bound, this stream measured +2,050.2 MiB of peak RSS.
    assert growth < 48 * MIB, f"scan grew peak RSS by {growth / MIB:.1f} MiB"


def test_an_object_stream_bomb_is_refused_before_qpdf_opens_it(tmp_path: Path) -> None:
    import pikepdf

    inflated = 48 * MIB
    document = pikepdf.new()
    document.add_blank_page()
    filler = pikepdf.Dictionary(Filler=pikepdf.String(b"0" * inflated))
    document.Root.Filler = document.make_indirect(filler)
    buffer = io.BytesIO()
    document.save(
        buffer,
        object_stream_mode=pikepdf.ObjectStreamMode.generate,
        compress_streams=True,
    )
    data = buffer.getvalue()
    del document, filler, buffer
    assert b"/ObjStm" in data
    assert inflated > 100 * len(data), (inflated, len(data))
    path = tmp_path / "objstm-bomb.pdf"
    path.write_bytes(data)

    growth, result = _growth(_SCAN, path)
    opened, _ = _growth(_OPEN, path)

    assert result["inspected"] is False
    assert "object or cross-reference stream" in str(result["basis"])
    assert growth < 16 * MIB, f"refusal grew peak RSS by {growth / MIB:.1f} MiB"
    # The control that makes the refusal necessary: opening the file inflates
    # the object stream, with no stream read at all.
    assert opened > inflated, f"open grew peak RSS by only {opened / MIB:.1f} MiB"


def test_flate_and_unfiltered_streams_are_counted_and_other_filters_are_named() -> None:
    flate = zlib.compress(b"BT (Aadhaar " + AADHAAR.encode() + b") Tj ET")
    plain = b"BT (PAN " + PAN.encode() + b") Tj ET"
    hexed = (b"BT (Aadhaar " + AADHAAR.encode() + b") Tj ET").hex().encode() + b">"
    predicted = zlib.compress(b"BT (PAN " + PAN.encode() + b") Tj ET")
    document = _pdf(
        [
            (b"/Filter /FlateDecode", flate),
            (b"", plain),
            (b"/Filter /ASCIIHexDecode", hexed),
            (b"/Filter /FlateDecode /DecodeParms << /Predictor 12 >>", predicted),
        ]
    )

    scan = pii.scan_content(
        document, ext="pdf", category="document", length=len(document)
    )

    assert scan.inspected
    assert scan.counts == {"aadhaar": 1, "pan": 1}
    assert scan.basis.startswith("2 decoded PDF streams; 2 not decoded")


def test_inflation_steps_are_bounded_and_a_cut_stream_yields_its_prefix() -> None:
    raw = zlib.compress(b"x" * (5 * MIB))
    pieces = list(pii._inflate_pieces(raw, 3 * MIB))
    assert max(len(piece) for piece in pieces) <= pii._PDF_CHUNK_BYTES
    assert sum(len(piece) for piece in pieces) == 3 * MIB

    # A recovered stream is often cut short: what inflated before the cut counts.
    text = bytes(range(256)) * 4096
    compressed = zlib.compress(text)
    recovered = b"".join(pii._inflate_pieces(compressed[: len(compressed) // 2], MIB))
    assert 0 < len(recovered) < len(text)
    assert text.startswith(recovered)
    # Bytes that are not a zlib stream at all yield nothing and raise nothing.
    assert list(pii._inflate_pieces(b"\xff" * 4096, MIB)) == []
