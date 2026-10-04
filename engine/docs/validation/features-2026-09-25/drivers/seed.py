"""Seed the synthetic population for the 2026-09-25 feature run.

Usage (project venv, repo root): python seed.py STATE_DIR

Everything is created under STATE_DIR, which the sandboxed server mounts at
/cases, with STATE_DIR/home mounted as /home/examiner:

* /cases/files/case-2149/ - two JPEGs and a CSV to erase;
* thumbnails of both JPEGs, named by the MD5 of their URI as the freedesktop
  specification says, a recent-files list naming all three, and an older copy
  of the CSV in the Trash with its .trashinfo - all in /home/examiner;
* /cases/images/case2149.dd - a 32 MiB image with zeroed, text, random, 0xFF,
  JPEG and 0xA5 regions at known offsets, for the media map.

The URIs are written as the server will see them, under /cases, not as they
lie on the host.
"""

import hashlib
import io
import random
import sys
from pathlib import Path
from urllib.parse import quote

from core.erase.traces import file_uris
from PIL import Image
from tests.erase.files.test_trace_sweep import XBEL_HEAD, png, xbel_entry

state = Path(sys.argv[1]).resolve()
home = state / "home"
work = state / "files" / "case-2149"
inside = Path("/cases/files/case-2149")
work.mkdir(parents=True, exist_ok=True)


def jpeg(colour: tuple[int, int, int], size: tuple[int, int] = (640, 480)) -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", size, colour).save(buffer, "JPEG", quality=85)
    return buffer.getvalue()


names = ["site-photo 01.jpg", "site-photo 02.jpg", "salary-sheet.csv"]
(work / names[0]).write_bytes(jpeg((180, 60, 40)))
(work / names[1]).write_bytes(jpeg((40, 120, 180)))
(work / names[2]).write_text("name,account,amount\nA. Rao,0042,91000\n")
uris = [file_uris(str(inside / name))[0] for name in names]

thumbs = home / ".cache" / "thumbnails" / "normal"
thumbs.mkdir(parents=True, exist_ok=True)
for uri in uris[:2]:
    digest = hashlib.md5(uri.encode(), usedforsecurity=False).hexdigest()
    (thumbs / f"{digest}.png").write_bytes(png(uri))

recent = home / ".local" / "share" / "recently-used.xbel"
recent.parent.mkdir(parents=True, exist_ok=True)
entries = [xbel_entry("file:///srv/share/minutes.odt")] + [xbel_entry(u) for u in uris]
recent.write_text(XBEL_HEAD + "".join(entries) + "</xbel>")

trash = home / ".local" / "share" / "Trash"
(trash / "files").mkdir(parents=True, exist_ok=True)
(trash / "info").mkdir(parents=True, exist_ok=True)
(trash / "files" / names[2]).write_text("name,account,amount\nA. Rao,0042,88000\n")
(trash / "info" / f"{names[2]}.trashinfo").write_text(
    f"[Trash Info]\nPath={quote(str(inside / names[2]))}\n"
    "DeletionDate=2026-09-20T11:22:33\n"
)

MIB = 1024 * 1024
image = bytearray(32 * MIB)
line = b"Case 2149 minutes. Transfer approved to account 0042 on 12 March.\n"
image[4 * MIB : 10 * MIB] = (line * (6 * MIB // len(line) + 1))[: 6 * MIB]
image[12 * MIB : 20 * MIB] = random.Random(3).randbytes(8 * MIB)
image[22 * MIB : 24 * MIB] = b"\xff" * (2 * MIB)
offset = 25 * MIB
for colour in [(200, 40, 40), (40, 160, 80), (30, 60, 200), (220, 200, 40)]:
    blob = jpeg(colour, (400, 300))
    image[offset : offset + len(blob)] = blob
    offset += (len(blob) // 4096 + 2) * 4096
image[28 * MIB : 30 * MIB] = b"\xa5" * (2 * MIB)
(state / "images").mkdir(exist_ok=True)
(state / "images" / "case2149.dd").write_bytes(bytes(image))
print(state)
