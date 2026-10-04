"""Build the AEGIS demo/test evidence image, deterministically, with ground truth.

    working\\engine-runtime\\python311\\python.exe tools\\make-demo-evidence.py [OUT_DIR]

Population label: SYNTHETIC. This is a disposable test image, never a device.

What it contains
----------------
An MBR-partitioned disk image (one FAT32 partition at sector 2048, the layout a
USB stick ships with). The volume is formatted and populated by ``pyfatfs``,
which writes the real FAT32 on-disk structures; deletion goes through the same
library, which does what an OS does on FAT (0xE5 the directory entry, free the
cluster chain).

* Allocated: four JPEG photos with EXIF, a PNG, a PDF, a DOCX, a text file.
* Deleted through the filesystem: one JPEG, the PDF, a ZIP.
* Planted directly into free clusters on the volume's cluster grid (no
  directory entry, the way bytes survive after a format): the AEGIS Variant's
  own difficult objects from ``scripts/demo_fragmented.py`` - a PNG and a
  baseline JPEG each split into two runs by a 32 KiB gap, an intact PNG, and a
  PNG signature followed by noise (a decoy that must not reach HIGH).

The manifest records the SHA-256 of every original object, so a recovery run
can be scored against it.
"""

from __future__ import annotations

import hashlib
import io
import json
import random
import struct
import sys
import zipfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "working" / "engine-devtools"))
sys.path.insert(0, str(ROOT / "external" / "aegis variant"))

from PIL import Image, ImageDraw, ImageFilter  # noqa: E402

SEED = 20261003
SECTOR = 512
CLUSTER = 4096
PART_START_SECTOR = 2048
VOLUME_BYTES = 96 * 1024 * 1024


def _photo(seed: int, size: tuple[int, int], title: str) -> bytes:
    """A photographic-looking JPEG: gradients, shapes, blur, and EXIF."""
    import piexif

    rng = random.Random(seed)
    w, h = size
    image = Image.new("RGB", size)
    draw = ImageDraw.Draw(image)
    top = (rng.randrange(40, 120), rng.randrange(90, 170), rng.randrange(150, 230))
    bottom = (rng.randrange(20, 90), rng.randrange(60, 140), rng.randrange(20, 90))
    for y in range(h):
        t = y / h
        draw.line([(0, y), (w, y)], fill=tuple(int(a + (b - a) * t) for a, b in zip(top, bottom)))
    for _ in range(18):
        x, y = rng.randrange(w), rng.randrange(h // 3, h)
        r = rng.randrange(20, 140)
        color = tuple(rng.randrange(30, 220) for _ in range(3))
        draw.polygon([(x - r, y + r), (x, y - r), (x + r, y + r)], fill=color)
    image = image.filter(ImageFilter.GaussianBlur(1.2))
    draw = ImageDraw.Draw(image)
    draw.text((16, 16), title, fill=(255, 255, 255))
    exif = {
        "0th": {piexif.ImageIFD.Make: b"AEGIS Test Camera", piexif.ImageIFD.Model: b"SYNTHETIC-1",
                piexif.ImageIFD.Software: b"AEGIS make-demo-evidence"},
        "Exif": {piexif.ExifIFD.DateTimeOriginal: datetime(2026, 9, 14, 11, 23, 45 + seed % 10).strftime(
            "%Y:%m:%d %H:%M:%S").encode()},
    }
    buffer = io.BytesIO()
    image.save(buffer, "JPEG", quality=88, exif=piexif.dump(exif))
    return buffer.getvalue()


def _png(seed: int) -> bytes:
    rng = random.Random(seed)
    image = Image.new("RGB", (480, 320), (245, 248, 252))
    draw = ImageDraw.Draw(image)
    for i in range(12):
        x0 = 30 + i * 36
        hgt = rng.randrange(40, 260)
        draw.rectangle([x0, 300 - hgt, x0 + 24, 300], fill=(45, 108, 223))
    draw.text((30, 10), "Quarterly transfers (synthetic)", fill=(15, 39, 71))
    buffer = io.BytesIO()
    image.save(buffer, "PNG")
    return buffer.getvalue()


def _pdf(title: str, lines: list[str]) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4, invariant=1)
    c.setTitle(title)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(72, 770, title)
    c.setFont("Helvetica", 11)
    for i, line in enumerate(lines):
        c.drawString(72, 740 - i * 16, line)
    c.showPage()
    c.save()
    return buffer.getvalue()


def _docx(text: str) -> bytes:
    buffer = io.BytesIO()
    fixed = (2026, 9, 15, 10, 0, 0)
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as z:
        def add(name: str, data: str) -> None:
            info = zipfile.ZipInfo(name, fixed)
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
        add("[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '</Types>')
        add("_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            '</Relationships>')
        add("word/document.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            f'<w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>')
    return buffer.getvalue()


def _zip(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            info = zipfile.ZipInfo(name, (2026, 9, 16, 9, 30, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, data)
    return buffer.getvalue()


class _Fat32:
    """Just enough FAT32 to delete a file the way Windows does."""

    def __init__(self, raw: bytearray) -> None:
        self.raw = raw
        self.bps, self.spc = struct.unpack_from("<HB", raw, 11)
        self.reserved, self.nfats = struct.unpack_from("<HB", raw, 14)
        self.fatsz = struct.unpack_from("<I", raw, 36)[0]
        self.root = struct.unpack_from("<I", raw, 44)[0]
        self.cluster = self.bps * self.spc
        self.data = (self.reserved + self.nfats * self.fatsz) * self.bps

    def fat_get(self, n: int) -> int:
        return struct.unpack_from("<I", self.raw, self.reserved * self.bps + n * 4)[0] & 0x0FFFFFFF

    def fat_set(self, n: int, value: int) -> None:
        for i in range(self.nfats):
            at = (self.reserved + i * self.fatsz) * self.bps + n * 4
            old = struct.unpack_from("<I", self.raw, at)[0]
            struct.pack_into("<I", self.raw, at, (old & 0xF0000000) | value)

    def chain(self, start: int) -> list[int]:
        out = []
        n = start
        while 2 <= n < 0x0FFFFFF8 and n not in out:
            out.append(n)
            n = self.fat_get(n)
        return out

    def entries(self, start: int):
        """(offset, long_name, short_entry_offset, lfn_offsets) for each live entry."""
        lfn: list[tuple[int, str]] = []
        for c in self.chain(start):
            base = self.data + (c - 2) * self.cluster
            for at in range(base, base + self.cluster, 32):
                first = self.raw[at]
                if first == 0x00:
                    return
                if first == 0xE5:
                    lfn = []
                    continue
                if self.raw[at + 11] == 0x0F:
                    part = bytes(self.raw[at + 1:at + 11] + self.raw[at + 14:at + 26] + self.raw[at + 28:at + 32])
                    lfn.insert(0, (at, part.decode("utf-16-le", "ignore").split("\x00")[0]))
                    continue
                short = bytes(self.raw[at:at + 11]).decode("ascii", "replace")
                name = "".join(p for _, p in lfn) or (short[:8].strip() + ("." + short[8:].strip() if short[8:].strip() else ""))
                yield at, name, [o for o, _ in lfn]
                lfn = []

    def delete(self, path: str) -> None:
        parts = [p for p in path.split("/") if p]
        directory = self.root
        for depth, part in enumerate(parts):
            match = next(((at, lfns) for at, name, lfns in self.entries(directory) if name.lower() == part.lower()), None)
            if match is None:
                raise SystemExit(f"{path}: {part} not found")
            at, lfns = match
            start = (struct.unpack_from("<H", self.raw, at + 20)[0] << 16) | struct.unpack_from("<H", self.raw, at + 26)[0]
            if depth < len(parts) - 1:
                directory = start
                continue
            for o in lfns + [at]:
                self.raw[o] = 0xE5
            for n in self.chain(start):
                self.fat_set(n, 0)


def build(out_dir: Path) -> dict:
    from pyfatfs.PyFat import PyFat
    from pyfatfs.PyFatFS import PyFatFS
    from scripts import demo_fragmented as frag

    out_dir.mkdir(parents=True, exist_ok=True)
    volume = out_dir / "aegis-demo-volume.tmp"
    volume.write_bytes(b"\x00" * VOLUME_BYTES)
    pf = PyFat()
    pf.mkfs(str(volume), fat_type=PyFat.FAT_TYPE_FAT32, size=VOLUME_BYTES, label="AEGISDEMO",
            volume_id=0x2026AE61)
    pf.close()

    files: dict[str, bytes] = {
        "/DCIM/IMG_0001.jpg": _photo(1, (1024, 768), "IMG_0001"),
        "/DCIM/IMG_0002.jpg": _photo(2, (1024, 768), "IMG_0002"),
        "/DCIM/IMG_0003.jpg": _photo(3, (1280, 960), "IMG_0003"),
        "/DCIM/IMG_0004.jpg": _photo(4, (800, 600), "IMG_0004"),
        "/Documents/transfers.png": _png(5),
        "/Documents/case-notes.txt": ("Meeting moved to Thursday.\r\nBring the drive.\r\n" * 40).encode(),
        "/Documents/summary.docx": _docx("Synthetic summary document for AEGIS recovery testing."),
        "/Documents/ledger-2026.pdf": _pdf("Ledger 2026 (synthetic)",
                                           [f"Line {i}: transfer reference {1000 + i}" for i in range(30)]),
        "/Archive/backup.zip": _zip({"a.txt": b"alpha " * 2000, "b.txt": b"bravo " * 3000}),
    }
    deleted = ["/DCIM/IMG_0003.jpg", "/Documents/ledger-2026.pdf", "/Archive/backup.zip"]
    fs = PyFatFS(str(volume))
    for folder in ("/DCIM", "/Documents", "/Archive"):
        fs.makedir(folder)
    for path, data in files.items():
        fs.writebytes(path, data)
    fs.close()

    # Delete as Windows does on FAT: 0xE5 the 8.3 and LFN entries, zero the
    # chain in both FATs. The data clusters are left as they were.
    raw = bytearray(volume.read_bytes())
    fat32 = _Fat32(raw)
    for path in deleted:
        fat32.delete(path)

    # Plant the Variant's difficult objects in free clusters at the end of the volume.
    bps, spc = struct.unpack_from("<HB", raw, 11)
    reserved, nfats = struct.unpack_from("<HB", raw, 14)
    fatsz = struct.unpack_from("<I", raw, 36)[0]
    cluster = bps * spc
    data_start = (reserved + nfats * fatsz) * bps
    total_clusters = (len(raw) - data_start) // cluster
    blob, truth = frag.build(random.Random(frag.SEED))
    first = 2 + total_clusters - (len(blob) // cluster) - 64
    fat = raw[reserved * bps: reserved * bps + fatsz * bps]
    for n in range(first, first + len(blob) // cluster + 1):
        if struct.unpack_from("<I", fat, n * 4)[0] & 0x0FFFFFFF:
            raise SystemExit(f"cluster {n} is allocated; the volume is too full to plant safely")
    plant_at = data_start + (first - 2) * cluster
    raw[plant_at: plant_at + len(blob)] = blob

    mbr = bytearray(PART_START_SECTOR * SECTOR)
    sectors = len(raw) // SECTOR
    entry = struct.pack("<B3sB3sII", 0x00, b"\x00\x02\x00", 0x0C, b"\xfe\xff\xff", PART_START_SECTOR, sectors)
    mbr[446:446 + 16] = entry
    struct.pack_into("<I", mbr, 440, 0x2026AE61)
    mbr[510:512] = b"\x55\xaa"
    image = out_dir / "aegis-demo-usb.dd"
    image.write_bytes(bytes(mbr) + bytes(raw))
    volume.unlink()

    volume_offset = PART_START_SECTOR * SECTOR
    manifest = {
        "population": "SYNTHETIC",
        "image": image.name,
        "sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
        "size_bytes": image.stat().st_size,
        "partition": {"start_sector": PART_START_SECTOR, "type": "FAT32 (0x0C)", "cluster_bytes": cluster},
        "files": [{"path": p, "sha256": hashlib.sha256(d).hexdigest(), "size": len(d),
                   "deleted": p in deleted} for p, d in files.items()],
        "planted_in_free_clusters": [
            {**t, "image_offset": volume_offset + plant_at + t["offset"]} for t in truth
        ],
        "generator": "tools/make-demo-evidence.py (pyfatfs + AEGIS Variant scripts/demo_fragmented.py)",
        "seed": SEED,
    }
    (out_dir / "aegis-demo-usb.manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    return manifest


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "working" / "testdata"
    result = build(target)
    print(json.dumps({"image": str(target / result["image"]), "sha256": result["sha256"],
                      "files": len(result["files"]), "planted": len(result["planted_in_free_clusters"])}, indent=1))
