#!/usr/bin/env python3
# ruff: noqa: E501, B905, E402
"""M2 file/folder eraser validation on a disposable local corpus. SYNTHETIC.

No block device is opened and nothing outside ``--work`` is touched. ``--work``
must be a directory this script creates itself, on the host's own disk.

    .venv/bin/python scripts/validation_m2_synthetic.py --work DIR --out OUT.json

Each case records what it expected, what happened, and a PASS/FAIL. Nothing here
claims a filesystem-level guarantee: the harness checks the residual findings the
tool reports, not that bytes are unrecoverable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:  # pragma: no cover - import bootstrap
    sys.path.insert(0, str(ROOT))

from core.erase.files import erase_paths  # noqa: E402
from core.erase.metadata import cleanse_only  # noqa: E402
from core.erase.sink import ChainLedgerSink  # noqa: E402
from core.errors import SanctumError  # noqa: E402
from core.ledger.chain import ChainStatus, Ledger  # noqa: E402
from core.models import FileEraseOptions  # noqa: E402

CASES: list[dict[str, Any]] = []


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def case(
    test_id: str, test: str, expected: str, actual: str, ok: bool, **extra: Any
) -> None:
    CASES.append(
        {
            "id": test_id,
            "population": "SYNTHETIC",
            "test": test,
            "expected": expected,
            "actual": actual,
            "result": "PASS" if ok else "FAIL",
            **extra,
        }
    )
    print(f"{'PASS' if ok else 'FAIL'} {test_id} {test}: {actual}")


def sink(root: Path) -> tuple[ChainLedgerSink, Ledger]:
    ledger = Ledger(
        root / "ledger", tool_version="validation", pubkey_fingerprint="AA:BB"
    )
    return ChainLedgerSink(ledger), ledger


def run(paths: list[Path], sk: ChainLedgerSink, job: str, **opt: Any) -> Any:
    options = FileEraseOptions(workers=1, **opt)
    gen = erase_paths(paths, options, job_id=job, ledger=sk)
    progress = 0
    try:
        while True:
            next(gen)
            progress += 1
    except StopIteration as stop:
        return stop.value, progress


REAL = {"confirm": True}


def build_corpus(base: Path) -> dict[str, Path]:
    if base.exists():
        shutil.rmtree(base)
    base.mkdir(parents=True)
    out: dict[str, Path] = {}
    (base / "normal.txt").write_text("alpha secret payload " * 200)
    out["normal"] = base / "normal.txt"
    (base / "empty.bin").write_bytes(b"")
    out["empty"] = base / "empty.bin"
    (base / "with space.txt").write_text("spaces " * 100)
    out["space"] = base / "with space.txt"
    uni = base / "दस्तावेज़-файл-文件-🔒.txt"
    uni.write_text("unicode body " * 100)
    out["unicode"] = uni
    big = base / "large.bin"
    with big.open("wb") as fh:
        for i in range(24):
            fh.write(bytes([i + 1]) * (1024 * 1024))
    out["large"] = big
    ro = base / "readonly.txt"
    ro.write_text("readonly content " * 50)
    ro.chmod(0o444)
    out["readonly"] = ro
    tree = base / "tree"
    (tree / "a" / "b" / "c").mkdir(parents=True)
    for i, d in enumerate([tree, tree / "a", tree / "a" / "b", tree / "a" / "b" / "c"]):
        (d / f"f{i}.txt").write_text(f"nested {i} " * 64)
    out["tree"] = tree
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    work: Path = args.work.resolve()
    if work.exists() and any(work.iterdir()):
        print("refusing: --work must be empty or absent", file=sys.stderr)
        return 2
    work.mkdir(parents=True, exist_ok=True)
    started = time.time()

    # ---- M2-A --------------------------------------------------------------
    c = build_corpus(work / "c1")
    sk, ledger = sink(work / "l1")
    before = {
        p: sha(p)
        for p in (c["normal"], c["space"], c["unicode"], c["large"], c["readonly"])
    }

    try:
        run([c["normal"], c["tree"]], sk, "m2-unconfirmed")  # default options
        refused, kind = False, "none"
    except SanctumError as exc:
        refused, kind = True, type(exc).__name__
    intact = c["normal"].exists() and all(
        sha(p) == h for p, h in before.items() if p.exists()
    )
    case(
        "M2-A-01",
        "default options (no confirm) are refused",
        "refused before anything is inspected; nothing written, nothing removed",
        f"refused={refused} kind={kind}, files intact={intact}",
        refused and kind == "ConfirmationMismatch" and intact and c["tree"].exists(),
    )

    try:
        FileEraseOptions(workers=1, dry_run=False)  # type: ignore[call-arg]
        rejected = False
    except ValueError:
        rejected = True
    case(
        "M2-A-02",
        "a removed dry_run switch",
        "rejected by the options model; there is no rehearsal mode to fall back to",
        f"rejected={rejected} file present={c['normal'].exists()}",
        rejected and c["normal"].exists(),
    )

    res, _ = run([c["normal"]], sk, "m2-single", **REAL)
    rec = res.records[0]
    case(
        "M2-A-03",
        "single file erase",
        "ok, unlinked, file gone, residual findings listed",
        f"ok={rec.ok} unlinked={rec.unlinked} exists={c['normal'].exists()} overwritten={rec.bytes_overwritten} findings={[f.kind.value for f in rec.findings]}",
        rec.ok and rec.unlinked and not c["normal"].exists(),
        verification=rec.verification.model_dump(mode="json")
        if rec.verification
        else None,
    )

    res, _ = run([c["empty"], c["space"], c["unicode"]], sk, "m2-batch", **REAL)
    case(
        "M2-A-04",
        "batch: empty file, spaces, unicode name",
        "all ok, all gone, input order kept",
        f"ok={[r.ok for r in res.records]} order={[Path(r.path).name for r in res.records]}",
        all(r.ok for r in res.records)
        and not any(p.exists() for p in (c["empty"], c["space"], c["unicode"]))
        and [Path(r.path).name for r in res.records]
        == [c["empty"].name, c["space"].name, c["unicode"].name],
    )

    t0 = time.time()
    res, _ = run([c["large"]], sk, "m2-large", **REAL)
    rec = res.records[0]
    case(
        "M2-A-05",
        "large file (24 MiB)",
        "ok, 24 MiB overwritten",
        f"ok={rec.ok} overwritten={rec.bytes_overwritten} in {time.time() - t0:.2f}s",
        rec.ok and rec.bytes_overwritten == 24 * 1024 * 1024,
    )

    res, _ = run([c["readonly"]], sk, "m2-ro", **REAL)
    rec = res.records[0]
    case(
        "M2-A-06",
        "read-only (0444) file",
        "either erased or a recorded error - never a silent pass",
        f"ok={rec.ok} exists={c['readonly'].exists()} error={rec.error_kind}:{rec.error}",
        (rec.ok and not c["readonly"].exists()) or (not rec.ok and rec.error),
    )

    tree_files = sorted(p.name for p in c["tree"].rglob("*") if p.is_file())
    res, _ = run([c["tree"]], sk, "m2-tree", **REAL)
    case(
        "M2-A-07",
        "recursive folder (4 levels, 4 files)",
        "files erased then directories removed, tree gone",
        f"records={len(res.records)} ok={res.succeeded} failed={res.failed} tree_exists={c['tree'].exists()} files={tree_files}",
        res.failed == 0 and not c["tree"].exists(),
    )

    missing = work / "c1" / "does-not-exist.txt"
    res, _ = run([missing], sk, "m2-missing", **REAL)
    rec = res.records[0]
    case(
        "M2-A-08",
        "missing file",
        "recorded error, no traceback, batch returns",
        f"ok={rec.ok} kind={rec.error_kind} error={rec.error}",
        (not rec.ok) and bool(rec.error),
    )

    res, _ = run([c["normal"]], sk, "m2-again", **REAL)
    rec = res.records[0]
    case(
        "M2-A-09",
        "already-deleted file",
        "recorded error, not a success",
        f"ok={rec.ok} kind={rec.error_kind}",
        not rec.ok,
    )

    # recursive=False on a directory
    c2 = build_corpus(work / "c2")
    res, _ = run([c2["tree"]], sk, "m2-nonrec", recursive=False, **REAL)
    case(
        "M2-A-10",
        "directory with recursive=False",
        "non-empty directory not removed",
        f"failed={res.failed} tree_exists={c2['tree'].exists()} nested_files_remain={sum(1 for p in c2['tree'].rglob('*') if p.is_file())}",
        c2["tree"].exists()
        and sum(1 for p in c2["tree"].rglob("*") if p.is_file()) == 4,
    )

    # hardlink
    c3 = build_corpus(work / "c3")
    link = work / "c3" / "hard.txt"
    os.link(c3["normal"], link)
    payload = link.read_bytes()
    res, _ = run([c3["normal"]], sk, "m2-hardlink", **REAL)
    rec = res.records[0]
    case(
        "M2-A-11",
        "hardlinked file, break_hardlinks=False",
        "unlinked but not overwritten; other name intact; HARDLINK_SURVIVES reported",
        f"unlinked={rec.unlinked} overwritten={rec.bytes_overwritten} other_name_intact={link.exists() and link.read_bytes() == payload} findings={[f.kind.value for f in rec.findings]}",
        link.exists()
        and link.read_bytes() == payload
        and any(f.kind.value == "HARDLINK_SURVIVES" for f in rec.findings),
    )

    # symlink: link removed, target untouched
    c4 = build_corpus(work / "c4")
    sym = work / "c4" / "sym.txt"
    sym.symlink_to(c4["space"])
    tgt = sha(c4["space"])
    res, _ = run([sym], sk, "m2-symlink", **REAL)
    case(
        "M2-A-12",
        "symlink",
        "the link is handled; its target is not overwritten",
        f"target_exists={c4['space'].exists()} target_intact={c4['space'].exists() and sha(c4['space']) == tgt} link_exists={os.path.lexists(sym)} ok={res.records[0].ok}",
        c4["space"].exists() and sha(c4["space"]) == tgt,
    )

    # permission denial: file inside a directory that cannot be modified
    build_corpus(work / "c5")
    lock = work / "c5" / "locked"
    lock.mkdir()
    victim = lock / "victim.txt"
    victim.write_text("keep me out of reach " * 20)
    lock.chmod(0o555)
    res, _ = run([victim], sk, "m2-perm", **REAL)
    rec = res.records[0]
    lock.chmod(0o755)
    case(
        "M2-A-13",
        "unlinking blocked by directory permissions (0555)",
        "recorded error; success is not claimed when the name survives",
        f"ok={rec.ok} unlinked={rec.unlinked} exists={victim.exists()} kind={rec.error_kind} error={rec.error}",
        (not rec.ok) or (not victim.exists()),
    )

    # protected paths
    for idx, prot in enumerate(("/", "/usr", "/etc")):
        try:
            res, _ = run([Path(prot)], sk, f"m2-prot{idx}")
            actual = f"records ok={[r.ok for r in res.records]} err={[r.error_kind for r in res.records]}"
            ok = not any(r.ok for r in res.records)
        except SanctumError as exc:
            actual, ok = f"{type(exc).__name__}: {exc.message[:80]}", True
        case(
            f"M2-A-14{'abc'[idx]}",
            f"protected path {prot} (unconfirmed)",
            "refused",
            actual,
            ok,
        )

    # interrupted operation: close generator after first yield
    build_corpus(work / "c6")
    many = []
    for i in range(6):
        p = work / "c6" / f"many{i}.txt"
        p.write_text(f"payload {i} " * 500)
        many.append(p)
    sk6, ledger6 = sink(work / "l6")
    gen = erase_paths(
        many, FileEraseOptions(workers=1, **REAL), job_id="m2-interrupt", ledger=sk6
    )
    next(gen)
    gen.close()
    ops = [e.operation for e in ledger6.entries()]
    remaining = [p.name for p in many if p.exists()]
    case(
        "M2-A-15",
        "interrupted batch (generator closed after first progress)",
        "ledger records erase.file.cancelled; chain valid",
        f"ledger_ops={ops[-3:]} files_remaining={len(remaining)} chain={ledger6.verify().status.value}",
        any("cancel" in o for o in ops)
        and ledger6.verify().status is ChainStatus.VALID,
    )

    v = ledger.verify()
    case(
        "M2-A-16",
        "audit trail across the whole M2-A run",
        "hash chain VALID, one entry per phase per record",
        f"status={v.status.value} entries={v.entry_count}",
        v.status is ChainStatus.VALID and v.entry_count > 30,
    )

    # ---- M2-B --------------------------------------------------------------
    mb = work / "meta"
    mb.mkdir()
    import piexif
    from PIL import Image, PngImagePlugin

    jpg = mb / "photo.jpg"
    Image.new("RGB", (64, 48), (120, 30, 200)).save(jpg, "JPEG", quality=90)
    piexif.insert(
        piexif.dump(
            {
                "0th": {
                    piexif.ImageIFD.Make: b"SanctumCam",
                    piexif.ImageIFD.Software: b"secret-v3",
                },
                "Exif": {},
                "GPS": {
                    piexif.GPSIFD.GPSLatitudeRef: b"N",
                    piexif.GPSIFD.GPSLatitude: ((12, 1), (58, 1), (0, 1)),
                },
                "1st": {},
                "thumbnail": None,
            }
        ),
        str(jpg),
    )
    r = cleanse_only(jpg)
    after = piexif.load(str(jpg))
    with Image.open(jpg) as im:
        im.load()
    case(
        "M2-B-01",
        "EXIF/GPS cleanse (JPEG)",
        "all tags removed, image still decodes",
        f"fields={[f.name for f in r.fields]} removed={r.removed_count} exif_after={after['0th']}/{after['GPS']}",
        r.parsed
        and after["0th"] == {}
        and after["GPS"] == {}
        and r.removed_count == len(r.fields) > 0,
    )

    docx = mb / "notes.docx"
    core = (
        '<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>an operator</dc:creator><dc:title>Ops</dc:title></cp:coreProperties>'
    )
    app = '<?xml version="1.0"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Company>NTRO</Company></Properties>'
    body = (
        '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        "<w:body><w:p><w:r><w:t>keep this text</w:t></w:r></w:p></w:body></w:document>"
    )
    ct = (
        '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="xml" ContentType="application/xml"/></Types>'
    )
    with zipfile.ZipFile(docx, "w") as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("docProps/core.xml", core)
        z.writestr("docProps/app.xml", app)
        z.writestr("word/document.xml", body)
    r = cleanse_only(docx)
    with zipfile.ZipFile(docx) as z:
        names = set(z.namelist())
        kept = b"keep this text" in z.read("word/document.xml")
    case(
        "M2-B-02",
        "OOXML properties cleanse (synthetic minimal .docx)",
        "core/app props removed, body kept",
        f"fields={[f.name for f in r.fields]} parts_left={sorted(names)}",
        r.parsed
        and "docProps/core.xml" not in names
        and "docProps/app.xml" not in names
        and kept,
        limitation="minimal hand-built package, not a Word-authored document",
    )

    pdf = mb / "doc.pdf"
    import pikepdf

    with pikepdf.new() as d:
        d.add_blank_page()
        with d.open_metadata() as m:
            m["dc:creator"] = ["an operator"]
        d.docinfo["/Author"] = "an operator"
        d.docinfo["/Producer"] = "secret-v3"
        d.save(pdf)
    r = cleanse_only(pdf)
    with pikepdf.open(pdf) as d:
        info_gone = "/Info" not in d.trailer
        with d.open_metadata() as m:
            xmp_gone = "dc:creator" not in m
    case(
        "M2-B-03",
        "PDF Info + XMP cleanse",
        "both stores cleared",
        f"containers={sorted({f.container for f in r.fields})} info_gone={info_gone} xmp_gone={xmp_gone}",
        r.parsed and info_gone and xmp_gone,
    )

    png = mb / "shot.png"
    info = PngImagePlugin.PngInfo()
    info.add_text("Author", "an operator")
    Image.new("RGB", (32, 32)).save(png, "PNG", pnginfo=info)
    r = cleanse_only(png)
    with Image.open(png) as im:
        im.load()
        gone = "Author" not in im.info
    case(
        "M2-B-04",
        "PNG text chunk cleanse",
        "text chunks removed, image decodes",
        f"removed={r.removed_count} gone={gone}",
        r.parsed and gone,
    )

    # OLE: a real one, produced by LibreOffice from the docx above, if available
    ole_actual, ole_ok, ole_lim = (
        "soffice not available",
        None,
        "no real OLE generator on host",
    )
    soffice = shutil.which("soffice")
    if soffice:
        src = mb / "ole-src.fodt"
        src.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
            'xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" '
            'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" office:version="1.2" '
            'office:mimetype="application/vnd.oasis.opendocument.text">'
            "<office:meta><dc:creator>an operator</dc:creator><dc:title>Operation Notes</dc:title></office:meta>"
            "<office:body><office:text><text:p>keep this text</text:p></office:text></office:body></office:document>"
        )
        try:
            subprocess.run(
                [
                    soffice,
                    "--headless",
                    "--convert-to",
                    "doc",
                    "--outdir",
                    str(mb / "ole"),
                    str(src),
                ],
                capture_output=True,
                timeout=120,
                check=False,
                env={**os.environ, "HOME": str(work / "lohome")},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            ole_actual = f"soffice failed: {exc}"
        doc = mb / "ole" / "ole-src.doc"
        if doc.exists():
            r = cleanse_only(doc)
            ole_actual = f"format={r.format} parsed={r.parsed} fields={[(f.name, f.removed) for f in r.fields]} limits={[x[:70] for x in r.limitations]}"
            ole_ok = (
                r.format == "OLE" and r.parsed and all(not f.removed for f in r.fields)
            )
            ole_lim = "OLE properties are reported, NOT removed, by design; the tool must not claim otherwise"
    case(
        "M2-B-05",
        "OLE property streams (LibreOffice-produced .doc)",
        "streams named, removed=False, limitation stated",
        ole_actual,
        bool(ole_ok) if ole_ok is not None else False,
        limitation=ole_lim,
        result_override="INCONCLUSIVE" if ole_ok is None else None,
    )

    # residual reporting on a real erase of a metadata-bearing file
    keep = work / "meta" / "photo2.jpg"
    shutil.copy(jpg, keep)
    sk2, _ = sink(work / "l7")
    res, _ = run([keep], sk2, "m2-meta-erase", **REAL)
    rec = res.records[0]
    kinds = sorted({f.kind.value for f in rec.findings})
    case(
        "M2-B-06",
        "residual findings after a real erase on this host filesystem",
        "findings enumerate what cannot be guaranteed; no claim of filesystem-metadata erasure",
        f"kinds={kinds} limitations={[x[:90] for x in rec.limitations]} verification={rec.verification.model_dump(mode='json') if rec.verification else None}",
        rec.ok,
        filesystem_note="host filesystem, not FAT32/NTFS; MFT/USN kinds only apply on NTFS and are not exercised here",
    )

    for c_ in CASES:
        if c_.get("result_override"):
            c_["result"] = c_["result_override"]
        c_.pop("result_override", None)
    summary = {
        k: sum(1 for c_ in CASES if c_["result"] == k)
        for k in ("PASS", "FAIL", "INCONCLUSIVE")
    }
    doc_out = {
        "population": "SYNTHETIC",
        "work": str(work),
        "seconds": round(time.time() - started, 2),
        "summary": summary,
        "cases": CASES,
    }
    args.out.write_text(json.dumps(doc_out, indent=2, default=str) + "\n")
    print(summary)
    return 0 if summary["FAIL"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
