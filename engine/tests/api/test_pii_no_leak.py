"""No planted identifier leaves the recovered object. The deliverable of PII triage.

A forensic tool that copies the Aadhaar numbers it found into its logs, its
ledger or its report has made a second copy of the data it was recovering, and
that copy is signed, hash-chained and built to travel. This test plants known,
synthetic identifiers in deleted files on a real FAT32 volume, drives the whole
product - carve route, job registry, SSE stream, report generation and report
verification - and then searches **every byte the product wrote or said** for
each value, in every form that would let it be read back:

* the value as planted and as bare digits, in ASCII and UTF-16LE;
* its SHA-256, SHA-1 and MD5, hex in both cases, and its base64 (a hash of a
  12-digit number is brute-forced in minutes, so a hash is a leak);
* a masked form ending in the real last four digits.

Sinks searched: the ledger directory, the reports directory (JSON, and the PDF
raw and with its streams decoded), the job status and result, the SSE replay,
the report and verification responses, the ledger entries endpoint, every
structlog event from every ``core``/``api``/``helper`` module at DEBUG, stdlib
logging, captured stdout and stderr, and every other file under the state and
key directories. The only files allowed to hold a value are the recovered
objects themselves, and the test asserts that nothing else - no sidecar - was
written beside them.

Positive controls, so the test cannot pass by the pipeline doing nothing: each
kind must be counted at least once, the DOCX and PDF must each be counted from
their extracted text, the log capture must contain the PII module's own event,
and a recovered object on disk must hold a planted value.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import io
import json
import logging
import re
import shutil
import sys
import time
import zipfile
from pathlib import Path
from typing import Any

import pytest
import structlog
from api.deps import AppServices
from core.carve import pii
from fastapi.testclient import TestClient

pytestmark = pytest.mark.skipif(
    shutil.which("mkfs.vfat") is None or shutil.which("mcopy") is None,
    reason="building the FAT32 volume needs mkfs.vfat and mtools",
)


def _complete(stem: str, valid: Any) -> str:
    return next(stem + d for d in "0123456789" if valid(stem + d))


#: Synthetic. Check digits are computed, so none is a real identifier.
AADHAAR = _complete("58213479106", pii.verhoeff_valid)
CARD = _complete("535110900014273", pii.luhn_valid)
PAN = "QWXPK4821M"
IFSC = "SNCT0A1B2C3"
MOBILE = "9123456780"
EMAIL = "leak.canary@sanctum-test.example.in"

AADHAAR_SPACED = f"{AADHAAR[:4]} {AADHAAR[4:8]} {AADHAAR[8:]}"
CARD_SPACED = f"{CARD[:4]} {CARD[4:8]} {CARD[8:12]} {CARD[12:]}"

NOTES = (
    f"Applicant Aadhaar {AADHAAR_SPACED}\n"
    f"PAN {PAN}\nIFSC {IFSC}\nMobile +91 {MOBILE}\n"
    f"Card {CARD_SPACED}\nEmail {EMAIL}\n"
).encode()


def _docx() -> bytes:
    body = (
        '<?xml version="1.0"?><w:document xmlns:w="w"><w:body>'
        f"<w:p><w:r><w:t>Aadhaar {AADHAAR[:5]}</w:t></w:r>"
        f"<w:r><w:t>{AADHAAR[5:]}</w:t></w:r></w:p>"
        f"<w:p><w:r><w:t>PAN {PAN}</w:t></w:r></w:p>"
        f"<w:p><w:r><w:t>{EMAIL}</w:t></w:r></w:p>"
        "</w:body></w:document>"
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="t">'
            '<Override PartName="/word/document.xml"/></Types>',
        )
        archive.writestr("word/document.xml", body)
    return buffer.getvalue()


def _pdf() -> bytes:
    import pikepdf

    document = pikepdf.new()
    document.add_blank_page(page_size=(300, 300))
    page = document.pages[0]
    page.obj.Contents = document.make_stream(
        f"BT /F1 10 Tf 20 250 Td (Aadhaar {AADHAAR}) Tj 0 -14 Td (Card {CARD}) Tj "
        f"0 -14 Td (IFSC {IFSC}) Tj ET".encode()
    )
    buffer = io.BytesIO()
    document.save(buffer)
    return buffer.getvalue()


CSV = f"name,mobile,email\nCanary,+91-{MOBILE},{EMAIL}\n".encode()


def _forms(value: str) -> set[bytes]:
    # The digits-only form is a real way to write a numeric identifier (an
    # Aadhaar, a card, a mobile number with its separators stripped). For an
    # alphanumeric one it is not: IFSC "SNCT0A1B2C3" reduces to "0123", which
    # occurs by chance in hex job ids, digests and timestamps and made this
    # test fail intermittently with no identifier anywhere near the output.
    plain = {value}
    if not any(c.isalpha() for c in value):
        plain.add(re.sub(r"\D", "", value))
    if value == AADHAAR:
        plain |= {AADHAAR_SPACED, AADHAAR_SPACED.replace(" ", "-")}
    if value == CARD:
        plain |= {CARD_SPACED, CARD_SPACED.replace(" ", "-")}
    out: set[bytes] = set()
    for form in plain:
        raw = form.encode()
        out |= {raw, form.encode("utf-16-le"), base64.b64encode(raw)}
        for algorithm in ("sha256", "sha1", "md5"):
            digest = hashlib.new(algorithm, raw).hexdigest()
            out |= {digest.encode(), digest.upper().encode()}
    return out


NEEDLES: dict[str, set[bytes]] = {
    name: _forms(value)
    for name, value in (
        ("aadhaar", AADHAAR),
        ("payment_card", CARD),
        ("pan", PAN),
        ("ifsc", IFSC),
        ("indian_mobile", MOBILE),
        ("email", EMAIL),
    )
}
MASKS = {
    "aadhaar": re.compile(rb"[Xx*#]{4}[ -]?[Xx*#]{4}[ -]?" + AADHAAR[-4:].encode()),
    "payment_card": re.compile(rb"(?:[Xx*#]{4}[ -]?){3}" + CARD[-4:].encode()),
}


def _leaks(blob: bytes) -> list[str]:
    found = [name for name, forms in NEEDLES.items() if any(f in blob for f in forms)]
    found += [f"masked {name}" for name, mask in MASKS.items() if mask.search(blob)]
    return found


def _pdf_streams(path: Path) -> bytes:
    import pikepdf

    with pikepdf.open(path) as document:
        return b"".join(
            obj.read_bytes()
            for obj in document.objects
            if isinstance(obj, pikepdf.Stream)
        )


def _capture_structlog(monkeypatch: pytest.MonkeyPatch, sink: io.StringIO) -> None:
    """Every module logger in core/api/helper, at DEBUG, rendered with all fields."""
    processors: list[Any] = [
        structlog.processors.add_log_level,
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(default=repr),
    ]
    capture = structlog.wrap_logger(
        structlog.PrintLogger(file=sink),
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG),
    )
    for name in (
        "api.carve_job",
        "api.jobs",
        "api.sse",
        "api.routes.jobs",
        "api.routes.audit",
        "core.carve.pii",
        "core.carve.classify",
        "core.carve.validate",
        "core.carve.score",
        "core.carve.structure",
        "core.carve.signature",
        "core.carve.fsaware",
        "core.carve.fragmentation",
        "core.carve.evidence",
        "core.report.render",
        "core.report.sign",
        "core.report.verify_report",
        "core.ledger.chain",
    ):
        importlib.import_module(name)
    patched = 0
    for module_name, module in list(sys.modules.items()):
        if module_name.split(".")[0] in {"core", "api", "helper"} and hasattr(
            module, "logger"
        ):
            monkeypatch.setattr(module, "logger", capture)
            patched += 1
    assert patched > 10
    # Any logger created from here on goes to the same sink.
    monkeypatch.setattr(
        structlog, "get_logger", lambda *args, **kwargs: capture, raising=True
    )


def test_no_planted_identifier_appears_in_any_sink(
    tmp_path: Path,
    client: TestClient,
    services: AppServices,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    capfd: pytest.CaptureFixture[str],
) -> None:
    from testkit.fsimage import PlantedFile, build_fat32

    caplog.set_level(logging.DEBUG)
    log_sink = io.StringIO()
    _capture_structlog(monkeypatch, log_sink)

    source_dir = tmp_path / "planted"
    source_dir.mkdir()
    image = source_dir / "leak.img"
    build_fat32(
        image,
        [
            PlantedFile("NOTES.TXT", NOTES, deleted=True),
            PlantedFile("RESUME.DOCX", _docx(), deleted=True),
            PlantedFile("REPORT.PDF", _pdf(), deleted=True),
            PlantedFile("CUST.CSV", CSV, deleted=True),
        ],
    )

    accepted = client.post(
        "/jobs/carve",
        json={
            "image": str(image),
            "undelete": True,
            "carve_signatures": True,
            "pii_triage": True,
            "out_dir": "leak-case",
        },
    )
    assert accepted.status_code == 200, accepted.text
    job_id = accepted.json()["job_id"]
    status: dict[str, Any] = {}
    for _ in range(1200):
        status = client.get(f"/jobs/{job_id}").json()
        if status["state"] in {"complete", "failed", "cancelled"}:
            break
        time.sleep(0.1)
    assert status["state"] == "complete", status

    spoken: dict[str, bytes] = {"job status and result": json.dumps(status).encode()}
    with client.stream("GET", f"/jobs/{job_id}/stream") as stream:
        spoken["SSE replay"] = b"".join(stream.iter_bytes())
    report = client.post(
        f"/reports/{job_id}", json={"case_id": "LEAK-1", "operator": "test"}
    )
    assert report.status_code == 200, report.text
    spoken["report response"] = report.content
    verification = client.get(f"/reports/{job_id}/verify")
    spoken["report verification"] = verification.content
    # The signed report still verifies with the new section, and carries it.
    assert verification.json()["passed"] is True, verification.text
    written = json.loads(Path(report.json()["json_path"]).read_text())
    triage = written["sections"]["pii_triage"]
    assert triage["objects_with_identifiers"] >= 4, triage
    spoken["ledger entries endpoint"] = client.get("/ledger/entries?limit=1000").content

    # ---- positive controls -------------------------------------------------
    candidates = status["result"]["candidates"]
    totals: dict[str, int] = {}
    for item in candidates:
        for kind, value in item["pii"]["counts"].items():
            totals[kind] = totals.get(kind, 0) + value
    assert set(totals) == set(pii.PII_KINDS), totals
    by_ext = {
        item["ext"]: item["pii"] for item in candidates if item["pii"]["inspected"]
    }
    assert by_ext["docx"]["counts"].get("aadhaar") == 1, by_ext
    assert "XML parts" in by_ext["docx"]["basis"]
    assert by_ext["pdf"]["counts"].get("aadhaar") == 1, by_ext
    assert "PDF streams" in by_ext["pdf"]["basis"]

    out_dir = services.recovered_dir / "leak-case"
    recovered = {str(path) for path in out_dir.rglob("*") if path.is_file()}
    assert recovered == set(status["result"]["written"]), "a sidecar was written"
    assert any(_leaks(Path(path).read_bytes()) for path in recovered), (
        "no recovered object holds a planted value, so the search below proves nothing"
    )

    logs = log_sink.getvalue().encode()
    assert b'"pii.scanned"' in logs, "the log capture did not see the PII module"

    # ---- the search --------------------------------------------------------
    sinks: dict[str, bytes] = dict(spoken)
    sinks["structlog events (DEBUG, all modules)"] = logs
    sinks["stdlib logging"] = caplog.text.encode()
    captured = capfd.readouterr()
    sinks["stdout"] = captured.out.encode()
    sinks["stderr"] = captured.err.encode()

    roots = [services.state_dir]
    if services.key_dir is not None:
        roots.append(Path(services.key_dir))
    for root in roots:
        for path in sorted(root.rglob("*")):
            if not path.is_file() or str(path) in recovered:
                continue
            blob = path.read_bytes()
            sinks[str(path.relative_to(tmp_path))] = blob
            if path.suffix == ".pdf":
                sinks[f"{path.relative_to(tmp_path)} (decoded streams)"] = _pdf_streams(
                    path
                )

    assert any("ledger" in name for name in sinks), sinks.keys()
    assert any(
        name.endswith(".forensic.json") or ".json" in name and "report" in name
        for name in sinks
    )

    leaked = {name: _leaks(blob) for name, blob in sinks.items() if _leaks(blob)}
    width = max(len(name) for name in sinks)
    print(f"\nplanted kinds counted: {totals}")
    forms = sum(map(len, NEEDLES.values()))
    print(f"searched {len(sinks)} sinks for {forms} forms of 6 values:")
    for name, blob in sinks.items():
        verdict = f"LEAK {leaked[name]}" if name in leaked else "clean"
        print(f"  {name:<{width}}  {len(blob):>9} bytes  {verdict}")
    assert not leaked, (
        f"planted identifiers found outside the recovered objects: {leaked}"
    )
