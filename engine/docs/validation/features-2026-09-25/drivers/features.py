"""Drive the 2026-09-25 features through the real UI and API: the media map,
the trace sweep (dry run, then real), and the Destroy record.

Usage: python features.py STATE_DIR OUT_DIR   (sandboxed-server.sh serving on 8812)

Playwright is not a project dependency; run this from a separate venv with
SANCTUM_BROWSER_EXE pointing at a Chromium. The server is the real app over the
synthetic helper, in a sandbox with no block device. STATE_DIR is the host path
of the directory the server sees as /cases. Every check lands in results.json.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

STATE = Path(sys.argv[1]).resolve()
OUT = Path(sys.argv[2]).resolve()
OUT.mkdir(parents=True, exist_ok=True)
BASE = "http://127.0.0.1:8812"
results: dict = {"checks": {}, "console_errors": [], "page_errors": []}


def check(name: str, ok: bool, detail: str = "") -> None:
    results["checks"][name] = {"ok": bool(ok), "detail": detail[:600]}
    print(("PASS " if ok else "FAIL ") + name, "" if ok else detail[:200])


def pdf_page(page, url: str, stem: str) -> None:
    """Fetch a PDF through the page's session and render its first page."""
    body = page.request.get(BASE + url).body()
    target = OUT / f"{stem}.pdf"
    target.write_bytes(body)
    subprocess.run(
        [
            "pdftoppm",
            "-r",
            "80",
            "-f",
            "1",
            "-l",
            "1",
            "-png",
            "-singlefile",
            str(target),
            str(OUT / stem),
        ],
        check=True,
    )
    target.unlink()


with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=os.environ["SANCTUM_BROWSER_EXE"])
    page = browser.new_page(viewport={"width": 1366, "height": 768})
    page.on(
        "console",
        lambda m: (
            results["console_errors"].append(m.text) if m.type == "error" else None
        ),
    )
    page.on("pageerror", lambda e: results["page_errors"].append(str(e)))
    accepted: list[dict] = []
    page.on(
        "response",
        lambda r: (
            accepted.append(r.json())
            if r.request.method == "POST" and "/jobs/" in r.url and r.ok
            else None
        ),
    )
    page.goto(f"{BASE}/session/browsercheck-token-0002")
    page.wait_for_timeout(800)
    nav = page.locator("nav.sidebar")

    # ---- media map -------------------------------------------------------
    nav.get_by_role("button", name="Recovery", exact=True).click()
    page.get_by_placeholder("/path/to/case.dd or case.E01").fill(
        "/cases/images/case2149.dd"
    )
    page.get_by_role("button", name="Scan", exact=True).click()
    mapped = page.get_by_test_id("media-map")
    mapped.wait_for(timeout=60000)
    text = mapped.inner_text()
    for word in ("Zeroed", "Fill pattern", "Text", "High entropy"):
        check(f"media map names {word}", word in text, text)
    check(
        "media map counts the four sector-aligned JPEG headers", "4 jpg" in text, text
    )
    check(
        "media map says every byte was read",
        "every byte read" in page.inner_text("main"),
    )
    mapped.scroll_into_view_if_needed()
    page.screenshot(path=str(OUT / "01-recovery-media-map.png"))

    # ---- trace sweep: dry run --------------------------------------------
    nav.get_by_role("button", name="File & folder eraser", exact=True).click()
    page.get_by_placeholder("/absolute/path/to/file-or-directory").fill(
        "/cases/files/case-2149"
    )
    page.get_by_role("button", name="Add", exact=True).click()
    page.get_by_role("button", name="Simulate 1 path(s)").click()
    table = page.get_by_test_id("trace-table")
    table.wait_for(timeout=30000)
    rows = table.locator("tbody tr")
    check("dry run finds seven traces", rows.count() == 7, str(rows.count()))
    outcomes = [
        cell.strip()
        for cell in table.locator("tbody tr td:last-child").all_inner_texts()
    ]
    check(
        "dry run removes nothing", outcomes == ["would be removed"] * 7, str(outcomes)
    )
    home = STATE / "home"
    thumbs = list((home / ".cache/thumbnails/normal").glob("*.png"))
    check("thumbnails still on disk after the dry run", len(thumbs) == 2, str(thumbs))
    table.scroll_into_view_if_needed()
    page.screenshot(path=str(OUT / "02-file-eraser-traces-dry-run.png"))

    # ---- trace sweep: real erase -----------------------------------------
    page.get_by_label("Dry run — enumerate what would survive, write nothing").uncheck()
    page.get_by_label("Confirm — the second gate, required when dry run is off").check()
    page.get_by_role("button", name="Erase 1 path(s)").click()
    page.wait_for_function(
        "() => [...document.querySelectorAll("
        "'[data-testid=trace-table] tbody tr td:last-child')]"
        ".some((cell) => cell.innerText.trim() === 'erased')",
        timeout=30000,
    )
    page.wait_for_timeout(500)
    table = page.get_by_test_id("trace-table")
    outcomes = [
        cell.strip()
        for cell in table.locator("tbody tr td:last-child").all_inner_texts()
    ]
    check(
        "real erase removes all seven traces",
        len(outcomes) == 7 and all(o in ("erased", "entry removed") for o in outcomes),
        str(outcomes),
    )
    thumbs = list((home / ".cache/thumbnails/normal").glob("*.png"))
    check("thumbnails gone from disk", thumbs == [], str(thumbs))
    xbel = (home / ".local/share/recently-used.xbel").read_text()
    check(
        "recent list keeps only the unrelated entry",
        "minutes.odt" in xbel and "case-2149" not in xbel,
        xbel[:400],
    )
    trash = home / ".local/share/Trash"
    check(
        "Trash copy and its record gone",
        not any((trash / "files").iterdir()) and not any((trash / "info").iterdir()),
    )
    check(
        "the erased files are gone",
        not any((STATE / "files/case-2149").iterdir())
        if (STATE / "files/case-2149").exists()
        else True,
    )
    table.scroll_into_view_if_needed()
    page.screenshot(path=str(OUT / "03-file-eraser-traces-removed.png"))

    erase_job = next(
        a["job_id"] for a in reversed(accepted) if a.get("kind") == "erase-files"
    )
    report = page.request.post(
        f"{BASE}/reports/{erase_job}", data={"case_id": "", "operator": ""}
    ).json()
    signed = page.request.get(BASE + report["json_url"]).json()
    section = signed["sections"]["traces"]
    check(
        "file report lists seven traces, seven removed",
        (section["found"], section["removed"]) == (7, 7),
        json.dumps(section)[:400],
    )
    check("file report names what was not searched", len(section["not_searched"]) >= 3)
    pdf_page(page, report["pdf_url"], "04-file-erase-certificate")

    # ---- Destroy record --------------------------------------------------
    nav.get_by_role("button", name="Devices", exact=True).click()
    page.wait_for_timeout(1000)
    page.get_by_role("button", name="Record a destruction").click()
    form = page.get_by_test_id("destroy-form")
    form.locator("select").first.select_option(index=1)
    form.get_by_label("Technique").select_option("DISINTEGRATE")
    form.get_by_label("Largest fragment (mm, optional)").fill("6")
    form.get_by_label("Destroyed on").fill("2026-09-24T15:30")
    form.get_by_label("Destroyed by").fill("A. Rao")
    form.get_by_label("Witnessed by").fill("S. Iyer")
    form.get_by_label("Where").fill("Evidence room 2, CFSL")
    form.get_by_label("Why it was destroyed rather than cleared or purged").fill(
        "Controller failed; Purge cannot be issued."
    )
    form.scroll_into_view_if_needed()
    page.screenshot(path=str(OUT / "05-destroy-record-form.png"))
    page.get_by_role("button", name="Record the destruction").click()
    page.get_by_role("button", name="Get the signed record").click(timeout=20000)
    seal = page.locator(".state-mark.is-seal", has_text="Signed record")
    seal.wait_for(timeout=20000)
    recorded = page.get_by_test_id("destroy-recorded").inner_text()
    check(
        "destroy record says attested, not observed",
        "attested, not observed" in recorded,
        recorded,
    )
    page.get_by_test_id("destroy-recorded").scroll_into_view_if_needed()
    page.screenshot(path=str(OUT / "06-destroy-record-signed.png"))
    href = page.get_by_role("link", name="Open PDF").get_attribute("href")
    pdf_page(page, href, "07-record-of-destruction")

    check(
        "no console errors",
        not results["console_errors"],
        str(results["console_errors"]),
    )
    check("no page errors", not results["page_errors"], str(results["page_errors"]))
    browser.close()

passed = sum(1 for c in results["checks"].values() if c["ok"])
results["summary"] = f"{passed} of {len(results['checks'])} checks passed"
(OUT / "results.json").write_text(json.dumps(results, indent=2) + "\n")
print(results["summary"])
