"""Drive the Cases, Platform, Audit and Recovery screens after the final polish.

Usage: python polish.py STATE_DIR OUT_DIR
(features-2026-09-25/drivers/sandboxed-server.sh serving a fresh seed on 8812)

Playwright is not a project dependency; run this from a separate venv with
SANCTUM_BROWSER_EXE pointing at a Chromium. The server is the real app over the
synthetic helper, in a bubblewrap sandbox with no block device. Everything a
case holds is created here through the real UI, except the one simulated drive
erase, which is submitted to the real route with ``dry_run: true`` so the case
has a simulation to label. Every check lands in results.json.
"""

import json
import os
import re
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

STATE = Path(sys.argv[1]).resolve()
OUT = Path(sys.argv[2]).resolve()
OUT.mkdir(parents=True, exist_ok=True)
BASE = "http://127.0.0.1:8812"
CASE = "CASE-2149"
results: dict = {"checks": {}, "console_errors": [], "page_errors": []}


def check(name: str, ok: bool, detail: str = "") -> None:
    results["checks"][name] = {"ok": bool(ok), "detail": str(detail)[:600]}
    print(("PASS " if ok else "FAIL ") + name, "" if ok else str(detail)[:200])


def no_sideways_scroll(page, where: str) -> None:
    """The screen's own scroll box never scrolls sideways; wide tables do."""
    overflow = page.evaluate(
        "() => { const m = document.querySelector('main');"
        " return [m.scrollWidth, m.clientWidth,"
        " document.documentElement.scrollWidth, window.innerWidth] }"
    )
    check(
        f"{where}: no sideways page scroll",
        overflow[0] <= overflow[1] and overflow[2] <= overflow[3],
        str(overflow),
    )


def wait_job(page, job_id: str) -> str:
    for _ in range(240):
        state = page.request.get(f"{BASE}/jobs/{job_id}").json()["state"]
        if state in ("complete", "failed", "cancelled"):
            return state
        time.sleep(0.5)
    return "timeout"


def tab(page, label: str):
    return page.locator("main").get_by_role("tab", name=re.compile("^" + label))


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
    main = page.locator("main")

    # ---- Cases: empty, then opened through the form -----------------------
    nav.get_by_role("button", name="Cases", exact=True).click()
    page.wait_for_timeout(500)
    check("empty case list explains what to do", "No cases yet" in main.inner_text())
    page.get_by_placeholder("CASE-2026-001").fill(CASE)
    page.get_by_placeholder("Seized laptop, exhibit 4").fill(
        "Seized USB image, exhibit 4"
    )
    page.get_by_placeholder("What this case covers").fill("Synthetic 32 MiB image")
    page.get_by_role("button", name="Open case", exact=True).click()
    page.wait_for_timeout(900)
    head = main.locator("section.panel").first
    check(
        "the open case is the first panel",
        CASE in head.locator(".panel-head").inner_text(),
    )
    check(
        "its integrity is the chain's",
        "INTEGRITY: VALID" in head.inner_text(),
        head.inner_text(),
    )
    check("case status shown", "case open" in head.inner_text())
    check(
        "an empty case says so on every figure",
        all(
            w in head.inner_text()
            for w in ("none registered", "none run", "none generated")
        ),
        head.inner_text(),
    )
    check(
        "tabs carry counts",
        tab(page, "Evidence").inner_text().split() == ["Evidence", "0"],
    )

    # ---- Evidence, registered through the form ----------------------------
    tab(page, "Evidence").click()
    page.get_by_placeholder("EX-1").fill("EX-4")
    page.get_by_placeholder("/dev/sdb, or the acquired image path").fill(
        "/cases/images/case2149.dd"
    )
    page.get_by_role("button", name="Register", exact=True).click()
    page.wait_for_timeout(800)
    evidence = main.locator("table").first.inner_text()
    check(
        "exhibit listed by its own name",
        "EX-4" in evidence and "case2149.dd" in evidence,
        evidence,
    )
    check("a missing hash reads 'not recorded'", "not recorded" in evidence, evidence)

    # ---- A recovery with the case open, through the Recovery screen -------
    nav.get_by_role("button", name="Recovery", exact=True).click()
    page.get_by_placeholder("/path/to/case.dd or case.E01").fill(
        "/cases/images/case2149.dd"
    )
    before = len(accepted)
    page.get_by_role("button", name="Scan", exact=True).click()
    page.get_by_test_id("media-map").wait_for(timeout=60000)
    carve_id = next(
        a["job_id"] for a in accepted[before:] if a["job_id"].startswith("carve-")
    )
    check("recovery completes", wait_job(page, carve_id) == "complete", carve_id)
    page.wait_for_timeout(600)
    no_sideways_scroll(page, "Recovery 1366")

    # ---- A simulated drive erase, filed against the case ------------------
    sim = page.request.post(
        f"{BASE}/jobs/erase-drive",
        data=json.dumps(
            {
                "path": "/dev/sdy",
                "level": "CLEAR",
                "dry_run": True,
                "typed_serial": "",
                "case_id": CASE,
                "operator": "examiner",
            }
        ),
        headers={"Content-Type": "application/json"},
    )
    sim_body = sim.json()
    check(
        "dry-run erase accepted as a simulation",
        sim.ok and sim_body.get("dry_run") is True,
        sim_body,
    )
    check("simulation completes", wait_job(page, sim_body["job_id"]) == "complete")

    # ---- A signed report, through the Audit screen ------------------------
    nav.get_by_role("button", name="Audit", exact=True).click()
    page.wait_for_timeout(600)
    page.get_by_placeholder("erase-drive-…").fill(carve_id)
    page.get_by_role("button", name="Generate signed report").click()
    page.get_by_test_id("report-panel").wait_for(timeout=60000)
    cells = page.evaluate(
        "() => [...document.querySelectorAll('table.itable tbody tr td:nth-child(3)')]"
        ".slice(0, 5).map(c => [c.scrollWidth, c.clientWidth, c.innerText])"
    )
    check(
        "Audit ledger timestamps are not truncated",
        all(a <= b for a, b, _ in cells),
        str(cells),
    )
    no_sideways_scroll(page, "Audit 1366")

    # ---- The case, as a judge reads it ------------------------------------
    for width in (1366, 1024):
        page.set_viewport_size({"width": width, "height": 768})
        nav.get_by_role("button", name="Cases", exact=True).click()
        main.get_by_role("button", name="Refresh", exact=True).click()
        page.wait_for_timeout(900)
        tab(page, "Overview").click()
        page.wait_for_timeout(300)
        head = main.locator("section.panel").first
        text = head.inner_text()
        check(
            f"{width}: operations figure counts the simulation within the total",
            "1 of 2 simulated" in text,
            text,
        )
        check(f"{width}: reports figure says signed", "1 signed" in text, text)
        check(
            f"{width}: tab counts",
            [
                tab(page, t).inner_text().split()[-1]
                for t in ("Evidence", "Operations", "Reports")
            ]
            == ["1", "2", "1"],
        )
        title_width = page.evaluate(
            "() => { const t = [...document.querySelectorAll('main table')].pop();"
            " return t.querySelector('tbody tr td:nth-child(3)').clientWidth }"
        )
        check(
            f"{width}: case list keeps its title column",
            title_width > 120,
            str(title_width),
        )
        no_sideways_scroll(page, f"Cases {width}")
        page.screenshot(path=str(OUT / f"cases-overview-{width}.png"))

        tab(page, "Operations").click()
        page.wait_for_timeout(300)
        ops = head.locator("table").inner_text()
        check(
            f"{width}: carve row in words",
            "Recovery (carve)" in ops and "COMPLETE" in ops,
            ops,
        )
        check(
            f"{width}: the dry run is labelled SIMULATION",
            "Drive sanitize" in ops and "SIMULATION" in ops,
            ops,
        )
        check(f"{width}: the carve's report is shown as SIGNED", "SIGNED" in ops, ops)
        clipped = page.evaluate(
            "() => [...document.querySelectorAll('main .cell-stack > *')]"
            ".map(e => [e.scrollWidth, e.clientWidth, e.innerText])"
        )
        check(
            f"{width}: operation words, SIMULATION and ids not clipped",
            len(clipped) == 4 and all(a <= b for a, b, _ in clipped),
            str(clipped),
        )
        page.screenshot(path=str(OUT / f"cases-operations-{width}.png"))

        tab(page, "Reports").click()
        page.wait_for_timeout(300)
        reports = head.inner_text()
        check(
            f"{width}: report marked SIGNED with its hash",
            "SIGNED" in reports and "SHA-256 (JSON)" in reports,
        )
        check(
            f"{width}: Open PDF offered",
            head.get_by_role("link", name="Open PDF").count() == 1,
        )

        tab(page, "Audit").click()
        page.wait_for_timeout(300)
        audit = head.inner_text()
        check(
            f"{width}: audit entries in words",
            "Case opened" in audit and "Evidence registered" in audit,
            audit[:400],
        )
        stamps = page.evaluate(
            "() => [...document.querySelectorAll("
            "'main section.panel table tbody tr td:nth-child(3)')]"
            ".slice(0, 4).map(c => [c.scrollWidth, c.clientWidth])"
        )
        check(
            f"{width}: case audit timestamps not truncated",
            all(a <= b for a, b in stamps),
            str(stamps),
        )
        no_sideways_scroll(page, f"Cases audit {width}")
        page.screenshot(path=str(OUT / f"cases-audit-{width}.png"))

    # ---- Platform ----------------------------------------------------------
    for width in (1366, 1024):
        page.set_viewport_size({"width": width, "height": 768})
        nav.get_by_role("button", name="Platform", exact=True).click()
        page.wait_for_timeout(900)
        body = main.inner_text()
        purge = page.evaluate(
            "() => [...document.querySelectorAll('.cap-row')]"
            ".find(r => r.innerText.includes('Whole-drive hardware Purge'))"
            ".querySelector('[data-status]').dataset.status"
        )
        check(
            f"{width}: firmware Purge is UNVERIFIED, not supported",
            purge == "UNVERIFIED",
            purge,
        )
        check(
            f"{width}: build identity names the commit",
            re.search(r"Build\s+[0-9a-f]{12}", body) is not None,
        )
        check(
            f"{width}: every status word is explained",
            page.locator(".status-legend > div").count() == 7,
        )
        check(f"{width}: detected-now line", "Detected now:" in body)
        check(
            f"{width}: not-proven-on-hardware list names firmware Purge and HPA/DCO",
            "Firmware Purge" in body and "HPA/DCO unlock: not run on hardware" in body,
        )
        check(
            f"{width}: safety restrictions listed",
            page.get_by_test_id("safety-restrictions").locator("li").count() == 4,
        )
        check(
            f"{width}: no run-result heading on a standing limit",
            "What this run could not guarantee" not in body,
        )
        no_sideways_scroll(page, f"Platform {width}")
        page.screenshot(path=str(OUT / f"platform-{width}.png"))
        main.evaluate("m => m.scrollTo(0, m.scrollHeight)")
        page.wait_for_timeout(200)
        page.screenshot(path=str(OUT / f"platform-bottom-{width}.png"))

    # ---- The other screens at the narrow width ----------------------------
    for name in (
        "Overview",
        "Devices",
        "Drive eraser",
        "File & folder eraser",
        "Recovery",
        "Audit",
    ):
        nav.get_by_role("button", name=name, exact=True).click()
        page.wait_for_timeout(700)
        no_sideways_scroll(page, f"{name} 1024")

    check(
        "no console errors",
        results["console_errors"] == [],
        str(results["console_errors"]),
    )
    check("no page errors", results["page_errors"] == [], str(results["page_errors"]))
    browser.close()

passed = sum(1 for c in results["checks"].values() if c["ok"])
results["passed"], results["total"] = passed, len(results["checks"])
(OUT / "results.json").write_text(json.dumps(results, indent=2) + "\n")
print(f"{passed} of {len(results['checks'])} checks passed")
sys.exit(0 if passed == len(results["checks"]) else 1)
