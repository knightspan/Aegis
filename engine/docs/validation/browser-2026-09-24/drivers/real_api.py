"""Browser checks against the real API on a demo state directory.

Usage: python real_api.py SCRATCH_DIR, with the API serving on 127.0.0.1:8799
and session token browsercheck-token-0001 (see ../README.md). The driver
aborts every request that could enumerate, probe or erase a real device.
"""

import json
import os
import re
import sys

from playwright.sync_api import sync_playwright

S = sys.argv[1]
STATE = f"{S}/demo-state"
BASE = "http://127.0.0.1:8799"
EXE = os.environ.get("SANCTUM_BROWSER_EXE")
out = {"blocked_requests": [], "checks": {}, "errors": []}


def check(name, ok, detail=""):
    out["checks"][name] = {"ok": bool(ok), "detail": detail[:600]}


def nav(page, label):
    page.locator("nav.sidebar").get_by_role("button", name=label, exact=True).click()
    page.wait_for_timeout(800)


with sync_playwright() as p:
    b = p.chromium.launch(executable_path=EXE)
    page = b.new_page(viewport={"width": 1366, "height": 768})
    page.on("pageerror", lambda e: out["errors"].append(str(e)))

    def block(route):
        out["blocked_requests"].append(route.request.url)
        route.abort()

    page.route("**/api/devices*", block)
    page.route("**/api/platform/devices/**", block)
    page.route("**/api/jobs/erase-drive*", block)
    page.goto(f"{BASE}/session/browsercheck-token-0001")
    page.wait_for_timeout(1200)
    # open demo case
    nav(page, "Cases")
    page.get_by_text("DEMO-CASE-001").first.click()
    page.wait_for_timeout(1000)
    nav(page, "Overview")
    page.wait_for_timeout(1200)
    page.screenshot(path=f"{S}/shots/01-overview.png")
    body = page.inner_text("body")
    for t in [
        "Sanctum",
        "Recover Evidence",
        "Secure Erase",
        "File / Folder Erase",
        "Verify Report",
        "Executive summary",
        "SECURE ERASURE",
        "EVIDENCE RECOVERY",
        "VERIFICATION",
        "INTEGRITY",
        "SAFETY",
        "LIMITATIONS: NOT PHYSICALLY VALIDATED",
    ]:
        check(f"overview:text:{t}", t in body)
    box = page.get_by_test_id("executive-summary").bounding_box()
    strip = page.locator(".status-strip").bounding_box()
    check(
        "overview:summary_fits_without_scroll",
        box["y"] + box["height"] <= strip["y"],
        f"summary bottom {box['y'] + box['height']:.0f}, "
        f"status strip top {strip['y']:.0f}",
    )
    check("overview:no_raw_enum", "NOT_AUTHORIZED" not in body)
    check("overview:case_shown", "DEMO-CASE-001" in body)
    # recovery
    nav(page, "Recovery")
    page.get_by_placeholder("/path/to/case.dd or case.E01").fill(
        f"{STATE}/demo-source/demo-evidence.dd"
    )
    page.get_by_placeholder("leave empty to list candidates without writing").fill(
        "demo-run"
    )
    page.get_by_role("button", name="Scan", exact=True).click()
    page.wait_for_selector("text=/Recovered \\(/", timeout=120000)
    page.wait_for_timeout(1500)
    page.locator("select").nth(1).select_option("HIGH")
    page.wait_for_timeout(600)
    rec_title = page.get_by_text(
        re.compile(r"Recovered \(\d+ of \d+\)")
    ).first.inner_text()
    check("recovery:high_filter", "Recovered" in rec_title, rec_title)
    page.screenshot(path=f"{S}/shots/02-recovery-high.png")
    page.locator(
        ".scroll-y button, .scroll-y [role=button], .gallery-card, .candidate-card"
    ).first.click()
    page.wait_for_timeout(800)
    page.screenshot(path=f"{S}/shots/03-recovery-candidate.png", full_page=True)
    rb = (
        page.inner_text("main")
        if page.query_selector("main")
        else page.inner_text("body")
    )
    out["recovery_text"] = rb[-4000:]
    check("recovery:score_breakdown", "Score breakdown" in rb)
    check("recovery:evidence_score_label", "evidence score" in rb.lower())
    job = re.search(r"(carve-[0-9a-f]+)", page.inner_text("body"))
    out["carve_job"] = job.group(1) if job else None
    # audit
    nav(page, "Audit")
    page.wait_for_timeout(800)
    jid = page.get_by_placeholder("erase-drive-…")
    if not jid.input_value() and out["carve_job"]:
        jid.fill(out["carve_job"])
    out["audit_jobid"] = jid.input_value()
    page.get_by_role("button", name="Generate signed report").click()
    page.wait_for_selector("[data-testid=report-panel]", timeout=60000)
    page.wait_for_timeout(800)
    panel = page.get_by_test_id("report-panel").inner_text()
    out["report_panel_text"] = panel
    check("certificate:signed_report_panel", "signed" in panel, panel)
    check("certificate:pdf_and_json_links", "PDF" in panel and "JSON" in panel, panel)
    page.get_by_test_id("report-panel").screenshot(path=f"{S}/shots/04b-report.png")
    page.get_by_role("button", name="Verify", exact=True).first.click()
    page.wait_for_timeout(2500)
    page.get_by_role("button", name="Simulate tampering").click()
    page.wait_for_selector("[data-testid=tamper-demo]", timeout=30000)
    page.wait_for_timeout(800)
    page.screenshot(path=f"{S}/shots/04-audit.png", full_page=True)
    ab = page.inner_text("body")
    out["audit_text"] = ab[:6000]
    check("audit:chain_valid", "VALID" in ab)
    check(
        "audit:verdict",
        any(
            v in ab
            for v in [
                "VERIFIED_WITH_LIMITATIONS",
                "VERIFIED WITH LIMITATIONS",
                "VERIFIED",
            ]
        ),
    )
    check("audit:tamper_demo", "tamper" in ab.lower())
    # cases linkage
    nav(page, "Cases")
    page.wait_for_timeout(1500)
    page.screenshot(path=f"{S}/shots/05-cases-report.png", full_page=True)
    cb = page.inner_text("body")
    out["cases_text"] = cb[:4000]
    # file eraser simulation
    nav(page, "File eraser")
    page.get_by_placeholder("/absolute/path/to/file-or-directory").fill(
        f"{STATE}/demo-erase-target"
    )
    page.get_by_role("button", name="Add", exact=True).click()
    page.get_by_role("button", name=re.compile(r"Simulate \d+ path")).click()
    page.wait_for_timeout(5000)
    page.screenshot(path=f"{S}/shots/06-file-simulation.png", full_page=True)
    fb = page.inner_text("body")
    out["files_text"] = fb[:3000]
    check("files:simulation_banner", "SIMULATION / NO PHYSICAL DEVICE MODIFIED" in fb)
    nav(page, "Overview")
    page.wait_for_timeout(1500)
    page.screenshot(path=f"{S}/shots/07-overview-after.png")
    ob = page.inner_text("body")
    out["overview_after"] = ob[:3000]
    b.close()
print(json.dumps(out, indent=1))
