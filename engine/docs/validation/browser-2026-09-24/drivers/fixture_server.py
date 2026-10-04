"""Browser checks on ui/preview.html, where the server is the fixture file.

Usage: python fixture_server.py SCRATCH_DIR, with `npx vite --port 5199` running
in ui/. No request leaves the dev server; the driver records any that does.
"""

import json
import os
import sys

from playwright.sync_api import sync_playwright

S = sys.argv[1]
BASE = "http://127.0.0.1:5199/preview.html"
EXE = os.environ.get("SANCTUM_BROWSER_EXE")
out = {"checks": {}, "foreign_requests": [], "errors": []}


def check(n, ok, d=""):
    out["checks"][n] = {"ok": bool(ok), "detail": d[:500]}


def strip(page):
    loc = page.get_by_test_id("workflow-state")
    return loc.inner_text() if loc.count() else ""


with sync_playwright() as p:
    b = p.chromium.launch(executable_path=EXE)
    page = b.new_page(viewport={"width": 1366, "height": 768})
    page.on(
        "request",
        lambda r: (
            out["foreign_requests"].append(r.url)
            if not r.url.startswith("http://127.0.0.1:5199")
            else None
        ),
    )
    page.on("pageerror", lambda e: out["errors"].append(str(e)))
    page.goto(f"{BASE}?screen=devices")
    page.wait_for_timeout(1500)
    page.screenshot(path=f"{S}/shots/10-devices.png", full_page=True)
    t = page.inner_text("body")
    for serial in ["S7DPNJ0X412906H", "4C530001120809117433", "50026B7683F1A0C2"]:
        check(f"devices:serial:{serial}", serial in t)
    check(
        "devices:why_blocked_mounted",
        "WHY BLOCKED: Filesystem is mounted at /mnt/case-2149" in t,
    )
    check(
        "devices:why_blocked_system",
        "WHY BLOCKED: This device hosts the running root filesystem" in t,
    )
    check("devices:human_unmount", "Human unmount required" in t)
    out["devices_text"] = t[:3500]
    # sanitize journey on the stick
    page.locator("tr.is-openable", has_text="/dev/sda").first.click()
    page.wait_for_timeout(800)
    s1 = strip(page)
    b1 = page.inner_text("body")
    page.screenshot(path=f"{S}/shots/11-sanitize-preflight.png")
    check("sanitize:preflight_sim", "PREFLIGHT (SIMULATION)" in s1, s1)
    check("sanitize:banner_dryrun", "SIMULATION / NO PHYSICAL DEVICE MODIFIED" in b1)
    check("sanitize:backup_note", "No backup gate" in s1)
    check(
        "sanitize:no_execution_before_start",
        "EXECUTING" not in s1.split("\n")[-4] if s1 else False,
        s1,
    )
    page.get_by_role("button", name="Review plan").click()
    page.wait_for_timeout(300)
    page.locator("input[type=checkbox]").first.uncheck()
    page.wait_for_timeout(300)
    s2 = strip(page)
    page.screenshot(path=f"{S}/shots/12-sanitize-approval.png")
    check(
        "sanitize:human_approval",
        "HUMAN APPROVAL REQUIRED" in s2 and "(SIMULATION)" not in s2,
        s2,
    )
    page.locator("button.destructive").first.click()
    page.wait_for_timeout(300)
    s3 = strip(page)
    check(
        "sanitize:modal_still_approval_not_executing",
        "HUMAN APPROVAL REQUIRED" in s3
        and "EXECUTING" not in page.locator(".workflow-headline").inner_text(),
        s3,
    )
    erase_btn = page.locator(".modal button.destructive")
    check("sanitize:erase_disabled_without_serial", erase_btn.is_disabled())
    page.locator(".modal-foot button", has_text="Cancel").click()
    page.wait_for_timeout(300)
    page.locator("input[type=checkbox]").first.check()
    page.wait_for_timeout(300)
    page.get_by_role("button", name="Run dry run").click()
    page.wait_for_timeout(1500)
    s4 = strip(page)
    b4 = page.inner_text("body")
    page.screenshot(path=f"{S}/shots/13-sanitize-dryrun-complete.png", full_page=True)
    check("sanitize:complete_simulation", "COMPLETE (SIMULATION)" in s4, s4)
    check(
        "sanitize:banner_after_job",
        b4.count("SIMULATION / NO PHYSICAL DEVICE MODIFIED") >= 1,
    )
    # blocked device on sanitize (no whole-drive engine on this platform)
    page2 = b.new_page(viewport={"width": 1366, "height": 768})
    page2.on(
        "request",
        lambda r: (
            out["foreign_requests"].append(r.url)
            if not r.url.startswith("http://127.0.0.1:5199")
            else None
        ),
    )
    page2.goto(f"{BASE}?screen=unavailable")
    page2.wait_for_timeout(1500)
    s5 = strip(page2)
    page2.screenshot(path=f"{S}/shots/14-sanitize-blocked.png")
    check("sanitize:blocked_why", "BLOCKED" in s5 and "WHY BLOCKED" in s5, s5)
    b.close()
print(json.dumps(out, indent=1))
