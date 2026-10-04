"""Capture the Recovery screen with a HIGH candidate's score components.

Usage: python recovery_capture.py SCRATCH_DIR, with the API as for real_api.py.
"""

import os
import sys

from playwright.sync_api import sync_playwright

S = sys.argv[1]
STATE = f"{S}/demo-state"
with sync_playwright() as p:
    b = p.chromium.launch(executable_path=os.environ.get("SANCTUM_BROWSER_EXE"))
    page = b.new_page(viewport={"width": 1366, "height": 1300})
    page.route("**/api/devices*", lambda r: r.abort())
    page.route("**/api/platform/devices/**", lambda r: r.abort())
    page.goto("http://127.0.0.1:8799/session/browsercheck-token-0001")
    page.wait_for_timeout(800)

    def nav(name: str) -> None:
        sidebar = page.locator("nav.sidebar")
        sidebar.get_by_role("button", name=name, exact=True).click()

    nav("Cases")
    page.wait_for_timeout(500)
    page.get_by_text("DEMO-CASE-001").first.click()
    page.wait_for_timeout(500)
    nav("Recovery")
    page.wait_for_timeout(500)
    page.get_by_placeholder("/path/to/case.dd or case.E01").fill(
        f"{STATE}/demo-source/demo-evidence.dd"
    )
    page.get_by_role("button", name="Scan", exact=True).click()
    page.wait_for_selector("text=/Recovered \\(/", timeout=120000)
    page.wait_for_timeout(1000)
    page.locator("select").nth(1).select_option("HIGH")
    page.wait_for_timeout(500)
    page.locator(".scroll-y button, .gallery-card, .candidate-card").first.click()
    page.wait_for_timeout(600)
    page.get_by_text("How this number was produced").scroll_into_view_if_needed()
    page.wait_for_timeout(400)
    page.get_by_text("Score breakdown").first.evaluate(
        "e => e.scrollIntoView({block:'start'})"
    )
    page.wait_for_timeout(400)
    page.screenshot(path=f"{S}/shots/recovery-components.png")
    b.close()
