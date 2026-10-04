"""Drive the screens the 2026-09-25 release-hold remediation changed.

Usage: python remediation.py STATE_DIR OUT_DIR
(../../browser-2026-09-25/drivers/sandboxed-server.sh serving STATE_DIR on 8811)

Playwright is not a project dependency; run this from a separate venv with
SANCTUM_BROWSER_EXE pointing at a Chromium. The server is the real app over the
synthetic recording helper, in a bubblewrap sandbox with no block device. No
physical device is enumerated, opened or written: /dev/sdz is a synthetic row,
and a "real" erase reaches only the recording helper's run_erase.

What it checks, all through the real UI:

- refusal UX: a write-seam refusal is BLOCKED on Sanitize, on the Overview and
  in Cases, never FAILED and never "partially sanitized"; a server failure is
  REQUEST FAILED and stays distinct from BLOCKED;
- firmware Purge: the Devices badge, the Sanitize option and the Platform row
  read Unverified without a recorded hardware result, never green;
- verification: a run whose read-back FAILED stays FAILED and the step tracker
  stops on Verify; a run whose read-back passed progresses normally.
"""

import json
import os
import re
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

STATE = Path(sys.argv[1]).resolve()
OUT = Path(sys.argv[2]).resolve()
OUT.mkdir(parents=True, exist_ok=True)
BASE = "http://127.0.0.1:8811"
SERIAL = "SYN-PURGE-1"
CASE = "CASE-REMEDIATION-1"
results: dict = {
    "checks": {},
    "page_errors": [],
    "console_errors": [],
    "http_errors": [],
}


def check(name: str, ok: bool, detail: str = "") -> None:
    results["checks"][name] = {"ok": bool(ok), "detail": str(detail)[:600]}
    print(("PASS " if ok else "FAIL ") + name, "" if ok else str(detail)[:200])


def helper_calls() -> list[dict]:
    log = STATE / "calls.log"
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines() if line]


def real_writes() -> int:
    return sum(
        1
        for c in helper_calls()
        if c["method"] == "run_erase"
        and c["dry_run"] is False
        and not c.get("refused_at_seam")
    )


def nav(page, name: str) -> None:
    page.locator("nav.sidebar").get_by_role("button", name=name, exact=True).click()
    page.wait_for_timeout(900)


def flow_text(page) -> str:
    return page.get_by_test_id("workflow-state").inner_text()


def steps(page) -> dict:
    """The step tracker: which step is current, stopped, and which are done."""
    items = page.locator("ol.flow-steps li")
    out = {"current": None, "stopped": False, "done": []}
    for i in range(items.count()):
        item = items.nth(i)
        cls = item.get_attribute("class") or ""
        label = item.inner_text().replace("stopped", "").strip()
        if "is-current" in cls:
            out["current"] = label
            out["stopped"] = "is-stopped" in cls
        if "is-done" in cls:
            out["done"].append(label)
    return out


def open_sanitize(page) -> None:
    nav(page, "Devices")
    page.locator("tr.is-openable", has_text="/dev/sdz").click()
    page.wait_for_selector("[data-testid=workflow-state]")
    page.wait_for_timeout(500)
    page.get_by_role("button", name="Review plan").click()
    page.wait_for_timeout(300)


def real_erase(page) -> None:
    """Open, approve and execute a real erase of the synthetic /dev/sdz."""
    open_sanitize(page)
    page.locator("input[type=checkbox]").first.uncheck()  # dry run off
    page.wait_for_timeout(200)
    page.get_by_role("button", name="Erase this device").click()
    page.wait_for_selector("[data-testid=erase-approval]", timeout=8000)
    page.get_by_test_id("backup-image").fill("backup.img")
    page.get_by_role("button", name="Open workflow and verify backup").click()
    page.wait_for_selector("[data-testid=workflow-plan]", timeout=8000)
    page.get_by_test_id("acknowledge").check()
    page.get_by_test_id("typed-serial").fill(SERIAL)
    page.get_by_test_id("approve").click()
    page.wait_for_selector("[data-testid=authorization-id]", timeout=8000)
    page.get_by_test_id("typed-serial").fill(SERIAL)
    page.get_by_test_id("execute").click()


def wait_settled(page) -> None:
    """Wait until the job's settled terminal status has reached the screen.

    The strip lists every state on the path, so its text cannot say when the
    job ended; the signed-record panel appears only once it has settled.
    """
    page.wait_for_selector("text=/Get (signed record|certificate)/", timeout=30000)
    page.wait_for_timeout(600)


def overview_erasure(page) -> str:
    nav(page, "Overview")
    page.wait_for_timeout(600)
    grid = page.get_by_test_id("executive-summary")
    return grid.inner_text()


def operations_rows(page) -> list[str]:
    nav(page, "Cases")
    page.wait_for_timeout(600)
    page.locator("main").get_by_role("tab", name=re.compile("^Operations")).click()
    page.wait_for_timeout(400)
    rows = page.locator("main table.itable tbody tr")
    return [rows.nth(i).inner_text() for i in range(rows.count())]


with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=os.environ.get("SANCTUM_BROWSER_EXE"))
    page = browser.new_page(viewport={"width": 1366, "height": 768})
    page.on("pageerror", lambda e: results["page_errors"].append(str(e)))
    page.on(
        "console",
        lambda m: (
            results["console_errors"].append(m.text) if m.type == "error" else None
        ),
    )
    page.on(
        "response",
        lambda r: (
            results["http_errors"].append(
                f"{r.request.method} {r.url.replace(BASE, '')} {r.status}"
            )
            if r.status >= 400
            else None
        ),
    )
    page.goto(f"{BASE}/session/browsercheck-token-0002")
    page.wait_for_timeout(900)

    # ---- Firmware Purge reads Unverified, never green --------------------------
    nav(page, "Devices")
    page.wait_for_timeout(600)
    row = page.locator("tr.is-openable", has_text="/dev/sdz")
    row_text = row.inner_text()
    verdict_cls = row.locator(".verdict").first.get_attribute("class") or ""
    devices_text = page.locator("main").inner_text()
    check(
        "purge:devices_badge_reads_unverified",
        "PURGE · UNVERIFIED" in row_text,
        row_text,
    )
    check(
        "purge:devices_badge_not_green",
        "is-success" not in verdict_cls,
        verdict_cls,
    )
    check(
        "purge:devices_no_purge_available",
        "PURGE AVAILABLE" not in devices_text,
        devices_text[:400],
    )
    page.screenshot(path=str(OUT / "01-devices-purge-unverified.png"))

    open_sanitize(page)
    body = page.locator("main").inner_text()
    check(
        "purge:sanitize_option_reads_unverified",
        re.search(r"Hardware purge\s+Unverified", body) is not None
        or ("Hardware purge" in body and "Unverified" in body),
        body[:800],
    )
    check(
        "purge:sanitize_explains_why",
        "no firmware sanitize has been run on a physical drive" in body,
        body[:800],
    )
    check(
        "purge:sanitize_not_called_supported",
        re.search(r"Hardware purge\s+Supported", body) is None,
        body[:800],
    )
    check(
        "purge:still_offered_under_that_word",
        page.get_by_role("button", name="Run dry run").count() == 1,
    )
    page.screenshot(path=str(OUT / "02-sanitize-purge-unverified.png"), full_page=True)

    nav(page, "Platform")
    platform = page.locator("main").inner_text()
    check(
        "purge:platform_row_unverified",
        re.search(r"Purge[^\n]*\n?[^\n]*Unverified", platform) is not None,
        platform[:800],
    )
    check(
        "release:no_physical_validation_line",
        "This release: no physical validation" in platform,
        platform[-800:],
    )

    # ---- A case, opened through the UI -----------------------------------------
    nav(page, "Cases")
    page.get_by_placeholder("CASE-2026-001").fill(CASE)
    page.get_by_role("button", name="Open case", exact=True).click()
    page.wait_for_timeout(900)
    check(
        "case:opened",
        CASE in page.locator("main section.panel").first.inner_text(),
    )

    # ---- Refusal at the write seam: BLOCKED everywhere --------------------------
    writes_before = real_writes()
    (STATE / "seam.flag").write_text("x")
    real_erase(page)
    page.wait_for_selector("text=/write seam/", timeout=20000)
    wait_settled(page)
    strip = flow_text(page)
    check(
        "refusal:sanitize_blocked",
        "BLOCKED" in strip and "FAILED" not in strip,
        strip,
    )
    track = steps(page)
    check(
        "refusal:tracker_never_reaches_verify",
        track["current"] == "Sanitize"
        and track["stopped"]
        and "Verify" not in track["done"],
        str(track),
    )
    check("refusal:no_write", real_writes() == writes_before)
    (STATE / "seam.flag").unlink()

    summary = overview_erasure(page)
    check(
        "refusal:overview_says_blocked",
        "BLOCKED by a safety refusal before any write; nothing was erased" in summary,
        summary[:900],
    )
    erasure_col = summary.split("Evidence recovery")[0]
    check(
        "refusal:overview_not_an_erase_failure",
        re.search(r"\bfail", erasure_col, re.I) is None,
        erasure_col,
    )
    check(
        "refusal:overview_no_partial_sanitization_language",
        re.search(r"partial|partly", summary, re.I) is None,
        summary[:900],
    )
    page.get_by_test_id("executive-summary").scroll_into_view_if_needed()
    page.screenshot(path=str(OUT / "03-overview-refusal-blocked.png"))

    rows = operations_rows(page)
    erase_rows = [r for r in rows if "Drive sanitize" in r]
    check(
        "refusal:cases_row_blocked",
        len(erase_rows) == 1 and "BLOCKED" in erase_rows[0],
        str(rows),
    )
    check(
        "refusal:cases_row_not_failed",
        all("FAILED" not in r for r in erase_rows),
        str(erase_rows),
    )
    page.locator("main").get_by_role("tab", name=re.compile("^Overview")).click()
    page.wait_for_timeout(400)
    head = page.locator("main section.panel").first.inner_text()
    check(
        "refusal:cases_figure_counts_blocked",
        "1 blocked" in head and "failed" not in head.lower(),
        head,
    )
    page.screenshot(path=str(OUT / "04-cases-refusal-blocked.png"))

    # ---- A server failure reading the case is REQUEST FAILED, not BLOCKED -------
    def boom(route):
        route.fulfill(
            status=500,
            content_type="application/json",
            body=json.dumps({"error": "synthetic server failure", "kind": "HttpError"}),
        )

    page.route(f"**/cases/{CASE}", boom)
    nav(page, "Cases")
    page.get_by_role("button", name="Refresh").click()
    page.wait_for_timeout(900)
    main = page.locator("main").inner_text()
    check(
        "request_failed:cases_says_request_failed",
        "REQUEST FAILED" in main,
        main[:600],
    )
    check(
        "request_failed:cases_not_blocked",
        "BLOCKED" not in main,
        main[:600],
    )
    page.screenshot(path=str(OUT / "05-cases-request-failed.png"))
    summary = overview_erasure(page)
    check(
        "request_failed:overview_says_request_failed",
        "REQUEST FAILED" in summary and "No case is open" not in summary,
        summary[:600],
    )
    check(
        "request_failed:overview_not_blocked",
        "BLOCKED" not in summary.split("Evidence recovery")[0],
        summary[:600],
    )
    page.unroute(f"**/cases/{CASE}")

    # ---- A failed read-back stays FAILED and stops on Verify --------------------
    (STATE / "readback.flag").write_text("x")
    real_erase(page)
    wait_settled(page)
    strip = flow_text(page)
    check(
        "readback:sanitize_failed_headline",
        "FAILED" in strip and "COMPLETE" not in strip,
        strip,
    )
    track = steps(page)
    check(
        "readback:tracker_stops_on_verify",
        track["current"] == "Verify" and track["stopped"],
        str(track),
    )
    check(
        "readback:verify_not_marked_done",
        "Verify" not in track["done"] and "Certificate" not in track["done"],
        str(track),
    )
    body = page.locator("main").inner_text()
    check(
        "readback:record_not_a_certificate",
        "Get signed record" in body and "Get certificate" not in body,
        body[-600:],
    )
    page.locator("ol.flow-steps").scroll_into_view_if_needed()
    page.screenshot(path=str(OUT / "06-sanitize-readback-failed.png"))
    (STATE / "readback.flag").unlink()

    summary = overview_erasure(page)
    check(
        "readback:overview_says_verification_failed",
        "read-back verification FAILED" in summary,
        summary[:900],
    )
    check(
        "readback:overview_not_counted_completed",
        "drive sanitization completed" not in summary,
        summary[:900],
    )
    rows = [r for r in operations_rows(page) if "Drive sanitize" in r]
    check(
        "readback:cases_row_verify_failed",
        any("VERIFY FAILED" in r for r in rows),
        str(rows),
    )

    # ---- A read-back that passed progresses normally ----------------------------
    real_erase(page)
    wait_settled(page)
    strip = flow_text(page)
    check(
        "verified:sanitize_complete",
        "COMPLETE" in strip and "FAILED" not in strip,
        strip,
    )
    track = steps(page)
    check(
        "verified:tracker_past_verify",
        "Verify" in track["done"] and not track["stopped"],
        str(track),
    )
    body = page.locator("main").inner_text()
    check(
        "verified:certificate_offered",
        "Get certificate" in body,
        body[-600:],
    )
    page.locator("ol.flow-steps").scroll_into_view_if_needed()
    page.screenshot(path=str(OUT / "07-sanitize-verified.png"))
    rows = [r for r in operations_rows(page) if "Drive sanitize" in r]
    check(
        "verified:cases_row_complete",
        sum("COMPLETE" in r for r in rows) == 1,
        str(rows),
    )
    summary = overview_erasure(page)
    check(
        "verified:overview_counts_one_completed",
        "1 drive sanitization completed" in summary,
        summary[:900],
    )
    check(
        "writes:exactly_two_real_writes_reached_the_synthetic_helper",
        real_writes() == 2,
        str(helper_calls()[-6:]),
    )

    expected = re.compile(rf"^GET /cases/{CASE} 500$")
    unexpected = [e for e in results["http_errors"] if not expected.match(e)]
    check("http:only_the_intentional_500", not unexpected, str(unexpected))
    stray = [
        m
        for m in results["console_errors"]
        if not re.search(r"Failed to load resource.*500", m)
    ]
    check("console:no_errors_beyond_the_intentional_500", not stray, str(stray))
    check("page:no_js_errors", not results["page_errors"], str(results["page_errors"]))
    browser.close()

results["passed"] = sum(1 for c in results["checks"].values() if c["ok"])
results["total"] = len(results["checks"])
(OUT / "results.json").write_text(json.dumps(results, indent=2))
print(f"{results['passed']}/{results['total']}")
sys.exit(0 if results["passed"] == results["total"] else 1)
