"""Drive the real Sanitize screen through UI -> API -> workflow -> gates.

Usage: python sanitize.py STATE_DIR OUT_DIR   (server.py already serving on 8811)

Playwright is not a project dependency; run this from a separate venv. The
server is the real app over a synthetic helper (see server.py). No physical
device is opened. Every check is recorded in OUT_DIR/results.json.
"""

import json
import os
import re
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

STATE = Path(sys.argv[1])
OUT = Path(sys.argv[2])
OUT.mkdir(parents=True, exist_ok=True)
BASE = "http://127.0.0.1:8811"
EXE = os.environ.get("SANCTUM_BROWSER_EXE")
SERIAL = "SYN-PURGE-1"
results: dict = {
    "checks": {},
    "errors": [],
    "console_errors": [],
    "http_errors": [],
    "workflow_requests": [],
}


def check(name: str, ok: bool, detail: str = "") -> None:
    results["checks"][name] = {"ok": bool(ok), "detail": detail[:500]}
    print(("PASS " if ok else "FAIL ") + name, detail[:160] if not ok else "")


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


def flow_text(page) -> str:
    return page.get_by_test_id("workflow-state").inner_text()


def open_sanitize(page) -> None:
    page.goto(f"{BASE}/session/browsercheck-token-0002")
    page.wait_for_timeout(800)
    page.locator("nav.sidebar").get_by_role(
        "button", name="Devices", exact=True
    ).click()
    page.wait_for_timeout(800)
    page.locator("tr.is-openable", has_text="/dev/sdz").click()
    page.wait_for_selector("[data-testid=workflow-state]")
    page.wait_for_timeout(500)
    page.get_by_role("button", name="Review plan").click()
    page.wait_for_timeout(300)


def to_approval_modal(page) -> None:
    page.locator("input[type=checkbox]").first.uncheck()  # dry run off
    page.wait_for_timeout(200)
    page.get_by_role("button", name="Erase this device").click()
    page.wait_for_selector("[data-testid=erase-approval]", timeout=8000)


def layout_ok(page, label: str) -> None:
    """The destructive warning and the action row are on screen, the body scrolls."""
    view = page.viewport_size
    modal = page.get_by_test_id("erase-approval").bounding_box()
    check(
        f"layout:{label}:modal_inside_viewport",
        modal["y"] >= 0
        and modal["y"] + modal["height"] <= view["height"] + 1
        and modal["x"] >= 0
        and modal["x"] + modal["width"] <= view["width"],
        f"{modal} in {view}",
    )
    body = page.locator(".modal-body")
    overflow = body.evaluate("e => getComputedStyle(e).overflowY")
    check(
        f"layout:{label}:body_scrolls_or_fits",
        overflow in ("auto", "scroll")
        or body.evaluate("e => e.scrollHeight <= e.clientHeight"),
        overflow,
    )
    body.evaluate("e => { e.scrollTop = 0 }")
    warning = page.get_by_text("This permanently destroys every byte").bounding_box()
    check(
        f"layout:{label}:warning_visible_unclipped",
        warning is not None
        and warning["y"] >= modal["y"]
        and warning["y"] + warning["height"] <= modal["y"] + modal["height"],
        str(warning),
    )
    foot = page.locator(".modal-foot").bounding_box()
    check(
        f"layout:{label}:action_row_on_screen",
        foot["y"] + foot["height"] <= view["height"] + 1,
        str(foot),
    )


def open_workflow(page) -> None:
    page.get_by_test_id("backup-image").fill("backup.img")
    page.get_by_role("button", name="Open workflow and verify backup").click()


with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=EXE)
    page = browser.new_page(viewport={"width": 1366, "height": 768})
    page.on("pageerror", lambda e: results["errors"].append(str(e)))
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
    page.on(
        "request",
        lambda r: (
            results["workflow_requests"].append(f"{r.method} {r.url.replace(BASE, '')}")
            if "/workflow/" in r.url or "/jobs/erase-drive" in r.url
            else None
        ),
    )

    # ---- Devices: a mounted device is BLOCKED and cannot be selected ---------
    (STATE / "mounted.flag").write_text("x")
    page.goto(f"{BASE}/session/browsercheck-token-0002")
    page.wait_for_timeout(800)
    page.locator("nav.sidebar").get_by_role(
        "button", name="Devices", exact=True
    ).click()
    page.wait_for_timeout(1200)
    body = page.inner_text("body")
    check(
        "blocked:mounted_device_shows_why_blocked",
        "BLOCKED" in body and "WHY BLOCKED" in body,
        body[:400],
    )
    check(
        "blocked:mounted_device_not_openable",
        page.locator("tr.is-openable", has_text="/dev/sdz").count() == 0,
    )
    page.screenshot(path=str(OUT / "00-devices-mounted-blocked.png"))
    (STATE / "mounted.flag").unlink()

    # ---- Sanitize, simulation first: banner, no authorization ----------------
    open_sanitize(page)
    text = flow_text(page)
    check("sim:preflight_state", "PREFLIGHT (SIMULATION)" in text, text)
    check(
        "sim:banner_visible",
        "SIMULATION / NO PHYSICAL DEVICE MODIFIED" in page.inner_text("body"),
    )
    check(
        "sim:identity_shown",
        SERIAL in page.inner_text("body") and "/dev/sdz" in page.inner_text("body"),
    )
    page.screenshot(path=str(OUT / "01-sanitize-simulation-preflight.png"))
    before = len(results["workflow_requests"])
    page.get_by_role("button", name="Run dry run").click()
    page.wait_for_selector("text=/COMPLETE \\(SIMULATION\\)/", timeout=15000)
    page.wait_for_timeout(400)
    check(
        "sim:complete_state",
        "COMPLETE (SIMULATION)" in flow_text(page),
        flow_text(page),
    )
    check(
        "sim:banner_on_complete",
        "SIMULATION / NO PHYSICAL DEVICE MODIFIED" in page.inner_text("body"),
    )
    reqs = results["workflow_requests"][before:]
    check(
        "sim:no_workflow_or_authorization_requested",
        all("/workflow/" not in r for r in reqs),
        str(reqs),
    )
    check("sim:helper_never_saw_a_real_write", real_writes() == 0)
    page.screenshot(path=str(OUT / "02-sanitize-simulation-complete.png"))

    # ---- Real erase: initial state, modal gates ------------------------------
    open_sanitize(page)
    to_approval_modal(page)
    check(
        "real:banner_absent",
        "SIMULATION" not in page.get_by_test_id("erase-approval").inner_text(),
    )
    check(
        "real:initial_state_human_approval_required",
        "HUMAN APPROVAL REQUIRED" in flow_text(page),
        flow_text(page),
    )
    check(
        "real:no_authorization_before_server_issues_one",
        re.search(r"auth-[0-9a-f]{16}", page.inner_text("body")) is None,
    )
    check(
        "real:open_disabled_without_backup_image",
        page.get_by_role(
            "button", name="Open workflow and verify backup"
        ).is_disabled(),
    )
    check(
        "real:no_approve_or_execute_before_workflow",
        page.get_by_test_id("approve").count() == 0
        and page.get_by_test_id("execute").count() == 0,
    )
    page.screenshot(path=str(OUT / "03-sanitize-approval-required.png"))

    # Refusal at open: the device became mounted after it was listed.
    (STATE / "mounted.flag").write_text("x")
    open_workflow(page)
    page.wait_for_selector("[data-testid=refusal]", timeout=8000)
    refusal = page.get_by_test_id("refusal").inner_text()
    check(
        "refusal:open_blocked",
        "BLOCKED" in refusal and "WHY BLOCKED" in refusal,
        refusal,
    )
    check("refusal:open_names_the_mount", "mounted" in refusal.lower(), refusal)
    check(
        "refusal:open_device_unmodified", "PHYSICAL DEVICE MODIFIED: FALSE" in refusal
    )
    check(
        "refusal:strip_state_is_blocked",
        "BLOCKED" in flow_text(page) and "WHY BLOCKED" in flow_text(page),
        flow_text(page),
    )
    page.screenshot(path=str(OUT / "04-sanitize-blocked-why-blocked.png"))
    (STATE / "mounted.flag").unlink()
    page.get_by_role("button", name="Cancel").click()

    # ---- Plan, typed-serial gate, authorization ------------------------------
    to_approval_modal(page)
    open_workflow(page)
    page.wait_for_selector("[data-testid=workflow-plan]", timeout=8000)
    modal = page.get_by_test_id("erase-approval").inner_text()
    check(
        "plan:shows_server_backup_and_plan",
        "sha256" in modal and "Plan the server recorded" in modal,
        modal,
    )
    check(
        "plan:state_still_human_approval",
        "HUMAN APPROVAL REQUIRED" in flow_text(page),
        flow_text(page),
    )
    layout_ok(page, "1366x768")
    page.set_viewport_size({"width": 1024, "height": 768})
    page.wait_for_timeout(200)
    layout_ok(page, "1024x768")
    page.screenshot(path=str(OUT / "05b-approval-modal-1024x768.png"))
    page.set_viewport_size({"width": 1366, "height": 768})
    page.wait_for_timeout(200)
    approve = page.get_by_test_id("approve")
    check("gate:approve_disabled_initially", approve.is_disabled())
    page.get_by_test_id("typed-serial").fill(SERIAL)
    check("gate:serial_alone_is_not_approval", approve.is_disabled())
    page.get_by_test_id("typed-serial").fill("")
    page.get_by_test_id("acknowledge").check()
    check("gate:ack_alone_is_not_approval", approve.is_disabled())
    page.get_by_test_id("typed-serial").fill("WRONG-SERIAL")
    check(
        "gate:wrong_serial_disabled",
        approve.is_disabled()
        and "serial does not match"
        in page.get_by_test_id("erase-approval").inner_text(),
    )
    page.screenshot(path=str(OUT / "05-sanitize-typed-serial-gate.png"))
    page.get_by_test_id("typed-serial").fill(SERIAL)
    check("gate:ack_and_serial_enable_approve", approve.is_enabled())
    approve.click()
    page.wait_for_selector("[data-testid=authorization-id]", timeout=8000)
    auth_id = page.get_by_test_id("authorization_id".replace("_", "-")).inner_text()
    check(
        "auth:server_issued_id",
        re.fullmatch(r"auth-[0-9a-f]{16}", auth_id) is not None,
        auth_id,
    )
    check("auth:state_plan_ready", "PLAN READY" in flow_text(page), flow_text(page))
    execute = page.get_by_test_id("execute")
    check("auth:execute_needs_serial_again", execute.is_disabled())
    page.screenshot(path=str(OUT / "06-sanitize-authorization-recorded.png"))

    # ---- Stale authorization: the backup changes after approval --------------
    image = STATE / "app" / "evidence" / "backup.img"
    if not image.exists():
        image = next(STATE.rglob("backup.img"))
    st = image.stat()
    os.utime(image, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))
    page.get_by_test_id("typed-serial").fill(SERIAL)
    execute.click()
    page.wait_for_selector("[data-testid=refusal]", timeout=8000)
    refusal = page.get_by_test_id("refusal").inner_text()
    check(
        "refusal:stale_backup_blocked",
        "BLOCKED" in refusal
        and "WHY BLOCKED" in refusal
        and "backup" in refusal.lower(),
        refusal,
    )
    check(
        "refusal:stale_backup_device_unmodified",
        "PHYSICAL DEVICE MODIFIED: FALSE" in refusal,
    )
    check("refusal:no_write_reached", real_writes() == 0)
    check(
        "refusal:not_generic_error", "went wrong" not in page.inner_text("body").lower()
    )
    page.screenshot(path=str(OUT / "07-sanitize-refused-stale-backup.png"))
    os.utime(image, ns=(st.st_atime_ns, st.st_mtime_ns))  # restore for the positive run

    # ---- Full positive path on the synthetic fixture -------------------------
    open_sanitize(page)
    to_approval_modal(page)
    open_workflow(page)
    page.wait_for_selector("[data-testid=workflow-plan]", timeout=8000)
    page.get_by_test_id("acknowledge").check()
    page.get_by_test_id("typed-serial").fill(SERIAL)
    page.get_by_test_id("approve").click()
    page.wait_for_selector("[data-testid=authorization-id]", timeout=8000)
    auth_id = page.get_by_test_id("authorization-id").inner_text()
    page.get_by_test_id("typed-serial").fill(SERIAL)
    page.get_by_test_id("execute").click()
    page.wait_for_selector("text=/COMPLETE/", timeout=20000)
    page.wait_for_timeout(500)
    state_text = flow_text(page)
    check(
        "exec:complete_on_fixture",
        "COMPLETE" in state_text and "SIMULATION" not in state_text,
        state_text,
    )
    check(
        "exec:existing_write_path_reached_once_on_synthetic_helper",
        real_writes() == 1,
        str(helper_calls()[-3:]),
    )
    page.screenshot(path=str(OUT / "08-sanitize-executed-on-fixture.png"))

    # ---- Direct API bypass attempts from the browser context -----------------
    def post(body: dict) -> dict:
        return page.evaluate(
            """async (b) => { const r = await fetch('/jobs/erase-drive', {method:'POST',
               headers:{'Content-Type':'application/json'}, body: JSON.stringify(b)});
               return {status: r.status, body: await r.json()} }""",
            body,
        )

    reuse = post(
        {
            "path": "/dev/sdz",
            "dry_run": False,
            "typed_serial": SERIAL,
            "authorization_id": auth_id,
        }
    )
    check(
        "bypass:reused_authorization_refused",
        reuse["status"] == 409
        and reuse["body"]["detail"]["verdict"] == "REFUSED"
        and reuse["body"]["detail"]["physical_device_modified"] is False,
        json.dumps(reuse)[:300],
    )
    bare = post({"path": "/dev/sdz", "dry_run": False, "typed_serial": SERIAL})
    check(
        "bypass:no_authorization_refused",
        bare["status"] == 409 and bare["body"]["detail"]["verdict"] == "REFUSED",
        json.dumps(bare)[:300],
    )
    invented = post(
        {
            "path": "/dev/sdz",
            "dry_run": False,
            "typed_serial": SERIAL,
            "authorization_id": "auth-0000000000000000",
        }
    )
    check("bypass:invented_id_refused", invented["status"] == 409)
    check("bypass:still_exactly_one_write", real_writes() == 1)

    # ---- Identity change after approval --------------------------------------
    open_sanitize(page)
    to_approval_modal(page)
    open_workflow(page)
    page.wait_for_selector("[data-testid=workflow-plan]", timeout=8000)
    page.get_by_test_id("acknowledge").check()
    page.get_by_test_id("typed-serial").fill(SERIAL)
    page.get_by_test_id("approve").click()
    page.wait_for_selector("[data-testid=authorization-id]", timeout=8000)
    (STATE / "serial.flag").write_text("x")
    page.get_by_test_id("typed-serial").fill(SERIAL)
    page.get_by_test_id("execute").click()
    page.wait_for_selector("[data-testid=refusal]", timeout=8000)
    refusal = page.get_by_test_id("refusal").inner_text()
    check(
        "refusal:identity_change_blocked",
        "WHY BLOCKED" in refusal and "serial" in refusal.lower(),
        refusal,
    )
    check(
        "refusal:identity_change_device_unmodified",
        "PHYSICAL DEVICE MODIFIED: FALSE" in refusal,
    )
    check("refusal:identity_change_no_extra_write", real_writes() == 1)
    (STATE / "serial.flag").unlink()

    # ---- A refusal at the helper's write seam is BLOCKED, not a failed erase -
    # The API gate passes; the helper refuses before the engine. The job fails
    # with the helper's own kind, and the screen must not call its record a
    # certificate.
    open_sanitize(page)
    to_approval_modal(page)
    open_workflow(page)
    page.wait_for_selector("[data-testid=workflow-plan]", timeout=8000)
    page.get_by_test_id("acknowledge").check()
    page.get_by_test_id("typed-serial").fill(SERIAL)
    page.get_by_test_id("approve").click()
    page.wait_for_selector("[data-testid=authorization-id]", timeout=8000)
    (STATE / "seam.flag").write_text("x")
    page.get_by_test_id("typed-serial").fill(SERIAL)
    page.get_by_test_id("execute").click()
    page.wait_for_selector("text=/write seam/", timeout=20000)
    page.wait_for_timeout(500)
    strip = flow_text(page)
    body = page.inner_text("body")
    check(
        "seam:refusal_shown_as_blocked_not_failed",
        "BLOCKED" in strip and "write seam" in strip and "FAILED" not in strip,
        strip,
    )
    check(
        "seam:record_is_not_called_a_certificate",
        "Get signed record" in body and "Get certificate" not in body,
        body[-600:],
    )
    check("seam:no_write_counted", real_writes() == 1)
    page.get_by_test_id("workflow-state").scroll_into_view_if_needed()
    page.screenshot(path=str(OUT / "10-sanitize-refused-at-write-seam.png"))
    (STATE / "seam.flag").unlink()

    # ---- A server failure is not a safety refusal ---------------------------
    open_sanitize(page)
    to_approval_modal(page)
    (STATE / "boom.flag").write_text("x")
    open_workflow(page)
    page.wait_for_selector("[data-testid=request-failure]", timeout=8000)
    failure = page.get_by_test_id("request-failure").inner_text()
    check(
        "failure:server_error_shown_as_request_failed",
        "REQUEST FAILED" in failure and "not a safety refusal" in failure,
        failure,
    )
    check(
        "failure:not_rendered_as_blocked_refusal",
        page.get_by_test_id("refusal").count() == 0,
    )
    check(
        "failure:no_host_path_or_traceback",
        "/var/lib/secret" not in page.inner_text("body")
        and "Traceback" not in page.inner_text("body"),
    )
    page.screenshot(path=str(OUT / "09-sanitize-request-failed-not-a-refusal.png"))
    (STATE / "boom.flag").unlink()

    # ---- A stale reply cannot land in a newer dialog -------------------------
    open_sanitize(page)
    to_approval_modal(page)

    def slow(route):
        page.wait_for_timeout(1500)
        route.continue_()

    page.route("**/workflow/erase-drive", slow)
    page.get_by_test_id("backup-image").fill("backup.img")
    page.get_by_role("button", name="Open workflow and verify backup").click()
    page.get_by_role("button", name="Cancel").click()  # operator gives up meanwhile
    page.wait_for_timeout(300)
    page.get_by_role("button", name="Erase this device").click()
    page.wait_for_selector("[data-testid=erase-approval]", timeout=8000)
    page.wait_for_timeout(3000)
    check(
        "stale:late_reply_does_not_populate_the_new_dialog",
        page.get_by_test_id("workflow-plan").count() == 0
        and page.get_by_test_id("approve").count() == 0
        and re.search(r"auth-[0-9a-f]{16}", page.inner_text("body")) is None,
    )
    page.unroute("**/workflow/erase-drive")

    expected = re.compile(r"^POST /(workflow/erase-drive|jobs/erase-drive) (409|500)$")
    unexpected = [e for e in results["http_errors"] if not expected.match(e)]
    check("http:only_intentional_refusals_failed", not unexpected, str(unexpected))
    stray = [
        m
        for m in results["console_errors"]
        if not re.search(r"Failed to load resource.*(409|500)", m)
    ]
    check("console:no_errors_beyond_the_intentional_responses", not stray, str(stray))
    check("page:no_js_errors", not results["errors"], str(results["errors"]))
    browser.close()

results["passed"] = sum(1 for c in results["checks"].values() if c["ok"])
results["total"] = len(results["checks"])
(OUT / "results.json").write_text(json.dumps(results, indent=2))
print(f"{results['passed']}/{results['total']}")
sys.exit(0 if results["passed"] == results["total"] else 1)
