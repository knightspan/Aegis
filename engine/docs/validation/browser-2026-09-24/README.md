# Browser validation, 2026-09-24

> **Current state (2026-09-28).** Current product execution no longer exposes
> a user-facing simulation/dry-run mode: every operation runs against the
> selected real device once its gates pass, and a request that asks for a
> rehearsal is refused. References below to a dry run or a simulation record
> what the build of that date did; they are historical evidence and are kept as
> run.

The Overview screen, the simulation banner and the Sanitize workflow state had
been checked by unit tests and a TypeScript build only. This run opened them in
a real browser and drove them with Playwright. Every screenshot here is the
output of that run; none was edited.

**Browser:** `chrome-headless-shell`, Chromium revision 1243, driven by
Playwright 1.63.0 from a separate virtual environment (Playwright is not a
project dependency). **Viewport:** 1366 x 768, the projector resolution, except
`03-recovery-score-components.png` at 1366 x 1300 so the whole score panel fits.

**Physical device:** none touched. No helper ran as root, nothing was
unmounted, acquired, backed up or written.

## Two servers, and what each one proves

| Pass | Server | What it proves | What it does not |
|---|---|---|---|
| Real API | `python -m api.main` on a fresh `scripts/demo_setup.py` state directory (SYNTHETIC evidence), in-process helper, unprivileged | Overview, Recovery, Audit, report linkage and the File eraser dry run work end to end on the real server | Nothing about device discovery: the driver aborts `/api/devices*`, `/api/platform/devices/**` and `/api/jobs/erase-drive*`, so no real device is enumerated, probed or erased. None of those requests was even attempted in the run |
| Fixture server | `ui/preview.html` under the Vite dev server: the real screens, with `fetch` and `EventSource` answered from `ui/src/preview/fixtures.ts` | Devices and Sanitize render identity, serial, capability, WHY BLOCKED and every workflow state correctly | That any of those devices exists. The data is fixture data and is labelled so in every file name (`-fixture`). No request left the dev server |

## Results

`results.json` holds every check. 24 of 24 passed on the real API and 16 of 16
on the fixture server, with no page errors.

| Screen | Checked | Result | Screenshot |
|---|---|---|---|
| Overview | `Sanctum`; the four workflows; the six-part executive summary; the whole summary above the status strip at 1366 x 768 with no scrolling; no raw enum text | PASS | `01-overview-case-open.png` |
| Recovery | real carve of the demo evidence; HIGH filter (13 of 22); a candidate selected; the score panel with its six evidence components and the reassembly hold; "evidence score 9000 / 10000" and "not a probability" | PASS | `02-recovery-high-filter.png`, `03-recovery-score-components.png` |
| Audit | signed report generated for the carve job; 5 of 5 checks; graded verdict `VERIFIED_WITH_LIMITATIONS` with every limitation listed; chain `VALID`; tamper simulation `BEFORE: VALID` / `AFTER: BROKEN` at the altered entry | PASS | `04-audit-tamper.png` |
| Certificate and case linkage | report panel: signed, case `DEMO-CASE-001`, SHA-256 of the authoritative JSON, signing-key fingerprint, chain `VALID`, Open PDF and View JSON; the Cases screen lists the reports under the case (2 after this second pass on the same state directory: one per carve run) | PASS | `04b-report-panel.png` |
| Simulation (file erase) | dry run of the designated demo target shows `SIMULATION / NO PHYSICAL DEVICE MODIFIED` | PASS | `05-file-erase-simulation.png` |
| Devices | three serials; `BLOCKED · WHY BLOCKED: This device hosts the running root filesystem…` and `…Filesystem is mounted at /mnt/case-2149. Human unmount required…`; capability badges | PASS (fixture) | `06-devices-fixture.png` |
| Sanitize workflow | `PREFLIGHT (SIMULATION)` with the banner before any job; `HUMAN APPROVAL REQUIRED` with dry run off and with the serial dialog open, the erase button disabled until the serial is typed, and no EXECUTING; `COMPLETE (SIMULATION)` after the dry run; `BLOCKED` with `WHY BLOCKED` on a platform with no whole-drive engine | PASS (fixture) | `07`–`10` |

## What the run found and this wave fixed

- The executive summary printed the raw enum `NOT_AUTHORIZED`. It now prints the
  status word the rest of the interface uses.
- At 1366 x 768 the Limitations column sat 48 px below the status strip. It now
  fits with 25 px to spare.
- The score panel said "Six components" above seven rows. It now names the six
  evidence components and the reassembly hold.
- The summary claimed "six recorded runs" of the physical Clear. `hardware.md`
  records three Phase A runs, of which the third is clean. Corrected.

## Reproducing

```sh
export SANCTUM_BROWSER_EXE=~/.cache/ms-playwright/chromium_headless_shell-1243/chrome-headless-shell-linux64/chrome-headless-shell
SCRATCH=$(mktemp -d)
SANCTUM_KEY_PASSPHRASE=browser-validation-passphrase \
  .venv/bin/python scripts/demo_setup.py --state-dir "$SCRATCH/demo-state"
SANCTUM_STATE_DIR="$SCRATCH/demo-state" SANCTUM_KEY_PASSPHRASE=browser-validation-passphrase \
  SANCTUM_SESSION_TOKEN=browsercheck-token-0001 SANCTUM_PORT=8799 \
  .venv/bin/python -m api.main &
(cd ui && npx vite --port 5199 --strictPort &)
mkdir -p "$SCRATCH/shots"
python drivers/real_api.py "$SCRATCH"
python drivers/fixture_server.py "$SCRATCH"
```
