# Sanitize screen browser run, 2026-09-25

> **Current state (2026-09-28).** Current product execution no longer exposes
> a user-facing simulation/dry-run mode: every operation runs against the
> selected real device once its gates pass, and a request that asks for a
> rehearsal is refused. References below to a dry run or a simulation record
> what the build of that date did; they are historical evidence and are kept as
> run.

**Repeated 2026-09-26 at `76dde42`** (the release-hold remediation), on a fresh
sandboxed server and the UI bundle packaged at that commit: 59 of 59, no assertion changed.
The pinned screenshots here were not regenerated. See
[`../remediation-2026-09-25/`](../remediation-2026-09-25/README.md).

`drivers/server.py` gained one flag for that run, `readback.flag` (a real
`run_erase` completes with a FAILED read-back); this driver does not use it.

**Re-run at `e21f88d`**, after the design-system v2 redesign and the stopped-step fix:
59 of 59 again, and the screenshots here are from that run. The tracker now stays on
the step where a flow stopped (`10-sanitize-refused-at-write-seam.png`: *Sanitize,
stopped*), and a preflight READY from before a refusal is labelled as the earlier
answer. The first run, at the commit this README first described, is in git history.

The real Sanitize screen, driven in Chromium (headless shell, revision 1243,
Playwright 1.63.0 from a separate venv), against the **real API app** (real routes,
workflow state machine, authorization store, job registry, ledger) over the synthetic
helper the API test suite uses. `drivers/server.py` builds it; `drivers/sanitize.py`
drives it. `results.json` holds all **59 checks: 59 pass**, zero JavaScript errors,
and no failed request other than the refusals the run provokes on purpose.

**Population: SYNTHETIC.** Device rows are synthetic `Device` records run through the
real Linux adapter and erase preview. The "positive" erase reaches the recording
helper's `run_erase` and nothing else. The server ran inside a bubblewrap sandbox with
no `/sys`, no block device in `/dev`, no udev database and no removable-media mount
(`drivers/sandboxed-server.sh`), so no code path could have reached a disk even if
the driver had missed one.

What it shows:

- a mounted device is `BLOCKED` with WHY BLOCKED and cannot be selected;
- the simulation banner at every simulation stage, and no `/workflow/` request during
  a dry run;
- the real erase's HUMAN APPROVAL REQUIRED, the backup and plan from the server, and
  the approve button disabled until the acknowledgement and the exact serial are both
  present; a server-issued `authorization_id`; PLAN READY; the serial asked again;
- refusals rendered as `BLOCKED`, WHY BLOCKED and `PHYSICAL DEVICE MODIFIED: FALSE` for
  a mount after listing, a backup changed after approval and a device identity changed
  after approval;
- a refusal by the privileged helper **at the write seam**, after the API gate passed:
  `BLOCKED`, not `FAILED`, and its signed record offered as "signed record", never as a
  certificate (`10-sanitize-refused-at-write-seam.png`);
- a server error shown as REQUEST FAILED, never as a refusal, with no host path or
  traceback;
- direct API bypass attempts (reused, missing, invented authorization) refused, with
  exactly one write on the synthetic helper;
- a stale reply that cannot populate a newer dialog; the approval modal at 1366×768 and
  1024×768, scrollable, the destructive warning unclipped.

Reproduce: `SANCTUM_KEY_PASSPHRASE=… bash drivers/sandboxed-server.sh STATE 8811`
(needs bubblewrap; nothing needs privilege), then
`SANCTUM_BROWSER_EXE=… python drivers/sanitize.py STATE OUT` from a venv with
Playwright.
