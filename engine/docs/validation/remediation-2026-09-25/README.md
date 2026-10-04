# Release-hold remediation browser run, 2026-09-26

The final freeze audit at `ea8c9f3` returned HOLD. This run drives the screens the
remediation changed, through the real UI and the real API, in Chromium (headless
shell, revision 1243, Playwright 1.63.0 from a separate venv) at **1366 × 768**, with
the UI bundle built at **`76dde42`**, byte-identical to the one packaged at that
commit. `results.json` holds **39 checks: 39 pass**, with no page error, and no
failed request or console error other than the two 500s the run provokes on
purpose (the case read, once from Cases and once from the Overview) and the
browser's reports of them.

**Population: SYNTHETIC.** The server is the Sanitize run's
(`../browser-2026-09-25/drivers/server.py`), the real app over the recording helper
the API test suite uses, in a bubblewrap sandbox with no `/sys`, no block device in
`/dev`, no udev database and no removable-media mount. `/dev/sdz` is a synthetic row;
a "real" erase reaches only the recording helper's `run_erase`. No physical device was
enumerated, opened or written. `server.py` gained one flag for this run,
`readback.flag`, which makes a real `run_erase` complete with a FAILED read-back.

What it checks:

- **Firmware Purge.** The Devices badge for the synthetic Purge-capable drive reads
  **PURGE · UNVERIFIED**, not in the success tone, and PURGE AVAILABLE appears
  nowhere; the Sanitize screen's Hardware purge reads *Unverified* with the reason and
  is never called *Supported*, and a run is still offered; the Platform row reads
  *Unverified*; the *Not yet proven on hardware* list opens with *This release: no
  physical validation*.
- **Refusal UX.** With a case open through the UI, a real erase refused at the
  helper's write seam (`WorkflowGateRefused`) is **BLOCKED** on Sanitize, and the
  tracker stops on Sanitize, never reaching Verify; the Overview's erasure column
  says *BLOCKED by a safety refusal before any write; nothing was erased*, with no
  "fail", "partial" or "partly" anywhere in it; the Cases row reads BLOCKED, not
  FAILED, and the case figure counts *1 blocked*. No write reached the helper.
- **REQUEST FAILED stays distinct.** With `GET /cases/{id}` answered 500 by the
  browser, Cases says REQUEST FAILED and not BLOCKED, and the Overview says REQUEST
  FAILED rather than "No case is open".
- **Verification.** A run whose read-back FAILED shows FAILED, the tracker stops on
  **Verify** marked stopped, neither Verify nor Certificate is done, and its record is
  offered as *Get signed record*, never a certificate; the Overview says the
  read-back FAILED and does not count it as a completed sanitization; Cases reads
  VERIFY FAILED. A run whose read-back passed is COMPLETE, the tracker moves past
  Verify, a certificate is offered, Cases reads COMPLETE and the Overview counts one
  completed drive sanitization. Exactly two writes reached the synthetic helper.

| Screenshot | What it shows |
|---|---|
| `01-devices-purge-unverified.png` | PURGE · UNVERIFIED on the synthetic drive, CLEAR ONLY on the other |
| `02-sanitize-purge-unverified.png` | Hardware purge, *Unverified*, with the reason |
| `03-overview-refusal-blocked.png` | The erasure column after a write-seam refusal |
| `04-cases-refusal-blocked.png` | The Cases operation: BLOCKED |
| `05-cases-request-failed.png` | A 500 on the case read: REQUEST FAILED |
| `06-sanitize-readback-failed.png` | FAILED, the tracker stopped on Verify |
| `07-sanitize-verified.png` | COMPLETE, the tracker past Verify |

**Found by this run.** The first attempt, with the full test suite running beside it,
left the Sanitize screen on PLAN READY after the job had ended. The job's terminal
stream event is sent before its outcome reaches the chain (`settled: false`), the
screen waits for `settled`, and nothing read the job again. Fixed in `644a2e3`
(`streamJob` re-reads the job until it is settled) with `ui/tests/streamJob.test.ts`.
Its results are not kept; every figure here is from the run after the fix.

The other three browser runs were repeated on the same `76dde42` bundle, each on a
fresh sandboxed server: the Sanitize run 59 of 59 (`../browser-2026-09-25/`), the
trace sweep, media map and Record of Destruction run 19 of 19
(`../features-2026-09-25/`), and the Cases, Platform, Audit and Recovery run at 1366
and 1024 wide 66 of 66 (`../polish-2026-09-25/`). None of their assertions was
changed. Their pinned screenshots were not regenerated, and their output was kept
outside the repository.

What this does **not** show: any physical device, any live desktop session, any
firmware Purge or HPA/DCO unlock, and a file erase that fails partway in a browser
(that is covered by `tests/erase/files/test_erase_single.py` and
`ui/tests/fileOutcome.test.ts`, not by this run).

Reproduce, from the repository root, after `cd ui && npm run build`:

```sh
SANCTUM_KEY_PASSPHRASE=… bash docs/validation/browser-2026-09-25/drivers/sandboxed-server.sh STATE 8811
SANCTUM_BROWSER_EXE=… python docs/validation/remediation-2026-09-25/drivers/remediation.py STATE OUT   # Playwright venv
```
