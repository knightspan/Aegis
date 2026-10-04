# Final polish run, 2026-09-25: Cases, Platform, Audit, Recovery

> **Current state (2026-09-28).** Current product execution no longer exposes
> a user-facing simulation/dry-run mode: every operation runs against the
> selected real device once its gates pass, and a request that asks for a
> rehearsal is refused. References below to a dry run or a simulation record
> what the build of that date did; they are historical evidence and are kept as
> run.

**Repeated 2026-09-26 at `76dde42`** (the release-hold remediation), on a fresh
sandboxed server and the UI bundle packaged at that commit: 66 of 66, no assertion changed.
The pinned screenshots here were not regenerated. See
[`../remediation-2026-09-25/`](../remediation-2026-09-25/README.md).

The Cases and Platform screens after the final judge-facing polish, driven through the
real UI and the real API in Chromium (headless shell, revision 1243, Playwright 1.63.0
from a separate venv) at commit **`d95603d`**, at **1366 × 768 and 1024 × 768**.
`results.json` holds **66 checks: 66 pass**, with no console error and no page error.

**Population: SYNTHETIC.** The server is the one the feature run uses
(`../features-2026-09-25/drivers/sandboxed-server.sh`, over a fresh
`../features-2026-09-25/drivers/seed.py` state): the real app over the synthetic
helper, in a bubblewrap sandbox with no `/sys`, no block device in `/dev`, no udev
database and no removable-media mount. No physical device was enumerated, opened or
written. The "devices detected now" on the Platform screenshots are the helper
double's two synthetic rows.

What the driver does, and checks:

- **Cases.** The empty list explains what to do. A case is opened, an exhibit
  registered, and a recovery run with the case open, all through the UI; one dry-run
  drive erase is submitted to the real route with `dry_run: true` so the case holds a
  simulation; a signed report is generated from the Audit screen. Then, at each width:
  the open case is the first panel, with its status and the chain's INTEGRITY: VALID;
  the tabs carry their counts; the operations figure counts the simulation within the
  total (*2 complete — 1 of 2 simulated*); operations are named in words with their
  job state (COMPLETE), the dry run labelled SIMULATION and the carve's report SIGNED,
  none of it clipped; the Reports tab marks the report SIGNED with its hash and offers
  Open PDF; the Audit tab words the chain entries and its timestamps are not truncated;
  the case list keeps its title column; the screen never scrolls sideways.
- **Platform.** Firmware Purge reads **Unverified**, not supported (`0d14af2`); the
  build line names the commit; all seven status words are explained; the detected-now
  line; the *Not yet proven on hardware* list names firmware Purge and HPA/DCO; the four
  safety restrictions; no standing limit is headed as a run's result; no sideways
  scroll.
- **Audit and Recovery.** The ledger's timestamps are not truncated, and neither screen
  scrolls sideways; Overview, Devices, both erasers, Recovery and Audit do not scroll
  sideways at 1024 × 768 either.

| Screenshot | What it shows |
|---|---|
| `cases-overview-1366.png`, `-1024.png` | The open case: verdict, four figures, the case record |
| `cases-operations-1366.png`, `-1024.png` | The carve and the SIMULATION, each over its id, job state, operator, report |
| `cases-audit-1366.png`, `-1024.png` | The chain entries that name the case, in words |
| `platform-1366.png`, `-1024.png` | Identity, device support with Purge *Unverified*, the status legend |
| `platform-bottom-1366.png`, `-1024.png` | Safety restrictions, *Not yet proven on hardware*, platform restrictions |

The Sanitize run (`../browser-2026-09-25/`, 59 of 59) and the feature run
(`../features-2026-09-25/`, 19 of 19) were repeated at `d95603d` and passed; their
pinned screenshots were not regenerated, and that run's output was kept outside the
repository.

What this does **not** show: any physical device, any live desktop session, and any
firmware Purge or HPA/DCO unlock, none of which has been run.

Reproduce, from the repository root:

```sh
python docs/validation/features-2026-09-25/drivers/seed.py STATE          # project venv, PYTHONPATH=.
SANCTUM_KEY_PASSPHRASE=… bash docs/validation/features-2026-09-25/drivers/sandboxed-server.sh STATE 8812
SANCTUM_BROWSER_EXE=… python docs/validation/polish-2026-09-25/drivers/polish.py STATE OUT   # Playwright venv
```
