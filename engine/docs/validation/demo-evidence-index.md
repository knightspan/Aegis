# Demo evidence index

**Date:** 2026-09-24, updated after the release-quality wave; *What must not be said* extended 2026-09-26 with the release-hold remediation, and reconciled 2026-09-28 with the capability resolver ([`capability-matrix.md`](capability-completion-2026-09-28/capability-matrix.md), [`capability-completion-2026-09-28/README.md`](capability-completion-2026-09-28/README.md)). This is the
source of truth for the presentation. **Real-device mode, 2026-09-28:** the
product has no dry-run or simulation mode any more and `scripts/demo_simulation.py`
was removed; rows that name them below the demo table are historical. Every
claim a presenter makes maps to
real software output: a screen, a command, a test that pins it, and the
recorded artifact behind it. A claim with no row here does not get said.

Population labels, never mixed: **SYNTHETIC** (generated on host storage),
**REAL DEVICE** (the disposable test stick erased live; one run of one stick,
recorded as a physical validation only when `scripts/record_physical_validation.py`
records it), **FIXTURE** (fixture servers and recording helpers that keep tests
off a disk; test infrastructure, never physical), **PHYSICAL** (the one Toshiba TransMemory stick in `hardware.md`, and
the Windows discovery and file-erase runs of 2026-09-27, each scoped to its
device class), **ADAPTER DOUBLE** (Windows and macOS native paths driven by
`testkit/fake_windows.py` and `testkit/fake_macos.py`, never a device),
**CI** (virtual disks on hosted runners), **FALLBACK** (the committed signed
report and ledger under `docs/demo/fallback/`, which are not a physical-device
result).

## CAN DEMONSTRATE LIVE?

Every row below carries one of four answers. They exist so that nothing is
said live that the room cannot be shown.

| Answer | Meaning |
|---|---|
| **YES** | Runs live on the presentation laptop, on real software, with no physical device written. |
| **TEST STICK ONLY** | Runs live, as a real erase, only on the disposable, backed-up test stick. Say "this is a real erase of our test stick; it is not a device-class validation". |
| **DOCUMENTATION ONLY** | Shown from a document, a test or a recorded artifact, not run live. |
| **PHYSICAL VALIDATION REQUIRED** | Not demonstrable and not claimable until a physical run is recorded. Do not say it. |

## The 4.5-minute demo

Rehearsed on 2026-09-24 as a technical run-through (below). The spoken
timings were not rehearsed aloud; the windows are the plan.

| Time | Beat | Show | Screen or command | Pinned by | Evidence | Population | CAN DEMONSTRATE LIVE? |
|---|---|---|---|---|---|---|---|
| 0:00–0:30 | Overview | One sentence: *"Sanctum recovers evidence from an image without ever writing to it, erases a drive only with a method the drive itself reports it supports, and signs a tamper-evident record of both."* Four workflows; the six-part executive summary, including what is not physically validated | Overview | `ui/tests/summary.test.ts` | `browser-2026-09-24/01-overview-case-open.png` | live host | YES |
| 0:30–1:00 | Devices | Identity, serial, capability badge, the locked row: `BLOCKED · WHY BLOCKED: Filesystem is mounted … Human unmount required` | Devices (needs the helper running) | `tests/device/`, `ui/tests/platform.test.ts` | `browser-2026-09-24/06-devices-fixture.png` (fixture) | live host | YES — the live device list was not browser-checked in this wave; the fixture capture is the fallback |
| 0:30–1:00 | Devices, terminal | A missing or stale device path is refused cleanly and nothing is substituted | `.venv/bin/python scripts/media_benchmark.py plan --device /dev/disk/by-id/usb-DOES_NOT_EXIST --work /tmp/x --expect-serial X` | `tests/scripts/test_media_benchmark_absent_device.py` | `{"refused": "… does not exist. … No other device was substituted …", "kind": "unavailable"}`, exit 2 | live host | YES |
| 1:00–1:45 | Real device | The **REAL DEVICE** card for the disposable test stick (model, serial, size, platform, method, verification); backup, approval with the typed serial, one-use authorization, final revalidation; the erase starts and keeps running | Sanitize; [real-device procedure](../demo/runbook.md) | `tests/api/test_sanitize_ui_chain.py`, `ui/tests/workflowState.test.ts`, `tests/erase/test_drive_loopback.py` | none yet: not rehearsed since the change | REAL DEVICE | TEST STICK ONLY |
| 1:45–2:30 | Recovery | Split PNG and JPEG rebuilt from two runs and held below HIGH; the duplicate collapsed; the decoy never HIGH; every digest against ground truth; the `why` line of components | `.venv/bin/python scripts/demo_fragmented.py` (0.5 s); Recovery screen, HIGH filter, Score breakdown | `tests/scripts/test_demo_fragmented.py`, `tests/carve/signature/test_png_fragmentation.py` | `browser-2026-09-24/02`, `03`; `docs/validation/png-reassembly.md` | SYNTHETIC | YES |
| 2:30–3:15 | Forensic integrity | Graded verdict, chain `VALID`, report SHA-256 and key fingerprint, *Tamper a scratch copy* (BEFORE VALID / AFTER BROKEN), the signed JSON and PDF | Audit: Generate signed report, Verify, Tamper a scratch copy | `tests/report/test_report_verdict.py`, `tests/api/test_tamper_demo.py`, `tests/report/test_sign.py` | `browser-2026-09-24/04`, `04b` | SYNTHETIC | YES |
| 3:15–4:00 | Sanitization | Capability probe; the method the engine selects and why; the workflow strip; the human approval gate (backup image, acknowledgement and typed serial, server-issued one-use authorization; each button disabled until its inputs exist - `browser-2026-09-25/`; earlier: serial dialog, button disabled until the serial matches); the test stick's erase finishing, read back, certificate. **On any device but the test stick, do not press Erase** | Sanitize | `tests/erase/test_erase_preview.py`, `ui/tests/workflowState.test.ts`, `tests/ui/test_workflow_vocabulary.py` | `browser-2026-09-24/08`, `10` (fixture) | live host; writes only the test stick | YES |
| 3:15–4:00 | Backup requirement | A destructive benchmark write needs a verified backup on another disk, bound to the device serial, the extent and the image hash, and the write re-verifies it itself | `docs/demo/qa.md` §25; `core/workflow.py` (BACKUP_REQUIRED) | `tests/scripts/test_media_benchmark_boundary.py`, `tests/test_workflow.py` | `scripts/media_benchmark.py:verify_backup`, `write_image` | none | DOCUMENTATION ONLY |
| 4:00–4:30 | Benchmark | Population SYNTHETIC; methodology; the result; the limits | `docs/performance/benchmark.md` §Results and §Limits | `tests/testkit/` | `benchmark.csv`, `calibration-pooled.md` | SYNTHETIC | DOCUMENTATION ONLY |
| — | Physical benchmark | Recovery under the registered methodology on the physical stick | none | `tests/scripts/test_media_benchmark*.py` | `methodology-open-decision.md` | PHYSICAL | PHYSICAL VALIDATION REQUIRED |

**Never say a synthetic or fixture result is a physical one, and never call the
test-stick erase a device-class validation.** Beats 1:00 and 4:00 say their
population aloud.

### Technical rehearsal, 2026-09-24 (historical: that build's beats)

| Beat | What ran | Result |
|---|---|---|
| Overview | real API on a fresh demo state, 1366 x 768 | PASS: all six summary answers visible without scrolling |
| Devices | fixture server; `media_benchmark.py plan` on a nonexistent by-id path | PASS: WHY BLOCKED rendered; clean refusal, exit 2 |
| Simulation | `scripts/demo_simulation.py` | PASS in 0.4 s: 7 stages, blocked medium unchanged, verification passed, verdict `VERIFIED_WITH_LIMITATIONS`, tampered copy `FAILED_VERIFICATION` |
| Recovery | `scripts/demo_fragmented.py`; Recovery screen on the real API | PASS in 0.5 s: both split objects `digest matches ground truth` at 7999; 13 of 22 HIGH on screen |
| Integrity | Audit screen on the real API | PASS: 5 of 5, `VERIFIED_WITH_LIMITATIONS`, tamper BROKEN at the altered entry |
| Sanitization | Sanitize screen, fixture server | PASS: PREFLIGHT (SIMULATION), HUMAN APPROVAL REQUIRED, COMPLETE (SIMULATION), BLOCKED |
| Benchmark | `docs/performance/benchmark.md` | PASS: states SYNTHETIC in its first paragraph |

**Not rehearsed:** the spoken script against a clock, the live Devices screen
with the privileged helper and a real device, and the real-device beats (1:00,
3:15) that replaced the removed simulation beat. The spoken script, its
measured word counts and the rehearsal table are in
[`judge-defense-card.md`](judge-defense-card.md); the gates the physical
benchmark still waits on are in
[`physical-benchmark-checklist.md`](physical-benchmark-checklist.md).

**Do not use the tamper step on the fallback files directly.** The Audit
screen's *Tamper a scratch copy* works on a server-side scratch copy and never
touches the live tree.

## Claims and where each one is proved

| Claim | Screen | Command | Test | Report / benchmark | Artifact | CAN DEMONSTRATE LIVE? |
|---|---|---|---|---|---|---|
| The erase method comes from probed capability, not preference | Sanitize | device probe | `tests/device/`, `tests/erase/test_erase_preview.py` | report `method.capability_evidence` | `core/device/capabilities.py` | YES |
| There is no rehearsal mode; a request asking for one is refused, and an incomplete one writes nothing | Sanitize, File eraser (REAL DEVICE card) | `POST /jobs/*` with `dry_run` (422) or without serial/authorization (409) | `tests/api/test_endpoints.py`, `tests/api/test_sanitize_ui_chain.py`, `tests/helper/test_daemon.py`, `tests/helper/test_write_seam_authorization.py` | none | `api/routes/models.py`, `core/device/guard.py` | YES |
| A mounted device is refused, with no sudo and no unmount | Devices (WHY BLOCKED) | `media_benchmark.py preflight` | `tests/scripts/test_media_benchmark_preflight.py` | `docs/demo/qa.md` §24 | refusal on the stick, 2026-09-23 | YES |
| A missing or stale device path is refused and never substituted | none | `media_benchmark.py plan` on a nonexistent path | `tests/scripts/test_media_benchmark_absent_device.py` | none | `scripts/media_benchmark.py:_require_present` | YES |
| The write re-verifies the backup itself | none | `media_benchmark.py write` (never run in a demo) | `tests/scripts/test_media_benchmark_boundary.py` | `docs/demo/qa.md` §25 | `scripts/media_benchmark.py:write_image` | DOCUMENTATION ONLY |
| Backup restoration works on a device | none | `/workflow/restore` (never run in a demo) | `tests/restore/` (synthetic file targets) | restore report section | `core/restore.py` | PHYSICAL VALIDATION REQUIRED (implemented with authorization and post-restore hash verification; never run on a physical device) |
| Workflow state and WHY BLOCKED are named with one vocabulary | Sanitize, Devices | `media_benchmark.py plan` | `tests/test_workflow.py`, `ui/tests/workflowState.test.ts`, `tests/ui/test_workflow_vocabulary.py` | none | `core/workflow.py`, `ui/src/lib/workflowState.ts` | YES |
| One real erase walks discovery to certificate on the disposable test stick | Sanitize | [real-device procedure](../demo/runbook.md) | `tests/api/test_sanitize_ui_chain.py`, `tests/erase/test_drive_loopback.py` (root-only) | the stick's own signed report | none yet | TEST STICK ONLY |
| Split PNG and JPEG are rebuilt only when their bytes prove the join | Recovery | `scripts/demo_fragmented.py` | `tests/carve/signature/test_png_fragmentation.py`, `tests/carve/signature/test_fragmentation.py` | `docs/validation/png-reassembly.md` | `core/carve/fragmentation.py` | YES |
| A reassembled object is never HIGH | Recovery | `scripts/demo_fragmented.py` (`reassembly -1001`) | `tests/scripts/test_demo_fragmented.py` | `docs/limitations.md` | `core/carve/score.py` | YES |
| The evidence score is not a probability | Recovery | `scripts/demo_fragmented.py` | `ui/tests/format.test.ts`, `tests/report/test_confidence_is_not_a_probability.py`, `tests/ui/test_no_percent_on_evidence_score.py` | `docs/performance/calibration-pooled.md` | `core/carve/score.py` | YES |
| Duplicates are reported once with every offset | Recovery | `scripts/demo_fragmented.py` | `tests/scripts/test_demo_fragmented.py` | none | `core/carve/classify.py:dedupe` | YES |
| Report bytes are tamper-evident | Audit | `verify-report`; *Tamper a scratch copy* | `tests/api/test_tamper_demo.py` | none | `browser-2026-09-24/04` | YES |
| The verdict never rounds a limited report up | Audit | `verify-report` | `tests/report/test_report_verdict.py`, `ui/tests/verdict.test.ts` | `docs/demo/qa.md` §29 | `core/report/verify_report.py:grade_report` | YES |
| The ledger is hash-chained and a torn tail is not a break | Audit | `GET /ledger/verify` | `tests/ledger/` | `docs/demo/qa.md` §22 | `core/ledger/chain.py` | YES |
| The certificate is integrity-protected, not identity-proving | Audit | report panel | `tests/report/test_sign.py` | `docs/compliance.md` | `browser-2026-09-24/04b` | YES |
| The executive summary never counts a historical rehearsal record as an erasure, and leads its limitations with what is not physically validated | Overview | none | `ui/tests/summary.test.ts` | none | `ui/src/lib/summary.ts` | YES |
| Overwrite Clear was run on a real USB flash stick | none | none | none | `docs/validation/hardware.md` | three Phase A runs; the third, 2026-09-05, clean | DOCUMENTATION ONLY |
| Recovery was run on a real USB flash stick | none | none | none | `docs/validation/hardware.md` | three Phase B passes, 2026-09-05; not the registered benchmark | DOCUMENTATION ONLY |
| Recovery benchmark under the registered methodology on real media | none | none | none | none | none | PHYSICAL VALIDATION REQUIRED |
| Firmware Purge (ATA SANITIZE, SECURITY ERASE UNIT, NVMe Sanitize/Format, crypto erase) on a drive | none | none | fixture and adapter-double tests in `tests/erase/`, `tests/device/` | none | none | PHYSICAL VALIDATION REQUIRED |
| HPA change on a drive (guarded workflow, Linux and Windows) | none | none | `tests/device/` | none | `core/device/hidden_area_workflow.py` | PHYSICAL VALIDATION REQUIRED |
| Windows or macOS whole-drive clear, or raw acquisition, on a device | Platform (state IMPLEMENTED / UNVALIDATED) | none | adapter-double tests | none | `core/erase/blockclear.py`, `core/carve/win_source.py`, `core/carve/mac_source.py` | PHYSICAL VALIDATION REQUIRED |
| Each capability's state on each platform, scoped to validated device classes | Platform | `python scripts/capability_matrix.py --check` | `tests/platform/test_capability_matrix_doc.py` | none | [`capability-matrix.md`](capability-completion-2026-09-28/capability-matrix.md) | YES |

## Captures still required from the live rehearsal

These three files do not exist. Nothing here generates them, and no placeholder
is acceptable. The browser-validation screenshots in `browser-2026-09-24/` are
test artifacts from SYNTHETIC and fixture data; they are not substitutes for
these captures of the physical stick.

| File | What it must show | Runbook line |
|---|---|---|
| `docs/demo/fallback/devices.png` | Devices screen, stick listed, `CLEAR ONLY` badge, tooltip open | `docs/demo/runbook.md:269` |
| `docs/demo/fallback/recovery.png` | Recovery filtered to HIGH, a candidate selected, all score components readable | `docs/demo/runbook.md:532` |
| `docs/demo/fallback/wipe-start.mp4` | confirm dialog, PREFLIGHT, plan panel, `CONTROLLER_WRITE_ELISION` at HIGH, residual risk **high** | `docs/demo/runbook.md:380` |

Line numbers were read on 2026-09-24 and move when the runbook is edited.

`wipe-start.mp4` belongs to the superseded six-minute demo, which erased the
stick on stage. The final 4.5-minute order above writes nothing, so it does
not need that capture, and none should be made for it during the freeze.

## What must not be said

- That the system was benchmarked on real media for recovery. No result under
  the registered methodology exists; the Phase B passes in `hardware.md` are a
  separate, smaller record and are described as such.
- That the fallback report, or anything the removed `demo_simulation.py`
  produced, is a physical-device result.
- That the live erase of the test stick is a physical validation of a device
  class. It is one run of one stick unless recorded.
- That any certificate is government-signed or PKI-backed.
- That firmware Purge (ATA SANITIZE, SECURITY ERASE UNIT, NVMe Sanitize/Format)
  has run on a drive, on any platform. It has been selected and dispatched in
  fixture and adapter-double tests only.
- That a backup has been restored on a device. Authorized restore with
  post-restore hash verification is implemented and has never been run on a
  physical device.
- That Windows or macOS whole-drive clear or raw acquisition has run on a disk.
  Both are implemented (IMPLEMENTED / UNVALIDATED) and tested against adapter
  doubles only. Equally, do not say they are "not implemented": that was true
  before 2026-09-28 and is not now.
- That a validation on one device class covers another. The USB stick runs
  validate `usb-flash` only.
- That macOS can sanitize a device or change an HPA (PLATFORM-LIMITED), or that
  Sanctum erases internal Apple storage. It never raw-writes it and recommends
  Erase All Content and Settings.
- That general fragmented-file reconstruction is solved. Two runs, two formats.
- That the evidence score is a probability or a confidence percentage.
- Compliance with DoD 5220.22-M, or with NIST SP 800-88 beyond using its
  vocabulary and mapping to it.
- That the Devices and Sanitize screens were browser-checked against real
  devices. They were checked against fixtures.
- That anything in *this demo script* was physically validated for the
  `76dde42` release — at that release every beat ran on SIMULATION or
  SYNTHETIC data. The simulation beat has since been replaced by a real erase
  of the test stick, which is not a validation record either. The physical runs for that release are from
  2026-09-05 and 2026-09-23, with earlier builds. Separately, a Windows
  physical run on 2026-09-27 (`docs/validation/windows-hardware-2026-09-27-fixes/`)
  validated packaged install, device discovery, the mounted-device refusal
  and file erase — none of that is part of this demo's beats, and it must not
  be presented as such.
- That an HPA change has run on a drive, that DCO is ever modified, or that the trace sweep has removed a
  trace from a live desktop. It searched a real Windows 11 desktop on 2026-09-27
  and found nothing to remove.
- That a Record of Destruction proves a destruction. It is attested, not
  observed.
- That the backup is proven to be a copy of the device, that the helper's
  check-to-first-write window is race-free, or that the API authenticates who
  approved.
- That the packages passed every smoke check. The isolated smoke is 22 PASS and
  2 NOT RUN: the two need a real device.
