# Release readiness: Module 1, cross-platform

> **Current capability state (2026-09-28, at `bf4c59b`).** The gate table
> below is the dated record of the 2026-09-22 CI release gate and is kept as
> it was run, with rows that have since changed annotated. The current state of
> every capability on every platform, separating implementation from physical
> validation by device class, is the generated
> [`capability-matrix.md`](validation/capability-completion-2026-09-28/capability-matrix.md);
> what changed is in
> [`capability-completion-2026-09-28/README.md`](validation/capability-completion-2026-09-28/README.md).
> Suite at `bf4c59b` on the Linux host: 3110 passed, 48 skipped, 0 failed; UI
> 148 passed.

What is true, what is not, and where the evidence is. Every line here points
at something a reader can open: a CI run, an evidence file in
`core/platform/validation_record.json`, or a document.

Statuses: **DONE** (evidence exists), **PARTIAL** (done for part of the
scope, named), **NOT DONE** (and why).

_Evidence: `platform-ci` run 35679982678 on the
`release/cross-platform-validation` branch (2026-09-22) - gate, three
platform jobs and three package jobs all green - plus the runs before it for
the defects each one found._

## The gate

| # | Condition | Status | Evidence |
|---|---|---|---|
| 1 | Windows CI actually runs | DONE | `platform-ci / platform (windows-latest)` - full Python suite, adapter smoke, file-erase suite |
| 2 | macOS CI actually runs | DONE | `platform-ci / platform (macos-14)` |
| 3 | Linux regression stays green | DONE | `gate / full suite` and `platform (ubuntu-latest)` |
| 4 | Windows device discovery executes | DONE | `platform-smoke-Windows.json`: disks enumerated from the Storage module, the system disk recognised and refused |
| 5 | macOS device discovery executes | DONE | `platform-smoke-macOS.json`: APFS containers traced to their physical stores, boot disk refused |
| 6 | Windows file/folder erase tests run | DONE | `validation-Windows.json`, suite `file_erase` |
| 7 | macOS file/folder erase tests run | DONE | `validation-macOS.json`, suite `file_erase` |
| 8 | Windows junction / reparse protections validated | DONE | `tests/platform/test_windows_filesystem.py` creates a real junction on the runner and proves the erase stays inside the named root |
| 9 | macOS APFS limitation behaviour validated | DONE | `tests/platform/test_macos_filesystem.py`: the erase runs, the verification is `not_possible` with a reason, and a residual finding is recorded |
| 10 | Windows installer built | DONE in CI | `package (windows-latest)`: `SanctumSetup.exe` (36,666,595 bytes) built, installed silently to `%LOCALAPPDATA%\Programs\Sanctum`, the installed app driven through 24 of 24 checks, then uninstalled and the directory confirmed gone |
| 11 | macOS DMG built | DONE in CI | `package (macos-14)`: `Sanctum.dmg` (44,013,635 bytes) built and mounted, `Sanctum.app` driven through 24 of 24 checks |
| 12 | Linux package still works | DONE | AppImage + `.deb` built locally and in CI; `package-smoke-Linux.json`: 23 of 23 checks - one fewer than the other two platforms, because the check that whole-drive work is refused off Linux does not apply on Linux. (2026-09-22 package smoke; since then `scripts/package_smoke.py` asserts resolver states and that each platform's backends ship, not a blanket refusal) |
| 13 | Capability states reflect real evidence | DONE | every row carries `source`; file-erase rows stay UNVERIFIED until `validation_record.json` records a passing suite for that platform |
| 14 | `validation_record.json` holds real platform results | DONE | suites plus per-feature rows (platform, OS, architecture, commit, tests, result, date, evidence, limitations) |
| 15 | No fake platform checkmarks | DONE | `tests/platform/test_assessment_and_matrix.py` pins that a Linux pass does not lift a Windows row. On 2026-09-22 it also pinned whole-drive as UNSUPPORTED off Linux; it now pins that Windows and macOS offer whole-drive through the resolver (`test_windows_and_macos_offer_whole_drive_through_the_resolver`), and `tests/platform/test_capability_matrix_doc.py` pins that no row claims physical validation without a recorded run |
| 16 | Security regression tests pass | DONE | `tests/platform/test_boundary_and_security.py`: missing, wrong, stale and cross-origin sessions; non-loopback Host; quit refusal |
| 17 | Packaged session-token protection verified | DONE | `package-smoke-*.json`: 401 without the cookie, 303 on the session link, 400 for a foreign Host |
| 18 | Dev-server exposure explicitly controlled | DONE | `python -m api.main` mints a token per start and prints the URL; `SANCTUM_DEV_INSECURE=1` is the only way off, and says so |
| 19 | Documentation matches the implementation | DONE | `docs/platform-support.md`, `docs/packaging.md`, `docs/validation/platform-matrix.md`, `docs/validation/hardware-platform-matrix.md` |
| 20 | Whole-drive Linux-only scope documented | DONE on 2026-09-22; **superseded** | Windows and macOS whole-drive clear are now IMPLEMENTED / UNVALIDATED (`core/erase/blockclear.py`); only Linux on `usb-flash` is SUPPORTED. See the generated matrix |
| 21 | Hardware limitations documented | DONE | `docs/validation/hardware-platform-matrix.md` separates VALIDATED, CI-VALIDATED, NOT YET VALIDATED and NOT IMPLEMENTED / PLATFORM-LIMITED, and quotes the resolver's state for each row |
| 22 | Build artifacts reproducible/documented | PARTIAL | every build records version, commit, platform, architecture, date, Python and Node (`packaging/build_info.py`), honours `SOURCE_DATE_EPOCH`, and publishes SHA-256 sums. Bit-for-bit reproducibility is **not** claimed: PyInstaller embeds timestamps and the wheels are not pinned by hash. |
| 23 | Full test suite passes | DONE | development host 1644 passed / 34 skipped / 0 failed on 2026-09-22; the same suite green on all three runners. At `bf4c59b` (2026-09-28): 3110 passed, 48 skipped, 0 failed on the Linux host |
| 24 | UI platform screen works | DONE | rows with a plain-English *Why?*, screenshotted from the real server; `ui/tests/platform.test.ts` |
| 25 | Demo runs offline | DONE | no network call at run time; `tests/api/test_offline_serving.py` and the CSP; the packaged app was driven with the runner's network unused |

## Open items, and why

| Item | Status | Reason |
|---|---|---|
| Windows whole-drive clear | IMPLEMENTED / UNVALIDATED | `core/erase/blockclear.py` over `\\.\PhysicalDriveN`, the handle bound to disk number, serial and length; the disk must be offline. Exercised through adapter doubles only; no physical run recorded. |
| Windows device sanitize (ATA SANITIZE, NVMe Sanitize) | DEVICE-DEPENDENT; never run on a drive | Offered only when IDENTIFY reports it. ATA SECURITY ERASE is NOT IMPLEMENTED on Windows; NVMe Format is PLATFORM-LIMITED. |
| macOS whole-drive clear (external disks) | IMPLEMENTED / UNVALIDATED | `/dev/rdiskN`; internal Apple storage is never raw-written, and *Erase All Content and Settings* is named instead, which this app can neither perform nor verify. macOS device sanitize is PLATFORM-LIMITED. |
| Windows and macOS raw acquisition | IMPLEMENTED / UNVALIDATED | Read-only open; no software write block exists on either OS, and the report says so. |
| Backup restore | IMPLEMENTED / UNVALIDATED on all three | Post-restore hash verification; never run on a physical device. |
| Firmware Purge on hardware | NOT DONE | Needs a drive that reports ATA SANITIZE or NVMe sanitize, and a person to lose the data on it. |
| Code signing and notarization | NOT DONE | No certificates. The remaining commands are in `docs/packaging.md`. |
| Physical-device validation on Windows and macOS | PARTIAL on Windows, NOT DONE on macOS | Windows: discovery on a USB stick and file erase on the host disk (2026-09-27). Nothing destructive at the device level and no raw acquisition has run on Windows hardware; no Mac has been used. `docs/validation/physical-validation-procedure.md` is how a row is closed. |

## The claim this supports

Sanctum is one cross-platform application with native capability adapters for
Linux, Windows and macOS. Device assessment and file and folder sanitization
are platform-aware and were executed on all three operating systems in CI.
Whole-drive clear is implemented on all three; it is physically validated only
on Linux, on one USB flash stick. Every other device-level capability off that
pathway is IMPLEMENTED / UNVALIDATED, DEVICE-DEPENDENT, PLATFORM-LIMITED or NOT
IMPLEMENTED, says which, and is refused with a reason rather than silently
downgraded.
