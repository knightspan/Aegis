# Cross-platform test matrix

> **Current capability state:** the generated
> [`capability-completion-2026-09-28/capability-matrix.md`](capability-completion-2026-09-28/capability-matrix.md)
> (see [`capability-completion-2026-09-28/README.md`](capability-completion-2026-09-28/README.md)).
> This page is the dated record of what CI ran on 2026-09-22, plus the
> physical Windows run of 2026-09-27. It predates the Windows and macOS block
> engines: where it says whole-drive is UNSUPPORTED off Linux, that was the
> build of that date. Windows and macOS whole-drive clear, raw acquisition and
> restore are now IMPLEMENTED / UNVALIDATED; none has run on a physical device.
> Since `d63a7c4` CI also proves each platform's backends ship in its package
> and runs a read-only native smoke on real Windows and macOS runners (one read
> handle, identity IOCTLs, one sector). That is not physical validation.

What was run, where, and what was not. **NOT RUN is not PASS.** A row marked
NOT RUN has code and, usually, fixture tests on another host; it has not been
executed on the platform named.

Recorded 2026-09-22 from `platform-ci` on the
`release/cross-platform-validation` branch, three runners:

| Runner | OS | Architecture | Python |
|---|---|---|---|
| `ubuntu-latest` | Ubuntu 24.04.5 (kernel 6.17) | x86_64 | 3.11 |
| `windows-latest` | Windows 11, build 10.0.26100 | AMD64 | 3.11.9 |
| `macos-14` | macOS 14.8.9 | arm64 | 3.11.9 |

plus the development host (Fedora Linux 44, x86_64, unprivileged user).

**No physical device was written by any of it.** CI runners have virtual
disks and no removable media; the stick attached to the development host was
mounted and refused by every path.

## Automated (CI and real runners)

| Area | Linux | Windows | macOS | Where |
|---|---|---|---|---|
| Lint, four strict typecheck passes, UI build and unit tests | PASS | — | — | `gate` |
| Full Python suite | PASS (1644 passed, 34 skipped on the host; PASS on the runner) | PASS on the runner | PASS on the runner | `platform` job |
| Platform adapter against the runner's own disks | PASS | PASS - 2 disks, both protected: `IsBoot`, and a page file on `D:` | PASS - internal disk protected: the running macOS boots from an APFS container on it | `scripts/platform_smoke.py`, `platform-smoke-*.json` |
| Capability rows all carry a source; whole-drive UNSUPPORTED off Linux (2026-09-22 build; now asserted as resolver states) | PASS | PASS | PASS | same |
| File, folder, batch erase; metadata; cancellation | PASS | PASS (`file_erase` suite: 201 passed, 71 skipped) | PASS (`file_erase` suite: 169 passed, 103 skipped) | `validation-*.json` |
| NTFS specifics: real junction, alternate data streams, resident MFT data | n/a | PASS | n/a | `tests/platform/test_windows_filesystem.py` |
| APFS: erase runs, verification refused with a reason, residual recorded | n/a | n/a | PASS | `tests/platform/test_macos_filesystem.py` |
| Protected system locations, path traversal | PASS | PASS | PASS | per-platform lists |
| Session token, DNS-rebinding host check, stale and cross-origin sessions | PASS | PASS | PASS | `tests/platform/test_boundary_and_security.py` |
| Platform recorded in the signed report; typed signing passphrase | PASS | PASS | PASS | `tests/api/test_platform_in_report.py` |
| API suite | PASS | PASS (201 passed, 9 skipped) | PASS (203 passed, 7 skipped) | `validation-*.json` |
| Recovery suite | PASS (400 passed) | not run as a suite | not run as a suite | `validation-linux` |
| UI units | PASS (32) | — | — | `ui/tests` |

## Packages

| Check | Linux | Windows | macOS |
|---|---|---|---|
| Package built | PASS - AppImage + `.deb`, locally and on `ubuntu-22.04` | PASS - `SanctumSetup.exe` on `windows-latest` | PASS - `Sanctum.dmg` (44,013,635 bytes) on `macos-14` |
| Installed the way a user would | PASS - `.deb` installed and removed on Debian 12 | PASS - silent install to `%LOCALAPPDATA%\Programs\Sanctum`, then uninstalled | PASS - DMG mounted, `Sanctum.app` copied and run |
| Runs with no developer environment | PASS - Debian 12 and Ubuntu 22.04 containers with no Python | PASS - runner Python not on the app's path | PASS |
| Session refusal, non-loopback Host refusal | PASS | PASS | PASS |
| Discovery and assessment through the package | PASS | PASS | PASS |
| Folder erase confined to its scratch directory | PASS | PASS | PASS |
| Signed certificate issued and verified | PASS | PASS | PASS |
| Quit stops the process | PASS | PASS | PASS |
| Packaged checks | 23 of 23 | 24 of 24 | 24 of 24 |

Linux runs one check fewer: *whole-drive unsupported off Linux* was a Windows and macOS check in the 2026-09-22 package smoke. `scripts/package_smoke.py` has since been changed to assert the resolver's states and that each platform's backends are present in the installed package.

The Windows column above is from the run that followed the one where the
packaged smoke test itself failed on the quit: Windows resets the connection
(`WinError 10054`) instead of closing it, and the script treated a missing
reply as an error. The installer, the install, the run and the uninstall all
worked in that earlier run too.

## Hardware

Updated 2026-09-27: three Windows rows below are now physically validated,
from a separate run, after this file's original recorded work — first at
`2d00526` (preserved at
[`windows-hardware-2026-09-27/`](windows-hardware-2026-09-27/README.md)),
then, after two packaging fixes that run itself found (`ba66fbe`,
`437081e`), at `437081e`. See [`hardware-platform-matrix.md`](hardware-platform-matrix.md)
and [`windows-hardware-2026-09-27-fixes/`](windows-hardware-2026-09-27-fixes/README.md)
for the full breakdown.

The implementation state in brackets is the resolver's label today; the
physical column is what has run.

| Check | Linux | Windows | macOS |
|---|---|---|---|
| Whole-drive Clear on real media | VALIDATED on `usb-flash` (`hardware.md`, 2026-09-05); not re-run | NOT RUN (IMPLEMENTED / UNVALIDATED) | NOT RUN (IMPLEMENTED / UNVALIDATED, external disks only) |
| Firmware Purge on real media | NOT RUN (DEVICE-DEPENDENT) | NOT RUN (ATA SANITIZE, NVMe Sanitize DEVICE-DEPENDENT; ATA SECURITY ERASE NOT IMPLEMENTED; NVMe Format PLATFORM-LIMITED) | PLATFORM-LIMITED |
| Discovery against a physical disk set | VALIDATED on `usb-flash` | **VALIDATED** on `usb-flash` (2026-09-27) | NOT RUN (IMPLEMENTED / UNVALIDATED) |
| File erase on physical NTFS / APFS media | n/a | **VALIDATED** (2026-09-27, host system disk, device class not recorded) | NOT RUN (IMPLEMENTED / UNVALIDATED) |
| Install by a human on a physical machine | VALIDATED | **VALIDATED** (2026-09-27) | NOT RUN |
| Raw physical-device acquisition | VALIDATED on `usb-flash` (`hardware.md`, 2026-09-05) | NOT RUN (IMPLEMENTED / UNVALIDATED; the 2026-09-27 build had no such code) | NOT RUN (IMPLEMENTED / UNVALIDATED) |
| Backup restore | NOT RUN (IMPLEMENTED / UNVALIDATED) | NOT RUN (IMPLEMENTED / UNVALIDATED) | NOT RUN (IMPLEMENTED / UNVALIDATED) |
| M3 carve, through the installed package, synthetic image | n/a (not this file's scope) | **VALIDATED** (2026-09-27, `437081e`) — 5/6 candidates, media map present | NOT RUN |

## To close the remaining rows

Every run follows [`physical-validation-procedure.md`](physical-validation-procedure.md),
is recorded with `scripts/record_physical_validation.py`, and lifts only its
own `(platform, capability, device class)`.

1. A Mac and a **disposable** external disk: install the package, confirm the
   disk appears and the internal disk reads NOT AVAILABLE with its reason,
   erase a scratch folder, clear and acquire the external disk.
2. Windows, run as Administrator, with a **disposable** USB stick taken
   offline: whole-drive clear and raw acquisition.
3. A spare drive that reports ATA SANITIZE or NVMe Sanitize, on Linux and on
   Windows, for the device-sanitize path.
4. A drive with an HPA set, for the hidden-area workflow.
5. A restore of a verified backup onto a disposable device.
