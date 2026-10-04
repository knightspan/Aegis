# Cross-platform release report

> **Current state, 2026-09-28 (`bf4c59b`).** Sections 1 to 6, 8, 9 and 15 are
> the record of `platform-ci` run 35706589476 at `ba13a9a` and are kept as
> run. Sections 7, 10, 11, 13 and 14 have been brought up to date: since that
> run, Windows and macOS gained whole-drive clear and raw acquisition, Windows
> gained device sanitize (ATA SANITIZE, NVMe Sanitize), Linux and Windows
> gained a guarded HPA/DCO workflow, and all three gained authorized backup
> restore. **None of those has run on a physical device.** The authoritative
> per-platform matrix is generated from the code:
> [`capability-completion-2026-09-28/capability-matrix.md`](capability-completion-2026-09-28/capability-matrix.md);
> what changed is in
> [`capability-completion-2026-09-28/README.md`](capability-completion-2026-09-28/README.md).
> Suite at `bf4c59b` on the Linux host: 3110 passed, 48 skipped, 0 failed; UI
> 148 passed.

What was validated, where, and what is still unvalidated. Every number below
comes from a recorded run: a job in `platform-ci`, an evidence file in
`core/platform/validation_record.json`, or a suite on the development host.
Nothing here is inferred from a platform name.

The evidence run is `platform-ci` run 35706589476 on
`release/cross-platform-validation`, commit `ba13a9a` — gate, three platform
jobs and three package jobs, all green. Earlier runs are cited where they
found a defect.

## 1. Windows test results

Runner `windows-latest`: Windows 11, build 10.0.26100, AMD64, Python 3.11.9.

| What ran | Result |
|---|---|
| Full Python suite | PASS — 1224 passed, 361 skipped, 0 failed |
| `file_erase` suite (`tests/erase/files`, `tests/platform`) | PASS — 203 passed, 71 skipped, 0 failed |
| `api` suite (`tests/api`) | PASS — 201 passed, 9 skipped, 0 failed |
| Adapter against the runner's own disks (`scripts/platform_smoke.py`) | PASS — 2 disks found and normalized, both refused: `PhysicalDrive0` for `IsBoot`, `IsSystem` and the `C:` system volume; `PhysicalDrive1` for an active page file on `D:` |
| Capability rows | every row carried a source; whole-drive rows UNSUPPORTED (that build had no Windows block engine) |

The Windows-specific behaviour is pinned by `tests/platform/test_windows_filesystem.py`,
which creates a **real** junction on the runner with `_winapi.CreateJunction`
and proves a recursive erase cannot be redirected out of the named root, plus
alternate data streams, resident-MFT detection and the read-only attribute.

Windows CI found three product defects, all fixed in this branch:

1. **The extent map recorded one cluster per run.** `FSCTL_GET_RETRIEVAL_POINTERS`
   returns a run as a starting VCN and the *next* run's starting VCN;
   `core/erase/_platform/win.py` kept only the start, so verification read back
   one cluster of each run and declared the rest unchecked. Runs now carry
   `next_vcn`, and a truncated map records a limitation instead of a pass.
2. **A job reported `complete` before its outcome reached the ledger.** The UI
   could ask for a certificate for a job whose chain entry was still being
   written. `api/jobs.py` now exposes `settled`, and both the UI and the tests
   wait for it.
3. **`os.statvfs` was bound as a default argument** in
   `scripts/hardware_validation.py`, so importing the module on Windows failed
   and took 36 unrelated carving tests with it.

## 2. macOS test results

Runner `macos-14`: macOS 14.8.9, arm64, Python 3.11.9.

| What ran | Result |
|---|---|
| Full Python suite | PASS — 1231 passed, 354 skipped, 0 failed |
| `file_erase` suite | PASS — 171 passed, 103 skipped, 0 failed |
| `api` suite | PASS — 203 passed, 7 skipped, 0 failed |
| Adapter against the runner's own disks | PASS — `disk0` (325 GB, SSD) found through `diskutil list/apfs list/info -plist`, the synthesized APFS container traced to its physical store, and the disk refused because the running macOS boots from a container on it |
| APFS honesty | `tests/platform/test_macos_filesystem.py`: the erase runs, verification is `not_possible` **with a reason**, and a residual finding is recorded. A pass is never claimed on copy-on-write storage. |

The skip count is high on macOS by design: the privileged-helper socket
suites are Linux-only (the daemon refuses non-Linux peers), as are the
loop-device and `lsblk` harness tests.

macOS CI found two defects: `ru_maxrss` is bytes on Darwin and KiB on Linux,
so the memory ceiling assertions were scaled per platform; and an AF_UNIX
path is capped near 104 bytes on macOS, shorter than pytest's temporary
directory, which is what the `short_socket_dir` fixture exists for.

## 3. Linux regression results

The Linux implementation was not modified except where a cross-platform
defect reached it. It is green on three hosts:

| Where | Result |
|---|---|
| `gate` job (`ubuntu-latest`) | 1601 passed, 82 skipped, 0 failed |
| `platform (ubuntu-latest)` job | 1601 passed, 82 skipped, 0 failed |
| Development host (Fedora Linux 44, x86_64, unprivileged) | 1648 passed, 34 skipped, 0 failed |
| `recovery` suite (`tests/carve`), development host | PASS — 400 passed, 1 skipped, 0 failed |
| `whole_drive` suite (`tests/erase`, `tests/device`, `tests/helper`), development host | PASS — 393 passed, 10 skipped, 0 failed |
| Lint (`ruff check .`) | clean |
| Typecheck — four `mypy --strict` passes (Linux, win32 on the Windows backend, win32 on the platform package, darwin on the platform package) | clean |
| UI | `tsc -b && vite build` clean, `oxlint` clean, 32 unit tests pass |

Whole-drive Clear on real USB flash remains validated by the six recorded runs
in `docs/validation/hardware.md`. Those were not re-run in this work, and
nothing in this branch changes the overwrite engine.

## 4. Windows installer result

| | |
|---|---|
| Artifact | `dist\SanctumSetup.exe` |
| Size | 36,665,388 bytes |
| Built by | `scripts/build-windows.ps1` — PyInstaller onedir + Inno Setup 6, job `package (windows-latest)` |
| Commit | `ba13a9a73bf8` |
| Python / Node | 3.11.9 / v22.23.2 |
| Installer | Inno Setup 6, per-user, no elevation prompt |
| OS | Windows 11, build 10.0.26100, AMD64 |
| Installed to | `%LOCALAPPDATA%\Programs\Sanctum\Sanctum.exe` (14,953,929 bytes) |
| Driven | 24 of 24 packaged checks |
| Uninstalled | `unins000.exe /VERYSILENT`, and the directory confirmed gone |
| Code signing | **NOT PERFORMED.** `build_info.json` records `"signed": "no"`. This is an unsigned build; SmartScreen will warn. |

## 5. macOS DMG result

| | |
|---|---|
| Artifact | `dist/Sanctum.dmg` |
| Size | 44,567,434 bytes |
| Built by | `scripts/build-macos.sh` — PyInstaller BUNDLE + `hdiutil`, job `package (macos-14)` |
| Commit | `ba13a9a73bf8` |
| Python / Node | 3.11.9 / v22.23.2 |
| OS | macOS 14.8.9, arm64 |
| Driven | DMG mounted with `hdiutil attach`, `Sanctum.app` copied out, `Contents/MacOS/Sanctum` (13,048,432 bytes) driven through 24 of 24 checks |
| Signing | **UNSIGNED BUILD.** Ad-hoc signature only, from PyInstaller. **Not notarized.** Gatekeeper blocks a double-click on another Mac; the first open needs right-click > Open. |

## 6. Linux package result

| | |
|---|---|
| Artifacts | `dist/Sanctum-0.0.0-x86_64.AppImage` (57,014,776 bytes), `dist/sanctum_0.0.0_amd64.deb` (60,297,362 bytes), `SHA256SUMS-linux.txt` |
| Built by | `scripts/build-linux.sh` in CI (`ubuntu-22.04`); `scripts/build-linux-portable.sh` builds in a `python:3.11-bullseye` container for glibc 2.31 portability |
| Driven | AppImage run with `--appimage-extract-and-run`, 23 of 23 packaged checks |
| Installed as a user would | `.deb` installed and removed in a Debian 12 container; AppImage run in Debian 12 and Ubuntu 22.04 containers with no Python present |
| Signing | unsigned; a SHA-256 sum file is produced |

Linux runs one packaged check fewer than the other two platforms: in that
build, the check that whole-drive work is refused off Linux had nothing to
assert on the platform where it was supported. The package smoke now asserts
resolver states and that each platform's backends ship instead.

The 24 packaged checks drive the **installed** application over loopback:
401 without the session cookie, 303 on the session link, 400 for a foreign
`Host`, `/health` carrying the build metadata, device discovery, an
assessment, a folder erase confined to a scratch directory, a signed
certificate that verifies, and a quit that stops the process.

## 7. Updated platform matrix

The authoritative matrix is the generated
[`capability-matrix.md`](capability-completion-2026-09-28/capability-matrix.md);
[`platform-support.md`](../platform-support.md) explains it and
[`platform-matrix.md`](platform-matrix.md) is the CI test record. Current
state, in the resolver's labels (SUPPORTED means a recorded physical run on
the named device class):

| Capability | Linux | Windows | macOS |
|---|---|---|---|
| Device discovery | SUPPORTED (`usb-flash`) | SUPPORTED (`usb-flash`, 2026-09-27) | IMPLEMENTED / UNVALIDATED |
| File and folder erase | IMPLEMENTED / UNVALIDATED | SUPPORTED (host disk, class not recorded, 2026-09-27) | IMPLEMENTED / UNVALIDATED; **NOT VERIFIABLE on APFS** |
| Free-space wipe | IMPLEMENTED / UNVALIDATED (FAT32, exFAT, ext4) | NOT IMPLEMENTED | NOT IMPLEMENTED |
| Whole-drive clear (addressable overwrite) | SUPPORTED (`usb-flash` only) | IMPLEMENTED / UNVALIDATED | IMPLEMENTED / UNVALIDATED (external disks; internal Apple storage BLOCKED FOR SAFETY) |
| Device sanitize (ATA SANITIZE, NVMe Sanitize, crypto erase) | DEVICE-DEPENDENT | DEVICE-DEPENDENT (ATA SECURITY ERASE NOT IMPLEMENTED, NVMe Format PLATFORM-LIMITED) | PLATFORM-LIMITED |
| Raw physical-device acquisition | SUPPORTED (`usb-flash`) | IMPLEMENTED / UNVALIDATED (no software write block) | IMPLEMENTED / UNVALIDATED (no software write block) |
| HPA / DCO modification | DEVICE-DEPENDENT | DEVICE-DEPENDENT | PLATFORM-LIMITED |
| Backup restore | IMPLEMENTED / UNVALIDATED | IMPLEMENTED / UNVALIDATED | IMPLEMENTED / UNVALIDATED |
| Signed certificate, hash-chained ledger | CI and physical (Linux stick, earlier build) | CI; physical certificate on 2026-09-27 | CI |
| Desktop package | CI and physical host | CI, unsigned; installed on a physical machine 2026-09-27 | CI, unsigned and not notarized |

Nothing destructive at the device level, and no raw acquisition, has been
performed on physical media on Windows or macOS. The run recorded in this
report (sections 1 to 6) predates every Windows and macOS row that now reads
IMPLEMENTED / UNVALIDATED or DEVICE-DEPENDENT.

## 8. Real validation records

`core/platform/validation_record.json` is written only by
`scripts/record_platform_validation.py`, from a real pytest run on the
platform it names. It holds two shapes:

* `suites` — what the capability model gates on. A suite that is not recorded
  as PASS for a platform leaves every capability it backs at UNVERIFIED
  there. This is the mechanism that makes a green cell impossible without a
  recorded run.
* `features` — 18 rows, one per platform feature, each carrying platform, OS
  name, OS build, architecture, app version, commit, the tests behind it, the
  result, the date, the evidence file and the limitations that still apply.
  There is no blanket "Windows verified" row anywhere in the file.

Recorded results:

| Platform | device discovery | file/folder erase | API and reporting | recovery | whole drive | packaged app |
|---|---|---|---|---|---|---|
| linux | PASS | PASS | PASS | PASS | PASS | PASS |
| windows | PASS | PASS | PASS | NOT RUN | UNSUPPORTED | PASS |
| macos | PASS | PASS | PASS | NOT RUN | UNSUPPORTED | PASS |

NOT RUN is not PASS, and UNSUPPORTED is a refusal, not a gap. (This table is
the record at `ba13a9a`. Since then the file also holds `physical_validations`,
matched on platform, capability and device class, and CI records the Windows
and macOS clear from the backends suite; see the generated matrix for the
current state.)

Every CI row names commit `ba13a9a73bf8`, the commit run 35706589476
tested; the two developer-host suites name the commit they ran at. No row
is marked `+dirty`. The commit that *carries* the file is necessarily a
later one: a record can only be written after the run it records.

Four recording defects were found and fixed while producing this record, and
they are worth naming because each one would have put a false statement in
the evidence file:

1. Every row was stamped `+dirty` against a pristine commit, because the
   dirtiness check counted the untracked evidence files the CI job had just
   written. It now looks at tracked files only.
2. The package job recorded a real Windows 11 run as "Windows 10", because it
   fell back to `platform.release()`, which answers "10" on Windows 11. It
   now uses the same host probe the adapter uses, and the dependency-free
   fallback reads the build number itself.
3. The same fallback named macOS by its kernel ("Darwin 23.6.0") and Linux by
   its kernel release. It now reports `macOS 14.8.9` and the distribution's
   `PRETTY_NAME`.
4. `main()` built the feature rows and never wrote them, so the per-feature
   section was empty in an earlier run.

## 9. Security changes

Ten findings, in [`security-review-cross-platform.md`](../security-review-cross-platform.md).
The ones that changed behaviour:

| Finding | Severity | Fix |
|---|---|---|
| Folder erase descended through Windows directory junctions (`is_dir(follow_symlinks=False)` is true for a junction, `is_symlink()` is false) | Critical, Windows | `core/erase/files.py` checks `FILE_ATTRIBUTE_REPARSE_POINT` from `lstat`; a reparse point is emitted as itself and refused |
| DNS rebinding against the loopback API | High | `api/security.py` refuses any request whose `Host` is not `127.0.0.1`, `localhost` or `[::1]`, with 400, before routing |
| Any local account could drive the API | High on multi-user hosts | per-launch 32-byte session token, `HttpOnly` + `SameSite=Strict` cookie set by one `/session/<token>` request, `hmac.compare_digest`, 401 otherwise |
| The development server had no such protection | High | `python -m api.main` now mints a token per start, binds 127.0.0.1 only, and prints the session URL. `SANCTUM_DEV_INSECURE=1` is the only way off and says so in the banner. A source guard test refuses any wildcard bind. |
| State directory defaulted to the current directory | Medium | per-user data directory per OS |
| Windows protected paths were case-sensitive and assumed `C:` | Medium, Windows | `core/platform/paths.py` reads `%SystemRoot%` and the Program Files variables, compares case-insensitively, and covers whole subtrees |
| Inside a container, the host's disks were assessed READY | High, containers | whole-drive work is NOT AVAILABLE in a container unless `SANCTUM_ALLOW_CONTAINER_DEVICES=1`, and an erase is refused in the privileged process before the device is opened |
| The packaged app could not sign a certificate | Medium | the passphrase is typed in the UI for that one request; never logged, stored or echoed |

Packaged security regression tests run against the **installed** application
on all three platforms: missing token, wrong token, stale token, cross-origin
session, foreign `Host`, and token reuse after relaunch.

One further defect was found by the Windows runner during this work and fixed
here: the ledger's append retry used a fixed doubling backoff, so writers that
collided woke together and one could be starved out of the lock entirely and
lose its entry with `LedgerBusy`. The wait is now jittered.

Build metadata (`packaging/build_info.py`) records version, commit, branch,
platform, architecture, build date, Python, Node, builder and `signed`. It
honours `SOURCE_DATE_EPOCH` and contains **no secrets**. Bit-for-bit
reproducibility is not claimed: PyInstaller embeds timestamps and the wheels
are not pinned by hash.

## 10. Remaining hardware-only validation

Full list in [`hardware-platform-matrix.md`](hardware-platform-matrix.md);
the procedure is [`physical-validation-procedure.md`](physical-validation-procedure.md).
None of this can be closed in CI, because a hosted runner has virtual disks
and no removable media. Windows discovery (USB stick), Windows file erase
(host disk) and the Windows package install by a human were closed on
2026-09-27.

| What | Needs |
|---|---|
| Windows whole-drive clear and raw acquisition | a Windows machine run as Administrator and a disposable USB stick taken offline |
| macOS discovery, file erase, whole-drive clear and raw acquisition | a Mac and a disposable external disk |
| macOS package installed by a human | the same Mac |
| Device sanitize (ATA SANITIZE, SECURITY ERASE, NVMe Sanitize/Format, Opal) | a Linux or Windows host and a drive that reports the capability, plus permission to lose its data |
| HPA modification through the guarded workflow | a drive with a hidden area set |
| Backup restore | a disposable device and an independent hashing tool |
| SSD residual behaviour after an overwrite | physical media and out-of-band reading |
| Whole-drive clear on internal SATA/NVMe | a spare internal drive; the development host's are refused because they hold the running system |

Each run validates only its own `(platform, capability, device class)`.

## 11. Remaining unavailable functionality

The app states the reason and performs nothing.

| Not available | Where | State | Why |
|---|---|---|---|
| ATA SECURITY ERASE UNIT | Windows | NOT IMPLEMENTED | The sequence sets a drive password first; a refused or interrupted erase leaves the drive locked, and no recovery path has been built and tested on Windows. ATA SANITIZE is offered instead where supported. |
| NVMe Format NVM | Windows | PLATFORM-LIMITED | The in-box NVMe driver does not pass Format NVM through `IOCTL_STORAGE_PROTOCOL_COMMAND`. NVMe Sanitize is used instead where supported. |
| Device sanitize, crypto erase, HPA/DCO | macOS | PLATFORM-LIMITED | No public ATA pass-through or NVMe admin-command interface. Internal storage is purged by *Erase All Content and Settings*, which this app names and can neither perform nor verify. |
| Raw write or image of internal Apple storage | macOS | BLOCKED FOR SAFETY | Secure Enclave-encrypted; a raw image is ciphertext, and a raw write is never the purge path. |
| Free-space wipe | Windows, macOS | NOT IMPLEMENTED | NTFS and APFS fill behaviour has not been measured |
| DCO modification | all | not issued | DCO RESTORE can make a drive report a different model's geometry |
| Software write block | Windows, macOS | not available on the OS | raw acquisition opens read-only and the report names a hardware write blocker as the control |
| File-erase verification | macOS (APFS) | NOT VERIFIABLE | copy-on-write: the overwrite cannot be proved to have reached the old blocks. Reported as *not verifiable*, with the reason, never as a pass. |
| Code signing, notarization | all | not performed | no certificates |

## 12. Commands to reproduce each build

```bash
# Linux, distributable (needs podman, or CONTAINER=docker)
cd ui && npm ci && npm run build && cd ..
bash scripts/build-linux-portable.sh
ls dist/   # Sanctum-0.0.0-x86_64.AppImage  sanctum_0.0.0_amd64.deb  SHA256SUMS-linux.txt

# Linux, on the host directly (needs the host's glibc on the target)
bash scripts/build-linux.sh
```

```powershell
# Windows: Python 3.11, Node 20+, Inno Setup 6
pwsh scripts\build-windows.ps1
# dist\SanctumSetup.exe
```

```bash
# macOS: Python 3.11, Node 20+, Xcode command line tools
bash scripts/build-macos.sh
# dist/Sanctum.dmg
```

All three are built in CI by `.github/workflows/platform-ci.yml` (job
`package`) and `.github/workflows/release.yml`.

## 13. Commands to run each packaged application

```bash
# Linux
./Sanctum-0.0.0-x86_64.AppImage                       # or --appimage-extract-and-run without FUSE
sudo apt install ./sanctum_0.0.0_amd64.deb && sanctum

# Linux whole-drive work, with the privileged helper (the UI never runs as root)
sudo mkdir -p /var/lib/sanctum
sudo ./Sanctum-0.0.0-x86_64.AppImage --appimage-extract-and-run helper \
     --operator-uid "$(id -u)" --state-dir /var/lib/sanctum
SANCTUM_HELPER_SOCKET=/run/sanctum/helper.sock SANCTUM_STATE_DIR=/var/lib/sanctum \
     ./Sanctum-0.0.0-x86_64.AppImage
```

```powershell
# Windows
.\SanctumSetup.exe        # per-user, no elevation prompt; then Sanctum in the Start menu
# Whole-drive, device sanitize, raw acquisition, HPA/DCO and restore need an
# elevated process: right-click Sanctum > Run as administrator. The Windows
# build has no separate helper. Take the target disk offline first
# (Devices > Prepare, or Disk Management > Offline).
```

```bash
# macOS
open Sanctum.dmg          # drag Sanctum to Applications, then right-click > Open the first time
# Raw-device work on an external disk needs root: the adapter's advice is to
# start the Sanctum helper with sudo, then rescan. Unmount the disk first
# (Devices > Prepare, or diskutil unmountDisk).
```

From a source checkout, on any of the three: `python -m api.desktop`, or
`make run` and open the `/session/<token>` URL it prints.

## 14. Recommendation on committing

**Commit and merge the branch.**

The branch is 24 commits on `release/cross-platform-validation`, each one
green in CI by itself or superseded by a later fix in the same series. The
final commit set is green on all seven jobs: gate, three platform jobs on
Linux, Windows and macOS, and three package jobs. No pre-existing work was
discarded; the uncommitted work that was in the tree at the start of this
effort was committed first, on its own, as `a0964be`.

The claim this evidence supported at `ba13a9a`, kept as made:

> Sanctum provides a unified cross-platform desktop experience with native
> Linux, Windows and macOS capability adapters. File and folder sanitization
> and device assessment are platform-aware and were executed on all three
> operating systems in CI; whole-drive sanitization remains explicitly limited
> to validated Linux pathways, with unsupported and unverified operations
> refused rather than silently downgraded.

What must **not** be claimed: that Windows or macOS whole-drive sanitization
works, that any package is signed or notarized, that a physical device has
been sanitized on Windows or macOS, or that the project is "cross-platform
complete".

The claim the evidence supports on 2026-09-28, at `bf4c59b`:

> Whole-drive clear, raw acquisition and backup restore are implemented on
> Linux, Windows and macOS, and device sanitize on Linux and Windows where the
> drive reports it. Only Linux whole-drive clear and raw acquisition, on one
> USB flash stick, are physically validated; everything else at the device
> level is implemented and tested against fixtures and adapter doubles, not
> physically validated, and says so on every screen and report.

What must still **not** be claimed: that a Windows or macOS whole-drive clear,
raw acquisition, device sanitize or restore has been run on a physical device,
that any firmware Purge has run on any drive, or that any package is signed or
notarized.

## 15. Files changed

162 files changed, 23890 insertions(+), 632 deletions(-) against `main`. By area:

| Area | Files |
|---|---|
| Platform adapters (new package) | `core/platform/`: `model.py`, `host.py`, `base.py`, `linux.py`, `windows.py`, `macos.py`, `paths.py`, `filesystems.py`, `validation.py`, `validation_record.json` |
| Erase engine | `core/erase/_platform/win.py` (extent runs), `core/erase/files.py` (reparse points, protected paths, `O_BINARY`), `core/erase/freespace.py` |
| Ledger | `core/ledger/chain.py` (jittered append backoff) |
| API | `api/main.py` (session token, banner, `/health` build), `api/security.py` (new), `api/desktop.py` (new launcher), `api/jobs.py` (`settled`), `api/routes/platform.py` (new) |
| Helper | `helper/daemon.py`, `helper/__main__.py` (refuses to start off Linux, delegates the confirmation rule) |
| Packaging | `packaging/` (`sanctum.spec`, `build_info.py`, `sanctum_entry.py`, `windows/sanctum.iss`, `linux/make_deb.py`, `make_icons.py`), `scripts/build-*.sh`, `scripts/build-windows.ps1` |
| Evidence tooling | `scripts/platform_smoke.py`, `scripts/package_smoke.py`, `scripts/record_platform_validation.py`, `scripts/ci_install.py` |
| CI | `.github/workflows/platform-ci.yml`, `.github/workflows/release.yml` |
| UI | `ui/src/screens/Platform.tsx` (new), `ui/src/components/sanitizeFlow.tsx` (new), `ui/src/lib/platform.ts` (new), `ui/src/screens/Sanitize.tsx`, `ui/src/screens/Devices.tsx`, `ui/src/screens/Cases.tsx` |
| Tests | `tests/platform/` (7 modules, new), `tests/api/test_platform_in_report.py`, `tests/scripts/test_record_os_name.py`, `tests/_loopback.py`, plus platform gates in the helper, erase, ledger and carve suites |
| Documentation | `docs/platform-support.md`, `docs/packaging.md`, `docs/security-review-cross-platform.md`, `docs/release-readiness.md`, `docs/limitations.md`, `docs/demo/cross-platform-demo.md`, `docs/validation/platform-matrix.md`, `docs/validation/hardware-platform-matrix.md`, this report, `README.md`, `docs/user-manual.md` |

`git diff --name-status main..HEAD` lists every one.
