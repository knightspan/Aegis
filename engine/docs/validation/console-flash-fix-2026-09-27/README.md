# Windows console-flash fix — validated on the real platform-ci matrix, 2026-09-27

Incremental record. Preserves and extends
[`../platform-ci-2026-09-27/`](../platform-ci-2026-09-27/README.md) and
[`../windows-hardware-2026-09-27-fixes/`](../windows-hardware-2026-09-27-fixes/README.md);
nothing in either is rewritten.

## What this fixes

Reported directly by a user, with a screenshot: clicking any sidebar section
in the installed Windows app briefly opened a terminal window titled
`C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe` — exactly the
path `core.platform.windows.powershell_path()` computes.

**Root cause.** The packaged app is `console=False`
(`packaging/sanctum.spec`). It has no console of its own. Windows
`CreateProcess` then opens a brand-new one for any console-subsystem child —
`powershell.exe`, `git`, `vssadmin`, `fsutil`, `ffprobe` — because the child
needs a console and the parent has none to give it. That window is visible
for the child's whole lifetime even though `subprocess.run(capture_output=
True)` pipes its output; piping and window creation are unrelated Win32
concerns.

**Claim, stated precisely, per this repository's own convention of never
claiming more than was checked:** Windows packaged subprocesses that may
invoke PowerShell or other external tools use `CREATE_NO_WINDOW` to prevent
console-window flashes during normal GUI operation. This is not a generic
guarantee about every possible child process anywhere in the codebase — it
is the specific, enumerated result of the audit below, which found and fixed
every subprocess call site in `core/`, `api/` and `helper/` that can run on
Windows. `scripts/*.py` are excluded from that audit's scope: none are
bundled into the frozen app (never imported from the entry point), and each
one always runs from a console the calling shell already provided, so
`CREATE_NO_WINDOW` would be a no-op there even if added.

## 1. Audit

Searched the whole repository for `subprocess.run`, `subprocess.Popen`,
`subprocess.call`, `subprocess.check_call`, `subprocess.check_output`,
`os.spawn*`, `os.system`, `shell=True`, `ShellExecute`, `CreateProcess`,
`os.startfile`, and explicit `powershell.exe`/`cmd.exe`/`ffprobe`/
`vssadmin`/`fsutil` invocations.

| Call site | Windows-reachable from the packaged app? | Fixed |
|---|---|---|
| `core/device/_sysio.py:SubprocessRunner.run` (PowerShell device inventory — the one in the report) | yes, every device probe | yes |
| `core/erase/_platform/win.py:vss_shadows` (`vssadmin`) | yes, during a real file erase | yes |
| `core/erase/_platform/win.py:trim_likely` (`fsutil`) | yes, during a real file erase | yes |
| `core/carve/validate.py` (`ffprobe`) | yes, during carving of media candidates | yes |
| `core/platform/host.py:_git` | dev-checkout builds only (packaged `_internal` has no `.git`, so this returns early before ever calling `subprocess.run` in a real package) | yes, for consistency and dev-mode windowed launches |
| `core/erase/_platform/posix.py` (`btrfs`, `zfs`, `tmutil`) | **no** — `core/erase/_platform/__init__.py:backend()` selects `WindowsBackend` on `win32` and `PosixBackend` on `linux`/`darwin` only; `PosixBackend` never runs on Windows. POSIX also has no console-flash phenomenon at all — spawning a child process never creates a GUI window on Linux or macOS, with or without a parent console. `CREATE_NO_WINDOW` does not exist there and was correctly not added. | n/a |
| Everything under `scripts/` (`media_benchmark.py`, `package_smoke.py`, `hardware_validation.py`, `record_platform_validation.py`, `ci_install.py`, ...) | no — never bundled into the frozen app, always run from an existing console | n/a |
| `os.system`, `shell=True`, `os.spawn*`, `ShellExecute`, `CreateProcess`, `os.startfile` | zero matches anywhere in `core/`, `api/`, `helper/` | n/a |

Shared fix: `core.platform.host.windows_creationflags() -> int` — `0`
(a no-op) off Windows, `CREATE_NO_WINDOW` on it — passed as a plain
`creationflags=` keyword at every fixed call site. Not `**kwargs`: mypy
cannot resolve `subprocess.run`'s overloads against a splatted dict, and
`creationflags` is a keyword in every overload regardless of platform, so a
plain `int` sidesteps that instead of fighting it.

## 2. Regression tests

Direct coverage of every fixed call site, mocking `subprocess.run` (no real
command ever executes in a test):

- `tests/device/test_sysio.py` — the shared `SubprocessRunner`.
- `tests/platform/test_paths_and_host.py` — the shared helper directly, and
  `core.platform.host._git`.
- `tests/carve/score/test_validate.py` — the ffprobe validator.
- `tests/platform/test_windows_filesystem.py` (Windows-only, its existing
  `pytestmark`) — `vss_shadows` and `trim_likely` directly, against the real
  `WindowsBackend`.

Each verified red before its fix (temporarily reverted one call site's
`creationflags=windows_creationflags()` to `creationflags=0` and confirmed
the corresponding test failed; restored, confirmed green).

**A real cross-platform test bug, found by CI and fixed in the same
session:** `subprocess.CREATE_NO_WINDOW` only exists on the real
`subprocess` module on real Windows. Three tests monkeypatched
`sys.platform` to `"win32"` and asserted the result was non-zero — true only
on a host where the constant actually exists. On Linux/macOS CI,
`getattr(subprocess, "CREATE_NO_WINDOW", 0)` correctly fell back to `0`
(the production code was never wrong), failing the *test's* assertion for a
reason unrelated to the code under test. Fixed by injecting a fake
`CREATE_NO_WINDOW` for the duration of each such test
(`create=True`/`raising=False`). Verified locally by deleting the real
attribute from the `subprocess` module before running the suite — the
closest local reproduction of the Linux/macOS condition available without
that hardware — and confirming all four affected tests still pass.

## 3. Real packaged validation, platform-ci, run 36335032347

Two pushes to `fix/no-console-and-carve-packaging` (same branch as the prior
carving fix), not `main`:

| Attempt | Result | Cause |
|---|---|---|
| `7dcae71` push | gate/Linux/macOS platform jobs failed | the cross-platform test bug above (§2) |
| `716fad9` push, first run | gate, all `platform` jobs, `package` (Linux, macOS) green; `package` (Windows) failed on `platform matrix served: 0` (a connection-level failure, not an assertion failure) | investigated below |
| `716fad9`, **rerun of the failed job only** (`gh run rerun --failed`, same commit, no new push) | **all 7 jobs green** | confirmed transient |

The one failure was investigated before assuming it was transient, not
dismissed: `/devices` (same `WindowsAdapter.inventory()` mechanism, same
`creationflags` fix, requested moments later in the same script run) passed
in that same failed attempt, and re-running the identical commit's identical
job with no code change succeeded outright. That pattern — one cold request
failing at the connection level while an equivalent later request on the
same mechanism succeeds — matches a runner cold-start/AV-scan stall on the
freshly-extracted `_internal` DLLs, not a defect `creationflags` could
plausibly cause deterministically. Recorded here rather than quietly
re-run-and-forgotten.

**Final result, all green:**

| Job | Linux | Windows | macOS |
|---|---|---|---|
| `gate` (lint, 4 mypy strict passes, full suite) | PASS (2534 passed, 96 skipped) | — | — |
| `platform` | PASS | PASS | PASS |
| `package` build + drive (`package_smoke.py`) | PASS | PASS | PASS |
| Packaged carving (`package_carve_smoke.py`) | PASS, 11/11 | PASS, 11/11 | PASS, 11/11 |
| Genuine no-console launch (`package_no_console_smoke.py`) | n/a | **PASS, 9/9** — `sys.stdout` genuinely `None`, `launcher.log` written: the exact original bug condition, now fixed | PASS, 9/9 — streams real (inherited) for this launch method, as established in the prior carving-fix validation; app still correct either way |

## 4. UI/browser validation — not run; gap named honestly

No Playwright/browser test suite exists in this repository (`ui/tests/*.
test.ts` are Node-native logic unit tests, not browser tests — 123/123
pass, unrelated to this fix). `git grep` for `.spec.ts` or a Playwright
config returns nothing. The `browser-2026-09-24/` and similar evidence
directories elsewhere in `docs/validation/` were produced by a one-off
external harness, not a suite checked into this repository, so "run the
relevant packaged-browser/UI tests" could not be fulfilled beyond: UI unit
tests (123/123), and the HTTP-level equivalents of every screen this fix
touches — `/devices` (Devices screen), `/platform` (Platform screen),
`/jobs/erase-files` (Sanitize/File-eraser backing), `/jobs/carve`
(Recovery screen backing) — all exercised for real through the installed
package in §3.

## 5. Package identity

| Platform | Artifact | SHA-256 |
|---|---|---|
| Windows | `SanctumSetup.exe` | `4dc70e36a68edbdfbdd00cb2740a4ddb5c32472032850f17e1294ceb283cb4ea` |
| Linux | `Sanctum-0.0.0-x86_64.AppImage` | `0629708312cf6fee573e48ee463508910da6b75eeee6b0ab9d1b22e619b3ca22` |
| Linux | `sanctum_0.0.0_amd64.deb` | `6a60509e2137f5542ac30375e1a0045aa9e69cace739acdad42d29c1fcf2da98` |
| macOS | `Sanctum-0.0.0.dmg` | `8507d42191230911f28fc81c58a308bc0027deca48c7df46fa829ce0621fe5f4` |

`core/platform/build_info.json` in every package: `commit:
716fad99e072354625417634b6dc088d61500093`, confirmed independently via each
platform's own `/health` response during the no-console and carve-smoke
checks, matching exactly.

Local commits on this branch, in order, none amended: `1ed3dca` (carving
CI-harness fix) → `7dcae71` (this fix's tests, plus the two more call sites
it found: `vss_shadows`/`trim_likely`/ffprobe) → `716fad9` (the
cross-platform test-portability fix). The core windowed-launch fix itself
(`ac2e28f`, `core.device._sysio.SubprocessRunner` + the shared
`windows_creationflags()` helper) predates this evidence folder; see the
repository's commit log.

## What this does not close

- A genuine macOS Dock/Finder double-click (LaunchServices launch, not a
  direct shell exec) remains unverified — unchanged from
  [`../windows-hardware-2026-09-27-fixes/`](../windows-hardware-2026-09-27-fixes/README.md).
- No Playwright/browser regression pass exists in this repository to run.
- This branch (`fix/no-console-and-carve-packaging`) was not merged to
  `main`.
