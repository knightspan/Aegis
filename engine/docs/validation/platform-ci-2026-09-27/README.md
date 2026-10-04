# platform-ci matrix, post-fix — 2026-09-27

The final validation mechanism for `ba66fbe` (desktop no-console crash) and
`437081e` (carving signature table): real `platform-ci` runs on Linux,
Windows and macOS, not local hardware. Branch
`fix/no-console-and-carve-packaging`, never merged or pushed to `main`
by this work.

## Runs

| Attempt | Commit | Run | Result |
|---|---|---|---|
| 1 | `fd37946` | [36329292776](https://github.com/Invinciblx777/sanctum-forensics/actions/runs/36329292776) | gate + all 3 `platform` jobs PASS; all 3 `package` jobs **FAIL** |
| 2 | `1ed3dca` | [36330577225](https://github.com/Invinciblx777/sanctum-forensics/actions/runs/36330577225) | **all 7 jobs PASS** |

Both failures in attempt 1 were real bugs in the new test scripts
themselves, found by running them for the first time in a clean
environment — not regressions in `ba66fbe` or `437081e`, and not flaws in
the checks' intent. Fixed in `1ed3dca`; see that commit message for the
full diagnosis. Summary:

1. **All three platforms**, `package_carve_smoke.py` failed at import:
   `ModuleNotFoundError: No module named 'structlog'`. It imported
   `scripts/demo_fragmented.py` for `build()` (Pillow only), but that
   module's top-level `from api.carve_job import carve_generator` pulled in
   the whole app dependency stack — never installed in this job by design
   (`package_smoke.py` is pure stdlib for the same reason). Fixed by making
   that import local to `demo_fragmented.run()`, and installing just Pillow
   for this job's own fixture builder.
2. **macOS only**, `package_no_console_smoke.py` failed two assertions
   ("launcher.log exists", "has real content") while every other check —
   including the app logging its own startup lines straight into the step's
   captured output — passed. That was the tell: `sys.stdout` was not
   `None`. Direct exec of the `.app`'s Mach-O binary from a shell (what this
   script does, and what `package_smoke.py` already does) inherits real,
   open file descriptors via ordinary POSIX fork/exec, unlike Windows, where
   `close_fds` genuinely detaches a `console=False` child from any console
   regardless of invocation method. The script asserted a Windows-specific
   precondition as if it were universal — a bug in the test, not the
   product, and not evidence the desktop fix does nothing on macOS: it is
   still correct and still a no-op when nothing is `None`, which
   `tests/platform/test_boundary_and_security.py`'s mechanism-level test
   covers directly, independent of how a real `None` might arise on any
   given platform.

## Final result, run 36330577225, commit `1ed3dca1032ae55af0da36aa10c8cd275dc4bfb9`

| Job | Linux | Windows | macOS |
|---|---|---|---|
| `gate` (lint, 4 mypy strict passes, full suite) | — (runs once, Ubuntu) | — | — |
| `platform` (adapter + full suite on that OS) | PASS | PASS | PASS |
| `package` build + drive | PASS | PASS | PASS |
| Packaged carving (`package_carve_smoke.py`) | **PASS, 11/11** | **PASS, 11/11** | **PASS, 11/11** |
| Genuine no-console launch (`package_no_console_smoke.py`) | n/a (`console=False` ignored) | **PASS, 9/9** | **PASS, 8/8** |

`gate`'s full suite, the authoritative count (clean Ubuntu runner, full
`.[dev]` install — not this session's ad-hoc local venv):
**2527 passed, 94 skipped, 0 failed** in 244.40s. This resolves the mypy
uncertainty this session's local HOLD verdict named: all four `mypy
--strict` passes (base, both `--platform win32`, `--platform darwin`) are
part of `gate` and it is green — the errors seen locally were specific to
this session's ad-hoc venv (missing dev extras, `pywebview` present from a
different install path) and do not reproduce in CI's properly-provisioned
environment.

## Package identity, commit `1ed3dca1032ae55af0da36aa10c8cd275dc4bfb9`

Built fresh in CI from this exact commit (not `437081e` — this run's own
commit, which also carries the CI-harness fixes; no product code differs
from `437081e`).

| Artifact | SHA-256 |
|---|---|
| `SanctumSetup.exe` (Windows) | `959b57f1489b74e6f2b99f11129859d393f3d3eb44f6f98a3239640183749f92` |
| `Sanctum-0.0.0.dmg` (macOS) | `4a3d54462cf2254921ed0d2e97cd9614f03572e2f801e546a5a163bfa5254c61` |
| `Sanctum-0.0.0-x86_64.AppImage` (Linux) | `ce2a1038489b108de24eb1ea64b8cd5eacf99573c1fbcb25231da4f188a48913` |
| `sanctum_0.0.0_amd64.deb` (Linux) | `f83e0689c7c63a6766131ac25858b918ce89d94c5f6a463589879e6025f3ba1e` |

`core/platform/build_info.json` in every package: `commit:
1ed3dca1032ae55af0da36aa10c8cd275dc4bfb9`, `branch:
fix/no-console-and-carve-packaging`, `builder: GitHub Actions run
36330577225`. Confirmed independently three times over: once per platform's
`/health` response during the no-console and carve-smoke checks, matching
exactly.

## Raw evidence in this folder

[`carve-smoke-Linux.json`](carve-smoke-Linux.json),
[`carve-smoke-Windows.json`](carve-smoke-Windows.json),
[`carve-smoke-macOS.json`](carve-smoke-macOS.json) —
[`no-console-smoke-Windows.json`](no-console-smoke-Windows.json),
[`no-console-smoke-macOS.json`](no-console-smoke-macOS.json). Downloaded
directly from run 36330577225's `evidence-package-*` artifacts, unedited.
`package-smoke-*.json` and `validation-package-*.json` for this run are CI
artifacts, not duplicated here — this project's convention keeps that
evidence in CI artifact storage and links the run rather than re-hosting
every packaged-checks JSON in the repository; the counts and content are
quoted above from those same files.

## What this does and does not close

**Closed:** all four gaps this session's earlier local-only HOLD verdict
named — macOS packaged carving (now proven, 11/11), Windows mypy strict
status (proven clean in CI's real environment), Linux/macOS packaged
carving after the signature-table fix (proven, 11/11 both), and the
platform-ci matrix itself (run, green, both attempts recorded above).

**Not closed, and not claimed:**

- **A genuine macOS Dock/Finder double-click**, going through
  LaunchServices rather than a direct shell exec of the bundle's binary.
  §"Runs" above explains why that is a different condition from what this
  check (or `package_smoke.py`, which uses the same direct-exec launch)
  actually exercises on macOS, and why it did not need to reproduce `None`
  stdio to prove the fix does not break anything there. Whether a true
  LaunchServices launch produces `None` stdio on this PyInstaller build is
  unverified.
- **Windows raw physical-device acquisition** — still not implemented
  (unchanged; see
  [`../windows-hardware-2026-09-27-fixes/`](../windows-hardware-2026-09-27-fixes/README.md)).
- **Windows/macOS whole-drive sanitization** — still UNSUPPORTED by design
  (unchanged).
- **No physical hardware was used for any of this.** Every check above ran
  against CI runners' own virtual disks and a synthetic carving image; see
  [`hardware-platform-matrix.md`](../hardware-platform-matrix.md) for what
  physical validation exists and on which platform (Windows only, and only
  via the separate session recorded in
  [`../windows-hardware-2026-09-27-fixes/`](../windows-hardware-2026-09-27-fixes/README.md)).
- **This branch was not merged.** `origin/main` is unchanged by this work.
