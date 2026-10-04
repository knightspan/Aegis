# Release record, 2026-09-25

> **Current state (2026-09-28).** Current product execution no longer exposes
> a user-facing simulation/dry-run mode: every operation runs against the
> selected real device once its gates pass, and a request that asks for a
> rehearsal is refused. References below to a dry run or a simulation record
> what the build of that date did; they are historical evidence and are kept as
> run.

Population: SYNTHETIC VALIDATION, SIMULATION and PACKAGE IDENTITY. **PHYSICAL
VALIDATION: none.** No sudo was used. Nothing was pushed.

## Release-hold remediation, 2026-09-26

The final freeze audit at `ea8c9f3` returned HOLD. This section supersedes every
package, test and browser figure further down. Population: SYNTHETIC, SIMULATION and
PACKAGE IDENTITY; **PHYSICAL VALIDATION: none**. No sudo, no physical device
enumerated, opened or written, no erase, acquisition or restore, no push. SANCTUMREC
was not accessed.

| Commit | Content |
|---|---|
| `e9253a3` | Platform: an executable per-device Purge option is UNVERIFIED without a hardware PASS in the validation record, and still offered under that word; the Devices badge reads PURGE · UNVERIFIED (or SED · OPAL · UNVERIFIED), never a green PURGE AVAILABLE. The engine's plan and the server's gates are unchanged |
| `c71c6b7` | UI: a write-seam refusal (`WorkflowGateRefused`, read from the structured `error_kind`) is BLOCKED in Cases and on the Overview, never a failed or partial erase; the case record keeps the job's `error_kind` and read-back verdict; a case that cannot be read is REQUEST FAILED; the Sanitize tracker passes Verify only on `passed === true`, and a failed read-back stops on Verify with a signed record, not a certificate; a file erase that failed partway reads *failed partway*, not "not attempted" (`FileEraseRecord.attempted`) |
| `338f955` | UI: the overview's physical-run lines are dated to their builds, and the *not physically validated* list opens with *This release: no physical validation*; a stale source comment on the backup gate corrected |
| `644a2e3` | UI: `streamJob` re-reads a finished job until its outcome is settled. Found by the remediation browser run (below) |
| `76dde42` | UI: the Cases note names BLOCKED and VERIFY FAILED. **Packages built here** |
| this record's commit | documentation and evidence only |

**Refusal flow, traced.** The helper raises `WorkflowGateRefused` at the write seam;
the job registry records `state: failed` with `error_kind: WorkflowGateRefused`
(`api/jobs.py`); `GET /cases/{id}` now copies that kind, and the drive erase's
read-back verdict, onto the case operation (`api/routes/cases.py`,
`core/cases.py:update_operation`); `ui/src/lib/refusal.ts` is the one place Sanitize,
Cases and the Overview ask whether a kind is a safety refusal. Before this, Cases
showed FAILED and the Overview said "failed or cancelled; the target is partially
sanitized" for a refusal that wrote nothing.

| Check | Result |
|---|---|
| Full pytest at `76dde42` | **2046 passed, 34 skipped, 0 failed** of 2080 collected; host-device guard 0 refusals; pytest's temporary directory on ext4 (`/var/tmp`). The five more than `d95603d` are this remediation's new tests. Counted from the run's progress record: with the project's `addopts = "-q"` and a second `-q`, pytest prints no summary line; exit 0 |
| Helper and authorization (`tests/helper`, `test_authorization_binding.py`, `api/test_gate_hardening.py`, `api/test_write_seam_integration.py`) | **92 passed** |
| Workflow and resume (`test_workflow.py`, `api/test_workflow_gate.py`, `api/test_workflow_failure_modes.py`, `api/test_resume.py`, `api/test_sanitize_ui_chain.py`) | **74 passed** |
| Erase (`tests/erase`) | **354 passed, 13 skipped**, 24 min 38 s on ext4: the synced 512-byte writes of the short-write tests are slow on a journalled filesystem |
| Ruff | `ruff check .` clean |
| mypy `--strict` (Linux, two win32, darwin) | clean, all four |
| UI unit tests; `tsc -b`; build | **123 of 123**; clean; built |
| Browser, remediation (refusal, REQUEST FAILED, Purge Unverified, read-back) | **39 of 39** at `76dde42` (`remediation-2026-09-25/`) |
| Browser, Sanitize, sandboxed | **59 of 59** at `76dde42`, no assertion changed |
| Browser, trace sweep / media map / Record of Destruction | **19 of 19** at `76dde42`, no assertion changed |
| Browser, Cases / Platform / Audit / Recovery, 1366 and 1024 wide | **66 of 66** at `76dde42`, no assertion changed |
| Packages at `76dde42`: identity | **PASS** both: `build_info.json` names `76dde42…` with no `+dirty`; 92 of 92 modules bytecode-identical; UI 8 of 8, and that bundle is byte-identical to the one the four browser runs were served; same executable, identical payload trees; `.deb` 202 files `root:root`, no maintainer scripts, `Depends: libc6 (>= 2.30), zlib1g` |
| Packages at `76dde42`: contents | the bundle carries the remediation's words (BLOCKED by a safety refusal, REQUEST FAILED, VERIFY FAILED, read-back verification FAILED, PURGE · UNVERIFIED, failed partway, This release: no physical validation) and still the Record of Destruction, media map and trace sweep; the archive holds `reportlab.graphics.barcode.code128` and `.qr`, `helper.authorization`, `api.authorization`, `core.erase.traces`, `core.carve.mediamap`, `core.destroy`; the packaged validation record's `hardware` section is empty |
| Packages at `76dde42`: isolated smoke | **22 PASS, 2 NOT RUN** each. The two NOT RUN (*every device assessed*, *protected devices are NOT AVAILABLE*) need a real device and were not run. A certificate is issued and verifies, so the reportlab QR fix holds |

| Artifact at `76dde42` | SHA-256 |
|---|---|
| `Sanctum-0.0.0-x86_64.AppImage` | `3997f9c5d62133293a8377f5a864cb595e57d364c554b54f5be22dcfc266f983` |
| `sanctum_0.0.0_amd64.deb` | `1642bfa308a6948098c487dbc8bdcb541e19c08cc9820605e4672135b38fcbd2` |

`dist/` now holds this build. Two intermediate builds were superseded before being
recorded: one at `338f955` (identity PASS, smoke 22 PASS and 2 NOT RUN, then
replaced when the browser run found the settle race) and one at `644a2e3` (built,
never checked, replaced for the Cases note). One build at an earlier `2aceef1` was
stopped part-way when a stale source comment was found; that commit was amended
into `338f955` before anything was pushed.

**Found by the remediation browser run.** A job's terminal stream event can leave
before its outcome reaches the chain (`settled: false`). The Sanitize screen waits
for `settled`, and nothing read the job again, so with the full test suite running
beside the browser the screen stayed on PLAN READY after a write-seam refusal. It
was a race, not a wrong answer: nothing false was shown, but nothing true either.
`644a2e3` fixes it; `ui/tests/streamJob.test.ts` pins it.

**The tmpfs record.** The row in *Final polish* below said the tmpfs run's quota was
"filled by other sessions' scratch files". That was not established, and is
corrected there. What is established: the spill test passes with pytest's
temporary directory on ext4; `/tmp` here is a 7.5 GB tmpfs mounted with `usrquota`;
the same user's other scratch data shares that quota (on 2026-09-26, 3.8 GB of
session scratch directories under `/tmp/claude-1000`); the test writes 2000 MiB, so
the failure is an environment and resource limit. How full the quota was at the
moment of the 2026-09-25 failure was not recorded. **Whether that run modified or
deleted any other session's files cannot be established**: no inventory of `/tmp`
was taken before or after it. The suite writes inside pytest's temporary directory,
and pytest's own retention keeps the three newest `pytest-N` directories under
`/tmp/pytest-of-<user>` and removes older ones, whichever session made them, so a
run there can delete an older run's temporary directory by design. This
remediation's first focused run used that default location and hit the same quota
error in the same test; every later run, including the full suite above, used an
ext4 `--basetemp` under `/var/tmp`. The test was not changed.

Not established, unchanged: anything on physical hardware (firmware Purge, HPA/DCO
unlock, backup restoration, a live-desktop trace sweep); that a backup image is a copy
of the device; race freedom between the helper's check and the first write; who
approved (the API does not authenticate a human). A simulation opens the device
`O_RDONLY` for its size and metadata. Destruction is attested, not observed.

## Final polish: Cases, Platform, rebuilt packages

This section supersedes every package and test figure further down. Population
unchanged: SYNTHETIC, SIMULATION and PACKAGE IDENTITY; **PHYSICAL VALIDATION: none**. No
sudo, no physical device enumerated, opened or written, no erase, acquisition or
restore, no push. SANCTUMREC was not accessed.

| Commit | Content |
|---|---|
| `0d14af2` | Platform: firmware Purge reads **Unverified** until the validation record's hardware section records a run; Clear names HPA/DCO unlock as not run on hardware. The row gates nothing; the per-device assessment is unchanged |
| `d95603d` | UI: Cases and Platform reorganised for a first-time reader; Audit and Devices tables scroll sideways at a narrow width instead of crushing a column. **Packages built here** |
| this record's commit | documentation, evidence, and line-length fixes in the 2026-09-25 feature driver |

**Why `0d14af2`.** The Platform screen said *Supported with limits* for hardware Purge
whenever `hdparm` or `nvme` was installed, beside a `limitations.md` that says firmware
Purge has never run on hardware and that the path is UNVERIFIED. The model defines
UNVERIFIED as exactly that. The screen now agrees with the document.

| Check | Result |
|---|---|
| Full pytest at `d95603d` | **2041 passed, 34 skipped, 0 failed**; host-device guard 0 refusals. Run with pytest's temporary directory on ext4 |
| The one skip more than before | `tests/erase/files/test_platform.py:134` tests a filesystem *without* extent mapping and skips on ext4, which has it; on tmpfs it runs and passes |
| The same suite with `/tmp` on tmpfs | 2041 passed, 33 skipped, **1 failed**: `test_a_large_candidate_set_holds_one_payload_at_a_time` writes 2000 MiB and hit the tmpfs per-user quota (`OSError: [Errno 122] Disk quota exceeded`). The same user's other scratch data shared that quota; how much of it was in use at the moment of the failure was not recorded. It passes on ext4. An environment and resource limit, recorded rather than hidden; the test was not changed. Whether the run modified or deleted another session's files cannot be established: see *Release-hold remediation* above |
| Ruff | clean. `ruff check .` was not clean at `4c81021`: 13 E501 and 1 I001 in `features-2026-09-25/drivers/`, fixed here without changing behaviour (the feature run passed again after) |
| mypy `--strict` (Linux, two win32, darwin) | clean |
| UI unit tests; `tsc -b`; build | **103 of 103**; clean; built |
| Browser, Sanitize, sandboxed | **59 of 59** at `d95603d` (`browser-2026-09-25/`; pinned screenshots not regenerated) |
| Browser, trace sweep / media map / Record of Destruction | **19 of 19** at `d95603d` (`features-2026-09-25/`; pinned screenshots not regenerated) |
| Browser, Cases / Platform / Audit / Recovery at 1366 × 768 and 1024 × 768 | **66 of 66** (`polish-2026-09-25/`) |
| Packages at `d95603d`: identity | **PASS** both: 92 of 92 modules bytecode-identical, UI 8 of 8, same executable, `.deb` 202 files `root:root`, no maintainer scripts, `Depends: libc6 (>= 2.30), zlib1g` |
| Packages at `d95603d`: isolated smoke | **22 PASS, 2 NOT RUN** each (the two need a real device); a certificate is issued and verifies, so the reportlab QR fix holds |

| Artifact at `d95603d` | SHA-256 |
|---|---|
| `Sanctum-0.0.0-x86_64.AppImage` | `d3f1fe6cb7ad6ec68edce5ede9190439c8a21172cdab257e5aa085a1045a02ff` |
| `sanctum_0.0.0_amd64.deb` | `ebe9f43d3500c2224442fd7b1d367f052c41ce6209346d24e626c0595f0afe4d` |

**Found while rebuilding.** `dist/` did not hold the `e81f491` packages the section
below names: it held the `b163834` build (`5d8d59f4…`, `18b85962…`), whose PDFs carry
no QR code. It now holds the `d95603d` build above.

Not established, unchanged: anything on physical hardware (firmware Purge, HPA/DCO
unlock, backup restoration, a live desktop trace sweep); race freedom between the
helper's check and the first write; that a backup image is a copy of the device; who
approved.

## Later the same day: features, redesign, rebuilt packages

This section supersedes the package and test figures further down, which describe the
`b163834` build. Population unchanged: SYNTHETIC, SIMULATION and PACKAGE IDENTITY;
**PHYSICAL VALIDATION: none**. No sudo, no physical device enumerated, opened or
written, no push.

| Commit | Content |
|---|---|
| `f82af2e` | UI design system v2: Atkinson Hyperlegible Next and Mono bundled, seal colour for what is cryptographically attested, chain-of-custody overview, chain explorer |
| `e582b1c` | certificate PDF: verdict band, NIST fields, signature block with QR; the drive report names device, levels and read-back |
| `e76b2cb` | trace sweep after a file erase: thumbnails, recent-files lists, Trash, Recycle Bin, Recent shortcuts |
| `62e67e4` | Sanitize tracker stops on the step where a flow stopped |
| `86aedb0` | media map before carving; Record of Destruction |
| `e21f88d` | `.deb` declares `Depends: libc6 (>= 2.30), zlib1g` |
| `b014c54` | documentation and browser evidence |
| `43d0fa6` | overview names the new features |
| `e81f491` | packaging: reportlab's barcode modules collected (below). **Packages built here** |

| Check | Result |
|---|---|
| Full pytest at `e21f88d` | **2039 passed, 33 skipped, 0 failed**; host-device guard 0 refusals. The same 33 skips as above |
| Added after that run | `tests/test_packaging_spec.py`, 2 passed |
| Ruff; mypy `--strict` (Linux, two win32, darwin) | clean |
| UI unit tests; `tsc -b`; build | 97 of 97; clean; built |
| Browser, Sanitize, sandboxed fixture server | **59 of 59**, re-run on the redesigned UI (`browser-2026-09-25/`) |
| Browser, new features, sandboxed, synthetic home and image | **19 of 19** (`features-2026-09-25/`) |
| Trace sweep safety properties | four removed on purpose (link walk, in-place overwrite, stale-list check, exact-only removal); each made its test fail |
| Packages at `e81f491`: identity | **PASS** both: 92 of 92 modules bytecode-identical, UI 8 of 8, same executable, `.deb` 202 files `root:root`, no maintainer scripts |
| Packages at `e81f491`: isolated smoke | **22 PASS, 2 NOT RUN** each (the two need a real device) |

**What the rebuild found.** The first rebuild, at `43d0fa6`, failed the isolated smoke:
every report request in the packaged app was a 500, `ModuleNotFoundError:
reportlab.graphics.barcode.code128`. reportlab loads its barcode symbologies through
`exec()`, PyInstaller cannot see that, and the new certificate draws its QR code
through the package. The source tree and the whole test suite pass either way; only
the frozen build fails. The renderer before the certificate rewrite caught the
ImportError, so the `b163834` packages below shipped PDFs with **no QR code**, silently.
The signed JSON, which is the authoritative artifact, was unaffected. Fixed and guarded
in `e81f491`.

| Artifact at `e81f491` | SHA-256 |
|---|---|
| `Sanctum-0.0.0-x86_64.AppImage` | `bbbadf170b0668ffd3fef5cea8a08d2324e8387835fc524f692e2d5ef6d0950e` |
| `sanctum_0.0.0_amd64.deb` | `6386c4612da665541e56edb20929234080cad70ddf2e0107c681ea7c398409b6` |

Claims boundaries, unchanged and extended: the trace sweep is validated on synthetic
homes built from the file formats' specifications, not on a live desktop session; the
Record of Destruction records an attestation and observes nothing; the media map
classes bytes and identifies no content.

## Correction to the first version of this record

The first version (commit `7f308ba`) said no physical device was "opened, read, hashed,
written, erased, acquired or restored". That holds for opens and I/O, and it was
incomplete. Every full test run up to then, this session's included, ran **real host
discovery** from inside the suite: five platform tests and one helper test ran `lsblk -J
-O -b` over sysfs (and, on its fallback, listed `/dev/disk/by-id` and `/sys/block`).
That enumerates the metadata of every attached disk - name, size, serial, mount points -
removable media included. lsblk reads kernel tables; no device was opened and no I/O
was issued to one. The file-erase tests also asked to open the host's own system disk
read-only to verify extents; the kernel refused, because the account is not in the
`disk` group, so nothing was read.

Since `d761125` the suite refuses all of that before the syscall
(`tests/_host_device_guard.py`), the affected tests are hermetic, and any refusal fails
the run. The runs below had **0 refusals**. The first version also said that source,
API and package `/health` "agree"; they did for the build commit, not for the record's
own later commit. The packages now report the build commit named below, and a source
checkout reports its live HEAD.

## Commits (branch `docs/readme-redesign`)

| Commit | Content |
|---|---|
| `9d601b8` | helper re-checks the erase authorization at the write seam; API gate hardening |
| `ace1e93` | Sanitize screen drives the workflow authorization API |
| `0127172` | tests, browser evidence, audit, doc fixes |
| `7f308ba` | first version of this record (docs only) |
| `d761125` | host-device guard in the suite; hermetic discovery and disk reads; per-field binding tests; `test_offline_serving` un-masked |
| `db38ea7` | job registry keeps the helper's refusal kind; a failure record is not called a certificate |
| `b163834` | `--isolated` package smoke. **The packages are built from this commit.** |
| this record's commit | documentation and evidence only |

## Results

Tests at `b163834` (the later commits touch documentation only).

| Check | Result |
|---|---|
| Full pytest | **1950 passed, 33 skipped, 0 failed**; host-device guard 0 refusals |
| Skips | 10 need root and `losetup`; 12 are Windows-only and 10 macOS-only behaviour; 1 is a Pillow TIFF byte-order case |
| Helper, authorization bindings, guard self-test | 92 passed |
| Workflow gate, write seam, failure modes, erase jobs, resume, streaming (one command) | 79 passed |
| `tests/api/test_resume.py` alone | 9 passed |
| `tests/test_workflow.py`, `tests/ui` | 32 passed |
| `tests/erase` | 317 passed, 12 skipped |
| Ruff; mypy `--strict` (Linux, two win32, darwin) | clean |
| UI unit tests; `tsc -b`; build | 78 of 78; clean; built |
| Browser, Sanitize screen, fixture server in a no-device sandbox | **59 of 59**, 0 JavaScript errors (`browser-2026-09-25/`) |
| `scripts/demo_simulation.py`, `scripts/demo_fragmented.py` | ran; `SIMULATION / NO PHYSICAL DEVICE MODIFIED` printed |
| Missing device (`media_benchmark.py preflight`, nonexistent by-id path) | refused before any probe: "No other device was substituted. Nothing was read and nothing was written." |

`test_offline_serving` had been skipped since 2026-09-21 with a message blaming the
host; the real cause was a `NameError` in its own probe. It now runs and passes.

## Package identity

Built from a clean clone at **`b1638340bf4e27834c8a096a6302b7883c5b3978`**; details and
reproduction in [`package-2026-09-25/`](package-2026-09-25/README.md).

| Artifact | SHA-256 |
|---|---|
| `Sanctum-0.0.0-x86_64.AppImage` | `5d8d59f492ac52cc8e31f52c3412c4de6173755015dbe4bde435582f14c7aefd` |
| `sanctum_0.0.0_amd64.deb` | `18b859622cee8eaa6be965dc4cd91cf73939653b21702681deb2aaeec601e023` |

- Identity **PASS** for both: `build_info.json` names that commit with no `+dirty`;
  88 of 88 `core`/`api`/`helper` modules are bytecode-identical to the commit's source,
  none missing or extra; the bundled UI equals the build, file for file; both packages
  carry the same executable.
- `.deb`: no maintainer scripts, all files `root:root`, no set-uid, set-gid or
  world-writable file. Needs glibc ≥ 2.30 and zlib from the system; declares no
  `Depends`.
- Isolated smoke (`scripts/package_smoke.py --isolated`), both packages: **22 PASS,
  2 NOT RUN** (the two checks that need a real device), in a sandbox with no block
  device, no sysfs, no udev database and no removable media. The packaged `/health`
  reports `b1638340…`.
- The packages from `0127172` are superseded and were replaced in `dist/`.

## What is established, and what is not

Established by test, synthetic devices only: a real erase needs a server-issued,
one-use authorization bound to the device's serial, model and size, the plan and a
backup image; the API gate and, again, the privileged helper refuse a missing,
fabricated, reused, cross-device or stale one, including a device or backup changed
after the API gate passed; twelve concurrent attempts admit one; a dry run never
reaches a write path.

Not established: race freedom between the helper's check and the first write; that a
backup image is a copy of the device; who approved (the API authenticates no person);
anything on physical hardware. A simulation opens a device read-only for its size at
most, and never for writing.
