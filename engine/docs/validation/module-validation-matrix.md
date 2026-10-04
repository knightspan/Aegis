# Module validation matrix — campaign of 2026-09-24

> **Current state (2026-09-28).** Current product execution no longer exposes
> a user-facing simulation/dry-run mode: every operation runs against the
> selected real device once its gates pass, and a request that asks for a
> rehearsal is refused. References below to a dry run or a simulation record
> what the build of that date did; they are historical evidence and are kept as
> run.

> This page is the record of one campaign and its rows are kept as run. For
> the current state of every capability on every platform, with physical
> validation scoped to device class, see the generated
> [`capability-completion-2026-09-28/capability-matrix.md`](capability-completion-2026-09-28/capability-matrix.md)
> and [`capability-completion-2026-09-28/README.md`](capability-completion-2026-09-28/README.md).
> Since this campaign, backup restore has been implemented in the app
> (IMPLEMENTED / UNVALIDATED, never run on a physical device), and Windows and
> macOS whole-drive clear and raw acquisition have been implemented
> (IMPLEMENTED / UNVALIDATED). Nothing in this campaign's physical rows
> changes.

**Software under test:** `ec73747` on `docs/readme-redesign` plus the four fixes
listed under "Defects found and fixed" (uncommitted at the time of writing).
**Host:** Fedora 44, Linux 6.19.10, Python 3.11.16 (`.venv`).
**Physical target:** TOSHIBA TransMemory, serial `B103B9C19DE1CCC1BD535ACB`, by-id
`/dev/disk/by-id/usb-TOSHIBA_TransMemory_B103B9C19DE1CCC1BD535ACB-0:0`, 7,759,462,400
bytes, one vfat partition labelled `SANCTUMREC`, mounted read-write at
`/run/media/v0idsai/SANCTUMREC` for the whole campaign. The kernel name (`/dev/sda`)
was informational only.

**Not run, by design:** M1-I controlled physical Clear, M1-J post-operation
verification, M2-C physical file erase on the stick, M3-F physical acquisition. The
first three need a human authorisation that was not given. M3-F needs raw read access
this account does not have (`/dev/sda` is `0660 root:disk`; no sudo was used).

**What changed on the physical device: nothing.** Baseline and post-campaign snapshots
(`physical-module-baseline.json`, `campaign-2026-09-24/physical-post-campaign-snapshot.json`)
show identical identity, mount options, and all 8 directory entries with identical size,
mtime, mode and SHA-256. `writes_completed` stayed at 1 and `sectors_written` at 1
throughout (the values at attach time). Only `sectors_read` grew (20978 → 21672), from
hashing files through the page cache.

Population labels: `PHYSICAL`, `SYNTHETIC`, `SIMULATION`, `CI`, `DOCUMENTATION`,
`HARDWARE-UNVERIFIED`. They are never merged in a row.

## Matrix

| Module | Test | Population | Expected | Actual | Result | Evidence | Limitation |
| ------ | ---- | ---------- | -------- | ------ | ------ | -------- | ---------- |
| Platform | P0 baseline snapshot: identity, serial, layout, mount, I/O counters, permissions, 8 files with SHA-256 | PHYSICAL | Read-only capture | Captured; write counters unchanged; files hashed with `O_NOATIME` | PASS | `physical-module-baseline.json`, `scripts/validation_baseline.py` | Reads still go through the page cache; `sectors_read` rises. |
| M1 | M1-A discovery via by-id path | PHYSICAL | Model, serial, size, transport, mounts | All reported; `rotational=true` is the kernel flag, `media.flash=true` from the usb transport with the reason printed | PASS | `plan` output in `m1/H-plan-nobackup.out`; `/devices` on live API | Capability fields are null (see M1-F). |
| M1 | M1-B mounted device preflight | PHYSICAL | `REFUSED`, structured, no write | `{"refused": "... has mounted filesystems ...", "kind": "safety"}`, rc 2, no traceback, I/O and mount unchanged | PASS | `m1/B-mounted-preflight.out` | Refusal is by the mount check, not by any other gate. |
| M1 | M1-C stale by-id link, nonexistent `/dev/sdz` | PHYSICAL | Refusal, no substitution | `kind: unavailable`, "No other device was substituted. Nothing was read and nothing was written." | PASS | `m1/C-*.out` | |
| M1 | M1-D wrong expected serial against the real device | PHYSICAL | `REFUSED` | Refused, but **by the mounted check first**, so the serial check was not the gate that fired | PASS (fail-closed) / INCONCLUSIVE for the serial gate on hardware | `m1/D-wrong-serial.out` | The serial gate on real hardware needs an unmounted device. Its logic is CI-tested. |
| M1 | M1-E permission path: `acquire`, `backup` as an unprivileged user | PHYSICAL | Structured refusal, no traceback, "not written" | `acquire`: `{"kind": "io", "errno": 13, ..., "device_state": "not written by this command"}`, rc 3. `backup`: refused earlier by the mount check. Capability probe: `UnsupportedCapability`, "do not treat this as an unsupported device" | PASS | `m1/E-*.out`; probe output in session | The write-open `EACCES` path was **not** exercised on the stick (would need a non-dry run). CI covers it: `test_a_permission_denied_write_is_a_privilege_refusal`. |
| M1 | M1-F capability selection | HARDWARE-UNVERIFIED | Methods considered/rejected with reasons | Probe cannot run unprivileged. Prior privileged run (2026-09-05, same serial): `CLEAR` only, no ATA security, HPA/DCO not probed behind the usb bridge | INCONCLUSIVE | `docs/validation/hardware.md` (DOCUMENTATION) | Needs a privileged probe of this device now. Firmware erase was not attempted. |
| M1 | M1-G read-only plan for the real device | PHYSICAL | Identity, serial, extent, backup state, approval state | State `BLOCKED`, `WHY BLOCKED`, two independent serial sources agree (`lsblk` udev, sysfs usb serial), `APPROVED: false`, `VERDICT: REVIEW ONLY`, privilege `INSUFFICIENT` | PASS | `m1/H-plan-nobackup.out` | Write extent is unknown because no corpus image was built. |
| M1 | M1-H backup gate: none / short / wrong disk / changed hash / wrong serial | CI (+ PHYSICAL for "none") | Every unsafe state fails closed | "none": `sufficient_for_restoring_the_modified_region: false`, three blocking reasons, on the real device. The rest: 268 script tests pass, including one added for defect D1 | PASS | `m1/H-verify-nobackup.out`; `tests/scripts/test_media_benchmark_boundary.py` | Backup restoration was not implemented in the app at the time (checklist gate 4 note). It has since been implemented (`core/restore.py`) and has never been run on a physical device. |
| M1 | M1-I controlled physical Clear, M1-J verification | — | Needs human authorisation | **Not run** | NOT RUN | — | Prerequisites 1–8 in the brief are not satisfied. A previous run is in `hardware.md`. |
| M2 | M2-A file/folder erase on a disposable corpus (18 cases) | SYNTHETIC | Correct erase, per-file errors, audit trail | 18/18 PASS: dry-run default, gate 2, single, batch, Unicode and space names, empty, 24 MiB, recursive 4 levels, missing, already deleted, hardlink, symlink refusal, permission denial, interrupted batch (cancel entry), chain VALID over 314 entries | PASS | `campaign-2026-09-24/m2-synthetic.json`, `scripts/validation_m2_synthetic.py` | Host ext4 disk, not FAT32/NTFS. A read-only (0444) file is **not** erased: the record is `EACCES`, honest but unhelpful. |
| M2 | M2-B metadata: EXIF/GPS, OOXML, PDF Info+XMP, PNG text, OLE | SYNTHETIC | Fields removed; OLE reported, not removed | EXIF, OOXML, PDF, PNG removed and files still open. OLE (real `.doc` made by LibreOffice): `removed=False` for both SummaryInformation streams, limitation printed | PASS | same JSON | OOXML fixture is hand-built, not Word-authored. |
| M2 | M2-B residual reporting | SYNTHETIC | Names what it cannot guarantee | Reports `TRIM_REMAP`, `FS_JOURNAL`, `FILE_SLACK`; file-erase verification `passed: null, strategy: not_possible` (no raw read) | PASS | same JSON, case M2-B-06 | MFT resident data, USN journal and directory-index slack apply to NTFS and were **not** exercised (no NTFS here). `HARDWARE-UNVERIFIED`. |
| M2 | M2-C physical file erase on `SANCTUMREC` | — | Needs explicit approval | **Not run** | NOT RUN | — | The stick is mounted and holds 5 images you did not tell me are disposable. |
| M2 | protected-root descendants | SYNTHETIC | `erase /usr` must not erase children | **FAIL before fix (D2)**, PASS after | PASS (after fix) | `tests/erase/files/test_protected_roots.py` | |
| M3 | M3-A deterministic corpus: 40 images, `sanctum-carve` and `sanctum-full` | SYNTHETIC | Reproduce the recorded baseline | Identical to the 2026-09-21 baseline. `sanctum-full`: 591 planted, 576 byte-identical, 15 corrupt, 0 missed, 88 false-positive outputs of 969 | PASS | `campaign-2026-09-24/bench.csv`; `docs/performance/benchmark-2026-09-21-sanctum.csv` | Synthetic images on NVMe. Says nothing about real media. |
| M3 | M3-B/E structure and decoder rejection, decoys | SYNTHETIC | Rejected candidates are not accepted | Demo: overwritten-tail PNG → `corrupt`, LOW, 3500; decoy PNG signature → `corrupt`, LOW, 2500, never HIGH. Fuzz: 16,500 cases, 0 crashes, timeouts or memory failures | PASS | `demo_fragmented.json`, `fuzz.out` | "Rejected" means low band and marked corrupt, not absent from the output. |
| M3 | M3-C fragmented JPEG | SYNTHETIC | Two-run reconstruction, digest matches | Runs `[172032,8192]`,`[212992,25529]`; digest matches ground truth; valid, MEDIUM, 7999 | PASS | `demo_fragmented.json` | One 32 KiB gap, baseline JPEG. |
| M3 | M3-D fragmented PNG | SYNTHETIC | CRC-checked join, unique, digest matches | Runs `[16384,12288]`,`[61440,98659]`; digest matches. 200/200 refused for each of 4 adversarial families; 0 wrong accepts | PASS | `demo_fragmented.json`, `png.json` | Two-fragment only. |
| M3 | M3-F physical acquisition and carve | — | Needs raw read | **Not run** | BLOCKED | — | Needs `disk`-group or root, granted by you. Without ground truth the result is observational, not a benchmark. |
| Ledger | append, chain, order, tamper, incomplete tail | SYNTHETIC | Detect each | intact VALID; half-written tail `INCOMPLETE_TAIL`; deleted middle entry `SEQ_GAP`; swapped entries `LINK_MISMATCH`; flipped byte `HASH_MISMATCH`; genesis removed `SEQ_GAP` | PASS | session output; 89 ledger tests | **Whole trailing entries can be cut and the chain stays VALID** (see limitation L1). |
| Report | verdicts `VERIFIED` / `VERIFIED_WITH_LIMITATIONS` / `PARTIAL` / `FAILED_VERIFICATION` | CI + SYNTHETIC | Every downgrade names its reason | Canonical fallback: `VERIFIED_WITH_LIMITATIONS` with 3 reasons. Without `--ledger-root`: `PARTIAL` with 3 reasons | PASS | session output; `tests/report/test_report_verdict.py` | `VERIFIED` (clean) is CI-only; the demo report is not clean. |
| Report | tamper one byte, copy of canonical | SYNTHETIC | `VALID → BROKEN`, original intact | Report byte: `signature FAIL`, `FAILED_VERIFICATION`. Ledger byte: `chain_store FAIL … HASH_MISMATCH at 33`. Original SHA-256 unchanged | PASS | session output | |
| Report | store truncated below what the report cites | SYNTHETIC | Detect | **PASS before fix: not detected (D4)**. After fix: `the report cites entry 20, but the store does not hold that entry` | PASS (after fix) | `tests/report/test_verify_report.py` | Cutting only entries the report does not cite is still undetectable. |
| Report | signature | SYNTHETIC | Ed25519, fingerprint, genesis match | Valid; fingerprint `69:45:A0:…:50:F5` matches genesis | PASS | session output | Proves internal consistency only. It does not prove who signed. Compare the fingerprint out-of-band. |
| Workflow | all 11 states × all 128 gate-fact combinations (15,488 pairs) | SYNTHETIC | Illegal edges refused; `EXECUTING` only from `PLAN_READY` with every gate | 1,079 allowed, 12,544 refused (no edge), 1,865 refused (facts). `EXECUTING` reachable from exactly one fact vector (all gates true). No edge leaves `COMPLETE`/`FAILED`. Every `BLOCKED` carries a reason | PASS | `workflow-matrix.json`, `scripts/validation_workflow_matrix.py` | See limitation L2: the API does not consult this state machine. |
| Workflow | simulation cannot reach a physical write path | SIMULATION / CI | | 34 skips include the loopback tests. Not re-proved live | CI only | `tests/` | |
| API | loopback bind, session token, Host check, validation | PHYSICAL host, no device write | Loopback only; 401 without cookie | Listens on `127.0.0.1:8799` only; no cookie 401; `Host: evil.example` 400; wrong token 403; empty body 422; bad level 422; non-dry without serial 409 with remediation; non-dry `erase-files` without confirm 409 | PASS | session output | Live helper (root daemon) path not exercised. |
| UI | 66 unit tests; source audit for probability language | CI | Score never called a probability | 66/66 pass. "not a probability" appears on Recovery, Home and the summary. `detection probability` on Sanitize is the erase read-back sampling figure, which the model documents as a genuine probability | PASS | `ui` tests | **No live browser run in this campaign.** Screens rest on the 2026-09-24 screenshots in `browser-2026-09-24/` (DOCUMENTATION). |
| Platform | perf | PHYSICAL host / SYNTHETIC | | Discovery 0.21 s, 36 MB; refused preflight 0.05 s; `verify-report` 0.23 s; demo carve 0.55 s, 56 MB | PASS | session output | Backup and acquisition throughput not measured (need raw read). |
| CI | full pytest | CI | 0 failures | **1839 passed, 34 skipped, 0 failed** (1873 with the 4 added tests). `ruff` clean, `mypy --strict` clean. Skips: 10 loopback needs root, 10 APFS, 12 NTFS/Win32, 1 netns, 1 TIFF endianness | PASS | `pytest-junit.xml` | The skips are not passes. |

## Defects found and fixed

| ID | Severity | Defect | Fix | Test |
| -- | -------- | ------ | --- | ---- |
| D1 | Low | A backup on `tmpfs` was reported as "a different disk" and counted as sufficient. RAM does not survive the reboot a failed write may force. | `scripts/media_benchmark.py` `backup_location`: a source with no `/dev/` backing returns `on_host_storage: None`, which blocks. | `test_a_backup_on_ram_backed_storage_is_not_sufficient` |
| D2 | **Medium** | `erase_paths(["/usr"])` expanded the tree first and refused only `/usr` itself, last. Every descendant the operator could write was erased before the refusal. Protected roots such as `/home` were affected the same way. | `core/erase/files.py` `expand_targets`: a protected requested root is emitted as itself, so the refusal happens before any child. | `test_erasing_a_protected_root_recursively_leaves_its_contents_alone` |
| D3 | Low | A non-empty directory with `recursive=False` was renamed to a random name, then `rmdir` failed. The directory kept its contents under a name nobody chose. | `_erase_directory` checks emptiness before the rename chain. | `test_a_non_empty_directory_keeps_its_name_when_it_cannot_be_removed` |
| D4 | Medium | `verify-report --ledger-root` passed when the store was cut short below what the signed report cites. Its own chain still verified. | `_check_store_chain` compares every excerpt entry's `seq` and `entry_hash` with the store. | `test_a_store_that_lost_entries_the_report_cites_fails` |

D2 was reproduced only against a monkeypatched protected prefix in a scratch directory. `/usr`
itself was never targeted with a real erase.

## Limitations that remain

- **L1. Tail truncation of the ledger.** Removing whole trailing entries leaves a valid
  chain. A signed report catches it only for entries the report cites (D4 fix). An
  external anchor (`core/ledger/anchor.py`) is the only full answer, and none is wired in.
- **L2. The API does not enforce the workflow state machine.** `POST /jobs/erase-drive`
  with `dry_run=false` is gated by the typed serial, the mounted/system-disk guard and
  the helper. It does not require a verified backup or a recorded approval. Those exist
  in `scripts/media_benchmark.py write` (backup, typed serial, acknowledgement flag) and
  in the UI and plan. `README.md` and `judge-defense-card.md` Q11 describe approval as
  "dry run off + typed serial", so the documents are honest. The brief's word "approval
  recorded" is not what the API checks.
- **Status update 2026-09-25 (docs only; the rows above are the campaign record):** L2
  and L3 were fixed after this matrix was written - see
  `l2-fix-and-m2c-procedure.md` and `final-audit-2026-09-25.md`. Both are
  SYNTHETIC-VALIDATED only; neither was exercised on the physical stick.
- **L3.** `/health` reports the build record (`930ee2c`, branch
  `release/cross-platform-validation`, built 2026-09-21), not the running `HEAD`.
- **Status update 2026-09-28 (docs only):** backup restore now exists in the app
  with post-restore hash verification, SYNTHETIC-VALIDATED only. No row above
  changes: nothing in this campaign exercised it.
- **L4.** The serial-mismatch gate and the write-open permission gate were not reached on
  the physical stick, because the mounted-device gate fires first (correctly).

## Recommended judge-demo claims

Say:

- Against a real, mounted USB stick, Sanctum refused every unsafe request with a
  structured reason, wrote nothing, and left the stick byte-identical (baseline and
  post-campaign snapshots).
- On a deterministic 40-image synthetic corpus it reproduces its recorded result:
  576 of 591 planted files byte-identical, 15 corrupt, 0 missed, 88 false-positive outputs.
- Fragmented JPEG and PNG reassembly works on synthetic two-fragment cases, with 0 wrong
  accepts in 800 adversarial PNG cases.
- Tampering with one byte of a report or ledger is detected. A signature proves internal
  consistency, not identity.

Do not say:

- "Fully validated." A physical Clear, physical file erase, physical acquisition and a
  privileged capability probe were not run in this campaign.
- Any recovery percentage for the real stick.
- That the API requires a verified backup before a drive erase (L2).
- That NTFS metadata (MFT, USN, index slack) handling was validated. No NTFS was available.
