# Feature matrix: project requirements against what the code does

**Audit date:** 2026-09-23, starting from `761dffe`; updated 2026-09-24 after the
upgrade waves, and again after the release-quality wave that browser-checked
the UI (`docs/validation/browser-2026-09-24/`); M1 rows reconciled 2026-09-26 with
the release-hold remediation (`docs/validation/remediation-2026-09-25/`). **No
physical validation was run for the `76dde42` release**; the PHYSICAL rows below are
from runs on 2026-09-05 and 2026-09-23 with earlier builds. **Update, 2026-09-27,
`437081e`:** a separate later run physically validated Windows packaged
install, device discovery, the mounted-device refusal and file erase (on the
host system disk), all through the installed exe. The same run also exercised,
after two packaging fixes it found itself (a windowed-launch crash and a
missing carve-engine data file), acquire and carve of a **synthetic image**,
media map and a metadata-only Destroy attestation; those did not touch a
device, and Windows raw acquisition stays IMPLEMENTED / UNVALIDATED — see row J and
[`windows-hardware-2026-09-27-fixes/`](windows-hardware-2026-09-27-fixes/README.md);
it does not change any other row here. This matrix and [`demo-evidence-index.md`](demo-evidence-index.md)
are the source of truth for the presentation. A row states what the code does,
where it is, what tests it, and what it does not do. It does not describe plans
as features.

**Update, 2026-09-28, `bf4c59b`:** Windows and macOS whole-drive clear, raw
acquisition, backup restore, Windows device sanitize and a guarded HPA/DCO
workflow are now implemented; rows A1, E and J below say so. None of them has
run on a physical device. Per-platform state, with physical validation scoped
to device class, is the generated
[`capability-completion-2026-09-28/capability-matrix.md`](capability-completion-2026-09-28/capability-matrix.md);
what changed is in
[`capability-completion-2026-09-28/README.md`](capability-completion-2026-09-28/README.md).
Physically validated is exactly: Linux whole-drive clear, discovery and raw
acquisition on one `usb-flash` stick (2026-09-05); Windows discovery on a
`usb-flash` stick and Windows file erase on the host system disk (device class
not recorded), both 2026-09-27.

The original requirement text is not in this repository. The rows below
follow the three modules named in `README.md` and `CLAUDE.md`, plus the
requirement areas (A to P) in the upgrade brief dated 2026-09-23.

## Status words

| Word | Meaning |
|---|---|
| **IMPLEMENTED + TESTED + DEMONSTRABLE** | The code exists, tests cover it, and a demo step shows it through real software output. |
| **IMPLEMENTED + TESTED + NOT YET DEMONSTRATED** | The code exists and tests cover it, but no demo step shows it yet. |
| **PARTIAL** | Implemented with a material gap, which the Limitation column names. |
| **HARDWARE-UNVERIFIED** | The software path is tested, but no physical device of that kind has run it in a recorded session. |
| **UNVERIFIED** | Code exists but has not been executed in the environment named. |
| **UNSUPPORTED** | Deliberately unavailable. The software refuses and says why. |
| **DOCUMENTED** | A written artifact for people, not software. Its evidence is the document and what it cites. |

Evidence populations are kept apart everywhere in this file: **SYNTHETIC**
(generated images on host storage), **PHYSICAL** (a real device, recorded in
`docs/validation/hardware.md`), and **CI** (virtual disks on hosted runners).

---

## A1. Secure Drive Eraser (M1)

| Requirement | Capability | Status | Evidence | Limitation |
|---|---|---|---|---|
| Device capability discovery | `core/device/capabilities.py:probe` reads `hdparm -I`, NVMe Identify (SANICAP, FNA), `sedutil-cli --scan`, sysfs | IMPLEMENTED + TESTED + DEMONSTRABLE | `tests/device/`; Devices screen `CLEAR ONLY` badge | A capability that was not observed is reported as not supported; a privilege failure is raised, not treated as "unsupported" |
| Method selection with rationale | `recommend_method` picks the strongest probed mechanism; the justification and the probed flags go into report section 3 | IMPLEMENTED + TESTED + DEMONSTRABLE | `tests/erase/`, `tests/device/`; report `method.justification`, `method.capability_evidence` | Never downgrades silently: NOT AUTHORIZED when the requested level is not reachable |
| ATA SECURITY ERASE UNIT (enhanced) | `EraseMethod.ATA_SECURITY_ERASE_ENHANCED` dispatch via `hdparm` (Linux) | HARDWARE-UNVERIFIED (resolver: DEVICE-DEPENDENT on Linux; NOT IMPLEMENTED on Windows; PLATFORM-LIMITED on macOS) | fixture tests in `tests/erase/` | Counted as Purge only on magnetic media, and that rule is unvalidated (`docs/limitations.md`); USB bridges block ATA pass-through; the password is fixed and published. Not built on Windows: a refused or interrupted erase would leave the drive locked with no tested recovery path |
| ATA SANITIZE (block, overwrite, crypto scramble) | `ATA_SANITIZE_*` methods; Linux via `hdparm`, Windows (block erase, crypto scramble) via `IOCTL_ATA_PASS_THROUGH` (`core/device/win/ata.py`, `core/erase/devicesanitize.py`) | HARDWARE-UNVERIFIED (DEVICE-DEPENDENT on Linux and Windows; PLATFORM-LIMITED on macOS) | fixture tests; `tests/platform/test_assessment_and_matrix.py` (a per-device Purge is never physically validated without a hardware record); `tests/device/test_windows_native.py`, `tests/platform/test_windows_engine.py` (adapter doubles) | Never executed on a drive in a recorded run. Offered only when IDENTIFY reports it; the Windows driver may refuse the pass-through, and the refusal is reported, never retried another way |
| NVMe Sanitize / Format (SES1) | `NVME_SANITIZE_BLOCK`, `NVME_FORMAT_SES1` via `nvme-cli` (Linux); NVMe Sanitize block and crypto via `IOCTL_STORAGE_REINITIALIZE_MEDIA` (Windows, `core/device/win/nvme.py`) | HARDWARE-UNVERIFIED (DEVICE-DEPENDENT; NVMe Format PLATFORM-LIMITED on Windows; all PLATFORM-LIMITED on macOS) | fixture tests; Windows adapter doubles | Format is per namespace; a multi-namespace controller needs sanitize. Windows gives no progress for the sanitize |
| Cryptographic erase | `ATA_SANITIZE_CRYPTO_SCRAMBLE`, `SED_CRYPTO_ERASE` (TCG Opal, not Pyrite) on Linux, planned but not executable: the build has no PSID input and the job refuses; ATA crypto scramble or NVMe Sanitize crypto on Windows | HARDWARE-UNVERIFIED (DEVICE-DEPENDENT; PLATFORM-LIMITED on macOS) | fixture tests; `tests/report/test_semantics.py` (the certificate says CRYPTO ERASE and that the ciphertext remains) | Pyrite is deliberately not counted as Opal. On macOS, *Erase All Content and Settings* is named, not performed |
| Overwrite Clear | Linux: `SINGLE_PASS_OVERWRITE` with `O_DIRECT`, 0xA5 write calibration (`core/erase/drive.py`). Windows and macOS: `core/erase/blockclear.py` over `\\.\PhysicalDriveN` (disk offline, handle bound to disk number, serial and length) or `/dev/rdiskN` (external disks) | Linux: IMPLEMENTED + TESTED + DEMONSTRABLE (PHYSICAL, `usb-flash` only). Windows, macOS: IMPLEMENTED + TESTED, not physically validated (IMPLEMENTED / UNVALIDATED) | `docs/validation/hardware.md`: three Phase A runs on one USB flash stick, the third (2026-09-05) clean; `tests/erase/test_blockclear.py`, `tests/platform/test_windows_engine.py`, `tests/platform/test_macos_engine.py` (adapter doubles) | Overwrite cannot reach remapped or over-provisioned flash; stated in every report, whose category is ADDRESSABLE WHOLE-DRIVE CLEAR. Internal Apple storage is never raw-written |
| Removable-media clearing | same engine, flash detected by transport, not by `rotational` (`core/device/media.py`) | IMPLEMENTED + TESTED + DEMONSTRABLE (PHYSICAL) | hardware.md; `tests/device/` | Some controllers elide zero fills (`CONTROLLER_WRITE_ELISION` finding) |
| Verification after the operation | `core/erase/verify.py`: full read to 64 GiB, seeded sampling above | IMPLEMENTED + TESTED + DEMONSTRABLE | `tests/erase/test_verify.py`; hardware.md | Sampled above 64 GiB; drive attestation is the drive's claim about itself |
| HPA / DCO detection and modification | detection `core/device/hidden_areas.py`; the guarded workflow `core/device/hidden_area_workflow.py` (API `/workflow/hidden-area`): plan, typed serial, volatile SET MAX by default (permanent only on request), read-back verification, every step ledgered; DCO discovered only, never modified. An ordinary erase no longer changes the HPA: it erases the accessible range and names the hidden byte count as a limitation | IMPLEMENTED + TESTED + NOT YET DEMONSTRATED; modification HARDWARE-UNVERIFIED (DEVICE-DEPENDENT on Linux and Windows; PLATFORM-LIMITED on macOS) | `tests/device/test_hidden_areas.py`, `tests/device/test_hidden_area_workflow.py`, `tests/api/test_hidden_area_workflow.py`, `tests/erase/test_hidden_area_phases.py` (faked probe) | Needs ATA pass-through, which USB bridges usually block. No drive with a hidden area has been through the workflow |
| Sector size, logical and physical capacity | report `device_identity.logical_block_size`, `physical_block_size`, `size_bytes` | IMPLEMENTED + TESTED + DEMONSTRABLE | `core/report/render.py:build_report`, `tests/report/test_render.py` | none recorded |
| Removable and read-only status | enumeration and preflight refuse a read-only or non-removable device without override | IMPLEMENTED + TESTED + DEMONSTRABLE | `tests/device/`, `tests/scripts/test_media_benchmark*.py` | none recorded |
| Encryption state | Opal SSC detected from `sedutil-cli`; macOS FileVault/APFS roles in `core/platform/macos.py` | PARTIAL | `tests/device/`, `tests/platform/` | No LUKS or BitLocker volume detection on the drive-erase path |
| Device health (SMART) | none | UNSUPPORTED | none | Not queried. Not a sanitization input; would be an observation only |
| Failure handling | typed errors in `core/errors.py`; unwritable ranges skipped and named | IMPLEMENTED + TESTED + NOT YET DEMONSTRATED | `tests/erase/` | Unwritable ranges are skipped, not fixed |
| Resume | overwrite resumes from the last ledgered checkpoint; firmware methods restart | PARTIAL | `tests/api/test_resume.py`, `tests/erase/test_blockclear.py` | Overwrite only (the Linux engine, and the block engine used on Windows and macOS) |
| Device preparation (take offline / unmount) | `POST /devices/prepare`: Windows takes the disk offline non-persistently, macOS runs `diskutil unmountDisk`; the volumes it affects shown first, typed serial, system and internal disks refused, ledgered, never part of an erase | IMPLEMENTED + TESTED + NOT YET DEMONSTRATED | `tests/api/test_endpoints.py`, `tests/helper/test_daemon.py` | Adapter doubles only; not run on a physical disk. Linux has no such step: a human unmounts |
| Read-only planning before a real run | `core/erase/drive.py:preview` and the workflow `open` call show method, evidence and limitations before approval; there is no dry-run execution mode, and a request carrying `dry_run`/`simulation` is rejected (422) | IMPLEMENTED + TESTED + DEMONSTRABLE | `tests/erase/test_erase_preview.py`, `tests/erase/test_no_rehearsal_mode.py`, `tests/api/test_endpoints.py` | The plan is computed from the scan; the job re-probes and re-selects |

## A2. Secure File and Folder Eraser (M2)

| Requirement | Capability | Status | Evidence | Limitation |
|---|---|---|---|---|
| Single file, recursive folder, batch | `core/erase/files.py` | IMPLEMENTED + TESTED + DEMONSTRABLE | `tests/erase/files/`; CI on three OSes (`docs/platform-support.md`) | Hard-linked files are not overwritten by default |
| Document metadata cleanse | EXIF, OOXML `docProps`, PDF info, OLE summary (`core/erase/metadata.py`) | IMPLEMENTED + TESTED + DEMONSTRABLE | `tests/erase/` | Runs before the overwrite; never claims a false clean |
| Filesystem metadata | rename chain and stepped truncation; journal, MFT and index copies reported | PARTIAL | `tests/erase/` | Detected and reported, never cleansed |
| Free-space (residual) wipe | `core/erase/freespace.py` | PARTIAL | `tests/erase/` | FAT32, exFAT and ext4 on Linux only |
| Verification | physical read-back of pre-captured extents | PARTIAL | `tests/erase/` | Needs raw read access; FAT/exFAT cannot be verified by extents; copy-on-write filesystems report NOT VERIFIABLE |
| Copy-on-write and journaling filesystems | Btrfs, F2FS, APFS, ReFS: the erase runs and the report says NOT VERIFIABLE with the reason | IMPLEMENTED + TESTED + DEMONSTRABLE | `core/platform/filesystems.py`, `tests/platform/` | A file-level overwrite cannot address old copies on copy-on-write storage |
| Audit trail, partial success | each file has its own outcome; ledger entry per operation | IMPLEMENTED + TESTED + DEMONSTRABLE | `tests/erase/files/`, `tests/ledger/` | none recorded |
| Plan before erase | the queued paths are PLANNED until confirmed; the erase itself is always real and refused without `confirm` | IMPLEMENTED + TESTED + DEMONSTRABLE | `ui/tests/fileEraseState.test.ts`, `tests/erase/files/test_erase_batch.py` | No per-file preview of residual findings before the erase; they are reported by the erase |

## A3. Advanced File Recovery and Carving (M3)

| Requirement | Capability | Status | Evidence | Limitation |
|---|---|---|---|---|
| Signature carving | 24 signatures (`core/carve/signature.py`) | IMPLEMENTED + TESTED + DEMONSTRABLE | `docs/supported-formats.md` (generated), `tests/carve/signature/` | none recorded |
| Structure validation, footer bounds | 16 structure parsers derive the exact end from length fields (`core/carve/structure.py`) | IMPLEMENTED + TESTED + DEMONSTRABLE | `tests/carve/`; footer bound fixes (`tests/carve/signature/test_footer_bound.py`) | Footerless formats are bounded by the next header of any type |
| Internal consistency, corruption detection | 17 decoders give a verdict that feeds the score (`core/carve/validate.py`); PNG CRC per chunk | IMPLEMENTED + TESTED + DEMONSTRABLE | `tests/carve/test_validate_malformed.py`; fuzz 66,000 cases (`docs/validation/fuzz.md`) | none recorded |
| Fragment detection | `possibly_fragmented` on every candidate whose parse does not close | IMPLEMENTED + TESTED + DEMONSTRABLE | `core/models.py`, `tests/carve/` | none recorded |
| Fragmented reconstruction | bifragment reassembly for baseline JPEG (exact Huffman scan oracle) and PNG (chunk CRC-32 plus exact-length zlib oracle) (`core/carve/fragmentation.py`) | PARTIAL | `tests/carve/signature/test_fragmentation.py`, `tests/carve/signature/test_png_fragmentation.py`, `scripts/demo_fragmented.py` | Two formats, exactly two runs; PDF and every other format are not reassembled |
| PNG bifragment reassembly | exhaustive, unique-or-refused join search; bound across both runs; held below HIGH | IMPLEMENTED + TESTED + DEMONSTRABLE (SYNTHETIC) | `docs/validation/png-reassembly.md`: 120/120 layouts to a 7 MiB gap, 40/40 with text or zero gaps, 0/800 adversarial joins accepted | Synthetic images from one encoder; CRC-32 and Adler-32 are not cryptographic |
| Multi-run (more than two) reconstruction | none | UNSUPPORTED | none | General reassembly is an open research problem; claiming it would not survive questioning |
| File-type classification | `core/carve/classify.py` | IMPLEMENTED + TESTED + NOT YET DEMONSTRATED | `tests/carve/` | none recorded |
| Duplicate detection | SHA-256 per candidate; identical objects collapse and keep every offset (`duplicate_offsets`) | IMPLEMENTED + TESTED + DEMONSTRABLE (SYNTHETIC) | `tests/scripts/test_demo_fragmented.py`, `scripts/demo_fragmented.py` | none recorded |
| Evidence score, components, ranking | six components, buckets HIGH/MEDIUM/LOW (`core/carve/score.py`) | IMPLEMENTED + TESTED + DEMONSTRABLE | calibration docs; Recovery screen Score breakdown | An evidence score, not a probability; a reassembled object is never HIGH |
| Preview where safe | real recovered-image preview, HTML/SVG never rendered | IMPLEMENTED + TESTED + DEMONSTRABLE | `tests/api/test_artifacts.py`, `ui/tests/artifacts.test.ts` | none recorded |
| Provenance, raw offsets | every candidate carries offset, length, runs and SHA-256 | IMPLEMENTED + TESTED + DEMONSTRABLE | `core/models.py:CarveCandidate` | none recorded |
| Undelete from filesystem metadata | NTFS, FAT12/16/32, exFAT, ext2/3/4 via pytsk3 | IMPLEMENTED + TESTED + DEMONSTRABLE (SYNTHETIC) | `docs/performance/benchmark.md` | ext4 recovers almost nothing by design |
| PII triage | counts identity and financial shapes, stores no values | IMPLEMENTED + TESTED + NOT YET DEMONSTRATED | `tests/carve/` | Reads only some types |
| Read-only evidence path | `core/carve/evidence.py` opens `O_RDONLY` and has no write method | IMPLEMENTED + TESTED + DEMONSTRABLE | `tests/carve/` | none recorded |

## A4. Filesystem and format support

| Requirement | Capability | Status | Evidence | Limitation |
|---|---|---|---|---|
| FAT/FAT32, exFAT | undelete, carve, file erase, free-space wipe (Linux) | IMPLEMENTED + TESTED + DEMONSTRABLE | `docs/platform-support.md` | File erase unverifiable by extents |
| NTFS | undelete, carve, file erase | IMPLEMENTED + TESTED + DEMONSTRABLE | same | Resident files and journal copies are reported, not removed |
| ext4 | undelete (little by design), carve, file erase, free-space wipe | IMPLEMENTED + TESTED + DEMONSTRABLE | same | none further |
| APFS | carve only; file erase runs on macOS, NOT VERIFIABLE | PARTIAL | same | No APFS undelete |
| Raw image, E01 | raw images and E01 acquisition | PARTIAL | `docs/performance/acquisition.md` | E01 writing depends on the libewf build; uncompressed |

## B/C. Forensic integrity and tamper-evident reporting

| Requirement | Capability | Status | Evidence | Limitation |
|---|---|---|---|---|
| Hash-chained ledger | entry N holds SHA-256 of N-1; BROKEN vs INCOMPLETE_TAIL (`core/ledger/chain.py`) | IMPLEMENTED + TESTED + DEMONSTRABLE | `tests/ledger/` | An insider with the whole state directory can rebuild it; only an external anchor prevents that, and none is configured by default |
| Evidence hashing | SHA-256 and BLAKE3 at acquisition; SHA-256 per carved object | IMPLEMENTED + TESTED + DEMONSTRABLE | `tests/carve/` | none recorded |
| Case ID, operator, timestamps, tool version | report `case_identity` | IMPLEMENTED + TESTED + DEMONSTRABLE | `tests/api/test_cases.py`, `tests/api/test_operator_identity.py` | Operator is a local account, not a verified person |
| Source device identity and serial | report `device_identity`, by-id path | IMPLEMENTED + TESTED + DEMONSTRABLE | report section 2; `tests/report/test_render.py` | none recorded |
| JSON report (authoritative) | Ed25519 over canonical JSON | IMPLEMENTED + TESTED + DEMONSTRABLE | `tests/report/` | Embedded key proves consistency, not identity |
| PDF report (human-readable) | `render_pdf`, states it is not authoritative | IMPLEMENTED + TESTED + DEMONSTRABLE | `tests/report/test_render.py` | Not signed; editable by design |
| HTML report | none | UNSUPPORTED | none | The PDF and the UI cover human reading |
| Report verification | `verify-report`: signature, fingerprint vs genesis, excerpt chain, store chain, blobs | IMPLEMENTED + TESTED + DEMONSTRABLE | `tests/report/`, fallback verified 5/5 on 2026-09-23 | Identity needs an out-of-band fingerprint |
| Graded report verdict | `VERIFIED`, `VERIFIED_WITH_LIMITATIONS`, `PARTIAL`, `FAILED_VERIFICATION`, with a reason for every downgrade; CLI, API and Audit screen | IMPLEMENTED + TESTED + DEMONSTRABLE | `tests/report/test_report_verdict.py`, `tests/api/test_report_verdict_api.py`, `ui/tests/verdict.test.ts`; fallback reads `VERIFIED_WITH_LIMITATIONS` | Exit code still follows `Result:`, not the verdict |
| Tamper demonstration | server-side copy, real verifier (`api/routes/audit.py:tamper_demo`) | IMPLEMENTED + TESTED + DEMONSTRABLE | `tests/api/test_tamper_demo.py` | none recorded |
| Merkle root and anchor receipt | in every report | IMPLEMENTED + TESTED + NOT YET DEMONSTRATED | `tests/api/test_report_anchor.py` | No external witness ships |
| Chain-of-custody timeline UI | Cases screen: the chain verdict, evidence, operations (with job state, historical-rehearsal marker and report status), reports, audit events | PARTIAL | `ui/src/screens/Cases.tsx`, `ui/tests/cases.test.ts`; browser `polish-2026-09-25/` (66 of 66, synthetic) | Not presented as one who/what/when timeline |

## D. Certificate

| Requirement | Capability | Status | Evidence | Limitation |
|---|---|---|---|---|
| Sanitization certificate | the signed erase report is the certificate: device, serial, capacity, method, rationale, verification, residual risk, limitations, tool version, chain status, signature; it names its category, one of FILE ERASE, ADDRESSABLE WHOLE-DRIVE CLEAR, DEVICE SANITIZE, CRYPTO ERASE, PHYSICAL DESTRUCTION ATTESTATION (`core/report/semantics.py`) | IMPLEMENTED + TESTED + DEMONSTRABLE | `core/report/render.py`, `tests/report/test_semantics.py`, `docs/compliance.md` (Sec. 4.6 / Appendix C mapping) | Signed with a local Ed25519 key, not a PKI. Label: "cryptographically integrity-protected", never "government-signed" |
| Verifier identity (second person) | none | UNSUPPORTED | none | Only the operator's local account is recorded |

## E. Safety of destructive operations

| Requirement | Capability | Status | Evidence | Limitation |
|---|---|---|---|---|
| Stable identity, independent serial sources | by-id path; `lsblk` vs sysfs serial cross-check | IMPLEMENTED + TESTED + DEMONSTRABLE (PHYSICAL preflight) | `scripts/media_benchmark.py`, preflight run 2026-09-23 | Both sources report what the firmware says |
| Mounted, root and system refusal | preflight and `core/device/guard.py` | IMPLEMENTED + TESTED + DEMONSTRABLE (PHYSICAL) | preflight refusal on the attached stick, 2026-09-23 | none recorded |
| Typed serial, acknowledgement, one-use authorization on every erase (no dry-run mode) | API and `media_benchmark.py write` | IMPLEMENTED + TESTED + DEMONSTRABLE | `tests/scripts/`, `tests/api/` | none recorded |
| Verified backup on another disk, hash and extent binding | `verify_backup`, re-run by `write_image`; in the app, `core/backup.py` binds source identity, image SHA-256 and chunk hashes | IMPLEMENTED + TESTED + NOT YET DEMONSTRATED | `tests/scripts/test_media_benchmark*.py`, `tests/restore/test_backup_record.py` | Nothing proves the backup is a copy of the device beyond its recorded identity and hashes |
| Authorized restore | `core/restore.py`, `/workflow/restore`, helper `run_restore`: target re-read, size/system/mounted refusal, typed serial, one-use restore authorization re-checked at the write seam, pre-write chunk verification, post-restore read-back hash verification; Linux, Windows (disk offline) and macOS (`/dev/rdiskN`) | IMPLEMENTED + TESTED + NOT YET DEMONSTRATED (IMPLEMENTED / UNVALIDATED on all three) | `tests/restore/`, `tests/api/test_restore_workflow.py` | Never run on a physical device. The benchmark harness still prints a manual `dd` command, also never run |
| No automatic sudo or unmount | no code path does either | IMPLEMENTED + TESTED + DEMONSTRABLE | refusal text | none recorded |
| Visible workflow state machine | `core/workflow.py`: eleven states, `derive()` with WHY BLOCKED and next action, `advance()` refuses illegal transitions; printed at the top of the benchmark `plan`; the Sanitize screen draws DISCOVERED → PREFLIGHT → BACKUP VERIFIED → HUMAN APPROVAL REQUIRED → PLAN READY → EXECUTING → VERIFYING → COMPLETE, the only path (there is no simulation path), with BLOCKED or FAILED and the reason (`ui/src/lib/workflowState.ts`) | IMPLEMENTED + TESTED + DEMONSTRABLE | `tests/test_workflow.py`, `tests/scripts/test_media_benchmark_boundary.py`, `ui/tests/workflowState.test.ts`, `tests/ui/test_workflow_vocabulary.py` (UI names = `core/workflow.py` names); browser `07`–`10` in `browser-2026-09-24/` | A model, not a gate: every destructive path re-checks its own gates and does not read it. A real whole-drive erase has a backup gate (the server verifies the image when the workflow opens; the helper re-checks it before the engine starts), and the benchmark write has its own. Browser checks used synthetic devices |
| Missing or stale device path in `media_benchmark.py` | every subcommand checks the path before any probe: a missing path or a dangling `/dev/disk/by-id` link is a structured refusal (`kind: unavailable`, exit 2), an `lsblk` failure is the same refusal, and any other I/O error is `kind: io`, exit 3, never a verdict; no other device is tried | IMPLEMENTED + TESTED + DEMONSTRABLE | `tests/scripts/test_media_benchmark_absent_device.py` (missing, stale by-id, `lsblk` failure, unparseable output, unrelated I/O error, I/O error during `write`, permission path preserved); `scripts/media_benchmark.py plan --device /dev/disk/by-id/usb-DOES_NOT_EXIST …` run 2026-09-24 | Scope is `media_benchmark.py`. The other harness scripts were not audited for this case in this wave |

## F. Simulation mode (removed 2026-09-28)

The product no longer has a simulation or dry-run mode: every operation runs
against the selected real device once its gates pass. The rows below are the
historical record of what existed; test doubles (fixture devices, recording
helpers, `testkit/fake_*.py`) remain as CI infrastructure and are never counted
as physical validation.

| Requirement | Capability | Status | Evidence | Limitation |
|---|---|---|---|---|
| Real-device workflow on a disposable device | [`docs/demo/runbook.md`](../demo/runbook.md) real-device procedure: discovery → preflight → identity → backup → plan → approval → final revalidation → real execution → verification → certificate | IMPLEMENTED / UNVALIDATED | `tests/api/test_sanitize_ui_chain.py`, `tests/erase/test_drive_loopback.py` (root-only), adapter doubles | One stick's run is not a device-class validation until recorded |
| *(historical)* Full workflow with no device | `scripts/demo_simulation.py`: DISCOVER → PREFLIGHT (a mounted medium BLOCKED by `core.device.guard` and `core.workflow.derive`) → PLAN (`select_method`) → SIMULATED SANITIZATION (`core.erase.drive.execute`, a real overwrite of a host file) → SIMULATED VERIFICATION (the same run's full read-back) → FORENSIC REPORT (`build_report`, graded) → CERTIFICATE (Ed25519, then a changed copy is rejected) | REMOVED 2026-09-28 (was IMPLEMENTED + TESTED + DEMONSTRABLE (SIMULATION)) | was `tests/scripts/test_demo_simulation.py` (every stage bannered, the blocked medium byte-identical, nothing under `/dev` opened, the engine refuses any target that is not its own file); run 2026-09-24 in 0.4 s | The media are host files. Two engine calls are substituted because a file cannot answer them (BLKGETSIZE64, the sysfs serial re-read), and the journey says so in its report. Capability is declared for the simulated medium, not probed. Terminal only, not a UI mode |
| *(historical)* Simulation label on screen | *SIMULATION / NO PHYSICAL DEVICE MODIFIED* on every screen showing a dry-run job, decided from the flag the server recorded; also on the Sanitize screen before a dry run starts. Replaced by the **REAL DEVICE** card | REMOVED 2026-09-28 | was `ui/tests/simulation.test.ts`, `ui/tests/workflowState.test.ts`; browser: File eraser dry run on the real API (`05`), Sanitize on fixtures (`07`, `09`) | The Sanitize dry run was browser-checked on fixture devices only; no real device was offered to the browser |

## G/H/I. Benchmarking, demo corpus, performance

| Requirement | Capability | Status | Evidence | Limitation |
|---|---|---|---|---|
| Precision, recall, false positives, corrupt recoveries | `testkit/benchmark.py`, `testkit/calibrate.py` | IMPLEMENTED + TESTED + DEMONSTRABLE (SYNTHETIC) | `docs/performance/benchmark.md`, `calibration-pooled.md` | Synthetic images only |
| Physical benchmark | `scripts/media_benchmark.py` | PARTIAL | preflight only; run blocked on the methodology decision (`methodology-open-decision.md`) and the gates in `physical-benchmark-checklist.md` | No result under the registered methodology exists. Three Phase B physical recovery passes on one stick are recorded separately in `hardware.md` and are not this benchmark |
| Deterministic corpus with ground truth | `testkit/generate_corpus.py`, `testkit/damage.py`, `testkit/fsimage.py` | IMPLEMENTED + TESTED + DEMONSTRABLE (SYNTHETIC) | `tests/testkit/` | Fragmented PNG/PDF cases are not reconstructable |
| Throughput and memory | 1 GiB and 7 GiB runs, peak RSS | IMPLEMENTED + TESTED + DEMONSTRABLE (SYNTHETIC) | `docs/validation/large-image.md` | Measured on one host |

## J. Cross-platform

See `docs/platform-support.md` for the full matrix.

| Requirement | Capability | Status | Evidence | Limitation |
|---|---|---|---|---|
| Whole-drive clear on Windows and macOS | `core/erase/blockclear.py` through each adapter; Windows needs an elevated process and an offline disk, macOS root and an unmounted external disk | IMPLEMENTED + TESTED, not physically validated (IMPLEMENTED / UNVALIDATED) | `tests/erase/test_blockclear.py`, `tests/platform/test_windows_engine.py`, `tests/platform/test_macos_engine.py` (adapter doubles); CI read-only native smoke | Internal Apple storage BLOCKED FOR SAFETY (Erase All Content and Settings recommended); a virtual or Storage Spaces disk is refused |
| Device sanitize on Windows and macOS | Windows ATA SANITIZE and NVMe Sanitize (block, crypto) when IDENTIFY reports them | HARDWARE-UNVERIFIED (DEVICE-DEPENDENT) | `tests/device/test_windows_native.py`, `tests/platform/test_windows_engine.py` | Windows ATA SECURITY ERASE NOT IMPLEMENTED; Windows NVMe Format PLATFORM-LIMITED; every macOS device sanitize PLATFORM-LIMITED |
| Raw physical-device and volume acquisition on Windows and macOS | `core/carve/win_source.py` (`GENERIC_READ` only, bound to disk number, serial and length), `core/carve/mac_source.py` (`/dev/rdiskN`, `O_RDONLY`) | IMPLEMENTED + TESTED, not physically validated (IMPLEMENTED / UNVALIDATED) | `tests/carve/test_platform_sources.py`, `tests/api/test_endpoints.py` | No software write block exists on either OS; the report says so and names a hardware write blocker as the control. Internal Apple storage is not offered |
| File erase on Linux, Windows, macOS | `core/erase/files.py` through each platform adapter | IMPLEMENTED + TESTED + DEMONSTRABLE (CI; Windows also PHYSICAL, 2026-09-27) | CI on all three (`docs/platform-support.md`); Windows physical: [`windows-hardware-2026-09-27-fixes/`](windows-hardware-2026-09-27-fixes/README.md) | Copy-on-write filesystems report NOT VERIFIABLE |
| Packages | Linux AppImage and portable, Windows and macOS builds | PARTIAL (Windows install also PHYSICAL, 2026-09-27) | CI build jobs (`scripts/build-*.sh`, `scripts/build-windows.ps1`); CI proves every backend the resolver names ships in each package (`tests/test_package_completeness.py`, `scripts/package_smoke.py`); Windows physical install: [`windows-hardware-2026-09-27-fixes/`](windows-hardware-2026-09-27-fixes/README.md) | Unsigned and not notarized; the build physically installed on 2026-09-27 predates the Windows block engines |

## K/L/M. UI, demo, judge questions

| Requirement | Capability | Status | Evidence | Limitation |
|---|---|---|---|---|
| Device card with capability and blocked reason | Devices and Sanitize screens; a locked row reads `BLOCKED · WHY BLOCKED:` and the reason, with the human remedy | IMPLEMENTED + TESTED + DEMONSTRABLE | `ui/src/screens/Devices.tsx`, `Sanitize.tsx`; browser `06-devices-fixture.png` | Browser-checked on fixture devices; the live host's devices were not offered to the browser |
| Landing screen with the workflows | Overview screen: Drive eraser, File & folder eraser and Recovery cards, each with the resolver's live state (the 2026-09-24 browser run showed an earlier four-card layout) | IMPLEMENTED + TESTED + DEMONSTRABLE | `ui/src/screens/Home.tsx`; browser `01-overview-case-open.png` on the real API | none recorded |
| Executive summary screen | six answers on the Overview: Secure Erasure, Evidence Recovery, Verification, Integrity, Safety, and Limitations led by what is not physically validated; historical rehearsal records never counted as erasures | IMPLEMENTED + TESTED + DEMONSTRABLE | `ui/tests/summary.test.ts`; browser: fits 1366 x 768 without scrolling (`01`) | The design-fact lines are fixed text backed by this matrix, not computed; the case lines are computed |
| Demo runbook | `docs/demo/runbook.md`; timed 4.5-minute order in `demo-evidence-index.md` | PARTIAL | automated technical rehearsal 2026-09-24 (every beat's command and screen ran) | Not rehearsed aloud by a presenter; the live physical-stick beats wait on the human methodology gate |
| Judge Q&A | `docs/demo/qa.md`, 29 questions, each traced to code or a record | DOCUMENTED | `docs/demo/qa.md` | Power loss is answered from design and tests; no real power cut has been recorded |
| Judge defense card | `docs/validation/judge-defense-card.md`: 34 adversarial questions with evidence and a population label each, seven one-line interruption answers, the timed spoken script | DOCUMENTED | the card; audit 2026-09-24 at `8e1777d` | Spoken and interruption rehearsals not yet done by a presenter; three answers (Q2, Q5, Q30) are marked NOT CURRENTLY PROVEN |

## N. Standards

| Requirement | Capability | Status | Evidence | Limitation |
|---|---|---|---|---|
| NIST SP 800-88 Rev. 2 vocabulary (Clear / Purge / Destroy) | every level, report and screen uses the three words; Rev. 1 was withdrawn 2025-09-26 | DOCUMENTED | `docs/compliance.md`, `CLAUDE.md`, report `method.standards` | Vocabulary and mapping only; no certification is claimed |
| IEEE 2883-2022, ISO/IEC 27040:2024 | mapped section by section | DOCUMENTED | `docs/compliance.md` | Mapped, not claimed as compliance |
| DoD 5220.22-M | legacy method offered by the engine with a warning; not offered in the UI | IMPLEMENTED + TESTED + NOT YET DEMONSTRATED | `docs/compliance.md`, `core/erase/drive.py`, `tests/erase/test_select_method.py` | No compliance claim; the UI deliberately has no method chooser |
