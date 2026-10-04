# Judge defense card

**Date:** first written 2026-09-24 at `8e1777d`; reconciled 2026-09-26 with the
release-hold remediation · **Code and packages at:** `76dde42` (see
[`release-report-2026-09-25.md`](release-report-2026-09-25.md)) · **Physical
validation as of that release: none** — every PHYSICALLY VALIDATED row below is a run
on 2026-09-05 or 2026-09-23 with an earlier build · Companion to
[`demo-evidence-index.md`](demo-evidence-index.md) and
[`feature-matrix.md`](feature-matrix.md), which stay the source of truth. If
this card and either of them disagree, they win and this card is wrong. For the
current per-platform capability state, the generated
[`capability-matrix.md`](capability-completion-2026-09-28/capability-matrix.md)
wins over all three.

## Update, 2026-09-28: what is implemented now, and what is physically validated

This section supersedes every current-state claim below about Windows,
macOS, backup restoration and HPA/DCO. The rows keep their evidence; where a
row still says "not implemented" for something listed here, this section is
right and the row is out of date.

**Physically validated, by device class** (the only entries in
`core/platform/validation_record.json`): Linux device discovery, whole-drive
clear and raw acquisition on one TOSHIBA TransMemory USB stick (`usb-flash`,
2026-09-05, `hardware.md`); Windows device discovery on a USB stick
(`usb-flash`, 2026-09-27); Windows file erase on the host system disk (device
class not recorded, 2026-09-27). Nothing else.

**Implemented, not physically validated** (IMPLEMENTED / UNVALIDATED or
DEVICE-DEPENDENT; synthetic and adapter-double tests only): Windows whole-drive
clear over `\\.\PhysicalDriveN` (the disk must be taken offline first,
Devices > Prepare); Windows raw physical and volume acquisition
(`GENERIC_READ` only; no software write block exists on Windows, and the report
says so); Windows ATA SANITIZE and NVMe Sanitize, offered only when the
drive's IDENTIFY reports them; macOS whole-drive clear and raw acquisition of
external disks through `/dev/rdiskN`; the guarded HPA/DCO workflow on Linux and
Windows; backup verification and authorized restore with post-restore hash
verification on all three platforms; every firmware Purge on Linux; macOS
discovery and file erase.

**Genuine limits:** Windows ATA SECURITY ERASE UNIT is NOT IMPLEMENTED; Windows
NVMe Format is PLATFORM-LIMITED; macOS device sanitize and HPA/DCO are
PLATFORM-LIMITED; internal Apple storage is never raw-written or imaged (the
recommended action is Erase All Content and Settings); free-space wipe is NOT
IMPLEMENTED on Windows and macOS. The registered physical benchmark is still
BLOCKED at gate 1. What changed and how a row becomes validated:
[`capability-completion-2026-09-28/README.md`](capability-completion-2026-09-28/README.md).

## Update, 2026-09-27: a separate physical Windows run, and two defects it found

This section supersedes every "none" or "nothing" said about physical
validation below; it does not change any row's evidence or wording, which
stays as it was written for the `76dde42` release. A separate, later run
installed the packaged app on a physical Windows 11 machine: device
discovery and the mounted-device refusal against a real USB stick, and a
file/folder erase → verify → certificate on the host system disk (the stick
was not written), 23 of 23 packaged checks. That first run, at commit `2d00526`, is preserved at
[`windows-hardware-2026-09-27/`](windows-hardware-2026-09-27/README.md).

Validating it end to end found two real defects no prior CI run or packaged
smoke test had caught: (1) the installed app crashed on a genuine
no-console launch — the actual double-click/Start-menu path, which
`package_smoke.py` never exercises because it redirects stdio; and (2) once
fixed, `/jobs/carve` through the installed exe failed outright, because the
carve engine's signature table (`testkit/signatures.yaml`) was never bundled
into any packaged build, on any platform — `package_smoke.py` has never
called `/jobs/carve` either. Both fixed (`ba66fbe`, `437081e`); acquire,
carve, media map and a Destroy attestation now run correctly through the
installed exe, still only against a synthetic image. At that build
(`437081e`) Windows whole-drive clear and raw physical-device acquisition did
not exist; both are implemented now (update above) and neither has run on a
physical disk. Full detail:
[`windows-hardware-2026-09-27-fixes/`](windows-hardware-2026-09-27-fixes/README.md).
If asked "is that real hardware?" for anything Windows, this is now the
answer for discovery, the mounted refusal, and file/folder erase; everything
else below about "no physical run this release" still describes the `76dde42`
build accurately and macOS still has no physical run.

Rules for the presenter:

1. Answer in one or two sentences, then point at the evidence. Do not argue.
2. Say the population label out loud. Never let a synthetic, CI or
   test-double number stand in for a physical one.
3. If a row says **NOT CURRENTLY PROVEN**, say exactly that. Do not improvise
   a better answer.

## Evidence labels

These labels are used on every row below and in the final slide. They never
merge. The app itself shows the resolver's words (SUPPORTED, IMPLEMENTED /
UNVALIDATED, DEVICE-DEPENDENT, PLATFORM-LIMITED, REQUIRES PRIVILEGE, BLOCKED FOR
SAFETY, NOT IMPLEMENTED); in the app, SUPPORTED means physically validated for
that device class and no other.

| Label | Meaning | What is in it |
|---|---|---|
| **PHYSICALLY VALIDATED** | Ran on a real device of a named class, recorded with the build of that date | Linux, `usb-flash` (one Toshiba TransMemory USB stick, 7.76 GB): three Phase A overwrite Clear runs (the third clean, 2026-09-05), a power-cycle re-verification, three Phase B recovery passes, discovery, the mounted-device refusal (2026-09-23). None was repeated for the current release. Windows, 2026-09-27 at `437081e`: packaged install, device discovery and mounted-device refusal against a real USB stick (`usb-flash`), file/folder erase → verify → certificate on real NTFS on the host system disk (class not recorded) (`windows-hardware-2026-09-27-fixes/`) |
| **SYNTHETICALLY VALIDATED** | Generated images with a ground-truth manifest, on host storage | Recovery benchmark and calibration, PNG/JPEG bifragment reassembly, 1 GiB and 7 GiB runs, fuzz |
| **TEST DOUBLE / FIXTURE** | Fake devices, recording helpers, adapter doubles and fixture servers that keep CI from touching a disk. Test infrastructure, never a product mode and never physical validation | the Sanitize screen browser checks (fixture devices); `tests/api/` (recording helper); `testkit/fake_windows.py`, `testkit/fake_macos.py` |
| **DOCUMENTED** | A written mapping or procedure, not an executed result | NIST SP 800-88 Rev. 2 / IEEE 2883 / ISO 27040 mapping, runbook, this card |
| **HARDWARE-UNVERIFIED** (implemented, not physically validated; the app says IMPLEMENTED / UNVALIDATED or DEVICE-DEPENDENT) | Software path tested with fixtures or adapter doubles, never run on a real device | Firmware Purge on any drive (ATA SANITIZE, ATA SECURITY ERASE UNIT, NVMe Sanitize, NVMe Format, crypto erase on Linux; ATA SANITIZE and NVMe Sanitize on Windows), HPA/DCO modification (Linux, Windows), Windows and macOS whole-drive clear, Windows and macOS raw acquisition, backup restore on every platform, the registered physical recovery benchmark (BLOCKED at gate 1), removing a real trace from a live desktop, any macOS physical device |
| **PLATFORM-LIMITED** | The operating system offers no path to the mechanism; refused with the reason | Windows NVMe Format; every device sanitize and HPA/DCO on macOS |
| **NOT IMPLEMENTED** | The OS could do it; this build has no code for it; refused, and said so | Windows ATA SECURITY ERASE UNIT; free-space wipe on Windows and macOS |

CI-validated (virtual disks on hosted runners) is its own population. It is
not physical validation.

## Interruptions: one-line answers

| They say | Say | Show |
|---|---|---|
| "Why?" | Answer the reason for the thing on screen in one sentence, then go back to the beat. If there is no reason on record, say "that is a design choice, not a measured one." | the row below for that beat |
| "What proves that?" | Name the test file or the recorded run. | the Evidence column of the row below |
| "Is that real hardware?" | Physical only for Linux overwrite Clear, discovery and raw acquisition with recovery passes on one USB stick (2026-09-05) and the mounted-device refusal (2026-09-23), all with earlier builds, and for Windows discovery on a USB stick and file erase on the host disk (2026-09-27). Everything else on screen is synthetic, adapter-double or fixture, and it is labelled. The product has no simulation mode: an erase on screen is a real erase of the disposable test stick. | Overview, LIMITATIONS: NOT PHYSICALLY VALIDATED column; `hardware.md` run table |
| "Can you demonstrate it?" | Check the CAN DEMONSTRATE LIVE? column in `demo-evidence-index.md`. YES: run it. FIXTURE ONLY: run it and say "fixture devices". Otherwise: "not live; here is the recorded artifact." | `demo-evidence-index.md` |
| "Does it work on Windows / macOS?" | Whole-drive clear, raw acquisition and restore are implemented on both and tested against adapter doubles only; none has run on a physical disk. Windows ATA SANITIZE and NVMe Sanitize are offered only when the drive reports them; Windows ATA SECURITY ERASE UNIT is NOT IMPLEMENTED and NVMe Format is PLATFORM-LIMITED. macOS has no device sanitize or HPA path (PLATFORM-LIMITED) and never raw-writes internal Apple storage: use Erase All Content and Settings. Free-space wipe is NOT IMPLEMENTED on either. | Platform screen; [`capability-matrix.md`](capability-completion-2026-09-28/capability-matrix.md) |
| "What happens if this fails?" | The operation stops, the job is recorded as failed in the ledger, and no sanitization level or certificate is issued. It never falls back to a weaker method or another device. | Q5, Q8, Q30 below |
| "How is this different from PhotoRec?" | PhotoRec returns files. Sanctum also returns why it believes each one: six named evidence components, a bucket calibrated against ground truth, and a split file rebuilt only when its own bytes prove the join. Every run is written to a signed, hash-chained record. | Recovery screen score breakdown; `scripts/demo_fragmented.py` |
| "How is this different from formatting the drive?" | A format rewrites filesystem metadata and leaves the data. On the physical stick, after a FAT32 quick format, carving still recovered all 10 of the 10 carvable planted files byte-exact. Sanitization overwrites or purges every addressable sector, verifies it by reading it back, and says what it could not reach. | `hardware.md` Phase B, `results-20260905T082656Z` |

## Adversarial audit: 37 questions

Status is one of the labels above, or **NOT CURRENTLY PROVEN**. Paths
are relative to the repository root.

### Safety

| # | Question | Answer | Evidence | Status |
|---|---|---|---|---|
| 1 | How can the wrong disk be selected? | The operator must type the serial of the selected disk. A mismatch refuses. The system disk and any disk with a mounted filesystem are refused before that. | `core/device/guard.py:assert_erasable`, `assert_serial_confirmed`; `tests/device/test_guard.py`; Devices screen WHY BLOCKED (`browser-2026-09-24/06`) | SYNTHETICALLY VALIDATED (unit tests). Mounted refusal PHYSICALLY VALIDATED. The typed-serial gate was not reached on the physical host: `qa.md` §14 |
| 2 | What prevents `/dev/sda` changing to another device? | Three re-reads. The API gate compares serial, model and size with what was approved. The helper does it again at the write seam, with plan and backup, before the engine starts. The engine then re-reads the serial and the `/dev/disk/by-id` link and raises `DeviceVanished` on a difference. On Windows the open `\\.\PhysicalDriveN` handle is itself asked its disk number, serial and length before any read or write. On macOS no ioctl returns a serial, so the serial is re-read from `system_profiler` just before `/dev/rdiskN` is opened and the handle is bound by size; that window is documented in the security review, not closed. | `api/authorization.py`, `helper/authorization.py`, `core/erase/drive.py:_reread_serial`; `tests/helper/test_write_seam_authorization.py`, `tests/api/test_write_seam_integration.py`; `tests/erase/test_drive_loopback.py::test_serial_swap_between_confirmation_and_execution_is_caught`; `core/device/win/disk.py`, `core/device/mac/rawdisk.py` | API gate and helper seam: SYNTHETICALLY VALIDATED, including a change made after the API gate passed. Windows and macOS binding: adapter doubles only. Engine re-read: the test needs root and a loop device and is **skipped** in the unprivileged suite, NOT CURRENTLY PROVEN. Race freedom between the helper's check and the first write is not claimed |
| 3 | What happens if the filesystem is mounted? | Refused, with the mount point named. No automatic unmount. The workflow state reads BLOCKED with WHY BLOCKED. | `core/device/guard.py`; `tests/device/test_guard.py`; `tests/scripts/test_media_benchmark_preflight.py`; `qa.md` §24 | PHYSICALLY VALIDATED (refusal on the stick, 2026-09-23; `/sys/block/sda/stat` unchanged, so no I/O) |
| 4 | What happens if the serial does not match? | `ConfirmationMismatch` with the remediation "Nothing has been modified". The erase does not start. | `core/device/guard.py:assert_serial_confirmed`; `tests/device/test_guard.py`, `tests/helper/test_daemon.py`; Sanitize screen: the approve and erase buttons stay disabled until the typed serial matches, and a mismatch the server sees is a structured REFUSED (`browser-2026-09-25/05`) | SYNTHETICALLY VALIDATED; UI on fixture devices |
| 5 | What happens if the device disappears? | Before the job: `DeviceVanished`, nothing written. In the benchmark harness a missing or stale by-id path is a structured refusal, exit 2, and no other device is tried. During a write: the non-EIO OS error ends the job as `failed`, recorded by the durable job outcome. No verification runs, so no level and no certificate. | `core/device/enumerate.py`, `tests/device/test_enumerate.py::test_get_device_raises_device_vanished`; `tests/scripts/test_media_benchmark_absent_device.py`; `api/jobs.py` (failed state), `api/durable.py` | Before the job: SYNTHETICALLY VALIDATED. Removal **during** a write: no test injects it, and no physical unplug is recorded. NOT CURRENTLY PROVEN |
| 6 | What happens if backup verification fails? | A real whole-drive erase is refused: the server will not open the workflow without a backup image it has hashed and sized to cover the device, and the helper refuses at the write seam if the image changed. The benchmark write refuses too: it re-runs its own backup verification straight before writing, and writes only if `sufficient_for_restoring_the_modified_region` is true. | `scripts/media_benchmark.py:verify_backup`, `write_image`; `tests/scripts/test_media_benchmark_boundary.py`; `qa.md` §25 | SYNTHETICALLY VALIDATED. The benchmark write re-verifies its own backup; a real whole-drive erase, since 2026-09-25, needs a backup image the server hashed and sized, bound by size, mtime, ctime and inode and re-checked by the helper (`tests/test_authorization_binding.py`). Neither proves the image is a copy of the device. Authorized restore with post-restore hash verification is implemented (`core/restore.py`, `/workflow/restore`) and has never been run on a physical device: HARDWARE-UNVERIFIED |
| 7 | What happens if permission is denied? | A privilege failure during probing raises and says to run the privileged helper. It is never reported as "unsupported", so a method is never downgraded because the tool could not see the device. | `core/device/capabilities.py`; `tests/device/test_capabilities.py::test_permission_error_raises_rather_than_reporting_unsupported`, `::test_usb_bridge_permission_error_still_raises` | SYNTHETICALLY VALIDATED |
| 8 | What happens if I/O fails halfway through? | An EIO span is retried block by block. Unwritable blocks are recorded with their errno, the wipe continues, and verification then fails for that region. Any other I/O error stops the job as failed. | `core/erase/drive.py:_write_block_by_block`; `tests/erase/test_overwrite_file.py::test_eio_is_recorded_and_the_wipe_continues`, `::test_eio_region_makes_verification_fail`; `tests/erase/test_residual_risk.py` | SYNTHETICALLY VALIDATED (injected errors). No physical bad-sector run recorded |
| 9 | Can the application auto-unmount? | No erase ever unmounts. On Linux no code path calls `umount` or `udisksctl`; the refusal tells a human to unmount. On Windows and macOS a separate, explicit Prepare step (`POST /devices/prepare`: take the disk offline, non-persistently, or `diskutil unmountDisk`) exists: the volumes it affects shown first, typed serial, system and internal disks refused, ledgered, never part of an erase. | `core/device/guard.py`; `api/routes/devices.py`; refusal text in `qa.md` §24; Overview SAFETY column | SYNTHETICALLY VALIDATED; Linux refusal PHYSICALLY VALIDATED; Prepare adapter doubles only |
| 10 | Can it silently escalate privileges? | No. On Linux the UI and API run unprivileged and raw device work goes through a separate helper that a human starts with `sudo`, over a static allowlist of typed operations. That helper is Linux-only. On Windows and macOS raw work runs in the Sanctum process itself: a human starts it with Run as administrator (Windows) or `sudo` (macOS), otherwise raw work reads REQUIRES PRIVILEGE. That is a wider privileged surface than the Linux split, and the security review says so. No code calls `sudo` or `pkexec` or requests elevation. | `helper/__main__.py`, `helper/daemon.py`; `docs/privilege-boundary.md`; `tests/helper/`; status strip `PRIVILEGE: Standard user` | SYNTHETICALLY VALIDATED; DOCUMENTED |
| 11 | What requires human approval before execution? | Whole-drive erase (every one is real; there is no dry-run mode): a backup image, an explicit acknowledgement with the typed serial (recorded as the approval, against the OS account; the API does not authenticate a person), then the typed serial again to spend the one-use authorization. Benchmark write: a recorded methodology decision, identity reconfirmation, manual unmount, a verified backup, a reviewed plan, and running `write` with the acknowledgement flag. | `api/routes/models.py` (no rehearsal switch; `dry_run`/`simulation` rejected with 422); `api/routes/workflow.py`; `core/workflow.py` (HUMAN_APPROVAL_REQUIRED); `physical-benchmark-checklist.md` | SYNTHETICALLY VALIDATED; UI on fixture devices (`browser-2026-09-25/`) |

### Recovery

| # | Question | Answer | Evidence | Status |
|---|---|---|---|---|
| 12 | How does recovery differ from ordinary signature carving? | Signatures only find candidates. Each candidate is then bounded by the format's own length fields, decoded, scored on named evidence, de-duplicated by SHA-256, and cross-checked with surviving filesystem metadata where it exists. | `core/carve/structure.py`, `validate.py`, `score.py`, `classify.py`; `docs/supported-formats.md` | SYNTHETICALLY VALIDATED; Phase B passes PHYSICALLY VALIDATED |
| 13 | How is fragmentation detected? | A candidate whose structure parse does not close is flagged `possibly_fragmented`. | `core/models.py`; `tests/carve/` | SYNTHETICALLY VALIDATED |
| 14 | How is a candidate validated? | A real decoder reads it (valid, truncated, corrupt, or no decoder), PNG chunk CRCs are checked, and entropy is compared with the format. A reassembled PNG must pass every chunk CRC-32 and a zlib stream that inflates to exactly the header size. A reassembled JPEG must pass an exact Huffman scan count. | `core/carve/validate.py`, `core/carve/fragmentation.py`; `tests/carve/test_validate_malformed.py`, `tests/carve/signature/test_png_fragmentation.py` | SYNTHETICALLY VALIDATED |
| 15 | What does the evidence score mean? | A sum of named components in basis points: header 2000, exact length 1500, decoder 4000, entropy 1000, filesystem metadata 1500, no overlap 500, with a reassembly hold that keeps a rebuilt object at 7999. HIGH is 8000 or more. | `core/carve/score.py`; Recovery screen score breakdown (`browser-2026-09-24/03`); `scripts/demo_fragmented.py` `why` line | SYNTHETICALLY VALIDATED |
| 16 | Why is it not a probability? | The components sum to 10,500 and are clamped at 10,000, so the top of the scale is a clamp, not a certainty. What was measured is a bucket's precision on a population: 104 of 104 HIGH byte-exact over eight synthetic seeds. That is not a rate for seized media. | `core/carve/score.py` docstring; `docs/performance/calibration-pooled.md`; `tests/report/test_confidence_is_not_a_probability.py`, `tests/ui/test_no_percent_on_evidence_score.py` | SYNTHETICALLY VALIDATED |
| 17 | How are false positives handled? | They are measured against ground truth and reported per bucket. Weights were moved only where the calibration showed it. A footer-bound defect that let 39 wrong PDFs into HIGH on the 7 GiB run was found and fixed (247 of 247 HIGH after). 0 of 800 deliberately wrong PNG joins were accepted. | `docs/performance/calibration.md`; `docs/validation/large-image.md`; `docs/validation/png-reassembly.md`; `tests/carve/signature/test_footer_bound.py` | SYNTHETICALLY VALIDATED |
| 18 | What is proven only on synthetic data? | Recall and precision figures, calibration weights, bifragment reassembly, and the 1 GiB and 7 GiB throughput. The registered physical recovery benchmark has not been run. | `docs/performance/benchmark.md` (states SYNTHETIC in its first paragraph); `methodology-open-decision.md` | SYNTHETICALLY VALIDATED; physical benchmark HARDWARE-UNVERIFIED |

### Integrity

| # | Question | Answer | Evidence | Status |
|---|---|---|---|---|
| 19 | How do you detect a changed forensic report? | `verify-report` runs five checks: Ed25519 signature over canonical JSON, key fingerprint against the ledger genesis, the chain excerpt inside the report, the store chain, and the blobs. One changed field fails verification. | `core/report/verify_report.py`; `tests/report/`; `tests/api/test_tamper_demo.py`; Audit screen *Tamper a scratch copy* (`browser-2026-09-24/04`) | SYNTHETICALLY VALIDATED; also run against the physical-run report (`hardware.md` A.7) |
| 20 | How do the ledger links work? | Entry N holds the SHA-256 of entry N-1 over canonical JSON. A torn last line is `INCOMPLETE_TAIL`, not `BROKEN`, and every earlier entry still verifies. | `core/ledger/chain.py`; `tests/ledger/test_chain.py` | SYNTHETICALLY VALIDATED |
| 21 | What does the Ed25519 signature prove? | That whoever held this private key signed exactly these bytes, and that the bytes have not changed since. | `core/report/sign.py` docstring; `tests/report/test_sign.py` | SYNTHETICALLY VALIDATED |
| 22 | What does it NOT prove? | Who signed it. The public key is embedded, so identity needs the fingerprint from another channel. The key is local, not PKI or government-issued. Someone with write access to the whole state directory can rebuild the chain unless an external anchor is configured, and none is by default. | `core/report/sign.py`; `docs/limitations.md`; Overview INTEGRITY column ("proves the report was not altered, not who signed it") | DOCUMENTED |
| 23 | What is in the certificate? | The category of what was done (FILE ERASE, ADDRESSABLE WHOLE-DRIVE CLEAR, DEVICE SANITIZE, CRYPTO ERASE or PHYSICAL DESTRUCTION ATTESTATION, `core/report/semantics.py`), then the signed erase report: case identity, device identity (model, serial, by-id path, capacity, block sizes), method with justification and probed capability, hidden areas, verification, residual risk, limitations, audit-trail excerpt, tool version, key fingerprint, signature. | `core/report/render.py:build_report`; `docs/demo/fallback/demo-erase.forensic.json`; `docs/validation/results-20260905T033655Z/reports/HW-VALIDATION.forensic.json` (physical run); `docs/compliance.md` | SYNTHETICALLY VALIDATED; the HW-VALIDATION report is from the PHYSICALLY VALIDATED run |

### Sanitization

| # | Question | Answer | Evidence | Status |
|---|---|---|---|---|
| 24 | How is the method selected? | From probed capability: `hdparm -I`, NVMe Identify, `sedutil-cli`, sysfs. The strongest mechanism the device reports is chosen, with the justification in the report. If the requested level cannot be reached the job is NOT AUTHORIZED; it never silently downgrades. The UI has no method chooser. | `core/device/capabilities.py`, `core/erase/drive.py:select_method`; `tests/erase/test_select_method.py`, `tests/erase/test_erase_preview.py`; report `method.justification` | SYNTHETICALLY VALIDATED |
| 25 | What happens on SSD/NVMe/flash? | Purge only through the device's own firmware (sanitize, crypto erase). Host overwrite on flash is at most Clear, and every flash report says overwrite cannot reach remapped or over-provisioned blocks. A write calibration catches controllers that fake zero writes. | `core/device/capabilities.py:purge_mechanisms`, `recommend_method`; `tests/device/test_purge_by_device_class.py`; `core/erase/calibrate.py`; `core/platform/base.py:FLASH_LIMITATION` | USB flash overwrite Clear PHYSICALLY VALIDATED; firmware Purge HARDWARE-UNVERIFIED |
| 26 | What is validated on physical hardware? | Overwrite Clear with read-back verification on one USB flash stick, including detection of zero-write elision (zero fill acknowledged 3.25 to 3.6 times faster than the medium programs), a power-cycle re-verification, three recovery passes, and the mounted-device refusal. | `docs/validation/hardware.md`; `results-20260905T033655Z` | PHYSICALLY VALIDATED (one device, one model, 2026-09-05 and 2026-09-23, earlier builds; not re-run for this release) |
| 27 | What is still firmware-unverified? | Every device sanitize: on Linux ATA SANITIZE, ATA SECURITY ERASE UNIT, NVMe Sanitize and Format, SED crypto erase; on Windows ATA SANITIZE and NVMe Sanitize. HPA/DCO modification on Linux and Windows. Selected and dispatched in fixture and adapter-double tests only; each is DEVICE-DEPENDENT and offered only when the drive reports it. | `tests/erase/`, `tests/device/`; [`capability-matrix.md`](capability-completion-2026-09-28/capability-matrix.md) | HARDWARE-UNVERIFIED |
| 28 | What if the device reports misleading capacity? | HPA and DCO are detected by comparing accessible and native max sectors. A nonsense reading from a USB bridge is discarded and recorded as "no determination", after it once produced a 512-byte "erase". The engine erases no less than the kernel's `BLKGETSIZE64`. A controller that lies consistently to every read cannot be caught from the host, and the report says so. | `core/device/hidden_areas.py`; `tests/device/test_hidden_areas.py`; `core/erase/drive.py` (kernel size floor); `qa.md` §23; `hardware.md` run 1 | Bridge discard PHYSICALLY VALIDATED (on the stick, 2026-09-05: the probe was skipped behind the USB bridge, so no hidden area was measured or unlocked); HPA/DCO detection and unlock on a drive that has a hidden area HARDWARE-UNVERIFIED |
| 29 | How are HPA/DCO limitations handled? | Detected and reported. An ordinary erase never changes the HPA: it erases the accessible range and names the hidden byte count in its limitations. Changing the HPA is a separate guarded workflow on Linux and Windows (volatile SET MAX by default, typed serial, read-back); DCO is never modified. It needs ATA pass-through, which most USB bridges block; on macOS it is PLATFORM-LIMITED. When it cannot be probed, the report and the verdict (`VERIFIED_WITH_LIMITATIONS`) say so. | `core/device/hidden_areas.py`, `core/device/hidden_area_workflow.py`; `tests/erase/test_hidden_area_phases.py`; `qa.md` §29 | Detection SYNTHETICALLY VALIDATED; HPA change HARDWARE-UNVERIFIED |
| 30 | What happens after power loss? | The ledger survives a torn write (`INCOMPLETE_TAIL`). An overwrite resumes from the last ledgered checkpoint. A firmware method restarts from the beginning. No certificate for a job that did not finish and verify. | `core/ledger/chain.py`; `tests/api/test_resume.py`; `tests/erase/test_cancelled_erase.py`; `qa.md` §22 | SYNTHETICALLY VALIDATED (cancel and torn tail). A real power cut during an erase: NOT CURRENTLY PROVEN. The power-cycle in `hardware.md` was after the erase finished, not during it |

### Added 2026-09-25: traces, Destroy, the media map

| # | Question | Answer | Evidence | Status |
|---|---|---|---|---|
| 35 | The file is erased, but its thumbnail and its recent-files entry are still there. | Not any more. After a file erase the sweep finds the thumbnail named by the MD5 of the file's URI, the recent-files entry, and older copies in the Trash or Recycle Bin, and removes the ones tied to the path on evidence. A same-name file in the macOS Trash is reported, not removed. Each report lists what was searched and what was not. | `core/erase/traces.py`; `tests/erase/files/test_trace_sweep.py` (31 tests, synthetic homes); report section 6; `windows-hardware-2026-09-27-fixes/` §4 | SYNTHETICALLY VALIDATED. Enumeration also ran on a physical Windows 11 desktop (2026-09-27) and found nothing to remove; removing a real desktop trace not validated |
| 36 | Where is Destroy? | Destroy is physical: a shredder does it and no software can, or can watch it. Sanctum records what the people who did it attest, chains it and signs it, and the record says the tool observed nothing and did not authenticate the names. | `core/destroy.py`; `tests/test_destroy.py`, `tests/api/test_destroy_record_api.py`; Devices screen, *Record a physical destruction* | SYNTHETICALLY VALIDATED (the record, not a destruction) |
| 37 | What does "intelligent carving" mean here? | Three things you can check: every candidate's score is six named evidence components; a split JPEG or PNG is rebuilt only when its own bytes prove the join; and the media map shows, before carving, where the image is zeroed, filled, text or high-entropy and where file headers sit. The map does not identify content, and says so. | `core/carve/score.py`, `core/carve/fragmentation.py`, `core/carve/mediamap.py`; `tests/carve/test_mediamap.py` | SYNTHETICALLY VALIDATED |

### Evidence

| # | Question | Answer | Evidence | Status |
|---|---|---|---|---|
| 31 | Which benchmark results are synthetic? | The recovery benchmark against PhotoRec and Foremost (40 images), pooled calibration (8 seeds), PNG reassembly, 1 GiB and 7 GiB runs, fuzz (66,000 cases). | `docs/performance/benchmark.md`, `calibration-pooled.md`; `docs/validation/png-reassembly.md`, `large-image.md`, `fuzz.md` | SYNTHETICALLY VALIDATED |
| 32 | Which are physical? | Linux, `usb-flash`: Phase A (three runs, third clean) and Phase B (FAT32 delete 456/456, exFAT delete 460/460, FAT32 quick format 10/10 carvable) on one USB stick, 2026-09-05; mounted refusal 2026-09-23. Windows, 2026-09-27: discovery on a USB stick, file erase on the host disk. | `docs/validation/hardware.md`; `results-20260905T*`; `windows-hardware-2026-09-27-fixes/` | PHYSICALLY VALIDATED |
| 33 | Which are documentation-only? | Standards mapping (NIST SP 800-88 Rev. 2, IEEE 2883, ISO/IEC 27040), the judge Q&A, the runbook, this card. | `docs/compliance.md`, `docs/demo/qa.md` | DOCUMENTED |
| 34 | Which are still unverified? | Implemented, not physically validated: firmware Purge on any drive, HPA/DCO modification, Windows and macOS whole-drive clear and raw acquisition, backup restore, the registered physical recovery benchmark (BLOCKED at gate 1), a real power cut, device removal mid-write, removing a real trace from a live desktop, macOS on physical devices. PLATFORM-LIMITED: Windows NVMe Format, macOS device sanitize and HPA/DCO. Not implemented: Windows ATA SECURITY ERASE UNIT, free-space wipe on Windows and macOS (each refused, and said so). | [`capability-matrix.md`](capability-completion-2026-09-28/capability-matrix.md); `feature-matrix.md`; `demo-evidence-index.md` "What must not be said"; `docs/validation/hardware-platform-matrix.md` | HARDWARE-UNVERIFIED / NOT CURRENTLY PROVEN |

## What Sanctum does that the presentation is built on

Stated as facts about this tool, with evidence. No comparison or ranking is
claimed.

| Property | Evidence | Label |
|---|---|---|
| Device-aware destructive safety: method from probed capability, never downgraded | Q24 | SYNTHETICALLY VALIDATED |
| Serial and by-id identity binding, re-read before execution | Q1, Q2 | SYNTHETICALLY VALIDATED (re-read test root-only) |
| Backup gate, re-verified by the write itself | Q6 | SYNTHETICALLY VALIDATED |
| Human approval gate: backup image, acknowledgement and typed serial, one-use server-issued authorization, on every erase | Q4, Q11; `browser-2026-09-25/` | SYNTHETICALLY VALIDATED; UI on fixtures |
| Authorization re-checked by the privileged helper at the write seam | Q2; `tests/helper/test_write_seam_authorization.py` | SYNTHETICALLY VALIDATED; race freedom not claimed |
| Evidence score with named components, not a probability | Q15, Q16 | SYNTHETICALLY VALIDATED |
| Bifragment recovery (PNG, baseline JPEG) accepted only when the bytes prove the join | Q14, Q17 | SYNTHETICALLY VALIDATED |
| Tamper-evident hash-chained ledger | Q20 | SYNTHETICALLY VALIDATED |
| Ed25519-signed reports with a graded verdict | Q19, Q21 | SYNTHETICALLY VALIDATED |
| Real-device journey from discovery to certificate on a disposable test stick | [`docs/demo/runbook.md`](../demo/runbook.md) real-device procedure; engine path in loopback and adapter-double tests | IMPLEMENTED / UNVALIDATED until a run is recorded |
| Reproducible benchmark infrastructure with seeds and manifests | `testkit/benchmark.py`, `testkit/calibrate.py`, `testkit/generate_corpus.py` | SYNTHETICALLY VALIDATED |
| Explicit population labels on every result | this card; `feature-matrix.md`; Overview LIMITATIONS column | DOCUMENTED |
| Zero-write elision detection on real flash | Q26 | PHYSICALLY VALIDATED |

## Spoken script, 4:30

Word counts are measured from the text below. At a natural 130 words per
minute with pauses for the screen, the target is no more than about 85% of
each window spent speaking.

| Window | Say | Show | Words | At 130 wpm |
|---|---|---|---:|---:|
| 0:00–0:30 | "Sanctum does three things. It recovers evidence from an image without ever writing to it. It erases a drive only with a method the drive itself reports it supports. And it signs a tamper-evident record of both. This summary shows what is proven, and on the right, what is not yet physically validated." | Overview | 53 | 24 s |
| 0:30–1:00 | "Every device shows its serial and what it can do. This one has a mounted filesystem, so it is blocked, and the tool tells a human to unmount it. It never unmounts or escalates on its own. A missing device path is refused, and no other device is substituted." | Devices; then the `media_benchmark.py plan` refusal | 49 | 23 s |
| 1:00–1:45 | "This is a real device, and the card says so: our disposable test stick, its serial, size, the method the engine chose and how it will be read back. There is no rehearsal mode. We give a backup, approve with the typed serial, and start the erase. It runs in the background." | Sanitize: REAL DEVICE card, approval dialog, progress | 52 | 24 s |
| 1:45–2:30 | "Synthetic image, known ground truth. These two files were split in two pieces. We rebuild a split file only when its own bytes prove the join: every PNG chunk checksum and an exact decompressed length. Both match ground truth, and both are held below HIGH on purpose. The score is a sum of named evidence, not a probability." | `scripts/demo_fragmented.py`; Recovery score breakdown | 58 | 27 s |
| 2:30–3:15 | "Every operation appends to a hash chain. Each entry holds the hash of the one before. The report is signed with Ed25519, and five independent checks pass. Watch: we change one byte in a copy, and the chain breaks at that entry. The signature proves the report was not altered. It does not prove who signed it, and we say that." | Audit: Verify, Tamper a scratch copy, report panel | 61 | 28 s |
| 3:15–4:00 | "Sanitization is a state machine, and every erase is real, so every gate runs every time. A human approves with the device serial, the server issues a one-use authorization, and the process that writes re-reads the device first. Here is the stick's erase finishing: read back, and a certificate." | Sanitize: workflow strip, verification panel, certificate | 49 | 23 s |
| 4:00–4:30 | "What is proven where. On a real USB stick: overwrite Clear, including catching a controller that fakes zero writes, and recovery passes. On synthetic images: the benchmark and calibration. Implemented but not yet validated on hardware: firmware Purge, HPA changes, restore, Windows and macOS whole-drive clear, and our registered physical benchmark." | Overview LIMITATIONS column; `benchmark.md` | 51 | 24 s |
| **Total** | | | **373** | **2:53** |

Spoken time is about 2:53, which leaves about 1:37 across seven beats for
screen changes, commands and one interruption. That fits under 4:30 without
rushing, **on paper**. It has not been timed aloud; see the rehearsal status
below.

## Rehearsal status

| Item | Status |
|---|---|
| Technical run of every beat | Done 2026-09-24 (`demo-evidence-index.md`) with that build's beats. At `8e1777d`: `demo_simulation.py` exit 0 in 0.48 s (historical: the script and its rehearsal mode were removed on 2026-09-28), `demo_fragmented.py` exit 0 in 0.57 s, the absent-device refusal exit 2. **The real-device beats (1:00, 3:15) have not been run since the change** |
| Spoken rehearsal against a stopwatch | **Not done.** It needs a human presenter. Log each run in the table below |
| Interruption rehearsal | **Not done.** A second person reads the seven interruptions above at random points |

| Run | Date | 0:30 | 1:00 | 1:45 | 2:30 | 3:15 | 4:00 | End | Interruptions | Under 4:30? |
|---:|---|---|---|---|---|---|---|---|---|---|
| 1 | | | | | | | | | | |
| 2 | | | | | | | | | | |
| 3 | | | | | | | | | | |
