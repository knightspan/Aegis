# Sanctum Forensics

**Secure sanitization, forensic recovery and tamper-evident verification in one offline workflow.**

One tool that erases storage by a method the
device itself supports, recovers evidence without writing to it, and signs a
record of both that a third party can check on their own machine.

`SANITIZATION` · `FILE ERASURE` · `FORENSIC RECOVERY` · `VERIFICATION` · `AUDIT`

![tests](https://img.shields.io/badge/pytest-3114%20passed%20·%2048%20skipped%20·%200%20failed-2ea44f)
![python](https://img.shields.io/badge/Python-3.11-3776ab)
![stack](https://img.shields.io/badge/FastAPI%20%2B%20React-localhost%20only-555)
![signing](https://img.shields.io/badge/reports-Ed25519-555)
![network](https://img.shields.io/badge/runtime-offline-555)
![license](https://img.shields.io/badge/license-Proprietary-555)

> **Current release evidence**
>
> | | |
> |---|---|
> | Source | branch `feat/platform-capability-completion` at `32b21bf` (2026-09-28). The last packaged builds on record are `76dde42` ([`release-report-2026-09-25.md`](docs/validation/release-report-2026-09-25.md)) and the Windows installer at `437081e` ([`windows-hardware-2026-09-27-fixes/`](docs/validation/windows-hardware-2026-09-27-fixes/README.md)); `platform-ci` built all three packages from `32b21bf` (run 36386022246) and drove each one on its runner; none of those builds was installed on physical hardware |
> | Test suite | 3114 passed · 48 skipped · 0 failed (Linux host, 2026-09-28, at `32b21bf`); UI 148 passed. `platform-ci` run 36386022246 at `32b21bf`: every job green (Linux 3066 passed, macOS 2621, Windows 2534; package on all three). CI proves every platform backend ships and runs a read-only native smoke on real Windows and macOS runners; that is not physical validation |
> | Capability state | Per platform and capability, generated from the resolver: [`capability-matrix.md`](docs/validation/capability-completion-2026-09-28/capability-matrix.md). What changed and why: [`capability-completion-2026-09-28/`](docs/validation/capability-completion-2026-09-28/README.md) |
> | Physically validated (device class) | Linux whole-drive clear, device discovery and raw acquisition on one TOSHIBA TransMemory USB stick (`usb-flash`, 2026-09-05, earlier build, [`hardware.md`](docs/validation/hardware.md)); Linux volume acquisition of one partition on the same stick (`usb-flash`, 2026-09-28, commit `a4fde30`, image hash confirmed independently, signed report verifies, [`volume-acquisition-2026-09-28/`](docs/validation/volume-acquisition-2026-09-28/)); Windows device discovery on a USB stick (`usb-flash`, 2026-09-27); Windows file erase on the host system disk (class not recorded, 2026-09-27); Linux file erase of one file on a FAT32 stick (`usb-flash`, 2026-09-28, read-back verification not possible on vfat) and Linux whole-device backup restore on the same stick (`usb-flash`, 2026-09-29, read-back hash matches), both in [`linux-file-erase-restore-2026-09-29/`](docs/validation/linux-file-erase-restore-2026-09-29/README.md). Nothing else |
> | Implemented, not physically validated | Windows whole-drive clear; Windows raw physical-device and volume acquisition; macOS whole-drive clear and raw acquisition of external disks; Firmware device sanitize on Linux and Windows (ATA SANITIZE, NVMe Sanitize, crypto erase; ATA SECURITY ERASE UNIT and NVMe Format on Linux only), DEVICE-DEPENDENT; the guarded HPA/DCO change (Linux, Windows); Backup restore with post-restore verification (Windows, macOS); file erase on macOS; Linux free-space wipe; removing a real trace from a live desktop; any macOS physical device; the registered physical recovery benchmark (BLOCKED at gate 1) |
> | Platform-limited | NVMe Format on Windows (the in-box driver does not pass it); every device sanitize, crypto erase and HPA/DCO operation on macOS (no public ATA or NVMe pass-through). Internal Apple storage is never raw-written or imaged; Erase All Content and Settings is the recommended path |
> | Not implemented | ATA SECURITY ERASE UNIT on Windows (no tested recovery for a drive left locked); Free-space wipe on Windows and macOS; DCO RESTORE or SET (never issued, by design) |
> | Evidence record | [`capability-completion-2026-09-28/`](docs/validation/capability-completion-2026-09-28/README.md); the earlier [`evidence-reconciliation-2026-09-28/`](docs/validation/evidence-reconciliation-2026-09-28/README.md) is kept as the record of the state before this work |

---

## Why Sanctum?

Forensic and sanitization tools usually do one job each. One tool erases. A
different tool recovers. The report is written by hand, and nobody can later
prove it was not edited.

Sanctum puts those jobs in one system, with one audit trail, and keeps every
destructive step behind gates a human has to pass on purpose.

```text
SANITIZE   DISCOVER → PREFLIGHT → BACKUP → PLAN → HUMAN APPROVAL → EXECUTE → VERIFY → REPORT
RECOVER    ACQUIRE  → CARVE     → VALIDATE → SCORE → EXPLAIN → REPORT
                                              │
                        both append to one hash-chained ledger
                        and end in one Ed25519-signed report
```

| Module | What it does |
|---|---|
| **M1 Secure Drive Eraser** | Whole-drive Clear or Purge in NIST SP 800-88 Rev. 2 vocabulary, method chosen from probed device capability; Destroy recorded as a signed attestation by the people who did it |
| **M2 Secure File & Folder Eraser** | File, folder and batch erasure, document metadata cleansing, a sweep of the thumbnails, recent-files entries and Trash copies the desktop kept, and a report of what the filesystem kept anyway |
| **M3 File Carving & Recovery** | Read-only acquisition, a media map of the image, filesystem-aware undelete, signature and structure carving, bifragment reconstruction, decoder validation, evidence scoring |

## What makes it different

**Device-aware sanitization.** The erase method comes from what the device
reports it can do (`hdparm -I`, NVMe Identify, `sedutil-cli` and sysfs on Linux;
ATA IDENTIFY through `IOCTL_ATA_PASS_THROUGH` and the NVMe Identify data on
Windows). The UI has no method dropdown. If the requested level cannot be
reached, the job is NOT AUTHORIZED; it never silently downgrades, and an
overwrite is never labelled a Purge.

**Destructive-operation safety.** Identity binding (serial and
`/dev/disk/by-id` on Linux; disk number, serial and length read from the open
`\\.\PhysicalDriveN` handle on Windows; size and a fresh `system_profiler`
serial on macOS), a typed-serial confirmation, a server-issued one-use
authorization after a recorded human approval, refusal of mounted and system
disks, and no automatic `sudo`, elevation or unmount. There is no dry-run or
simulation mode: every operation runs against the selected real device once
its gates pass, and a request that asks for a rehearsal is refused. See
[The safety model](#the-safety-model).

**Residual traces, not only residual data.** Erasing a file leaves what the
desktop made of it: a thumbnail named by the MD5 of its URI, a recent-files
entry, an older copy in the Trash or Recycle Bin. After a file erase, Sanctum
finds those and removes the ones it can tie to the erased path on evidence
(`core/erase/traces.py`). Anything weaker, such as a same-name file in the macOS
Trash, is reported and left alone. The report names every place searched and
the places on that platform it did not search.

**Destroy, recorded honestly.** No software can shred a drive or watch one being
shredded. When a medium is physically destroyed, Sanctum chains and signs what
the people who did it attest: technique, fragment size, who, witness, when. The
signed record states that the tool observed nothing (`core/destroy.py`).

**Explainable recovery.** Every candidate is bounded by its format's own
length fields, read by a real decoder, and scored on named evidence. A file
split in two is rebuilt only when its own bytes prove the join.

**Tamper-evident reporting.** Every operation appends to a hash-chained
ledger. Reports are signed with Ed25519 and checked by a verifier a third
party runs themselves. One changed field fails verification.

**Reproducible validation.** Deterministic synthetic corpora with ground-truth
manifests, a bounded fuzz pass, 1 GiB and 7 GiB image runs, and a benchmark
against PhotoRec and Foremost. Every figure links to its raw result.

**Honest cross-platform capability states.** One resolver
(`core/platform/capability.py`) answers for every capability on every platform
and device, and keeps three things apart: whether code exists, whether this
device and this process can run it, and whether a run on real hardware *of this
device class* is recorded. Its words are SUPPORTED (physically validated for
that class), IMPLEMENTED / UNVALIDATED, DEVICE-DEPENDENT, PLATFORM-LIMITED,
REQUIRES PRIVILEGE, BLOCKED FOR SAFETY and NOT IMPLEMENTED, each with a reason.
A run on one USB stick validates `usb-flash` only, never an internal SSD. The
committed [capability matrix](docs/validation/capability-completion-2026-09-28/capability-matrix.md)
is generated from the resolver, and a test fails if it goes stale.

**Explicit uncertainty.** Every result carries its population: physical,
synthetic, CI, documented or hardware-unverified. They are never merged. Test
doubles (fake devices, recording helpers) keep CI safe and are never counted as
physical validation.

## The safety model

Destructive work follows one state machine (`core/workflow.py`), which refuses
any illegal transition. The Sanitize screen draws it, and `BLOCKED` always
carries a **WHY BLOCKED** reason and the human action that clears it.

```text
DISCOVERED
   ↓
PREFLIGHT ─────────────→ BLOCKED   device absent, mounted, system disk,
   ↓                               serial sources disagree …
BACKUP REQUIRED → BACKUP VERIFIED   an image the server hashed and sized
   ↓
HUMAN APPROVAL REQUIRED   acknowledge and type the serial
   ↓
PLAN READY                approval recorded; a one-use authorization issued
   ↓
EXECUTING                 serial typed again; the helper re-reads device,
   ↓                      plan and backup before the engine starts
VERIFYING
   ↓
COMPLETE / FAILED
```

- **Mounted and system disks are refused**, with the mount point named. No
  erase unmounts anything. On Linux a human unmounts. On Windows and macOS an
  explicit **Prepare** step (`POST /devices/prepare`: the volumes it affects
  shown first, typed serial, ledgered, system and internal disks refused) takes a disk offline
  (Windows, not persistent) or runs `diskutil unmountDisk` (macOS); it is never
  part of an erase.
- **Identity is the serial, not the kernel name.** The operator types the
  serial of the selected disk. Right before writing, the engine re-reads the
  device and raises `DeviceVanished` if the serial or by-id link changed. On
  Windows the identity is read from the open handle itself, and a drive letter
  is never a target. On macOS no ioctl returns a serial: the serial is re-read
  from `system_profiler` just before the raw device is opened, and the size is
  bound from the open descriptor. A different disk of the same size taking the
  same `diskN` between the re-read and the open would not be detected; that
  window is documented, not closed
  ([security review](docs/security-review-cross-platform.md)).
- **Nothing is substituted.** A missing or stale device path is a structured
  refusal; no other device is tried.
- **Every run is real, so every gate runs every time.** There is no dry-run or
  simulation mode, and a request carrying `dry_run`, `simulation` or `simulate`
  is rejected (422) rather than honoured or ignored. An erase needs a backup
  image the server has hashed and sized, an approval with the acknowledgement
  and the typed serial, and the one-use authorization the server returns. The
  helper re-checks device, plan and backup before its first write. SYNTHETIC
  VALIDATION only; the backup is not proven to be a copy of the device, and the
  API does not authenticate who approved.
- **Privilege is explicit.** On Linux the UI and API run unprivileged, and
  raw device work goes through one helper that a human starts with `sudo`, over
  a static allowlist of typed operations
  ([privilege boundary](docs/privilege-boundary.md)). That socket helper is
  Linux-only. On Windows and macOS raw device work runs in the Sanctum process
  itself, so that process must be elevated: *Run as administrator* on Windows,
  started with `sudo` on macOS. Otherwise those capabilities read REQUIRES
  PRIVILEGE. Elevating the whole process is a wider privileged surface than the
  Linux split, and the [security review](docs/security-review-cross-platform.md)
  records it.
- **The HPA is never changed by an erase.** An ordinary erase covers the
  accessible range, and when hidden sectors exist the report says how many were
  not covered. Changing the HPA is its own guarded workflow
  (`/workflow/hidden-area`: volatile SET MAX by default, typed serial,
  read-back); DCO is read, never modified.
- **Verification follows every erase.** Full read-back up to 64 GiB, seeded
  sampling above that, with the detection probability in the report.
- **The physical benchmark has its own backup gate too.** `scripts/media_benchmark.py
  write` re-verifies, by itself and just before the first write, a backup on
  another disk bound to the device serial, the write extent and the image's
  SHA-256. This is in addition to the backup gate every real whole-drive erase
  passes (above).

## Forensic recovery

```text
Acquisition (O_RDONLY, SHA-256 + BLAKE3)
   ↓
Media map                   every region classed by its bytes: zero, fill,
   ↓                        text, structured, high-entropy; headers counted
Filesystem-aware undelete   NTFS, FAT12/16/32, exFAT, ext2/3/4
   ↓
Signature carving           24 signatures
   ↓
Structure carving           16 parsers derive the exact end from length fields
   ↓
Fragment reconstruction     baseline JPEG and PNG, exactly two runs
   ↓
Decoder validation          17 decoders
   ↓
Evidence scoring            six named components
   ↓
Explainable candidate       offset, runs, SHA-256, score breakdown
```

The evidence path is read-only: `core/carve/evidence.py` opens `O_RDONLY` and
has no write method. Raw acquisition opens the device read-only on every
platform: `O_RDONLY` with `BLKROSET` applied and read back on Linux,
`GENERIC_READ` on a `\\.\PhysicalDriveN` handle bound to the selected disk on
Windows (`core/carve/win_source.py`), `O_RDONLY` on `/dev/rdiskN` for an
external disk on macOS (`core/carve/mac_source.py`). Windows and macOS have no
software write block, and the acquisition record says so; a hardware write
blocker is the answer there. Only the Linux path is physically validated
(`usb-flash`).

**The media map.** Before anything is carved, the Recovery screen draws the
image as one strip: where it is zeroed, where it holds a fill pattern (erased
flash reads 0xFF; the free-space wipe leaves 0xA5), where the text, structured
binary and high-entropy data are, and where known file headers sit on sector
boundaries (`core/carve/mediamap.py`). An image of a wiped medium maps as zero
or fill from end to end, so the map is also a quick check of a wipe. Byte
statistics do not identify content: high entropy is compressed, encrypted or
random, and the map says so. Above 64 MiB it samples evenly within a fixed read
budget and says that too. Format coverage is generated from the code into
[`docs/supported-formats.md`](docs/supported-formats.md), and a test fails if
it drifts.

**Bifragment reconstruction.** A candidate whose structure does not close is
flagged `possibly_fragmented`. Sanctum then searches for a second run and
accepts a join only if it is unique and the bytes prove it: an exact Huffman
scan count for JPEG, every chunk CRC-32 plus a zlib stream of exactly the
header's size for PNG. On synthetic images, 120 of 120 PNG layouts were
rebuilt and 0 of 800 deliberately wrong joins were accepted
([`png-reassembly.md`](docs/validation/png-reassembly.md)). A rebuilt object
keeps both runs, so its digest can be recomputed from the image.

**The evidence score.** A sum of named components in basis points: header
2000, exact length 1500, decoder 4000, entropy 1000, filesystem metadata 1500,
no overlap 500, clamped at 10,000. HIGH is 8000 or more. A reassembled object
is held at 7999, so it is never HIGH. **It is an evidence score, not a
probability.** What was measured is how often each bucket was right on a
population: 104 of 104 HIGH candidates byte-exact across eight synthetic seeds
([`calibration-pooled.md`](docs/performance/calibration-pooled.md)). That is
not a rate for seized media.

## Trust and forensics

```text
DEVICE
  ↓
ACQUISITION HASH        SHA-256 + BLAKE3; SHA-256 per carved object
  ↓
OPERATION LOG
  ↓
HASH-CHAINED LEDGER     entry N holds SHA-256 of entry N−1
  ↓
REPORT                  canonical JSON (authoritative) + PDF (for reading)
  ↓
ED25519 SIGNATURE
  ↓
INDEPENDENT VERIFICATION   `sanctum verify-report`, five checks
```

`verify-report` checks the signature over canonical JSON, the key fingerprint
against the ledger genesis, the chain excerpt inside the report, the store
chain, and the stored blobs. It returns a graded verdict: `VERIFIED`,
`VERIFIED_WITH_LIMITATIONS`, `PARTIAL` or `FAILED_VERIFICATION`, with a reason
for every downgrade.

**What a certificate says was done.** Every report names one of five
categories (`core/report/semantics.py`): FILE ERASE, ADDRESSABLE WHOLE-DRIVE
CLEAR, DEVICE SANITIZE, CRYPTO ERASE or PHYSICAL DESTRUCTION ATTESTATION, with
the command, protocol, scope, verification and assurance. An overwrite is never
called a Purge or NAND-level destruction, and a crypto erase says the
ciphertext remains.

**Change one field and verification fails.** The Audit screen shows this live
on a server-side scratch copy: chain `VALID` before, `BROKEN` at the altered
entry after.

**What the signature proves:** whoever held this private key signed exactly
these bytes, and they have not changed since.

**What it does not prove:** who signed. The key is local, not PKI and not
government-issued, so identity needs the key fingerprint from another channel.
Someone with write access to the whole state directory can rebuild the chain
unless an external anchor is configured, and none is by default. The PDF is
not signed and says so.

How to verify a report on your own machine:
[user manual §7](docs/user-manual.md#7-reports-and-verification).

## Validation

**Automated.** 3114 passed · 48 skipped · 0 failed on the Linux host
(2026-09-28, at `32b21bf`). On the runners, `platform-ci` run 36386022246 at the
same commit: Linux 3066 passed · 96 skipped, macOS 2621 · 430, Windows
2534 · 517, 0 failed, and the package job green on all three. Each skip names its reason: root and `losetup`, and
behaviour that only exists on Windows or macOS, which runs on those runners in
`platform-ci`. The Windows and macOS whole-drive, raw-acquisition, device-sanitize
and restore paths are exercised on every host through adapter doubles
(`testkit/fake_windows.py`, `testkit/fake_macos.py`) that answer the native
calls from a byte buffer; no test touches a device. The last run
with a per-skip breakdown is 2046 passed · 34 skipped at `76dde42` (2026-09-26). With
`/tmp` on tmpfs, one test that writes 2000 MiB fails on the per-user quota; that is
an environment limit, and the test is unchanged
([release record](docs/validation/release-report-2026-09-25.md)). The suite
refuses any access to a host block device beyond the disk holding its own files, and
fails the run if one is attempted (`tests/_host_device_guard.py`); these runs had none.
Since 2026-09-27 the guard has its own rule set for each of Linux, macOS
(`/dev/diskN`, `/dev/rdiskN`, `diskutil`, ...) and Windows (`\\.\PhysicalDriveN`, raw
volumes, `diskpart`, PowerShell's `Get-Disk`, ...), and each run's summary names the
one it applied (`Host-device guard: Linux rules active`). Its self-test checks all
three rule sets on every host through intercepted launches and replayed audit events;
no physical device was used to test it. The guard's docstring lists its limits.
The Windows and macOS suites run on their own runners in `platform-ci`, which
also proves every platform backend ships in the package and binds on its real
OS, and runs a read-only native smoke (one read handle, identity IOCTLs, one
sector; no write handle exists in it). That is CI evidence, not physical
validation: the runners' disks are virtual.

**Static analysis.** Ruff clean. Four `mypy --strict` passes clean: Linux,
two `--platform win32` passes, and `--platform darwin`.

**UI.** 148 of 148 unit tests pass (`cd ui && npm test`, at `bf4c59b`).

**Browser.** Playwright in Chromium at 1366 × 768: 24 of 24 checks on the real
API, 16 of 16 on fixture devices, no page errors
([`browser-2026-09-24/`](docs/validation/browser-2026-09-24/README.md)); the
Sanitize workflow, 59 of 59 against the real API over a synthetic helper, the server
in a sandbox with no block device
([`browser-2026-09-25/`](docs/validation/browser-2026-09-25/README.md)), repeated
after the redesign; the trace sweep, the media map and the Record of Destruction, 19 of
19 over a synthetic home and image in the same sandbox
([`features-2026-09-25/`](docs/validation/features-2026-09-25/README.md)); the Cases,
Platform, Audit and Recovery screens after the final polish, 66 of 66 at 1366 × 768
and 1024 × 768 ([`polish-2026-09-25/`](docs/validation/polish-2026-09-25/README.md));
and the release-hold remediation, 39 of 39: a write-seam refusal is BLOCKED on
Sanitize, the Overview and Cases, never a failed or partial erase; REQUEST FAILED
stays distinct; firmware Purge reads *Unverified*; a failed read-back stops on
Verify ([`remediation-2026-09-25/`](docs/validation/remediation-2026-09-25/README.md)).
All four ran on 2026-09-26 against the UI bundle packaged at `76dde42`. The Devices
and Sanitize screens were checked against synthetic devices, not real ones.

**Packages.** The last recorded package build is `76dde42` (2026-09-26); no
package build from `bf4c59b` is recorded here, so the packaged figures below
predate the Windows and macOS drive backends. `tests/test_package_completeness.py`
pins that every module the capability table names is collected by the
PyInstaller spec. AppImage and `.deb` rebuilt from `76dde42`; all 92 packaged
`core`/`api`/`helper` modules are bytecode-identical to that commit, and the bundled
UI matches file for file. The isolated smoke test, inside a no-device sandbox, is
**22 PASS and 2 NOT RUN** for each package: the two NOT RUN checks need a real
device and were not run. A signed certificate is issued and verifies. An earlier rebuild failed that: the packaged app
could not render any PDF, a PyInstaller gap the source tree cannot show, fixed in
`e81f491` and still in place
([`package-2026-09-25/`](docs/validation/package-2026-09-25/README.md)).

**Recovery (synthetic).** Against PhotoRec and Foremost on the same 25
volumes, carve only: Sanctum 423 of 446 byte-identical, PhotoRec 372,
Foremost 220. Sanctum is about 68 times slower than PhotoRec and returns 45
false positives to PhotoRec's 0 ([`benchmark.md`](docs/performance/benchmark.md)).
7 GiB image: recall 288 of 288, 247 of 247 HIGH correct, peak RSS 513 MiB
([`large-image.md`](docs/validation/large-image.md)). Fuzz: 66,000 cases, 0
crashes after one fix ([`fuzz.md`](docs/validation/fuzz.md)).

**Physical.** The validation record
(`core/platform/validation_record.json`, `physical_validations`) holds exactly
these runs, and the capability matrix reads SUPPORTED only for them, only for
that device class:

| Platform | Capability | Device class | Device, date | Evidence |
|---|---|---|---|---|
| Linux | Whole-drive clear (addressable overwrite) | `usb-flash` | TOSHIBA TransMemory 7.76 GB, 2026-09-05, earlier build | [`hardware.md`](docs/validation/hardware.md) Phase A: full read-back; PhotoRec 14 of 14 planted files before, 0 after |
| Linux | Device discovery | `usb-flash` | same stick, 2026-09-05 | `hardware.md` A.1: 0 disagreements with `lsblk` and `udevadm` |
| Linux | Raw physical-device acquisition | `usb-flash` | same stick, 2026-09-05 | `hardware.md` Phase B: three acquisitions, carving 456/456, 460/460, 10 of 10 recoverable |
| Windows | Device discovery | `usb-flash` | TOSHIBA TransMemory (`SANCTUMREC`), Windows 11, 2026-09-27 | [`windows-hardware-2026-09-27-fixes/`](docs/validation/windows-hardware-2026-09-27-fixes/README.md) |
| Windows | File erase | not recorded (host system disk) | Windows 11, NTFS, 2026-09-27, `437081e` | same folder: read-back, signed certificate verified |

Also on record, as dated runs rather than capability rows: the mounted-device
refusal on the stick (2026-09-23, earlier build, [`demo/qa.md`](docs/demo/qa.md)
§24), two earlier Clear runs that found nine defects, a power-cycle
re-verification, and detection of a controller that acknowledges zero writes
3.25 to 3.6 times faster than it programs them (all in `hardware.md`).

**Implemented, not physically validated.** Each of these has code, runs
through the full workflow gates, and is tested with fixtures or adapter doubles
only: Windows whole-drive clear (`core/erase/blockclear.py` over
`\\.\PhysicalDriveN`, disk offline first); Windows raw physical-device and
volume acquisition; macOS whole-drive clear and raw acquisition of external
disks through `/dev/rdiskN`; firmware device sanitize on any platform (ATA
SANITIZE and NVMe Sanitize on Linux and Windows, ATA SECURITY ERASE UNIT and NVMe
Format on Linux, crypto erase), each DEVICE-DEPENDENT and offered only when the
controller reports it and no USB bridge hides it; the guarded HPA/DCO change on
Linux and Windows; backup verification and restore with post-restore
verification on all three platforms; file erase on Linux and macOS; the Linux
free-space wipe; removing a real trace from a live desktop; a power cut or
device removal during a write; and any macOS physical device. The registered
physical recovery benchmark has a first-class runner (`core/benchmark`,
SYNTHETIC and PHYSICAL never merged) and is BLOCKED at its first gate
([`physical-benchmark-checklist.md`](docs/validation/physical-benchmark-checklist.md)).

**Platform-limited or not implemented.** NVMe Format on Windows and every
device sanitize, crypto erase and HPA/DCO operation on macOS are
PLATFORM-LIMITED: the operating system offers no path to the command. ATA
SECURITY ERASE UNIT on Windows and the free-space wipe on Windows and macOS are
NOT IMPLEMENTED, each with its reason in the matrix. DCO RESTORE and SET are
never issued.

## What we have actually proven

| Capability | Evidence | Status |
|---|---|---|
| Linux whole-drive clear (addressable overwrite) with read-back | three recorded runs on one stick, the third clean (2026-09-05) | **PHYSICAL VALIDATION**, `usb-flash` only (one device, one model, an earlier build) |
| Mounted-device refusal | refusal on the stick, no I/O recorded (2026-09-23) | **PHYSICAL VALIDATION** (an earlier build) |
| Linux raw acquisition, then recovery after delete and quick format | three passes on the same stick (2026-09-05) | **PHYSICAL VALIDATION**, `usb-flash` only (an earlier build; not the registered benchmark) |
| Windows packaged install, device discovery and mounted-device refusal, file/folder erase → verify → certificate | 23 of 23 packaged checks on a physical Windows 11 machine, 2026-09-27, `437081e` | **PHYSICAL VALIDATION**: discovery on `usb-flash`; file erase on the host system disk, class not recorded ([`windows-hardware-2026-09-27-fixes/`](docs/validation/windows-hardware-2026-09-27-fixes/README.md)) |
| File and folder erase | suites plus packaged app on each OS runner | **CI VALIDATION**; physical on Windows only (above) |
| Cross-platform adapters, discovery, system-disk refusal, backends shipped, read-only native smoke | `platform-ci` against each runner's own (virtual) disks | **CI VALIDATION**, not physical |
| Fragmented JPEG recovery | 10 of 10 on the benchmark volumes | **SYNTHETIC VALIDATION** |
| Fragmented PNG recovery | 120/120 layouts, 0/800 wrong joins accepted | **SYNTHETIC VALIDATION** |
| Recovery benchmark and calibration | 40 images, 8 pooled seeds | **SYNTHETIC VALIDATION** |
| Tamper-evident report and ledger | `tests/report/`, `tests/ledger/`, live tamper demo | **SYNTHETIC VALIDATION**; verifier also run on the physical-run report |
| Discovery-to-certificate journey on a real device | the real-device procedure in [`docs/demo/runbook.md`](docs/demo/runbook.md) on a disposable test stick; engine path covered by loopback and adapter-double tests | **IMPLEMENTED / UNVALIDATED** until a physical run is recorded |
| NIST SP 800-88 Rev. 2, IEEE 2883, ISO/IEC 27040 | section-by-section mapping | **DOCUMENTED** (mapped, not certified) |
| Firmware device sanitize (ATA SANITIZE, ATA SECURITY ERASE UNIT, NVMe Sanitize, NVMe Format, crypto erase; a TCG Opal drive is recognised but not reverted, no PSID input) | selected and dispatched in fixture and adapter-double tests only (all on Linux; ATA SANITIZE, NVMe Sanitize and crypto erase also on Windows); offered only when the controller reports it | **IMPLEMENTED / UNVALIDATED**, DEVICE-DEPENDENT |
| Guarded HPA change (DCO read only) | state machine, plan, typed serial and read-back tested against faked probes on Linux and Windows; never run on a drive | **IMPLEMENTED / UNVALIDATED**, DEVICE-DEPENDENT; PLATFORM-LIMITED on macOS |
| Trace sweep | synthetic home directories, tests and a sandboxed browser run; on a physical Windows 11 desktop (2026-09-27) it searched the real Recycle Bin and Recent shortcuts and found nothing to remove | **SYNTHETIC VALIDATION**; removing a real desktop trace not validated |
| Record of Destruction | signed attestation by the people named in it | **SYNTHETIC VALIDATION**; destruction attested, not observed |
| Physical recovery benchmark | first-class runner (`core/benchmark`), harness built, preflight run; no result | **BLOCKED at gate 1** |
| Windows whole-drive clear, Windows raw physical-device and volume acquisition | `core/erase/blockclear.py`, `core/carve/win_source.py` over a handle bound to disk number, serial and length; adapter-double tests only | **IMPLEMENTED / UNVALIDATED** |
| macOS whole-drive clear and raw acquisition, external disks | `/dev/rdiskN`; internal Apple storage refused; adapter-double tests only | **IMPLEMENTED / UNVALIDATED** |
| Backup verification and restore | `core/backup.py`, `core/restore.py`: pre-write chunk verification, exact byte accounting, post-restore read-back hash; Linux: one same-device restore on a `usb-flash` stick, 2026-09-29; Windows and macOS: synthetic targets only | **SUPPORTED** (Linux, `usb-flash`); **IMPLEMENTED / UNVALIDATED** on Windows and macOS |
| ATA SECURITY ERASE UNIT on Windows; free-space wipe on Windows and macOS | no code, each with its reason in the matrix | **NOT IMPLEMENTED** |
| NVMe Format on Windows; device sanitize, crypto erase and HPA/DCO on macOS | the OS offers no path to the command | **PLATFORM-LIMITED** |

Row by row with code paths and tests: [`feature-matrix.md`](docs/validation/feature-matrix.md).
Per platform and capability: [`capability-matrix.md`](docs/validation/capability-completion-2026-09-28/capability-matrix.md).

## The 4½-minute demo

The only device erased on stage is a disposable test stick the presenter owns
and has backed up (step 3); it is a real erase, and it is not recorded as a
physical validation of any device class unless the run is recorded with
`scripts/record_physical_validation.py`. The Sanitize beat on any other device
stops at the approval gate. Every step maps to a screen, a command, a test and a recorded artifact in the
[demo evidence index](docs/validation/demo-evidence-index.md).

| # | Step | Shown with | Population |
|---|---|---|---|
| 1 | Overview: four workflows and the six-part executive summary, including what is not physically validated | Overview screen | live host |
| 2 | Device identity and refusal: serial, capability badge, `BLOCKED · WHY BLOCKED`; a missing device path refused, exit 2 | Devices; `scripts/media_benchmark.py plan` | live host |
| 3 | Real device from discovery to certificate on a disposable, backed-up test stick: preflight, backup, approval, final revalidation, erase, read-back, certificate | Sanitize, [real-device procedure](docs/demo/runbook.md) | REAL DEVICE (one stick; not a device-class validation until recorded) |
| 4 | Fragmented recovery: split PNG and JPEG rebuilt, checked against ground truth | `scripts/demo_fragmented.py`; Recovery | SYNTHETIC |
| 5 | Evidence explanation: the six components and the reassembly hold | Recovery score breakdown | SYNTHETIC |
| 6 | Signed report generated for the job | Audit | SYNTHETIC |
| 7 | Tamper verification: one byte changed, chain `BROKEN` | Audit, *Tamper a scratch copy* | SYNTHETIC |
| 8 | Certificate: case, report SHA-256, key fingerprint, signed JSON and PDF | Audit report panel | SYNTHETIC |
| 9 | Sanitization workflow on a device that is not the test stick: probe, selected method, approval gate. **Erase is not pressed** | Sanitize | live host, no write |
| 10 | Benchmark evidence, with its population said aloud | [`benchmark.md`](docs/performance/benchmark.md) | SYNTHETIC |

Every beat ran in a technical rehearsal on 2026-09-24. The spoken script has
not yet been timed aloud; it and the rehearsal log are in the
[judge defense card](docs/validation/judge-defense-card.md#spoken-script-430).

## Judge questions

**Why not just format the drive?** A format rewrites filesystem metadata and
leaves the data. On the physical stick, after a FAT32 quick format, carving
still recovered all 10 of the 10 carvable planted files byte-exact.

**How do you prevent erasing the wrong device?** The operator types the
serial; a mismatch refuses. System and mounted disks are refused before that,
and the serial is re-read right before writing. That re-read test needs root
and a loop device, so it is skipped in the unprivileged suite.

**What happens when the filesystem is mounted?** Refused with the mount point
named, and the tool never unmounts. Physically validated on the stick on
2026-09-23, with an earlier build.

**How is SSD or flash different?** Overwrite cannot reach remapped or
over-provisioned blocks, so on flash it is at most Clear and every report says
so. Purge needs the device's own firmware command; that path is implemented,
offered only when the controller reports it, and has never run on a physical
drive. Behind a USB bridge it is refused, because the bridge does not pass the
command through.

**How is fragmented recovery different from normal carving?** A split file is
rebuilt only when a decoder-level check proves the join, and the result is
held below HIGH. Two formats, exactly two runs.

**Is the evidence score a probability?** No. It is a sum of named evidence
components, clamped at 10,000. Its buckets were measured against synthetic
ground truth, not seized media.

**How do you prove the report was not changed?** Ed25519 over canonical JSON,
checked with the ledger chain by `verify-report`. One changed field fails.

**What is physically validated?** Linux whole-drive clear, discovery and raw
acquisition on one USB flash stick (`usb-flash`, 2026-09-05, earlier build);
Linux file erase (one file, FAT32, read-back not possible) and whole-device
backup restore on the same stick (`usb-flash`, 2026-09-28 and 2026-09-29);
Windows device discovery on a USB stick (`usb-flash`) and file erase on the host
system disk (class not recorded), both 2026-09-27. macOS: none. A run on a USB
stick says nothing about an internal SSD or NVMe drive, and the matrix never
extends it.

**What is still not physically validated?** Windows and macOS whole-drive
clear and raw acquisition, firmware device sanitize on any platform, the HPA
change, backup restore on Windows and macOS, the registered physical benchmark (BLOCKED at gate 1),
removing a real trace from a live desktop, a power cut mid-write, and any macOS
physical device. All of these are implemented and tested with fixtures or
adapter doubles. **Not implemented:** ATA SECURITY ERASE UNIT on Windows and the
free-space wipe on Windows and macOS. **Platform-limited:** NVMe Format on
Windows; device sanitize and HPA/DCO on macOS.

**What happens if the device disappears?** Before the job: `DeviceVanished`,
nothing written, no other device tried. During a write: the job ends `failed`
and no certificate is issued. Removal during a write has not been tested.

All 37 questions, with evidence and a status for each:
[`judge-defense-card.md`](docs/validation/judge-defense-card.md).

## What Sanctum does not claim

- Physical validation is scoped to device class and limited to the runs in
  the [validation record](docs/validation/capability-completion-2026-09-28/README.md):
  Linux whole-drive clear, discovery and raw acquisition on `usb-flash`
  (2026-09-05, earlier build); Windows discovery on `usb-flash` and file erase on
  the host system disk (2026-09-27). The Windows and macOS whole-drive clear and
  raw acquisition added since are implemented and have never run on a physical
  disk. macOS has no physical run of anything.
- Firmware Purge has not run on any physical drive. It is selected and
  dispatched from probed capability, tested with fixtures and adapter doubles,
  and shown as IMPLEMENTED / UNVALIDATED (PURGE · UNVERIFIED on the Devices
  screen) until a hardware result for that device class is recorded.
- The HPA change has not run on a drive that has a hidden area. An ordinary
  erase never changes the HPA; hidden sectors it did not reach are counted in
  the report.
- A real erase's backup is hashed, sized and re-checked, but nothing proves it
  is a copy of the device. Restore is implemented, verifies what it wrote, and
  has never been run on a physical device.
- The helper re-checks device, plan and backup just before the engine starts;
  the window from that check to the first write is not proven race-free.
- The API does not authenticate a human. Approval is a deliberate second call
  with the typed serial, not proof of who approved.
- There is no rehearsal mode. Every erase that passes the gates writes to the
  real device; what would run is shown beforehand by the read-only plan
  (`core.erase.drive.preview`), which opens nothing for writing.
- An overwrite does not reach remapped or over-provisioned flash blocks.
- Fragmented-file reconstruction is not general: baseline JPEG and PNG,
  exactly two runs, nothing else.
- The certificate is integrity-protected, not identity-proving. It is not
  government-signed and not PKI-backed.
- No certification or compliance is claimed. Sanctum uses NIST SP 800-88
  Rev. 2 vocabulary and maps to it, IEEE 2883 and ISO/IEC 27040. DoD
  5220.22-M is a legacy engine method with a warning, not a standard claimed.
- Windows and macOS have no software write block, so raw acquisition there
  relies on a read-only handle and the report says so; use a hardware write
  blocker for evidence. Internal Apple storage is never raw-written or imaged:
  macOS's own Erase All Content and Settings is the recommended path, and
  Sanctum cannot perform or verify it.
- On Windows, NVMe Sanitize reports no progress, and the storage driver may
  refuse an ATA pass-through; the refusal is reported and nothing is retried
  another way. ATA SECURITY ERASE UNIT is not issued on Windows.
- Recovery rates are synthetic. No result exists yet under the registered
  physical benchmark.
- Per-file erasure is often unverifiable (copy-on-write filesystems, FAT
  extents), and is reported as such rather than as a pass.
- ext4 undelete recovers almost nothing, because the kernel zeroes the extent
  tree on unlink. That is measured.
- Destroy is not performed or observed. A Destroy record is what the people
  named in it attest (destruction attested, not observed), and the application
  does not authenticate them.
- The trace sweep covers the desktop's shared thumbnail cache, recent-files
  lists, Trash and Recycle Bin, Windows jump lists, and macOS recent items and
  the Quick Look cache. The macOS recent items, the Quick Look cache and a jump
  list that also names other files are reported only, never edited, because a
  daemon or the shell owns them. Application caches, search indexes,
  `thumbcache_*.db` (keyed by hash, not path), snapshots and sync clients are
  listed in each report as not searched. On a
  physical Windows 11 desktop (2026-09-27) it searched the real Recycle Bin and
  Recent shortcuts and found nothing to remove; removing a real desktop trace
  has not been validated on any platform.
- The media map classes bytes by their statistics. It does not identify
  content, and a sampled map can miss what its samples did not read.

**When the evidence is insufficient, Sanctum reports the limitation instead of
upgrading it into a guarantee.** The full list is
[`docs/limitations.md`](docs/limitations.md).

## Platform support

A summary of the generated [capability matrix](docs/validation/capability-completion-2026-09-28/capability-matrix.md),
which is authoritative. SUPPORTED means physically validated, for the device
class named, and nothing wider.

| Platform | File erase | Whole-drive clear | Device sanitize | Raw acquisition | HPA/DCO change | Restore |
|---|---|---|---|---|---|---|
| Linux | **SUPPORTED** (`usb-flash`) | **SUPPORTED** (`usb-flash`) | DEVICE-DEPENDENT | **SUPPORTED** (`usb-flash`) | DEVICE-DEPENDENT (HPA only) |  **SUPPORTED** (`usb-flash`) |
| Windows | **SUPPORTED** (host disk, class not recorded) | IMPLEMENTED / UNVALIDATED (disk offline, administrator) | DEVICE-DEPENDENT (ATA SANITIZE, NVMe Sanitize); ATA SECURITY ERASE UNIT NOT IMPLEMENTED; NVMe Format PLATFORM-LIMITED | IMPLEMENTED / UNVALIDATED (no software write block) | DEVICE-DEPENDENT (HPA only) | IMPLEMENTED / UNVALIDATED |
| macOS | IMPLEMENTED / UNVALIDATED (APFS copy-on-write limit) | IMPLEMENTED / UNVALIDATED (external disks; internal Apple storage refused) | PLATFORM-LIMITED | IMPLEMENTED / UNVALIDATED (external disks; no software write block) | PLATFORM-LIMITED | IMPLEMENTED / UNVALIDATED (external disks) |

Device discovery is SUPPORTED on Linux and Windows (`usb-flash`) and
IMPLEMENTED / UNVALIDATED on macOS. The free-space wipe is IMPLEMENTED /
UNVALIDATED on Linux and NOT IMPLEMENTED on Windows and macOS. Recovery
(carving, undelete, scoring) runs on an image and is the same code on every
platform; its figures are synthetic plus the three Linux passes on one stick.

Packages: AppImage and `.deb`, `SanctumSetup.exe`, `Sanctum.dmg`. All are
unsigned and not notarized. CI runners have virtual disks, so CI-validated is
not hardware-validated; the Windows package was additionally installed and
driven on a physical machine, 2026-09-27
([`windows-hardware-2026-09-27-fixes/`](docs/validation/windows-hardware-2026-09-27-fixes/README.md)).
Details: [`platform-support.md`](docs/platform-support.md),
[`hardware-platform-matrix.md`](docs/validation/hardware-platform-matrix.md).

## Quick start

Step-by-step installation for Linux, Windows and macOS, from a package or from
source: [`INSTALL.md`](INSTALL.md).

Fedora or Debian/Ubuntu with Python 3.11. The host `python3` is often not
3.11; [`docs/technical.md`](docs/technical.md) explains why that matters.

```bash
./scripts/devsetup.sh
source .venv/bin/activate
make check          # ruff + four mypy --strict passes + pytest
make run            # prints http://127.0.0.1:8787/session/<token>; open it
```

To run it as a desktop app in its own window instead of a browser tab:

```bash
pip install --constraint constraints.txt -e ".[desktop]"   # Qt backend on Linux
python -m api.desktop
```

The control surface binds `127.0.0.1` only, serves its own bundled assets, and
makes no network call. It mints a session token per run and refuses any
request without it, or addressed to a non-loopback host name.

Run the terminal demo that needs no device:

```bash
python scripts/demo_fragmented.py     # SYNTHETIC: split PNG and JPEG rebuilt
```

There is no device-free erase demo: every erase is real. Demonstrate one on a
disposable test stick with the procedure in
[`docs/demo/runbook.md`](docs/demo/runbook.md).

Whole-device operations need privilege: on Linux, the helper started with
`sudo`; on macOS, the Sanctum process itself started with `sudo` (the Linux
helper does not run there); on Windows, Sanctum started with *Run as
administrator* and the disk taken offline first. See [`INSTALL.md`](INSTALL.md) and the
[user manual §3](docs/user-manual.md#3-starting-it).

## Documentation map

**For judges**
[Feature matrix](docs/validation/feature-matrix.md) ·
[Judge defense card](docs/validation/judge-defense-card.md) ·
[Demo evidence index](docs/validation/demo-evidence-index.md) ·
[Browser validation](docs/validation/browser-2026-09-24/README.md)

**For examiners**
[User manual](docs/user-manual.md) ·
[Report verification](docs/user-manual.md#7-reports-and-verification) ·
[Threat model](docs/threat-model.md) ·
[Limitations](docs/limitations.md) ·
[Compliance mapping](docs/compliance.md)

**For engineers**
[Technical reference](docs/technical.md) ·
[Architecture](docs/architecture.md) ·
[Privilege boundary](docs/privilege-boundary.md) ·
[Platform support](docs/platform-support.md) ·
[Supported formats](docs/supported-formats.md) ·
[Acquisition performance](docs/performance/acquisition.md) ·
[Fuzzing](docs/validation/fuzz.md) ·
[Packaging](docs/packaging.md) ·
[Cross-platform security review](docs/security-review-cross-platform.md)

**For validation**
[Hardware runs](docs/validation/hardware.md) ·
[Capability matrix](docs/validation/capability-completion-2026-09-28/capability-matrix.md) ·
[Physical validation procedure](docs/validation/physical-validation-procedure.md) ·
[Hardware platform matrix](docs/validation/hardware-platform-matrix.md) ·
[CI platform matrix](docs/validation/platform-matrix.md) ·
[Release readiness](docs/release-readiness.md) ·
[Recovery benchmark](docs/performance/benchmark.md) ·
[Calibration](docs/performance/calibration.md) ·
[Pooled calibration](docs/performance/calibration-pooled.md) ·
[PNG reassembly](docs/validation/png-reassembly.md) ·
[Large-image runs](docs/validation/large-image.md) ·
[Physical benchmark gates](docs/validation/physical-benchmark-checklist.md)

`CLAUDE.md` holds the non-negotiables every change is checked against.
[`final-sih-readiness.md`](docs/validation/final-sih-readiness.md) is a
2026-09-21 snapshot, kept for history.

---

## Engineering and build details

### Layout

```text
core/device/   enumeration, capability probe, HPA/DCO workflow, safety guards;
               win/ (kernel32 behind a NativeApi seam), mac/ (/dev/rdiskN)
core/erase/    M1 whole-device (drive.py on Linux, blockclear.py on Windows
               and macOS, devicesanitize.py) and M2 file/folder engines
core/carve/    M3 acquisition, undelete, signature, structure, validate, score
core/ledger/   hash-chained append-only audit log
core/report/   render, detached-sign, independently verify
core/platform/ Linux, Windows and macOS adapters; capability.py, the resolver
core/backup.py, core/restore.py   backup verification and authorized restore
core/benchmark/  recovery benchmark runner, SYNTHETIC and PHYSICAL never merged
helper/        the one privileged process
api/           FastAPI, localhost, SSE progress
ui/            React + Vite, fully bundled, zero CDN
testkit/       synthetic media generator and ground-truth evaluator
```

### Container

```bash
docker build -t sanctum-forensics .          # or: podman build -t sanctum-forensics .
docker run --rm --network host \
    -e SANCTUM_STATE_DIR=/var/lib/sanctum \
    sanctum-forensics
```

`--network host` is required: the API binds `127.0.0.1` only, so there is no
port to publish. The image has **no privileged helper**, so device operations
inside it fail rather than escalate; it is for the API, UI, recovery and
reporting. The build refuses a UI bundle that references any external origin,
and builds a `libewf-python` that can write E01.

Building on a Fedora host directly, and the libewf details:
[`docs/technical.md`](docs/technical.md). Desktop packages:
[`docs/packaging.md`](docs/packaging.md).
