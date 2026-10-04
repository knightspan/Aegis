# Capability completion, 2026-09-28

> **Current state (2026-09-28).** Current product execution no longer exposes
> a user-facing simulation/dry-run mode: every operation runs against the
> selected real device once its gates pass, and a request that asks for a
> rehearsal is refused. References below to a dry run or a simulation record
> what the build of that date did; they are historical evidence and are kept as
> run.

**Question.** The [evidence reconciliation of 2026-09-28](../evidence-reconciliation-2026-09-28/README.md)
found capabilities that were not merely unvalidated but missing: Windows
whole-drive sanitization, Windows raw acquisition and backup restoration had no
code. Which of those, and of the other platform gaps, now have code, and what
does the evidence support for each?

**Answer.** Windows whole-drive clear, Windows raw physical-device and volume
acquisition, Windows ATA SANITIZE and NVMe Sanitize, macOS whole-drive clear
and raw acquisition of external disks, a guarded HPA workflow, and backup
verification with an authorized restore now exist. **None of them has run on a
physical device.** They are tested with fixtures and adapter doubles only. The
physical evidence is unchanged: the five runs listed below.

The authoritative per-platform table is generated from the capability resolver,
not written by hand:

- [`capability-matrix.md`](capability-matrix.md) and
  [`capability-matrix.json`](capability-matrix.json), written by
  `python scripts/capability_matrix.py`. `tests/platform/test_capability_matrix_doc.py`
  fails when the committed copy drifts from the resolver or the validation
  record. Do not edit them by hand.
- [`historical-physical-runs.json`](historical-physical-runs.json): the runs
  already documented in `hardware.md` and the Windows hardware records, entered
  into `core/platform/validation_record.json` (`physical_validations`) by
  `scripts/record_physical_validation.py`.

## States

Each capability on each platform, and on each device, resolves to one state
(`core/platform/model.py`, `CapabilityState`). The interface shows the label.

| Label | State | Meaning |
|---|---|---|
| SUPPORTED | `VALIDATED_PHYSICAL` | Runnable, and a PASS run on real hardware **of this device class** is in the validation record |
| IMPLEMENTED / UNVALIDATED | `IMPLEMENTED_NOT_PHYSICALLY_VALIDATED` | Runnable; synthetic and adapter-double tests only |
| DEVICE-DEPENDENT | `IMPLEMENTED_DEVICE_DEPENDENT`, `UNSUPPORTED_BY_DEVICE` | Implemented; runs only when the device reports the command and no bridge hides it |
| REQUIRES PRIVILEGE | `AVAILABLE_BUT_REQUIRES_PRIVILEGE` | Implemented; this process is not root / not elevated |
| PLATFORM-LIMITED | `UNSUPPORTED_BY_PLATFORM` | The operating system offers no path to the mechanism |
| BLOCKED FOR SAFETY | `BLOCKED_BY_SAFETY_POLICY` | Implemented, refused by a safety rule for this device (system disk, mounted, internal Apple storage, virtual disk) |
| NOT IMPLEMENTED | `NOT_IMPLEMENTED` | The OS could do it; this build has no code for it |

Evidence is matched on `(platform, capability, device class)` exactly. A run on
a USB stick validates `usb-flash` on that platform and nothing else.

## What changed

Commits `601b996..bf4c59b` on `feat/platform-capability-completion`:

| Commit | Change |
|---|---|
| `601b996` | Capability resolver (`core/platform/capability.py`): implementation, availability and class-scoped physical evidence kept apart; eight states |
| `4da977b` | Trace sweep OS adapters: macOS Trash put-back records, recent items and Quick Look (report only), Windows jump lists |
| `f24e63c` | First-class recovery benchmark runner (`core/benchmark`): sealed ground truth, SYNTHETIC and PHYSICAL never merged |
| `2f10063` | Backup verification (`core/backup.py`) and authorized restore (`core/restore.py`) with pre-write chunk verification and post-restore read-back |
| `0697c9c` | Windows native layer (`core/device/win`, kernel32 behind a `NativeApi` seam): raw acquisition (`core/carve/win_source.py`), whole-drive clear (`core/erase/blockclear.py`), ATA SANITIZE and NVMe Sanitize (`core/erase/devicesanitize.py`). macOS `/dev/rdiskN` (`core/device/mac`): whole-drive clear and raw acquisition of external disks |
| `92dcbf3` | Certificates name the category: FILE ERASE, ADDRESSABLE WHOLE-DRIVE CLEAR, DEVICE SANITIZE, CRYPTO ERASE, PHYSICAL DESTRUCTION ATTESTATION (`core/report/semantics.py`) |
| `d63a7c4` | CI proves every backend ships and binds on its real OS; `scripts/native_smoke.py` runs the real bindings read-only on Windows and macOS runners |
| `ce2328b`, `e1088ef` | A Windows write or restore is refused while any volume on the disk is still exposed |
| `e0d9f4c` | [`physical-validation-procedure.md`](../physical-validation-procedure.md) |
| `d82002a` | The UI shows the resolver's state, reason and mechanism on every screen |
| `1f3aca7`, `9b1e856` | `POST /devices/prepare`: an explicit take-offline (Windows, not persistent) or `diskutil unmountDisk` (macOS) step, dry run first, typed serial, never part of an erase |
| `c74192b` | Guarded HPA/DCO workflow (`core/device/hidden_area_workflow.py`, `/workflow/hidden-area`): volatile SET MAX by default, DCO never modified. An ordinary Linux erase no longer unlocks the HPA; it erases the accessible range and counts the hidden bytes in the report |
| `bf4c59b` | The capability matrix above, generated from the resolver; package completeness pinned |

Tests at `bf4c59b`, Linux host: 3110 passed, 48 skipped, 0 failed; UI 148
passed.

## Physically validated

Exactly these runs, and only for the device class shown:

| Platform | Capability | Device class | Device | Date | Evidence |
|---|---|---|---|---|---|
| Linux | Whole-drive clear (addressable overwrite) | `usb-flash` | TOSHIBA TransMemory, serial `B103B9C19DE1CCC1BD535ACB` | 2026-09-05, earlier build | [`hardware.md`](../hardware.md) Phase A |
| Linux | Device discovery | `usb-flash` | same stick | 2026-09-05 | `hardware.md` A.1 |
| Linux | Raw physical-device acquisition | `usb-flash` | same stick | 2026-09-05 | `hardware.md` Phase B |
| Windows | Device discovery | `usb-flash` | TOSHIBA TransMemory (`SANCTUMREC`) | 2026-09-27 | [`windows-hardware-2026-09-27-fixes/`](../windows-hardware-2026-09-27-fixes/README.md) |
| Windows | File erase | not recorded (`unknown`) | host system disk, model not recorded | 2026-09-27, `437081e` | same |

Nothing else is physically validated. In particular: no firmware Purge on any
drive, no HPA or DCO change, no Windows or macOS whole-drive clear, no Windows
or macOS raw acquisition, no restore, and no macOS device at all.

## Implemented, not physically validated

Tested with fixtures, synthetic images and adapter doubles
(`testkit/fake_windows.py`, `testkit/fake_macos.py`); no test touches a device.

| Platform | Capability | Notes |
|---|---|---|
| Windows | Whole-drive clear | `\\.\PhysicalDriveN` handle bound to disk number, serial and length; disk must be offline; Run as administrator |
| Windows | Raw physical-device and volume acquisition | `GENERIC_READ` only; no software write block, and the record says so |
| Windows | ATA SANITIZE (block erase, crypto scramble), NVMe Sanitize (block, crypto) | DEVICE-DEPENDENT: offered only when IDENTIFY reports it; the storage driver may refuse the pass-through; NVMe Sanitize reports no progress |
| Windows | HPA discovery and change | DEVICE-DEPENDENT, through ATA pass-through; DCO never modified |
| macOS | Whole-drive clear, raw and volume acquisition | External disks through `/dev/rdiskN`; the Sanctum process must run as root (the Linux socket helper does not start on macOS); serial from `system_profiler` |
| macOS | Device discovery, file erase | APFS is copy-on-write: a file overwrite lands in new blocks |
| Linux | ATA SANITIZE, ATA SECURITY ERASE UNIT, NVMe Sanitize, NVMe Format, crypto erase | DEVICE-DEPENDENT; never run on a physical drive |
| Linux | HPA change | DEVICE-DEPENDENT; volatile SET MAX by default |
| Linux | File erase, free-space wipe, logical volume acquisition | No physical record |
| All three | Backup restore | Pre-write chunk verification, post-restore read-back hash |
| All three | Live-desktop trace sweep | Enumeration ran on a real Windows 11 desktop (2026-09-27) and found nothing to remove; no removal on a real desktop |
| All three | Registered physical recovery benchmark | Runner exists; BLOCKED at gate 1 of [`physical-benchmark-checklist.md`](../physical-benchmark-checklist.md) |

## Remaining limits

These are not missing evidence. They are what the platform or the device
allows, or what this build deliberately does not do.

| Platform | Capability | State | Why |
|---|---|---|---|
| Windows | ATA SECURITY ERASE UNIT | NOT IMPLEMENTED | The sequence sets a drive password first; a refused or interrupted erase leaves the drive locked, and no recovery path has been built and tested on Windows. ATA SANITIZE is offered instead |
| Windows | NVMe Format NVM | PLATFORM-LIMITED | The in-box NVMe driver does not pass Format NVM through `IOCTL_STORAGE_PROTOCOL_COMMAND` |
| Windows | Free-space wipe | NOT IMPLEMENTED | How NTFS allocates a filling file (MFT zone, reserved clusters) has not been measured |
| macOS | ATA and NVMe device sanitize, crypto erase | PLATFORM-LIMITED | No public ATA pass-through or NVMe admin-command interface for applications |
| macOS | HPA/DCO discovery and change | PLATFORM-LIMITED | No public ATA pass-through |
| macOS | Free-space wipe | NOT IMPLEMENTED | APFS is copy-on-write and shares free space across a container's volumes |
| macOS | Internal Apple storage | BLOCKED FOR SAFETY | Never raw-written or imaged: the Secure Enclave encrypts it. Erase All Content and Settings is the recommended path; Sanctum cannot perform or verify it |
| All | Device sanitize behind a USB or card-reader bridge | DEVICE-DEPENDENT (refused on `usb-flash`, `mmc`) | The bridge translates reads and writes only |
| All | Overwrite on flash | limit on SUPPORTED / IMPLEMENTED | Cannot reach remapped or over-provisioned blocks: a Clear of the addressable storage, not NAND-level destruction |
| Linux, Windows | DCO | never modified | DCO RESTORE can make a drive report another model's geometry; it is discovered only |
| Windows, macOS | Raw acquisition | limit | No software write block exists; use a hardware write blocker for evidence |
| macOS | Identity binding | limit | No ioctl returns a serial; it is re-read from `system_profiler` just before the raw device is opened and the size is bound from the open descriptor. A different disk of the same size taking the same `diskN` in that window is not detected; see [`security-review-cross-platform.md`](../../security-review-cross-platform.md) |
| Windows, macOS | Privilege | limit | The Linux socket helper does not run here; raw work runs in the elevated Sanctum process itself, a wider privileged surface than the Linux split |

## How a row becomes SUPPORTED

Follow [`physical-validation-procedure.md`](../physical-validation-procedure.md):
designated test media, a clean build, a discovery cross-check against the OS's
own tools, the full workflow with backup, approval and typed serial, independent
verification, then `scripts/record_physical_validation.py` with every field and
the run folder committed. Regenerating the matrix with
`python scripts/capability_matrix.py` then lifts that capability to SUPPORTED
for that platform and device class only. A failed run is recorded too, as
`FAIL`, and lifts nothing.
