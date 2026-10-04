# Hardware validation matrix

CI success is not hardware validation. Everything in `platform-ci` runs on a
virtual machine with virtual disks; it proves the code runs on that operating
system, not that a physical device was sanitized. This page keeps the two
apart.

**The authoritative per-platform, per-device-class matrix is generated from
the code:** [`capability-completion-2026-09-28/capability-matrix.md`](capability-completion-2026-09-28/capability-matrix.md),
with what changed in
[`capability-completion-2026-09-28/README.md`](capability-completion-2026-09-28/README.md).
This page is the hardware-evidence view of the same facts. Where the
implementation state is quoted, it uses the resolver's labels (SUPPORTED,
IMPLEMENTED / UNVALIDATED, DEVICE-DEPENDENT, PLATFORM-LIMITED, REQUIRES
PRIVILEGE, BLOCKED FOR SAFETY, NOT IMPLEMENTED).

Evidence states on this page, not interchangeable:

| State | Meaning |
|---|---|
| **VALIDATED** | Performed on real hardware, on real media, with the run recorded in `docs/validation/` and, since 2026-09-28, in `core/platform/validation_record.json` `physical_validations` for that device class. |
| **CI-VALIDATED** | Executed on a real runner of that OS, against that runner's own disks and filesystems. No physical media. |
| **NOT YET VALIDATED** | The software path is implemented; nobody has run it on hardware of that kind. The resolver shows it IMPLEMENTED / UNVALIDATED or DEVICE-DEPENDENT. |
| **NOT IMPLEMENTED / PLATFORM-LIMITED** | No code in this build, or the OS offers no path. Refused by the app with a reason. |

Physically validated, and nothing else: Linux whole-drive clear, device
discovery and raw acquisition on one TOSHIBA TransMemory USB stick
(`usb-flash`, 2026-09-05); Windows device discovery on a USB stick
(`usb-flash`, 2026-09-27); Windows file erase on the host system disk (device
class not recorded, 2026-09-27).

The 2026-09-28 per-capability evidence search, with every physical run found
and every capability that has none, is kept as a dated record in
[`evidence-reconciliation-2026-09-28/`](evidence-reconciliation-2026-09-28/README.md).
Its Windows whole-drive, Windows raw-acquisition and backup-restoration rows
were NOT IMPLEMENTED on that date; all three have since been implemented and
none has been run on a physical device.

Most VALIDATED rows below are a run from 2026-09-05 or 2026-09-23 with the build of
that date, on Linux. **No physical validation was run for the `76dde42`
release** (2026-09-26). A later, separate run on 2026-09-27, first at
`2d00526` and then, after two packaging fixes that run itself found
(`ba66fbe`, `437081e`), at `437081e`, physically validated the Windows rows
below for the first time — see
[`windows-hardware-2026-09-27-fixes/`](windows-hardware-2026-09-27-fixes/README.md)
(the `2d00526` record is preserved at
[`windows-hardware-2026-09-27/`](windows-hardware-2026-09-27/README.md)) —
and is marked accordingly. The app shows firmware Purge and HPA/DCO
modification as DEVICE-DEPENDENT and never physically validated until a
hardware result for that device class is recorded.

## Whole-drive sanitization

| Target | State | Evidence |
|---|---|---|
| Linux, USB flash (TransMemory 7.76 GB), Clear by overwrite | **VALIDATED** | `docs/validation/hardware.md`: three Phase A runs, the third (2026-09-05) clean |
| Linux, SATA/NVMe internal, Clear | NOT YET VALIDATED | refused on this host: internal disks hold the running system |
| Linux, firmware Purge (ATA SANITIZE, SECURITY ERASE, NVMe sanitize/format) | NOT YET VALIDATED (DEVICE-DEPENDENT) | selected and dispatched in code; no drive has executed it; refused behind USB and card-reader bridges. A TCG Opal drive is recognised but not reverted: the build has no PSID input |
| Linux, HPA/DCO modification on a drive that has one | NOT YET VALIDATED (DEVICE-DEPENDENT) | guarded workflow (`core/device/hidden_area_workflow.py`): HPA only, volatile SET MAX by default, DCO never modified; an ordinary erase no longer changes the HPA. No device with an HPA was available |
| Windows, whole-drive clear | NOT YET VALIDATED (IMPLEMENTED / UNVALIDATED) | `core/erase/blockclear.py` over `\\.\PhysicalDriveN`, bound to disk number, serial and length; disk must be offline. Adapter doubles only |
| Windows, ATA SANITIZE / NVMe Sanitize (block, crypto) | NOT YET VALIDATED (DEVICE-DEPENDENT) | offered only when IDENTIFY reports it; never run on a drive |
| Windows, ATA SECURITY ERASE UNIT | **NOT IMPLEMENTED** | a failed or interrupted erase would leave the drive locked with no tested recovery path |
| Windows, NVMe Format NVM | **PLATFORM-LIMITED** | the in-box driver does not pass Format NVM through |
| Windows, HPA/DCO modification | NOT YET VALIDATED (DEVICE-DEPENDENT) | same guarded workflow, ATA pass-through |
| macOS, whole-drive clear of an external disk | NOT YET VALIDATED (IMPLEMENTED / UNVALIDATED) | `/dev/rdiskN`; internal Apple storage is BLOCKED FOR SAFETY and *Erase All Content and Settings* is recommended instead |
| macOS, device sanitize, crypto erase, HPA/DCO | **PLATFORM-LIMITED** | no public ATA pass-through or NVMe admin interface |
| Any platform, backup restore | NOT YET VALIDATED (IMPLEMENTED / UNVALIDATED) | `core/restore.py` with post-restore hash verification; never run on a physical device. `scripts/media_benchmark.py` still prints a manual `dd` command, also never run |

## Device discovery and protection

| Target | State | Evidence |
|---|---|---|
| Linux, USB stick | **VALIDATED** (`usb-flash`, 2026-09-05) | `docs/validation/hardware.md` A.1 |
| Linux, host disks | **CI-VALIDATED** | `scripts/platform_smoke.py` on the development host and in CI; no physical record |
| Windows, runner's own disks | **CI-VALIDATED** | `platform-smoke-Windows.json`, `platform-ci` |
| Windows, physical machine with removable media | **VALIDATED** (2026-09-27) | installed package on a physical Windows 11 machine found 3 real devices including a USB stick, and correctly assessed the mounted one NOT AVAILABLE; [`windows-hardware-2026-09-27-fixes/`](windows-hardware-2026-09-27-fixes/README.md) |
| macOS, runner's own APFS disks | **CI-VALIDATED** | `platform-smoke-macOS.json`, `platform-ci` |
| macOS, physical Mac with removable media | NOT YET VALIDATED | needs a Mac and a disposable stick |

## File and folder erasure

| Target | State | Evidence |
|---|---|---|
| Linux, ext4/xfs/tmpfs | **CI-VALIDATED** (IMPLEMENTED / UNVALIDATED physically) | suite plus packaged smoke on the development host and in CI; no `physical_validations` record |
| Windows, NTFS on the runner | **CI-VALIDATED** | `validation-Windows.json` |
| Windows, real junction / reparse point | **CI-VALIDATED** | `tests/platform/test_windows_filesystem.py` creates a real junction on the runner |
| Windows, real machine, NTFS via the installed package | **VALIDATED** (2026-09-27) | erase → read-back verify → certificate issue → certificate verify, real, in a scratch directory on the machine's own system disk; trace sweep enumeration confirmed real (searched this machine's actual Recycle Bin and Recent shortcuts, found nothing to remove); [`windows-hardware-2026-09-27-fixes/`](windows-hardware-2026-09-27-fixes/README.md) |
| Any platform, trace sweep removing a real desktop trace | NOT YET VALIDATED | only synthetic homes have had a trace removed; no Linux or macOS desktop run |
| macOS, APFS on the runner | **CI-VALIDATED** | `validation-macOS.json` |
| Any platform, SSD residual behaviour after erase | NOT YET VALIDATED | needs physical media and out-of-band reading |

## Packages

| Target | State | Evidence |
|---|---|---|
| Linux AppImage / `.deb` on the build host | **VALIDATED** | packaged smoke; `.deb` installed and removed in Debian 12, AppImage run in Debian 12 and Ubuntu 22.04 |
| Windows `SanctumSetup.exe`, silent install → run → uninstall | **CI-VALIDATED**; also **VALIDATED** silent-install on a physical machine, 2026-09-27 (uninstall not exercised there) | `package-smoke-Windows.json`; [`windows-hardware-2026-09-27-fixes/`](windows-hardware-2026-09-27-fixes/README.md) |
| macOS `Sanctum.dmg` mounted and run | **CI-VALIDATED** | `package-smoke-macOS.json` |
| Windows install on a physical machine by a human | **VALIDATED** (2026-09-27) | [`windows-hardware-2026-09-27-fixes/`](windows-hardware-2026-09-27-fixes/README.md) |
| macOS install on a physical machine by a human | NOT YET VALIDATED | |
| Code signing / notarization | NOT PERFORMED | no certificates; `docs/packaging.md` |

## Acquisition

| Target | State | Evidence |
|---|---|---|
| Linux, raw physical-device acquisition, USB flash | **VALIDATED** (2026-09-05, `usb-flash`) | `hardware.md` Phase B: three acquisitions with `BLKROSET`, recovery 456/456, 460/460, 10 of 10 recoverable |
| Windows, raw physical-device and volume acquisition (`\\.\PhysicalDriveN`, a raw volume) | NOT YET VALIDATED (IMPLEMENTED / UNVALIDATED) | `core/carve/win_source.py`: `GENERIC_READ` only, bound to disk number, serial and length; no software write block exists on Windows and the report says so. Adapter doubles only. On 2026-09-27 the build of that date had no such code, confirmed directly: [`windows-hardware-2026-09-27/`](windows-hardware-2026-09-27/README.md) §4 (dated record) |
| macOS, raw acquisition of an external disk | NOT YET VALIDATED (IMPLEMENTED / UNVALIDATED) | `core/carve/mac_source.py` over `/dev/rdiskN`, `O_RDONLY`; internal Apple storage is not offered (Secure Enclave ciphertext) |
| Windows, M3 carving over a synthetic image, via `scripts/demo_fragmented.py` (dev venv, direct) | **SYNTHETIC, run on physical Windows hardware** (2026-09-27) | 6/6 ground-truth scenarios correct; [`windows-hardware-2026-09-27/`](windows-hardware-2026-09-27/README.md) §3 |
| Windows, M3 acquire + carve + media map, through the *installed package's own API* (`/jobs/acquire`, `/jobs/carve`), synthetic image | **SYNTHETIC, run through the installed package on physical Windows hardware** (2026-09-27) | Failed before `437081e` — the packaged app could not find its own signature table (`testkit/signatures.yaml` excluded from every prior build); fixed, then 5/6 candidates recovered (1 correctly deduplicated), media map present; [`windows-hardware-2026-09-27-fixes/`](windows-hardware-2026-09-27-fixes/README.md) §4–§5 |

## What would close the remaining rows

1. A Mac with a **disposable** external disk: discovery, the refusal on the
   internal disk, a whole-drive clear and a raw acquisition of the external
   disk.
2. The same disposable USB stick on Windows, run as Administrator and taken
   offline: whole-drive clear and raw acquisition (validates `usb-flash` only).
3. A spare SATA or NVMe drive that reports ATA SANITIZE or NVMe Sanitize, on
   Linux and on Windows, for the device-sanitize path.
4. A drive with an HPA set, for the hidden-area workflow.
5. A restore of a verified backup onto a disposable device, hashed by an
   independent tool.

Each run follows [`physical-validation-procedure.md`](physical-validation-procedure.md)
and is recorded with `scripts/record_physical_validation.py`; the matrix is
then regenerated with `scripts/capability_matrix.py`. A run lifts only its own
`(platform, capability, device class)`.

## Recorded CI evidence, 2026-09-22

`platform-ci` run 35680288845 on `release/cross-platform-validation`, all
jobs green. What the runners actually reported:

| Runner | Disks found | Protected, and why |
|---|---|---|
| Ubuntu 24.04.5, x86_64 | 1 (`/dev/sda`, 150 GB) | 1 — holds the running root filesystem |
| Windows 11 10.0.26100, AMD64 | 2 (`PhysicalDrive0`, `PhysicalDrive1`, 150 GB each) | 2 — `IsBoot` on the first, an active page file on `D:` for the second |
| macOS 14.8.9, arm64 | 1 (`disk0`, 325 GB, SSD) | 1 — the running macOS boots from an APFS container on it |

Every protected device was assessed NOT AVAILABLE, every capability row
carried a source, and whole-drive rows were UNSUPPORTED on Windows and macOS
(the state of that build; see the generated matrix for today's).

This is still not hardware validation: those are virtual disks on hosted
runners, and no removable media was attached to any of them.
