# Platform support

One sanitization product, one capability model, three platform adapters.
**Nothing here is inferred from the platform name.** Support is stated per
capability, per platform and, for physical validation, per device class.

**The authoritative per-platform matrix is generated, not written:**
[`validation/capability-completion-2026-09-28/capability-matrix.md`](validation/capability-completion-2026-09-28/capability-matrix.md)
(and `.json`), produced by `scripts/capability_matrix.py` from the capability
resolver (`core/platform/capability.py`) and the validation record
(`core/platform/validation_record.json`). A test fails if the committed copy
drifts from the code. What changed and what remains is in
[`validation/capability-completion-2026-09-28/README.md`](validation/capability-completion-2026-09-28/README.md).
The app computes the same answers live (the *Platform* screen, `GET
/platform`, and each device's assessment on *Devices*).

## Legend

The resolver's states, with the words the interface shows
(`core/platform/model.py: STATE_LABELS`). Implementation and physical
validation are separate columns in the matrix and are never merged.

| Label | Meaning |
|---|---|
| **SUPPORTED** | Implemented, runnable here, and a PASS run on real hardware **of that device class** is recorded in `validation_record.json`. One class never validates another. |
| **IMPLEMENTED / UNVALIDATED** | Implemented and runnable; tested with fixtures, synthetic images and adapter doubles only. No recorded physical run. |
| **DEVICE-DEPENDENT** | Implemented; runs only when the device itself reports the mechanism and no USB or card-reader bridge hides it. The reason says which. |
| **REQUIRES PRIVILEGE** | Implemented, but this process lacks the OS privilege (root on Linux and macOS, Administrator on Windows). |
| **PLATFORM-LIMITED** | The operating system offers applications no path to the mechanism. |
| **BLOCKED FOR SAFETY** | Implemented, and refused for this device by a safety rule (system disk, mounted volume, internal Apple storage, virtual disk). |
| **NOT IMPLEMENTED** | The OS could do it; this build has no code for it. Refused with the reason. |

CI runs on virtual machines with virtual disks. **CI-validated is not
physically validated.** CI proves each platform's backends ship in the package
and runs a read-only native smoke (one read handle, identity IOCTLs, one
sector) on real Windows and macOS runners; no write handle and no destructive
command exist in it.

## Physically validated, and nothing else

From `core/platform/validation_record.json` `physical_validations`:

| Platform | Capability | Device class | Device, date | Evidence |
|---|---|---|---|---|
| Linux | Whole-drive clear (addressable overwrite) | usb-flash | TOSHIBA TransMemory 7.76 GB, 2026-09-05, earlier build | [`validation/hardware.md`](validation/hardware.md) Phase A |
| Linux | Device discovery | usb-flash | same stick, 2026-09-05 | `hardware.md` A.1 |
| Linux | Raw physical-device acquisition | usb-flash | same stick, 2026-09-05 | `hardware.md` Phase B |
| Windows | Device discovery | usb-flash | TOSHIBA TransMemory (`SANCTUMREC`), 2026-09-27 | [`validation/windows-hardware-2026-09-27-fixes/`](validation/windows-hardware-2026-09-27-fixes/README.md) |
| Windows | File erase | class not recorded | host system disk (NTFS), 2026-09-27 | same |
| Linux | File erase | usb-flash | same stick (FAT32), 2026-09-28; the overwrite could not be read back (vfat has no extent map) | [`validation/linux-file-erase-restore-2026-09-29/`](validation/linux-file-erase-restore-2026-09-29/README.md) |
| Linux | Backup restore | usb-flash | same stick, whole device, same-device restore, 2026-09-29; read-back sha256 matches | same |

No firmware Purge has run on any drive, no HPA/DCO change has been made on a
drive, no Windows or macOS whole-drive clear or raw acquisition has run on a
physical device, no restore has run on a physical device other than that one Linux stick, and no macOS device
has been through the app at all.

## Summary by capability

This condenses the generated matrix; where they differ, the generated matrix
is right.

| Capability | Linux | Windows | macOS |
|---|---|---|---|
| Device discovery | SUPPORTED (usb-flash) | SUPPORTED (usb-flash) | IMPLEMENTED / UNVALIDATED |
| File erase | SUPPORTED (usb-flash; FAT32, read-back not possible) | SUPPORTED (host disk, class not recorded) | IMPLEMENTED / UNVALIDATED; on APFS the verification is refused rather than claimed |
| Free-space wipe | IMPLEMENTED / UNVALIDATED (FAT32, exFAT, ext4) | NOT IMPLEMENTED | NOT IMPLEMENTED |
| Whole-drive clear (addressable overwrite) | SUPPORTED (usb-flash only) | IMPLEMENTED / UNVALIDATED (`core/erase/blockclear.py` over `\\.\PhysicalDriveN`; the disk must be offline) | IMPLEMENTED / UNVALIDATED (external disks via `/dev/rdiskN`; internal Apple storage BLOCKED FOR SAFETY) |
| ATA SANITIZE | DEVICE-DEPENDENT | DEVICE-DEPENDENT (`IOCTL_ATA_PASS_THROUGH`) | PLATFORM-LIMITED |
| ATA SECURITY ERASE UNIT | DEVICE-DEPENDENT | NOT IMPLEMENTED | PLATFORM-LIMITED |
| NVMe Sanitize | DEVICE-DEPENDENT | DEVICE-DEPENDENT (`IOCTL_STORAGE_REINITIALIZE_MEDIA`) | PLATFORM-LIMITED |
| NVMe Format NVM | DEVICE-DEPENDENT | PLATFORM-LIMITED | PLATFORM-LIMITED |
| Cryptographic erase | DEVICE-DEPENDENT (ATA crypto scramble; a TCG Opal drive is recognised but not reverted: no PSID input) | DEVICE-DEPENDENT (ATA crypto scramble or NVMe Sanitize crypto) | PLATFORM-LIMITED (Erase All Content and Settings is recommended, not performed) |
| Raw physical-device acquisition | SUPPORTED (usb-flash) | IMPLEMENTED / UNVALIDATED (`GENERIC_READ` only; no software write block exists, and the report says so) | IMPLEMENTED / UNVALIDATED (external disks; internal Apple storage not offered) |
| Logical volume acquisition | IMPLEMENTED / UNVALIDATED | IMPLEMENTED / UNVALIDATED | IMPLEMENTED / UNVALIDATED |
| HPA / DCO discovery | DEVICE-DEPENDENT | DEVICE-DEPENDENT | PLATFORM-LIMITED |
| HPA / DCO modification | DEVICE-DEPENDENT (guarded workflow; HPA only, volatile SET MAX by default; DCO never modified) | DEVICE-DEPENDENT (same workflow) | PLATFORM-LIMITED |
| Backup restore | SUPPORTED (usb-flash, same-device) | IMPLEMENTED / UNVALIDATED | IMPLEMENTED / UNVALIDATED |
| Live-desktop trace sweep | IMPLEMENTED / UNVALIDATED | IMPLEMENTED / UNVALIDATED | IMPLEMENTED / UNVALIDATED |

Every DEVICE-DEPENDENT device-sanitize and HPA/DCO row is refused on
`usb-flash` and `mmc` where the matrix says so: a USB or card-reader bridge
usually translates only reads and writes, so the command does not reach the
controller behind it. An ordinary erase never changes the HPA; when hidden
bytes are found it erases the accessible range and reports the hidden byte
count as a limitation.

## CI record, 2026-09-22 to 2026-09-27

The table below is the software-path evidence from `platform-ci` on
`release/cross-platform-validation`, three runners - Ubuntu 24.04.5 (x86_64),
Windows 11 build 10.0.26100 (AMD64), macOS 14.8.9 (arm64). Suite results are in
`core/platform/validation_record.json`; the adapter and package evidence are
the `platform-smoke-*.json` and `package-smoke-*.json` artifacts of that run.
**VALIDATED** here means executed on that OS's runner (virtual disks), not on
a physical device. The record predates the Windows and macOS block engines;
for whole-drive, device sanitize, acquisition and restore the current state is
the summary above.

| Feature | Linux | Windows | macOS |
|---|---|---|---|
| Device discovery | **VALIDATED** - `lsblk -J -O -b` with a `/sys/block` fallback and by-id identity; run on the host and on the CI runner | **VALIDATED** - Storage module (`Get-Disk`, `Get-PhysicalDisk`, `Get-Partition`, `Get-Volume`, `Win32_PageFileUsage`) through one encoded PowerShell script; on the runner it found both disks and normalised them | **VALIDATED** - `diskutil list/apfs list/info -plist`; on the runner it found the internal disk and traced the boot APFS container to it |
| System/boot/mounted refusal | **VALIDATED** - root, `/boot`, swap and mounts; the runner's own disk was refused | **VALIDATED** - `IsBoot`, `IsSystem`, `%SystemDrive%`, page file, `hiberfil.sys`; the runner's boot disk **and** its page-file disk were both refused, each with its reason | **VALIDATED** - "the running macOS boots from an APFS container on this disk"; System/Data/VM/Preboot/Recovery roles also protect |
| Normalized device + assessment | **VALIDATED** | **VALIDATED** - every discovered device carried an assessment; protected ones read NOT AVAILABLE | **VALIDATED** |
| File erase | **VALIDATED** - `PosixBackend`: FIEMAP extents, xattrs, chattr flags, snapshot listing | **VALIDATED** - `WindowsBackend` on the runner's NTFS: retrieval pointers, resident-MFT detection, alternate data streams, read-only attribute | **VALIDATED** - `PosixBackend` darwin paths on APFS; the erase runs and the verification is refused rather than claimed |
| Folder / recursive erase | **VALIDATED** | **VALIDATED** - a real NTFS junction is created on the runner and proved unable to redirect the erase out of the named root | **VALIDATED** |
| Batch erase, progress, cancellation | **VALIDATED** | **VALIDATED** | **VALIDATED** |
| Document metadata cleanse | **VALIDATED** | **VALIDATED** (pure Python, run in the Windows suite) | **VALIDATED** |
| Filesystem metadata (names, size) | **PARTIAL** - rename chain and stepped truncation; journal and index copies are reported, not removed | **PARTIAL** - as Linux, and no unprivileged directory flush exists on Windows | **PARTIAL** |
| File-erase verification | **PARTIAL** - physical read-back of pre-captured extents; needs raw read access, impossible on tmpfs | **PARTIAL** - extents come from `FSCTL_GET_RETRIEVAL_POINTERS` (whole runs); the read-back itself needs elevation, and unelevated it is reported *not verified* | **NOT VERIFIABLE on APFS** - copy-on-write; reported with its reason, never as a pass |
| Signed certificate, hash-chained ledger | **VALIDATED** | **VALIDATED** - the packaged app issued and verified one on the runner | **VALIDATED** - same |
| Desktop package | **VALIDATED** - AppImage and `.deb`; installed and run on Debian 12 and Ubuntu 22.04 with 23 of 23 packaged checks in CI (`platform-ci` run 35706589476, commit `ba13a9a`, 2026-09-22, an earlier build). Isolated smoke of the 2026-09-26 build: 22 PASS, 2 NOT RUN (the two need a real device), [`validation/package-2026-09-25/`](validation/package-2026-09-25/README.md) | **VALIDATED in CI** - `SanctumSetup.exe` built, installed silently, driven and uninstalled on the runner. Unsigned. | **VALIDATED in CI** - `Sanctum.dmg` built and mounted, `Sanctum.app` driven through erase and certificate, 24 of 24 checks. Unsigned, not notarized. |

Since then CI also asserts that every backend module the resolver names is
present in each package and binds on its own OS, and runs the read-only native
smoke described above. None of that is physical validation.

Separately, on 2026-09-27 a human installed the package on a physical Windows
11 machine: device discovery and the mounted-device refusal against a real
USB stick, and file/folder erase → verify → certificate on the host system
disk (the stick was not written)
([`validation/windows-hardware-2026-09-27-fixes/`](validation/windows-hardware-2026-09-27-fixes/README.md)).
At that date Windows had no whole-drive or raw-acquisition engine; both have
since been implemented and neither has run on a physical device. The
2026-09-28 per-capability evidence search is kept as a dated record in
[`validation/evidence-reconciliation-2026-09-28/`](validation/evidence-reconciliation-2026-09-28/README.md).
Row-by-row physical breakdown:
[`validation/hardware-platform-matrix.md`](validation/hardware-platform-matrix.md).

## Whole-drive work per platform

| | Linux | Windows | macOS |
|---|---|---|---|
| Engine | `core/erase/drive.py` (`O_DIRECT`, `BLKGETSIZE64`, `hdparm`, `nvme-cli`, `sedutil-cli`) | `core/erase/blockclear.py` over `\\.\PhysicalDriveN` (`FILE_FLAG_NO_BUFFERING`, `FILE_FLAG_WRITE_THROUGH`); device sanitize in `core/erase/devicesanitize.py` | `core/erase/blockclear.py` over `/dev/rdiskN` |
| Identity binding | serial and `/dev/disk/by-id` re-read before writing | the open handle is asked its disk number, serial and length (`IOCTL_STORAGE_GET_DEVICE_NUMBER`, `IOCTL_STORAGE_QUERY_PROPERTY`, `IOCTL_DISK_GET_LENGTH_INFO`) and refused on any difference from the plan; a drive letter is never a target | size and block size from the open descriptor; no ioctl returns a serial, so the serial is re-read from `system_profiler` just before opening, a window the report states |
| Before a write | mounted and system disks refused; a human unmounts | the disk must expose no volume: take it offline first (`POST /devices/prepare`, non-persistent, or Disk Management); system and boot disks refused | every volume unmounted (`POST /devices/prepare` runs `diskutil unmountDisk`); internal Apple storage and synthesized APFS containers refused |
| Verification | full read-back to 64 GiB, seeded sampling above | same rule, same verifier | same rule, same verifier |
| Resume | from the last ledgered checkpoint; firmware methods restart | checkpoints and resume in the engine | checkpoints and resume in the engine |
| Physical validation | usb-flash only (2026-09-05) | none recorded | none recorded |

The preparation step is never part of an erase: it is its own call on the real
disk, it shows the volumes it affects first, and it needs the serial typed by
hand. There is no dry-run mode anywhere in the product.

The app's *Filesystems* table (`core/platform/filesystems.py`) gives one
platform-wide word for whole-drive clear: SUPPORTED on Linux, UNVERIFIED on
Windows and macOS. Per-device answers come from the resolver, and the matrix
generated from it is authoritative for whole-drive state.

## Filesystems

Detecting a filesystem is not supporting it. The app's *Filesystems* table
keeps six rows per filesystem — detect, recover from image, erase files,
filesystem metadata, free-space wipe, whole drive — per platform, computed by
`core/platform/filesystems.py` from the code that implements each operation.
The summary:

| Filesystem | Linux | Windows | macOS |
|---|---|---|---|
| NTFS | erase files, undelete from image | erase files (UNVERIFIED) | detect only when mounted read-only; erase UNSUPPORTED |
| FAT32 / exFAT | erase files, free-space wipe, undelete | erase files (UNVERIFIED) | erase files (UNVERIFIED) |
| ext4 | erase files, free-space wipe, undelete (recovers little by design) | UNSUPPORTED (not mountable) | UNSUPPORTED |
| XFS | erase files | UNSUPPORTED | UNSUPPORTED |
| Btrfs, F2FS | erase *runs*, NOT VERIFIABLE (copy-on-write) | UNSUPPORTED | UNSUPPORTED |
| APFS | UNSUPPORTED (not mountable read-write) | UNSUPPORTED | erase *runs*, NOT VERIFIABLE (copy-on-write) |
| HFS+ | erase files | UNSUPPORTED | erase files (UNVERIFIED) |
| ReFS | UNSUPPORTED | erase *runs*, NOT VERIFIABLE (copy-on-write) | UNSUPPORTED |

These words are the filesystem table's own status vocabulary, not the
resolver's. Whole-drive work is filesystem-independent; its state is in the
summary above.

## SSD and flash, on every platform

The same sentence is shown on Linux, Windows and macOS
(`core/platform/base.py: FLASH_LIMITATION`): an overwrite cannot address
blocks the flash controller has remapped or held in over-provisioned space.
A whole-drive clear is a Clear of the addressable storage, not NAND-level
destruction. The application therefore probes for a purge-capable mechanism,
offers it only when the device reports it, refuses rather than silently
downgrading, and reports the limitation. A USB, NVMe, SD or eMMC device is
treated as flash unless the OS positively reports a spinning disk, so the
limitation is never left out.

## What remains limited, and why

- **Windows ATA SECURITY ERASE UNIT: NOT IMPLEMENTED.** The sequence sets a
  drive password first; if the erase is then refused or interrupted the drive
  stays locked, and no recovery path for that has been built and tested on
  Windows. ATA SANITIZE is offered instead where the drive supports it.
- **Windows NVMe Format NVM: PLATFORM-LIMITED.** The in-box NVMe driver does
  not pass Format NVM through `IOCTL_STORAGE_PROTOCOL_COMMAND`. NVMe Sanitize
  is used instead where the drive supports it.
- **macOS device sanitize, crypto erase and HPA/DCO: PLATFORM-LIMITED.**
  macOS exposes no public ATA pass-through or NVMe admin-command interface to
  applications. Internal Apple storage is purged by macOS's own *Erase All
  Content and Settings*, which the app recommends and cannot perform or
  verify.
- **Free-space wipe on Windows and macOS: NOT IMPLEMENTED.** Its fill
  behaviour was measured on FAT32, exFAT and ext4 on Linux only; NTFS
  allocation of a filling file and APFS shared free space have not been
  measured.
- **No software write block on Windows or macOS.** Raw acquisition opens the
  device read-only (`GENERIC_READ` on Windows, a read-only descriptor on
  macOS), but nothing equivalent to Linux's `BLKROSET` exists; the acquisition
  report says so.
- **DCO is never modified** on any platform; DCO RESTORE is not issued by this
  build.

## Privilege

| | Linux | Windows | macOS |
|---|---|---|---|
| UI and API | unprivileged, loopback only | unprivileged, loopback only | unprivileged, loopback only |
| Raw-device work (whole-drive clear, device sanitize, raw acquisition, HPA/DCO, restore) | separate root helper over a `SO_PEERCRED`-authenticated Unix socket | an elevated process: **Run as administrator**. The Windows build has no separate helper | root: the adapter's advice is to start Sanctum itself with `sudo`. The socket helper's `SO_PEERCRED` peer check is Linux-only, so on macOS privilege is the process's own effective uid |
| Without it | the capability reads REQUIRES PRIVILEGE | the capability reads REQUIRES PRIVILEGE | the capability reads REQUIRES PRIVILEGE |

The app never elevates itself. The Windows installer is per-user by default
and has no elevation manifest (`uac_admin=False`); elevation is a deliberate
*Run as administrator* by the operator.
