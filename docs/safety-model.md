# AEGIS safety model

AEGIS handles two kinds of operation that can do lasting harm: changing evidence, and destroying
data. This document lists what AEGIS will and will not do, and **where each rule is enforced**. A rule
enforced only in the user interface is treated as a convenience; every rule below that protects data
is enforced by the engine, which re-checks it immediately before acting.

## 1. Evidence is only read

| Rule | Enforcement |
|---|---|
| Acquisition opens the source read-only (file handle or `\\.\PhysicalDriveN` with read access only). | Engine `acquire` |
| An acquisition destination may not be on the source disk. | Engine preflight |
| Windows has no kernel software write blocker; every acquisition records `NO_SOFTWARE_WRITE_BLOCK` so the report says so. Use a hardware write blocker for court evidence. | Engine (recorded limitation) |
| Recovery runs on images only; a live device path is refused (`EvidenceOnly`). | Engine `recover` |
| Recovered files are written to the case folder, never next to the evidence. | Engine |
| AI enhancement writes a separate, labelled derivative. The original is hashed before and after and must be unchanged. | Engine `enhance` |
| The original image's size and modification time are checked unchanged by the real-media tests. | `PendriveImagesSelfTest` |

## 2. Destruction is fail-closed

### Which devices can be sanitized

Only removable media attached over **USB** or **SD/MMC** are eligible. Everything else is refused:

- internal SSD, NVMe, SATA, SAS and RAID disks, **whether or not they hold the operating system**;
- the system disk and the boot disk;
- any device whose bus type the engine cannot determine;
- virtual disks.

This rule is checked in three independent places, so a defect in one does not open a path:

1. the engine bridge (`sanitize-device`, `prepare-device`): refuses before the Variant engine is
   called, and writes an `aegis.sanitize.refused` ledger entry;
2. the Windows device adapter (`execute_drive_sanitization`): refuses a non-USB/MMC or internal device
   even if called directly;
3. the user interface: internal drives show **Internal drive — sanitization disabled** and cannot be
   selected.

The system disk is checked **before** privilege, so even an elevated AEGIS refuses it.

### Gates before the first write

| Gate | Purpose |
|---|---|
| Device eligibility (above) | Never touch internal storage |
| Typed serial number | The operator types the serial of the device they mean |
| Explicit acknowledgement | `--confirm-destructive` is never implied |
| Backup gate | A verified AEGIS acquisition of the **same serial**, or the typed waiver `NO BACKUP`, which is ledgered |
| Identity re-binding | Immediately before the first write the engine re-resolves the disk number, serial and size and binds them to the write handle; any difference aborts (`IdentityMismatch`, `DeviceVanished`) |
| Mounted volumes | Volumes are taken offline (non-persistently) by **Prepare**; a mounted target is refused (`MountedRefused`) |

### Methods offered

Methods come from what the engine **probed** on the device, never from a fixed list. A method the
engine cannot run on that device is shown with its state and reason and cannot be selected; nothing is
silently substituted.

| Method | Outcome | Notes |
|---|---|---|
| Zero-fill overwrite, single pass | Clear | Every addressable sector written and read back |
| Legacy DoD 5220.22-M, 3 passes | Clear | Historical profile; NIST SP 800-88 Rev. 2 does not require multiple passes |
| ATA SANITIZE, NVMe Sanitize, cryptographic erase | Purge | Only if the device reports support; USB bridges rarely pass these through |
| Pseudorandom fill | — | Not implemented, so not offered |
| Gutmann, 35 passes | — | Not meaningful for modern media; not offered |

AEGIS uses NIST SP 800-88 Rev. 2 vocabulary but is **not** NIST-certified. A Clear reaches only the
addressable LBA range: remapped flash blocks and HPA/DCO areas are not covered unless the HPA/DCO
workflow ran first. The report states the outcome actually achieved.

### No dry run

Every device operation runs for real once its gates pass. Test only on disposable media.

## 3. File and folder sanitization

Files and folders are overwritten by the native AEGIS sanitizer (`aegis_cli.exe`) and verified by
read-back. Overwriting a file through a filesystem cannot guarantee that SSD or flash controllers did
not keep older copies elsewhere; the report says so. Each run is recorded in the case ledger
(`aegis.desktop.sanitize.file`).

### Deep Forensic Purge

After a sanitization, AEGIS can remove the traces Windows keeps of the erased item:

- Recent shortcuts, jump lists and Recycle Bin copies are removed **only when the engine ties them to
  the erased path on evidence**; weaker matches are reported, never removed;
- the Windows thumbnail cache cannot be tied to one file, so clearing it is a separate opt-in that
  clears the whole per-user cache. Explorer is asked to close through the Restart Manager and is
  restarted; **nothing is force-killed**;
- not searched: the Windows Search index, application-private recent lists, shadow copies and sync
  clients. The report lists the places searched and not searched.

## 4. Everything is recorded and verifiable

- Each case has a hash-chained, content-addressed ledger. Every engine operation, refusal and desktop
  action (`aegis.desktop.*`) is appended; a forged engine operation through the desktop `record`
  command is blocked.
- Editing any entry breaks the chain at that sequence number (`BROKEN`), which **Verify Audit Chain**
  reports.
- Reports are signed with Ed25519. The signing key lives in `%APPDATA%\AEGIS\keys`, its passphrase
  protected by Windows DPAPI. **Verify Signature & Chain** checks the signature, the genesis key and
  the ledger; a one-byte change yields `FAILED_VERIFICATION`.

## 5. Honest results

The engine reports `SUCCESS`, `SUCCESS_WITH_WARNINGS`, `FAILED`, `BLOCKED` (a safety gate refused),
`UNSUPPORTED`, `UNAVAILABLE` or `CANCELLED`. A cancelled
or failed operation is never shown as a success, progress is never simulated, and demo data is never
presented as real.
