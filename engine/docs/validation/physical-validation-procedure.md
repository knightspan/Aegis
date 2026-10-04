# Physical validation procedure

A capability reads **SUPPORTED** (`VALIDATED_PHYSICAL`) for a device only when
the validation record holds a PASS run of that capability, on that platform,
on that **device class**. This file is the procedure that produces such a run.
Nothing in it runs automatically, CI never runs it, and it must never be run
against a device that holds data anyone needs.

## What one run validates, and what it does not

Evidence is matched on three keys at once:
`(platform, capability, device class)`.

| A run of ... | validates ... | does **not** validate ... |
|---|---|---|
| ATA SANITIZE on a SATA SSD, Linux | `linux / ata_sanitize / sata-ssd` | NVMe sanitize; ATA SANITIZE on Windows; any USB device |
| Whole-drive clear of a USB stick, Windows | `windows / whole_drive_clear / usb-flash` | an internal Windows disk; the system disk (always refused) |
| Raw acquisition of an external SSD, macOS | `macos / raw_acquisition / usb-ssd` | internal Apple storage (never offered) |

Device classes are computed by `core.platform.capability.device_class`:
`usb-flash`, `usb-ssd`, `usb-hdd`, `sata-hdd`, `sata-ssd`, `nvme`, `sas`, `mmc`,
`thunderbolt`, `apple-internal`, `virtual`, `unknown`.

## Before the run

1. **Designated test media only.** Write the device's model and serial in the
   run folder before anything is connected. A device that holds any data
   anyone may need is not a test device.
2. **Clean build.** Build from a clean checkout; the build's
   `core/platform/build_info.json` must carry the commit with no `+dirty`.
3. **Discovery cross-check.** Record Sanctum's discovery row for the device and
   the OS's own answer (`lsblk -O` / `udevadm info` on Linux, `Get-Disk` and
   `Get-PhysicalDisk` on Windows, `diskutil info -plist` and
   `system_profiler -json` on macOS). Model, serial and size must agree.
4. **Preflight.** Save the assessment (`GET /devices` or the Sanitize screen)
   showing the resolver's state for the capability under test. A capability
   the resolver does not offer on that device is not run.

## The run

5. For a destructive capability, go through the workflow in full: backup,
   verify-backup, plan, human approval with the typed serial, then execute with
   the one-use authorization. Never call the engine around the workflow.
6. Keep the signed report JSON, its PDF, the ledger excerpt and the job's
   progress log.
7. Run the independent checks the capability needs:
   * Clear: `sanctum verify-report`, and a recovery attempt (PhotoRec) before
     and after, as `hardware.md` Phase A did.
   * Device sanitize: the drive's own status (`hdparm --sanitize-status`,
     `nvme sanitize-log`, or the SANITIZE STATUS the report records) plus the
     read-back in the report.
   * Acquisition: hash the image with an independent tool and compare it to the
     record's SHA-256.
   * HPA/DCO: the native and accessible maxima read back by an independent
     tool after the change.
   * Restore: hash the restored range with an independent tool.

## Recording it

8. Commit the run folder under `docs/validation/<capability>-<date>/` with the
   report, ledger excerpt, logs and a README stating each field below.
9. Write an evidence JSON with every field and record it:

   ```
   python scripts/record_physical_validation.py evidence.json
   ```

   Required fields: `platform`, `capability`, `device_class`, `model`,
   `serial`, `interface`, `os`, `date`, `commit`, `method`, `preflight`,
   `operation`, `verification`, `artifacts` (paths that exist in the
   repository), `result` (`PASS` or `FAIL`), plus `report_hash` and
   `ledger_entry`. The script refuses an incomplete entry, an artifact that
   does not exist, and a duplicate.
10. Regenerate the matrix: `python scripts/capability_matrix.py`. The
    capability now reads SUPPORTED for that device class only.

A failed run is recorded too, with `result: FAIL`. It lifts nothing, and it is
evidence.

## Historical runs already recorded

`docs/validation/capability-completion-2026-09-28/historical-physical-runs.json`
entered the runs `hardware.md` and the Windows hardware records already
documented: Linux whole-drive clear, discovery and raw acquisition on a
TOSHIBA TransMemory USB stick (2026-09-05), and Windows discovery and file
erase on a physical Windows 11 machine (2026-09-27). Their build commit is
recorded where the source document names one, and says so where it does not.
