Superseded for current capability state by ../capability-completion-2026-09-28/README.md; kept unchanged below as the record of 2026-09-28.

# Evidence reconciliation, 2026-09-28

**Question.** Several capabilities are described as hardware-unverified. The
owner reports that some of them have been physically tested many times,
including on macOS. Does the repository hold evidence of those runs?

**Answer.** For five of the capabilities listed below, no. The repository
records physical runs for overwrite Clear, recovery after delete and quick
format, and the Windows package. It records no physical run of firmware Purge,
HPA/DCO unlock, backup restoration, the registered physical benchmark, or any
macOS device. Two of the listed items are not missing evidence but missing code,
and a third, backup restoration, turned out to be missing code as well.

Machine-readable table: [`reconciliation.json`](reconciliation.json). The
regression test that pins it to the app's own record is
`tests/platform/test_evidence_reconciliation.py`.

## What was searched

- `docs/validation/`, every file and subdirectory, including `hardware.md`,
  `hardware-platform-matrix.md`, `platform-matrix.md`, `feature-matrix.md`,
  `module-validation-matrix.md`, the release and audit reports, the campaign,
  remediation, polish, browser, package and Windows hardware folders.
- `core/platform/validation_record.json`, in every committed version.
- `docs/validation/physical-module-baseline.json` and
  `campaign-2026-09-24/physical-post-campaign-snapshot.json`.
- Every branch on `origin`, and the full git history including deleted files
  and commit messages (`git log --all`, `--diff-filter=D`, `-S` on
  `whole_drive_purge` and `hidden_area_unlock`).
- The code: `core/platform/*.py`, `core/erase/`, `core/carve/acquire.py`,
  `core/carve/evidence.py`, `scripts/media_benchmark.py`, `ui/src/`.

No `results-<timestamp>/` run directory is committed; `hardware.md` is the
record of those runs.

## Five states

| State | Meaning |
|---|---|
| PHYSICALLY VALIDATED | A recorded run on real hardware, with its evidence in the repository |
| SOFTWARE/SYNTHETIC ONLY | Tested against fixtures, loop devices or synthetic images |
| SUPPORTED BUT NOT PHYSICALLY VALIDATED | The code exists and is offered; no recorded run on real hardware |
| UNSUPPORTED / NOT IMPLEMENTED | No code performs it; the app refuses with the reason, or offers nothing |
| EVIDENCE MISSING | The owner reports a physical run, but no record of it exists here |

## Result

| # | Capability | Status | Physical evidence found |
|---|---|---|---|
| 1 | Firmware Purge | SUPPORTED BUT NOT PHYSICALLY VALIDATED; owner-reported runs EVIDENCE MISSING | none |
| 2 | ATA SANITIZE | same | none |
| 3 | ATA SECURITY ERASE | same | none |
| 4 | NVMe sanitize | same | none |
| 5 | NVMe format / crypto erase | same | none |
| 6 | HPA/DCO unlock | SUPPORTED BUT NOT PHYSICALLY VALIDATED; owner-reported runs EVIDENCE MISSING | none; on the one stick the probe was skipped behind the USB bridge, by design |
| 7 | Backup creation | SOFTWARE/SYNTHETIC ONLY | none; the gate hashes an image the operator supplies |
| 8 | Backup restoration | **UNSUPPORTED / NOT IMPLEMENTED** | no restore exists in the app; the benchmark prints a manual `dd` command, never run |
| 9 | Registered physical recovery benchmark | SUPPORTED BUT NOT PHYSICALLY VALIDATED | none; checklist blocked at gate 1 |
| 10 | Trace sweep on a live desktop | SUPPORTED BUT NOT PHYSICALLY VALIDATED | enumeration on a real Windows 11 desktop, 2026-09-27, found nothing to remove; no removal on a real desktop |
| 11 | macOS physical device | SUPPORTED BUT NOT PHYSICALLY VALIDATED; owner-reported runs EVIDENCE MISSING | none; the 2026-09-27 record says no Mac hardware was available |
| 12 | Windows whole-drive sanitization | **UNSUPPORTED / NOT IMPLEMENTED** | n/a |
| 13 | Windows raw physical-device acquisition | **UNSUPPORTED / NOT IMPLEMENTED** | n/a; confirmed on the physical Windows machine, 2026-09-27 |

Physically validated, unchanged by this search:

| Capability | Device | Date, build | Evidence |
|---|---|---|---|
| Linux overwrite Clear, full read-back, report tamper check | TOSHIBA TransMemory 7.76 GB, USB, serial `B103B9C19DE1CCC1BD535ACB` | 2026-09-05, earlier build | `hardware.md` Phase A |
| Recovery after delete (FAT32, exFAT) and quick format | same stick | 2026-09-05, earlier build | `hardware.md` Phase B: 456/456, 460/460, 10 of 10 recoverable |
| Mounted-device refusal | same stick | 2026-09-23, earlier build | `demo/qa.md` §24 |
| Windows install, discovery, mounted refusal, file/folder erase → verify → certificate | physical Windows 11 Home 10.0.26200, USB stick `SANCTUMREC` | 2026-09-27, `437081e` | `windows-hardware-2026-09-27-fixes/` |

### Why firmware Purge cannot have run on the recorded device

The only physical drive in the record probed as `ata_security_erase: false`,
`ata_sanitize_ops: []`, `is_sed_opal: false`, achievable levels `CLEAR` only
(`hardware.md`, Phase A capability probe). The app would not have offered Purge
on it. A Purge run would need a different drive, and no such drive appears
anywhere in the record.

### Why `validation_record.json` is unchanged

The app shows Purge and HPA/DCO unlock as *Unverified* until
`validation_record.json` has `hardware.linux.whole_drive_purge` or
`hardware.linux.hidden_area_unlock` with `state: PASS`. That section has been
`{}` in every committed version. Nothing found here justifies a PASS, so it
stays empty.

## What changed in the application

- **Windows raw acquisition is refused with its real reason.** A
  `\\.\PhysicalDriveN`, `\\.\E:` or `\\?\Volume{...}` source used to fail as
  "acquisition source not found". It now fails before anything is opened with
  "raw physical-device acquisition is not implemented on Windows", in both
  `core/carve/acquire.py` and `POST /jobs/acquire`.
- **The *Not yet proven on hardware* list names each item's state.**
  `ui/src/lib/summary.ts` now separates "implemented, never run on a drive"
  from "not implemented", adds Windows raw acquisition, restates backup
  restoration as not implemented, records the Windows physical run, and says
  no macOS physical run is recorded. Its first line used to say this release
  had no physical validation, which the Windows run of 2026-09-27 made false.

## How to close a row

A capability moves to PHYSICALLY VALIDATED when its run is recorded here, in
the same shape as `hardware.md`: date, build commit, device model, serial,
interface, exact method, result, verification output, and the signed report
and ledger. For Purge and HPA/DCO, `validation_record.json` then gets a
`hardware` PASS entry, which is what lifts *Unverified* in the app.

If the runs the owner describes exist on another machine, committing their
result folders and signed reports is enough to reopen this reconciliation.
