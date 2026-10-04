# Windows physical-hardware validation, 2026-09-27

> **Historical record, preserved unchanged.** Commit `2d00526`, validated
> below, crashes on a genuine no-console launch (the real double-click path;
> this record's own §2 used `package_smoke.py`, which redirects stdio and
> so never hit it). Fixed in `ba66fbe`, and a second packaging defect (M3
> carving broken in every packaged build) found and fixed in `437081e`. See
> [`../windows-hardware-2026-09-27-fixes/`](../windows-hardware-2026-09-27-fixes/README.md)
> for the post-fix validation. Nothing below this line was changed.

The first time this project's Windows package has been built, installed and
driven by a human on a physical Windows machine, and the first time device
discovery ran against a real removable disk on Windows. Everything below was
run once, on one machine, by one operator; it is not a CI job.

**Machine:** Windows 11 Home Single Language, build 10.0.26200, AMD64.
**Commit:** `2d00526` (`main`, working tree clean before and after this run).
**Physical target:** TOSHIBA TransMemory USB stick, labelled `SANCTUMREC`,
FAT32, 7.76 GB, attached as disk 2 / drive `E:`. Windows reports this device's
serial as the single character `B` (`Get-Disk`, `Get-CimInstance
Win32_DiskDrive` agree) — a hardware/driver quirk of this bridge, recorded
honestly rather than assumed to be a query error.

Population labels, as used throughout this repository: **PHYSICAL** (this
machine, this build, real disks), **SYNTHETIC** (a ground-truth image on host
storage, no device opened).

## 1. Package build and install — PHYSICAL

Built with `scripts/build-windows.ps1` from this commit. Inno Setup 6 was not
present on the machine and was installed via `winget` (`JRSoftware.InnoSetup`,
per-user, under `%LocalAppData%`) to complete the build; no other tool was
missing and no source change was needed.

- `dist/SanctumSetup.exe`, 36,395,215 bytes, SHA-256
  `cc9eb3b50f90cdfc694c1f9d018af4691771a060dbc8b41e1abfca664caecd1e`.
- Installed with `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART`, the way the
  documented silent path works, to `%LocalAppData%\Programs\Sanctum`. No
  administrator elevation used or requested, matching the "never asks for
  elevation" design. Uninstall was not exercised this run.

## 2. Packaged-app smoke test, against the installed exe — PHYSICAL

`scripts/package_smoke.py` run against
`%LocalAppData%\Programs\Sanctum\Sanctum.exe`, **not isolated**: real device
discovery saw this machine's actual disks, including `SANCTUMREC`. Full
result: [`package-smoke-windows.json`](package-smoke-windows.json).

**23 of 23 checks PASS, 0 NOT RUN, `"result": "PASS"`.**

What that run means concretely:

- Session cookie enforcement, non-loopback `Host` refusal, UI bundle served
  from the package — all pass, on the real installed binary.
- **Device discovery found 3 real devices** through the installed package
  (`"device discovery through the package"` → PASS, count 3), every one
  carrying an assessment, and **every protected device — including the
  mounted `SANCTUMREC` — was assessed NOT AVAILABLE** (`"protected devices
  are NOT AVAILABLE"` → PASS). This is the CLAUDE.md safety rule working on
  real hardware: a mounted filesystem refuses destructive operations, and the
  refusal was not asked for, it is what the discovery/assessment path does by
  default.
- **Whole-drive Clear and Purge correctly report UNSUPPORTED on Windows**
  (`"whole-drive unsupported off Linux"` → PASS). No whole-drive operation was
  attempted against any device, real or otherwise.
- **A real M2 file/folder erase ran on this machine's own physical NTFS
  storage** — in a scratch directory the smoke test created under the user's
  temp folder, never on `SANCTUMREC` or on anything the operator did not
  create for this purpose — through erase → read-back verify → signed
  certificate issue → certificate verify, all PASS. `verification is never
  invented` also passes: every record's verification is `True`, `False` or
  `None`, never fabricated.
- Quit stops the process; the exe exited cleanly.

**Nothing on `SANCTUMREC` was read, written, erased or otherwise modified by
this run.** The only write this run performed was to its own scratch
directory on the system disk, deleted by the erase job itself, then by the
script's cleanup.

## 3. M3 carving, deterministic ground-truth demo — SYNTHETIC

`scripts/demo_fragmented.py`, the project's real carving engine
(`api.carve_job.carve_generator`) against a synthetic image built on host
storage — **run on this physical Windows machine**, but the image itself is
synthetic and no device was opened. Full result:
[`demo-fragmented-windows.json`](demo-fragmented-windows.json).

All 6 ground-truth scenarios matched expectation exactly:

| Object | Expected | Result |
|---|---|---|
| PNG split by a 32 KiB gap | reassembled, below HIGH | MEDIUM 7999/10000, digest matches |
| Baseline JPEG split by a 32 KiB gap | reassembled, below HIGH | MEDIUM 7999/10000, digest matches |
| Intact PNG | recovered whole, HIGH | HIGH 9000/10000, digest matches |
| Duplicate of the intact PNG | deduplicated | correctly deduplicated to the first offset |
| PNG with its tail overwritten | not rebuilt | LOW 3500/10000, correctly not valid |
| Decoy PNG signature over noise | never HIGH | LOW 2500/10000 |

This exercises the carving engine correctly on Windows for the first time on
this machine. It is **not** a physical-recovery result: no image was acquired
from `SANCTUMREC` or any other real device.

## 4. Windows raw physical-device acquisition — NOT VALIDATED, NOT IMPLEMENTED

`POST /jobs/acquire` takes a filesystem path and opens it with a plain
`open(..., "rb")` (`core/carve/acquire.py` via `core/carve/evidence.py`); there
is no Windows-specific handling for a device path. Confirmed directly on this
machine, outside the app, with the installed build's own interpreter:

```
Path(r"\\.\PhysicalDrive2").exists()  -> False
open(r"\\.\PhysicalDrive2", "rb")     -> FileNotFoundError
open(r"\\.\E:", "rb")                 -> OSError: [Errno 22] Invalid argument
```

Python's buffered `open()` cannot address the Win32 device namespace; nothing
in this codebase wires up `CreateFile` on a `\\.\PhysicalDriveN` or `\\.\X:`
path today. This was not worked around — no `pywin32`/`ctypes` code was
written, and no new capability was added. It remains exactly what
`docs/packaging.md` and `hardware-platform-matrix.md` already said: acquiring
an image directly from a physical Windows device is unimplemented, not merely
untested.

## What this does and does not change

**Now physically validated on Windows, for the first time:** the packaged
installer build and silent install; device discovery and assessment against
real disks, including the correct mounted-device refusal; file/folder erase,
verification and certificate issue/verify on real NTFS.

**Unchanged:** whole-drive Clear/Purge remains UNSUPPORTED on Windows by
design (no engine exists). M3 carving remains SYNTHETICALLY VALIDATED only —
this run exercised it on real Windows hardware, but still against a synthetic
image, never against `SANCTUMREC` or any other physical device. Raw
physical-device acquisition on Windows is not implemented, and this run did
not implement it.

**Not touched:** `SANCTUMREC` was never opened for writing, erasing, or raw
reading by anything in this run. The only operation that ran against a real
disk was read-only device discovery/assessment, which is exactly what
correctly refused it.
