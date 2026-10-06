# Testing AEGIS

AEGIS is tested at five levels, from engine unit tests to an automated end-to-end rehearsal that
drives the packaged application. Results below are from the AEGIS 1.0.0 release pass (3–4 October 2026)
on Windows 11 x64.

## Results

| Suite | What it covers | Result |
|---|---|---|
| Engine test suite (pytest) | Acquisition, carving, validation, scoring, ledger, reports, device adapters, erase engine | 2,854 passed, 922 skipped on CPython 3.11 (5 failures need Windows symlink privilege; 7 errors need the unused web UI bundle) |
| Engine carving suite after the performance patches | Signature, structure and recovery pipeline | 467 passed, 74 skipped, 0 failed |
| Engine acquisition tests after the verify-progress change | `test_acquire*`, cancelled acquisition | 7 passed, 36 skipped |
| AEGIS internal-drive policy tests | Simulated devices: internal SSD/NVMe/SATA, system disk, unknown bus, USB, SD | 8/8 pass |
| `EngineBridgeSelfTest` (Java ↔ engine) | Protocol, health, devices, acquisition (RAW/E01), verification, recovery, refusals, cancellation, ledger tamper detection, report signing and tamper detection | 52/52 pass on the packaged engine and bundled JRE |
| `PendriveImagesSelfTest` | A real 8.6 GB pendrive image, read-only: E01 acquisition + verification, signed reports, recovery, copy hashes, original unchanged, ledger | 16/16 pass |
| Legacy Java self-tests | Protocol, device eligibility, carve engine, acquisition service, report signer, device enumeration | 6/6 pass |
| Native sanitizer `engine_tests.exe` | Overwrite patterns, verification, error paths | pass |
| End-to-end rehearsal (`AegisUiDriver`) | The whole product flow inside the packaged app (below) | 44/44 steps, 0 failures, 0 timeouts |
| Recovery equivalence | Performance patches vs. the unpatched engine on a 768 MB slice of a real pendrive image | 546/546 candidates identical |
| Recovery equivalence after the progress hooks | Full 8.6 GB pendrive image, list-only, on the 1.0.0 package | 8,380/8,380 candidates identical; 28 minutes |

### Real pendrive image (`PendriveImagesSelfTest`)

`Drive F.e01`, 8,589,934,592 bytes, FAT32, opened read-only:

- E01 acquisition in 330 s (26 MB/s) with SHA-256 + BLAKE3; read-back verification passed; no unreadable sectors;
- recovery in 75 minutes: **8,380 objects** — 5 FAT undeletes, 7,229 with parser-derived lengths,
  1,146 by signature; HIGH 6,697 / MEDIUM 141 / LOW 1,542;
- 300 recovered copies re-hashed: all equal to their recorded SHA-256;
- signed acquisition and recovery reports verify; the ledger chain is VALID;
- the original image's size and modification time are unchanged.

### End-to-end rehearsal

`AegisUiDriver` runs inside the packaged application (`-J-Daegis.uidriver.out=...`) and drives the real
UI, capturing screenshots along the way:

case creation → Disk Imager E01 acquisition and verification → registration (data source, ledger
entry, signed report) → ingest → Recovery scan → signed recovery report → add recovered files to the
case → EDSR ×2 enhancement (original unchanged; derivative and model hashed) → file sanitization
(verified; file gone; ledgered) → Deep Forensic Purge → device view (system disk not eligible) →
Reports (Verify Signature & Chain) → ORACLE (graph with 100% edge provenance) → close and reopen the
case → reports and ledger persisted.

## Failure injection

| Injected failure | Expected and observed behaviour |
|---|---|
| Edit one ledger entry | `ledger-verify` → `BROKEN` at that exact sequence number |
| Change one byte of a signed report | `verify-report` → `FAILED_VERIFICATION` |
| Forge an engine operation through the desktop `record` command | Refused (only `aegis.desktop.*` accepted) |
| Sanitize a non-existent disk | `BLOCKED` `DeviceVanished`; nothing written |
| Sanitize without destructive confirmation | `BLOCKED` `ConfirmationMissing` |
| Sanitize an internal or system disk | `BLOCKED` `InternalDriveRefused` / `SystemDiskRefused`, ledgered as `aegis.sanitize.refused` (verified on simulated devices; never attempted on a real internal disk) |
| Recover from a live device path | `BLOCKED` `EvidenceOnly` |
| E01 from an odd-sized source | `BLOCKED` `E01NeedsWholeSectors` (libewf would otherwise truncate; caught first by read-back verification) |
| Cancel a scan | `CANCELLED`, never success |

## Running the tests

```powershell
# Engine (from engine/), with the engine runtime's Python
python -m pytest -q
python -m pytest -q tests/aegis                 # internal-drive policy

# Java bridge tests (compile against the built module classes)
javac -d out -cp build\classes test\EngineBridgeSelfTest.java
java -Daegis.engine.home=<AEGIS>\aegis-engine -cp "out;build\classes" EngineBridgeSelfTest <work dir>

# Real-media test on your own images (read-only; copies go to <work dir>)
java -Daegis.engine.home=<AEGIS>\aegis-engine -Dpendrive.deleteCopies=true -cp "out;build\classes" `
     PendriveImagesSelfTest <work dir> "D:\images\usb.e01"

# End-to-end rehearsal and screenshots in the packaged app
powershell -ExecutionPolicy Bypass -File tools\aegis-e2e.ps1 -Out <dir> -Source <demo image> `
     -CaseName "Demo Case" -CaseNumber 2026-001 -Examiner "Demo Examiner"

# Deterministic demo evidence (FAT32 image with ground truth)
python tools\make-demo-evidence.py
```

### Installer

`AEGIS-1.0.0-Setup.exe` (1,419,007,086 bytes, SHA-256
`467f51fa468ebe8e88bbeafe45f9775519b97fbf1fbf77eaec6dedef73331b69`):

- silent per-user install in 107 s: 13,566 files, engine bytecode precompiled, Start-menu shortcuts
  (the *AEGIS (Administrator)* shortcut carries the run-as-administrator flag), uninstall entry
  "AEGIS 1.0.0 / knightspan";
- the installed `AEGIS.exe` starts with its own bundled Java (`<install>\jre`) and reports AEGIS 1.0.0;
  the installed engine passes `health` with every native module and E01 writing available;
- the full end-to-end rehearsal on the **installed** copy: 44/44 steps, 0 failures;
- silent uninstall removes the folder, shortcuts and uninstall entry, and keeps `%APPDATA%\AEGIS`.

A machine-wide install to `Program Files` (administrator) was not exercised by the automated test,
which ran without elevation.

### Physical USB acquisition (operator run, elevated)

On 4 October 2026 an operator acquired a 61.5 GB USB stick (`\\.\PhysicalDrive1`, FAT32, removable,
not system/boot) to E01 through the Disk Imager: 61,504,880,640 bytes read, 33 E01 segments, **0
unreadable sectors, read-back verification passed** (SHA-256, BLAKE3 and every chunk), followed by
registration and a signed acquisition report.
