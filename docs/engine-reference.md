# AEGIS engine reference

The engine is a separate Python 3.11 process. The desktop calls it through `EngineBridge`; it can also
be run by hand for testing:

```powershell
$E = "C:\AEGIS\aegis-engine"     # inside an extracted package
& "$E\runtime\python311\python.exe" -X utf8 -u "$E\engine\aegis_engine_cli.py" health
```

Output is one JSON object per line (`HELLO`, `PROGRESS`, `LOG`, `RESULT`); see
[`architecture.md`](architecture.md#the-engine-process-protocol). The exit code follows the result status:
`0` success (with or without warnings), `1` failed, `2` blocked by a safety gate, `3` unsupported or
unavailable, `4` cancelled, `5` invalid arguments.

## Common options

| Option | Meaning |
|---|---|
| `--state <dir>` | The case's AEGIS workspace (`<case>\AEGIS`): ledger, jobs, reports, logs |
| `--keys <dir>` | Signing-key directory (default `%APPDATA%\AEGIS\keys`) |
| `--case-id <id>` | Case identifier recorded in every ledger entry and report |
| `--operator <name>` | Operator recorded in the ledger (default: the Windows user) |
| `--job-id <id>` | The job a command refers to (`report`, `verify-image`, ...) |
| `--cancel-file <path>` | The operation is cancelled as soon as this file exists |

Any string option may be passed as `b64:<base64 of UTF-8 text>` to survive Windows command-line quoting.

## Commands

### `health`
Engine and protocol versions, Python version, platform, elevation, the version of every native module
(pytsk3, pyewf, blake3, OpenCV, ...), E01 writing support and the libewf writer version, the hashes in
use (SHA-256, BLAKE3), enhancement support and installed models, the state and key directories, and
the list of supported commands. The Home page's System Status is built from this.

### `devices [--include-virtual]`
Read-only enumeration of physical disks: model, serial, size, bus, removable, system/boot flags,
volumes and mounts, plus the engine's verdicts:

- `sanitization`: `{eligible, status, reason}`; internal, system, boot and unknown-bus disks are never eligible;
- `acquisition`: whether the disk can be imaged (the live system disk cannot);
- `capabilities`: probed firmware sanitize, crypto erase and overwrite support (firmware probes need elevation).

### `acquire --source <path|\\.\PhysicalDriveN> --dest <file> [--format raw|e01]`
Read-only acquisition with SHA-256 and BLAKE3 in one pass, sector salvage for unreadable sectors
(retried, filled and recorded), then a full read-back verification.

| Option | Meaning |
|---|---|
| `--expected-serial`, `--expected-size` | Identity bound to the open read handle; a mismatch aborts |
| `--sector-size` | Default 512 |
| `--evidence-number`, `--examiner`, `--description`, `--notes`, `--device-model` | E01 header fields and report metadata |

E01 needs a whole number of sectors; an odd-sized file source is refused (`E01NeedsWholeSectors`) and
must be acquired as RAW. Large E01 images are segmented (`.E01`, `.E02`, ...).
Result: `record` (hashes, bytes read, bad sectors, chunk hashes), `verification`, `image_path`, `segments`.

### `verify-image --job-id <acquisition job>`
Re-reads an earlier acquisition and compares SHA-256, BLAKE3 and every chunk with its record.

### `recover --image <path> [options]`
Recovery from an image (live devices are refused).

| Option | Meaning |
|---|---|
| `--out <dir>` | Where recovered copies go (default `<state>\recovered\<job>`) |
| `--source-job <id>` | Link to the acquisition that produced the image (provenance) |
| `--no-undelete`, `--no-carve`, `--no-media-map` | Skip a stage |
| `--no-write` | List and score candidates without writing copies (triage of large images) |

Result: candidate summary inline; the full list (offset, length, extension, source, validation,
bucket, score components, SHA-256, fragments, output path) in the file named by `result_file`.

### `prepare-device --device <id> --typed-serial <serial>`
Takes the device's volumes offline (not persistent) so a whole-drive operation can run. Same
eligibility rules as sanitization.

### `sanitize-device --device <id> --typed-serial <serial> --confirm-destructive [options]`

| Option | Meaning |
|---|---|
| `--expected-serial`, `--expected-size` | Identity the operator saw; re-checked before the first write |
| `--level CLEAR|PURGE` | Outcome requested |
| `--overwrite-method SINGLE_PASS_OVERWRITE|DOD_5220_22_M_3PASS` | Overwrite profile for a Clear |
| `--backup-job <id>` | A verified acquisition of the same serial |
| `--waive-backup "NO BACKUP"` | Explicit, ledgered waiver of the backup gate |

Refusals (status `BLOCKED`) include `InternalDriveRefused`, `SystemDiskRefused`, `ConfirmationMissing`,
`ConfirmationMismatch`, `IdentityMismatch`, `DeviceVanished`, `DeviceFrozen`, `MountedRefused`,
`WorkflowGateRefused` and backup-gate failures. Each is ledgered.

### `traces --erased <path> [--erased <path> ...] [--directory] [--find-only] [--source-job <id>]`
Deep Forensic Purge: finds Recent shortcuts, jump lists and Recycle Bin copies tied to the erased
paths and removes them (or only lists them with `--find-only`).

### `thumbcache [--find-only]`
Clears the per-user Windows thumbnail cache through the Restart Manager (graceful shutdown only).

### `ledger-verify`, `ledger-list [--job <id>]`
Verify the case ledger chain (`VALID` / `BROKEN` at a sequence number) or list its entries.

### `record --operation aegis.desktop.<name> [--params-json ...] [--result-json ...]`
Lets the desktop record its own actions. Only the `aegis.desktop.*` namespace is accepted, so an
engine operation cannot be forged.

### `report --job-id <id>`
Builds the signed report (JSON + PDF) for an acquisition, recovery, sanitization or trace job, with the
case ledger chain as its audit excerpt.

### `verify-report --report <report.json>`
Checks the Ed25519 signature, the signing key against the ledger genesis, and the ledger chain:
`VERIFIED`, `VERIFIED_WITH_LIMITATIONS` (declared excerpt gaps) or `FAILED_VERIFICATION`.

### `enhance --input <image> [--model EDSR] [--scale 2|3|4] [--tile 192]`
EDSR super-resolution in tiles with progress. Writes a labelled derivative to `<state>\enhanced`,
re-hashes the original to prove it is unchanged and records the model's SHA-256 in the ledger.
