# AEGIS user guide

This guide walks through every AEGIS page. For what AEGIS will and will not do to a device, read the
[safety model](safety-model.md) first.

- [Starting AEGIS](#starting-aegis)
- [Home](#home)
- [Cases](#cases)
- [Disk Imager](#disk-imager)
- [Advanced File Recovery](#advanced-file-recovery)
- [AI Enhancement](#ai-enhancement)
- [Data Sanitization: files and folders](#data-sanitization-files-and-folders)
- [Data Sanitization: devices](#data-sanitization-devices)
- [Deep Forensic Purge](#deep-forensic-purge)
- [Reports](#reports)
- [ORACLE](#oracle)
- [Analysis pages](#analysis-pages)
- [Troubleshooting](#troubleshooting)

## Starting AEGIS

Install with `AEGIS-1.0.0-Setup.exe` and start **AEGIS** from the Start menu (or run `AEGIS.exe` in the
installation folder). Java and the engine runtime are bundled.

Raw access to USB or SD devices (device acquisition, device sanitization, firmware capability probes)
needs administrator rights: use the **AEGIS (Administrator)** Start-menu shortcut, or right-click
`AEGIS.exe` → **Run as administrator**. Without elevation those
functions say **REQUIRES PRIVILEGE**; everything else works normally.

The window has a sidebar (pages and the **Current Case** box), a top bar with search
(`Ctrl+K` opens the command palette) and the page area.

## Home

The **System Status** panel is live, read from the running system rather than hard-coded:

| Row | Meaning |
|---|---|
| Core Modules, Search Engine, Timeline Engine, Hash Database, Reporting | Analysis suite components |
| AEGIS Engine | The engine process answered `health` (Python version shown) |
| E01 Writer | libewf is available for E01 writing |
| File Sanitizer | The native sanitizer is present |
| Privilege | Standard or elevated |
| Case Ledger | Ledger state for the open case (VALID, entry count) |
| Signed Reports | Number of signed reports in the case |

Quick actions create or open a case and jump to the main workflows.

## Cases

Create a case with a name, number and examiner, or open an existing one. The current case is shown in
the sidebar and in the window title. AEGIS keeps its own files for the case in `<case folder>\AEGIS`
(see [architecture](architecture.md#case-workspace)). Closing and reopening a case keeps its reports,
ledger and ORACLE history.

## Disk Imager

A nine-step guided acquisition. The stepper only advances when a step's checks pass.

| Step | What happens |
|---|---|
| 1. Select Source | **Refresh Devices** lists physical disks with model, serial, capacity, filesystem and mount. Internal and system disks are marked and cannot be imaged live. Or choose **Image or file** to acquire an existing image. |
| 2. Preflight | Elevation (for devices), not the system disk, identity bound, destination free space, destination not on the source. |
| 3. Device Identity | Model, serial, size, bus, removable, system/boot flags, physical path. |
| 4. Case & Evidence | Case, examiner, evidence name and number, description and notes. These go into the E01 header and the report. |
| 5. Image Configuration | **E01** (Expert Witness, compressed, segmented for large sources) or **RAW**; destination folder and image name. The right panel previews destination and settings. |
| 6. Acquisition | **Start Acquisition**. The progress ring shows bytes copied, speed and time remaining; the live log records each stage. The source is read once while SHA-256 and BLAKE3 are computed; unreadable sectors are retried, filled and recorded. |
| 7. Verification | The engine re-reads the written image and compares SHA-256, BLAKE3 and every chunk with the acquisition record. Progress shows *Bytes verified*. A large E01 takes about as long to verify as to write. |
| 8. Registration | **Add Image to Case** registers the image as a data source, appends a ledger entry and produces a signed acquisition report. |
| 9. Complete | Summary and shortcuts: open the report, start **Advanced Recovery** on the new image. |

Notes:

- An image file whose size is not a whole number of 512-byte sectors cannot be stored as E01; choose RAW.
- **Cancel Acquisition** stops cleanly; a cancelled or failed acquisition is never shown as complete.
  Cancelling during verification leaves an image that is written but **not verified**.

## Advanced File Recovery

Recovers deleted and orphaned files from an image. Evidence is only read.

**1. Select source and configure.** Choose a case image (an acquisition from this case is listed with
its job) or **Browse…** for an image file. Options:

- **Filesystem-aware undelete** (NTFS, FAT, exFAT, ext): deleted directory entries, with original names;
- **Signature + structure carving** (24 signatures, 16 format parsers): files without metadata;
- **Media map**: classifies regions of the image (filesystem, structured, high entropy, text, fill,
  zero, unreadable), sampled on large images;
- **Write recovered copies to the case folder**: turn off to triage a very large image (list and score only).

**2. Scan.** The progress ring and stage list follow the engine: media map, undelete, signature scan,
building candidates, parsing structures, validation, scoring, writing. On a 31 GB image the full
pipeline can take hours; on a few-GB pendrive typically well under an hour.

**3. Results.** Every object has a score bucket:

| Bucket | Meaning |
|---|---|
| HIGH | Exact length known, header matches, a decoder validated it |
| MEDIUM | Valid but with a weaker signal, e.g. a reassembled bifragment object |
| LOW | Truncated, corrupt or unvalidated; often partial or a false match |

Filter by type, source and score; the **Media Map** marks where recovered objects lie. Selecting a file
opens **File Preview & Analysis**:

| Tab | Contents |
|---|---|
| Preview | Image or text preview |
| Metadata | Name (original name when known), size, offsets, SHA-256, source stage |
| Validation | Score components: header, exact length, decoder, entropy, reassembly |
| Fragments | For reassembled files, the runs on the medium and the gap between them |
| Hex View | Raw bytes |

Actions: **Signed Report** (recovery report), **Add to Case** (recovered copies become a data source),
**Export Selected** (copy chosen files out), **AI Enhance (derivative)** (photos).

## AI Enhancement

For a recovered photo, **AI Enhance** opens the enhancement dialog. Choose EDSR ×2, ×3 or ×4 and
**Create Enhanced Derivative**. Processing runs on the CPU in tiles with progress (about 1–3 minutes
for a typical photo at ×2). The dialog shows the **original** and the **enhanced derivative** side by
side; the derivative is labelled as such and stored in `<case>\AEGIS\enhanced`. The original is
re-hashed and shown unchanged, and the model's SHA-256 and parameters are written to the ledger.
An enhanced image is an aid to viewing, **never evidence**.

## Data Sanitization: files and folders

Choose **File** or **Folder** in the target row, then:

1. **Target Selection**: **Browse…** for the file or folder. Target Information shows its path, size and
   the volume it is on.
2. **Method Selection**: *Logical zero overwrite (1 pass)*, *Logical zero (NIST label)*, *DoD 3-pass
   legacy (0x00, 0xFF, PRNG)*, *PRNG logical passes* (configurable pass count) or *Gutmann-style 35
   shuffled logical writes*. All are logical overwrites through the filesystem; extra passes add time,
   not assurance, on modern flash.
3. **Verification**: read-back verification (on by default) and optional before/after hashing.
4. **Confirmation**: review the operation preview and confirm.
5. **Execution**: live progress from the native sanitizer.
6. **Results**: outcome, verification result, links to the audit record and the report. The run is
   recorded in the case ledger. **Deep Forensic Purge** is offered from here.

## Data Sanitization: devices

Choose **Volume** or **Physical Device** in the target row. (A volume cannot be bound to a device
identity by its drive letter, so both open the device workflow.)

1. **Select Target Device**: the device table shows each disk's type, model, serial, capacity,
   filesystem, status and **Eligible**. Internal drives show **Internal drive — sanitization disabled**.
   Only USB and SD/MMC media can be selected.
2. **Device Capability Analysis**: what the engine probed (needs elevation for firmware probes).
3. **Select Sanitization Method**: methods offered from the probe; unavailable ones show why. See the
   [safety model](safety-model.md#methods-offered).
4. **Deep Forensic Purge**: choose whether to remove host traces of files that were on the device.
5. **Sanitize Device…** opens the authorization dialog: choose the backup acquisition (or type the
   `NO BACKUP` waiver), tick the acknowledgement and type the serial exactly.
6. **Execution**: the engine takes the volumes offline, re-binds the identity, writes, and reads back.
   The live log and the **Verification Results** panel show the outcome achieved (Clear or Purge).
7. **Open Signed Report**. Replug the device afterwards to bring it back online.

## Deep Forensic Purge

Available after a file/folder sanitization and as part of the device workflow. It removes Recent
shortcuts, jump lists and Recycle Bin copies **that the engine ties to the erased path on evidence**,
and reports weaker matches without touching them. The Windows thumbnail cache is a separate opt-in
because it cannot be tied to one file: it clears the whole per-user cache, asking Explorer to close
through the Restart Manager. The signed result lists the places searched and not searched.

## Reports

The Report Viewer lists every report of the case: AEGIS engine reports (acquisition, recovery, device
sanitization, trace sweep) and file-sanitization reports.

| Tab | Contents |
|---|---|
| Overview | Operation, target, outcome, key hashes |
| Detailed Analysis | The full report content |
| Verification Results | **Verify Signature & Chain**: Ed25519 signature, signing key against the ledger genesis, ledger chain; result `VERIFIED`, `VERIFIED_WITH_LIMITATIONS` (lists the declared reasons) or `FAILED_VERIFICATION` |
| Audit Trail | Ledger excerpt; **Verify Audit Chain** checks the live ledger (`VALID` with entry count, or `BROKEN` at a sequence number) |
| Secondary Artifacts | Trace sweep results tied to the operation |
| Technical Details | Engine, runtime, parameters |
| Warnings & Limitations | Everything the operation could not guarantee |
| Cryptographic Integrity | Report hash, signature, public key |

Reports can be exported as PDF, HTML or JSON.

## ORACLE

ORACLE is a provenance-aware knowledge graph of the case, built from the case database, the engine
ledger and the job records. It is not a chatbot: every node and edge is a recorded fact and shows its
source.

| Tab | Contents |
|---|---|
| Knowledge Graph | Ego-centred graph around the selected entity (evidence, device, recovered file, operation, report); click a node to re-centre |
| Timeline Correlation | Recorded events in time order |
| Entity Explorer | Searchable list of entities with details |
| Evidence Paths | How a file connects to its evidence and the device it came from |
| Case Insights | Counts and findings derived from recorded facts |
| Graph Analytics | Relationships by type, most-connected entities |

The inspector on the right shows the selected entity's **Details**, **Relationships**, **Timeline**,
**Provenance** (ledger sequence and entry hash, or Sleuth Kit object id) and **Metadata**.

## Analysis pages

**Ingest, Search, Timeline, Analysis, Artifacts, Media, Communications, Registry, Tags** give the full
case analysis of registered data sources on The Sleuth Kit: file system views (including deleted
files), keyword search, timeline, extracted artifacts, media, communications, registry and tags.

## Troubleshooting

| Symptom | Meaning | Action |
|---|---|---|
| **REQUIRES PRIVILEGE** | AEGIS is not elevated | Restart with *Run as administrator* |
| **Internal drive — sanitization disabled** | Policy: internal drives are never sanitized | Expected; use removable USB/SD media |
| `MountedRefused` / *READY AFTER PREPARE* | A volume on the device is mounted | Authorize: AEGIS takes it offline; close Explorer windows on it |
| `IdentityMismatch` / `DeviceVanished` | The device was replugged or swapped | Refresh and select it again; nothing was written |
| `E01NeedsWholeSectors` | File source is not a whole number of sectors | Choose RAW |
| Engine *Unavailable* on Home | The `aegis-engine` folder is missing or damaged | Reinstall / re-extract AEGIS |
| Recovery seems slow on a large image | Validation of tens of thousands of objects | Watch the stage message; turn off *Write recovered copies* for triage |
