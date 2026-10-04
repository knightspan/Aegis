# AEGIS integration provenance

Date: 2026-10-03. Scope: how the AEGIS Variant engine and third-party components enter the AEGIS desktop build, what was reused, what was changed, and the licence position of each part.

## Integration model

AEGIS Desktop (NetBeans Platform / Autopsy 4.23.1 / Swing, Java 17) calls the AEGIS Variant engine **as a separate process**. The Java class `org.sleuthkit.autopsy.aegis.engine.EngineBridge` starts a packaged CPython 3.11 runtime and runs `aegis_engine_cli.py`. That script imports the Variant's own modules and calls them. The two sides exchange JSON lines (`HELLO`, `PROGRESS`, `LOG`, `RESULT`) over stdout. Cancellation is signalled by creating the flag file named by `--cancel-file`. The engine never reads stdin (a stdin reader thread deadlocked DLL loading on Windows), so the Java side redirects stdin from `NUL`. No Variant code is compiled into or linked with the Java module. The Variant's FastAPI server and its React UI are not used, started or shipped by the desktop.

## Variant engine: reused, bridged, modified

Source tree: `engine/` (packaged as `aegis-engine/engine`).

| Variant module | Desktop capability | Use |
|---|---|---|
| `core/carve/acquire.py` (`acquire`, `verify_image`) | Disk Imager RAW/E01 imaging, single-pass SHA-256 + BLAKE3, sector salvage, bad-sector record, read-back verification | Reused unchanged except the E01 writer hook below |
| `core/carve/evidence.py` | Read-only RAW / split RAW / E01 evidence access | Reused unchanged |
| `api/carve_job.py` (`carve_generator`) with `core/carve/*` (mediamap, fsaware, signature, structure, validate, score, classify, fragmentation, pii) | Advanced Recovery: media map, filesystem-aware undelete, structure carving, bifragment JPEG/PNG reassembly, decoder validation, evidence score, PII counts | Reused unchanged (imported, not re-implemented) |
| `core/platform/windows.py` (`WindowsAdapter`), `core/device/win/*`, `core/platform/capability.py`, `core/platform/base.py` | Windows device enumeration, assessment, capability resolution, guarded whole-drive Clear, ATA/NVMe sanitize, crypto erase, take-offline (Prepare) | Reused, plus one parameter (overwrite profile) below |
| `core/erase/blockclear.py`, `core/erase/devicesanitize.py`, `core/erase/verify.py`, `core/erase/patterns.py` | Overwrite engine, read-back verification, residual risk | Reused unchanged |
| `core/erase/traces.py` (`find_traces`, `sweep`) | Deep Forensic Purge (Recent shortcuts, jump lists, Recycle Bin) | Reused unchanged |
| `core/ledger/chain.py`, `core/ledger/store.py` | Per-case hash-chained ledger, verification, tamper detection | Reused; one Windows robustness fix in `store.py` below |
| `core/report/render.py`, `core/report/sign.py`, `core/report/verify_report.py`, `core/report/certificate.py` | Signed JSON + PDF reports, Ed25519 signing and independent verification | Reused unchanged; the acquisition report is assembled from the Variant's own `_envelope` and `_audit_trail` helpers |

### Files added to the Variant tree by this integration

| File | Purpose |
|---|---|
| `aegis_engine_cli.py` | Replaces the earlier fail-closed facade. It is the JSON-lines bridge. Each command calls the Variant functions listed above. It adds AEGIS gates on top of the engine's own: an acquisition destination may not sit on the source disk; the backup gate; identity re-check before a destructive operation; recovery refuses a live device path; a desktop event can only be written under `aegis.desktop.*`. It also adds the DPAPI protection of the signing-key passphrase, the Restart Manager thumbnail-cache command, and the EDSR enhancement command. |
| `core/carve/ewf_ctypes.py` | E01 writer over a write-capable `libewf.dll` through ctypes. The PyPI `libewf-python` wheel for Windows cannot write E01, because it has no deflate support. |
| `models/EDSR_x2.pb`, `EDSR_x3.pb`, `EDSR_x4.pb` | Super-resolution models (see third-party table). |

### Variant files modified by this integration (each change is commented "AEGIS integration")

| File | Change |
|---|---|
| `core/carve/acquire.py` | `e01_write_supported()` also accepts the ctypes libewf writer. `_EwfWriter` uses that writer when pyewf cannot write, passing the media size, sector size, compression, and the case/evidence/examiner headers. The acquisition's limitations name the writer that was used. Reading and verification still go through pyewf. `verify_image` takes an optional `progress(bytes_verified, bytes_total)` callback, called after each chunk, so the desktop can show the read-back. It does not change what is read, hashed or compared. |
| `core/ledger/store.py` | `BlobStore.put` tolerates Windows sharing violations on rename. A content-addressed target that already holds identical bytes is accepted. Otherwise the rename is retried briefly and then the error is raised. |
| `core/carve/signature.py` | Performance only. Footer searches are memoized per evidence handle (weak-keyed): the answer is still the first footer at or after the start and within the limit, but already-scanned stretches are not re-read. Also adds an optional `SCAN_PROGRESS_HOOK` called once per scan chunk, and `STAGE_PROGRESS_HOOK(stage, done, total)` called per hit while candidates are built and (from `structure.py`) per candidate while structures are parsed; both are only called, never consulted. Results were checked identical on the demo image and on a 768 MB slice of a real pendrive image ([testing.md](testing.md)). |
| `core/carve/structure.py` | Performance and progress only (calls `signature.STAGE_PROGRESS_HOOK` per candidate). ZIP end-of-central-directory records are read once per handle and re-evaluated per parse with the original acceptance test and order, so every member of an Office archive no longer rescans up to 1 GiB. Same equivalence evidence. |
| `core/platform/windows.py` | `execute_drive_sanitization` accepts `overwrite_method`, limited to `core.erase.patterns.SOFTWARE_METHODS` (`SINGLE_PASS_OVERWRITE`, `DOD_5220_22_M_3PASS`). Any other value is refused. It also refuses any device whose interface is not USB or MMC/SD, or which is reported internal (AEGIS operator policy: internal drives are never sanitized). |

No Variant algorithm was ported to Java. The desktop's earlier in-process Java carver (`recovery/carve/CarvingEngine.java`) remains in the source and its self-test. The Recovery workspace no longer uses it; the Variant pipeline replaced it.

## Desktop components preserved

| Component | Status |
|---|---|
| C++ sanitizer (`sanitizer/`, `aegis_cli.exe`) | Still the engine for **File** and **Folder** sanitization. Its outcome is now also recorded in the case ledger as `aegis.desktop.sanitize.file`. |
| Java `AuditLedgerService`, `ReportSigner`, `HtmlSanitizationReport` | Kept for the C++ file/folder path and its signed HTML report. The Report Viewer verifies these reports with `ReportSigner`. |
| Volume target, previously the C++ `wipe-disk` path on `\\.\X:` | **Withdrawn.** A wipe addressed by drive letter cannot be bound to a device identity. Volume now routes to the engine's identity-bound device workflow. |

## Licence and notice status

| Item | Licence | Notes |
|---|---|---|
| AEGIS Variant engine (`engine/`) | **Proprietary** (AEGIS Proprietary License) | Until 2026-10-04 the `LICENSE` file said GNU GPL v3 while `pyproject.toml` said "Proprietary". On 2026-10-04 the copyright holder chose the proprietary licence for all of AEGIS; `LICENSE` and the README badge were changed to match. Third-party components keep their own licences (`THIRD_PARTY_NOTICES.md`). |
| Autopsy 4.23.1, Sleuth Kit 4.15.0 | Apache 2.0 (Autopsy), IBM Public Licence / CPL / GPL components (TSK) | Unchanged upstream notices in the package. |
| CPython 3.11.15 (python-build-standalone, via uv) | PSF licence | `aegis-engine/runtime/python311/LICENSE.txt` |
| libewf 20130416 (Autopsy's ewfexport build) used for E01 writing | LGPL v3 | `aegis-engine/runtime/libewf/LICENSE.libewf.txt` (copied from Autopsy's `ewfexport_exec/licenses`); zlib licence for `zlib.dll` |
| libewf-python 20240506 (pyewf, reading) | LGPL v3 | PyPI wheel, unmodified |
| pytsk3 20260715 | Apache 2.0 | PyPI wheel |
| blake3, pyahocorasick, construct, pydantic, cryptography, reportlab, pikepdf, Pillow, olefile, piexif, mutagen, structlog, typer, PyYAML, fastapi/uvicorn (not started by the desktop) | Their respective permissive licences (MIT/BSD/Apache/PSF/MPL-2.0 for pikepdf) | Pinned versions from the Variant `pyproject.toml` |
| opencv-contrib-python-headless 4.12.0.88, numpy 2.2.6 | Apache 2.0 / BSD | Used only by the enhancement command |
| EDSR super-resolution models (`EDSR_x{2,3,4}.pb`) | Apache 2.0 (repository `Saafke/EDSR_Tensorflow`, as reported by the GitHub licence API) | Downloaded 2026-10-03. SHA-256: x2 `585623221baa070279a0d1e7e113a4c3faba0f318ca7fdd9a65d9afc0763d9b4`, x3 `3baa3740fdb8ee9c52f1a41d69fa74cb9feef0fa9bfeec24f0ee58b928068e9a`, x4 `dd35ce3cae53ecee2d16045e08a932c3e7242d641bb65cb971d123e06904347f`. The model hash is also recorded in every enhancement ledger entry. |
| Tabler icons (UI) | MIT | `tabler-icons-main` |
| pyfatfs (test-image generator only, the build workspace only) | MIT | Not packaged |
