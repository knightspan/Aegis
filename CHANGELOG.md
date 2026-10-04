# Changelog

## 1.0.0 — 2026-10-04

First release of AEGIS as a single desktop product.

### Added
- **AEGIS desktop shell** on the NetBeans Platform: sidebar, top bar with command palette (`Ctrl+K`),
  live System Status on Home, and the AEGIS pages below.
- **Disk Imager**: 9-step acquisition of USB/SD devices and image files to RAW or E01, SHA-256 + BLAKE3
  in one pass, unreadable-sector salvage, chunk-level read-back verification with live progress, case
  registration and signed acquisition reports.
- **Advanced File Recovery**: media map, filesystem-aware undelete, signature and structure carving,
  bifragment JPEG/PNG reassembly, decoder validation, evidence scoring, recovered-copy hashing, signed
  recovery reports, and progress for every pipeline stage.
- **AI Enhancement**: EDSR ×2/×3/×4 super-resolution on labelled derivatives with original re-hashing
  and model provenance.
- **Data Sanitization**: verified file/folder overwrite (native sanitizer) and capability-driven device
  sanitization for USB/SD media with typed-serial authorization, backup gate, identity re-binding and
  read-back verification.
- **Deep Forensic Purge**: removal of Recent shortcuts, jump lists and Recycle Bin copies tied to an
  erased path; opt-in thumbnail-cache clearing through the Restart Manager.
- **Report Viewer** with in-app Ed25519 signature, ledger-chain and audit-chain verification and
  PDF/HTML/JSON export.
- **ORACLE**: provenance-aware knowledge graph with timeline correlation, entity explorer, evidence
  paths, case insights and graph analytics.
- Per-case hash-chained ledger; DPAPI-protected signing key.
- `AEGIS.exe` launcher with bundled Java 17 and Python 3.11 runtimes.

### Safety
- Internal drives (SSD, NVMe, SATA, SAS, RAID) and the system disk are refused for sanitization by the
  engine bridge, the device adapter and the UI; refusals are ledgered.

### Validation
- 61.5 GB USB stick acquired to E01 on hardware with verification passed; 8.6 GB real pendrive image
  recovered (8,380 objects) with all checks passing; end-to-end rehearsal 44/44 steps.
