# AEGIS known limitations

Date: 2026-10-03. Every item below is a limit established by execution or by the code itself. Nothing here is a planned feature presented as done.

## Not yet proven on physical hardware

| Area | State | What is needed |
|---|---|---|
| Physical USB acquisition, Windows | **Verified on hardware** on 2026-10-04 by the operator: a 61.5 GB USB stick (`\\.\PhysicalDrive1`) acquired to E01 (33 segments) in the elevated packaged app; 61,504,880,640 bytes read, 0 unreadable sectors, read-back verification passed, signed report produced. The engine opens the device read-only and checks the serial and size on the open handle. | — |
| Physical USB sanitization | Implemented: the Variant `WindowsAdapter` whole-drive Clear (single pass, or the legacy DoD 3-pass profile) with read-back verification. Every gate is enforced by the engine. **Not run on a USB device in this pass**, for the same reasons. | Same runbook section, on disposable media only. |
| Firmware sanitize (ATA SANITIZE, NVMe Sanitize, crypto erase) | Implemented in the Variant. Offered only when the engine's probe reports support. USB bridges rarely pass these commands through. AEGIS policy refuses every internal drive, so these firmware methods will in practice be shown as unavailable. | None for the demo. |
| Windows device enumeration | **Verified** without elevation on this machine: one internal NVMe disk, correctly marked as the system and boot disk (`DeviceEnumerationSelfTest` and the engine's `devices` command). Firmware capability probes need an elevated process and show *REQUIRES PRIVILEGE* otherwise. | — |

## Policy limits (by design)

- **Internal drives are never sanitized.** This covers internal SSD, NVMe, SATA, SAS and RAID disks, whether or not they are the system disk. Only USB- or SD/MMC-attached media are eligible. An unknown bus type is refused. The rule is enforced in three places: the bridge (`sanitize-device`, `prepare-device`), the Variant Windows adapter, and the UI. A refusal is ledgered as `aegis.sanitize.refused`.
- **Volume wipe by drive letter is withdrawn.** A drive letter cannot be bound to a device identity, so Volume routes to the device workflow.
- **The live system disk is not imaged.** An image of a running OS disk is internally inconsistent; acquire it from external boot media instead.
- **No dry-run mode.** Every device operation runs for real once its gates pass. That is why physical testing must use disposable media.
- **A backup gate applies before device sanitization.** The operator must name a verified AEGIS acquisition of the same serial, or type the waiver `NO BACKUP`, which is ledgered.

## Engine and format limits

- **E01 needs whole sectors.** libewf stores whole sectors. A source whose size is not a multiple of the sector size is refused for E01 (`E01NeedsWholeSectors`) and must be acquired as RAW. Physical disks are always whole sectors. Measured: libewf rounded a 3,146,962-byte source down to 3,146,752 bytes, and read-back verification caught it before this refusal was added.
- **E01 writer.** The PyPI libewf wheel cannot write E01 on Windows. AEGIS writes E01 through Autopsy's libewf 20130416 build via ctypes and reads it back through pyewf 20240506. E01 checkpoints are not durable mid-run (`E01_NO_DURABLE_CHECKPOINT`), and an E01 acquisition cannot be resumed.
- **No Windows software write blocker.** The source is opened read-only, but Windows offers no kernel write block. Every acquisition carries `NO_SOFTWARE_WRITE_BLOCK`. Use a hardware write blocker for court evidence.
- **Overwrite profiles.** Zero-fill single pass (Clear) and the legacy DoD 5220.22-M 3-pass profile (still a Clear) are implemented. Pseudorandom fill is not implemented. Gutmann is not implemented and is not meaningful for modern media. Both are shown as such in the UI.
- **A Clear is not a Purge.** Overwriting reaches only the addressable LBA range, so remapped flash blocks and HPA/DCO areas are not covered unless the HPA/DCO workflow ran first. The report states the level achieved. AEGIS is not NIST-certified.
- **Recovery scope.**
  - Bifragment reassembly covers baseline JPEG and PNG in exactly two runs, with a gap of at most 2 MiB on the volume's cluster grid. Such objects are scored MEDIUM at most.
  - FAT undelete marks every candidate `contiguity_assumed`, because FAT deletion zeroes the cluster chain.
  - Plain text has no signature to carve. Allocated text files remain visible through Autopsy.
  - The media map is sampled on large images, which the UI labels "(sampled)".
- **Recovery speed and time budgets.** The Variant parsers and decoders run under per-object time budgets. Under heavy load (for example, two scans of the same image at once, or console debug logging) a large object can come back `decoder_unavailable` instead of `valid`; its offset, length and SHA-256 do not change. This was measured on 2026-10-03: on a 768 MB slice of a real pendrive image, 2 of 546 verdicts differed in a log-flooded run, and a quiet run matched exactly. The dominant recovery cost is the Variant's pure-Python JPEG scan check (about 60% of run time), which proves a JPEG is whole rather than spliced. Two re-read hotspots (footer search and ZIP end-record search) were removed without changing results. A 31 GB image can still take on the order of hours. Use *Write recovered copies* off for triage of very large images.
- **Deep Forensic Purge.** It removes only traces the engine ties to the erased path on evidence: Recent shortcuts, jump lists and Recycle Bin copies. Weaker matches are reported, not touched. The Windows thumbnail cache cannot be tied to one path, so clearing it is a separate opt-in that clears the whole per-user cache through Restart Manager (graceful shutdown only). Not searched: the Windows Search index, application-private recent lists, shadow copies and sync clients.
- **AI enhancement.** EDSR ×2/×3/×4 runs on CPU with OpenCV `dnn_superres`. It took about 86 s for an 800×600 photo and longer for larger images, with tiled progress shown. The output is a labelled derivative and never evidence.
- **Report verification grading.** A report whose ledger excerpt carries only its own job's entries verifies as `VERIFIED_WITH_LIMITATIONS`: the signature, the genesis key and the full store chain all verify, and the excerpt gaps are declared. A real modification yields `FAILED_VERIFICATION`.

## Packaging and environment

- **Licence.** AEGIS, including the engine, is proprietary (decided by the copyright holder on 2026-10-04; previously the engine's `LICENSE` said GPL-3.0). Third-party components keep their own licences and notices (`THIRD_PARTY_NOTICES.md`).
- **The full Autopsy suite was not recompiled in this pass.** The AEGIS module was clean-built. The other ten Autopsy cluster jars in the package are byte-identical to the working build produced on 2026-10-02, which the staging manifest checks.
- **NetBeans class cache.** Replacing a module jar requires touching `autopsy\.lastModified`, or an existing profile runs cached classes. `tools/stage-aegis-package.ps1` does this. A manual jar swap must do the same.
- **Variant UI tests.** `tests/api/test_bundle_offline.py` fails because the React bundle is not built; the desktop does not use it. Five tests that create symlinks fail without Windows symlink privilege (Developer Mode or administrator).
