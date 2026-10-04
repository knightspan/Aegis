# Limitations

Every guarantee this tool cannot make, stated plainly. If something here reads
as uncomfortable, that is the point: an operator who over-trusts a wipe is worse
off than one who knows exactly what it did and did not cover.

What each platform implements, and what has run on real hardware of which device
class, is not restated here: it is generated from the capability resolver into
[`validation/capability-completion-2026-09-28/capability-matrix.md`](validation/capability-completion-2026-09-28/capability-matrix.md),
and summarised in
[`validation/capability-completion-2026-09-28/README.md`](validation/capability-completion-2026-09-28/README.md).
In short, the only physical runs on record are: on Linux, whole-drive clear,
discovery and raw acquisition of one USB flash stick (TOSHIBA TransMemory,
2026-09-05); on Windows, discovery of a USB stick and a file erase on the host's
own system disk (device class not recorded), both 2026-09-27. Everything else in
this file that runs is **IMPLEMENTED / UNVALIDATED** or **DEVICE-DEPENDENT** at
best.

## The ATA security-erase password is fixed and published

`core/erase/drive.py` uses a fixed password for the ATA SECURITY ERASE sequence:

```
ATA_RECOVERY_PASSWORD = "SanctumForensics"
```

The sequence is `SECURITY SET PASSWORD` → `SECURITY ERASE PREPARE` →
`SECURITY ERASE UNIT`. Between the first and last step the drive is
password-locked. If the process dies in that window — crash, `SIGKILL`, power
cut — **the drive stays locked and is unusable until the password is cleared.**

Three mitigations, all in code:

1. The password is written to the ledger *before* `SET PASSWORD` is issued, so
   the recovery value survives the crash that makes it necessary.
2. A `SIGINT`/`SIGTERM` handler and an `atexit` hook both attempt
   `SECURITY DISABLE PASSWORD`.
3. The command refuses to start on a frozen drive.

If a drive is left locked, clear it by hand:

```bash
hdparm --user-master u --security-disable SanctumForensics /dev/sdX
```

A fixed, published value is a deliberate trade. The password protects nothing —
it is a transient precondition of the erase command, not a secret — and making
it recoverable matters far more than making it unguessable.

This sequence exists on Linux only. **ATA SECURITY ERASE UNIT is NOT IMPLEMENTED
on Windows**, for exactly the reason above: the drive is password-locked between
the first and last command, and no recovery path for a refused or interrupted
erase has been built and tested on Windows. ATA SANITIZE is offered there
instead, where the drive reports it. On macOS it is PLATFORM-LIMITED: macOS
exposes no public ATA pass-through to applications.

## DoD 5220.22-M's third pass is not random here

The historical sequence is a character, its complement, then a **random**
character. A random final pass cannot be read back and checked, and an
unverifiable erase is not something this project will report as verified. The
third pass is therefore a fixed zero character, keeping the
character/complement/character shape and leaving a result
`core/erase/verify.py` can actually verify.

On a device whose controller does not program zeros, both zero passes become
`0xA5` — see "Some controllers do not program a zero fill at all" below. That
loses the character/complement/character shape, which is worth less than passes
that actually reach the medium. The plan records the fill bytes and the reason.

The engine implements the method because operators are sometimes contractually
required to name it. It is **not offered in the UI or the API**: the erase request
carries a level only, so a screen control naming DoD could not be honoured, and an
earlier build that showed one produced a certificate contradicting the confirmation
dialog. It is reachable only by calling `core/erase/drive.py:execute` with
`EraseJob.method` set. NIST SP 800-88r2 (September 2025) states that multi-pass
overwrite is not needed for clear and calls the DoD 5220.22-M pass-count language
obsolete (Appendix D); for SSDs with over-provisioning it says such practices
should be avoided, as very little confidentiality protection is achieved
(Sec. 3.1.1). This tool measures no benefit over a single pass, and on flash
media every extra pass burns program/erase cycles without reaching a single
remapped or over-provisioned block.

## Overwrite cannot reach all of a flash device

A host overwrite only reaches host-addressable LBAs. On SSDs, eMMC and USB
flash, these are unreachable by any write pattern:

- blocks the FTL has remapped after wear or failure,
- over-provisioned capacity never exposed to the host,
- data still live in the write cache or in an unmapped erase block,
- cells the controller never programmed because it elided the write — see the
  next section.

Only a firmware sanitize or a cryptographic erase covers those. Where neither is
available, the result is a **Clear**, not a **Purge**, and the report says so.

**No host-side read can establish physical removal on flash.** Every read is
answered by the flash translation layer, which decides what a logical block
returns. A full read-back proves that the device now reports the expected
pattern for every addressable block. It cannot prove that the cells holding the
prior contents were erased, and no verification strategy — full, sampled,
seeded, repeated — changes that. The report states this rather than leaving a
reader to infer it from a passing verification.

## Some controllers do not program a zero fill at all

Measured on a Toshiba TransMemory USB stick across three hardware-validation
runs. Every write used `O_DIRECT` with the same 4 MiB buffer, on the same
device:

| Write | Bytes | Seconds | MiB/s |
|---|---:|---:|---:|
| `0x00`, whole device | 7,759,462,400 | 521.5 | **14.19** |
| `0x00`, 64 MiB calibration | 67,108,864 | 4.60 | **13.92** |
| `0xA5`, whole device (×3) | 7,759,462,400 | 1886.3-1910.8 | 3.87-3.92 |
| `0xA5`, 64 MiB calibration | 67,108,864 | 14.96 | 4.28 |
| `0xFF`, 1 GiB, via pipe | 1,073,741,824 | 242.2 | 4.23 |
| `0xFF`, 1 GiB, via `cat` | 1,073,741,824 | 266.2 | 3.85 |

Every byte the controller actually programs lands between 3.85 and 4.28 MiB/s,
across three fill values, two tools, three transfer sizes and three runs. Zeros
run 3.25-3.62x faster than any of them. A write that completes faster than the
medium can be programmed was not performed: the controller mapped the addresses
to a zero token, or compressed the all-zero buffer away. Which of the two is not
distinguishable from the host and does not matter — either way the cells still
hold what they held before.

Reads show the same asymmetry. The same device reads `0x00` at 39.13 MiB/s and
`0xA5` at 23.89-23.93 MiB/s, two independent reads of the `0xA5` medium agreeing
to 0.2%. Consistent with the FTL answering a zero-mapped block without touching
NAND on the read path too; recorded as an inference from timing rather than a
proven mechanism. **Published throughput for this class of device: ~4.0 MiB/s
write, ~23.9 MiB/s read.**

This is worse than the general flash caveat above, and for a different reason.
There, the write happened and could not reach everything. Here the write did not
happen, so it created none of the free-block pressure that forces garbage
collection to erase the old blocks — which is the only mechanism by which a
host-side overwrite improves anything on flash.

`core/erase/calibrate.py` measures this before every software overwrite: one
64 MiB non-zero fill and one 64 MiB zero fill over the same region, timed. A
ratio at or above 2.0 records `CONTROLLER_WRITE_ELISION` at HIGH severity with
the measurement attached, and `core/erase/patterns.py` substitutes `0xA5` for
every `0x00` pass so the write is actually performed and the verification checks
a pattern the controller had to store. **A device wiped this way holds `0xA5`
afterwards, not zeros.** The plan states the fill bytes before the run starts.

The substitution is a truthfulness fix before it is a security one: the report
names `SINGLE_PASS_OVERWRITE`, and a controller that elides wrote nothing. NIST
SP 800-88r2 Sec. 3.1.1 describes overwrite as replacing target data with
non-sensitive data, and an elided write replaced nothing. The Clear *outcome*
still holds — every block reads as zero through the device's own interface,
which is what clear is defined to protect against — but the method statement
would have been false.

### What this does to a three-pass estimate

`DOD_5220_22_M_3PASS` writes `(0x00, 0xFF, 0x00)`, or `(0xA5, 0xFF, 0xA5)` after
substitution. Costing every pass at the zero rate is what makes a naive estimate
wrong by a factor of two:

| Estimate | Arithmetic | Total |
|---|---|---|
| Naive, all passes at the zero rate | 3 × 521.5 | 1564.5s = **26.1 min** |
| Measured, zero passes elided | 521.5 + 1886.75 + 521.5 | 2929.8s = **48.8 min** |
| Upper bound, every pass programmed | 3 × 1886.75 | 5660.3s = **94.3 min** |

`core/erase/calibrate.py:estimate_seconds` costs each pass at the rate measured
for the byte that pass writes, and `ErasePlan.est_basis` records where the
number came from. An operator must not discover a 3.6x mid-run.

**14.19 MiB/s is not a write throughput** and must not be quoted as one. It is
the rate this controller acknowledges zeros. The device's real write rate is
~4.0 MiB/s. The same applies to the 39.13 MiB/s read: that is the rate it
answers zero-mapped blocks, and the real read rate is ~23.9 MiB/s.

The substitution was exercised end to end on 2026-09-05: the erase wrote
`0xA5` over the whole device at 3.92 MiB/s, verification passed against `0xA5`
with 0 failed offsets, and a full re-verification after an unplug/replug cycle
passed again. See `docs/validation/hardware.md`.

## `queue/rotational` is not a flash test

A USB bridge does not clear the kernel's `queue/rotational` flag. The validation
stick reports `rotational: True` and `lsblk` agrees, so it is not even a
disagreement to report. Every flash caveat in the erase path was gated on
`not device.rotational`, so none of them reached the report for a USB flash
stick — the media that needs them most.

`core/device/media.py:is_flash` makes a positive determination instead, from the
transport, the flag, the model string, or the write calibration, and returns the
signal that decided it so the report can say how it knew. Transport wins over
the flag: there are no rotating USB sticks or SD cards, and the flag being wrong
is the documented failure mode.

## ATA enhanced SECURITY ERASE is Purge on magnetic media only, and that rule is unvalidated

On a device `is_flash` determines to be flash, ATA enhanced SECURITY ERASE and
ATA SANITIZE overwrite are not counted as Purge. The authority is the withdrawn
NIST SP 800-88r1 Table A-8, which lists SECURITY ERASE UNIT under Clear for ATA
SSDs; SP 800-88r2 does not name the command and defers to IEEE 2883, which has
not been read. `docs/compliance.md` quotes the text.

What this does not establish:

- **No SATA SSD has been available**, so the flash half of the rule has never
  run on real media. No ATA firmware erase has run on hardware at all. The unit
  tests in `tests/device/test_purge_by_device_class.py` and
  `tests/erase/test_enhanced_erase_on_flash.py` are the only evidence.
- **The rule is only as good as the flash determination.** A hybrid drive, or an
  SSD whose kernel reports `rotational=1` and whose model string names no flash,
  is treated as magnetic, and its enhanced erase is counted as Purge. r1 Table
  A-5 itself warns that hybrid drives "may not be easily identifiable by the
  label".
- **On magnetic media the Purge claim rests on a withdrawn table.** The capability
  record says so on every device where enhanced erase would be the Purge method.
- r1 advises consulting the manufacturer before relying on SECURITY ERASE UNIT
  on either media type. This tool does not, and cannot.

## USB and MMC bridges block ATA pass-through

Most USB-SATA bridges do not forward ATA pass-through commands, so `hdparm -I`
fails and neither SANITIZE nor SECURITY ERASE can be issued or even confirmed to
exist. Those devices are limited to overwrite-based CLEAR. Attach the drive to a
native SATA port to do better.

The resolver applies this per device class on every platform: on `usb-flash` and
`mmc` devices, ATA SANITIZE, ATA SECURITY ERASE, cryptographic erase and HPA/DCO
discovery and modification read DEVICE-DEPENDENT and are refused, because the
bridge usually translates only reads and writes. A firmware command is offered
only when the controller itself reports it and no bridge hides it.

## A software write block is a claim about a flag, not about a refusal

`core/carve/acquire.py:apply_write_block` sets `BLKROSET`, reads it back with
`BLKROGET`, and reports `applied` from the read-back. That establishes that the
kernel holds the device read-only. It does **not** establish that a write would
be refused, and the record says so with `WRITE_BLOCK_NOT_VERIFIED`.

Proving the refusal means attempting a write, and the acquisition path never
writes to a device. The asymmetry is the reason: a write test fails safe only
when the block works, and it is precisely when the block does not work — the
case the test exists to detect — that the test writes to the evidence it was
protecting. The restore is another write, and on flash it programs a new page.

Verification by attempted write lives in `scripts/probe-write-block.py`, gated
behind `--i-understand-this-may-write-to-the-device`, run once against **scratch
media** to qualify an interface. `AcquisitionRecord.write_block_verified_by`
records which claim is being made: `flag_read_back` from the acquisition path,
`attempted_write` only from a qualification.

Measured on a Toshiba TransMemory behind a USB bridge, 2026-09-05:
`WRITE_BLOCK_WORKS`. The refusal arrived at `write()` with `EPERM` while
`open(O_WRONLY)` **succeeded** — a check that stopped at the open would report a
working block on a cosmetic flag. That refusal point is a kernel property, not a
bridge one; `BLKROSET` sets `bd_read_only` on the kernel's block device and the
kernel is what refuses.

Two paths are not covered by the flag at all, on any bridge:

- **SG_IO and ATA pass-through**, which address the device below the block layer
  where `bd_read_only` is never consulted. `hdparm --write-sector` and `sg_dd`
  write straight through a set flag.
- **A partition node whose own flag was never set.** The flag is applied to the
  path given to the acquisition; an automount writing through `/dev/sdX1` while
  only `/dev/sdX` was set is exactly the accident a write block exists to stop.
  Untested.

Use a hardware write blocker for evidence that will be presented.

**Windows and macOS have no software write block at all.** Raw acquisition on
Windows (`core/carve/win_source.py`) opens the disk or volume with `GENERIC_READ`
only, and on macOS (`core/carve/mac_source.py`) opens `/dev/rdiskN` `O_RDONLY`.
That means Sanctum itself cannot write through the handle; it does nothing to stop
the operating system, another process, or an automount from writing to the device
during the read. The acquisition record says so and names a hardware write blocker
as the control. Internal Apple storage is never imaged: it is encrypted by the
Secure Enclave, and a raw image of it is ciphertext that cannot be decrypted off
the machine. Raw acquisition on both platforms is IMPLEMENTED / UNVALIDATED: it has
been tested through adapter doubles only, and no physical device has been imaged on
Windows or macOS.

## Verification above 64 GiB is sampled, not exhaustive

At or below 64 GiB every block is read. Above it, verification reads the first
and last 1 GiB in full plus 4096 random 1 MiB windows from a seeded RNG. The seed
is recorded so a third party can redraw the same sample set.

The report carries the detection-probability formula rather than a bare
percentage:

```
P = 1 - (1 - (r + u - 1) / n)^k
```

`n` total bytes, `u` sample window, `r` size of a hypothetical residual region,
`k` random draws. **This is the chance of detecting a residual region of a given
size. It is not proof that none exists.**

## Hardware attestation is the drive's claim about itself

After a firmware sanitize, the ATA SANITIZE STATUS or NVMe sanitize log is read
and recorded. That is evidence, not proof: it is the drive reporting on its own
behaviour. Verification therefore always reads the medium as well, and a clean
attestation never excuses residual data found by sampling.

Firmware sanitize is accepted as leaving either `0x00` or `0xFF`, because vendors
differ. Any other byte value is treated as residual data. A crypto erase leaves
ciphertext under a new key, which reads as noise, so no pattern can be required of
it: the same seeded windows are hashed before and after and every one must differ.
That shows the command changed every sampled window; it cannot show the old key is
gone (`core/erase/devicesanitize.py`).

**Windows NVMe Sanitize reports no progress.** It is issued through
`IOCTL_STORAGE_REINITIALIZE_MEDIA`, which returns when the driver reports
completion or the timeout expires; nothing in between can be shown. **NVMe Format
NVM is PLATFORM-LIMITED on Windows**: the in-box NVMe driver does not pass it
through `IOCTL_STORAGE_PROTOCOL_COMMAND`, so NVMe Sanitize is used instead where
the drive supports it. The Windows storage driver may also refuse an ATA
pass-through; the refusal is reported and nothing is retried another way. None of
the Windows firmware paths (ATA SANITIZE block erase and crypto scramble, NVMe
Sanitize block and crypto) has run on a physical drive.

## Unwritable ranges are skipped, not fixed

A sector that returns `EIO` is recorded in `unwritable_ranges` and skipped; the
wipe continues, because one bad sector must not cost a four-terabyte job. Those
ranges still hold whatever they held before, and they raise the residual-risk
level to high.

## HPA and DCO

Hidden areas are detected read-only. **An ordinary erase never unlocks or
modifies an HPA or a DCO.** When the probe finds hidden bytes, an overwrite
erases the accessible range only, the result records `hidden_covered=False`,
the limitations name the hidden byte count and tell the operator to run the
HPA/DCO workflow first, and the residual risk is high ("part of the medium was
not erased"). Firmware sanitize covers the full media by design, so nothing is
reported missing there.

The `HIDDEN_AREA_UNLOCK` phase is ledgered on **every** run: `not_required`
when the drive reports no hidden area, carrying the probed sector counts;
`not_authorized` when it reports one that this erase deliberately left alone;
`skipped` for a firmware method. A chain that simply omitted the phase would be
indistinguishable from one where the tool never probed. `HIDDEN_AREA_RESTORE`
always records `not_required`, because the erase never changed anything.

Exposing the hidden sectors is the separate, guarded HPA/DCO workflow
(`core/device/hidden_area_workflow.py`, `POST /workflow/hidden-area`): a
plausibility-checked reading of the native and accessible maxima, a verified
backup of at least the accessible range, a human approval with the serial typed,
a one-use authorization, a re-read of the drive immediately before the command
(a drifted plan is refused as stale), and a read-back afterwards. The change is
**volatile by default** (lost at the next power cycle); a permanent change is
made only when explicitly requested and acknowledged. Only SET MAX ADDRESS is
ever sent: **DCO RESTORE and DCO SET are never issued**, so sectors a DCO hides
beyond the native maximum stay hidden and the workflow says so. The workflow
erases nothing; the exposed sectors are sanitized by a later ordinary erase. On
Linux the kernel keeps the size it read at attach time, so the device must be
rescanned or re-attached before that erase sees the new size. On macOS HPA/DCO
discovery and modification are PLATFORM-LIMITED: macOS exposes no public ATA
pass-through, so neither the native maximum can be read nor SET MAX ADDRESS
issued.

No loopback device reports an HPA or a DCO - they are ATA features of real
media. The erase branch is covered against a faked hidden-area report in
`tests/erase/test_hidden_area_phases.py`; the workflow against a fake hdparm
runner and the Windows ATA pass-through double (`testkit/fake_windows.py`) in
`tests/device/test_hidden_area_workflow.py` and
`tests/api/test_hidden_area_workflow.py`.

**The HPA/DCO workflow is DEVICE-DEPENDENT and physically unvalidated.** No drive with a hidden area has
been through it on Linux or Windows. On the one physical stick the project has
run (2026-09-05), the probe was skipped behind the USB bridge, which is the
bridge-discard behaviour working.

## NVMe scope

`sanitize` acts at **controller** scope: it destroys every namespace on the
controller, not only the one named. `format` acts **per namespace**; every
namespace is iterated and named, and a namespace created after the run is not
covered.

## The ledger is mandatory, and there is no longer a fallback

This section previously recorded that `core/erase/drive.py` defaulted to an
in-memory ledger that was neither durable nor hash-chained, so a run made
without an explicit sink was not independently auditable.

That hole is closed. `execute()` now **refuses to start** without a ledger:

```
execute() needs a ledger: every phase must be recorded in the hash-chained
audit log. Pass ChainLedgerSink(Ledger(root, ...)).
```

The in-memory implementation is gone from `core/`. An equivalent lives in
`tests/erase/test_overwrite_file.py`, where its lack of durability costs
nothing, because what those tests need is to see the phase records the
overwrite loop emits — the chain itself is covered by `tests/ledger/`.

## Undelete recovers a different amount on every filesystem

`core/carve/fsaware.py` recovers deleted files from surviving filesystem
records. How much that is worth is not the same on any two filesystems, and
averaging them into one number would describe none of them. Measured against
`testkit/generate_corpus.py`'s real filesystem images, on the date in
`docs/performance/calibration.md`:

| filesystem | deleted | recovered exactly | recall |
|---|---:|---:|---:|
| NTFS | 25 | 24 | 96.0% |
| FAT32 | 246 | 235 | 95.5% |
| ext2 | 2 | 2 | 100.0% |
| ext3 | 2 | 2 | 100.0% |
| exFAT | 2 | 1 | 50.0% |
| **ext4** | **2** | **0** | **0.0%** |

### ext4 recovers essentially nothing, by design

`ext4_ext_remove_space` zeroes the inode's extent tree when a file is
unlinked. The inode survives with its size, its mode and its timestamps, and
points at **no blocks at all**. There is nothing to follow, and no
implementation can change that.

What is recovered instead comes from the jbd2 journal: stale copies of
inode-table blocks written before the tree was zeroed. The journal is a
circular buffer covering only the recent past, so a file deleted before it
wrapped is gone from it, and the recovered inodes carry no filename — ext4
keeps names in directory blocks, which cannot be tied to an inode number
without the transaction that wrote both.

**ext4 is not demonstrated.** On ext4, use the signature carver over the
unallocated map, which `undelete_report()` returns for exactly this reason.

### FAT recovery is a reconstruction, however clean the result looks

FAT deletion zeroes the file's cluster chain. The start cluster and the size
survive; the layout does not. Recovery walks forward from the start cluster
taking clusters the FAT currently shows as free and skipping any a live file
now owns.

That reconstruction is right for an unfragmented file, and right surprisingly
often for a fragmented one — but only while its neighbours still exist. Once a
neighbouring file has *also* been deleted, its freed clusters are
indistinguishable from this file's and are pulled into the result. The
recovered file is then the right length and the wrong content, and **nothing on
the volume can detect it**. Every FAT candidate is therefore marked
`contiguity_assumed`, whatever it looks like.

Where a cluster between a file's first and last is allocated to a live file,
fragmentation is *proven* and the candidate says so separately. The absence of
that proof is not evidence of contiguity.

### exFAT is the one case where the filesystem records the answer

The stream extension entry carries a `NoFatChain` flag. When it is set, exFAT
stored the file as one run and kept no chain for it *while it was live*, so a
contiguous read is a recorded fact rather than an assumption, and
`contiguity_assumed` is false. When it is clear, the file used a chain that
deletion destroyed and exFAT is no better off than FAT32. Which case applied is
recorded on every exFAT candidate.

### ext3's measured recall is an upper bound

The corpus deletes ext2 and ext3 files by unlinking, freeing the blocks and
setting `i_dtime`, leaving the block pointers in the inode. That is exactly
what ext2 does. A Linux 2.6 or later kernel also runs `ext3_truncate` on
delete, which zeroes `i_block` as well — so **real ext3 recall is at or below
the 100% measured here**, and on a modern kernel it will be closer to ext4's.
ext2's figure stands as measured.

### NTFS resident files are reassembled around the update sequence

A file small enough to fit inside its MFT record has no run list: its content
is part of the record, and NTFS has overwritten the last two bytes of each
sector of that record with a check value. Those bytes are spliced back from the
record's update sequence array, so the recovered content is exact. If a future
NTFS variant changed the fixup layout, this would produce two wrong bytes per
sector in small files, which is why `candidate.sha256` is computed over the
same extents `read_recovered()` returns rather than over the bytes TSK hands
back — the claim is checkable.

## What each carved format's length comes from, and which ones are a guess

A carved object has no filename and no recorded size, so its end is either derived from
the format's own structure or it is guessed. The difference decides whether the recovered
file opens, and it is not uniform across the table in `testkit/signatures.yaml`:

| Format | Where the end comes from | Exact? |
|---|---|---|
| JPEG | segment walk to the EOI marker | yes |
| PNG | length-prefixed chunk walk to IEND, every CRC verified | yes |
| PDF | the last `%%EOF` a `startxref` corroborates | yes |
| ZIP, DOCX, XLSX | the end-of-central-directory record | yes |
| SQLite | `page_size` × `page_count` from the header | yes |
| MP4 | the top-level box sizes | yes |
| TIFF | the IFD chain and the strip offsets it points at | yes |
| BMP | the 32-bit file size in the file header | yes |
| WebP, WAV | the RIFF size field | yes |
| GZIP | inflating the member, bounded at 256 MiB of output | yes |
| RTF | counting braces to the one closing the document group | yes |
| TAR | member headers to the end-of-archive marker | yes, with the caveat below |
| **HTML** | **the closing `</html>` tag, or the next object** | **no** |
| GIF | footer search | no |
| OLE, ELF, PE, RAR, 7z, EVTX | no parser; footer or next-object bound | no |

**HTML is a footer bound and says so.** The format carries no length anywhere, and
`</html>` is a convention rather than a requirement. A document that ends without one is
bounded by wherever the next object's header begins, which is an upper bound and not a
length; the candidate reports `possibly_fragmented` and does not claim an exact length.
Only the lower-case `<!DOCTYPE html` and `<html>` spellings are matched, so an
upper-case or mixed-case document is not found at all.

**A tar is returned without its trailing padding, and is therefore usually not
byte-identical to the file as written.** GNU tar pads an archive to its blocking factor -
10,240 bytes by default - after the two zero blocks that end it. Those padding bytes are
zeros, and so are the bytes of the last cluster's slack on every filesystem, so nothing
in the content distinguishes them. Rounding the length up to a blocking factor would
return the file exactly and would be an assumption about the writer rather than a
measurement of the medium, which is the same defect as reading cluster slack as an MP4
box. The archive therefore ends where the format says it ends. Where the filesystem
record survives, the undelete pass recovers the tar at its recorded size and this does
not apply.

**A gzip member that inflates beyond 256 MiB gets no derived length.** Deriving the end
of a gzip stream means decompressing it, and a carved candidate is exactly the kind of
untrusted input that is a decompression bomb. The output is counted and discarded, never
held; past the bound the parser declines and the candidate keeps the scan's bound.

**Two formats share a header.** WebP and WAV are both `RIFF`, and what separates them is
the form type four bytes later. Both are in the table and both are checked.

## Bifragment reassembly is narrow, and depends on the volume's cluster size

`core/carve/fragmentation.py` rebuilds a baseline JPEG or a PNG split into two runs.
PNG's reach and refusals are measured separately in
[`validation/png-reassembly.md`](validation/png-reassembly.md): 120 of 120 layouts to
a 7 MiB gap, 0 of 800 adversarial joins accepted, on synthetic images. The rest of
this section is about JPEG. What it can be trusted with is exactly this and no more:

* **One baseline JPEG, exactly two runs, both still on the medium.** Progressive,
  arithmetic-coded, lossless and multi-scan JPEGs are never reassembled, and no format
  other than JPEG and PNG is. A file in three or more pieces is not recovered.
* **Reach: the gap between the runs at most 2 MiB (2,097,152 bytes).** Measured over
  ten random layouts at each of 64 KiB, 128 KiB, 256 KiB, 512 KiB, 1 MiB and 2 MiB, on
  512-byte and 4096-byte clusters with the size known: all recovered byte for byte.
  Beyond that it is not reliable on small clusters — 7 of 10 at 4 MiB and 3 of 10 at
  8 MiB on 512-byte clusters, 10 of 10 to 8 MiB on 4096-byte ones — and the object must
  end within 8 MiB of its header in every case. Failures are refusals; none of the
  layouts was reassembled wrongly.
* **The volume's cluster size has to be known for that reach.** It is read per volume
  by the undelete pass (boot sector, BPB or superblock) and limits every join to that
  grid. On a raw image, a damaged boot sector or a carve run without undelete, the
  search walks 512-byte sectors instead: still safe, since every real layout lies on
  that grid, but slower and with less reach — on a 4096-byte volume, 10 of 10 recovered
  to 1 MiB and 8 of 10 at 8 MiB, and two or more clusters of ambiguous gap bytes next
  to a run edge were refused.
* **Ambiguous gap bytes cost reach.** Bytes that cannot occur inside a JPEG scan mark
  where the gap starts and ends. Zeros, directory entries, text and another JPEG's scan
  data do not, so the search has to try every join through them: up to 8 clusters of
  them next to a run edge were recovered, 16 were refused.
* **A refused search costs time.** Up to about 1.7 seconds per JPEG header, against
  tens of milliseconds before Batch 7. Measured on an adversarial image with an EOI
  every 4 KiB: 396 ms per header, against 23 ms before.

### Why a reassembled object is never HIGH

Acceptance rests on an exact count of the scan's entropy-coded data against its frame
header, which Pillow does not do: libjpeg reports a short, overlong or misaligned scan
as a warning and returns an image regardless, and at `hwval-run4` that let the tool
emit a real head joined to its own tail read 3,584 bytes late, scored HIGH (PREFLIGHT2
FINDING 1). The count is much stronger — 0 of 600 insertions, 0 of 400 chimeras of two
JPEGs and 0 of 7,200 same-length substitutions accepted — but it is not a proof. **A
join that drops 512 to 1,536 bytes of the object's own scan passes about one time in
twenty on noise-like JPEGs** (18, 21 and 14 of 400 at 512 and 1,024 bytes; none at
3,584 bytes or more; none on a smooth photographic image). The search tries the true
join before any such one whenever the true join is on the medium, so this bites when it
is not: a tail whose first sectors were overwritten. That is why every reassembled
candidate carries a `reassembly` score component holding it at 7999, one basis point
below HIGH, and why the report and the UI both say it was rebuilt from runs.

### The JPEG verdict has been checked against one camera's photos

The same exact scan count also marks a contiguous baseline JPEG `corrupt` when it
decodes but its entropy-coded data does not account for its frame header — including
the first image of a JPEG whose MPF index lists further images, which Pillow opens as
MPO — and that verdict has been checked against the JPEGs of one camera firmware
only, an Apple iPhone 15 Pro Max on iOS 18.5 (7 photos, 6 EXIF thumbnails and 7 HDR
gain maps, every one with restart intervals, all counted exactly), and against no
Android phone and no dedicated camera, so on JPEGs from any other device that verdict
is not yet shown to mean damage.

**Only the first image of an MPO is counted.** A further image the candidate holds —
the gain map of a phone photo recovered whole by undelete, or a second stereo view —
is judged by the decoder alone, which reports foreign bytes inside a scan only as a
warning. Damage confined to that second image can therefore still read `valid`.

**A carved phone photo is its first image only.** The object ends at the EOI its scan
reaches, and the gain map an iPhone stores after that EOI is carved as a separate
candidate. The photo's `validation_detail` says how many images its MPF index
declares, how many the object holds, and where the absent ones were declared to be;
the photo's bytes and digest are exact.

**Every recall and precision figure in `docs/validation/` and `docs/performance/` was
measured on populations whose JPEGs were all Pillow encodes**: the calibration corpora
built by `testkit/generate_corpus.py` and `testkit/fsimage.py`, and the files
`scripts/hardware-validation.sh` plants on real media. No camera-written JPEG was in
any measured population. That is a limit of those figures, not a finding about the
tool: they say nothing, in either direction, about how camera photos are recovered or
scored.

## E01 acquisition is uncompressed, and slightly larger than the source

`pyewf` binds exactly one write-configuration setter, `set_header_codepage`.
`libewf_handle_set_compression_values` is not reachable from Python, so
`AcquireOptions.compression` is accepted and **has no effect**. libewf's default
is not "fast"; it is *no compression*.

An E01 written by this tool is therefore marginally **larger** than the source.
Confirmed with `ewfinfo` against a container this codebase wrote: 8 MiB of a
single repeated byte produced 8,394,899 bytes. E01 here is a container format
and an integrity record, never a space saving. Use `ewfacquire -c fast` where a
compressed container is required.

An E01 acquisition also **cannot be resumed** — libewf has no append mode for
an existing segment set — and checkpoints during one are recorded in the ledger
but not forced to disk, because `pyewf` exposes no flush. Both are refused or
recorded rather than worked around. Acquiring to raw resumes normally.

## Per-file overwrite is best effort, and the report names every gap

`core/erase/files.py` writes through a file handle. That reaches the file's
current data extents and nothing else. It does not reach:

- the ext3/ext4/xfs journal or the NTFS `$LogFile`,
- the NTFS `$UsnJrnl` change journal,
- `$MFT` record slack or `$I30` index slack,
- file slack between end-of-file and end-of-cluster,
- any block a copy-on-write filesystem has already redirected away from,
- a page a flash translation layer remapped after a TRIM.

`core/erase/residual.py` enumerates each of these as a named finding with a
derived severity rather than leaving them out of the report. **The enumeration
is the deliverable.** A separate free-space wipe now overwrites the blocks a
volume calls free (next section); every class in the list above is still only
detected and reported. A tool that reports "shredded, unrecoverable" is lying; a
tool that reports "overwrote 3 extents, the ext4 journal may retain content, and
2 snapshots still reference the old extents" is evidence.

That the journal really is a recovery route is not a claim taken on trust here:
`core/carve/fsaware.py` recovers deleted ext4 content from exactly that
structure, and `tests/erase/files/test_residual_against_real_filesystems.py`
pins the two modules to the same mechanism.

### A free-space wipe reaches free blocks and nothing else

`core/erase/freespace.py` fills a mounted volume's free space with `0xA5` through
files in a directory of its own until `ENOSPC`, then deletes them. What it can be
trusted with:

**Measured, on udisks loop volumes mounted by the kernel's own drivers.** Six JPEGs
were planted and deleted, then the recovery pipeline (`api.carve_job`) was run over
the image before and after the wipe
(`tests/erase/files/test_free_space_wipe_carve.py`):

| Volume | Recovered before | Recovered after | Raw slices after | Bytes written | Free before (`f_bavail`) | Blocks still free at `ENOSPC` |
|---|---|---|---|---|---|---|
| FAT32, 512-byte clusters | 6 of 6 | 0 | 0 | 66,053,120 | 66,056,704 | 0 |
| FAT32, 4096-byte clusters | 6 of 6 | 0 | 0 | 326,975,488 | 326,979,584 | 0 |
| exFAT, 4096-byte clusters | 6 of 6 | 0 | 0 | 64,974,848 | 64,978,944 | 0 |
| exFAT, 32768-byte clusters | 6 of 6 | 0 | 0 | 64,749,568 | 64,782,336 | 0 |
| ext4, 4096-byte blocks | 6 of 6 | 0 | 0 | 53,805,056 | 53,809,152 | 4,694,016 |

"Raw slices after" counts planted files a 512-byte slice of which was still
anywhere in the image, whatever the carver made of it. On each volume, the gap
between free space and bytes written is one cluster: the one the filler
directory itself took.

What that does not establish:

- **None of it ran on real media.** A loop device has no flash translation layer.
  On flash the fill reaches the logical blocks the filesystem calls free, and the
  controller chooses which physical pages receive it (see "Overwrite cannot reach
  all of a flash device"). No USB stick or SD card run has been recorded.
- **The fill must reach `ENOSPC`, because every allocator measured here is
  next-fit.** On each of the five volumes, a file written right after a deletion
  did not land on the clusters just freed. A partial fill therefore misses the most
  recently freed space first. A cancelled wipe claims no coverage.
- **ext4's reserved blocks are not written.** The fill runs unprivileged and stops
  at `ENOSPC` with the root reserve still free: 4,694,016 bytes on the 64 MiB test
  volume, reported as `free_blocks_bytes_at_full`. None of the planted content was
  there in the measured run. The allocator's placement decided that, not the wipe's
  coverage, and a different history could leave content in those blocks.
- **Not reached, on any filesystem:** file slack (writing past the end of a file
  the operator did not name is refused on principle: that file is evidence);
  deleted directory entries, whose names, sizes and timestamps the undelete pass
  still reads; journals and filesystem metadata; the filler directory's own
  clusters. One side effect was measured, and it is not coverage: on FAT32 and
  exFAT the filler directory's own entry in the volume root was placed in the
  slots of a deleted root entry, and that one name was gone after the wipe. On
  ext4 the deleted name was still in its directory block afterwards.
- **Nothing is read back.** `verified` is always `null`. The carve before and
  after is test evidence, not something the product does on every run.
- **Only kernel `vfat`, `exfat` and `ext4` are accepted.** NTFS has not been
  measured, and neither has FUSE (including `fuse2fs`). Copy-on-write filesystems
  would write the fill beside old data rather than over it. All are refused. Linux
  only.
- **The flash caveat is attached to loop volumes too.** The `trim_likely` probe
  treats a device that advertises discard as flash, and a loop device does. For
  these test volumes the caveat is a false positive, and it is reported rather
  than suppressed.
- **The integration tests need a desktop session.** udisks attaches and mounts loop
  devices for the active local user through polkit. Elsewhere (CI, SSH, a
  container) the tests skip, and they name the reason.

### A file erase is usually unverifiable, and is reported as unverifiable

`verify_file_erase` returns a **tri-state** `passed`. `None` means "the original
physical location could not be read, so nothing is claimed", and it is the
common answer. It refuses in four distinct situations:

| situation | why nothing can be claimed |
|---|---|
| no extent map was captured | there is no address to read back |
| copy-on-write filesystem | the overwrite went to freshly allocated blocks |
| data was resident in metadata | there is no data extent at all |
| raw device read refused | reading the original blocks needs root |

Only after all four are cleared does it open the block device read-only, seek to
the pre-erase physical offsets and compare. **Exactly one function in
`core/erase/verify.py` can construct `passed=True`, and it is reachable only
after that read.** A test parses the module's AST and fails the build if a
second construction site appears.

On an ordinary unprivileged run the honest outcome is: the file was overwritten,
renamed, unlinked — and verification reports `not_possible`.

### No file erase on FAT or exFAT can be verified by reading back extents

The extent map a file erase is verified against is captured with the `FS_IOC_FIEMAP`
ioctl on Linux. **Neither `vfat` nor `exfat` answers it**: both return
`[Errno 95] Operation not supported`, measured on loopback mounts of each during the
second hardware pre-flight (PREFLIGHT2 FINDING 2). So `core/erase/inspect.py` captures
no extents for any file on either filesystem, and `verify_file_erase` reports
`not_possible` for every one of them.

That is not an edge case. FAT32 and exFAT are what a USB stick or an SD card is
formatted with out of the box, so **a per-file erase on a removable device's own
filesystem can never be verified by reading the medium back.** The overwrite, the
renames and the unlink still happen and are recorded; the verification claim is
absent, and the report says why.

### Hard-linked files are not overwritten by default

A file with `st_nlink > 1` shares its inode with names the operator did not
give. Overwriting it would destroy their content too, so by default only the
named link is unlinked and `HARDLINK_SURVIVES` is reported at HIGH with the link
count. **The data survives, and the report says so.** `break_hardlinks=True`
overwrites anyway, and the finding still reports that it happened.

### Metadata cleansing runs before the overwrite, and never claims a false clean

Cleansed bytes are what get destroyed. The other order would leave the original
EXIF block in whatever the overwrite did not reach.

A file that could not be parsed is reported `parsed=False` with a reason, never
as a clean file with zero fields — those two read identically in a report and
only one of them is true. OLE compound documents (`.doc`, `.xls`, `.ppt`) and
HTML are **identified but not rewritten**: doing so safely needs a full writer
for each format, and a partial rewrite risks a document that no longer opens.
Their metadata is destroyed by the overwrite that follows, not by the cleanser.

A PDF updated incrementally keeps its earlier revisions in the same file.
Clearing the current metadata does not clear a copy held in a previous revision.

### Directory fsync is not available on Windows

The rename chain is flushed with `fsync` on a directory handle, which POSIX
supports and Windows does not expose unprivileged. On Windows the renames may
remain recoverable from the directory index until the filesystem flushes on its
own schedule, and the limitation is recorded on the record.

### The Windows backend: what has now run, and what has not

`core/erase/_platform/win.py` now runs on a real Windows 11 runner in CI
(`platform-ci`), against that machine's NTFS volume: alternate data streams,
resident MFT data, the read-only attribute, and a real directory junction that
must not redirect a recursive erase. Those results are recorded in
`core/platform/validation_record.json`, and the app's capability screen lifts
file erase on Windows out of *Unverified* only because that record exists.

Updated 2026-09-27: a human has now installed the package on a physical
Windows 11 machine and driven it against a real USB stick — device discovery,
the mounted-device refusal, and a file/folder erase → verify → certificate on
that machine's own NTFS, all real (`docs/validation/windows-hardware-2026-09-27-fixes/`).
What has still never happened on Windows: raw physical-device acquisition and
whole-drive clear or device sanitize of a physical disk. All three are now
implemented (`core/carve/win_source.py`, `core/erase/blockclear.py`,
`core/erase/devicesanitize.py` over the native layer in `core/device/win/`) and
tested through the adapter double `testkit/fake_windows.py` only, so they read
IMPLEMENTED / UNVALIDATED or DEVICE-DEPENDENT; none has run against a physical disk.
Every file-erase method still degrades to an honest unknown plus a recorded
limitation when a call fails.

One defect that testing found and fixed: the extent map recorded one cluster
per run, so a post-erase read-back of a contiguous 256 KiB file verified
4 KiB of it. Runs now carry their length, and a map truncated by fragmentation
says so.

## Platform differences

The full matrix is [`platform-support.md`](platform-support.md). The limits
that change what an operator can do:

- **Whole-drive clear runs on all three platforms; it has run on hardware only on
  Linux.** Linux uses `core/erase/drive.py`; Windows and macOS use
  `core/erase/blockclear.py` over a handle bound to the planned disk. On Linux it
  is SUPPORTED for `usb-flash` only (one stick, 2026-09-05); on Windows and macOS
  it is IMPLEMENTED / UNVALIDATED. A Windows disk must be offline before it is
  written (Devices > Prepare takes it offline, non-persistently; any exposed
  volume refuses the write), and Sanctum must be started with *Run as
  administrator*. A macOS external disk must be unmounted (Prepare, or `diskutil
  unmountDisk`) and the raw work needs root. A Storage Spaces or virtual disk is
  refused on Windows, and internal Apple storage is never raw-written on macOS.
- **Firmware Purge has never run on hardware**, on any platform. It is
  selected from probed capability and dispatched on Linux (ATA SANITIZE, ATA
  SECURITY ERASE, NVMe Sanitize, NVMe Format, Opal) and on Windows (ATA SANITIZE,
  NVMe Sanitize); that path is DEVICE-DEPENDENT and physically unvalidated. The
  Platform row, each device's Purge option and the Devices badge (PURGE ·
  UNVERIFIED, never a green PURGE AVAILABLE) say so until the validation record
  holds a PASS for that capability on that device class. The option is still
  offered, under that word: the code exists and the drive reported the command,
  and it is never presented as a hardware-validated result. On Windows, ATA
  SECURITY ERASE is NOT IMPLEMENTED and NVMe Format is PLATFORM-LIMITED (above).
  On macOS every device sanitize command and cryptographic erase is
  PLATFORM-LIMITED: macOS exposes no public ATA pass-through or NVMe
  admin-command interface to applications.
- **Free-space wipe is NOT IMPLEMENTED on Windows or macOS.** On NTFS, how the
  filling file is allocated (MFT zone, reserved clusters) has not been measured,
  so the fill could not be described honestly; APFS is copy-on-write and shares
  free space across a container's volumes, so a fill does not map to released
  blocks in a way that could be verified.
- **APFS, Btrfs, ReFS and F2FS are copy-on-write.** A file erase on them
  removes the file and reports residuals; it cannot destroy the old blocks and
  is never reported as verified.
- **macOS internal storage** is purged by macOS's own *Erase All Content and
  Settings* (Apple silicon, T2), which destroys the storage keys. The app
  names that path and does not perform or verify it.
- **macOS discovery is IMPLEMENTED / UNVALIDATED.** The parser is tested from
  captured `diskutil` output on Linux, and the CI macOS runner discovers its own
  virtual disks; it has not been run against a physical macOS disk set, and no
  macOS physical device run of any capability is recorded. **Windows discovery was run against a real disk set** on 2026-09-27,
  through the installed package on a physical Windows 11 machine: it found 3
  real devices, and correctly assessed the mounted one NOT AVAILABLE
  (`docs/validation/windows-hardware-2026-09-27-fixes/`).
- **Windows and macOS raw physical-device acquisition are IMPLEMENTED /
  UNVALIDATED.** Until 2026-09-28 Windows raw acquisition was not implemented:
  `POST /jobs/acquire` opened its source with a plain `open(..., "rb")`, which
  cannot address the Win32 device namespace (confirmed on a physical Windows 11
  machine, 2026-09-27, `docs/validation/windows-hardware-2026-09-27-fixes/`).
  `core/carve/win_source.py` now opens `\\.\PhysicalDriveN` or a volume with
  `GENERIC_READ` only and binds the handle to the selected disk's number, serial
  and length; `core/carve/mac_source.py` opens `/dev/rdiskN` `O_RDONLY`, bound to
  the selected size. Neither has imaged a physical device. M3 carving itself has
  run correctly on real Windows hardware, including through the installed
  package's own API (`/jobs/acquire` + `/jobs/carve`), but only against a
  synthetic image. A separate, now-fixed defect meant the *installed* package
  could not carve at all until 2026-09-27: `core/carve/signature.py`'s signature
  table (`testkit/signatures.yaml`) was never bundled into any packaged build, on
  any platform - `docs/validation/windows-hardware-2026-09-27-fixes/` §5.
- **Windows file verification needs elevation** (raw volume read); the app
  never elevates, so unelevated erases are reported *not verified*.
- **diskutil reports no serial numbers, and no macOS ioctl returns one.** Serials
  come from `system_profiler`. A raw `/dev/rdiskN` handle is bound only by its
  size (`DKIOCGETBLOCKCOUNT` × `DKIOCGETBLOCKSIZE`, read from the open descriptor)
  against the plan; the serial is re-read from `system_profiler` / `diskutil`
  immediately before the device is opened. Between that re-read and `open()` there
  is a window in which a different disk of the same size could take the same
  `diskN`. It is not closed; the report records how the binding was made and does
  not claim more
  ([security review](security-review-cross-platform.md#the-native-device-layer-windows-and-macos)).
- **The development server is loopback-only and session-protected**, like the
  packaged app: `python -m api.main` prints a `/session/<token>` URL and
  refuses anything without that cookie. `SANCTUM_DEV_INSECURE=1` disables the
  check for a single-user development machine and prints a warning; there is
  no configuration that binds anything other than `127.0.0.1`.
- **Containers.** Inside a container the host's root, mounts and swap are
  invisible while `/sys` still lists the host's disks, so the system disk
  cannot be identified. Whole-drive work is refused there unless
  `SANCTUM_ALLOW_CONTAINER_DEVICES=1` is set for a container that was given
  exactly the target device.
- **Hardware validation of the Windows and macOS device layers: none.** No
  designated disposable media was used on either platform; no device was written or
  raw-read. They are tested through adapter doubles, and `scripts/native_smoke.py`
  exercises the real bindings read-only on the CI runners, which is not physical
  validation. See
  [`validation/platform-matrix.md`](validation/platform-matrix.md) and the
  [capability matrix](validation/capability-completion-2026-09-28/capability-matrix.md).

## PII triage counts shapes, stores no values, and reads only some types

`core/carve/pii.py` counts Aadhaar (Verhoeff), PAN, IFSC, Indian mobile, payment
card (Luhn) and email shapes in each recovered object. The user manual (§6, "PII
triage") lists the exact patterns.

**Values are never stored.** Each recovered object gets kinds and counts only. No
matched value, prefix, suffix, mask, hash or offset is written to the report, the
ledger, the job result or any log. A hash is excluded because an Aadhaar number
has 10^11 checksum-valid values, which is brute-forced against a SHA-256 in
minutes. An offset is excluded because, with the recovered object, it gives the
value back. `tests/api/test_pii_no_leak.py` plants synthetic values in deleted
files on a FAT32 volume and runs the carve, the SSE stream, report generation and
verification. It then searches the ledger, the reports (the JSON, and the PDF raw
and decoded), the job result, the SSE replay, every structlog event at DEBUG,
stdlib logging, stdout, stderr and every other file under the state and key
directories. It searches for each value as planted, as bare digits, in UTF-16LE,
base64, SHA-256/SHA-1/MD5 hex, and as a mask ending in the real last four digits.
It fails on any match. It was also run with a deliberate leak (a debug log of the
match) and failed, naming the sink.

**A count is a signal to look, not a finding.** A shape plus a checksum does not
establish an identifier. One random 12-digit string in ten passes Verhoeff, and
one random 16-digit string in ten passes Luhn. A 16-digit Aadhaar Virtual ID that
happens to pass Luhn is counted as a card. International phone numbers,
non-Indian identity numbers and postal addresses are not detected at all.

**Measured false-positive rates.** Raw bytes, no type gate, data holding no planted
identifier; hits per MiB:

| Corpus | Size | Aadhaar | PAN | IFSC | Mobile | Card | Email |
|---|---:|---:|---:|---:|---:|---:|---:|
| Synthetic carving corpus, seed 0 | 12.5 MiB | 0 | 0 | 0 | 0 | 0 | 0 |
| Filesystem corpus images, seed 0 (13) | 414.0 MiB | 0 | 0 | 0.188 | 0 | 0 | 0 |
| iPhone camera JPEGs (7) | 13.9 MiB | 0 | 0 | 0 | 0 | 0.072 | 0.144 |
| iPhone HEIC (6) | 7.8 MiB | 0 | 0 | 0 | 0 | 0 | 0 |
| Thumbnails and gain maps carved from those photos (19) | 0.87 MiB | 0 | 0 | 0 | 0 | 0 | 0 |

All three JPEG hits are in entropy-coded image data. One card hit is inside a
secondary (gain-map) image. All 78 IFSC hits are FAT 8.3 directory entries
(`FILL0001PAD`), a false-positive class that camera names such as `DSCN0001JPG`
also fall into. Zero means none were seen in that many bytes, not a zero rate.
These corpora are small, and the photos come from one phone.

**Therefore only documents, databases and unclassified objects are scanned.**
Images, media, archives and executables are not. Scanned as raw bytes, 2 of the 7
camera JPEGs measured would have shown an identifier that is not there. A ZIP's
members are therefore not scanned, and neither is text inside an image, such as a
photographed ID card.

What the scan reads, and misses:

* **OOXML:** the text of the XML parts, tags removed, capped at 64 MiB of inflated
  text. Each part is inflated 64 KiB at a time and never held whole; a 32 MiB part
  measured 2.37 MiB of peak allocation. Paragraph, cell and row boundaries are
  kept, so two cells never fuse into one number.
* **PDF:** content streams, skipping image and font streams. Text drawn
  with per-glyph kerning (`[(98765)-20(43210)]TJ`), hex strings or a custom
  encoding is not reassembled and is missed. So is an encrypted PDF. A recovered
  PDF is untrusted input, so no stream is decoded whole: each stream's raw bytes
  are read, unfiltered and `FlateDecode` streams are inflated 64 KiB at a time
  into the counter, and reading stops at the 64 MiB budget. A 1 GiB Flate stream
  stored in 1 MiB costs +6.7 MiB of peak RSS (it cost +2,050 MiB before this
  bound). **Streams behind any other filter** (`ASCII85Decode`, `LZWDecode`,
  `RunLengthDecode`), with a predictor, or in an encrypted file **are not
  decoded and are missed**; the `basis` counts them. qpdf inflates object and
  cross-reference streams while it opens a file, so those are measured in the raw
  bytes first, and a PDF with one that inflates beyond 16 MiB, or that uses a
  filter whose size cannot be measured, is not opened or scanned at all.
* **Raw bytes** (`.txt`, `.csv`, SQLite, legacy `.doc` and unclassified objects):
  ASCII/UTF-8 only. UTF-16 text is missed; that covers most legacy `.doc` bodies
  and EVTX. So is a number stored as a binary integer. The false-positive rate on
  OLE and unclassified binary objects has not been measured.
* **Objects above 64 MiB:** raw-byte types are scanned through the read-only handle
  in 1 MiB windows. OOXML and PDF objects that large are not scanned, and their
  `basis` says so.

## The operator identity is a local account, not a person

The ledger's `actor` is resolved server-side by the privileged helper from the
uid it was started with (`api/identity.py`, `helper/daemon.py:_op_whoami`). A
client can no longer write an arbitrary name into it. What that establishes is
**which operating-system account** ran the operation. It does not establish who
was at the keyboard, and on a shared account it does not distinguish two people.
With no helper socket configured the identity is the API process's own uid and
its basis sentence says so. A label an examiner types is recorded beside the
identity and marked `[label: …]`; it is not verified.

## Reports rebuilt after a restart carry no progress trace

A finished job's result is written into the chain as a `job.outcome` entry, so
`POST /reports/{job_id}` works after the API restarts (`api/durable.py`). The
result object is byte-identical — it is content-addressed — but the per-record
progress stream never entered the chain and is absent, and the report's
limitations say it was rebuilt. A job that never reached a terminal state (the
process was killed mid-run) has no outcome entry and still cannot be reported.

## Spilled carve bytes are deleted, not sanitized

During a carve, fragmented and multi-extent objects are spilled to
`<state>/work/` and removed on success, failure and cancel
(`api/carve_job.py:SpillStore`). Removal is `unlink`. On flash media the bytes
may persist physically until the FTL reclaims them. Keep the state directory on
an encrypted volume if recovered content is sensitive.

## The case document is an index

`<state>/cases/*.json` is ordinary mutable JSON. It groups operations and
reports for the UI and proves nothing; the hash chain is the record, and the
case screen's integrity verdict is always the chain's. Editing a case document
changes the grouping, not the evidence.

## A real erase's gates: what they do not prove

A real whole-drive erase needs a backup image the server hashes and sizes when
the workflow opens, an approval with the typed serial, and a one-use
authorization, and the privileged helper re-checks device, plan and backup
before the engine starts. Tested with synthetic helpers only (SYNTHETIC
VALIDATION). What that does not establish:

- **Backup provenance is not proven.** The image is checked by SHA-256 at open
  and by size, mtime, ctime and inode at execution. Nothing proves it is a copy
  of this device, and it is not re-hashed at execution. A backup record made from
  Sanctum's own acquisition of that device carries the acquisition job id, which
  establishes the image equals what that run read from that path, still not that
  the device carried the recorded identity at that moment (`core/backup.py`).
- **Restore is implemented and has never run on a physical device.**
  `core/restore.py` with `/workflow/restore` verifies every chunk against the
  backup record before writing it, accounts for every byte, and reads the range
  back afterwards; it is gated like an erase (recorded approval, typed serial,
  one-use authorization re-checked at the write seam) on Linux, Windows and macOS. It is
  IMPLEMENTED / UNVALIDATED everywhere: tested against image files and adapter
  doubles only. The post-restore read-back goes through the operating system, so
  a drive's volatile cache can answer it; a pass shows the target returns the
  image's bytes now, not that they survive a power loss. The physical benchmark
  harness still prints a manual `dd` restore command, which has never been run,
  and the physical benchmark itself is still BLOCKED at gate 1
  ([`validation/physical-benchmark-checklist.md`](validation/physical-benchmark-checklist.md)).
- **The helper's check and the first write are not proven race-free.** The
  helper re-reads the device and the backup immediately before entering the
  engine; between that check and the first write only the engine's own guards
  (system disk, mount, serial re-read) stand.
- **The API does not authenticate a human.** Approval is a deliberate second
  call with the typed serial, not proof of who made it (see below).
- **There is no rehearsal mode.** Every erase, restore, HPA change, free-space
  wipe and device preparation that passes its gates runs against the real
  target; a request carrying `dry_run`, `simulation` or `simulate` is refused.
  What would run is shown by the read-only plan (`core.erase.drive.preview`,
  the workflow `open` calls, `POST /workflow/wipe-free-space`), which writes
  nothing. Reports signed by earlier builds may record a rehearsal (a
  "SIMULATION" or "DRY RUN" limitation); those remain historical evidence and
  still render as "nothing was sanitized".

## The API has no authentication

It binds `127.0.0.1` only. Any local account that can reach that port can drive
it. Run it on a single-user examination workstation. See
[`threat-model.md`](threat-model.md#local-multi-user-threat).

## Platform

`core/erase/drive.py`, the Linux whole-drive engine, still refuses to import
elsewhere: it needs `O_DIRECT`, `BLKGETSIZE64` and hdparm/nvme-cli. Windows and
macOS use their own engine, `core/erase/blockclear.py`, over the native handles
in `core/device/win/` and `core/device/mac/` (see "Platform differences" above
for what that path has and has not done). `core/erase/files.py` stays
cross-platform.

**The Windows file-erasure backend (`core/erase/_platform/win.py`) is
type-checked under `--platform win32` and now also runs on a real Windows 11
runner in CI** — see "The Windows backend: what has now run, and what has not"
above, which is the authoritative statement, and the `file_folder_erase` /
Windows 11 row of `core/platform/validation_record.json`. Alternate data
streams, resident MFT data and a real directory junction are covered there. The
USN journal and Windows file locking are still implemented from documentation
and exercised by no test. **An erase has now run on physical Windows media**:
2026-09-27, a file/folder erase → verify → certificate through the installed
package on a real Windows 11 machine's own NTFS
(`docs/validation/windows-hardware-2026-09-27-fixes/`); no erase has run against a
physical Windows *removable* device, and no whole-drive clear, device sanitize or
raw acquisition has run on any physical Windows disk.

This paragraph previously said the backend had never executed on a Windows
host. That stopped being true when `platform-ci` began running the suites on a
Windows runner, and the sentence outlived the fact. It then said no erase had
run on physical Windows media at all; that stopped being true on 2026-09-27.

**E01 limits.** Acquisition to E01 is uncompressed (see above). E01 reading
depends on the `libewf-python` build; the tests that need an E01-writing build
are among the suite's skips and name their reason.

## Destroy

`SanitizationLevel.DESTROY` is never achievable in software and is never
returned by method selection. It means physical destruction: shred, disintegrate,
incinerate, melt.

The application records a destruction but cannot perform or observe one. A
**Record of Destruction** (`POST /jobs/record-destroy`, the Devices screen) chains
and signs what the people named in it attest. Its signature proves the record has
not changed since it was signed, not that the destruction happened; the names are
typed in and not authenticated; and whether the technique and fragment size reach
Destroy for that media is the facility's determination, not the tool's.

## Trace sweep

The sweep after a file erase searches the desktop's shared thumbnail cache,
recent-files lists (GTK 2, 3 and 4, and KDE), the home Trash, the Trash on the
file's volume (`.Trash-$uid`, or `.Trash/$uid` when `.Trash` is sticky and not a
link), the Windows Recycle Bin, Recent shortcuts and jump lists
(AutomaticDestinations and CustomDestinations), and on macOS the Trash (home and
per-volume `.Trashes/$uid`), the recent items (`.sfl2`/`.sfl3` shared file lists)
and the Quick Look thumbnail cache. Every report lists each place inspected with
its outcome (searched, absent, unreadable, permission-denied). It does not search
application caches and history (office suites, viewers, browsers), search and
activity indexes (Tracker, the KDE activity database, Windows Search, Spotlight),
snapshots, backups or sync clients; every report lists these as not searched.

- `thumbcache_*.db` is listed as not searched: its entries are keyed by a cache
  hash, not the file path, so none can be tied to an erased path on evidence.
- A macOS Trash item is removed only when its put-back record (`ptbL`/`ptbN` in
  the Trash's `.DS_Store`) names the erased path. A same-name item with no record,
  or with a record naming another path, is reported as a possible copy and never
  removed. The record itself stays in the `.DS_Store`, which Finder owns; it
  names the path, not the content. Put-back paths are compared literally: a
  firmlink or symlinked alias of the erased path is not resolved.
- A macOS recent item, a Quick Look cache entry, a jump-list entry in a jump list
  that also names other files, and any custom jump-list entry are tied on
  evidence but **reported only**, with the reason: each sits in a file a daemon
  or the shell owns and rewrites, and editing it in place could corrupt the other
  entries. A jump list every entry of which names an erased path is erased as a
  whole file. `qlmanage -r cache` resets the Quick Look cache by deleting, not
  overwriting, its files.
- A recent item's bookmark is matched only when its whole path decodes; a
  bookmark that holds only a file ID or volume-relative data is not matched. The
  Quick Look index is read immutable, so an entry still only in
  `index.sqlite-wal` is not seen (the report notes when such a log exists), and a
  cache whose schema is not the known `files(folder, file_name)` layout is listed
  as not searched with that reason.

A thumbnail made under a URI other than the one the file was erased by (through a
link, another mount point or a network share) is found only when its `Thumb::URI`
names a file inside an erased folder.

The `.DS_Store`, bookmark, shared-file-list and jump-list parsers are tested
against artifacts built byte for byte from their format descriptions, not against
files taken from a real Mac or Windows profile.

**Removal not validated on a live desktop.** The sweep has run against synthetic
home directories in the test suite and in a sandboxed browser run
(`validation/features-2026-09-25/`). On a physical Windows 11 desktop (2026-09-27, build `437081e`) the sweep searched the machine's real `C:\$Recycle.Bin` and Recent shortcuts and found nothing, because the erased file had no traces (`validation/windows-hardware-2026-09-27-fixes/` §4). So the enumeration has
run against one real desktop; removing a real trace from a live session, with
its own thumbnailer, recent-files writers and Trash, has not been run on any
platform, and no Linux or macOS desktop run is recorded.

## Media map

The map classes bytes by statistics over 4 KiB blocks. It does not identify
content. Above 64 MiB it reads evenly spaced samples within a 64 MiB budget, so a
region is classed by its samples and can hold what they missed. Header counts are
of headers on 512-byte sector boundaries, not validated files, and two-byte
signatures (`MZ`, `BM`) are not counted at all.
