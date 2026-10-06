# Twenty-nine questions an evaluation panel asks, and the answers

Every number here is traceable to a file in this repository. Where the answer is
"we cannot", the answer includes the measurement that shows why — those are the
strongest ones in the set, and they are the reason the honest ones are worth
rehearsing hardest.

Sources: `docs/validation/hardware.md` (hardware run, 2026-09-05),
`docs/performance/calibration.md` (confidence weights),
`docs/limitations.md` (everything the tool cannot do), and, for what runs on
which platform and what is physically validated on which device class, the
generated
[`capability-matrix.md`](../validation/capability-completion-2026-09-28/capability-matrix.md)
(2026-09-28). Where an answer below and the matrix disagree about a platform,
the matrix is right.

---

## 1 · Why not 35-pass Gutmann, or DoD 5220.22-M three-pass?

> **Say it out loud:** Gutmann targets encoding schemes that left the market in
> 2001, and its own author wrote the epilogue saying so. We offer DoD three-pass
> because operators are sometimes contractually required to name it — and on this
> stick we measured it at **94.3 minutes against 26.1 for a single calibrated
> pass**, because two of its three passes are zeros this controller elides. More
> passes on flash is more wear for no measurable gain.

**The full written answer, for the follow-up:**

Because neither buys anything we can measure over a single pass, and on flash
the extra passes are actively harmful.

Gutmann's 35 passes target MFM and RLL encoding on drives with areal densities
five orders of magnitude below current ones. Gutmann himself wrote the epilogue
saying so. On modern perpendicular recording the patterns are noise.

DoD 5220.22-M we do offer, because operators are sometimes contractually
required to name it. NIST SP 800-88r2 calls its pass-count language obsolete. On this
validation stick we measured what it actually costs: **94.3 minutes against 26.1
minutes** for a naive estimate, because two of its three passes are zero passes
that this controller elides, and the tool substitutes `0xA5` so they are
genuinely programmed. Three passes of real programming on flash burn three times
the program/erase cycles and still reach not one remapped or over-provisioned
block.

One caveat we state rather than hide: our third pass is a fixed zero character,
not the historical random one. A random pass cannot be read back and checked,
and an unverifiable erase is not something this project reports as verified.

**NIST SP 800-88r2 (September 2025) states that multi-pass overwrite is not
needed for clear, and for SSDs with over-provisioning says such practices should
be avoided because very little confidentiality protection is achieved.** We name
the method we achieved. (Its predecessor, r1, was withdrawn on 2025-09-26.)

---

## 2 · How do you guarantee an SSD is unrecoverable?

> **Say it out loud:** We do not, and we will not claim to. Every read from
> flash is answered by the translation layer, so a clean read-back proves the
> device *reports* the pattern — never that the cells were erased. There are
> **four things a host overwrite provably cannot reach**, we name all four in the
> report, and the only routes that do reach them are a firmware sanitize or a
> cryptographic erase.

**The full written answer, for the follow-up:**

**We do not, and we will not claim to.** Here is the measurement.

Every read from a flash device is answered by the flash translation layer, which
decides what a logical block returns. A full read-back proves the device now
*reports* the expected pattern for every addressable block. It cannot prove the
cells holding the prior contents were erased. No verification strategy — full,
sampled, seeded, repeated, or repeated across a power cycle — changes that,
because it is a property of the interface, not a weakness in the verifier.

Four things a host overwrite provably cannot reach:

- blocks the FTL remapped after wear or failure,
- over-provisioned capacity never exposed to the host,
- data still live in the write cache or an unmapped erase block,
- cells the controller never programmed because it elided the write.

We measured the fourth one directly. On the validation stick, `0x00` was
acknowledged at 14.19 MB/s while any byte the controller actually programs lands
at 3.85–4.28 MB/s. **Ratio 3.25 to 3.62, reproduced across two runs and three
sample sizes.** A write that completes faster than the medium can be programmed
was not performed.

What we do instead: probe the device, and if a firmware sanitize or a
cryptographic erase is reachable, use it and record the drive's attestation. If
neither is — as on any USB bridge — the result is a **Clear**, not a **Purge**,
the report says `purge_achieved: false`, and the residual risk is recorded at
`high` with every contributing factor named.

For an SSD holding material that actually matters: ATA SANITIZE block erase or
crypto scramble on a native SATA port, or physical destruction. Not our
overwrite. We will tell you that in the report.

---

## 3 · What is your recovery rate?

> **Say it out loud:** There is no single number, and any tool quoting one is
> averaging filesystems that behave nothing like each other. On real media on
> 2026-09-05 we recovered **456 of 456 on FAT32 and 460 of 460 on exFAT,
> byte-identical** — on the carve pipeline as it was before structure carving was
> wired in, so not the one that ships now, and every file on those volumes was
> contiguous, so that is 100% on a contiguous population, not 100%.
> Synthetically, FAT32 is 95.5% and ext4 is 0%, and the 0% is physics, not a
> defect.

**The full written answer, for the follow-up:**

There is no single number, and any tool quoting one is averaging filesystems
that behave nothing like each other. Per filesystem, measured against real
`mkfs` images with byte-identical recovery as the only success criterion
(`docs/performance/calibration.md`):

| Filesystem | Deleted | Recovered exactly | Recall | n |
|---|---:|---:|---:|---|
| NTFS | 25 | 24 | **96.0%** | 25 |
| FAT32 | 246 | 235 | **95.5%** | 246 |
| ext2 | 2 | 2 | 100.0% | **n=2 — not a rate** |
| ext3 | 2 | 2 | 100.0% | **n=2 — not a rate** |
| exFAT | 2 | 1 | 50.0% | **n=2 — not a rate** |
| ext4 | 2 | 0 | **0.0%** | **n=2 — but see below** |

**The three rows that are n=2 are ext2, ext3 and exFAT, plus ext4.** They show
which mechanism applies, not a rate. exFAT's "50%" is one file that had
`NoFatChain` set and came back exactly, and one that used a chain deletion
destroyed. That is two data points.

Two more honest readings of the good rows:

- **FAT32's 95.5% is dominated by filler files.** 244 of the 246 are 256 KiB
  blocks of pseudo-random bytes written to force fragmentation. They are real deleted
  files and they are in the manifest, so excluding them would be marking our own
  homework — but the row describes recovery of filler more than recovery of
  documents.
- **NTFS misses one of 25 deliberately.** Its MFT record was reused, so only the
  name survived, out of `$I30` index slack. We report the name and no content.
  Reporting content for it would be attributing one file's bytes to another.

**ext4's 0.0% is the finding, not a defect.** `ext4_ext_remove_space` zeroes the
inode's extent tree on unlink. The inode survives with its size, mode and
timestamps and points at no blocks at all. No implementation can change that.
What we recover instead comes from the jbd2 journal — stale inode-table blocks
written before the tree was zeroed — which is a circular buffer covering only
the recent past, and those inodes carry no filename. **On ext4 we tell you to
use the signature carver over the unallocated map, and `undelete_report()`
returns that map for exactly this reason.**

Everything above is synthetic-corpus data. The real-media numbers follow.

### Real removable media, measured 2026-09-05

Three passes against a Toshiba TransMemory USB stick, volume images acquired and
verified before carving (`docs/validation/hardware.md`, Phase B).

**Every figure in this subsection was measured on the pre-Batch-2 pipeline.**
Phase B ran on 2026-09-05, when `api/carve_job.py` still called the signature
carver alone. Batch 2 then routed it through `carve_structures`, which adds the
format parsers and bifragment reassembly. The pipeline that ships has not yet
been measured on real media; that is the next hardware run, and these figures
are not a stand-in for it.

| Filesystem | Damage | Deleted | Recovered exactly | Recall |
|---|---|---:|---:|---:|
| FAT32 | half the files deleted | 456 | 456 | **100.00%** |
| exFAT | half the files deleted | 460 | 460 | **100.00%** |
| FAT32 | quick format | 912 | 10 | **1.10%** |

Three things have to be said about those rows or they mislead.

**The two 100% rows are 100% on a contiguous population.** The harness populates
a freshly formatted volume in one sequential pass and only then deletes, so no
file on either volume was fragmented and **0 of the 916 needed multi-extent
reconstruction**. FAT deletion zeroes the cluster chain and we walk forward from
the start cluster; on a contiguous file that cannot go wrong. The case
`contiguity_assumed` exists to warn about — a deleted neighbour's freed clusters
being pulled in — was never exercised. Real evidence is fragmented. **We do not
yet know what that costs us**, and it is now our biggest weakness (question 10).

**The 1.10% is the test population, not the media and not the carver.** 902 of
the 912 planted files are 256 KiB of pseudo-random bytes with no header, no
footer and no signature. A quick format destroys every directory entry, which is
their only route home, and leaves signature carving, which can address the 10
planted JPEGs and nothing else. **The ceiling for that pass was 10 files, and we
recovered 10 — 100% of what was recoverable at all.** The data itself was still
physically on the stick: the JPEGs came back byte-exact from raw bytes after the
`mkfs`, and `lsblk -D` reports `DISC-MAX 0B`, so this device honours no discard
and `mkfs.fat` 4.2 issues none. **A quick format on this media sanitizes
nothing.**

**Precision held where it matters.** 98.09% and 98.10% on the delete passes,
52.63% on the quick-format pass, over 963 candidates in total:

| Bucket | Candidates | True | Precision |
|---|---:|---:|---:|
| HIGH | 30 | 30 | **100.00%** |
| MEDIUM | 924 | 906 | 98.05% |
| LOW | 9 | 0 | 0.00% |

**No false positive reached HIGH in any pass.** All 27 false positives — 9 per
pass — were signature hits inside the pseudo-random filler bytes; the filler
stream contains exactly 8 occurrences of `FF D8 FF` and 1 of `50 4B 03 04`, and
the carver produced exactly 8 JPEG and 1 ZIP false positives from them. That is
the carver behaving correctly on a corpus built to defeat it. Where MEDIUM is
weak is ordering, not the floor: 906 correct recoveries scored 0.5500 and one
false positive scored 0.6000, so **within MEDIUM the confidence number does not
rank truth.** The HIGH floor at 0.8000 separated them cleanly, which is what the
report relies on.

---

## 4 · How did you derive the confidence weights?

> **Say it out loud:** By measuring them against ground truth and publishing the
> sweep. A candidate counts as a true positive only when its SHA-256 matches, and
> three weights moved because the measurement moved them. The interesting one is
> the weight we did **not** move: at 5000 the aggregate looks better, and it gets
> there by promoting **237 candidates no decoder ever confirmed** — so 1500 is the
> largest value the evidence permits.

**First, the question underneath it: what is the number?** An evidence score out
of 10000, not a probability that the object is correct. Six components fire or
do not, each worth a fixed number of basis points; they come to 10,500 when all
six fire, so a candidate showing `10000 / 10000` hit the clamp rather than a
measurement of certainty. That is why the screen shows a score against its
denominator and not a percentage. **What is calibrated is the bucket**, and its
precision on a stated population: pooled over eight seeds and 173 candidates,
104 of 104 HIGH candidates matched a planted object byte for byte
(`docs/performance/calibration-pooled.md`). Say the limit in the same breath —
those are synthetic corpora, and on the 7 GiB image HIGH precision was **86.6%**
until the footer-bound fix of 2026-09-21. If a judge asks "so is a HIGH file
100% certain?", the answer is no: *every HIGH candidate in that population was
correct, and the population is small and synthetic.*

**The full written answer, for the follow-up:**

By measuring them against ground truth, then publishing the sweep.

`testkit/generate_corpus.py` plants 24 objects at known offsets and records a
manifest with SHA-256, offset, length and kind. The full pipeline runs over the
image exactly as the product runs it. **A candidate is a true positive only when
its SHA-256 matches a recoverable manifest entry.** Not "starts at the right
offset", not "is the right type" — a recovered file that differs by one byte
does not open.

Three weights moved, each for a stated reason:

| Component | Was | Is | Why |
|---|---:|---:|---|
| `decoder_valid` | 3500 | **4000** | Every candidate with header + derived length + clean decode was a true positive (100% precision, n=13). At 3500 the total was 7500 and four of them sat in MEDIUM. At 4000 that combination is exactly 8000, the HIGH floor. HIGH recall 60.0% → 86.7%, precision unchanged at 100.0%. |
| `decoder_truncated` | 1500 | **1000** | Truncated candidates scored zero true positives, and at 1500 one reached MEDIUM. **n=1, so a small correction, not a strong claim** — but a file the decoder could not finish reading is by definition not the file that was there. |
| `decoder_unavailable` | 0 | **1000** | Scoring a missing verdict as zero put two true positives in LOW alongside genuine false positives. "No decoder ran" is not evidence the bytes are bad. At 1000 they reach MEDIUM and cannot reach HIGH by construction. |

**The one to ask about is `fs_metadata`, which did not move.** We swept it 0 to
5000 over the whole filesystem corpus and watched two columns:

| `fs_metadata` | HIGH precision | Empty candidates ≥ MEDIUM | Unconfirmed at HIGH |
|---:|---:|---:|---:|
| 0 – **1500** | 100.0% | **0** | **0** |
| 2000 | 100.0% | **2** | 0 |
| 4000 | 86.4% | 3 | **7** |
| 5000 | 95.6% | 3 | 237 |

At 5000 the aggregate looks dramatically better — 95.6% precision and 93.9%
recall against 100.0% and 13.3%. **It is worse.** The gain comes from promoting
237 candidates no decoder confirmed, and among them is a FAT32 recovery the
corpus knows is wrong, scored HIGH. Below 2000 the sweep is flat.

**So 1500 is the largest value the evidence permits, not a number somebody
chose.** The measurement bounds it from above and says nothing from below, and
the document says exactly that.

Calibration also paid for itself in defects: it found `parse_zip` taking the
last EOCD record within a gigabyte cap (producing a 6.8 MB "file" of 582 bytes
of content), `parse_pdf` merging two identical PDFs into one 5 MB candidate that
pikepdf then validated as `valid` — a false positive scored HIGH, the single
worst outcome this scoring exists to prevent — and `gather_evidence` awarding
the entropy component to candidates holding **zero bytes**. All three were
shipped code that every existing test passed.

---

## 5 · What stops someone forging your report?

> **Say it out loud:** Five independent checks, and the one that matters against
> forgery is `chain_store` — it re-verifies **every ledger entry from the store
> itself**, not from the copy inside the report, so a forged report cannot make it
> agree. Change one byte and the signature fails while the other four hold. And
> the honest half: an embedded key proves internal consistency, never identity —
> you have to compare the fingerprint against a value published out of band.

**The full written answer, for the follow-up:**

Five independent checks, and the honest answer that a signature is only as good
as the key.

| Check | What it proves | What it does not |
|---|---|---|
| `signature` | the canonical JSON bytes have not changed since signing | nothing about who signed |
| `fingerprint_matches_genesis` | the signing key is the one that opened this ledger | nothing, if you hold the key |
| `chain_integrity` | the excerpt inside the report is internally consistent | nothing about entries not carried |
| `chain_store` | **the whole chain re-verifies from the store, independently of the report** | nothing, if you also control the store |
| `blobs_available` | every referenced blob is present | nothing about the blobs' content |

`chain_store` is the one that matters against forgery: it re-verifies all
entries from the ledger store rather than from the copy inside the report, so a
report claiming a clean chain cannot make the store agree.

**What we do not claim.** An attacker with the private key and write access to
the ledger root can produce a report that passes all five. There is no hardware
root of trust here, no HSM, no external timestamp authority and no remote
anchor. `core/ledger/anchor.py` exists for publishing chain roots to an external
witness; that witness is the operator's to choose and we do not ship one.

The chain makes tampering **detectable after the fact by anyone holding an
earlier root**, and it makes selective deletion detectable at all — which is
what an audit log is for. It does not make forgery impossible for someone who
owns the machine.

---

## 6 · Why does your chain check say `VERIFIED_PARTIAL` and not just valid?

> **Say it out loud:** Because the excerpt genuinely is partial, and calling it
> complete would be the exact lie this project exists not to tell. On the
> validation run the report carried **37 entries out of 43** — its own job plus
> genesis — and declared the six-entry gap *under its own signature*, in a field
> called `excerpt_gaps`. An earlier build called that a broken chain; reporting
> a gap as a gap is the difference between a report an examiner can defend and
> one they cannot.

**The full written answer, for the follow-up:**

Because the excerpt inside the report genuinely is partial, and calling it
complete would be a lie of exactly the kind this project exists not to tell.

A report carries the ledger entries belonging to *its* job, plus genesis. On the
validation run that was 37 entries out of 43, with a 6-entry gap at seq 1–6
belonging to another job (a rehearsal job of that earlier build). The report declares that gap **under its own
signature**, in a field called `excerpt_gaps`:

```json
"excerpt_gaps": [{"from_seq": 1, "to_seq": 6, "count": 6}]
```

Three outcomes, not two:

- `VERIFIED_COMPLETE` — contiguous, every entry hashes, every link holds.
- `VERIFIED_PARTIAL` — every entry present hashes, every **adjacent** pair
  links, and the gaps are named.
- `BROKEN` — a link that should hold does not.

This is defect 6 of the nine the hardware run found. The earlier implementation
walked the excerpt as if contiguous and called the first entry after a gap a
broken link, so it reported `FAIL` in all three tamper stages for a store where
all 42 entries verified. It was invisible synthetically because every loop-device
run had one job on a fresh ledger.

**Reporting a gap as a gap is the difference between a report an examiner can
defend and one they cannot. A report that calls it a break, or hides it, cannot
be defended.**

---

## 7 · How is this different from DBAN plus PhotoRec?

> **Say it out loud:** DBAN would have reported this stick as wiped when it was
> not. This controller acknowledges a zero fill **3.25× faster than it can program
> the medium**, so the cells keep their contents and every read comes back zero
> from the translation layer — DBAN's own verification pass would have passed. We
> measure the controller before writing, substitute `0xA5`, and record it as a
> HIGH-severity finding with the timing attached.

**The full written answer, for the follow-up:**

Four differences, and the first is the only one that would matter to you.

**1 · DBAN would have reported this stick as wiped when it was not.** DBAN
writes zeros and does not time them. On this controller a zero fill is
acknowledged 3.25× faster than the medium can be programmed, so the cells keep
their prior contents and every read comes back zero from the FTL. DBAN's own
verification pass would have passed. We measure the controller before writing,
detect the elision, substitute `0xA5`, and record `CONTROLLER_WRITE_ELISION` at
HIGH severity with the timing attached. **We know of no wiping tool that does
this.**

**2 · Neither tool tells you what it could not reach.** Our report names HPA and
DCO as not probed, and says why: this is behind a USB bridge and a bridge's
answer to a SET_MAX query describes the bridge, not the medium. It names the
absence of a firmware sanitize path. It states that overwrite on flash cannot
reach remapped or over-provisioned blocks. Residual risk `high`, four factors,
`purge_achieved: false`.

**3 · PhotoRec gives you files; it does not give you a defensible confidence.**
It found 198 objects on this stick before the wipe. Fourteen of them were ours.
After a zero-fill wipe it found **94,720** — more than before — because its
`dovecot` signature accepts any all-zero 80 KiB block. Our candidates carry a
calibrated confidence in basis points with six components, each showing what it
establishes, calibrated against ground truth with a published weight sweep.

**4 · Neither produces an audit trail.** Every phase here appends a
hash-chained ledger entry, the report is detached-signed, and verification is a
separate command anyone can run against a report they were handed.

What DBAN and PhotoRec are better at: being twenty years old and widely
trusted. We are not asking you to replace them on that basis. We are asking you
to look at what the elision measurement means for every zero-fill wipe your
organisation has ever performed on flash.

---

## 8 · What happens on an encrypted drive?

> **Say it out loud:** Three cases, and we probe which one applies rather than
> assuming. On an OPAL self-encrypting drive, destroying the media encryption key
> is the correct Purge and the one case where Purge takes seconds on a
> multi-terabyte drive — on this stick `is_sed_opal` is **false**, so that route
> does not exist. With software encryption the ciphertext is what is on the
> medium, so an overwrite is exactly as effective as on plaintext, no more.

**The full written answer, for the follow-up:**

Three distinct cases, and we detect which one applies rather than assuming.

**Self-encrypting drive with OPAL.** `core/device/capabilities.py` probes
`is_sed_opal`. Where the drive supports it, cryptographic erase — destroying
the media encryption key — is the correct and fastest Purge, and it is the one
case where Purge is reachable in seconds on a multi-terabyte drive. The drive's
sanitize attestation is read and recorded. On the validation stick,
`is_sed_opal: false`.

**Software full-disk encryption (LUKS, BitLocker).** The ciphertext is what
lives on the medium, so an overwrite of the LBA space is exactly as effective as
on plaintext — no more, no less. Destroying the LUKS header is *not* a
sanitization method we will report as one: header backups exist, and the key
slots may have been copied. We wipe the medium.

**Encrypted volumes we cannot see.** A container file inside a filesystem is
just bytes to us. M2's file eraser overwrites it in place with the usual
filesystem caveats — copy-on-write, journals, and SSD remapping mean an in-place
overwrite of a file is a weaker guarantee than an overwrite of a device, and
`docs/limitations.md` says so per filesystem.

**The honest recommendation, which we give in the report:** full-disk encryption
from first power-on, with a cryptographic erase at end of life, is a stronger
and far cheaper guarantee than any overwrite we can perform. Our tool is for the
drives that were not encrypted, which in practice is most of them.

---

## 9 · Have you tested this on real hardware?

> **Say it out loud:** Three runs against one USB stick, and it is the most
> useful thing we did. Run one reported a **completed wipe, exit status zero,
> having written 512 bytes of a 7.76 gigabyte device** — `hdparm` through a USB
> bridge prints an error and exits zero, and we trusted the exit code. Nine
> defects between run one and run three, none of them caught by a synthetic suite
> that was green throughout, and every one now has a regression test.

**The full written answer, for the follow-up:**

**Yes — and it is the most useful thing we did.** Three runs against a Toshiba
TransMemory USB stick, serial `B103B9C19DE1CCC1BD535ACB`, 7,759,462,400 bytes.
Full write-up in `docs/validation/hardware.md`, one JSON file per step.

Run 1 reported a **completed** wipe, exit status **zero**, having written **512
bytes** of a 7.76 GB device.

`hdparm -N` through a USB bridge prints `max sectors = 0/1, HPA setting seems
invalid` **and exits 0**. The probe trusted the exit code and the regex match,
reported a native max of one sector, the unlock branch rebuilt the geometry from
it, and the erase covered 512 bytes. Then the console printed `COMPLETE`,
because no step checked an exit status or an output file. PhotoRec recovered
14 of 14 planted files afterwards.

Nine defects separate run 1 from run 3. **None was caught by the synthetic
suite, which was green throughout at 757 tests — 1211 today.** Loop devices have
no controller, no bridge and no FTL, so three of the nine are physically
unreachable on one. Three needed a step to fail, and on a loop device none does.
Two needed two jobs on one ledger and a key created after the chain started.

Run 3, 2026-09-05, is clean: 100% of the device written with a programmed
`0xA5` fill, verification passed against that pattern over all 7,759,462,400
bytes with 0 failed offsets, 14 of 14 planted files recovered before and 0
after, every caveat present in the report, exit 0 with `{"failed_phases": [],
"failures": 0}`.

We also power-cycled it: unplug, 30 seconds, replug, full re-verify.
`passed: true`, 0 failed offsets. **The Clear outcome is durable on this
device** — which needed testing, because a controller satisfying reads from a
mapping rather than from cells could lose that mapping across a power cycle, and
that would mean the Clear itself had failed.

**Phase B — the recovery side on real media — has now been run too, three times
on 2026-09-05.** It was blocked for a long time because the validation host had
no card reader; it runs on a USB volume instead, which is the same filesystem
code path (see question 21). **It ran on the pre-Batch-2 carve pipeline** — the
signature carver alone, before structure carving and reassembly were wired in —
so the figures below describe that pipeline, not the one that ships.

FAT32 with half the files deleted: **456 of 456 recovered byte-exact.** exFAT
with half the files deleted: **460 of 460.** FAT32 quick-formatted: 10 of 912,
which is 10 of the 10 that were recoverable at all once the directory entries
were gone — see question 3, because that row is easy to misread. Six
acquisitions, three raw and three E01, every one verifying against its own
`AcquisitionRecord` with **zero bad sectors**. `{"failed_phases": [],
"failures": 0}` on all three passes.

**Phase B also found things.** Not nine, but six, and **none of them in the
carver** — all six are in the harness that scores it: the comparison step looked
its calibration row up by filesystem name and so scored a quick-format run
against a delete baseline; the synthetic `precision` column is measured with the
signature carver switched off while the real one is measured with it on; a
correctly recovered *live* file was counted as a false positive; the divergence
test had no minimum sample size and flagged an `n=2` synthetic row; the
quick-format damage model cannot measure quick-format recovery against a
filler-dominated population; and the harness deletes the image after a
successful carve, which is exactly the wrong moment when the result is
surprising.

**Four are fixed, with a regression test each** in
`tests/scripts/test_compare_baseline.py`. The baseline is now keyed on
`(filesystem, damage)`; a baseline under 30 files reports
`baseline_underpowered` instead of a divergence; candidates are split by source
so an undelete-only baseline is compared against the undelete-only slice; and a
candidate is correct when it matches any planted file, which moves delete-pass
precision from 97.02%/97.05% to **98.09%/98.10%**. Recall is untouched — a live
file was never in its denominator.

The two left open are open deliberately: fixing the quick-format population
changes what every Phase B recall figure is measured over, which is a new
experiment rather than a repair. All six are written up in
`docs/validation/hardware.md`.

**What Phase B did not find is a divergence in the carver it ran.** HIGH was 30
for 30 across the three passes, matching the synthetic calibration's 100.0% HIGH
precision. That is agreement between the pre-Batch-2 signature pipeline on real
media and the structure pipeline on the corpus; it is not a real-media
measurement of the weights as the shipped pipeline applies them. The next
hardware run is.

Every one of the nine defects now has a regression test that fails without its
fix.

**Everything else, as of 2026-09-28.** The only other physical record is
Windows, 2026-09-27: discovery on a USB stick and file erase on the host disk
(`docs/validation/windows-hardware-2026-09-27-fixes/`). Each run validates its
own platform and device class only. Firmware Purge, HPA changes, restore,
Windows and macOS whole-drive clear and raw acquisition are implemented and
have never run on a physical device; no macOS device has been tested at all.

---

## 10 · What is your biggest weakness?

> **Say it out loud:** We have never recovered a fragmented file from real media.
> Recovery was measured on real hardware — 456 of 456 and 460 of 460, on the
> pipeline before structure carving was wired in — but
> **every file on both volumes was contiguous**, so the reconstruction that can go
> wrong never had to make a decision. On a used card fragmentation is the common
> case, and we do not yet know what it costs us. That is the honest answer, and
> the fix is a harness change we have scoped.

**The full written answer, for the follow-up:**

**We have never recovered a fragmented file from real media.** Recovery has now
been measured on real removable media — three Phase B passes, 456 of 456 and
460 of 460 byte-exact, on the pre-Batch-2 carve pipeline — but **every file on
both volumes was contiguous**, and that is the caveat this answer is about. The
other is that the shipped pipeline, with structure carving and reassembly, has
not been run on real media at all.

The harness populates a freshly formatted volume in one sequential pass and only
then deletes. Nothing is ever written into a hole, so **0 of the 916 recovered
files needed multi-extent reconstruction.**

That matters because of exactly which code it leaves untested. FAT deletion
zeroes the cluster chain; the start cluster and the recorded size survive and
the layout does not. We walk forward from the start cluster taking clusters the
FAT shows as free. On a contiguous file the first `size` bytes from the start
cluster *are* the file, and the walk cannot go wrong. **But only while its
neighbours still exist.** Once a neighbour has also been deleted, its freed
clusters are indistinguishable from this file's and get pulled in. The result is
the right length and the wrong content, and **nothing on the volume can detect
it.** Every FAT candidate is marked `contiguity_assumed` for this reason.

**Half the files on the Phase B volume were deleted and that failure mode still
never fired**, because contiguity made the neighbours' clusters irrelevant. So
the 100.00% is real, it is honestly measured, and it is a statement about a
population that a used card would not resemble. On a real, long-used card
fragmentation is the common case, not the exception.

The fix is a known, small change to the harness: fill the volume, delete
alternate fillers, then write files sized to span several of the resulting
holes, and measure what walk-forward reconstruction does when it has to guess.
Until that has been run, **we do not know what fragmentation costs us**, and we
would rather say that than quote 100% without the qualifier.

Two things that are *not* the answer to this question, since Phase B settled
them:

- **It is probably not the confidence calibration.** HIGH was 30 for 30 across
  the three passes and no false positive reached it, matching the synthetic
  corpus's 100.0% HIGH precision — but on the pre-Batch-2 pipeline, so this is
  not yet a real-media measurement of what ships. The one soft spot is ordering *within* MEDIUM, where
  906 correct recoveries scored 0.5500 and a false positive scored 0.6000 — the
  bucket floor separates them, the number inside the bucket does not.
- **It is not the media.** Six acquisitions of a stick this validation has
  written end to end twice and reformatted three times more: zero bad sectors,
  every image verifying against its own record.

Second weakness, stated for completeness: no hardware root of trust for the
signing key. See question 5.

---

## 11 · Your verification "passed". What does that actually prove?

That every addressable block returns the byte the erase wrote — nothing more,
and we print the limitation rather than leaving you to infer it from a pass.

On the validation run: `full_read`, `sample_count: 0`, all 7,759,462,400 bytes
compared against `0xA5`, 0 failed offsets, then again after a power cycle.

Three things it does not prove:

1. **That the cells holding the prior contents were erased.** Every read is
   answered by the FTL. No host-side read can establish physical removal on
   flash. This appears in the report.
2. **That hidden sectors were covered.** HPA and DCO were not probed through
   the bridge, so hidden sectors, if any, were neither detected nor erased. The
   report carries that sentence verbatim.
3. **That a device over 64 GiB was fully read.** Above that threshold
   verification reads the first and last 1 GiB in full plus 4096 random 1 MiB
   windows from a seeded RNG. The seed is recorded so a third party can redraw
   the same sample, and the report carries the detection-probability formula
   rather than a bare percentage:

   ```
   P = 1 - (1 - (r + u - 1) / n)^k
   ```

   **That is the chance of detecting a residual region of a given size. It is
   not proof that none exists.**

---

## 12 · Why is the ATA security-erase password fixed and published in your source?

`ATA_RECOVERY_PASSWORD = "SanctumForensics"`, and it is a deliberate trade.

The sequence is SET PASSWORD → ERASE PREPARE → ERASE UNIT. Between the first
and last step the drive is password-locked. If the process dies in that window —
crash, `SIGKILL`, power cut — **the drive stays locked and is unusable until the
password is cleared.** A random password would make that drive a paperweight.

The password protects nothing. It is a transient precondition of the erase
command, not a secret, and the drive is about to be erased. Making it
recoverable matters far more than making it unguessable.

Three mitigations, all in code: the password is written to the ledger *before*
SET PASSWORD is issued so the recovery value survives the crash that makes it
necessary; `SIGINT`/`SIGTERM` handlers and an `atexit` hook both attempt
SECURITY DISABLE PASSWORD; and the command refuses to start on a frozen drive.
Manual recovery is one documented `hdparm` line.

This is the Linux path. On Windows, ATA SECURITY ERASE UNIT is **NOT
IMPLEMENTED** for exactly this reason: no recovery path for a drive left
locked has been built and tested there, so ATA SANITIZE is offered instead
where the drive supports it. macOS exposes no ATA pass-through at all
(PLATFORM-LIMITED).

---

## 13 · Your write block "works". Prove it.

We can, for one interface, and we are careful about what that proves.

`scripts/probe-write-block.py` against the validation stick returned
`WRITE_BLOCK_WORKS`: `BLKROSET` honoured, region byte-identical before and
after, and the write refused.

**The refusal arrived at `write()` with `EPERM`. `open(O_WRONLY)` succeeded.**
Anything that verified by opening for write and stopping there would have
reported a working block on a device where the flag was cosmetic. Test the
write, not the open.

Three limits we state:

- **That refusal is a kernel property, not a bridge one.** `BLKROSET` sets
  `bd_read_only` on the kernel's block device and the kernel refuses the write;
  the bridge is never consulted. What the probe establishes about *this bridge*
  is only that nothing in this stack let the write through.
- **SG_IO and ATA pass-through bypass the flag entirely.** `hdparm
  --write-sector` and `sg_dd` write straight through a set flag.
- **A partition node whose own flag was never set is unprotected.** Setting it
  on `/dev/sda` is not obviously the same as setting it on `/dev/sda1`, and an
  automount writing through the partition is exactly the accident a write block
  exists to stop. **Untested.**

**And the acquisition path deliberately does not run this test.** A write test
fails safe only when the write block works — precisely when it does *not* work,
the case the test exists to detect, the test writes to the evidence it was
protecting. On flash the restore programs a new page and may remap, and the
honest answer to "did your tool write to the exhibit?" becomes yes, by design,
every time. So `apply_write_block` reports `verified_by: flag_read_back` and
records the limitation `WRITE_BLOCK_NOT_VERIFIED`. Verification by attempted
write is a qualification run against scratch media, behind
`--i-understand-this-may-write-to-the-device`.

**For evidence that will be presented: use a hardware write blocker.** We say
that in `docs/limitations.md`.

**On Windows and macOS there is no software write block at all.** Raw
acquisition there opens the disk read-only (`GENERIC_READ` on
`\\.\PhysicalDriveN`, `O_RDONLY` on `/dev/rdiskN`), and the acquisition
report states that no software write block exists. It is implemented and has
not been run on a physical disk.

---

## 14 · What stops this tool wiping the wrong drive?

Two gates in the tool, three more in the validation harness, and one of them has
been exercised against a real device.

In the tool: there is no rehearsal mode, so every gate runs on every erase. The
operator must type the device serial, and it must match. Every erase also needs
a one-use authorization the server issues after a backup image and an explicit
approval, bound to the device's serial, model and size, the plan and the backup;
the privileged helper re-checks all of it immediately before the engine starts,
and refuses any request that still asks for the removed dry-run mode. That part
is SYNTHETICALLY VALIDATED only. (On the 2026-09-05 validation run an earlier
build's dry run was hashed around - the whole device, not a sample - and wrote
nothing; that is historical evidence. The harness now hashes around a *refused*
run instead: a wrong serial must write nothing.)

Refusals, tested against real devices on the validation host:

| Gate | Tested against | Result |
|---|---|---|
| Missing `--i-understand-this-destroys-data` | `/dev/sda` | Refused |
| Not a block device | `/etc/hosts` | Refused |
| Holds the running root filesystem | `/dev/nvme1n1` | Refused |
| Has mounted filesystems | `/dev/sda` | Refused, naming the mount point |
| Not removable | — | **Not reachable on this host** |
| Above the 128 GiB sanity limit | — | **Not reachable on this host** |
| Typed serial must match | — | **Not reachable without passing the earlier gates** |

**The last three are unexercised**, and `docs/validation/hardware.md` records
that as a gap in the document rather than as a claim they work. On that host no
fixed disk survives the root-filesystem gate, so the removable and size gates
could not be reached.

A mounted device is refused, never auto-unmounted: if the operator did not know
it was mounted, they do not yet know what is on it. On Windows and macOS the
operator can take a disk offline or unmount it through a separate Prepare step
(the volumes it affects shown first, typed serial, system and internal disks
refused, ledgered); it is never part of an erase.

The table above is the Linux host. On Windows the open `\\.\PhysicalDriveN`
handle is itself asked its disk number, serial and length, and any difference
from the plan refuses before a byte is read or written; a drive letter is never
accepted as a disk. On macOS no ioctl returns a serial, so the serial is re-read
from `system_profiler` immediately before `/dev/rdiskN` is opened and the handle
is bound by size and block size; the window between that re-read and the open
is stated in the report, not closed. Both are tested against adapter doubles
only.

---

## 15 · Why is `rotational: True` on a flash stick, and did that break anything?

It broke three things, it was defect 8, and it is the best example of why the
hardware run mattered.

The kernel's `queue/rotational` flag is `1` for this stick because the USB
bridge does not clear it. `lsblk` agrees, so it does not even show up as a
disagreement between our enumeration and the system's.

`flash = not device.rotational` was the flash test in **three** places: the
residual-risk assessment, the DoD "extra passes buy nothing on flash" warning,
and the per-file TRIM detection. All three silently skipped their flash caveats
on the one class of device most likely to need them. **A USB flash stick got a
report with no flash caveat in it.**

`core/device/media.py:is_flash` now makes a positive determination from the
transport, the flag, the model string, or the write calibration, and **returns
the signal that decided it** so the report can say how it knew. Transport wins
over the flag: there are no rotating USB sticks or SD cards, and the flag being
wrong is the documented failure mode.

No loop device can produce this. It needs a bridge.

---

## 16 · Your E01 image came out larger than the source. Explain.

`pyewf` binds no compression setter and libewf's default is no compression, so
an E01 is the source bytes plus segment headers and CRCs. Measured: 41,943,040
bytes in, **41,961,613 bytes out**.

We could shell out to `ewfacquire`, but that puts an external binary on the
evidence path, and we would rather carry a documented 0.04% overhead than an
undocumented dependency. It is in `docs/limitations.md` next to the number, and
the acquisition record states the format's integrity check passed either way.

The `--compression fast` flag exists on the acquire command and currently does
nothing for E01. That is recorded rather than removed, because removing it would
hide the limitation.

---

## 17 · What is the privilege model? Does the web UI run as root?

No. There is exactly one privilege boundary and the UI is on the far side of it.

| Layer | Privilege | Network |
|---|---|---|
| UI (Vite/React) | none | localhost only |
| API (FastAPI) | none | **binds 127.0.0.1 and nothing else** |
| Core (`core.*`) | none | **never touches the network** |
| Helper daemon | root | none |

The helper is a Unix socket with a **static allowlist** mapping method names to
typed handlers. A method not in the allowlist is rejected. **No shell string
ever crosses that boundary.** The socket is mode 0600 and the daemon checks
`SO_PEERCRED` against the operator UID.

The API binds loopback explicitly in code, not by configuration: an erase
console reachable from the network is a remote wipe primitive, and no
authentication scheme we could ship would make that a good trade. The UI is
served from disk with a `default-src 'self'` CSP, no CDN link, no external font,
no analytics. **It works with the ethernet unplugged**, which is the state a
forensic workstation should be in.

For development there is an in-process helper that runs the **same** allowlist
through the **same** dispatcher, so an operation reachable one way is reachable
the other and the two cannot diverge. It grants no privilege of its own.

The table is Linux, where a human starts the helper with `sudo`. **Windows and
macOS are different, and we say so:** the socket helper is Linux-only (its peer
check uses `SO_PEERCRED`), so there is no separate helper. Raw disk work runs in
the Sanctum process itself, which must be elevated: on Windows the operator
closes Sanctum and starts it again with *Run as administrator*; on macOS the
Sanctum process is started with `sudo`. Until then those capabilities read
REQUIRES PRIVILEGE. Elevating the whole process is a wider privileged surface
than the Linux split, and the security review records it. Sanctum never
requests elevation itself.

---

## 18 · Why does your ETA get it wrong, and by how much?

8.3% optimistic on the validation run: the write took 1886.3 s against an
estimate of 1729 s.

The cause is sample size. Calibration times a 64 MiB sample and measured
4.28 MiB/s; the sustained whole-device rate over 7.4 GiB is 3.92 MiB/s. An
estimate from a 64 MiB sample of a 7.4 GiB write is going to be a few percent
out.

We publish it rather than tuning it away, for two reasons. First, being 8%
optimistic is the wrong direction to be wrong in, and we would rather say so than
quietly pad the number. Second, the alternative is far worse: a zero-rate
estimate on this device would have been **3.6× wrong**, and `ErasePlan.est_basis`
records where the number came from — `measured on this device before the run` —
precisely so an operator does not discover a 3.6× mid-run.

The same fix applies to multi-pass methods: `estimate_seconds` costs each pass
at the rate measured for the byte that pass writes. That is the difference
between 26.1 minutes and 94.3 minutes for DoD 3-pass on this stick.

---

## 19 · You found 94,720 files after a wipe. How is that not a failure?

It is a carver artefact, and it is worth walking through because it is the
clearest example of why raw counts are not evidence.

PhotoRec's `dovecot` signature accepts an all-zero 80 KiB block and emits it as
a fixed-size 81,920-byte file, non-overlapping. That run ended with the medium
holding `0x00`, so the count was `7,759,462,400 / 81,920 = 94,720` **exactly**.
It is a property of the medium's uniformity, not of what was recoverable.

Reproduced on the validation host with the same PhotoRec build:

| Input | Files recovered |
|---|---:|
| 100 MiB of `0x00` | **1280** (= 104,857,600 / 81,920, exactly) |
| 100 MiB of `0xA5` | **0** |
| 81,919 bytes of `0x00` | 0 — a short block does not qualify |
| 122,880 bytes of `0x00` | 1, of 81,920 bytes — no partial tail |

**Zero of the 94,720 matched any planted file.** The honest number is the hash
match against the manifest: **14 before, 0 after**, in both the zero-fill run and
the `0xA5` run. The raw counts — 198 → 94,720 and 198 → 0 — are dominated by this
artefact in opposite directions and neither describes the wipe.

The later run reports 0 because the medium ends holding `0xA5`, which produces
no candidates at all. **That is a change in the fill byte, not an improvement in
the wipe**, and the validation document says so in bold so nobody quotes it as
one.

---

## 20 · What would it take for you to say a drive is unrecoverable?

A firmware sanitize on a native interface, with attestation, on a drive that is
not behind a bridge — and even then we would report what the drive told us about
itself, not a proof.

The ladder, in the vocabulary of NIST SP 800-88r2 Sec. 3.1 (clear, purge,
destroy — unchanged from the withdrawn r1). Which technique reaches purge on a
given device is, under r2, a matter for IEEE 2883, which we have not been able to
check this table against:

| Level | Achieved by | What we report |
|---|---|---|
| **Clear** | overwrite, verified by full or sampled read-back | "every addressable block returns the expected pattern"; residual risk with every unreached region named |
| **Purge** | ATA SANITIZE block erase / crypto scramble, NVMe sanitize, OPAL cryptographic erase | the drive's own attestation, **plus** a read of the medium, because attestation is the drive reporting on itself |
| **Destroy** | not a software function | we say so |

We never report Purge from an overwrite. On the validation stick, achievable
levels were `["CLEAR"]` and the report said `purge_achieved: false`.

Three things that would still be true after a successful Purge, and which we
would still record: a clean attestation is evidence, not proof — it is the drive
reporting on its own behaviour, so verification always reads the medium as well,
and a clean attestation never excuses residual data found by sampling.
Unwritable ranges that returned `EIO` are skipped, not fixed, and they raise
residual risk to high. And if an HPA unlock failed, the hidden region was not
erased and the report says so.

**For material where recovery would be unacceptable, the answer is physical
destruction, and we will tell you that in the report rather than sell you a
guarantee we cannot make.** If a guarantee cannot be made, the report says so.
That is the first line of our design document and it is the only reason any of
the rest of it is worth anything.

---

## 21 · Why is your recovery demo on a USB stick? Investigators mostly see SD cards.

Because for everything this pipeline does to recover a file, **FAT32 and exFAT
on USB are the same filesystems as on a card** — and because we are honest about
the part that is not the same.

What the carver actually reads, and why the media does not change it:

| Structure | On an SD card | On a USB stick |
|---|---|---|
| Directory entry, 32 bytes | identical | identical |
| Deletion marker `0xE5` in byte 0 of the name | identical | identical |
| 8.3 short name + LFN entries | identical | identical |
| FAT cluster chain, zeroed on delete | identical | identical |
| exFAT stream extension, `NoFatChain` flag | identical | identical |
| TRIM/discard issued on file delete | **no** | **no** |

That last row is the one that would matter if it differed. TRIM on delete is a
property of the *filesystem driver and mount options*, not of the bus: Linux
`vfat` and `exfat` do not issue discards on unlink, on either media. Neither
does Windows for removable volumes. So a deleted file's clusters still hold its
data on both, which is the precondition every recovery number here depends on.

The recovery pipeline never talks to the bus. It reads an image file. Two images
of the same FAT32 volume, one taken from a card and one from a stick, are the
same bytes.

**Now the part that is not the same, which we volunteer rather than wait to be
asked.** The *media and its controller* differ, and controller behaviour is
exactly where this project has been burned:

- A card reader is a different bridge with a different controller. Every one of
  the nine defects Phase A found was bridge or controller behaviour — a USB
  bridge answering `hdparm -N` with nonsense and exiting 0, a controller
  eliding zero writes 3.6× faster than it can program, a bridge not clearing
  `queue/rotational`.
- SD cards have their own wear-levelling firmware, and cheap ones behave worse
  than cheap sticks.
- Whether a given reader passes discards through is a property of that reader.

**We have not tested a card, because we do not have one.** What we claim is that
the filesystem recovery logic is media-independent and we have measured it on
real removable media. What we do not claim is that a card reader's controller
behaves like this USB bridge's — and after what the bridge did to run 1, we
would not assume it.

---

## 22 · What happens if power is lost in the middle of an erase?

> **Say it out loud:** The device is left partially sanitized, and the tool says
> so instead of guessing. The ledger is append-only, so a torn last write shows
> up as `INCOMPLETE_TAIL`, not as a broken chain, and everything before it still
> verifies. An overwrite resumes from the last checkpoint the ledger recorded.
> A firmware sanitize is started again from the beginning. No certificate is
> issued for a job that did not finish and verify.

**The full written answer, for the follow-up:**

- **The chain survives a torn write.** A power cut during an append leaves at
  most a partial last line. `core/ledger/chain.py` reports that as
  `INCOMPLETE_TAIL`, distinct from `BROKEN`, and the entries before it verify.
- **Overwrite resumes from a ledgered checkpoint.** `GET/POST /jobs/{id}/resume`
  restarts the overwrite at the last checkpoint the chain holds
  (`tests/api/test_resume.py`). The recorded resume tests use the Linux
  engine; the Windows and macOS clear engine (`core/erase/blockclear.py`)
  checkpoints the same way and is tested only synthetically.
- **Firmware methods restart.** ATA SANITIZE, SECURITY ERASE and NVMe
  sanitize/format are re-issued from the beginning. The tool does not rely on
  a drive resuming its own operation after power returns.
- **No certificate for an unfinished job.** A job that did not reach
  verification gets no sanitization level and no certificate. The ledger entry
  says **PARTIALLY SANITIZED** (`docs/user-manual.md` §10).
- **Not tested with a real power cut.** Cancellation and a vanished client are
  tested. Pulling power from a device mid-write has not been done in a recorded
  run.

---

## 23 · What happens if the device lies about its capacity?

> **Say it out loud:** Some lies we can see and some we cannot, and we say which.
> A Host Protected Area or DCO makes the drive report less than it has. We read
> both the accessible and the native maximum and report any difference. A
> controller that lies consistently to every host read cannot be caught from the
> host, and no software tool can catch it. That is why flash reports always say
> overwrite cannot reach remapped or over-provisioned blocks.

**The full written answer, for the follow-up:**

- **HPA and DCO.** `core/device/hidden_areas.py` reads `hdparm -N` and
  `hdparm --dco-identify`, both read-only (on Windows, the same readings
  through ATA pass-through). It compares accessible with native max sectors,
  and the report's `hidden_areas` section records the difference. An ordinary
  erase never changes the HPA: it erases the accessible range and names the
  hidden bytes as a limitation. Changing the HPA is a separate guarded
  workflow (volatile SET MAX by default, typed serial, read-back); DCO is
  never modified. Neither has run on a drive with a hidden area. On macOS
  HPA/DCO is PLATFORM-LIMITED.
- **A bridge that answers nonsense is caught.** A USB bridge answered
  `max sectors = 0/1, HPA setting seems invalid` and exited 0. That once
  produced a 512-byte "erase" of a 7.76 GB stick. The tool now discards that
  reading and records that no HPA/DCO determination was made, rather than
  trusting the exit code (`core/device/hidden_areas.py`,
  `docs/validation/hardware.md`).
- **Over-provisioning is not host-addressable.** No host read or write reaches
  it. Every flash report carries that sentence (`core/platform/base.py:
  FLASH_LIMITATION`) and a residual-risk level to match.
- **The benchmark harness refuses implausible sizes.** Its preflight refuses a
  device smaller than the corpus or larger than 128 GiB.

---

## 24 · What happens if the filesystem is mounted?

> **Say it out loud:** It refuses, and it will not unmount anything for you. We
> ran that preflight on the attached stick on 23 September and it said: *has
> mounted filesystems: /run/media/…/SANCTUMREC. Unmount them yourself - if you
> did not know it was mounted, you do not yet know what is on it.* No sudo, no
> automatic unmount, and zero I/O to the device.

**The full written answer, for the follow-up:**

- The preflight in `scripts/media_benchmark.py` and the device guard in
  `core/device/guard.py` refuse any device with a mounted filesystem, the root
  filesystem, or a system or boot role.
- The refusal was recorded on the physical stick on 2026-09-23.
  `/sys/block/sda/stat` was identical before and after, so the check did no I/O.
- The workflow state for that device reads `BLOCKED`, and WHY BLOCKED quotes the
  refusal (`core/workflow.py`).

---

## 25 · What happens if backup verification fails?

> **Say it out loud:** The write refuses. It does not trust a report someone
> read; it runs the whole backup verification again itself, straight before
> writing. A backup must cover every byte the write can reach, sit on another
> physical disk, come from this serial and this device path, and be bound to
> the image's exact SHA-256. If any of that fails, nothing is written.

**The full written answer, for the follow-up:**

- `verify_backup` checks coverage of the write extent, backup location on a
  different disk, serial, device string, extent, byte count, backup hash, image
  path and image hash.
- `write_image` re-runs it and refuses unless
  `sufficient_for_restoring_the_modified_region` is true. It then writes the
  exact bytes that were hashed, read once before the device is opened.
- **Exit 0 from `verify-backup` does not mean "verified".** It means the command
  ran. The answer is the field `sufficient_for_restoring_the_modified_region`.
- A backup that has never been restored is not a proven restore, and the tool
  says so: `restoration: "backup captured; restoration not validated"`.
- Restore itself is implemented (`core/restore.py`, `/workflow/restore`): the
  backup is re-verified chunk by chunk before any write, the target is re-read
  and bound, a human authorizes with the typed serial, and the restored range
  is hashed again afterwards. It has been tested on synthetic targets only and
  **has never been run on a physical device.**

---

## 26 · What platforms are actually supported?

> **Say it out loud:** Whole-drive clear, raw acquisition and restore are
> implemented on Linux, Windows and macOS. Physically validated is narrower:
> Linux whole-drive clear, discovery and raw acquisition on one USB stick, and
> on Windows discovery on a USB stick and file erase on the host disk. The
> Windows and macOS disk paths have only been tested against adapter doubles.
> Firmware Purge has been selected and dispatched, but never executed on a
> real drive in a recorded run. The packages are unsigned and not notarized.

**The full written answer, for the follow-up:** the generated
[`capability-matrix.md`](../validation/capability-completion-2026-09-28/capability-matrix.md)
has every capability on every platform, with its implementation, its runtime
state, the device classes it is physically validated on, and its limit. Its
states are SUPPORTED (a physical run on that device class is recorded),
IMPLEMENTED / UNVALIDATED, DEVICE-DEPENDENT, PLATFORM-LIMITED, REQUIRES
PRIVILEGE, BLOCKED FOR SAFETY and NOT IMPLEMENTED, and they never merge. The
genuine limits: Windows ATA SECURITY ERASE UNIT is NOT IMPLEMENTED and NVMe
Format is PLATFORM-LIMITED; macOS has no device sanitize or HPA/DCO path
(PLATFORM-LIMITED) and never raw-writes or images internal Apple storage
(Erase All Content and Settings is recommended instead); free-space wipe is
NOT IMPLEMENTED on Windows and macOS. **CI-validated is not
hardware-validated.** CI runners have virtual disks and no removable device;
the read-only native smoke on the Windows and macOS runners proves the
bindings load, not that a disk was cleared.

---

## 27 · Is there a dry run, and what is real hardware?

> **Say it out loud:** No. Every erase runs on the selected real device once its
> gates pass: a backup, a recorded approval, a one-use server authorization,
> the serial typed twice, and a final re-read of the device by the process that
> writes. What would run is shown before approval by a read-only plan, which
> writes nothing and is not a rehearsal. Our measurements carry a population
> label: synthetic images, the one physical USB stick, or CI virtual disks. We
> never mix them, and a fake device passing a test is never called physical
> validation. The physical recovery benchmark has not been run yet, so no
> physical benchmark result exists.

**The full written answer, for the follow-up:**

- No erase request model has a `dry_run` field, and every request model rejects
  `dry_run`, `simulation` and `simulate` with 422 (`api/routes/models.py`); the
  helper refuses them again at the write seam (`core/device/guard.py`).
- Case records written by earlier builds that ran a rehearsal are shown as
  HISTORICAL · NOTHING WRITTEN and never counted as an erasure
  (`ui/src/lib/legacy.ts`).
- The physical media recorded in `docs/validation/hardware.md` is one Toshiba
  TransMemory USB stick. The Windows record of 2026-09-27 adds a USB stick
  (discovery only) and the host disk (file erase). Recovery calibration and
  benchmarks are synthetic.
- The physical benchmark (`scripts/media_benchmark.py`) is at preflight. It is
  BLOCKED at gate 1, the experiment owner's methodology decision
  (`docs/validation/physical-benchmark-checklist.md`).

---

## 28 · How do you reconstruct fragmented files?

> **Say it out loud:** For two formats, and only when the file's own bytes prove
> the join. A baseline JPEG is checked with an exact Huffman scan count. A PNG
> is checked with every chunk's CRC-32 plus a zlib stream that must inflate to
> exactly the size in its header. On synthetic images, PNG recovered 120 of 120
> layouts up to a 7 MiB gap and accepted 0 of 800 deliberately wrong joins. A
> file in three or more pieces is not reconstructed, and we say so.

**The full written answer, for the follow-up:**

- Two runs only. A second passing join means the medium does not say where the
  file was, so the object is refused.
- A reassembled object is held one point below HIGH, and the report lists its
  runs so anyone can re-read the same bytes.
- JPEG figures: `docs/limitations.md`. PNG figures and the script that
  reproduces them: `docs/validation/png-reassembly.md`.
- The CRC-32 and Adler-32 are not cryptographic. They defend against
  accidental joins, not against someone who forges the gap bytes.

---

## 29 · Your verifier says `VERIFIED_WITH_LIMITATIONS`. Is the report good or not?

> **Say it out loud:** The report is authentic. All five checks ran and passed.
> The verdict is not a plain `VERIFIED` because the report itself declares what
> it could not do: on this stick, that overwrite cannot reach remapped flash, and
> that HPA/DCO could not be probed through the USB bridge. The verifier will not
> round that up to a clean pass.

**The full written answer, for the follow-up:** there are four verdicts, in
fixed precedence. `FAILED_VERIFICATION` means a check failed. `PARTIAL` means a
check could not run. `VERIFIED_WITH_LIMITATIONS` means the report declares
limitations, residual risk above low, a failed self-verification, or excerpt
gaps. `VERIFIED` means none of those apply. The exit code still follows
`Result:`. The implementation is `core/report/verify_report.py:grade_report`.
