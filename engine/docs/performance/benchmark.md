# Recovery benchmark: Sanctum, PhotoRec and Foremost

**Run date:** 2026-09-16 (fix6 re-run; the fix5 baseline it is compared against ran 2026-09-15) · **Sanctum measured at:** `hwval-run4-fix6`, clean tree
· **Harness:** `testkit/benchmark.py`, `testkit/damage.py` · **Table:** [`benchmark.csv`](benchmark.csv)
· **Host:** one Fedora 44 laptop, Linux 6.19.10, 16 logical CPUs, 14 GiB RAM

This is the performance evaluation of the recovery module against the two
open-source carvers a forensic examiner is most likely to reach for. It exists to
answer one question with numbers: **given the same image and the same ground truth,
which tool returns the planted files byte for byte, what else does it return, and how
long does it take.**

Every figure here is from synthetic images built on this host. No real storage medium
was measured. Read [Limits](#limits) before quoting any number.

## Re-run of the Sanctum rows, 2026-09-21

After the changes of 2026-09-21 — carve payloads spilled to disk instead of held
in memory, the footer search bounded at the next same-format header, the WAV
validator fix, the PDF incremental-update check — the two Sanctum rows were rebuilt and re-run over the same 40
images (`testkit.benchmark build --seed 0`, `run --tool sanctum-carve --tool
sanctum-full`, `score`). Raw table:
[`benchmark-2026-09-21-sanctum.csv`](benchmark-2026-09-21-sanctum.csv).

| Row, summed over 40 images | FULL | Byte-identical | Corrupt | Missed | False positives | Outputs | Seconds |
|---|---:|---:|---:|---:|---:|---:|---:|
| sanctum-carve, 2026-09-16 | 591 | 565 | 26 | 0 | 63 | 687 | 184.1 |
| sanctum-carve, 2026-09-21 | 591 | 565 | 26 | 0 | 63 | 687 | 186.7 |
| sanctum-full, 2026-09-16 | 591 | 576 | 15 | 0 | 88 | 969 | 201.1 |
| sanctum-full, 2026-09-21 | 591 | 576 | 15 | 0 | 88 | 969 | 202.9 |

Every recovery count is identical. The changes did not move a single file on
these images; the footer-bound fix matters on images where objects are
megabytes apart (see [`../validation/large-image.md`](../validation/large-image.md)),
which these are not. The 2026-09-21 run was the only job on the host; one run
each, so a few seconds of difference is within run-to-run variation and is not
claimed as a change. **PhotoRec and Foremost were not re-run**
(Foremost is not installed on this host); their rows below are the 2026-09-16
measurements.

## Tools, versions and settings

| Row | Tool and version | How it was run | Settings |
|---|---|---|---|
| Sanctum, carve only | Sanctum at `hwval-run4-fix6` | `api.carve_job.carve_generator(image, undelete=False, out_dir=…)` in a fresh process | Defaults: structure carving, bifragment reassembly, validation, scoring, PII triage on |
| PhotoRec | PhotoRec 7.2 (February 2024), Fedora package `testdisk-7.2-6.fc44.x86_64` | `photorec /log /d <out>/recup /cmd <image> partition_none,wholespace,search` | Default file-type selection. The only option given is scope: the whole image, as one unpartitioned space |
| Foremost | Foremost 1.5.7, Fedora package `foremost-1.5.7-37.fc44`, **not installed on the host**: the RPM was downloaded with `dnf download` and unpacked into a scratch directory, because installing needs root | `foremost -i <image> -o <out>` | No configuration file, which selects Foremost's built-in type set |
| Sanctum, undelete + carve | Sanctum at `hwval-run4-fix6` | `carve_generator(image, undelete=True, out_dir=…)` | Defaults. **Not a peer of the carvers**; see fairness rule 1 |

Scalpel was not measured.

Time is wall-clock seconds for the whole process, measured from outside with
`time.perf_counter`, one run each, tools run one at a time. Sanctum's figure includes
starting Python and importing its modules (about a second); the carvers are native
binaries.

## Fairness rules

1. **Like with like.** PhotoRec and Foremost carve. They never read filesystem
   metadata. Sanctum's comparable row is **carve only**. Sanctum's full pipeline runs
   undelete first, which reads the surviving filesystem records; it is reported in its
   own row, below a separator, and no sentence in this document compares it with a
   carver as if it were one.
2. **Default settings for all three.** Nobody was tuned. PhotoRec's one non-default
   choice is scope, `partition_none,wholespace`: without it PhotoRec's `/cmd` mode scans
   only the first recognised partition (measured: on the two-partition image it analysed
   the NTFS partition and never reached the FAT32 one), while Sanctum and Foremost scan
   the whole image. Its file-type selection is left at its default.
3. **One scorer.** Each tool writes files into a directory. The same function
   (`score_run`) hashes and attributes every file for every tool. No tool's log, report,
   file name or claimed offset is read; renaming every output does not change a score
   (`tests/testkit/test_benchmark_scoring.py`).
4. **Report the losses.** The planted set deliberately includes seven formats whose
   header is not in Sanctum's signature table and which PhotoRec knows.

## Corpora

| Corpus | Images | What it is |
|---|---:|---|
| Flat corpus as shipped | 1 | `generate_corpus` seed 0: 24 objects in 12.5 MiB of pseudo-random filler, the first at byte 1337 and every 512 KiB after. Includes 3 truncated plants, 3 decoys and a 40000×40000 PNG bomb header. |
| Flat corpus, sector-aligned | 1 | The same objects with the first at byte 4096. Added for this benchmark: no filesystem places a file off a sector boundary, and a carver that looks for headers only at block starts (PhotoRec) finds nothing in the shipped layout for that reason alone. |
| Filesystem corpus | 13 | `generate_filesystem_corpus` seed 0, unchanged: NTFS, NTFS with a reused MFT record, FAT32 fragmented with and without live neighbours, exFAT, ext2, ext3, ext4, plain FAT32, two partitions, boot sector zeroed, partition table garbage, quick format. |
| Benchmark volumes | 5 | New. FAT32 255 MiB (512-byte clusters), FAT32 511 MiB (4096-byte clusters), exFAT 255 MiB (4096-byte clusters) — the geometries earlier batches proved on real sticks — plus NTFS 64 MiB (4096) and ext4 64 MiB (1024-byte blocks). Each built by the real `mkfs` and populated through `mtools`, `ntfscp`, `debugfs` or the exFAT builder. |
| Damage models over the benchmark volumes | 20 | Four models × five volumes. See below. |

Each benchmark volume holds 21 real files, 17 of them deleted:

| Format | Header in Sanctum's signature table | Structure parser | Files | Encoder |
|---|---|---|---:|---|
| JPEG | yes | yes | 3 (+1 on FAT32) | Pillow, noise, q95; 128, 384 and 768 px |
| PNG | yes | yes | 2 | Pillow, noise |
| GIF | yes | no (footer bound) | 1 | Pillow |
| PDF | yes | yes | 2 | hand-built, correct xref |
| ZIP | yes | yes | 1 | `zipfile`, deflate |
| DOCX, XLSX | yes (as ZIP) | yes (as ZIP) | 1 each | `zipfile`, OPC parts |
| SQLite | yes | yes | 1 | `sqlite3`, 2000 rows |
| MP4 | yes | yes | 1 | `ftyp` + `mdat` boxes |
| TIFF | yes | yes | 1 | Pillow |
| BMP | yes | yes | 1 | Pillow |
| WebP | yes | yes | 1 | Pillow, lossy |
| WAV | yes | yes | 1 | `wave`, 1 s PCM |
| GZIP | yes | yes | 1 | `gzip` |
| TAR | yes | yes | 1 | `tarfile`, ustar |
| HTML | yes | yes | 1 | text |
| RTF | yes | yes | 1 | text |

The header and parser columns describe the tree at commit `20a6439` and later,
which is what every "after" figure in this document was measured on. The
**before** figures predate it: at that point BMP, WebP, WAV, GZIP, TAR, HTML and
RTF had no signature and TIFF had no parser, which is part of why they were worse.
The authoritative, generated list of what the current tree supports is
[`../supported-formats.md`](../supported-formats.md); it is regenerated from the
signature table and parser registry and a test fails if it drifts.

On both FAT32 volumes a fifth JPEG, `frag.jpg`, is written **in exactly two runs** the
way a real volume splits a file: two 64 KiB pads are written, the first is deleted, and
the JPEG is written into the hole with the free-cluster hint cleared, so its head lands
in the hole and its tail after the live second pad. The manifest verifies it is two
runs. On exFAT, `shot.png` is stored with a FAT chain and a one-cluster gap between
each run (28 runs).

## Damage models

`testkit/damage.py`. Each model rewrites a copy of a benchmark volume. **Every manifest
records, for every planted object, whether it is FULL, PARTIAL or GONE, and the status is
computed, not declared**: the planted bytes are searched for on the medium, their runs
are recorded as extents, and the status is the overlap between those extents and the
byte ranges the model destroyed.

* **FULL** — every stored byte is where it was written. Only these can come back
  byte-identical, and only these are in a recall denominator.
* **PARTIAL** — some bytes survive. A tool can return something, never the original.
* **GONE** — nothing survives. Anything returned for it did not come from this medium.

| Model | What is done | Parameters recorded |
|---|---|---|
| Truncation | The image ends halfway through the median file in medium order: files before it survive, it is cut, files after it are gone. An acquisition that died. | kept bytes, percentage lost |
| Zeroed regions | Eight zero-filled bands: one covering the median-sized contiguous file whole, one over the middle third of the largest file, six of 256 KiB placed by seed. How unreadable sectors look after imaging with a zero-filling tool. | every band, seed |
| Metadata destroyed | Every structure the volume needs to find its files is zeroed, located from the volume's own boot record and descriptors: FAT32 reserved region, both FAT copies and the root directory; exFAT main and backup boot regions, FAT, allocation bitmap, up-case table and root directory; NTFS boot sector, backup boot sector, `$MFT` and `$MFTMirr`; ext4 every superblock and descriptor copy, block and inode bitmaps and inode tables. File data is not touched. | every range and its label |
| Interleaved overwrite | Two later files written on the cluster grid: a 160 px JPEG over the head of `contacts.sqlite` (as first-fit reuse of freed clusters does), and a 128 px PNG starting halfway through `photo-large.jpg`. No filesystem record is updated. | victim, later file, offset, length |

The metadata model is tested against each filesystem's own reader: The Sleuth Kit opens
every volume before damage and none after, the planted bytes are unchanged, and the
ranges cover structures found independently — both FAT media-byte signatures, every
sector-aligned `FILE` record, and every inode table and superblock `dumpe2fs` lists
(`tests/testkit/test_damage_models.py`).

Status of the formatted planted files in every image, as the manifests record it:

| Image | Model | Filesystem, cluster | FULL | PARTIAL | GONE | Fragmented | Unformatted plants |
|---|---|---|---:|---:|---:|---:|---:|
| `flat-aligned.img` | none | none, 512 | 18 | 3 | 0 | 0 | 0 |
| `flat-offset1337.img` | none | none, 512 | 18 | 3 | 0 | 0 | 0 |
| `fs-exfat.img` | delete | exfat, 4096 | 3 | 0 | 0 | 1 | 0 |
| `fs-ext2.img` | delete | ext2, 1024 | 3 | 0 | 0 | 1 | 0 |
| `fs-ext3.img` | delete | ext3, 1024 | 3 | 0 | 0 | 1 | 0 |
| `fs-ext4.img` | delete | ext4, 1024 | 3 | 0 | 0 | 0 | 0 |
| `fs-fat32-neighbours.img` | delete | fat32, 512 | 3 | 0 | 0 | 0 | 158 |
| `fs-fat32-plain.img` | delete | fat32, 512 | 3 | 0 | 0 | 0 | 0 |
| `fs-fat32.img` | delete | fat32, 512 | 3 | 0 | 0 | 0 | 158 |
| `fs-ntfs-reused.img` | delete | ntfs, 4096 | 17 | 3 | 0 | 0 | 0 |
| `fs-ntfs.img` | delete | ntfs, 4096 | 17 | 3 | 0 | 0 | 0 |
| `fs-two-partitions.img` | delete | fat32+ntfs, 512 | 20 | 3 | 0 | 0 | 0 |
| `fs-damaged-boot.img` | boot_sector_zeroed | ntfs, 512 | 17 | 3 | 0 | 0 | 0 |
| `fs-damaged-parttable.img` | partition_table_garbage | fat32+ntfs, 512 | 20 | 3 | 0 | 0 | 0 |
| `fs-quick-formatted.img` | quick_format | fat32, 512 | 3 | 0 | 0 | 0 | 0 |
| `media-exfat-255m.img` | delete | exfat, 4096 | 21 | 0 | 0 | 1 | 0 |
| `media-ext4-64m.img` | delete | ext4, 1024 | 21 | 0 | 0 | 0 | 0 |
| `media-fat32-255m.img` | delete | fat32, 512 | 22 | 0 | 0 | 1 | 2 |
| `media-fat32-511m.img` | delete | fat32, 4096 | 22 | 0 | 0 | 1 | 2 |
| `media-ntfs-64m.img` | delete | ntfs, 4096 | 17 | 4 | 0 | 0 | 0 |
| `dmg-interleave-exfat-255m.img` | interleaved_overwrite | exfat, 4096 | 21 | 2 | 0 | 1 | 0 |
| `dmg-interleave-ext4-64m.img` | interleaved_overwrite | ext4, 1024 | 21 | 2 | 0 | 0 | 0 |
| `dmg-interleave-fat32-255m.img` | interleaved_overwrite | fat32, 512 | 22 | 2 | 0 | 1 | 2 |
| `dmg-interleave-fat32-511m.img` | interleaved_overwrite | fat32, 4096 | 22 | 2 | 0 | 1 | 2 |
| `dmg-interleave-ntfs-64m.img` | interleaved_overwrite | ntfs, 4096 | 17 | 6 | 0 | 0 | 0 |
| `dmg-metadata-exfat-255m.img` | metadata_destroyed | exfat, 4096 | 21 | 0 | 0 | 1 | 0 |
| `dmg-metadata-ext4-64m.img` | metadata_destroyed | ext4, 1024 | 21 | 0 | 0 | 0 | 0 |
| `dmg-metadata-fat32-255m.img` | metadata_destroyed | fat32, 512 | 22 | 0 | 0 | 1 | 2 |
| `dmg-metadata-fat32-511m.img` | metadata_destroyed | fat32, 4096 | 22 | 0 | 0 | 1 | 2 |
| `dmg-metadata-ntfs-64m.img` | metadata_destroyed | ntfs, 4096 | 16 | 0 | 5 | 0 | 0 |
| `dmg-truncation-exfat-255m.img` | truncation | exfat, 4096 | 9 | 2 | 10 | 1 | 0 |
| `dmg-truncation-ext4-64m.img` | truncation | ext4, 1024 | 10 | 0 | 11 | 0 | 0 |
| `dmg-truncation-fat32-255m.img` | truncation | fat32, 512 | 11 | 0 | 11 | 1 | 2 |
| `dmg-truncation-fat32-511m.img` | truncation | fat32, 4096 | 11 | 0 | 11 | 1 | 2 |
| `dmg-truncation-ntfs-64m.img` | truncation | ntfs, 4096 | 8 | 5 | 8 | 0 | 0 |
| `dmg-zeroed-exfat-255m.img` | zeroed_regions | exfat, 4096 | 19 | 1 | 1 | 1 | 0 |
| `dmg-zeroed-ext4-64m.img` | zeroed_regions | ext4, 1024 | 19 | 1 | 1 | 0 | 0 |
| `dmg-zeroed-fat32-255m.img` | zeroed_regions | fat32, 512 | 20 | 1 | 1 | 1 | 2 |
| `dmg-zeroed-fat32-511m.img` | zeroed_regions | fat32, 4096 | 20 | 1 | 1 | 1 | 2 |
| `dmg-zeroed-ntfs-64m.img` | zeroed_regions | ntfs, 4096 | 11 | 6 | 4 | 0 | 0 |

Three things in those manifests that a reader should know:

* **NTFS resident files are PARTIAL on an undamaged volume.** A file of a few hundred
  bytes lives inside its MFT record, and NTFS's update-sequence fixups replace the last
  two bytes of each sector of that record on disk. The raw bytes on the medium are
  therefore not the file; only a reader that applies the fixups (undelete) can return
  it exactly. Four benchmark files and three filesystem-corpus ZIPs are in this state.
* **ext4 files with zero blocks are sparse.** `debugfs write` stores an all-zero block as
  a hole. `contacts.sqlite` (4096 bytes of holes) and `backup.tar` (3072) are recorded as
  FULL with `hole_bytes`: every stored byte is present, and the holes were never on the
  medium to damage.
* **The ext4 metadata model leaves the journal blocks** (the inode that locates the
  journal is in a zeroed inode table).

## Scoring

`testkit/benchmark.py:score_run`, the same for every row:

* **Byte-identical** — an output file's SHA-256 equals a FULL planted object's.
  Objects with identical content (the flat corpus's three copies of one PNG) count once.
* **Corrupt** — no identical output, but an output whose leading bytes agree with this
  object for at least 64 bytes and for longer than with any other planted object.
* **Missed** — neither.
* **PARTIAL returned** — any output identical to, or attributed to, a PARTIAL object.
  *Identical* in brackets means byte-identical, which on the raw medium is only possible
  through filesystem metadata.
* **GONE returned** — must be zero; it would mean the ground truth is wrong.
* **False positives** — outputs attributed to no planted object, split into *fragment*
  (the output's first 256 bytes lie inside a planted file: a ZIP member, an embedded
  stream), *decoy* (a planted fake header), *ambiguous* (agrees equally with two
  different planted objects) and *unrelated*.
* Unformatted planted content (FAT32 fillers, random pads, `split.bin`) is kept out of
  every recall denominator, because no signature carver can find it.

## Results

### fix6 against the fix5 baseline

Every table in this section is the **fix6** run, at tag `hwval-run4-fix6`. The fix5
numbers are kept here as the before column, because the improvement is itself the
evidence that these were defects rather than tuning: deleting them would remove the
only proof of that. `hwval-run4-fix5` is tag `c4eb08c`; what changed between the two
runs is Sanctum and nothing else, and PhotoRec and Foremost re-ran to identical scores
in every column.

Byte-identical recoveries, carve-only rows:

| Corpus / model | Images | FULL | Sanctum carve fix5 | **Sanctum carve fix6** | PhotoRec | Foremost |
|---|---:|---:|---:|---:|---:|---:|
| Flat, shipped (byte 1337 + k x 512 KiB) | 1 | 15 | 15 | **15** | 0 | 7 |
| Flat, sector-aligned (byte 4096) | 1 | 15 | 15 | **15** | 15 | 7 |
| Filesystem corpus | 13 | 115 | 112 | **112** | 108 | 99 |
| Benchmark volumes, undamaged (delete) | 5 | 103 | 56 | **96** | 84 | 47 |
| Truncation | 5 | 49 | 49 | **49** | 46 | 36 |
| Zeroed regions | 5 | 89 | 46 | **86** | 73 | 39 |
| Metadata destroyed | 5 | 102 | 55 | **95** | 84 | 46 |
| Interleaved overwrite | 5 | 103 | 57 | **97** | 85 | 52 |
| **25 benchmark volumes** | 25 | 446 | 263 (59.0%) | **423 (94.8%)** | 372 (83.4%) | 220 (49.3%) |
| **20 damaged volumes** | 20 | 343 | 207 (60.3%) | **327 (95.3%)** | 288 (84.0%) | 173 (50.4%) |

The full pipeline, which is not a carver's peer and is reported against its own carve
row only: 368 (82.5%) to **432 (96.9%)** over the 25 volumes, 276 to **332** over the
20 damaged ones.

Other columns, over the 25 benchmark volumes:

| Measure | fix5 | **fix6** |
|---|---:|---:|
| Byte-identical, carve only | 263 | **423** |
| Corrupt | 47 | **23** |
| Missed | 136 | **0** |
| Outputs matching no planted file | 252 | **45** |
| Outputs | 573 | **503** |
| Wall clock | 2,071.8 s | **170.2 s** |
| Bytes written, all 40 images | 48.0 GiB | **0.034 GiB** |

What moved, and why, is recorded in the message of commit `20a6439` (`git show 20a6439`): three causes of candidates
that ran to the end of the image (ZIP member headers, MP4 cluster slack read as a
size-0 box, TIFF having no parser), and seven formats that had no signature at all.

#### Flat corpus as shipped (objects at byte 1337 + k x 512 KiB)

Images: `flat-offset1337.img`

| Row | FULL files | Byte-identical | Corrupt | Missed | Identical / FULL | PARTIAL returned | GONE returned | False positives (frag/decoy/amb/unrel) | Outputs | Time (s) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Sanctum, carve only | 15 | **15** | 0 | 0 | 100.0% | 2/3 | 0/0 | 3 (0/0/2/1) | 21 | 0.9 |
| PhotoRec | 15 | **0** | 0 | 15 | 0.0% | 0/3 | 0/0 | 0 (0/0/0/0) | 0 | 0.0 |
| Foremost | 15 | **7** | 6 | 2 | 46.7% | 1/3 | 0/0 | 0 (0/0/0/0) | 17 | 0.2 |
| *not a carver's peer:* | | | | | | | | | | |
| Sanctum, undelete + carve | 15 | **15** | 0 | 0 | 100.0% | 2/3 | 0/0 | 3 (0/0/2/1) | 21 | 0.9 |

#### Flat corpus, sector-aligned (objects at byte 4096 + k x 512 KiB)

Images: `flat-aligned.img`

| Row | FULL files | Byte-identical | Corrupt | Missed | Identical / FULL | PARTIAL returned | GONE returned | False positives (frag/decoy/amb/unrel) | Outputs | Time (s) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Sanctum, carve only | 15 | **15** | 0 | 0 | 100.0% | 2/3 | 0/0 | 3 (0/0/2/1) | 21 | 0.9 |
| PhotoRec | 15 | **15** | 0 | 0 | 100.0% | 0/3 | 0/0 | 0 (0/0/0/0) | 19 | 0.0 |
| Foremost | 15 | **7** | 6 | 2 | 46.7% | 1/3 | 0/0 | 0 (0/0/0/0) | 17 | 0.2 |
| *not a carver's peer:* | | | | | | | | | | |
| Sanctum, undelete + carve | 15 | **15** | 0 | 0 | 100.0% | 2/3 | 0/0 | 3 (0/0/2/1) | 21 | 1.0 |

#### Filesystem corpus (13 images, generate_filesystem_corpus)

Images: `fs-damaged-boot.img`, `fs-damaged-parttable.img`, `fs-exfat.img`, `fs-ext2.img`, `fs-ext3.img`, `fs-ext4.img`, `fs-fat32-neighbours.img`, `fs-fat32-plain.img`, `fs-fat32.img`, `fs-ntfs-reused.img`, `fs-ntfs.img`, `fs-quick-formatted.img`, `fs-two-partitions.img`

| Row | FULL files | Byte-identical | Corrupt | Missed | Identical / FULL | PARTIAL returned | GONE returned | False positives (frag/decoy/amb/unrel) | Outputs | Time (s) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Sanctum, carve only | 115 | **112** | 3 | 0 | 97.4% | 15/15 | 0/0 | 12 (0/0/0/12) | 142 | 12.1 |
| PhotoRec | 115 | **108** | 0 | 7 | 93.9% | 0/15 | 0/0 | 0 (0/0/0/0) | 108 | 0.9 |
| Foremost | 115 | **99** | 5 | 11 | 86.1% | 15/15 | 0/0 | 0 (0/0/0/0) | 119 | 5.1 |
| *not a carver's peer:* | | | | | | | | | | |
| Sanctum, undelete + carve | 115 | **114** | 1 | 0 | 99.1% | 15/15 (3 identical) | 0/0 | 23 (0/0/0/23) | 384 | 19.3 |

#### Benchmark volumes, files written then some deleted (5 volumes)

Images: `media-exfat-255m.img`, `media-ext4-64m.img`, `media-fat32-255m.img`, `media-fat32-511m.img`, `media-ntfs-64m.img`

| Row | FULL files | Byte-identical | Corrupt | Missed | Identical / FULL | PARTIAL returned | GONE returned | False positives (frag/decoy/amb/unrel) | Outputs | Time (s) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Sanctum, carve only | 103 | **96** | 7 | 0 | 93.2% | 0/4 | 0/0 | 10 (1/0/4/5) | 113 | 19.8 |
| PhotoRec | 103 | **84** | 15 | 4 | 81.6% | 0/4 | 0/0 | 0 (0/0/0/0) | 99 | 0.5 |
| Foremost | 103 | **47** | 20 | 36 | 45.6% | 0/4 | 0/0 | 9 (5/0/4/0) | 76 | 14.1 |
| *not a carver's peer:* | | | | | | | | | | |
| Sanctum, undelete + carve | 103 | **100** | 3 | 0 | 97.1% | 2/4 (2 identical) | 0/0 | 11 (1/0/4/6) | 121 | 21.1 |

#### Damage model: truncation (5 volumes)

Images: `dmg-truncation-exfat-255m.img`, `dmg-truncation-ext4-64m.img`, `dmg-truncation-fat32-255m.img`, `dmg-truncation-fat32-511m.img`, `dmg-truncation-ntfs-64m.img`

| Row | FULL files | Byte-identical | Corrupt | Missed | Identical / FULL | PARTIAL returned | GONE returned | False positives (frag/decoy/amb/unrel) | Outputs | Time (s) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Sanctum, carve only | 49 | **49** | 0 | 0 | 100.0% | 2/7 | 0/51 | 10 (0/0/4/6) | 61 | 7.2 |
| PhotoRec | 49 | **46** | 0 | 3 | 93.9% | 1/7 | 0/51 | 0 (0/0/0/0) | 47 | 0.2 |
| Foremost | 49 | **36** | 12 | 1 | 73.5% | 0/7 | 0/51 | 4 (0/0/4/0) | 52 | 0.7 |
| *not a carver's peer:* | | | | | | | | | | |
| Sanctum, undelete + carve | 49 | **49** | 0 | 0 | 100.0% | 5/7 (2 identical) | 0/51 | 14 (0/0/4/10) | 69 | 8.1 |

#### Damage model: zeroed regions (5 volumes)

Images: `dmg-zeroed-exfat-255m.img`, `dmg-zeroed-ext4-64m.img`, `dmg-zeroed-fat32-255m.img`, `dmg-zeroed-fat32-511m.img`, `dmg-zeroed-ntfs-64m.img`

| Row | FULL files | Byte-identical | Corrupt | Missed | Identical / FULL | PARTIAL returned | GONE returned | False positives (frag/decoy/amb/unrel) | Outputs | Time (s) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Sanctum, carve only | 89 | **86** | 3 | 0 | 96.6% | 5/10 | 0/8 | 8 (0/0/4/4) | 102 | 63.7 |
| PhotoRec | 89 | **73** | 12 | 4 | 82.0% | 0/10 | 0/8 | 0 (0/0/0/0) | 85 | 0.7 |
| Foremost | 89 | **39** | 19 | 31 | 43.8% | 5/10 | 0/8 | 9 (5/0/4/0) | 72 | 14.1 |
| *not a carver's peer:* | | | | | | | | | | |
| Sanctum, undelete + carve | 89 | **87** | 2 | 0 | 97.8% | 7/10 (2 identical) | 0/8 | 16 (7/0/4/5) | 114 | 69.9 |

#### Damage model: filesystem metadata destroyed (5 volumes)

Images: `dmg-metadata-exfat-255m.img`, `dmg-metadata-ext4-64m.img`, `dmg-metadata-fat32-255m.img`, `dmg-metadata-fat32-511m.img`, `dmg-metadata-ntfs-64m.img`

| Row | FULL files | Byte-identical | Corrupt | Missed | Identical / FULL | PARTIAL returned | GONE returned | False positives (frag/decoy/amb/unrel) | Outputs | Time (s) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Sanctum, carve only | 102 | **95** | 7 | 0 | 93.1% | 0/0 | 0/5 | 6 (1/0/0/5) | 108 | 19.7 |
| PhotoRec | 102 | **84** | 15 | 3 | 82.4% | 0/0 | 0/5 | 0 (0/0/0/0) | 99 | 0.5 |
| Foremost | 102 | **46** | 20 | 36 | 45.1% | 0/0 | 0/5 | 5 (5/0/0/0) | 71 | 14.1 |
| *not a carver's peer:* | | | | | | | | | | |
| Sanctum, undelete + carve | 102 | **95** | 7 | 0 | 93.1% | 0/0 | 0/5 | 6 (1/0/0/5) | 108 | 19.8 |

#### Damage model: interleaved overwrite (5 volumes)

Images: `dmg-interleave-exfat-255m.img`, `dmg-interleave-ext4-64m.img`, `dmg-interleave-fat32-255m.img`, `dmg-interleave-fat32-511m.img`, `dmg-interleave-ntfs-64m.img`

| Row | FULL files | Byte-identical | Corrupt | Missed | Identical / FULL | PARTIAL returned | GONE returned | False positives (frag/decoy/amb/unrel) | Outputs | Time (s) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Sanctum, carve only | 103 | **97** | 6 | 0 | 94.2% | 5/14 | 0/0 | 11 (2/0/4/5) | 119 | 59.9 |
| PhotoRec | 103 | **85** | 14 | 4 | 82.5% | 0/14 | 0/0 | 0 (0/0/0/0) | 99 | 0.7 |
| Foremost | 103 | **52** | 20 | 31 | 50.5% | 5/14 | 0/0 | 9 (5/0/4/0) | 86 | 14.1 |
| *not a carver's peer:* | | | | | | | | | | |
| Sanctum, undelete + carve | 103 | **101** | 2 | 0 | 98.1% | 7/14 (2 identical) | 0/0 | 12 (2/0/4/6) | 131 | 61.0 |

#### By format: benchmark volumes and every damage model (25 images)

Cells are byte-identical / corrupt, over FULL objects of that format.

| Format | Header in Sanctum's table | FULL | Sanctum carve | PhotoRec | Foremost | Sanctum full |
|---|---|---:|---:|---:|---:|---:|
| BMP | yes | 20 | 20/0 | 20/0 | 20/0 | 20/0 |
| DOCX | yes | 20 | 20/0 | 20/0 | 0/20 | 20/0 |
| GIF | yes | 24 | 24/0 | 20/0 | 24/0 | 24/0 |
| GZIP | yes | 20 | 20/0 | 0/20 | 0/0 | 20/0 |
| HTML | yes | 20 | 20/0 | 20/0 | 0/0 | 20/0 |
| JPEG | yes | 79 | 79/0 | 69/0 | 69/10 | 79/0 |
| MP4 | yes | 20 | 20/0 | 20/0 | 20/0 | 20/0 |
| PDF | yes | 40 | 40/0 | 40/0 | 40/0 | 40/0 |
| PNG | yes | 51 | 47/4 | 47/0 | 47/0 | 47/4 |
| RTF | yes | 20 | 20/0 | 20/0 | 0/0 | 20/0 |
| SQLite | yes | 15 | 12/3 | 12/3 | 0/0 | 12/3 |
| TAR | yes | 16 | 0/16 | 3/13 | 0/0 | 9/7 |
| TIFF | yes | 20 | 20/0 | 0/20 | 0/0 | 20/0 |
| WAV | yes | 20 | 20/0 | 20/0 | 0/20 | 20/0 |
| WebP | yes | 20 | 20/0 | 20/0 | 0/0 | 20/0 |
| XLSX | yes | 17 | 17/0 | 17/0 | 0/17 | 17/0 |
| ZIP | yes | 24 | 24/0 | 24/0 | 0/24 | 24/0 |

#### Object by object: who returned a FULL file byte-identical

| Pair | Both | Only Sanctum carve | Only the other tool | Neither |
|---|---:|---:|---:|---:|
| Sanctum carve vs PhotoRec | 495 | 76 | 3 | 23 |
| Sanctum carve vs Foremost | 339 | 232 | 0 | 26 |

<details><summary>Sanctum carve only (Sanctum carve vs PhotoRec): 76 objects</summary>

`dmg-interleave-exfat-255m.img:notes.gz`, `dmg-interleave-exfat-255m.img:scan.tiff`, `dmg-interleave-ext4-64m.img:notes.gz`, `dmg-interleave-ext4-64m.img:scan.tiff`, `dmg-interleave-fat32-255m.img:frag.jpg`, `dmg-interleave-fat32-255m.img:notes.gz`, `dmg-interleave-fat32-255m.img:scan.tiff`, `dmg-interleave-fat32-511m.img:frag.jpg`, `dmg-interleave-fat32-511m.img:notes.gz`, `dmg-interleave-fat32-511m.img:scan.tiff`, `dmg-interleave-ntfs-64m.img:notes.gz`, `dmg-interleave-ntfs-64m.img:scan.tiff`, `dmg-interleave-ntfs-64m.img:sticker.gif`, `dmg-metadata-exfat-255m.img:notes.gz`, `dmg-metadata-exfat-255m.img:scan.tiff`, `dmg-metadata-ext4-64m.img:notes.gz`, `dmg-metadata-ext4-64m.img:scan.tiff`, `dmg-metadata-fat32-255m.img:frag.jpg`, `dmg-metadata-fat32-255m.img:notes.gz`, `dmg-metadata-fat32-255m.img:scan.tiff`, `dmg-metadata-fat32-511m.img:frag.jpg`, `dmg-metadata-fat32-511m.img:notes.gz`, `dmg-metadata-fat32-511m.img:scan.tiff`, `dmg-metadata-ntfs-64m.img:notes.gz`, `dmg-metadata-ntfs-64m.img:scan.tiff`, `dmg-truncation-fat32-255m.img:frag.jpg`, `dmg-truncation-fat32-511m.img:frag.jpg`, `dmg-truncation-ntfs-64m.img:sticker.gif`, `dmg-zeroed-exfat-255m.img:notes.gz`, `dmg-zeroed-exfat-255m.img:scan.tiff`, `dmg-zeroed-ext4-64m.img:notes.gz`, `dmg-zeroed-ext4-64m.img:scan.tiff`, `dmg-zeroed-fat32-255m.img:frag.jpg`, `dmg-zeroed-fat32-255m.img:notes.gz`, `dmg-zeroed-fat32-255m.img:scan.tiff`, `dmg-zeroed-fat32-511m.img:frag.jpg`, `dmg-zeroed-fat32-511m.img:notes.gz`, `dmg-zeroed-fat32-511m.img:scan.tiff`, `dmg-zeroed-ntfs-64m.img:notes.gz`, `dmg-zeroed-ntfs-64m.img:scan.tiff`, `dmg-zeroed-ntfs-64m.img:sticker.gif`, `flat-offset1337.img:archive.zip@1574201`, `flat-offset1337.img:budget-macros.docm@2622777`, `flat-offset1337.img:chart.png@5768505`, `flat-offset1337.img:clip.mp4@4195641`, `flat-offset1337.img:contacts.sqlite@3147065`, `flat-offset1337.img:invoice.pdf@6292793`, `flat-offset1337.img:letter.docx@2098489`, `flat-offset1337.img:locked.zip@12059961`, `flat-offset1337.img:messages.sqlite@7341369`, `flat-offset1337.img:photo-with-gps.jpg@1337`, `flat-offset1337.img:screenshot.png@525625`, `flat-offset1337.img:screenshot.png@7865657`, `flat-offset1337.img:screenshot.png@8389945`, `flat-offset1337.img:second-photo.jpg@4719929`, `flat-offset1337.img:sheet.xlsx@6817081`, `flat-offset1337.img:statement.pdf@1049913`, `flat-offset1337.img:sticker.gif@3671353`, `flat-offset1337.img:third-photo.jpg@5244217`, `fs-damaged-parttable.img:holiday.jpg`, `fs-damaged-parttable.img:kept.gif`, `fs-two-partitions.img:holiday.jpg`, `fs-two-partitions.img:kept.gif`, `media-exfat-255m.img:notes.gz`, `media-exfat-255m.img:scan.tiff`, `media-ext4-64m.img:notes.gz`, `media-ext4-64m.img:scan.tiff`, `media-fat32-255m.img:frag.jpg`, `media-fat32-255m.img:notes.gz`, `media-fat32-255m.img:scan.tiff`, `media-fat32-511m.img:frag.jpg`, `media-fat32-511m.img:notes.gz`, `media-fat32-511m.img:scan.tiff`, `media-ntfs-64m.img:notes.gz`, `media-ntfs-64m.img:scan.tiff`, `media-ntfs-64m.img:sticker.gif`

</details>

<details><summary>PhotoRec only (Sanctum carve vs PhotoRec): 3 objects</summary>

`dmg-interleave-fat32-255m.img:backup.tar`, `dmg-metadata-fat32-255m.img:backup.tar`, `media-fat32-255m.img:backup.tar`

</details>

<details><summary>Sanctum carve only (Sanctum carve vs Foremost): 232 objects</summary>

`dmg-interleave-exfat-255m.img:archive.zip`, `dmg-interleave-exfat-255m.img:budget.xlsx`, `dmg-interleave-exfat-255m.img:letter.docx`, `dmg-interleave-exfat-255m.img:memo.rtf`, `dmg-interleave-exfat-255m.img:notes.gz`, `dmg-interleave-exfat-255m.img:page.html`, `dmg-interleave-exfat-255m.img:photo.webp`, `dmg-interleave-exfat-255m.img:scan.tiff`, `dmg-interleave-exfat-255m.img:voice.wav`, `dmg-interleave-ext4-64m.img:archive.zip`, `dmg-interleave-ext4-64m.img:budget.xlsx`, `dmg-interleave-ext4-64m.img:letter.docx`, `dmg-interleave-ext4-64m.img:memo.rtf`, `dmg-interleave-ext4-64m.img:notes.gz`, `dmg-interleave-ext4-64m.img:page.html`, `dmg-interleave-ext4-64m.img:photo.webp`, `dmg-interleave-ext4-64m.img:scan.tiff`, `dmg-interleave-ext4-64m.img:voice.wav`, `dmg-interleave-fat32-255m.img:archive.zip`, `dmg-interleave-fat32-255m.img:budget.xlsx`, `dmg-interleave-fat32-255m.img:frag.jpg`, `dmg-interleave-fat32-255m.img:letter.docx`, `dmg-interleave-fat32-255m.img:memo.rtf`, `dmg-interleave-fat32-255m.img:notes.gz`, `dmg-interleave-fat32-255m.img:page.html`, `dmg-interleave-fat32-255m.img:photo.webp`, `dmg-interleave-fat32-255m.img:scan.tiff`, `dmg-interleave-fat32-255m.img:voice.wav`, `dmg-interleave-fat32-511m.img:archive.zip`, `dmg-interleave-fat32-511m.img:budget.xlsx`, `dmg-interleave-fat32-511m.img:frag.jpg`, `dmg-interleave-fat32-511m.img:letter.docx`, `dmg-interleave-fat32-511m.img:memo.rtf`, `dmg-interleave-fat32-511m.img:notes.gz`, `dmg-interleave-fat32-511m.img:page.html`, `dmg-interleave-fat32-511m.img:photo.webp`, `dmg-interleave-fat32-511m.img:scan.tiff`, `dmg-interleave-fat32-511m.img:voice.wav`, `dmg-interleave-ntfs-64m.img:archive.zip`, `dmg-interleave-ntfs-64m.img:memo.rtf`, `dmg-interleave-ntfs-64m.img:notes.gz`, `dmg-interleave-ntfs-64m.img:page.html`, `dmg-interleave-ntfs-64m.img:photo.webp`, `dmg-interleave-ntfs-64m.img:scan.tiff`, `dmg-interleave-ntfs-64m.img:voice.wav`, `dmg-metadata-exfat-255m.img:archive.zip`, `dmg-metadata-exfat-255m.img:budget.xlsx`, `dmg-metadata-exfat-255m.img:contacts.sqlite`, `dmg-metadata-exfat-255m.img:letter.docx`, `dmg-metadata-exfat-255m.img:memo.rtf`, `dmg-metadata-exfat-255m.img:notes.gz`, `dmg-metadata-exfat-255m.img:page.html`, `dmg-metadata-exfat-255m.img:photo.webp`, `dmg-metadata-exfat-255m.img:scan.tiff`, `dmg-metadata-exfat-255m.img:voice.wav`, `dmg-metadata-ext4-64m.img:archive.zip`, `dmg-metadata-ext4-64m.img:budget.xlsx`, `dmg-metadata-ext4-64m.img:letter.docx`, `dmg-metadata-ext4-64m.img:memo.rtf`, `dmg-metadata-ext4-64m.img:notes.gz`, `dmg-metadata-ext4-64m.img:page.html`, `dmg-metadata-ext4-64m.img:photo.webp`, `dmg-metadata-ext4-64m.img:scan.tiff`, `dmg-metadata-ext4-64m.img:voice.wav`, `dmg-metadata-fat32-255m.img:archive.zip`, `dmg-metadata-fat32-255m.img:budget.xlsx`, `dmg-metadata-fat32-255m.img:contacts.sqlite`, `dmg-metadata-fat32-255m.img:frag.jpg`, `dmg-metadata-fat32-255m.img:letter.docx`, `dmg-metadata-fat32-255m.img:memo.rtf`, `dmg-metadata-fat32-255m.img:notes.gz`, `dmg-metadata-fat32-255m.img:page.html`, `dmg-metadata-fat32-255m.img:photo.webp`, `dmg-metadata-fat32-255m.img:scan.tiff`, `dmg-metadata-fat32-255m.img:voice.wav`, `dmg-metadata-fat32-511m.img:archive.zip`, `dmg-metadata-fat32-511m.img:budget.xlsx`, `dmg-metadata-fat32-511m.img:contacts.sqlite`, `dmg-metadata-fat32-511m.img:frag.jpg`, `dmg-metadata-fat32-511m.img:letter.docx`, `dmg-metadata-fat32-511m.img:memo.rtf`, `dmg-metadata-fat32-511m.img:notes.gz`, `dmg-metadata-fat32-511m.img:page.html`, `dmg-metadata-fat32-511m.img:photo.webp`, `dmg-metadata-fat32-511m.img:scan.tiff`, `dmg-metadata-fat32-511m.img:voice.wav`, `dmg-metadata-ntfs-64m.img:archive.zip`, `dmg-metadata-ntfs-64m.img:contacts.sqlite`, `dmg-metadata-ntfs-64m.img:memo.rtf`, `dmg-metadata-ntfs-64m.img:notes.gz`, `dmg-metadata-ntfs-64m.img:page.html`, `dmg-metadata-ntfs-64m.img:photo.webp`, `dmg-metadata-ntfs-64m.img:scan.tiff`, `dmg-metadata-ntfs-64m.img:voice.wav`, `dmg-truncation-exfat-255m.img:archive.zip`, `dmg-truncation-exfat-255m.img:budget.xlsx`, `dmg-truncation-exfat-255m.img:letter.docx`, `dmg-truncation-ext4-64m.img:archive.zip`, `dmg-truncation-ext4-64m.img:letter.docx`, `dmg-truncation-fat32-255m.img:archive.zip`, `dmg-truncation-fat32-255m.img:frag.jpg`, `dmg-truncation-fat32-255m.img:letter.docx`, `dmg-truncation-fat32-511m.img:archive.zip`, `dmg-truncation-fat32-511m.img:frag.jpg`, `dmg-truncation-fat32-511m.img:letter.docx`, `dmg-truncation-ntfs-64m.img:archive.zip`, `dmg-truncation-ntfs-64m.img:contacts.sqlite`, `dmg-zeroed-exfat-255m.img:archive.zip`, `dmg-zeroed-exfat-255m.img:budget.xlsx`, `dmg-zeroed-exfat-255m.img:contacts.sqlite`, `dmg-zeroed-exfat-255m.img:letter.docx`, `dmg-zeroed-exfat-255m.img:memo.rtf`, `dmg-zeroed-exfat-255m.img:notes.gz`, `dmg-zeroed-exfat-255m.img:page.html`, `dmg-zeroed-exfat-255m.img:photo.webp`, `dmg-zeroed-exfat-255m.img:scan.tiff`, `dmg-zeroed-exfat-255m.img:voice.wav`, `dmg-zeroed-ext4-64m.img:archive.zip`, `dmg-zeroed-ext4-64m.img:budget.xlsx`, `dmg-zeroed-ext4-64m.img:letter.docx`, `dmg-zeroed-ext4-64m.img:memo.rtf`, `dmg-zeroed-ext4-64m.img:notes.gz`, `dmg-zeroed-ext4-64m.img:page.html`, `dmg-zeroed-ext4-64m.img:photo.webp`, `dmg-zeroed-ext4-64m.img:scan.tiff`, `dmg-zeroed-ext4-64m.img:voice.wav`, `dmg-zeroed-fat32-255m.img:archive.zip`, `dmg-zeroed-fat32-255m.img:budget.xlsx`, `dmg-zeroed-fat32-255m.img:contacts.sqlite`, `dmg-zeroed-fat32-255m.img:frag.jpg`, `dmg-zeroed-fat32-255m.img:letter.docx`, `dmg-zeroed-fat32-255m.img:memo.rtf`, `dmg-zeroed-fat32-255m.img:notes.gz`, `dmg-zeroed-fat32-255m.img:page.html`, `dmg-zeroed-fat32-255m.img:photo.webp`, `dmg-zeroed-fat32-255m.img:scan.tiff`, `dmg-zeroed-fat32-255m.img:voice.wav`, `dmg-zeroed-fat32-511m.img:archive.zip`, `dmg-zeroed-fat32-511m.img:budget.xlsx`, `dmg-zeroed-fat32-511m.img:contacts.sqlite`, `dmg-zeroed-fat32-511m.img:frag.jpg`, `dmg-zeroed-fat32-511m.img:letter.docx`, `dmg-zeroed-fat32-511m.img:memo.rtf`, `dmg-zeroed-fat32-511m.img:notes.gz`, `dmg-zeroed-fat32-511m.img:page.html`, `dmg-zeroed-fat32-511m.img:photo.webp`, `dmg-zeroed-fat32-511m.img:scan.tiff`, `dmg-zeroed-fat32-511m.img:voice.wav`, `dmg-zeroed-ntfs-64m.img:memo.rtf`, `dmg-zeroed-ntfs-64m.img:notes.gz`, `dmg-zeroed-ntfs-64m.img:page.html`, `dmg-zeroed-ntfs-64m.img:photo.webp`, `dmg-zeroed-ntfs-64m.img:scan.tiff`, `dmg-zeroed-ntfs-64m.img:voice.wav`, `flat-aligned.img:archive.zip@1576960`, `flat-aligned.img:budget-macros.docm@2625536`, `flat-aligned.img:clip.mp4@4198400`, `flat-aligned.img:contacts.sqlite@3149824`, `flat-aligned.img:letter.docx@2101248`, `flat-aligned.img:locked.zip@12062720`, `flat-aligned.img:messages.sqlite@7344128`, `flat-aligned.img:sheet.xlsx@6819840`, `flat-offset1337.img:archive.zip@1574201`, `flat-offset1337.img:budget-macros.docm@2622777`, `flat-offset1337.img:clip.mp4@4195641`, `flat-offset1337.img:contacts.sqlite@3147065`, `flat-offset1337.img:letter.docx@2098489`, `flat-offset1337.img:locked.zip@12059961`, `flat-offset1337.img:messages.sqlite@7341369`, `flat-offset1337.img:sheet.xlsx@6817081`, `fs-damaged-boot.img:18-contacts.sqlite`, `fs-damaged-boot.img:19-messages.sqlite`, `fs-damaged-parttable.img:18-contacts.sqlite`, `fs-damaged-parttable.img:19-messages.sqlite`, `fs-ext2.img:kept.zip`, `fs-ext3.img:kept.zip`, `fs-ext4.img:kept.zip`, `fs-ntfs-reused.img:18-contacts.sqlite`, `fs-ntfs-reused.img:19-messages.sqlite`, `fs-ntfs.img:18-contacts.sqlite`, `fs-ntfs.img:19-messages.sqlite`, `fs-two-partitions.img:18-contacts.sqlite`, `fs-two-partitions.img:19-messages.sqlite`, `media-exfat-255m.img:archive.zip`, `media-exfat-255m.img:budget.xlsx`, `media-exfat-255m.img:contacts.sqlite`, `media-exfat-255m.img:letter.docx`, `media-exfat-255m.img:memo.rtf`, `media-exfat-255m.img:notes.gz`, `media-exfat-255m.img:page.html`, `media-exfat-255m.img:photo.webp`, `media-exfat-255m.img:scan.tiff`, `media-exfat-255m.img:voice.wav`, `media-ext4-64m.img:archive.zip`, `media-ext4-64m.img:budget.xlsx`, `media-ext4-64m.img:letter.docx`, `media-ext4-64m.img:memo.rtf`, `media-ext4-64m.img:notes.gz`, `media-ext4-64m.img:page.html`, `media-ext4-64m.img:photo.webp`, `media-ext4-64m.img:scan.tiff`, `media-ext4-64m.img:voice.wav`, `media-fat32-255m.img:archive.zip`, `media-fat32-255m.img:budget.xlsx`, `media-fat32-255m.img:contacts.sqlite`, `media-fat32-255m.img:frag.jpg`, `media-fat32-255m.img:letter.docx`, `media-fat32-255m.img:memo.rtf`, `media-fat32-255m.img:notes.gz`, `media-fat32-255m.img:page.html`, `media-fat32-255m.img:photo.webp`, `media-fat32-255m.img:scan.tiff`, `media-fat32-255m.img:voice.wav`, `media-fat32-511m.img:archive.zip`, `media-fat32-511m.img:budget.xlsx`, `media-fat32-511m.img:contacts.sqlite`, `media-fat32-511m.img:frag.jpg`, `media-fat32-511m.img:letter.docx`, `media-fat32-511m.img:memo.rtf`, `media-fat32-511m.img:notes.gz`, `media-fat32-511m.img:page.html`, `media-fat32-511m.img:photo.webp`, `media-fat32-511m.img:scan.tiff`, `media-fat32-511m.img:voice.wav`, `media-ntfs-64m.img:archive.zip`, `media-ntfs-64m.img:contacts.sqlite`, `media-ntfs-64m.img:memo.rtf`, `media-ntfs-64m.img:notes.gz`, `media-ntfs-64m.img:page.html`, `media-ntfs-64m.img:photo.webp`, `media-ntfs-64m.img:scan.tiff`, `media-ntfs-64m.img:voice.wav`

</details>

#### Supplementary, not comparable: Sanctum HIGH and MEDIUM only

| Row | FULL files | Byte-identical | Corrupt | Missed | Identical / FULL | PARTIAL returned | GONE returned | False positives (frag/decoy/amb/unrel) | Outputs | Time (s) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Sanctum carve, HIGH+MEDIUM only (all 40 images) | 591 | **565** | 13 | 13 | 95.6% | 0/56 | 0/64 | 9 (0/0/8/1) | 587 | 184.1 |
| Sanctum full, HIGH+MEDIUM only (all 40 images) | 591 | **576** | 8 | 7 | 97.5% | 14/56 (11 identical) | 0/64 | 17 (0/0/8/9) | 625 | 201.1 |

#### Every run

| Image | Row | FULL | Identical | Corrupt | Missed | PARTIAL ret. | FP | Outputs | Time (s) | Exit |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `dmg-interleave-exfat-255m.img` | Sanctum, carve only | 21 | 19 | 2 | 0 | 1/2 | 1 | 23 | 12.59 | 0 |
| `dmg-interleave-exfat-255m.img` | PhotoRec | 21 | 17 | 3 | 1 | 0/2 | 0 | 20 | 0.06 | 0 |
| `dmg-interleave-exfat-255m.img` | Foremost | 21 | 10 | 4 | 7 | 1/2 | 1 | 16 | 3.12 | 0 |
| `dmg-interleave-exfat-255m.img` | Sanctum, undelete + carve | 21 | 20 | 1 | 0 | 1/2 | 1 | 26 | 13.34 | 0 |
| `dmg-interleave-ext4-64m.img` | Sanctum, carve only | 21 | 20 | 1 | 0 | 1/2 | 2 | 24 | 10.59 | 0 |
| `dmg-interleave-ext4-64m.img` | PhotoRec | 21 | 18 | 3 | 0 | 0/2 | 0 | 21 | 0.12 | 0 |
| `dmg-interleave-ext4-64m.img` | Foremost | 21 | 11 | 4 | 6 | 1/2 | 1 | 17 | 0.82 | 0 |
| `dmg-interleave-ext4-64m.img` | Sanctum, undelete + carve | 21 | 20 | 1 | 0 | 1/2 | 3 | 25 | 11.04 | 0 |
| `dmg-interleave-fat32-255m.img` | Sanctum, carve only | 22 | 21 | 1 | 0 | 1/2 | 1 | 24 | 12.64 | 0 |
| `dmg-interleave-fat32-255m.img` | PhotoRec | 22 | 19 | 2 | 1 | 0/2 | 0 | 21 | 0.21 | 0 |
| `dmg-interleave-fat32-255m.img` | Foremost | 22 | 11 | 5 | 6 | 1/2 | 1 | 18 | 3.12 | 0 |
| `dmg-interleave-fat32-255m.img` | Sanctum, undelete + carve | 22 | 22 | 0 | 0 | 1/2 | 1 | 26 | 12.89 | 0 |
| `dmg-interleave-fat32-511m.img` | Sanctum, carve only | 22 | 21 | 1 | 0 | 1/2 | 2 | 25 | 14.70 | 0 |
| `dmg-interleave-fat32-511m.img` | PhotoRec | 22 | 18 | 3 | 1 | 0/2 | 0 | 21 | 0.21 | 0 |
| `dmg-interleave-fat32-511m.img` | Foremost | 22 | 11 | 5 | 6 | 1/2 | 1 | 18 | 6.23 | 0 |
| `dmg-interleave-fat32-511m.img` | Sanctum, undelete + carve | 22 | 22 | 0 | 0 | 1/2 | 2 | 27 | 13.34 | 0 |
| `dmg-interleave-ntfs-64m.img` | Sanctum, carve only | 17 | 16 | 1 | 0 | 1/6 | 5 | 23 | 9.38 | 0 |
| `dmg-interleave-ntfs-64m.img` | PhotoRec | 17 | 13 | 3 | 1 | 0/6 | 0 | 16 | 0.06 | 0 |
| `dmg-interleave-ntfs-64m.img` | Foremost | 17 | 9 | 2 | 6 | 1/6 | 5 | 17 | 0.82 | 0 |
| `dmg-interleave-ntfs-64m.img` | Sanctum, undelete + carve | 17 | 17 | 0 | 0 | 3/6 | 5 | 27 | 10.39 | 0 |
| `dmg-metadata-exfat-255m.img` | Sanctum, carve only | 21 | 19 | 2 | 0 | 0/0 | 1 | 22 | 4.17 | 0 |
| `dmg-metadata-exfat-255m.img` | PhotoRec | 21 | 17 | 3 | 1 | 0/0 | 0 | 20 | 0.06 | 0 |
| `dmg-metadata-exfat-255m.img` | Foremost | 21 | 9 | 4 | 8 | 0/0 | 1 | 14 | 3.12 | 0 |
| `dmg-metadata-exfat-255m.img` | Sanctum, undelete + carve | 21 | 19 | 2 | 0 | 0/0 | 1 | 22 | 4.18 | 0 |
| `dmg-metadata-ext4-64m.img` | Sanctum, carve only | 21 | 19 | 2 | 0 | 0/0 | 2 | 23 | 2.12 | 0 |
| `dmg-metadata-ext4-64m.img` | PhotoRec | 21 | 17 | 4 | 0 | 0/0 | 0 | 21 | 0.06 | 0 |
| `dmg-metadata-ext4-64m.img` | Foremost | 21 | 10 | 4 | 7 | 0/0 | 1 | 15 | 0.82 | 0 |
| `dmg-metadata-ext4-64m.img` | Sanctum, undelete + carve | 21 | 19 | 2 | 0 | 0/0 | 2 | 23 | 2.12 | 0 |
| `dmg-metadata-fat32-255m.img` | Sanctum, carve only | 22 | 21 | 1 | 0 | 0/0 | 1 | 23 | 4.38 | 0 |
| `dmg-metadata-fat32-255m.img` | PhotoRec | 22 | 19 | 2 | 1 | 0/0 | 0 | 21 | 0.21 | 0 |
| `dmg-metadata-fat32-255m.img` | Foremost | 22 | 10 | 5 | 7 | 0/0 | 1 | 16 | 3.12 | 0 |
| `dmg-metadata-fat32-255m.img` | Sanctum, undelete + carve | 22 | 21 | 1 | 0 | 0/0 | 1 | 23 | 4.43 | 0 |
| `dmg-metadata-fat32-511m.img` | Sanctum, carve only | 22 | 21 | 1 | 0 | 0/0 | 1 | 23 | 7.03 | 0 |
| `dmg-metadata-fat32-511m.img` | PhotoRec | 22 | 18 | 3 | 1 | 0/0 | 0 | 21 | 0.12 | 0 |
| `dmg-metadata-fat32-511m.img` | Foremost | 22 | 10 | 5 | 7 | 0/0 | 1 | 16 | 6.18 | 0 |
| `dmg-metadata-fat32-511m.img` | Sanctum, undelete + carve | 22 | 21 | 1 | 0 | 0/0 | 1 | 23 | 7.13 | 0 |
| `dmg-metadata-ntfs-64m.img` | Sanctum, carve only | 16 | 15 | 1 | 0 | 0/0 | 1 | 17 | 1.97 | 0 |
| `dmg-metadata-ntfs-64m.img` | PhotoRec | 16 | 13 | 3 | 0 | 0/0 | 0 | 16 | 0.06 | 0 |
| `dmg-metadata-ntfs-64m.img` | Foremost | 16 | 7 | 2 | 7 | 0/0 | 1 | 10 | 0.82 | 0 |
| `dmg-metadata-ntfs-64m.img` | Sanctum, undelete + carve | 16 | 15 | 1 | 0 | 0/0 | 1 | 17 | 1.97 | 0 |
| `dmg-truncation-exfat-255m.img` | Sanctum, carve only | 9 | 9 | 0 | 0 | 2/2 | 1 | 12 | 1.27 | 0 |
| `dmg-truncation-exfat-255m.img` | PhotoRec | 9 | 9 | 0 | 0 | 1/2 | 0 | 10 | 0.03 | 0 |
| `dmg-truncation-exfat-255m.img` | Foremost | 9 | 6 | 3 | 0 | 0/2 | 0 | 9 | 0.07 | 0 |
| `dmg-truncation-exfat-255m.img` | Sanctum, undelete + carve | 9 | 9 | 0 | 0 | 2/2 | 2 | 14 | 1.52 | 0 |
| `dmg-truncation-ext4-64m.img` | Sanctum, carve only | 10 | 10 | 0 | 0 | 0/0 | 1 | 11 | 1.27 | 0 |
| `dmg-truncation-ext4-64m.img` | PhotoRec | 10 | 10 | 0 | 0 | 0/0 | 0 | 10 | 0.03 | 0 |
| `dmg-truncation-ext4-64m.img` | Foremost | 10 | 8 | 2 | 0 | 0/0 | 0 | 10 | 0.11 | 0 |
| `dmg-truncation-ext4-64m.img` | Sanctum, undelete + carve | 10 | 10 | 0 | 0 | 0/0 | 2 | 12 | 1.47 | 0 |
| `dmg-truncation-fat32-255m.img` | Sanctum, carve only | 11 | 11 | 0 | 0 | 0/0 | 1 | 12 | 1.47 | 0 |
| `dmg-truncation-fat32-255m.img` | PhotoRec | 11 | 10 | 0 | 1 | 0/0 | 0 | 10 | 0.03 | 0 |
| `dmg-truncation-fat32-255m.img` | Foremost | 11 | 8 | 3 | 0 | 0/0 | 0 | 11 | 0.07 | 0 |
| `dmg-truncation-fat32-255m.img` | Sanctum, undelete + carve | 11 | 11 | 0 | 0 | 0/0 | 1 | 12 | 1.47 | 0 |
| `dmg-truncation-fat32-511m.img` | Sanctum, carve only | 11 | 11 | 0 | 0 | 0/0 | 1 | 12 | 1.52 | 0 |
| `dmg-truncation-fat32-511m.img` | PhotoRec | 11 | 10 | 0 | 1 | 0/0 | 0 | 10 | 0.03 | 0 |
| `dmg-truncation-fat32-511m.img` | Foremost | 11 | 8 | 3 | 0 | 0/0 | 0 | 11 | 0.03 | 0 |
| `dmg-truncation-fat32-511m.img` | Sanctum, undelete + carve | 11 | 11 | 0 | 0 | 0/0 | 2 | 13 | 1.72 | 0 |
| `dmg-truncation-ntfs-64m.img` | Sanctum, carve only | 8 | 8 | 0 | 0 | 0/5 | 6 | 14 | 1.67 | 0 |
| `dmg-truncation-ntfs-64m.img` | PhotoRec | 8 | 7 | 0 | 1 | 0/5 | 0 | 7 | 0.03 | 0 |
| `dmg-truncation-ntfs-64m.img` | Foremost | 8 | 6 | 1 | 1 | 0/5 | 4 | 11 | 0.47 | 0 |
| `dmg-truncation-ntfs-64m.img` | Sanctum, undelete + carve | 8 | 8 | 0 | 0 | 3/5 | 7 | 18 | 1.92 | 0 |
| `dmg-zeroed-exfat-255m.img` | Sanctum, carve only | 19 | 18 | 1 | 0 | 1/1 | 1 | 21 | 14.04 | 0 |
| `dmg-zeroed-exfat-255m.img` | PhotoRec | 19 | 16 | 2 | 1 | 0/1 | 0 | 18 | 0.06 | 0 |
| `dmg-zeroed-exfat-255m.img` | Foremost | 19 | 8 | 4 | 7 | 1/1 | 1 | 14 | 3.12 | 0 |
| `dmg-zeroed-exfat-255m.img` | Sanctum, undelete + carve | 19 | 18 | 1 | 0 | 1/1 | 2 | 23 | 14.29 | 0 |
| `dmg-zeroed-ext4-64m.img` | Sanctum, carve only | 19 | 18 | 1 | 0 | 1/1 | 1 | 21 | 11.94 | 0 |
| `dmg-zeroed-ext4-64m.img` | PhotoRec | 19 | 16 | 3 | 0 | 0/1 | 0 | 19 | 0.12 | 0 |
| `dmg-zeroed-ext4-64m.img` | Foremost | 19 | 9 | 4 | 6 | 1/1 | 1 | 15 | 0.82 | 0 |
| `dmg-zeroed-ext4-64m.img` | Sanctum, undelete + carve | 19 | 18 | 1 | 0 | 1/1 | 2 | 22 | 12.14 | 0 |
| `dmg-zeroed-fat32-255m.img` | Sanctum, carve only | 20 | 20 | 0 | 0 | 1/1 | 1 | 22 | 14.25 | 0 |
| `dmg-zeroed-fat32-255m.img` | PhotoRec | 20 | 17 | 2 | 1 | 0/1 | 0 | 19 | 0.21 | 0 |
| `dmg-zeroed-fat32-255m.img` | Foremost | 20 | 9 | 5 | 6 | 1/1 | 1 | 16 | 3.12 | 0 |
| `dmg-zeroed-fat32-255m.img` | Sanctum, undelete + carve | 20 | 20 | 0 | 0 | 1/1 | 2 | 23 | 14.55 | 0 |
| `dmg-zeroed-fat32-511m.img` | Sanctum, carve only | 20 | 20 | 0 | 0 | 1/1 | 1 | 22 | 16.40 | 0 |
| `dmg-zeroed-fat32-511m.img` | PhotoRec | 20 | 17 | 2 | 1 | 0/1 | 0 | 19 | 0.16 | 0 |
| `dmg-zeroed-fat32-511m.img` | Foremost | 20 | 9 | 5 | 6 | 1/1 | 1 | 16 | 6.18 | 0 |
| `dmg-zeroed-fat32-511m.img` | Sanctum, undelete + carve | 20 | 20 | 0 | 0 | 1/1 | 2 | 23 | 17.10 | 0 |
| `dmg-zeroed-ntfs-64m.img` | Sanctum, carve only | 11 | 10 | 1 | 0 | 1/6 | 4 | 16 | 7.03 | 0 |
| `dmg-zeroed-ntfs-64m.img` | PhotoRec | 11 | 7 | 3 | 1 | 0/6 | 0 | 10 | 0.11 | 0 |
| `dmg-zeroed-ntfs-64m.img` | Foremost | 11 | 4 | 1 | 6 | 1/6 | 5 | 11 | 0.82 | 0 |
| `dmg-zeroed-ntfs-64m.img` | Sanctum, undelete + carve | 11 | 11 | 0 | 0 | 3/6 | 8 | 23 | 11.79 | 0 |
| `flat-aligned.img` | Sanctum, carve only | 15 | 15 | 0 | 0 | 2/3 | 3 | 21 | 0.92 | 0 |
| `flat-aligned.img` | PhotoRec | 15 | 15 | 0 | 0 | 0/3 | 0 | 19 | 0.03 | 0 |
| `flat-aligned.img` | Foremost | 15 | 7 | 6 | 2 | 1/3 | 0 | 17 | 0.17 | 0 |
| `flat-aligned.img` | Sanctum, undelete + carve | 15 | 15 | 0 | 0 | 2/3 | 3 | 21 | 0.97 | 0 |
| `flat-offset1337.img` | Sanctum, carve only | 15 | 15 | 0 | 0 | 2/3 | 3 | 21 | 0.92 | 0 |
| `flat-offset1337.img` | PhotoRec | 15 | 0 | 0 | 15 | 0/3 | 0 | 0 | 0.03 | 0 |
| `flat-offset1337.img` | Foremost | 15 | 7 | 6 | 2 | 1/3 | 0 | 17 | 0.17 | 0 |
| `flat-offset1337.img` | Sanctum, undelete + carve | 15 | 15 | 0 | 0 | 2/3 | 3 | 21 | 0.92 | 0 |
| `fs-damaged-boot.img` | Sanctum, carve only | 17 | 17 | 0 | 0 | 3/3 | 1 | 21 | 1.02 | 0 |
| `fs-damaged-boot.img` | PhotoRec | 17 | 17 | 0 | 0 | 0/3 | 0 | 17 | 0.03 | 0 |
| `fs-damaged-boot.img` | Foremost | 17 | 15 | 0 | 2 | 3/3 | 0 | 18 | 0.32 | 0 |
| `fs-damaged-boot.img` | Sanctum, undelete + carve | 17 | 17 | 0 | 0 | 3/3 | 1 | 21 | 1.07 | 0 |
| `fs-damaged-parttable.img` | Sanctum, carve only | 20 | 20 | 0 | 0 | 3/3 | 1 | 24 | 1.62 | 0 |
| `fs-damaged-parttable.img` | PhotoRec | 20 | 18 | 0 | 2 | 0/3 | 0 | 18 | 0.11 | 0 |
| `fs-damaged-parttable.img` | Foremost | 20 | 18 | 0 | 2 | 3/3 | 0 | 21 | 0.87 | 0 |
| `fs-damaged-parttable.img` | Sanctum, undelete + carve | 20 | 20 | 0 | 0 | 3/3 | 1 | 24 | 1.62 | 0 |
| `fs-exfat.img` | Sanctum, carve only | 3 | 2 | 1 | 0 | 0/0 | 0 | 3 | 0.52 | 0 |
| `fs-exfat.img` | PhotoRec | 3 | 2 | 0 | 1 | 0/0 | 0 | 2 | 0.06 | 0 |
| `fs-exfat.img` | Foremost | 3 | 2 | 0 | 1 | 0/0 | 0 | 2 | 0.16 | 0 |
| `fs-exfat.img` | Sanctum, undelete + carve | 3 | 2 | 1 | 0 | 0/0 | 0 | 4 | 0.57 | 0 |
| `fs-ext2.img` | Sanctum, carve only | 3 | 2 | 1 | 0 | 0/0 | 1 | 4 | 0.77 | 0 |
| `fs-ext2.img` | PhotoRec | 3 | 2 | 0 | 1 | 0/0 | 0 | 2 | 0.07 | 0 |
| `fs-ext2.img` | Foremost | 3 | 1 | 2 | 0 | 0/0 | 0 | 3 | 0.17 | 0 |
| `fs-ext2.img` | Sanctum, undelete + carve | 3 | 3 | 0 | 0 | 0/0 | 1 | 4 | 0.67 | 0 |
| `fs-ext3.img` | Sanctum, carve only | 3 | 2 | 1 | 0 | 0/0 | 1 | 4 | 0.77 | 0 |
| `fs-ext3.img` | PhotoRec | 3 | 2 | 0 | 1 | 0/0 | 0 | 2 | 0.07 | 0 |
| `fs-ext3.img` | Foremost | 3 | 1 | 2 | 0 | 0/0 | 0 | 3 | 0.16 | 0 |
| `fs-ext3.img` | Sanctum, undelete + carve | 3 | 3 | 0 | 0 | 0/0 | 1 | 4 | 0.67 | 0 |
| `fs-ext4.img` | Sanctum, carve only | 3 | 3 | 0 | 0 | 0/0 | 1 | 4 | 0.52 | 0 |
| `fs-ext4.img` | PhotoRec | 3 | 3 | 0 | 0 | 0/0 | 0 | 3 | 0.03 | 0 |
| `fs-ext4.img` | Foremost | 3 | 2 | 1 | 0 | 0/0 | 0 | 3 | 0.16 | 0 |
| `fs-ext4.img` | Sanctum, undelete + carve | 3 | 3 | 0 | 0 | 0/0 | 2 | 5 | 0.57 | 0 |
| `fs-fat32-neighbours.img` | Sanctum, carve only | 3 | 3 | 0 | 0 | 0/0 | 1 | 4 | 0.82 | 0 |
| `fs-fat32-neighbours.img` | PhotoRec | 3 | 3 | 0 | 0 | 0/0 | 0 | 3 | 0.11 | 0 |
| `fs-fat32-neighbours.img` | Foremost | 3 | 3 | 0 | 0 | 0/0 | 0 | 3 | 0.36 | 0 |
| `fs-fat32-neighbours.img` | Sanctum, undelete + carve | 3 | 3 | 0 | 0 | 0/0 | 5 | 83 | 3.07 | 0 |
| `fs-fat32-plain.img` | Sanctum, carve only | 3 | 3 | 0 | 0 | 0/0 | 1 | 4 | 0.82 | 0 |
| `fs-fat32-plain.img` | PhotoRec | 3 | 3 | 0 | 0 | 0/0 | 0 | 3 | 0.06 | 0 |
| `fs-fat32-plain.img` | Foremost | 3 | 3 | 0 | 0 | 0/0 | 0 | 3 | 0.52 | 0 |
| `fs-fat32-plain.img` | Sanctum, undelete + carve | 3 | 3 | 0 | 0 | 0/0 | 1 | 4 | 0.92 | 0 |
| `fs-fat32.img` | Sanctum, carve only | 3 | 3 | 0 | 0 | 0/0 | 1 | 4 | 0.87 | 0 |
| `fs-fat32.img` | PhotoRec | 3 | 3 | 0 | 0 | 0/0 | 0 | 3 | 0.11 | 0 |
| `fs-fat32.img` | Foremost | 3 | 3 | 0 | 0 | 0/0 | 0 | 3 | 0.36 | 0 |
| `fs-fat32.img` | Sanctum, undelete + carve | 3 | 3 | 0 | 0 | 0/0 | 6 | 161 | 5.28 | 0 |
| `fs-ntfs-reused.img` | Sanctum, carve only | 17 | 17 | 0 | 0 | 3/3 | 1 | 21 | 1.02 | 0 |
| `fs-ntfs-reused.img` | PhotoRec | 17 | 17 | 0 | 0 | 0/3 | 0 | 17 | 0.03 | 0 |
| `fs-ntfs-reused.img` | Foremost | 17 | 15 | 0 | 2 | 3/3 | 0 | 18 | 0.32 | 0 |
| `fs-ntfs-reused.img` | Sanctum, undelete + carve | 17 | 17 | 0 | 0 | 3/3 | 2 | 23 | 1.17 | 0 |
| `fs-ntfs.img` | Sanctum, carve only | 17 | 17 | 0 | 0 | 3/3 | 1 | 21 | 1.02 | 0 |
| `fs-ntfs.img` | PhotoRec | 17 | 17 | 0 | 0 | 0/3 | 0 | 17 | 0.03 | 0 |
| `fs-ntfs.img` | Foremost | 17 | 15 | 0 | 2 | 3/3 | 0 | 18 | 0.32 | 0 |
| `fs-ntfs.img` | Sanctum, undelete + carve | 17 | 17 | 0 | 0 | 3/3 | 1 | 22 | 1.17 | 0 |
| `fs-quick-formatted.img` | Sanctum, carve only | 3 | 3 | 0 | 0 | 0/0 | 1 | 4 | 0.82 | 0 |
| `fs-quick-formatted.img` | PhotoRec | 3 | 3 | 0 | 0 | 0/0 | 0 | 3 | 0.06 | 0 |
| `fs-quick-formatted.img` | Foremost | 3 | 3 | 0 | 0 | 0/0 | 0 | 3 | 0.52 | 0 |
| `fs-quick-formatted.img` | Sanctum, undelete + carve | 3 | 3 | 0 | 0 | 0/0 | 1 | 4 | 0.82 | 0 |
| `fs-two-partitions.img` | Sanctum, carve only | 20 | 20 | 0 | 0 | 3/3 | 1 | 24 | 1.57 | 0 |
| `fs-two-partitions.img` | PhotoRec | 20 | 18 | 0 | 2 | 0/3 | 0 | 18 | 0.12 | 0 |
| `fs-two-partitions.img` | Foremost | 20 | 18 | 0 | 2 | 3/3 | 0 | 21 | 0.87 | 0 |
| `fs-two-partitions.img` | Sanctum, undelete + carve | 20 | 20 | 0 | 0 | 3/3 | 1 | 25 | 1.77 | 0 |
| `media-exfat-255m.img` | Sanctum, carve only | 21 | 19 | 2 | 0 | 0/0 | 1 | 22 | 4.12 | 0 |
| `media-exfat-255m.img` | PhotoRec | 21 | 17 | 3 | 1 | 0/0 | 0 | 20 | 0.06 | 0 |
| `media-exfat-255m.img` | Foremost | 21 | 9 | 4 | 8 | 0/0 | 1 | 14 | 3.12 | 0 |
| `media-exfat-255m.img` | Sanctum, undelete + carve | 21 | 20 | 1 | 0 | 0/0 | 1 | 24 | 4.42 | 0 |
| `media-ext4-64m.img` | Sanctum, carve only | 21 | 19 | 2 | 0 | 0/0 | 2 | 23 | 2.12 | 0 |
| `media-ext4-64m.img` | PhotoRec | 21 | 17 | 4 | 0 | 0/0 | 0 | 21 | 0.07 | 0 |
| `media-ext4-64m.img` | Foremost | 21 | 10 | 4 | 7 | 0/0 | 1 | 15 | 0.82 | 0 |
| `media-ext4-64m.img` | Sanctum, undelete + carve | 21 | 19 | 2 | 0 | 0/0 | 3 | 24 | 2.32 | 0 |
| `media-fat32-255m.img` | Sanctum, carve only | 22 | 21 | 1 | 0 | 0/0 | 1 | 23 | 4.37 | 0 |
| `media-fat32-255m.img` | PhotoRec | 22 | 19 | 2 | 1 | 0/0 | 0 | 21 | 0.21 | 0 |
| `media-fat32-255m.img` | Foremost | 22 | 10 | 5 | 7 | 0/0 | 1 | 16 | 3.12 | 0 |
| `media-fat32-255m.img` | Sanctum, undelete + carve | 22 | 22 | 0 | 0 | 0/0 | 1 | 24 | 4.67 | 0 |
| `media-fat32-511m.img` | Sanctum, carve only | 22 | 21 | 1 | 0 | 0/0 | 1 | 23 | 7.08 | 0 |
| `media-fat32-511m.img` | PhotoRec | 22 | 18 | 3 | 1 | 0/0 | 0 | 21 | 0.12 | 0 |
| `media-fat32-511m.img` | Foremost | 22 | 10 | 5 | 7 | 0/0 | 1 | 16 | 6.23 | 0 |
| `media-fat32-511m.img` | Sanctum, undelete + carve | 22 | 22 | 0 | 0 | 0/0 | 1 | 24 | 7.28 | 0 |
| `media-ntfs-64m.img` | Sanctum, carve only | 17 | 16 | 1 | 0 | 0/4 | 5 | 22 | 2.07 | 0 |
| `media-ntfs-64m.img` | PhotoRec | 17 | 13 | 3 | 1 | 0/4 | 0 | 16 | 0.07 | 0 |
| `media-ntfs-64m.img` | Foremost | 17 | 8 | 2 | 7 | 0/4 | 5 | 15 | 0.82 | 0 |
| `media-ntfs-64m.img` | Sanctum, undelete + carve | 17 | 17 | 0 | 0 | 2/4 | 5 | 25 | 2.37 | 0 |

#### What "corrupt" means, output by output

Over all 40 images. An output counted *corrupt* is attributed to a FULL planted file but
is not identical to it. Classified by comparing the output's recorded first 64 KiB and
its size with the planted file. JPEG rows whose outputs agree only in the first 163 bytes
(the header every Pillow q95 JPEG shares) are left out: they are an artefact of this
classification, which reads only stored payloads, not of the scorer.

| Row | Format | How the output differs | Outputs |
|---|---|---|---:|
| Foremost | DOCX, XLSX, ZIP | the whole file, then **1 extra byte** | 24, 19, 31 |
| Foremost | WAV | correct prefix, **8 bytes short** | 20 |
| Foremost | JPEG (`frag.jpg`) | head + the gap's bytes | 10 |
| PhotoRec | GZIP | the whole file, then block padding (3,316 B file, 172,032 B output) | 20 |
| PhotoRec | TIFF | the whole file, then block padding (49,292 → 53,248 B) | 20 |
| PhotoRec | TAR | the whole file, then padding (10); correct prefix, short (3, ext4 sparse) | 13 |
| All four rows | SQLite (ext4 `contacts.sqlite`) | 4096 B of the file were holes on ext4; a raw read puts other bytes there | 3 each |
| **Sanctum carve** | **TAR** | **the archive, ending at its end-of-archive marker, without the padding its writer added past it** | **16** |
| Sanctum carve / full | PNG (exFAT `shot.png`, 28 runs) | first cluster right, then the next cluster on the medium | 4 / 4 |

**At fix5 this table carried two more Sanctum rows, and they are the reason for this
batch:** MP4 and TIFF, 20 outputs each, described as "the whole file, then **the rest of
the image** (up to 263,958,528 B)". Both are now returned byte-identical.

Strict byte-identity is the only success in the tables above. A reader who would accept a
whole file followed by padding would move Foremost's 74 archives and PhotoRec's 53
GZIP/TIFF/TAR files into the success column. Sanctum's 16 TAR outputs are the opposite
case — a file that is *short* of the original by its writer's padding, never longer — and
the reasoning for refusing to claim those bytes is in item 1 of "Where Sanctum wins, where it loses" below.

## Where Sanctum wins, where it loses, where the three are equivalent

All comparisons are between the three carve-only rows, over the 25 benchmark volumes
(446 FULL files) unless a corpus is named.

| Row | Byte-identical / 446 FULL | False positives | Wall time |
|---|---:|---:|---:|
| Sanctum, carve only | **423 (94.8%)** | 45 | 170.2 s |
| PhotoRec | 372 (83.4%) | 0 | 2.5 s |
| Foremost | 220 (49.3%) | 36 | 57.1 s |

At fix5 the same three rows were 263, 372 and 220. Only Sanctum changed.

### Where Sanctum loses

1. **TAR: 0 of 16 byte-identical, against PhotoRec's 3.** The only format where PhotoRec
   returns a file Sanctum does not, and the only three objects in its "only PhotoRec"
   column (`backup.tar` on three FAT32 images). Sanctum returns all 16 as *corrupt*: the
   archive without the padding its writer added past the end-of-archive marker. Those
   bytes are zeros, and so is the last cluster's slack, so nothing in the content
   separates them; claiming them would be an assumption about the writer's blocking
   factor.
2. **PNG: 47 of 51.** The four misses are exFAT's `shot.png`, stored in 28 runs.
   Reassembly handles exactly two.
3. **SQLite: 12 of 15.** The three misses are ext4's sparse `contacts.sqlite`, which no
   raw read of the medium can reproduce. PhotoRec scores 12 of 15 for the same reason.
4. **Time: 170.2 s against PhotoRec's 2.5 s — still about 68x.** Down from roughly 700x,
   and still a Python carver against a C one.
5. **False positives: 45 against PhotoRec's 0**, and 503 outputs against 429. Down from
   252, but PhotoRec returns nothing that was not planted and Sanctum returns 45 things
   that were not.
6. **On metadata destroyed the product still equals its carver: 95 and 95.** Undelete
   adds nothing where no filesystem metadata survives, and that is the damage model the
   problem statement describes most closely.

### Where Sanctum wins

1. **A file in two runs.** `frag.jpg`, split around a live 64 KiB pad on both FAT32
   volumes: Sanctum 10 of 10, PhotoRec 0, Foremost 0. Unchanged, and still the only
   structural capability here that neither other tool has.
2. **TIFF: 20 of 20, against 0 for both.** PhotoRec's 20 outputs carry block padding;
   Foremost has no TIFF. Sanctum derives the length from the IFD chain.
3. **GZIP: 20 of 20, against PhotoRec's 0 of 20** (its outputs are padded to its block
   size) and Foremost's none.
4. **Against Foremost on containers.** ZIP 24, DOCX 20, XLSX 17, SQLite 12 against
   Foremost's 0 each. Object by object Sanctum returned 232 files Foremost did not, and
   Foremost none that Sanctum did not.
5. **Small files off a block boundary.** `sticker.gif` inside NTFS MFT records, and files
   in the second partition of the two-partition images, which PhotoRec does not return.
6. **The shipped flat corpus**, 15 of 15 against PhotoRec's 0 — an artefact of that
   corpus placing objects off every sector boundary, recorded in the Limits below rather
   than claimed as a capability.

### Where the three are equivalent

* **PDF**: 40 of 40 for all three.
* **JPEG and PNG laid down contiguously**, apart from the fragmented and off-grid cases.
* **BMP, WAV, WebP, HTML, RTF**: 20 of 20 for both Sanctum and PhotoRec.
* **Nothing returned for GONE files**: 0 outputs for all 64 GONE objects, every tool,
  both runs. That is the check that the ground truth credits no recovery that cannot
  exist.

## Time

Wall clock over the 25 benchmark volumes: **Sanctum carve 170.2 s**, PhotoRec 2.5 s,
Foremost 57.1 s. At fix5 Sanctum was 2,071.8 s; PhotoRec and Foremost are unchanged
(2.7 s and 57.2 s). Per-image figures are in the Every run table above.

The whole of that reduction is the length fixes rather than any optimisation of the
measurement. Profiled on `media-fat32-255m.img`, carve only:

| | fix5 | fix6 |
|---|---:|---:|
| Wall clock | 108.07 s | **5.9 s** |
| Candidates | 25 | 23 |
| Total bytes in candidates | 2,750 MiB | **1.4 MiB** |
| `core/carve/score.py:measure_entropy` | 236.5 s of a 249.9 s profile | not in the top 16 by cumulative time |

`measure_entropy` was a pure-Python per-byte histogram over candidates that ran to the
end of the image. Once those candidates stopped existing it left the profile, so the
sampling change considered for it was **not** made — sampling would change the measured
value and invalidate the calibration for no measured gain. The histogram does now tally
with `collections.Counter`, which is the same arithmetic in C; that the value did not
move is pinned by `tests/carve/score/test_entropy_measurement.py` against an independent
implementation of the definition. The remaining costs are the Aho-Corasick scan itself
(2.68 s) and JPEG scan accounting (1.85 s), both real work over the whole image.

## What this means for "increase recovery rates from damaged storage media"

The phrase is comparative, so it needs a baseline: PhotoRec and Foremost at their
defaults, on the same images, scored by the same function.

**On these corpora and these four damage models, Sanctum's carver now recovers more
surviving files byte-for-byte than either.** Over the 20 damaged volumes it returned 327
of 343 (95.3%), PhotoRec 288 (84.0%) and Foremost 173 (50.4%). At fix5 the same figure
was 207 (60.3%), and the difference is entirely the defects listed in
commit `20a6439` — candidates that ran to the end of the image, and seven formats
with no signature.

**This reversal was checked before it was believed.** The scorer is byte-identical to the
one that produced the fix5 tables apart from one display column; PhotoRec and Foremost
were re-run and scored identically in every column; no output was credited to any of the
64 GONE objects; and the losses above survive. A benchmark that stopped being
unflattering after its subject was fixed would be a benchmark to distrust.

**Where metadata survives, undelete still adds** 33 to 36 files per damage model over
Sanctum's own carver, and **zero** where metadata is destroyed.

**Not measured, and not claimed:** real damaged media; unreadable sectors met during
acquisition; media larger than 511 MiB; fragmentation beyond one two-run JPEG and one
chained PNG; camera or phone files; Scalpel or any commercial tool.

A sentence the tables support: *"On synthetic FAT32, exFAT, NTFS and ext4 images with
modelled truncation, zeroed sectors, destroyed metadata and overwrite, our carver
recovered 95% of surviving files byte-for-byte, against PhotoRec's 84% and Foremost's
50%, and it was the only tool to reassemble a two-fragment JPEG. It is still about 68
times slower than PhotoRec, and it returns a tar archive without its trailing padding."*

## Limits

Each of these bounds what the tables can be quoted for.

* **Synthetic content.** Every planted file comes from a real encoder, but images are
  noise, documents are a few lines, and no file came from a camera or a phone: no EXIF
  thumbnails, no MPF secondary images, no HEIC, no progressive JPEG. The camera-JPEG
  verdicts are in `CAMERA_JPEG_REPORT.md` and are not re-measured here.
* **Small populations.** 21 files per benchmark volume, 3 per small filesystem image. A
  difference of one or two files in a row is not a rate.
* **Image files, not media.** Every image is an ordinary file on this host's NVMe disk.
  No loop device, USB stick, card or disk was read, so no controller, no read error and
  no acquisition is in any figure. "Damaged" here means damage **modelled** in the image
  bytes: zero-filled bands placed deliberately, a truncation placed relative to the
  files, metadata zeroed rather than overwritten with garbage, and an overwrite written
  without the filesystem record that would accompany it. Sanctum's retry-and-fill
  acquisition path for unreadable sectors (`core/carve/acquire.py`) is not exercised.
* **One machine, one run.** Every figure is a single run. Earlier batches measured
  run-to-run noise of about ±0.4 s per image for Sanctum.
* **Fragmentation is thin.** One two-run JPEG on each FAT32 volume and one 28-run PNG on
  exFAT. NTFS and ext4 allocation was not controlled.
* **Builder artefacts.** `debugfs write` stores zero blocks as holes, so two ext4 files
  are sparse; NTFS resident files carry fixup bytes. Both are recorded in the manifests
  and neither is how an application usually writes a file.
* **Strict scoring.** Byte-identical is the only success. A tool that returns a usable
  file with extra trailing bytes scores *corrupt*. An output that starts inside a
  planted file is a *fragment* false positive, so a recovery of a PARTIAL file's
  surviving tail is not credited as a recovery of that file.
* **A tar is returned short.** Sanctum ends a tar at the end-of-archive marker and does
  not claim the padding its writer added past it, because those bytes are
  indistinguishable from cluster slack. Archives written by GNU tar at its default
  blocking factor are therefore never byte-identical from the carver; where the
  filesystem record survives, undelete returns them at their recorded size.
* **HTML is footer-bounded, not derived.** `</html>` is a convention rather than a
  requirement, and only the lower-case `<!DOCTYPE html` and `<html>` spellings are
  matched. A document without the closing tag is bounded by the next object and says so.
* **Tool coverage.** PhotoRec 7.2 in `/cmd` mode and Foremost 1.5.7 only, each at
  defaults. Scalpel, PhotoRec's paranoid-off and brute-force options, and Foremost's
  quick mode were not run. Foremost was run from an unpacked Fedora RPM, not an
  installed package.
* **Not measured:** volumes larger than 511 MiB, real damaged media, multi-process
  carving, and memory use.

## Reproduce

```
dnf download foremost && rpm2cpio foremost-*.rpm | cpio -idm   # if Foremost is not installed
python -m testkit.benchmark build  --work /var/tmp/sanctum-bench/work
python -m testkit.benchmark run    --work /var/tmp/sanctum-bench/work --foremost ./usr/bin/foremost
python -m testkit.benchmark score  --work /var/tmp/sanctum-bench/work --csv docs/performance/benchmark.csv
python -m testkit.benchmark report --work /var/tmp/sanctum-bench/work --out tables.md
```

The build takes about 30 seconds and needs no root. The run took 74 minutes (19:38:46 to 20:52:47), almost all of it Sanctum on this host.

For the fix6 re-run the `build` step was deliberately **not** repeated: the images,
payloads and manifests from the fix5 run were reused unchanged, so the new code ran over
the very same bytes and the only variable is Sanctum. The run took about 7.5 minutes
(08:27:23 to 08:34:55), against 74 minutes at fix5.
