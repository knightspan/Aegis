# Carve confidence calibration

**Run date:** 2026-09-04, re-measured 2026-09-16 · **Corpus seed:** 0
· **Superseded population:** the eight-seed pooled re-run of 2026-09-21 is in
[`calibration-pooled.md`](calibration-pooled.md); weights unchanged by it · **Harness:** `testkit/calibrate.py`
· **Table:** [`calibration.csv`](calibration.csv) · **Chart:** [`calibration.png`](calibration.png)

An uncalibrated score is a number somebody made up. This document records the
measurement that turns `core/carve/score.py` into something an examiner can
check, the weights that moved because of it, and why each one moved.

Reproduce it with:

```
python -m testkit.calibrate --corpus-dir <scratch dir> --seed 0
```

## Method

`testkit/generate_corpus.py` plants 24 objects at known offsets in a 12.5 MB
image and records a manifest: SHA-256, offset, length, format, and what kind of
object it is. Fifteen distinct byte sequences are marked recoverable; the rest
are there to be scored against rather than found.

| kind | count | what it is |
|---|---|---|
| `intact` | 16 | a whole file, produced by a real encoder |
| `duplicate` | 2 | the same PNG planted at two further offsets |
| `truncated` | 3 | a real file with its tail removed |
| `decoy` | 3 | a valid header on bytes of another kind entirely |

The pipeline then runs over the image — carve, validate, classify, score,
resolve overlaps, dedupe. **A candidate is a true positive when its SHA-256
matches a recoverable manifest entry.** Nothing softer counts: not "starts at
the right offset", not "is the right type". A recovered file that differs from
the original by one byte does not open.

### Which pipeline these numbers came from

The carve stage here is `core.carve.structure.carve_structures`
(`testkit/calibrate.py`), and **the shipped API pipeline now runs the same
call.** `api/carve_job.py` was routed through `carve_structures` after these
weights were measured; before that it called
`core.carve.signature.carve_signatures`, so thirty of the thirty-three
candidates below — `source,structure,30` against `source,signature,3` in
[`calibration.csv`](calibration.csv) — came from a code path the product did not
execute. That divergence is closed: the calibration harness and the product now
run carve, validate, classify, score, resolve overlaps and dedupe in the same
order through the same functions.

Two things that follow, and one that does not:

- The per-bucket figures below now describe the pipeline that ships, for the
  carving half of it.
- The product additionally runs the filesystem-aware undelete pass ahead of
  carving, which this sweep does not. Undelete is calibrated separately; see the
  filesystem section and [`calibration-filesystems.csv`](calibration-filesystems.csv).
- **These numbers have not been re-measured since the pipelines converged.** The
  sweep was not re-run as part of that change, and it did not need to be — the
  carve stage is the same call — but a re-run is what would turn "the same
  pipeline" into "the same pipeline, remeasured". The command at the top of this
  document reproduces it.

The **hardware figures** in [`../validation/hardware.md`](../validation/hardware.md)
were produced by `scripts/hardware_validation.py`, which drives
`api.carve_job.carve_generator`. They therefore describe whichever pipeline was
in the tree when each run happened; the Phase B runs predate this change. See
that document's own notes before quoting them against the current build.

Precision is true positives over candidates in the slice. Recall is distinct
manifest files recovered by the slice, over the 15 that exist.

## Measured result, calibrated weights

| bucket | n | TP | precision | recall |
|---|---:|---:|---:|---:|
| HIGH | 13 | 13 | 100.0% | 86.7% |
| MEDIUM | 2 | 2 | 100.0% | 13.3% |
| LOW | 6 | 0 | 0.0% | 0.0% |
| **ALL** | 21 | 15 | 71.4% | **100.0%** |

By source and by decoder verdict:

| dimension | key | n | TP | precision | recall |
|---|---|---:|---:|---:|---:|
| source | structure | 19 | 14 | 73.7% | 93.3% |
| source | signature | 2 | 1 | 50.0% | 6.7% |
| validation | valid | 13 | 13 | 100.0% | 86.7% |
| validation | decoder_unavailable | 2 | 2 | 100.0% | 13.3% |
| validation | truncated | 1 | 0 | 0.0% | 0.0% |
| validation | corrupt | 5 | 0 | 0.0% | 0.0% |

### What moved when the runaway-length defect was fixed, and what did not

The table above was re-measured on 2026-09-16, after the fixes recorded in
commit `20a6439` (`git show 20a6439`). **No weight changed, and no threshold changed.** What
changed is the population being scored:

| Row | Before (2026-09-04) | After (2026-09-16) | Why |
|---|---:|---:|---|
| LOW, n | 18 | 6 | Twelve of the LOW candidates were ZIP member headers. Every member of an archive carries `PK\x03\x04`, and each one started a candidate whose parse could not read the archive's end record; they were scored, bucketed LOW and reported. They are not objects, so they are no longer emitted. |
| ALL, n | 33 | 21 | The same twelve. |
| ALL, precision | 45.5% | 71.4% | Arithmetic: the same 15 true positives over 12 fewer candidates. |
| `source,structure` n | 30 | 19 | As above. |
| `validation,corrupt` n | 17 | 5 | Those member candidates decoded as corrupt, which is what they were. |
| `format,zip` n | 13 | 2 | Eleven member headers inside two archives. |
| `format,tiff` n | 2 | 1 | TIFF now has a parser, so one candidate covers the object instead of two spans. |
| **HIGH and MEDIUM, every column** | — | **unchanged** | 13/13 and 2/2, 100.0% precision each, recall 86.7% and 13.3%. |
| **ALL, recall** | 100.0% | **100.0%** | Every planted object still comes back byte for byte. |

The two rows the acceptance criteria are stated against - HIGH precision and
MEDIUM precision - did not move at all, and neither did recall. A carver that
stops reporting objects that were never on the medium scores better on
aggregate precision without having been tuned to; that improvement is the
removal of false candidates, not a change to what the score means.

Per-format rows are in the CSV. The one that matters for reading the rest:
`zip` shows 13 candidates for 2 true positives, because a signature scan hits
the `PK\x03\x04` at the head of *every member* of an archive as well as the
archive itself. Those inner hits are resolved as overlaps, kept, and marked —
they are what fills the LOW bucket, and every one of them is genuinely not a
file.

## Weights: before and after

| component | original | calibrated | moved |
|---|---:|---:|---|
| `header` | 2000 | 2000 | — |
| `exact_length` | 1500 | 1500 | — |
| `decoder_valid` | 3500 | **4000** | yes |
| `decoder_truncated` | 1500 | **1000** | yes |
| `decoder_unavailable` | 0 | **1000** | yes |
| `entropy` | 1000 | 1000 | — |
| `fs_metadata` | 1500 | 1500 | — (measured separately, below) |
| `no_overlap` | 500 | 500 | — |

The same corpus, same pipeline, original weights:

| bucket | n | TP | precision | recall |
|---|---:|---:|---:|---:|
| HIGH | 9 | 9 | 100.0% | 60.0% |
| MEDIUM | 5 | 4 | 80.0% | 26.7% |
| LOW | 19 | 2 | 10.5% | 13.3% |

### Why each weight moved

**`decoder_valid` 3500 → 4000.** Under the original weights, a candidate whose
header matched, whose length a parser derived, and which a real decoder read
end to end scored 2000 + 1500 + 3500 + 500 = 7500 — MEDIUM — unless its entropy
profile also matched. Every one of the 13 candidates meeting that description
was a true positive (100.0% precision on the `valid` row), and the missing 500
left four of them out of HIGH. At 4000, header + derived length + clean decode
+ no overlap is exactly 8000, the HIGH floor. HIGH recall rose from 60.0% to
86.7% with precision unchanged at 100.0%.

**`decoder_truncated` 1500 → 1000.** Truncated candidates scored zero true
positives, and at 1500 one of them reached MEDIUM (2000 + 1500 + 1000 + 500 =
5000), which is what cost MEDIUM its 80.0% precision. This is `n=1`, so it is a
small correction rather than a strong claim; the direction is not in doubt,
because a file the decoder could not finish reading is by definition not the
file that was there.

**`decoder_unavailable` 0 → 1000.** Scoring a missing verdict as zero put two
true positives — an MP4 whose box tree walks cleanly with no `ffprobe` on PATH,
and a password-protected ZIP — in LOW, alongside genuine false positives. That
is the opposite of honest: "no decoder ran" is not evidence the bytes are bad.
At 1000 they land in MEDIUM, and no decoder-unavailable candidate can reach
HIGH by construction: 2000 + 1500 + 1000 + 1000 + 1500 + 500 is 7500 even with
every other component awarded. LOW precision fell to 0.0%, which is the goal —
nothing recoverable is left in the bucket the report tells an examiner to skip.

### Two entropy thresholds also moved

Both are measurements, not preferences:

* `MIXED_ENTROPY_FLOOR_MILLIBITS` 3000 → 2000. A real SQLite database of text
  rows measures 2.96 bits/byte. The old floor rejected it for being what it is.
* `sqlite` and `evtx` moved from the `mixed` profile to `low`. A database page
  is text and padding; an event log is repeated record templates. Both sit near
  3 bits/byte, and calling them "no expectation" threw away a usable signal.

## Two parser bugs this run found

Calibration is worth running for the weights. It paid for itself on these:

* **`parse_zip` took the last EOCD record inside `max_size`.** A ZIP's cap is a
  gigabyte, so in an image holding several archives the first archive was given
  an end address belonging to another one megabytes away — a 6.8 MB "recovered"
  file of 582 bytes of content. Fixed by requiring the record's central
  directory to start at `PK\x01\x02` and to end exactly where the record
  begins, and by taking the first such record.
* **`parse_pdf` took the last `%%EOF` without the corroboration its docstring
  claimed.** Two identical PDFs in the image merged into one 5 MB candidate
  that pikepdf then validated as `valid` — a false positive scored HIGH, the
  single worst outcome this scoring exists to prevent. Fixed by following
  `startxref` from each marker and by requiring incremental revisions to be
  contiguous.

Both were shipped code that every existing test passed. Ground truth is what
found them.

## Honest limits of this measurement

* The corpus is synthetic and small: 33 candidates, 15 recoverable files. MEDIUM
  carries two candidates, so its 100.0% precision is a weak claim and is quoted
  here as "above the 70% target", not as a rate.
* No fragmented file and no filesystem-metadata source is exercised **in this
  run**, so the `fs_metadata` weight is not calibrated by it. That gap is now
  closed by a second run over real filesystem images; see
  "Filesystem-aware recovery" below.
* MP4 is scored on a structural walk alone on any machine without `ffprobe`.
  The number that machine produces is a different number, and the candidate
  says so in its `validation_detail`.
* Real media is messier than any generator: fragmentation, partial overwrites
  and slack are what a live case looks like. These figures describe this
  corpus, on this build, on this date.

---

# Filesystem-aware recovery

**Run date:** 2026-09-04 · **Corpus seed:** 0 · **Harness:**
`testkit/calibrate.py --filesystems` · **Table:**
[`calibration-filesystems.csv`](calibration-filesystems.csv)

Reproduce it with:

```
python -m testkit.calibrate --corpus-dir <scratch dir> --filesystems
```

The corpus above is a flat image, so it produces no `fs_metadata` candidates at
all — which is why the `fs_metadata` weight went through the first run
uncalibrated. This second run builds thirteen **real filesystem images** with
the real `mkfs` for each, populates them through tools that write the real
on-disk structures, deletes a recorded subset the way the kernel deletes it, and
runs the whole pipeline over the result.

No image needs root. See `docs/technical.md` for how, and
`tests/carve/fsaware/test_corpus_needs_no_root.py` for the test that fails
loudly if that ever stops being true.

## Per-filesystem recall

A recovery counts only when it reproduces the planted file **byte for byte**.
The denominator is every deleted file, not only the ones the manifest expects
to be recoverable — using the latter would be marking our own homework.

| filesystem | deleted | candidates | named | exact | recall | precision |
|---|---:|---:|---:|---:|---:|---:|
| ntfs | 25 | 25 | 25 | 24 | **96.0%** | 96.0% |
| fat32 | 246 | 244 | 244 | 235 | **95.5%** | 96.3% |
| ext2 | 2 | 2 | 2 | 2 | **100.0%** | 100.0% |
| ext3 | 2 | 2 | 2 | 2 | **100.0%** | 100.0% |
| exfat | 2 | 2 | 2 | 1 | **50.0%** | 50.0% |
| ext4 | 2 | 2 | 2 | 0 | **0.0%** | 0.0% |

Reading the rows:

* **NTFS** misses one of twenty-five, and that one is deliberate: its MFT
  record was reused by another file, so only its name survives, recovered from
  `$I30` index slack. Reporting the name is right; reporting content for it
  would be attributing one file's bytes to another.
* **FAT32**'s large counts are the filler files written to force
  fragmentation. They are real deleted files and are in the manifest — omitting
  them would have scored two hundred correct recoveries as false positives. The
  misses are the fragmented file whose neighbours were also deleted, and the
  handful of fillers whose clusters it took.
* **exFAT**'s two files are the whole point of the row: one had `NoFatChain`
  set and came back exactly, one used a chain that deletion destroyed and did
  not. 50% here is two data points, not a rate.
* **ext3**'s 100% is an **upper bound**, not a measurement of ext3 on a modern
  kernel. See `docs/limitations.md`.
* **ext4**'s 0.0% is the finding. It is what `ext4_ext_remove_space` guarantees.

`ext2`, `ext3` and `exfat` carry two files each. Those rows are illustrations,
not rates.

## The fs_metadata weight, measured at last

Swept from 0 to 5000 over the whole filesystem corpus:

| fs_metadata | HIGH n | precision | recall | empty ≥ MEDIUM | unconfirmed @ HIGH |
|---:|---:|---:|---:|---:|---:|
| 0 | 37 | 100.0% | 13.3% | 0 | 0 |
| 500 | 37 | 100.0% | 13.3% | 0 | 0 |
| 1000 | 37 | 100.0% | 13.3% | 0 | 0 |
| **1500** | **37** | **100.0%** | **13.3%** | **0** | **0** |
| 2000 | 37 | 100.0% | 13.3% | **2** | 0 |
| 2500 | 37 | 100.0% | 13.3% | 3 | 0 |
| 3000 | 37 | 100.0% | 13.3% | 3 | 0 |
| 3500 | 37 | 100.0% | 13.3% | 3 | 0 |
| 4000 | 44 | 86.4% | 13.6% | 3 | **7** |
| 5000 | 274 | 95.6% | 93.9% | 3 | 237 |

The last two columns are the ones that decide it:

* **empty ≥ MEDIUM** counts candidates that recovered **zero bytes** and were
  still scored MEDIUM or better — a filename out of `$I30` slack with nothing
  behind it. It goes non-zero at **2000**.
* **unconfirmed @ HIGH** counts candidates in HIGH that no decoder confirmed.
  It goes non-zero at **4000**, where 2000 header + 1500 derived length + 500
  no-overlap + 4000 reaches the 8000 floor with a decoder verdict of *corrupt*.

Below 2000 the sweep is flat: precision stays at 100.0% and the bucket contents
do not change. **The measurement bounds the weight from above and says nothing
from below, so `fs_metadata` stays at 1500 — now as the largest value the
evidence permits rather than as a number somebody chose.**

### The row that looks best is the one to distrust

At 5000 the aggregate improves sharply: 95.6% precision and 93.9% recall
against 100.0% and 13.3%. It is worse. The gain comes from promoting 237
candidates that no decoder confirmed — mostly filler files, which happen to be
correct — and among them is a FAT32 recovery **the corpus knows is wrong**,
scored HIGH. The aggregate is carried by the easy cases while the component
starts doing exactly what it must not: treating "a filesystem record says a file
lived at this offset" as evidence that the bytes there now are that file.

## A scoring defect this run found

`gather_evidence` awarded the **entropy component to candidates holding no
bytes**. Zero bytes measure as zero bits per byte, which clears the "low
entropy" floor for formats like `.txt` and `.sqlite`, so a name recovered from
`$I30` slack — with nothing behind it at all — was collecting 1000 bp for its
byte distribution and being pushed towards MEDIUM.

Fixed: an unmeasurable component scores zero rather than full marks for being
empty. `entropy_millibits_per_byte` and `high_entropy_windows_bp` are left
`None` on such a candidate, which is the difference between "not measured" and
"measured zero" that the field comments already promised.

This did not change the flat corpus's numbers by a single basis point — it has
no empty candidates — which is precisely why it took a filesystem corpus to
find.

## Honest limits of this measurement

* Four of the six filesystems carry two deleted files each. Those rows show
  which mechanism applies, not a rate.
* FAT32's counts are dominated by filler files of identical shape. They are
  real, they are in the manifest, and they are also 244 of the 246 rows — so
  FAT32's 95.5% describes recovery of 256 KiB blocks of repeated bytes more
  than it describes recovery of documents.
* The ext4 journal scan is not exercised by this corpus at all. The corpus is
  built with `debugfs`, which writes no journal; that parser is measured
  separately against a journal constructed byte by byte in
  `tests/carve/fsaware/test_ext4_journal.py`.
* Every image is small and freshly made. Real media is older, fuller and
  messier, and its metadata has been overwritten more times.
