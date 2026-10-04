# Carve confidence calibration — pooled, eight seeds

**Run date:** 2026-09-21 · **Seeds:** 0,1,2,3,4,5,6,7 · **Harness:**
`testkit/calibrate.py` · **Table:** [`calibration-pooled.csv`](calibration-pooled.csv)
· **Chart:** [`calibration-pooled.png`](calibration-pooled.png)
· **Tool version:** `sanctum-forensics/0.0.0`, Python 3.11.16
· **Tree:** measured on the working tree that introduced this document; the
single-seed run it supersedes is recorded in [`calibration.md`](calibration.md)
at commit `20a6439`.

Reproduce it with:

```
python -m testkit.calibrate --corpus-dir <scratch dir> --seeds 0,1,2,3,4,5,6,7
```

## Reproducibility, and a defect this run found in the harness

The first pooled run reported 73 distinct recoverable objects and the second,
minutes later, 70. Same seeds, same code. The cause was the corpus generator:
`zipfile.ZipFile.writestr` stamps every member with the current local time, so
every ZIP, DOCX, DOCM and XLSX had a different SHA-256 on every run, and the
OOXML packages - identical across seeds apart from that stamp - coincided or
not depending on which two-second window each seed was built in.

`testkit/generate_corpus.py` now stamps members with a fixed time
(`FIXED_ZIP_TIME`). Two consecutive runs of the command above now produce a
byte-identical `calibration-pooled.csv` (MD5 `a85d7955c6177381fd081364bae461d9`
both times). The candidate counts, true positives and precision figures were
the same in every run before and after the fix; only the recall denominator
moved. The single-seed `calibration.csv` is unchanged by it.

The two carve fixes made on the same day (a truncated PDF may no longer borrow
the next PDF's `%%EOF`, and `parse_pdf` no longer treats an identical PDF further
along as an incremental update; see `docs/validation/large-image.md`) left every
figure here unchanged — the CSV was regenerated after both and its MD5 is the
one above: in these corpora every object sits 512 KiB from its
neighbour, which is precisely why the defect never showed up in them.

## Why this run exists

The previous calibration measured **one** corpus: 24 planted objects, 15 of
them recoverable, 21 candidates. That is enough to show the buckets are
ordered and too few to say what HIGH is worth. One decoy landing in the wrong
bucket moves precision by roughly four points, so the number carried more
significant figures than the population supported.

Nothing about the scoring changed. The pipeline is the same call chain the
product runs — `carve_structures`, `validate_candidate`, `classify_candidate`,
`score_candidate`, `resolve_overlaps`, `dedupe` — and the weights are the same
`CALIBRATED_WEIGHTS`. What changed is the population: eight seeds, each
planting a different set of objects at different offsets, measured as one
population rather than averaged.

Pooled rather than averaged, deliberately. Precision is a ratio of counts, and
the mean of per-seed ratios is not the ratio of the pooled counts unless every
seed produced the same number of candidates — which they did not (21 to 23 per
seed). The pooled figure is the one an examiner would compute from the raw
rows.

## Method

Unchanged from [`calibration.md`](calibration.md), which remains the reference
for how the corpus is built and what counts as a true positive. In short:

- `testkit/generate_corpus.py` plants objects at known offsets in a ~12.5 MB
  image and records a manifest with each one's SHA-256.
- A candidate is a **true positive when its SHA-256 matches a recoverable
  manifest entry**. Not "starts at the right offset", not "is the right type":
  a recovered file that differs by one byte does not open.
- Precision is true positives over candidates in the slice. Recall is distinct
  manifest digests recovered by the slice over the **distinct** recoverable
  digests across all eight corpora. The OOXML packages and the GIF carry no
  seeded content, so they are the same bytes in every corpus and count once;
  that is why 8 × 15 planted recoverable objects are 64 distinct ones.

Each seed carves its own directory, so a run is reproducible from the seed list
alone and two seeds cannot overwrite each other's image.

## Population

|  | single seed (previous) | pooled, 8 seeds (this run) |
|---|---:|---:|
| corpora | 1 | 8 |
| candidates scored | 21 | **173** |
| distinct recoverable objects | 15 | **64** |

## Per-seed spread

The pooled number with the spread beside it, so nobody has to assume the seeds
agreed. They did: HIGH precision is 100% on every seed individually, and every
seed recovered every recoverable object it planted.

| seed | candidates | true positives | HIGH precision | ALL recall |
|---:|---:|---:|---:|---:|
| 0 | 21 | 15 | 100.0% | 100.0% |
| 1 | 21 | 15 | 100.0% | 100.0% |
| 2 | 21 | 15 | 100.0% | 100.0% |
| 3 | 23 | 15 | 100.0% | 100.0% |
| 4 | 23 | 15 | 100.0% | 100.0% |
| 5 | 21 | 15 | 100.0% | 100.0% |
| 6 | 21 | 15 | 100.0% | 100.0% |
| 7 | 22 | 15 | 100.0% | 100.0% |

## Measured result

Thresholds unchanged: HIGH at 8000 basis points, MEDIUM at 5000. The total is
clamped at 10000, never scaled.

| bucket | n | TP | precision | recall |
|---|---:|---:|---:|---:|
| HIGH | 104 | 104 | 100.0% | 85.9% |
| MEDIUM | 16 | 16 | 100.0% | 14.1% |
| LOW | 53 | 0 | 0.0% | 0.0% |
| **ALL** | 173 | 120 | 69.4% | **100.0%** |

### By format

| format | n | TP | precision | recall |
|---|---:|---:|---:|---:|
| docm | 8 | 8 | 100.0% | 1.6% |
| docx | 8 | 8 | 100.0% | 1.6% |
| gif | 8 | 8 | 100.0% | 1.6% |
| jpg | 45 | 24 | 53.3% | 37.5% |
| mp4 | 8 | 8 | 100.0% | 1.6% |
| pdf | 16 | 8 | 50.0% | 1.6% |
| png | 32 | 16 | 50.0% | 25.0% |
| sqlite | 16 | 16 | 100.0% | 3.1% |
| tiff | 8 | 0 | 0.0% | 0.0% |
| xlsx | 8 | 8 | 100.0% | 1.6% |
| zip | 16 | 16 | 100.0% | 25.0% |

### By source

| source | n | TP | precision | recall |
|---|---:|---:|---:|---:|
| signature | 16 | 8 | 50.0% | 1.6% |
| structure | 157 | 112 | 71.3% | 98.4% |

### By decoder verdict

| verdict | n | TP | precision | recall |
|---|---:|---:|---:|---:|
| corrupt | 45 | 0 | 0.0% | 0.0% |
| decoder_unavailable | 16 | 16 | 100.0% | 14.1% |
| truncated | 8 | 0 | 0.0% | 0.0% |
| valid | 104 | 104 | 100.0% | 85.9% |

## What this run changed

**No weight moved.** That is the result, and it is stated plainly rather than
dressed up as an improvement. The weights in `core/carve/score.py` were
measured on the single-seed corpus and this run reproduces the same behaviour
on a population eight times the size. The calibration is now supported by more
evidence; it is not *better* in the sense of scoring anything differently, and
this document does not claim it is.

Three things the larger population does establish that the small one could not:

1. **HIGH precision is 100% over 104 candidates, not 13.** The claim "a HIGH
   candidate matched a planted object byte for byte" now rests on 104
   observations across eight independently generated corpora.
2. **LOW precision is 0% over 53 candidates.** Every decoy, every truncated
   object and every corrupt span landed in LOW, on every seed. The bucket is
   doing the job it exists for.
3. **The `corrupt` and `truncated` decoder verdicts are 0% precision over 53
   candidates between them.** A failing decoder is a reliable negative signal
   at this population, which is what justifies `decoder_valid` being the
   largest single weight.

## What it does not establish

- **HIGH = 100% did not hold at scale before a fix.** On the 7 GiB validation
  image, with objects megabytes apart in random filler, 39 of 292 HIGH
  candidates matched no planted file (86.6% HIGH precision) until the
  footer-bound fix of 2026-09-21. These small corpora could not reveal it. See
  [`../validation/large-image.md`](../validation/large-image.md) for the
  before-and-after figures. Treat the 100% here as a property of these corpora.

- **These are generated corpora, not seized media.** The objects are produced
  by real encoders and planted at real cluster-aligned offsets, and they are
  still synthetic. Precision on a disk somebody actually used will differ, and
  nothing here predicts by how much.
- **Recall is measured against what was planted.** 100% recall means the
  pipeline recovered every object the manifest marks recoverable. It says
  nothing about objects that were never planted, or about formats absent from
  the corpus.
- **The per-format rows are thin.** `gif`, `mp4`, `tiff`, `docm`, `docx` and
  `xlsx` have 8 candidates each — one per seed. A per-format precision figure
  at n=8 is an observation, not a rate, and should not be quoted as one.
- **The filesystem-aware undelete pass is not in this sweep.** It is calibrated
  separately; see [`calibration-filesystems.csv`](calibration-filesystems.csv)
  and the filesystem section of [`calibration.md`](calibration.md).
- **No hardware is involved.** The hardware figures are in
  [`../validation/hardware.md`](../validation/hardware.md) and were produced by
  a different harness against different media.

## The score remains deterministic and explainable

Nothing in this run introduced a learned model, a fitted curve or a tuned
constant. `score_candidate` awards a fixed number of basis points per component
established, the components are listed in the report and in the UI with their
individual values, and the same candidate scores the same number on every run.
A reader who disagrees with a score can see which component they disagree with.
