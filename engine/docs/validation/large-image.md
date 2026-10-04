# Large-image validation: 7 GiB carve

**Date:** 2026-09-21 · **Harness:** `testkit/largeimage.py` · **Raw results:**
[`large-image-7gib.json`](large-image-7gib.json) (after the footer-bound fix),
[`large-image-7gib-before-footer-fix.json`](large-image-7gib-before-footer-fix.json)
(before), [`large-image-7gib-isolated.json`](large-image-7gib-isolated.json)
and [`large-image-1gib-isolated.json`](large-image-1gib-isolated.json) (final
runs, both fixes in, nothing else on the host) · **Host:** Fedora 44 laptop, Linux 6.19.10,
16 logical CPUs, NVMe, Python 3.11.16

```
python -m testkit.largeimage --work-dir ~/.cache/sanctum-large \
    --size-gib 7 --seeds 40 --json docs/validation/large-image-7gib.json
```

## What was carved

- **Image:** 7,516,192,768 bytes (7.0 GiB) of seeded pseudo-random filler.
- **Planted:** 960 objects — forty independent `generate_corpus` seeds of 24
  objects each (JPEG, PNG, GIF, PDF, ZIP, DOCX, DOCM, XLSX, SQLite, MP4, TIFF,
  plus truncated objects and decoys), 4 KiB-aligned, evenly spaced about
  7.4 MiB apart. **294 distinct recoverable** SHA-256 digests.
- **Pipeline:** `api.carve_job.carve_generator` — the product's own carve path,
  with undelete, structure carving, reassembly, validation, scoring and PII
  triage all on, writing every recovered object to an output directory. Run in a
  child process so `ru_maxrss` is the carve's own peak.
- Random filler is the hard case for a signature carver: three-byte magics occur
  by chance, so the image holds hundreds of headers that were never files.

Scoring needs no judgement: a candidate is a **true positive** when its SHA-256
matches a recoverable plant, and **unplanted** when it matches nothing that was
planted.

## Result

| | before the footer fix | after the footer fix |
|---|---:|---:|
| Carve wall clock | 320.6 s ¹ | 158.7 s ² |
| Throughput | 22.4 MiB/s ¹ | 45.2 MiB/s ² |
| Peak RSS (carve process) | 570.1 MiB | 512.4 MiB |
| Candidates | 951 | 951 |
| Objects written | 951 | 951 |
| Distinct recoverable recovered | **294 / 294** | **294 / 294** |
| HIGH: n / true positives / unplanted | 292 / 253 / **39** | 253 / 253 / **0** |
| MEDIUM: n / TP / unplanted | 2 / 2 / 0 | 41 / 40 / 1 |
| LOW: n / TP / unplanted | 657 / 39 / 617 | 657 / 1 / 655 |
| Spilled temp files left afterwards | 0 | 0 |
| Failures / errors | none | none |

¹ Measured while the fuzz pass was running on the same host.
² Measured while the recovery benchmark was running on the same host.
Neither timing is clean; the isolated runs below are the ones to quote.

The limitations the run reported are the honest ones for a raw image of noise:
no partition table could be parsed, no filesystem could be opened (TSK: "Possible
encryption detected (High entropy (8.00))"), so the whole image was carved as
unallocated.

## The defect this run found

**Before the fix, 39 of 292 HIGH candidates matched no planted file**, and 39
recoverable objects sat in LOW. Neither happened on any of the small corpora.

Every one of the 39 was a *truncated* planted PDF — header present, `%%EOF`
gone. The signature scan searched for its footer up to the format's 100 MiB cap,
found the **next** PDF's `%%EOF` about 11.7 MB later, and claimed the whole span.
pikepdf repairs from any trailer it can reach, so it called the span valid and it
scored 9000 (HIGH). That oversized span then overlapped a small intact ZIP
planted between them, won the overlap, and pushed the ZIP down to LOW — which is
where the 39 misplaced true positives came from.

The small corpora could not show this: their objects sit 512 KiB apart, so a
truncated PDF's footer search ran into the next object's header long before any
other PDF's trailer.

**Fix** (`core/carve/signature.py:_find_footer`): the footer search stops at the
next header of the **same** format, for formats whose objects cannot legitimately
contain their own header. ZIP, TAR, HTML, JPEG (EXIF thumbnails) and the OOXML
containers are exempt because they do nest. Regression:
`tests/carve/signature/test_footer_bound.py` — fails on the old code, passes on
the new. The pooled calibration and the recovery benchmark were re-run after the
fix; see below.

After the fix: HIGH is 253 candidates, 253 true positives, 0 unplanted.

## A second defect, found by the 1 GiB timing run

The first isolated 1 GiB run reported **one** HIGH candidate matching no planted
file: a 453-byte PDF carved by the **structure** parser at 11,141,573 bytes. The
corpus generator's PDF carries no seeded content, so all forty seeds plant the
same bytes. `parse_pdf` follows incremental updates by accepting a later
`%%EOF` whose `startxref` corroborates — and an identical PDF 11 MB later has a
`startxref` that, measured from the *first* PDF's start, lands exactly on the
first PDF's xref. The only other gate, `_revision_follows`, looked at the first
bytes after the previous `%%EOF`; random filler that begins with `%` or
whitespace passes it.

**Fix** (`core/carve/structure.py:_revision_follows`): an incremental update
never contains a second `%PDF-` header, so one between the two markers ends the
walk. Regression tests in `tests/carve/signature/test_footer_bound.py`: the
absorbing case fails on the old code and passes on the new; a genuine
incremental update is still followed.

## Final measurement: isolated runs, both fixes in

Nothing else ran on the host. Same 960 planted objects in each; the recoverable
total is 288 rather than the 294 above because the ZIP-timestamp fix
(`testkit/generate_corpus.py:FIXED_ZIP_TIME`) made the OOXML packages
byte-identical across seeds, so fewer distinct digests exist.

| | 1 GiB | 7 GiB |
|---|---:|---:|
| Image bytes | 1,073,741,824 | 7,516,192,768 |
| Carve wall clock | **37.4 s** | **155.5 s** |
| Signature + structure scan phase | 20.8 s | 104.3 s |
| Throughput | 27.4 MiB/s | 46.1 MiB/s |
| Peak RSS (carve process) | 406.0 MiB | 513.4 MiB |
| Candidates / objects written | 487 / 487 | 945 / 945 |
| Distinct recoverable recovered | **288 / 288** | **288 / 288** |
| HIGH: n / TP / unplanted | 247 / 247 / **0** | 247 / 247 / **0** |
| MEDIUM: n / TP / unplanted | 41 / 41 / 0 | 41 / 40 / 1 |
| LOW: n / TP / unplanted | 199 / 0 / 198 | 657 / 1 / 655 |
| Spilled temp files left | 0 | 0 |
| Failures / errors | none | none |

Throughput is higher on the larger image because the object count is the same:
validating and scoring 960 objects is a fixed cost, and the extra six gigabytes
are filler the scan passes over quickly. Peak RSS rose by 107 MiB for a 7×
larger image with the same objects; this document does not claim memory is
constant in image size, only what it measured at two sizes.

## Memory

The carve holds at most one recovered object's bytes at a time: fragmented and
multi-extent objects are spilled to the state directory's `work/` and read back
one by one (`api/carve_job.py:SpillStore`). Peak RSS is reported above for the
whole carve process, which also holds the signature automaton, the parsed
candidate list and the decoder libraries. The spill directory was empty after
every run.

## What this does not establish

- **One synthetic image per size.** Not a seized disk, not a real filesystem,
  not real fragmentation. Precision on real media will differ.
- **Throughput is this host's.** Single-process carve on an NVMe laptop. The
  scan is single-process in the product pipeline (`api/carve_job.py` docstring).
- **The one unplanted MEDIUM and the one LOW true positive after the fix were
  not individually investigated.** They are reported, not explained.
- **No E01, no acquisition.** This measures carving a raw image already on disk.
