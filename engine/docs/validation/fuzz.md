# Parser and validator fuzz pass

**Date:** 2026-09-21 · **Harness:** `testkit/fuzz.py` · **Seed:** 0 ·
**Iterations:** 2,000 per target · **Raw result:** [`fuzz-seed0.json`](fuzz-seed0.json)
· **Host:** Fedora 44, Linux 6.19.10, Python 3.11.16, 16 logical CPUs

Reproduce with:

```
python -m testkit.fuzz --iterations 2000 --seed 0 --json docs/validation/fuzz-seed0.json
```

## What was fuzzed

The two layers that read attacker-controlled bytes off a seized disk:

- **16 structure-parser registrations** (`core.carve.structure.PARSERS`) — the
  code that walks a format's own length fields to find an object's end.
- **17 decoder registrations** (`core.carve.validate.VALIDATORS`) — the code that
  hands recovered bytes to Pillow, pikepdf, `zipfile`, `sqlite3`, `wave`,
  `gzip`, `tarfile`, `olefile` and friends.

Each input starts from the format's real header, so mutations land inside
structure rather than being rejected at byte 0, and is then mutated in one of
seven categories:

| Category | What it does |
|---|---|
| generic corruption | bit flips, byte replacement, truncation, appended garbage |
| hostile size field | overwrites a 16/32/64-bit field, either endianness, with 0, 1, the signed/unsigned boundaries, or all-ones |
| invalid offset | points an internal 32-bit offset past the end, to 0, or to `0xFFFFFFFF` |
| recursive structure | the format's own header nested inside itself 8–64 times |
| compression bomb | a real gzip or zip of 32 MiB of zeros |
| header only | the header and nothing else |
| random noise | header plus up to 8 KiB of random bytes |

A **crash** is any exception escaping the parser or validator. A **timeout** is
one input taking more than 2 s. A **memory failure** is `MemoryError`. A parser
returning `None` ("refused") is correct behaviour, not a failure.

## Result

**66,000 cases. No crashes, no timeouts, no memory failures** — on the tree
after the one fix below.

| Target | Cases | Refused | Accepted | Crash | Timeout | OOM | Slowest |
|---|---:|---:|---:|---:|---:|---:|---:|
| structure.BMP | 2000 | 2000 | 0 | 0 | 0 | 0 | 0.000 s |
| structure.GZIP | 2000 | 1566 | 434 | 0 | 0 | 0 | 0.023 s |
| structure.HTML | 2000 | 2000 | 0 | 0 | 0 | 0 | 0.000 s |
| structure.HTML-tag | 2000 | 2000 | 0 | 0 | 0 | 0 | 0.000 s |
| structure.JPEG | 2000 | 267 | 1733 | 0 | 0 | 0 | 0.000 s |
| structure.MP4 | 2000 | 4 | 1996 | 0 | 0 | 0 | 0.000 s |
| structure.PDF | 2000 | 2000 | 0 | 0 | 0 | 0 | 0.000 s |
| structure.PNG | 2000 | 330 | 1670 | 0 | 0 | 0 | 0.000 s |
| structure.RTF | 2000 | 279 | 1721 | 0 | 0 | 0 | 0.001 s |
| structure.SQLite | 2000 | 2000 | 0 | 0 | 0 | 0 | 0.000 s |
| structure.TAR | 2000 | 2000 | 0 | 0 | 0 | 0 | 0.000 s |
| structure.TIFF-BE | 2000 | 311 | 1689 | 0 | 0 | 0 | 0.000 s |
| structure.TIFF-LE | 2000 | 319 | 1681 | 0 | 0 | 0 | 0.000 s |
| structure.WAV | 2000 | 873 | 1127 | 0 | 0 | 0 | 0.000 s |
| structure.WebP | 2000 | 890 | 1110 | 0 | 0 | 0 | 0.000 s |
| structure.ZIP | 2000 | 1860 | 140 | 0 | 0 | 0 | 0.000 s |
| validate.bmp | 2000 | 0 | 2000 | 0 | 0 | 0 | 0.020 s |
| validate.doc | 2000 | 0 | 2000 | 0 | 0 | 0 | 0.001 s |
| validate.docx | 2000 | 0 | 2000 | 0 | 0 | 0 | 0.026 s |
| validate.gif | 2000 | 0 | 2000 | 0 | 0 | 0 | 0.001 s |
| validate.gz | 2000 | 0 | 2000 | 0 | 0 | 0 | 0.038 s |
| validate.jpg | 2000 | 0 | 2000 | 0 | 0 | 0 | 0.000 s |
| validate.mp4 | 2000 | 0 | 2000 | 0 | 0 | 0 | 0.000 s |
| validate.pdf | 2000 | 0 | 2000 | 0 | 0 | 0 | 0.019 s |
| validate.png | 2000 | 0 | 2000 | 0 | 0 | 0 | 0.000 s |
| validate.pptx | 2000 | 0 | 2000 | 0 | 0 | 0 | 0.031 s |
| validate.sqlite | 2000 | 0 | 2000 | 0 | 0 | 0 | 0.000 s |
| validate.tar | 2000 | 0 | 2000 | 0 | 0 | 0 | 0.000 s |
| validate.tiff | 2000 | 0 | 2000 | 0 | 0 | 0 | 0.003 s |
| validate.wav | 2000 | 0 | 2000 | 0 | 0 | 0 | 0.000 s |
| validate.webp | 2000 | 0 | 2000 | 0 | 0 | 0 | 0.000 s |
| validate.xlsx | 2000 | 0 | 2000 | 0 | 0 | 0 | 0.028 s |
| validate.zip | 2000 | 0 | 2000 | 0 | 0 | 0 | 0.027 s |

For validators "accepted" means **returned a verdict** — `valid`, `truncated`,
`corrupt` or `decoder_unavailable`. A validator never returns `None`; it is
supposed to have an opinion about every input, and it did.

## The one defect found

The first smoke run (25 iterations) crashed `validate.wav` on 17 of 25 inputs.
CPython's `wave` module raises a **bare `RuntimeError`** — no message, not a
`wave.Error` — from its internal `Chunk.seek` when a chunk header declares more
bytes than the file holds. `validate_wav` caught `wave.Error`, `OSError`,
`ValueError` and `EOFError`, so this escaped into the carve pipeline: **a
malformed RIFF header in evidence would have failed the whole recovery job.**

Fixed in `core/carve/validate.py:validate_wav`, narrowly (this one standard
library behaviour on this one decoder, reported as `corrupt`), and held by
`tests/carve/test_validate_malformed.py`, which also asserts that every
registered validator returns a verdict for a truncated header, pure noise and
all-zero fill.

## What this run does not establish

- **It is not coverage-guided.** Five parsers — BMP, HTML, PDF, SQLite, TAR —
  refused all 2,000 inputs. The mutations never produced something those
  parsers would walk into deeply, so their inner branches were barely exercised
  by this pass. Their deeper paths are covered only by the unit tests in
  `tests/carve/signature/test_structure.py` and
  `tests/carve/signature/test_derived_lengths.py`.
- **It is short.** 66,000 cases in one run, one seed. Coverage-guided fuzzers
  are run for days against millions of inputs. This is a bounded regression
  pass, not an assurance argument.
- **Warnings are not failures.** Pillow emitted `UserWarning: Corrupt EXIF
  data` on many TIFF/JPEG inputs; those are the decoder reporting malformed
  input correctly.
- **Decoders are third-party.** A clean pass says the *wrapping* in this
  project turns every tested failure into a verdict. It says nothing about
  memory-safety bugs inside libjpeg, zlib, libtiff or qpdf, which run in this
  process.
- **Two carve fixes were made after this run.** The footer bound in
  `core/carve/signature.py` changes the signature scan, not any fuzzed target.
  The incremental-update check in `core/carve/structure.py:_revision_follows`
  does change `parse_pdf`, which refused every one of its 2,000 inputs here, so
  that parser's new branch is covered by its unit tests and not by this run.

No formal security assurance is claimed from this pass.
