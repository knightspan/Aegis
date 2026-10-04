# PNG bifragment reassembly: measured reach and refusals

**Date:** 2026-09-23 · **Code:** `core/carve/fragmentation.py:reassemble_bifragmented_png_runs`
· **Raw results:** [`png-reassembly.json`](png-reassembly.json) · **Reproduce:**
`.venv/bin/python scripts/measure_png_reassembly.py docs/validation/png-reassembly.json`

Population: **SYNTHETIC**. Every image is generated on host storage from a fixed
seed. No device was read, and no figure here is a physical-media result.

## What is accepted

A PNG split into exactly two runs is rebuilt only when one join makes all of
these true at once:

1. every chunk from the break to IEND has a letters-only type and a matching CRC-32;
2. the IDAT data inflates to **exactly** the byte count the IHDR implies (per
   Adam7 pass for interlaced images), the zlib stream ends there with a valid
   Adler-32, and nothing is left over;
3. the join is bound: a chunk straddles it, or IDAT data lies on both sides of it;
4. no other join in the 8 MiB window passes. A second passing join is a refusal,
   even when it would give identical bytes, because the runs would be a guess.

The candidate is then scored with the `reassembly` component, which holds it at
7999 basis points, one below HIGH, as for JPEG.

## Reach

Noise-filled gaps, 10 layouts per cell, half noisy images and half gradient
images with low-amplitude noise, random head length on the grid.

| Grid | 64 KiB | 256 KiB | 1 MiB | 2 MiB | 4 MiB | 7 MiB | Worst time |
|---|---|---|---|---|---|---|---|
| 512 B (cluster size unknown) | 10/10 | 10/10 | 10/10 | 10/10 | 10/10 | 10/10 | 0.155 s |
| 4096 B (cluster size known) | 10/10 | 10/10 | 10/10 | 10/10 | 10/10 | 10/10 | 0.159 s |

Wrong reassemblies: **0 of 120**. Refusals: 0 of 120.

## Gap contents

Text puts a candidate chunk type almost everywhere; zeros put one nowhere.
5 layouts per cell.

| Gap fill | Grid | 1 MiB | 7 MiB | Worst time |
|---|---|---|---|---|
| text | 512 B | 5/5 | 5/5 | 0.715 s |
| text | 4096 B | 5/5 | 5/5 | 0.689 s |
| zeros | 512 B | 5/5 | 5/5 | 0.134 s |
| zeros | 4096 B | 5/5 | 5/5 | 0.123 s |

Wrong reassemblies: **0 of 40**.

## Adversarial populations

Every accept in these populations would be wrong by construction. 200 cases
each, 4096-byte grid.

| Population | Wrongly accepted | Worst time |
|---|---|---|
| Head of one PNG, tail of another with identical dimensions and colour type | **0 / 200** | 0.004 s |
| Tail's first cluster overwritten | **0 / 200** | 0.003 s |
| Tail missing its first 512 bytes | **0 / 200** | 0.003 s |
| 512 bytes substituted inside the tail | **0 / 200** | 0.003 s |

## What this does not cover

- **Two runs only.** A PNG in three or more pieces is not rebuilt.
- **8 MiB window.** The object must end within 8 MiB of its header.
- **Both runs must be on the medium.** An overwritten tail is refused, never patched.
- **Budget.** 4,000,000 join pairs, 200,000 chunk CRCs and 10 s per header.
  Running out before the join is shown unique is a refusal.
- **Synthetic images from one encoder (Pillow).** Encoders that write very large
  IDAT chunks widen the head search; the budget bounds it but reach on such files
  has not been measured.
- **The CRC-32 and Adler-32 are not cryptographic.** A deliberately forged tail
  can satisfy both. The oracle defends against accidental joins on a medium, not
  against an adversary who controls the gap bytes.
