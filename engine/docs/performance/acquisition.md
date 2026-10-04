# Acquisition throughput

**Run date:** 2026-09-04 · **Host:** Fedora Linux 44, kernel 6.19.10, CPython
3.11.16 · **Harness:** `scripts/measure-e01-throughput.py`

Reproduce with:

```
.venv/bin/python scripts/measure-e01-throughput.py --ewfacquire <path>
```

## Method

The source is **not** random bytes. A disk image is mostly unused space, and
measuring deflate against incompressible noise reports a throughput no real
acquisition ever sees. The synthetic source is 512 MiB made of 60% zero fill,
25% text-like records and 15% incompressible data — a partly-used disk.

Figures are **page-cache warm**: the source was written immediately before
being read, so these measure the code path and not the storage device. A cold
read from spinning media will be bounded by the disk, not by this.

Sanctum's own numbers include **both hashes** — SHA-256 and BLAKE3 — computed
in the same read pass, because that is what the product does. `ewfacquire`'s
row computes SHA-1 only and is not comparable on that axis; it is here for the
one comparison Sanctum cannot make itself.

## Measured

| tool | setting | elapsed | throughput | on disk |
|---|---|---:|---:|---:|
| `core.carve.acquire` | raw | 0.79 s | 645.4 MiB/s | 100.0% of source |
| `core.carve.acquire` | **E01** | 0.82 s | **622.1 MiB/s** | **100.0% of source** |
| `ewfacquire` | `-c none` | 1.66 s | 308.4 MiB/s | 100.0% |
| `ewfacquire` | `-c fast` | 2.22 s | 230.5 MiB/s | 15.5% |
| `ewfacquire` | `-c best` | 2.66 s | 192.8 MiB/s | 15.4% |

## What the E01 row means, and what it does not

**Sanctum cannot select a compression level, and the level it gets is `none`.**
`pyewf` binds `set_header_codepage` and no other setter, so
`libewf_handle_set_compression_values` is unreachable. `AcquireOptions.compression`
is accepted, has no effect, and every E01 acquisition record carries
`E01_COMPRESSION_NOT_SELECTABLE` saying so with the requested value named.

So there is no "fast versus best" figure for Sanctum to report: both settings
run the same code and produce the same uncompressed container. Reporting them
as two rows would be inventing a distinction. The E01 row above is the honest
single number, and its 100.0%-of-source column is the important part — the
container comes out slightly *larger* than the source, confirmed with
`ewfinfo`: `Compression level: no compression`.

The `ewfacquire` rows are the measurement Sanctum cannot make, and they say
what binding that setter would be worth: **`fast` costs 25% of `none`'s
throughput and returns 84% of the space**, while `best` costs a further 16% of
throughput for 0.1 percentage points of size. If E01 compression is ever wanted
here, `fast` is the setting; `best` is not worth its cost on this data.
