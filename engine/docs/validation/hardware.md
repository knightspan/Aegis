# Hardware validation — first contact with real removable media

> **Current state (2026-09-28).** Current product execution no longer exposes
> a user-facing simulation/dry-run mode: every operation runs against the
> selected real device once its gates pass, and a request that asks for a
> rehearsal is refused. References below to a dry run or a simulation record
> what the build of that date did; they are historical evidence and are kept as
> run.

**Status: PHASE A COMPLETE AND CLEAN (2026-09-05). PHASE B RUN, THREE PASSES,
CLEAN (2026-09-05).**

Everything Sanctum had been measured against before this was a loop device or an
image file. Both are perfect media: no vendor firmware, no USB bridge, no wear
levelling, no controller deciding on its own where a write lands. This document
is where the first runs against real hardware get written up.

Phase A has been run three times against a real USB stick, and the third run is
clean: every phase passed, no phase was recorded as failed, and the script
exited 0.

Phase B — the recovery half — has now been run three times against the same
stick: FAT32 with half the files deleted, exFAT with half the files deleted, and
FAT32 quick-formatted. Every acquisition verified clean with zero bad sectors.
Recall was 100.00% on both delete passes and 1.10% on the quick-format pass,
**and the 1.10% is a property of the test population, not of the media and not
of the carver** — the section on it says why, at length, because the number is
easy to misread in either direction.

**Nothing in this document is estimated, extrapolated or inferred from the
synthetic runs.** Every unmeasured table stays empty until a real run fills it,
and every inference that is not a measurement is labelled as one.

| Run | Date | Outcome |
|---|---|---|
| `results-20260904T163645Z` | 2026-09-04 | **Invalid.** The erase covered 512 bytes of the 7.76 GB device and the run printed `COMPLETE`. |
| `results-20260904T212839Z` | 2026-09-04 | Wipe correct, reporting wrong. A.7 failed on a chain check, the elision went undetected, and the flash caveats were missing. |
| `results-20260905T033655Z` | 2026-09-05 | **Clean.** The numbers in this document are from this run, plus a power-cycle re-verification afterwards. |
| `results-20260905T081354Z` | 2026-09-05 | **Phase B, FAT32, delete.** Clean. 456 of 456 recovered byte-exact. |
| `results-20260905T082418Z` | 2026-09-05 | **Phase B, exFAT, delete.** Clean. 460 of 460 recovered byte-exact. |
| `results-20260905T082656Z` | 2026-09-05 | **Phase B, FAT32, quick format.** Clean. 10 of 912 — which is 10 of the 10 that were recoverable at all. |

Nine defects separate the first run from the third. Every one of them was
invisible to the synthetic suite; see "The three runs, and the nine defects
between them" below.

---

## Why Phase B had not happened

All four blockers are now cleared. Blockers 1, 2 and 4 were cleared by an
operator: PhotoRec was installed, a scratch USB stick was supplied, and the
script was run under `sudo` directly. Blocker 3 was cleared by moving Phase B
off SD entirely.

| # | Blocker | Blocks | Status |
|---|---|---|---|
| 1 | `sudo` requires a password this session does not have | Raw device access is root-only | **Cleared** — an operator ran the script |
| 2 | PhotoRec is not installed | Phase A steps 3 and 6 | **Cleared** — `testdisk` installed |
| 3 | No SD card is attached | ~~All of Phase B~~ | **Cleared by moving Phase B to USB** — see below |
| 4 | The only removable device is a Windows installer | Phase A | **Cleared** — a scratch TransMemory stick was supplied |

The original blocker write-ups are kept below, because the conditions that
produced them are the normal ones on a fresh host.

### 1. No raw device access

```
$ dd if=/dev/sda of=/dev/null bs=512 count=1
dd: failed to open '/dev/sda': Permission denied

$ id
uid=1000(v0idsai) gid=1000(v0idsai) groups=1000(v0idsai),10(wheel)

$ ls -l /dev/sda
brw-rw----. 1 root disk 8, 0 /dev/sda
```

The account is in `wheel` but not in `disk`, and `sudo` prompts for a password.
Every step of Phase A and Phase B needs to open a block device, so nothing can
run. This is correct system configuration, not a fault.

### 2. PhotoRec is not installed

```
$ command -v photorec
(nothing)

$ dnf repoquery testdisk
testdisk-7.2
```

It is one `dnf install` away, and that also needs `sudo`.

This matters more than it looks. The brief is right that the after-count proves
nothing without the before-count — but the failure mode is worse than that. If
PhotoRec is missing at step 6, "0 files recovered" and "nobody looked" produce
the same number. The harness therefore writes
`{"skipped": "photorec is not installed"}` rather than a zero, so the
distinction survives into this document.

### 3. No SD card, so Phase B had no target

```
$ ls /dev/mmcblk*
no mmcblk devices

$ ls /sys/block/
loop0  nvme0n1  nvme1n1  sda  zram0
```

`nvme0n1` and `nvme1n1` are the machine's own disks — `/` is on `nvme1n1p1`.
`sda` is the USB stick discussed below. There is no removable card reader
device of any kind.

**Resolved by running Phase B on `/dev/sda` instead.** The recovery pipeline
reads an image file and never touches the bus, and FAT32 and exFAT are the same
on-disk structures on either medium, so the filesystem measurement is unaffected.
What is lost is any claim about a card reader's *controller*, and that loss is
stated rather than glossed — see below. Waiting indefinitely for a card reader
while the recovery half of the project stayed entirely unvalidated against real
media was the worse trade.

### 4. The only removable device is Windows installation media

```
$ lsblk -f /dev/sda
NAME   FSTYPE LABEL                    SIZE
sda                                    7.2G
└─sda1 ntfs   CCCOMA_X64FRE_EN-US_DV9  7.2G   /run/media/v0idsai/...

$ udevadm info --name=/dev/sda | grep ID_
ID_VENDOR=TOSHIBA
ID_MODEL=TransMemory
ID_SERIAL_SHORT=B103B9C19DE1CCC1BD535ACB
ID_BUS=usb

$ ls /run/media/v0idsai/CCCOMA_X64FRE_EN-US_DV9/
autorun.ico  autorun.inf  System Volume Information
```

`CCCOMA_X64FRE_EN-US_DV9` is the volume label Microsoft's Media Creation Tool
writes. Together with `autorun.inf` this is a Windows installer USB stick.

Phase A ends with the target holding nothing. **Running it here destroys that
installer**, and a bootable installer is not obviously a scratch device.
This was not done. The harness prints a warning for exactly this case and
still permits it — refusing outright would be the harness overruling an
operator who may well have a spare installer they no longer need — but nobody
should discover afterwards that this is what the target was.

---

## What *was* verified

The harness itself, verified before any hardware was attached and kept here
because it is separate evidence from the run. All of the following was executed
on this host, against loop devices and images.

### Safety gates, against real devices

| Gate | Tested against | Result |
|---|---|---|
| Missing `--i-understand-this-destroys-data` | `/dev/sda` | Refused |
| Not a block device | `/etc/hosts` | Refused |
| Holds the running root filesystem | `/dev/nvme1n1` | Refused |
| Has mounted filesystems | `/dev/sda` | Refused, naming the mount point |
| Not removable | — | Not reachable: no fixed disk survives the root-filesystem gate on this host |
| Above the 128 GiB sanity limit | — | Not reachable for the same reason |
| Typed serial must match | — | Not reachable without passing the earlier gates |

The last three gates are unexercised. That is a gap in this document, not a
claim that they work.

### The Sanctum-side steps, against real filesystem images

Every subcommand of `scripts/hardware_validation.py` was run against a real
FAT32 image built by `testkit/fsimage.py` (40 MiB, 10 JPEGs, 5 deleted):

| Step | Result |
|---|---|
| `hash-tree` / `mark-deleted` | 3 files hashed, 2 marked deleted |
| `carve` | 5 candidates, 5 of 5 deleted files recovered byte-identical |
| `compare` | Produced the real-vs-synthetic row correctly |
| `acquire --fmt raw` | 41,943,040 bytes, integrity check passed |
| `acquire --fmt e01` | 41,961,613 bytes on disk (larger than source; see below), integrity passed |
| `report` | 3,748-byte JSON, 38,906-byte PDF, 3 ledger entries |
| `report` tamper cycle | See below |

The tamper cycle behaved exactly as step A.7 requires:

| Report state | `signature` | `fingerprint` | `chain` | `blobs` | overall |
|---|---|---|---|---|---|
| As written | PASS | PASS | PASS | PASS | **PASS** |
| One byte flipped at offset 2165 | **FAIL** | PASS | PASS | PASS | **FAIL** |
| Restored | PASS | PASS | PASS | PASS | **PASS** |

Only the signature check moved. The other three are independent of the report
bytes and correctly stayed put, which is the property that makes reporting them
separately worth doing.

### One harness defect found and fixed while testing it

`structlog` writes to stdout by default, so its log lines interleaved with the
JSON each subcommand emits and made the output unparsable:

```
json.decoder.JSONDecodeError: Extra data: line 1 column 5 (char 4)
```

Logging now goes to stderr. The lines are kept, not silenced: on a real run the
ledger and progress logs are half the evidence about what happened.

This was found by running the harness, not by reading it — which is the same
reason the hardware run matters.

---

## Phase A results — MEASURED

Source: `docs/validation/results-20260905T033655Z/`. Target: Toshiba
TransMemory, serial `B103B9C19DE1CCC1BD535ACB`, 7,759,462,400 bytes, USB,
removable. Total wall clock 5932.07s (98.9 min). `zz-failures.json`:
`{"failed_phases": [], "failures": 0}`.

### A.1 Enumeration cross-check

| Field | Sanctum | `lsblk -O` | `udevadm` | Agrees? |
|---|---|---|---|---|
| model | TransMemory | TransMemory | TransMemory | yes |
| serial | B103B9C19DE1CCC1BD535ACB | B103B9C19DE1CCC1BD535ACB | B103B9C19DE1CCC1BD535ACB | yes |
| size_bytes | 7759462400 | 7759462400 | — | yes |
| transport | usb | usb | usb | yes |
| rotational | True | True (`ROTA=1`) | — | yes |

**Disagreements found: 0.**

`rotational: True` for a flash stick is the kernel's own answer: this bridge
does not set the non-rotational queue flag, and Sanctum reports what the kernel
says rather than inferring from the device class. It is recorded as an agreement
because it is one. Three code paths used to read that flag as a flash test and
all three were wrong; see defect 8.

| Probe | Result |
|---|---|
| Capability probe | `ata_security_erase: false`, `ata_sanitize_ops: []`, `is_sed_opal: false`, `security_frozen: false` |
| Achievable levels | `CLEAR` only |
| HPA / DCO | **Not probed** — `probe_failed`, with the reason recorded |
| Hidden bytes | Unknown; none detected because none was looked for |

The HPA/DCO probe is skipped on USB and MMC transports by design. A bridge's
answer to a SET_MAX query describes the bridge, not the medium behind it, and
nothing in the answer says which. The report carries the limitation verbatim:

> `/dev/sda` is behind a usb bridge, where ATA pass-through is not dependable;
> HPA/DCO was not probed and hidden sectors, if any, were neither detected nor
> erased.

### A.2 Known pattern and planted files

| | |
|---|---|
| Pattern byte | `0xA5` across the whole device |
| Bytes written | 7,759,462,400 (100%) |
| Elapsed | 1910.76s |
| Throughput | **3.87 MiB/s** |
| Buffer / `O_DIRECT` | 4,194,304 bytes / yes |
| Files planted | 14 (11 distinct digests, 3 files duplicating another's content) |
| Filesystem | FAT32 |

`0xA5` rather than `0x00` on purpose: a wipe that leaves zeros over a device
that was *already* zeroed proves nothing. On this device that choice turned out
to matter far more than intended — see the throughput section.

The 14/11 split is why the manifest is keyed by path. Three of the planted PDFs
are byte-identical to each other and two of the docx files are byte-identical to
each other; a digest-keyed manifest recorded 11 entries for 14 files, and any
recall denominator taken from that count is 27% too small.

### A.4 PREFLIGHT write calibration

New in this run, and it decided everything downstream. Two timed fills over the
same 64 MiB region, non-zero first so the zero write cannot be skipped as a
no-op against matching content:

| Fill | Bytes | Seconds | MiB/s |
|---|---:|---:|---:|
| `0xA5` | 67,108,864 | 14.961 | 4.28 |
| `0x00` | 67,108,864 | 4.598 | 13.92 |

**Ratio 3.25, threshold 2.00, `elision_detected: true`.** Cost: 19.6s and
128 MiB of a device about to be erased entirely.

Consequences, all recorded in the plan and the ledger:

| | |
|---|---|
| `fill_bytes` | `["0xA5"]` — substituted for the method's default `0x00` |
| `fill_reason` | the write calibration measured this controller acknowledging a zero fill far faster than it programs the medium, so 0x00 passes were replaced with 0xA5 to force a real program |
| `est_seconds` | 1729 (28.8 min) |
| `est_basis` | measured on this device before the run: 0xA5 at 4.28 MiB/s over 67108864 bytes per sample |

The ETA was **8.3% optimistic**: the write took 1886.3s against an estimate of
1729s, because the 64 MiB sample ran at 4.28 MiB/s and the sustained
whole-device rate is 3.92 MiB/s. That is the right direction to be wrong in only
by accident, and the sample size is the reason. It is worth noting rather than
tuning away: an estimate derived from a 64 MiB sample of a 7.4 GiB write is
going to be a few percent out, and 8% is far better than the 3.6x error a
zero-rate estimate would have produced.

### A.3 / A.6 PhotoRec, before and after

Raw counts, as PhotoRec reported them:

| Run | Files recovered | Elapsed |
|---|---|---|
| **Before wipe** | 198 | 309.46s |
| **After wipe** | **0** | 563.32s |

Every recovered file hashed and compared against the A.2 manifest:

| Run | Files | Byte-identical to a planted file | All-zero 81,920-byte `.dovecot` | Other |
|---|---:|---:|---:|---:|
| Before wipe | 198 | **14** | 184 | 0 |
| After wipe | 0 | **0** | 0 | 0 |

**14 of 14 planted files recovered before sanitization, 0 after.**

#### The after-count fell to zero because the fill changed, not because the wipe improved

This must not be read as an improvement over the previous run. Both wipes that
ran to completion left nothing recoverable: run 2 also recovered 0 of 14, under
94,720 raw candidates.

PhotoRec's `dovecot` signature accepts an all-zero 80 KiB block and emits it as
a fixed-size 81,920-byte file, non-overlapping. Run 2 ended with the medium
holding `0x00`, so the count was `7,759,462,400 / 81,920 = 94,720` exactly — a
property of the medium's uniformity, not of what was recoverable. Run 3 ends
with the medium holding `0xA5`, which produces no candidates at all.

Reproduced on the validation host with the same PhotoRec build and command:

| Input | Files recovered |
|---|---:|
| 100 MiB of `0x00` | **1280** (= 104,857,600 / 81,920, exactly) |
| 100 MiB of `0xA5` | **0** |
| 81,919 bytes of `0x00` | **0** — a short block does not qualify |
| 122,880 bytes of `0x00` | **1**, of 81,920 bytes — no partial tail |

The before-run's 184 artefacts account for 15,073,280 bytes of zeros, which is
consistent with the two FAT32 file allocation tables `mkfs.vfat` wrote over the
`0xA5` pattern. That number is identical in runs 2 and 3.

Both runs use the identical command, recorded in the results JSON:

```
photorec /log /d <out>/recup /cmd <device> partition_none,fileopt,everything,enable,search
```

That string now lives in exactly one place, `harness_photorec` in
`scripts/harness-steps.sh`, sourced by both this harness and `demo-reset.sh`.
They previously held a copy each. Nothing had drifted between them, but the
before/after count is worth something only because both runs are the same
measurement, and a difference either copy could acquire without anyone noticing
is a difference in a number that goes on a slide.

Three properties were added at the same time, none of which change what is
measured:

* **A bound.** Every call is killed at 1500s (`SANCTUM_PHOTOREC_TIMEOUT_S`),
  roughly 2.6x the slowest run recorded above. A timeout is a recorded failure
  carrying `"timed_out": true`, never a zero count — "nobody looked" and
  "nothing was recoverable" support opposite conclusions about a wipe.
* **A heartbeat.** Elapsed time, files so far and bytes on disk, every 30s. A
  step that can run for nine minutes in silence is indistinguishable from one
  that has hung.
* **A refusal, on two counts.** `demo-reset.sh` wrote its recup tree under
  `mktemp -d`. On a host where `/tmp` is tmpfs, a device holding `0x00` produces
  94,720 dovecot artefacts totalling 7.76 GB *in RAM*, which does not fail — it
  swaps, and a swapping host is indistinguishable from a hung one at 1% CPU.
  That cost forty minutes of a rehearsal window at 1% CPU with a clean `dmesg`.
  This was a printed warning first; a warning read at 2am is not a guard.
  `harness_workdir` now picks the work directory before the first destructive
  step and refuses to start unless it is disk-backed and has at least the
  device's size free, relocating a memory-backed `TMPDIR` to `/var/tmp` and
  saying why. `harness_photorec` re-checks both at the output directory it is
  handed, so a run that never went through `harness_workdir` is covered too.
  Neither check can be silenced by an operator who is tired.

`SANCTUM_PHOTOREC_OPTS` can narrow the signature set to the formats the demo
plants (`HARNESS_PHOTOREC_OPTS_PLANTED`). It is deliberately not the default: a
run using it cannot be compared with the figures in this section, and the
14-of-14 result depends on that comparison holding.

**The honest slide is 14 → 0, in both runs.** The raw counts, 198 → 94,720 and
198 → 0, are dominated by a carver artefact in opposite directions and neither
describes the wipe.

### A.4 Dry run writes nothing

| | |
|---|---|
| Device SHA-256 before dry run | `138b8cbee0902dcd7b036120750ac2ba0d22740e1089a1dcb2b36165506e2173` |
| Device SHA-256 after dry run | `138b8cbee0902dcd7b036120750ac2ba0d22740e1089a1dcb2b36165506e2173` |
| Unchanged | **yes** |

Hashed over the whole device, not a sample, so this is a claim about every byte.
The calibration writes happen inside the *real* erase's PREFLIGHT, after this
comparison; a dry run never calibrates, and its plan says its fill bytes are
provisional for that reason.

### A.4 / A.5 Real wipe and verification

| | |
|---|---|
| Method selected | `SINGLE_PASS_OVERWRITE` |
| Level | `CLEAR` |
| Passes / fill byte | 1 / **`0xA5`**, substituted by calibration |
| Bytes written | 7,759,462,400 of 7,759,462,400 (**100.00%**) |
| Write elapsed | 1886.3s (ledger `erase.preflight.plan` → `erase.erase.complete`) |
| Write throughput | **3.92 MiB/s** |
| Checkpoints recorded | 29 |
| Step elapsed | 2215.8s, of which 19.6s is calibration and 309.8s the engine's own read-back |
| Phases recorded | PREFLIGHT, HIDDEN_AREA_UNLOCK, ERASE, HIDDEN_AREA_RESTORE, VERIFY, REPORT |
| Verify strategy | `full_read` |
| **Expected fill** | **`0xA5`**, source `--expect-fill`, taken from the erase plan |
| Bytes checked | 7,759,462,400 |
| Sample count / seed | 0 / none — every addressable block was compared |
| Failed offsets | **0** |
| Verification passed | **yes** |
| A.5 verify elapsed | 309.11s (23.93 MiB/s read) |
| Residual level | **high**, `purge_achieved: false` |

Residual risk is `high` rather than `medium` because of the elision finding, not
because anything went wrong with the wipe. Four factors are recorded:

1. the pattern substitution and what the medium holds afterwards;
2. HPA/DCO was not probed through the bridge;
3. no firmware sanitize could be issued through the bridge;
4. overwrite on flash cannot reach remapped or over-provisioned blocks, and no
   host-side read can establish physical removal on flash.

And one structured finding:

```
CONTROLLER_WRITE_ELISION   severity HIGH   addressable false
  ratio_bp 32538   threshold_bp 20000   sample_bytes 67108864
  zero 0x00 at 14,595,162 B/s   non-zero 0xA5 at 4,485,620 B/s
  read_back 25,051,089 B/s
```

### Power cycle: is the Clear outcome durable?

**What was tested.** After the wipe completed and verified, the stick was
unplugged, left out for 30 seconds, replugged, and re-verified end to end:

```
verify --device /dev/sda --expect-fill 0xA5
```

**Result: `passed: true`, `failed_offsets: 0`, `full_read` of all 7,759,462,400
bytes against `0xA5`.**

**Why it matters.** Deterministic-read-after-deallocate is a per-device
property. A SATA drive advertises it (DRAT/RZAT); a USB bridge advertises
nothing, and this host cannot query it. If a controller satisfies reads from a
mapping rather than from the cells, that mapping is a data structure, and a data
structure can fail to survive a power cycle or a firmware quirk — in which case
an LBA that read as sanitized before the cycle could return its old page after
it. That would mean the **Clear outcome itself failed**, which is a far larger
finding than anything else in this document.

It did not. The medium still holds the pattern the erase wrote, byte for byte,
across a power cycle. The Clear outcome is durable on this device.

**What it does not establish.** That the prior contents are gone from the NAND.
Nothing read through the device's own interface can establish that; see below.

An earlier attempt at this test was inconclusive and is recorded here so the
result above is not over-read: the first 2 GB came back non-zero, which was a
leftover `0xFF` region from the throughput measurement rather than surviving
data, and a read at the 5 GB offset returned zeros as expected. The clean Phase A
rerun replaced it and gives the power-cycle check for free.

### Write throughput depends on the byte being written

Every write below used the same aligned `O_DIRECT` path on the same device.

| Write | Where | Bytes | Seconds | MiB/s |
|---|---|---:|---:|---:|
| `0xA5` | run 3, A.2 pattern | 7,759,462,400 | 1910.76 | **3.87** |
| `0xA5` | run 2, A.2 pattern | 7,759,462,400 | 1886.75 | **3.92** |
| `0xA5` | run 3, A.4 erase | 7,759,462,400 | 1886.3 | **3.92** |
| `0xA5` | run 3, calibration | 67,108,864 | 14.96 | 4.28 |
| `0xFF` | 1 GiB via pipe, `oflag=direct` | 1,073,741,824 | 242.2 | 4.23 |
| `0xFF` | 1 GiB via `cat`, `oflag=direct` | 1,073,741,824 | 266.2 | 3.85 |
| `0x00` | run 2, A.4 erase | 7,759,462,400 | 521.5 | **14.19** |
| `0x00` | run 3, calibration | 67,108,864 | 4.60 | **13.92** |

**Published write throughput: ~4.0 MiB/s.** Every byte this controller actually
programs lands between 3.85 and 4.28 MiB/s, across three fill values, two tools,
three transfer sizes and three runs.

**14.19 MiB/s is not a write throughput and must never be quoted as one.** It is
the rate this controller acknowledges zeros, reproduced at 13.92 MiB/s on a
64 MiB sample in an independent run. The ratio between the two is 3.25-3.62
depending on sample size.

#### Reads are faster on zeros too

A correction to what this document said after run 2. Read-back rates:

| Read | Medium holds | Seconds | MiB/s |
|---|---|---:|---:|
| run 2, A.5 | `0x00` | 189.12 | **39.13** |
| run 3, engine VERIFY | `0xA5` | 309.8 | 23.89 |
| run 3, A.5 | `0xA5` | 309.11 | 23.93 |

Run 2's 39.13 MiB/s was published here as "the only figure that describes the
medium without qualification". Run 3 falsifies that: the same device reads
`0xA5` at **23.9 MiB/s**, and the two independent reads in run 3 agree to within
0.2%. **Published read throughput: ~23.9 MiB/s.**

Reading zeros is 1.64x faster than reading real data on this controller. The
straightforward reading is that the FTL answers a deallocated or zero-mapped
block without touching NAND on the read path as well as the write path. That is
consistent with the write measurement and with nothing else observed here, but
it is an inference from timing, not a proven mechanism, and it is recorded as
one.

### What that means for the erase claim

The **level does not change**. Clear is defined by its threat model: resistance
to recovery through the device's standard interface. Every LBA returns the
pattern the erase wrote, verified across the whole address space and again after
a power cycle. Purge was never claimed and is not reachable here.

What the elision changed is the **method statement**. Run 2's report named
`SINGLE_PASS_OVERWRITE` for a write the device never performed, and overwrite
means replacing the data with non-sensitive data (NIST SP 800-88r2 Sec. 3.1.1;
this citation was updated on 2026-09-14 from the since-withdrawn r1). Run 3
writes `0xA5`, which this controller has to program, so the method named is the
method performed.

**No host-side read can establish physical removal on flash.** Every read is
answered by the flash translation layer. A full read-back proves the device now
reports the expected pattern for every addressable block; it cannot prove the
cells holding the prior contents were erased, and no verification strategy —
full, sampled, seeded, repeated, or repeated across a power cycle — changes
that. This is a property of the interface, not a weakness in the verifier, and
the report states it rather than leaving a reader to infer it from a pass.

Elision is also worse than the general flash caveat, for a different reason. A
performed full-device write consumes the free pool and forces garbage collection
to erase previously-used blocks — the only mechanism by which a host-side
overwrite improves anything on flash. An elided pass programs almost nothing, so
it creates none of that pressure. Run 3's wipe programmed 7.4 GiB; run 2's
programmed almost none of it.

### `DOD_5220_22_M_3PASS` on this device

The method writes `(0x00, 0xFF, 0x00)`, or `(0xA5, 0xFF, 0xA5)` after
substitution.

| Estimate | Arithmetic | Total |
|---|---|---|
| Naive, all passes at the zero rate | 3 × 521.5 | 1564.5s = **26.1 min** |
| Zero passes elided | 521.5 + 1886.75 + 521.5 | 2929.8s = **48.8 min** |
| Every pass programmed, which is what the tool now does | 3 × 1886.3 | 5658.9s = **94.3 min** |

With the substitution in place the bottom row is the operative one: all three
passes are programmed, so the method costs **~94 minutes** on this device
against the ~26 a uniform-rate reading gives. `est_basis` records that the
number came from a measurement rather than a manufacturer's claim.

### A.7 Report, tamper, restore

| Report state | `signature` | `fingerprint` | `chain_integrity` | `chain_store` | `blobs` | overall |
|---|---|---|---|---|---|---|
| As written | PASS | PASS (`OK`) | PASS (`VERIFIED_PARTIAL`) | PASS (`VALID`) | PASS | **PASS** |
| One byte flipped at offset 19636 | **FAIL** | PASS | PASS | PASS | PASS | **FAIL** |
| Restored | PASS | PASS (`OK`) | PASS (`VERIFIED_PARTIAL`) | PASS (`VALID`) | PASS | **PASS** |

true / false / true, and **only the signature moved**. The flip was one byte,
`111 → 110`.

- `fingerprint_matches_genesis` reads `OK`: the harness now loads the signing
  key before the first ledger append, so genesis records a real fingerprint.
  Runs 1 and 2 reported `no genesis entry was available` about reports whose
  excerpt carried genesis at seq 0.
- `chain_integrity` reads `VERIFIED_PARTIAL`: 37 excerpt entries hash correctly,
  all 35 adjacent pairs link, span 0..42, and the 6 entries at seq 1-6 belonging
  to the dry-run job are named as not carried. The report declares that gap
  under its own signature: `excerpt_gaps: [{"from_seq": 1, "to_seq": 6,
  "count": 6}]`.
- `chain_store` re-verifies the whole chain independently of the excerpt and of
  the `chain_status` the report prints about itself: **all 43 entries verify,
  0..42.**

### A.8 Wall-clock per phase

| Phase | Seconds |
|---|---:|
| A.1 enumerate | < 1 |
| A.2 pattern write | 1910.76 |
| A.2 plant + hash | ~5 |
| A.3 photorec before | 309.46 |
| A.4 dry run | < 1 |
| A.4 write calibration | 19.6 |
| A.4 real wipe (write 1886.3 + read-back 309.8) | 2215.82 |
| A.5 verify | 309.11 |
| A.6 photorec after | 563.32 |
| A.7 report | ~2 |
| **Total** | **5932.07** |

98.9 minutes against run 2's 64.1. The difference is almost entirely the erase
write going from 521.5s to 1886.3s, because it is now actually writing. **That
is the fix working, not a regression.**

---

## The three runs, and the nine defects between them

The first run reported a completed wipe having written 512 bytes. The third
wiped every byte and reported every caveat. Nothing between them was a change of
intent — the same code path, the same device, the same command.

| | Run 1 `163645Z` | Run 2 `212839Z` | Run 3 `033655Z` |
|---|---|---|---|
| Bytes written | **512** (0.0000066%) | 7,759,462,400 (100%) | 7,759,462,400 (100%) |
| Fill written | `0x00` | `0x00` | **`0xA5`** by calibration |
| Write programmed by the controller? | no | **no** | **yes** |
| HPA/DCO | "1 native sector", believed | not probed, said so | not probed, said so |
| Verification | `passed: false`, 7388 bad offsets | `passed: true` against `0x00` | `passed: true` against `0xA5` |
| Verification printed? | **no**, only `strategy=full_read` | in full | in full |
| PhotoRec, planted-hash matches | 14 before / **14 after** | 14 before / 0 after | 14 before / 0 after |
| PhotoRec, raw counts | 199 / 199 | 198 / 94,720 | 198 / **0** |
| Residual level | `high` (verification failed) | `medium` | `high` (elision finding) |
| Flash caveats present? | no | **no** | yes |
| Elision finding | — | — | `CONTROLLER_WRITE_ELISION` HIGH |
| A.7 tamper table | **crashed, printed nothing** | printed, `chain_integrity` FAIL ×3 | true / false / true, all checks pass |
| Console verdict | `COMPLETE` | `COMPLETE WITH FAILURES` | `COMPLETE` |
| Exit status | **0** | 1 | 0 |
| Wall clock | 3666.89s | 3845.37s | 5932.07s |

Run 1's `COMPLETE` and exit 0 over a 512-byte wipe is the single worst outcome
this project can produce, and it is the reason the harness changes matter more
than any individual erase fix: **run 2's much smaller failure was reported, and
run 1's much larger one was not.**

### The nine defects

| # | Symptom | Mechanism | Fix |
|---|---|---|---|
| 1 | Erase covered 512 bytes of a 7.76 GB device | `hdparm -N` on a USB bridge prints `max sectors = 0/1, HPA setting seems invalid` **and exits 0**. The probe trusted the exit code and the regex match, and reported a native max of one sector | `core/device/hidden_areas.py` sanity-checks parsed values against the kernel size, detects the invalid-HPA string explicitly, and skips the probe entirely on `usb`/`mmc`. A failed probe returns `probe_failed` with a reason, never "no hidden area" |
| 2 | Geometry silently shrank to 512 bytes | The unlock branch rebuilt `Geometry` from `native_max_sectors × block_size` unconditionally | `core/erase/drive.py` widens only. `BLKGETSIZE64` is the floor, asserted before ERASE; `GeometryRefused` is raised rather than erasing part of a device |
| 3 | Console printed `COMPLETE`, exit 0, over a failed wipe | No step checked an exit status or an output file, and no phase could record a failure | `scripts/harness-steps.sh`: every step judged on exit status *and* a non-empty output file, stderr printed on failure, `zz-failures.json` always written, non-zero exit when any phase failed |
| 4 | A.5 printed `strategy=full_read` over `passed: false` and 7388 failing offsets | One `sed` extracting one field | `harness_report_verification` prints the whole `VerificationResult` and fails the phase when it did not pass. `harness_report_erase` does the same for `bytes_written` and `residual_risk` |
| 5 | A.7 crashed and the console stayed blank | `load_or_create_key` was handed a directory by both real callers and stat-ed it for 0600, then would have read it as PEM | `key_file_for` resolves a directory to `<dir>/sanctum-signing.key.pem`; `KeyPathUnusable` replaces `IsADirectoryError` |
| 6 | `chain_integrity` FAIL in all three tamper stages, for a store that verified all 42 entries | The excerpt carries one job's entries plus genesis. `_check_chain` walked it as though contiguous and called the first entry after the gap a broken link | Links checked only between adjacent `seq`; gaps named, not failed; three outcomes `VERIFIED_COMPLETE` / `VERIFIED_PARTIAL` / `BROKEN`; `excerpt_gaps` declared under the signature and cross-checked; new `chain_store` check re-verifies the whole chain from the store |
| 7 | "no genesis entry was available" about a report carrying genesis at seq 0 | Five distinct causes all returned `None` and printed the first one's message | Each cause reports itself (`GENESIS_ABSENT`, `NO_LEDGER_ROOT`, `BLOB_MISSING`, `BLOB_UNPARSABLE`, `FINGERPRINT_EMPTY`). The harness loads the signing key before the first ledger append, so genesis records a real fingerprint; a chain started without one records `NO_SIGNING_KEY`, not `""` |
| 8 | No flash caveat in the report of a USB flash stick | `flash = not device.rotational`, in three places, and a USB bridge does not clear `queue/rotational`. It also suppressed the DoD "extra passes buy nothing on flash" warning and blocked `TRIM_REMAP` for files on removable flash | `core/device/media.py:is_flash` makes a positive determination from calibration, transport, flag or model string, and returns the deciding signal so the report says how it knew |
| 9 | Zero fill acknowledged 3.25-3.62x faster than the medium can be programmed | The controller maps an all-zero write to a token or compresses it away. The cells keep their prior contents, the verification compares against the one value the FTL synthesizes for free, and the report names an overwrite the device performed as a deallocate | `core/erase/calibrate.py` times a non-zero fill against a zero fill in PREFLIGHT; at or above 2.0 it records `CONTROLLER_WRITE_ELISION` at HIGH with the measurement. `patterns.select_fills` substitutes `0xA5`, verification checks that pattern, and the ETA costs each pass at its own fill's measured rate |

**None of these was caught by the synthetic suite**, which was green throughout
at 757 tests. Loop devices have no controller, no bridge and no FTL: defects 1,
8 and 9 are unreachable on one. Defects 3, 4 and 5 needed a step to fail, and on
a loop device none does. Defects 6 and 7 needed two jobs on one ledger and a key
created after the chain, and every synthetic run had one job and a fixture key.

Every one of them now has a regression test that fails without the fix.

---

## Phase B pre-flight, run before sourcing a card

Two things Phase B depends on that no synthetic run exercises, checked in
advance so the first hardware run finds tool defects rather than harness ones.
Both are settled: the FAT name round-trip has no defect, and the software write
block is verified on this hardware. A third defect turned up while checking
them and is fixed below.

### FAT name round-trip: no defect

B.2 deletes five files by name and then asks `mark-deleted` to mark those names
in a manifest built by walking the *mounted* volume. If the kernel reported a
name differently from the one written, the manifest and the request would
disagree, `mark-deleted` would mark nothing, and the carve recall denominator
would be zero — with `deleted_planted: 0` and `recall_bp: 0` for a run that
worked.

The concern is FAT's 8.3 short names. Checked by building a FAT32 volume the way
Phase B does and decoding the raw directory entries rather than trusting a
tool's rendering:

| Name written | Raw 8.3 entry | Case byte | LFN? | What Linux vfat reports |
|---|---|---|---|---|
| `img00.jpg` | `IMG00.JPG` | `0x18` | no | `img00.jpg` |
| `img00.jpeg` | `IMG00~1.JPE` | `0x00` | yes | `img00.jpeg` |
| `Img02.Jpg` | `IMG02.JPG` | `0x00` | yes | `Img02.Jpg` |
| `IMG01.JPG` | `IMG01.JPG` | `0x00` | no | `IMG01.JPG` |
| `a-very-long-name-00.jpg` | `A-VERY~1.JPG` | `0x00` | yes | `a-very-long-name-00.jpg` |

Case byte `0x18` is `LOWER_BASE | LOWER_EXT`: an all-lowercase name that fits 8.3
is stored uppercase with those bits set and displayed lowercase, which is the
Windows NT rule the Linux `vfat` driver follows under its default
`shortname=mixed`. Anything the bits cannot express gets a long-name entry and
round-trips verbatim. Phase B's `img{NN}.jpg` is the first row.

Corroborated on the real device rather than only in a test image: Phase A's
`a2-manifest.json`, built by walking a mounted vfat volume on this stick, holds
`photo00.jpg` (fits 8.3, case bits) and `memo00.docx` (four-character extension,
so a long-name entry) — both lowercase, in both runs.

End to end, against the five names B.2 actually uses:

```
mark-deleted --names img00.jpg img02.jpg img04.jpg img06.jpg img08.jpg
  {"marked": 5, "not_in_manifest": [], "requested": 5}   exit 0
```

And the failure is loud if it ever does diverge — a manifest built from
uppercase names against the same request:

```
  {"marked": 0, "not_in_manifest": ["img00.jpg", "img02.jpg"], "requested": 2}   exit 1
```

which fails the B.2 phase rather than producing a silent zero recall. That exit
status is new; before the counting fix, `mark-deleted` marked nothing and exited
0.

exFAT is not tested here. It stores names in UTF-16 with no short-name
mechanism and is case-preserving by construction, so the failure mode above
cannot arise; it stays unverified until the run.

### Software write block: verified on this bridge

`scripts/probe-write-block.py`, run against the wiped stick as scratch media:

```
verdict            WRITE_BLOCK_WORKS
flag_at_start 0 -> flag_after_set 1 -> flag_final 0 (restored)
region_distinct_bytes_before [165]   region_changed false
region_sha256 identical before and after
write_attempt      open_refused false, open_errno null,
                   write_refused true, write_errno EPERM, bytes_written 0
apply_write_block  applied true
```

**The write block holds on this hardware.** BLKROSET was honoured, the write was
refused, and the probe region was byte-identical afterwards.

#### The refusal arrives at `write()`, not at `open()`

`open(O_WRONLY)` **succeeded**; `write()` returned `EPERM`. Anything that
verified by opening for write and stopping there would have reported a working
block on a device where the flag was cosmetic. **Test the write, not the open.**

This is a property of the kernel's block layer, not of the bridge: `BLKROSET`
sets `bd_read_only` on the kernel's block device, and the kernel is what refuses
the write. The bridge is not consulted. What the probe establishes about *this
bridge* is that nothing in this stack let the write through.

#### This is a per-interface property, not a Linux guarantee

Do not generalise `WRITE_BLOCK_WORKS` from one bridge to all of them, and do not
read it as "BLKROSET protects a device". Two paths bypass the flag entirely and
are not covered by this result:

- **SG_IO and ATA pass-through.** They address the device below the block layer,
  where `bd_read_only` is never consulted. `hdparm --write-sector` and `sg_dd`
  write straight through a set flag.
- **A partition node whose own flag was never set.** `BLKROSET` is applied to
  the path the acquisition was given. Setting it on `/dev/sda` is not obviously
  the same as setting it on `/dev/sda1`, and an automount writing through the
  partition is exactly the accident a write block exists to stop. Untested here,
  because the stick has no partition table after a wipe. Settle it by running
  the probe against a partition node while the whole-disk flag is set.

Which is why the verification changed from a read-back to an attempted write —
and why the attempted write does not live on the evidence path.

### Why `apply_write_block` still does not attempt a write

The obvious response to the finding above is to make `apply_write_block` verify
by writing. It does not, deliberately.

A write test fails safe **only when the write block works**. It is precisely
when the block does *not* work — the case the test exists to detect — that the
test writes to the device it was protecting. On evidence that is spoliation, and
"we wrote to the exhibit and put it back" is not a position worth defending: the
restore is itself another write, on flash it programs a new page and may remap,
and the honest answer to "did your tool write to the exhibit?" becomes yes, by
design, every time. CLAUDE.md's non-negotiable is unambiguous — the evidence
path is read-only.

So the claim was made honest instead of the test made dangerous:

| | Before | Now |
|---|---|---|
| `applied` | `True` on the read-back | `True` on the read-back — unchanged, and it always only meant "the flag is set" |
| `verified_by` | — | `flag_read_back` |
| Record limitation | none | `WRITE_BLOCK_NOT_VERIFIED`, stating that the refusal was not tested, why, and what does not fall under the flag |

`AcquisitionRecord` gained `write_block_verified_by`, so a reader can tell "the
kernel holds this device read-only" from "a write was attempted and refused".
Verification by attempted write lives in `scripts/probe-write-block.py`, gated
behind `--i-understand-this-may-write-to-the-device`, run once against scratch
media to qualify an interface. That is how write blockers are qualified in
practice: you qualify the equipment, then you trust the qualification, and you
re-qualify when the equipment changes.

### The harness collision, fixed

`apply_write_block` sets `BLKROSET 1` and **nothing ever clears it.** For
evidence handling that is right — the source stays protected after acquisition.
It collides with Phase B being run twice, once per filesystem: the second
invocation opens with `parted` and `mkfs`, both of which need a write open, on a
device the first invocation left read-only.

Both phases now call `harness_clear_write_block` before partitioning. It reads
the flag, and if it is set, says so, says *why* it is being cleared — Phase B
re-purposes an evidence device as a test fixture — clears it, confirms the
clear, and fails the phase if it does not take. Clearing evidence protection is
an explicit logged action, never a side effect.

`parted`, `mkfs` and `mount` in both phases had their output discarded and no
exit check, so a failure surfaced one step later as `could not mount`, pointing
at the wrong thing. All of them are now checked, with their output captured and
printed on failure. In Phase A a failed mount used to `warn` and continue; it
now fails the phase, because A.3's before-count is meaningless without the
planted files, and a run whose before-count is meaningless proves nothing about
its after-count.

---

## Phase B results — MEASURED

### Phase B now runs on USB, not on an SD card

The blocker was never the code. It was that this host has no card reader, and
Phase B was written to target `/dev/mmcblkN`. It now targets whatever removable
block device it is given, and the intended target is the same USB stick Phase A
used.

**What that changes: nothing in the filesystem path. What it does not change:
the media caveat.**

FAT32 and exFAT on USB are the same filesystems as on a card for every
structure the recovery code reads — the same 32-byte directory entries, the same
`0xE5` marker in byte 0 of a deleted name, the same cluster chains zeroed on
delete, the same exFAT stream extension with its `NoFatChain` flag. Neither
`vfat` nor `exfat` on Linux issues a discard on unlink, on either bus, so a
deleted file's clusters still hold its data in both cases. The carver reads an
image file and never talks to the bus; two images of the same FAT32 volume, one
from a card and one from a stick, are the same bytes.

What is **not** the same is the media and its controller — and controller
behaviour is precisely where this project has been burned. Every one of the nine
defects below was bridge or controller behaviour. A card reader is a different
bridge; SD cards run their own wear-levelling firmware; whether a given reader
passes discards through is a property of that reader. **So Phase B on USB
measures the filesystem recovery logic on real removable media, and it does not
measure an SD card's controller.** Both halves of that go in the write-up.

### How Phase B is shaped, and why

| Choice | Value | Why |
|---|---|---|
| Test partition | `--fs-size`, default **256 MiB** | Populating 7.4 GiB at ~4 MiB/s is half an hour per pass and measures nothing the first 256 MiB does not. Recall is a property of deletion mechanics, not of unused space past the last cluster. |
| Filler files | `--filler-bytes`, default **256 KiB** | Matches `testkit/generate_corpus.py`. The synthetic FAT32 row is 244 fillers out of 246 deleted files; a real run of ten JPEGs would be compared against a population it does not resemble. |
| Damage model | `--damage delete\|quickformat` | `delete` removes half the fillers and half the named files. `quickformat` writes a fresh FAT and root directory over the whole volume, which destroys every directory entry and leaves signature carving as the only route. |
| Acquisition scope | `--acquire-scope partition\|device`, default **partition** | The synthetic corpus is volume images, so a volume image is the directly comparable unit — and it is ~30x less to read. `device` images the whole stick, which is what an investigator does and which exercises partition detection. |

#### Cluster geometry: matched to the synthetic corpus, and unrepresentative in the same way

Measured with `mkfs.vfat -F 32` on this host:

| Volume | Sectors/cluster | Cluster size |
|---|---:|---:|
| 40 MiB — `FAT_IMAGE_BYTES`, the synthetic corpus | 1 | **512 B** |
| 128 MiB | 1 | 512 B |
| **256 MiB — the Phase B default** | **1** | **512 B** |
| 512 MiB | 8 | 4096 B |

FAT32 needs at least 65,525 clusters, so anything under about 500 MiB lands on
one-sector clusters. **The 256 MiB default therefore has the same cluster
geometry as the corpus it is compared against**, which is what makes the
comparison a comparison.

It also inherits the corpus's limitation: **512-byte clusters are not what real
media uses.** A retail card or stick is formatted with 4 KiB to 32 KiB clusters,
and cluster size changes how much slack each file leaves and how coarse the
allocator's decisions are. Neither the synthetic corpus nor this run describes
that. `--fs-size 512` buys 4 KiB clusters and costs the direct comparison;
running both is the honest answer if there is time.

#### One other deliberate difference

`build_fat32` fragments one file by writing it into holes left by deleted
fillers. The USB run does not fragment anything.

This was written up as making the run "marginally optimistic against the
synthetic row — by one file in a few hundred". **After the run, that reads as an
understatement.** Not fragmenting anything does not cost one file: it removes the
only condition under which FAT walk-forward reconstruction can produce the wrong
answer, and it is why both delete passes returned 100.00%. See "100% recall is a
statement about a contiguous population" below.

### B.3 Acquisition

Three passes, 2026-09-05, all against the same Toshiba TransMemory USB stick,
serial `B103B9C19DE1CCC1BD535ACB`, partition scope (`/dev/sda1`, 267,386,880
bytes). Every acquisition verified itself against its own `AcquisitionRecord`
inside `cmd_acquire`.

| Filesystem | Damage | Format | Bytes read | On disk | MiB/s | Integrity |
|---|---|---|---:|---:|---:|---|
| FAT32 | delete | raw | 267,386,880 | 267,386,880 | 23.44 | pass |
| FAT32 | delete | E01 | 267,386,880 | 267,488,019 | 23.73 | pass |
| exFAT | delete | raw | 267,386,880 | 267,386,880 | 24.03 | pass |
| exFAT | delete | E01 | 267,386,880 | 267,488,017 | 24.08 | pass |
| FAT32 | quickformat | raw | 267,386,880 | 267,386,880 | 23.65 | pass |
| FAT32 | quickformat | E01 | 267,386,880 | 267,488,014 | 23.80 | pass |

"Integrity: pass" is the full verdict in each case: `sha256=True`,
`blake3=True`, `verified=267386880 bytes`, `mismatched_chunks=0`,
**`bad_sectors=0`**. Six acquisitions of a stick that this validation has
written end to end twice in Phase A and re-partitioned, re-formatted and
repopulated three times more in Phase B, and not one unreadable sector.

The E01 came out **larger** than the source every time, by 101,134 to 101,139
bytes. That is expected and documented: `pyewf` binds no compression setter and
libewf's default is no compression, so an E01 is the source plus segment
headers. See `docs/limitations.md`.

Wall clock, whole phase: 192.15 s (FAT32 delete), 86.60 s (exFAT delete),
130.04 s (FAT32 quickformat). `{"failed_phases": [], "failures": 0}` on all
three.

### B.4 Real media versus the synthetic calibration

**This table is the point of Phase B.** Every confidence number the report
prints comes from weights calibrated on synthetic images. If real-media recall
diverges, the calibration describes something other than reality and every
number inherits the error.

| Filesystem | Damage | Real deleted | Real exact | Real recall | Synthetic recall | Δ | Flagged as run | Flagged now |
|---|---|---:|---:|---:|---:|---:|---|---|
| fat32 | delete | 456 | 456 | **100.00%** | 95.53% (n=246) | +4.47 pt | no divergence | `agrees` |
| exfat | delete | 460 | 460 | **100.00%** | 50.00% (**n=2**) | +50.00 pt | diverges | `baseline_underpowered` |
| fat32 | quickformat | 912 | 10 | **1.10%** | 95.53% (n=246) | −94.43 pt | diverges | `no_baseline` |

Synthetic figures from `docs/performance/calibration-filesystems.csv`. The
harness flags a recall gap wider than 10 percentage points.

**Both flagged rows were flagging the harness, not the media.** Neither was a
real-media divergence. The next three sections say why, and each ends with what
was changed so the next run cannot repeat it — the "Flagged now" column above is
what `cmd_compare` reports after those changes, against the same numbers.

One caveat on reproducing that column from the archived JSON: the three
`b4-carve-*.json` files in `results-20260905T08*` predate `--damage`, so
`compare` reads them as delete runs and the quick-format row still comes back
`diverges`. Re-running the pass records the damage model and the row comes back
`no_baseline`; the behaviour is covered by
`tests/scripts/test_compare_baseline.py` rather than by re-reading a file
written before the field existed.

#### The exFAT flag is an under-powered synthetic row

The exFAT calibration row is `n=2`: one file with `NoFatChain` set that came
back, one that used a chain the deletion destroyed and did not. 460 of 460 on
real media against "50%" from two files is not a divergence between synthetic
and real. It is a comparison against a number that was never a rate. The row
should be excluded from the divergence test until the synthetic exFAT corpus is
large enough to be one.

**Fixed.** `MIN_BASELINE_N = 30`. Below it the comparison reports
`baseline_underpowered`, still prints the gap, and does not call it a
divergence.

#### The quick-format flag compares two different experiments

`cmd_compare` looked the calibration row up by **filesystem name alone**.
`calibration-filesystems.csv` had no damage-model column, so the quick-format
pass was scored against the FAT32 **delete** baseline. Those are two different
experiments with two different recoverable sets, and −94.43 points is the
distance between them, not an error in the calibration.

**Fixed.** `calibration-filesystems.csv` now carries a `damage` column, `carve`
takes `--damage` and records it, and the baseline is keyed on
`(filesystem, damage)`. Nothing in `testkit/` quick-formats a volume, so that
row now comes back `no_baseline` — a new measurement, which is what it is,
rather than a comparison against the wrong experiment.

#### The calibration's precision column measures a different pipeline

`testkit/calibrate.py` builds the per-filesystem table by calling
`undelete_report()` and nothing else — the signature carver never runs. That is
visible in the CSV itself: the FAT32 row has `candidates == named == 244`, so
every synthetic candidate came from a directory entry. The real runs carve
signatures as well as undelete. **`precision_bp` therefore means "undelete
precision" on the synthetic side and "undelete + signature-carve precision" on
the real side, under one column name.** Every signature-carve false positive
below exists only on the real side of the comparison.

**Fixed by comparing like against like rather than by changing the corpus.**
The CSV now carries a `pipeline` column (`undelete` for every existing row),
`carve` splits its candidates by `source` into a `by_pipeline` block, and
`compare` scores the baseline against the slice the baseline actually measured.
Running the signature carver inside `testkit/calibrate.py` as well would move
every published calibration figure, which is not a change to make in the week of
a demo; the slice costs nothing and says which half it is talking about.

On this run the undelete slice is 456 candidates of 470 on FAT32 and 460 of 474
on exFAT, all of them correct, so the like-for-like precision is **100.00%
against the baseline's 96.31%**.

### The quick-format collapse: not discard, not a carver defect

1.10% is neither of the two things it looks like. **The data is provably still
on the media, and the carver recovered every file it was possible to recover.**

#### What the population actually is

`hardware-validation.sh` plants 10 named JPEGs and 902 filler files. The fillers
are `rng.randbytes(262144)` — 256 KiB of pseudo-random bytes each, deliberately
never zeros. **They carry no header, no footer and no signature of any kind.**
No signature carver can find them, on any media, ever. The only route to a
filler is its directory entry.

A quick format destroys every directory entry. That removes the only route to
902 of the 912 planted files and leaves signature carving, which can address the
10 JPEGs and nothing else.

**The ceiling for that pass was 10 files. 10 / 912 = 1.10%.** The carver hit the
ceiling exactly: 10 of 10 named JPEGs, all byte-identical to the manifest, all
in HIGH. Recall against the set that was recoverable at all was **100.0%**.

#### Proof the bytes survived the format

Three independent lines, two of them from the run's own output:

* **The 10 JPEGs came back byte-exact from raw signature carving after the
  `mkfs`**, at offsets 4,130,304 through 4,416,000 — the very start of the data
  area, the region a discard would take first.
* **Eight of the nine false positives in the quick-format pass are byte-identical
  to eight from the FAT32 delete pass, at identical offsets**, and all eight were
  traced (below) into the *filler payloads*. The furthest is at offset
  239,764,738, near the end of a 267 MB volume. Filler bytes were still
  physically present, from 7.8 MB to 239.8 MB, after the quick format.
* **The device advertises no discard at all.** `lsblk -D` reports `DISC-GRAN 0B`
  and `DISC-MAX 0B` for `/dev/sda` and `/dev/sda1`, so the kernel will refuse a
  `BLKDISCARD` and `fstrim` has nothing to issue. Separately, **`mkfs.fat` 4.2
  has no discard support** — no option, no code path. The warning this document
  used to carry ("`mkfs` may issue discards") was hypothetical and is wrong for
  this combination of tool and device.

#### The 2.863 s carve time does not corroborate "data gone"

It corroborates "no metadata candidates". The signature scan in the quick-format
pass covered **more** ground than in the delete pass — `unallocated_bytes`
267,386,880 against 148,984,299 — because no filesystem could be opened and the
whole image became unallocated. What the quick-format pass did not do was read,
hash and write out 456 reconstructed 256 KiB files: 6.8 MiB of recovered output
against 120 MiB. That is the 8 seconds.

#### What this pass therefore measures, and what it does not

It measures that the harness's quick-format damage model works and that this
controller does not discard. **It does not measure quick-format recovery**,
because 98.9% of its denominator was unfindable by construction the moment the
directory entries went. A pass that could measure it needs a population of
signature-bearing files — the same JPEG/PDF/ZIP mix `testkit/generate_corpus.py`
uses for its format rows — rather than 902 headerless blobs.

#### The finding that does survive, and it is not a small one

A quick format on this media **does not sanitize anything**. Every byte of 225.8
MiB of planted data was still there afterwards. Sanctum recovered only 10 files
because 902 of them were random noise with no structure to recognise; a real
volume holds documents, and a signature carver over that image would return most
of them. **Quick format is not a clear and not a purge:** NIST SP 800-88r2
Sec. 3.1.1 defines clear over all user-addressable storage locations, and this
format left 225.8 MiB of them holding planted data. If a report is ever asked
whether a formatted volume is sanitized, this
run is the evidence that the answer is no.

### Precision: what the extra candidates are

Precision is **98.09%** and **98.10%** on the delete passes and 52.63% on the
quick-format pass. The run itself recorded 97.02% and 97.05%, which was a
scoring error, not a measurement: see below the table. Every candidate in all
three passes accounted for:

| Pass | Bucket | Candidates | Score | What they are |
|---|---|---:|---:|---|
| fat32 delete | HIGH | 5 | 1.0000 | deleted JPEGs, recovered **with their names** from surviving directory entries |
| | HIGH | 5 | 0.9000 | **live** JPEGs, signature-carved, byte-exact |
| | MEDIUM | 451 | 0.5500 | deleted fillers, undeleted, byte-exact |
| | MEDIUM | 5 | 0.5000–0.6000 | **false positives** |
| | LOW | 4 | 0.3000–0.4500 | **false positives** |
| exfat delete | HIGH | 5 | 1.0000 | deleted JPEGs, named |
| | HIGH | 5 | 0.9000 | live JPEGs, signature-carved, byte-exact |
| | MEDIUM | 455 | 0.5500 | deleted fillers, undeleted, byte-exact |
| | MEDIUM | 5 | 0.5000–0.6000 | **false positives** |
| | LOW | 4 | 0.3000–0.4500 | **false positives** |
| fat32 quickformat | HIGH | 10 | 0.9000 | all 10 JPEGs, signature-carved, byte-exact, unnamed |
| | MEDIUM | 8 | 0.5000–0.6000 | **false positives** |
| | LOW | 1 | 0.3500 | **false positive** |

**The 14 "extra" candidates on each delete pass are 5 correct recoveries plus 9
false positives.**

The 5 are the live JPEGs. They are byte-identical to files that were planted and
never deleted, and the carver found them by signature over the unallocated map.
`cmd_carve` counted a candidate as correct only if it matched a **deleted**
file, so five correct recoveries were scored as misses. **Precision on the
delete passes is 461/470 and 465/474 — 98.09% and 98.10% — not the 97.02% and
97.05% the run printed.**

**Fixed.** A candidate is correct when its bytes match any planted file, live or
deleted. `precision_bp` counts candidates rather than digests and includes live
hits; `deleted_hit_candidates`, `live_hit_candidates` and
`false_positive_candidates` are reported separately so the composition is
visible rather than inferred; and the old figure survives under
`precision_deleted_only_bp` so nothing already written up becomes
irreproducible. **Recall is untouched** — a live file is not in its denominator
and never was, so 100.00% and 1.10% stand exactly as measured.

#### Where the 9 false positives come from, exactly

All nine are manufactured out of the random filler bytes. Regenerating the
filler stream from its seed (`random.Random(7)`, verified byte-exact against the
manifest: 10/10 named, 902/902 fillers) and searching it for each false
positive's content:

| Offset in image | Size | Type | Found inside filler | Filler # |
|---:|---:|---|---|---:|
| 7,801,802 | 39,274 | JPEG | yes | 12 |
| 28,883,523 | 135,766 | JPEG | yes | 93 |
| 29,848,084 | 26,547 | JPEG | yes | 96 |
| 72,489,255 | 8,161 | JPEG | yes | 259 |
| 126,396,441 | 12,998 | JPEG | yes | 465 |
| 133,023,550 | 15,853 | JPEG | yes | 490 |
| 138,418,155 | 27,546 | JPEG | yes | 510 |
| 239,764,738 | 109,706 | JPEG | yes | 897 |
| 233,389,610 | 6,375,128 | ZIP | starts inside, runs past the end of the stream | ~890 |

The filler stream is 236,453,888 bytes of pseudo-random data. It contains
**exactly 8 occurrences of `FF D8 FF`** and **exactly 1 of `50 4B 03 04`** — and
the carver produced exactly 8 JPEG false positives and exactly 1 ZIP false
positive. Chance alone puts about 14 three-byte JPEG SOI markers in 236 MB of
random bytes; 8 is that number.

**This is the signature carver working correctly on a corpus designed to defeat
it.** A 256 KiB block of random data is the worst possible input for signature
carving, and 902 of them is 236 MB of it. It is not a defect and it is not
something to tune away.

#### The buckets held, and that is the result that matters

Pooling all three passes — 963 candidates:

| Bucket | Candidates | True | Precision, real media | Precision, synthetic (n=33) |
|---|---:|---:|---:|---:|
| HIGH | 30 | 30 | **100.00%** | 100.00% |
| MEDIUM | 924 | 906 | 98.05% | 100.00% (**n=2**) |
| LOW | 9 | 0 | **0.00%** | 0.00% |

("True" = byte-identical to a file this run planted, live or deleted.)

**Not one false positive reached HIGH, in any pass.** HIGH is 30 for 30 on real
media, which is exactly what `docs/performance/calibration.md` measured on the
synthetic corpus. **The score weights do not need revisiting**, and the
`fs_metadata` weight that the calibration deliberately held at 1500 is consistent
with this run rather than challenged by it.

> **Note added 2026-09-14.** Every Phase B figure here was measured on the carve
> pipeline as it stood on 2026-09-05, which called the signature carver alone.
> Batch 2 then routed `api/carve_job.py` through `carve_structures` — format
> parsers and bifragment reassembly — which is the pipeline the calibration
> measured and the one that ships. The conclusion above is therefore agreement
> between two different pipelines, not a real-media measurement of the shipped
> one. That measurement is the next hardware run.

LOW also behaved as designed: 9 candidates, 0 true, which is the bucket the
report tells an examiner to skip.

**MEDIUM is the band with a real problem, and the synthetic corpus could never
have shown it.** Within MEDIUM, confidence does not rank truth: 906 correct
recoveries scored **0.5500**, and one false positive scored **0.6000** — above
all of them. The MEDIUM floor is doing its job (nothing false got past 0.8000)
but the ordering inside MEDIUM carries no information. The synthetic MEDIUM row
is `n=2` and says 100.0%, so this is the first measurement of that band that
means anything.

### 100% recall is a statement about a contiguous population

**0 of the 456 and 0 of the 460 recovered files needed multi-extent
reconstruction, because not one file on either volume was fragmented.**

That is by construction, and the harness says so. `hardware-validation.sh`
populates a freshly formatted volume in a single sequential pass and only then
deletes; nothing is ever written into a hole. The script's own comment records
the deliberate difference from the synthetic corpus:

> `build_fat32` fragments one file by writing it into holes left by deleted
> fillers. The USB run does not fragment anything. That makes it marginally
> optimistic against the synthetic row — by one file in a few hundred.

The FAT reconstruction is the code this matters for. FAT deletion zeroes the
cluster chain; the start cluster and the recorded size survive and the layout
does not, so `fsaware` walks forward from the start cluster taking clusters the
FAT shows as free. On a contiguous file the first `size` bytes from the start
cluster are the file, and the walk cannot go wrong. **The failure mode that
`contiguity_assumed` exists to warn about — a deleted neighbour's freed clusters
being pulled in — was never exercised**, even though half the files on the volume
were deleted, because contiguity made the neighbours' clusters irrelevant.

So the honest claim is **100% recall on a contiguous population**, and every
candidate on both delete passes is still marked `contiguity_assumed`, correctly.
What real media does to fragmented files remains unmeasured. That is now the
single largest untested assumption in the recovery path, and it needs a Phase B
pass that fragments deliberately: fill the volume, delete alternate fillers,
then write files sized to span several of the resulting holes.

### Six things this run found in the harness

None of them is in the carver, and none of them changes a recall figure above.
Four are fixed, with a regression test each in
`tests/scripts/test_compare_baseline.py`. Two are open and are open deliberately.

**Fixed:**

1. **`cmd_compare` ignored the damage model.** It looked the calibration row up
   by filesystem name, so a quick-format run was scored against a delete
   baseline. `calibration-filesystems.csv` now has a `damage` column, `carve`
   takes `--damage`, and the lookup is keyed on `(filesystem, damage)`.
2. **`precision_bp` named two different pipelines** — undelete-only on the
   synthetic side, undelete + signature carve on the real side. The CSV now
   declares a `pipeline`, `carve` emits a `by_pipeline` split by candidate
   `source`, and `compare` scores the slice the baseline measured.
3. **A correctly recovered live file was scored as a false positive.**
   Correctness is now "matches any planted file", live or deleted; the deleted
   set is still what recall is measured against.
4. **The divergence test had no minimum n.** It flagged an `n=2` synthetic row
   as a real-media divergence. Below `MIN_BASELINE_N = 30` the comparison now
   reports `baseline_underpowered` and prints the gap without calling it a
   finding.

**Open, and why:**

5. **The quick-format damage model cannot measure quick-format recovery**
   against a filler-dominated population. The fix is a signature-bearing corpus,
   which changes what the pass plants and therefore what every Phase B recall
   figure is measured over. That is a new experiment, not a repair, and it goes
   after the demo.
6. **The harness deletes the image after a successful carve.** The quick-format
   result was surprising and the image it came from was already gone, so the
   raw-byte check had to be reconstructed from the recovered candidates instead
   of read directly. A `--keep-images` flag costs 267 MB and one line. It is not
   in yet because adding a flag to the Phase B path without a Phase B run to
   exercise it is how the nine Phase A defects got in.

---

## Behaved differently on real hardware than on loop devices

Eight things behaved differently from every loop-device run, and five of them
were defects. Two more were confirmed only by the third run.

1. **`hdparm -N` through a USB bridge answers, wrongly, and exits 0.** It printed
   `max sectors = 0/1, HPA setting seems invalid`. No loop device can produce
   this, and trusting it cost the first run its entire wipe. The probe is now
   skipped on bridged transports and sanity-checked everywhere else.
2. **PhotoRec on a zeroed device reports one candidate per 80 KiB.** 94,720 of
   them in run 2, none matching any planted file; 0 in run 3, because the medium
   ends holding `0xA5`. On a loop device nobody had ever pointed a carver at a
   freshly wiped medium, so the artefact had never appeared. It is a property of
   signature carving on uniform data, not of the wipe.
3. **Write throughput depends on the byte written.** ~4.0 MiB/s for any byte the
   controller programs against 13.92-14.19 MiB/s for `0x00`, same buffer, same
   code, same device. Loop devices run at RAM speed and hide this completely. It
   roughly doubles what a 3-pass estimate should say.
4. **The report's chain check cannot handle a filtered excerpt.** Every
   loop-device run had a single job on a fresh ledger, so the excerpt was always
   contiguous and the whole-chain rule always held. The first run with two jobs
   on one ledger broke it in all three tamper stages.
5. **Genesis records the signing key's fingerprint, and the key did not exist
   yet.** Again invisible with one job and a fixture-built ledger.
6. **`rotational` is `True` for a flash stick, and three code paths believed
   it.** The bridge does not set the kernel's non-rotational flag, and `lsblk`
   agrees, so it never showed up as a disagreement. `flash = not
   device.rotational` was the flash test in the residual assessment, in the DoD
   pass warning, and (as `rotational == "0"`) in the per-file TRIM detection.
   All three silently skipped their flash caveats on the one class of device
   most likely to need them. Replaced by `core/device/media.py:is_flash`, which
   makes a positive determination and returns the signal that decided it.
7. **Zeros are not written at all.** The controller acknowledges a zero fill
   3.25-3.62x faster than it programs any non-zero byte, reproduced across two
   runs and three sample sizes. A loop device cannot show this: it has no
   controller.
8. **Zeros are not *read* from the medium either.** The same device reads `0x00`
   at 39.13 MiB/s and `0xA5` at 23.9 MiB/s, with two independent reads of the
   `0xA5` medium agreeing to 0.2%. Consistent with the FTL answering a
   zero-mapped block without touching NAND on the read path; recorded as an
   inference from timing, not a proven mechanism.

Candidates still to watch for, from what the code assumes. Struck-through
entries were resolved by the run:

- ~~**`hdparm -I` through a USB bridge.**~~ Confirmed: `CLEAR` only, with the
  bridge named in the limitations. The probe did not report PURGE. What was not
  anticipated is that `hdparm -N` would answer with nonsense and exit 0; see
  above.
- **`BLKROSET` on a USB device.** The acquisition path sets the block device
  read-only and reads the flag back. Whether that takes on a USB bridge is
  untested.
- ~~**Write throughput.**~~ Measured: **~4.0 MiB/s** write and **~23.9 MiB/s**
  read for any byte this controller actually handles, against RAM speed on loop
  devices. The 14.19 MiB/s write and 39.13 MiB/s read figures for `0x00` are
  elision, not throughput. 29 checkpoints were recorded across the 1886.3s write
  in run 3, so the checkpoint interval behaved, and the ETA now costs each pass
  at its own fill byte's measured rate — 8.3% optimistic on a 64 MiB sample.
- ~~**`O_DIRECT` alignment.**~~ Confirmed working: this stick reports a
  512-byte logical block, `O_DIRECT` was accepted for both the pattern write and
  the erase, and no fallback to `O_DSYNC` was recorded. A device reporting a
  4096-byte physical block over a 512-byte logical one is still untested.
- ~~**Verification sampling.**~~ Confirmed: `full_read`, `sample_count: 0`,
  every addressable block compared. The sampled path stays untested until
  something larger than the 64 GiB threshold is used.
- ~~**Data surviving a power cycle.**~~ Not on the original list, and it should
  have been. A controller that satisfies reads from a mapping rather than from
  cells could lose that mapping across a power cycle. Tested after run 3:
  unplug, 30s, replug, full re-verify against `0xA5` — `passed: true`,
  `failed_offsets: 0`. The Clear outcome is durable on this device.
- **Device disappearing mid-wipe.** A cheap stick that overheats and re-enumerates
  is a real failure mode and exercises `DeviceVanished` for the first time.

---

## How to run it

```bash
sudo dnf install -y testdisk           # PhotoRec, for steps A.3 and A.6

# Phase B formats the device, and a desktop will automount the volume it just
# made. The harness refuses a mounted device - correctly - so the second and
# third passes fail at the gate unless it is unmounted first:
udisksctl unmount -b /dev/sdX1 2>/dev/null || true

# Phase A, against a SCRATCH usb stick - this destroys everything on it
sudo ./scripts/hardware-validation.sh \
    --device /dev/sdX \
    --i-understand-this-destroys-data \
    --phase a

# Phase B, against a USB stick, once per filesystem-and-damage combination.
# Each invocation writes its own docs/validation/results-<timestamp>/ and
# prompts for the serial. Phase B destroys whatever Phase A left on the device.
sudo ./scripts/hardware-validation.sh --device /dev/sdX \
    --i-understand-this-destroys-data --phase b \
    --filesystem fat32 --damage delete
sudo ./scripts/hardware-validation.sh --device /dev/sdX \
    --i-understand-this-destroys-data --phase b \
    --filesystem exfat --damage delete
sudo ./scripts/hardware-validation.sh --device /dev/sdX \
    --i-understand-this-destroys-data --phase b \
    --filesystem fat32 --damage quickformat

# Optional fourth pass: image the whole stick rather than the test volume, to
# exercise partition detection and whole-device acquisition. Adds ~10 min of
# reading plus a much slower carve.
sudo ./scripts/hardware-validation.sh --device /dev/sdX \
    --i-understand-this-destroys-data --phase b \
    --filesystem fat32 --damage delete --acquire-scope device
```

The script refuses without the flag, refuses a mounted device, refuses the
system disk, refuses a non-removable device without `--allow-fixed`, and then
asks for the device serial to be typed — the same two-gate shape the tool
itself enforces.

Phase A now exits non-zero when any phase failed and writes `zz-failures.json`
either way, so `echo $?` is a usable verdict.

### The power-cycle check

After Phase A, unplug the device, wait 30 seconds, replug it, and re-verify
against the byte the erase actually wrote — which is in `plan.fill_bytes` of
`a4-erase.json`, and is **not** `0x00` on a controller that elides zeros:

```bash
FILL=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["result"]["plan"]["fill_bytes"][-1])' \
        docs/validation/results-<timestamp>/a4-erase.json)

sudo .venv/bin/python scripts/hardware_validation.py verify \
    --device /dev/sdX --expect-fill "$FILL" | tee a5-postcycle.json \
  | python3 -c 'import json,sys;r=json.load(sys.stdin)["result"];print("passed:",r["passed"],"failed_offsets:",len(r["failed_offsets"]))'
```

`verify` exits 0 even when verification fails — a disappointing measurement is a
finding, not an error — so read `.result.passed` rather than the exit status.

### A hand-run verify after staging fails on purpose, in two places

A verify run by hand against a device that has since been *staged* — partitioned
and formatted for a demo or a rehearsal — reports a failure that looks alarming
and is not. It happened on 2026-09-05 against the 7.4 GiB validation stick and
cost an evening, so it is written down here.

The symptom, from a `full_read` verify expecting the fill the erase wrote:

```
verification_complete bytes_checked=7759462400 failures=17 passed=False
  failed_offsets [0, 1048576, 2097152, ... , 15728640, 7759452672]
```

Seventeen offsets: sixteen at a 1 MiB stride from zero, and one 9,728 bytes
before the end of the device. Two separate causes, neither of them the eraser.

**Read `failed_offsets` correctly first.** `_read_windows` in
`core/erase/verify.py` records the *first* bad byte of each read chunk and then
moves to the next chunk, and `VerifyConfig.read_chunk` is 1 MiB. So sixteen
consecutive strided offsets do not mean sixteen scattered bad bytes — they mean
the whole first 16 MiB is not the expected fill. Everything between 16 MiB and
7,759,452,672 held it.

**The head** is the filesystem. `dmesg` showed `sda: sda1`, so the stick carried
a partition table again: staging had partitioned and formatted it after the
erase. A `mkfs.vfat` reserved area plus two FATs lands inside the first 16 MiB.
Expected by sequence.

**The tail is `parted`.** `parted mklabel msdos` zeroes the last 19 sectors of
the device — libparted clears the GPT backup area so a stale GPT cannot shadow
the new msdos label. On this device that is bytes 7,759,452,672 to the end,
which is exactly where the verify pointed. It reproduces on a plain file, with
no device and no root:

```bash
truncate -s 7759462400 img
python3 -c 'fh=open("img","r+b"); fh.seek(7759462400-(1<<20)); fh.write(b"\xa5"*(1<<20))'
parted -s img mklabel msdos
tail -c 65536 img | od -An -tu1 -v | tr ' ' '\n' | grep -v '^$' | sort | uniq -c
```

| last 64 KiB | `0xa5` | `0x00` |
|---|---:|---:|
| `/dev/sda`, after staging | 55808 | 9728 |
| `img`, after `mklabel msdos` | 55808 | 9728 |

Byte-identical, and the first zero sits at 7,759,452,672 in both. Measured with
GNU parted 3.6. `mkpart` is not involved — `mklabel` alone does it. `mklabel
gpt` also writes over the end of the device, but with a backup header and entry
array rather than zeros. `wipefs -a` leaves the tail untouched.

Staging calls it at `scripts/demo-reset.sh:878`, and again at `:446` and `:513`.

**None of this touches the erase claim.** The staging `parted` runs *before* the
wipe, and the wipe then covers the whole device including the tail:
`_overwrite` pads a trailing partial block rather than short-writing it, and for
a software method `choose_strategy` picks `full_read` at or under
`VerifyConfig.full_read_max_bytes` (64 GiB), so a 7.4 GiB device is read end to
end and the last 19 sectors are checked every time — no sampling, nothing to
miss. Two consecutive recorded runs on this exact stick confirm it:

```
results-20260904T212839Z/a5-verify.json  passed=true  failed_offsets=[]  bytes_checked=7759462400
results-20260905T033655Z/a5-verify.json  passed=true  failed_offsets=[]  bytes_checked=7759462400
```

So: do not stage a smaller partition to avoid the tail, and do not treat this as
a media defect. The media persists writes there; the two passing full reads
above are the evidence.

**Telling this apart from a real failure.** A genuine one is a verify run
directly after an erase, with nothing between them — which is what the harness
does, A.4 straight into A.5. If a device has been partitioned since the erase,
re-verifying it against the erase fill measures the staging, not the wipe. Check
`docs/validation/results-<timestamp>/a5-verify.json` from the run itself before
believing a hand-run verify.

Read while chasing this and fixed separately: `_overwrite` advanced its offset
by the length it handed to `os.write` rather than the length that came back, so
a short write would have left a hole under a run still reporting a complete
overwrite. It now finishes short writes, and reconciles what it planned against
what it wrote before returning — see `OverwriteIncomplete` in `core/errors.py`.

Results land in `docs/validation/results-<timestamp>/` as one JSON file per
step, written as each step finishes, so a crash halfway through still leaves
everything measured up to that point. They are gitignored: one run is 7.3 GB of
PhotoRec output, and its ledger and signing key are root-owned 0600 by design.

Fill this document from those files. Do not fill it from anywhere else.
