# Slide outline — ten slides

> **Superseded for the final presentation (2026-09-24).** This document
> describes the earlier six-minute demo, which erased the USB stick live on
> stage. The final presentation is the 4.5-minute order in
> [`docs/validation/demo-evidence-index.md`](../validation/demo-evidence-index.md),
> answered from [`docs/validation/judge-defense-card.md`](../validation/judge-defense-card.md).
> It performs **no** physical write: the Sanitize beat stops at the approval
> gate and erase is not pressed. The numbers on these slides are sourced; the demo
> slide (7) and its timings are not the final order.
>
> **Capability state (2026-09-28).** These slides predate the Windows and macOS
> native backends. Any statement about what runs on which platform comes from the
> generated
> [`capability-matrix.md`](../validation/capability-completion-2026-09-28/capability-matrix.md),
> not from this outline. Physically validated, by device class, is only: Linux
> discovery, whole-drive clear and raw acquisition on one USB stick (`usb-flash`,
> 2026-09-05), Windows discovery on a USB stick (`usb-flash`, 2026-09-27) and
> Windows file erase on the host disk (2026-09-27). Firmware Purge, HPA changes,
> restore, and Windows/macOS whole-drive clear and raw acquisition are
> implemented and not physically validated.

Outline only. Each slide carries **one number nobody else in the room has**,
large, with its source underneath. Everything else on the slide is support for
that number.

Rule for building these: if a bullet cannot be traced to a file in this
repository, cut it. The whole pitch rests on the audience believing our numbers,
and one unsourced claim costs more than any slide gains.

---

## 1 · The problem

> # 3.6×
> **How much faster this USB controller acknowledges a zero write than it can
> program the medium.**
> *Measured, `docs/limitations.md`*

- Sanitization is a claim, and almost nobody measures whether the claim is true.
- A zero-fill wipe on this controller completes, verifies, and leaves the cells
  holding what they held before. Every read comes back zero — from the flash
  translation layer, not from the medium.
- Every wiping tool we know of would have passed this device.
- Recovery has the mirror problem: a tool hands you files with no defensible
  statement of how likely they are to be the file that was there.

**Say:** "Both halves of this problem are the same problem. Nobody is measuring
what they claim."

---

## 2 · Architecture

> # 1
> **One privilege boundary. A static allowlist, typed handlers, and no shell
> string ever crosses it.**
> *`helper/daemon.py`, `docs/privilege-boundary.md`*

- UI and API run unprivileged. `core.*` never touches the network. The API binds
  `127.0.0.1` in code, not in configuration.
- Root lives in one daemon behind a 0600 Unix socket that checks `SO_PEERCRED`.
- The UI is served from disk under `default-src 'self'`: no CDN, no font, no
  beacon. **It works with the ethernet unplugged.**
- Development uses an in-process helper running the *same* allowlist through the
  *same* dispatcher, so the two paths cannot diverge.

**Say:** "An erase console reachable from the network is a remote wipe
primitive. No authentication scheme we could ship would make that a good trade."

---

## 3 · The three modules

> # 1211
> **Tests passing, 12 skipped — and nine defects that none of them caught.**
> *`make test`; the nine are on slide 6*

| | Module | Does |
|---|---|---|
| **M1** | Secure Drive Eraser | capability-probed method selection, NIST Clear/Purge/Destroy, verified read-back |
| **M2** | Secure File & Folder Eraser | targeted erasure, per-filesystem caveats stated rather than assumed |
| **M3** | Advanced Carving & Recovery | undelete from surviving metadata + signature and structure carving, two-run baseline-JPEG reassembly (gap ≤ 2 MiB, on the volume's own cluster grid, never above MEDIUM), decoder-validated, calibrated confidence |

- One vocabulary throughout: **sanitize** destroys, **carve** recovers without
  filesystem metadata, **undelete** recovers using it.
- One hash-chained ledger and one signing key across all three.

**Say:** "The test count is on this slide so that slide six lands. Green is not
the same as correct."

---

## 4 · The differentiator: residual risk, stated not implied

> # `high`
> **The risk level our own tool assigned to its own clean, fully verified wipe.**
> *`docs/validation/results-20260905T033655Z/a4-erase.json`*

Every byte written. Every byte verified. Verified again after a power cycle.
And the report still says **`purge_achieved: false`**, residual risk **high**,
with four factors named:

1. the pattern substitution, and what the medium holds afterwards;
2. HPA/DCO not probed — this is behind a USB bridge, and a bridge's answer to a
   SET_MAX query describes the bridge, not the medium;
3. no firmware sanitize reachable through the bridge;
4. overwrite on flash cannot reach remapped or over-provisioned blocks, and
   **no host-side read can establish physical removal on flash**.

Plus one structured finding: `CONTROLLER_WRITE_ELISION`, severity HIGH, with the
timing attached.

**Say:** "Every other tool in this space reports success. We report success and
then tell you the four things that success does not cover. That is the product."

---

## 5 · Calibration: the weight we did not move

> # 1500
> **`fs_metadata`. At 5000 the aggregate scores 95.6% precision against 100.0% —
> and it is worse.**
> *`docs/performance/calibration.md`*

- Weights swept 0 → 5000 against a corpus with known ground truth. A candidate
  counts as a true positive only when its **SHA-256 matches**.
- At 5000, precision and recall both jump. The gain comes from promoting **237
  candidates no decoder confirmed** — and among them is a FAT32 recovery the
  corpus knows is wrong, scored HIGH.
- Below 2000 the sweep is flat. **1500 is the largest value the evidence
  permits, not a number somebody chose.**
- Three weights did move, each with the measurement that moved it. HIGH recall
  60.0% → 86.7%, precision unchanged at 100.0%.
- Calibration found three shipped defects on the way: `parse_zip`, `parse_pdf`
  merging two PDFs into one HIGH-scored false positive, and the entropy
  component being awarded to candidates holding **zero bytes**.
- **Then real media agreed — on the pre-Batch-2 pipeline.** Across three Phase B
  passes on a USB stick, **HIGH was 30 candidates and 30 true positives — 100.00%
  precision**, the same figure the synthetic corpus produced. **Not one false
  positive reached HIGH**, including 27 signature hits manufactured out of 236 MB
  of pseudo-random filler. Those passes ran before structure carving was wired
  in; the shipped pipeline has not yet been measured on real media.
- Where real media went further than the corpus could: **inside MEDIUM the score
  does not rank truth.** 906 correct recoveries scored 0.5500 and a false
  positive scored 0.6000. The bucket floor separates them; the number within the
  bucket does not. The synthetic MEDIUM row is n=2 and could never have shown
  that.

**Say:** "The row that looks best is the one to distrust. We published the sweep
so you can check that yourselves — and real hardware returned the same HIGH
precision the corpus predicted, on the pipeline before structure carving went in.
The shipped one is the next hardware run."

---

## 6 · Nine defects real hardware found

> # 512
> **Bytes written, of a 7,759,462,400-byte device, by a run that printed
> `COMPLETE` and exited 0.**
> *Run 1, `docs/validation/hardware.md`*

- `hdparm -N` through a USB bridge prints `HPA setting seems invalid` **and
  exits 0**. We trusted the exit code. The geometry silently shrank to one
  sector. PhotoRec then recovered **14 of 14** planted files.
- Nine defects between run 1 and run 3. **None was caught by 757 green tests.**
- Three are physically unreachable on a loop device — no controller, no bridge,
  no FTL. Three needed a step to fail, and on a loop device none does. Two
  needed two jobs on one ledger.
- The worst defect is not the wipe. **Run 2's much smaller failure was reported;
  run 1's much larger one was not.**
- Every one of the nine now has a regression test that fails without its fix.

| | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| Bytes written | **512** | 100% | 100% |
| Programmed by the controller | no | **no** | **yes** |
| Planted files recoverable after | **14/14** | 0/14 | 0/14 |
| Exit status | **0** | 1 | 0 |

---

## 7 · The demo

> # 19.6 s
> **What the write calibration costs, before a single byte of the wipe is
> written — and it decides everything downstream.**
> *`core/erase/calibrate.py`, 64 MiB per fill*

Six minutes, live:

| | |
|---|---|
| 0:45 | the calibration runs, the elision finding lands, the fill switches to `0xA5` |
| 1:30 | PhotoRec against a wiped stick: **14 → 0** |
| 2:15 | recovery, confidence buckets, the six score components |
| 3:15 | one byte flipped: **signature FAIL, the other four checks hold** |

**Say out loud, on stage:** "This wipe takes sixteen minutes at four megabytes a
second, and I am not going to fake a fast one. It will keep running while we
talk."

---

## 8 · Limitations

> # 0.0%
> **ext4 recovery. Not a defect — `ext4_ext_remove_space` zeroes the extent tree
> on unlink, and no implementation can change that.**
> *`docs/limitations.md`*

- The inode survives with its size, mode and timestamps, and points at **no
  blocks at all**. What we recover comes from the jbd2 journal — a circular
  buffer of the recent past, whose inodes carry no filename.
- **On ext4 we tell you to use the signature carver**, and `undelete_report()`
  returns the unallocated map for exactly that reason.
- Every FAT candidate is marked `contiguity_assumed`. Once a neighbouring file
  has also been deleted, its freed clusters are indistinguishable from this
  file's — the result is the right length and the wrong content, and **nothing
  on the volume can detect it**.
- A software write block is a claim about a flag. SG_IO and ATA pass-through go
  straight through it. **Use a hardware write blocker for evidence.**
- `docs/limitations.md` is 614 lines and is the document we are proudest of.

**Say:** "If a guarantee cannot be made, the report says so. That is the first
line of our design document."

---

## 9 · Roadmap

> # 0
> **Fragmented files recovered from real media. Every file on both Phase B
> volumes was contiguous, so the reconstruction that can go wrong never had to
> make a decision.**
> *`docs/validation/hardware.md`, "100% recall is a statement about a contiguous
> population"*

- **Phase B ran, on the pre-Batch-2 pipeline.** Three passes on a real USB stick:
  FAT32 delete, exFAT delete, FAT32 quick format. 456/456 and 460/460 byte-exact.
  Six acquisitions, zero bad sectors. **No false positive reached HIGH in any
  pass — 30 for 30.** Structure carving and reassembly were wired in afterwards;
  the shipped pipeline has no real-media figures yet.
- **The weakness that replaces "no real-media runs" is narrower and worse.**
  A freshly populated volume is contiguous by construction, so `contiguity_assumed`
  — the caveat we print on every FAT candidate — was never tested against the
  case it warns about. Real evidence is fragmented. **We still do not know what
  that costs us**, and it is the one number a judge would ask for.
- **Next pass, and it is a small change to the harness:** fill the volume,
  delete alternate fillers, write files sized to span several holes, and measure
  what walk-forward reconstruction does when a deleted neighbour's clusters are
  indistinguishable from the file's own.
- **The quick-format pass measured the media, not the carver.** A quick format
  on this stick sanitizes nothing — 225.8 MiB of planted data was still there
  afterwards. The pass could not measure recovery, because 902 of its 912 files
  were headerless random blobs. It needs a signature-bearing corpus.
- Also queued: six harness defects this run exposed (the comparison ignores the
  damage model; the synthetic precision column measures a different pipeline),
  the unexercised safety gates (non-removable, >128 GiB), 4096-byte physical
  sectors, sampled verification above 64 GiB, and an external anchor for the
  ledger root.

---

## 10 · Team

> # AEGIS
> **Integrated secure data sanitization and forensic file recovery.**

- Names, roles, contact.
- One line each on what each person owns, matched to the module numbers on
  slide 3.
- Repository, licence, and the two documents to read first:
  `docs/validation/hardware.md` and `docs/limitations.md`.

**Closing line:** "We would rather hand you a tool that tells you what it could
not do than one that tells you it did everything."

---

## Build notes

- **One number per slide, and never repeat one.** The numbers above are chosen
  to be non-overlapping: 3.6×, 1, 1211, `high`, 1500, 512, 19.6 s, 0.0%, 0.
- Source line under every number, in the file path form used above. A panel that
  can check a number trusts the ones it does not check.
- No screenshots of code. One screenshot maximum, and it is the residual-risk
  panel on slide 4.
- Slides 4, 6 and 8 are the pitch. Slides 1, 2, 3 exist to get there and should
  be delivered fast.
- If time is cut to four minutes, drop 2, 3 and 10. Never drop 6.
