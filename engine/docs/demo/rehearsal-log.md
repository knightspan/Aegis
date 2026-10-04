# Rehearsal log

> **Superseded for the final presentation (2026-09-24).** This document
> describes the earlier six-minute demo, which erased the USB stick live on
> stage. The final presentation is the 4.5-minute order in
> [`docs/validation/demo-evidence-index.md`](../validation/demo-evidence-index.md),
> answered from [`docs/validation/judge-defense-card.md`](../validation/judge-defense-card.md).
> It performs **no** physical write: the Sanitize beat stops at the approval
> gate and erase is not pressed. Log rehearsals of the final order in the table at the
> end of the judge defense card instead.

Fill this in by hand, one row per run. Ten rows, because the tenth is the one
that goes on stage and the first nine are how it gets there.

**Read the running clock at each transition. Do not stop the timer.** One phone
timer cannot measure seven separate elapsed times, so every number below is the
clock reading when that beat *ends* — which is what you can glance at while
still talking.

---

## The rig

One USB stick. `/dev/sdX`, serial written on the sticky note. It is the stage
device, the recovery volume and the 0:45 live-wipe target all at once — see
"Why one stick is enough" in `docs/demo/runbook.md`.

Before run 1: `sudo ./scripts/demo-reset.sh --full --usb /dev/sdX
--i-understand-this-destroys-data` (~1 h 35 min on 7.4 GiB).
Between every run after that: `sudo ./scripts/demo-reset.sh --quick` (~15 s),
then **restart the server**.

## Target

| Beat | Ends at | Length |
|---|---|---|
| **B1** Devices, capability badges | **0:45** | 45 s |
| **B2** Start the wipe, calibration, elision finding | **1:30** | 45 s |
| **B3** PhotoRec, 14 → 0 | **2:15** | 45 s |
| **B4** USB recovery, buckets, score breakdown | **3:15** | 60 s |
| **B5** Report, tamper, verify, restore | **4:15** | 60 s |
| **B6** Nine defects slide | **5:00** | 45 s |
| **End** Q&A buffer closes | **6:00** | 60 s |

Anything past **6:15** is an overrun. Anything before **5:30** means you are
rushing and the panel is not following.

## Drift, at a glance

Write the clock reading, then the signed drift against the target in the row
above it. `+12` means twelve seconds late at that transition. Drift is
cumulative — a late B2 makes every later beat late unless you take the time back
somewhere, so the number to watch is not any single cell but whether the row
gets *worse* left to right.

| Run | Date | B1 /0:45 | B2 /1:30 | B3 /2:15 | B4 /3:15 | B5 /4:15 | B6 /5:00 | End /6:00 | Verdict |
|---:|---|---|---|---|---|---|---|---|---|
| 1 | | | | | | | | | |
| 2 | | | | | | | | | |
| 3 | | | | | | | | | |
| 4 | | | | | | | | | |
| 5 | | | | | | | | | |
| 6 | | | | | | | | | |
| 7 | | | | | | | | | |
| 8 | | | | | | | | | |
| 9 | | | | | | | | | |
| 10 | | | | | | | | | |

Verdict is one word: **clean**, **overran**, **fell back**, or **aborted**.

---

## What went wrong, and what changed

One block per run. Keep it short enough that you will actually write it.

### Run 1
- **Went wrong:**
- **Fell back on:**
- **Changed before the next run:**

### Run 2
- **Went wrong:**
- **Fell back on:**
- **Changed before the next run:**

### Run 3
- **Went wrong:**
- **Fell back on:**
- **Changed before the next run:**

### Run 4
- **Went wrong:**
- **Fell back on:**
- **Changed before the next run:**

### Run 5
- **Went wrong:**
- **Fell back on:**
- **Changed before the next run:**

### Run 6
- **Went wrong:**
- **Fell back on:**
- **Changed before the next run:**

### Run 7
- **Went wrong:**
- **Fell back on:**
- **Changed before the next run:**

### Run 8
- **Went wrong:**
- **Fell back on:**
- **Changed before the next run:**

### Run 9
- **Went wrong:**
- **Fell back on:**
- **Changed before the next run:**

### Run 10
- **Went wrong:**
- **Fell back on:**
- **Changed before the next run:**

---

## Reading the log afterwards

Three patterns worth acting on:

**One beat drifts every run.** It is too long, not badly delivered. Cut a
sentence from what you say, not from what you show.

**B4 drifts because the carve is slow.** That is not delivery, it is the image
size. `demo-reset.sh --full` prints the real carve duration; if it is over about
40 seconds, the beat cannot fit and you should be showing a finished result
rather than starting a job on stage.

**Drift appears at B2 and never recovers.** The confirm dialog is the usual
cause — reading the serial off the screen instead of the sticky note costs
fifteen seconds every time.

**A beat is fast in every run.** You are skipping something you meant to say.
Check it against the runbook's script rather than congratulating yourself.

## What to change, and what not to

Change the words. Do not change the numbers, the commands, or the order of the
beats between rehearsals — a run that used different material is not comparable
to the ones before it, and the log stops being a measurement.

If a beat cannot be made to fit after three attempts, it is the runbook that is
wrong. Edit `docs/demo/runbook.md`, note the edit in the block above, and start
the drift column again from that run.
