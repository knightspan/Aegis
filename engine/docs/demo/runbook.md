# Six-minute demo runbook

> **Superseded for the final presentation (2026-09-24).** This document
> describes the earlier six-minute demo, which erased the USB stick live on
> stage. The final presentation is the 4.5-minute order in
> [`docs/validation/demo-evidence-index.md`](../validation/demo-evidence-index.md),
> answered from [`docs/validation/judge-defense-card.md`](../validation/judge-defense-card.md).
> It performs **no** physical write: the Sanitize beat stops at the approval
> gate and erase is not pressed. Keep this file for its measured numbers and
> fallback commands. Do not rehearse from its timings.
>
> **Capability state (2026-09-28).** This runbook is Linux-only because the
> demo it scripts was. It does not describe what other platforms can do: the
> generated
> [`capability-matrix.md`](../validation/capability-completion-2026-09-28/capability-matrix.md)
> does. Windows and macOS whole-drive clear, raw acquisition and restore are
> implemented and not physically validated; see
> [`capability-completion-2026-09-28/README.md`](../validation/capability-completion-2026-09-28/README.md).

> **Real-device mode (2026-09-28).** The product has no dry-run or simulation
> mode any more, and `scripts/demo_simulation.py` has been removed. Every erase
> the UI starts is real. The procedure below is the only erase demonstration:
> it runs on a disposable test device. Beats elsewhere in this file that
> mention a dry run describe the earlier build.

## Real-device demonstration on a disposable test device

Use a USB stick you own, that holds nothing you need, and that you have imaged
first. Never demonstrate on a laptop's internal disk: the system disk is refused
anyway, and a mounted volume is refused until it is unmounted by hand.

1. **Discovery.** Devices screen: the stick appears with its model, serial,
   size, platform and capability badge. The system disk shows *BLOCKED FOR
   SAFETY* and cannot be selected.
2. **Select the real device.** Click the stick. The Sanitize screen opens with
   the **REAL DEVICE** card: model, serial, size, platform, the method the
   engine will run and how it will be verified.
3. **Preflight.** The screen re-reads the device from the OS. A mounted volume
   is `BLOCKED` with the mount point named; unmount it yourself (Linux) or use
   *Prepare* (Windows, macOS: type the serial; it writes nothing to the medium).
4. **Exact identity check.** The serial on the card must match the sticker on
   the stick. The server binds the plan to serial, model and size.
5. **Backup check.** Take an image of the stick into `<state dir>/evidence/`
   (`POST /jobs/acquire`, read-only). *Erase this device* → name the image →
   *Open workflow and verify backup*: the server hashes and sizes it.
6. **Plan.** The workflow shows the plan digest, method, level, fill bytes and
   estimate. Nothing has been written.
7. **Approval.** Tick the acknowledgement, type the serial, *Approve erasure*.
   The server records the approval and issues a one-use authorization.
8. **Final revalidation.** Type the serial again and press *Erase*. The API
   re-reads the device and re-derives the plan; the helper does it again at the
   write seam, checks the backup is unchanged, and takes the single-use marker.
   Any drift is `BLOCKED` with **WHY BLOCKED**; nothing is written.
9. **Real execution.** The progress panel shows `PREFLIGHT` (write calibration),
   `ERASE`, `VERIFY`, `REPORT`.
10. **Verification.** The verification panel shows PASSED, FAILED, INCONCLUSIVE
    or NOT APPLICABLE, with the strategy, bytes read back and probability.
11. **Certificate.** *Get certificate* signs the report; the Audit screen
    verifies it.

**Say, and mean it:** this is one real erase of one stick. It is **not** a
physical validation of any device class until the run is recorded with
`scripts/record_physical_validation.py` under the procedure in
[`physical-validation-procedure.md`](../validation/physical-validation-procedure.md).
Until then the capability stays **IMPLEMENTED / UNVALIDATED**.

---

Read this as a script, not as notes. Every command is copy-pasteable, every
expected output is what the tool actually printed on the validation host, and
every beat has a fallback that needs no hardware.

**The timing problem is solved by staging, not by pretending.** A 4 GB stick
does not wipe in 45 seconds on any controller measured here; see
[Wipe arithmetic](#wipe-arithmetic) below. What the 45-second beat shows is the
wipe *starting* — the plan, the write calibration completing, the elision
finding landing, the residual-risk panel — on a stick that then keeps running in
the background for the rest of the talk. The stick that gets carved against was
wiped before the session with the same command, and **you say so out loud.** An
An evaluation panel will forgive a wipe that takes sixteen minutes. It will not forgive
one that appears to take forty-five seconds.

---

## Before the room fills

**Two hours ahead on a 7.4 GiB stick.** The reset is a ninety-five-minute job —
see the breakdown below. Everything here must be green before you walk on.

```bash
cd ~/Projects/sanctum-forensics
sudo ./scripts/demo-reset.sh --full --usb /dev/sdX \
    --i-understand-this-destroys-data
```

That stages every device from scratch, clears the ledger, creates the signing
key **before** the first ledger append, and prints a pre-flight table. Run it,
then leave it alone.

**On the 7.4 GiB validation stick `--full` takes about 1 hour 35 minutes.** Most
rows below are not estimates: they are the wall-clock times Phase A recorded on
this exact device on 2026-09-05. The reset prints its own measured numbers at
the end; use those once you have run it on your stick.

| Reset step | 7.4 GiB stick | Source |
|---|---:|---|
| `0xA5` pattern across the whole device | 31 min 51 s | measured |
| partition, format, plant 14 files | ~30 s | measured |
| PhotoRec **before** | 5 min 09 s | measured |
| erase — calibration 20 s + write 31:26 + read-back 5:10 | 36 min 56 s | measured |
| standalone verify, full read | 5 min 09 s | measured |
| PhotoRec **after** | 9 min 23 s | measured |
| sign the report | ~5 s | measured |
| recovery volume — format, plant 10, delete 5 | ~10 s | estimate |
| recovery acquire — full device read at 23.9 MiB/s | 5 min 10 s | derived |
| recovery carve over a 7.4 GiB image | **unmeasured** | — |
| **Total** | **~1 h 35 min** + carve | |

A 4 GB stick roughly halves every device-bound row: ~48 minutes.

`--skip-photorec` removes 14 min 32 s of that — the two scans — and costs the
1:30 beat its live numbers. It is the right flag for rehearsal staging once you
have one good set of PhotoRec numbers on file, and the wrong one for the run you
take the slide numbers from.

**If `--full` stops part-way, resume it — do not start again.** It records each
step as it completes and prints the exact command; `--resume-from <step>` skips
everything before that step, and `./scripts/demo-reset.sh --list-steps` prints
the twelve names without needing root or a device. Details in
[Rehearsal 1, step 6](#part-a--set-up-about-1-h-40-min-mostly-waiting).

**Run `--full` once per session, not once per rehearsal.** Between rehearsals:

```bash
sudo ./scripts/demo-reset.sh --quick
```

About fifteen seconds — the non-device work measured **0.36 s**, and the rest is
`parted`, `mkfs` and a flush to flash. It restores the ledger, the signing key,
the signed report and the demo JSONs from the snapshot `--full` took, puts the
recovery filesystem back on whichever stick the 0:45 beat wiped, and clears the
carve output.

It does **not** re-run the PhotoRec scans — the 1:30 beat reads its counts out
of JSON, which a rehearsal cannot change — and it does **not** re-acquire the
recovery image, because the 2:15 beat carves an image and acquisition is
read-only. `--with-recovery` redoes both; that costs a full read of the device
and is the only thing that pushes `--quick` past a minute.

`--quick` rolls the ledger back, which is the one place this tool does the thing
it tells everyone else not to do. It therefore **archives** the rehearsal's
ledger under `<state-dir>/demo/rehearsals/<timestamp>/` rather than deleting it,
and says so on the console.

**Restart the server after every `--quick`.** Job state lives in memory
(`api/jobs.py:JobRegistry`), so a restart is the only way to clear the previous
rehearsal's jobs off the screen.

**One USB stick runs the whole demo.** See
[Why one stick is enough](#why-one-stick-is-enough); the short version is that
only the 0:45 beat opens a device at all. `--usb-b` is optional and buys exactly
one thing: the 0:45 wipe targets the second stick, so the recovery volume on
`--usb` survives and `--quick` has less to put back. Nothing in the six minutes
requires it.

It will ask you to type the serial of `--usb` before it writes anything. That is
deliberate: a reset that skipped the gate would train you to click through the
one on stage.

Two flags for a faster `--full`: `--skip-photorec` saves about seven and a half
minutes on a 4 GB stick and costs you the live numbers at 1:30, and
`--skip-recovery` stages no recovery volume, which drops the 2:15 beat to the
synthetic image.

Five minutes ahead:

```bash
sudo ./scripts/demo-reset.sh --check-only --state-dir /var/lib/sanctum-demo
```

Every row must read `OK`. If any row reads `STALE` or `MISSING`, that beat runs
from its fallback and you say the fallback line.

**Two processes, and only one of them is root.** This is the architecture the
project documents in `docs/privilege-boundary.md`, and it is what a judge will
check first: the helper holds raw device access, the API and the browser do not.
Start them in this order, in two terminals.

**Terminal 0 — the privileged helper.** It serves five allowlisted operations
over a 0600 Unix socket, authenticates its peer with `SO_PEERCRED`, and spawns
no shell. Neither argument is guessed. `--operator-uid` is the *only* uid it
will serve, and it is also the uid every file it writes into the ledger is
handed to, so the unprivileged API can read back the chain a wipe produced.
`--state-dir` is the only directory tree it will write into: every path in every
request is resolved against it and refused if it lands outside, which is what
stops a request body from aiming a root process at the rest of the filesystem.

```bash
sudo .venv/bin/python -m helper \
     --operator-uid "$(id -u)" \
     --state-dir /var/lib/sanctum-demo
```

Expect one line, `helper_listening socket=/run/sanctum/helper.sock mode=0o600`.
Leave it running. Nothing else in the demo is root.

**Terminal 1 — the API, as yourself.** `SANCTUM_HELPER_SOCKET` is what makes it
use the daemon rather than dispatching privileged operations inside the web
server process. **All four variables are required** — without the socket
variable the API falls back to the in-process helper and `GET /health` reports
the `HELPER_IN_PROCESS` limitation, which is the state this sequence exists to
avoid; `core.report.sign` refuses to open an unprotected signing key, whose
passphrase has to match the one `demo-reset.sh` staged with; and without
`SANCTUM_SESSION_TOKEN` the server mints a fresh random token at every start,
which makes every URL below unusable until you read it off the banner:

```bash
SANCTUM_HELPER_SOCKET=/run/sanctum/helper.sock \
SANCTUM_STATE_DIR=/var/lib/sanctum-demo \
SANCTUM_KEY_PASSPHRASE=sanctum-demo \
SANCTUM_SESSION_TOKEN=sanctum-demo-session \
.venv/bin/python -m api.main
```

No `sudo`. The previous version of this runbook ran this line under `sudo`,
which put every privileged operation back inside the web server, made the
socket's uid authentication and its five-operation allowlist authenticate
nothing, and contradicted `docs/privilege-boundary.md` in a way anyone reading
both documents finds in two minutes.

If you overrode `SANCTUM_KEY_PASSPHRASE` when you ran the reset, use that value
here. Get it wrong and the 3:15 report beat fails at "Generate signed report"
with a key error, which is a bad place to discover it.

**Why `SANCTUM_SESSION_TOKEN` is pinned, and why it is not a weakening.** The
server refuses every request that does not carry its session cookie, including
`GET /health`, and mints a new token per start unless you supply one
(`api/main.py:dev_session_token`). An earlier version of this runbook opened
`http://127.0.0.1:8787` directly and health-checked it with a bare `curl`; both
now answer **401 `SessionRequired`**, so the pre-flight check could not be read
and the browser never reached the UI. Pinning the token keeps every command on
this page copy-pasteable. It changes nothing about the boundary: the server
still binds `127.0.0.1` only, still refuses any non-loopback `Host`, and still
refuses every request without the cookie. Do not use this value outside the
demo state directory.

Confirm the boundary is actually up before the room fills:

```bash
curl -s --cookie "sanctum_session=sanctum-demo-session" \
     http://127.0.0.1:8787/health | python -m json.tool
```

`limitations` must **not** contain `HELPER_IN_PROCESS`. If it does, the API did
not see the socket: check that Terminal 0 is still running and that the path in
`SANCTUM_HELPER_SOCKET` matches the one it printed. It must not contain
`NO_SIGNING_KEY` or `CHAIN_WITHOUT_KEY_FINGERPRINT` either: the first means no key
exists yet, the second that the chain was started without one, and both mean the
`fingerprint_matches_genesis` check will be SKIP on the 3:15 report. Re-run the
reset rather than continuing.

If instead you get `{"error": "Refused: this request did not come from the
Sanctum window."}`, the token in the cookie is not the token the server started
with — restart Terminal 1 with the variable set.

It binds `127.0.0.1:8787` and nothing else. **Open the browser full-screen on
`http://127.0.0.1:8787/session/sanctum-demo-session`** — that one request sets
the cookie and redirects to the UI. Land on the Devices screen before anyone is
looking. Opening `http://127.0.0.1:8787` without the `/session/` prefix first
returns 401 and shows a refusal, not the app.

Five things on screen, arranged before you start:

| Window | Contents | Used at |
|---|---|---|
| Browser, full screen | the UI, opened once via `http://127.0.0.1:8787/session/sanctum-demo-session` | every beat |
| Terminal 0, minimised | the root helper daemon | background |
| Terminal 1, visible | the API server log, running as you | background |
| Terminal 2, large font | empty, cwd is the repo | 3:15 tamper beat |
| Terminal 3, minimised | stick B's wipe, after 0:45 | 5:00 closer |

Font size 16pt minimum in every terminal. Rehearse once with the projector, not
only with the laptop screen.

---

## 0:00 — 0:45 · Devices, and the badge that says how it knows

**Do:** Devices screen is already on-screen. Point at the row for stick A.

**Command (already run — the screen is live):** none. The Devices screen calls
`GET /devices` on load and on the Refresh button.

**Expected on screen:**

```
/dev/sdX   TOSHIBA TransMemory   B103B9C19DE1CCC1BD535ACB   7.76 GB   usb
           [ CLEAR ONLY ]
```

Hovering the badge shows its evidence string. The badge is `capabilityBadge()`
in `ui/src/lib/capability.ts`; the evidence is not decoration, it is the text
the panel will ask you about. A drive that reports a firmware sanitize reads
**PURGE · UNVERIFIED**, not a green PURGE AVAILABLE: no firmware sanitize has been
recorded on a physical drive, so the badge stays in the unknown tone until one is.

**Say — 40 seconds, rehearsed word for word:**

> This is the device screen. Every badge here carries the evidence for its own
> claim, not just the conclusion.
>
> This stick reads CLEAR ONLY. Not because we chose Clear — because `hdparm -I`
> through this USB bridge reported no SANITIZE feature set and no ATA security
> erase, so Purge is not reachable on this hardware and the tool will not offer
> it. The method is selected from what we probed, never from what the operator
> would prefer.
>
> And when the wipe starts, the tool will pick a `0xA5` fill rather than zeros —
> because it measured this controller acknowledging zero writes 3.6 times faster
> than it can program the medium. A write that completes faster than the medium
> can be programmed was not performed. You will watch it make that measurement
> in about ninety seconds.

**If it fails:**

| Failure | What you see | Fallback |
|---|---|---|
| Device list empty | "no devices, because …" with the reason | Say the reason aloud — it is a designed output, not a crash. Switch to the pre-captured screenshot at `docs/demo/fallback/devices.png` — see `docs/demo/fallback/README.md` for how it was made. |
| Badge reads UNKNOWN | capability probe did not complete | This is the honest path and it is worth showing: "the probe did not complete, so nothing is claimed." Keep going. |
| Server not running | browser cannot connect | Terminal 1 has the log. Restart it; you have 45 seconds of Devices-screen talk that needs no server if you use the screenshot. |

---

## 0:45 — 1:30 · Start the wipe. Watch the calibration decide.

This is the beat that changed. Read [Wipe arithmetic](#wipe-arithmetic) before
you rehearse it.

**Changed on 2026-09-25, not yet rehearsed on hardware.** A real erase now
needs a backup image of the whole stick, at least as large as the stick, inside
the API's evidence directory (`<state dir>/evidence/`). Take it before the
session, as a read-only acquisition of the stick onto the laptop's disk. Without
it the Sanitize screen stops at *Open workflow and verify backup* and nothing can
be erased - that is the gate working, and it cannot be fixed on stage. The server
hashes and sizes the image; that does not prove it is a copy of the stick.

**Do:**

1. Devices screen → click the stick you are wiping → Sanitize.
   **On a one-stick setup that is the same stick the whole demo runs on**, and
   wiping it is the point: the recovery beat at 2:15 carves an *image file*, not
   the device, so destroying the volume costs the demo nothing. `--quick` puts
   the filesystem back before the next rehearsal. If you staged `--usb-b`, this
   is stick B instead and the recovery volume survives.
2. Method panel already shows `SINGLE_PASS_OVERWRITE` selected, everything else
   greyed with its evidence string. The **REAL DEVICE** card names the stick.
3. Click **Erase this device**.
4. Type the backup image's name and click **Open workflow and verify backup**.
   The plan and the image's SHA-256 appear.
5. Tick the acknowledgement and type the serial. Have it on a sticky note — do
   not read it off the screen behind you, that looks worse than it is.
6. Click **Approve erasure**. The server issues a one-use authorization id.
7. Type the serial again and click **Erase**.

**Expected, in this order, on the clock:**

| t+ | On screen |
|---|---|
| 0 s | phase `PREFLIGHT`, "calibrating write" |
| ~15 s | first fill done |
| ~20 s | calibration completes; the plan panel fills in |
| ~20 s | `CONTROLLER_WRITE_ELISION` appears in the findings, severity HIGH |
| ~21 s | Residual risk panel: level **high**, four factors |
| ~22 s | phase `ERASE`, progress bar starts moving, ETA ≈ 16 min |

The plan panel reads:

```
method      SINGLE_PASS_OVERWRITE
level       CLEAR
passes      1
fill_bytes  ["0xA5"]
fill_reason the write calibration measured this controller acknowledging a zero
            fill far faster than it programs the medium, so 0x00 passes were
            replaced with 0xA5 to force a real program
est_seconds 954
est_basis   measured on this device before the run: 0xA5 at 4.28 MiB/s over
            67108864 bytes per sample
```

`est_seconds` is the only size-dependent line: **954 on a 4 GB stick, 1729 on
the 7.76 GB validation stick** (`a4-erase.json`, `.result.plan.est_seconds`).
Everything else in that panel — including the `est_basis` sentence and every
number in the finding below — is verbatim from the validation run and does not
move with device size.

The finding reads:

```
CONTROLLER_WRITE_ELISION   severity HIGH   addressable false
  ratio_bp 32538   threshold_bp 20000   sample_bytes 67108864
  zero 0x00 at 14,595,162 B/s   non-zero 0xA5 at 4,485,620 B/s
```

**Say — the calibration is the beat, and the honesty line is not optional:**

> Two gates: a recorded approval that the server turns into a one-use
> authorization, and the serial typed by hand. There is no rehearsal mode, so
> neither is ever skipped.
>
> [as PREFLIGHT runs] It is writing 64 megabytes of `0xA5`, then 64 megabytes of
> zeros, over the same region, and timing both.
>
> [when the finding lands] There it is. Ratio 3.25 against a threshold of 2.0.
> This controller acknowledges a zero fill at 14.6 megabytes a second and
> programs a real byte at 4.5. So the tool substitutes `0xA5` for every zero
> pass — because otherwise we would print the word "overwrite" over a write the
> device never performed, and NIST SP 800-88r2 describes overwrite as replacing
> the data with something else.
>
> Residual risk: **high**. Four factors, all named. HPA and DCO were not probed,
> because this is behind a USB bridge and a bridge's answer to a SET_MAX query
> describes the bridge, not the medium. No firmware sanitize is reachable. And
> overwrite on flash cannot reach remapped or over-provisioned blocks — no
> host-side read can establish physical removal on flash, ever, and we say that
> in the report rather than letting a passing verification imply it.
>
> **This wipe takes sixteen minutes at four megabytes a second, and I am not
> going to fake a fast one. It will keep running while we talk. The stick I am
> about to carve against was wiped this morning with this exact command, and its
> ledger is on screen at the end.**

Then minimise it to Terminal 3 and move on. **Do not wait for it.**

**Nothing to do here about ledger ownership.** Earlier drafts of this runbook
carried a `sudo chown -R` after the wipe, because the helper writes the wipe's
entries and blobs as root at mode `0600` and the unprivileged API has to read
them back at the 3:15 report beat. That is now handled where it belongs: the
helper hands each file it creates to the uid you passed as `--operator-uid`,
mode unchanged. See `docs/privilege-boundary.md`, "Who owns the chain".

**If it fails:**

| Failure | What you see | Fallback |
|---|---|---|
| Refused: mounted filesystem | `REFUSED` naming the mount point | Best possible failure. Say "that is the guard working", `umount` it, retry. Costs 15 s. |
| Refused: serial mismatch | **Approve** stays disabled, or `BLOCKED` with the server's WHY BLOCKED | You typed it wrong. Sticky note. 10 s. |
| Stops at *Open workflow* | `BLOCKED`: the backup image is missing or smaller than the stick | The gate working. Cannot be fixed on stage; cut to the fallback capture. |
| No elision finding | calibration ratio below 2.0 | **This is a real outcome, not a bug.** Say: "this controller programs zeros honestly, so no substitution is needed — the check is the point, not the finding." Then show the recorded finding from the validation run instead: `docs/validation/results-20260905T033655Z/a4-erase.json`. |
| Device vanished mid-wipe | `DeviceVanished` | Say it: "cheap sticks re-enumerate under sustained write, and that is a named error with a remediation, not a crash." Move on. |
| Whole beat unusable | anything else | Pre-recorded 50-second screen capture: `docs/demo/fallback/wipe-start.mp4`. Play it and narrate the same words. **Check it exists before the session** — nothing generates it. |

---

## 1:30 — 2:15 · PhotoRec against the wiped stick. Zero results.

**The scan was run before the session.** A full PhotoRec pass over a wiped 4 GB
stick takes about 4 minutes 50 seconds at the measured 13.8 MB/s; on the 7.76 GB
validation stick it took 563.32 s. What you show live is the count, and the
count is the part that matters.

**Do:** Terminal 2, three commands.

```bash
# What PhotoRec found on this stick BEFORE the wipe
jq -r '.files_recovered' /var/lib/sanctum-demo/demo/photorec-before.json

# What it found AFTER
jq -r '.files_recovered' /var/lib/sanctum-demo/demo/photorec-after.json

# And the number that actually means something
cat /var/lib/sanctum-demo/demo/planted-match.txt
```

**Expected output:**

```
198
0
planted files: 14   recovered before: 14/14   recovered after: 0/14
```

**Say:**

> Before the wipe, PhotoRec recovered 198 objects from this stick, and 14 of
> them hash byte-for-byte to files we planted. After the wipe: zero recovered,
> zero matches.
>
> The honest number here is **14 to 0**, not 198 to 0. In an earlier run the raw
> after-count was 94,720 — higher than the before-count — because PhotoRec's
> `dovecot` signature accepts any all-zero 80-kilobyte block and the device had
> just been filled with zeros. 7,759,462,400 divided by 81,920 is exactly
> 94,720. That is a carver artefact, not a recovery, and it is why we report
> hash matches against a manifest rather than a file count.
>
> This run ends holding `0xA5`, which produces no candidates at all.

**If it fails:**

| Failure | Fallback |
|---|---|
| Files missing / stale | Use the validation run instead: `docs/validation/results-20260905T033655Z/photorec-before.json` and `photorec-after.json`. Same numbers, 7.76 GB stick, and it is checked into the repo. Say "these are from the hardware validation run on the fifth". |
| Panel asks to see it run | `sudo photorec /log /d /tmp/demo-recup /cmd /dev/sdX partition_none,fileopt,everything,enable,search` over a 512 MiB slice takes ~39 s. Offer it for after the session, not during. |

---

## 2:15 — 3:15 · USB recovery, confidence buckets, score breakdown

**Read this before rehearsing.** The recovery beat runs on a USB volume, not an
SD card, and a judge may ask why — investigators handle far more cards than
sticks. The answer is in `docs/demo/qa.md` question 21 and it is a good one:
**for everything this pipeline does, FAT32 and exFAT on USB are the same
filesystems as on a card.** Same directory entries, same `0xE5` deletion marker
in the first byte of the name, same cluster chains, same `NoFatChain` flag on
exFAT. Neither path issues TRIM on delete. The block device underneath differs;
the on-disk structures the carver reads do not.

**And say the honest half too:** the *media* differs, and the media is where
this project has been burned before. A card reader is a different bridge with a
different controller, and the nine defects Phase A found were all bridge and
controller behaviour. We have no card, so we have not measured one.

**Do:**

1. Recovery screen → source is the pre-acquired image
   `/var/lib/sanctum-demo/demo/recovery-fat32.dd`.
2. Undelete and signature carving both checked.
3. Run.
4. Filter to HIGH. Click one candidate. The **Score breakdown** panel opens.

**Expected on screen:** ten planted JPEGs, five deleted, five recovered. Each
recovered candidate shows an **evidence score** out of 10000, its bucket, and
six score components with their evidence.

```
img00.jpg   HIGH   evidence score 10000 / 10000
  header             2000   the magic number for this format is present
  exact_length       1500   a parser derived the length from the structure
  decoder_valid      4000   a real decoder read it end to end
  entropy            1000   the byte distribution matches this format
  fs_metadata        1500   a surviving filesystem record names this file
  no_overlap          500   no other candidate claims these bytes
                          ------
                          10500   clamped to 10000
```

The six components sum to 10,500 and `core/carve/score.py` clamps the total to
10,000, so a candidate carrying all six reads `10000 / 10000`. Phase B
recovered its named deleted JPEGs at exactly `10000`.

**Do not say "one hundred percent", and the screen no longer offers it.** This
number is a sum of evidence, not a probability that the file is correct — the
components simply add up past the clamp. An earlier build rendered it as
`100.00%`, which is the single easiest sentence for a judge to take apart, and
it was right to. What the calibration supports is the *bucket*, and that is the
claim to make out loud.

**Say:**

> Five deleted JPEGs, five recovered, byte-identical. The number beside each
> one is an **evidence score**, not a probability — it is a sum of six measured
> components, and every component is on screen with what it establishes. Ten
> thousand out of ten thousand means every check fired, not that the file is
> certainly right.
>
> What is calibrated is the **bucket**. Pooled over eight seeds and 173
> candidates, all 104 HIGH candidates matched a planted object byte for byte.
> That is a precision figure for a bucket on a synthetic population, and I will
> tell you where it broke: on a 7 GiB image, HIGH precision was 86.6% until we
> fixed the footer bound. It is in the document.
>
> These weights are not opinions either. They were calibrated against a corpus
> with known ground truth, and a candidate only counts as a true positive if its
> SHA-256 matches. `decoder_valid` moved from 3500 to 4000 because every
> candidate meeting that description was a true positive and the missing 500 was
> keeping four of them out of HIGH.
>
> `fs_metadata` stayed at 1500 — and that is the interesting one. We swept it
> from 0 to 5000. At 5000 the aggregate looks far better: 95.6% precision
> against 100%. It is worse. The gain comes from promoting 237 candidates no
> decoder confirmed, and one of them is a recovery the corpus knows is wrong,
> scored HIGH. **1500 is the largest value the evidence permits, not a number
> somebody picked.**
>
> LOW is 0% precision by design. Nothing recoverable is left in the bucket the
> report tells an examiner to skip.
>
> And then we ran it against real media. Three passes on a USB stick: **HIGH was
> thirty candidates and thirty true positives. Not one false positive reached
> HIGH** — including twenty-seven signature hits the carver manufactured out of
> 236 megabytes of pseudo-random filler, every one of which it scored MEDIUM or
> LOW. That is thirty HIGH candidates from the pipeline as it stood on
> 5 September, before Batch 2 wired in structure carving, so it is a sample of
> thirty and not a claim about performance in general. The pipeline that ships,
> with structure carving, has not yet been measured on real media.

**If it fails:**

| Failure | Fallback |
|---|---|
| Recovery volume never staged | Run against `testkit/fsimage.py`'s 40 MiB FAT32 image and say: "this is a synthetic filesystem image, not real media." That honesty plays well; hiding it does not. |
| "Why not an SD card?" | Question 21 in `docs/demo/qa.md`. Structurally identical filesystems, different bridge, and we say we have not measured the bridge. |
| Carve returns nothing | Show the calibration table instead: `docs/performance/calibration.md`, per-filesystem recall. It is measured and it is checked in. Screenshot fallback: `docs/demo/fallback/recovery.png`. |
| exFAT row questioned | "50% is one file out of two. It is two data points, not a rate, and the document says so. On real media exFAT was 460 of 460, measured before structure carving was wired in — and our comparison now refuses to call that a divergence from a baseline of two." |
| "Your real recall is 100%, that's not credible" | "It is 100% on a *contiguous* population, and we say so on the slide. Every file was written to a fresh volume in one pass, so nothing was fragmented and the reconstruction that can go wrong never had to guess. That is our biggest open weakness — question 10." |

---

## 3:15 — 4:15 · Sign the report. Break one byte. Watch one check move.

The strongest 60 seconds in the demo. Rehearse it until the typing is muscle
memory.

**Do:** Audit screen → **Generate signed report** for the **2:15 carve job** →
note the path. Then Terminal 2.

**Which job id to type, and the two that will be refused.** A report is only
generated for a job this API process ran and that has finished. The job id field
suggests `erase-drive-…`, and both erase jobs on the demo are wrong answers:

* **The 0:45 live wipe is still running** — it is a 37-minute job. The API
  answers `409 JobNotFinished`.
* **The staged erase behind `demo-erase.forensic.json` ran during
  `demo-reset.sh --full`, in a different process**, and the server has been
  restarted since (step 15). The API answers `404 JobNotKnown`: a report is built
  from the job's result, which lived in the process that ran the job.

The one finished job this process owns at 3:15 is the carve from 2:15. Its id is
on the Recovery screen, in the **Scan job** panel that appears when the scan
starts (`carve-…`). Press **Copy** at the end of the 2:15 beat and paste it into
the Audit screen's job id field at 3:15 — do not retype it.

**If the server was restarted after 2:15** (the "Server not running" fallback), the
carve job is gone with it. Either re-run the 2:15 scan first — it takes seconds —
or skip the Generate click and go straight to Terminal 2. Nothing below depends on
the generated file: the tamper sequence verifies the staged
`demo-erase.forensic.json`, which was signed during the reset and is unaffected by
a restart.

```bash
REPORT=/var/lib/sanctum-demo/reports/demo-erase.forensic.json
LEDGER=/var/lib/sanctum-demo/ledger

# 1. As written
.venv/bin/sanctum verify-report "$REPORT" --ledger-root "$LEDGER"
```

**Expected:**

```
Report: /var/lib/sanctum-demo/reports/demo-erase.forensic.json
Signed by fingerprint: 27:9F:14:59:56:96:F6:D9:…

[PASS] signature: valid Ed25519 signature by 27:9F:14:59:…
[PASS] fingerprint_matches_genesis: signing key 27:9F:14:59:… is the key recorded in the ledger genesis
[PASS] chain_integrity: all <N> excerpt entries link and hash correctly (<span>)
[PASS] chain_store: the ledger store verifies independently: <explanation>
[PASS] blobs_available: every blob referenced by <N> entries is present

Result: PASS
Verdict: VERIFIED_WITH_LIMITATIONS
  - <one line per limitation or residual-risk finding the report declares>

Note: An embedded public key proves internal consistency only. It does not
prove identity: a third party must compare the fingerprint above against a
value published out-of-band before treating this signature as evidence of who
produced the report.
```

**Read the right-hand side, not a status word.** `core/report/cli.py:_render`
prints each check's *detail sentence*; `VERIFIED_PARTIAL` and `VALID` are
internal status values that never appear on this line. `Verdict:` follows
`Result:` and grades the whole result; an erase report on flash reads
`VERIFIED_WITH_LIMITATIONS` because it declares what overwrite cannot reach. The
`Note:` line always prints, after the verdict. Fill the `<…>` in from your own reset — the counts are
whatever your ledger holds. If the report's job interleaved with another job in
the ledger, `chain_integrity` instead reads "<N> excerpt entries hash correctly
and all <N-2> adjacent pair(s) link (<span>); <M> entr(y/ies) are not carried by
this excerpt at seq <range> and are not evidenced by it". Say only what the
screen shows.

The committed fallback (`docs/demo/fallback/`, verified 2026-09-23) is the
complete-chain case: `chain_integrity: all 37 excerpt entries link and hash
correctly (0..36)`, `chain_store: … All 67 entries verify, 0..66.`, and
`excerpt_gaps` is empty. The **Say** block below matches that fallback.

```bash
# 2. Flip one byte. Offset 19636 was the one used in validation; any offset
#    inside the signed body works.
cp "$REPORT" "$REPORT.bak"
printf '0' | dd of="$REPORT" bs=1 seek=19636 count=1 conv=notrunc status=none

.venv/bin/sanctum verify-report "$REPORT" --ledger-root "$LEDGER"
```

**Expected — and this is the whole point:**

```
[FAIL] signature: signature does not match the report contents; the report was altered after signing, or signed by a different key
[PASS] fingerprint_matches_genesis: signing key 27:9F:14:59:… is the key recorded in the ledger genesis
[PASS] chain_integrity: <unchanged from the PASS run>
[PASS] chain_store: the ledger store verifies independently: <explanation>
[PASS] blobs_available: every blob referenced by <N> entries is present

Result: FAIL
Verdict: FAILED_VERIFICATION
  - signature failed: signature does not match the report contents; …
```

```bash
# 3. Restore
mv "$REPORT.bak" "$REPORT"
.venv/bin/sanctum verify-report "$REPORT" --ledger-root "$LEDGER"    # PASS
```

**Say:**

> Five independent checks. One byte changed — a `1` to a `0`, one character.
>
> Signature fails. **The other four hold**, and that is deliberate: they are
> independent of the report bytes. `chain_store` re-verified all 67 ledger
> entries from the store itself, not from the copy inside the report, so a
> forged report cannot make it agree.
>
> `chain_integrity` checks the excerpt the report carries under its own
> signature: 37 entries, every one hashing correctly and linking to the one
> before it, no gaps. Had another job's entries fallen between them, the report
> would name them as not carried, under its own signature, in a field called
> `excerpt_gaps` — here that field is empty. An earlier build called a gap a
> broken chain. Reporting a gap as a gap, and no gap as none, is the
> difference between a report an examiner can defend and one they cannot.
>
> And read the verdict line. Before the tamper it said
> `VERIFIED_WITH_LIMITATIONS`, not `VERIFIED`: the signature is good, but the
> report itself says what overwrite could not reach on this stick, and the
> verifier will not round that up.
>
> Restore the byte. Passes again.

**If it fails:**

| Failure | Fallback |
|---|---|
| `dd` offset lands outside the signed body | signature still passes. Say "wrong offset, try again" and use `seek=2165`. Two attempts maximum, then go to the fallback. |
| Report generation fails | Pre-generated report at `docs/demo/fallback/demo-erase.forensic.json` with `--ledger-root docs/demo/fallback/demo-ledger`. Same three commands, same output. Both must be copied from the *same* reset or two of the five checks go SKIP. |
| `sanctum` not on PATH | `.venv/bin/python -m core.report.cli verify-report ...` |
| Terminal too small to read | You rehearsed the font size. If not: `--ledger-root` output is five lines; read them aloud. |

---

## 4:15 — 5:00 · Nine defects real hardware found and 1211 synthetic tests did not

**Do:** slide. No commands.

**Say:**

> Three runs against one USB stick. Same code path, same device, same command.
>
> Run one reported a **completed** wipe, exit status zero, having written 512
> bytes of a 7.76 gigabyte device. `hdparm -N` through a USB bridge prints
> "HPA setting seems invalid" **and exits zero**, we trusted the exit code, and
> the geometry silently shrank to one sector.
>
> Nine defects between run one and run three. None of them was caught by the
> synthetic suite, which was green throughout at 757 tests — 1211 today. A loop
> device has no controller, no bridge and no flash translation layer, so three
> of those defects are physically unreachable on one. Three more needed a step
> to fail, and on a loop device none does. Two needed two jobs on one ledger.
>
> The worst one is not the wipe. It is that run one printed COMPLETE. Run two's
> much smaller failure was reported; run one's much larger one was not.
>
> Every one of the nine now has a regression test that fails without the fix.

Numbers on the slide, nothing else:

| | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| Bytes written | **512** | 7,759,462,400 | 7,759,462,400 |
| Programmed by the controller | no | **no** | **yes** |
| Planted files recoverable after | **14/14** | 0/14 | 0/14 |
| Console verdict | `COMPLETE` | `COMPLETE WITH FAILURES` | `COMPLETE` |
| Exit status | **0** | 1 | 0 |

---

## 5:00 — 6:00 · Q&A buffer, and the closer

Restore Terminal 3. Stick B's wipe has been running for four and a quarter
minutes: roughly 1 GB written, about 26% of a 4 GB stick, ETA holding near
sixteen minutes.

> That is the wipe I started at forty-five seconds. Four minutes in, a gigabyte
> written, and the ETA has not moved — because it was derived from a measurement
> on this device rather than from a datasheet. On the validation stick that
> estimate came in 8.3% optimistic against a 64-megabyte sample of a 7.4-gigabyte
> write.

Then take questions. `docs/demo/qa.md` has twenty of them with answers.

### If a question opens the door: 30-second beats (added 2026-09-25)

Each runs on synthetic material, labelled as such, and needs nothing staged but
`docs/validation/features-2026-09-25/drivers/seed.py` run into a state directory
beforehand. None touches a device. Recorded screenshots are in that directory if
there is no time to run them.

* **"Erasing the file leaves its thumbnail."** File & folder eraser, the seeded
  `case-2149` folder (throwaway files), confirm and *Erase*: seven traces, each
  with its evidence. Say: *"It removes only what it can tie to the file on
  evidence, and the report lists every place it did not search."*
* **"What is intelligent about the carving?"** Recovery, the seeded image: the
  media map draws before the carve. Say: *"Zeros, fill, text, high entropy, and
  where the JPEG headers sit. Statistics, not identification, and the map says
  so."*
* **"Where is Destroy?"** Devices, *Record a physical destruction*. Say: *"No
  software shreds a drive or can watch one shredded. This records what the
  people who did it attest, signed, and the record says we observed nothing."*
* **"What can it actually do on this machine?"** Platform. Point at device
  sanitize reading *DEVICE-DEPENDENT* and at *Not proven on hardware, or not
  available*. Say: *"Every state comes from a probe or a recorded test run,
  with its reason and mechanism shown. SUPPORTED means a recorded physical run
  on that kind of device. Firmware Purge is dispatched from the drive's own
  capability, and it is not SUPPORTED because no drive has run it in a
  recorded test."*
* **"Show me everything for one investigation."** Cases, the open case: the
  chain verdict at the top, then evidence, operations, reports and audit
  entries, each a tab with its count. Say: *"The counts come from the case
  index; the integrity verdict comes from the hash chain. If they ever
  disagree, the chain is right."* A record an earlier build filed as a
  rehearsal is marked HISTORICAL · NOTHING WRITTEN and is never counted.

---

## Why one stick is enough

The question is whether one device can be both "wiped, so PhotoRec finds
nothing" and "holding deleted files, so recovery finds them". Those are opposite
states, so the instinct is that you need two sticks.

You do not, because **only one beat in the six minutes opens a device.**

| Beat | What it reads | Touches a device? |
|---|---|---|
| 0:00 Devices | `GET /devices` — enumerate and probe | read-only probe |
| 0:45 Wipe | the stick, `O_DIRECT`, for real | **yes, the only one** |
| 1:30 PhotoRec | `photorec-before.json`, `photorec-after.json`, `planted-match.txt` | no |
| 2:15 Recovery | `recovery-fat32.dd`, an image file on local disk | no |
| 3:15 Report | the report and the ledger, both on local disk | no |
| 4:15 Defects | a slide | no |

So the two states never have to coexist. They exist in sequence, during staging,
and the artefacts outlive the state that produced them. `--full` walks the stick
through the whole story:

```
0xA5 pattern  →  FAT32 + 14 files  →  PhotoRec: 198 raw, 14 planted
              →  ERASE (0xA5, calibrated)  →  verify: 0 failed offsets
              →  PhotoRec: 0 raw, 0 planted  →  sign the report
              →  FAT32 + 10 files, 5 deleted  →  acquire to recovery-fat32.dd
```

It ends holding a FAT32 volume with five deleted files — which is exactly what
you want on screen at 0:00 and exactly what is worth destroying at 0:45.

**The staging order is the demo's own narrative**, and that is worth saying out
loud rather than hiding: *this stick was populated, scanned, wiped, scanned
again, and repopulated, all before you sat down; you are about to watch it get
wiped a second time.*

### What you must say, because it is true

The 1:30 numbers and the 2:15 image were produced before the session. The stick
in the room is not, at 1:30, in the state the counts describe. Say so:

> The scan I am showing you ran this morning against this stick, with this
> command, and the JSON is on screen. It takes nine and a half minutes on 7.4
> gigabytes and I am not going to spend a sixth of my slot watching a progress
> bar.

A panel that catches you implying a live scan will stop believing the rest. A
panel told plainly why it is pre-run will not care.

### Re-staging between beats does not fit, and is not needed

For completeness, since it is the obvious alternative: re-staging the stick
between 1:30 and 2:15 means partition, format, populate, and **acquire** — and
the acquire is a full read of the device at 23.9 MiB/s, which is **5 minutes 10
seconds** on 7.4 GiB. That alone is longer than the entire demo. Even at a
256 MiB volume it is 11 seconds of imaging on top of format and populate, inside
a 45-second beat, with a device that may take seconds to settle after `parted`.

Do not do it. Nothing needs it.

### What a second stick would buy

One thing: the 0:45 wipe would target the second stick, leaving the recovery
volume on the first one intact. `--quick` would then have slightly less to put
back — about ten seconds' worth. **That is the entire benefit.** Do not buy a
stick for it.

---

## Wipe arithmetic

Everything below uses the throughput measured on the validation stick and
recorded in `docs/validation/hardware.md`: **4.0 MiB/s programmed write,
23.9 MiB/s read, 19.6 s fixed write calibration.** Substitute your own stick's
measured numbers — `demo-reset.sh` prints them.

### A 4 GB stick does not fit in 45 seconds

Taking 4 GB as 4,000,000,000 bytes = 3,814.70 MiB:

| Phase | Arithmetic | Seconds |
|---|---|---:|
| PREFLIGHT calibration | 64 MiB ÷ 4.28 + 64 MiB ÷ 13.92 | 19.6 |
| ERASE write | 3,814.70 ÷ 4.0 | **953.7** |
| VERIFY full read-back | 3,814.70 ÷ 23.9 | 159.6 |
| **Total** | | **1,132.9 s = 18 min 53 s** |

**Over budget by 25×** on the whole job, 21× on the write alone. It does not
fit, and no flag makes it fit — the write is the floor.

### What does fit in 45 seconds

Solving `19.6 + S/4.0 + S/23.9 ≤ 45` for the device size S in MiB:

- **Whole job in 45 s:** S ≤ **87 MiB** (91 MB).
- **Write phase only in 45 s**, deferring verification: S ≤ **180 MiB** (189 MB).

Against sizes you can actually buy:

| Device | Write | Calibration | Verify | Total |
|---|---:|---:|---:|---:|
| 128 MB | 30.5 s | 19.6 s | 5.1 s | **55.2 s** |
| 256 MB | 61.0 s | 19.6 s | 10.2 s | **90.8 s** |
| 512 MB | 122.1 s | 19.6 s | 20.4 s | **2 min 42 s** |
| 1 GB | 238.4 s | 19.6 s | 39.9 s | **4 min 58 s** |
| 2 GB | 476.8 s | 19.6 s | 79.8 s | **9 min 36 s** |
| 4 GB | 953.7 s | 19.6 s | 159.6 s | **18 min 53 s** |
| **7.76 GB — the stick you have** | **1886.3 s** | **19.6 s** | **309.8 s** | **36 min 56 s** |

Every figure in the last row is measured, not derived. On your stick the 0:45
beat shows the first 45 seconds of a **37-minute** job.

Note the shape: **calibration is a fixed 19.6 s** whatever the device size,
because it always samples 64 MiB per fill. On anything small enough to fit the
beat, the calibration is half the runtime. Even a 128 MB stick — which is not
purchasable in 2026 — overruns at 55 s.

**Conclusion: no device you can source wipes end to end in 45 seconds on a
controller that programs at 4 MiB/s.** Stop trying to make the wipe fit and
change what the beat shows.

### How to stage it

Three options, ranked. The runbook above uses the first.

**1 · Wipe before the session, and wipe again live. (Recommended, and what the
runbook above does.)**

The stick is wiped during staging, its ledger and report left on disk, and then
wiped again live at 0:45 and left running. A second stick (`--usb-b`) moves the
live wipe off the stage device so the recovery volume survives; it is optional
and buys about ten seconds of `--quick` time. The 45-second beat shows the plan, the calibration,
the elision finding and the residual-risk panel — which is 45 seconds of the
best material in the demo and needs no completion. The closer at 5:00 comes back
to the progress bar.

Costs nothing, hides nothing, and turns the timing constraint into the point:
*this is what a real wipe of real flash costs, and here is why we measured it
rather than estimated it.*

**2 · Resume from a checkpoint. (Not available without new code.)**

`core/erase/drive.py:resume()` exists and continues an interrupted overwrite
from its last ledger checkpoint. Staging would mean: start the wipe with
`checkpoint_bytes=128*MIB`, kill it after the checkpoint at 3.75 GiB, and resume
the last 180 MiB on stage in ~45 s.

It does not work today, for two reasons, and fixing either is a new feature:

- `resume()` is a library function. It is not exposed by `api/routes/jobs.py`,
  by the UI, or by `scripts/hardware_validation.py`. There is no way to reach it
  from the demo path.
- VERIFY still full-reads the whole device afterwards — 159.6 s on a 4 GB
  stick — so even a 45-second resume does not give you a 45-second beat.

Recorded here so nobody re-derives it under pressure.

**3 · Shrink the target. (Only if you already own the hardware.)**

A ≤ 87 MiB device finishes inside the beat. A 128 MB stick misses at 55 s. Do
not substitute a loop device or a file: the entire differentiator in this demo
is that the measurements came from a controller, and a loop device has none.

### Two other beats that do not fit, and what was done about them

Flagged because they break the same way and the original outline assumed
otherwise:

| Beat | Budget | Actual | Fix used |
|---|---|---|---|
| PhotoRec on a wiped 7.4 GiB stick | 45 s | **9 min 23 s**, measured | Scan pre-run; the count is shown live |
| Carve on a real USB volume | 60 s | **unmeasured on a 7.4 GiB image** | `demo-reset.sh` runs it beforehand and prints the real duration; if it overruns, carve the volume rather than the whole-device image |

---

## Rehearsal 1, step by step

Written for one person, alone, with a phone timer and nobody to hand them
anything. Follow it in order. Do not skip step 4 because it is boring.

### Part A — set up (about 1 h 40 min, mostly waiting)

1. **Label the stick with tape before you plug it in.** Write `STAGE` on it.
   One stick runs the whole demo — see
   [Why one stick is enough](#why-one-stick-is-enough).

2. **Unplug every other USB storage device.** Then run `lsblk` and photograph
   the output with your phone. That is your "nothing plugged in" baseline, and
   it is what tells you which row is new.

3. **Plug in `STAGE`.** Run `lsblk` again. The new whole-disk row is your
   device. Confirm it is the right one:

   ```bash
   lsblk -ndo NAME,SERIAL,SIZE,MODEL,TRAN,RM /dev/sdX
   ```

   You are looking for `RM` = 1 and the serial you expect. On the validation
   host that is `B103B9C19DE1CCC1BD535ACB`, 7.2G, usb.

4. **Write the serial on a sticky note and stick it to the laptop palm rest.**
   You will type it at 0:45 and you must not be reading it off the projector.

5. **Check nothing is mounted.** Your desktop probably automounted it:

   ```bash
   lsblk -o NAME,MOUNTPOINTS /dev/sdX
   ```

   Anything with a mount point, unmount it now. The reset refuses a mounted
   device by design, and finding that out ninety minutes in is a waste of ninety
   minutes.

6. **Run the full reset:**

   ```bash
   cd ~/Projects/sanctum-forensics
   sudo ./scripts/demo-reset.sh --full --usb /dev/sdX \
       --i-understand-this-destroys-data
   ```

   It will ask you to type the **serial** — not the device path. The banner
   directly above the prompt shows the path more prominently, which is exactly
   why the prompt says "SERIAL - not the device path" and gives the character
   count. Type the value after the word `serial` in that banner. Then it runs
   for **about an hour and thirty-five minutes** on a 7.4 GiB stick. **Do not use the laptop for
   anything else** — the PhotoRec scans and the write throughput measurement
   both get noisier if the machine is busy, and those numbers go in your slides.

   If you have already banked one good set of PhotoRec numbers and just want the
   stage reset, add `--skip-photorec` and it drops to about eighty minutes.

   **If it stops part-way, do not start again from the top.** The reset records
   each step as it completes and prints the exact command to pick up from:

   ```bash
   sudo ./scripts/demo-reset.sh --full --usb /dev/sdX \
       --i-understand-this-destroys-data --resume-from <step>
   ```

   `./scripts/demo-reset.sh --list-steps` prints the twelve step names in order
   and needs neither root nor a device. Resuming skips every step before the one
   named — including `state`, so the ledger, keys and artefacts from the
   interrupted run are kept rather than cleared.

   **Resume is never automatic, and it trusts you.** The checkpoint records what
   finished; it cannot know whether the stick still holds what those steps wrote.
   If the device has been touched, reformatted or unplugged since, start again
   without `--resume-from`.

7. **Read the last three sections of its output before you do anything else.**
   `PRE-DEMO CHECK` must be `OK` on every row, `SUMMARY` must say "all phases
   completed with no recorded failure", and `MEASURED ON THIS HARDWARE` gives
   you your stick's real write throughput. **If that number is not near
   4.0 MiB/s, the timings in this runbook are wrong for your hardware** — redo
   the arithmetic in [Wipe arithmetic](#wipe-arithmetic) with your number.

8. **Start the privileged helper in its own terminal and leave it alone:**

   ```bash
   sudo .venv/bin/python -m helper \
        --operator-uid "$(id -u)" \
        --state-dir /var/lib/sanctum-demo
   ```

   This is the only root process in the demo. It prints
   `helper_listening socket=/run/sanctum/helper.sock mode=0o600` and then says
   nothing until you erase something.

9. **Confirm the signing key exists before anything can start a job.** The
   chain's genesis entry records the fingerprint of whichever key exists when the
   first job starts it. If none does, genesis records none, and
   `fingerprint_matches_genesis` is SKIP on every report that chain will ever
   carry — nothing afterwards repairs it. The reset creates the key; this checks
   it, with the passphrase the API will use, and creates one only if it is
   missing:

   ```bash
   SANCTUM_KEY_PASSPHRASE=sanctum-demo \
   .venv/bin/python scripts/hardware_validation.py keygen \
       --key-dir /var/lib/sanctum-demo/keys
   ```

   It prints `{"fingerprint": "…", "step": "keygen"}`. Compare the fingerprint
   with the one the reset printed after `KEY`; they must match. An error here
   means the passphrase is wrong — fix that now, not at 3:15.

   **Then start the API in a second terminal, as yourself — no `sudo`:**

   ```bash
   SANCTUM_HELPER_SOCKET=/run/sanctum/helper.sock \
   SANCTUM_STATE_DIR=/var/lib/sanctum-demo \
   SANCTUM_KEY_PASSPHRASE=sanctum-demo \
   SANCTUM_SESSION_TOKEN=sanctum-demo-session \
   .venv/bin/python -m api.main
   ```

   The fourth variable is not optional. Without it the server mints a random
   session token at every start, and both the check below and step 10 answer
   401 until you read that run's token off the banner.

   Then check the boundary is real, not assumed:

   ```bash
   curl -s --cookie "sanctum_session=sanctum-demo-session" \
        http://127.0.0.1:8787/health | python -m json.tool
   ```

   `limitations` must not contain `HELPER_IN_PROCESS`, `NO_SIGNING_KEY` or
   `CHAIN_WITHOUT_KEY_FINGERPRINT`.

10. **Open the browser to
    `http://127.0.0.1:8787/session/sanctum-demo-session`, full screen, Devices
    tab.** That request sets the session cookie and redirects to the UI; the
    bare `http://127.0.0.1:8787` returns 401 until it has.
    Your stick must be listed — both, if you staged `--usb-b`. If it is not,
    refresh once; if it is still not, the *helper* is not running or is not
    serving your uid: read Terminal 0. The API itself is unprivileged and never
    probes a device on its own.

11. **Open two more terminals.** Terminal 2, font 16pt or larger, `cd` to the
    repo — this is the one the audience reads at 1:30 and 3:15. Terminal 3,
    minimised — this is where the live wipe will be.

### Part B — the run

12. **Open `docs/demo/qa.md` on your phone**, not on the laptop. You will need
    it during Q&A and you cannot alt-tab away from the demo to find it.

13. **Open `docs/demo/rehearsal-log.md` on paper or a second screen.** You are
    writing seven numbers into it. Have a pen.

14. **Read the whole runbook top to bottom once, out loud, at normal speaking
    pace, with the timer off.** This is not the rehearsal. This is finding out
    which sentences you cannot say. Expect it to take eight minutes the first
    time.

15. **Reset for the real run:**

    ```bash
    sudo ./scripts/demo-reset.sh --quick
    ```

    About fifteen seconds. Then **restart the server** (Ctrl-C in terminal 1,
    re-run the command from step 8). Job state lives in memory, so a restart is
    the only way to clear the jobs step 13 may have created.

16. **Put the browser back on the Devices screen, full screen.** Check the stick
    is listed and shows a FAT32 volume — `--quick` put one back. Check the sticky
    note with the serial is where you can see it without turning your head.

17. **Start the timer, and start talking, in that order.** Press start on the
    phone with your left hand while your right hand is already on the trackpad.
    **The clock starts on your first word, not on your first click** — the
    Devices screen is already up, so beat 1 is pure talking.

18. **At each transition, glance at the phone and say the number out loud to
    yourself.** You will not remember seven numbers. Saying them makes them
    stick long enough to write down. The transitions are: finishing the badge
    explanation, minimising the wipe, finishing the PhotoRec counts, finishing
    the score breakdown, the report passing again after restore, and finishing
    the nine-defects slide.

19. **Do not stop for mistakes.** A rehearsal you paused is a rehearsal that
    measured nothing. If a beat fails, use its fallback exactly as written and
    keep the clock running — that *is* the thing you are practising.

20. **Stop the timer at 6:00 or when you run out of words, whichever comes
    first.** Write the seven numbers into `rehearsal-log.md` immediately, before
    you make coffee.

21. **Fill in the "Run 1" block** — what went wrong, what you fell back on, what
    you are changing. Then, for rehearsal 2, go back to step 14. **You do not
    run `--full` again** unless you have physically re-plugged the sticks or
    something is genuinely broken.

### If you get to the end of Part A and something is red

Do not start rehearsing. A rehearsal against a broken stage teaches you the
fallbacks and nothing else. Re-read the failing row's path, check the `SUMMARY`
section for which phase failed, and fix that first. `--full` is idempotent: you
can run it again.

---

## The five things that must be true at 0:00

1. `sudo ./scripts/demo-reset.sh --check-only` prints `OK` on every row and
   exits 0.
2. The root helper is running (Terminal 0) and the API is running **as you**,
   with `SANCTUM_HELPER_SOCKET`, `SANCTUM_STATE_DIR`, `SANCTUM_KEY_PASSPHRASE`
   and `SANCTUM_SESSION_TOKEN` all set, matching what the reset staged with.
   `GET /health`, sent with the session cookie, does not report
   `HELPER_IN_PROCESS`.
3. The browser has already been opened once on
   `http://127.0.0.1:8787/session/sanctum-demo-session`, so it holds the
   session cookie, and is now on the Devices screen, full-screen, showing the
   stick with a FAT32 volume on it.
4. The serial is written on a sticky note stuck to the laptop.
5. `docs/demo/fallback/` is populated. Nothing generates it; see its README.

Record every run in `docs/demo/rehearsal-log.md`. Seven numbers and three lines
of notes, written down before you make coffee.
