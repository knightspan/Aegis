# Sanctum Forensics — user manual

For the examiner or administrator who has been handed this tool and a drive.
It assumes you know what a filesystem is. It does not assume you have read the
source, and nothing here requires you to.

Every claim below was checked against the code as it stands. Where the tool
cannot do something, this manual says so in the same breath as the thing it can
do. Measured figures — recall, precision, throughput, timings — are deliberately
**not** repeated here; they live in
[`performance/calibration.md`](performance/calibration.md),
[`performance/acquisition.md`](performance/acquisition.md) and
[`validation/hardware.md`](validation/hardware.md), and several are pending a
re-run. A number you need for a court or a report comes from those documents, not
from this one.

**Contents**

1. [Before you start](#1-before-you-start)
2. [Installation](#2-installation)
3. [Starting it](#3-starting-it)
4. [Sanitize a drive (M1)](#4-sanitize-a-drive-m1)
5. [Erase files and folders (M2)](#5-erase-files-and-folders-m2)
6. [Acquire and recover (M3)](#6-acquire-and-recover-m3)
7. [Reports and verification](#7-reports-and-verification)
8. [Reading the ledger](#8-reading-the-ledger)
9. [When something refuses](#9-when-something-refuses)
10. [Cancelling, and what a cancelled operation leaves](#10-cancelling-and-what-a-cancelled-operation-leaves)
11. [Limitations](#11-limitations)

---

## 1. Before you start

Sanctum Forensics does two opposite jobs from one program, and keeps them apart
by construction.

| Module | What it does | Vocabulary |
|---|---|---|
| **M1 Secure Drive Eraser** | Sanitizes a whole block device, using the mechanism the device reported it can perform | NIST SP 800-88r2: **Clear**, **Purge** |
| **M2 Secure File & Folder Eraser** | Overwrites named files and folders, cleanses *document* metadata, and enumerates the filesystem metadata it did **not** cleanse | No sanitization method is claimed: clear covers every user-addressable location of a medium, and a file erase reaches only the named files' extents |
| **M3 Advanced File Carving & Recovery** | Acquires an image read-only, then recovers objects by filesystem metadata (*undelete*) and by content (*carve*) | read-only throughout |

Two words are used here in one sense each, everywhere:

* **sanitize** — destroy data so it cannot be recovered.
* **carve** — recover an object without filesystem metadata. Recovering *with*
  surviving filesystem metadata is **undelete**, and it is reported separately.

### What this tool does not guarantee

The three sanitization methods come from NIST SP 800-88r2 (September 2025; r1
was withdrawn on 2025-09-26) and the tool uses no others. **Clear** overwrites every user-addressable location and resists
keyboard-level recovery. **Purge** uses a mechanism — a firmware sanitize, a
cryptographic erase — that makes recovery infeasible with laboratory technique.
**Destroy** is physical: disintegrate, incinerate, pulverize, shred, melt. This
tool **never returns Destroy**, because no software can perform it; where Destroy
is what your policy requires, the tool tells you so, and can afterwards record the
people's attestation that it was done (§4, *Destroy*). It observes nothing.

Which of Clear or Purge you get is decided by what the device reported, never by
what you selected — see §4. On media where the tool can only Clear, the report
says Clear and says why. It does not say "military-grade", and it does not offer
Gutmann-style multi-pass overwrite on flash, because extra passes on flash
consume program/erase cycles for no security benefit.

The full list of guarantees the tool declines to make is
[`limitations.md`](limitations.md). Read it before you rely on a result. §11
points at the parts you are most likely to need.

### Implemented is not the same as physically validated

Every capability on every platform has one state, computed by the capability
resolver (`core/platform/capability.py`) and shown on the **Platform**,
**Devices** and **Sanitize** screens with its reason:

| State | Meaning |
|---|---|
| **SUPPORTED** | Runnable here, and a PASS run on a physical device *of this device class* is recorded. One class never validates another. |
| **IMPLEMENTED / UNVALIDATED** | Runnable here; tested with synthetic media and adapter doubles only. No physical run is recorded. |
| **DEVICE-DEPENDENT** | Implemented; whether it runs depends on what this device (or the USB bridge in front of it) reports. |
| **REQUIRES PRIVILEGE** | Implemented; this process lacks the OS privilege it needs. |
| **PLATFORM-LIMITED** | The operating system offers applications no path to the mechanism. |
| **BLOCKED FOR SAFETY** | Implemented, and refused for this device by a safety rule (system disk, mounted, internal Apple storage, virtual disk). |
| **NOT IMPLEMENTED** | The OS could do it; this build has no code for it. |

The physical runs on record are few: on Linux, discovery, whole-drive clear
and raw acquisition of one USB flash stick (`usb-flash`, 2026-09-05); on
Windows, discovery of a USB stick (`usb-flash`) and file erase on the host
system disk (device class not recorded), both 2026-09-27. Nothing else — no
firmware Purge, no HPA/DCO change, no Windows or macOS whole-drive clear or raw
acquisition, no restore, no macOS device — has been run on physical hardware.
The generated matrix is
[`validation/capability-completion-2026-09-28/capability-matrix.md`](validation/capability-completion-2026-09-28/capability-matrix.md),
the summary is
[`validation/capability-completion-2026-09-28/README.md`](validation/capability-completion-2026-09-28/README.md),
and how a row moves to SUPPORTED is
[`validation/physical-validation-procedure.md`](validation/physical-validation-procedure.md).

---

## 2. Installation

Linux is the primary platform and the only one with physical whole-drive
evidence. Whole-drive clear and raw acquisition are also implemented on Windows
(`\\.\PhysicalDriveN`, elevated process) and for external disks on macOS
(`/dev/rdiskN`, root), and are IMPLEMENTED / UNVALIDATED there (§1). Per-platform
installation, including *Run as administrator* on Windows and root on macOS, is
in [`INSTALL.md`](../INSTALL.md). The commands below are the Linux source install.

**Python 3.11 is required and your host `python3` is probably not it.** Fedora 44
ships CPython 3.14, which fails the pin and has no `libewf-python` wheel.

```bash
sudo dnf install -y python3.11 python3.11-devel     # or the Debian equivalents
cd sanctum-forensics
make install        # bootstraps .venv with python3.11 and installs under constraints.txt
make check          # ruff + mypy --strict + the test suite
```

Two dependencies have sharp edges:

* **`pytsk3`** installs from a `cp311` wheel that bundles its own libtsk. It needs
  no Sleuth Kit build and no `libtsk-dev`. Installing `sleuthkit` for the `fls` /
  `icat` command-line tools is useful for cross-checking a recovery by hand;
  nothing in the code shells out to them.
* **`libewf-python` builds from source, and a stock `pip install` of it cannot
  write E01.** The upstream `setup.py` passes `--disable-shared-libs`, which also
  disables zlib, and the first write fails with
  `libewf_handle_open: write access currently not supported - compiled without zlib`.
  Reading E01 works either way. If you need to *acquire* to E01, run
  `scripts/build-libewf-python.sh`, which round-trips a 1 MiB E01 during the build
  and fails if it cannot. Check what you have with:

  ```bash
  .venv/bin/python -c "from core.carve.acquire import e01_write_supported; print(e01_write_supported())"
  ```

  `False` means raw (`fmt: "raw"`) acquisition only.

The details behind all three are in [`technical.md`](technical.md).

### The container

```bash
docker build -t sanctum-forensics .
docker run --rm --network host -e SANCTUM_STATE_DIR=/var/lib/sanctum sanctum-forensics
```

`--network host` is required: the API binds `127.0.0.1` and nothing else, so there
is no port to publish. The image builds the UI with `npm ci` and fails if the
bundle references any external origin, and runs `scripts/build-libewf-python.sh`,
so an image that cannot write E01 does not get built.

**The container has no privileged helper.** `/health` reports the
`HELPER_IN_PROCESS` limitation and device operations inside it fail rather than
escalate. Drive sanitization is a host operation. The image is for the API, the
UI, carving and recovery, and reporting.

---

## 3. Starting it

**Two processes. Exactly one of them is root.** Start them in this order.
This section is the Linux arrangement. The socket helper is Linux-only (it
authenticates its peer with `SO_PEERCRED`) and refuses to start elsewhere. On
Windows the privileged work runs in the Sanctum process itself, which must be
started with *Run as administrator*; on macOS it likewise runs in the Sanctum
process, which needs root for `/dev/rdiskN`. See [`INSTALL.md`](../INSTALL.md).

### Terminal 0 — the privileged helper

It serves five allowlisted operations over a `0600` Unix socket, authenticates the
peer with `SO_PEERCRED`, and never spawns a shell.

```bash
sudo mkdir -p /var/lib/sanctum
sudo .venv/bin/python -m helper \
     --operator-uid "$(id -u)" \
     --state-dir /var/lib/sanctum
```

Expect one line — a `helper_listening` record naming the socket path and
`mode=0o600`. Leave it running.

Neither argument is guessed, and both are required:

* `--operator-uid` is the **only** uid allowed to connect, and it is also the uid
  every file the helper writes into the ledger is handed to — which is what lets
  the unprivileged API read back the chain a wipe produced. Pass the account that
  will run the API, normally `$(id -u)`.
* `--state-dir` is the **only** directory tree the helper will write into. Every
  path in every request (`ledger_root`, `dest`) is resolved against it — symlinks
  resolved before the comparison — and refused if it lands outside. It must exist
  already; the helper will not invent a directory nobody chose.

An older two-argument form of this command (without `--state-dir`) now fails with
`python -m helper: error: the following arguments are required: --state-dir`. That
is the correct failure — a root daemon that invented its own directory would be
worse — so add the argument rather than working around it.

### Terminal 1 — the API, as yourself

**No `sudo`.** Running the API as root puts every privileged operation back inside
the web server and makes the socket's uid check and its five-operation allowlist
authenticate nothing.

```bash
SANCTUM_HELPER_SOCKET=/run/sanctum/helper.sock \
SANCTUM_STATE_DIR=/var/lib/sanctum \
SANCTUM_KEY_PASSPHRASE='<your passphrase>' \
.venv/bin/python -m api.main
```

It binds `127.0.0.1:8787` and nothing else, and it prints the one URL that
opens it:

```
  Sanctum development server
  Address     http://127.0.0.1:8787  (loopback only; never 0.0.0.0)
  Open this   http://127.0.0.1:8787/session/<token>
  Session     one token for this run
              every request without its cookie is refused
```

**Open the `/session/<token>` line.** It sets an `HttpOnly`, `SameSite=Strict`
cookie for that run; every request without it gets 401, and every request
addressed to a name other than `127.0.0.1`, `localhost` or `[::1]` gets 400.
Loopback alone is not an authorisation boundary: on a shared machine, any
other account can reach a loopback port.

To open the same session in its own window instead of a browser tab, install
the `desktop` extra (`pip install -c constraints.txt -e ".[desktop]"`) and run
`.venv/bin/python -m api.desktop` with the same three variables. It picks a
free port and mints its own token, so it ignores `SANCTUM_PORT` and
`SANCTUM_SESSION_TOKEN`; closing the window stops it.

A new token is minted each start. To script against the API, set
`SANCTUM_SESSION_TOKEN` yourself and send `Cookie: sanctum_session=<token>`.
`SANCTUM_DEV_INSECURE=1` turns the session off entirely, prints a warning
saying so, and is for a single-user development machine only.

| Variable | What happens without it |
|---|---|
| `SANCTUM_HELPER_SOCKET` | **The API silently falls back to an in-process helper.** Nothing warns you on the console. Device operations then run with the web server's own privileges, which as an ordinary user means they *fail* — they are never escalated. See the check below. |
| `SANCTUM_STATE_DIR` | The state directory defaults to `~/.local/share/sanctum`. Your ledger, reports, evidence and recovered objects go there instead of where you meant. |
| `SANCTUM_KEY_PASSPHRASE` | Report signing refuses to write or read an unprotected key. In a terminal you are prompted; with no TTY the report fails with `KeyPassphraseMissing`. |
| `SANCTUM_PORT` | Defaults to `8787`. |
| `SANCTUM_SESSION_TOKEN` | A fresh token is generated for each run and printed. Set it to script against the API. |
| `SANCTUM_DEV_INSECURE` | With `=1` the session check is off and the server says so loudly. Any local process can then drive it, including the endpoints that erase files. |

### The one check to run before anything matters

```bash
curl -s --cookie "sanctum_session=$SANCTUM_SESSION_TOKEN" \
     http://127.0.0.1:8787/health | python3 -m json.tool
```

Started **without** a helper socket, it answers like this — and this is the state
the sequence above exists to avoid:

```json
{
    "status": "ok",
    "tool_version": "sanctum-forensics/0.0.0",
    "state_dir": "/var/lib/sanctum",
    "ui_bundled": true,
    "limitations": [
        "HELPER_IN_PROCESS: no helper socket was configured, so privileged operations run with this process's own privileges rather than through the root daemon. On an unprivileged process the device operations will fail; nothing is silently escalated."
    ]
}
```

**`limitations` must be empty — it must not contain `HELPER_IN_PROCESS`.** If it
does, the API did not see the socket:

```
"HELPER_IN_PROCESS: no helper socket was configured, so privileged operations
run with this process's own privileges rather than through the root daemon. On
an unprivileged process the device operations will fail; nothing is silently
escalated."
```

Check that Terminal 0 is still running and that `SANCTUM_HELPER_SOCKET` matches
the path it printed. Until then the Devices screen will still list devices, but
every capability probe comes back
`hdparm could not read /dev/sdX: permission denied.` and no wipe can start. That
string is a privilege failure, not a statement about the drive.

If the limitation is present when a report is generated, it is copied into the
report's limitations section, so a report produced in this state says so on its
face.

> `make run` is `python -m api.main` and honours `SANCTUM_PORT`. It used to be
> a bare `uvicorn --reload` on port 8000 with no session protection; the entry
> point is what prints the session URL and refuses anything without its
> cookie, so that is what the target runs.

### One more thing, before the first job

Create the signing key **before the first ledger entry is written**:

```bash
SANCTUM_KEY_PASSPHRASE='<your passphrase>' \
.venv/bin/python scripts/hardware_validation.py keygen --key-dir /var/lib/sanctum/keys
```

```json
{
  "fingerprint": "43:62:3F:92:1A:22:4C:25:82:87:55:B8:0C:CB:6B:1E:AB:32:C7:8A:3E:83:D5:F2:7B:DB:2C:94:AB:C1:29:67",
  "step": "keygen"
}
```

The chain's genesis entry records whichever signing fingerprint exists when the
chain is started. Start the chain first and the genesis records none, and the
report check `fingerprint_matches_genesis` will report **SKIP — "the chain was
created before any signing key existed"** for every report on that chain, for the
life of that chain. Nothing is broken and the report still verifies; you have
simply lost one of the five checks. Write the fingerprint down: §7 explains why a
third party needs it from somewhere other than the report.

---

## 4. Sanitize a drive (M1)

Use the **Devices** screen to pick a target, then **Sanitize**.

### The method is selected from probed capability, never from preference

You choose a *level* — CLEAR or PURGE. The tool chooses the *mechanism*. The
request the browser sends carries `path`, `level`, `typed_serial` and the
`authorization_id` the server issued, and has no field for a method at all; `core/erase/drive.py:select_method` reads a
decision table over what the capability probe returned.

There is no method chooser on the Sanitize screen. An earlier build had one: an
operator could select DoD 5220.22-M, the confirmation dialog said DoD, the request
carried only the level, and the certificate recorded a single pass. The screen now
shows, **before you commit**, what the engine will run:

* **Level** — the two levels as radio buttons. A level the engine cannot run on
  this device is disabled. PURGE is preselected where the engine can run it.
* **What the engine will run** — the method, by name and identifier; the engine's
  own justification sentence; whether the device was determined to be flash and
  the signal that decided it; the probed evidence for the choice (for example
  *"hdparm -I listed BLOCK_ERASE_EXT in the ATA SANITIZE feature set"*); and, for
  PURGE, any other Purge mechanisms the device reported, in the engine's order.
* **For Purge this device would need** — shown when PURGE is unreachable, naming
  the commands that would make it reachable on this bus and media.
* **Residual risk** — the capability limitations the probe recorded, and the flash
  caveat when Clear is chosen on a device the engine determined to be flash.

These come from `core/erase/drive.py:preview`, which the helper computes during the
device scan by calling the same `select_method` the job calls. The job re-probes the
device when it starts. If the method it runs differs from the one shown — possible
only if the device's capabilities changed in between — the Progress panel says so
in red, and the ledger and certificate record what ran.

**DoD 5220.22-M is not offered in the UI.** The engine still implements it
(`EraseMethod.DOD_5220_22_M_3PASS`, with its legacy warning), but the API cannot
carry a method, and a control whose choice is not honoured is worse than no control.

**Clear** is a host-pattern overwrite of every user-addressable location. It is
always achievable on a writable device.

**Purge** needs a mechanism inside the device. What the probe looks for:

| Reported by | Purge mechanism |
|---|---|
| `hdparm -I`, SANITIZE feature set | ATA SANITIZE — block erase or crypto scramble; overwrite on magnetic media only |
| `hdparm -I`, security block | ATA SECURITY ERASE (enhanced), if security is not frozen, **on magnetic media only** |
| `nvme id-ctrl`, SANICAP | NVMe SANITIZE (block or crypto); or Format NVM with a crypto setting |
| `sedutil-cli` | Opal SSC — see the exception below |

If none of those is reported, PURGE is **not offered**, and asking for it returns
`UnsupportedCapability` naming the levels that are reachable. A USB stick is the
common case: ATA pass-through is not dependable through a USB bridge, so the
capability record says *"ATA pass-through is unavailable through this usb bridge,
so firmware sanitize and secure erase cannot be verified or issued. Only
overwrite-based CLEAR can be assured."* — which is a statement about the bridge,
not a claim that the device lacks the feature.

**SED cryptographic erase (Opal) cannot be issued by this build.** It needs the
PSID printed on the drive label, and the build has no way to accept it. On a drive
where Opal is the engine's only Purge mechanism, the plan names it and says, in
red, *"This build cannot issue this method"*, and the PURGE radio is disabled. A
Clear with a single-pass overwrite remains available and **achieves Clear, not
Purge; the report will say so.**

### The gates

There is no dry-run or simulation mode. Every erase this screen starts runs on
the selected real device once its gates pass, so the gates run every time. A
request that still carries `dry_run`, `simulation` or `simulate` is rejected
with HTTP 422 and never reaches the helper: it is neither honoured nor ignored.
What would run is shown **before** you commit, from the read-only plan
(`core/erase/drive.py:preview`); that plan writes nothing and is not a rehearsal.

Destructive erasure is opt-in twice, and the gates are re-checked inside the root
helper, not in the browser:

1. **A human approval, bound to the plan.** See steps 3-5 below: a verified
   backup, a recorded approval, and a one-use authorization the server issues.
2. **You type the device serial.** The helper compares it against the serial *it*
   re-reads from the device, so a browser tab that went stale before the drive was
   swapped cannot authorise the wipe. A device that reports no serial is confirmed
   by typing its full `/dev/disk/by-id/...` path instead — still a value you read
   off the capability report, never one you can guess.

The **workflow authorization** the server issues and spends once (added
2026-09-25):

3. **A backup image.** *Open workflow and verify backup* names an image inside the
   evidence directory, at least as large as the device. The server hashes and
   sizes it read-only and records its size, mtime, ctime and inode. This does not
   prove the image is a copy of this device.
4. **An approval.** Tick the acknowledgement and type the serial, then *Approve
   erasure*. The approval is recorded against the OS account the helper reports;
   the API does not authenticate a person.
5. **The authorization, once.** Type the serial again and *Erase*. The request
   carries the authorization id the server returned; a second use, a changed
   device, plan or backup, or a missing id is `REFUSED` with a **WHY BLOCKED**
   list, and nothing is written. The helper checks the same things again, from
   its own read of the device and the image, before the engine starts.

A refusal is shown as `BLOCKED`. A server failure is shown as *Request failed*,
never as a refusal. A job that did not complete gets a *signed record*, not a
certificate.

Before any gate matters, the tool refuses outright to touch a device that holds
the running system (root, `/boot` or active swap) or that has any mounted
filesystem. Unmount first; there is no override. On Windows a disk that still
exposes any volume is refused, and on macOS a disk with any mounted volume.
**No erase unmounts or takes a disk offline by itself.** On Windows and macOS
the **Devices** screen offers a separate **Prepare** step for a mounted,
non-system disk (`POST /devices/prepare`, body `path` and `typed_serial`):
the screen lists the volumes the step affects from the device scan, and the
step runs on the real disk once the serial is typed by hand. The Windows offline state is not persistent. System and internal disks
are refused, and every call is ledgered. On Linux you unmount yourself.

### The 0xA5 write calibration

Immediately after the gates clear, and never on a resume, a Clear-level overwrite
runs a **write calibration**: 64 MiB of `0x00` and 64 MiB of `0xA5`, both
`O_DIRECT`, both timed. It is destructive — it writes 128 MiB over a region of the
target — and it exists because a flash controller can acknowledge an all-zero write
without programming a single cell, and no host-side *read* can tell the difference.
The write's duration can.

If the non-zero write takes more than **2.0×** as long as the zero write, the zero
fill was not programmed. The tool then writes the pattern with `0xA5` rather than
zeros, and raises a `CONTROLLER_WRITE_ELISION` residual finding carrying the
measurement. This is why a wiped device may read back as `0xA5` rather than zeros:
a device holding `0xA5` was written, and a device holding zeros may not have been.

A ratio below the threshold is reported as **"no elision detected"** and never as
"the write was performed". The calibration measures the controller's behaviour, not
the state of the cells. If the device is too small, the region is unwritable, or the
clock produced a zero duration, the result is *unknown* — recorded with its reason,
never as a pass.

### What you get

The job moves through six phases — `PREFLIGHT`, `HIDDEN_AREA_UNLOCK`, `ERASE`,
`HIDDEN_AREA_RESTORE`, `VERIFY`, `REPORT` — and each writes a ledger entry as it
completes. The two hidden-area phases only record: an ordinary erase never
changes an HPA or a DCO. If the drive hides sectors, the erase covers the
accessible range, the report says the hidden bytes were not covered, and the
HPA/DCO workflow (`POST /workflow/hidden-area`) is the separate, approved way to
expose them before erasing again. Progress streams to the screen while the wipe runs. Verification reads
the medium back: exhaustively at or below 64 GiB, and above that the first and last
1 GiB in full plus 4096 seeded random 1 MiB windows, with the report carrying the
detection-probability formula and the seed rather than a bare percentage — so a
third party can redraw the same sample.

### On Windows and macOS

The same workflow — backup, approval, typed serial, one-use authorization,
write-seam re-check — runs on all three platforms. What differs is the engine
and what has been proven:

* **Addressable whole-drive clear** on Windows and macOS is
  `core/erase/blockclear.py`: an aligned sequential overwrite with exact byte
  accounting, checkpoints and resume, and a full or sampled read-back. On
  Windows it writes `\\.\PhysicalDriveN` through a handle bound, before the
  first write, to the planned disk number, serial and length read from the
  handle itself; a drive letter is never a target. On macOS it writes the
  external disk's `/dev/rdiskN`; macOS has no ioctl that returns a serial, so
  the serial is re-read from `system_profiler` immediately before the device is
  opened and the handle is checked against the planned size and block size.
  Internal Apple storage is never raw-written (BLOCKED FOR SAFETY); use
  *Erase All Content and Settings*. **Both are IMPLEMENTED / UNVALIDATED:
  never run on a physical disk.**
* **Device sanitize on Windows**: ATA SANITIZE (block erase, crypto scramble)
  through `IOCTL_ATA_PASS_THROUGH`, and NVMe Sanitize (block, crypto) through
  `IOCTL_STORAGE_REINITIALIZE_MEDIA`. Each is offered only when the
  controller's own IDENTIFY answer reports it, and never downgraded to an
  overwrite; the storage driver may still refuse the pass-through, and the
  refusal is reported. Windows reports no sanitize progress. ATA SECURITY
  ERASE is **NOT IMPLEMENTED** on Windows (a failed or interrupted run would
  leave the drive locked with no tested recovery path), and NVMe Format is
  **PLATFORM-LIMITED** (the in-box driver does not pass it through). Device
  sanitize is **DEVICE-DEPENDENT** and has never run on a physical drive.
* **Device sanitize on macOS** is **PLATFORM-LIMITED**: macOS exposes no
  public ATA or NVMe pass-through to applications.

### Hidden areas: the separate HPA/DCO workflow

An ordinary erase **never changes an HPA or a DCO**. If the drive hides sectors
behind a Host Protected Area, the erase covers the accessible range, records
`hidden_covered=False`, names the hidden byte count in its limitations, and
points here. Exposing them is its own workflow, authorized like an erase:

1. `POST /workflow/hidden-area` (`path`, `backup_id`, `volatile`) reads the
   native and accessible maxima read-only, rejects an implausible reading, and
   plans one change: SET MAX ADDRESS to the native maximum. **Volatile is the
   default**: the drive returns to its original maximum at the next power
   cycle. Nothing is sent to the drive.
2. `POST /workflow/hidden-area/{id}/approve` needs the typed serial and
   `acknowledge_configuration_change`, plus `acknowledge_permanent` for a
   permanent change, and a recorded, verified backup of at least the
   accessible range.
3. `POST /workflow/hidden-area/{id}/execute` sends the real command. With the
   typed serial, the drive is re-read just before the command, a stale plan is
   refused, and the change is verified by reading the maxima back. There is no
   dry-run mode; a body carrying one is rejected (422).

The DCO is discovered and reported only: DCO RESTORE and DCO SET are never
issued, and sectors a DCO hides stay hidden, which the result says. Backends:
`hdparm` on Linux, ATA pass-through on Windows; on macOS HPA/DCO is
PLATFORM-LIMITED, and behind a USB or card-reader bridge it is refused. **The
workflow has never changed an HPA on a physical drive.**

### Backups and restore

`POST /workflow/backup` (`backup_image`, `source_path`, optionally the
`acquisition_job_id` whose hashes it reuses) records an image under the
evidence directory as a backup of a device whose identity the helper re-reads,
with the image's SHA-256 and per-chunk hashes. `POST
/workflow/backup/{id}/verify` re-hashes it and names the first chunk that no
longer matches. Neither writes anything. The record states what it cannot
prove, including that the image is a faithful copy of the device.

A restore overwrites its target, so it is authorized exactly like an erase:

1. `POST /workflow/restore` (`backup_id`, `target_path`) re-reads the target,
   refuses a system, mounted or too-small one, and plans the exact byte range.
   Nothing is written.
2. `POST /workflow/restore/{id}/approve` needs the typed serial and
   `acknowledge_data_overwrite: true`.
3. `POST /workflow/restore/{id}/execute` runs the real restore, with the target
   serial typed again. It verifies each backup chunk before writing it, accounts
   for every byte, and finishes with a read-back of the restored range against
   the backup hashes. There is no dry-run mode; a body carrying one is rejected
   (422).

An erase authorization can never be spent as a restore, or the reverse. On
Windows the restore target also refuses a disk that still exposes a volume.
**Restore is IMPLEMENTED / UNVALIDATED on all three platforms: it has never
been run against a physical device.**

### Make usable: a filesystem after an erase

A completed erase leaves a device with nothing on it, which an operating system
reads as unformatted. **Make usable** on the Sanitize screen writes one MS-DOS
partition table with a single partition spanning the device, and one filesystem
on it (exFAT, FAT32 or ext4, with a label). It is authorized like an erase, in
three separate calls:

1. `POST /workflow/format` (`path`, `filesystem`, `label`) re-reads the device
   and refuses unless the ledger's newest job on that device is a completed
   erase of the same serial. It refuses a system, mounted or serial-less
   device. Nothing is written.
2. `POST /workflow/format/{id}/approve` needs the typed serial and
   `acknowledge_format: true`.
3. `POST /workflow/format/{id}/execute` runs the real format, with the serial
   typed again. The helper re-checks the authorization, the device identity and
   the serial in its own process. The engine appends `format.begin` before the
   first write and `format.complete` or `format.failed` after, and reads the
   filesystem type and label back. There is no dry-run mode.

A `format` authorization can never be spent as an erase, restore or HPA change,
or the reverse. Once a device has been formatted, the ledger's newest job on it
is the format, so a second format is refused until it is erased again.

What it does not claim: **it does not sanitize.** It writes filesystem metadata
to a few sectors and leaves every other block as the erase left it; the
certificate describes the device at the end of the erase, before this step. A
step that fails after the first write can leave the device with no partition
table; the failure names the step. Linux only: other hosts refuse with the
platform's reason and no command runs. **Make usable is IMPLEMENTED / UNVALIDATED:
it has never been run against a physical device.**

### What the certificate calls it

Every drive or file report names one category, from
`core/report/semantics.py`, with the command, protocol, scope, verification
and assurance it prints:

| Category | What was done |
|---|---|
| **FILE ERASE** | A file's current blocks overwritten through the filesystem. Not a sanitization of the medium. |
| **ADDRESSABLE WHOLE-DRIVE CLEAR** | Every LBA the operating system exposes overwritten by the host. On flash, remapped and over-provisioned blocks are not reached. Never called a Purge. |
| **DEVICE SANITIZE** | The drive's own firmware command (ATA SANITIZE, NVMe Sanitize, ...). |
| **CRYPTO ERASE** | The media encryption key replaced. The ciphertext remains on the medium. |
| **PHYSICAL DESTRUCTION ATTESTATION** | A person's signed statement about a physical destruction; the tool observed nothing. |

### Destroy: recording a physical destruction

NIST SP 800-88 Rev. 2 has a third outcome, **Destroy**, for media that cannot be
cleared or purged or must never be reused. A shredder, a disintegrator or a furnace
performs it; no software can, and none can watch it happen. So the application
does not offer Destroy as a method. It records what the people who did it attest.

On the **Devices** screen, open *Record a physical destruction*. Pick a detected
device to fill in its serial, model and capacity, or type them. Enter the technique
(shred, disintegrate, pulverize, incinerate, melt, or other with a description), the
largest fragment in millimetres if it was measured, when and where it was done, who
did it, who witnessed it, a vendor certificate number if a vendor did it, and why the
medium was destroyed rather than cleared or purged. *Record the destruction* writes
one `destroy.recorded` ledger entry; *Get the signed record* signs it.

The record is titled **Record of Destruction** and its headline is *Destruction
attested, not observed*. The date it was destroyed is the attesters' statement; the
date it was recorded is this machine's clock, and the two are separate fields. A
date after this machine's clock is refused. The limitations say that the tool did
not see the destruction, that the names were typed in and not authenticated, and
that whether the technique reaches Destroy for that media is the facility's call.
A record with no witness or no fragment size says so.

The same through the API:

```bash
curl -s -X POST http://127.0.0.1:8787/jobs/record-destroy \
  -H 'Content-Type: application/json' \
  -d '{"serial":"WD-WX41A12345","media_type":"HDD","technique":"SHRED",
       "particle_size_mm":20,"reason":"Heads failed; Purge cannot be issued.",
       "performed_by":"A. Rao","witnessed_by":"S. Iyer",
       "performed_at":"2026-09-24T15:30:00+05:30","case_id":"CASE-001"}'
```

---

## 5. Erase files and folders (M2)

Use the **File eraser** screen, or `POST /jobs/erase-files`. This path is
unprivileged: it writes through ordinary file handles and runs in the API process,
because the API can already open any file you can.

**Every erase here is real**, and its gate is an explicit `confirm` rather than
a serial — there is no device to identify. A request without `confirm: true` is
refused before any path is inspected (HTTP 409), and a request that still
carries `dry_run` is rejected (422). The screen shows the queued paths
(**PLANNED**), then **AUTHORIZED** once you confirm, then **EXECUTING**,
**VERIFYING** and **COMPLETE**, or **FAILED** / **BLOCKED** with the reason;
**COMPLETE** is shown only when every path was erased.

Eleven steps run per file in a fixed order: inspect, cleanse metadata, overwrite,
alternate data streams, truncate, rename to a **same-length** random name (a shorter
name leaves the tail of the original in the directory entry), unlink, residual scan,
verify. A per-file `OSError` sets `ok=false` on that record and the batch continues;
one bad file does not abort a run. The record's `attempted` field says whether the
erase steps had begun: the File eraser shows a path that failed partway as
**failed partway** with an INCOMPLETE residual (its state is unknown), a path
refused or stopped before any step ran as NOT RUN, and a record without the field
(an older server) as UNKNOWN - never "not attempted" for a path it started on.

Two options change what is destroyed:

* **`cleanse_metadata`** (default on) rewrites *document* metadata before the
  overwrite: EXIF, OOXML `docProps`, PDF info dictionaries, OLE summary streams. It
  never claims a clean it did not achieve — a format it cannot rewrite is reported,
  not silently skipped.
* **`break_hardlinks`** (default **off**). Overwriting a file with more than one
  hard link destroys data reachable under names you did not give. With the option
  off, such a file is reported as `HARDLINK_SURVIVES` and its content is left. The
  finding is reported either way.

### What is overwritten, and what is only reported

**Overwritten:**

* by a file erase: the named file's data, its alternate data streams and extended
  attribute values, and its document metadata (above);
* by a free-space wipe (below): the blocks a FAT32, exFAT or ext4 volume reports
  as free. On those filesystems that is where the content of files deleted earlier
  lies.

**Detected and reported, never removed:** resident MFT data, the filesystem journal,
the USN journal, MFT slack, `$I30` index slack, file slack, deleted directory
entries, copy-on-write snapshots, VSS shadow copies, TRIM remapping, compressed
reallocation, EFS encryption, sparse unwritten regions, likely backup copies. A file
erase lists each as a residual finding with a severity; a free-space wipe lists the
ones it does not reach under `not_reached`. The tool tells you what the filesystem
kept; it does not claim to have removed it.

### Traces the desktop kept of the file

Overwriting a file does not reach what the desktop made of it. After the erase,
the *Remove what the desktop kept* option (on by default; `sweep_traces` in the
API) searches for:

| Trace | Where | Tied to the file by |
|---|---|---|
| Thumbnail, failed-thumbnail marker | `~/.cache/thumbnails`, `~/.thumbnails` | its name is the MD5 of the file's URI; its `Thumb::URI` is checked |
| Recent-files entry | `~/.local/share/recently-used.xbel` | the entry's `href` |
| KDE recent document | `~/.local/share/RecentDocuments/*.desktop` | its `URL=` |
| Trash copy and its record | the home Trash, and `.Trash-<uid>` on the file's own volume | the `.trashinfo` `Path=` |
| Recycle Bin copy and its record (Windows) | `<volume>\$Recycle.Bin\<SID>` | the `$I` record's original path |
| Recent shortcut (Windows) | `%APPDATA%\Microsoft\Windows\Recent` | the shortcut's LinkInfo target |
| Possible copy (macOS) | `~/.Trash` | a same name only: **reported, never removed** |

A run removes only the traces tied to an erased path on evidence; every other
trace is listed and left alone. A trace file is erased through the same
steps as a target, so the same residual findings apply to it. An entry in a shared
list is cut out and the list is overwritten in place, padded to its old length, so
the bytes that named the file are overwritten rather than freed. Nothing follows a
link: a thumbnail that is a link is refused, and a Trash folder reached through a
link is not searched. A list that changed while it was being read is left alone.
A running application that holds the recent list in memory can write an entry
back, so close file managers and viewers first.

For a folder, a thumbnail whose `Thumb::URI` names any file inside it is also
found, including files deleted from it long ago. A Trash folder that once held
the file loses only the copy of that file; the folder's other contents stay.

The file report adds a **6. Desktop Traces** section: every trace with its
evidence and what became of it, every place inspected with its outcome
(searched, absent, unreadable, permission-denied), and the places on this
platform that keep traces and were not searched (application caches, search
indexes, `thumbcache_*.db`, snapshots, sync clients). A trace tied on evidence
but held in a file a daemon or the shell owns - a macOS recent item, a Quick Look
cache entry, a jump-list entry beside other entries, a Trash `.DS_Store` record -
is marked **reported only**, with the reason, and left as it is. Each trace also gets an
`erase.file.trace` ledger entry, and the sweep closes with `erase.file.traces`.

**A per-file erase is usually unverifiable, and is reported as unverifiable rather
than as a pass.** Verification needs a physical extent map, which needs FIEMAP; on a
filesystem that does not answer FIEMAP the record says so in as many words — e.g.
*"FIEMAP is unavailable for `<path>` (\[Errno 95\] Operation not supported), so no
physical extent map was captured and the overwrite cannot be verified by reading the
medium."* Read the `limitations` list on each file's record; it is per-file and per
filesystem, not a global footnote.

The tool refuses a filesystem root and a protected system location
(`/`, `/boot`, `/etc`, `/usr`, `/var`, `/System`, `C:\Windows`, …) outright.

### Wipe free space

Deleting a file leaves its content in clusters the filesystem now calls free, and
the Recovery screen will carve it back. A file erase cannot reach it, because the
file no longer exists. A free-space wipe does.

Use the **Wipe free space** panel at the foot of the File eraser screen, or
`POST /workflow/wipe-free-space` with `mount_point` to plan it (read-only), then
`POST /jobs/wipe-free-space` with `mount_point` and `typed_identifier` to run it.

**What it does.** It creates one directory, `.sanctum-freespace-<job id>`, at the
root of the volume, writes `0xA5` into files inside it until the filesystem answers
`ENOSPC`, forces each file to disk, then deletes the files and the directory. It
opens no other file. `ENOSPC` is the normal end of the fill, not an error. The fill
pattern is non-zero because some flash controllers skip writing zeros (§11).

**What it accepts.** A FAT32 (`vfat`), exFAT or ext4 volume mounted by the Linux
kernel, named by its **mount point exactly**. A folder inside a volume is refused
and the answer names the volume's mount point. Any other filesystem is refused with
`UnsupportedCapability` (HTTP 422), which names the type: NTFS has not been
measured, copy-on-write filesystems would put the fill beside old data rather than
over it, and FUSE mounts have not been measured. There is no Windows or macOS
implementation.

**The gates.**

1. **Plan first.** *Plan* (`POST /workflow/wipe-free-space`) resolves the
   volume, applies every refusal below, and reports its filesystem, free space,
   what the fill cannot reach and the identifier to type. It writes nothing,
   creates no job, and is not a rehearsal of the wipe.
2. **The system volume is refused outright** (`SystemDiskRefused`, HTTP 409). That
   means any volume holding `/`, `/boot`, `/boot/efi`, `/etc`, `/home`, `/opt`,
   `/root`, `/srv`, `/usr` or `/var`, an active swap file, or this deployment's
   state, ledger, report or key directory. Filling one of those to zero free space
   can stop the host, or leave the wipe unrecorded.
3. **The wipe needs the volume identifier** (`ConfirmationMismatch`, HTTP 409).
   The identifier is the filesystem UUID when `/dev/disk/by-uuid` has one for the
   volume, and the mount point otherwise, exactly as the plan printed it.

While the wipe runs the volume is full, and anything else writing to it fails with
"No space left on device".

**What the result reports.**

| Field | Meaning |
|---|---|
| `bytes_written` | Bytes of `0xA5` written into the filler files |
| `free_bytes_before` | Free space an unprivileged writer may allocate (`statvfs` `f_bavail`) |
| `free_blocks_bytes_before` | Every free block, including those reserved for root (`f_bfree`) |
| `free_bytes_at_full`, `free_blocks_bytes_at_full` | The same two figures with the volume full |
| `free_bytes_after` | Free space after the filler was deleted |
| `stopped_by` | `ENOSPC` normally; anything else is named in `limitations` |
| `filler_removed` | Whether every filler file and the directory were deleted |
| `not_reached` | The residue this operation does not touch, always listed |
| `limitations` | Flash, reserved blocks, blocks still free at the end, errors |
| `verified` | Always `null`. Nothing is read back, so no pass is claimed. |

`free_blocks_bytes_at_full` is what the fill did **not** write. On ext4 it is the
root-reserved blocks: 4,694,016 bytes on a 64 MiB test volume.

**What it does not reach**, listed in every result: file slack inside other files'
last clusters; deleted directory entries (names, sizes and timestamps, which the
Recovery screen's undelete still lists); filesystem metadata and journals; blocks
reserved for root; the clusters of its own filler directory; and on flash, pages the
controller has remapped. On FAT32 and exFAT the filler directory's own entry can
land in the slots of a deleted entry in the volume root and overwrite that one name.
That is a side effect, not coverage.

**The ledger** records `erase.freespace.preflight`, `erase.freespace.fill` and
`erase.freespace.complete`, or `erase.freespace.cancelled`. A cancelled wipe deletes
its filler before the entry is written, and the entry says that no coverage is
claimed. **No signed report is generated** for a free-space wipe in this build; the
ledger entries and the job result are the record.

**Measured.** On udisks loop volumes, six JPEGs were planted and deleted, and the
Recovery pipeline recovered all six. After the wipe it recovered none, and no
512-byte slice of any of them remained in the image. This held on FAT32 with
512-byte and 4096-byte clusters, exFAT with 4096-byte and 32768-byte clusters, and
ext4 with 4096-byte blocks. It has not been run on a real USB stick or SD card. See
§11.

---

## 6. Acquire and recover (M3)

**The evidence path is read-only by construction.** Nothing under `core/carve`
opens a device or an image `O_RDWR`; the evidence classes declare no write method
at all and open `O_RDONLY`. Acquisition and carving need no confirmation gate,
because there is nothing to destroy.

### Acquire

The **Recovery** screen has an acquisition panel: pick a device from the
Devices data (the source path and serial are taken from it, never typed), a
destination and a format. The button follows the resolver's raw-acquisition
state for that device, shown beside it with its reason. The same through the
API is `POST /jobs/acquire`, passing `source`, `dest` and `fmt` (`raw` or `e01`),
and for a raw device on Windows or macOS `expected_serial`:

```bash
curl -s -X POST http://127.0.0.1:8787/jobs/acquire \
  -H 'Content-Type: application/json' \
  -d '{"source":"/dev/sdX","dest":"case-001/source.dd","fmt":"raw",
       "case_id":"CASE-001","operator":"examiner"}'
```

On Linux, against a block device, the acquisition sets the kernel's read-only flag
with `BLKROSET` and reads it back with `BLKROGET` before opening anything.

**Read what that establishes.** It establishes that *the kernel holds the device
read-only*. It does **not** establish that a write would be refused, and the
acquisition record says so: `write_block_verified_by: flag_read_back`, plus a
`WRITE_BLOCK_NOT_VERIFIED` note. Proving the refusal means attempting a write, and
this path never writes to a device. Two routes are not covered by the flag on any
bridge: **SG_IO / ATA pass-through**, which addresses the device below the block
layer where the flag is never consulted, and **a partition node whose own flag was
never set** — an automount writing through `/dev/sdX1` while only `/dev/sdX` was
blocked. `scripts/probe-write-block.py`, gated behind
`--i-understand-this-may-write-to-the-device`, qualifies an interface by attempting
a write against **scratch media**; a record produced that way says
`write_block_verified_by: attempted_write`. **For evidence that will be presented,
use a hardware write blocker.**

**On Windows and macOS there is no software write block, and the record says
so.** On Windows the source is `\\.\PhysicalDriveN` (or a volume), opened
`GENERIC_READ` only and unbuffered; the handle is bound to the disk number,
serial and length before the first read, medium errors are salvaged, and a
vanished disk aborts the job. On macOS the source is an external disk's
`/dev/rdiskN`; internal Apple storage is never imaged, because a raw image of
it is Secure Enclave ciphertext. Both need an elevated process (§3). Both are
**IMPLEMENTED / UNVALIDATED**: no Windows or macOS raw acquisition has been run
on a physical device. On Linux, raw acquisition is SUPPORTED for `usb-flash`
only (one stick, 2026-09-05). **For evidence that will be presented, use a
hardware write blocker on every platform.**

`dest` is confined to `<state-dir>/evidence/`. A relative path is taken as relative
to it, so `case-001/source.dd` is the ordinary form and no absolute path is needed.
An absolute path outside it is refused with a 400 before anything is opened.

### Carve

Use the **Recovery** screen — image path, *Undelete*, *Signature and structure
carve*, output directory — or `POST /jobs/carve`:

```bash
curl -s -X POST http://127.0.0.1:8787/jobs/carve \
  -H 'Content-Type: application/json' \
  -d '{"image":"/var/lib/sanctum/evidence/case-001/source.dd",
       "undelete": true, "carve_signatures": true,
       "out_dir": "case-001", "case_id":"CASE-001", "operator":"examiner"}'
```

```json
{"job_id":"carve-43c34d2ca280","kind":"carve","state":"running",
 "stream_url":"/jobs/carve-43c34d2ca280/stream"}
```

`out_dir` is confined to `<state-dir>/recovered/` — deliberately *not* the evidence
directory, so a recovery can never write into the tree holding the image it is
reading. Omit `out_dir` entirely and nothing is written: you get the candidate list
only. Written filenames encode what produced them:
`000000001337_09000_carved-000000001337.jpg` is offset 1337, confidence 9000 basis
points.

`media_map` (on by default) runs first and draws the **media map** on the Recovery
screen: the image as one strip, each region coloured by the class most of its
4 KiB blocks fell into, with ticks where known file headers sit on sector
boundaries. The classes are *zeroed* (all 0x00), *fill pattern* (one byte
repeated: 0xFF from erased flash, 0xA5 from the free-space wipe), *text*,
*structured binary* and *high entropy* (compressed, encrypted or random; the bytes
alone do not say which). Hover a region for its offsets, class share, entropy and
headers. An image up to 64 MiB is read in full; a larger one is sampled evenly
within a 64 MiB budget, and the result says so. The map is ledgered as
`carve.mediamap` and summarised in the report's evidence section. An image of a
wiped medium maps as zero or fill throughout, which makes the map a quick
corroboration of a wipe; it is not a verification.

`undelete` walks filesystem metadata for deleted entries; `carve_signatures` runs
the signature and structure carvers over the image. The undelete pass also returns
the allocated/unallocated map, which is reported but deliberately does **not** bound
the carve — bounding it was measured and loses recall.

### PII triage: which recovered files hold identity or financial data

`pii_triage` (on by default; the *PII triage (counts only)* box on the Recovery
screen) counts six kinds of identifier in each recovered object, so an examiner
facing hundreds of files can open the ones holding personal data first. The
Recovery screen adds an **Identifiers** column (`Aadhaar 1 · PAN 1 · Card 1`,
`none seen`, or `not scanned`), a filter for *any identifier* or one kind, and a
*most identifiers first* sort. The report carries the same counts per object and a
`pii_triage` section with totals.

| Kind | What is matched |
|---|---|
| Aadhaar | 12 digits, first digit 2–9, optionally grouped 4-4-4 by one consistent space or hyphen, **Verhoeff checksum valid**. A bare 12-digit run is not counted. |
| PAN | `AAA?A9999A`, where the fourth letter is one of the holder types `ABCFGHLJPT`. |
| IFSC | four capitals, a literal `0`, six capitals or digits. |
| Mobile | ten digits starting 6–9, optionally prefixed `+91` or `0091` with one optional separator. |
| Card | 13–19 digits, optionally separated by single spaces or hyphens, **Luhn valid**. |
| Email | a local part of up to 64 characters, `@`, one to four DNS labels and an alphabetic TLD. |

Every kind needs a non-alphanumeric character, or the start or end of the data, on
both sides, so the middle of a longer run is never counted.

**No value is ever stored.** Not in the report, the ledger, the job result, the
logs or anywhere else: not the value, not the last four digits, not a hash of it
(a 12-digit Aadhaar is brute-forced from a hash in minutes), and not its offset
(an offset plus the recovered file gives the value back, and the report travels
further than the file). To see what was counted, open the recovered object. It
already holds the value. `tests/api/test_pii_no_leak.py` plants known values,
runs the whole pipeline, and fails if any of them appears in any other place the
product writes.

**A count is a signal to look, not a finding.** The detectors match a shape and,
for Aadhaar and cards, a checksum. One random 12-digit string in ten passes
Verhoeff, and one 16-digit string in ten passes Luhn. `Aadhaar 1` means "a
12-digit number with a valid Aadhaar check digit is in this file". It does not
mean "this file holds someone's Aadhaar number". `none seen` means none of these
shapes was found by the method named in the object's `basis`. It does not mean the
file holds no personal data.

What is scanned, and how:

* **Documents, databases and unclassified objects only.** DOCX/XLSX/PPTX (and
  macro variants) are scanned as the text of their XML parts with the tags removed.
  PDF is scanned as its decoded content streams, skipping image and font streams.
  Everything else in those categories, including `.txt`, `.csv`, SQLite and legacy
  `.doc`, is scanned as raw bytes.
* **Images, media, archives and executables are not scanned.** Their bytes produce
  false matches: on the camera JPEGs in the measurement below, one email-shaped or
  card-shaped hit per 4.6 MiB, all of them in compressed image data. On a photo
  collection, that would mark a large share of the photos.

Measured false-positive rates, raw bytes with no type gate, on data holding no
planted identifier. Figures are hits per MiB:

| Corpus | Size | Aadhaar | PAN | IFSC | Mobile | Card | Email |
|---|---:|---:|---:|---:|---:|---:|---:|
| Synthetic carving corpus (`generate_corpus`, seed 0) | 12.5 MiB | 0 | 0 | 0 | 0 | 0 | 0 |
| Filesystem corpus images (13 images, seed 0) | 414.0 MiB | 0 | 0 | 0.188 | 0 | 0 | 0 |
| Camera JPEGs, iPhone (7 files) | 13.9 MiB | 0 | 0 | 0 | 0 | 0.072 | 0.144 |
| HEIC, iPhone (6 files) | 7.8 MiB | 0 | 0 | 0 | 0 | 0 | 0 |
| Thumbnails and gain maps carved from those photos (19 objects) | 0.87 MiB | 0 | 0 | 0 | 0 | 0 | 0 |

A zero here means none were seen in that many bytes, not a rate of zero. The IFSC
hits are all FAT 8.3 directory names. `FILL0001PAD` has the IFSC shape, and so
would `DSCN0001JPG`. They are in filesystem metadata, which is not a recovered
object. With the type gate on the synthetic corpus, 6 of 33 candidates were
scanned and none produced a hit.

Turn triage off with `"pii_triage": false` if you do not want it. The run records
the setting in its `carve.start` ledger entry.

### Evidence score and confidence buckets: what each does and does not assert

The screen calls this number the **evidence score** and shows it as
`9500 / 10000`, never as a percentage. `confidence_bp` in the JSON report is the
same number under the name the signed schema has always used.

It is the sum of six measured components in basis points — `header`,
`exact_length`, `decoder`, `entropy`, `fs_metadata`, `no_overlap` — plus a seventh,
`reassembly`, which is 0 for every candidate except one rebuilt from separate runs
(see below). Clamped, never scaled. Those six come to **10,500** when every one is
established, so a candidate reading `10000 / 10000` is at the clamp; that is not a
measurement of certainty, and it is why the percent sign is gone. The buckets are
a reading of that number:

| Bucket | Score | What it asserts |
|---|---|---|
| **HIGH** | ≥ 8000 | Several independent components agreed: a header at the start, a length derived rather than guessed, and usually a decoder that consumed the object without error. |
| **MEDIUM** | 5000–7999 | Enough evidence to be worth an examiner's time, typically with one component missing — most often no decoder for the format (`validation: decoder_unavailable`). |
| **LOW** | < 5000 | A signature was found and little else agreed. Reported, never dropped. |

**A bucket asserts nothing about what the object is or who made it.** It does not
mean "this file is intact", it does not mean "this file was deleted by the suspect",
and it is not a probability. It is a reading of a measurement whose weights were
calibrated against a ground-truth corpus — see
[`performance/calibration.md`](performance/calibration.md) for the derivation and
the measured per-bucket precision and recall. The report prints
`score_components` per candidate so the number can be taken apart by someone who
was not there when it was computed.

**What the calibration does support is per-bucket precision on a named
population.** Pooled over eight seeds and 173 candidates, 104 of 104 HIGH
candidates matched a planted object byte for byte
([`performance/calibration-pooled.md`](performance/calibration-pooled.md)). Two
things follow, and the second matters as much as the first: that is a property
of those synthetic corpora, and on the 7 GiB validation image HIGH precision was
**86.6%** — 39 of 292 HIGH candidates matched no planted file — until the
footer-bound fix of 2026-09-21. Quote the bucket's precision with its
population, never a single candidate's score as a likelihood of correctness.

`confidence_bp` is also the name of a field on a post-erase
`VerificationResult`, and **there it genuinely is a probability**: the chance of
detecting a residual region of a given size under sampling, or 10000 for a full
read. The two numbers share a field name and nothing else.

A LOW candidate is not a false positive. A candidate whose `validation` reads
`corrupt` or `truncated` is telling you what the decoder found, and both are
findings.

### Candidates carrying `fragments`

Most candidates are one contiguous span: `fragments` is empty, and
`offset`..`offset + length` says where the bytes are. A candidate whose `fragments`
list is **non-empty is not a span**. It was reassembled from two runs with somebody
else's bytes in between:

```json
{"bucket":"MEDIUM","confidence_bp":7999,"ext":"jpg","offset":0,"length":77458,
 "fragments":[{"offset":0,"length":4096},{"offset":36864,"length":73362}],
 "sha256":"72dc6393d6a4b85e…","validation":"valid",
 "score_components":{"header":2000,"exact_length":1500,"decoder":4000,"entropy":1000,
                     "fs_metadata":0,"no_overlap":500,"reassembly":-1001}}
```

**A reassembled candidate is never HIGH.** Every byte it emits was checked — the
header, an exact count of the JPEG's entropy-coded data against its frame header, a
decode, the entropy — but *where the gap was* is an inference the medium cannot
confirm, and the check has a measured residual that no contiguous candidate has
(see [`limitations.md`](limitations.md)). The `reassembly` component holds the total
at 7999, one basis point under HIGH, whatever the others add up to, so the arithmetic
still reconciles and the reason is on the record. The bytes and the runs are the
same either way; only the claim about certainty differs.

`length` is the **sum of the runs**, `offset` is the first run's offset, and
`sha256` is the digest of **the runs concatenated** — not of `offset`..`offset +
length`, which would cover the gap as well and hash to something that was never a
file. Hash the span and you will not reproduce the digest; that is correct
behaviour, not a mismatch.

**Check it against the medium yourself.** Save this as `check_digests.py` in the
repository root and run it, with the venv's interpreter, against the report and the
image:

```python
"""Recompute every carved candidate's SHA-256 from the image itself."""
import hashlib, json, sys
from pathlib import Path
from core.carve.evidence import open_evidence
from core.carve.fragmentation import read_fragments
from core.models import CarveFragment

report = json.loads(Path(sys.argv[1]).read_text())
image = Path(sys.argv[2])
items = report["sections"]["recovery"]["items"]
handle = open_evidence(image)
bad = 0
for item in items:
    runs = [CarveFragment(**f) for f in item.get("fragments") or []]
    data = read_fragments(handle, runs) if runs else handle.read(item["offset"], item["length"])
    got = hashlib.sha256(data).hexdigest()
    if got != item["sha256"]:
        bad += 1
    print(f"{'OK  ' if got == item['sha256'] else 'BAD '}{item['offset']:>10} "
          f"{item['ext']:<7} {len(runs)} runs  {got[:16]}")
print(f"{len(items) - bad}/{len(items)} candidates match the image")
sys.exit(1 if bad else 0)
```

```
$ .venv/bin/python check_digests.py <state>/reports/<job_id>/CASE-001.forensic.json image.dd
OK           0 jpg     2 runs  72dc6393d6a4b85e
1/1 candidates match the image
```

It reads the runs back through the same read-only handle the carve used, so it
recomputes rather than trusts. The report's recovery section also carries
`reassembled_from_fragments`, a count of how many candidates in this run were built
this way.

**What it recovers, exactly.** One baseline JPEG in **exactly two runs**, both still
on the medium, whose gap is **at most 2 MiB (2,097,152 bytes)**, on a volume whose
cluster size the undelete pass read from its boot sector or superblock. Measured over
ten random layouts each at 64 KiB to 2 MiB: every one recovered byte for byte on
512-byte and on 4096-byte clusters. That is the claim, and it is deliberately narrow.

**What it refuses rather than guesses at:**

* **Anything but a baseline JPEG** — progressive, arithmetic-coded, lossless or
  multi-scan JPEG, and every other format — gets `possibly_fragmented: true` and no
  reconstruction attempt at all.
* **A layout the volume could not produce.** Runs are sought only on the volume's own
  cluster grid. When no filesystem is recognised the grid is the 512-byte sector,
  which every real layout lies on; the search is then slower and refuses sooner, and
  accepts nothing it would otherwise refuse.
* **A join the bytes do not settle.** If more than one join accounts for the object,
  or the search runs out of budget before showing that only one does, nothing is
  reassembled. Gap bytes that cannot be told apart from JPEG data — zeros, directory
  entries, text, another JPEG's scan — next to a run edge are what use the budget up:
  measured, up to 8 clusters of them recovered and 16 were refused.
* **A gap beyond 2 MiB is not a promise either way.** On 4096-byte clusters every
  layout measured recovered out to the 8 MiB search window; on 512-byte clusters
  7 of 10 did at 4 MiB and 3 of 10 at 8 MiB, the rest refused. None was fabricated.

Each refusal leaves the candidate the parser delineated, over a span that really is
on the medium, with a digest of exactly those bytes. General reassembly of arbitrary
fragmented files is an open research problem, and this tool does not claim it.

---

## 7. Reports and verification

This is the section that carries the tool's central claim, so it is the one to
read carefully.

### Generating

```bash
curl -s -X POST http://127.0.0.1:8787/reports/<job_id> \
  -H 'Content-Type: application/json' \
  -d '{"case_id":"CASE-001","operator":"examiner"}'
```

```json
{
    "job_id": "carve-43c34d2ca280",
    "json_path": "<state>/reports/<job_id>/CASE-001.forensic.json",
    "pdf_path":  "<state>/reports/<job_id>/CASE-001.forensic.pdf",
    "pubkey_fingerprint": "43:62:3F:92:1A:…:29:67",
    "sha256": "aabc749cd11bd67e7fea3dbacc37671b475211a8e1cf52e9e0033dafcd3d68b1",
    "bytes": 20150
}
```

**The JSON is authoritative; the PDF is not.** The signature covers the canonical
JSON bytes. The PDF is a rendering for a human and says so on itself. Generating a
report is itself a ledger event (`report.generated`), which is how verification
later finds the right file for a job instead of guessing at filenames.

**A report is generated only for a job that has finished.** Asking for one while
the job is `pending` or `running` is refused with HTTP 409 `JobNotFinished`, and
nothing is written. Asking for one for a job this API process has no record of —
the id is wrong, or the API was restarted since the job ran — is refused with
HTTP 404 `JobNotKnown`; the message says whether the chain holds entries for that
job and names the last one, because a report is built from the job's result and
that result lived in the process that ran it.

A job that ended `failed` or `cancelled` does get a report. Its
`case_identity.job_state` says which, and its first limitation begins
`JOB FAILED` or `JOB CANCELLED` and explains that an empty section means the job
did not get that far. A report for a finished job carries `"job_state": "complete"`.

Generating a report while another job is still writing to the chain is safe: every
ledger writer waits its turn for the chain's writer lock, so neither append is
lost.

### Verifying on this host

`GET /reports/<job_id>/verify` resolves the report through the ledger and runs the
five checks. Beyond the five it reports one more field:

* **`ledger_digest_matches`** — whether the file on disk is still the bytes the
  chain recorded when the report was generated. It is reported alongside the checks
  rather than folded into them: a digest mismatch and a broken signature are the
  same event seen twice, and an examiner reading one wants to see the other.

### The five checks

| Check | What a PASS means | When it is SKIP |
|---|---|---|
| **`signature`** | The detached Ed25519 signature is valid for **these exact bytes** under the public key embedded in the report. A FAIL means the report was altered after signing, or signed by a different key. | never |
| **`fingerprint_matches_genesis`** | That public key's fingerprint is the one recorded in the ledger's **genesis** entry, so the report was signed by the key the chain was started with. | when there is no genesis entry in the excerpt, no reachable ledger store, a missing or unparsable genesis blob, or the chain was started before any key existed — and the result names **which** of those it is |
| **`chain_integrity`** | The ledger excerpt carried **inside** the report hashes and links correctly on its own terms. An excerpt is a filtered view of one job's entries, so gaps are expected: the status is `VERIFIED_COMPLETE`, `VERIFIED_PARTIAL` (gaps named and cross-checked against the gaps the report declares), or `BROKEN`. | never |
| **`chain_store`** | The **whole** chain re-verified from the store on disk, independently of the excerpt and of the `chain_status` the report prints. | when no ledger store was given, or it is unreachable or unreadable |
| **`blobs_available`** | Every params and result blob the excerpt references is present in the store. | when no blob store is reachable |

**An inapplicable check is not a passing one.** A report verified on a host with no
ledger cannot have its chain checked, and the output prints `SKIP`, not `PASS`.
`Result: PASS` means every *applicable* check passed — read the lines, not only the
last one.

The next line, `Verdict:`, grades the whole result in one of four words, and prints
the reason for every downgrade underneath it:

| Verdict | Meaning |
|---|---|
| `FAILED_VERIFICATION` | an applicable check failed |
| `PARTIAL` | every check that ran passed, but at least one could not run (`SKIP`) |
| `VERIFIED_WITH_LIMITATIONS` | all five ran and passed, and the report declares limitations, residual risk above low, a verification it records as not passed, or an excerpt with declared gaps |
| `VERIFIED` | all five ran and passed, and the report declares none of those |

The exit code still follows `Result:`, not the verdict. The identity caveat applies
to every report and is not a downgrade.

### The command a third party runs, on their own machine, without your help

They need the report file and — to get all five checks — a copy of the ledger
directory. They do not need your API, your helper, or your cooperation while they
run it. This is the exact command, run here against the copy shipped in this
repository:

```bash
# `sanctum` is a console script installed into the venv; with the venv activated
# the bare name works, and .venv/bin/sanctum always does.
.venv/bin/sanctum verify-report docs/demo/fallback/demo-erase.forensic.json \
        --ledger-root docs/demo/fallback/demo-ledger
```

```
Report: docs/demo/fallback/demo-erase.forensic.json
Signed by fingerprint: 69:45:A0:97:57:16:4D:A0:63:36:61:BF:B5:18:BD:4D:38:70:F5:3F:29:F6:9C:45:69:7A:75:FD:37:25:50:F5

[PASS] signature: valid Ed25519 signature by 69:45:A0:97:…:50:F5
[PASS] fingerprint_matches_genesis: signing key 69:45:A0:97:…:50:F5 is the key recorded in the ledger genesis
[PASS] chain_integrity: all 37 excerpt entries link and hash correctly (0..36)
[PASS] chain_store: the ledger store verifies independently: All 67 entries verify, 0..66.
[PASS] blobs_available: every blob referenced by 37 entries is present

Result: PASS
Verdict: VERIFIED_WITH_LIMITATIONS
  - the report declares a limitation: The overwrite pattern was changed from this method's default because …
  - the report declares a limitation: /dev/sda is behind a usb bridge, where ATA pass-through is not dependable; …
  - the report records residual risk high (4 factors in section residual_risk)

Note: An embedded public key proves internal consistency only. It does not prove
identity: a third party must compare the fingerprint above against a value published
out-of-band before treating this signature as evidence of who produced the report.
```

`sanctum` exits **0** only when every applicable check passed, **1** when one
failed, and **2** when the file is missing or is not valid JSON — so it drops
straight into a script. Without `--ledger-root` the signature and excerpt checks
still run and the other three report `SKIP`.

Altering one byte anywhere inside the signed body produces exactly one changed
line, and the other four still pass:

```
[FAIL] signature: signature does not match the report contents; the report was
       altered after signing, or signed by a different key
…
Result: FAIL
Verdict: FAILED_VERIFICATION
  - signature failed: signature does not match the report contents; …
```

### The caveat that travels with every result

> An embedded public key proves internal consistency only. It does not prove
> identity: a third party must compare the fingerprint above against a value
> published out-of-band before treating this signature as evidence of who produced
> the report.

Anyone can generate a key, sign a fabricated report, embed their own public key,
and pass all five checks. The fingerprint must be compared against a value
published somewhere the report cannot reach — an organisation's key listing, a
printed card, a prior communication — before the signature says anything about
*who*. Until then it says only that these bytes have not changed since they were
signed.

---

## 8. Reading the ledger

Every operation appends an entry to a hash-chained, append-only log.

```bash
curl -s http://127.0.0.1:8787/ledger/verify | python3 -m json.tool
```

```json
{
    "status": "VALID",
    "entry_count": 4,
    "explanation": "All 4 entries verify, 0..3.",
    "first_broken_seq": null,
    "root": "/var/lib/sanctum/ledger",
    "entries": [ … newest first … ]
}
```

`GET /ledger/entries?limit=N` lists entries without re-verifying; the **Audit**
screen shows the same thing.

An entry carries a sequence number, a UTC timestamp, a monotonic clock reading and
a boot id (so a clock that moved cannot silently reorder history), the actor, the
operation name, the SHA-256 of its parameters and of its result, **the SHA-256 of
the previous entry**, and its own hash. Parameters and results themselves live in a
content-addressed blob store beside the chain, `0600`, because operation parameters
are case material.

Entry 0 is `GENESIS`. Operation names are readable and specific:
`erase.preflight.*`, `erase.erase.checkpoint`, `erase.erase.cancelled`,
`erase.verify.*`, `erase.file.*` for M2's eleven steps, `acquire.start`,
`erase.file.cancelled`, `acquire.checkpoint`, `acquire.complete`,
`acquire.cancelled`, `carve.start`, `carve.complete`, `carve.cancelled`, and
`report.generated`.

### What the chain proves, and what it does not

**It proves entries were not altered after the fact.** Because entry *N* contains
the hash of entry *N-1*, insertion, deletion and mutation are all detectable, and
`verify()` names the first broken sequence number rather than returning a bare
"invalid". You do not have to trust the tool's own verdict: `sanctum verify-report
--ledger-root` recomputes it, and so can anything else that can hash.

**It does not prove the operator did not choose what to record.** The operator runs
the tool. The chain has two writers by design — the API appends carve, file-erase
and `report.generated` entries as the operator; the root helper appends the six
phases of a drive erase and its checkpoints — and the helper hands each file it
creates to the operator uid it was started with, so the unprivileged half can read
the chain back and build a report. That handover changes an owner, never a mode
(files stay `0600`) and never a hash. Tamper-*evidence* comes from the links, not
from file permissions, and no file mode this tool could set would make the chain
evidence of custody rather than evidence of sequence.

Two further honest limits: the helper does not ledger every call it is *asked* for
— a bare `enumerate_devices` leaves no entry — so the chain evidences what was
**done**, not everything that was **requested**. And the `report.generated` entry
is appended after the report's own excerpt is built, so a report never contains the
entry that names it; the chain that resolves a report is the *live* chain, which is
exactly what the `chain_store` check verifies independently.

---

## 9. When something refuses

A refusal is a designed output. Every one carries a remediation written by whoever
implemented the guard, and the API passes that sentence through verbatim. Search
this section for the text you were shown.

### Device and erase

**`{device} ({model}) holds the running system (root, /boot or active swap). Refusing to erase it.`** — HTTP 409, `SystemDiskRefused`
The target hosts the running root filesystem. The guard is inside the erase path,
not in the UI, so nothing can route around it.
*Do:* Boot from separate media and run the erase against the drive as a non-system disk.

**`{device} has mounted filesystems: {mounts}. Refusing to erase it.`** — HTTP 409, `MountedRefused`
Writing under a live filesystem corrupts the page cache's view of a device the
kernel still believes it owns.
*Do:* Unmount every filesystem on the device and retry.

**`Refusing to erase {path}: no serial was typed. Destructive erasure is opt-in twice: an approved authorization and the typed serial.`** — HTTP 409, `ConfirmationMismatch`
The serial is missing. *Do:* Re-read the device serial from the capability report and
type it exactly.

**`dry_run is not accepted: there is no simulation or dry-run mode. Every destructive request runs against the real device. Remove the field.`** — HTTP 422
The client sent a switch from an older build (`dry_run`, `simulation` or
`simulate`). It is refused rather than honoured or ignored, because the sender
expected nothing to be written. The helper refuses the same keys at its write
seam (`WorkflowGateRefused`). *Do:* Remove the field; send the request only
when the operation is meant to run on the real device.

**`The typed serial {typed!r} does not match {path}, whose serial is {serial!r}. Nothing was erased.`** — HTTP 409, `ConfirmationMismatch`
Also seen as `Typed value does not match the serial of {device}.` from inside the
helper, which re-reads the serial itself.
*Do:* Re-read the device serial from the capability report and type it exactly.
Nothing has been modified.

**`{device} reports no serial, and the typed value does not match its stable identifier.`** — HTTP 409, `ConfirmationMismatch`
*Do:* This device exposes no serial. Confirm it by typing its full
`/dev/disk/by-id` path from the capability report instead.

**`Refusing to erase: confirm was not set. Destructive file erasure needs an explicit confirmation. Nothing was touched.`** — HTTP 409, `ConfirmationMismatch`
The M2 equivalent. *Do:* Review the selected paths, then send `confirm=true` to
erase them.

**`Refusing to erase {path}: it is a filesystem root.`** / **`… it is a protected system location, and erasing it would break the running system.`** — `SystemDiskRefused`
*Do:* Name the files or folders, not the root.

**`{device} supports an enhanced security erase, but ATA security is frozen so it cannot be issued. Refusing to fall back to a Clear-level overwrite, which would not be the Purge you asked for.`** — HTTP 409, `DeviceFrozen`
Also `{device} has ATA security frozen; SECURITY SET PASSWORD cannot be issued.`
The BIOS or firmware froze ATA security at boot. The tool refuses to quietly give
you a weaker level than you asked for.
*Do:* Issue an S3 sleep/wake cycle or power-cycle the drive to clear the frozen
state, then re-probe capabilities.

**`{level} is not achievable on this device. {reason}`** — HTTP 422, `UnsupportedCapability`
The probe found no mechanism for that level. The reason names what was observed —
often the USB-bridge sentence from §4.
*Do:* Choose one of the reachable levels, which the remediation lists. If your
policy requires a level this media cannot reach, the remaining outcome is Destroy
(physical destruction, recorded with *Record a physical destruction*). Destroy is a
different outcome from Clear and Purge, not a way of reaching either.

**`{method} cannot be requested directly; firmware methods are selected from probed capability only.`** — HTTP 422, `UnsupportedCapability`
*Do:* Ask for a sanitization level and let capability probing choose the mechanism.

**`{device} is an Opal drive; a PSID revert needs the PSID printed on the physical drive label.`** — HTTP 422, `UnsupportedCapability`
This build has no way to accept a PSID (§4).
*Do:* Use ATA or NVMe SANITIZE if the drive reports one; otherwise a single-pass
overwrite achieves Clear, not Purge. If policy requires more than Clear on this
drive, the remaining outcome is Destroy, which is physical destruction and not a
Purge; the tool records it as an attestation and performs nothing.

**`hdparm could not read {device}: permission denied.`** / **`nvme id-ctrl could not read {device}: permission denied.`** — HTTP 422, `UnsupportedCapability`
Capability probing needs raw device access and did not have it. **This is not a
statement that the device lacks the feature.**
*Do:* Run the privileged helper as root and retry — see §3 — and do not treat this
as an unsupported device. On Windows the equivalent state is **REQUIRES
PRIVILEGE**: restart Sanctum with *Run as administrator*.

**`No block device matches {path!r}.`** / **`No device identifier was supplied.`** — HTTP 410, `DeviceVanished`
*Do:* Re-enumerate devices and confirm the target is still connected before retry.

**`The erase geometry for {device} is N bytes, smaller than the M bytes the kernel reports. Refusing to erase part of a device and call it done.`** — `GeometryRefused`
A hidden-area probe produced a size smaller than the kernel's.
*Do:* Re-run enumeration and HPA/DCO detection. If the hidden-area probe cannot
produce a trustworthy native max, erase using the kernel-reported size and record
that hidden sectors were not covered.

**`the overwrite planned N byte(s) … but accounts for only M: X written and Y recorded unwritable. Z byte(s) are unaccounted for and the medium is not erased.`** — `OverwriteIncomplete`
Every planned byte must end up either written or named in `unwritable`. A byte that
is neither is a hole, and a run that reported success over a hole is the one result
this tool must never produce.
*Do:* **Do not treat the medium as sanitized.** Re-run the erase; if it stops at the
same offset again, the device is failing writes without reporting an error and
should be physically destroyed rather than reused.

**`PlatformUnsupported`** — HTTP 501
The platform offers no path for this operation on this target. Windows and
macOS now have a whole-drive clear engine, so for those the message and its
remediation come from the adapter: on Windows *"Run Sanctum as Administrator.
Take the disk offline first ..."*, on macOS *"External disks: unmount every
volume (Devices > Prepare, or diskutil unmountDisk) and start Sanctum with
sudo. Internal Mac storage: use ... Erase All Content and Settings"*. The
generic remediation *"Open the Platform screen: it names, per capability, the
platforms and device classes where this runs ..."* is only the fallback for a
code path that supplies none.
*Do:* Follow the remediation shown. File and folder erasure remains available
on every platform.

### Evidence, paths and the helper

**`evidence not found: {path}`** / **`acquisition source not found: {path}`** — HTTP 422, `EvidenceIntegrityError`
*Do:* Check the path; nothing was opened.

**`Refusing to write out_dir={value!r}: it resolves to {target}, which is outside the configured output directory {base}. Nothing was created.`** — HTTP 400, `OutputPathRefused`
Same message with `dest=` for acquisitions. Symlinks are resolved *before* the
comparison, so a link planted inside the directory cannot point the write out of it.
*Do:* Pass a path inside the named directory, or a relative path — it is taken as
relative to that directory. Set `SANCTUM_STATE_DIR` to move it.

**`{field}={value!r} resolves to {path}, which is outside the helper's state directory {base}. The helper runs as root and will not write outside the directory it was started with.`**
The same rule inside the root helper, applied to `ledger_root` and `dest` before any
handler runs. It arrives as an ordinary error frame; the daemon keeps serving.
*Do:* Use paths under the `--state-dir` the helper was started with, and give the API
the same value in `SANCTUM_STATE_DIR`.

**`The privileged helper could not be reached: {error}`** — HTTP 501
*Do:* Start the helper daemon and set `SANCTUM_HELPER_SOCKET` — §3.

**`The helper must run as root: it exists to be the one process that holds raw device access.`** — exit code 2
Printed with the exact `sudo` line to run.

**`python -m helper: error: the following arguments are required: --state-dir`** — exit code 2
*Do:* Add `--state-dir`; see §3.

**`--state-dir {path} does not exist. Create it before starting the helper …`** — exit code 2
*Do:* `sudo mkdir -p <path>` and start again.

**`peer uid N is neither root nor the operator uid M`**
Something other than the account named by `--operator-uid` connected. The peer is
dropped before a byte of its request is read.
*Do:* Run the API as that account, or restart the helper with the right uid.

**`the helper sent no frame for 120s during {method}; it is not slow, it has stopped speaking. Whatever it was doing to the device may still be running: check the helper log and the ledger before doing anything else.`** — `TimeoutError`
The deadline is on **silence**, not on completion — an operation may legitimately
run for hours, and both progress and heartbeat frames reset it. This fires only when
nothing at all arrives.
*Do:* Exactly what it says. Read Terminal 0's log and the ledger before touching the
device.

### Reports, keys and the chain

**`No report has been generated for job {job_id!r}. The chain at {root} carries no report.generated entry for it, so there is nothing to verify.`** — HTTP 404, `ReportNotFound`
*Do:* Generate one first: `POST /reports/{job_id}`. Reports are resolved through the
ledger, never by guessing at filenames — a report for a different job is not an
answer to this question.

**`The chain records a report for job {job_id!r} at {path}, but that file is not there.`** — HTTP 404, `ReportNotFound`
*Do:* The report was moved or deleted after it was generated. Restore it, or
generate a new one.

**`No passphrase available for {path} (SANCTUM_KEY_PASSPHRASE is unset and no interactive prompt was possible); refusing to write or read an unprotected signing key.`** — HTTP 503, `KeyPassphraseMissing`
*Do:* Set `SANCTUM_KEY_PASSPHRASE` in the environment, or run interactively so the
passphrase can be prompted for. There is deliberately no default.

**`{path} has mode {mode}; a signing key must be 0600 so only its owner can read it.`** — HTTP 503, `KeyPermissionsUnsafe`
*Do:* Restore owner-only access with `chmod 0600 <keyfile>` and confirm no copy was
made while it was exposed. Rotate the key if in doubt.

**`Job {id} is {state}, not finished. A report built now would be signed over a result that does not exist yet: …`** — HTTP 409, `JobNotFinished`
*Do:* Wait until `GET /jobs/<id>` reports `complete`, `failed` or `cancelled`, then
generate the report. Nothing was written.

**`No job {id} is known to this process, and the chain at {root} holds no entries for it.`** — HTTP 404, `JobNotKnown`
*Do:* Check the id — it is the `job_id` a `POST /jobs/*` call returned.

**`Job {id} is not known to this process - the API was restarted since it ran, or it ran in another process - but the chain holds N entries for it, the last being {operation} at seq {seq}. …`** — HTTP 404, `JobNotKnown`
The job's result, which a report is built from, did not survive the restart. Its
chain entries did.
*Do:* Read the entries with `GET /ledger/verify`. To get a report, run the job again
and generate the report from the process that ran it.

**`Ledger entry {operation} was NOT recorded: the writer lock {path} was held by another writer through 20 attempts over {seconds} s. …`** — `LedgerBusy`; HTTP 503 when it comes from report generation
Every ledger writer takes the chain's lock for one append, which lasts well under a
second, and retries for about 13 seconds before giving up. Reaching this means
something held the lock far longer than an append does. When it comes from a job,
the job is `failed` with this message; when it comes from report generation, the
message adds that the report files were written but are not recorded in the chain.
*Do:* Look for a hung Sanctum process (API, helper or harness script) using the same
state directory, stop it, and retry. Do not delete the lock file while a writer may
still be running. Regenerate a report whose entry was not recorded.

**`The ledger at {root} could not be read: {error}`** — HTTP 500, `LedgerChainBroken`
*Do:* Check that the ledger root exists and is readable. If the chain itself is
broken rather than unreadable: treat the ledger as compromised, preserve the raw
store, and investigate from the last verified entry.

**`signature does not match the report contents; the report was altered after signing, or signed by a different key`**
*Do:* Confirm the correct public key and that the payload was not modified after
signing.

---

## 10. Cancelling, and what a cancelled operation leaves

Cancel is on every running job's panel, and `POST /jobs/<id>/cancel`. It is
**cooperative, never a kill**: the job stops at its next yield point, so a wipe is
never interrupted between a seek and a write. A client that simply disappears is
treated identically to one that cancelled.

### A cancelled wipe leaves a partially sanitized device, and the ledger says so

The `erase.erase.cancelled` entry is written during teardown, before the
cancellation is allowed to continue, and reads:

> Erase cancelled before completion. The device is **PARTIALLY SANITIZED**: data up
> to the last recorded checkpoint was overwritten and the remainder was not. No
> verification ran, so no sanitization level was achieved and no certificate is
> issued for this job.

It carries `resumable: true` when the method was a host-pattern overwrite, which can
be resumed from the last checkpoint. No progress is yielded — a generator cannot
yield while closing — so the ledger is the only channel out, and it is the right one:
a cancelled wipe that left no record would be indistinguishable from one that never
ran.

**For a firmware method, cancelling stops the tool watching, not the drive.** The
entry adds:

> This method runs inside the drive's own firmware: cancelling stopped this tool from
> watching it, and does not stop the drive. **Re-probe the device before drawing any
> conclusion about it.**

Say that twice, because it is the one that gets people: an ATA or NVMe SANITIZE runs
inside the device. Pressing Cancel ends this program's involvement. **The drive keeps
erasing.** Do not unplug it, do not assume its contents, and re-probe before you say
anything about it.

### A cancelled acquisition leaves a partial image with no published digest

`acquire.cancelled` records the destination, `bytes_acquired`, `bytes_expected`, the
container size on disk, and:

> Acquisition cancelled before completion. The file at this destination is a
> **PARTIAL IMAGE**: it holds the first N of M source bytes and is NOT a complete copy
> of the source. **No sha256 or blake3 is recorded for it** — the digests an
> acquisition publishes cover the whole source as it was read, and this read did not
> finish, so any hash of this file attests to the fragment only. **Do not carve it and
> report the results as coverage of the source.** Re-acquire, or resume from the last
> `acquire.checkpoint` entry for this job.

The entry exists because a truncated `.dd` looks exactly like a complete one. Nothing
was destroyed; the record is about what the artifact *is*.

### Cancelling a carve or a file erase

Both stop at their next yield, the job state becomes `cancelled`, and each writes a
cancellation entry in place of its terminal one.

`carve.cancelled` names the image, the stage the carve had reached, how many bytes
the signature scan covered, and every recovered object already written to `out_dir`.
It records **no** `findings_sha256`: that digest attests to a finished candidate list,
and a cancelled carve has none. Do not report a partial carve's output as coverage of
the image.

`erase.file.cancelled` names every target once: `processed` (with the phases each
file reached), `not_processed` (untouched), or — when the batch was running in a
process pool — `in_flight_unknown`, meaning the pool's workers were stopped while
those files were queued and their state must be checked on disk. It records no batch
verdict; a cancelled file erase is not an erasure certificate.

**Neither a cancellation nor a `failed` job is a crash.** Both are recorded states.
Read `GET /jobs/<id>` for `state`, `error` and `remediation` before concluding
anything.

---

## 10a. Cases, artifacts, resume, and the tamper demonstration

These were added on 2026-09-21. Each is covered by its own test file, named in
brackets.

**Cases** (`tests/api/test_cases.py`). Open one on the **Cases** screen before
doing evidence work. The sidebar shows the open case on every screen, and every
recovery, acquisition and drive erase started while it is open is filed against
it; a report generated later inherits its id. The open case is the first thing
on the screen: its id and title, the case status and the chain verdict, then
tabs that carry their counts. *Overview* shows the integrity verdict and one
figure each for evidence, operations, reports and audit entries (click a figure
to open its tab). *Operations* names each job in words over the id the Audit
screen asks for, with its job state in the registry's own word (COMPLETE,
FAILED, CANCELLED, RUNNING) except in two cases: **BLOCKED** is a safety refusal
at the helper's write seam, before any write (the registry says failed; the
screen reads the job's structured `error_kind`, never its message), and **VERIFY
FAILED** is a drive erase that ran but whose read-back failed (the registry says
complete). A record an earlier build filed as a rehearsal is marked
**HISTORICAL · NOTHING WRITTEN** and never counted as an erasure; this build
creates none. It also shows whether a signed report exists. A case that cannot be read shows **REQUEST FAILED**, never an
empty case and never BLOCKED. The Overview's *Secure erasure* column says the
same four things apart: blocked (nothing was erased), failed (the target may be
partly overwritten), stopped on request (CANCELLED), and a read-back that
FAILED. *Reports* has Open/Download links and marks each SIGNED
or UNSIGNED; *Audit* lists the chain entries that name the case. **The
integrity verdict on that screen is the ledger's**; the case file itself is an
index and proves nothing. `POST /cases`, `GET /cases`, `GET /cases/{id}`,
`POST /cases/{id}/evidence`.

**Operator identity** (`tests/api/test_operator_identity.py`). The actor in the
ledger is the operating-system account the helper was started for, shown as
`alice (uid 1000)`. What you type in an operator box is kept as
`[label: …]` beside it. You cannot change the actor from the browser.

**Recovered artifacts** (`tests/api/test_artifacts.py`). Run a scan with an
output directory and the Recovery screen shows a gallery of the files actually
written, with thumbnails for raster images, and for each: type, size,
confidence, structure verdict, fragment count and identifier count (never a
value). Recovered PDFs and every other non-image download; they are never
opened in the browser. `GET /artifacts/recovered`,
`GET /artifacts/recovered/{name}`, `GET /artifacts/reports/{name}`.

**Reassembly explainer.** Selecting a reconstructed JPEG shows both runs, the
gap between them to scale, the structure verdict, the MCU-accounting component
and the scope statement: baseline JPEG, exactly two runs.

**Reports survive a restart** (`tests/api/test_report_job_state.py`). A finished
job's result is written to the ledger, so a report can be generated and verified
after the API restarts. The Audit screen offers Open PDF, Download PDF, View
JSON and Verify; no host path is shown.

**Tamper demonstration** (`tests/api/test_tamper_demo.py`). On the Audit screen,
**Tamper a scratch copy** copies the chain to a scratch directory, changes one
entry's `actor` in the copy, and runs the real verifier on it. You see BEFORE:
VALID, AFTER: BROKEN at the exact sequence, and how much of the chain still
verifies. The live chain is not opened for writing, and the screen re-reads it
afterwards so you can see it is still VALID.

**Resume** (`tests/api/test_resume.py`). After an overwrite is cancelled or
fails, the Sanitize screen reads the chain for a checkpoint. If there is one it
offers *Authorize resume on the real device*: a resume writes, so it goes
through the same approval dialog as an erase (backup, approval with the typed
serial, a new one-use authorization) and the server refuses it without one. A firmware sanitize shows **RESUME NOT AVAILABLE** with the reason:
the drive reports no progress, so there is no offset to continue from.

**Verification panel.** After a run the Sanitize screen shows one of four
words: PASSED, FAILED, INCONCLUSIVE, NOT APPLICABLE. No recorded verification is
NOT APPLICABLE. An unsettled read-back is INCONCLUSIVE, never PASSED.

**Demo state** (`tests/scripts/test_demo_workflow.py`).
`SANCTUM_KEY_PASSPHRASE=… python scripts/demo_setup.py --state-dir ~/sanctum-demo`
stages a separate state directory with a key, a demo case, a synthetic evidence
image containing a bifragmented JPEG, and a directory of throwaway files for the
File eraser. It refuses a non-empty directory and never touches a device. Start
the API with `SANCTUM_STATE_DIR=~/sanctum-demo`.

## 10b. The desktop app, and what each platform can do

**Installing.** Linux: run the AppImage, or `sudo apt install ./sanctum_<ver>_amd64.deb`.
Windows: run `SanctumSetup.exe` (no administrator needed to install; whole-drive
and raw device work needs Sanctum started with *Run as administrator*). macOS:
open `Sanctum.dmg` and drag Sanctum to Applications. None of them needs Python or
Node on the machine. Details, including signing status: `docs/packaging.md`.

**Opening.** The app starts its own server on a private loopback port and
opens a window. Only that window can talk to it. Press *Quit Sanctum* in the
sidebar to stop it.

**The Platform screen** answers "what can this computer do?". It leads with the
resolver matrix: every capability with its state (§1: SUPPORTED, IMPLEMENTED /
UNVALIDATED, DEVICE-DEPENDENT, REQUIRES PRIVILEGE, PLATFORM-LIMITED, BLOCKED
FOR SAFETY, NOT IMPLEMENTED), its reason and its mechanism, with SUPPORTED
scoped to the device classes a physical run is recorded for. The older status
words (*Supported*, *Needs privilege*, *Unverified*, *Unsupported*, ...) are
still explained under *How to read the older status words*, for payloads that
carry no state. IMPLEMENTED / UNVALIDATED and *Unverified* both mean the code
exists and nothing on record says it works on real hardware of that kind;
treat them as not yet proven. The screen also names this build's
commit, says how many storage devices it detects now (detecting is not
supporting), explains every status word under *How to read a status*, and lists
the safety restrictions and what is *Not yet proven on hardware*. A status says
what this build can do here; it is not a record that anything was run on the
storage attached now.

**The status strip** at the bottom of every screen shows the platform, your
privilege, the selected device, whether it can be sanitized, whether the
result can be verified, and the state of the audit chain.

**Sanitizing a device** follows eight steps, shown across the top of the
screen: choose the target, the app analyses it, you see the recommended
method, review the warning, confirm by typing the serial, it sanitizes, it
verifies, you get the certificate. A flow that stops stays on the step where
it stopped, marked *stopped*: a refusal never reaches Verify, and a run whose
read-back FAILED stops on Verify and never reaches Certificate - its signed
record is not a certificate. Only a read-back that passed moves past Verify. The
first panel answers three questions in plain words - which device, what will
happen, can it be verified - and lists the safety checks. The engine's evidence
is under *Technical details*.

On the Devices screen a drive that reports a firmware sanitize reads **PURGE ·
UNVERIFIED** (or **SED · OPAL · UNVERIFIED**), not a green PURGE AVAILABLE: no
firmware sanitize has been recorded on a physical drive. The Purge option on
the Sanitize screen reads *Unverified* for the same reason. It is still offered;
it is never presented as a hardware-validated result.

**"Sanitization not available"** is a result, not an error. It names the
reason (for example: this is the system disk; a volume is in use; this is
internal Apple storage; this process is not elevated) and what to do instead,
and it says that nothing was done to the device. On Windows and macOS an
external or secondary disk can now be cleared once the process is elevated and
the disk is prepared (§4, *On Windows and macOS*); that path reads IMPLEMENTED /
UNVALIDATED, because it has never been run on a physical disk.

**Getting the certificate.** After a run, press *Get certificate*. The first
time, the app asks for a passphrase for the signing key (12 characters or
more); keep it, because every later certificate from this installation is
signed with the same key.

## 11. Limitations

[`limitations.md`](limitations.md) is the complete list, and it is not duplicated
here. The entries an operator hits most often:

* **The ATA security-erase password is fixed and published.** If the process dies
  between `SECURITY SET PASSWORD` and `SECURITY ERASE UNIT`, the drive stays locked;
  the password is written to the ledger *before* it is set so the recovery value
  survives the crash, and the document gives the `hdparm` line to clear it.
* **Overwrite cannot reach remapped or over-provisioned blocks on flash.** Where the
  device cannot Purge, the report says Clear and says why.
* **Some controllers do not program a zero fill at all** — §4's calibration.
* **Verification above 64 GiB is sampled**, with the detection probability and the
  seed in the report rather than a bare percentage.
* **A software write block is a claim about a flag, not about a refusal** — §6.
  On Windows and macOS there is no software write block at all.
* **Implemented is not validated.** Windows and macOS whole-drive clear, raw
  acquisition, Windows device sanitize, the HPA/DCO workflow and restore have
  run against synthetic media and adapter doubles only — §1.
* **An ordinary erase does not reach an HPA** — it reports the hidden bytes;
  the separate HPA/DCO workflow (§4) exposes them, and a DCO is never modified.
* **Undelete recovers a different amount on every filesystem**, and **ext4 recovers
  essentially nothing by design**, because `ext4_ext_remove_space` zeroes the extent
  tree on unlink. That is measured, not assumed. FAT recovery is a *reconstruction*
  however clean it looks; exFAT is the one case where the filesystem records the
  answer.
* **Per-file erasure is usually unverifiable**, and is reported as unverifiable
  rather than as a pass — §5.
* **A PII count is a signal to look, not a finding.** Triage counts identifier
  shapes in documents, databases and unclassified objects only. It never stores a
  value, and `none seen` does not mean a file holds no personal data — §6.
* **Destroy is not achievable in software** and this tool will not claim it.
* **The local API has no authentication.** Path confinements bound what an
  unauthenticated local caller can write; they do not stop one from asking. Run it
  on a workstation you control, on loopback, as the design intends —
  [`privilege-boundary.md`](privilege-boundary.md) records this as the largest open
  item.

A guarantee this tool cannot make is printed as a limitation, in the report as well
as in that document. If a result looks stronger than you expected, read the
limitations attached to it before you rely on it.

---

**See also**
[`architecture.md`](architecture.md) (layer map and invariants) ·
[`privilege-boundary.md`](privilege-boundary.md) (threat model around the root
process) · [`compliance.md`](compliance.md) (NIST SP 800-88r2 and Indian
instruments: what the tool does, what it does not, and what is unverified) ·
[`technical.md`](technical.md) (build environment) ·
[`validation/hardware.md`](validation/hardware.md) (real-media runs and the defects
they found) · [`demo/runbook.md`](demo/runbook.md) (the six-minute demonstration
script).
