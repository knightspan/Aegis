# Architecture

One rule shapes the whole layout: **a layer may only make claims it can evidence.**
Everything below follows from it — why carving cannot open a device for writing, why
one process holds root and the rest hold none, why every operation ends in a ledger
entry before it is considered done.

## Layers

| Layer | Package | Privilege | Network | Notes |
|-------|---------|-----------|---------|-------|
| Models | `core.models` | none | no | Pydantic v2 data contracts, shared everywhere. |
| Errors | `core.errors` | none | no | Every error carries a `remediation`. |
| Platform | `core.platform` | none | no | One adapter per OS (`linux.py`, `windows.py`, `macos.py`) and the capability resolver (`capability.py`), the one place that decides a capability state. |
| Device | `core.device` | via helper | no | Enumerate, probe capability, detect HPA/DCO, safety guard; the Windows native layer (`core.device.win`) and macOS raw-disk layer (`core.device.mac`); the guarded HPA/DCO workflow (`hidden_area_workflow.py`). |
| Erase | `core.erase` | via helper | no | Whole-drive (M1: `drive.py` on Linux, `blockclear.py` on Windows/macOS, `devicesanitize.py` for firmware commands on Windows) and file/folder (M2). Destructive: every call executes; the read-only plan is `drive.preview`. |
| Carve | `core.carve` | via helper (read-only) | no | Acquire (`acquire.py`; `win_source.py` and `mac_source.py` for raw Windows/macOS sources), undelete, signature, structure, validate, score, classify. |
| Backup / restore | `core.backup`, `core.restore` | via helper (restore writes) | no | Backup identity records and read-only verification; authorized restore with post-restore read-back. |
| Benchmark | `core.benchmark` | none | no | Sealed ground-truth manifests and scored results; SYNTHETIC and PHYSICAL never merged. |
| Ledger | `core.ledger` | none | no | Hash-chained append-only audit log. Entry N embeds SHA-256 of N-1. |
| Report | `core.report` | none | no | Render + detached-sign + independent verify. `semantics.py` names the category of what was done. States honest limits. |
| Helper | `helper` | root (Linux socket daemon) or the process's own | no | The single privilege boundary. On Linux a root daemon over a Unix socket; on Windows and macOS the same allowlist runs in-process, so the process itself must be elevated (see [Privilege split](#privilege-split)). |
| API | `api` | none | localhost | FastAPI, non-blocking, streams job progress over SSE. |
| UI | `ui` | none | localhost | Vite + React + TypeScript, fully bundled. |

## Invariants

Each of these is enforced by a test, not by convention.

- **Method selection flows from probed `DeviceCapabilities`, never user preference
  alone.** `core/erase/drive.py:select_method` is a decision table over what the probe
  returned on Linux; on Windows the options come from the resolver over the
  controller's own IDENTIFY answer. The UI preselects what the engine would have
  chosen on its own.
- **One resolver decides every capability state.** `core/platform/capability.py`
  keeps implementation (the `IMPLEMENTATIONS` table), availability (device, bridge,
  safety policy, privilege) and physical evidence apart, and matches evidence on
  (platform, capability, device class) exactly. A package test asserts that every
  module the table names ships.
- **Destructive ops require two gates**: a server-issued, human-approved, single-use
  authorization *and* an operator-typed serial the server re-reads from the device
  itself. There is no dry-run or simulation mode: every request that passes the
  gates reaches the real backend, and a request carrying `dry_run`, `simulation` or
  `simulate` is refused at the API (422) and again at the helper's write seam
  (`core.device.guard.refuse_removed_mode_keys`).
- **Nothing under `core.carve` opens a device or image `O_RDWR`.**
  `core/carve/evidence.py` declares no write method at all and opens `O_RDONLY`;
  `core/carve/win_source.py` opens `GENERIC_READ` only and `core/carve/mac_source.py`
  opens `/dev/rdiskN` `O_RDONLY`.
- **A raw handle proves which disk it is before it is used.** On Windows a
  `\\.\PhysicalDriveN` handle is bound to the planned disk number, serial and length
  through the handle itself (`core/device/win/disk.py:WindowsDisk.bind`); on macOS a
  `/dev/rdiskN` handle is bound to the planned size and block size
  (`core/device/mac/rawdisk.py:MacRawDisk.bind`). A drive letter is never a target.
- **Core layers never touch the network.** There is no base-URL constant anywhere in
  `ui/src/lib/api.ts`, which makes the offline property a grep rather than an audit.
- **Every operation appends a ledger entry before it is considered done.**
  `core/erase/drive.py:execute` refuses to start without a sink.
- **An unknown is never reported as a negative.** Every field a platform may be unable
  to determine is `T | None`, and `None` means "could not determine" — see the class
  docstring on `FileInspection` in `core/models.py`.

## How a job flows

```
UI            POST /jobs/erase-drive          (typed_serial and authorization_id,
 │                                            issued by the server from
 │                                            POST /workflow/erase-drive and
 │                                            .../approve - see api/authorization.py)
 │
API           api/routes/jobs.py              builds the job, opens the Ledger,
 │                                            hands the generator to the registry
 │
Registry      api/jobs.py                     runs the generator on a worker thread,
 │                                            publishes Progress to SSE subscribers
 │
Engine        core/erase/drive.py             yields Progress, records each phase
 │                                            through core/erase/sink.py
 │
Ledger        core/ledger/chain.py            appends; entry N carries SHA-256 of N-1
 │
Report        core/report/render.py           nine sections, canonical JSON, Ed25519
                                              detached signature, PDF rendering
```

On Windows and macOS the engine step is `core/erase/blockclear.py` (addressable
clear) or `core/erase/devicesanitize.py` (Windows ATA SANITIZE / NVMe Sanitize),
reached through the platform adapter, and `core/report/semantics.py` gives the
certificate its category: FILE ERASE, ADDRESSABLE WHOLE-DRIVE CLEAR, DEVICE
SANITIZE, CRYPTO ERASE or PHYSICAL DESTRUCTION ATTESTATION.

The other destructive flows use the same shape (open, approve with the typed serial,
execute with a one-use authorization re-checked at the write seam):

| Flow | Routes | Engine |
|---|---|---|
| Whole-drive erase | `POST /workflow/erase-drive`, `.../approve`, `POST /jobs/erase-drive` | `core/erase/drive.py` (Linux), `core/erase/blockclear.py`, `core/erase/devicesanitize.py` |
| Backup and restore | `POST /workflow/backup`, `.../verify`; `POST /workflow/restore`, `.../approve`, `.../execute` | `core/backup.py`, `core/restore.py` |
| HPA/DCO change | `POST /workflow/hidden-area`, `.../approve`, `.../execute` | `core/device/hidden_area_workflow.py` (Linux hdparm, Windows ATA pass-through) |
| Device preparation | `POST /devices/prepare` (typed serial) | the adapter's take-offline (Windows, non-persistent) or `diskutil unmountDisk` (macOS) step; never part of an erase |

An authorization is issued for one kind (erase, restore, HPA) and cannot be spent as
another.

The registry is the only component that knows a job is asynchronous. Engines are plain
generators, which is what makes them testable without an event loop and resumable from
a ledger checkpoint after a crash.

## Privilege split

On Linux the API, the UI and every core layer run as an ordinary user. One process
runs as root: `helper/daemon.py`, reached over a `0600` Unix socket with `SO_PEERCRED`
checking, taking JSON-RPC calls whose `method` must be a key in a static allowlist. No
shell string is ever accepted from a caller and the daemon never spawns a shell.

The socket daemon is Linux-only, because `SO_PEERCRED` is. On Windows and macOS the
same allowlist runs in-process (`InProcessHelper`), with the process's own privileges:
whole-drive and raw work on Windows needs Sanctum started with *Run as administrator*,
and on macOS a root process. Without it the resolver reports REQUIRES PRIVILEGE and
nothing is escalated. Discovery and file erase run unprivileged on every platform.
The native layer's trust boundary is reviewed in
[`security-review-cross-platform.md`](security-review-cross-platform.md#the-native-device-layer-windows-and-macos).

Full threat model in [`privilege-boundary.md`](privilege-boundary.md).

## What is implemented, and what has run on hardware

The per-platform capability matrix is generated from the resolver and the validation
record, not written by hand:
[`validation/capability-completion-2026-09-28/capability-matrix.md`](validation/capability-completion-2026-09-28/capability-matrix.md).
What changed and what is physically validated (by device class) is summarised in
[`validation/capability-completion-2026-09-28/README.md`](validation/capability-completion-2026-09-28/README.md).

## Why the ledger is a hash chain and not a blockchain

The theme is "Blockchain & Cybersecurity" and the honest engineering answer is a
hash-chained append-only log with an anchoring interface, not a chain we cannot run
offline. Entry N contains the SHA-256 of entry N-1, so insertion, deletion and mutation
are all detectable and `verify()` names the first broken sequence number rather than
returning a bare invalid. Periodic Merkle roots can be published through
`core/ledger/anchor.py`, whose default implementation records plainly that no external
witness was configured.

This is the defensible version. A distributed ledger adds a network dependency to a tool
whose entire operating environment is air-gapped, and it would not make a single claim
in the report more true.
