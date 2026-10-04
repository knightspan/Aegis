# Privilege boundary

One process runs as root. Everything else — the API, the UI, every core layer, the
CLI — runs as an ordinary user and reaches raw hardware only by asking that process
to do one of five named things.

The authoritative description is the module docstring of `helper/daemon.py`. This file
is the threat model around it.

## The boundary

| Property | Value | Enforced at |
|---|---|---|
| Socket | `/run/sanctum/helper.sock` | `helper/daemon.py:61` |
| Mode | `0600`, set *after* bind so a permissive umask cannot leave a window | `helper/daemon.py:258` |
| Peer authentication | `SO_PEERCRED`; a uid other than the configured operator uid is dropped **before any request body is read** | `HelperDaemon` |
| Protocol | Newline-delimited JSON-RPC 2.0, one frame per line | `helper/rpc.py` |
| Frame cap | `MAX_FRAME_BYTES = 1 MiB`; a longer frame drops the peer rather than exhausting memory in a root process | `helper/rpc.py:38` |
| Read timeout | `READ_TIMEOUT_SECONDS = 30` per complete frame | `helper/daemon.py:65` |
| Operations | A static allowlist of exactly five | `helper/daemon.py:222` |

The five operations, and nothing else, ever:

```
enumerate_devices     probe_capabilities     detect_hidden_areas
run_erase             acquire_image
```

`method` is a dictionary key, not a command. **No shell string, no path to an
executable and no argv crosses this socket.** The daemon never spawns a shell.

## What the design assumes an attacker can do

The threat is an attacker who already has code execution as the unprivileged operator
uid — a compromised browser tab, a malicious dependency in the API process, a user
tricked into running something. The boundary exists to bound what that buys them.

**What they can do.** Call the five operations with any parameters that pass typing.
They can enumerate devices, probe capabilities, read hidden-area geometry, acquire an
image to a path they choose, and request an erase.

**What they cannot do.**

- *Erase without both gates.* `run_erase` refuses unless its authorization holds up
  against a fresh read **and** the typed serial matches a serial the helper re-reads
  from the device itself; there is no non-writing mode to fall back to, and a request
  carrying `dry_run` or `simulation` is refused outright
  (`helper/daemon.py:150`). The API cannot talk the helper out of either check, which
  is precisely why both live on this side of the socket rather than in the request
  handler. A caller who has compromised the API still cannot wipe a drive without
  knowing its serial.
- *Erase without a current authorization* (added 2026-09-25, SYNTHETIC-VALIDATED).
  A real `run_erase` or `resume_erase` must also carry an authorization the helper
  re-checks itself, from a fresh read of the device and the backup image
  (`helper/authorization.py`, before the engine is entered): approved record, spent by
  the API, identity, plan and backup unchanged, and a single-use `.executed` marker
  taken by exclusive create. **Limit:** the record is a file in the operator's state
  directory, so a process that can write it as the operator can forge a consistent
  set; the socket permissions, not this check, keep other users out. The backup is
  not re-hashed, and the window between this check and the first write is narrowed,
  not closed.
- *Reach the system disk or a mounted filesystem.* `core/device/guard.py` refuses both,
  and the refusal is inside the erase path, not in the UI.
- *Run an arbitrary command as root.* There is no operation that takes one.
- *Learn the root process's internals from a failure.* An error crossing the socket
  carries a message and a remediation and never a traceback, because a traceback from a
  root process describes the filesystem layout and the code path that reached it.
- *Write to evidence.* `acquire_image` is read-only by construction:
  `core/carve/evidence.py` declares no write method and opens `O_RDONLY`.

**What is out of scope.** An attacker who is already root does not need this socket. An
attacker with physical access to the machine defeats every software control here, which
is why the tool reports residual risk rather than claiming unrecoverability.

## Who owns the chain

This document used to say which *operations* cross the boundary and nothing about
who owns the artefacts written on the far side. That silence was the root cause of a
demo-stopping defect, so it is settled here explicitly.

**The hash-chained ledger has two writers, by design.**

| Writer | What it appends | Runs as |
|---|---|---|
| The API | carve, file-erase and `report.generated` entries | the operator |
| The root helper | the six phases of a drive erase, and its checkpoints | root |

They write to the *same* chain. That is deliberate: one device, one operator, one audit
trail. A per-writer chain would mean an examiner had to be told which file to read for
which kind of operation, and would have to trust the tool's account of how the two
relate.

**Every file the ledger creates is mode `0600`**, because operation parameters are case
material and must not be world-readable. A file created by root at `0600` is therefore
unreadable to the operator — and the operator is who generates the certificate, which
has to read those blobs back. Left alone, a helper-run wipe produced a chain the API
could not turn into a report: `POST /reports/{id}` failed on a permission error against
a blob path. The interim fix was a manual `sudo chown -R` in the demo runbook, which is
not a design.

**The rule now: a root writer hands each file it creates to the operator uid it was
started with.** `core/ledger/_ownership.py`, reached from `LedgerStore.append`,
`BlobStore.put` and the chain's lock file. The uid comes from `--operator-uid` and never
from a request; the mode does not change; only the owner does; and `follow_symlinks` is
false on every call, so a link planted in the ledger directory cannot redirect a
root-owned change onto another file. Only files the call itself creates are handed over,
so pointing the ledger at an existing tree never re-owns that tree.

**What this does not cost.** Tamper-evidence comes from entry *N* containing the SHA-256
of *N-1*, not from file permissions. The operator could already append to this chain —
the API does, for every job that does not go through the helper — so handing them a blob
grants no capability they did not have. Hiding one from them only breaks the report.

**What an examiner is being asked to trust**, stated plainly:

- that the chain's links verify, which they can check themselves with
  `sanctum verify-report --ledger-root`;
- that a chain writable by the operator is *evidence of sequence, not of custody*. It
  proves entries were not altered after the fact without detection. It does not prove the
  operator did not choose what to record. No file mode this tool could set would change
  that, because the operator runs the tool.

**And the confinement that makes the root writer safe at all.** The daemon takes a
`--state-dir` when it starts and resolves every path in every request against it —
`ledger_root`, `dest` — refusing anything that lands outside, symlinks resolved before
the comparison. Without it, a request body naming `ledger_root` would let an
unauthenticated local caller ask a root process to create files anywhere.

## Residual weaknesses, named

- **A confused-deputy erase remains possible if the attacker can read the serial.** The
  serial is not a secret; it is on the device label and in `lsblk`. The typed-serial gate
  defends against the wrong-drive accident, which is the common failure, and not against
  a determined local attacker, which is the rare one. Saying otherwise would overstate it.
- **~~`acquire_image` writes to an operator-chosen destination path as root.~~**
  *Closed.* The daemon now confines `dest` — and `ledger_root` — to the `--state-dir` it
  was started with, resolving symlinks before the comparison. The API side constrains
  `POST /jobs/acquire`'s `dest` to the evidence directory and `POST /jobs/carve`'s
  `out_dir` to the recovered directory independently, so the check does not depend on
  the deployment being configured correctly.
- **The API still has no authentication.** No token, no session, no `Host` header
  validation. The path confinements above bound what an unauthenticated local caller can
  write; they do not stop one from asking. This is the largest thing on this page.
- **No per-operation rate limit or concurrency cap.** A caller can issue probes in a
  loop. Probing is read-only and bounded by device response time, so the cost is
  denial of service against the operator's own machine, not disclosure.
- **The helper does not itself ledger every dispatched call.** Erase and acquire write
  their own ledger entries from inside the engines; a bare `enumerate_devices` does not
  appear in the chain. The chain therefore evidences what was *done*, not everything
  that was *asked*.

## Running it

The daemon takes the operator uid it will accept and refuses to guess it. A daemon
that inferred its operator from the invoking environment would accept whoever `sudo`
happened to be called by:

```bash
sudo .venv/bin/python -m helper \
     --operator-uid "$(id -u)" \
     --state-dir /var/lib/sanctum
```

Both arguments are required. The uid decides who may connect *and* who owns what the
daemon writes; the state directory decides what it may write to at all. Neither is
inferred, because both are answers only the human starting the root process has.

`helper/__main__.py` is the entry point and enforces no rules of its own — every check
lives in `HelperDaemon`, so starting it this way and constructing it by hand cannot
diverge. `InProcessHelper` runs the same `OPERATIONS` table through the same dispatch
for development and the test suite, and grants no privilege at all: whatever the calling
process could already do is all it can do.

Without the daemon, whole-device operations fail with a remediation naming this command.
Everything else — file and folder erasure, carving an image file, report generation and
verification — runs with no privilege at all.
