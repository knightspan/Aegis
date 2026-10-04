# Final audit of the Sanitize workflow, 2026-09-25

> **Current state (2026-09-28).** Current product execution no longer exposes
> a user-facing simulation/dry-run mode: every operation runs against the
> selected real device once its gates pass, and a request that asks for a
> rehearsal is refused. References below to a dry run or a simulation record
> what the build of that date did; they are historical evidence and are kept as
> run.

Base: branch `docs/readme-redesign`, HEAD `5534214c60be1adab593527f7cdb3f7700f7ff99`,
working tree dirty (uncommitted, not committed by this audit). Every result below was
produced on this tree; nothing is carried over from an earlier run. Population labels:
SYNTHETIC = synthetic helper or files, never a physical device.

## Test inconsistency: resolved as a pytest quirk, not a product defect

The focused command listed `tests/api/*` files, then `tests/test_workflow.py`, then more
`tests/api/*` files. The later `tests/api` files failed at setup with
`fixture 'client' not found`. Reproduced with zero project code: a package with
`tests/api/conftest.py` defining a fixture, `tests/api/test_a.py`, `tests/test_top.py`
(a file in the parent directory) and `tests/api/test_b.py`, run as `a top b` on
pytest 9.1.1, fails `test_b` the same way; `a b top` passes. Any file directly under
`tests/` placed between two `tests/api` arguments triggers it. It is argument order, not
shared state, ports, temp directories or fixture scope. No assertion was weakened and
nothing was skipped. Mitigation: group arguments by directory, or pass directories.

## What changed in this audit (all uncommitted)

- `api/authorization.py`, `api/routes/workflow.py`: the backup fingerprint now also
  records inode and `st_ctime_ns` (which `utime` cannot restore). A same-size in-place
  edit with the mtime restored used to pass the gate; it is refused. A record without the
  fields fails closed. The plan (achievable levels, limitations, blocking) is compared
  against a fresh probe at execution. Approval is written once and never after use.
- `ui/`: workflow calls are guarded against stale replies (`lib/epoch.ts`); a server
  failure (5xx, unreachable platform) is shown as REQUEST FAILED, not as a BLOCKED
  refusal; a finished real job whose read-back FAILED is FAILED, not COMPLETE; the
  approval modal scrolls.
- Tests: `test_gate_hardening.py`, `test_workflow_failure_modes.py`,
  `test_sanitize_ui_chain.py`, `tests/erase/test_dry_run_write_path.py`, UI tests.

## Stated limits (do not overclaim)

- A dry run opens the device node `O_RDONLY` for the `BLKGETSIZE64` geometry ioctl
  (`core/erase/drive.py:184`). "A simulation never opens /dev" is false; "a simulation
  never opens a device for writing and never reaches the write path" is what is tested.
- `scripts/demo_simulation.py` really overwrites a temporary regular file. It is a
  simulation of a device, not of a write.
- The backup is verified by sha256 at open and by size, mtime, ctime and inode at
  execution. It is not re-hashed at execution, raw-device tampering is not detected,
  and it does not prove the image is a copy of this device.
- **Superseded by the hardening pass below:** the helper now re-checks the authorization
  itself. The API still has no user authentication; approval is a deliberate second call,
  not proof a person made it.
- Between the gate passing and the helper writing there was a window. It is now narrowed:
  `helper/authorization.py` re-reads the device and the backup immediately before the
  engine is entered. What remains is the time from that check to the first write, covered
  only by the engine's own guards (system disk, mount, serial re-read).
- The authorization is spent when the gate passes, before the helper runs. A failure after
  that consumes it; the operator opens a new workflow. This is fail-closed by design.
- The workflow record only derives pre-execution states. EXECUTING, VERIFYING, COMPLETE
  and FAILED shown on screen come from the job's own status.
- Packaged artifacts (`dist/*.deb`, `*.AppImage`, 2026-09-21/22, record `930ee2c`) were
  not rebuilt at the time of this audit and contained the old Sanitize screen.
  **Superseded:** rebuilt from commit `0127172`; see `release-report-2026-09-25.md`.

## Physical device

SANCTUMREC stayed mounted at `/run/media/v0idsai/SANCTUMREC`. Nothing in this audit
opened, read, wrote, acquired or restored it. During the previous session the
assistant read img01/03/05/07 with `sha256sum`; that updated the FAT last-access date of
those files (atime is now 2026-09-25 on four files, 2026-09-06 on img09) and moved
`/sys/block/sda/stat` from 1 write / 1 sector (the 2026-09-24 snapshot) to 2 writes /
3 sectors. The three hashes read match `physical-module-baseline.json`; img07 and img09
contents were not re-verified. The counters did not change during this audit.

## Hardening pass (same day): helper-side revalidation

`helper/authorization.py` runs in `run_erase` and `resume_erase` before the engine, for
requests whose `dry_run` is explicitly false. It requires an approved record that the API
spent and that matches the request, re-reads the device (identity, mount, system disk,
capability plan) and the backup (size, mtime, ctime, inode) from the host, and takes an
exclusive-create `<id>.executed` marker last. Refusals raise `WorkflowGateRefused`
(structured, no traceback). The shared comparisons live in `core/authorization.py`.

Proven by test, synthetic devices only: a missing, fabricated, unapproved, unspent,
mismatched, reused or changed authorization never enters the engine; a device or backup
changed *after* the API gate passed is refused by the helper (`test_write_seam_integration.py`);
twelve concurrent attempts admit exactly one, at the API gate and at the helper marker;
a dry run never consults an authorization. Mutation check: with the helper call removed,
18 of these tests fail.

Not established: race freedom in general. The record and markers are files the operator can
write, so a same-user process can forge a consistent set (the socket permissions keep other
users out, not this check); the backup is not re-hashed; the interval between the helper's
check and the first write remains. The destructive engine was never run on a device.

## Correction, later the same day

This audit said "Nothing in this audit opened, read, wrote, acquired or restored" the
stick. No open or I/O is known to have happened, but the full test runs it relied on
ran real host discovery (`lsblk -J -O -b` over sysfs, and `/dev/disk/by-id` and
`/sys/block` listings on the fallback) from five platform tests and one helper test,
which enumerates every attached disk's metadata, the stick's included. File-erase tests
also asked to open the system disk read-only and were refused by the kernel. Details,
the guard that now refuses all of it, and the re-run with 0 refusals are in
[`release-report-2026-09-25.md`](release-report-2026-09-25.md).

The `error_kind` the job registry recorded for any helper failure was `RpcError`, so the
Sanitize screen showed a write-seam refusal as FAILED; fixed in `db38ea7`.
