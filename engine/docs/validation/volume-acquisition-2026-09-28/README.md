# Linux volume acquisition, usb-flash, 2026-09-28

One read-only run on one device. It validates `linux / volume_acquisition /
usb-flash` and nothing else.

| | |
|---|---|
| Device | TOSHIBA TransMemory, serial `B103B9C19DE1CCC1BD535ACB`, 7.23 GiB, USB, designated test media |
| Source | `/dev/sda1` (vfat, 7,758,413,824 bytes), read through the root helper |
| Build | commit `a4fde30d15405537b8c773224d5e2998e2580f2e`, clean tree |
| Signing | key created before the first ledger entry; the report's `fingerprint_matches_genesis` check passes |
| Result | PASS |

## What was checked

* The job read 7,758,413,824 of 7,758,413,824 bytes; `write_blocked` is true,
  verified by reading the flag back.
* An independent `sha256sum` of `/dev/sda1` and of the image both equal the
  job's SHA-256 (`independent-sha256.txt`).
* The signed report verifies (`verify-report.txt`), with the limitations below.

## What this does not establish

* The write block is `BLKROSET` at the block layer. No write was attempted to
  prove refusal, and SG_IO and ATA pass-through bypass it. The report says so.
* The volume was mounted read-write while it was read, so its contents could
  have changed during the read; the hashes agree, which shows that they did not.
* One USB flash stick. Nothing here says anything about internal disks, other
  device classes, Windows or macOS.
* The operator identity is a local account, not a person.

## Defects found and fixed on the way

The run was only possible after three fixes: the helper socket was owned by
root so the operator could not connect; `/jobs/acquire` opened block devices in
the unprivileged API process; and a single partition could not be selected. A
fourth fix stopped the verifier grading an acquisition report with a false
"its own verification did not pass" reason. The verifier fix landed after the
run, so `verify-report.txt` was produced by the fixed verifier.
