# Physical benchmark: gate checklist

**Status on 2026-09-24: BLOCKED at gate 1.** No gate below has been
completed. Nothing in this file authorizes a run.

The physical recovery benchmark (`scripts/media_benchmark.py`) writes to a
real device. It runs only after every gate below is complete, **in this
order**, and each completion is recorded here by the person who did it. The
software checks gates 2 to 4 again by itself. A tick in this file does not
replace those checks, and those checks do not replace a tick in this file.

This file collects gates that are already stated elsewhere. It adds no new
rule and changes none.

| # | Gate | Who | Where the rule is | Recorded (date, name, evidence) |
|---|---|---|---|---|
| 1 | **Methodology decision.** The experiment owner records one of the two options in `methodology-open-decision.md`, before the run. **Option A:** amend the methodology with an explicit HIGH false-positive condition, define whether a corrupt HIGH recovery counts as a HIGH false positive, and record the amendment date and time, the approver, the exact wording, and whether it adds to the 5/10 rule or replaces part of it. **Option B:** do not adopt the HIGH false-positive condition; the registered 5/10 recall rule stays the only pass/fail criterion, with HIGH false positives listed as an observation; record the owner, the date and time, and the decision. | Experiment owner | [`methodology-open-decision.md`](methodology-open-decision.md) | |
| 2 | **Device identity reconfirmed.** The by-id path and the serial are read again from `lsblk` and sysfs and match the serial written down for the stick. | Operator | `scripts/media_benchmark.py preflight`, `--expect-serial` | |
| 3 | **Filesystem unmounted by a human.** The tool refuses a mounted device and never unmounts it. | Operator | `core/device/guard.py`; [`../demo/qa.md`](../demo/qa.md) §24 | |
| 4 | **Verified backup on another physical disk.** `verify-backup` reports `sufficient_for_restoring_the_modified_region: true`. Exit 0 alone does not mean verified. | Operator | `scripts/media_benchmark.py verify-backup`; [`../demo/qa.md`](../demo/qa.md) §25 | |
| 5 | **Plan reviewed.** The output of `media_benchmark.py plan` is read by someone other than the operator, including the exact write command it prints. | Reviewer | `scripts/media_benchmark.py plan` | |
| 6 | **Human approval recorded.** The approver writes their name and the date here before `write` is run. | Approver | `core/workflow.py` (HUMAN_APPROVAL_REQUIRED) | |

Only after row 6 is filled in may `media_benchmark.py write` be run. If any
row is filled in after the results are known, the report must say so.

Backup restoration is now implemented in the app (`core/restore.py`,
`/workflow/restore`, the helper's `run_restore`: pre-write chunk verification
and post-restore read-back hash verification), but it has never been run on a
physical device. A completed gate 4 means a backup exists and covers the write
region. It does not mean a restore has been tested. The benchmark harness
(`scripts/media_benchmark.py`) still prints a manual `dd` restore command,
which has never been run either.
