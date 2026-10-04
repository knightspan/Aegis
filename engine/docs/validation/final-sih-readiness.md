# SIH 26149 readiness — what is implemented, measured, and not verified

> **Current state (2026-09-28).** Current product execution no longer exposes
> a user-facing simulation/dry-run mode: every operation runs against the
> selected real device once its gates pass, and a request that asks for a
> rehearsal is refused. References below to a dry run or a simulation record
> what the build of that date did; they are historical evidence and are kept as
> run.

> **Historical snapshot (2026-09-21, `20a6439`).** Superseded by
> [`feature-matrix.md`](feature-matrix.md),
> [`demo-evidence-index.md`](demo-evidence-index.md) and
> [`judge-defense-card.md`](judge-defense-card.md). Several statements below
> were true on that date and are not now: the UI has since been checked in a
> real browser (`browser-2026-09-24/`), PNG bifragment reassembly was added,
> and the test counts have grown. Quote the newer documents.

**Date:** 2026-09-21 · **Base commit:** `20a6439` · Every figure below is
measured on this host (Fedora 44, Linux 6.19.10, 16 logical CPUs, NVMe,
Python 3.11.16) and each links to its raw result. Nothing here is estimated.

## Implemented

| Requirement | Where | Test |
|---|---|---|
| Reports survive an API restart; the ledger stays the single source of truth | `api/durable.py` (`job.outcome` entry, result in the content-addressed blob store) | `tests/api/test_report_job_state.py` (restart → generate → verify), `tests/scripts/test_demo_workflow.py` |
| Secure artifact serving | `api/artifacts.py`, `api/routes/artifacts.py` | `tests/api/test_artifacts.py` (traversal, encoded traversal, absolute, symlink escape, unlisted root, directory, MIME, HTML/SVG never renderable, header injection) |
| Real recovered-image preview and gallery | `ui/src/screens/Recovery.tsx`, `ui/src/lib/artifacts.ts` | `ui/tests/artifacts.test.ts` |
| Report open / download / JSON / verify, no host path on screen | `ui/src/screens/Audit.tsx`, `ui/src/screens/Cases.tsx` | `tests/api/test_report_anchor.py`, demo workflow test |
| Case entity: case, evidence, operations, reports, audit events | `core/cases.py`, `api/routes/cases.py`, `ui/src/screens/Cases.tsx` | `tests/api/test_cases.py` |
| Trusted operator identity from the helper, never from the client | `helper/daemon.py:_op_whoami`, `api/identity.py` | `tests/api/test_operator_identity.py` |
| Bounded recovery memory: payloads spilled to disk, cleaned on success/failure/cancel | `api/carve_job.py:SpillStore` | `tests/api/test_carve_spill.py` |
| Calibration re-run on a larger, deterministic population | `testkit/calibrate.py --seeds` | [`../performance/calibration-pooled.md`](../performance/calibration-pooled.md) |
| Tamper demonstration on a scratch copy, real verifier | `api/routes/audit.py:tamper_demo` | `tests/api/test_tamper_demo.py` (live tree hashed before/after) |
| Reassembly explainer (baseline JPEG, bifragment only) | `Recovery.tsx:ReassemblyExplainer` | demo workflow test asserts two runs, reassembly component, confidence < HIGH |
| Sanitization decision visible; NOT AUTHORIZED with no downgrade | `ui/src/screens/Sanitize.tsx` (target, capability probe, plan) | engine logic unchanged; existing `tests/erase/` |
| Four-way verification verdict | `ui/src/lib/artifacts.ts:verificationWord` | `ui/tests/artifacts.test.ts` (INCONCLUSIVE never PASSED; dry run always NOT APPLICABLE) |
| Resume exposed where supported, refused for firmware | `helper/daemon.py:resume_erase`, `GET/POST /jobs/{id}/resume` | `tests/api/test_resume.py` |
| Merkle root and anchor receipt in every report | `api/routes/audit.py:_anchor_fields` (`SANCTUM_ANCHOR_FILE` → `FileAnchor`, else `NullAnchor`) | `tests/api/test_report_anchor.py` |
| Unhandled errors disclose nothing | `api/main.py:_unhandled` (incident id only) | `tests/api/test_endpoints.py` |
| Case-first navigation, open case always visible, live status strip | `ui/src/App.tsx` | UI build + typecheck |
| Offline demo state | `scripts/demo_setup.py` | `tests/scripts/test_demo_workflow.py` |
| Threat model, generated format table, fuzz and large-image validation | `docs/threat-model.md`, `docs/supported-formats.md`, `docs/validation/` | `tests/scripts/test_supported_formats_doc.py` |

## Defects found and fixed during this work

1. **WAV validator crash on malformed evidence** — found by the fuzz pass.
   CPython's `wave` raises a bare `RuntimeError`; it escaped into the carve job.
   Fixed; `tests/carve/test_validate_malformed.py`.
2. **Truncated PDFs scored HIGH at scale** — found by the 7 GiB run. 39 of 292
   HIGH candidates matched no planted file. The footer search now stops at the
   next same-format header; `tests/carve/signature/test_footer_bound.py`.
3. **Non-deterministic calibration corpus** — ZIP members were stamped with the
   wall clock, so the recoverable total moved between runs. Fixed timestamp.
4. **Registry race** — a job's state became `complete` before its `job.outcome`
   entry was written; `JobRecord.settled` now marks the latter.
5. **Test pollution** — `tests/scripts/test_compare_baseline.py` left a stub
   `api.carve_job` in `sys.modules`; now scoped with `mock.patch.dict`.
6. **`parse_pdf` absorbed an identical PDF 11 MB later** — found by the 1 GiB
   run. An incremental update may no longer span a second `%PDF-` header;
   `tests/carve/signature/test_footer_bound.py`.

## Test results

Run on 2026-09-21 after every change, nothing else on the host:

| Command | Result |
|---|---|
| `make lint` (ruff) | All checks passed |
| `make typecheck` (mypy --strict, linux pass and win32 pass) | no issues in 69 source files; no issues in 1 source file |
| `make test` (pytest) | **1529 passed, 13 skipped, 0 failed** (1542 collected) |
| `python scripts/gen_supported_formats.py --check` | current |
| `cd ui && npx tsc -b --force` | no errors |
| `npm run build` (production bundle) | built |
| `npm run lint` (oxlint) | 0 errors, 14 warnings (React hook-dependency and set-state-in-effect style warnings; the pattern pre-exists in `Devices.tsx`) |
| `npm test` | 26 passed, 0 failed |

Baseline before this work: 1394 collected, 13 skipped. The baseline run
reported 2 failures, both in `tests/test_stubs_raise.py` and both caused by
`core/cases.py` being created while that run was in progress; with it
allowlisted the baseline is 1381 passed, 0 failed. The README said 1211 / 12,
which was stale. New tests: 148 Python, 16 UI.

## Measured results

| Measurement | Result | Source |
|---|---|---|
| Recovery benchmark, Sanctum rows, 40 images | carve-only 565 / 591 byte-identical, 0 missed; undelete+carve 576 / 591 — unchanged from 2026-09-16 | [`../performance/benchmark.md`](../performance/benchmark.md) |
| Pooled calibration, 8 seeds | 173 candidates; HIGH 104/104, MEDIUM 16/16, LOW 0/53; recall 64/64 distinct | [`../performance/calibration-pooled.md`](../performance/calibration-pooled.md) |
| 7 GiB carve, both fixes, isolated | 155.5 s, 46.1 MiB/s, peak RSS 513.4 MiB; recall 288/288; HIGH 247/247, 0 unplanted | [`large-image.md`](large-image.md) |
| 7 GiB carve, before fix | HIGH 292, of which 39 unplanted | [`large-image.md`](large-image.md) |
| 1 GiB carve, isolated | 37.4 s, 27.4 MiB/s, peak RSS 406.0 MiB; recall 288/288; HIGH 247/247 | [`large-image.md`](large-image.md) |
| Fuzz, seed 0 | 66,000 cases, 0 crashes / timeouts / OOM after fix 1 | [`fuzz.md`](fuzz.md) |

## Forensic integrity

- Evidence opened `O_RDONLY`; the carving path has no write method
  (`core/carve/evidence.py`). Recovered output is confined to the recovered
  directory, never the evidence tree.
- SHA-256 and BLAKE3 at acquisition; each carved object carries its SHA-256.
- Ledger: entry N carries SHA-256 of entry N−1; BROKEN is distinguished from
  INCOMPLETE_TAIL; blobs are checked.
- Reports: Ed25519 over canonical JSON; five independent checks; the chain
  records the report digest; Merkle root plus anchor receipt in every report.

## Supported media, filesystems and formats

See the generated [`../supported-formats.md`](../supported-formats.md): 24
signatures, 16 structure parsers, 17 decoders. Undelete: NTFS, FAT12/16/32,
exFAT, ext2/3/4 (ext4 recovers essentially nothing by design). Bifragment
reassembly: baseline JPEG, exactly two runs, gap ≤ 2 MiB.

## Remaining limitations

- Operator identity is a local account, not a person.
- The API has no authentication; single-user workstation required.
- An insider with write access to the whole state directory can rebuild the
  chain; only an external anchor on write-once media prevents that, and none is
  configured by default.
- Overwrite cannot reach remapped or over-provisioned flash; Purge needs device
  support; firmware sanitize has not run on hardware.
- Spilled temp bytes are unlinked, not sanitized.
- Calibration and benchmarks are on synthetic images.
- Full list: [`../limitations.md`](../limitations.md).

## Known unverified environments

- **Windows.** The file-erasure backend is type-checked for win32 and has not
  been executed on Windows in this project's recorded validation.
- **Hardware firmware sanitize** (ATA SANITIZE, NVMe Sanitize/Format): selected
  and dispatched from probed capability, never executed on hardware here.
- **E01 writing** depends on the libewf build; the tests that need it are skipped
  on this host.
- **Root-only tests** (loop devices, block-layer read-only) are among the skips.
- **UI rendering in a browser** was not exercised by an automated browser in
  this work: the UI was verified by TypeScript typecheck, the production build,
  26 unit tests, and a live server serving the bundle. No screenshot was taken.
- **No destructive operation was performed on any host or system disk.** Every
  erase in the test suite targets fixtures, recorders, or scratch files.

## Demo workflow

The exact six-minute sequence, with what each beat shows, is in the final
report of this change and in `docs/user-manual.md` §10a. It is exercised end to
end by `tests/scripts/test_demo_workflow.py`.
