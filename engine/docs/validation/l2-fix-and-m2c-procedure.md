# L2 / L3 fixes and the M2-C procedure (not executed)

Written 2026-09-25 against HEAD `ec73747`. Historical campaign evidence in
`docs/validation/campaign-2026-09-24/` and `physical-module-baseline.json` is
unchanged; this file is a new record.

## Security property: API CANNOT BYPASS WORKFLOW SAFETY GATES

`POST /jobs/erase-drive` (and `POST /jobs/{id}/resume`) refuses unless an authorization record exists that `core.workflow.derive`
places at `PLAN_READY` from a fresh read of the device, and
`core.workflow.advance(PLAN_READY, EXECUTING)` accepts. The record is built by
`POST /workflow/erase-drive` (read-only backup image check) and
`POST /workflow/erase-drive/{id}/approve` (the only place approval is written),
and is spent once. The typed serial is never approval. A refusal is HTTP 409,
`verdict: REFUSED`, with a `WHY BLOCKED` list, and reaches no write path.
Proof: `tests/api/test_workflow_gate.py`.

Limits, stated plainly:

- The backup check hashes and sizes an image; it does not prove the image is a
  copy of the target device.
- The API has no user authentication. "Human approval" is a deliberate separate
  call by the operator account, not proof a person made it.
- The privileged helper daemon does not re-check this gate. The boundary is the
  API's. A process that reaches the helper socket directly is outside it.
- Whole-drive sanitization previously had no backup gate by design
  (`ui/src/lib/workflowState.ts` `BACKUP_NOTE`). The API now requires one,
  because `core/workflow.py` requires it for `PLAN_READY`. The Sanitize screen
  does not yet drive the new workflow calls; a real erase from the UI is refused
  until it does. **Superseded 2026-09-25:** the Sanitize screen now drives
  `/workflow/erase-drive`, `.../approve` and `/jobs/erase-drive` with the
  server-issued `authorization_id`. Evidence: `browser-2026-09-25/` (fixture
  server, synthetic helper, not a physical device) and
  `final-audit-2026-09-25.md`.

## L3

`core/platform/host.py::build_info` is the single source for `/health` and the
Platform screen. A packaged build reports its record. A checkout reports live
git HEAD and names any stale record it ignored.

## M2-C physical file erase: NOT EXECUTED, human-gated

The stick holds `img01/03/05/07/09.jpg`. Do not run until a person states, in
writing, that those files are disposable. Filenames are not evidence.

1. Person confirms disposability and records who, when.
2. Read-only: `sha256sum` each file and record the list.
3. *(Superseded 2026-09-28: there is no dry-run mode.)* Instead, send
   `POST /jobs/erase-files` without `confirm` and confirm it is refused (409)
   and that the hashes are unchanged.
4. Only then a real erase of a single confirmed file, `confirm=true`.
5. Verify read-back, the certificate, and `sectors_written` deltas.
Flash wear levelling means an overwrite is a Clear-level claim at best.
