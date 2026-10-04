import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  caseFacts,
  caseRequestFailed,
  isHistoricalRehearsalOp,
  operationStatus,
  operationType,
  reportsByOperation,
} from '../src/lib/cases.ts'
import type { CaseDetail, CaseReportRecord, OperationRecord } from '../src/lib/api.ts'

function op(over: Partial<OperationRecord>): OperationRecord {
  return {
    operation_id: 'carve-1',
    case_id: 'C',
    evidence_id: '',
    type: 'carve',
    status: 'complete',
    started_at: '2026-09-25T10:00:00Z',
    completed_at: null,
    operator: 'alice (uid 1000)',
    result_ref: '',
    recovered_artifacts: 0,
    params: {},
    ...over,
  }
}

function report(over: Partial<CaseReportRecord>): CaseReportRecord {
  return {
    report_id: 'r',
    case_id: 'C',
    operation_id: 'carve-1',
    json_name: 'a.json',
    pdf_name: 'a.pdf',
    report_hash: 'ab',
    signed: true,
    pubkey_fingerprint: '',
    generated_at: '2026-09-25T10:00:00Z',
    ...over,
  }
}

function detail(over: Partial<CaseDetail>): CaseDetail {
  return {
    case: {
      case_id: 'C',
      title: '',
      description: '',
      status: 'open',
      created_at: '',
      created_by: '',
      updated_at: '',
      evidence_count: 0,
      operation_count: 0,
      report_count: 0,
      recovered_artifact_count: 0,
    },
    evidence: [],
    operations: [],
    reports: [],
    audit: {
      chain_status: 'VALID',
      chain_explanation: '',
      first_broken_seq: null,
      entry_count: 8,
      events: [],
    },
    ...over,
  }
}

test('job kinds read as words, and an unknown kind keeps its name', () => {
  assert.equal(operationType('carve'), 'Recovery (carve)')
  assert.equal(operationType('erase-drive'), 'Drive sanitize')
  assert.equal(operationType('destroy-record'), 'Destruction record')
  assert.equal(operationType('something-new'), 'something-new')
})

test('job states keep the registry word; failure is never inferred', () => {
  assert.deepEqual(operationStatus({ status: 'complete' }), { word: 'COMPLETE', tone: 'success' })
  assert.deepEqual(operationStatus({ status: 'failed' }), { word: 'FAILED', tone: 'destructive' })
  assert.equal(operationStatus({ status: 'cancelled' }).word, 'CANCELLED')
  assert.deepEqual(operationStatus({ status: 'odd' }), { word: 'ODD', tone: 'unknown' })
  assert.deepEqual(operationStatus({ status: '' }), { word: 'UNKNOWN', tone: 'unknown' })
})

test('a write-seam refusal is BLOCKED, never a FAILED erase', () => {
  const refused = operationStatus({ status: 'failed', error_kind: 'WorkflowGateRefused' })
  assert.deepEqual(refused, { word: 'BLOCKED', tone: 'warning' })
  // Any other kind is still a failure; the message is never read.
  assert.equal(operationStatus({ status: 'failed', error_kind: 'OverwriteIncomplete' }).word, 'FAILED')
  assert.equal(operationStatus({ status: 'failed', error_kind: 'RpcError' }).word, 'FAILED')
})

test('a completed run whose read-back FAILED is not COMPLETE', () => {
  const outcome = operationStatus({ status: 'complete', verification_passed: false })
  assert.equal(outcome.word, 'VERIFY FAILED')
  assert.equal(outcome.tone, 'destructive')
  assert.equal(operationStatus({ status: 'complete', verification_passed: true }).word, 'COMPLETE')
})

test('the overview line counts a refusal as blocked, not failed', () => {
  const facts = caseFacts(
    detail({
      operations: [
        op({ operation_id: 'a', type: 'erase-drive', status: 'failed', error_kind: 'WorkflowGateRefused' }),
        op({ operation_id: 'b', type: 'erase-drive', status: 'failed', error_kind: 'OverwriteIncomplete' }),
      ],
    }),
  )
  assert.match(facts.operations, /1 blocked/)
  assert.match(facts.operations, /1 failed/)
})

test('a case that cannot be read says REQUEST FAILED, not BLOCKED', () => {
  const words = caseRequestFailed('500 Internal Server Error')
  assert.match(words, /^REQUEST FAILED/)
  assert.doesNotMatch(words, /BLOCKED|refus/i)
})

test('only a record an earlier build filed as a rehearsal is historical', () => {
  // Historical evidence: case files written before real-device mode.
  assert.equal(isHistoricalRehearsalOp(op({ params: { dry_run: true } })), true)
  assert.equal(isHistoricalRehearsalOp(op({ params: { dry_run: false } })), false)
  assert.equal(isHistoricalRehearsalOp(op({ params: { dry_run: 'true' } })), false)
  // What this build files: no flag at all, which is a real operation.
  assert.equal(isHistoricalRehearsalOp(op({ params: {} })), false)
})

test('the latest report stands for its operation', () => {
  const byOp = reportsByOperation([
    report({ report_id: 'old', generated_at: '2026-09-25T10:00:00Z' }),
    report({ report_id: 'new', generated_at: '2026-09-25T11:00:00Z' }),
    report({ report_id: 'other', operation_id: 'erase-2' }),
  ])
  assert.equal(byOp.get('carve-1')?.report_id, 'new')
  assert.equal(byOp.get('erase-2')?.report_id, 'other')
})

test('the overview lines count what the case holds and say so when empty', () => {
  const empty = caseFacts(detail({}))
  assert.equal(empty.evidence, 'none registered')
  assert.equal(empty.operations, 'none run')
  assert.equal(empty.reports, 'none generated')
  assert.equal(empty.audit, 'of 8 entries in the chain')

  const full = caseFacts(
    detail({
      operations: [
        op({}),
        op({ operation_id: 'e', type: 'erase-drive', status: 'failed' }),
        op({ operation_id: 's', type: 'erase-drive', params: { dry_run: true } }),
      ],
      reports: [report({}), report({ operation_id: 'e', signed: false })],
    }),
  )
  assert.equal(full.operations, '2 complete · 1 failed — 1 of 3 historical records that wrote nothing')
  assert.equal(full.reports, '1 signed · 1 unsigned')

  const rehearsal = caseFacts(
    detail({ operations: [op({ params: { dry_run: true } })] }),
  )
  assert.equal(rehearsal.operations, '1 complete — all historical records that wrote nothing')
})
