/**
 * The executive summary counts only what the case record says, and never
 * counts a historical rehearsal record as an erasure.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import type { CaseDetail, OperationRecord, PlatformStatus } from '../src/lib/api.ts'
import { NOT_PHYSICALLY_VALIDATED, executiveSummary, judgeSummary } from '../src/lib/summary.ts'

function op(type: string, status: string, params: Record<string, unknown> = {}, recovered = 0): OperationRecord {
  return {
    operation_id: `${type}-${status}-${Math.random()}`,
    case_id: 'C1',
    evidence_id: '',
    type,
    status,
    started_at: '',
    completed_at: null,
    operator: 'u',
    result_ref: '',
    recovered_artifacts: recovered,
    params,
  }
}

function detail(operations: OperationRecord[], chain = 'VALID', signed = [true]): CaseDetail {
  return {
    case: {} as CaseDetail['case'],
    evidence: [{} as CaseDetail['evidence'][number]],
    operations,
    reports: signed.map((value, index) => ({
      report_id: `r${index}`,
      case_id: 'C1',
      operation_id: '',
      json_name: '',
      pdf_name: '',
      report_hash: '',
      signed: value,
      pubkey_fingerprint: '',
      generated_at: '',
    })),
    audit: { chain_status: chain, chain_explanation: 'why', first_broken_seq: null, entry_count: 5, events: [] },
  }
}

const platform = { limitations: ['Overwrite cannot reach remapped flash.'] } as PlatformStatus

test('a historical rehearsal record is never counted as an erasure', () => {
  const s = executiveSummary(detail([op('erase-drive', 'complete', { dry_run: true })]), platform)
  assert.ok(s.erased.some((line) => line.includes('historical rehearsal record')))
  assert.ok(!s.erased.some((line) => line.includes('drive sanitization completed')))
})

test('a completed erase this build ran is counted: every one is real', () => {
  const s = executiveSummary(detail([op('erase-drive', 'complete', {})]), platform)
  assert.ok(s.erased.includes('1 drive sanitization completed'))
  const files = executiveSummary(detail([op('erase-files', 'complete', {})]), platform)
  assert.ok(!files.erased.some((line) => /dry run|rehearsal/.test(line)))
})

test('a legacy real erase record still counts as real', () => {
  const s = executiveSummary(detail([op('erase-drive', 'complete', {})]), platform)
  assert.ok(s.erased.includes('1 drive sanitization completed'))
})

test('recovered artifacts are summed over completed carves only', () => {
  const s = executiveSummary(
    detail([op('carve', 'complete', {}, 7), op('carve', 'running', {}, 99), op('carve', 'complete', {}, 3)]),
    platform,
  )
  assert.ok(s.found.includes('10 recovered artifacts from 2 completed recovery runs'))
  assert.ok(s.unverified.some((line) => line.includes('still running')))
})

test('a broken chain and unsigned reports are listed as unverified', () => {
  const s = executiveSummary(detail([], 'BROKEN', [true, false]), platform)
  assert.ok(s.unverified.some((line) => line.includes('BROKEN')))
  assert.ok(s.unverified.includes('1 report not signed'))
  assert.ok(s.verified.includes('1 signed report of 2'))
})

test('platform limitations always reach the unverified column', () => {
  const s = executiveSummary(detail([]), platform)
  assert.ok(s.unverified.includes('Overwrite cannot reach remapped flash.'))
})

test('no open case says so in every column it can', () => {
  const s = executiveSummary(null, platform)
  assert.ok(s.found[0].includes('No case is open'))
  assert.ok(s.erased[0].includes('No case is open'))
})

test('the chain line uses a correct plural', () => {
  const s = executiveSummary(detail([]), platform)
  assert.ok(s.verified.includes('Audit chain VALID over 5 entries'))
})

test('the judge summary answers all six questions even with no case open', () => {
  const summary = judgeSummary(null, null, 'UNREAD')
  for (const key of ['erasure', 'recovery', 'verification', 'integrity', 'safety', 'limitations'] as const) {
    assert.ok(summary[key].length > 0, key)
  }
  assert.ok(summary.integrity.includes('Audit chain: UNREAD.'))
})

test('the limitations always lead with what is not physically validated', () => {
  const summary = judgeSummary(detail([op('carve', 'complete', {}, 3)]), null, 'VALID')
  assert.deepEqual(summary.limitations.slice(0, NOT_PHYSICALLY_VALIDATED.length), [...NOT_PHYSICALLY_VALIDATED])
  assert.ok(summary.limitations.some((line) => line.includes('SYNTHETIC')))
})

test('each unvalidated or unavailable capability is named with its state', () => {
  const find = (prefix: string) => NOT_PHYSICALLY_VALIDATED.filter((line) => line.startsWith(prefix))
  for (const prefix of [
    'Windows whole-drive clear',
    'Windows raw physical-device acquisition',
    'Windows device sanitize',
    'macOS whole-drive clear and raw acquisition',
    'Backup restore',
  ]) {
    const lines = find(prefix)
    assert.equal(lines.length, 1, prefix)
    // The resolver's label (core/platform/model.py STATE_LABELS), not a paraphrase.
    assert.match(lines[0], /IMPLEMENTED \/ UNVALIDATED/, prefix)
    assert.doesNotMatch(lines[0], /not implemented/i, prefix)
  }
  assert.match(find('ATA SECURITY ERASE on Windows')[0], /NOT IMPLEMENTED/)
  assert.match(find('NVMe Format on Windows')[0], /PLATFORM-LIMITED/)
  assert.match(find('HPA/DCO discovery and modification on macOS')[0], /PLATFORM-LIMITED/)
  assert.match(find('Firmware Purge')[0], /never run on a physical drive/)
  assert.match(find('Device sanitize, crypto erase')[0], /on macOS: PLATFORM-LIMITED/)
  assert.match(find('Free-space wipe on Windows and macOS')[0], /NOT IMPLEMENTED/)
  assert.match(find('HPA change')[0], /DCO is discovered only, never modified/)
  assert.ok(!NOT_PHYSICALLY_VALIDATED.some((line) => /NOT PHYSICALLY VALIDATED|HPA\/DCO unlock/.test(line)))
  assert.ok(NOT_PHYSICALLY_VALIDATED.some((line) => /No macOS physical device run is recorded/.test(line)))
})

test('the judge summary never counts a historical rehearsal as an erasure', () => {
  const summary = judgeSummary(detail([op('erase-drive', 'complete', { dry_run: true })]), null, 'VALID')
  assert.ok(!summary.erasure.some((line) => /drive sanitization completed/.test(line)))
  assert.ok(summary.erasure.some((line) => line.includes('historical rehearsal')))
})

test('the safety lines describe real operation, not a dry-run default', () => {
  const summary = judgeSummary(detail([]), null, 'VALID')
  assert.ok(!summary.safety.some((line) => /dry run is the default/i.test(line)))
  assert.ok(summary.safety.some((line) => /no rehearsal mode/.test(line)))
})

test('no judge summary line states a percentage', () => {
  const summary = judgeSummary(detail([op('carve', 'complete', {}, 3)]), null, 'VALID')
  const lines = Object.values(summary).flat()
  assert.ok(!lines.some((line) => /\d+(\.\d+)?%/.test(line)))
})

test('a write-seam refusal is BLOCKED on the overview, never a failed or partial erase', () => {
  const refused = { ...op('erase-drive', 'failed', {}), error_kind: 'WorkflowGateRefused' }
  const s = executiveSummary(detail([refused]), platform)
  assert.ok(s.erased.some((line) => /BLOCKED by a safety refusal before any write; nothing was erased/.test(line)))
  for (const line of s.erased) {
    assert.doesNotMatch(line, /partial|partly|FAILED|failed/, line)
  }
  const judge = judgeSummary(detail([refused]), null, 'VALID')
  assert.ok(!judge.erasure.some((line) => /partial|partly|failed/i.test(line)))
})

test('an erase that started and failed, and one stopped on request, are said apart', () => {
  const failed = { ...op('erase-drive', 'failed', {}), error_kind: 'OverwriteIncomplete' }
  const stopped = op('erase-drive', 'cancelled', {})
  const s = executiveSummary(detail([failed, stopped]), platform)
  assert.ok(s.erased.some((line) => /^1 erase FAILED/.test(line)))
  assert.ok(s.erased.some((line) => /stopped on request \(CANCELLED\)/.test(line)))
  assert.ok(!s.erased.some((line) => /BLOCKED/.test(line)))
})

test('a completed run whose read-back FAILED is not counted as completed', () => {
  const run = { ...op('erase-drive', 'complete', {}), verification_passed: false }
  const s = executiveSummary(detail([run]), platform)
  assert.ok(!s.erased.some((line) => line.includes('drive sanitization completed')))
  assert.ok(s.erased.some((line) => /read-back verification FAILED/.test(line)))
})

test('an unreadable case is REQUEST FAILED, not an empty case and not a refusal', () => {
  const s = executiveSummary(null, platform, '500 Internal Server Error')
  assert.match(s.erased[0], /^REQUEST FAILED/)
  assert.doesNotMatch(s.erased[0], /BLOCKED|No case is open/)
  assert.match(executiveSummary(null, platform).erased[0], /No case is open/)
  const judge = judgeSummary(null, null, 'VALID', '500 Internal Server Error')
  assert.ok(judge.erasure.some((line) => /^REQUEST FAILED/.test(line)))
})
