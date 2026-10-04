// Plain words for the case screen. Pure functions, unit-tested in
// ui/tests/cases.test.ts. Every word is derived from a field the server
// returned; a value this file does not know keeps its own name rather than
// being guessed at.

import type { CaseDetail, CaseReportRecord, OperationRecord } from './api'
import type { Tone } from '../components/widgets'
import { isSafetyRefusal } from './refusal.ts'
import { isHistoricalRehearsal } from './legacy.ts'

/** The job kinds api/routes/jobs.py files against a case, in words. */
const OPERATION_TYPES: Record<string, string> = {
  carve: 'Recovery (carve)',
  acquire: 'Acquisition',
  'erase-drive': 'Drive sanitize',
  'erase-files': 'File erase',
  'wipe-free-space': 'Free-space wipe',
  'destroy-record': 'Destruction record',
}

export function operationType(type: string): string {
  return OPERATION_TYPES[type] ?? type
}

/**
 * The job state, in the job registry's own word, capitalised - except where
 * the record carries a fact that word would misstate.
 *
 * - A `failed` job whose structured `error_kind` is a safety refusal is
 *   BLOCKED: the helper refused before any write, so it is not a failed erase.
 * - A `complete` drive erase whose read-back verdict is recorded as failed is
 *   VERIFY FAILED: the run ended, the medium is not verified sanitized.
 *
 * `cancelled` stays CANCELLED: the registry records that the job was stopped
 * on request before it finished, and renaming it here would put a word in the
 * case screen that the chain does not contain. A state this file does not know
 * is shown as itself, in the unknown tone - never as a failure it was not.
 */
export function operationStatus(
  operation: Pick<OperationRecord, 'status' | 'error_kind' | 'verification_passed'>,
): { word: string; tone: Tone } {
  switch (operation.status) {
    case 'complete':
      return operation.verification_passed === false
        ? { word: 'VERIFY FAILED', tone: 'destructive' }
        : { word: 'COMPLETE', tone: 'success' }
    case 'failed':
      return isSafetyRefusal(operation.error_kind)
        ? { word: 'BLOCKED', tone: 'warning' }
        : { word: 'FAILED', tone: 'destructive' }
    case 'cancelled':
      return { word: 'CANCELLED', tone: 'warning' }
    case 'running':
      return { word: 'RUNNING', tone: 'warning' }
    case 'pending':
      return { word: 'PENDING', tone: 'unknown' }
    default:
      return { word: (operation.status || 'unknown').toUpperCase(), tone: 'unknown' }
  }
}

/** The words the Cases screen shows when the case record itself cannot be read. */
export function caseRequestFailed(message: string): string {
  return `REQUEST FAILED - the case record could not be read (${message}). Nothing is inferred about its operations.`
}

/**
 * True only for an operation an earlier build filed as a rehearsal.
 *
 * Read from the parameters the job was filed with. Current jobs never carry
 * the flag: every operation this build runs is real. See lib/legacy.ts.
 */
export function isHistoricalRehearsalOp(operation: OperationRecord): boolean {
  return isHistoricalRehearsal(operation.params)
}

/** The report generated for each operation, keyed by operation id. */
export function reportsByOperation(
  reports: CaseReportRecord[],
): Map<string, CaseReportRecord> {
  const out = new Map<string, CaseReportRecord>()
  for (const item of reports) {
    const seen = out.get(item.operation_id)
    // The latest report stands for the operation; older ones stay listed on
    // the Reports tab.
    if (!seen || item.generated_at > seen.generated_at) out.set(item.operation_id, item)
  }
  return out
}

function plural(count: number, one: string, many = `${one}s`): string {
  return `${count.toLocaleString('en-US')} ${count === 1 ? one : many}`
}

/** One line under each figure on the overview. */
export interface CaseFacts {
  evidence: string
  operations: string
  reports: string
  audit: string
}

export function caseFacts(detail: CaseDetail): CaseFacts {
  const counts = new Map<string, number>()
  for (const op of detail.operations) {
    const word = operationStatus(op).word.toLowerCase()
    counts.set(word, (counts.get(word) ?? 0) + 1)
  }
  const historical = detail.operations.filter(isHistoricalRehearsalOp).length
  const states = [...counts.entries()].map(([word, n]) => `${n} ${word}`)
  // Said as part of the total, never beside it: "2 complete · 1 historical"
  // reads as three operations.
  const total = detail.operations.length
  const rehearsals = !historical
    ? ''
    : historical === total
      ? ' — all historical records that wrote nothing'
      : ` — ${historical} of ${total} historical records that wrote nothing`

  const hashed = detail.evidence.filter((item) => item.source_hash).length
  const signed = detail.reports.filter((item) => item.signed).length
  const unsigned = detail.reports.length - signed

  return {
    evidence: detail.evidence.length
      ? `${hashed} with a recorded hash`
      : 'none registered',
    operations: states.length ? states.join(' · ') + rehearsals : 'none run',
    reports: detail.reports.length
      ? [signed && `${signed} signed`, unsigned && `${unsigned} unsigned`]
          .filter(Boolean)
          .join(' · ')
      : 'none generated',
    audit: `of ${plural(detail.audit.entry_count, 'entry', 'entries')} in the chain`,
  }
}
