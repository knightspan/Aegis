/**
 * Ledger operation names, in words.
 *
 * The chain records dotted operation names (`erase.approved`,
 * `carve.complete`, `case.evidence.registered`). The overview and the chain
 * explorer show them to people, so they are translated here once. An
 * operation this file does not know keeps its own name rather than being
 * dropped or guessed at.
 */

export type OperationKind = 'erase' | 'recover' | 'report' | 'case' | 'chain' | 'job' | 'other'

const KIND: Record<string, OperationKind> = {
  erase: 'erase',
  carve: 'recover',
  acquire: 'recover',
  report: 'report',
  case: 'case',
  GENESIS: 'chain',
  job: 'job',
}

const SUBJECT: Record<string, string> = {
  erase: 'Erase',
  carve: 'Recovery',
  acquire: 'Acquisition',
  report: 'Report',
  case: 'Case',
  job: 'Job',
}

/** Specific wording where the dotted name reads badly. */
const EXACT: Record<string, string> = {
  GENESIS: 'Chain started',
  'erase.approved': 'Erase approved by the operator',
  'erase.refused': 'Erase refused at the gate',
  'job.outcome': 'Job outcome recorded',
  'report.generated': 'Signed report generated',
  'case.opened': 'Case opened',
  'case.evidence.registered': 'Evidence registered',
  'carve.start': 'Recovery started',
  'carve.complete': 'Recovery complete',
  'carve.cancelled': 'Recovery cancelled',
  'acquire.start': 'Acquisition started',
  'acquire.complete': 'Acquisition complete',
  'acquire.checkpoint': 'Acquisition checkpoint',
  'acquire.cancelled': 'Acquisition cancelled',
  'erase.file.trace': 'Trace of an erased file',
  'erase.file.traces': 'Trace sweep finished',
}

export function operationKind(operation: string): OperationKind {
  return KIND[operation.split('.')[0]] ?? 'other'
}

export function operationLabel(operation: string): string {
  if (EXACT[operation]) return EXACT[operation]
  const [head, ...rest] = operation.split('.')
  const subject = SUBJECT[head]
  if (!subject || !rest.length) return operation
  const words = rest.join(' ').replace(/_/g, ' ')
  return `${subject}: ${words}`
}

/** "12:04" today, "24 Sep 12:04" otherwise; the raw string if unparseable. */
export function shortTime(isoUtc: string, now: Date = new Date()): string {
  const at = new Date(isoUtc)
  if (Number.isNaN(at.getTime())) return isoUtc
  const time = at.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
  if (at.toDateString() === now.toDateString()) return time
  const day = at.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })
  return `${day} ${time}`
}
