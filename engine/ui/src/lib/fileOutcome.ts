/**
 * What happened to one path in a file erase, in words.
 *
 * Three outcomes that must never be confused: the erase completed, it started
 * and failed partway, or it stopped before it began (refused, or failed a
 * check). The server's `attempted` flag separates the
 * last two; a record without it (an older server) is said to be unknown
 * rather than guessed at. A path the erase started on and did not finish is
 * in an unknown state, so it is never labelled "not attempted".
 */

import type { FileEraseRecord } from './api'

export type OutcomeTone = 'success' | 'destructive' | 'unknown'

export interface FileOutcome {
  /** The Status column's word. */
  word: string
  /** Tone of that word. */
  tone: OutcomeTone
  /** The residual column's level when the erase did not complete. */
  residual: string
  /** The residual column's basis when the erase did not complete. */
  basis: string
}

export function fileOutcome(
  record: Pick<FileEraseRecord, 'ok' | 'error_kind' | 'attempted'>,
): FileOutcome {
  if (record.ok) return { word: 'erased', tone: 'success', residual: '', basis: '' }
  const kind = record.error_kind ?? 'failed'
  if (record.attempted === true) {
    return {
      word: `failed partway · ${kind}`,
      tone: 'destructive',
      residual: 'INCOMPLETE',
      basis: 'erase started, then failed; state unknown',
    }
  }
  if (record.attempted === false) {
    return {
      word: kind,
      tone: 'destructive',
      residual: 'NOT RUN',
      basis: 'stopped before any erase step ran',
    }
  }
  return {
    word: kind,
    tone: 'destructive',
    residual: 'UNKNOWN',
    basis: 'failed; whether any step ran is not recorded',
  }
}
