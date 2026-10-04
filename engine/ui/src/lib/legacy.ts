/**
 * Records written by earlier builds, read so they are never misreported.
 *
 * The product no longer has a rehearsal mode: every job this build starts is a
 * real operation on the selected target. Case files and job records written
 * before that change can still hold operations that were rehearsals - their
 * parameters carry `dry_run: true` - and those wrote nothing. They are
 * historical evidence: they stay readable, and they are never counted as an
 * erasure. Nothing in this build creates one.
 */

/** True only for a record an earlier build filed as a rehearsal. */
export function isHistoricalRehearsal(params: Record<string, unknown> | undefined | null): boolean {
  return params?.dry_run === true
}

/** The label a historical rehearsal record carries wherever it is listed. */
export const HISTORICAL_REHEARSAL_LABEL = 'HISTORICAL · NOTHING WRITTEN'
