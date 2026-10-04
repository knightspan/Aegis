/**
 * Where a file erase is, in the words the screen shows.
 *
 * Every erase this screen starts is real: the paths are overwritten, renamed
 * and unlinked. The state is derived from what exists - a queue, the operator's
 * confirmation, a job and its terminal status - and never from a guess:
 *
 *   PLANNED -> AUTHORIZED -> EXECUTING -> VERIFYING -> COMPLETE
 *
 * with BLOCKED when the server refused before a job existed and FAILED when a
 * job ended without completing, or completed with a path it could not erase.
 * Nothing here is an intermediate success: EXECUTING and later are only
 * derived from a job that exists.
 *
 * Kept free of React so `node --test` can run it: see ui/tests/fileEraseState.test.ts.
 */
import type { FileEraseRecord, JobStatus } from './api'

export type FileEraseStateName =
  | 'PLANNED'
  | 'AUTHORIZED'
  | 'EXECUTING'
  | 'VERIFYING'
  | 'COMPLETE'
  | 'FAILED'
  | 'BLOCKED'

export interface FileEraseFacts {
  /** Paths in the queue. */
  queued: number
  /** The operator ticked the confirmation. */
  confirmed: boolean
  /** A job id exists. */
  started: boolean
  /** The latest progress phase the job reported, if any. */
  phase: string | null
  /** The job's terminal status, once it has one. */
  status: JobStatus | null
  /** The server's refusal of the request, when no job was created. */
  refusal: string | null
}

export interface FileEraseState {
  state: FileEraseStateName
  /** One sentence on what the state means and what happens next. */
  detail: string
}

/** Phases after the last write: the residual scan and the physical read-back. */
const CHECKING_PHASES: ReadonlySet<string> = new Set(['RESIDUAL', 'VERIFY'])

export function fileEraseState(facts: FileEraseFacts): FileEraseState | null {
  const status = facts.status
  if (status && status.state !== 'running') {
    if (status.state !== 'complete') {
      return {
        state: 'FAILED',
        detail:
          (status.error || `The job ended ${status.state}.`) +
          ' Paths it reached may be partly overwritten; each is listed with what it reached.',
      }
    }
    const records = (status.result?.records ?? []) as FileEraseRecord[]
    const failed = records.filter((record) => !record.ok).length
    if (failed) {
      return {
        state: 'FAILED',
        detail: `${failed} of ${records.length} path(s) could not be erased. Each one is listed with why.`,
      }
    }
    return {
      state: 'COMPLETE',
      detail: 'Every path was erased. Read the residual findings: they list what the filesystem kept anyway.',
    }
  }
  if (facts.started) {
    if (facts.phase && CHECKING_PHASES.has(facts.phase)) {
      return { state: 'VERIFYING', detail: 'Writing is done; checking what survived.' }
    }
    return { state: 'EXECUTING', detail: 'Overwriting, renaming and unlinking the paths now.' }
  }
  if (facts.refusal) {
    return { state: 'BLOCKED', detail: `${facts.refusal} Nothing was touched.` }
  }
  if (!facts.queued) return null
  if (!facts.confirmed) {
    return {
      state: 'PLANNED',
      detail: `${facts.queued} path(s) queued. Nothing is written until you confirm.`,
    }
  }
  return {
    state: 'AUTHORIZED',
    detail: `${facts.queued} path(s) will be permanently erased when you press Erase.`,
  }
}
