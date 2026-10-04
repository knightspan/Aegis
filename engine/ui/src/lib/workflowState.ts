/**
 * The Sanitize screen's position in the destructive-workflow state machine.
 *
 * The names are the ones `core/workflow.py` defines, so the screen, the plan
 * JSON and the documentation use one word for one state. This function derives
 * the state from what the screen already holds - the server's assessment, the
 * engine's plan, the confirmation dialog and the job's own status - and never
 * from a guess. It decides nothing: the server re-checks every gate when a job
 * starts, whatever this returns.
 *
 * There is one path, and it is a real operation on the selected device. There
 * is no rehearsal mode: every job this screen starts writes to the device once
 * the server's gates pass. The rule that keeps it honest:
 *
 * - EXECUTING and later are only derived from a job that exists. A dialog that
 *   is open, or a button that is enabled, is never shown as execution.
 *
 * The server verifies a backup image when the workflow opens
 * (POST /workflow/erase-drive) and the helper re-checks it before the engine
 * starts, so REAL_ERASE_PATH draws BACKUP_VERIFIED. The physical benchmark
 * write in `scripts/media_benchmark.py` has its own backup gate on top.
 */
import type { DeviceAssessment, JobStatus } from './api'
import { isSafetyRefusal } from './refusal.ts'

export type WorkflowStateName =
  | 'DISCOVERED'
  | 'PREFLIGHT'
  | 'BLOCKED'
  | 'BACKUP_REQUIRED'
  | 'BACKUP_VERIFIED'
  | 'PLAN_READY'
  | 'HUMAN_APPROVAL_REQUIRED'
  | 'EXECUTING'
  | 'VERIFYING'
  | 'COMPLETE'
  | 'FAILED'

/**
 * The happy path of a real erase. The states and their order are
 * `core/workflow.py`'s: the server derives HUMAN_APPROVAL_REQUIRED until a
 * person approves, and PLAN_READY only once an approval is recorded.
 */
export const REAL_ERASE_PATH: readonly WorkflowStateName[] = [
  'DISCOVERED',
  'PREFLIGHT',
  'BACKUP_VERIFIED',
  'HUMAN_APPROVAL_REQUIRED',
  'PLAN_READY',
  'EXECUTING',
  'VERIFYING',
  'COMPLETE',
]

export const BACKUP_NOTE =
  'Every erase needs a backup image the server has hashed and sized, and a ' +
  'recorded approval; the server enforces both (POST /workflow/erase-drive, ' +
  'then /approve). Neither proves the image is a copy of this device or who ' +
  'approved.'

/** What the server's workflow endpoint reported, verbatim. */
export interface ServerWorkflow {
  state: string
  why_blocked: string[]
  next_action: string
}

/** A 409 REFUSED from the server, verbatim. */
export interface ServerRefusal {
  message: string
  whyBlocked: string[]
  workflowState: string
  physicalDeviceModified: boolean | null
}

export interface SanitizeFacts {
  assessment: DeviceAssessment | null
  /** The assessment and the engine agree a method is runnable. */
  offered: boolean
  /** The engine's plan for the chosen level is runnable. */
  canRun: boolean
  /** The engine's refusal for the chosen level, when it has one. */
  planRefusal: string
  /** The serial-confirmation dialog is open. */
  confirming: boolean
  /** A job id exists and no terminal status has arrived. */
  running: boolean
  /** The latest progress phase the job reported, if any. */
  phase: string | null
  /** The job's terminal status, once it has one. */
  status: JobStatus | null
  /** The server's workflow record for a real erase, once one is open. */
  server?: ServerWorkflow | null
  /** The server's refusal of a real erase, until the operator acts again. */
  refusal?: ServerRefusal | null
}

export interface SanitizeWorkflow {
  state: WorkflowStateName
  /** The label shown for the state. */
  headline: string
  /** Empty unless the state is BLOCKED or FAILED. */
  whyBlocked: string[]
  nextAction: string
  /** The states drawn in the strip, with BLOCKED or FAILED placed where reached. */
  path: WorkflowStateName[]
}

function label(state: WorkflowStateName): string {
  return state.replace(/_/g, ' ')
}

function pathFor(state: WorkflowStateName): WorkflowStateName[] {
  if (state === 'BLOCKED') return ['DISCOVERED', 'PREFLIGHT', 'BLOCKED']
  if (state === 'BACKUP_REQUIRED') return ['DISCOVERED', 'PREFLIGHT', 'BACKUP_REQUIRED']
  if (state === 'FAILED') return ['DISCOVERED', 'PREFLIGHT', 'HUMAN_APPROVAL_REQUIRED', 'EXECUTING', 'FAILED']
  return [...REAL_ERASE_PATH]
}

const STATE_NAMES: ReadonlySet<string> = new Set<WorkflowStateName>([
  'DISCOVERED',
  'PREFLIGHT',
  'BLOCKED',
  'BACKUP_REQUIRED',
  'BACKUP_VERIFIED',
  'PLAN_READY',
  'HUMAN_APPROVAL_REQUIRED',
  'EXECUTING',
  'VERIFYING',
  'COMPLETE',
  'FAILED',
])

function isStateName(value: string): value is WorkflowStateName {
  return STATE_NAMES.has(value)
}

function result(
  state: WorkflowStateName,
  nextAction: string,
  whyBlocked: string[] = [],
): SanitizeWorkflow {
  return {
    state,
    headline: label(state),
    whyBlocked,
    nextAction,
    path: pathFor(state),
  }
}

/** Every reason the preflight gives for refusing, in the server's own words. */
function refusals(facts: SanitizeFacts): string[] {
  const reasons: string[] = []
  const assessment = facts.assessment
  if (assessment && assessment.headline === 'NOT AVAILABLE') {
    reasons.push(assessment.reason)
  }
  for (const check of assessment?.safety_checks ?? []) {
    if (check.passed === false) reasons.push(`${check.label}: ${check.detail}`)
  }
  if (!facts.offered || !facts.canRun) {
    reasons.push(facts.planRefusal || 'No sanitization method is reachable on this device.')
  }
  return [...new Set(reasons.filter(Boolean))]
}

export function sanitizeWorkflow(facts: SanitizeFacts): SanitizeWorkflow {
  const status = facts.status

  if (status && status.state !== 'running') {
    if (status.state === 'complete') {
      // "The job returned" is not "the medium was sanitized". The engine ends a
      // job normally even when the read-back failed, so COMPLETE is only shown
      // when verification did not fail, and says so when it settled nothing.
      const verification = status.result?.verification as
        | { passed: boolean | null; failed_offsets?: number[] }
        | undefined
      if (verification?.passed === false) {
        return result(
          'FAILED',
          'The medium is NOT sanitized. Read the verification panel; the device is in an unknown state until checked.',
          [
            `read-back verification FAILED at ${verification.failed_offsets?.length ?? 0} sampled offset(s)`,
          ],
        )
      }
      return result(
        'COMPLETE',
        verification?.passed === true
          ? 'Read the verification and the residual risk before relying on the result.'
          : 'The run finished but verification did not confirm it (inconclusive or not attempted). Do not treat the medium as verified sanitized; read the residual risk.',
      )
    }
    if (isSafetyRefusal(status.error_kind)) {
      // The helper re-checked the authorization at the write seam and refused
      // before entering the engine. That is a refusal, not a failed erase.
      return result(
        'BLOCKED',
        'The helper refused at the write seam, before any write. The authorization is spent: open a new workflow.',
        [status.error || 'The helper refused the authorization.'],
      )
    }
    const why = status.error || `The job ended ${status.state}.`
    return result(
      'FAILED',
      'The device is in an unknown state until checked. Read the failure.',
      [why],
    )
  }

  if (facts.running) {
    if (facts.phase === 'VERIFY') {
      return result('VERIFYING', 'Wait for read-back verification to finish.')
    }
    return result(
      'EXECUTING',
      'Wait for the operation to finish. Do not disconnect the device.',
    )
  }

  if (facts.refusal) {
    // The server refused. Say so in its words; never a generic failure.
    const refusal = facts.refusal
    return result(
      'BLOCKED',
      `The server refused at ${refusal.workflowState || 'the workflow gate'}. ` +
        (refusal.physicalDeviceModified === false
          ? 'PHYSICAL DEVICE MODIFIED: FALSE'
          : 'Check the device before trusting it.'),
      refusal.whyBlocked.length ? refusal.whyBlocked : [refusal.message],
    )
  }

  if (facts.server && isStateName(facts.server.state)) {
    // The state is the server's own, from core/workflow.py:derive. This screen
    // names it and decides nothing.
    const state = facts.server.state
    const stopped = state === 'BLOCKED' || state === 'BACKUP_REQUIRED'
    return result(state, facts.server.next_action, stopped ? facts.server.why_blocked : [])
  }

  if (!facts.assessment) {
    return result('DISCOVERED', 'Waiting for the server preflight of this device.')
  }

  const reasons = refusals(facts)
  if (reasons.length) {
    return result(
      'BLOCKED',
      facts.assessment.recommended_action ||
        'Resolve every reason listed by hand, then rescan. Nothing here unmounts, elevates or retries on its own.',
      reasons,
    )
  }
  if (facts.assessment.headline === 'NOT AUTHORIZED') {
    return result('BLOCKED', facts.assessment.recommended_action, [facts.assessment.reason])
  }

  return result(
    'HUMAN_APPROVAL_REQUIRED',
    facts.confirming
      ? 'Give a backup image, open the workflow, then approve with the typed serial. The server re-reads the device and refuses a mismatch.'
      : 'Nothing is written until a verified backup exists and a person approves with the typed serial.',
  )
}

/** The fields of a failed request this module reads; `RequestFailed` has them. */
interface FailedRequest {
  message: string
  remediation: string
  whyBlocked: string[]
  workflowState: string
  physicalDeviceModified: boolean | null
}

/**
 * A refusal to show, from a failed workflow or execution request.
 *
 * `noWritePath` is for the open and approve calls: neither can reach a device
 * write, so a refusal there modified nothing whether or not the body says so.
 * The execution call's own `physical_device_modified` is never overridden.
 */
export function refusalFrom(failure: FailedRequest, noWritePath = false): ServerRefusal {
  const why = failure.whyBlocked.length
    ? failure.whyBlocked
    : [failure.message, failure.remediation].filter(Boolean)
  return {
    message: failure.message,
    whyBlocked: why,
    workflowState: failure.workflowState,
    physicalDeviceModified: failure.physicalDeviceModified ?? (noWritePath ? false : null),
  }
}

/** How the signed report of a finished job is named on this screen. */
export interface SignedRecordWording {
  title: string
  action: string
  issued: string
  tone: 'success' | 'warning'
  note: string
}

/**
 * Only a completed job gets a certificate.
 *
 * A failed, refused or cancelled job still gets a signed record - the audit
 * trail needs one - but calling that a certificate would put the word next to
 * a sanitization that did not happen. A job that ran to the end but whose
 * read-back FAILED gets the same signed record, never a certificate.
 */
export function signedRecordWording(
  state: string,
  readBackFailed = false,
): SignedRecordWording {
  if (state === 'complete' && readBackFailed) {
    return {
      title: 'Signed record',
      action: 'Get signed record',
      issued: 'Signed record issued - not a sanitization certificate',
      tone: 'warning',
      note:
        'The erase ran, but read-back verification FAILED. The signed record documents ' +
        'what happened; it is not a sanitization certificate.',
    }
  }
  if (state === 'complete') {
    return {
      title: 'Certificate',
      action: 'Get certificate',
      issued: 'Certificate issued',
      tone: 'success',
      note: 'The certificate records what ran, how it was verified, and what it could not claim.',
    }
  }
  return {
    title: 'Signed record',
    action: 'Get signed record',
    issued: 'Signed record issued - not a sanitization certificate',
    tone: 'warning',
    note:
      `This job did not complete (${state || 'no terminal state'}). The signed record ` +
      'documents what happened and what it could not claim; it is not a sanitization certificate.',
  }
}
