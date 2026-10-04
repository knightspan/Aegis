/**
 * Which job failures are safety refusals, read from the job's structured
 * `error_kind`, never from its message.
 *
 * `WorkflowGateRefused` is raised by the privileged helper when its re-check
 * of the authorization fails at the write seam, before the engine is entered:
 * nothing was written. Every screen that labels a finished job (Sanitize,
 * Cases, the overview) asks this module, so a refusal is BLOCKED everywhere
 * and never a failed or partial erase anywhere.
 */

export const SAFETY_REFUSAL_KINDS: ReadonlySet<string> = new Set(['WorkflowGateRefused'])

export function isSafetyRefusal(errorKind: string | null | undefined): boolean {
  return Boolean(errorKind) && SAFETY_REFUSAL_KINDS.has(errorKind as string)
}
