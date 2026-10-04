/**
 * A guard against a stale response overwriting newer state.
 *
 * Every async step captures a token when it starts and applies its answer only
 * if the token is still current. Anything that invalidates the step in flight -
 * the operator closes the dialog, picks another device, changes the level or
 * the mode - calls `bump()`. Without it, a slow "open workflow" reply for
 * device A could land after the operator moved to device B and show A's plan
 * and authorization id in B's dialog.
 */
export interface Epoch {
  /** Invalidate every token issued so far, and return the new current one. */
  bump: () => number
  /** The token to capture before an async step starts. */
  current: () => number
  /** True only if nothing has invalidated `token` since it was issued. */
  isCurrent: (token: number) => boolean
}

export function createEpoch(): Epoch {
  let value = 0
  return {
    bump: () => ++value,
    current: () => value,
    isCurrent: (token) => token === value,
  }
}
