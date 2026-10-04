import { test } from 'node:test'
import assert from 'node:assert/strict'

import { createEpoch } from '../src/lib/epoch.ts'

test('a token is current until something invalidates it', () => {
  const epoch = createEpoch()
  const token = epoch.current()
  assert.ok(epoch.isCurrent(token))
  epoch.bump()
  assert.equal(epoch.isCurrent(token), false)
})

test('a slow reply for an older context is dropped, a newer one applies', () => {
  const epoch = createEpoch()
  const applied: string[] = []
  const first = epoch.current()
  epoch.bump() // the operator switched device
  const second = epoch.current()
  // The second reply arrives first, then the stale first reply.
  if (epoch.isCurrent(second)) applied.push('device B plan')
  if (epoch.isCurrent(first)) applied.push('device A plan')
  assert.deepEqual(applied, ['device B plan'])
})
