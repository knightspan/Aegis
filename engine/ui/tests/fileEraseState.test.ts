import { test } from 'node:test'
import assert from 'node:assert/strict'

import type { JobStatus } from '../src/lib/api.ts'
import { fileEraseState } from '../src/lib/fileEraseState.ts'
import type { FileEraseFacts } from '../src/lib/fileEraseState.ts'

function facts(overrides: Partial<FileEraseFacts> = {}): FileEraseFacts {
  return {
    queued: 2,
    confirmed: false,
    started: false,
    phase: null,
    status: null,
    refusal: null,
    ...overrides,
  }
}

function done(state: string, records: { ok: boolean }[] = [], error: string | null = null): JobStatus {
  return { state, params: {}, result: { records }, error } as unknown as JobStatus
}

test('an empty queue has no state to show', () => {
  assert.equal(fileEraseState(facts({ queued: 0 })), null)
})

test('queued paths are PLANNED until confirmed, then AUTHORIZED', () => {
  assert.equal(fileEraseState(facts())?.state, 'PLANNED')
  assert.match(fileEraseState(facts())?.detail ?? '', /Nothing is written until you confirm/)
  assert.equal(fileEraseState(facts({ confirmed: true }))?.state, 'AUTHORIZED')
})

test('EXECUTING and VERIFYING come only from a job that exists', () => {
  assert.notEqual(fileEraseState(facts({ confirmed: true }))?.state, 'EXECUTING')
  assert.equal(fileEraseState(facts({ started: true, phase: 'OVERWRITE' }))?.state, 'EXECUTING')
  assert.equal(fileEraseState(facts({ started: true, phase: 'RESIDUAL' }))?.state, 'VERIFYING')
  assert.equal(fileEraseState(facts({ started: true, phase: 'VERIFY' }))?.state, 'VERIFYING')
})

test('COMPLETE only when every path was erased; otherwise FAILED, never a partial success', () => {
  const all = fileEraseState(facts({ started: true, status: done('complete', [{ ok: true }, { ok: true }]) }))
  assert.equal(all?.state, 'COMPLETE')
  const some = fileEraseState(facts({ started: true, status: done('complete', [{ ok: true }, { ok: false }]) }))
  assert.equal(some?.state, 'FAILED')
  assert.match(some?.detail ?? '', /1 of 2/)
  const crashed = fileEraseState(facts({ started: true, status: done('failed', [], 'disk went away') }))
  assert.equal(crashed?.state, 'FAILED')
  assert.match(crashed?.detail ?? '', /disk went away/)
})

test('a server refusal before any job is BLOCKED and says nothing was touched', () => {
  const blocked = fileEraseState(facts({ refusal: 'Refusing to erase: confirm was not set.' }))
  assert.equal(blocked?.state, 'BLOCKED')
  assert.match(blocked?.detail ?? '', /Nothing was touched/)
})

test('no state names a rehearsal', () => {
  const states = [
    facts(),
    facts({ confirmed: true }),
    facts({ started: true }),
    facts({ started: true, status: done('complete', [{ ok: true }]) }),
  ].map((item) => fileEraseState(item))
  for (const state of states) assert.doesNotMatch(JSON.stringify(state), /dry|simulat/i)
})
