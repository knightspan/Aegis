import { test } from 'node:test'
import assert from 'node:assert/strict'

import { fileOutcome } from '../src/lib/fileOutcome.ts'

test('a completed erase is erased: there is no simulated outcome', () => {
  assert.equal(fileOutcome({ ok: true, error_kind: null }).word, 'erased')
})

test('an erase that started and failed partway is never "not attempted"', () => {
  const outcome = fileOutcome({ ok: false, error_kind: 'EIO', attempted: true })
  assert.match(outcome.word, /failed partway/)
  assert.match(outcome.word, /EIO/)
  assert.equal(outcome.tone, 'destructive')
  assert.equal(outcome.residual, 'INCOMPLETE')
  assert.doesNotMatch(outcome.basis, /not attempted/)
  assert.match(outcome.basis, /started/)
})

test('a path refused before any step ran says so', () => {
  const outcome = fileOutcome({
    ok: false,
   
    error_kind: 'REPARSE_POINT_REFUSED',
    attempted: false,
  })
  assert.equal(outcome.word, 'REPARSE_POINT_REFUSED')
  assert.equal(outcome.residual, 'NOT RUN')
  assert.match(outcome.basis, /before any erase step ran/)
})

test('a failure from a server that does not record the attempt is unknown, not "not attempted"', () => {
  const outcome = fileOutcome({ ok: false, error_kind: 'EACCES' })
  assert.equal(outcome.residual, 'UNKNOWN')
  assert.doesNotMatch(outcome.basis, /not attempted/)
})
