import { test } from 'node:test'
import assert from 'node:assert/strict'

import { operationKind, operationLabel, shortTime } from '../src/lib/ledger.ts'

test('known operations read as sentences', () => {
  assert.equal(operationLabel('GENESIS'), 'Chain started')
  assert.equal(operationLabel('erase.approved'), 'Erase approved by the operator')
  assert.equal(operationLabel('carve.complete'), 'Recovery complete')
})

test('a dotted operation this file does not list is worded, not dropped', () => {
  assert.equal(operationLabel('erase.preflight.write_calibration'), 'Erase: preflight write calibration')
  assert.equal(operationLabel('erase.file.overwrite'), 'Erase: file overwrite')
})

test('an unknown operation keeps its own name', () => {
  assert.equal(operationLabel('something.new'), 'something.new')
  assert.equal(operationLabel('plain'), 'plain')
  assert.equal(operationKind('something.new'), 'other')
})

test('kinds group operations by module', () => {
  assert.equal(operationKind('erase.freespace.fill'), 'erase')
  assert.equal(operationKind('acquire.start'), 'recover')
  assert.equal(operationKind('report.generated'), 'report')
  assert.equal(operationKind('GENESIS'), 'chain')
})

test('times are short, and an unparseable one is shown as it came', () => {
  const now = new Date('2026-09-25T12:00:00Z')
  assert.match(shortTime('2026-09-25T07:09:44Z', now), /^\d{2}:\d{2}$/)
  assert.match(shortTime('2026-09-24T07:09:44Z', now), /Sep/)
  assert.equal(shortTime('not a time', now), 'not a time')
})
