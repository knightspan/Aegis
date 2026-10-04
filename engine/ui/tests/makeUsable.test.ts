import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  FORMAT_FILESYSTEMS,
  canStartFormat,
  formatOutcome,
  labelProblem,
  showMakeUsable,
} from '../src/lib/makeUsable.ts'

test('three filesystems are offered, exFAT first', () => {
  assert.deepEqual(
    FORMAT_FILESYSTEMS.map((fs) => fs.id),
    ['exfat', 'fat32', 'ext4'],
  )
})

test('a label is limited per filesystem, as the server limits it', () => {
  assert.equal(labelProblem('exfat', 'A'.repeat(15)), null)
  assert.match(labelProblem('exfat', 'A'.repeat(16)) ?? '', /15/)
  assert.match(labelProblem('fat32', 'A'.repeat(12)) ?? '', /11/)
  assert.match(labelProblem('ext4', 'A'.repeat(17)) ?? '', /16/)
})

test('a label with a character the server refuses is refused here too', () => {
  assert.match(labelProblem('exfat', 'bad/label') ?? '', /letters|digits/)
  assert.equal(labelProblem('exfat', 'My USB-1_x'), null)
})

test('the panel needs the server to say eligible', () => {
  assert.equal(showMakeUsable(false, { started: false, finished: false }), false)
  assert.equal(showMakeUsable(true, { started: false, finished: false }), true)
})

test('the panel is hidden while a job of this screen is still running', () => {
  assert.equal(showMakeUsable(true, { started: true, finished: false }), false)
  assert.equal(showMakeUsable(true, { started: true, finished: true }), true)
})

test('starting needs the exact serial, the acknowledgement and a valid label', () => {
  const ok = { serial: 'SYN-1', typed: 'SYN-1', acknowledged: true, filesystem: 'exfat', label: 'USB' }
  assert.equal(canStartFormat(ok), true)
  assert.equal(canStartFormat({ ...ok, typed: 'syn-1 ' }), true)
  assert.equal(canStartFormat({ ...ok, typed: 'SYN-2' }), false)
  assert.equal(canStartFormat({ ...ok, typed: '' }), false)
  assert.equal(canStartFormat({ ...ok, acknowledged: false }), false)
  assert.equal(canStartFormat({ ...ok, label: 'A'.repeat(40) }), false)
  assert.equal(canStartFormat({ ...ok, serial: '' }), false)
})

test('a verified format is success and says it is not a sanitization', () => {
  const outcome = formatOutcome('complete', {
    verified: true,
    filesystem: 'exfat',
    label: 'USB',
    limitations: ['Formatting writes a partition table.'],
  })
  assert.equal(outcome.tone, 'ok')
  assert.match(outcome.headline, /exFAT/)
  assert.deepEqual(outcome.notes, ['Formatting writes a partition table.'])
})

test('a format whose read-back did not match is never shown as success', () => {
  const outcome = formatOutcome('complete', {
    verified: false,
    filesystem: 'exfat',
    label: 'USB',
    limitations: ['read-back found filesystem ntfs'],
  })
  assert.equal(outcome.tone, 'warn')
  assert.match(outcome.headline, /not verified/i)
})

test('a failed job is shown as a failure with the reason', () => {
  const outcome = formatOutcome('failed', null, 'mkfs.exfat failed at the filesystem step')
  assert.equal(outcome.tone, 'danger')
  assert.match(outcome.notes.join(' '), /mkfs\.exfat failed/)
})
