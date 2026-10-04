import { test } from 'node:test'
import assert from 'node:assert/strict'

import type { Device } from '../src/lib/api.ts'
import { localToIso, mediaTypeOf, missingFields } from '../src/lib/destroy.ts'

const device: Device = {
  path: '/dev/sdz',
  model: 'Cruzer',
  serial: 'SYN-1',
  size_bytes: 1,
  rotational: false,
  transport: 'usb',
  is_system_disk: false,
  mounted_at: [],
  pt_type: null,
  by_id_path: null,
}

test('a detected device suggests its media type', () => {
  assert.equal(mediaTypeOf(device), 'USB')
  assert.equal(mediaTypeOf({ ...device, transport: 'sata', rotational: true }), 'HDD')
  assert.equal(mediaTypeOf({ ...device, transport: 'nvme' }), 'SSD')
})

test('the missing fields are named in words', () => {
  const draft = {
    serial: '',
    reason: 'failed',
    performedBy: '',
    performedAt: '',
    technique: 'OTHER' as const,
    techniqueDetail: '',
  }
  assert.deepEqual(missingFields(draft), [
    'serial number',
    'who destroyed it',
    'when it was destroyed',
    'what the other technique was',
  ])
})

test('a local date and time keeps its own offset', () => {
  // getTimezoneOffset() is -330 in India: UTC+05:30.
  assert.equal(localToIso('2026-09-24T15:30', -330), '2026-09-24T15:30:00+05:30')
  assert.equal(localToIso('2026-09-24T15:30', 0), '2026-09-24T15:30:00+00:00')
  assert.equal(localToIso('2026-09-24T15:30', 240), '2026-09-24T15:30:00-04:00')
  assert.equal(localToIso('', 0), '')
})
