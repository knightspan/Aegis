import { test } from 'node:test'
import assert from 'node:assert/strict'

import type { MediaMap, MediaRegion } from '../src/lib/api.ts'
import {
  contentBytes,
  describeRegion,
  kindName,
  sharePercent,
} from '../src/lib/mediaMap.ts'

const map: MediaMap = {
  size_bytes: 1000,
  region_bytes: 250,
  block_bytes: 4096,
  sampled: false,
  bytes_read: 1000,
  regions: [],
  by_kind: { ZERO: 600, FILL: 200, TEXT: 0, STRUCTURED: 195, HIGH_ENTROPY: 5 },
  headers: {},
  limitations: [],
}

test('classes read as words, and an unknown one keeps its name', () => {
  assert.equal(kindName('HIGH_ENTROPY'), 'High entropy')
  assert.equal(kindName('NEW_CLASS'), 'NEW_CLASS')
})

test('a small share is shown as under one percent, never as zero', () => {
  assert.equal(sharePercent(map, 'ZERO'), '60%')
  assert.equal(sharePercent(map, 'HIGH_ENTROPY'), '<1%')
  assert.equal(sharePercent(map, 'TEXT'), '0%')
})

test('content bytes leave out what is zeroed or filled', () => {
  assert.equal(contentBytes(map), 200)
})

test('a region is described by where it is, what it is and how sure', () => {
  const region: MediaRegion = {
    offset: 4096,
    length: 4096,
    kind: 'FILL',
    share_bp: 9_950,
    entropy_mb: 0,
    fill_byte: 0xa5,
    headers: { jpg: 2 },
    bytes_read: 4096,
    substituted: false,
  }
  const line = describeRegion(region)
  assert.match(line, /^0x1000 to 0x2000/)
  assert.match(line, /Fill pattern in 99% of the blocks read/)
  assert.match(line, /fill byte 0xA5/)
  assert.match(line, /headers: 2 jpg/)
})
