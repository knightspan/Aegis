import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  matchesPii,
  piiSummary,
  piiTotal,
  sortByPii,
} from '../src/lib/triage.ts'
import type { CarveCandidate, PiiFindings } from '../src/lib/api.ts'

function candidate(offset: number, pii?: PiiFindings): CarveCandidate {
  return {
    offset,
    length: 10,
    ext: 'docx',
    mime: '',
    source: 'fs_metadata',
    validation: 'valid',
    confidence_bp: 9000,
    bucket: 'HIGH',
    sha256: '',
    original_name: null,
    possibly_fragmented: false,
    fragments: [],
    validation_detail: '',
    entropy_millibits_per_byte: null,
    high_entropy_windows_bp: null,
    score_components: {},
    overlapped: false,
    overlaps_with: null,
    category: 'document',
    flags: {
      has_exif_gps: false,
      is_password_protected: false,
      is_encrypted: false,
      contains_macros: false,
      has_embedded_files: false,
      is_signed: false,
      inspected: true,
    },
    pii,
    duplicate_offsets: [],
    fs_type: '',
    contiguity_assumed: false,
    contiguity_contradicted: false,
  }
}

const RESUME = candidate(300, {
  inspected: true,
  basis: 'Text of 9 XML parts, tags removed',
  counts: { aadhaar: 1, pan: 1, payment_card: 1 },
})
const LEDGER = candidate(100, {
  inspected: true,
  basis: 'Raw bytes, as ASCII/UTF-8',
  counts: { email: 4 },
})
const CLEAN = candidate(50, { inspected: true, basis: 'Raw bytes', counts: {} })
const PHOTO = candidate(10, { inspected: false, basis: 'Not scanned: image content.', counts: {} })
const OLD = candidate(5)

test('the summary is kinds and counts, and says when nothing was scanned', () => {
  assert.equal(piiSummary(RESUME), 'Aadhaar 1 · PAN 1 · Card 1')
  assert.equal(piiSummary(CLEAN), 'none seen')
  assert.equal(piiSummary(PHOTO), 'not scanned')
  assert.equal(piiSummary(OLD), 'not scanned')
})

test('totals and filters', () => {
  assert.equal(piiTotal(RESUME), 3)
  assert.equal(piiTotal(OLD), 0)
  assert.ok(matchesPii(LEDGER, 'any'))
  assert.ok(!matchesPii(CLEAN, 'any'))
  assert.ok(matchesPii(RESUME, 'aadhaar'))
  assert.ok(!matchesPii(LEDGER, 'aadhaar'))
  assert.ok(matchesPii(PHOTO, ''))
})

test('sorting puts the most identifiers first, then kinds, then offset', () => {
  const two = candidate(400, { inspected: true, basis: '', counts: { pan: 2, ifsc: 1 } })
  const order = sortByPii([PHOTO, CLEAN, LEDGER, RESUME, two, OLD]).map((c) => c.offset)
  assert.deepEqual(order, [100, 300, 400, 5, 10, 50])
})
