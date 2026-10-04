/**
 * A carve candidate's evidence score must never render as a percentage.
 *
 * The number is a clamped sum of evidence components, and the screen used to
 * print it as "100.00%" beside the word HIGH. That reads as a probability of
 * correctness, which nothing in the calibration establishes: what was measured
 * is a bucket's precision on a synthetic population. These tests pin the two
 * formatters apart, because the erase path has a `confidence_bp` of its own
 * that genuinely *is* a probability and must keep its percent sign.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { evidenceScore, percent } from '../src/lib/format.ts'

test('an evidence score is rendered against its denominator, never as a percent', () => {
  assert.equal(evidenceScore(9500), '9500 / 10000')
  assert.ok(!evidenceScore(9500).includes('%'))
})

test('a clamped total reads as the clamp, not as certainty', () => {
  // header 2000 + exact_length 1500 + decoder 4000 + entropy 1000 +
  // fs_metadata 1500 + no_overlap 500 = 10500, clamped to 10000. The old
  // rendering turned that into "100.00%".
  assert.equal(evidenceScore(10000), '10000 / 10000')
  assert.ok(!evidenceScore(10000).includes('100.00%'))
})

test('the reassembly ceiling stays visibly one point under the HIGH floor', () => {
  // 7999 must not round to anything that reads as 80% beside MEDIUM.
  assert.equal(evidenceScore(7999), '7999 / 10000')
})

test('a bucket boundary is exact in the rendering, not rounded', () => {
  assert.equal(evidenceScore(8000), '8000 / 10000')
  assert.equal(evidenceScore(5000), '5000 / 10000')
  assert.equal(evidenceScore(4999), '4999 / 10000')
})

test('percent still formats the quantities that really are proportions', () => {
  // Post-erase detection probability, and the share of high-entropy windows.
  assert.equal(percent(10000, 2), '100.00%')
  assert.equal(percent(9940, 2), '99.40%')
  assert.equal(percent(6000), '60.0%')
})
