/**
 * The verdict word is the server's, and the screen must not upgrade it.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { verdictMeaning } from '../src/lib/verdict.ts'

test('only VERIFIED is coloured as a success', () => {
  assert.equal(verdictMeaning('VERIFIED').tone, 'success')
  assert.equal(verdictMeaning('VERIFIED_WITH_LIMITATIONS').tone, 'warning')
  assert.equal(verdictMeaning('PARTIAL').tone, 'warning')
  assert.equal(verdictMeaning('FAILED_VERIFICATION').tone, 'destructive')
})

test('an unknown or missing verdict is unknown, never success', () => {
  assert.equal(verdictMeaning('VALID').tone, 'unknown')
  assert.equal(verdictMeaning(undefined).tone, 'unknown')
  assert.equal(verdictMeaning('').known, false)
})

test('a limited verdict says the report is authentic and limited', () => {
  const meaning = verdictMeaning('VERIFIED_WITH_LIMITATIONS')
  assert.ok(meaning.label.includes('authentic'))
  assert.ok(meaning.label.includes('limits'))
})
