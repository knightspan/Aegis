import { test } from 'node:test'
import assert from 'node:assert/strict'

import type { TraceRecord, TraceSweep } from '../src/lib/api.ts'
import { traceKind, traceOutcome, traceSummary } from '../src/lib/traces.ts'

function trace(overrides: Partial<TraceRecord> = {}): TraceRecord {
  return {
    kind: 'THUMBNAIL',
    target: '/home/asha/plan.jpg',
    location: '/home/asha/.cache/thumbnails/normal/0f3a.png',
    evidence: 'Named by the MD5 of file:///home/asha/plan.jpg.',
    content_copy: true,
    exact: true,
    action: '',
    removed: false,
    bytes_overwritten: 0,
    error: '',
    ...overrides,
  }
}

function sweep(traces: TraceRecord[]): TraceSweep {
  return { searched: ['a', 'b', 'c'], not_searched: [], traces, notes: [] }
}

test('kinds read as words, and an unknown kind keeps its name', () => {
  assert.equal(traceKind('TRASH_COPY'), 'Copy in the Trash')
  assert.equal(traceKind('SOMETHING_NEW'), 'SOMETHING_NEW')
})

test('a removed trace says how it was removed', () => {
  assert.deepEqual(traceOutcome(trace({ removed: true, action: 'erased' })), {
    word: 'erased',
    tone: 'success',
  })
})

test('an inexact match is never called removable', () => {
  assert.equal(traceOutcome(trace({ exact: false })).word, 'left for you to judge')
})

test('an exact trace that was not removed says so; nothing is promised', () => {
  assert.deepEqual(traceOutcome(trace()), { word: 'not removed', tone: 'warning' })
})

test('a failure is shown as one', () => {
  assert.deepEqual(traceOutcome(trace({ error: 'EACCES' })), {
    word: 'not removed',
    tone: 'destructive',
  })
})

test('the summary counts what was found, removed and left', () => {
  assert.equal(traceSummary(sweep([])), 'Nothing found in the 3 places searched.')
  assert.equal(
    traceSummary(sweep([trace({ removed: true }), trace({ exact: false })])),
    '2 found, 1 removed, 1 left.',
  )
})

test('a trace tied on evidence but held in a daemon-owned file is reported, not removed', () => {
  const reported = trace({
    kind: 'QUICKLOOK_THUMBNAIL',
    report_only: true,
    report_only_reason: 'The Quick Look cache is a shared database owned by a system daemon.',
  })
  assert.equal(traceKind('JUMP_LIST_ENTRY'), 'Jump-list entry')
  assert.deepEqual(traceOutcome(reported), { word: 'reported, not edited', tone: 'warning' })
  assert.equal(traceSummary(sweep([trace({ removed: true }), reported])), '2 found, 1 removed, 1 left.')
})
