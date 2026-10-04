/**
 * A job's terminal stream event can leave before its outcome reaches the chain
 * (`settled: false`). The Sanitize screen waits for `settled`, so streamJob
 * must re-read the job until it has, or the screen stays on PLAN READY for a
 * job that already ended.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import type { JobStatus } from '../src/lib/api.ts'
import { streamJob } from '../src/lib/api.ts'

type Listener = (event: { data: string }) => void

class FakeEventSource {
  static last: FakeEventSource | null = null
  listeners = new Map<string, Listener>()
  closed = false
  url: string
  constructor(url: string) {
    this.url = url
    FakeEventSource.last = this
  }
  addEventListener(name: string, listener: Listener): void {
    this.listeners.set(name, listener)
  }
  close(): void {
    this.closed = true
  }
  emit(name: string, body: unknown): void {
    this.listeners.get(name)?.({ data: JSON.stringify(body) })
  }
}

function status(over: Partial<JobStatus>): JobStatus {
  return { job_id: 'erase-drive-1', state: 'failed', settled: true, ...over } as JobStatus
}

test('an unsettled terminal event is followed by the settled status', async () => {
  const globals = globalThis as unknown as Record<string, unknown>
  globals.EventSource = FakeEventSource
  let reads = 0
  globals.fetch = async () => {
    reads += 1
    const body = status({ settled: reads >= 2, error_kind: 'WorkflowGateRefused' })
    return { ok: true, json: async () => body } as Response
  }
  const seen: JobStatus[] = []
  streamJob('erase-drive-1', { onProgress: () => undefined, onState: (s) => seen.push(s) })
  FakeEventSource.last!.emit('state', status({ settled: false }))

  assert.equal(seen.length, 1)
  assert.equal(seen[0].settled, false)
  assert.equal(FakeEventSource.last!.closed, true)
  await new Promise((resolve) => setTimeout(resolve, 900))
  assert.equal(seen.length, 2, 'the settled status is delivered')
  assert.equal(seen[1].settled, true)
  assert.equal(seen[1].error_kind, 'WorkflowGateRefused')
})

test('a settled terminal event needs no second read, and detaching stops polling', async () => {
  const globals = globalThis as unknown as Record<string, unknown>
  globals.EventSource = FakeEventSource
  let reads = 0
  globals.fetch = async () => {
    reads += 1
    return { ok: true, json: async () => status({ settled: false }) } as Response
  }
  const seen: JobStatus[] = []
  streamJob('erase-drive-2', { onProgress: () => undefined, onState: (s) => seen.push(s) })
  FakeEventSource.last!.emit('state', status({ settled: true }))
  await new Promise((resolve) => setTimeout(resolve, 400))
  assert.equal(reads, 0)
  assert.equal(seen.length, 1)

  const detach = streamJob('erase-drive-3', { onProgress: () => undefined, onState: (s) => seen.push(s) })
  FakeEventSource.last!.emit('state', status({ settled: false }))
  detach()
  await new Promise((resolve) => setTimeout(resolve, 600))
  assert.equal(reads, 0, 'a detached screen is not polled for')
})
