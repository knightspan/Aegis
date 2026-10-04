import { test } from 'node:test'
import assert from 'node:assert/strict'

import { pickPaths, pickerAvailable } from '../src/lib/nativePicker.ts'
import type { PickerFetch } from '../src/lib/nativePicker.ts'

function answering(body: unknown, ok = true): { fetcher: PickerFetch; calls: unknown[] } {
  const calls: unknown[] = []
  const fetcher: PickerFetch = async (input, init) => {
    calls.push({ input, ...init })
    return { ok, json: async () => body }
  }
  return { fetcher, calls }
}

const failing: PickerFetch = async () => {
  throw new Error('network down')
}

test('the picker is available only when the desktop shell says so', async () => {
  assert.equal(await pickerAvailable(answering({ available: true }).fetcher), true)
  assert.equal(await pickerAvailable(answering({ available: false }).fetcher), false)
  assert.equal(await pickerAvailable(answering({}).fetcher), false)
  assert.equal(await pickerAvailable(answering({ available: true }, false).fetcher), false)
  assert.equal(await pickerAvailable(failing), false)
})

test('the chosen paths come back, and the kind is sent to the server', async () => {
  const { fetcher, calls } = answering({ paths: ['/a/one', '/a/two'] })
  assert.deepEqual(await pickPaths('files', fetcher), ['/a/one', '/a/two'])
  assert.deepEqual(calls, [
    {
      input: '/native-picker',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"kind":"files"}',
    },
  ])
})

test('a cancelled dialog is an empty list', async () => {
  assert.deepEqual(await pickPaths('file', answering({ paths: [] }).fetcher), [])
})

test('a refused request, a failure or a malformed answer is an empty list', async () => {
  assert.deepEqual(await pickPaths('folder', answering({ paths: ['/a'] }, false).fetcher), [])
  assert.deepEqual(await pickPaths('folder', failing), [])
  assert.deepEqual(await pickPaths('folder', answering({ paths: 'nope' }).fetcher), [])
  assert.deepEqual(await pickPaths('folder', answering(null).fetcher), [])
})

test('non-string and empty entries are dropped', async () => {
  const { fetcher } = answering({ paths: ['/a/one', '', 3, null, '/a/two'] })
  assert.deepEqual(await pickPaths('files', fetcher), ['/a/one', '/a/two'])
})
