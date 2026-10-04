import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  checkWord,
  currentStep,
  deviceKind,
  headlineTone,
  offeredOption,
  readBack,
  runnableStatus,
  STATUS_MEANINGS,
  statusWord,
} from '../src/lib/platform.ts'
import type { DeviceAssessment, NormalizedDevice } from '../src/lib/api.ts'

const base: NormalizedDevice = {
  id: 'PhysicalDrive2',
  platform: 'windows',
  path: '\\\\.\\PhysicalDrive2',
  vendor: 'Kingston',
  model: 'DataTraveler',
  serial: 'S',
  capacity_bytes: 1,
  interface: 'usb',
  media_type: 'flash',
  media_basis: '',
  removable: true,
  mounted: false,
  mount_points: [],
  system_device: false,
  system_reasons: [],
  filesystems: [],
  partitions: [],
  stable_id: '',
  limitations: [],
}

test('only supported statuses are runnable', () => {
  assert.equal(runnableStatus('SUPPORTED'), true)
  assert.equal(runnableStatus('SUPPORTED_WITH_LIMITATIONS'), true)
  for (const s of ['UNSUPPORTED', 'UNVERIFIED', 'NOT_AUTHORIZED', 'INCONCLUSIVE'] as const) {
    assert.equal(runnableStatus(s), false, s)
  }
  assert.equal(runnableStatus(undefined), false)
})

test('unverified is never drawn as success', () => {
  assert.notEqual(statusWord('UNVERIFIED').tone, 'success')
  assert.notEqual(statusWord('SUPPORTED_WITH_LIMITATIONS').tone, 'success')
  assert.equal(statusWord('UNSUPPORTED').tone, 'destructive')
})

test('an undecided safety check is not a pass', () => {
  assert.equal(checkWord({ key: 'k', label: 'l', passed: null, detail: '' }).word, 'unknown')
  assert.equal(checkWord({ key: 'k', label: 'l', passed: false, detail: '' }).tone, 'destructive')
})

test('device kind reads without storage vocabulary', () => {
  assert.equal(deviceKind(base), 'External USB Flash')
  assert.equal(
    deviceKind({ ...base, removable: false, interface: 'nvme', media_type: 'ssd' }),
    'Internal NVMe SSD',
  )
})

test('the step follows the flow', () => {
  const s = {
    hasDevice: true,
    hasAssessment: true,
    reviewing: false,
    confirming: false,
    running: false,
    finished: false,
    verified: false,
    certified: false,
  }
  assert.equal(currentStep({ ...s, hasDevice: false }), 0)
  assert.equal(currentStep(s), 2)
  assert.equal(currentStep({ ...s, reviewing: true }), 3)
  assert.equal(currentStep({ ...s, running: true }), 5)
  assert.equal(currentStep({ ...s, finished: true }), 6)
  assert.equal(currentStep({ ...s, finished: true, verified: true }), 7)
})

test('a stopped flow stays where it stopped, and never reaches Verify', () => {
  const s = {
    hasDevice: true,
    hasAssessment: true,
    reviewing: true,
    confirming: false,
    running: false,
    finished: false,
    verified: false,
    certified: false,
  }
  // Refused at the API gate: no job, the modal may already be closed.
  assert.equal(currentStep({ ...s, refused: true }), 4)
  // Refused by the helper, failed or cancelled: the job ended at Sanitize.
  assert.equal(currentStep({ ...s, finished: true, failed: true }), 5)
  assert.equal(currentStep({ ...s, finished: true, failed: true, verified: true }), 5)
})

test('a verification object that FAILED never advances past Verify', () => {
  const s = {
    hasDevice: true,
    hasAssessment: true,
    reviewing: false,
    confirming: false,
    running: false,
    finished: true,
    verified: false,
    certified: false,
  }
  // The object exists and says the read-back failed.
  const failedReadBack = readBack({ passed: false })
  assert.deepEqual(failedReadBack, { verified: false, verifyFailed: true })
  assert.equal(currentStep({ ...s, ...failedReadBack }), 6)
  // Even with a signed record in hand, a failed read-back is not a certificate step.
  assert.equal(currentStep({ ...s, ...failedReadBack, certified: true }), 6)
  // Inconclusive is not a pass either: the tracker waits on Verify.
  assert.deepEqual(readBack({ passed: null }), { verified: false, verifyFailed: false })
  assert.equal(currentStep({ ...s, ...readBack({ passed: null }) }), 6)
  assert.equal(currentStep({ ...s, ...readBack(null) }), 6)
  // Only a passed read-back progresses: no verification is never a pass.
  assert.equal(currentStep({ ...s, ...readBack({ passed: true }) }), 7)
})

test('an UNVERIFIED option with a method is offered; one without is not', () => {
  assert.equal(offeredOption({ status: 'UNVERIFIED', method: 'ATA_SANITIZE_BLOCK_ERASE' }), true)
  assert.equal(offeredOption({ status: 'UNVERIFIED', method: null }), false)
  assert.equal(offeredOption({ status: 'SUPPORTED', method: 'SINGLE_PASS_OVERWRITE' }), true)
  assert.equal(offeredOption({ status: 'UNSUPPORTED', method: 'X' }), false)
  assert.equal(offeredOption(null), false)
})

test('headline tone', () => {
  const a = { headline: 'NOT AVAILABLE', status: 'UNSUPPORTED' } as DeviceAssessment
  assert.equal(headlineTone(a), 'destructive')
  assert.equal(headlineTone({ ...a, headline: 'READY', status: 'SUPPORTED' }), 'success')
  assert.equal(headlineTone(null), 'unknown')
})

test('the legend explains every status once, and none of them as a pass it is not', () => {
  const statuses = STATUS_MEANINGS.map((row) => row.status)
  assert.equal(new Set(statuses).size, 7)
  for (const status of [
    'SUPPORTED',
    'SUPPORTED_WITH_LIMITATIONS',
    'NOT_AUTHORIZED',
    'NOT_VERIFIABLE',
    'UNVERIFIED',
    'INCONCLUSIVE',
    'UNSUPPORTED',
  ] as const) {
    assert.ok(statuses.includes(status), status)
  }
  const unverified = STATUS_MEANINGS.find((row) => row.status === 'UNVERIFIED')
  assert.match(unverified?.meaning ?? '', /Not a claim that it works/)
  assert.equal(statusWord('UNVERIFIED').tone, 'unknown')
})
