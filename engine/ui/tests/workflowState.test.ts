import { test } from 'node:test'
import assert from 'node:assert/strict'

import type { DeviceAssessment, JobStatus, SafetyCheck } from '../src/lib/api.ts'
import {
  REAL_ERASE_PATH,
  refusalFrom,
  sanitizeWorkflow,
  signedRecordWording,
} from '../src/lib/workflowState.ts'
import type { SanitizeFacts } from '../src/lib/workflowState.ts'

function check(key: string, label: string, passed: boolean | null, detail: string): SafetyCheck {
  return { key, label, passed, detail } as SafetyCheck
}

function assessment(overrides: Partial<DeviceAssessment> = {}): DeviceAssessment {
  return {
    device_id: 'usb-stick',
    platform: 'linux',
    status: 'SUPPORTED',
    headline: 'READY',
    reason: 'Overwrite is available.',
    recommended_action: '',
    recommended: null,
    alternatives: [],
    unavailable: [],
    verification: '',
    safety_checks: [
      check('not_mounted', 'No mounted filesystem', true, 'Nothing on this device is mounted.'),
      check('privilege', 'Privilege available', true, 'helper socket'),
    ],
    flash_limitation: '',
    ...overrides,
  } as DeviceAssessment
}

function facts(overrides: Partial<SanitizeFacts> = {}): SanitizeFacts {
  return {
    assessment: assessment(),
    offered: true,
    canRun: true,
    planRefusal: '',
    confirming: false,
    running: false,
    phase: null,
    status: null,
    ...overrides,
  }
}

function job(state: string, error: string | null = null): JobStatus {
  return { state, params: {}, error } as JobStatus
}

test('the state names are the ones core/workflow.py defines, on one real path', () => {
  assert.deepEqual(REAL_ERASE_PATH, [
    'DISCOVERED',
    'PREFLIGHT',
    'BACKUP_VERIFIED',
    'HUMAN_APPROVAL_REQUIRED',
    'PLAN_READY',
    'EXECUTING',
    'VERIFYING',
    'COMPLETE',
  ])
})

test('no state or headline names a rehearsal', () => {
  const cases: Partial<SanitizeFacts>[] = [
    {},
    { confirming: true },
    { running: true, phase: 'ERASE' },
    { running: true, phase: 'VERIFY' },
    { status: job('complete') },
    { status: job('failed', 'device went away') },
  ]
  for (const overrides of cases) {
    const flow = sanitizeWorkflow(facts(overrides))
    assert.doesNotMatch(flow.headline, /DRY RUN|SIMULAT/i)
    assert.doesNotMatch(flow.nextAction, /dry run|simulat/i)
    assert.ok(!('simulation' in flow))
  }
})

test('no assessment yet is DISCOVERED, not a pass', () => {
  assert.equal(sanitizeWorkflow(facts({ assessment: null })).state, 'DISCOVERED')
})

test('a mounted device is BLOCKED with the reason and the human remedy', () => {
  const flow = sanitizeWorkflow(
    facts({
      offered: false,
      canRun: false,
      assessment: assessment({
        headline: 'NOT AVAILABLE',
        reason: 'A filesystem on this device is in use (/run/media/stick).',
        recommended_action: 'Unmount or eject every volume on this device, then rescan.',
        safety_checks: [
          check('not_mounted', 'No mounted filesystem', false, 'Mounted at /run/media/stick.'),
        ],
      }),
    }),
  )
  assert.equal(flow.state, 'BLOCKED')
  assert.ok(flow.whyBlocked.some((line) => line.includes('in use')))
  assert.ok(flow.whyBlocked.includes('No mounted filesystem: Mounted at /run/media/stick.'))
  assert.match(flow.nextAction, /Unmount/)
  assert.deepEqual(flow.path, ['DISCOVERED', 'PREFLIGHT', 'BLOCKED'])
})

test('an unreachable method is BLOCKED with the engine refusal', () => {
  const flow = sanitizeWorkflow(
    facts({ canRun: false, planRefusal: 'Purge is not reachable.' }),
  )
  assert.equal(flow.state, 'BLOCKED')
  assert.deepEqual(flow.whyBlocked, ['Purge is not reachable.'])
})

test('a real erase waits for HUMAN APPROVAL and shows no execution', () => {
  const flow = sanitizeWorkflow(facts())
  assert.equal(flow.state, 'HUMAN_APPROVAL_REQUIRED')
  assert.equal(flow.headline, 'HUMAN APPROVAL REQUIRED')
  const open = sanitizeWorkflow(facts({ confirming: true }))
  assert.equal(open.state, 'HUMAN_APPROVAL_REQUIRED')
  assert.match(open.nextAction, /serial/)
  assert.match(open.nextAction, /backup/)
})

test('NOT AUTHORIZED blocks the erase: there is no mode that needs no privilege', () => {
  const denied = assessment({
    headline: 'NOT AUTHORIZED',
    reason: 'This process does not have the privilege.',
    recommended_action: 'Start the privileged helper, then rescan.',
    safety_checks: [check('privilege', 'Privilege available', false, 'Not elevated.')],
  })
  assert.equal(sanitizeWorkflow(facts({ assessment: denied })).state, 'BLOCKED')
})

test('EXECUTING is only derived from a running job', () => {
  assert.notEqual(sanitizeWorkflow(facts({ confirming: true })).state, 'EXECUTING')
  const real = sanitizeWorkflow(facts({ running: true, phase: 'ERASE' }))
  assert.equal(real.state, 'EXECUTING')
  assert.equal(real.headline, 'EXECUTING')
})

test('the VERIFY phase is VERIFYING', () => {
  assert.equal(sanitizeWorkflow(facts({ running: true, phase: 'VERIFY' })).state, 'VERIFYING')
})

test('a failed real erase is FAILED with the reason and an unknown device state', () => {
  const flow = sanitizeWorkflow(facts({ status: job('failed', 'device went away') }))
  assert.equal(flow.state, 'FAILED')
  assert.deepEqual(flow.whyBlocked, ['device went away'])
  assert.match(flow.nextAction, /unknown state/)
})

const server = (state: string, why: string[] = []) => ({
  state,
  why_blocked: why,
  next_action: `server says ${state}`,
})

test('a real erase shows the state the server derived, in its words', () => {
  for (const state of ['HUMAN_APPROVAL_REQUIRED', 'PLAN_READY', 'BACKUP_VERIFIED']) {
    const flow = sanitizeWorkflow(facts({ server: server(state, ['no person approved']) }))
    assert.equal(flow.state, state)
    assert.equal(flow.nextAction, `server says ${state}`)
    assert.deepEqual(flow.whyBlocked, [], `${state} is not a block`)
    assert.deepEqual(flow.path, [...REAL_ERASE_PATH])
  }
  const blocked = sanitizeWorkflow(facts({ server: server('BLOCKED', ['device identity changed']) }))
  assert.equal(blocked.state, 'BLOCKED')
  assert.deepEqual(blocked.whyBlocked, ['device identity changed'])
  const noBackup = sanitizeWorkflow(facts({ server: server('BACKUP_REQUIRED', ['backup gone']) }))
  assert.deepEqual(noBackup.path, ['DISCOVERED', 'PREFLIGHT', 'BACKUP_REQUIRED'])
})

test('an unknown server state is never invented into a screen state', () => {
  const flow = sanitizeWorkflow(facts({ server: server('SOMETHING_NEW') }))
  assert.equal(flow.state, 'HUMAN_APPROVAL_REQUIRED')
})

test('a server refusal is BLOCKED with its WHY BLOCKED, not a generic failure', () => {
  const refusal = refusalFrom({
    message: 'REFUSED: nothing was erased',
    remediation: 'open the workflow',
    whyBlocked: ['authorization auth-1 was already used'],
    workflowState: 'BLOCKED',
    physicalDeviceModified: false,
  })
  const flow = sanitizeWorkflow(facts({ refusal, server: server('PLAN_READY') }))
  assert.equal(flow.state, 'BLOCKED')
  assert.deepEqual(flow.whyBlocked, ['authorization auth-1 was already used'])
  assert.match(flow.nextAction, /PHYSICAL DEVICE MODIFIED: FALSE/)
})

test('a refusal never says the device is untouched unless the server said so', () => {
  const unknown = refusalFrom({
    message: 'x',
    remediation: '',
    whyBlocked: [],
    workflowState: '',
    physicalDeviceModified: null,
  })
  assert.equal(unknown.physicalDeviceModified, null)
  assert.deepEqual(unknown.whyBlocked, ['x'])
  assert.equal(
    refusalFrom({ ...unknown, whyBlocked: [] }, true).physicalDeviceModified,
    false,
    'open and approve have no write path',
  )
})

function realJob(verification: unknown): JobStatus {
  return { state: 'complete', params: {}, result: { verification }, error: null } as unknown as JobStatus
}

test('a finished real job whose read-back FAILED is FAILED, never COMPLETE', () => {
  const flow = sanitizeWorkflow(
    facts({ status: realJob({ passed: false, failed_offsets: [0, 4096] }) }),
  )
  assert.equal(flow.state, 'FAILED')
  assert.match(flow.whyBlocked[0], /verification FAILED at 2/)
  assert.match(flow.nextAction, /NOT sanitized/)
})

test('COMPLETE on a real job only claims what verification supports', () => {
  const passed = sanitizeWorkflow(facts({ status: realJob({ passed: true, failed_offsets: [] }) }))
  assert.equal(passed.state, 'COMPLETE')
  assert.doesNotMatch(passed.nextAction, /Do not treat/)
  for (const verification of [{ passed: null, failed_offsets: [] }, undefined]) {
    const flow = sanitizeWorkflow(facts({ status: realJob(verification) }))
    assert.equal(flow.state, 'COMPLETE')
    assert.match(flow.nextAction, /Do not treat the medium as verified/)
  }
})

test('a helper refusal at the write seam is BLOCKED, not a failed erase', () => {
  const status = {
    state: 'failed',
    params: {},
    error: 'REFUSED at the write seam: model changed. Nothing was erased.',
    error_kind: 'WorkflowGateRefused',
  } as unknown as JobStatus
  const flow = sanitizeWorkflow(facts({ status }))
  assert.equal(flow.state, 'BLOCKED')
  assert.match(flow.whyBlocked[0], /model changed/)
  assert.match(flow.nextAction, /new workflow/)
  const other = { ...status, error_kind: 'OverwriteIncomplete' } as unknown as JobStatus
  assert.equal(sanitizeWorkflow(facts({ status: other })).state, 'FAILED')
})

test('only a completed job is offered a certificate', () => {
  assert.equal(signedRecordWording('complete').title, 'Certificate')
  assert.doesNotMatch(signedRecordWording('complete').note, /dry run|nothing was written/)
  for (const state of ['failed', 'cancelled', '']) {
    const wording = signedRecordWording(state)
    assert.equal(wording.title, 'Signed record', state)
    assert.doesNotMatch(wording.action, /certificate/i)
    assert.match(wording.issued, /not a sanitization certificate/)
    assert.equal(wording.tone, 'warning')
  }
  // Ran to the end, read-back FAILED: a signed record, never a certificate.
  const failedReadBack = signedRecordWording('complete', true)
  assert.equal(failedReadBack.title, 'Signed record')
  assert.match(failedReadBack.issued, /not a sanitization certificate/)
  assert.match(failedReadBack.note, /read-back verification FAILED/)
})
