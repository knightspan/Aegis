// Run with `npm test` (node --test; Node 22 strips the types itself).
// Also run by tests/ui/test_ui_units.py, so the pytest gate covers it.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  contradiction,
  defaultLevel,
  eraseBody,
  flashOf,
  methodLabel,
  planFor,
  plannedVerification,
  runnable,
} from '../src/lib/erasePlan.ts'
import type { DeviceRow, PlannedErase } from '../src/lib/api.ts'

function plan(over: Partial<PlannedErase>): PlannedErase {
  return {
    level: 'CLEAR',
    reachable: true,
    method: 'SINGLE_PASS_OVERWRITE',
    justification: '',
    evidence: [],
    executable: true,
    not_executable_reason: '',
    limitations: [],
    refusal: '',
    remediation: '',
    ...over,
  }
}

function row(over: Partial<DeviceRow>): DeviceRow {
  return {
    device: {
      path: '/dev/sdq',
      model: 'TransMemory',
      serial: 'STICK-1',
      size_bytes: 8,
      rotational: true,
      transport: 'usb',
      is_system_disk: false,
      mounted_at: [],
      pt_type: null,
      by_id_path: null,
    },
    capabilities: null,
    hidden_areas: null,
    ...over,
  }
}

const STICK = row({
  media: { flash: true, reason: 'the device is on the usb bus' },
  erase_preview: {
    flash: true,
    flash_reason: 'the device is on the usb bus',
    purge_mechanisms: [],
    purge_requires: 'ATA SANITIZE block erase or crypto scramble.',
    plans: [
      plan({ level: 'CLEAR' }),
      plan({
        level: 'PURGE',
        reachable: false,
        method: null,
        refusal: 'PURGE is not achievable on this device.',
        remediation: 'Choose one of: CLEAR.',
      }),
    ],
  },
})

test('F5: a USB stick reporting rotational=true is flash, from the engine', () => {
  assert.equal(STICK.device.rotational, true)
  assert.deepEqual(flashOf(STICK), {
    flash: true,
    reason: 'the device is on the usb bus',
  })
})

test('F5: with no determination sent, flash is unknown, never inferred', () => {
  assert.equal(flashOf(row({ device: { ...STICK.device, rotational: false } })).flash, null)
})

test('F6: the request body carries a level and never a method', () => {
  const body = eraseBody('/dev/sdq', 'CLEAR', 'STICK-1', 'auth-0123456789abcdef')
  assert.deepEqual(Object.keys(body).sort(), [
    'authorization_id',
    'level',
    'path',
    'typed_serial',
  ])
  assert.equal(body.authorization_id, 'auth-0123456789abcdef')
  assert.equal(body.typed_serial, 'STICK-1')
})

test('the request body never carries a simulation switch', () => {
  const body = eraseBody('/dev/sdq', 'CLEAR', 'STICK-1', 'auth-x') as unknown as Record<string, unknown>
  for (const key of ['dry_run', 'simulation', 'simulate']) assert.ok(!(key in body), key)
})

test('the planned verification is named before the run', () => {
  assert.match(plannedVerification('SINGLE_PASS_OVERWRITE'), /Read-back/)
  assert.match(plannedVerification('NVME_SANITIZE_BLOCK'), /completion status/)
  assert.match(plannedVerification('SED_CRYPTO_ERASE'), /must change/)
  assert.match(plannedVerification(null), /not planned/)
})

test('the shown plan is the engine plan for the chosen level', () => {
  assert.equal(planFor(STICK, 'CLEAR')?.method, 'SINGLE_PASS_OVERWRITE')
  assert.equal(planFor(STICK, 'PURGE')?.reachable, false)
  assert.equal(planFor(row({}), 'CLEAR'), null)
})

test('F7: Purge methods the old list omitted are shown and preselected', () => {
  for (const method of ['ATA_SANITIZE_OVERWRITE', 'NVME_FORMAT_SES1']) {
    const drive = row({
      erase_preview: {
        flash: false,
        flash_reason: '',
        purge_mechanisms: [method],
        purge_requires: '',
        plans: [plan({ level: 'CLEAR' }), plan({ level: 'PURGE', method })],
      },
    })
    assert.equal(defaultLevel(drive), 'PURGE')
    assert.equal(planFor(drive, 'PURGE')?.method, method)
    assert.notEqual(methodLabel(method), method)
  }
})

test('unreachable or unexecutable Purge is not runnable and not preselected', () => {
  assert.equal(defaultLevel(STICK), 'CLEAR')
  assert.equal(runnable(planFor(STICK, 'PURGE')), false)
  const opal = plan({
    level: 'PURGE',
    method: 'SED_CRYPTO_ERASE',
    executable: false,
  })
  assert.equal(runnable(opal), false)
  assert.equal(runnable(null), false)
})

test('a job that ran a different method than shown is called out', () => {
  const shown = plan({ level: 'PURGE', method: 'ATA_SANITIZE_BLOCK_ERASE' })
  assert.equal(contradiction(shown, { method: 'ATA_SANITIZE_BLOCK_ERASE' }), null)
  const said = contradiction(shown, { method: 'ATA_SANITIZE_CRYPTO_SCRAMBLE' })
  assert.match(said ?? '', /ATA_SANITIZE_CRYPTO_SCRAMBLE/)
  assert.equal(contradiction(shown, null), null)
})
