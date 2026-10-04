import { test } from 'node:test'
import assert from 'node:assert/strict'

import type { Capabilities, DeviceAssessment, SanitizeOption } from '../src/lib/api.ts'
import { capabilityBadge } from '../src/lib/capability.ts'

const caps: Capabilities = {
  ata_security_erase: true,
  ata_enhanced_erase: true,
  ata_sanitize_ops: ['BLOCK_ERASE_EXT'],
  nvme_sanicap: {},
  is_sed_opal: false,
  security_frozen: false,
  est_erase_seconds: 60,
  achievable_levels: ['CLEAR', 'PURGE'],
  limitations: [],
}

function purge(status: SanitizeOption['status']): SanitizeOption {
  return {
    level: 'PURGE',
    title: 'Hardware purge',
    status,
    method: 'ATA_SANITIZE_BLOCK_ERASE',
    why: '',
    technical: [],
    verification: '',
    remediation: '',
  }
}

function assessment(option: SanitizeOption): DeviceAssessment {
  return {
    device_id: 'sda',
    platform: 'linux',
    status: option.status,
    headline: 'READY',
    reason: '',
    recommended_action: '',
    recommended: option,
    alternatives: [],
    unavailable: [],
    verification: '',
    safety_checks: [],
    flash_limitation: '',
  }
}

test('a reported firmware sanitize without a hardware record is UNVERIFIED, never green', () => {
  for (const given of [assessment(purge('UNVERIFIED')), null, undefined]) {
    const badge = capabilityBadge(caps, given)
    assert.equal(badge.label, 'PURGE · UNVERIFIED')
    assert.notEqual(badge.tone, 'success')
    assert.doesNotMatch(badge.label, /AVAILABLE/)
    assert.match(badge.why, /UNVERIFIED/)
  }
})

test('a Purge the server reports as supported reads PURGE AVAILABLE', () => {
  const badge = capabilityBadge(caps, assessment(purge('SUPPORTED')))
  assert.equal(badge.label, 'PURGE AVAILABLE')
  assert.equal(badge.tone, 'success')
})

test('an Opal crypto erase without a hardware record is not green either', () => {
  const opal = { ...caps, is_sed_opal: true }
  const badge = capabilityBadge(opal, assessment(purge('UNVERIFIED')))
  assert.match(badge.label, /UNVERIFIED/)
  assert.notEqual(badge.tone, 'success')
})

test('the resolver state outranks the older status for the Purge verdict', () => {
  const unvalidated = { ...purge('SUPPORTED'), state: 'IMPLEMENTED_NOT_PHYSICALLY_VALIDATED' as const }
  assert.equal(capabilityBadge(caps, assessment(unvalidated)).label, 'PURGE · UNVERIFIED')
  const validated = { ...purge('UNVERIFIED'), state: 'VALIDATED_PHYSICAL' as const }
  assert.equal(capabilityBadge(caps, assessment(validated)).label, 'PURGE AVAILABLE')
})

test('no Linux probe but a resolver answer is not "Not probed"', () => {
  const clear: SanitizeOption = {
    ...purge('UNVERIFIED'),
    level: 'CLEAR',
    title: 'Addressable overwrite (Clear)',
    method: 'SINGLE_PASS_OVERWRITE',
    why: 'Available - WriteFile to the disk.',
    state: 'IMPLEMENTED_NOT_PHYSICALLY_VALIDATED',
    state_label: 'IMPLEMENTED / UNVALIDATED',
    capability: 'whole_drive_clear',
    protocol: 'block',
  }
  const badge = capabilityBadge(null, { ...assessment(clear), platform: 'windows' })
  assert.equal(badge.label, 'CLEAR ONLY')
  assert.match(badge.basis, /IMPLEMENTED \/ UNVALIDATED/)
  assert.equal(capabilityBadge(null, null).label, 'Not probed')
})

test('no firmware sanitize is still CLEAR ONLY', () => {
  const badge = capabilityBadge({ ...caps, achievable_levels: ['CLEAR'], ata_sanitize_ops: [] })
  assert.equal(badge.label, 'CLEAR ONLY')
})
