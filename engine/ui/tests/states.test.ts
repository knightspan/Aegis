/**
 * The resolver's states reach every screen as its own words: the precise
 * state label with its reason, a fallback to the older status only when no
 * state was sent, physical validation scoped to device classes, and the exact
 * reason a Purge is not available.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import type {
  DeviceAssessment,
  DeviceRow,
  OperationCapability,
  PlatformStatus,
  ResolvedCapability,
  SanitizeOption,
} from '../src/lib/api.ts'
import {
  acquireBody,
  capabilityWord,
  deviceCapabilityLines,
  honestLevel,
  optionTitle,
  platformMatrix,
  preparable,
  purgeAbsence,
  rawSource,
  STATE_LABELS,
  STATE_MEANINGS,
  validationScope,
} from '../src/lib/states.ts'
import { assessmentBadge } from '../src/lib/capability.ts'
import { offeredOption } from '../src/lib/platform.ts'
import { judgeSummary } from '../src/lib/summary.ts'

const CLEAR_REASON =
  'Available - WriteFile to \\\\.\\PhysicalDriveN opened with FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH. No run on a physical usb-flash device is recorded, so it is implemented, not physically validated.'
const BRIDGE_REASON =
  'A USB or card-reader bridge usually translates only reads and writes; ATA and NVMe sanitize commands do not reach the controller behind it.'

function resolved(over: Partial<ResolvedCapability>): ResolvedCapability {
  return {
    capability: 'whole_drive_clear',
    label: 'Whole-drive clear (addressable overwrite)',
    state: 'IMPLEMENTED_NOT_PHYSICALLY_VALIDATED',
    state_label: 'IMPLEMENTED / UNVALIDATED',
    reason: CLEAR_REASON,
    source: 'core.platform.capability',
    mechanism: 'WriteFile to \\\\.\\PhysicalDriveN opened with FILE_FLAG_NO_BUFFERING',
    protocol: 'block',
    required_privilege: 'administrator',
    safety_restrictions: [],
    verification: '',
    assurance: '',
    limitations: [],
    device_class: 'usb-flash',
    evidence: [],
    validated_classes: [],
    module: '',
    ...over,
  }
}

function option(over: Partial<SanitizeOption>): SanitizeOption {
  return {
    level: 'CLEAR',
    title: 'Addressable overwrite (Clear)',
    status: 'UNVERIFIED',
    method: 'SINGLE_PASS_OVERWRITE',
    why: CLEAR_REASON,
    technical: [],
    verification: 'Read-back of every addressable block up to 64 GiB.',
    remediation: '',
    state: 'IMPLEMENTED_NOT_PHYSICALLY_VALIDATED',
    state_label: 'IMPLEMENTED / UNVALIDATED',
    capability: 'whole_drive_clear',
    mechanism: 'WriteFile to \\\\.\\PhysicalDriveN',
    protocol: 'block',
    assurance: 'NIST SP 800-88 Rev. 2 Clear of the addressable LBA range the OS reports.',
    limitations: [],
    ...over,
  }
}

const bridgePurge = option({
  level: 'PURGE',
  title: 'Device sanitize (Purge)',
  status: 'UNSUPPORTED',
  method: null,
  why: 'The Windows storage stack did not pass ATA command 0xEC to \\\\.\\PhysicalDrive2 (Win32 error 1). A USB bridge, a RAID or NVMe controller, or the driver refuses ATA pass-through here.',
  state: 'UNSUPPORTED_BY_DEVICE',
  state_label: 'DEVICE-DEPENDENT',
  capability: 'nvme_sanitize',
  mechanism: 'IOCTL_STORAGE_REINITIALIZE_MEDIA with the block-erase sanitize method',
  protocol: 'NVMe',
})

function stick(over: Partial<DeviceAssessment> = {}): DeviceAssessment {
  return {
    device_id: 'PhysicalDrive2',
    platform: 'windows',
    status: 'UNVERIFIED',
    headline: 'READY',
    reason: CLEAR_REASON,
    recommended_action: '',
    recommended: option({}),
    alternatives: [],
    unavailable: [bridgePurge],
    verification: '',
    safety_checks: [],
    flash_limitation: '',
    device_class: 'usb-flash',
    capabilities: [
      resolved({}),
      resolved({
        capability: 'nvme_format',
        label: 'NVMe Format NVM',
        state: 'UNSUPPORTED_BY_PLATFORM',
        state_label: 'PLATFORM-LIMITED',
        reason:
          "Windows' in-box NVMe driver does not pass Format NVM through IOCTL_STORAGE_PROTOCOL_COMMAND, so it cannot be issued from Windows.",
        mechanism: '',
        protocol: '',
      }),
      resolved({
        capability: 'ata_sanitize',
        label: 'ATA SANITIZE',
        state: 'UNSUPPORTED_BY_DEVICE',
        state_label: 'DEVICE-DEPENDENT',
        reason: BRIDGE_REASON,
        mechanism: 'ATA SANITIZE DEVICE (B4h) BLOCK ERASE EXT through IOCTL_ATA_PASS_THROUGH',
        protocol: 'ATA',
      }),
      resolved({
        capability: 'raw_acquisition',
        label: 'Raw physical-device acquisition',
        reason: 'Available - CreateFileW(\\\\.\\PhysicalDriveN, GENERIC_READ). No run on a physical usb-flash device is recorded.',
        mechanism: 'CreateFileW(\\\\.\\PhysicalDriveN, GENERIC_READ)',
      }),
      resolved({
        capability: 'backup_restore',
        label: 'Backup restore',
        reason: 'Available - WriteFile of the verified image to \\\\.\\PhysicalDriveN.',
      }),
      resolved({
        capability: 'future_thing',
        label: 'Something added later',
        state: 'NOT_IMPLEMENTED',
        state_label: 'NOT IMPLEMENTED',
        reason: 'Not implemented on Windows.',
        mechanism: '',
      }),
    ],
    ...over,
  }
}

// -- state label rendering ------------------------------------------------------

test('a row with a state shows the resolver label, never the older status word', () => {
  const row = { status: 'UNSUPPORTED' as const, state: 'UNSUPPORTED_BY_PLATFORM' as const, state_label: 'PLATFORM-LIMITED' }
  const word = capabilityWord(row)
  assert.equal(word.word, 'PLATFORM-LIMITED')
  assert.equal(word.precise, true)
  assert.doesNotMatch(word.word, /unsupported/i)
})

test('every state has its interface word, and only a physical run is green', () => {
  assert.equal(Object.keys(STATE_LABELS).length, 8)
  for (const [state, label] of Object.entries(STATE_LABELS)) {
    const word = capabilityWord({ state: state as keyof typeof STATE_LABELS })
    assert.equal(word.word, label, state)
    if (state !== 'VALIDATED_PHYSICAL') assert.notEqual(word.tone, 'success', state)
  }
  assert.equal(capabilityWord({ state: 'VALIDATED_PHYSICAL' }).tone, 'success')
  assert.equal(
    capabilityWord({ state: 'IMPLEMENTED_NOT_PHYSICALLY_VALIDATED', state_label: '' }).word,
    'IMPLEMENTED / UNVALIDATED',
  )
  const labels = new Set(STATE_MEANINGS.map((row) => row.label))
  assert.deepEqual(labels, new Set(Object.values(STATE_LABELS)))
})

test('the judge summary line uses the state word when the row has one', () => {
  const operations = [
    {
      operation: 'whole_drive_clear',
      label: 'Whole-drive Clear',
      status: 'UNVERIFIED',
      reason: CLEAR_REASON,
      source: 's',
      verification: '',
      limitations: [],
      requires_privilege: true,
      state: 'IMPLEMENTED_NOT_PHYSICALLY_VALIDATED',
      state_label: 'IMPLEMENTED / UNVALIDATED',
    },
    {
      operation: 'whole_drive_purge',
      label: 'Whole-drive Purge',
      status: 'INCONCLUSIVE',
      reason: 'Implemented. Offered per device.',
      source: 's',
      verification: '',
      limitations: [],
      requires_privilege: true,
      state: 'IMPLEMENTED_DEVICE_DEPENDENT',
      state_label: 'DEVICE-DEPENDENT',
    },
  ] as OperationCapability[]
  const summary = judgeSummary(null, { operations, limitations: [] } as unknown as PlatformStatus, 'VALID')
  assert.ok(summary.erasure.includes('Whole-drive Clear: IMPLEMENTED / UNVALIDATED.'))
  assert.ok(summary.erasure.includes('Whole-drive Purge: DEVICE-DEPENDENT.'))
})

// -- fallback to status ---------------------------------------------------------

test('a payload without a state falls back to the older status word', () => {
  const word = capabilityWord({ status: 'UNSUPPORTED' })
  assert.equal(word.word, 'Unsupported')
  assert.equal(word.precise, false)
  assert.equal(capabilityWord({ status: 'UNVERIFIED', state: null }).word, 'Unverified')
  assert.equal(capabilityWord(undefined).word, 'not probed')
})

test('offering an option follows the state when present, the status otherwise', () => {
  assert.equal(offeredOption(option({})), true)
  assert.equal(offeredOption(bridgePurge), false)
  // A state that is not runnable is not offered, whatever the older status says.
  assert.equal(offeredOption(option({ status: 'SUPPORTED', state: 'NOT_IMPLEMENTED' })), false)
  // Privilege is offered (the gate asks for it), like core/platform/base.py.
  assert.equal(offeredOption(option({ state: 'AVAILABLE_BUT_REQUIRES_PRIVILEGE' })), true)
  // No state: the older rule.
  assert.equal(offeredOption(option({ state: null, status: 'UNVERIFIED', method: 'X' })), true)
  assert.equal(offeredOption(option({ state: undefined, status: 'UNSUPPORTED' })), false)
})

// -- device capability list ------------------------------------------------------

test('the device capability list is ordered, named, and carries each reason', () => {
  const lines = deviceCapabilityLines(stick())
  assert.deepEqual(
    lines.map((line) => line.key),
    ['whole_drive_clear', 'ata_sanitize', 'nvme_format', 'raw_acquisition', 'backup_restore', 'future_thing'],
  )
  const clear = lines[0]
  assert.equal(clear.name, 'WHOLE-DRIVE CLEAR')
  assert.equal(clear.word, 'IMPLEMENTED / UNVALIDATED')
  assert.equal(clear.text, `WHOLE-DRIVE CLEAR — IMPLEMENTED / UNVALIDATED — ${CLEAR_REASON}`)
  assert.match(clear.mechanism, /PhysicalDriveN/)
  const format = lines.find((line) => line.key === 'nvme_format')
  assert.equal(format?.word, 'PLATFORM-LIMITED')
  assert.match(format?.reason ?? '', /in-box NVMe driver/)
  const sanitize = lines.find((line) => line.key === 'ata_sanitize')
  assert.equal(sanitize?.word, 'DEVICE-DEPENDENT')
  assert.equal(sanitize?.protocol, 'ATA')
  // A capability the list does not know is kept under its own label.
  assert.equal(lines.at(-1)?.name, 'SOMETHING ADDED LATER')
  for (const line of lines) {
    assert.ok(line.reason.length > 0, line.key)
    assert.doesNotMatch(line.word, /^Unsupported$/)
  }
})

test('a device with no resolver answer has an empty list, not invented rows', () => {
  assert.deepEqual(deviceCapabilityLines(stick({ capabilities: undefined })), [])
  assert.deepEqual(deviceCapabilityLines(null), [])
})

test('a Windows row with no Linux probe gets its verdict from the assessment', () => {
  const badge = assessmentBadge(stick())
  assert.equal(badge.label, 'CLEAR ONLY')
  assert.match(badge.basis, /IMPLEMENTED \/ UNVALIDATED/)
  assert.match(badge.why, /bridge/)
  assert.notEqual(badge.tone, 'success')
})

// -- platform matrix -------------------------------------------------------------

test('platform matrix: physical validation is scoped to the recorded classes', () => {
  const status = {
    capabilities: [
      resolved({
        capability: 'whole_drive_clear',
        state: 'VALIDATED_PHYSICAL',
        state_label: 'SUPPORTED',
        reason: 'Available - O_DIRECT overwrite. Physically validated on: usb-flash only.',
        mechanism: 'O_DIRECT sequential overwrite of every LBA',
        validated_classes: ['usb-flash'],
        device_class: '',
      }),
      resolved({
        capability: 'nvme_sanitize',
        state: 'IMPLEMENTED_DEVICE_DEPENDENT',
        state_label: 'DEVICE-DEPENDENT',
        reason: 'Implemented (NVMe Sanitize). Offered per device.',
        device_class: '',
      }),
    ],
  } as PlatformStatus
  const rows = platformMatrix(status)
  assert.ok(rows)
  const clear = rows[0]
  assert.equal(clear.word, 'SUPPORTED')
  assert.deepEqual(clear.validatedClasses, ['usb-flash'])
  assert.match(clear.scope, /usb-flash only/)
  assert.match(clear.scope, /Every other device class: not physically validated/)
  assert.equal(clear.mechanism, 'O_DIRECT sequential overwrite of every LBA')
  const sanitize = rows[1]
  assert.equal(sanitize.word, 'DEVICE-DEPENDENT')
  assert.deepEqual(sanitize.validatedClasses, [])
  assert.equal(sanitize.scope, 'No physical run recorded.')
  // Never generalised: a validated state with no class names none.
  assert.doesNotMatch(validationScope({ state: 'VALIDATED_PHYSICAL', validated_classes: [] }), /all|every device/i)
})

test('an older server with no matrix gets null, so the screen falls back', () => {
  assert.equal(platformMatrix({ capabilities: [] } as unknown as PlatformStatus), null)
  assert.equal(platformMatrix({} as PlatformStatus), null)
  assert.equal(platformMatrix(null), null)
})

// -- Purge unavailable -----------------------------------------------------------

test('a Purge hidden by a bridge says bridge, with the exact reason', () => {
  const absence = purgeAbsence(stick())
  assert.ok(absence)
  assert.equal(absence.cause, 'bridge')
  assert.equal(absence.word, 'DEVICE-DEPENDENT')
  assert.equal(absence.reason, bridgePurge.why)
  assert.equal(absence.protocol, 'NVMe')
})

test('a Purge the platform cannot issue says platform', () => {
  const mac = option({
    level: 'PURGE',
    title: 'Device sanitize (Purge)',
    status: 'UNSUPPORTED',
    method: null,
    why: 'macOS exposes no public NVMe admin-command interface to applications.',
    state: 'UNSUPPORTED_BY_PLATFORM',
    state_label: 'PLATFORM-LIMITED',
    capability: 'nvme_sanitize',
  })
  const absence = purgeAbsence(stick({ platform: 'macos', unavailable: [mac] }))
  assert.equal(absence?.cause, 'platform')
  assert.equal(absence?.word, 'PLATFORM-LIMITED')
  assert.equal(absence?.reason, mac.why)
})

test('a Purge whose probe did not settle it says not probed', () => {
  const unsettled = option({
    level: 'PURGE',
    title: 'Device sanitize (Purge)',
    status: 'INCONCLUSIVE',
    method: null,
    why: 'The capability probe did not complete, so whether the drive reports SANITIZE is unknown.',
    state: 'IMPLEMENTED_DEVICE_DEPENDENT',
    state_label: 'DEVICE-DEPENDENT',
    capability: 'ata_sanitize',
  })
  assert.equal(purgeAbsence(stick({ unavailable: [unsettled] }))?.cause, 'not probed')
  assert.equal(purgeAbsence(null)?.cause, 'not probed')
  // An older payload with no state: the status and the sentence decide.
  const legacy = { ...unsettled, state: undefined, state_label: undefined }
  assert.equal(purgeAbsence(stick({ unavailable: [legacy] }))?.cause, 'not probed')
})

test('an offered Purge means no absence is reported', () => {
  const nvme = option({
    level: 'PURGE',
    title: 'Device sanitize (Purge)',
    method: 'NVME_SANITIZE_BLOCK',
    capability: 'nvme_sanitize',
    protocol: 'NVMe',
  })
  assert.equal(purgeAbsence(stick({ recommended: nvme, unavailable: [] })), null)
})

test('an overwrite is never presented as a Purge', () => {
  const mislabelled = option({ level: 'PURGE', title: 'Hardware purge' })
  assert.equal(honestLevel(mislabelled), 'CLEAR')
  assert.equal(optionTitle(mislabelled), 'Addressable overwrite (Clear)')
  assert.equal(honestLevel(option({ level: 'PURGE', capability: null, protocol: '', method: 'DOD_5220_22_M_3PASS' })), 'CLEAR')
  // A firmware sanitize stays a Purge.
  const firmware = option({ level: 'PURGE', title: 'Device sanitize (Purge)', method: 'NVME_SANITIZE_BLOCK', capability: 'nvme_sanitize', protocol: 'NVMe' })
  assert.equal(honestLevel(firmware), 'PURGE')
  // An "offered" overwrite labelled PURGE does not count as an offered Purge.
  const absence = purgeAbsence(stick({ recommended: mislabelled, unavailable: [bridgePurge] }))
  assert.equal(absence?.cause, 'bridge')
  assert.equal(assessmentBadge(stick({ recommended: mislabelled })).label, 'CLEAR ONLY')
})

// -- raw acquisition ---------------------------------------------------------------

function row(platform: string, serial: string, assessment?: DeviceAssessment): DeviceRow {
  const path = platform === 'windows' ? '\\\\.\\PhysicalDrive2' : '/dev/disk4'
  return {
    device: {
      path,
      model: 'Stick',
      serial,
      size_bytes: 1,
      rotational: false,
      transport: 'usb',
      is_system_disk: false,
      mounted_at: [],
      pt_type: null,
      by_id_path: null,
    },
    capabilities: null,
    hidden_areas: null,
    assessment,
    normalized: {
      id: 'PhysicalDrive2',
      platform,
      path,
      vendor: '',
      model: 'Stick',
      serial,
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
    },
  }
}

test('raw acquisition sends the selected device path and its serial', () => {
  const source = rawSource(row('windows', 'STICK01', stick()))
  assert.equal(source.source, '\\\\.\\PhysicalDrive2')
  assert.equal(source.expectedSerial, 'STICK01')
  assert.equal(source.allowed, true)
  assert.equal(source.word.word, 'IMPLEMENTED / UNVALIDATED')
  const body = acquireBody(source, { dest: 'disk2.dd', fmt: 'raw', compression: 'fast', caseId: 'C1' })
  assert.deepEqual(body, {
    source: '\\\\.\\PhysicalDrive2',
    dest: 'disk2.dd',
    fmt: 'raw',
    compression: 'fast',
    case_id: 'C1',
    expected_serial: 'STICK01',
  })
})

test('raw acquisition is refused with the reason when the state is not runnable or there is no serial', () => {
  const blocked = stick({
    capabilities: [
      resolved({
        capability: 'raw_acquisition',
        state: 'AVAILABLE_BUT_REQUIRES_PRIVILEGE',
        state_label: 'REQUIRES PRIVILEGE',
        reason: 'Available, but it needs administrator and this process does not hold it.',
      }),
    ],
  })
  const privileged = rawSource(row('windows', 'STICK01', blocked))
  assert.equal(privileged.allowed, false)
  assert.equal(privileged.word.word, 'REQUIRES PRIVILEGE')
  assert.match(privileged.reason, /administrator/)
  const noSerial = rawSource(row('macos', '', stick()))
  assert.equal(noSerial.allowed, false)
  assert.match(noSerial.reason, /no serial/)
  // No resolver answer off Linux: nothing is claimed.
  assert.equal(rawSource(row('windows', 'S', undefined)).allowed, false)
})


test('the prepare step is offered only for a mounted, non-system Windows or macOS disk', () => {
  const base = {
    device: {} as DeviceRow['device'],
    capabilities: null,
    hidden_areas: null,
  }
  const normalized = (over: Record<string, unknown>) =>
    ({ id: 'disk4', platform: 'macos', mounted: true, system_device: false, serial: 'S', ...over }) as unknown as DeviceRow['normalized']
  assert.equal(preparable({ ...base, normalized: normalized({}) } as DeviceRow), true)
  assert.equal(preparable({ ...base, normalized: normalized({ platform: 'windows' }) } as DeviceRow), true)
  assert.equal(preparable({ ...base, normalized: normalized({ platform: 'linux' }) } as DeviceRow), false)
  assert.equal(preparable({ ...base, normalized: normalized({ mounted: false }) } as DeviceRow), false)
  assert.equal(preparable({ ...base, normalized: normalized({ system_device: true }) } as DeviceRow), false)
  assert.equal(preparable({ ...base } as DeviceRow), false)
})
