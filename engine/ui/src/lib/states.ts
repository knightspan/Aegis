// The resolver's capability states, in the words the interface shows. Pure,
// and free of React, so `node --test` runs it: see ui/tests/states.test.ts.
//
// The server decides every state (core/platform/capability.py). This file only
// names it, colours it and orders it. When a payload carries a `state`, the
// precise word is shown and the older `status` is ignored; only a payload saved
// before the resolver existed falls back to `status`.

import type {
  AcquireBody,
  CapabilityState,
  CapabilityStatus,
  DeviceAssessment,
  DeviceRow,
  PlatformStatus,
  ResolvedCapability,
  SanitizeOption,
} from './api'
import type { Tone } from '../components/widgets'
import { statusWord } from './platform.ts'

/** Mirrors `STATE_LABELS` in core/platform/model.py. Used only when a payload
 * carries a state but no label. */
export const STATE_LABELS: Record<CapabilityState, string> = {
  VALIDATED_PHYSICAL: 'SUPPORTED',
  IMPLEMENTED_NOT_PHYSICALLY_VALIDATED: 'IMPLEMENTED / UNVALIDATED',
  IMPLEMENTED_DEVICE_DEPENDENT: 'DEVICE-DEPENDENT',
  AVAILABLE_BUT_REQUIRES_PRIVILEGE: 'REQUIRES PRIVILEGE',
  UNSUPPORTED_BY_DEVICE: 'DEVICE-DEPENDENT',
  UNSUPPORTED_BY_PLATFORM: 'PLATFORM-LIMITED',
  NOT_IMPLEMENTED: 'NOT IMPLEMENTED',
  BLOCKED_BY_SAFETY_POLICY: 'BLOCKED FOR SAFETY',
}

/**
 * The tone of a state. Only a recorded physical run is drawn as success:
 * IMPLEMENTED / UNVALIDATED runs, but nothing on record says it works on real
 * hardware, so it is never green.
 */
export const STATE_TONES: Record<CapabilityState, Tone> = {
  VALIDATED_PHYSICAL: 'success',
  IMPLEMENTED_NOT_PHYSICALLY_VALIDATED: 'unknown',
  IMPLEMENTED_DEVICE_DEPENDENT: 'unknown',
  AVAILABLE_BUT_REQUIRES_PRIVILEGE: 'warning',
  UNSUPPORTED_BY_DEVICE: 'warning',
  UNSUPPORTED_BY_PLATFORM: 'destructive',
  NOT_IMPLEMENTED: 'destructive',
  BLOCKED_BY_SAFETY_POLICY: 'destructive',
}

/** States in which an operation may be started (after the workflow gates). */
export const RUNNABLE_STATES: ReadonlySet<CapabilityState> = new Set<CapabilityState>([
  'VALIDATED_PHYSICAL',
  'IMPLEMENTED_NOT_PHYSICALLY_VALIDATED',
])

/**
 * What each interface word means, one entry per word. Paraphrases the enum
 * comments in core/platform/model.py; the server decides the state.
 */
export const STATE_MEANINGS: readonly { label: string; states: CapabilityState[]; meaning: string }[] = [
  {
    label: 'SUPPORTED',
    states: ['VALIDATED_PHYSICAL'],
    meaning:
      'Runs here, and a run on real hardware of the listed device classes is recorded. Other classes are not covered by that run.',
  },
  {
    label: 'IMPLEMENTED / UNVALIDATED',
    states: ['IMPLEMENTED_NOT_PHYSICALLY_VALIDATED'],
    meaning:
      'Runs here. Tested against synthetic media and adapter doubles only; no run on a physical device of this kind is recorded. Not a claim that it works on hardware.',
  },
  {
    label: 'DEVICE-DEPENDENT',
    states: ['IMPLEMENTED_DEVICE_DEPENDENT', 'UNSUPPORTED_BY_DEVICE'],
    meaning:
      'Implemented, but whether it runs depends on what the device (or a bridge in front of it) reports. The reason says which.',
  },
  {
    label: 'REQUIRES PRIVILEGE',
    states: ['AVAILABLE_BUT_REQUIRES_PRIVILEGE'],
    meaning: 'Implemented, but this process lacks the operating-system privilege it needs.',
  },
  {
    label: 'PLATFORM-LIMITED',
    states: ['UNSUPPORTED_BY_PLATFORM'],
    meaning: 'This operating system offers applications no path to the mechanism at all.',
  },
  {
    label: 'NOT IMPLEMENTED',
    states: ['NOT_IMPLEMENTED'],
    meaning: 'The operating system could do it; this build has no code for it.',
  },
  {
    label: 'BLOCKED FOR SAFETY',
    states: ['BLOCKED_BY_SAFETY_POLICY'],
    meaning: 'Implemented and exposed, and refused by a safety rule for this device.',
  },
]

/** Anything that may carry a resolver state, or only the older status. */
export interface StatefulRow {
  state?: CapabilityState | null
  state_label?: string
  status?: CapabilityStatus
}

export interface StateWord {
  word: string
  tone: Tone
  /** True when the word is the resolver's; false for the older status. */
  precise: boolean
  /** The machine value the word stands for, for `data-` attributes. */
  value: string
}

/**
 * The word a capability is shown under.
 *
 * The resolver's `state_label` whenever a `state` is present: never a generic
 * UNSUPPORTED over a precise state. Only a payload with no state at all (saved
 * before the resolver existed) falls back to the older status word.
 */
export function capabilityWord(row: StatefulRow | null | undefined): StateWord {
  if (row?.state) {
    return {
      word: row.state_label || STATE_LABELS[row.state] || row.state,
      tone: STATE_TONES[row.state] ?? 'unknown',
      precise: true,
      value: row.state,
    }
  }
  if (row?.status) {
    const legacy = statusWord(row.status)
    return { word: legacy.word, tone: legacy.tone, precise: false, value: row.status }
  }
  return { word: 'not probed', tone: 'unknown', precise: false, value: '' }
}

/** Whether a row with a resolver state may be started. */
export function runnableState(state: CapabilityState | null | undefined): boolean {
  return Boolean(state && RUNNABLE_STATES.has(state))
}

// -- device capabilities ------------------------------------------------------

/**
 * The order and the short names of the Devices screen's capability list:
 * clear, then device sanitize per protocol, then crypto erase, acquisition,
 * hidden areas and restore. A capability the server adds later is listed
 * after these under its own label, never dropped.
 */
export const DEVICE_CAPABILITY_NAMES: readonly { key: string; name: string }[] = [
  { key: 'whole_drive_clear', name: 'WHOLE-DRIVE CLEAR' },
  { key: 'ata_sanitize', name: 'ATA SANITIZE' },
  { key: 'ata_security_erase', name: 'ATA SECURITY ERASE' },
  { key: 'nvme_sanitize', name: 'NVME SANITIZE' },
  { key: 'nvme_format', name: 'NVME FORMAT' },
  { key: 'crypto_erase', name: 'CRYPTO ERASE' },
  { key: 'raw_acquisition', name: 'RAW ACQUISITION' },
  { key: 'volume_acquisition', name: 'VOLUME ACQUISITION' },
  { key: 'hpa_dco_discovery', name: 'HPA/DCO DISCOVERY' },
  { key: 'hpa_dco_modify', name: 'HPA/DCO MODIFY' },
  { key: 'backup_restore', name: 'BACKUP RESTORE' },
]

export interface CapabilityLine {
  key: string
  name: string
  word: string
  tone: Tone
  reason: string
  mechanism: string
  protocol: string
  /** "NAME — WORD — reason", the line as a reader would quote it. */
  text: string
}

function line(row: ResolvedCapability, name: string): CapabilityLine {
  const word = capabilityWord(row)
  const reason = row.reason || 'No reason was recorded for this state.'
  return {
    key: row.capability,
    name,
    word: word.word,
    tone: word.tone,
    reason,
    mechanism: row.mechanism ?? '',
    protocol: row.protocol ?? '',
    text: `${name} — ${word.word} — ${reason}`,
  }
}

/** Every capability the resolver answered for one device, in reading order. */
export function deviceCapabilityLines(
  assessment: DeviceAssessment | null | undefined,
): CapabilityLine[] {
  const rows = assessment?.capabilities ?? []
  const byKey = new Map(rows.map((row) => [row.capability, row]))
  const known = new Set(DEVICE_CAPABILITY_NAMES.map((item) => item.key))
  const ordered = DEVICE_CAPABILITY_NAMES.flatMap((item) => {
    const row = byKey.get(item.key)
    return row ? [line(row, item.name)] : []
  })
  const extra = rows
    .filter((row) => !known.has(row.capability))
    .map((row) => line(row, (row.label || row.capability).toUpperCase()))
  return [...ordered, ...extra]
}

/** One resolved capability of a device, by key. */
export function deviceCapability(
  assessment: DeviceAssessment | null | undefined,
  key: string,
): ResolvedCapability | undefined {
  return assessment?.capabilities?.find((row) => row.capability === key)
}

/** "usb-flash", or a sentence saying the server did not classify it. */
export function deviceClassWord(assessment: DeviceAssessment | null | undefined): string {
  return assessment?.device_class || 'not classified'
}

// -- platform matrix -----------------------------------------------------------

/**
 * What the physical validation of one capability covers.
 *
 * Scoped to the device classes a run is recorded for and never generalised:
 * a clear of one USB stick says nothing about an NVMe drive.
 */
export function validationScope(row: {
  state?: CapabilityState | null
  validated_classes?: string[]
}): string {
  const classes = row.validated_classes ?? []
  if (classes.length > 0) {
    return (
      `Physically validated on ${classes.join(', ')} only. ` +
      'Every other device class: not physically validated.'
    )
  }
  if (row.state === 'VALIDATED_PHYSICAL') {
    return 'A physical run is recorded, but not the device class it ran on.'
  }
  return 'No physical run recorded.'
}

export interface MatrixRow {
  key: string
  label: string
  word: string
  tone: Tone
  reason: string
  mechanism: string
  scope: string
  validatedClasses: string[]
  source: string
  verification: string
  assurance: string
  limitations: string[]
}

/**
 * The resolver's platform matrix as table rows, or null when the server sent
 * none (an older server; the screen then falls back to the operation rows).
 */
export function platformMatrix(status: PlatformStatus | null | undefined): MatrixRow[] | null {
  const rows = status?.capabilities
  if (!rows || rows.length === 0) return null
  return rows.map((row) => {
    const word = capabilityWord(row)
    return {
      key: row.capability,
      label: row.label || row.capability,
      word: word.word,
      tone: word.tone,
      reason: row.reason,
      mechanism: row.mechanism ?? '',
      scope: validationScope(row),
      validatedClasses: [...(row.validated_classes ?? [])],
      source: row.source ?? '',
      verification: row.verification ?? '',
      assurance: row.assurance ?? '',
      limitations: [...(row.limitations ?? [])],
    }
  })
}

// -- sanitize options ------------------------------------------------------------

/** Host-overwrite methods. Whatever an option is labelled, these are a Clear. */
const OVERWRITE_METHODS = new Set(['SINGLE_PASS_OVERWRITE', 'DOD_5220_22_M_3PASS'])

/**
 * The NIST level an option may be shown under.
 *
 * An overwrite issued by the host is a Clear, never a Purge, whatever level
 * field it arrives with: the capability, the method or the protocol saying
 * "host overwrite" decides.
 */
export function honestLevel(option: Pick<SanitizeOption, 'level' | 'method' | 'capability' | 'protocol'>): 'CLEAR' | 'PURGE' {
  if (option.level !== 'PURGE') return 'CLEAR'
  if (option.capability === 'whole_drive_clear') return 'CLEAR'
  if (option.method && OVERWRITE_METHODS.has(option.method)) return 'CLEAR'
  if (option.protocol === 'block') return 'CLEAR'
  return 'PURGE'
}

/**
 * The title an option is shown under, naming its honest level. An option that
 * arrived as PURGE but is a host overwrite is retitled as the Clear it is.
 */
export function optionTitle(
  option: Pick<SanitizeOption, 'level' | 'method' | 'capability' | 'protocol' | 'title'>,
): string {
  const level = honestLevel(option)
  const title = level === option.level ? option.title : 'Addressable overwrite (Clear)'
  const word = level === 'PURGE' ? 'Purge' : 'Clear'
  return title.toLowerCase().includes(word.toLowerCase()) ? title : `${title} (${word})`
}

/** Why a Purge is not offered, in one of the words an operator can act on. */
export type PurgeCause =
  | 'bridge'
  | 'platform'
  | 'not probed'
  | 'device'
  | 'privilege'
  | 'safety'
  | 'not implemented'
  | 'unknown'

const CAUSE_WORDS: Record<PurgeCause, string> = {
  bridge: 'a bridge in front of the drive hides the command',
  platform: 'this operating system offers no path to the command',
  'not probed': 'the device was not probed, or the probe did not settle it',
  device: 'the device does not report the command',
  privilege: 'this process lacks the privilege to issue it',
  safety: 'a safety rule refuses it for this device',
  'not implemented': 'this build has no code for it on this platform',
  unknown: 'the server gave no category',
}

export interface PurgeAbsence {
  cause: PurgeCause
  /** Plain sentence for the cause. */
  causeWord: string
  /** The option's state word, or the older status word. */
  word: string
  tone: Tone
  /** The server's exact reason, never paraphrased. */
  reason: string
  title: string
  mechanism: string
  protocol: string
}

function causeOf(option: SanitizeOption): PurgeCause {
  const why = option.why ?? ''
  switch (option.state) {
    case 'UNSUPPORTED_BY_PLATFORM':
      return 'platform'
    case 'UNSUPPORTED_BY_DEVICE':
      return /bridge/i.test(why) ? 'bridge' : 'device'
    case 'IMPLEMENTED_DEVICE_DEPENDENT':
      return 'not probed'
    case 'AVAILABLE_BUT_REQUIRES_PRIVILEGE':
      return 'privilege'
    case 'BLOCKED_BY_SAFETY_POLICY':
      return 'safety'
    case 'NOT_IMPLEMENTED':
      return 'not implemented'
    default:
      break
  }
  if (option.state) return 'unknown'
  // An older payload: only the status and the sentence are there.
  if (option.status === 'INCONCLUSIVE') return 'not probed'
  if (option.status === 'NOT_AUTHORIZED') return 'privilege'
  if (/bridge/i.test(why)) return 'bridge'
  if (/not probed|probe did not/i.test(why)) return 'not probed'
  return 'unknown'
}

/**
 * Why no Purge is offered for this device, with the server's exact reason.
 *
 * Null when a Purge is offered. A device with no assessment at all is "not
 * probed", said as such rather than guessed at.
 */
export function purgeAbsence(
  assessment: DeviceAssessment | null | undefined,
): PurgeAbsence | null {
  if (!assessment) {
    return {
      cause: 'not probed',
      causeWord: CAUSE_WORDS['not probed'],
      word: 'not probed',
      tone: 'unknown',
      reason: 'No assessment was returned for this device, so whether it can Purge was not probed.',
      title: 'Device sanitize (Purge)',
      mechanism: '',
      protocol: '',
    }
  }
  const all = [assessment.recommended, ...assessment.alternatives]
  const offered = all.some(
    (option) => option && honestLevel(option) === 'PURGE' && offeredPurge(option),
  )
  if (offered) return null
  const refused = assessment.unavailable.find((option) => option.level === 'PURGE')
  if (!refused) {
    return {
      cause: 'unknown',
      causeWord: CAUSE_WORDS.unknown,
      word: 'not offered',
      tone: 'unknown',
      reason:
        'The server offered no Purge for this device and sent no reason for it.',
      title: 'Device sanitize (Purge)',
      mechanism: '',
      protocol: '',
    }
  }
  const cause = causeOf(refused)
  const word = capabilityWord(refused)
  return {
    cause,
    causeWord: CAUSE_WORDS[cause],
    word: word.word,
    tone: word.tone,
    reason: refused.why,
    title: refused.title,
    mechanism: refused.mechanism ?? '',
    protocol: refused.protocol ?? '',
  }
}

function offeredPurge(option: SanitizeOption): boolean {
  if (option.state) {
    return (
      (RUNNABLE_STATES.has(option.state) ||
        option.state === 'AVAILABLE_BUT_REQUIRES_PRIVILEGE') &&
      Boolean(option.method)
    )
  }
  return (
    option.status === 'SUPPORTED' ||
    option.status === 'SUPPORTED_WITH_LIMITATIONS' ||
    (option.status === 'UNVERIFIED' && Boolean(option.method))
  )
}

/** Why a single unavailable option is unavailable, as a cause word. */
export function optionCause(option: SanitizeOption): string {
  return CAUSE_WORDS[causeOf(option)]
}

// -- acquisition -------------------------------------------------------------------

export interface RawSource {
  /** The path the server re-reads: `\\.\PhysicalDriveN`, `/dev/diskN`, `/dev/sdX`. */
  source: string
  /** The serial the selected disk reported; the server refuses a mismatch. */
  expectedSerial: string
  platform: string
  capability: ResolvedCapability | undefined
  word: StateWord
  allowed: boolean
  /** Why it is refused here, or the capability's own reason when allowed. */
  reason: string
}

/**
 * A raw-device acquisition source, built from a Devices row.
 *
 * The source path and the serial both come from the row the operator picked,
 * never from typing: on Windows and macOS the server re-reads the device and
 * refuses the job unless the serial matches. Whether it may start follows the
 * resolver's raw-acquisition state for that device.
 */
export function rawSource(row: DeviceRow, partition?: string): RawSource {
  const normalized = row.normalized
  const platform = normalized?.platform ?? 'linux'
  // A partition is imaged as the volume it is: the source is its own node, it
  // is bound to the serial of the disk that holds it, and the resolver's
  // volume-acquisition state decides whether it is offered.
  const source = partition || normalized?.path || row.device.path
  const expectedSerial = (normalized?.serial ?? row.device.serial ?? '').trim()
  const capability = deviceCapability(
    row.assessment,
    partition ? 'volume_acquisition' : 'raw_acquisition',
  )
  const word = capabilityWord(capability)
  const serialRequired = platform === 'windows' || platform === 'macos'
  if (serialRequired && !expectedSerial) {
    return {
      source,
      expectedSerial,
      platform,
      capability,
      word,
      allowed: false,
      reason:
        'The disk reports no serial. Raw acquisition on this platform binds to the serial of the selected disk, and the server refuses it without one.',
    }
  }
  if (capability) {
    return {
      source,
      expectedSerial,
      platform,
      capability,
      word,
      allowed: runnableState(capability.state),
      reason: capability.reason,
    }
  }
  // No resolver answer: an older server. Linux always had raw acquisition;
  // elsewhere nothing is claimed.
  return {
    source,
    expectedSerial,
    platform,
    capability,
    word,
    allowed: platform === 'linux',
    reason:
      platform === 'linux'
        ? 'The server sent no capability state for this device; Linux raw acquisition is read-only and was available before the resolver existed.'
        : 'The server sent no capability state for this device, so raw acquisition is not offered.',
  }
}

/**
 * The `POST /jobs/acquire` body for a raw device. The serial always travels
 * with the source: on Windows and macOS the server re-reads the disk and
 * refuses a mismatch; on Linux it is recorded and not needed to open it.
 */
export function acquireBody(
  source: RawSource,
  options: {
    dest: string
    fmt: 'raw' | 'e01'
    compression: 'none' | 'fast' | 'best'
    caseId?: string
  },
): AcquireBody {
  return {
    source: source.source,
    dest: options.dest,
    fmt: options.fmt,
    compression: options.compression,
    case_id: options.caseId ?? '',
    expected_serial: source.expectedSerial,
  }
}


/**
 * Whether the explicit unmount / take-offline step applies to a device row:
 * Windows or macOS, mounted, and not the system disk (the server refuses that
 * anyway, and internal Mac storage too).
 */
export function preparable(row: DeviceRow): boolean {
  const device = row.normalized
  if (!device) return false
  if (device.platform !== 'windows' && device.platform !== 'macos') return false
  return device.mounted && !device.system_device
}
