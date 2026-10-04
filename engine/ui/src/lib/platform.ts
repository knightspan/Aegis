// Plain-language words for the platform model. Pure functions, unit-tested in
// ui/tests/platform.test.ts. Every word here is derived from a status the
// server computed; nothing is asserted by this file.

import type {
  CapabilityState,
  CapabilityStatus,
  DeviceAssessment,
  NormalizedDevice,
  PrivilegeState,
  SafetyCheck,
} from './api'
import type { Tone } from '../components/widgets'

/** One word a judge can read, and the tone it is drawn in. */
export function statusWord(status: CapabilityStatus): { word: string; tone: Tone } {
  switch (status) {
    case 'SUPPORTED':
      return { word: 'Supported', tone: 'success' }
    case 'SUPPORTED_WITH_LIMITATIONS':
      return { word: 'Supported with limits', tone: 'warning' }
    case 'NOT_AUTHORIZED':
      return { word: 'Needs privilege', tone: 'warning' }
    case 'NOT_VERIFIABLE':
      return { word: 'Runs, not verifiable', tone: 'warning' }
    case 'UNVERIFIED':
      return { word: 'Unverified', tone: 'unknown' }
    case 'INCONCLUSIVE':
      return { word: 'Inconclusive', tone: 'unknown' }
    case 'UNSUPPORTED':
      return { word: 'Unsupported', tone: 'destructive' }
  }
}

/**
 * What each status word means, in the order a reader meets them. Paraphrases
 * the definitions in core/platform/model.py; the server decides the status,
 * and this only explains the word.
 */
export const STATUS_MEANINGS: readonly { status: CapabilityStatus; meaning: string }[] = [
  {
    status: 'SUPPORTED',
    meaning: 'A real backend runs on this computer and has a way to check its result.',
  },
  {
    status: 'SUPPORTED_WITH_LIMITATIONS',
    meaning: 'It runs, but part of the claim cannot be made here. Why? names the limits.',
  },
  {
    status: 'NOT_AUTHORIZED',
    meaning: 'A backend exists, but this process lacks the privilege it needs.',
  },
  {
    status: 'NOT_VERIFIABLE',
    meaning: 'It can run, but nothing on this computer can check the result.',
  },
  {
    status: 'UNVERIFIED',
    meaning:
      'The code exists, but no passing test run on this platform, or no run on physical hardware, is recorded for it. Not a claim that it works.',
  },
  {
    status: 'INCONCLUSIVE',
    meaning: 'A probe ran and could not settle the question.',
  },
  {
    status: 'UNSUPPORTED',
    meaning: 'Not available on this platform in this build, or refused outright.',
  },
]

/** Whether an option can actually be started on this host. */
export function runnableStatus(status: CapabilityStatus | undefined): boolean {
  return status === 'SUPPORTED' || status === 'SUPPORTED_WITH_LIMITATIONS'
}

/**
 * Whether a drive option is offered, mirroring `_offerable` in
 * `core/platform/base.py`.
 *
 * With a resolver state: a runnable state (SUPPORTED or IMPLEMENTED /
 * UNVALIDATED), or REQUIRES PRIVILEGE, and a method to run (a Clear always has
 * one). IMPLEMENTED / UNVALIDATED is offered under that word, never as
 * supported. Without a state (an older payload): a runnable status, or
 * UNVERIFIED with a method the engine would run.
 */
export function offeredOption(
  option:
    | {
        status: CapabilityStatus
        method?: string | null
        level?: string
        state?: CapabilityState | null
      }
    | null
    | undefined,
): boolean {
  if (!option) return false
  if (option.state) {
    const available =
      option.state === 'VALIDATED_PHYSICAL' ||
      option.state === 'IMPLEMENTED_NOT_PHYSICALLY_VALIDATED' ||
      option.state === 'AVAILABLE_BUT_REQUIRES_PRIVILEGE'
    return available && (Boolean(option.method) || option.level === 'CLEAR')
  }
  if (runnableStatus(option.status)) return true
  return option.status === 'UNVERIFIED' && Boolean(option.method)
}

export function privilegeWord(privilege: PrivilegeState | null): string {
  if (!privilege) return 'Unknown'
  if (privilege.helper === 'socket') return 'Privileged helper'
  switch (privilege.level) {
    case 'root':
      return 'Root'
    case 'administrator':
      return 'Administrator'
    case 'standard':
      return 'Standard user'
    default:
      return 'Unknown'
  }
}

const INTERFACE_WORDS: Record<string, string> = {
  usb: 'USB',
  nvme: 'NVMe',
  sata: 'SATA',
  mmc: 'SD / memory card',
  sas: 'SAS',
  scsi: 'SCSI',
  thunderbolt: 'Thunderbolt',
  virtual: 'Virtual disk',
}

const MEDIA_WORDS: Record<string, string> = {
  hdd: 'Hard disk',
  ssd: 'SSD',
  flash: 'Flash',
  unknown: 'Unknown medium',
}

/** "External USB flash", "Internal NVMe SSD" - no storage vocabulary needed. */
export function deviceKind(device: NormalizedDevice): string {
  const place =
    device.removable === true ? 'External' : device.removable === false ? 'Internal' : ''
  const bus = INTERFACE_WORDS[device.interface] ?? ''
  const medium = MEDIA_WORDS[device.media_type] ?? 'Unknown medium'
  return [place, bus, medium].filter(Boolean).join(' ')
}

export function deviceName(device: NormalizedDevice): string {
  return [device.vendor, device.model].filter(Boolean).join(' ') || device.id
}

/** The eight steps, in order. The sequence is real: each gates the next. */
export const STEPS = [
  'Choose target',
  'Analyse',
  'Recommended method',
  'Review warning',
  'Confirm',
  'Sanitize',
  'Verify',
  'Certificate',
] as const

export interface FlowState {
  hasDevice: boolean
  hasAssessment: boolean
  reviewing: boolean
  confirming: boolean
  running: boolean
  finished: boolean
  /** Read back and passed. */
  verified: boolean
  certified: boolean
  /** The server refused the erase at its gate: no job was created. */
  refused?: boolean
  /** The job ended without completing: refused by the helper, failed or cancelled. */
  failed?: boolean
  /** The job completed but its read-back verification FAILED. */
  verifyFailed?: boolean
}

/**
 * What a job's read-back says about the Verify step.
 *
 * A verification object existing is not a pass: only `passed === true`
 * verifies. `passed === false` is a failed read-back, and no verification at
 * all verifies nothing.
 */
export function readBack(
  verification: { passed: boolean | null } | null | undefined,
): { verified: boolean; verifyFailed: boolean } {
  return {
    verified: verification?.passed === true,
    verifyFailed: verification?.passed === false,
  }
}

/**
 * Index of the step the operator is on (0-based).
 *
 * A flow that stopped stays on the step where it stopped. A refused or failed
 * job never advances the tracker to Verify: nothing was completed there, and a
 * tracker that moved on would say the erase ran. A failed read-back stops on
 * Verify and never reaches Certificate, whatever else is set.
 */
export function currentStep(state: FlowState): number {
  if (!state.hasDevice) return 0
  if (!state.hasAssessment) return 1
  if (state.verifyFailed) return 6
  if (state.certified) return 7
  if (state.failed) return 5
  if (state.finished) return state.verified ? 7 : 6
  if (state.running) return 5
  if (state.refused || state.confirming) return 4
  if (state.reviewing) return 3
  return 2
}

/** A check that could not be decided is never counted as passed. */
export function checkWord(check: SafetyCheck): { word: string; tone: Tone } {
  if (check.passed === true) return { word: 'yes', tone: 'success' }
  if (check.passed === false) return { word: 'no', tone: 'destructive' }
  return { word: 'unknown', tone: 'unknown' }
}

/** Tone of the whole assessment headline. */
export function headlineTone(assessment: DeviceAssessment | null | undefined): Tone {
  if (!assessment) return 'unknown'
  if (assessment.headline === 'READY') {
    return assessment.status === 'SUPPORTED' ? 'success' : 'warning'
  }
  if (assessment.headline === 'NOT AUTHORIZED') return 'warning'
  return 'destructive'
}
