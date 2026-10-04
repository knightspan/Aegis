/**
 * The Destroy record form, without the form.
 *
 * Destroy is the NIST SP 800-88 Rev. 2 outcome no software performs: a
 * shredder or a furnace does it. The interface only records what the people
 * who did it attest, so these helpers prefill what the machine knows about a
 * device, say what is still missing, and turn a local date and time into the
 * ISO string the server stores. They never decide that a destruction happened.
 */

import type { Device, DestroyMediaType, DestroyTechnique } from './api'

export const TECHNIQUES: { value: DestroyTechnique; label: string }[] = [
  { value: 'SHRED', label: 'Shred' },
  { value: 'DISINTEGRATE', label: 'Disintegrate' },
  { value: 'PULVERIZE', label: 'Pulverize' },
  { value: 'INCINERATE', label: 'Incinerate' },
  { value: 'MELT', label: 'Melt' },
  { value: 'OTHER', label: 'Other (describe it)' },
]

export const MEDIA_TYPES: { value: DestroyMediaType; label: string }[] = [
  { value: 'HDD', label: 'Hard disk' },
  { value: 'SSD', label: 'Solid-state drive' },
  { value: 'USB', label: 'USB flash drive' },
  { value: 'SD_CARD', label: 'Memory card' },
  { value: 'OPTICAL', label: 'Optical disc' },
  { value: 'TAPE', label: 'Tape' },
  { value: 'OTHER', label: 'Other' },
]

/** The media type a detected device most likely is; the operator can change it. */
export function mediaTypeOf(device: Device): DestroyMediaType {
  const transport = device.transport.toLowerCase()
  if (transport === 'usb') return 'USB'
  if (transport === 'mmc' || transport === 'sd') return 'SD_CARD'
  return device.rotational ? 'HDD' : 'SSD'
}

export interface DestroyDraft {
  serial: string
  reason: string
  performedBy: string
  performedAt: string
  technique: DestroyTechnique
  techniqueDetail: string
}

/** What must still be filled in before the record can be submitted. */
export function missingFields(draft: DestroyDraft): string[] {
  const missing: string[] = []
  if (!draft.serial.trim()) missing.push('serial number')
  if (!draft.reason.trim()) missing.push('why it was destroyed')
  if (!draft.performedBy.trim()) missing.push('who destroyed it')
  if (!draft.performedAt) missing.push('when it was destroyed')
  if (draft.technique === 'OTHER' && !draft.techniqueDetail.trim()) {
    missing.push('what the other technique was')
  }
  return missing
}

function pad(value: number): string {
  return String(Math.abs(value)).padStart(2, '0')
}

/**
 * "2026-09-24T15:30" from a datetime-local input, as ISO 8601 with this
 * machine's offset: the moment the operator meant, not the same clock
 * reading in UTC.
 */
export function localToIso(local: string, offsetMinutes: number): string {
  if (!local) return ''
  const east = -offsetMinutes
  const sign = east >= 0 ? '+' : '-'
  const seconds = local.length === 16 ? ':00' : ''
  return `${local}${seconds}${sign}${pad(Math.trunc(east / 60))}:${pad(east % 60)}`
}
