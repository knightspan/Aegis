/**
 * The media map, in words.
 *
 * The server classes each region of an evidence image by its byte statistics
 * (core/carve/mediamap.py). This file names the classes, orders them, and
 * describes a region for its tooltip. It decides nothing about the image.
 */

import type { MediaMap, MediaRegion } from './api'

/** The classes, in the order the strip and the legend draw them. */
export const MAP_KINDS = ['ZERO', 'FILL', 'TEXT', 'STRUCTURED', 'HIGH_ENTROPY'] as const

const WORDS: Record<string, { name: string; means: string }> = {
  ZERO: { name: 'Zeroed', means: 'all bytes 0x00: never written, or wiped' },
  FILL: { name: 'Fill pattern', means: 'one byte repeated: erased flash, or a wipe pattern' },
  TEXT: { name: 'Text', means: 'mostly printable characters' },
  STRUCTURED: { name: 'Structured binary', means: 'executables, databases, filesystem metadata' },
  HIGH_ENTROPY: {
    name: 'High entropy',
    means: 'compressed, encrypted or random; the bytes alone do not say which',
  },
}

export function kindName(kind: string): string {
  return WORDS[kind]?.name ?? kind
}

export function kindMeaning(kind: string): string {
  return WORDS[kind]?.means ?? ''
}

/** A class's share of the image, in whole percent; "<1%" rather than a false 0. */
export function sharePercent(map: MediaMap, kind: string): string {
  const bytes = map.by_kind[kind] ?? 0
  if (!bytes || !map.size_bytes) return '0%'
  const percent = (100 * bytes) / map.size_bytes
  return percent < 1 ? '<1%' : `${Math.round(percent)}%`
}

function hex(value: number): string {
  return `0x${value.toString(16).toUpperCase()}`
}

/** One line for a region's tooltip: where it is, what it is, how sure. */
export function describeRegion(region: MediaRegion): string {
  const end = region.offset + region.length
  const parts = [
    `${hex(region.offset)} to ${hex(end)}`,
    `${kindName(region.kind)} in ${Math.floor(region.share_bp / 100)}% of the blocks read`,
    `${(region.entropy_mb / 1000).toFixed(2)} bits per byte`,
  ]
  if (region.fill_byte !== null) parts.push(`fill byte ${hex(region.fill_byte)}`)
  const headers = Object.entries(region.headers)
    .map(([ext, count]) => `${count} ${ext}`)
    .join(', ')
  if (headers) parts.push(`headers: ${headers}`)
  if (region.substituted) parts.push('includes bytes substituted for unreadable ones')
  return parts.join('; ')
}

/** Bytes that could hold recoverable content: everything not zeroed or filled. */
export function contentBytes(map: MediaMap): number {
  return map.size_bytes - (map.by_kind.ZERO ?? 0) - (map.by_kind.FILL ?? 0)
}
