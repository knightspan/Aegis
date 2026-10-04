// PII triage on the Recovery screen: labels, totals, filter and sort.
//
// Everything here works from kinds and counts, because that is all the server
// sends. There is no value to display, and this module must never be the
// place one appears. Free of React so `node --test` runs it directly.

import type { CarveCandidate } from './api'

/** Display names for the kinds core/carve/pii.py reports, in its order. */
export const PII_LABELS: Record<string, string> = {
  aadhaar: 'Aadhaar',
  pan: 'PAN',
  ifsc: 'IFSC',
  indian_mobile: 'Mobile',
  payment_card: 'Card',
  email: 'Email',
}

export const PII_KINDS = Object.keys(PII_LABELS)

/** Total identifiers counted in one object; 0 when not inspected. */
export function piiTotal(candidate: CarveCandidate): number {
  const counts = candidate.pii?.counts ?? {}
  return Object.values(counts).reduce((sum, value) => sum + value, 0)
}

/**
 * The one-line cell: "Aadhaar 2 · Card 1", "none seen", or "not scanned".
 * "none seen" is not "none present" - the detectors look for shapes.
 */
export function piiSummary(candidate: CarveCandidate): string {
  if (!candidate.pii?.inspected) return 'not scanned'
  const parts = PII_KINDS.filter((kind) => candidate.pii!.counts[kind]).map(
    (kind) => `${PII_LABELS[kind]} ${candidate.pii!.counts[kind]}`,
  )
  return parts.length ? parts.join(' · ') : 'none seen'
}

/** Filter values: '' all, 'any' any identifier, or one kind. */
export function matchesPii(candidate: CarveCandidate, filter: string): boolean {
  if (!filter) return true
  if (filter === 'any') return piiTotal(candidate) > 0
  return (candidate.pii?.counts[filter] ?? 0) > 0
}

/**
 * Most identifiers first, then most kinds, then image order. Returns a new
 * array; the server's order is left alone for every other view.
 */
export function sortByPii(candidates: CarveCandidate[]): CarveCandidate[] {
  const kinds = (item: CarveCandidate) =>
    Object.values(item.pii?.counts ?? {}).filter((value) => value > 0).length
  return [...candidates].sort(
    (a, b) =>
      piiTotal(b) - piiTotal(a) || kinds(b) - kinds(a) || a.offset - b.offset,
  )
}
