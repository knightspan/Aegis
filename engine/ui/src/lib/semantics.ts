// What a drive report may claim, read from the signed report itself. Pure, and
// free of React: see ui/tests/semantics.test.ts.
//
// The words are core/report/semantics.py's, carried in the signed JSON under
// `method.semantics`. The screen shows them; it never derives a category of
// its own from a method name.

/** The five certificate categories, never merged. */
export const REPORT_CATEGORIES = [
  'FILE ERASE',
  'ADDRESSABLE WHOLE-DRIVE CLEAR',
  'DEVICE SANITIZE',
  'CRYPTO ERASE',
  'PHYSICAL DESTRUCTION ATTESTATION',
] as const

export interface ReportSemantics {
  category: string
  method: string
  protocol: string
  transport: string
  scope: string
  verification: string
  assurance: string
  limitations: string[]
}

function text(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

/**
 * `method.semantics` from a signed report's JSON, or null when the report has
 * none (a carve, file-erase or destruction report, or one signed before the
 * categories existed). Null is "not recorded", and the screen says so rather
 * than guessing a category.
 */
export function reportSemantics(report: unknown): ReportSemantics | null {
  if (!report || typeof report !== 'object') return null
  const method = (report as Record<string, unknown>).method
  if (!method || typeof method !== 'object') return null
  const words = (method as Record<string, unknown>).semantics
  if (!words || typeof words !== 'object') return null
  const row = words as Record<string, unknown>
  const category = text(row.category)
  if (!category) return null
  return {
    category,
    method: text(row.method),
    protocol: text(row.protocol),
    transport: text(row.transport),
    scope: text(row.scope),
    verification: text(row.verification),
    assurance: text(row.assurance),
    limitations: Array.isArray(row.limitations)
      ? row.limitations.filter((item): item is string => typeof item === 'string')
      : [],
  }
}

/** Only the reports directory's artifact URLs are fetched for this. */
export function isReportUrl(url: string): boolean {
  return url.startsWith('/artifacts/reports/') && !url.split('/').includes('..')
}
