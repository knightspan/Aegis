/**
 * The graded report verdict, as the verifier in core computed it.
 *
 * The screen never grades a report itself. It renders the word the server sent
 * and every reason for a downgrade, and it refuses to colour an unknown word as
 * a success: a verdict the screen does not recognise is shown as unknown.
 */

export type ReportVerdictWord =
  | 'VERIFIED'
  | 'VERIFIED_WITH_LIMITATIONS'
  | 'PARTIAL'
  | 'FAILED_VERIFICATION'

export type VerdictTone = 'destructive' | 'warning' | 'success' | 'unknown'

const MEANING: Record<ReportVerdictWord, { tone: VerdictTone; label: string }> = {
  VERIFIED: {
    tone: 'success',
    label: 'All five checks ran and passed, and the report declares no limitation.',
  },
  VERIFIED_WITH_LIMITATIONS: {
    tone: 'warning',
    label:
      'All five checks ran and passed. The report is authentic and declares ' +
      'limits on what it proves; read them below.',
  },
  PARTIAL: {
    tone: 'warning',
    label:
      'Every check that ran passed, but at least one could not run here, so ' +
      'less was confirmed than the five checks can confirm.',
  },
  FAILED_VERIFICATION: {
    tone: 'destructive',
    label: 'A check failed. Do not treat this report as evidence until you know why.',
  },
}

export function verdictMeaning(word: string | undefined): {
  tone: VerdictTone
  label: string
  known: boolean
} {
  if (word && word in MEANING) {
    return { ...MEANING[word as ReportVerdictWord], known: true }
  }
  return {
    tone: 'unknown',
    label: 'The server sent no verdict this screen recognises.',
    known: false,
  }
}
