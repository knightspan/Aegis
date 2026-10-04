import { createContext, useContext, useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { api } from './api'
import type { CaseSummary } from './api'

/**
 * The open case, shared by every screen.
 *
 * Every operation this tool performs belongs to an investigation, and before
 * this the only place that fact was recorded was a text box on the Audit
 * screen that the operator retyped for each report. Holding the selection in
 * one place means a recovery started from the Recovery screen and a wipe
 * started from the Sanitize screen file themselves against the same case
 * without the operator restating it, and a report generated later inherits it.
 *
 * Deliberately *not* persisted to localStorage. The open case is part of what
 * an examiner is asserting about a run, and a stale selection silently
 * restored on the next launch is the wrong kind of convenience: a wipe filed
 * against yesterday's case because the browser remembered it is a
 * chain-of-custody error the tool would have introduced by itself.
 */
export interface CaseContextValue {
  /** The open case, or null when none has been chosen. */
  openCase: CaseSummary | null
  /** Every case the server knows about, newest first. */
  cases: CaseSummary[]
  /** Select a case by id, or clear the selection with null. */
  select: (caseId: string | null) => void
  /** Re-read the case list from the server. */
  refresh: () => Promise<void>
  loading: boolean
}

const CaseContext = createContext<CaseContextValue>({
  openCase: null,
  cases: [],
  select: () => {},
  refresh: async () => {},
  loading: false,
})

export function CaseProvider({ children }: { children: ReactNode }) {
  const [cases, setCases] = useState<CaseSummary[]>([])
  const [caseId, setCaseId] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  async function refresh() {
    setLoading(true)
    try {
      setCases((await api.cases()).cases)
    } catch {
      // A case list that cannot be read is an empty one on screen. The panels
      // that need it render their own empty state, which explains what is
      // missing; a thrown error here would blank every screen at once.
      setCases([])
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void refresh()
  }, [])

  const openCase = cases.find((item) => item.case_id === caseId) ?? null

  return (
    <CaseContext.Provider
      value={{ openCase, cases, select: setCaseId, refresh, loading }}
    >
      {children}
    </CaseContext.Provider>
  )
}

export function useCase(): CaseContextValue {
  return useContext(CaseContext)
}
