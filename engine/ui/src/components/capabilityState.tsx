import { useEffect, useState } from 'react'
import { api } from '../lib/api'
import type { DeviceAssessment } from '../lib/api'
import { capabilityWord, deviceCapabilityLines } from '../lib/states'
import type { StatefulRow } from '../lib/states'
import { isReportUrl, reportSemantics } from '../lib/semantics'
import type { ReportSemantics as Semantics } from '../lib/semantics'
import { Evidence, Limitations } from './widgets'

/**
 * A capability's word: the resolver's `state_label` when the row carries a
 * state, the older status word only when it does not.
 */
export function StateMark({ row, title }: { row: StatefulRow | null | undefined; title?: string }) {
  const word = capabilityWord(row)
  return (
    <span
      className={`state-mark is-${word.tone}`}
      data-state={word.precise ? word.value : undefined}
      data-status={word.precise ? undefined : word.value}
      title={title}
    >
      {word.word}
    </span>
  )
}

/**
 * Every capability the resolver answered for one device, each with its word,
 * its reason and the mechanism it would use. Nothing here is a checkmark: a
 * line with no state is not drawn.
 */
export function DeviceCapabilityList({ assessment }: { assessment: DeviceAssessment | null | undefined }) {
  const lines = deviceCapabilityLines(assessment)
  if (lines.length === 0) {
    return (
      <p className="note-faint">
        The server sent no per-capability answer for this device.
      </p>
    )
  }
  return (
    <ul className="cap-list" aria-label="Device capabilities">
      {lines.map((item) => (
        <li key={item.key} data-capability={item.key}>
          <span className="cap-list-name">{item.name}</span>
          <span className={`state-mark is-${item.tone}`}>{item.word}</span>
          <span className="cap-list-reason">{item.reason}</span>
          {item.mechanism && (
            <span className="cap-list-mech mono">
              {item.protocol ? `${item.protocol} · ` : ''}
              {item.mechanism}
            </span>
          )}
        </li>
      ))}
    </ul>
  )
}

/** The category and assurance words of a drive report, as its signer wrote them. */
export function SemanticsView({ semantics }: { semantics: Semantics }) {
  return (
    <div className="col tight" data-testid="report-semantics">
      <Evidence
        stacked
        rows={[
          { label: 'Category', value: <strong>{semantics.category}</strong> },
          { label: 'Method', value: semantics.method || 'not recorded' },
          {
            label: 'Protocol / transport',
            value: `${semantics.protocol || 'not recorded'} · ${semantics.transport || 'not recorded'}`,
            kind: 'mono',
          },
          { label: 'Scope', value: semantics.scope || 'not recorded' },
          { label: 'Verification', value: semantics.verification || 'not recorded' },
          { label: 'Assurance', value: semantics.assurance || 'not recorded' },
        ]}
      />
      <Limitations items={semantics.limitations} title="Limitations the report states" />
    </div>
  )
}

/**
 * Reads a signed report's JSON through its artifact URL and shows what the
 * report says it is. A report with no `method.semantics` (not a drive report,
 * or signed before the categories existed) says exactly that.
 */
export function ReportSemanticsPanel({ url }: { url: string }) {
  const [state, setState] = useState<{
    url: string
    semantics: Semantics | null
    error: string
  } | null>(null)

  useEffect(() => {
    if (!isReportUrl(url)) return
    let stale = false
    api
      .reportJson(url)
      .then((json) => {
        if (!stale) setState({ url, semantics: reportSemantics(json), error: '' })
      })
      .catch((exc: Error) => {
        if (!stale) setState({ url, semantics: null, error: exc.message })
      })
    return () => {
      stale = true
    }
  }, [url])

  if (!isReportUrl(url)) return null
  if (!state || state.url !== url) {
    return <p className="note-faint">Reading the signed report&hellip;</p>
  }
  if (state.error) {
    return (
      <p className="note-faint">
        The signed report could not be read ({state.error}), so its category is
        not shown.
      </p>
    )
  }
  if (!state.semantics) {
    return (
      <p className="note-faint" data-testid="report-semantics-none">
        Category: not recorded in this report (not a drive report, or signed
        before categories were recorded).
      </p>
    )
  }
  return <SemanticsView semantics={state.semantics} />
}
