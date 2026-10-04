import { useEffect, useState } from 'react'
import { api, artifactUrl, RequestFailed } from '../lib/api'
import type { CaseDetail, CaseSummary, OperationRecord } from '../lib/api'
import { useCase } from '../lib/caseContext'
import {
  caseFacts,
  caseRequestFailed,
  isHistoricalRehearsalOp,
  operationStatus,
  operationType,
  reportsByOperation,
} from '../lib/cases'
import { timestamp } from '../lib/format'
import { HISTORICAL_REHEARSAL_LABEL } from '../lib/legacy'
import { operationLabel } from '../lib/ledger'
import {
  BrowseButton,
  Chip,
  Empty,
  ErrorNotice,
  Evidence,
  Hash,
  Notice,
  Panel,
  Railed,
  Verdict,
} from '../components/widgets'
import type { Tone } from '../components/widgets'
import { ReportSemanticsPanel } from '../components/capabilityState'

/**
 * The case screen: one page that accounts for an investigation.
 *
 * What was seized, what was done to it, what came out, and what the chain says
 * about all of it. Before this, those four answers lived on four screens keyed
 * by job ids the operator had to copy between them.
 *
 * One rule runs through every number here: **the counts come from the case
 * document and the integrity verdict comes from the chain**, and the screen
 * says which is which. The case document is an ordinary mutable JSON index and
 * proves nothing; the hash chain is the record. Rendering the document's word
 * for its own integrity would be the tool vouching for itself.
 */

function chainTone(status: string): Tone {
  if (status === 'VALID') return 'success'
  if (status === 'EMPTY' || status === 'UNREADABLE') return 'unknown'
  if (status === 'INCOMPLETE_TAIL') return 'warning'
  return 'destructive'
}

type TabId =
  | 'overview'
  | 'evidence'
  | 'operations'
  | 'reports'
  | 'audit'

/** Each tab and the count it carries, so a judge sees what is in it unopened. */
function tabsFor(detail: CaseDetail): { id: TabId; label: string; count?: number }[] {
  return [
    { id: 'overview', label: 'Overview' },
    { id: 'evidence', label: 'Evidence', count: detail.evidence.length },
    { id: 'operations', label: 'Operations', count: detail.operations.length },
    { id: 'reports', label: 'Reports', count: detail.reports.length },
    { id: 'audit', label: 'Audit', count: detail.audit.events.length },
  ]
}

function NewCase({ onCreated }: { onCreated: (id: string) => void }) {
  const [caseId, setCaseId] = useState('')
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [error, setError] = useState<{
    message: string
    kind?: string
    remediation?: string
  } | null>(null)

  async function create() {
    setError(null)
    try {
      const answer = await api.createCase({
        case_id: caseId,
        title,
        description,
      })
      onCreated(answer.case.case_id)
      setCaseId('')
      setTitle('')
      setDescription('')
    } catch (exc) {
      const failure = exc as RequestFailed
      setError({
        message: failure.message,
        kind: failure.kind,
        remediation: failure.remediation,
      })
    }
  }

  return (
    <Panel
      title="Open a case"
      subtitle="The author is the local account that opened it, resolved server-side."
    >
      <div className="col">
        <ErrorNotice error={error} />
        <div className="row wrap" style={{ alignItems: 'flex-end' }}>
          <label>
            Case id
            <input
              type="text"
              value={caseId}
              spellCheck={false}
              placeholder="CASE-2026-001"
              onChange={(event) => setCaseId(event.target.value)}
            />
          </label>
          <label className="grow">
            Title
            <input
              type="text"
              value={title}
              placeholder="Seized laptop, exhibit 4"
              onChange={(event) => setTitle(event.target.value)}
            />
          </label>
        </div>
        <label>
          Description
          <input
            type="text"
            value={description}
            placeholder="What this case covers"
            onChange={(event) => setDescription(event.target.value)}
          />
        </label>
        <div className="row">
          <button
            className="btn primary"
            disabled={!caseId}
            onClick={() => void create()}
          >
            Open case
          </button>
        </div>
        <p className="note">
          A case id becomes a filename, so it is checked against a whitelist
          rather than escaped: 1&ndash;64 characters from A&ndash;Z, a&ndash;z,
          0&ndash;9, dot, dash and underscore.
        </p>
      </div>
    </Panel>
  )
}

function RegisterEvidence({
  caseId,
  onRegistered,
}: {
  caseId: string
  onRegistered: () => void
}) {
  const [evidenceId, setEvidenceId] = useState('')
  const [source, setSource] = useState('')
  const [mediaType, setMediaType] = useState('raw image')
  const [sourceHash, setSourceHash] = useState('')
  const [error, setError] = useState<{
    message: string
    kind?: string
    remediation?: string
  } | null>(null)

  async function register() {
    setError(null)
    try {
      await api.registerEvidence(caseId, {
        evidence_id: evidenceId,
        source,
        media_type: mediaType,
        source_hash: sourceHash,
        state: 'registered',
      })
      setEvidenceId('')
      setSource('')
      setSourceHash('')
      onRegistered()
    } catch (exc) {
      const failure = exc as RequestFailed
      setError({
        message: failure.message,
        kind: failure.kind,
        remediation: failure.remediation,
      })
    }
  }

  return (
    <Panel
      title="Register an exhibit"
      subtitle="Records that an exhibit exists. It does not open, read or hash it."
    >
      <div className="col">
        <ErrorNotice error={error} />
        <div className="row wrap" style={{ alignItems: 'flex-end' }}>
          <label>
            Exhibit id
            <input
              type="text"
              value={evidenceId}
              spellCheck={false}
              placeholder="EX-1"
              onChange={(event) => setEvidenceId(event.target.value)}
            />
          </label>
          <label className="grow">
            Source
            <div className="row">
              <input
                type="text"
                className="grow"
                value={source}
                spellCheck={false}
                placeholder="/dev/sdb, or the acquired image path"
                onChange={(event) => setSource(event.target.value)}
              />
              <BrowseButton kind="file" onPick={([chosen]) => setSource(chosen)} />
            </div>
          </label>
          <label>
            Media type
            <input
              type="text"
              value={mediaType}
              onChange={(event) => setMediaType(event.target.value)}
            />
          </label>
          <button
            className="btn"
            disabled={!evidenceId}
            onClick={() => void register()}
          >
            Register
          </button>
        </div>
        <label>
          Source hash (optional)
          <input
            type="text"
            value={sourceHash}
            spellCheck={false}
            placeholder="the digest acquisition recorded, if there is one"
            onChange={(event) => setSourceHash(event.target.value)}
          />
        </label>
        <p className="note">
          Acquisition is a job with its own read-only path and its own chain
          entries. A registration endpoint that quietly read a device would be a
          privileged operation wearing a bookkeeping name.
        </p>
      </div>
    </Panel>
  )
}

/** The last component of a path: the exhibit's name, not the host's layout. */
function sourceName(source: string): string {
  const cleaned = (source || '').replace(/[\\/]+$/, '')
  const cut = Math.max(cleaned.lastIndexOf('/'), cleaned.lastIndexOf('\\'))
  return cut >= 0 ? cleaned.slice(cut + 1) : cleaned
}

/** A job state in the registry's word (or BLOCKED / VERIFY FAILED), coloured by the shared tones. */
function OperationState({ operation }: { operation: OperationRecord }) {
  const { word, tone } = operationStatus(operation)
  return <span className={`state-mark is-${tone}`}>{word}</span>
}

function CaseList({
  cases,
  loading,
  selected,
  onSelect,
}: {
  cases: CaseSummary[]
  loading: boolean
  selected: string | undefined
  onSelect: (id: string) => void
}) {
  return (
    <Panel
      title={`All cases (${cases.length})`}
      subtitle="Select one to open it on every screen."
      tight
    >
      {loading ? (
        <Empty>Reading the case list&hellip;</Empty>
      ) : cases.length === 0 ? (
        <Empty>
          No cases yet. Open one with <strong>Open a case</strong>; every
          operation this tool performs can then be filed against it, and the
          report inherits the case id without anyone retyping it.
        </Empty>
      ) : (
        <div className="scroll-y" style={{ maxHeight: '40vh' }}>
          <table className="itable">
            <colgroup>
              <col style={{ width: 'var(--gutter)' }} />
              <col style={{ width: 150 }} />
              <col />
              <col style={{ width: 82 }} />
              <col style={{ width: 94 }} />
              <col style={{ width: 74 }} />
            </colgroup>
            <thead>
              <tr>
                <th className="rail" />
                <th>Case</th>
                <th>Title</th>
                <th>Evidence</th>
                <th>Operations</th>
                <th>Reports</th>
              </tr>
            </thead>
            <tbody>
              {cases.map((item) => {
                const active = selected === item.case_id
                return (
                  <tr
                    key={item.case_id}
                    className={
                      active
                        ? 'irow is-compact is-openable is-selected'
                        : 'irow is-compact is-openable'
                    }
                    aria-selected={active}
                    onClick={() => onSelect(item.case_id)}
                  >
                    <td className="rail" aria-hidden>
                      <i />
                    </td>
                    <td className="mono">{item.case_id}</td>
                    <td title={item.description}>{item.title || '—'}</td>
                    <td className="mono">{item.evidence_count}</td>
                    <td className="mono">{item.operation_count}</td>
                    <td className="mono">{item.report_count}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  )
}

function Overview({
  detail,
  onOpen,
}: {
  detail: CaseDetail
  onOpen: (tab: TabId) => void
}) {
  const facts = caseFacts(detail)
  const tone = chainTone(detail.audit.chain_status)
  const figures: { tab: TabId; label: string; value: number; foot: string }[] = [
    { tab: 'evidence', label: 'Evidence', value: detail.evidence.length, foot: facts.evidence },
    { tab: 'operations', label: 'Operations', value: detail.operations.length, foot: facts.operations },
    { tab: 'reports', label: 'Reports', value: detail.reports.length, foot: facts.reports },
    { tab: 'audit', label: 'Audit entries', value: detail.audit.events.length, foot: facts.audit },
  ]
  return (
    <div className="col loose">
      {/* The integrity verdict is the chain's, always. The counts below come
          from the case document, which is an index. */}
      <Railed tone={tone}>
        <Verdict
          level={`INTEGRITY: ${detail.audit.chain_status}`}
          basis={`whole chain, ${detail.audit.entry_count} entries; ${detail.audit.events.length} name this case`}
          tone={tone}
        />
        <span className="note">{detail.audit.chain_explanation}</span>
      </Railed>

      <div className="figures">
        {figures.map((figure) => (
          <button
            key={figure.tab}
            type="button"
            className="figure is-link"
            onClick={() => onOpen(figure.tab)}
          >
            <span className="figure-label">{figure.label}</span>
            <span className="figure-value">{figure.value.toLocaleString('en-US')}</span>
            <span className="figure-foot" title={figure.foot}>
              {figure.foot}
            </span>
          </button>
        ))}
      </div>

      <Evidence
        rows={[
          { label: 'Case status', value: detail.case.status },
          { label: 'Opened by', value: detail.case.created_by, kind: 'mono' },
          { label: 'Opened at', value: timestamp(detail.case.created_at), kind: 'mono' },
          { label: 'Last updated', value: timestamp(detail.case.updated_at), kind: 'mono' },
          {
            label: 'Recovered artifacts',
            value: detail.case.recovered_artifact_count.toLocaleString('en-US'),
          },
          { label: 'Description', value: detail.case.description || '—' },
        ]}
      />

      <Notice tone="info">
        The counts above are read from this case&apos;s index document. The
        integrity verdict is read from the hash-chained ledger. Deleting the
        index loses the grouping and loses no evidence; if the two ever
        disagree, the ledger is right.
      </Notice>
    </div>
  )
}

function EvidenceTab({ detail }: { detail: CaseDetail }) {
  if (detail.evidence.length === 0) {
    return (
      <Empty>
        No exhibit is registered against this case yet. Register one below, or
        run an acquisition with this case selected.
      </Empty>
    )
  }
  return (
    <div className="col">
      <div className="scroll-x">
        <table className="itable" style={{ minWidth: 640 }}>
          <colgroup>
            <col style={{ width: 120 }} />
            <col />
            <col style={{ width: 120 }} />
            <col style={{ width: 170 }} />
            <col style={{ width: 110 }} />
          </colgroup>
          <thead>
            <tr>
              <th>Exhibit</th>
              <th>Source</th>
              <th>Type</th>
              <th>Source hash</th>
              <th>State</th>
            </tr>
          </thead>
          <tbody>
            {detail.evidence.map((item) => (
              <tr key={item.evidence_id} className="irow is-compact">
                <td className="mono">{item.evidence_id}</td>
                {/* The exhibit's own name, not where this host keeps it. The
                    full path identifies the examiner's machine rather than the
                    evidence, and this screen is what gets projected; it is
                    under Technical details below, and in the signed report
                    either way. */}
                <td title={item.source}>{sourceName(item.source) || '—'}</td>
                <td className="mono">{item.media_type}</td>
                <td>
                  {item.source_hash ? (
                    <Hash value={item.source_hash} />
                  ) : (
                    <span className="note-faint">not recorded</span>
                  )}
                </td>
                <td className="mono">{item.state}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="note-faint">
        Registering an exhibit records that it exists. It does not open, read
        or hash it; a hash shown here is the one acquisition recorded.
      </p>
      <details className="tech">
        <summary>Technical details: full source paths</summary>
        <div className="tech-body">
          <Evidence
            stacked
            rows={detail.evidence.map((item) => ({
              label: item.evidence_id,
              value: item.source || 'not recorded',
              kind: 'path',
            }))}
          />
        </div>
      </details>
    </div>
  )
}

function OperationsTab({ detail }: { detail: CaseDetail }) {
  if (detail.operations.length === 0) {
    return (
      <Empty>
        No operation has been run under this case. Start a recovery or a
        sanitization with this case open and it appears here.
      </Empty>
    )
  }
  const reports = reportsByOperation(detail.reports)
  return (
    <div className="col">
      <div className="scroll-x">
        <table className="itable" style={{ minWidth: 640 }}>
          <colgroup>
            <col style={{ width: 'var(--gutter)' }} />
            <col style={{ width: 280 }} />
            <col style={{ width: 112 }} />
            <col />
            <col style={{ width: 104 }} />
          </colgroup>
          <thead>
            <tr>
              <th className="rail" />
              <th>Operation</th>
              <th>Job state</th>
              <th>Operator</th>
              <th>Report</th>
            </tr>
          </thead>
          <tbody>
            {detail.operations.map((item) => {
              const report = reports.get(item.operation_id)
              return (
                <tr key={item.operation_id} className="irow">
                  <td
                    className={`rail is-${operationStatus(item).tone}`}
                    aria-hidden
                  >
                    <i />
                  </td>
                  {/* What it was, in words, over the id the Audit screen asks
                      for: the judge reads the first line, the operator copies
                      the second. */}
                  <td
                    title={`started ${timestamp(item.started_at)}, finished ${timestamp(item.completed_at)}, ${item.recovered_artifacts} artifact(s) recovered`}
                  >
                    <span className="cell-stack">
                      <span className="row" style={{ gap: 'var(--space-2)' }}>
                        {operationType(item.type)}
                        {isHistoricalRehearsalOp(item) && (
                          <Chip>{HISTORICAL_REHEARSAL_LABEL}</Chip>
                        )}
                      </span>
                      <span className="mono note-faint">{item.operation_id}</span>
                    </span>
                  </td>
                  <td>
                    <OperationState operation={item} />
                  </td>
                  <td className="mono" title={item.operator}>
                    {item.operator}
                  </td>
                  <td>
                    {report ? (
                      <span
                        className={`state-mark ${report.signed ? 'is-seal' : 'is-unknown'}`}
                      >
                        {report.signed ? 'SIGNED' : 'UNSIGNED'}
                      </span>
                    ) : (
                      <span className="note-faint">none</span>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      <p className="note-faint">
        The job state is the job registry&apos;s word for how the run ended,
        with two exceptions: BLOCKED is a safety refusal before any write (the
        registry says failed), and VERIFY FAILED is a drive erase that ran but
        whose read-back failed (the registry says complete). The full
        verification is on the report. Generate one from the Audit screen with
        the operation id.
      </p>
    </div>
  )
}

function ReportsTab({ detail }: { detail: CaseDetail }) {
  if (detail.reports.length === 0) {
    return (
      <Empty>
        No report has been generated for this case. Generate one from the Audit
        screen using an operation id from the Operations tab.
      </Empty>
    )
  }
  // Drive reports carry `method.semantics`: the category and the assurance
  // the report may claim. They are read from the signed JSON itself.
  const kinds = new Map(detail.operations.map((op) => [op.operation_id, op.type]))
  return (
    <div className="col">
      {detail.reports.map((item) => (
        // Seal means cryptographically attested: only a signed report has it.
        <Railed key={item.report_id} tone={item.signed ? 'seal' : 'unknown'}>
          <div className="row wrap spread">
            <span className="mono">{item.operation_id}</span>
            <span className={`state-mark ${item.signed ? 'is-seal' : 'is-unknown'}`}>
              {item.signed ? 'SIGNED' : 'UNSIGNED'}
            </span>
          </div>
          <Evidence
            rows={[
              { label: 'Generated', value: timestamp(item.generated_at), kind: 'mono' },
              { label: 'SHA-256 (JSON)', value: item.report_hash, kind: 'hash' },
              ...(item.pubkey_fingerprint
                ? [
                    {
                      label: 'Key fingerprint',
                      value: item.pubkey_fingerprint,
                      kind: 'hash' as const,
                    },
                  ]
                : []),
            ]}
          />
          {kinds.get(item.operation_id) === 'erase-drive' && (
            <ReportSemanticsPanel url={artifactUrl('reports', item.json_name)} />
          )}
          <div className="row wrap" style={{ gap: 'var(--space-2)' }}>
            <a
              className="btn"
              href={artifactUrl('reports', item.pdf_name)}
              target="_blank"
              rel="noreferrer"
            >
              Open PDF
            </a>
            <a
              className="btn"
              href={artifactUrl('reports', item.pdf_name, {
                download: true,
              })}
            >
              Download PDF
            </a>
            <a
              className="btn"
              href={artifactUrl('reports', item.json_name)}
              target="_blank"
              rel="noreferrer"
            >
              View JSON
            </a>
          </div>
          <span className="note-faint">
            The JSON is authoritative and the PDF is not: the signature covers
            the canonical JSON bytes. Verify it on the Audit screen.
          </span>
        </Railed>
      ))}
    </div>
  )
}

function AuditTab({ detail }: { detail: CaseDetail }) {
  if (detail.audit.events.length === 0) {
    return <Empty>The chain carries no entries for this case yet.</Empty>
  }
  return (
    <div className="col">
      <p className="note">
        The hash-chained ledger entries that name this case, newest first. Each
        entry holds the SHA-256 of the one before it; the Audit screen verifies
        the whole chain and demonstrates tampering on a copy.
      </p>
      <div className="scroll-y scroll-x" style={{ maxHeight: '52vh' }}>
        <table className="itable" style={{ minWidth: 760 }}>
          <colgroup>
            <col style={{ width: 'var(--gutter)' }} />
            <col style={{ width: 56 }} />
            <col style={{ width: 196 }} />
            <col style={{ width: 180 }} />
            <col />
            <col style={{ width: 152 }} />
          </colgroup>
          <thead>
            <tr>
              <th className="rail" />
              <th>Seq</th>
              <th>Timestamp</th>
              <th>Actor</th>
              <th>Event</th>
              <th>Entry hash</th>
            </tr>
          </thead>
          <tbody>
            {detail.audit.events.map((item) => {
              const broken =
                detail.audit.first_broken_seq !== null &&
                item.seq >= detail.audit.first_broken_seq
              return (
                <tr
                  key={item.current_hash}
                  className={broken ? 'irow is-compact is-bad' : 'irow is-compact'}
                >
                  <td className={broken ? 'rail is-destructive' : 'rail'} aria-hidden>
                    <i />
                  </td>
                  <td className="mono">{item.seq}</td>
                  <td className="mono">{timestamp(item.timestamp)}</td>
                  <td className="mono" title={item.actor}>
                    {item.actor}
                  </td>
                  <td title={item.event}>{operationLabel(item.event)}</td>
                  <td>
                    <Hash value={item.current_hash} />
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export default function Cases() {
  const { cases, openCase, select, refresh, loading } = useCase()
  const [detail, setDetail] = useState<CaseDetail | null>(null)
  const [tab, setTab] = useState<TabId>('overview')
  const [error, setError] = useState<{
    message: string
    kind?: string
    remediation?: string
  } | null>(null)

  async function load(caseId: string) {
    setError(null)
    try {
      setDetail(await api.case(caseId))
    } catch (exc) {
      const failure = exc as RequestFailed
      setDetail(null)
      setError({
        message: caseRequestFailed(failure.message),
        kind: failure.kind,
        remediation: failure.remediation,
      })
    }
  }

  useEffect(() => {
    if (openCase) void load(openCase.case_id)
    else setDetail(null)
  }, [openCase?.case_id])

  async function closeOpenCase(caseId: string) {
    const sure = window.confirm(
      `Close case ${caseId}? It keeps everything recorded against it, stops ` +
        'taking new evidence, and the closing is written to the audit chain.',
    )
    if (!sure) return
    setError(null)
    try {
      await api.closeCase(caseId)
      await refresh()
      select(null)
    } catch (exc) {
      const failure = exc as RequestFailed
      setError({
        message: caseRequestFailed(failure.message),
        kind: failure.kind,
        remediation: failure.remediation,
      })
    }
  }

  // The open case comes first: it is what a first-time reader is looking
  // for. The list and the form to open another follow it.
  const shown = openCase && detail?.case.case_id === openCase.case_id ? detail : null
  const integrity = shown ? chainTone(shown.audit.chain_status) : 'unknown'

  return (
    <>
      <div className="screen-head">
        <h1>Cases</h1>
        <p>
          Evidence, operations, reports and the audit trail, grouped by
          investigation.
        </p>
        <div className="grow" />
        <button
          className="btn"
          onClick={() => {
            void refresh()
            if (openCase) void load(openCase.case_id)
          }}
        >
          Refresh
        </button>
      </div>

      <div className="screen-body">
        <ErrorNotice error={error} />

        {shown && (
          <>
            <Panel
              title={shown.case.case_id}
              subtitle={shown.case.title || undefined}
              actions={
                <span className="row" style={{ gap: 'var(--space-3)' }}>
                  <Chip>case {shown.case.status}</Chip>
                  <span className={`state-mark is-${integrity}`}>
                    Chain {shown.audit.chain_status}
                  </span>
                  <button className="btn" onClick={() => select(null)}>
                    Deselect
                  </button>
                  {shown.case.status !== 'closed' && (
                    <button
                      className="btn"
                      onClick={() => void closeOpenCase(shown.case.case_id)}
                    >
                      Close case
                    </button>
                  )}
                </span>
              }
            >
              <div className="col loose">
                <div className="row wrap" role="tablist" aria-label="Case sections">
                  {tabsFor(shown).map((item) => (
                    <button
                      key={item.id}
                      role="tab"
                      aria-selected={tab === item.id}
                      className={tab === item.id ? 'btn primary' : 'btn'}
                      onClick={() => setTab(item.id)}
                    >
                      {item.label}
                      {item.count !== undefined && (
                        <span className="tab-count">{item.count}</span>
                      )}
                    </button>
                  ))}
                </div>

                <div role="tabpanel">
                  {tab === 'overview' && <Overview detail={shown} onOpen={setTab} />}
                  {tab === 'evidence' && <EvidenceTab detail={shown} />}
                  {tab === 'operations' && <OperationsTab detail={shown} />}
                  {tab === 'reports' && <ReportsTab detail={shown} />}
                  {tab === 'audit' && <AuditTab detail={shown} />}
                </div>
              </div>
            </Panel>

            {tab === 'evidence' && shown.case.status !== 'closed' && (
              <RegisterEvidence
                caseId={shown.case.case_id}
                onRegistered={() => void load(shown.case.case_id)}
              />
            )}
          </>
        )}

        {!openCase && cases.length > 0 && (
          <Panel title="No case open">
            <Empty>
              Select a case below. Every screen then files what it does against
              it, and a report generated later inherits the case id rather than
              having it retyped.
            </Empty>
          </Panel>
        )}

        <div className="cases-split">
          <CaseList
            cases={cases}
            loading={loading}
            selected={openCase?.case_id}
            onSelect={select}
          />
          <NewCase
            onCreated={(id) => {
              void refresh().then(() => select(id))
            }}
          />
        </div>
      </div>
    </>
  )
}
