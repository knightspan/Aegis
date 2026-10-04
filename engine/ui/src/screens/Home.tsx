import { useEffect, useState } from 'react'
import type { LucideIcon } from 'lucide-react'
import {
  ArrowUpRight,
  Blocks,
  FileSearch,
  FileX2,
  FolderKanban,
  HardDrive,
  Link2,
  ScanSearch,
  ScrollText,
  Server,
  ShieldX,
} from 'lucide-react'
import { api } from '../lib/api'
import type {
  CaseDetail,
  CaseSummary,
  LedgerEntry,
  OperationCapability,
  PlatformStatus,
} from '../lib/api'
import { useCase } from '../lib/caseContext'
import { capabilityWord } from '../lib/states'
import { NOT_PHYSICALLY_VALIDATED, judgeSummary } from '../lib/summary'
import { operationKind, operationLabel, shortTime } from '../lib/ledger'
import type { OperationKind } from '../lib/ledger'
import { ChainStrip } from '../components/chain'
import { Panel, Verdict } from '../components/widgets'
import { isHistoricalRehearsal } from '../lib/legacy'

/**
 * The overview: the chain of custody first, then the three modules, then
 * what the open case - or every case - holds so far.
 *
 * Every figure and status here is read from the server. A historical rehearsal
 * record from an earlier build is never counted as an erasure; a capability is the platform
 * probe's word for this host, never a hopeful one. The chain block is the one
 * bold element on the screen because it is the claim everything else rests on:
 * each operation is sealed into an entry that carries the SHA-256 of the one
 * before it.
 */

export type WorkflowTarget = 'recovery' | 'sanitize' | 'files' | 'audit' | 'devices' | 'cases'

/** How many chain entries the overview draws. */
const CHAIN_SHOWN = 9

/** How many entries the statistics read, newest first. */
const CHAIN_READ = 200

function capability(
  platform: PlatformStatus | null,
  operation: string,
): OperationCapability | undefined {
  return platform?.operations.find((row) => row.operation === operation)
}

function CapabilityMark({ row }: { row: OperationCapability | undefined }) {
  if (!row) return <span className="state-mark is-unknown">not probed</span>
  // The resolver's word when the row carries a state, never a generic
  // UNSUPPORTED over it; the older status word only for an older payload.
  const { word, tone } = capabilityWord(row)
  return (
    <span className={`state-mark is-${tone}`} title={row.reason}>
      {word}
    </span>
  )
}

const KIND_ICON: Record<OperationKind, LucideIcon> = {
  erase: ShieldX,
  recover: ScanSearch,
  report: ScrollText,
  case: FolderKanban,
  chain: Link2,
  job: Blocks,
  other: Blocks,
}

function chainTone(status: string): 'seal' | 'destructive' | 'warning' | 'unknown' {
  if (status === 'VALID') return 'seal'
  if (status === 'INCONCLUSIVE_TAIL' || status === 'INCOMPLETE_TAIL') return 'warning'
  if (status === 'UNREAD' || status === 'EMPTY') return 'unknown'
  return 'destructive'
}

function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? '' : 's'}`
}

interface Figure {
  label: string
  value: string
  foot: string
}

function figuresFor(
  detail: CaseDetail | null,
  cases: CaseSummary[],
  entryCount: number | null,
  chainStatus: string,
): Figure[] {
  const sealed: Figure = {
    label: 'Sealed operations',
    value: entryCount === null ? '—' : String(entryCount),
    foot: `Chain ${chainStatus.toLowerCase()}`,
  }
  if (detail) {
    const carves = detail.operations.filter((op) => op.type === 'carve' && op.status === 'complete')
    const recovered = carves.reduce((sum, op) => sum + (op.recovered_artifacts || 0), 0)
    const signed = detail.reports.filter((report) => report.signed).length
    const erased = detail.operations.filter(
      (op) =>
        ['erase-drive', 'erase-files', 'wipe-free-space'].includes(op.type) &&
        !isHistoricalRehearsal(op.params) &&
        op.status === 'complete' &&
        op.verification_passed !== false,
    ).length
    return [
      sealed,
      { label: 'Evidence items', value: String(detail.evidence.length), foot: `In ${detail.case.case_id}` },
      { label: 'Recovered artifacts', value: String(recovered), foot: `From ${plural(carves.length, 'completed recovery run')}` },
      { label: 'Signed reports', value: String(signed), foot: `${plural(erased, 'completed erasure')} in this case` },
    ]
  }
  const sum = (pick: (item: CaseSummary) => number) =>
    cases.reduce((total, item) => total + (pick(item) || 0), 0)
  return [
    sealed,
    { label: 'Cases', value: String(cases.length), foot: plural(sum((c) => c.evidence_count), 'evidence item') + ' registered' },
    {
      label: 'Recovered artifacts',
      value: String(sum((c) => c.recovered_artifact_count)),
      foot: 'Across every case',
    },
    { label: 'Reports', value: String(sum((c) => c.report_count)), foot: 'Across every case' },
  ]
}

const KIND_WORD: Record<OperationKind, string> = {
  erase: 'erase',
  recover: 'recover',
  report: 'report',
  case: 'case',
  chain: 'chain',
  job: 'job',
  other: 'other',
}

/**
 * The sealed-operations figure's tubes: one per kind of operation, filled to
 * its share of the entries read. The same counts are written out for a screen
 * reader and in the tooltip, so the picture never holds a number the text
 * does not.
 */
function KindTubes({ entries }: { entries: LedgerEntry[] }) {
  if (!entries.length) return null
  const counts = new Map<OperationKind, number>()
  for (const entry of entries) {
    const kind = operationKind(entry.operation)
    counts.set(kind, (counts.get(kind) ?? 0) + 1)
  }
  const rows = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6)
  const most = rows[0][1]
  const said = rows.map(([kind, count]) => `${KIND_WORD[kind]} ${count}`).join(', ')
  return (
    <span className="tubes" title={`Of the last ${entries.length} entries: ${said}`}>
      {rows.map(([kind, count]) => (
        <span key={kind} className="tube" aria-hidden>
          <i style={{ height: `${Math.max(8, (count / most) * 100)}%` }} />
        </span>
      ))}
      <span className="visually-hidden">
        Of the last {entries.length} entries: {said}
      </span>
    </span>
  )
}

/**
 * The lifted card: the open case, or this host when none is open. What it
 * holds, what this host can do, and the way into each module along its foot.
 */
function CaseCard({
  openCase,
  platform,
  onOpen,
}: {
  openCase: CaseSummary | null
  platform: PlatformStatus | null
  onOpen: (target: WorkflowTarget) => void
}) {
  const holds = openCase
    ? [
        plural(openCase.evidence_count, 'evidence item'),
        plural(openCase.operation_count, 'operation'),
        plural(openCase.recovered_artifact_count, 'recovered artifact'),
        plural(openCase.report_count, 'report'),
      ]
    : []
  const can: [string, string][] = [
    ['Clear', 'whole_drive_clear'],
    ['Purge', 'whole_drive_purge'],
    ['File erase', 'file_erase'],
  ]
  const tabs: { target: WorkflowTarget; label: string; icon: LucideIcon }[] = [
    { target: 'devices', label: 'Devices', icon: HardDrive },
    { target: 'sanitize', label: 'Drive eraser', icon: ShieldX },
    { target: 'files', label: 'File & folder eraser', icon: FileX2 },
    { target: 'recovery', label: 'Recovery', icon: ScanSearch },
    { target: 'audit', label: 'Audit', icon: Blocks },
  ]
  const osName = (platform?.platform.os_name ?? 'This host').replace(/\s*\(.*\)$/, '')

  return (
    <section className="case-card" data-testid="case-card" aria-labelledby="case-card-name">
      <div className="case-card-field">
        <div className="case-card-bar">
          <h2>{openCase ? 'Open case' : 'This host'}</h2>
          <button
            className="btn icon-only"
            aria-label="Go to cases"
            title="Go to cases"
            onClick={() => onOpen('cases')}
          >
            <ArrowUpRight className="icon" size={18} aria-hidden />
          </button>
        </div>
      </div>
      <span className="case-card-avatar" aria-hidden>
        {openCase ? <FolderKanban size={36} /> : <Server size={36} />}
      </span>
      <div className="case-card-body">
        <div className="col" style={{ gap: 6 }}>
          <p className="case-card-name" id="case-card-name">
            {openCase ? openCase.title || 'Untitled case' : 'No case open'}
          </p>
          <span className="case-card-id">
            {openCase ? `${openCase.case_id}, opened by ${openCase.created_by}` : osName}
          </span>
        </div>

        <div className="case-card-section">
          <h3>{openCase ? 'Description' : 'What happens now'}</h3>
          <p className="note">
            {openCase
              ? openCase.description || 'No description was given when the case was opened.'
              : 'Operations run now are sealed into the chain but filed under no case. Open one first so every erase and recovery lands in an investigation.'}
          </p>
        </div>

        {openCase && (
          <div className="case-card-section">
            <h3>Holds</h3>
            <div className="tags">
              {holds.map((line) => (
                <span key={line} className="tag">
                  {line}
                </span>
              ))}
            </div>
          </div>
        )}

        <div className="case-card-section">
          <h3>This host can</h3>
          <div className="tags">
            {can.map(([label, operation]) => (
              <span key={operation} className="tag">
                {label}
                <CapabilityMark row={capability(platform, operation)} />
              </span>
            ))}
          </div>
        </div>

        <div className="case-card-actions">
          <button className="btn primary" onClick={() => onOpen('cases')}>
            <span className="btn-dot">
              <FolderKanban className="icon" size={11} strokeWidth={3} aria-hidden />
            </span>
            {openCase ? 'Open the case record' : 'Open a case'}
          </button>
          <button
            className="btn icon-only"
            aria-label="Open the audit trail"
            title="Open the audit trail"
            onClick={() => onOpen('audit')}
          >
            <Blocks className="icon" size={17} aria-hidden />
          </button>
          <button
            className="btn icon-only"
            aria-label="Verify a signed report"
            title="Verify a signed report"
            onClick={() => onOpen('audit')}
          >
            <FileSearch className="icon" size={17} aria-hidden />
          </button>
        </div>
      </div>
      <nav className="case-card-tabs" aria-label="Modules">
        {tabs.map((tab) => {
          const Icon = tab.icon
          return (
            <button key={tab.target} aria-label={tab.label} title={tab.label} onClick={() => onOpen(tab.target)}>
              <Icon className="icon" size={19} aria-hidden />
            </button>
          )
        })}
      </nav>
    </section>
  )
}

export default function Home({ onOpen }: { onOpen: (target: WorkflowTarget) => void }) {
  const { openCase } = useCase()
  const [platform, setPlatform] = useState<PlatformStatus | null>(null)
  const [chain, setChain] = useState<{
    status: string
    entry_count: number
    first_broken_seq: number | null
  }>({ status: 'UNREAD', entry_count: 0, first_broken_seq: null })
  const [entries, setEntries] = useState<LedgerEntry[]>([])
  const [cases, setCases] = useState<CaseSummary[]>([])
  // Keyed by case id, so a stale answer for a previous case is never shown.
  const [fetched, setFetched] = useState<{ id: string; body: CaseDetail } | null>(null)
  // A failed read of the open case, keyed the same way. Kept apart from "no
  // case open" so the overview never reads a server failure as an empty case.
  const [unread, setUnread] = useState<{ id: string; message: string } | null>(null)

  useEffect(() => {
    void api.platform().then(setPlatform).catch(() => setPlatform(null))
    void api
      .ledgerVerify()
      .then((answer) =>
        setChain({
          status: answer.status,
          entry_count: answer.entry_count,
          first_broken_seq: answer.first_broken_seq ?? null,
        }),
      )
      .catch(() => setChain({ status: 'UNREAD', entry_count: 0, first_broken_seq: null }))
    void api
      .ledgerEntries(CHAIN_READ)
      .then((answer) => setEntries(answer.entries ?? []))
      .catch(() => setEntries([]))
    void api
      .cases()
      .then((answer) => setCases(answer.cases ?? []))
      .catch(() => setCases([]))
  }, [])

  useEffect(() => {
    if (!openCase) return
    const id = openCase.case_id
    void api
      .case(id)
      .then((body) => {
        setFetched({ id, body })
        setUnread(null)
      })
      .catch((exc: unknown) => {
        setFetched(null)
        setUnread({ id, message: exc instanceof Error ? exc.message : String(exc) })
      })
  }, [openCase])

  const detail = openCase && fetched?.id === openCase.case_id ? fetched.body : null
  const requestFailed = openCase && unread?.id === openCase.case_id ? unread.message : ''
  const summary = judgeSummary(detail, platform, chain.status, requestFailed)
  const shown = entries.slice(0, CHAIN_SHOWN)
  const oldestFirst = [...shown].reverse()
  const head = entries[0]
  const figures = figuresFor(
    detail,
    cases,
    chain.status === 'UNREAD' ? null : chain.entry_count,
    chain.status,
  )

  const modules: {
    target: WorkflowTarget
    icon: LucideIcon
    title: string
    level: string
    does: string
    status: React.ReactNode
  }[] = [
    {
      target: 'devices',
      icon: ShieldX,
      title: 'Drive eraser',
      level: 'NIST SP 800-88 Clear or Purge; Destroy recorded',
      does:
        'Erases a whole HDD, SSD, USB drive or card with the strongest method the drive itself reports, then reads it back. A physical destruction is recorded as its witnesses attest it.',
      status: <CapabilityMark row={capability(platform, 'whole_drive_clear')} />,
    },
    {
      target: 'files',
      icon: FileX2,
      title: 'File & folder eraser',
      level: 'Files, folders, free space, metadata',
      does:
        'Overwrites the files you choose, strips document and photo metadata, removes the thumbnails, recent entries and Trash copies the desktop kept, and says what the filesystem may still hold.',
      status: <CapabilityMark row={capability(platform, 'file_erase')} />,
    },
    {
      target: 'recovery',
      icon: ScanSearch,
      title: 'Recovery',
      level: 'Media map, then signature, structure and fragment carving',
      does:
        'Maps where an image holds data, recovers files from formatted or damaged images without a filesystem, and scores each one with the evidence behind the score.',
      status: <span className="state-mark is-success">read-only</span>,
    },
  ]

  return (
    <>
      <div className="screen-head">
        <h1>Overview</h1>
        <p>Sanitize drives and files, recover evidence, and prove every step.</p>
      </div>
      <div className="screen-body">
        <div className="overview-grid">
          <div className="overview-main">
            <section className="overview-section" aria-labelledby="stats-title">
              <h2 className="section-title" id="stats-title">
                Statistics
              </h2>
              <div className="figures" data-testid="figures">
                {figures.map((figure, index) => (
                  <div key={figure.label} className="figure">
                    <span className="figure-label">{figure.label}</span>
                    <span className="figure-row">
                      <span className="figure-value">{figure.value}</span>
                      {index === 0 && <KindTubes entries={entries} />}
                    </span>
                    <span className="figure-foot">{figure.foot}</span>
                  </div>
                ))}
              </div>
            </section>

            <section className="custody" data-testid="custody" aria-labelledby="custody-title">
              <div className="custody-head">
                <div>
                  <h2 className="custody-title" id="custody-title">
                    Chain of custody
                  </h2>
                  <p className="custody-sub">
                    Every operation is sealed into an entry that carries the SHA-256 of
                    the entry before it. Change one byte of any entry and every later
                    link breaks.
                  </p>
                </div>
                <div className="custody-verdict">
                  <Verdict
                    level={chain.status === 'VALID' ? 'Valid' : chain.status.toLowerCase()}
                    basis={
                      head
                        ? `${chain.entry_count} entries, head ${head.entry_hash.slice(0, 16)}`
                        : `${chain.entry_count} entries`
                    }
                    tone={chainTone(chain.status)}
                  />
                </div>
              </div>
              {oldestFirst.length ? (
                <ChainStrip
                  entries={oldestFirst}
                  firstBrokenSeq={chain.first_broken_seq}
                  label="The most recent entries in the chain, oldest first"
                />
              ) : (
                <p className="note">
                  Nothing has been sealed yet. The first operation starts the chain.
                </p>
              )}
              <div className="row wrap">
                <button className="btn primary" onClick={() => onOpen('audit')}>
                  <Blocks className="icon" size={16} aria-hidden />
                  Open the audit trail
                </button>
                <button className="btn" onClick={() => onOpen('audit')}>
                  <FileSearch className="icon" size={16} aria-hidden />
                  Verify a signed report
                </button>
              </div>
            </section>

            <section className="overview-section" aria-labelledby="modules-title">
              <h2 className="section-title" id="modules-title">
                Modules
              </h2>
              <div className="modules" data-testid="modules">
                {modules.map((module) => {
                  const Icon = module.icon
                  return (
                    <button
                      key={module.target}
                      className="module"
                      onClick={() => onOpen(module.target)}
                    >
                      <span className="module-top">
                        <span className="module-icon">
                          <Icon className="icon" size={20} aria-hidden />
                        </span>
                        <span className="col" style={{ gap: 2 }}>
                          <span className="module-title">{module.title}</span>
                          <span className="module-level">{module.level}</span>
                        </span>
                      </span>
                      <p className="note">{module.does}</p>
                      <span className="module-foot">
                        {module.status}
                        <ArrowUpRight className="icon" size={17} aria-hidden />
                      </span>
                    </button>
                  )
                })}
              </div>
            </section>

            <section className="overview-section" aria-labelledby="updates-title">
              <div className="overview-section-head">
                <h2 className="section-title" id="updates-title">
                  Latest updates
                </h2>
                <span className="note-faint">Newest first, from the chain</span>
              </div>
              {entries.length ? (
                <ul className="activity">
                  {entries.slice(0, 5).map((entry) => {
                    const Icon = KIND_ICON[operationKind(entry.operation)]
                    return (
                      <li key={entry.seq}>
                        <span className="activity-icon">
                          <Icon className="icon" size={18} aria-hidden />
                        </span>
                        <span className="activity-body">
                          <span className="activity-what" title={entry.operation}>
                            {operationLabel(entry.operation)}
                          </span>
                          <span className="activity-hash" title={entry.entry_hash}>
                            {entry.actor} sealed {entry.entry_hash.slice(0, 16)}
                          </span>
                        </span>
                        <span className="activity-when">
                          #{entry.seq}
                          <br />
                          {shortTime(entry.ts_utc)}
                        </span>
                      </li>
                    )
                  })}
                </ul>
              ) : (
                <p className="note">No operations recorded yet.</p>
              )}
            </section>

            <Panel
              title={openCase ? `What case ${openCase.case_id} shows` : 'What this host shows'}
              subtitle={
                openCase
                  ? 'Counted from the case record, the chain and the platform probe'
                  : 'No case open: host capability, chain and design facts only'
              }
            >
              <div className="summary-grid" data-testid="executive-summary">
                {(
                  [
                    ['Secure erasure', summary.erasure],
                    ['Evidence recovery', summary.recovery],
                    ['Verification', summary.verification],
                    ['Safety', summary.safety],
                  ] as const
                ).map(([title, lines]) => (
                  <div key={title} className="col tight">
                    <span className="summary-title">{title}</span>
                    {lines.map((line) => (
                      <span key={line} className="note">
                        {line}
                      </span>
                    ))}
                  </div>
                ))}
              </div>
            </Panel>
          </div>

          <aside className="overview-aside">
            <CaseCard openCase={openCase} platform={platform} onOpen={onOpen} />
            <Panel title="Not proven on hardware, or not available">
              <ul className="limitations">
                {NOT_PHYSICALLY_VALIDATED.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
            </Panel>
          </aside>
        </div>
      </div>
    </>
  )
}
