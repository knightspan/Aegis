import { useEffect, useState } from 'react'
import type { LucideIcon } from 'lucide-react'
import {
  ArchiveRestore,
  Blocks,
  ChevronRight,
  Cpu,
  FileX2,
  FolderKanban,
  Globe,
  HardDrive,
  LayoutDashboard,
  Moon,
  Plus,
  Power,
  ScanSearch,
  Server,
  ShieldCheck,
  ShieldX,
  Sun,
} from 'lucide-react'
import type { DeviceRow, PlatformStatus } from './lib/api'
import { api } from './lib/api'
import { deviceKind, privilegeWord, statusWord } from './lib/platform'
import { capabilityWord } from './lib/states'
import { bytes } from './lib/format'
import Platform from './screens/Platform'
import { CaseProvider, useCase } from './lib/caseContext'
import Audit from './screens/Audit'
import Cases from './screens/Cases'
import Devices from './screens/Devices'
import Home from './screens/Home'
import FileEraser from './screens/FileEraser'
import Recovery from './screens/Recovery'
import Restore from './screens/Restore'
import Sanitize from './screens/Sanitize'
import logoUrl from './assets/sanctum-logo.png'

/**
 * Navigation, in the order an investigation happens.
 *
 * Overview first: the three modules and the open case's summary, so the tool
 * explains itself in one screen. Then Cases, because everything else files
 * itself against one. An examiner opens a case, registers what was seized,
 * recovers from it or sanitizes it, and then reports. A sidebar that opened
 * on a list of block devices invited the operator to start wiping before
 * anything recorded why.
 */
type ScreenId =
  | 'home'
  | 'cases'
  | 'devices'
  | 'sanitize'
  | 'files'
  | 'recovery'
  | 'restore'
  | 'audit'
  | 'platform'

interface NavEntry {
  id: ScreenId
  label: string
  hint: string
  icon: LucideIcon
}

/**
 * Grouped by the three things the tool does - sanitize, recover, prove - in
 * the order an investigation happens. A group label names the verb, not a
 * section of the codebase.
 */
const NAV: { group: string; items: NavEntry[] }[] = [
  {
    group: 'Navigation',
    items: [
      { id: 'home', label: 'Overview', hint: 'The chain of custody, the three modules, the open case', icon: LayoutDashboard },
      { id: 'cases', label: 'Cases', hint: 'Evidence, operations, reports, audit', icon: FolderKanban },
    ],
  },
  {
    group: 'Sanitize',
    items: [
      { id: 'devices', label: 'Devices', hint: 'Enumerate and probe, read-only', icon: HardDrive },
      { id: 'sanitize', label: 'Drive eraser', hint: 'Capability-driven Clear or Purge of a whole drive', icon: ShieldX },
      { id: 'files', label: 'File & folder eraser', hint: 'Files, folders, free space, metadata', icon: FileX2 },
    ],
  },
  {
    group: 'Recover',
    items: [
      { id: 'recovery', label: 'Recovery', hint: 'Carve and undelete, read-only', icon: ScanSearch },
      { id: 'restore', label: 'Disk restore', hint: 'Write a verified backup image back to a disk', icon: ArchiveRestore },
    ],
  },
  {
    group: 'Prove',
    items: [
      { id: 'audit', label: 'Audit', hint: 'Chain, signed reports, verification', icon: Blocks },
      { id: 'platform', label: 'Platform', hint: 'What this computer can do, and why', icon: Cpu },
    ],
  },
]

const SCREEN_GROUP: Record<ScreenId, { group: string; label: string }> = Object.fromEntries(
  NAV.flatMap((section) =>
    section.items.map((item) => [item.id, { group: section.group, label: item.label }]),
  ),
) as Record<ScreenId, { group: string; label: string }>

type Theme = 'light' | 'dark'
const THEME_KEY = 'sanctum.theme'

/**
 * Light or dark, remembered on this workstation only. A stored choice wins;
 * with none, the system's preference. Storage can be unavailable (a locked-down
 * profile), so every read and write is allowed to fail.
 */
function useTheme(): [Theme, (theme: Theme) => void] {
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      const stored = window.localStorage.getItem(THEME_KEY)
      if (stored === 'light' || stored === 'dark') return stored
    } catch {
      // Storage refused: fall through to the system preference.
    }
    return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  })
  useEffect(() => {
    document.documentElement.dataset.theme = theme
  }, [theme])
  return [
    theme,
    (next: Theme) => {
      setTheme(next)
      try {
        window.localStorage.setItem(THEME_KEY, next)
      } catch {
        // Not remembered; the choice still holds for this session.
      }
    },
  ]
}

interface ChainState {
  status: string
  entry_count: number
}

function chainToneOf(chain: ChainState | null): string {
  if (chain?.status === 'VALID') return 'seal'
  if (chain?.status === 'INCONCLUSIVE_TAIL' || chain?.status === 'INCOMPLETE_TAIL') return 'warning'
  return chain ? 'destructive' : 'unknown'
}

/** One claim in the status bar: a muted label, and the value in its state. */
function Pill({
  label,
  value,
  tone,
  title,
}: {
  label: string
  value: string
  tone: string
  title?: string
}) {
  return (
    <span className={`state-mark is-${tone}`} title={title ?? `${label}: ${value}`}>
      <span className="pill-label">{label}</span>
      {value}
    </span>
  )
}

/**
 * The claims that have to be true at a glance, at the bottom of every screen.
 *
 * Each one is read from the server rather than asserted by this file:
 * integrity is the chain's verdict, evidence read-only is a property of the
 * carving path that the health endpoint reports as a limitation when it is
 * *not* true, and the helper line says which privilege boundary is actually in
 * force. A status strip that hard-coded "VALID" would be decoration.
 */
function StatusStrip({
  selected,
  chain,
  platform,
}: {
  selected: DeviceRow | null
  chain: ChainState | null
  platform: PlatformStatus | null
}) {
  const device = selected?.normalized
  const assessment = selected?.assessment
  const sanitization = assessment
    ? assessment.headline === 'READY'
      ? assessment.recommended?.state
        ? capabilityWord(assessment.recommended)
        : statusWord(assessment.status)
      : { word: assessment.headline.toLowerCase(), tone: assessment.headline === 'NOT AUTHORIZED' ? 'warning' : 'destructive' }
    : null
  const verification = assessment?.recommended?.verification
  const osName = (platform?.platform.os_name ?? 'not read').replace(/\s*\(.*\)$/, '')

  return (
    <div className="status-strip" aria-label="Status">
      <Pill label="Platform" value={osName} tone="unknown" title={platform?.platform.os_build} />
      <Pill
        label="Privilege"
        value={privilegeWord(platform?.privilege ?? null)}
        tone={
          platform?.privilege.elevated || platform?.privilege.helper === 'socket'
            ? 'success'
            : 'warning'
        }
        title={platform?.privilege.basis}
      />
      <Pill
        label="Device"
        value={device ? `${deviceKind(device)} ${bytes(device.capacity_bytes)}` : 'none'}
        tone="unknown"
        title={device?.path}
      />
      <Pill
        label="Sanitization"
        value={sanitization?.word ?? 'no device'}
        tone={sanitization?.tone ?? 'unknown'}
        title={assessment?.reason}
      />
      <Pill
        label="Verification"
        value={verification ? 'available' : assessment ? 'not available' : 'no device'}
        tone={verification ? 'success' : 'unknown'}
        title={verification}
      />
      <Pill
        label="Chain"
        value={chain?.status === 'VALID' ? `valid (${chain.entry_count})` : (chain?.status.toLowerCase() ?? 'not read')}
        tone={chainToneOf(chain)}
        title={chain ? `${chain.entry_count} chain entries` : 'chain not read'}
      />
      <Pill label="Evidence" value="read-only" tone="success" title="core/carve never opens O_RDWR" />
    </div>
  )
}

function Shell() {
  const [screen, setScreen] = useState<ScreenId>('home')
  const [selected, setSelected] = useState<DeviceRow | null>(null)
  const [health, setHealth] = useState<Record<string, unknown> | null>(null)
  const [platform, setPlatform] = useState<PlatformStatus | null>(null)
  const [chain, setChain] = useState<ChainState | null>(null)
  const [theme, setTheme] = useTheme()
  const { openCase, cases } = useCase()

  useEffect(() => {
    void api.health().then(setHealth).catch(() => setHealth(null))
    void api.platform().then(setPlatform).catch(() => setPlatform(null))
  }, [])
  // Re-read on every navigation, so the chain line is read, not remembered.
  useEffect(() => {
    void api
      .ledgerVerify()
      .then((answer) => setChain({ status: answer.status, entry_count: answer.entry_count }))
      .catch(() => setChain(null))
  }, [screen])
  // Each screen opens at its top. The scroll container is shared, so without
  // this a screen opened from the bottom of another started half-way down.
  useEffect(() => {
    document.querySelector('.main')?.scrollTo(0, 0)
  }, [screen])
  const buildCommit = String(
    (health?.build as { commit?: string } | undefined)?.commit ?? '',
  )
  const toolVersion = (health?.tool_version as string | undefined) ?? 'offline'

  // A count is drawn only once it has been read from the server.
  const badges: Partial<Record<ScreenId, { value: number; lime?: boolean }>> = {
    cases: cases.length ? { value: cases.length } : undefined,
    audit: chain ? { value: chain.entry_count, lime: true } : undefined,
  }
  const where = SCREEN_GROUP[screen]

  return (
    <div className="shell">
      <nav className="sidebar" aria-label="Sanctum">
        <div className="brand">
          <img className="brand-logo" src={logoUrl} alt="Sanctum Forensics" width={150} height={93} />
        </div>

        <div className="side-scroll">
          <div className="nav">
            {NAV.map((section) => (
              <div key={section.group} className="col" style={{ gap: 0 }}>
                <span className="nav-group">{section.group}</span>
                <div className="nav-list">
                  {section.items.map((item) => {
                    const Icon = item.icon
                    const badge = badges[item.id]
                    return (
                      <button
                        key={item.id}
                        className={screen === item.id ? 'nav-item active' : 'nav-item'}
                        aria-current={screen === item.id ? 'page' : undefined}
                        onClick={() => setScreen(item.id)}
                        title={item.hint}
                      >
                        <Icon className="icon" size={18} aria-hidden />
                        <span className="nav-text">{item.label}</span>
                        {badge && (
                          <span className={badge.lime ? 'nav-badge is-lime' : 'nav-badge'}>
                            {badge.value}
                          </span>
                        )}
                      </button>
                    )
                  })}
                </div>
              </div>
            ))}
          </div>

          {/* The open case, always visible. Every screen files what it does
              against this, so hiding it on one screen would mean an operator
              could start a wipe without seeing which investigation it lands in. */}
          <div className="side-case">
            <span className="side-label">Open case</span>
            <button
              className={openCase ? 'case-badge is-open' : 'case-badge'}
              onClick={() => setScreen('cases')}
              title={openCase ? openCase.title : 'No case is open'}
            >
              <span className="case-avatar">
                <FolderKanban className="icon" size={16} aria-hidden />
              </span>
              <span className="case-badge-text">
                <span className="case-badge-id">
                  {openCase ? openCase.case_id : 'none open'}
                </span>
                <span className="case-badge-label">
                  {openCase ? openCase.title || 'Untitled case' : 'Operations file nowhere'}
                </span>
              </span>
            </button>
            <button className="side-more" onClick={() => setScreen('cases')}>
              <ChevronRight className="icon" size={14} aria-hidden />
              {cases.length ? `All ${cases.length} cases` : 'Open a case'}
            </button>
          </div>
        </div>

        <div className="sidebar-foot">
          <div className="host-row">
            <span className="host-avatar">
              <Server className="icon" size={16} aria-hidden />
            </span>
            <span className="col" style={{ gap: 0, minWidth: 0 }}>
              <span className="host-name">{toolVersion}</span>
              <span className="host-sub">Listening on 127.0.0.1 only</span>
            </span>
            {health?.launcher === true && (
              <button
                className="rail-btn"
                aria-label="Quit Sanctum"
                title="Quit Sanctum"
                onClick={() => {
                  void api.quit().then(() =>
                    document.body.replaceChildren(
                      Object.assign(document.createElement('p'), {
                        className: 'empty',
                        textContent: 'Sanctum has stopped. You can close this window.',
                      }),
                    ),
                  )
                }}
              >
                <Power className="icon" size={15} aria-hidden />
              </button>
            )}
          </div>
          {buildCommit && (
            <span className="mono" title={buildCommit}>
              build {buildCommit.slice(0, 12)}
            </span>
          )}
          {selected && (
            <span className="mono" title={selected.device.path}>
              Selected {selected.device.path}
            </span>
          )}
        </div>
      </nav>

      <div className="main">
        <header className="topbar">
          <span className="topbar-where">
            {where.group !== 'Navigation' && (
              <>
                {where.group}
                <ChevronRight className="icon" size={14} aria-hidden />
              </>
            )}
            <strong>{where.label}</strong>
          </span>
          <div className="topbar-actions">
            <button className="top-link" onClick={() => setScreen('audit')} title="Open the audit trail">
              <ShieldCheck className="icon" size={17} aria-hidden />
              <span className={`state-mark is-${chainToneOf(chain)}`}>
                {chain?.status === 'VALID'
                  ? 'Chain valid'
                  : chain
                    ? `Chain ${chain.status.toLowerCase().replace(/_/g, ' ')}`
                    : 'Chain not read'}
              </span>
            </button>
            <button className="top-link is-secondary" onClick={() => setScreen('platform')}>
              <Cpu className="icon" size={17} aria-hidden />
              Platform
            </button>
            <button className="btn primary" onClick={() => setScreen('cases')}>
              <span className="btn-dot">
                <Plus className="icon" size={13} strokeWidth={3} aria-hidden />
              </span>
              Open a case
            </button>
          </div>
        </header>

        <main className="page">
        {screen === 'home' && <Home onOpen={(target) => setScreen(target)} />}
        {screen === 'cases' && <Cases />}
        {screen === 'devices' && (
          <Devices
            onSelect={(row) => {
              setSelected(row)
              setScreen('sanitize')
            }}
          />
        )}
        {screen === 'sanitize' && <Sanitize selected={selected} />}
        {screen === 'files' && <FileEraser />}
        {screen === 'recovery' && <Recovery />}
        {screen === 'restore' && <Restore />}
        {screen === 'audit' && <Audit />}
        {screen === 'platform' && <Platform />}
        </main>

        <footer className="page-foot">
          <span className="foot-item">
            <Globe className="icon" size={15} aria-hidden />
            Offline: no request leaves this host
          </span>
          <span className="foot-item">NIST SP 800-88 Rev. 2</span>
          <span className="foot-item is-muted">{toolVersion}</span>
          <div className="theme-toggle" role="group" aria-label="Theme">
            <button
              type="button"
              aria-label="Light theme"
              aria-pressed={theme === 'light'}
              onClick={() => setTheme('light')}
            >
              <Sun className="icon" size={15} aria-hidden />
            </button>
            <button
              type="button"
              aria-label="Dark theme"
              aria-pressed={theme === 'dark'}
              onClick={() => setTheme('dark')}
            >
              <Moon className="icon" size={15} aria-hidden />
            </button>
          </div>
        </footer>

        <StatusStrip selected={selected} chain={chain} platform={platform} />
      </div>
    </div>
  )
}

export default function App() {
  return (
    <CaseProvider>
      <Shell />
    </CaseProvider>
  )
}
