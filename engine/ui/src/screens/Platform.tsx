import { useEffect, useState } from 'react'
import { api, RequestFailed } from '../lib/api'
import type { CapabilityStatus, OperationCapability, PlatformStatus } from '../lib/api'
import { privilegeWord, STATUS_MEANINGS, statusWord } from '../lib/platform'
import { NOT_PHYSICALLY_VALIDATED, SAFETY_LINES } from '../lib/summary'
import { platformMatrix, STATE_MEANINGS, STATE_TONES, validationScope } from '../lib/states'
import type { MatrixRow } from '../lib/states'
import { StateMark } from '../components/capabilityState'
import { Empty, ErrorNotice, Evidence, Limitations, Panel, Stat } from '../components/widgets'

/**
 * Sanctum platform status.
 *
 * Five lines an examiner reads without knowing what an adapter is: which
 * computer this is, who they are on it, and what it can do to storage. Every
 * row opens a plain-English *Why?*, and the probe behind it sits under
 * Technical details for the judge who asks.
 *
 * There is no checkmark in this file. A status the server did not compute
 * cannot appear, and UNVERIFIED is drawn as unverified. What a status is
 * *not* - a run on the storage attached now, or a result on physical
 * hardware - is said on the page, beside the statuses, rather than left to be
 * inferred from a green word.
 */

/** The rows a non-specialist cares about, in the order they matter. */
const HEADLINE_ROWS = [
  'device_discovery',
  'file_erase',
  'folder_erase',
  'file_verification',
  'whole_drive_clear',
  'whole_drive_purge',
]

function Status({ status }: { status: CapabilityStatus }) {
  const { word, tone } = statusWord(status)
  return (
    <span className={`state-mark is-${tone}`} data-status={status}>
      {word}
    </span>
  )
}

function CapabilityRow({ row }: { row: OperationCapability }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <div className="cap-row">
        <span className="cap-row-label">{row.label}</span>
        {/* The resolver's word when the row carries a state; the older
            status word only for a payload from before the resolver. */}
        <StateMark row={row} />
        <button
          className="link-button"
          aria-expanded={open}
          onClick={() => setOpen(!open)}
        >
          {open ? 'Hide' : 'Why?'}
        </button>
      </div>
      {open && (
        <div className="cap-row-why">
          <p className="answer-detail">{row.reason}</p>
          {row.mechanism && (
            <p className="answer-detail">
              <strong>Mechanism: </strong>
              <span className="mono">{row.mechanism}</span>
            </p>
          )}
          {row.state && (
            <p className="answer-detail">
              <strong>Physical validation: </strong>
              {validationScope(row)}
            </p>
          )}
          {row.assurance && (
            <p className="answer-detail">
              <strong>Assurance: </strong>
              {row.assurance}
            </p>
          )}
          {row.verification && (
            <p className="answer-detail">
              <strong>Verification: </strong>
              {row.verification}
            </p>
          )}
          {row.limitations.length > 0 && (
            <Limitations items={row.limitations} title="Limits" />
          )}
          <p className="note-faint mono">Established by: {row.source}</p>
        </div>
      )}
    </>
  )
}

/**
 * The resolver's platform matrix: every capability, its precise state, the
 * reason, the mechanism, and the device classes a physical run is recorded
 * for. Validation is scoped to those classes and never generalised: a clear
 * of one USB stick says nothing about an NVMe drive.
 */
function CapabilityMatrix({ rows }: { rows: MatrixRow[] }) {
  return (
    <div className="scroll-x">
      <table
        className="itable cap-table matrix-table"
        style={{ minWidth: 900 }}
        data-testid="capability-matrix"
      >
        <colgroup>
          <col style={{ width: '20%' }} />
          <col style={{ width: 180 }} />
          <col />
          <col style={{ width: '20%' }} />
        </colgroup>
        <thead>
          <tr>
            <th>Capability</th>
            <th>State</th>
            <th>Reason and mechanism</th>
            <th>Physically validated on</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.key} data-capability={row.key}>
              <td>{row.label}</td>
              <td>
                <span className={`state-mark is-${row.tone}`}>{row.word}</span>
              </td>
              <td>
                <span className="cell-stack">
                  <span className="matrix-reason">{row.reason}</span>
                  {row.mechanism && (
                    <span className="matrix-mech mono">{row.mechanism}</span>
                  )}
                </span>
              </td>
              <td>
                <span className="cell-stack">
                  <span className="mono">
                    {row.validatedClasses.length > 0
                      ? row.validatedClasses.join(', ')
                      : 'none recorded'}
                  </span>
                  <span className="note-faint">{row.scope}</span>
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

const FS_ROWS: { key: string; label: string }[] = [
  { key: 'detect', label: 'Detect' },
  { key: 'read', label: 'Recover from image' },
  { key: 'erase_files', label: 'Erase files' },
  { key: 'metadata', label: 'Filesystem metadata' },
  { key: 'free_space', label: 'Free-space wipe' },
  { key: 'whole_drive', label: 'Whole drive' },
]

const PLATFORMS: { key: string; label: string }[] = [
  { key: 'linux', label: 'Linux' },
  { key: 'windows', label: 'Windows' },
  { key: 'macos', label: 'macOS' },
]

/** "4c8102155b6f · git checkout (live)", or the packaged build's own record. */
function buildIdentity(status: PlatformStatus): string {
  const build = status.platform.build ?? {}
  const commit = build.commit ? build.commit.slice(0, 12) : 'commit not recorded'
  if (status.platform.packaged) {
    return `${commit} · packaged ${build.version || status.platform.app_version}`
  }
  return `${commit} · ${build.source || 'source checkout'}`
}

export default function Platform() {
  const [status, setStatus] = useState<PlatformStatus | null>(null)
  const [error, setError] = useState<{
    message: string
    kind?: string
    remediation?: string
  } | null>(null)
  const [filesystem, setFilesystem] = useState('NTFS')

  useEffect(() => {
    void api
      .platform()
      .then(setStatus)
      .catch((exc: RequestFailed) =>
        setError({ message: exc.message, kind: exc.kind, remediation: exc.remediation }),
      )
  }, [])

  const fs = status?.filesystems.find((item) => item.filesystem === filesystem)
  const byOperation = new Map(status?.operations.map((row) => [row.operation, row]))
  const headline = HEADLINE_ROWS.map((name) => byOperation.get(name)).filter(
    (row): row is OperationCapability => Boolean(row),
  )
  const rest = (status?.operations ?? []).filter(
    (row) => !HEADLINE_ROWS.includes(row.operation),
  )
  const build = status?.platform.build ?? {}
  const detected = (status?.media_classes ?? []).filter((row) => row.detected_now > 0)
  const detectedTotal = detected.reduce((sum, row) => sum + row.detected_now, 0)
  const matrix = platformMatrix(status)

  return (
    <>
      <div className="screen-head">
        <h1>Platform</h1>
        <p>What this computer can do, and why.</p>
      </div>
      <div className="screen-body">
        <ErrorNotice error={error} />
        {!status && !error && <Empty>Asking this computer&hellip;</Empty>}
        {status && (
          <>
            <Panel title="This computer">
              <div className="row wrap" style={{ gap: 'var(--space-6)' }}>
                <Stat label="Operating system" value={status.platform.os_name} />
                <Stat
                  label="Application"
                  value={`Sanctum ${status.platform.app_version}${status.platform.packaged ? '' : ' (from source)'}`}
                />
                <Stat label="Build" value={buildIdentity(status)} />
                <Stat label="Privilege" value={privilegeWord(status.privilege)} />
              </div>
            </Panel>

            {matrix && (
              <Panel
                title="Capabilities on this computer"
                subtitle="The resolver's answer for this build, this platform and this privilege, before any device is chosen. Each device is assessed again on the Devices screen."
              >
                <CapabilityMatrix rows={matrix} />
              </Panel>
            )}

            <div className="overview-grid">
              <Panel
                title="Device support"
                subtitle="Decided before anything runs, from this build, this platform and this privilege."
              >
                <div className="col">
                  <div className="cap-rows">
                    {headline.map((row) => (
                      <CapabilityRow key={row.operation} row={row} />
                    ))}
                  </div>
                  <p className="note" data-testid="detected-now">
                    <strong>Detected now: </strong>
                    {detectedTotal === 0
                      ? 'no storage device of a listed kind.'
                      : `${detectedTotal} storage device${detectedTotal === 1 ? '' : 's'} (${detected
                          .map((row) => `${row.detected_now} ${row.media_class}`)
                          .join(', ')}).`}{' '}
                    Detecting a device is not supporting it: each one is assessed
                    on its own on the Devices screen.
                  </p>
                </div>
              </Panel>

              <Panel title={matrix ? 'How to read a state' : 'How to read a status'}>
                <div className="col">
                  {matrix ? (
                    <dl className="status-legend" data-testid="state-legend">
                      {STATE_MEANINGS.map((row) => (
                        <div key={row.label}>
                          <dt>
                            <span className={`state-mark is-${STATE_TONES[row.states[0]]}`}>
                              {row.label}
                            </span>
                          </dt>
                          <dd>{row.meaning}</dd>
                        </div>
                      ))}
                    </dl>
                  ) : (
                    <dl className="status-legend">
                      {STATUS_MEANINGS.map((row) => (
                        <div key={row.status}>
                          <dt>
                            <Status status={row.status} />
                          </dt>
                          <dd>{row.meaning}</dd>
                        </div>
                      ))}
                    </dl>
                  )}
                  <p className="note">
                    A status says what this build can do here. It is not a
                    record that the operation was run on the storage attached
                    now.
                  </p>
                </div>
              </Panel>
            </div>

            <div className="overview-grid">
              <Panel title="Safety restrictions" subtitle="The same on every platform.">
                <ul className="limitations" data-testid="safety-restrictions">
                  {SAFETY_LINES.map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                </ul>
              </Panel>

              <Panel title="Not proven on hardware, or not available">
                <ul className="limitations" data-testid="not-on-hardware">
                  {NOT_PHYSICALLY_VALIDATED.map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                </ul>
              </Panel>
            </div>

            <Panel title="What this computer cannot do">
              <Limitations
                items={status.restrictions}
                title="Restrictions on this platform, in this release"
              />
            </Panel>

            <details className="tech">
              <summary>Technical details</summary>
              <div className="tech-body">
                <Panel title="Every operation">
                  <div className="cap-rows">
                    {rest.map((row) => (
                      <CapabilityRow key={row.operation} row={row} />
                    ))}
                  </div>
                </Panel>

                <Panel title="How this build was made">
                  <Evidence
                    stacked
                    rows={[
                      {
                        label: 'Build',
                        value: build.version
                          ? `${build.version} (${build.platform} ${build.architecture})`
                          : 'built from a source checkout',
                      },
                      { label: 'Commit', value: build.commit || 'not recorded', kind: 'mono' },
                      { label: 'Built', value: build.build_date || 'not recorded' },
                      { label: 'Built by', value: build.builder || 'not recorded' },
                      {
                        label: 'Runtime',
                        value: build.python ? `Python ${build.python}` : 'not recorded',
                      },
                      { label: 'Signed', value: build.signed === 'yes' ? 'yes' : 'no' },
                      { label: 'Privilege basis', value: status.privilege.basis },
                      { label: 'Helper', value: status.privilege.helper_basis || status.privilege.helper },
                      { label: 'Adapter', value: status.adapter, kind: 'mono' },
                      {
                        label: 'OS build',
                        value: `${status.platform.os_build || status.platform.os_version} (${status.platform.machine})`,
                      },
                    ]}
                  />
                </Panel>

                {matrix && (
                  <Panel
                    title="How to read the older status words"
                    subtitle="The storage and filesystem tables below still use them."
                  >
                    <dl className="status-legend">
                      {STATUS_MEANINGS.map((row) => (
                        <div key={row.status}>
                          <dt>
                            <Status status={row.status} />
                          </dt>
                          <dd>{row.meaning}</dd>
                        </div>
                      ))}
                    </dl>
                  </Panel>
                )}

                <Panel
                  title="Storage support"
                  subtitle="By kind of device. The count is what this computer has now."
                >
                  <div className="scroll-x">
                    <table className="itable cap-table" style={{ minWidth: 640 }}>
                      <thead>
                        <tr>
                          <th style={{ width: '22%' }}>Storage</th>
                          <th>Found now</th>
                          <th>Discovery</th>
                          <th>File erase</th>
                          <th>Whole drive</th>
                        </tr>
                      </thead>
                      <tbody>
                        {status.media_classes.map((row) => (
                          <tr key={row.media_class} title={row.reason}>
                            <td>{row.media_class}</td>
                            <td className="mono">{row.detected_now}</td>
                            <td>
                              <Status status={row.discovery} />
                            </td>
                            <td>
                              <Status status={row.file_erase} />
                            </td>
                            <td>
                              <Status status={row.whole_drive} />
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Panel>

                <Panel
                  title="Filesystems"
                  subtitle="Detecting a filesystem is not supporting it."
                >
                  <div className="row wrap" role="tablist" aria-label="Filesystem">
                    {status.filesystems.map((item) => (
                      <button
                        key={item.filesystem}
                        role="tab"
                        aria-selected={item.filesystem === filesystem}
                        className={item.filesystem === filesystem ? 'btn primary' : 'btn'}
                        onClick={() => setFilesystem(item.filesystem)}
                      >
                        {item.filesystem}
                      </button>
                    ))}
                  </div>
                  {fs && (
                    <div className="scroll-x" style={{ marginTop: 'var(--space-3)' }}>
                      <table className="itable cap-table" style={{ minWidth: 640 }}>
                        <thead>
                          <tr>
                            <th style={{ width: '22%' }}>{fs.filesystem}</th>
                            {PLATFORMS.map((p) => (
                              <th key={p.key}>
                                {p.label}
                                {p.key === status.platform.family ? ' (this computer)' : ''}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {FS_ROWS.map((r) => (
                            <tr key={r.key} title={fs.notes[r.key]}>
                              <td>{r.label}</td>
                              {PLATFORMS.map((p) => (
                                <td key={p.key}>
                                  <Status
                                    status={fs.cells[r.key]?.[p.key] ?? 'UNVERIFIED'}
                                  />
                                </td>
                              ))}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </Panel>
              </div>
            </details>
          </>
        )}
      </div>
    </>
  )
}
