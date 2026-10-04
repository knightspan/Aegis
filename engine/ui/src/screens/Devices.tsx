import { Fragment, useEffect, useState } from 'react'
import { api, RequestFailed } from '../lib/api'
import type { DeviceAssessment, DeviceRow, HiddenAreaReport } from '../lib/api'
import { capabilityBadge } from '../lib/capability'
import { deviceCapability, deviceClassWord } from '../lib/states'
import { DeviceCapabilityList, StateMark } from '../components/capabilityState'
import { bytes, exactBytes } from '../lib/format'
import { flashOf } from '../lib/erasePlan'
import { Empty, ErrorNotice, Limitations, Panel, Verdict } from '../components/widgets'
import { DestroyRecordPanel } from '../components/destroyRecord'
import { PreparePanel } from '../components/preparePanel'

/**
 * Hidden areas.
 *
 * The word carries the state and the colour reinforces it. "none", "not
 * probed" and "HPA 1.05 GB" are already distinct read as text alone, so this
 * column loses nothing in greyscale and needs no glyph beside it.
 */
function HiddenAreas({
  report,
  assessment,
}: {
  report: HiddenAreaReport | null
  assessment?: DeviceAssessment
}) {
  if (!report) {
    // No measurement in the row. Where the resolver answered for HPA/DCO
    // discovery on this device, its word stands in, never a bare "not probed".
    const resolved = deviceCapability(assessment, 'hpa_dco_discovery')
    if (resolved) return <StateMark row={resolved} title={resolved.reason} />
    return <span className="state-mark is-muted">not probed</span>
  }
  if (report.hidden_bytes <= 0) {
    return <span className="state-mark is-success">none</span>
  }
  return (
    <span className="state-mark is-destructive">
      {report.hpa_present ? 'HPA' : 'DCO'} {bytes(report.hidden_bytes)}
    </span>
  )
}

/** A shackle. Drawn inline: no icon font, no sprite fetched from anywhere. */
function Shackle() {
  return (
    <svg width="13" height="15" viewBox="0 0 13 15" aria-hidden>
      <rect
        x="0.75"
        y="6.25"
        width="11.5"
        height="8"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
      />
      <path
        d="M3 6.25 V4 a3.5 3.5 0 0 1 7 0 V6.25"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
      />
      <rect x="5.75" y="9" width="1.5" height="3" fill="currentColor" />
    </svg>
  )
}

export default function Devices({
  onSelect,
}: {
  onSelect: (row: DeviceRow) => void
}) {
  const [rows, setRows] = useState<DeviceRow[]>([])
  const [limitations, setLimitations] = useState<string[]>([])
  const [openPath, setOpenPath] = useState<string | null>(null)
  const [error, setError] = useState<{
    message: string
    kind?: string
    remediation?: string
  } | null>(null)
  const [loading, setLoading] = useState(true)

  async function refresh() {
    setLoading(true)
    try {
      const answer = await api.devices(true)
      setRows(answer.devices)
      setLimitations(answer.limitations)
      setError(null)
    } catch (exc) {
      const failure = exc as RequestFailed
      setError({
        message: failure.message,
        kind: failure.kind,
        remediation: failure.remediation,
      })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void refresh()
  }, [])

  return (
    <>
      <div className="screen-head">
        <h1>Devices</h1>
        <p>Enumerated from the host, capability probed, hidden areas measured.</p>
        <div className="grow" />
        <button className="btn" onClick={() => void refresh()} disabled={loading}>
          {loading ? 'Probing…' : 'Rescan'}
        </button>
      </div>
      <div className="screen-body">
        <ErrorNotice error={error} />
        <Limitations items={limitations} />

        <Panel
          title={`Block devices (${rows.length})`}
          subtitle="Capability is what the probe and the resolver reported, not what was requested. Open a verdict to see every capability, its state and why."
          tight
        >
          {rows.length === 0 ? (
            <Empty>
              {loading
                ? 'Probing the host…'
                : 'No block devices were reported. The privileged helper may not be running.'}
            </Empty>
          ) : (
            <div className="scroll-x-narrow">
              <table className="itable" style={{ minWidth: 1120 }}>
                {/* Fixed widths so the columns line up down the table and the
                    header never truncates mid-word. Capability takes what is
                    left, and its basis line ellipsises rather than wrapping -
                    the full sentence is one click away on the sub-row. */}
                {/* Widths are sized to the longest real value each column
                    holds, not divided evenly. A serial is typed character by
                    character into the confirm dialog, so it gets the 24
                    monospace characters it needs and never ellipsises; so do
                    size and bus, which are short by nature. Model is the only
                    column that can lose its tail without costing anything, so
                    Model is the one that flexes. */}
                <colgroup>
                  <col style={{ width: 'var(--gutter)' }} />
                  <col style={{ width: 140 }} />
                  <col />
                  <col style={{ width: 186 }} />
                  <col style={{ width: 92 }} />
                  <col style={{ width: 104 }} />
                  <col style={{ width: 112 }} />
                  <col style={{ width: 238 }} />
                  <col style={{ width: 150 }} />
                </colgroup>
                <thead>
                  <tr>
                    <th className="rail" />
                    <th>Path</th>
                    <th>Model</th>
                    <th>Serial</th>
                    <th>Size</th>
                    <th>Bus</th>
                    <th>Class</th>
                    <th>Capability</th>
                    <th>Hidden areas</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) => {
                    const badge = capabilityBadge(row.capabilities, row.assessment)
                    const barred =
                      row.device.is_system_disk || row.device.mounted_at.length > 0
                    // The same words as the workflow state machine: BLOCKED,
                    // then WHY. The remedy is a human act; nothing here
                    // unmounts or reboots on the operator's behalf.
                    const mounts = row.device.mounted_at
                    const systemWhy = mounts.includes('/')
                      ? 'hosts the running root filesystem'
                      : mounts.some((m) => m === '/boot' || m.startsWith('/boot/'))
                        ? `holds the boot partition (${mounts
                            .filter((m) => m === '/boot' || m.startsWith('/boot/'))
                            .join(', ')})`
                        : 'backs active swap or another volume the running system needs'
                    const reason = row.device.is_system_disk
                      ? `This device ${systemWhy}. ` +
                        'Boot from separate media and run the erase against it as ' +
                        'a non-system disk.'
                      : `Filesystem is mounted at ${row.device.mounted_at.join(', ')}. ` +
                        'Human unmount required: unmount every filesystem on the ' +
                        'device yourself, then rescan.'
                    const open = openPath === row.device.path
                    return (
                      <Fragment key={row.device.path}>
                        <tr
                          className={
                            barred ? 'irow is-barred' : 'irow is-openable'
                          }
                          onClick={() => !barred && onSelect(row)}
                        >
                          <td
                            className={barred ? 'rail is-destructive' : 'rail'}
                            aria-hidden
                          >
                            <i />
                          </td>
                          {/* Path and a shackle. Nothing else: the refusal is a
                              sentence and belongs on a row wide enough to hold
                              one. */}
                          <td className="path">
                            {barred ? (
                              <span className="lockup">
                                <Shackle />
                                <span className="path">{row.device.path}</span>
                              </span>
                            ) : (
                              row.device.path
                            )}
                          </td>
                          <td title={row.device.model}>{row.device.model}</td>
                          <td className="serial">{row.device.serial}</td>
                          <td className="mono" title={exactBytes(row.device.size_bytes)}>
                            {bytes(row.device.size_bytes)}
                          </td>
                          {/* The engine's determination, not `rotational`: a USB
                              bridge leaves that flag set on a flash stick. */}
                          <td className="mono" title={flashOf(row).reason}>
                            {row.device.transport}
                            {flashOf(row).flash ? ' flash' : ''}
                          </td>
                          {/* The evidence bucket the resolver matched physical
                              runs against: validation is scoped to it. */}
                          <td className="mono" data-testid="device-class">
                            {deviceClassWord(row.assessment)}
                          </td>
                          <td>
                            <Verdict
                              level={badge.label}
                              basis={badge.basis}
                              tone={badge.tone}
                              open={open}
                              onToggle={() =>
                                setOpenPath(open ? null : row.device.path)
                              }
                            />
                          </td>
                          <td>
                            <HiddenAreas
                              report={row.hidden_areas}
                              assessment={row.assessment}
                            />
                          </td>
                        </tr>
                        {barred && (
                          <tr className="subrow is-locked">
                            <td className="rail is-destructive" aria-hidden>
                              <i />
                            </td>
                            <td colSpan={8}>
                              <span className="lock-reason">
                                <strong>BLOCKED</strong> · WHY BLOCKED: {reason}
                              </span>
                            </td>
                          </tr>
                        )}
                        {open && (
                          <tr className="subrow">
                            <td className="rail" aria-hidden>
                              <i />
                            </td>
                            <td colSpan={8}>
                              <dl className="evidence">
                                <dt>Claim</dt>
                                <dd>{badge.label}</dd>
                                <dt>Because</dt>
                                <dd>{badge.why}</dd>
                                <dt>Device class</dt>
                                <dd className="mono">{deviceClassWord(row.assessment)}</dd>
                                {row.capabilities && (
                                  <>
                                    <dt>Levels</dt>
                                    <dd className="mono">
                                      {row.capabilities.achievable_levels.join(', ') ||
                                        'none reported'}
                                    </dd>
                                    <dt>Sanitize ops</dt>
                                    <dd className="mono">
                                      {row.capabilities.ata_sanitize_ops.join(', ') ||
                                        'none reported'}
                                    </dd>
                                  </>
                                )}
                                {row.hidden_areas && row.hidden_areas.hidden_bytes > 0 && (
                                  <>
                                    <dt>Hidden</dt>
                                    <dd>
                                      {exactBytes(row.hidden_areas.hidden_bytes)} lie beyond
                                      the accessible max (
                                      {row.hidden_areas.accessible_sectors} of{' '}
                                      {row.hidden_areas.native_max_sectors} sectors). An
                                      overwrite does not reach them unless the native max is
                                      unlocked first.
                                    </dd>
                                  </>
                                )}
                              </dl>
                              {/* Each capability with the resolver's word, its
                                  reason and its mechanism. Physical validation
                                  is scoped to the device class above. */}
                              <DeviceCapabilityList assessment={row.assessment} />
                              <PreparePanel row={row} onDone={refresh} />
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        {/* On Windows and macOS these carry the platform's own reason - the
            probe is not offered there at all - so the panel is titled for
            what it actually lists rather than implying a failure. */}
        {rows.some(
          (row) =>
            row.capability_error ||
            (row.hidden_area_error &&
              !deviceCapability(row.assessment, 'hpa_dco_discovery')),
        ) && (
          <Panel title="What was not probed on this computer, and why">
            <ul className="limitations">
              {rows.flatMap((row) =>
                [
                  row.capability_error,
                  // Where the resolver answered for HPA/DCO discovery, its
                  // reason (in the device's capability list) is the answer; a
                  // row-level message from before the resolver would contradict it.
                  deviceCapability(row.assessment, 'hpa_dco_discovery')
                    ? ''
                    : row.hidden_area_error,
                ]
                  .filter(Boolean)
                  .map((message, index) => (
                    <li key={`${row.device.path}-${index}`}>
                      <span className="path">{row.device.path}</span>: {message}
                    </li>
                  )),
              )}
            </ul>
          </Panel>
        )}

        <DestroyRecordPanel rows={rows} />
      </div>
    </>
  )
}
