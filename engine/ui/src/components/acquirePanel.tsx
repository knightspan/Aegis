import { useEffect, useRef, useState } from 'react'
import { api, RequestFailed, streamJob } from '../lib/api'
import type { DeviceRow, JobStatus, Progress } from '../lib/api'
import { bytes } from '../lib/format'
import { acquireBody, rawSource } from '../lib/states'
import { StateMark } from './capabilityState'
import { Empty, ErrorNotice, JobId, Notice, Panel, ProgressView } from './widgets'

/**
 * Image a physical device read-only, from the device the operator selects.
 *
 * The source path and the serial come from the Devices data, never from
 * typing: on Windows (`\\.\PhysicalDriveN`) and macOS (`/dev/diskN`) the
 * server re-reads the disk and refuses the job if it no longer reports that
 * serial. Whether the button is offered follows the resolver's raw-acquisition
 * state for that device, shown beside it with its reason.
 */
export function AcquirePanel({
  caseId,
  onImage,
}: {
  caseId: string
  /** Called with the written image's path, to carve it. */
  onImage: (path: string) => void
}) {
  const [rows, setRows] = useState<DeviceRow[] | null>(null)
  const [loading, setLoading] = useState(false)
  const [path, setPath] = useState('')
  const [partition, setPartition] = useState('')
  const [dest, setDest] = useState('')
  const [fmt, setFmt] = useState<'raw' | 'e01'>('raw')
  const [compression, setCompression] = useState<'none' | 'fast' | 'best'>('fast')
  const [jobId, setJobId] = useState<string | null>(null)
  const [progress, setProgress] = useState<Progress | null>(null)
  const [status, setStatus] = useState<JobStatus | null>(null)
  const [error, setError] = useState<{
    message: string
    kind?: string
    remediation?: string
  } | null>(null)
  const detach = useRef<(() => void) | null>(null)

  useEffect(() => () => detach.current?.(), [])

  async function load() {
    setLoading(true)
    setError(null)
    try {
      const answer = await api.devices(false)
      setRows(answer.devices)
    } catch (exc) {
      const failure = exc as RequestFailed
      setError({ message: failure.message, kind: failure.kind, remediation: failure.remediation })
    } finally {
      setLoading(false)
    }
  }

  const row = rows?.find((item) => item.device.path === path) ?? null
  const partitions = row?.normalized?.partitions ?? []
  const source = row ? rawSource(row, partition || undefined) : null

  async function start() {
    if (!source || !source.allowed || !dest) return
    setError(null)
    try {
      const accepted = await api.acquire(
        acquireBody(source, { dest, fmt, compression, caseId }),
      )
      setJobId(accepted.job_id)
      setProgress(null)
      setStatus(null)
      detach.current?.()
      detach.current = streamJob(accepted.job_id, {
        onProgress: setProgress,
        onState: setStatus,
      })
    } catch (exc) {
      const failure = exc as RequestFailed
      setError({ message: failure.message, kind: failure.kind, remediation: failure.remediation })
    }
  }

  const written = status?.state === 'complete' ? String(status.params?.dest ?? '') : ''

  return (
    <Panel
      title="Acquire a device image (read-only)"
      subtitle="Images a physical device into the evidence directory. The device is opened for reading only."
    >
      <div className="col">
        <ErrorNotice error={error} />
        {rows === null ? (
          <div className="row">
            <button className="btn" onClick={() => void load()} disabled={loading}>
              {loading ? 'Listing devices…' : 'List devices'}
            </button>
            <span className="note">
              The device list comes from the Devices data: the path and serial
              sent with the job are the ones the selected disk reported.
            </span>
          </div>
        ) : rows.length === 0 ? (
          <Empty>No devices were reported.</Empty>
        ) : (
          <>
            <label>
              Source device
              <select
                value={path}
                onChange={(event) => {
                  setPath(event.target.value)
                  setPartition('')
                }}
              >
                <option value="">choose a device</option>
                {rows.map((item) => (
                  <option key={item.device.path} value={item.device.path}>
                    {item.normalized?.path || item.device.path} · {item.device.model || 'model not reported'} ·{' '}
                    {bytes(item.device.size_bytes)} · serial {item.device.serial || 'not reported'}
                  </option>
                ))}
              </select>
            </label>

            {partitions.length > 0 && row?.normalized?.platform === 'linux' && (
              <label>
                What to image
                <select
                  value={partition}
                  onChange={(event) => setPartition(event.target.value)}
                >
                  <option value="">the whole disk</option>
                  {partitions.map((item) => (
                    <option key={item.id} value={item.id}>
                      {item.id} · {bytes(item.size_bytes)} · {item.filesystem || 'no filesystem'}
                    </option>
                  ))}
                </select>
              </label>
            )}

            {source && (
              <div className="col tight" data-testid="raw-acquisition-state">
                <span className="row" style={{ gap: 'var(--space-2)' }}>
                  <strong>{partition ? 'Volume acquisition:' : 'Raw acquisition:'}</strong>
                  <StateMark row={source.capability ?? null} />
                </span>
                <span className="note">{source.reason}</span>
                {source.capability?.mechanism && (
                  <span className="note-faint mono">{source.capability.mechanism}</span>
                )}
                {source.capability?.assurance && (
                  <span className="note-faint">
                    <strong>Assurance: </strong>
                    {source.capability.assurance}
                  </span>
                )}
                <span className="note-faint mono">
                  source {source.source} · expected serial {source.expectedSerial || 'none'}
                </span>
              </div>
            )}

            <div className="row wrap" style={{ alignItems: 'flex-end' }}>
              <label className="grow">
                Image name (inside the evidence directory)
                <input
                  type="text"
                  value={dest}
                  spellCheck={false}
                  placeholder="disk2.dd or disk2.E01"
                  onChange={(event) => setDest(event.target.value)}
                />
              </label>
              <label>
                Format
                <select value={fmt} onChange={(event) => setFmt(event.target.value as 'raw' | 'e01')}>
                  <option value="raw">raw</option>
                  <option value="e01">E01</option>
                </select>
              </label>
              <label>
                Compression
                <select
                  value={compression}
                  onChange={(event) =>
                    setCompression(event.target.value as 'none' | 'fast' | 'best')
                  }
                >
                  <option value="none">none</option>
                  <option value="fast">fast</option>
                  <option value="best">best</option>
                </select>
              </label>
              <button
                className="btn primary"
                disabled={!source || !source.allowed || !dest || Boolean(jobId && !status)}
                onClick={() => void start()}
              >
                Acquire
              </button>
            </div>
            {source && !source.allowed && (
              <Notice tone="warn">
                Not offered for this device: {source.reason}
              </Notice>
            )}
          </>
        )}

        {jobId && (
          <div className="col tight">
            <JobId value={jobId} />
            {!status && <ProgressView progress={progress} />}
            {status && (
              <p className="note">
                Acquisition {status.state}.
                {status.error ? ` ${status.error}` : ''}
              </p>
            )}
            {written && (
              <div className="row">
                <span className="note mono">{written}</span>
                <button className="btn" onClick={() => onImage(written)}>
                  Use as evidence image
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </Panel>
  )
}
