import { useEffect, useRef, useState } from 'react'
import { api, RequestFailed, streamJob } from '../lib/api'
import type { DeviceRow, JobStatus, Progress, RestoreView } from '../lib/api'
import { useCase } from '../lib/caseContext'
import { bytes, duration } from '../lib/format'
import { refusalFrom } from '../lib/workflowState'
import type { ServerRefusal } from '../lib/workflowState'
import {
  BrowseButton,
  Empty,
  ErrorNotice,
  Evidence,
  JobId,
  Limitations,
  Notice,
  Panel,
  ProgressView,
  Railed,
  Verdict,
} from '../components/widgets'

type Failure = { message: string; kind?: string; remediation?: string }

function failureOf(exc: unknown): Failure {
  const failed = exc as RequestFailed
  return { message: failed.message, kind: failed.kind, remediation: failed.remediation }
}

/**
 * Write a verified backup image back to a disk.
 *
 * Presentational over the server's restore workflow: plan, approve, execute.
 * Every button only asks the server for the next step; the server re-reads the
 * disk and refuses a mounted or system target, and the helper re-checks it at
 * the write. There is no dry run. The serial is typed twice, once to approve
 * and once to execute.
 */
export default function Restore() {
  const { openCase } = useCase()
  const caseId = openCase?.case_id ?? ''
  const [rows, setRows] = useState<DeviceRow[] | null>(null)
  const [loading, setLoading] = useState(false)
  const [path, setPath] = useState('')
  const [image, setImage] = useState('')
  const [view, setView] = useState<RestoreView | null>(null)
  const [hashing, setHashing] = useState<Progress | null>(null)
  const [acknowledged, setAcknowledged] = useState(false)
  const [typed, setTyped] = useState('')
  const [busy, setBusy] = useState(false)
  const [failure, setFailure] = useState<Failure | null>(null)
  const [refusal, setRefusal] = useState<ServerRefusal | null>(null)
  const [jobId, setJobId] = useState<string | null>(null)
  const [progress, setProgress] = useState<Progress | null>(null)
  const [status, setStatus] = useState<JobStatus | null>(null)
  const detach = useRef<(() => void) | null>(null)

  useEffect(() => () => detach.current?.(), [])

  const row = rows?.find((item) => item.device.path === path) ?? null
  const device = row?.device ?? null
  const serialOk = Boolean(device?.serial) && typed === device?.serial

  async function listDevices() {
    setLoading(true)
    setFailure(null)
    try {
      setRows((await api.devices(false)).devices)
    } catch (exc) {
      setFailure(failureOf(exc))
    } finally {
      setLoading(false)
    }
  }

  function reset() {
    detach.current?.()
    setView(null)
    setHashing(null)
    setAcknowledged(false)
    setTyped('')
    setRefusal(null)
    setFailure(null)
    setJobId(null)
    setProgress(null)
    setStatus(null)
    setBusy(false)
  }

  /** Record the image as a backup of the disk, then ask the server to plan. */
  function plan() {
    if (!device || !image.trim()) return
    reset()
    setBusy(true)
    void (async () => {
      try {
        const accepted = await api.createBackup({
          backup_image: image.trim(),
          source_path: device.path,
          case_id: caseId,
        })
        detach.current = streamJob(accepted.job_id, {
          onProgress: setHashing,
          onState: (state) => {
            if (state.state !== 'complete') {
              setBusy(false)
              setFailure({
                message: state.error ?? `The backup record ended ${state.state}.`,
                kind: state.error_kind ?? undefined,
                remediation: state.remediation,
              })
              return
            }
            const backupId = String(state.result?.backup_id ?? '')
            void (async () => {
              try {
                setView(await api.openRestore({ backup_id: backupId, target_path: device.path }))
              } catch (exc) {
                if (exc instanceof RequestFailed && exc.status === 409) {
                  setRefusal(refusalFrom(exc, true))
                } else {
                  setFailure(failureOf(exc))
                }
              } finally {
                setBusy(false)
              }
            })()
          },
        })
      } catch (exc) {
        setFailure(failureOf(exc))
        setBusy(false)
      }
    })()
  }

  async function approve() {
    if (!view) return
    setBusy(true)
    setRefusal(null)
    setFailure(null)
    try {
      setView(
        await api.approveRestore(view.authorization_id, {
          typed_serial: typed,
          acknowledge_data_overwrite: acknowledged,
        }),
      )
      setTyped('')
    } catch (exc) {
      if (exc instanceof RequestFailed && exc.status === 409) setRefusal(refusalFrom(exc, true))
      else setFailure(failureOf(exc))
    } finally {
      setBusy(false)
    }
  }

  async function execute() {
    if (!view) return
    setBusy(true)
    setRefusal(null)
    setFailure(null)
    try {
      const accepted = await api.executeRestore(view.authorization_id, {
        typed_serial: typed,
        case_id: caseId,
      })
      setJobId(accepted.job_id)
      detach.current?.()
      detach.current = streamJob(accepted.job_id, {
        onProgress: setProgress,
        onState: setStatus,
      })
    } catch (exc) {
      if (exc instanceof RequestFailed && exc.status === 409) setRefusal(refusalFrom(exc))
      else setFailure(failureOf(exc))
    } finally {
      setBusy(false)
    }
  }

  const state = view?.workflow.state ?? ''
  const canPlan = Boolean(device) && image.trim() !== '' && !busy && !view && !jobId
  const canApprove =
    Boolean(view) && !view?.approved && state === 'HUMAN_APPROVAL_REQUIRED' && acknowledged && serialOk && !busy
  const canExecute =
    Boolean(view?.approved) && !view?.spent && state === 'PLAN_READY' && serialOk && !busy && !jobId
  const running = Boolean(jobId) && (!status || status.state === 'running')

  return (
    <div className="col">
      <div className="screen-head">
        <h1>Disk restore</h1>
        <span className="note">
          Writes a verified backup image back to a disk. This overwrites the disk.
        </span>
      </div>

      <Notice tone="danger">
        <strong>A restore overwrites the target.</strong> It needs a backup image under the
        evidence directory, your approval with the disk serial typed, and the serial typed
        again to run. Each chunk of the image is checked against its record before it is
        written, and the written range is read back at the end. Restore has not yet been
        run on physical hardware.
      </Notice>

      <Panel title="1. Choose the disk and the backup" subtitle="Nothing is written in this step.">
        <div className="col">
          <ErrorNotice error={view || jobId ? null : failure} />
          {rows === null ? (
            <div className="row">
              <button className="btn" onClick={() => void listDevices()} disabled={loading}>
                {loading ? 'Listing devices…' : 'List devices'}
              </button>
            </div>
          ) : rows.length === 0 ? (
            <Empty>No devices were reported.</Empty>
          ) : (
            <>
              <label>
                Disk to restore
                <select
                  value={path}
                  disabled={Boolean(view) || busy}
                  onChange={(event) => setPath(event.target.value)}
                >
                  <option value="">choose a disk</option>
                  {rows.map((item) => (
                    <option key={item.device.path} value={item.device.path}>
                      {item.device.path} · {item.device.model || 'model not reported'} ·{' '}
                      {bytes(item.device.size_bytes)} · serial {item.device.serial || 'not reported'}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Backup image, under the evidence directory
                <div className="row">
                  <input
                    type="text"
                    className="grow"
                    data-testid="restore-image"
                    value={image}
                    spellCheck={false}
                    placeholder="backup.dd"
                    disabled={Boolean(view) || busy}
                    onChange={(event) => setImage(event.target.value)}
                  />
                  <BrowseButton
                    kind="file"
                    disabled={Boolean(view) || busy}
                    onPick={([chosen]) => setImage(chosen)}
                  />
                </div>
              </label>
              <span className="note-faint">
                The image is recorded as a backup of the chosen disk, hashed read-only, and the
                server plans the exact byte range. The disk must not be mounted.
              </span>
              <div className="row">
                <button className="btn primary" disabled={!canPlan} onClick={plan}>
                  {busy && !view ? 'Recording backup…' : 'Record backup and plan restore'}
                </button>
                {(view || refusal || failure) && !jobId && (
                  <button className="btn" onClick={reset}>
                    Start over
                  </button>
                )}
              </div>
              {hashing && !view && <ProgressView progress={hashing} />}
            </>
          )}
          {refusal && !view && <RefusalCard refusal={refusal} />}
        </div>
      </Panel>

      {view && device && (
        <Panel title="2. Review the plan and approve" subtitle="The server recorded this plan from a fresh read of the disk.">
          <div className="col">
            <Evidence
              stacked
              rows={[
                { label: 'Target', value: `${device.model} (${device.path})` },
                { label: 'Serial', value: device.serial, kind: 'serial' },
                { label: 'Backup', value: `${view.backup.path} (${bytes(view.backup.size_bytes)}, sha256 ${view.backup.sha256.slice(0, 16)}…)` },
                { label: 'Writes', value: `${bytes(view.plan.write_length)} from offset ${view.plan.write_offset}` },
                { label: 'Left untouched', value: bytes(view.plan.target_tail_untouched_bytes) },
                {
                  label: 'Estimated',
                  value: `${duration(view.plan.estimated_write_seconds)} to write, ${duration(view.plan.estimated_verify_seconds)} to verify`,
                },
                { label: 'Identity', value: view.identity_statement },
              ]}
            />
            {view.plan.limitations.length > 0 && <Limitations items={view.plan.limitations} />}
            <span className="note-faint">{view.backup_limitation}</span>

            {view.workflow.why_blocked.length > 0 && !view.executed && (
              <Limitations items={view.workflow.why_blocked} title="Why this restore is blocked" />
            )}

            {!view.approved && (
              <>
                <label className="inline">
                  <input
                    type="checkbox"
                    data-testid="restore-acknowledge"
                    checked={acknowledged}
                    onChange={(event) => setAcknowledged(event.target.checked)}
                  />
                  <span>
                    I understand this overwrites the data on {device.path} and cannot be undone.
                  </span>
                </label>
                <label>
                  Type the disk serial to approve
                  <input
                    type="text"
                    data-testid="restore-serial"
                    value={typed}
                    spellCheck={false}
                    placeholder={device.serial}
                    onChange={(event) => setTyped(event.target.value)}
                  />
                </label>
                {typed && !serialOk && <span className="state-mark is-destructive">serial does not match</span>}
                <div className="row">
                  <button className="btn destructive" data-testid="restore-approve" disabled={!canApprove} onClick={() => void approve()}>
                    Approve restore
                  </button>
                </div>
              </>
            )}

            {view.approved && (
              <Railed tone="warning">
                <Verdict level="AUTHORIZATION RECORDED" basis={view.approved_by} tone="warning" />
                <span className="note">
                  Authorization <span className="mono">{view.authorization_id}</span> authorizes one
                  execution.
                </span>
                {!jobId && (
                  <>
                    <label>
                      Type the disk serial again to run the restore
                      <input
                        type="text"
                        data-testid="restore-serial"
                        value={typed}
                        spellCheck={false}
                        placeholder={device.serial}
                        onChange={(event) => setTyped(event.target.value)}
                      />
                    </label>
                    <div className="row">
                      <button className="btn destructive" data-testid="restore-execute" disabled={!canExecute} onClick={() => void execute()}>
                        Restore {device.path}
                      </button>
                    </div>
                  </>
                )}
              </Railed>
            )}

            <ErrorNotice error={failure} />
            {refusal && <RefusalCard refusal={refusal} />}
          </div>
        </Panel>
      )}

      {jobId && (
        <Panel title="3. Progress">
          <div className="col">
            <JobId value={jobId} />
            <ProgressView progress={progress} destructive />
            {running && <span className="note">Do not unplug the disk while this runs.</span>}
            {status && status.state === 'complete' && (
              <Notice tone="warn">
                <strong>Restore finished.</strong> Read the verification in the job result before
                relying on the disk.
              </Notice>
            )}
            {status && status.state !== 'complete' && status.state !== 'running' && (
              <ErrorNotice
                error={{
                  message: status.error ?? `The restore ended ${status.state}.`,
                  kind: status.error_kind ?? undefined,
                  remediation: status.remediation,
                }}
              />
            )}
          </div>
        </Panel>
      )}
    </div>
  )
}

function RefusalCard({ refusal }: { refusal: ServerRefusal }) {
  return (
    <Railed tone="destructive">
      <div data-testid="restore-refusal">
        <Verdict level="BLOCKED" basis="REFUSED by the server" tone="destructive" />
        <strong>WHY BLOCKED</strong>
        <ul>
          {refusal.whyBlocked.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
        {refusal.physicalDeviceModified === false && (
          <p className="mono">PHYSICAL DEVICE MODIFIED: FALSE</p>
        )}
      </div>
    </Railed>
  )
}
