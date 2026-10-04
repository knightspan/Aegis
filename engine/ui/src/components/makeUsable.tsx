import { useEffect, useRef, useState } from 'react'

import { api, RequestFailed, streamJob } from '../lib/api'
import type { Device, JobStatus } from '../lib/api'
import {
  FORMAT_FILESYSTEMS,
  canStartFormat,
  formatOutcome,
  labelProblem,
} from '../lib/makeUsable'
import type { FormatFilesystem } from '../lib/makeUsable'
import { ErrorNotice, Notice, Panel } from './widgets'

/**
 * Make an erased device usable again.
 *
 * Shown only after a completed erase. It writes one partition table and one
 * filesystem, behind the same gates as the erase: a server-issued approval, the
 * device serial typed by hand, and a single-use authorization. Open, approve
 * and execute are three separate server calls; this only sequences them once
 * the person has typed the serial and ticked the acknowledgement.
 */
export function MakeUsable({
  device,
  caseId,
}: {
  device: Pick<Device, 'path' | 'serial' | 'model'>
  caseId: string
}) {
  const [filesystem, setFilesystem] = useState<FormatFilesystem>('exfat')
  const [label, setLabel] = useState('USB')
  const [typed, setTyped] = useState('')
  const [acknowledged, setAcknowledged] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<{
    message: string
    kind?: string
    remediation?: string
    why?: string[]
  } | null>(null)
  const [status, setStatus] = useState<JobStatus | null>(null)
  const detach = useRef<(() => void) | null>(null)

  useEffect(() => () => detach.current?.(), [])

  const chosen = FORMAT_FILESYSTEMS.find((fs) => fs.id === filesystem)
  const problem = labelProblem(filesystem, label)
  const ready = canStartFormat({
    serial: device.serial,
    typed,
    acknowledged,
    filesystem,
    label,
  })

  async function run() {
    if (!ready || busy) return
    setBusy(true)
    setError(null)
    setStatus(null)
    try {
      const opened = await api.openFormat({ path: device.path, filesystem, label })
      await api.approveFormat(opened.authorization_id, {
        typed_serial: typed,
        acknowledge_format: acknowledged,
      })
      const accepted = await api.executeFormat(opened.authorization_id, {
        typed_serial: typed,
        case_id: caseId,
      })
      detach.current?.()
      detach.current = streamJob(accepted.job_id, {
        onProgress: () => undefined,
        onState: (next) => {
          setStatus(next)
          if (next.settled !== false) setBusy(false)
        },
      })
    } catch (exc) {
      const failure = exc as RequestFailed
      setError({
        message: failure.message,
        kind: failure.kind,
        remediation: failure.remediation,
        why: failure.whyBlocked,
      })
      setBusy(false)
    }
  }

  const finished = status !== null && ['complete', 'failed', 'cancelled'].includes(status.state)
  const outcome = finished ? formatOutcome(status.state, status.result, status.error) : null

  return (
    <Panel
      title="Make usable"
      subtitle="Write a partition table and one filesystem so the device works again."
    >
      <div className="col tight">
        <Notice tone="info">
          This is not part of the sanitization. It writes filesystem metadata to a few
          sectors and leaves every other block as the erase left it. The certificate
          describes the device at the end of the erase, before this step.
        </Notice>
        {outcome ? (
          <>
            <Notice tone={outcome.tone}>
              <strong>{outcome.headline}</strong>
              {outcome.notes.map((note) => (
                <div key={note}>{note}</div>
              ))}
            </Notice>
          </>
        ) : (
          <>
            <div className="row wrap">
              <label>
                Filesystem
                <select
                  value={filesystem}
                  disabled={busy}
                  onChange={(event) => setFilesystem(event.target.value as FormatFilesystem)}
                >
                  {FORMAT_FILESYSTEMS.map((fs) => (
                    <option key={fs.id} value={fs.id}>
                      {fs.name}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Label
                <input
                  value={label}
                  disabled={busy}
                  maxLength={chosen?.maxLabel ?? 15}
                  onChange={(event) => setLabel(event.target.value)}
                />
              </label>
              <label className="grow">
                Type the device serial to confirm ({device.serial || 'none reported'})
                <input
                  value={typed}
                  disabled={busy}
                  autoComplete="off"
                  spellCheck={false}
                  onChange={(event) => setTyped(event.target.value)}
                />
              </label>
            </div>
            {chosen && <span className="note">{chosen.note}</span>}
            {problem && <Notice tone="warn">{problem}</Notice>}
            <label className="row">
              <input
                type="checkbox"
                checked={acknowledged}
                disabled={busy}
                onChange={(event) => setAcknowledged(event.target.checked)}
              />
              <span>
                I understand this writes to {device.model} ({device.path}) and cannot be
                undone.
              </span>
            </label>
            <div className="row">
              <button className="btn primary" disabled={!ready || busy} onClick={() => void run()}>
                {busy ? 'Formatting...' : 'Make usable'}
              </button>
            </div>
          </>
        )}
        <ErrorNotice error={error} />
        {error?.why && error.why.length > 0 && (
          <ul>
            {error.why.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
        )}
      </div>
    </Panel>
  )
}
