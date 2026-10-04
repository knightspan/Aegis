import { useState } from 'react'
import { api, RequestFailed } from '../lib/api'
import type { DeviceRow, PrepareDeviceResult } from '../lib/api'
import { preparable } from '../lib/states'
import { ErrorNotice, OperationModeBadge } from './widgets'

/**
 * Unmount (macOS) or take offline (Windows) one disk, as its own step.
 *
 * An erase never unmounts anything: it refuses a mounted disk. This is the
 * separate, explicit action an operator takes first, on the real disk. What
 * it will affect is shown from the device scan before anything is sent, and
 * the action needs the serial typed by hand; the helper re-reads the disk and
 * refuses a mismatch. It writes nothing to the medium.
 */
export function PreparePanel({ row, onDone }: { row: DeviceRow; onDone: () => void }) {
  const device = row.normalized
  const [done, setDone] = useState<PrepareDeviceResult | null>(null)
  const [typed, setTyped] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<{ message: string; kind?: string; remediation?: string } | null>(
    null,
  )
  if (!device || !preparable(row)) return null
  const word = device.platform === 'windows' ? 'Take offline' : 'Unmount'

  async function run() {
    if (!device) return
    setBusy(true)
    setError(null)
    try {
      const answer = await api.prepareDevice({ path: device.id, typed_serial: typed })
      setDone(answer)
      if (answer.performed) onDone()
    } catch (exc) {
      if (exc instanceof RequestFailed) {
        setError({ message: exc.message, kind: exc.kind, remediation: exc.remediation })
      } else {
        setError({ message: String(exc) })
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="prepare">
      <p>
        <OperationModeBadge /> {word} this disk before a whole-drive operation. This is a
        separate step: an erase never unmounts anything, and this step writes nothing to the
        medium.
      </p>
      <dl>
        <dt>Disk</dt>
        <dd>
          {device.model || device.id} · serial {device.serial || '(none reported)'}
        </dd>
        <dt>Volumes affected</dt>
        <dd>{device.mount_points.join(', ') || 'none mounted'}</dd>
      </dl>
      <div>
        <label>
          Type the serial {device.serial || '(none reported)'} to confirm{' '}
          <input value={typed} onChange={(event) => setTyped(event.target.value)} />
        </label>
        <button type="button" disabled={busy || !typed} onClick={() => void run()}>
          {word}
        </button>
      </div>
      {done && (
        <dl>
          <dt>Action</dt>
          <dd>{done.action}</dd>
          <dt>Performed</dt>
          <dd>{done.performed ? 'yes' : 'no'}</dd>
        </dl>
      )}
      <ErrorNotice error={error} />
    </div>
  )
}
