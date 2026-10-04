import type { DeviceRow, EraseWorkflowView } from '../lib/api'
import type { ServerRefusal } from '../lib/workflowState'
import { bytes, exactBytes } from '../lib/format'
import { Evidence, Limitations, Notice, Railed, Verdict } from './widgets'

/**
 * The human-approval step of a real erase. Presentational only.
 *
 * Every fact here comes from the server's workflow record, and every button
 * only asks the server for the next step. The client never invents an
 * authorization id, never marks a step done itself, and never decides whether
 * an erase is safe: the buttons are disabled until the inputs exist, and the
 * server re-checks all of them when they are pressed.
 */
export interface EraseApprovalProps {
  device: NonNullable<DeviceRow['device']>
  level: string
  method: string
  view: EraseWorkflowView | null
  refusal: ServerRefusal | null
  /** A failure of the request itself, which is not a safety refusal. */
  failure: { message: string; kind?: string; remediation?: string } | null
  backupImage: string
  acknowledged: boolean
  typed: string
  busy: boolean
  onBackupImage: (value: string) => void
  onAcknowledge: (value: boolean) => void
  onTyped: (value: string) => void
  onOpen: () => void
  onApprove: () => void
  onExecute: () => void
  onCancel: () => void
  /** The execute button's words; a resume says it is a resume. */
  executeLabel?: string
}

export function EraseApproval(props: EraseApprovalProps) {
  const { device, view, refusal, typed } = props
  const state = view?.workflow.state ?? ''
  const serialOk = Boolean(device.serial) && typed === device.serial
  const canOpen = props.backupImage.trim() !== '' && !view && !props.busy
  const canApprove =
    Boolean(view) &&
    state === 'HUMAN_APPROVAL_REQUIRED' &&
    !view?.approved &&
    props.acknowledged &&
    serialOk &&
    !props.busy
  const canExecute =
    Boolean(view?.approved) &&
    state === 'PLAN_READY' &&
    !view?.spent &&
    serialOk &&
    !props.busy

  return (
    <div className="modal-backdrop" onClick={props.onCancel}>
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="confirm-title"
        data-testid="erase-approval"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="modal-head" id="confirm-title">
          HUMAN APPROVAL REQUIRED: irreversible erasure
        </div>
        <div className="modal-body">
          <Notice tone="danger">
            <strong>This permanently destroys every byte</strong> on{' '}
            <span className="path">{device.path}</span> ({bytes(device.size_bytes)}).
            There is no undo. Nothing is written until the server holds a
            verified backup, your recorded approval and the device serial you
            type.
          </Notice>

          <Evidence
            stacked
            rows={[
              { label: 'Device', value: `${device.model} (${device.path})` },
              { label: 'Serial', value: device.serial, kind: 'serial' },
              { label: 'Capacity', value: exactBytes(device.size_bytes) },
              { label: 'Level', value: props.level },
              { label: 'Method', value: props.method || 'none', kind: 'mono' },
              {
                label: 'Backup',
                value: view
                  ? `${view.backup.path} (${bytes(view.backup.size_bytes)}, sha256 ${view.backup.sha256.slice(0, 16)}…)`
                  : 'not verified yet: open the workflow',
              },
            ]}
          />

          {!view && (
            <label>
              Backup image, under the evidence directory
              <input
                type="text"
                data-testid="backup-image"
                value={props.backupImage}
                spellCheck={false}
                placeholder="backup.img"
                onChange={(event) => props.onBackupImage(event.target.value)}
              />
            </label>
          )}

          {view && (
            <div className="col tight" data-testid="workflow-plan">
              <strong>Plan the server recorded</strong>
              <span className="note">
                Achievable levels: {view.plan.achievable_levels.join(', ') || 'none'}.
                Estimated {view.plan.estimated_seconds ?? 'unknown'} s.
              </span>
              {view.plan.blocking.length > 0 && (
                <Limitations items={view.plan.blocking} />
              )}
              {view.plan.limitations.length > 0 && (
                <Limitations items={view.plan.limitations} />
              )}
              <span className="note-faint">{view.backup_limitation}</span>
            </div>
          )}

          {view && !view.approved && (
            <>
              <label className="inline">
                <input
                  type="checkbox"
                  data-testid="acknowledge"
                  checked={props.acknowledged}
                  onChange={(event) => props.onAcknowledge(event.target.checked)}
                />
                <span>
                  I understand this destroys all data on {device.path} and
                  cannot be undone.
                </span>
              </label>
              <label>
                Type the device serial to confirm
                <input
                  type="text"
                  data-testid="typed-serial"
                  value={typed}
                  spellCheck={false}
                  placeholder={device.serial}
                  onChange={(event) => props.onTyped(event.target.value)}
                />
              </label>
              {typed && !serialOk && (
                <span className="state-mark is-destructive">serial does not match</span>
              )}
            </>
          )}

          {view?.approved && (
            <Railed tone="warning">
              <Verdict level="AUTHORIZATION RECORDED" basis={view.approved_by} tone="warning" />
              <span className="note">
                Authorization <span className="mono" data-testid="authorization-id">{view.authorization_id}</span>{' '}
                was issued by the server. It authorizes one execution.
              </span>
              {!view.spent && (
                <label>
                  Type the device serial again to execute
                  <input
                    type="text"
                    data-testid="typed-serial"
                    value={typed}
                    spellCheck={false}
                    placeholder={device.serial}
                    onChange={(event) => props.onTyped(event.target.value)}
                  />
                </label>
              )}
            </Railed>
          )}

          {props.failure && (
            <div data-testid="request-failure">
              <Notice tone="danger">
                <strong>REQUEST FAILED</strong> (not a safety refusal
                {props.failure.kind ? `: ${props.failure.kind}` : ''}).{' '}
                {props.failure.message} {props.failure.remediation}
              </Notice>
            </div>
          )}

          {refusal && (
            <Railed tone="destructive">
              <div data-testid="refusal">
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
          )}
        </div>
        <div className="modal-foot">
          <button className="btn" onClick={props.onCancel}>
            Cancel
          </button>
          {!view && (
            <button className="btn primary" disabled={!canOpen} onClick={props.onOpen}>
              Open workflow and verify backup
            </button>
          )}
          {view && !view.approved && (
            <button
              className="btn destructive"
              data-testid="approve"
              disabled={!canApprove}
              onClick={props.onApprove}
            >
              Approve erasure
            </button>
          )}
          {view?.approved && (
            <button
              className="btn destructive"
              data-testid="execute"
              disabled={!canExecute}
              onClick={props.onExecute}
            >
              {props.executeLabel ?? `Erase ${device.path}`}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
