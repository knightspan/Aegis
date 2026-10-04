import type { DeviceAssessment, NormalizedDevice, SanitizeOption } from '../lib/api'
import { bytes } from '../lib/format'
import {
  checkWord,
  deviceKind,
  deviceName,
  headlineTone,
  STEPS,
} from '../lib/platform'
import { capabilityWord, honestLevel, optionCause, optionTitle, purgeAbsence } from '../lib/states'
import { BACKUP_NOTE } from '../lib/workflowState'
import type { SanitizeWorkflow } from '../lib/workflowState'
import { Limitations, Notice, Panel, Railed } from './widgets'

/** The eight-step tracker. The current step is computed, never clicked. */
export function FlowSteps({
  current,
  stopped = false,
}: {
  current: number
  /** The flow stopped on the current step: refused, blocked or failed there. */
  stopped?: boolean
}) {
  return (
    <ol className="flow-steps" aria-label="Sanitization steps">
      {STEPS.map((label, index) => (
        <li
          key={label}
          className={
            index === current
              ? stopped
                ? 'is-current is-stopped'
                : 'is-current'
              : index < current
                ? 'is-done'
                : ''
          }
          aria-current={index === current ? 'step' : undefined}
        >
          {label}
          {index === current && stopped && <span className="step-stopped">stopped</span>}
        </li>
      ))}
    </ol>
  )
}

/**
 * One sanitize option: its NIST level, the resolver's state word, the
 * mechanism and protocol it would use, and the assurance it can claim.
 *
 * The level is the honest one: a host overwrite is shown as Clear whatever
 * level it arrived with, so an overwrite is never presented as a Purge.
 */
function Option({ option, unavailable = false }: { option: SanitizeOption; unavailable?: boolean }) {
  const { word, tone } = capabilityWord(option)
  const level = honestLevel(option)
  const relabelled = level !== option.level
  return (
    <Railed tone={tone}>
      <span className="row spread">
        <span className="option-title">{optionTitle(option)}</span>
        <span className={`state-mark is-${tone}`} data-state={option.state ?? undefined}>
          {word}
        </span>
      </span>
      {unavailable && (
        <span className="note" data-testid="option-cause">
          <strong>Not available: </strong>
          {optionCause(option)}.
        </span>
      )}
      <span className="note">{option.why}</span>
      {relabelled && (
        <span className="note-faint">
          This option arrived labelled {option.level}. It is a host overwrite,
          which is a Clear, and is shown as one.
        </span>
      )}
      {(option.mechanism || option.protocol) && (
        <span className="note-faint mono">
          {option.protocol ? `${option.protocol} \u00b7 ` : ''}
          {option.mechanism || 'mechanism not recorded'}
        </span>
      )}
      {option.assurance && (
        <span className="note-faint">
          <strong>Assurance: </strong>
          {option.assurance}
        </span>
      )}
      {(option.limitations ?? []).length > 0 && (
        <ul className="limitations">
          {(option.limitations ?? []).map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      )}
      {option.remediation && <span className="note-faint">{option.remediation}</span>}
    </Railed>
  )
}

/**
 * Why no Purge is offered, with the server's exact reason: a bridge, the
 * platform, a probe that did not run, the device itself. Nothing when a Purge
 * is offered.
 */
export function PurgeUnavailable({ assessment }: { assessment: DeviceAssessment }) {
  const absence = purgeAbsence(assessment)
  if (!absence) return null
  return (
    <Railed tone={absence.tone}>
      <p className="answer-q">Purge</p>
      <p className="answer-a" data-testid="purge-unavailable">
        Not available &mdash; {absence.word}
      </p>
      <p className="answer-detail">
        <strong>Because {absence.causeWord}: </strong>
        {absence.reason}
      </p>
      {absence.mechanism && (
        <p className="note-faint mono">
          {absence.protocol ? `${absence.protocol} \u00b7 ` : ''}
          {absence.mechanism}
        </p>
      )}
      <p className="note-faint">
        A Clear is not a substitute: it overwrites the addressable range only.
      </p>
    </Railed>
  )
}

/**
 * The three questions, answered before anything else on the screen.
 *
 * 1. What device am I about to operate on?
 * 2. What will happen?
 * 3. Can the application verify it?
 *
 * Everything shown is the server's assessment of the device as re-read from
 * the OS; this component decides nothing.
 */
export function AssessmentSummary({
  device,
  assessment,
  superseded = false,
}: {
  device: NormalizedDevice
  assessment: DeviceAssessment
  /**
   * A later answer - a refusal, a block, a failed job - has replaced this
   * preflight. The panel then says it is the earlier answer, so a READY from
   * before the refusal never sits beside the BLOCKED that replaced it.
   */
  superseded?: boolean
}) {
  const tone = superseded ? 'unknown' : headlineTone(assessment)
  const recommended = assessment.recommended
  const recommendedWord = recommended ? capabilityWord(recommended) : null
  const available = assessment.headline === 'READY' || assessment.headline === 'NOT AUTHORIZED'
  const verifyTone = recommended?.verification ? 'success' : 'unknown'
  const title = superseded
    ? 'Preflight, before the erase was stopped'
    : available
      ? 'Ready to sanitize'
      : 'Sanitization not available'

  return (
    <Panel title={title}>
      <div className="col" style={{ gap: 'var(--space-4)' }}>
        <div className="headline-block">
          {superseded && (
            <p className="note" data-testid="assessment-superseded">
              The preflight said {assessment.headline}. The erase was stopped after
              it: the state above is the current answer.
            </p>
          )}
          <p className={`headline-word is-${tone}`} data-testid="assessment-headline">
            {assessment.headline}
          </p>
          <p className="answer-detail">{assessment.reason}</p>
          {assessment.recommended_action && (
            <p className="answer-detail">
              <strong>What to do instead: </strong>
              {assessment.recommended_action}
            </p>
          )}
          {!available && (
            <p className="note-faint">No operation was performed on this device.</p>
          )}
        </div>

        <div className="answers">
          <Railed tone={device.system_device || device.mounted ? 'destructive' : 'unknown'}>
            <p className="answer-q">Device</p>
            <p className="answer-a">{deviceName(device)}</p>
            <p className="answer-detail">
              {bytes(device.capacity_bytes)}, {deviceKind(device)}
            </p>
            <p className="answer-detail">
              Serial {device.serial || 'not reported'}
            </p>
          </Railed>
          <Railed tone={recommendedWord ? recommendedWord.tone : 'destructive'}>
            <p className="answer-q">What will happen</p>
            <p className="answer-a">
              {recommended ? optionTitle(recommended) : 'Nothing: no method is available'}
            </p>
            {recommendedWord && (
              <p className="answer-detail">
                <span
                  className={`state-mark is-${recommendedWord.tone}`}
                  data-state={recommended?.state ?? undefined}
                >
                  {recommendedWord.word}
                </span>
                {recommended?.protocol ? ` \u00b7 ${recommended.protocol}` : ''}
              </p>
            )}
            <p className="answer-detail">
              {recommended ? recommended.why : 'The device is left untouched.'}
            </p>
            {recommended?.mechanism && (
              <p className="note-faint mono">{recommended.mechanism}</p>
            )}
            {recommended?.assurance && (
              <p className="answer-detail">
                <strong>Assurance: </strong>
                {recommended.assurance}
              </p>
            )}
            {recommended && (
              <p className="answer-detail">All data on the device will be destroyed.</p>
            )}
          </Railed>
          <Railed tone={verifyTone}>
            <p className="answer-q">Can it be verified?</p>
            <p className="answer-a">
              {recommended?.verification ? 'Yes' : 'No verification'}
            </p>
            <p className="answer-detail">
              {recommended?.verification || assessment.verification}
            </p>
          </Railed>
        </div>

        <ul className="checks" aria-label="Safety checks">
          {assessment.safety_checks.map((check) => {
            const mark = checkWord(check)
            return (
              <li key={check.key}>
                <span className={`state-mark is-${mark.tone}`}>{mark.word}</span>
                <span>{check.label}</span>
                <span className="check-detail">{check.detail}</span>
              </li>
            )
          })}
        </ul>

        {assessment.flash_limitation && (
          <Notice tone="warn">{assessment.flash_limitation}</Notice>
        )}

        <PurgeUnavailable assessment={assessment} />

        {(assessment.alternatives.length > 0 || assessment.unavailable.length > 0) && (
          <div className="options">
            {assessment.alternatives.length > 0 && <strong>Alternative</strong>}
            {assessment.alternatives.map((option) => (
              <Option
                key={`alt-${option.level}-${option.capability ?? option.title}`}
                option={option}
              />
            ))}
            {assessment.unavailable.length > 0 && <strong>Unavailable, and why</strong>}
            {assessment.unavailable.map((option) => (
              <Option
                key={`na-${option.level}-${option.capability ?? option.title}`}
                option={option}
                unavailable
              />
            ))}
          </div>
        )}

        {device.limitations.length > 0 && <Limitations items={device.limitations} />}
      </div>
    </Panel>
  )
}

/**
 * Where the job is in the destructive-workflow state machine, and why it
 * cannot move on. The state is derived by `lib/workflowState.ts`; this only
 * draws it. BLOCKED and FAILED list their reasons under WHY BLOCKED.
 */
export function WorkflowStrip({ flow }: { flow: SanitizeWorkflow }) {
  const stopped = flow.state === 'BLOCKED' || flow.state === 'FAILED'
  const index = flow.path.indexOf(flow.state)
  return (
    <section className="workflow-state" data-testid="workflow-state" aria-label="Workflow state">
      <ol className="workflow-path">
        {flow.path.map((state, at) => (
          <li
            key={state}
            className={
              state === flow.state
                ? `is-current${stopped ? ' is-stopped' : ''}`
                : at < index
                  ? 'is-done'
                  : ''
            }
            aria-current={state === flow.state ? 'step' : undefined}
          >
            {state.replace(/_/g, ' ')}
          </li>
        ))}
      </ol>
      <p className={`workflow-headline${stopped ? ' is-stopped' : ''}`}>{flow.headline}</p>
      {flow.whyBlocked.length > 0 && (
        <div className="why-blocked">
          <strong>{flow.state === 'FAILED' ? 'WHY IT FAILED' : 'WHY BLOCKED'}</strong>
          <ul>
            {flow.whyBlocked.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </div>
      )}
      <p className="note">{flow.nextAction}</p>
      <p className="note-faint">{BACKUP_NOTE}</p>
    </section>
  )
}
