import { useEffect, useState } from 'react'
import { api, RequestFailed } from '../lib/api'
import type {
  LedgerEntry,
  LedgerVerification,
  ReportCheck,
  ReportResult,
  ReportVerification,
  TamperDemo,
} from '../lib/api'
import { useCase } from '../lib/caseContext'
import { timestamp } from '../lib/format'
import { verdictMeaning } from '../lib/verdict'
import { operationLabel } from '../lib/ledger'
import { ChainStrip } from '../components/chain'
import { ReportSemanticsPanel } from '../components/capabilityState'
import {
  Empty,
  ErrorNotice,
  Evidence,
  Hash,
  Notice,
  Panel,
  Railed,
  Verdict,
} from '../components/widgets'
import type { Tone } from '../components/widgets'

/**
 * What each report check actually proves, and what it does not.
 *
 * Keyed by the value core/report/verify_report.py's `CheckName` emits. Getting
 * a key wrong here is silent - the lookup misses and the line renders empty -
 * so the five names below are the five members of that enum and nothing else.
 */
const CHECK_MEANING: Record<string, string> = {
  signature:
    'The signature verifies against the public key embedded in the report, so the canonical JSON bytes have not changed since signing.',
  fingerprint_matches_genesis:
    'The signing key is the key recorded in the ledger genesis entry. A mismatch is not proof of tampering — it means the report was signed by a different key than the one this chain was opened with.',
  chain_integrity:
    'The ledger excerpt carried inside the report is internally consistent: each entry hashes to what it records, and each links to the one before it.',
  chain_store:
    'The whole chain was re-verified from this host’s ledger store, independently of the excerpt the report carries. Without it, a reader is taking the report’s own word for the property the report exists to evidence.',
  blobs_available:
    'Every parameter and result blob referenced by the excerpt is present in the store and hashes to the value the entry records.',
}

/** The three outcomes a check can have. Two of them are not failures. */
function checkVerdict(check: ReportCheck): { word: string; tone: Tone } {
  if (!check.applicable) return { word: 'NOT CHECKED', tone: 'unknown' }
  return check.passed
    ? { word: 'PASS', tone: 'success' }
    : { word: 'FAIL', tone: 'destructive' }
}

/**
 * The chain's own status.
 *
 * INCOMPLETE_TAIL is not BROKEN: it means the last append did not finish, so
 * everything before it still verifies. Colouring it like a break would tell an
 * examiner to distrust a chain that is intact up to its final entry.
 */
function chainTone(status: string): Tone {
  // Valid is a cryptographic property, so it takes the seal colour.
  if (status === 'VALID') return 'seal'
  if (status === 'EMPTY') return 'unknown'
  if (status === 'INCOMPLETE_TAIL') return 'warning'
  return 'destructive'
}

/** The headline over the five checks: a count, not a boolean. */
function summarise(verification: ReportVerification): {
  word: string
  tone: Tone
  note: string
} {
  const total = verification.checks.length
  const applicable = verification.checks.filter((item) => item.applicable)
  const failed = applicable.filter((item) => !item.passed).length
  const skipped = total - applicable.length
  const passed = applicable.length - failed
  const word = `${passed} OF ${total} PASSED`
  if (failed > 0) {
    // Both counts, when there are both. A reader who is told only about the
    // failure is left to work out for themselves where the fifth check went.
    const skippedClause = skipped
      ? `, and ${skipped} could not run on this host`
      : ''
    return {
      word,
      tone: 'destructive',
      note: `${failed} check${failed === 1 ? '' : 's'} did not pass${skippedClause}. Read the failing one before treating this report as evidence.`,
    }
  }
  if (skipped > 0) {
    return {
      word,
      tone: 'warning',
      note: `${skipped} check${skipped === 1 ? ' was' : 's were'} not applicable on this host. Nothing failed, and nothing was established about the part that could not run.`,
    }
  }
  return { word, tone: 'success', note: 'Every check ran and every check passed.' }
}

/**
 * The tamper demonstration, rendered from the real verifier's two verdicts.
 *
 * Nothing here is animated or staged. The server copies this
 * host's chain to a scratch directory, changes one field of one entry in the
 * copy, hands the copy to `Ledger.verify` - the same call that guards the live
 * chain - and deletes the copy. Both verdicts below came back from that call.
 */
function TamperPanel({ demo, entries }: { demo: TamperDemo; entries: LedgerEntry[] }) {
  // The copy is the live chain with one field of one entry changed, so the
  // live entries drawn with the copy's verdict show exactly where the
  // verifier stopped trusting it.
  const oldestFirst = [...entries].reverse()
  return (
    <div className="col loose" data-testid="tamper-demo">
      {oldestFirst.length > 1 && (
        <div className="col tight">
          <span className="note">
            The copy after entry <strong>#{demo.tampered_seq}</strong> was changed:
            the verifier stops at the first entry whose hash no longer matches, and
            vouches for nothing after it.
          </span>
          <ChainStrip
            entries={oldestFirst}
            firstBrokenSeq={demo.after.first_broken_seq}
            label="The tampered copy of the chain, oldest first"
          />
        </div>
      )}
      <div className="split" style={{ gridTemplateColumns: '1fr 1fr' }}>
        <Railed tone="seal">
          <Verdict
            level={`BEFORE: ${demo.before.status}`}
            basis={`${demo.before.entry_count} entries`}
            tone="seal"
          />
          <span className="note">{demo.before.explanation}</span>
        </Railed>

        <Railed tone="destructive">
          <Verdict
            level={`AFTER: ${demo.after.status}`}
            basis={
              demo.after.first_broken_seq !== null
                ? `first broken sequence: #${demo.after.first_broken_seq}`
                : 'no break located'
            }
            tone="destructive"
          />
          <span className="note">{demo.after.explanation}</span>
        </Railed>
      </div>

      <Evidence
        rows={[
          { label: 'Record altered', value: `#${demo.tampered_seq}`, kind: 'mono' },
          { label: 'Field', value: demo.field, kind: 'mono' },
          { label: 'Was', value: demo.original_value, kind: 'mono' },
          { label: 'Changed to', value: demo.modified_value, kind: 'mono' },
          {
            label: 'Failure kind',
            value: demo.after.failure_kind ?? 'none',
            kind: 'mono',
          },
          {
            label: 'Still verified',
            value:
              demo.after.verified_through !== null &&
              demo.after.verified_through !== undefined
                ? `entries 0..${demo.after.verified_through}`
                : 'none',
            kind: 'mono',
          },
          {
            label: 'Unverifiable after the break',
            value: String(demo.after.unverifiable_count ?? 0),
            kind: 'mono',
          },
        ]}
      />

      <Notice tone={demo.production_ledger_modified ? 'danger' : 'ok'}>
        {demo.note}
      </Notice>
    </div>
  )
}

/** How many of the newest entries the explorer draws as blocks. */
const EXPLORER_BLOCKS = 14

function ChainExplorer({
  chain,
  broken,
}: {
  chain: LedgerVerification
  broken: number | null
}) {
  const newest = chain.entries.slice(0, EXPLORER_BLOCKS)
  const oldestFirst = [...newest].reverse()
  const [selectedSeq, setSelectedSeq] = useState<number | null>(null)
  const selected =
    chain.entries.find((entry) => entry.seq === selectedSeq) ?? chain.entries[0] ?? null
  const previous = selected
    ? chain.entries.find((entry) => entry.seq === selected.seq - 1) ?? null
    : null
  const links = selected
    ? selected.seq === 0
      ? { word: 'GENESIS', tone: 'seal' as Tone, basis: 'the first entry links to nothing' }
      : previous
        ? previous.entry_hash === selected.prev_entry_hash
          ? { word: 'LINKED', tone: 'seal' as Tone, basis: `prev hash = hash of #${previous.seq}` }
          : { word: 'BROKEN LINK', tone: 'destructive' as Tone, basis: `prev hash is not the hash of #${previous.seq}` }
        : { word: 'NOT SHOWN', tone: 'unknown' as Tone, basis: `#${selected.seq - 1} is not in this view` }
    : null

  return (
    <section className="custody" data-testid="chain-explorer" aria-labelledby="chain-title">
      <div className="custody-head">
        <div>
          <h2 className="custody-title" id="chain-title">
            Chain
          </h2>
          <p className="custody-sub">{chain.explanation}</p>
          {broken !== null && (
            <p className="custody-sub">
              The first break is at entry <strong>{broken}</strong>. Everything
              before it is still internally consistent; everything after it is not.
            </p>
          )}
        </div>
        <div className="custody-verdict">
          <Verdict
            level={chain.status}
            basis={`${chain.entry_count} ${chain.entry_count === 1 ? 'entry' : 'entries'}`}
            tone={chainTone(chain.status)}
          />
        </div>
      </div>
      {oldestFirst.length > 0 && (
        <ChainStrip
          entries={oldestFirst}
          firstBrokenSeq={broken}
          selectedSeq={selected?.seq ?? null}
          onSelect={(entry) => setSelectedSeq(entry.seq)}
          label={`The newest ${oldestFirst.length} entries of the chain, oldest first. Select one to inspect it.`}
        />
      )}
      {selected && links && (
        <div className="split" style={{ gridTemplateColumns: '1fr 300px' }}>
          <Evidence
            rows={[
              { label: 'Entry', value: `#${selected.seq}`, kind: 'mono' },
              { label: 'Operation', value: `${operationLabel(selected.operation)} (${selected.operation})` },
              { label: 'Recorded', value: timestamp(selected.ts_utc), kind: 'mono' },
              { label: 'Actor', value: selected.actor, kind: 'mono' },
              { label: 'Entry hash', value: selected.entry_hash, kind: 'hash' },
              { label: 'Previous hash', value: selected.prev_entry_hash, kind: 'hash' },
              { label: 'Parameters hash', value: selected.params_hash, kind: 'hash' },
              { label: 'Result hash', value: selected.result_hash, kind: 'hash' },
            ]}
          />
          <Railed tone={links.tone}>
            <Verdict level={links.word} basis={links.basis} tone={links.tone} />
            <span className="note">
              The entry hash is SHA-256 over this entry's fields, including the
              previous hash. Rewriting any earlier entry changes its hash, so
              this link would stop matching.
            </span>
          </Railed>
        </div>
      )}
    </section>
  )
}

export default function Audit() {
  const { openCase } = useCase()
  const [chain, setChain] = useState<LedgerVerification | null>(null)
  const [jobId, setJobId] = useState('')
  const [caseId, setCaseId] = useState('')
  const [operator, setOperator] = useState('')
  const [demo, setDemo] = useState<TamperDemo | null>(null)
  const [demoSeq, setDemoSeq] = useState('')
  const [report, setReport] = useState<ReportResult | null>(null)
  const [verification, setVerification] = useState<ReportVerification | null>(null)
  const [error, setError] = useState<{
    message: string
    kind?: string
    remediation?: string
  } | null>(null)

  async function refresh() {
    try {
      setChain(await api.ledgerVerify())
      setError(null)
    } catch (exc) {
      const failure = exc as RequestFailed
      setError({
        message: failure.message,
        kind: failure.kind,
        remediation: failure.remediation,
      })
    }
  }

  useEffect(() => {
    void refresh()
  }, [])

  // The open case pre-fills the field rather than replacing it: a report can
  // legitimately be generated for a job run before the case existed, and the
  // operator decides which case it documents.
  useEffect(() => {
    if (openCase) setCaseId(openCase.case_id)
  }, [openCase?.case_id])

  async function tamperScratchCopy() {
    setError(null)
    try {
      const parsed = Number.parseInt(demoSeq, 10)
      setDemo(await api.tamperDemo(Number.isNaN(parsed) ? undefined : parsed))
      // Re-read the live chain afterwards, on screen, so the claim that it was
      // not touched is something a viewer watches rather than is told.
      await refresh()
    } catch (exc) {
      const failure = exc as RequestFailed
      setDemo(null)
      setError({
        message: failure.message,
        kind: failure.kind,
        remediation: failure.remediation,
      })
    }
  }

  async function generate() {
    setError(null)
    try {
      setReport(await api.generateReport(jobId, { case_id: caseId, operator }))
      setVerification(null)
    } catch (exc) {
      const failure = exc as RequestFailed
      setError({
        message: failure.message,
        kind: failure.kind,
        remediation: failure.remediation,
      })
    }
  }

  async function verify() {
    setError(null)
    try {
      setVerification(await api.verifyReport(jobId))
    } catch (exc) {
      const failure = exc as RequestFailed
      // The previous verdict is cleared, not left on screen. A 404 means no
      // report was ever generated for this job; leaving the last job's green
      // tick above the error would read as "this one verified too", which is
      // the confusion the endpoint's own filename fallback used to create.
      setVerification(null)
      setError({
        message: failure.message,
        kind: failure.kind,
        remediation: failure.remediation,
      })
    }
  }

  const broken = chain?.first_broken_seq ?? null
  const summary = verification ? summarise(verification) : null

  return (
    <>
      <div className="screen-head">
        <h1>Audit</h1>
        <p>Hash-chained ledger, signed reports, and independent verification.</p>
        <div className="grow" />
        <button className="btn" onClick={() => void refresh()}>
          Re-verify chain
        </button>
      </div>

      <div className="screen-body">
        <ErrorNotice error={error} />

        {/* The chain's status is the one claim on this screen that has to
            carry to the back of the room, so it is a verdict and not a line
            inside a notice. The blocks under it are the chain itself: each
            one links to the one before it only when its recorded previous
            hash is that block's hash, computed here from the entries. */}
        {chain && (
          <ChainExplorer chain={chain} broken={broken} />
        )}

        {/* The ledger is six columns of hashes and timestamps and it does not
            fit beside anything. Squeezed into half the width it truncated the
            operation name and the timestamp - the two columns an auditor reads
            first - so it takes the whole width and the report controls sit
            under it. */}
        <Panel
          title={`Ledger (${chain?.entries.length ?? 0} shown, newest first)`}
          subtitle="Entry N carries the SHA-256 of entry N-1."
          tight
        >
          {!chain || chain.entries.length === 0 ? (
            <Empty>No ledger entries yet.</Empty>
          ) : (
            <div className="scroll-y scroll-x" style={{ maxHeight: '38vh' }}>
              <table className="itable" style={{ minWidth: 900 }}>
                <colgroup>
                  <col style={{ width: 'var(--gutter)' }} />
                  <col style={{ width: 56 }} />
                  <col style={{ width: 196 }} />
                  <col style={{ width: 122 }} />
                  <col />
                  <col style={{ width: 152 }} />
                  <col style={{ width: 152 }} />
                </colgroup>
                <thead>
                  <tr>
                    <th className="rail" />
                    <th>Seq</th>
                    <th>Timestamp</th>
                    <th>Actor</th>
                    <th>Operation</th>
                    <th>Entry hash</th>
                    <th>Prev hash</th>
                  </tr>
                </thead>
                <tbody>
                  {chain.entries.map((entry) => {
                    // The rail marks the span the break invalidated and nothing
                    // else. A rail on every row is decoration, and it stops
                    // meaning anything on the row that counts.
                    const after = broken !== null && entry.seq >= broken
                    return (
                      <tr
                        key={entry.entry_hash}
                        className={
                          after ? 'irow is-compact is-bad' : 'irow is-compact'
                        }
                      >
                        <td
                          className={after ? 'rail is-destructive' : 'rail'}
                          aria-hidden
                        >
                          <i />
                        </td>
                        <td className="mono">{entry.seq}</td>
                        <td className="mono">{timestamp(entry.ts_utc)}</td>
                        <td className="mono">{entry.actor}</td>
                        <td className="mono">{entry.operation}</td>
                        <td>
                          <Hash value={entry.entry_hash} />
                        </td>
                        <td>
                          <Hash value={entry.prev_entry_hash} />
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        <Panel
          title="Tamper demonstration"
          subtitle="Runs the real verifier against a scratch copy. The live chain is never opened for writing."
          actions={
            <div className="row" style={{ gap: 'var(--space-2)' }}>
              <input
                type="text"
                value={demoSeq}
                spellCheck={false}
                placeholder="entry # (optional)"
                style={{ width: 150 }}
                onChange={(event) => setDemoSeq(event.target.value)}
              />
              <button
                className="btn"
                disabled={!chain || chain.entry_count < 2}
                onClick={() => void tamperScratchCopy()}
              >
                Tamper a scratch copy
              </button>
            </div>
          }
        >
          {demo ? (
            <TamperPanel demo={demo} entries={chain?.entries ?? []} />
          ) : (
            <Empty>
              Press <strong>Tamper a scratch copy</strong>. The server copies this
              chain to a scratch directory, changes one field of one entry in
              the copy, and hands the copy to the same verification call that
              guards the live chain. The copy is deleted before the answer comes
              back, and the live chain is left byte for byte as it was &mdash;
              the panel above is re-read afterwards so you can watch that hold.
            </Empty>
          )}
        </Panel>

        <div className="split">
          {verification && summary ? (
            <Panel
              title="Report verification"
              subtitle="Five checks, each reported on its own."
            >
              <div className="col">
                <Railed tone={summary.tone}>
                  <Verdict
                    level={summary.word}
                    basis={verification.fingerprint}
                    tone={summary.tone}
                  />
                </Railed>
                <p className="note">{summary.note}</p>
                {/* The graded word is core's. The screen renders it and every
                    reason for a downgrade, and never computes its own. */}
                <Railed tone={verdictMeaning(verification.verdict).tone}>
                  <Verdict
                    level={verification.verdict || 'NO VERDICT'}
                    basis="graded verdict"
                    tone={verdictMeaning(verification.verdict).tone}
                  />
                  <span className="note">
                    {verdictMeaning(verification.verdict).label}
                  </span>
                  {(verification.verdict_reasons ?? []).map((reason) => (
                    <span key={reason} className="note-faint">
                      {reason}
                    </span>
                  ))}
                </Railed>
                {!verification.ledger_digest_matches && (
                  <Notice tone="danger">
                    The file checked is <strong>not</strong> the bytes the
                    ledger recorded when this job&apos;s report was generated.
                    The checks above describe whatever file is on disk now,
                    not the report this job produced.
                  </Notice>
                )}

                {/* Each check reported on its own. Reducing them to one boolean
                    would hide the difference between "the bytes changed" and
                    "the key was never published anywhere I can reach", and only
                    the first is a reason to distrust the report. NOT CHECKED is
                    the third outcome and is neither of the other two: a check
                    that could not run is not a check that ran and held. */}
                {verification.checks.map((check) => {
                  const outcome = checkVerdict(check)
                  return (
                    <Railed key={check.name} tone={outcome.tone}>
                      <Verdict
                        level={outcome.word}
                        basis={check.name}
                        tone={outcome.tone}
                      />
                      <span className="note">{check.detail}</span>
                      <span className="note-faint">
                        {CHECK_MEANING[check.name] ?? ''}
                      </span>
                    </Railed>
                  )
                })}

                <Notice tone="info">{verification.caveat}</Notice>

                {/* What the verified report says it documents: category and
                    assurance, read from the signed JSON. */}
                <ReportSemanticsPanel url={verification.json_url} />
              </div>
            </Panel>
          ) : (
            <Panel title="Report verification">
              <Empty>
                Verify a report to see the five checks, each reported on its own.
              </Empty>
            </Panel>
          )}

          <Panel title="Report generator">
            <div className="col">
              <label>
                Job id
                <input
                  type="text"
                  value={jobId}
                  spellCheck={false}
                  placeholder="erase-drive-…"
                  onChange={(event) => setJobId(event.target.value)}
                />
              </label>
              <label>
                Case id
                <input
                  type="text"
                  value={caseId}
                  spellCheck={false}
                  onChange={(event) => setCaseId(event.target.value)}
                />
              </label>
              <label>
                Operator label (optional)
                <input
                  type="text"
                  value={operator}
                  spellCheck={false}
                  placeholder="your own label for this run"
                  onChange={(event) => setOperator(event.target.value)}
                />
              </label>
              <p className="note-faint">
                This is a <strong>label</strong>, not an identity. The actor in
                the ledger is the operating-system account that ran the
                operation, resolved by the privileged helper from the uid it was
                started with and never from anything this browser sends.
                Whatever is typed here is kept beside it and marked as typed.
              </p>
              <div className="row">
                <button
                  className="btn primary"
                  disabled={!jobId}
                  onClick={() => void generate()}
                >
                  Generate signed report
                </button>
                <button className="btn" disabled={!jobId} onClick={() => void verify()}>
                  Verify
                </button>
              </div>

              {report && (
                <div className="col tight" data-testid="report-panel">
                  {/* The report as a thing you can open, not a path you have
                      to find in a file manager. Every link goes through the
                      artifact endpoint, which serves only the configured
                      reports directory - so no host path is on screen and none
                      needs to be. */}
                  <Railed tone={summary ? summary.tone : 'success'}>
                    <Verdict
                      level="REPORT"
                      basis={`signed \u00b7 ${report.sha256.slice(0, 16)}\u2026`}
                      tone={summary ? summary.tone : 'success'}
                    />
                  </Railed>

                  <Evidence
                    stacked
                    rows={[
                      { label: 'Case', value: report.case_id, kind: 'mono' },
                      {
                        label: 'Generated',
                        value: timestamp(report.generated_at),
                      },
                      {
                        label: 'SHA-256 (JSON, authoritative)',
                        value: report.sha256,
                        kind: 'hash',
                      },
                      {
                        label: 'Signing key',
                        value: report.pubkey_fingerprint,
                        kind: 'hash',
                      },
                      {
                        label: 'Chain',
                        value: chain
                          ? `${chain.status} \u00b7 ${chain.entry_count} entries`
                          : 'not read',
                      },
                      {
                        label: 'Verification',
                        value: summary
                          ? summary.word
                          : 'not run \u2014 press Verify',
                      },
                    ]}
                  />

                  <ReportSemanticsPanel url={report.json_url} />

                  <div className="row wrap" style={{ gap: 'var(--space-2)' }}>
                    <a
                      className="btn"
                      href={report.pdf_url}
                      target="_blank"
                      rel="noreferrer"
                    >
                      Open PDF
                    </a>
                    <a className="btn" href={`${report.pdf_url}?download=true`}>
                      Download PDF
                    </a>
                    <a
                      className="btn"
                      href={report.json_url}
                      target="_blank"
                      rel="noreferrer"
                    >
                      View JSON
                    </a>
                    <a className="btn" href={`${report.json_url}?download=true`}>
                      Download JSON
                    </a>
                    <button className="btn primary" onClick={() => void verify()}>
                      Verify
                    </button>
                  </div>

                  <Notice tone="info">
                    The JSON is authoritative and the PDF is not: the signature
                    covers the canonical JSON bytes, and the PDF is a rendering
                    for a human. Both describe the same operation, and the PDF
                    carries the JSON&apos;s digest so the pair can be matched.
                  </Notice>
                </div>
              )}
            </div>
          </Panel>
        </div>
      </div>
    </>
  )
}
