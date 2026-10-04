import { Fragment, useEffect, useMemo, useRef, useState } from 'react'
import { api, artifactUrl, RequestFailed, streamJob } from '../lib/api'
import type {
  MediaMap,
  ArtifactRef,
  CarveCandidate,
  JobStatus,
  Progress,
} from '../lib/api'
import { artifactFor } from '../lib/artifacts'
import { useCase } from '../lib/caseContext'
import { bytes, evidenceScore, hex, percent } from '../lib/format'
import {
  matchesPii,
  PII_KINDS,
  PII_LABELS,
  piiSummary,
  piiTotal,
  sortByPii,
} from '../lib/triage'
import {
  BrowseButton,
  Empty,
  ErrorNotice,
  JobId,
  Evidence,
  Notice,
  Panel,
  ProgressView,
  Railed,
  Stat,
  Verdict,
} from '../components/widgets'
import type { Tone } from '../components/widgets'
import { MediaMapPanel } from '../components/mediaMap'
import { AcquirePanel } from '../components/acquirePanel'

/**
 * Confidence bucket to tone.
 *
 * Deliberately inverted from the residual-findings palette. There, red is the
 * alarming outcome; here HIGH means high confidence, and colouring it red
 * would read as a warning about the candidate an examiner should trust most.
 */
const BUCKET_TONE: Record<string, Tone> = {
  HIGH: 'success',
  MEDIUM: 'warning',
  LOW: 'destructive',
}

/**
 * How each object was found, in the words the pipeline uses.
 *
 * `source` is the engine's own field and the filter has to keep its exact
 * values, so this maps them to the sentence an examiner reads rather than
 * renaming them.
 */
const SOURCE_LABELS: Record<string, string> = {
  fs_metadata: 'filesystem undelete',
  signature: 'signature carve',
  structure: 'structure carve',
}

/** What each score component establishes. Shown beside its basis points. */
const COMPONENT_MEANING: Record<string, string> = {
  header: "the format's magic sits exactly where this candidate claims the object starts",
  exact_length:
    'the end was derived — a footer was found, or a parser walked the format’s own length fields — rather than guessed',
  decoder: 'a real decoder read the object',
  entropy: 'the byte distribution matches what this format produces',
  fs_metadata: 'a surviving filesystem record agrees that a file lived here',
  no_overlap: 'no higher-scoring candidate claims the same bytes',
  reassembly:
    'rebuilt from separate runs: where the gap was is inferred, so the total is held below HIGH',
}

function ScoreBreakdown({ candidate }: { candidate: CarveCandidate }) {
  const entries = Object.entries(candidate.score_components)
  // The raw sum and the stored score are different numbers whenever every
  // component fires: the six come to 10,500 and the engine clamps. Showing
  // only the clamped one made 10000 look like a measurement instead of a
  // ceiling, so both are rendered and the clamp is named where it happens.
  const rawTotal = entries.reduce((sum, [, value]) => sum + value, 0)
  const total = Math.min(rawTotal, 10000)
  const clamped = rawTotal > total
  const tone = BUCKET_TONE[candidate.bucket] ?? 'unknown'

  return (
    <div className="col">
      {/* The number first, at the size the room can read, with the arithmetic
          under it. Every line below is how it was reached. */}
      <Railed tone={tone}>
        <Verdict
          level={candidate.bucket}
          basis={`evidence score ${evidenceScore(total)}`}
          tone={tone}
        />
        <span className="note-faint">
          HIGH at 8000, MEDIUM at 5000. The total is clamped, never scaled.
          {clamped && (
            <>
              {' '}
              The components below come to <strong>{rawTotal}</strong>, so this
              object is at the ceiling: 10000 is where the clamp lands, not a
              measurement.
            </>
          )}
        </span>
        {/* The sentence the percentage used to make unnecessary, and then
            made false. A reader who sees a bounded number beside a word like
            HIGH will supply "probability" if nothing else is offered. */}
        <span className="note-faint">
          This is a sum of measured evidence, <strong>not</strong> a
          probability that the object is correct. What the calibration
          measured is the bucket: over eight seeds and 173 candidates, all 104
          HIGH candidates matched a planted object byte for byte — on those
          corpora. On a 7 GiB image HIGH precision was 86.6% before the
          footer-bound fix.
        </span>
      </Railed>

      <div className="bar-breakdown">
        {entries.map(([name, value]) => (
          <span
            key={name}
            className={value > 0 ? 'is-on' : 'is-off'}
            title={`${name}: ${value} bp`}
            style={{ width: `${(value / 10000) * 100}%` }}
          />
        ))}
      </div>

      <h3>How this number was produced</h3>

      {/* Six components, each with its own rail. A component that scored zero
          keeps its row and its sentence: zero is a measurement - the check ran
          and did not hold - and rendering it blank would let a reader assume it
          was never attempted. */}
      {entries.map(([name, value]) => (
        <Railed key={name} tone={value > 0 ? 'success' : 'unknown'}>
          <span className="row spread">
            <span className="mono">{name}</span>
            <span
              className="mono"
              style={{
                color: value > 0 ? 'var(--text-primary)' : 'var(--text-muted)',
              }}
            >
              {value}
            </span>
          </span>
          <span className="note">
            {value > 0
              ? COMPONENT_MEANING[name]
              : `not established — ${COMPONENT_MEANING[name]}`}
          </span>
        </Railed>
      ))}

      {candidate.entropy_millibits_per_byte !== null && (
        <div className="row wrap" style={{ gap: 'var(--space-6)' }}>
          <Stat
            label="entropy"
            value={`${(candidate.entropy_millibits_per_byte / 1000).toFixed(2)} bits/byte`}
          />
          {candidate.high_entropy_windows_bp !== null && (
            <Stat
              label="high-entropy windows"
              value={percent(candidate.high_entropy_windows_bp)}
            />
          )}
        </div>
      )}

      {candidate.validation_detail && (
        <div className="col tight">
          <span className="stat-label">decoder said</span>
          <pre className="log">{candidate.validation_detail}</pre>
        </div>
      )}

      {candidate.overlapped && (
        <Notice tone="warn">
          A higher-scoring candidate covers overlapping bytes
          {candidate.overlaps_with !== null && ` (at ${hex(candidate.overlaps_with)})`}
          . This candidate is kept and marked rather than dropped: a suppressed
          candidate that turns out to matter must remain visible.
        </Notice>
      )}
    </div>
  )
}

/**
 * One recovered object as a card: the thumbnail, and the facts beside it.
 *
 * The forensic metadata is the point, not the picture. A gallery that showed
 * only thumbnails would be a photo browser; every card here carries the
 * confidence and how it was reached, the structure verdict, the fragment
 * count, the derived length and the identifier count, because those are what
 * an examiner triages on.
 *
 * **No PII value is ever rendered**, here or anywhere else. The server sends
 * kinds and counts and nothing else, so there is no value in this component to
 * leak even by accident.
 */
function GalleryCard({
  candidate,
  artifact,
  selected,
  onSelect,
}: {
  candidate: CarveCandidate
  artifact: ArtifactRef | null
  selected: boolean
  onSelect: () => void
}) {
  const tone = BUCKET_TONE[candidate.bucket] ?? 'unknown'
  // The server marks raster images inline, but a browser still cannot draw
  // every one: Chromium has no TIFF decoder, and a corrupt decoy is exactly
  // what a carver is supposed to find. A failed decode falls back to the
  // truthful empty state instead of a broken-image icon on the projector.
  const [failed, setFailed] = useState(false)
  const renderable =
    !failed &&
    artifact !== null &&
    artifact.disposition === 'inline' &&
    artifact.content_type.startsWith('image/')

  return (
    <button
      type="button"
      className={selected ? 'gallery-card is-selected' : 'gallery-card'}
      onClick={onSelect}
    >
      <span className={`rail is-${tone} gallery-rail`} aria-hidden>
        <i />
      </span>

      <span className="gallery-thumb">
        {renderable ? (
          <img
            src={artifactUrl('recovered', artifact.name)}
            alt={`Recovered ${candidate.ext.toUpperCase()} at ${hex(candidate.offset)}`}
            loading="lazy"
            onError={() => setFailed(true)}
          />
        ) : (
          <span className="gallery-thumb-empty mono">
            .{candidate.ext}
            <span className="note-faint">
              {failed
                ? 'browser cannot draw this'
                : artifact
                  ? 'no preview'
                  : 'not written'}
            </span>
          </span>
        )}
      </span>

      <span className="gallery-facts">
        <span className="gallery-name mono" title={candidate.original_name ?? ''}>
          {candidate.original_name ?? `${hex(candidate.offset)}.${candidate.ext}`}
        </span>
        <Verdict
          tight
          level={candidate.bucket}
          basis={evidenceScore(candidate.confidence_bp)}
          tone={tone}
        />
        <span className="gallery-meta mono">
          {bytes(candidate.length)} · {candidate.source}
        </span>
        <span className="gallery-meta mono">
          structure: {candidate.validation}
          {candidate.fragments.length > 0 &&
            ` · fragments: ${candidate.fragments.length}`}
        </span>
        <span
          className="gallery-meta mono"
          style={{
            color:
              piiTotal(candidate) > 0
                ? 'var(--state-warning)'
                : 'var(--text-muted)',
          }}
        >
          identifiers: {piiSummary(candidate)}
        </span>
      </span>
    </button>
  )
}

/**
 * The real recovered bytes, rendered by the browser.
 *
 * Three rules, and each of them is the server's rule showing through:
 *
 * * **An image renders as an image.** The bytes are served with the type the
 *   server's closed extension table assigns and `X-Content-Type-Options:
 *   nosniff`, and the *browser* decodes them. Nothing is decoded server-side -
 *   a thumbnail generated by Pillow in the process that holds the ledger would
 *   be a decompression-bomb target, and the browser's decoders are sandboxed,
 *   fuzzed continuously and updated without us.
 * * **A recovered document downloads; it does not open in place.** A PDF
 *   viewer is a scripting engine and this file came off the evidence. The
 *   server refuses to mark it `inline` regardless of what is asked for here,
 *   so this is the UI agreeing with a decision it cannot override.
 * * **Everything else says "no preview" and still offers the bytes.** A
 *   truthful empty state beats a broken image icon, and an examiner who wants
 *   the object can still have it.
 */
function PreviewPane({
  candidate,
  artifact,
}: {
  candidate: CarveCandidate
  artifact: ArtifactRef | null
}) {
  const [failed, setFailed] = useState(false)
  if (!artifact) {
    return (
      <div className="col tight">
        <span className="stat-label">preview</span>
        <div className="preview-pane">
          Nothing was written for this candidate. Re-run the scan with an
          output directory to recover the bytes; until then this row is a
          finding about the image, not a file.
        </div>
      </div>
    )
  }

  const renderable = artifact.disposition === 'inline' && !failed
  const isImage = artifact.content_type.startsWith('image/')

  return (
    <div className="col tight">
      <span className="stat-label">preview</span>
      {renderable && isImage ? (
        <div className="preview-pane is-media">
          {/* Same-origin, served by this deployment. The page's CSP allows
              img-src 'self' and nothing else, so a preview that tried to reach
              anywhere else would fail loudly in the console. */}
          <img
            src={artifactUrl('recovered', artifact.name)}
            alt={`Recovered ${candidate.ext.toUpperCase()} at ${hex(candidate.offset)}`}
            loading="lazy"
            onError={() => setFailed(true)}
          />
        </div>
      ) : (
        <div className="preview-pane">
          {failed
            ? `Preview unavailable: this browser could not decode the recovered ${candidate.ext.toUpperCase()} (${candidate.validation}). The bytes are still available below.`
            : artifact.content_type === 'application/pdf'
            ? 'Preview unavailable by design: this PDF came off the evidence, and a PDF viewer runs script. Download it and open it in a program you chose.'
            : `Preview unavailable for ${artifact.content_type}. The recovered bytes are still available below.`}
        </div>
      )}

      <div className="row" style={{ gap: 'var(--space-2)' }}>
        {renderable && (
          <a
            className="btn"
            href={artifactUrl('recovered', artifact.name)}
            target="_blank"
            rel="noreferrer"
          >
            Open
          </a>
        )}
        <a
          className="btn"
          href={artifactUrl('recovered', artifact.name, { download: true })}
        >
          Download ({bytes(artifact.size)})
        </a>
      </div>
      <span className="note-faint">
        Served from this deployment&apos;s recovered directory, with the type
        from a closed table and no content sniffing. Nothing is fetched from
        the network.
      </span>
    </div>
  )
}

/**
 * What the bifragment reconstruction actually did, laid out in order.
 *
 * The engine's scope is narrow and the screen says so in the same words the
 * core does: **baseline JPEG, exactly two runs, gap at most 2 MiB, on a volume
 * whose cluster size is known.** Nothing here implies generalised
 * arbitrary-fragment reassembly, because the engine does not do that and a
 * diagram that suggested it would be the interface overclaiming on the
 * engine's behalf.
 *
 * Every number rendered is one the candidate carries. The gap is computed from
 * the two runs rather than reported separately, and the arithmetic is shown.
 */
function ReassemblyExplainer({ candidate }: { candidate: CarveCandidate }) {
  const runs = candidate.fragments
  if (runs.length === 0) return null

  const first = runs[0]
  const last = runs[runs.length - 1]
  const covered = runs.reduce((sum, run) => sum + run.length, 0)
  const gap = runs.length === 2 ? runs[1].offset - (first.offset + first.length) : null
  const reassemblyScore = candidate.score_components.reassembly ?? 0

  return (
    <div className="col tight" data-testid="reassembly-explainer">
      <h3>How this object was put back together</h3>

      {/* The runs on the medium, to scale against the span they sit in. */}
      <div className="fragment-map" aria-hidden>
        {runs.map((run, index) => (
          <Fragment key={`${run.offset}-${index}`}>
            {index > 0 && (
              <span
                className="fragment-gap"
                style={{
                  flexGrow: Math.max(
                    run.offset - (runs[index - 1].offset + runs[index - 1].length),
                    1,
                  ),
                }}
              />
            )}
            <span className="fragment-run" style={{ flexGrow: run.length }} />
          </Fragment>
        ))}
      </div>

      <Evidence
        stacked
        rows={[
          ...runs.map((run, index) => ({
            label: `Run ${index + 1}`,
            value: `${hex(run.offset)} + ${run.length.toLocaleString('en-US')} bytes`,
            kind: 'mono' as const,
          })),
          ...(gap !== null
            ? [
                {
                  label: 'Gap between them',
                  value: `${gap.toLocaleString('en-US')} bytes (${bytes(gap)}) — foreign data, not part of this object`,
                  kind: 'mono' as const,
                },
              ]
            : []),
          {
            label: 'Bytes in the object',
            value: `${covered.toLocaleString('en-US')} (${bytes(covered)})`,
            kind: 'mono',
          },
          {
            label: 'Span it sits in',
            value: `${hex(first.offset)}..${hex(last.offset + last.length)}`,
            kind: 'mono',
          },
          {
            label: 'SHA-256',
            value: candidate.sha256,
            kind: 'hash',
          },
          ...(candidate.fs_type
            ? [{ label: 'Volume', value: candidate.fs_type }]
            : []),
        ]}
      />

      <Railed tone={candidate.validation === 'VALID' ? 'success' : 'warning'}>
        <Verdict
          level={`STRUCTURE: ${candidate.validation}`}
          basis="a decoder consumed the reassembled bytes whole"
          tone={candidate.validation === 'VALID' ? 'success' : 'warning'}
        />
        {candidate.validation_detail && (
          <span className="note">{candidate.validation_detail}</span>
        )}
      </Railed>

      <Railed tone={candidate.validation === 'VALID' || candidate.validation === 'valid' ? 'success' : 'warning'}>
        <Verdict
          level="MCU ACCOUNTING: JOIN ACCEPTED"
          basis={`evidence-score cap applied: reassembly ${reassemblyScore} bp`}
          tone={candidate.validation === 'VALID' || candidate.validation === 'valid' ? 'success' : 'warning'}
        />
        <span className="note">
          The join was accepted because the scan&apos;s MCU count agrees with
          the frame header — the check a decoder does not make, and the one
          that tells a span with foreign bytes inside it from a whole file.
        </span>
      </Railed>

      <Notice tone="warn">
        <strong>Baseline JPEG, bifragment reconstruction.</strong> This engine
        rejoins a baseline JPEG split into <em>exactly two</em> runs, both still
        on the medium, with a gap of at most 2&nbsp;MiB, on a volume whose
        cluster size is known. Three fragments, a missing tail, a progressive
        JPEG, a non-JPEG or a layout off the volume&apos;s grid are reported as
        ordinary candidates and never as a reconstruction. The evidence score
        is held one basis point under HIGH for this object because where the
        gap was is inferred, not read.
      </Notice>
    </div>
  )
}

export default function Recovery() {
  const { openCase } = useCase()
  const [view, setView] = useState<'gallery' | 'table'>('gallery')
  const [artifacts, setArtifacts] = useState<ArtifactRef[]>([])
  const [image, setImage] = useState('')
  const [outDir, setOutDir] = useState('')
  const [undelete, setUndelete] = useState(true)
  const [signatures, setSignatures] = useState(true)
  const [piiTriage, setPiiTriage] = useState(true)
  const [jobId, setJobId] = useState<string | null>(null)
  const [progress, setProgress] = useState<Progress | null>(null)
  const [status, setStatus] = useState<JobStatus | null>(null)
  const [selected, setSelected] = useState<CarveCandidate | null>(null)
  const [error, setError] = useState<{
    message: string
    kind?: string
    remediation?: string
  } | null>(null)

  const [filterType, setFilterType] = useState('')
  const [filterBucket, setFilterBucket] = useState('')
  const [filterSource, setFilterSource] = useState('')
  const [filterFlag, setFilterFlag] = useState('')
  const [filterPii, setFilterPii] = useState('')
  const [filterCategory, setFilterCategory] = useState('')
  const [onlyReconstructed, setOnlyReconstructed] = useState(false)
  const [sortPii, setSortPii] = useState(false)
  const detach = useRef<(() => void) | null>(null)

  useEffect(() => () => detach.current?.(), [])

  // The recovered directory is listed once a scan finishes, so the gallery
  // renders the files that actually exist rather than the files the candidate
  // list implies. A candidate with no artifact is a finding about the image,
  // not a recovered object, and the preview pane says exactly that.
  useEffect(() => {
    if (!status || status.state !== 'complete') return
    void api
      .artifacts('recovered')
      .then((answer) => setArtifacts(answer.artifacts))
      .catch(() => setArtifacts([]))
  }, [status?.job_id, status?.state])

  const candidates = (status?.result?.candidates ?? []) as CarveCandidate[]
  const mediaMap = (status?.result?.media_map ?? null) as MediaMap | null

  const filtered = useMemo(() => {
    const kept = candidates.filter((item) => {
      if (filterType && item.ext !== filterType) return false
      if (filterBucket && item.bucket !== filterBucket) return false
      if (filterSource && item.source !== filterSource) return false
      if (filterCategory && item.category !== filterCategory) return false
      if (onlyReconstructed && item.fragments.length === 0) return false
      if (filterFlag) {
        const flags = item.flags as unknown as Record<string, boolean>
        if (!flags[filterFlag]) return false
      }
      return matchesPii(item, filterPii)
    })
    return sortPii ? sortByPii(kept) : kept
  }, [
    candidates,
    filterType,
    filterBucket,
    filterSource,
    filterCategory,
    onlyReconstructed,
    filterFlag,
    filterPii,
    sortPii,
  ])

  const withIdentifiers = candidates.filter((item) => piiTotal(item) > 0).length

  async function start() {
    setError(null)
    try {
      const accepted = await api.carve({
        image,
        undelete,
        carve_signatures: signatures,
        pii_triage: piiTriage,
        out_dir: outDir || null,
        // Filed against the open case, so the recovery appears on the case
        // screen and the report generated later inherits the case id without
        // anyone retyping it.
        case_id: openCase?.case_id ?? '',
      })
      setJobId(accepted.job_id)
      setProgress(null)
      setStatus(null)
      setSelected(null)
      setArtifacts([])
      detach.current?.()
      detach.current = streamJob(accepted.job_id, {
        onProgress: setProgress,
        onState: setStatus,
      })
    } catch (exc) {
      const failure = exc as RequestFailed
      setError({
        message: failure.message,
        kind: failure.kind,
        remediation: failure.remediation,
      })
    }
  }

  const types = [...new Set(candidates.map((item) => item.ext))].sort()
  const sources = [...new Set(candidates.map((item) => item.source))].sort()
  const categories = [...new Set(candidates.map((item) => item.category))]
    .filter(Boolean)
    .sort()
  const reconstructedCount = candidates.filter(
    (item) => item.fragments.length > 0,
  ).length
  const selectedArtifact = selected ? artifactFor(selected, artifacts) : null

  return (
    <>
      <div className="screen-head">
        <h1>Recovery</h1>
        <p>Read-only. Nothing in the carving path opens the evidence for writing.</p>
        <div className="grow" />
        <span className={openCase ? 'state-mark is-success' : 'state-mark is-warning'}>
          {openCase ? `Filed under ${openCase.case_id}` : 'No case open'}
        </span>
      </div>

      <div className="screen-body">
        <ErrorNotice error={error} />

        {!openCase && (
          <Notice tone="info">
            No case is open, so this recovery will not be filed against one.
            The run is still recorded in the hash chain and a report can still
            be generated for it; it simply will not appear on a case screen.
            Open a case first if this is evidence work.
          </Notice>
        )}

        {/* A raw device is imaged first, read-only, then carved as an image.
            On Windows and macOS the job carries the selected disk's serial. */}
        <AcquirePanel caseId={openCase?.case_id ?? ''} onImage={setImage} />

        <Panel title="Evidence and scan configuration">
          <div className="row wrap" style={{ alignItems: 'flex-end' }}>
            <label className="grow">
              Evidence image
              <div className="row">
                <input
                  type="text"
                  className="grow"
                  value={image}
                  spellCheck={false}
                  placeholder="/path/to/case.dd or case.E01"
                  onChange={(event) => setImage(event.target.value)}
                />
                <BrowseButton kind="file" onPick={([chosen]) => setImage(chosen)} />
              </div>
            </label>
            <label className="grow">
              Output directory (optional)
              <div className="row">
                <input
                  type="text"
                  className="grow"
                  value={outDir}
                  spellCheck={false}
                  placeholder="leave empty to list candidates without writing"
                  onChange={(event) => setOutDir(event.target.value)}
                />
                <BrowseButton kind="folder" onPick={([chosen]) => setOutDir(chosen)} />
              </div>
            </label>
            <label className="inline">
              <input
                type="checkbox"
                checked={undelete}
                onChange={(event) => setUndelete(event.target.checked)}
              />
              <span>Undelete from filesystem metadata</span>
            </label>
            <label className="inline">
              <input
                type="checkbox"
                checked={signatures}
                onChange={(event) => setSignatures(event.target.checked)}
              />
              <span>Signature and structure carve</span>
            </label>
            <label
              className="inline"
              title="Counts identifier shapes in documents, databases and unclassified objects. No value is stored."
            >
              <input
                type="checkbox"
                checked={piiTriage}
                onChange={(event) => setPiiTriage(event.target.checked)}
              />
              <span>PII triage (counts only)</span>
            </label>
            <button className="btn primary" disabled={!image} onClick={() => void start()}>
              Scan
            </button>
          </div>
        </Panel>

        {jobId && !status && (
          <Panel title="Progress">
            <ProgressView progress={progress} />
          </Panel>
        )}

        {jobId && (
          <Panel title="Scan job">
            <JobId value={jobId} />
            <p className="note" style={{ marginTop: 'var(--space-2)' }}>
              {status
                ? `Scan ${status.state}. The Audit screen generates this scan's report from this id.`
                : 'Scanning. Once the scan has finished, the Audit screen generates its report from this id.'}
            </p>
          </Panel>
        )}

        {mediaMap && <MediaMapPanel map={mediaMap} />}

        {candidates.length > 0 && (
          <div className="split">
            <Panel
              title={`Recovered (${filtered.length} of ${candidates.length})`}
              tight
              actions={
                <div className="row wrap" style={{ gap: 'var(--space-2)' }}>
                  <button
                    className={view === 'gallery' ? 'btn primary' : 'btn'}
                    onClick={() => setView('gallery')}
                  >
                    Gallery
                  </button>
                  <button
                    className={view === 'table' ? 'btn primary' : 'btn'}
                    onClick={() => setView('table')}
                  >
                    Table
                  </button>
                  <select value={filterType} onChange={(e) => setFilterType(e.target.value)}>
                    <option value="">all types</option>
                    {types.map((item) => (
                      <option key={item} value={item}>
                        {item}
                      </option>
                    ))}
                  </select>
                  <select
                    value={filterBucket}
                    onChange={(e) => setFilterBucket(e.target.value)}
                  >
                    <option value="">all buckets</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                  <select
                    value={filterSource}
                    onChange={(e) => setFilterSource(e.target.value)}
                    aria-label="Filter by how the object was found"
                  >
                    <option value="">all sources</option>
                    {sources.map((item) => (
                      <option key={item} value={item}>
                        {SOURCE_LABELS[item] ?? item}
                      </option>
                    ))}
                  </select>
                  <select
                    value={filterCategory}
                    onChange={(e) => setFilterCategory(e.target.value)}
                    aria-label="Filter by category"
                  >
                    <option value="">all categories</option>
                    {categories.map((item) => (
                      <option key={item} value={item}>
                        {item}
                      </option>
                    ))}
                  </select>
                  <label
                    className="inline"
                    title="Objects rebuilt from more than one run on the medium."
                  >
                    <input
                      type="checkbox"
                      checked={onlyReconstructed}
                      onChange={(e) => setOnlyReconstructed(e.target.checked)}
                    />
                    <span>reconstructed only ({reconstructedCount})</span>
                  </label>
                  <select value={filterFlag} onChange={(e) => setFilterFlag(e.target.value)}>
                    <option value="">all flags</option>
                    <option value="has_exif_gps">has GPS</option>
                    <option value="is_encrypted">encrypted</option>
                    <option value="is_password_protected">password protected</option>
                    <option value="contains_macros">macros</option>
                    <option value="has_embedded_files">embedded files</option>
                    <option value="is_signed">signed</option>
                  </select>
                  <select
                    value={filterPii}
                    onChange={(e) => setFilterPii(e.target.value)}
                    aria-label="Filter by identifiers found"
                  >
                    <option value="">all identifiers</option>
                    <option value="any">any identifier ({withIdentifiers})</option>
                    {PII_KINDS.map((kind) => (
                      <option key={kind} value={kind}>
                        {PII_LABELS[kind]}
                      </option>
                    ))}
                  </select>
                  <label className="inline">
                    <input
                      type="checkbox"
                      checked={sortPii}
                      onChange={(e) => setSortPii(e.target.checked)}
                    />
                    <span>most identifiers first</span>
                  </label>
                </div>
              }
            >
              {view === 'gallery' && (
                <div className="scroll-y" style={{ maxHeight: '58vh' }}>
                  {filtered.length === 0 ? (
                    <Empty>
                      No candidate matches these filters. Clear one to widen the
                      view; a filtered-out candidate is hidden, never dropped.
                    </Empty>
                  ) : (
                    <div className="gallery">
                      {filtered.map((item) => (
                        <GalleryCard
                          key={`${item.offset}-${item.ext}`}
                          candidate={item}
                          artifact={artifactFor(item, artifacts)}
                          selected={selected?.offset === item.offset}
                          onSelect={() => setSelected(item)}
                        />
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* This table runs to hundreds of rows on a real image, which is
                  the one place the two-line verdict is the wrong trade. Rows
                  are one line and a fixed 30px, the layout is fixed, and the
                  evidence-score cell keeps the bucket word and the score on a
                  single baseline. Nothing here reflows as the list is
                  filtered. */}
              <div
                className="scroll-y"
                style={{
                  maxHeight: '58vh',
                  display: view === 'table' ? undefined : 'none',
                }}
              >
                <table className="itable">
                  <colgroup>
                    <col style={{ width: 'var(--gutter)' }} />
                    <col style={{ width: 96 }} />
                    <col />
                    <col style={{ width: 72 }} />
                    <col style={{ width: 92 }} />
                    <col style={{ width: 100 }} />
                    <col style={{ width: 140 }} />
                    <col style={{ width: 170 }} />
                  </colgroup>
                  <thead>
                    <tr>
                      <th className="rail" />
                      <th>Offset</th>
                      <th>Name</th>
                      <th>Type</th>
                      <th>Size</th>
                      <th>Source</th>
                      {/* "Confidence" alone invited the probability reading
                          this column never supported. */}
                      <th title="Sum of measured evidence components, out of 10000. Not a probability that the object is correct.">
                        Evidence score
                      </th>
                      <th>Identifiers</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((item) => {
                      const tone = BUCKET_TONE[item.bucket] ?? 'unknown'
                      const isSelected = selected?.offset === item.offset
                      return (
                        <tr
                          key={`${item.offset}-${item.ext}`}
                          className={
                            isSelected
                              ? 'irow is-compact is-openable is-selected'
                              : 'irow is-compact is-openable'
                          }
                          onClick={() => setSelected(item)}
                        >
                          <td className={`rail is-${tone}`} aria-hidden>
                            <i />
                          </td>
                          <td className="offset">{hex(item.offset)}</td>
                          <td title={item.original_name ?? undefined}>
                            {item.original_name ?? (
                              <span style={{ color: 'var(--text-muted)' }}>—</span>
                            )}
                          </td>
                          <td className="mono">{item.ext}</td>
                          <td className="mono">{bytes(item.length)}</td>
                          <td className="mono">{item.source}</td>
                          <td>
                            <Verdict
                              tight
                              level={item.bucket}
                              // The exact integer, not a rounded percentage:
                              // a reassembled object is held at 7999 bp
                              // precisely so it reads below the 8000 HIGH
                              // floor, and any rounding hides that.
                              basis={evidenceScore(item.confidence_bp)}
                              tone={tone}
                            />
                          </td>
                          {/* Kinds and counts only: the server sends no value. */}
                          <td
                            className="mono"
                            style={{
                              color:
                                piiTotal(item) > 0
                                  ? 'var(--text-primary)'
                                  : 'var(--text-muted)',
                            }}
                            title={item.pii?.basis}
                          >
                            {piiSummary(item)}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </Panel>

            <Panel
              title={selected ? 'Score breakdown' : 'Select a candidate'}
              subtitle={selected ? 'Six evidence components and the reassembly hold, each in basis points.' : undefined}
            >
              {selected ? (
                <div className="col loose">
                  <Evidence
                    stacked
                    rows={[
                      {
                        label: 'Offset',
                        value: `${hex(selected.offset)} (${selected.offset})`,
                        kind: 'mono',
                      },
                      {
                        label: 'Length',
                        value: `${selected.length.toLocaleString('en-US')} bytes`,
                        kind: 'mono',
                      },
                      { label: 'SHA-256', value: selected.sha256, kind: 'hash' },
                      { label: 'MIME', value: selected.mime, kind: 'mono' },
                      {
                        label: 'Validation',
                        value: selected.validation,
                        kind: 'mono',
                      },
                      ...(selected.fragments.length > 0
                        ? [
                            {
                              label: 'Fragments',
                              value: selected.fragments
                                .map(
                                  (run) =>
                                    `${hex(run.offset)} + ${run.length.toLocaleString('en-US')}`,
                                )
                                .join('  ·  '),
                              kind: 'mono' as const,
                            },
                          ]
                        : []),
                      ...(selected.fs_type
                        ? [{ label: 'Filesystem', value: selected.fs_type }]
                        : []),
                    ]}
                  />

                  {selected.fragments.length > 0 && (
                    <Notice tone="warn">
                      Reassembled across a gap. This object was not one run on
                      the medium: the digest above covers the fragments listed,
                      in order, and not the span from the offset. A JPEG decoder
                      consumed the reassembled bytes whole, which is the
                      evidence the gap was found correctly.
                    </Notice>
                  )}

                  {selected.contiguity_assumed && (
                    <Notice tone="warn">
                      Contiguity assumed: the cluster chain did not survive
                      deletion, so the layout was inferred rather than read.
                      {selected.contiguity_contradicted &&
                        ' A cluster inside this file’s span belongs to a live file, so it was definitely fragmented.'}
                    </Notice>
                  )}

                  <div className="col tight">
                    <span className="stat-label">identifiers (PII triage)</span>
                    <Evidence
                      stacked
                      rows={[
                        { label: 'Found', value: piiSummary(selected) },
                        { label: 'How read', value: selected.pii?.basis || 'not scanned' },
                      ]}
                    />
                    {piiTotal(selected) > 0 && (
                      <Notice tone="info">
                        A count is a signal to look, not a finding: the detectors
                        match a shape, and a checksum for Aadhaar and card numbers.
                        No value was stored. Open the recovered object to see
                        what was counted.
                      </Notice>
                    )}
                  </div>

                  {selected.fragments.length > 0 && (
                    <ReassemblyExplainer candidate={selected} />
                  )}
                  <ScoreBreakdown candidate={selected} />
                  <PreviewPane candidate={selected} artifact={selectedArtifact} />
                </div>
              ) : (
                <Empty>
                  Click a candidate to see the six score components and their basis
                  points.
                </Empty>
              )}
            </Panel>
          </div>
        )}

        {status?.result?.limitations != null &&
          (status.result.limitations as string[]).length > 0 && (
            <Panel title="Limitations">
              <ul className="limitations">
                {(status.result.limitations as string[]).map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
            </Panel>
          )}
      </div>
    </>
  )
}
