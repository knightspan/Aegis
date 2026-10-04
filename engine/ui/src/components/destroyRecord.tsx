import { useEffect, useRef, useState } from 'react'
import { api, RequestFailed, streamJob } from '../lib/api'
import type {
  DestroyMediaType,
  DestroyTechnique,
  DeviceRow,
  JobStatus,
  ReportResult,
} from '../lib/api'
import { useCase } from '../lib/caseContext'
import { bytes } from '../lib/format'
import { MEDIA_TYPES, TECHNIQUES, localToIso, mediaTypeOf, missingFields } from '../lib/destroy'
import { ErrorNotice, JobId, Notice, Panel } from './widgets'

/**
 * Destroy, recorded.
 *
 * NIST SP 800-88 Rev. 2 has three outcomes. Clear and Purge are things this
 * application does to a drive and reads back. Destroy is done by a shredder,
 * a disintegrator or a furnace, and no software can perform or observe it.
 * This panel records what the people who did it attest, chains it and signs
 * it - and the record says, in its signed bytes, that the tool saw nothing.
 * It opens no device.
 */
export function DestroyRecordPanel({ rows }: { rows: DeviceRow[] }) {
  const { openCase } = useCase()
  const [open, setOpen] = useState(false)
  const [from, setFrom] = useState('')
  const [serial, setSerial] = useState('')
  const [model, setModel] = useState('')
  const [capacity, setCapacity] = useState<number | null>(null)
  const [mediaType, setMediaType] = useState<DestroyMediaType>('HDD')
  const [technique, setTechnique] = useState<DestroyTechnique>('SHRED')
  const [techniqueDetail, setTechniqueDetail] = useState('')
  const [particle, setParticle] = useState('')
  const [reason, setReason] = useState('')
  const [performedBy, setPerformedBy] = useState('')
  const [witnessedBy, setWitnessedBy] = useState('')
  const [performedAt, setPerformedAt] = useState('')
  const [location, setLocation] = useState('')
  const [vendor, setVendor] = useState('')
  const [jobId, setJobId] = useState<string | null>(null)
  const [status, setStatus] = useState<JobStatus | null>(null)
  const [report, setReport] = useState<ReportResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [passphrase, setPassphrase] = useState('')
  const [needsPassphrase, setNeedsPassphrase] = useState(false)
  const [error, setError] = useState<{
    message: string
    kind?: string
    remediation?: string
  } | null>(null)
  const detach = useRef<(() => void) | null>(null)

  useEffect(() => () => detach.current?.(), [])

  function prefill(path: string) {
    setFrom(path)
    const row = rows.find((item) => item.device.path === path)
    if (!row) return
    setSerial(row.device.serial)
    setModel(row.device.model)
    setCapacity(row.device.size_bytes || null)
    setMediaType(mediaTypeOf(row.device))
  }

  const missing = missingFields({
    serial,
    reason,
    performedBy,
    performedAt,
    technique,
    techniqueDetail,
  })

  function fail(exc: unknown) {
    const failure = exc as RequestFailed
    setError({ message: failure.message, kind: failure.kind, remediation: failure.remediation })
  }

  async function submit() {
    setError(null)
    setBusy(true)
    try {
      const accepted = await api.recordDestroy({
        serial: serial.trim(),
        model: model.trim(),
        capacity_bytes: capacity,
        media_type: mediaType,
        technique,
        technique_detail: techniqueDetail.trim(),
        particle_size_mm: particle ? Number(particle) : null,
        reason: reason.trim(),
        performed_by: performedBy.trim(),
        witnessed_by: witnessedBy.trim(),
        performed_at: localToIso(performedAt, new Date(performedAt).getTimezoneOffset()),
        location: location.trim(),
        vendor_certificate: vendor.trim(),
        notes: '',
        case_id: openCase?.case_id ?? '',
      })
      setJobId(accepted.job_id)
      setStatus(null)
      setReport(null)
      detach.current?.()
      detach.current = streamJob(accepted.job_id, {
        onProgress: () => undefined,
        onState: setStatus,
      })
    } catch (exc) {
      fail(exc)
    } finally {
      setBusy(false)
    }
  }

  async function sign() {
    if (!jobId) return
    setError(null)
    try {
      setReport(
        await api.generateReport(jobId, {
          case_id: openCase?.case_id ?? '',
          operator: '',
          key_passphrase: passphrase || undefined,
        }),
      )
      setPassphrase('')
      setNeedsPassphrase(false)
    } catch (exc) {
      if ((exc as RequestFailed).kind === 'KeyPassphraseMissing') setNeedsPassphrase(true)
      fail(exc)
    }
  }

  const recorded = status?.state === 'complete' && status.settled !== false

  return (
    <Panel
      title="Record a physical destruction"
      subtitle="NIST Destroy: for media that cannot be cleared or purged, or must never be reused"
      actions={
        <button className="btn" onClick={() => setOpen(!open)} aria-expanded={open}>
          {open ? 'Close' : 'Record a destruction'}
        </button>
      }
    >
      {!open ? (
        <p className="note">
          A shredder or a furnace destroys a drive; no software can, or can see it
          happen. This records what the people who did it attest, chained and
          signed, and the record says the application observed nothing.
        </p>
      ) : (
        <div className="col" data-testid="destroy-form">
          <ErrorNotice error={error} />
          <div className="form-grid">
            <label>
              Detected device (optional)
              <select value={from} onChange={(event) => prefill(event.target.value)}>
                <option value="">type the details instead</option>
                {rows.map((row) => (
                  <option key={row.device.path} value={row.device.path}>
                    {row.device.model || row.device.path}, serial {row.device.serial || 'none'}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Serial number
              <input
                className="mono"
                value={serial}
                spellCheck={false}
                onChange={(event) => setSerial(event.target.value)}
              />
            </label>
            <label>
              Model
              <input value={model} onChange={(event) => setModel(event.target.value)} />
            </label>
            <label>
              Media type
              <select
                value={mediaType}
                onChange={(event) => setMediaType(event.target.value as DestroyMediaType)}
              >
                {MEDIA_TYPES.map((item) => (
                  <option key={item.value} value={item.value}>
                    {item.label}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Technique
              <select
                value={technique}
                onChange={(event) => setTechnique(event.target.value as DestroyTechnique)}
              >
                {TECHNIQUES.map((item) => (
                  <option key={item.value} value={item.value}>
                    {item.label}
                  </option>
                ))}
              </select>
            </label>
            {technique === 'OTHER' && (
              <label>
                What was done
                <input
                  value={techniqueDetail}
                  onChange={(event) => setTechniqueDetail(event.target.value)}
                />
              </label>
            )}
            <label>
              Largest fragment (mm, optional)
              <input
                type="number"
                min={1}
                max={1000}
                value={particle}
                onChange={(event) => setParticle(event.target.value)}
              />
            </label>
            <label>
              Destroyed on
              <input
                type="datetime-local"
                value={performedAt}
                onChange={(event) => setPerformedAt(event.target.value)}
              />
            </label>
            <label>
              Destroyed by
              <input value={performedBy} onChange={(event) => setPerformedBy(event.target.value)} />
            </label>
            <label>
              Witnessed by
              <input value={witnessedBy} onChange={(event) => setWitnessedBy(event.target.value)} />
            </label>
            <label>
              Where
              <input value={location} onChange={(event) => setLocation(event.target.value)} />
            </label>
            <label>
              Vendor certificate number (optional)
              <input
                className="mono"
                value={vendor}
                onChange={(event) => setVendor(event.target.value)}
              />
            </label>
            <label className="span-2">
              Why it was destroyed rather than cleared or purged
              <input value={reason} onChange={(event) => setReason(event.target.value)} />
            </label>
          </div>
          {capacity !== null && <span className="note-faint">Capacity {bytes(capacity)}</span>}
          <Notice tone="info">
            The record states what the named people attest. The application does
            not authenticate them, and did not observe the destruction; both are
            written into the signed record.
          </Notice>
          <div className="row wrap">
            <button
              className="btn primary"
              disabled={missing.length > 0 || busy}
              onClick={() => void submit()}
            >
              Record the destruction
            </button>
            {missing.length > 0 && (
              <span className="note">Still needed: {missing.join(', ')}.</span>
            )}
          </div>
          {jobId && (
            <div className="col tight" data-testid="destroy-recorded">
              <JobId value={jobId} />
              {recorded ? (
                <>
                  <span className="state-mark is-warning">
                    Recorded in the chain: attested, not observed
                  </span>
                  {report ? (
                    <div className="row">
                      <span className="state-mark is-seal">Signed record {report.json_name}</span>
                      <a className="btn" href={report.pdf_url} target="_blank" rel="noreferrer">
                        Open PDF
                      </a>
                    </div>
                  ) : (
                    <div className="row wrap">
                      {needsPassphrase && (
                        <input
                          type="password"
                          aria-label="Signing key passphrase"
                          placeholder="Signing key passphrase"
                          value={passphrase}
                          onChange={(event) => setPassphrase(event.target.value)}
                        />
                      )}
                      <button className="btn" onClick={() => void sign()}>
                        Get the signed record
                      </button>
                    </div>
                  )}
                </>
              ) : (
                <span className="note">
                  {status ? `The record job ${status.state}.` : 'Recording…'}
                  {status?.error ? ` ${status.error}` : ''}
                </span>
              )}
            </div>
          )}
        </div>
      )}
    </Panel>
  )
}
