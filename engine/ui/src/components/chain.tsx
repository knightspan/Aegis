import type { LedgerEntry } from '../lib/api'
import { operationLabel, shortTime } from '../lib/ledger'

/**
 * A run of chain entries as blocks, each linked to the one before it.
 *
 * The link is drawn from data, not assumed: it is solid when this entry's
 * `prev_entry_hash` is the previous block's `entry_hash`, and dashed and red
 * when it is not - or when the server's verification put the first broken
 * entry at or before this one. Entries after a break are drawn unchecked,
 * because a verifier that stopped at the break vouches for nothing after it.
 */
export function ChainStrip({
  entries,
  firstBrokenSeq = null,
  selectedSeq = null,
  onSelect,
  label,
}: {
  /** Oldest first. */
  entries: LedgerEntry[]
  firstBrokenSeq?: number | null
  selectedSeq?: number | null
  onSelect?: (entry: LedgerEntry) => void
  label: string
}) {
  return (
    <ol className="chain" aria-label={label} style={{ listStyle: 'none', margin: 0 }}>
      {entries.map((entry, index) => {
        const previous = index > 0 ? entries[index - 1] : null
        const linked = !previous || entry.prev_entry_hash === previous.entry_hash
        const broken = firstBrokenSeq !== null && entry.seq === firstBrokenSeq
        const unchecked = firstBrokenSeq !== null && entry.seq > firstBrokenSeq
        const state = broken ? ' is-broken' : unchecked ? ' is-unchecked' : ''
        const selected = selectedSeq === entry.seq ? ' is-selected' : ''
        const body = (
          <>
            <span className="chain-seq">#{entry.seq}</span>
            <span className="chain-op" title={entry.operation}>
              {operationLabel(entry.operation)}
            </span>
            <span className="chain-hash" title={entry.entry_hash}>
              {entry.entry_hash.slice(0, 10)}
            </span>
            <span>{shortTime(entry.ts_utc)}</span>
          </>
        )
        return (
          <li key={entry.seq} style={{ display: 'flex' }}>
            {previous && (
              <span
                className={linked && !broken ? 'chain-link' : 'chain-link is-broken'}
                aria-hidden
              />
            )}
            {onSelect ? (
              <button
                type="button"
                className={`chain-block${state}${selected}`}
                aria-pressed={selectedSeq === entry.seq}
                onClick={() => onSelect(entry)}
              >
                {body}
              </button>
            ) : (
              <div className={`chain-block${state}`}>{body}</div>
            )}
          </li>
        )
      })}
    </ol>
  )
}
