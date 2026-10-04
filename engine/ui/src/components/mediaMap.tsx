import type { MediaMap } from '../lib/api'
import { bytes } from '../lib/format'
import {
  MAP_KINDS,
  contentBytes,
  describeRegion,
  kindMeaning,
  kindName,
  sharePercent,
} from '../lib/mediaMap'
import { Panel } from './widgets'

const FILL: Record<string, string> = {
  ZERO: 'var(--map-zero)',
  FILL: 'var(--map-fill)',
  TEXT: 'var(--map-text)',
  STRUCTURED: 'var(--map-structured)',
  HIGH_ENTROPY: 'var(--map-entropy)',
}

/** Adjacent regions of one class, drawn as one cell so no seam shows between them. */
function runs(map: MediaMap): { start: number; count: number; kind: string }[] {
  const out: { start: number; count: number; kind: string }[] = []
  map.regions.forEach((region, index) => {
    const last = out[out.length - 1]
    if (last && last.kind === region.kind) last.count += 1
    else out.push({ start: index, count: 1, kind: region.kind })
  })
  return out
}

/**
 * The image from its first byte to its last, one cell per region, coloured by
 * the class most of the region's bytes fell into. Under it, a tick wherever a
 * file header the carver knows sits on a sector boundary.
 *
 * Every cell carries its own description, and the legend names each class
 * with its share, so nothing depends on telling the colours apart.
 */
export function MediaMapPanel({ map }: { map: MediaMap }) {
  const count = map.regions.length
  const headerTotal = Object.values(map.headers).reduce((sum, value) => sum + value, 0)
  return (
    <Panel
      title="Media map"
      subtitle={
        map.sampled
          ? `${count} regions, sampled: ${bytes(map.bytes_read)} of ${bytes(map.size_bytes)} read`
          : `${count} regions, every byte read`
      }
    >
      <div className="col" data-testid="media-map">
        <svg
          className="media-strip"
          viewBox={`0 0 ${Math.max(count, 1)} 10`}
          preserveAspectRatio="none"
          shapeRendering="crispEdges"
          role="img"
          aria-label={`Media map of ${bytes(map.size_bytes)}: ${MAP_KINDS.map(
            (kind) => `${kindName(kind)} ${sharePercent(map, kind)}`,
          ).join(', ')}`}
        >
          {runs(map).map((run) => (
            <rect
              key={run.start}
              x={run.start}
              y={0}
              width={run.count}
              height={7}
              fill={FILL[run.kind] ?? 'var(--map-fill)'}
            />
          ))}
          {map.regions.map((region, index) => (
            <rect key={region.offset} x={index} y={0} width={1} height={10} fill="transparent">
              <title>{describeRegion(region)}</title>
            </rect>
          ))}
          {map.regions.map((region, index) =>
            Object.keys(region.headers).length ? (
              <rect
                key={`h${region.offset}`}
                x={index + 0.2}
                y={8}
                width={0.6}
                height={2}
                fill="var(--text-primary)"
              />
            ) : null,
          )}
        </svg>
        <div className="media-axis note-faint">
          <span>0</span>
          <span>{bytes(map.size_bytes)}</span>
        </div>
        <ul className="media-legend">
          {MAP_KINDS.map((kind) => (
            <li key={kind}>
              <i style={{ background: FILL[kind] }} aria-hidden />
              <strong>{kindName(kind)}</strong>
              <span className="mono">{sharePercent(map, kind)}</span>
              <span className="note-faint">{kindMeaning(kind)}</span>
            </li>
          ))}
        </ul>
        <p className="note">
          {bytes(contentBytes(map))} could hold recoverable content; the rest is
          zeroed or filled.{' '}
          {headerTotal
            ? `${headerTotal} file header${headerTotal === 1 ? '' : 's'} on sector boundaries (ticks under the strip): ${Object.entries(
                map.headers,
              )
                .map(([ext, value]) => `${value} ${ext}`)
                .join(', ')}. Headers, not validated files.`
            : 'No known file header was found on a sector boundary in the bytes read.'}
        </p>
      </div>
    </Panel>
  )
}
