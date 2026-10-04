/**
 * The trace sweep, in words.
 *
 * After a file erase the server looks for what the desktop kept of the files:
 * thumbnails, recent-files entries, Trash and Recycle Bin copies, jump lists
 * and the Quick Look cache. Each trace
 * comes back with the evidence that ties it to an erased path and what became
 * of it. This file turns that into the words and tones the File eraser shows.
 */

import type { TraceRecord, TraceSweep } from './api'

export type TraceTone = 'success' | 'warning' | 'destructive' | 'unknown'

const KIND_WORDS: Record<string, string> = {
  THUMBNAIL: 'Thumbnail',
  THUMBNAIL_FAILURE: 'Failed-thumbnail marker',
  RECENT_ENTRY: 'Recent-files entry',
  RECENT_DOCUMENT: 'Recent document link',
  TRASH_COPY: 'Copy in the Trash',
  TRASH_RECORD: 'Trash record',
  RECYCLE_BIN_COPY: 'Copy in the Recycle Bin',
  RECYCLE_BIN_RECORD: 'Recycle Bin record',
  RECENT_SHORTCUT: 'Recent shortcut',
  POSSIBLE_COPY: 'Possible copy',
  JUMP_LIST_ENTRY: 'Jump-list entry',
  QUICKLOOK_THUMBNAIL: 'Quick Look thumbnail',
}

/** A kind in words. A kind this file does not know keeps its own name. */
export function traceKind(kind: string): string {
  return KIND_WORDS[kind] ?? kind
}

/**
 * What became of one trace. The word carries the meaning; the tone separates
 * done, left for a person to judge, and failed.
 */
export function traceOutcome(trace: TraceRecord): { word: string; tone: TraceTone } {
  if (trace.removed) return { word: trace.action || 'removed', tone: 'success' }
  if (!trace.exact) return { word: 'left for you to judge', tone: 'warning' }
  if (trace.report_only) return { word: 'reported, not edited', tone: 'warning' }
  if (trace.error) return { word: 'not removed', tone: 'destructive' }
  return { word: 'not removed', tone: 'warning' }
}

/** One line for the whole sweep. */
export function traceSummary(sweep: TraceSweep): string {
  const found = sweep.traces.length
  const places = sweep.searched.length
  if (!found) {
    return `Nothing found in the ${places} place${places === 1 ? '' : 's'} searched.`
  }
  const removed = sweep.traces.filter((trace) => trace.removed).length
  const left = found - removed
  return `${found} found, ${removed} removed${left ? `, ${left} left` : ''}.`
}
