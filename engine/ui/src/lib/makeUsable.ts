/**
 * "Make usable": the format that follows an erase.
 *
 * A sanitization leaves a device with nothing on it, which an operating system
 * reads as unformatted. This is the pure half of the screen that fixes that:
 * which filesystems are offered, whether a label is acceptable, when the action
 * is offered at all, when it may start, and how its outcome is worded. The
 * limits mirror core/format.py; the server checks them again and is the
 * authority. Nothing here touches the network.
 */

export type FormatFilesystem = 'exfat' | 'fat32' | 'ext4'

export interface FormatFilesystemOption {
  id: FormatFilesystem
  name: string
  maxLabel: number
  note: string
}

export const FORMAT_FILESYSTEMS: readonly FormatFilesystemOption[] = [
  {
    id: 'exfat',
    name: 'exFAT',
    maxLabel: 15,
    note: 'Windows, macOS and Linux. No 4 GiB file limit. The usual choice for a USB stick.',
  },
  {
    id: 'fat32',
    name: 'FAT32',
    maxLabel: 11,
    note: 'Works almost everywhere, including old devices. A file cannot exceed 4 GiB.',
  },
  {
    id: 'ext4',
    name: 'ext4',
    maxLabel: 16,
    note: 'Linux only. Ownership is given to the operator who ran the format.',
  },
]

const LABEL = /^[A-Za-z0-9_ -]*$/

function option(id: string): FormatFilesystemOption | undefined {
  return FORMAT_FILESYSTEMS.find((fs) => fs.id === id)
}

/** Why a label is not acceptable, or null. */
export function labelProblem(filesystem: string, label: string): string | null {
  const chosen = option(filesystem)
  if (!chosen) return `${filesystem} is not offered`
  if (label.length > chosen.maxLabel) {
    return `A ${chosen.name} label is at most ${chosen.maxLabel} characters.`
  }
  if (!LABEL.test(label)) {
    return 'A label may hold letters, digits, space, "_" and "-" only.'
  }
  return null
}

/**
 * Whether the panel is shown: the server says this device was just erased, and
 * no job of this screen is still running. A running erase would otherwise sit
 * beside an older completed one that the ledger still remembers.
 */
export function showMakeUsable(
  eligible: boolean,
  job: { started: boolean; finished: boolean },
): boolean {
  return eligible && (!job.started || job.finished)
}

export interface FormatStartInput {
  serial: string
  typed: string
  acknowledged: boolean
  filesystem: string
  label: string
}

/** Whether every local precondition holds. The server enforces them again. */
export function canStartFormat(input: FormatStartInput): boolean {
  const serial = input.serial.trim()
  return (
    serial !== '' &&
    input.typed.trim().toLowerCase() === serial.toLowerCase() &&
    input.acknowledged &&
    labelProblem(input.filesystem, input.label) === null
  )
}

export interface FormatOutcome {
  tone: 'ok' | 'warn' | 'danger'
  headline: string
  notes: string[]
}

/** How a finished format job is worded. A read-back mismatch is never success. */
export function formatOutcome(
  state: string,
  result: Record<string, unknown> | null,
  error?: string | null,
): FormatOutcome {
  if (state !== 'complete') {
    return {
      tone: 'danger',
      headline: 'The format did not finish',
      notes: [
        error ?? `The job ended ${state || 'without a state'}.`,
        'The device may be left without a partition table or filesystem. Nothing from before the erase is on it.',
      ],
    }
  }
  const filesystem = String(result?.filesystem ?? '')
  const name = option(filesystem)?.name ?? filesystem
  const label = String(result?.label ?? '')
  const notes = Array.isArray(result?.limitations)
    ? (result.limitations as unknown[]).map(String)
    : []
  if (result?.verified === true) {
    return { tone: 'ok', headline: `Formatted as ${name}, labelled "${label}"`, notes }
  }
  return { tone: 'warn', headline: `Formatted as ${name}, but not verified`, notes }
}
