// What the Sanitize screen shows, derived only from what the engine sent.
//
// Nothing in this module decides a method, a level's reachability or whether
// a device is flash. Each of those used to be decided here, in parallel with
// the engine, and each disagreed with it: a DoD choice the request never
// carried (audit F6), a flash test on `rotational` that a USB bridge defeats
// (F5), and a Purge preference list missing two methods (F7). The engine now
// sends its decision on the device row (helper/daemon.py enumerate_devices),
// and this module only reads it.
//
// Kept free of React and of runtime imports so `node --test` can run it
// directly: see ui/tests/erasePlan.test.ts.

import type {
  DeviceRow,
  EraseDriveBody,
  Level,
  PlannedErase,
} from './api'

/** Operator-facing names for the engine's method identifiers. */
export const METHOD_LABELS: Record<string, string> = {
  SINGLE_PASS_OVERWRITE: 'Single-pass overwrite',
  DOD_5220_22_M_3PASS: 'DoD 5220.22-M — 3 pass',
  ATA_SECURITY_ERASE_ENHANCED: 'ATA SECURITY ERASE (enhanced)',
  ATA_SANITIZE_BLOCK_ERASE: 'ATA SANITIZE — block erase',
  ATA_SANITIZE_OVERWRITE: 'ATA SANITIZE — overwrite',
  ATA_SANITIZE_CRYPTO_SCRAMBLE: 'ATA SANITIZE — cryptographic scramble',
  NVME_SANITIZE_BLOCK: 'NVMe SANITIZE',
  NVME_FORMAT_SES1: 'NVMe Format NVM — cryptographic erase',
  SED_CRYPTO_ERASE: 'SED cryptographic erase (Opal)',
}

/** Methods the host writes itself, so the host can read the pattern back. */
const HOST_OVERWRITES: ReadonlySet<string> = new Set([
  'SINGLE_PASS_OVERWRITE',
  'DOD_5220_22_M_3PASS',
])

/** Methods that change the key rather than the data: verified by change, not pattern. */
const CRYPTOGRAPHIC: ReadonlySet<string> = new Set([
  'ATA_SANITIZE_CRYPTO_SCRAMBLE',
  'NVME_FORMAT_SES1',
  'SED_CRYPTO_ERASE',
])

/**
 * How a method's result is checked, in the words the certificate uses.
 *
 * Stated before the run so the operator knows what "verified" will mean for
 * this device: a host read-back of the written pattern, a sampled check that
 * the data changed, or the drive's own completion status plus a sampled read.
 */
export function plannedVerification(method: string | null | undefined): string {
  if (!method) return 'not planned: no method is reachable'
  if (HOST_OVERWRITES.has(method)) return 'Read-back of the written pattern'
  if (CRYPTOGRAPHIC.has(method)) return 'Sampled windows must change; device completion status'
  return 'Device completion status, then a sampled read-back'
}

/** The label for a method id, falling back to the id itself, never to blank. */
export function methodLabel(method: string | null | undefined): string {
  if (!method) return 'no method'
  return METHOD_LABELS[method] ?? method
}

/** The engine's plan for `level` on this row, or null when none was sent. */
export function planFor(
  row: DeviceRow | null,
  level: Level,
): PlannedErase | null {
  const plans = row?.erase_preview?.plans ?? []
  return plans.find((plan) => plan.level === level) ?? null
}

/** True only when the engine chose a method this build can issue. */
export function runnable(plan: PlannedErase | null): boolean {
  return Boolean(plan && plan.reachable && plan.executable && plan.method)
}

/** Purge where the engine can run one, otherwise Clear. */
export function defaultLevel(row: DeviceRow | null): Level {
  return runnable(planFor(row, 'PURGE')) ? 'PURGE' : 'CLEAR'
}

/**
 * The engine's flash determination for this row.
 *
 * `flash` is null when the helper sent none. The kernel's rotational flag is
 * deliberately not consulted as a fallback: it is the signal that was wrong.
 */
export function flashOf(row: DeviceRow | null): {
  flash: boolean | null
  reason: string
} {
  if (row?.media) return { flash: row.media.flash, reason: row.media.reason }
  if (row?.erase_preview) {
    return {
      flash: row.erase_preview.flash,
      reason: row.erase_preview.flash_reason,
    }
  }
  return { flash: null, reason: 'The helper sent no flash determination.' }
}

/**
 * The request body. A level, never a method: the engine selects the method
 * from probed capability, and a field here would be a choice it overrides.
 */
export function eraseBody(
  path: string,
  level: Level,
  typedSerial: string,
  authorizationId: string,
): EraseDriveBody {
  // Always a real erase of the selected device. The serial and the server's
  // one-use authorization travel with every request; the server refuses one
  // that is missing either, and there is no mode that needs neither.
  return {
    path,
    level,
    typed_serial: typedSerial,
    authorization_id: authorizationId,
  }
}

/**
 * A sentence when the job ran something other than what was shown, else null.
 *
 * The preview comes from the device scan and the job re-probes the device, so
 * they can only disagree if the device changed in between. If they do, the
 * operator must be told on this screen, not discover it in the certificate.
 */
export function contradiction(
  shown: PlannedErase | null,
  result: Record<string, unknown> | null | undefined,
): string | null {
  if (!shown || !result) return null
  const ran = typeof result.method === 'string' ? result.method : null
  if (!ran || ran === shown.method) return null
  return (
    `The engine ran ${methodLabel(ran)} (${ran}), but this screen showed ` +
    `${methodLabel(shown.method)} before you committed. The device's ` +
    'capabilities changed between the device scan and the job’s own probe. ' +
    'The ledger and the certificate record what ran. Rescan the device.'
  )
}
