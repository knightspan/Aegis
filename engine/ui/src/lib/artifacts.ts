import type { ArtifactRef, CarveCandidate, EraseVerification } from './api'

/**
 * Pure helpers about recovered artifacts and verification verdicts.
 *
 * Kept out of the screens so they can be tested without a DOM. Both of the
 * decisions here are ones the interface must not get wrong: which file on disk
 * a candidate row refers to, and whether a sanitization actually proved
 * anything.
 */

/**
 * The recovered file that corresponds to one candidate, if the carve wrote one.
 *
 * `core.carve.classify.output_filename` names every written object
 * `<offset>_<confidence>_<name>.<ext>` with the offset zero-padded to twelve
 * digits, so the offset alone locates it in the listing.
 *
 * The match is on the **offset and extension first**, falling back to the
 * offset alone. Not on the whole filename: the confidence is part of the name
 * and a re-scan can legitimately score the same object differently, so a
 * whole-name match would silently stop finding files that are right there.
 * Returns `null` rather than guessing when nothing matches - a candidate with
 * no artifact is a finding about the image, not a recovered file, and the
 * preview pane says exactly that.
 */
export function artifactFor(
  candidate: CarveCandidate,
  artifacts: ArtifactRef[],
): ArtifactRef | null {
  const prefix = String(candidate.offset).padStart(12, '0') + '_'
  const base = (item: ArtifactRef) => item.name.split('/').pop() ?? item.name
  return (
    artifacts.find(
      (item) =>
        base(item).startsWith(prefix) &&
        base(item).endsWith(`.${candidate.ext.toLowerCase()}`),
    ) ??
    artifacts.find((item) => base(item).startsWith(prefix)) ??
    null
  )
}

/** The four outcomes a sanitization verification can have. */
export type VerificationWord =
  | 'PASSED'
  | 'FAILED'
  | 'INCONCLUSIVE'
  | 'NOT APPLICABLE'

/**
 * What a run's verification established, in four words rather than two.
 *
 * **Uncertainty is never collapsed into PASS.** The engine reports
 * `passed: true`, `passed: false` or `passed: null`, and the third is not a
 * quiet version of the first: it means the check ran and settled nothing, or
 * could not run at all. An interface that rendered `null` as a tick would be
 * making a claim the engine deliberately refused to make.
 *
 * NOT APPLICABLE is separated from INCONCLUSIVE by whether any bytes were
 * read: a verification that checked nothing did not attempt the measurement,
 * and one that checked bytes and could not conclude did.
 */
export function verificationWord(verification: EraseVerification | null): VerificationWord {
  if (!verification) return 'NOT APPLICABLE'
  if (verification.passed === true) return 'PASSED'
  if (verification.passed === false) return 'FAILED'
  if (verification.bytes_checked === 0) return 'NOT APPLICABLE'
  return 'INCONCLUSIVE'
}
