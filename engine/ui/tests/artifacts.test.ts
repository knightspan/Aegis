import { test } from 'node:test'
import assert from 'node:assert/strict'

import { artifactFor, verificationWord } from '../src/lib/artifacts.ts'
import { artifactUrl } from '../src/lib/api.ts'
import type {
  ArtifactRef,
  CarveCandidate,
  EraseVerification,
} from '../src/lib/api.ts'

function artifact(name: string): ArtifactRef {
  return {
    name,
    size: 1024,
    content_type: 'image/jpeg',
    disposition: 'inline',
    url: `/artifacts/recovered/${name}`,
  }
}

function candidate(offset: number, ext = 'jpg'): CarveCandidate {
  return {
    offset,
    length: 1024,
    ext,
    mime: 'image/jpeg',
    source: 'structure',
    validation: 'VALID',
    confidence_bp: 9300,
    bucket: 'HIGH',
    sha256: '',
    original_name: null,
    possibly_fragmented: false,
    fragments: [],
    validation_detail: '',
    entropy_millibits_per_byte: null,
    high_entropy_windows_bp: null,
    score_components: {},
    overlapped: false,
    overlaps_with: null,
    category: 'image',
    flags: {
      has_exif_gps: false,
      is_password_protected: false,
      is_encrypted: false,
      contains_macros: false,
      has_embedded_files: false,
      is_signed: false,
      inspected: true,
    },
    duplicate_offsets: [],
    fs_type: '',
    contiguity_assumed: false,
    contiguity_contradicted: false,
  }
}

function verification(
  overrides: Partial<EraseVerification> = {},
): EraseVerification {
  return {
    strategy: 'sampled',
    passed: true,
    bytes_checked: 4096,
    sample_count: 16,
    sample_seed: 7,
    confidence_bp: 9900,
    failed_offsets: [],
    probability_note: '',
    hw_attested: false,
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// Matching a candidate to the file the carve wrote
// ---------------------------------------------------------------------------

test('a candidate resolves to the object written at its offset', () => {
  const listing = [
    artifact('000000004096_09300_recovered.jpg'),
    artifact('000000008192_07100_other.png'),
  ]

  assert.equal(
    artifactFor(candidate(4096), listing)?.name,
    '000000004096_09300_recovered.jpg',
  )
})

test('the match survives a confidence that changed between scans', () => {
  // The confidence is in the filename, so matching the whole name would
  // silently stop finding a file that is right there.
  const listing = [artifact('000000004096_08800_recovered.jpg')]

  assert.equal(
    artifactFor(candidate(4096), listing)?.name,
    '000000004096_08800_recovered.jpg',
  )
})

test('an offset with no written object resolves to null, not a guess', () => {
  const listing = [artifact('000000008192_07100_other.png')]

  assert.equal(artifactFor(candidate(4096), listing), null)
})

test('a candidate in a nested output directory still resolves', () => {
  const listing = [artifact('run-2/000000004096_09300_recovered.jpg')]

  assert.equal(
    artifactFor(candidate(4096), listing)?.name,
    'run-2/000000004096_09300_recovered.jpg',
  )
})

test('an empty listing resolves to null', () => {
  assert.equal(artifactFor(candidate(4096), []), null)
})

// ---------------------------------------------------------------------------
// Artifact URLs
// ---------------------------------------------------------------------------

test('an artifact url encodes each path component separately', () => {
  assert.equal(
    artifactUrl('recovered', 'run 2/a b.jpg'),
    '/artifacts/recovered/run%202/a%20b.jpg',
  )
})

test('a traversing name throws rather than being sent', () => {
  // Every name this function is given came out of a server listing, so one
  // that walks upward is a bug here, not a request to forward. The server
  // refuses it too; that boundary is tested on the server.
  assert.throws(() => artifactUrl('recovered', '../../etc/passwd'), /leaves it/)
})

test('an absolute name throws rather than being sent', () => {
  assert.throws(() => artifactUrl('recovered', '/etc/passwd'), /leaves it/)
})

test('a dot in an ordinary name is not mistaken for a traversal', () => {
  assert.equal(
    artifactUrl('recovered', '000000004096_09300_a.b.jpg'),
    '/artifacts/recovered/000000004096_09300_a.b.jpg',
  )
})

test('download=true is the only query the helper emits', () => {
  assert.equal(
    artifactUrl('reports', 'case.forensic.pdf', { download: true }),
    '/artifacts/reports/case.forensic.pdf?download=true',
  )
})

// ---------------------------------------------------------------------------
// Verification verdicts: four outcomes, never three
// ---------------------------------------------------------------------------

test('a passing read-back is PASSED', () => {
  assert.equal(verificationWord(verification()), 'PASSED')
})

test('a failing read-back is FAILED', () => {
  assert.equal(
    verificationWord(verification({ passed: false, failed_offsets: [0] })),
    'FAILED',
  )
})

test('an unsettled read-back is INCONCLUSIVE and never PASSED', () => {
  // This is the one that matters. `passed: null` is not a quiet yes.
  assert.equal(
    verificationWord(verification({ passed: null })),
    'INCONCLUSIVE',
  )
})

test('a verification that read nothing is NOT APPLICABLE', () => {
  assert.equal(
    verificationWord(verification({ passed: null, bytes_checked: 0 })),
    'NOT APPLICABLE',
  )
})

test('a missing verification is NOT APPLICABLE', () => {
  assert.equal(verificationWord(null), 'NOT APPLICABLE')
})
