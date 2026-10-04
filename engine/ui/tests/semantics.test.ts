/**
 * A drive report's category and assurance are read from the signed JSON, and
 * a report without them says "not recorded" rather than a guessed category.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { isReportUrl, REPORT_CATEGORIES, reportSemantics } from '../src/lib/semantics.ts'

const drive = {
  method: {
    method: 'SINGLE_PASS_OVERWRITE',
    semantics: {
      category: 'ADDRESSABLE WHOLE-DRIVE CLEAR',
      method: 'host overwrite, one pass',
      protocol: 'block',
      transport: 'usb',
      scope: 'LBA 0 to the last LBA the operating system exposed.',
      verification: 'every addressable byte read back and compared',
      assurance: 'NIST SP 800-88 Rev. 2 Clear of the addressable storage. Not a Purge.',
      limitations: ['Flash remapped blocks are not addressable.'],
    },
  },
}

test('the category and assurance come from method.semantics', () => {
  const words = reportSemantics(drive)
  assert.ok(words)
  assert.equal(words.category, 'ADDRESSABLE WHOLE-DRIVE CLEAR')
  assert.match(words.assurance, /Not a Purge/)
  assert.deepEqual(words.limitations, ['Flash remapped blocks are not addressable.'])
  assert.ok((REPORT_CATEGORIES as readonly string[]).includes(words.category))
})

test('a report without semantics is not given a category', () => {
  assert.equal(reportSemantics({ method: { method: 'SINGLE_PASS_OVERWRITE' } }), null)
  assert.equal(reportSemantics({ recovery: {} }), null)
  assert.equal(reportSemantics(null), null)
  assert.equal(reportSemantics({ method: { semantics: { category: '' } } }), null)
})

test('only report artifact URLs are fetched', () => {
  assert.equal(isReportUrl('/artifacts/reports/x.forensic.json'), true)
  assert.equal(isReportUrl('/artifacts/recovered/x.json'), false)
  assert.equal(isReportUrl('/artifacts/reports/../x.json'), false)
  assert.equal(isReportUrl('https://example.org/x.json'), false)
})
