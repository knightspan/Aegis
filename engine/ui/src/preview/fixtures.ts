// Fixture data for the design preview. Never imported by src/main.tsx, and the
// production build has only index.html as an entry point, so none of this can
// reach a shipped bundle.
//
// The values are shaped like real ones on purpose. A screen laid out against
// "Device 1 / 100 GB / abc123" looks fine and then breaks on a 24-character
// serial, a 7.76 GB capacity that has to print its exact byte count, and a
// candidate list 500 rows long. These are the awkward cases, not the tidy ones.

import type {
  CarveCandidate,
  DeviceRow,
  PlatformStatus,
  SafetyCheck,
  FileEraseRecord,
  LedgerEntry,
  LedgerVerification,
  ReportVerification,
} from '../lib/api'

function digest(seed: number): string {
  // Deterministic filler that looks like SHA-256 and is not one. Nothing here
  // is verified; it exists so the hash columns have realistic width.
  let value = BigInt(seed) * 6364136223846793005n + 1442695040888963407n
  let out = ''
  while (out.length < 64) {
    value = (value * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n)
    out += value.toString(16).padStart(16, '0')
  }
  return out.slice(0, 64)
}

export const DEVICES: DeviceRow[] = [
  {
    device: {
      path: '/dev/nvme0n1',
      model: 'Samsung SSD 990 PRO 2TB',
      serial: 'S7DPNJ0X412906H',
      size_bytes: 2000398934016,
      rotational: false,
      transport: 'nvme',
      is_system_disk: true,
      mounted_at: ['/', '/boot', '/home'],
      pt_type: 'gpt',
      by_id_path: '/dev/disk/by-id/nvme-Samsung_SSD_990_PRO_2TB',
    },
    capabilities: {
      ata_security_erase: false,
      ata_enhanced_erase: false,
      ata_sanitize_ops: [],
      nvme_sanicap: { block_erase: true, crypto_erase: true },
      is_sed_opal: false,
      security_frozen: false,
      est_erase_seconds: 240,
      achievable_levels: ['CLEAR', 'PURGE'],
      limitations: [],
    },
    hidden_areas: {
      hpa_present: false,
      dco_present: false,
      native_max_sectors: 3907029168,
      accessible_sectors: 3907029168,
      hidden_bytes: 0,
    },
  },
  {
    device: {
      path: '/dev/sda',
      model: 'SanDisk Cruzer Blade',
      serial: '4C530001120809117433',
      size_bytes: 7759462400,
      rotational: false,
      transport: 'usb',
      is_system_disk: false,
      mounted_at: [],
      pt_type: 'dos',
      by_id_path: '/dev/disk/by-id/usb-SanDisk_Cruzer_Blade_4C530001120809117433-0:0',
    },
    capabilities: {
      ata_security_erase: false,
      ata_enhanced_erase: false,
      ata_sanitize_ops: [],
      nvme_sanicap: {},
      is_sed_opal: false,
      security_frozen: false,
      est_erase_seconds: 1911,
      achievable_levels: ['CLEAR'],
      limitations: [
        'The USB bridge does not pass ATA pass-through, so no firmware sanitize ' +
          'or ATA security command can be issued to the media behind it.',
      ],
    },
    // Shaped like helper/daemon.py enumerate_devices: rotational is true, as
    // it is on the real stick, and the engine still calls it flash.
    media: { flash: true, reason: 'the device is on the usb bus' },
    erase_preview: {
      flash: true,
      flash_reason: 'the device is on the usb bus',
      purge_mechanisms: [],
      purge_requires:
        'ATA SANITIZE block erase or crypto scramble. Enhanced SECURITY ERASE ' +
        'and SANITIZE overwrite do not count on flash. On the usb bus these ATA ' +
        'commands usually do not pass the bridge at all; connect the drive ' +
        'directly to a SATA port and re-probe.',
      plans: [
        {
          level: 'CLEAR',
          reachable: true,
          method: 'SINGLE_PASS_OVERWRITE',
          justification:
            'SINGLE_PASS_OVERWRITE was selected because no firmware sanitize ' +
            'mechanism was observed on this device; host overwrite reaches CLEAR.',
          evidence: [
            'Clear is always delivered by one host overwrite pass over every ' +
              'addressable LBA. NIST SP 800-88r2 states that multi-pass ' +
              'overwrite is not needed for clear.',
            'The device was determined to be flash because the device is on ' +
              'the usb bus. A host overwrite cannot reach blocks the flash ' +
              'translation layer has remapped, over-provisioned capacity, or ' +
              'the write cache.',
          ],
          executable: true,
          not_executable_reason: '',
          limitations: [
            'The USB bridge does not pass ATA pass-through, so no firmware ' +
              'sanitize or ATA security command can be issued to the media ' +
              'behind it.',
          ],
          refusal: '',
          remediation: '',
        },
        {
          level: 'PURGE',
          reachable: false,
          method: null,
          justification: '',
          evidence: [],
          executable: true,
          not_executable_reason: '',
          limitations: [],
          refusal: 'PURGE is not achievable on this device.',
          remediation:
            'Choose one of: CLEAR. To reach PURGE on this media, physical ' +
            'destruction is the remaining option.',
        },
      ],
    },
    hidden_areas: {
      hpa_present: false,
      dco_present: false,
      native_max_sectors: 15155200,
      accessible_sectors: 15155200,
      hidden_bytes: 0,
    },
  },
  {
    device: {
      path: '/dev/sdb',
      model: 'ST2000DM008-2FR102',
      serial: 'ZFL2X9Q7',
      size_bytes: 2000398934016,
      rotational: true,
      transport: 'sata',
      is_system_disk: false,
      mounted_at: [],
      pt_type: 'gpt',
      by_id_path: '/dev/disk/by-id/ata-ST2000DM008-2FR102_ZFL2X9Q7',
    },
    capabilities: {
      ata_security_erase: true,
      ata_enhanced_erase: true,
      ata_sanitize_ops: ['BLOCK_ERASE_EXT', 'OVERWRITE_EXT'],
      nvme_sanicap: {},
      is_sed_opal: false,
      security_frozen: false,
      est_erase_seconds: 14400,
      achievable_levels: ['CLEAR', 'PURGE'],
      limitations: [],
    },
    hidden_areas: {
      hpa_present: true,
      dco_present: false,
      native_max_sectors: 3907029168,
      accessible_sectors: 3904978800,
      hidden_bytes: 1049788416,
    },
  },
  {
    device: {
      path: '/dev/sdc',
      model: 'KINGSTON SA400S37480G',
      serial: '50026B7683F1A0C2',
      size_bytes: 480103981056,
      rotational: false,
      transport: 'sata',
      is_system_disk: false,
      mounted_at: ['/mnt/case-2149'],
      pt_type: 'gpt',
      by_id_path: '/dev/disk/by-id/ata-KINGSTON_SA400S37480G_50026B7683F1A0C2',
    },
    capabilities: {
      ata_security_erase: true,
      ata_enhanced_erase: false,
      ata_sanitize_ops: [],
      nvme_sanicap: {},
      is_sed_opal: true,
      security_frozen: false,
      est_erase_seconds: 900,
      achievable_levels: ['CLEAR'],
      limitations: [
        'sedutil-cli reports a Pyrite SSC. Pyrite implements the Opal command ' +
          'set without media encryption, so there is no key to destroy.',
      ],
    },
    hidden_areas: {
      hpa_present: false,
      dco_present: false,
      native_max_sectors: 937703088,
      accessible_sectors: 937703088,
      hidden_bytes: 0,
    },
  },
]

/** The stick from the hardware run. The Sanitize preview targets this one. */
export const SANITIZE_TARGET = DEVICES[1]

const OPERATIONS = [
  'erase.report.sign',
  'erase.verify.complete',
  'erase.erase.complete',
  'erase.erase.start',
  'erase.hidden_area_unlock.skip',
  'erase.preflight.complete',
  'erase.preflight.start',
  'acquire.complete',
  'acquire.start',
  'GENESIS',
]

const LEDGER_ENTRIES: LedgerEntry[] = OPERATIONS.map((operation, index) => {
  const seq = OPERATIONS.length - 1 - index
  return {
    seq,
    ts_utc: `2026-09-05T${String(18 + Math.floor(seq / 4)).padStart(2, '0')}:${String((seq * 7) % 60).padStart(2, '0')}:${String((seq * 13) % 60).padStart(2, '0')}+00:00`,
    actor: operation === 'GENESIS' ? 'sanctum' : 'operator@ntro',
    operation,
    params_hash: digest(seq * 3 + 1),
    result_hash: digest(seq * 3 + 2),
    prev_entry_hash: seq === 0 ? '0'.repeat(64) : digest(seq - 1),
    entry_hash: digest(seq),
  }
})

export const LEDGER: LedgerVerification = {
  status: 'VALID',
  entry_count: LEDGER_ENTRIES.length,
  explanation:
    'All 10 entries link end to end: each entry hashes to the value it records, ' +
    'and each carries the SHA-256 of the entry before it.',
  first_broken_seq: null,
  root: '/var/lib/sanctum/ledger',
  entries: LEDGER_ENTRIES,
}

/**
 * One of each outcome.
 *
 * A preview that shows five passes proves only that green renders. The point
 * of the screen is that FAIL, PASS and NOT CHECKED are three different things
 * and that a reader can tell which is which from across the room.
 */
export const REPORT_VERIFICATION: ReportVerification = {
  report: '/var/lib/sanctum/reports/erase-drive-3f9c2a.forensic.json',
  report_name: 'erase-drive-3f9c2a.forensic.json',
  json_url: '/artifacts/reports/erase-drive-3f9c2a.forensic.json',
  pdf_url: '/artifacts/reports/erase-drive-3f9c2a.forensic.pdf',
  passed: false,
  verdict: 'FAILED_VERIFICATION',
  verdict_reasons: [
    'signature failed: signature does not match the report contents; the ' +
      'report was altered after signing, or signed by a different key',
  ],
  fingerprint: 'SHA256:9f2c1a7e4b0d8365c1ae92f0d47b6a83',
  ledger_digest: '4a7d1ed414474e4033ac29ccb8653d9b1ee2b0bd0d4a3a3a1c1f7f5a2b3c4d5e',
  // False, matching `passed: false` above: this fixture is the tampered case,
  // and a report whose bytes changed after generation no longer hashes to what
  // the chain recorded. The two facts have to agree in a preview or the screen
  // is teaching a reader something untrue.
  ledger_digest_matches: false,
  caveat:
    'An embedded public key proves internal consistency only. It does not prove ' +
    'identity: compare the fingerprint above against a value published ' +
    'out-of-band before treating this signature as evidence of who produced ' +
    'the report.',
  checks: [
    {
      name: 'signature',
      passed: true,
      applicable: true,
      detail: 'valid ed25519 signature by SHA256:9f2c1a7e4b0d8365c1ae92f0d47b6a83',
    },
    {
      name: 'fingerprint_matches_genesis',
      passed: false,
      applicable: true,
      detail:
        'report was signed by SHA256:9f2c1a7e4b0d8365c1ae92f0d47b6a83, but the ' +
        'ledger genesis records SHA256:41d0be55c2f7a9138e6b0c74aa215de9',
    },
    {
      name: 'chain_integrity',
      passed: true,
      applicable: true,
      detail: 'the excerpt links end to end across all 10 entries it carries',
    },
    {
      name: 'chain_store',
      passed: true,
      applicable: false,
      detail:
        'no chain file at /var/lib/sanctum/ledger/chain.jsonl, so the full chain ' +
        'was not re-verified',
    },
    {
      name: 'blobs_available',
      passed: true,
      applicable: true,
      detail: 'every blob referenced by 10 entries is present',
    },
  ],
}

const EXTENSIONS = [
  ['jpg', 'image/jpeg'],
  ['png', 'image/png'],
  ['pdf', 'application/pdf'],
  ['docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
  ['zip', 'application/zip'],
  ['sqlite', 'application/vnd.sqlite3'],
  ['mp4', 'video/mp4'],
  ['eml', 'message/rfc822'],
]

const SOURCES = ['signature', 'undelete', 'fs_journal', 'structure']

/**
 * Five hundred candidates.
 *
 * The number is the point. A table that reads well at eight rows and turns
 * into a wall at five hundred has not been tested at the size the tool
 * actually produces on a 7.4 GiB image.
 */
export const CANDIDATES: CarveCandidate[] = Array.from({ length: 500 }, (_, index) => {
  const [ext, mime] = EXTENSIONS[index % EXTENSIONS.length]
  const source = SOURCES[index % SOURCES.length]
  const header = 2500
  const exactLength = index % 3 === 0 ? 2000 : 0
  const decoder = index % 4 === 0 ? 0 : 2000
  const entropy = index % 5 === 0 ? 0 : 1200
  const fsMetadata = source === 'undelete' ? 1800 : 0
  const noOverlap = index % 11 === 0 ? 0 : 800
  const measured = header + exactLength + decoder + entropy + fsMetadata + noOverlap
  // Every ninth candidate is reassembled (see fragments below). Like the real
  // scorer, a reassembly component holds its total one basis point under HIGH.
  const reassembly = index % 9 === 0 ? Math.min(0, 7999 - measured) : 0
  const bp = Math.min(measured + reassembly, 10000)
  const bucket = bp >= 8000 ? 'HIGH' : bp >= 5000 ? 'MEDIUM' : 'LOW'
  const offset = 1048576 + index * 262144 + (index % 7) * 512
  const length = 8192 + ((index * 7919) % 4194304)
  return {
    offset,
    length,
    ext,
    mime,
    source,
    validation: decoder > 0 ? 'DECODED' : 'HEADER_ONLY',
    confidence_bp: bp,
    bucket,
    sha256: digest(index + 1000),
    original_name: source === 'undelete' ? `IMG_${4000 + index}.${ext}` : null,
    possibly_fragmented: index % 9 === 0,
    // Every ninth candidate is reassembled across one gap, so the preview
    // exercises the fragment rows and the notice that goes with them.
    fragments:
      index % 9 === 0
        ? [
            { offset, length: 4096 },
            { offset: offset + 4096 + 32768, length: length - 4096 },
          ]
        : [],
    validation_detail:
      decoder > 0
        ? `Pillow opened the object: ${ext.toUpperCase()} ${1920 + (index % 8) * 160}x${1080 + (index % 8) * 90}, mode RGB. Full decode to the last scanline succeeded.`
        : 'No decoder accepted the object; only the header magic matched.',
    entropy_millibits_per_byte: 7100 + (index % 900),
    high_entropy_windows_bp: 6000 + (index % 3500),
    score_components: {
      header,
      exact_length: exactLength,
      decoder,
      entropy,
      fs_metadata: fsMetadata,
      no_overlap: noOverlap,
      reassembly,
    },
    overlapped: noOverlap === 0,
    overlaps_with: noOverlap === 0 ? 1048576 + (index - 1) * 262144 : null,
    category: 'document',
    flags: {
      has_exif_gps: index % 13 === 0,
      is_password_protected: index % 17 === 0,
      is_encrypted: index % 23 === 0,
      contains_macros: index % 29 === 0,
      has_embedded_files: index % 6 === 0,
      is_signed: index % 31 === 0,
      inspected: true,
    },
    duplicate_offsets: [],
    fs_type: source === 'undelete' ? 'vfat' : '',
    contiguity_assumed: source === 'undelete',
    contiguity_contradicted: source === 'undelete' && index % 19 === 0,
  }
})

export const FILE_RECORDS: FileEraseRecord[] = [
  {
    path: '/home/analyst/case-2149/interview-notes.docx',
    ok: true,
    bytes_overwritten: 41984,
    streams_removed: [],
    xattrs_removed: ['user.xdg.origin.url'],
    rename_chain: ['a0b1c2d3e4f5', 'f5e4d3c2b1a0'],
    unlinked: true,
    is_directory: false,
    findings: [
      {
        kind: 'FS_JOURNAL',
        severity: 'MEDIUM',
        explanation:
          'The filesystem is ext4 and journals metadata, and sometimes data. ' +
          'Content that passed through the journal can outlive an overwrite of ' +
          "the file's own blocks.",
        addressable: false,
        detail: {},
      },
      {
        kind: 'FILE_SLACK',
        severity: 'LOW',
        explanation:
          'The file does not fill its last cluster. The remainder of that ' +
          'cluster is not addressable through the file and was not overwritten.',
        addressable: false,
        detail: {},
      },
    ],
    limitations: [],
    error: null,
    error_kind: null,
    verification: {
      passed: null,
      strategy: 'none',
      reason: 'the filesystem does not expose physical extents to an unprivileged read',
    },
  },
  {
    path: '/home/analyst/case-2149/exhibits/DSC_0491.NEF',
    ok: true,
    bytes_overwritten: 25165824,
    streams_removed: [],
    xattrs_removed: [],
    rename_chain: ['a0b1c2d3e4f5', 'f5e4d3c2b1a0'],
    unlinked: true,
    is_directory: false,
    findings: [
      {
        kind: 'COW_SNAPSHOT',
        severity: 'HIGH',
        explanation:
          'Two btrfs snapshots still reference the extents this file occupied. ' +
          'The overwrite was redirected to newly allocated blocks and the ' +
          'original content is intact and reachable through the snapshots.',
        addressable: true,
        detail: {},
      },
      {
        kind: 'TRIM_REMAP',
        severity: 'MEDIUM',
        explanation:
          'The volume sits on flash with discard enabled. Blocks the FTL has ' +
          'remapped are not reachable by any write through the filesystem.',
        addressable: false,
        detail: {},
      },
    ],
    limitations: [
      'Snapshot enumeration required root and ran unprivileged, so the count ' +
        'above is a lower bound.',
    ],
    error: null,
    error_kind: null,
    verification: {
      passed: null,
      strategy: 'none',
      reason: 'the filesystem does not expose physical extents to an unprivileged read',
    },
  },
  {
    path: '/home/analyst/case-2149/index.sqlite',
    ok: true,
    bytes_overwritten: 1048576,
    streams_removed: [],
    xattrs_removed: [],
    rename_chain: ['a0b1c2d3e4f5', 'f5e4d3c2b1a0'],
    unlinked: true,
    is_directory: false,
    findings: [],
    limitations: [],
    error: null,
    error_kind: null,
    verification: {
      passed: null,
      strategy: 'none',
      reason: 'the filesystem does not expose physical extents to an unprivileged read',
    },
  },
  {
    path: '/home/analyst/case-2149/transcript.txt',
    ok: true,
    bytes_overwritten: 892,
    streams_removed: [],
    xattrs_removed: [],
    rename_chain: ['a0b1c2d3e4f5', 'f5e4d3c2b1a0'],
    unlinked: true,
    is_directory: false,
    findings: [
      {
        kind: 'HARDLINK_SURVIVES',
        severity: 'HIGH',
        explanation:
          'The inode has 3 links. Overwriting through this name destroys the ' +
          'content behind all of them; leaving it intact means the content ' +
          'survives under two names that were not given.',
        addressable: true,
        detail: {},
      },
    ],
    limitations: [],
    error: null,
    error_kind: null,
    verification: {
      passed: null,
      strategy: 'none',
      reason: 'the filesystem does not expose physical extents to an unprivileged read',
    },
  },
  {
    path: '/var/log/journal/sanctum',
    ok: false,
    bytes_overwritten: 0,
    streams_removed: [],
    xattrs_removed: [],
    rename_chain: [],
    unlinked: false,
    is_directory: true,
    findings: [],
    limitations: [],
    error: 'refused: path is under a protected prefix',
    error_kind: 'PathRefused',
    verification: null,
  },
]

// ---------------------------------------------------------------------------
// Platform model (core/platform). Shaped like the helper's answers.
// ---------------------------------------------------------------------------

const STICK_CHECKS: SafetyCheck[] = [
  { key: 'detected', label: 'Device detected', passed: true, detail: '/dev/sda was read from the OS by linux discovery.' },
  { key: 'identity', label: 'Identity readable', passed: true, detail: 'Serial 4C530001120809117433.' },
  { key: 'capacity', label: 'Capacity known', passed: true, detail: '7759462400 bytes.' },
  { key: 'not_system', label: 'Not the system or boot disk', passed: true, detail: 'Holds no running system, boot, swap or page file.' },
  { key: 'not_mounted', label: 'No mounted filesystem', passed: true, detail: 'Nothing on this device is mounted.' },
  { key: 'media_type', label: 'Media type identified', passed: true, detail: 'Decided because the device is on the usb bus.' },
  { key: 'privilege', label: 'Privilege available', passed: true, detail: 'Privileged work runs in the separate helper process over its authenticated socket; this interface stays unprivileged.' },
]

const FLASH_LIMITATION =
  'SSD / flash limitation: an overwrite cannot address blocks the flash ' +
  'controller has remapped or held in over-provisioned space. Only a firmware ' +
  'sanitize or cryptographic erase reaches them, so an overwrite of flash is ' +
  'reported as Clear, never as Purge.'

SANITIZE_TARGET.normalized = {
  id: '/dev/sda',
  platform: 'linux',
  path: '/dev/sda',
  vendor: '',
  model: 'SanDisk Cruzer Blade',
  serial: '4C530001120809117433',
  capacity_bytes: 7759462400,
  interface: 'usb',
  media_type: 'flash',
  media_basis: 'Decided because the device is on the usb bus.',
  removable: true,
  mounted: false,
  mount_points: [],
  system_device: false,
  system_reasons: [],
  filesystems: ['vfat'],
  partitions: [],
  stable_id: '/dev/disk/by-id/usb-SanDisk_Cruzer_Blade_4C530001120809117433-0:0',
  limitations: [],
}

SANITIZE_TARGET.assessment = {
  device_id: '/dev/sda',
  platform: 'linux',
  status: 'SUPPORTED_WITH_LIMITATIONS',
  headline: 'READY',
  reason:
    'Every addressable block is overwritten from this computer. On flash this ' +
    'cannot reach remapped or spare blocks, so the result is recorded as Clear.',
  recommended_action: '',
  recommended: {
    level: 'CLEAR',
    title: 'Overwrite (Clear)',
    status: 'SUPPORTED_WITH_LIMITATIONS',
    method: 'SINGLE_PASS_OVERWRITE',
    why:
      'Every addressable block is overwritten from this computer. On flash this ' +
      'cannot reach remapped or spare blocks, so the result is recorded as Clear.',
    technical: ['Method: SINGLE_PASS_OVERWRITE'],
    verification: 'Every byte is read back after the overwrite and checked.',
    remediation: '',
  },
  alternatives: [],
  unavailable: [
    {
      level: 'PURGE',
      title: 'Hardware purge',
      status: 'UNSUPPORTED',
      method: null,
      why:
        'No purge pathway: the USB bridge does not pass ATA SANITIZE or ' +
        'SECURITY ERASE to the media behind it.',
      technical: [],
      verification: '',
      remediation:
        'Connect the drive directly to a SATA port and re-probe.',
    },
  ],
  verification: 'Every byte is read back after the overwrite and checked.',
  safety_checks: STICK_CHECKS,
  flash_limitation: FLASH_LIMITATION,
}

/** A Windows host: device discovered, whole-drive honestly unavailable. */
export const WINDOWS_ROW: DeviceRow = {
  device: {
    path: '\\\\.\\PhysicalDrive2',
    model: 'DataTraveler 3.0',
    serial: 'E0D55EA574E2F4B1',
    size_bytes: 30943995904,
    rotational: false,
    transport: 'usb',
    is_system_disk: false,
    mounted_at: [],
    pt_type: null,
    by_id_path: null,
  },
  capabilities: null,
  erase_preview: null,
  hidden_areas: null,
  capability_error:
    'Legacy payload from a build before the capability resolver (no state field); the preview exercises the status fallback.',
  normalized: {
    ...SANITIZE_TARGET.normalized,
    id: 'PhysicalDrive2',
    platform: 'windows',
    path: '\\\\.\\PhysicalDrive2',
    vendor: 'Kingston',
    model: 'DataTraveler 3.0',
    serial: 'E0D55EA574E2F4B1',
    capacity_bytes: 30943995904,
    stable_id: 'USBSTOR\\DISK&VEN_KINGSTON',
  },
  assessment: {
    ...SANITIZE_TARGET.assessment,
    device_id: 'PhysicalDrive2',
    platform: 'windows',
    status: 'UNSUPPORTED',
    headline: 'NOT AVAILABLE',
    reason:
      'Legacy payload from a build before the capability resolver (no state field); the preview exercises the status fallback. ' +
      'Windows can reach a disk through \\\\.\\PhysicalDriveN and ' +
      'IOCTL_STORAGE_PROTOCOL_COMMAND, but no engine using them has been ' +
      'written and validated, so none is offered.',
    recommended_action:
      'Sanitize this device with the Sanctum Linux build (AppImage) on any ' +
      'Linux host or live USB, where the validated whole-drive engine runs, ' +
      "or use the drive vendor's own sanitize tool.",
    recommended: null,
    unavailable: [
      { ...SANITIZE_TARGET.assessment.unavailable[0], why: 'Not implemented for Windows in this build.', remediation: '' },
      { ...SANITIZE_TARGET.assessment.recommended!, status: 'UNSUPPORTED', why: 'Not implemented for Windows in this build.', verification: '' },
    ],
    verification: 'No verification: no whole-drive operation is offered here.',
    safety_checks: STICK_CHECKS.map((check) =>
      check.key === 'detected'
        ? { ...check, detail: 'PhysicalDrive2 was read from the OS by windows discovery.' }
        : check.key === 'identity'
          ? { ...check, detail: 'Serial E0D55EA574E2F4B1.' }
          : check.key === 'capacity'
            ? { ...check, detail: '30943995904 bytes.' }
            : check.key === 'privilege'
              ? { ...check, passed: false, detail: 'This process is not elevated (shell32.IsUserAnAdmin()).' }
              : check,
    ),
  },
}

export const PLATFORM: PlatformStatus = {
  platform: {
    family: 'windows',
    os_name: 'Windows 11',
    os_version: '10',
    os_build: '10.0.26100',
    machine: 'AMD64',
    app_version: '0.0.0',
    packaged: true,
    build: {
      version: '0.0.0',
      commit: '705429b0f1a2',
      platform: 'win32',
      architecture: 'AMD64',
      build_date: '2026-09-21T18:41:02Z',
      python: '3.11.9',
      node: 'v22.23.1',
      builder: 'GitHub Actions run 35645670025',
      signed: 'no',
    },
    sys_platform: 'win32',
  },
  privilege: {
    level: 'standard',
    elevated: false,
    basis: 'shell32.IsUserAnAdmin()',
    helper: 'none',
    helper_basis: '',
  },
  adapter: 'windows',
  limitations: [],
  restrictions: [
    'Whole-drive sanitization is not available on Windows in this build; use the Linux build for whole-drive work.',
    'Free-space wipe is Linux-only (fill behaviour not measured on NTFS).',
  ],
  operations: [
    { operation: 'device_discovery', label: 'Device discovery', status: 'SUPPORTED', reason: '3 storage device(s) found.', source: 'PowerShell Get-Disk / Get-PhysicalDisk / Get-Partition / Get-Volume', verification: '', limitations: [], requires_privilege: false },
    { operation: 'file_erase', label: 'File erase', status: 'UNVERIFIED', reason: 'Overwrites the file in place, renames, truncates, deletes. The file-erase test suite has not been recorded as passing on this platform for this build, so this is UNVERIFIED rather than supported.', source: "core.erase.files with the 'windows' file backend; validation record: file_erase suite on windows NOT RUN", verification: '', limitations: [], requires_privilege: false },
    { operation: 'whole_drive_clear', label: 'Whole-drive Clear', status: 'UNSUPPORTED', reason: 'Legacy payload from a build before the capability resolver (no state field); the preview exercises the status fallback.', source: 'core.platform.windows.WindowsAdapter', verification: '', limitations: [], requires_privilege: false },
  ],
  media_classes: [
    { media_class: 'Internal SSD', discovery: 'SUPPORTED', file_erase: 'UNVERIFIED', whole_drive: 'UNSUPPORTED', reason: 'Legacy payload from a build before the capability resolver (no state field); the preview exercises the status fallback.', detected_now: 1 },
    { media_class: 'USB SSD / flash drive', discovery: 'SUPPORTED', file_erase: 'UNVERIFIED', whole_drive: 'UNSUPPORTED', reason: '', detected_now: 2 },
  ],
  filesystems: [
    {
      filesystem: 'NTFS',
      cells: {
        detect: { linux: 'SUPPORTED', windows: 'SUPPORTED', macos: 'UNSUPPORTED' },
        read: { linux: 'SUPPORTED', windows: 'UNVERIFIED', macos: 'UNVERIFIED' },
        erase_files: { linux: 'SUPPORTED_WITH_LIMITATIONS', windows: 'UNVERIFIED', macos: 'UNSUPPORTED' },
        metadata: { linux: 'SUPPORTED_WITH_LIMITATIONS', windows: 'UNVERIFIED', macos: 'UNSUPPORTED' },
        free_space: { linux: 'UNSUPPORTED', windows: 'UNSUPPORTED', macos: 'UNSUPPORTED' },
        whole_drive: { linux: 'SUPPORTED_WITH_LIMITATIONS', windows: 'UNSUPPORTED', macos: 'UNSUPPORTED' },
      },
      notes: {},
    },
  ],
}
