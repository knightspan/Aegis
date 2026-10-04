"""Canonical data models for Sanctum Forensics.

Pydantic v2 models shared across every core layer, the helper, and the API.
These are pure data containers: no behaviour, no I/O, no business logic.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

__all__ = [
    "SanitizationLevel",
    "EraseMethod",
    "ErasePhase",
    "UnwritableRange",
    "EraseCheckpoint",
    "ErasePlan",
    "PlannedErase",
    "ErasePreview",
    "EraseResult",
    "Device",
    "DeviceCapabilities",
    "HiddenAreaReport",
    "ResidualRiskAssessment",
    "EraseJob",
    "VerificationResult",
    "Validation",
    "CarveCategory",
    "CarveFlags",
    "PiiFindings",
    "MacTimestamps",
    "CarveFragment",
    "CarveCandidate",
    "MediaRegion",
    "MediaMap",
    "DestroyTechnique",
    "DestructionRecord",
    "SubstitutedRange",
    "BadSectorRange",
    "EvidenceSource",
    "AcquisitionRecord",
    "IntegrityResult",
    "LedgerEntry",
    "ForensicReport",
    "Progress",
    # M2: file and folder erasure
    "Extent",
    "FileInspection",
    "ResidualKind",
    "DRIVE_PATH_KINDS",
    "FILE_PATH_KINDS",
    "Severity",
    "ResidualFinding",
    "MetadataField",
    "MetadataCleanseResult",
    "FileErasePhase",
    "FileEraseOptions",
    "FileEraseRecord",
    "FileEraseResult",
    "TraceInspection",
    "TraceRecord",
    "TraceSweepResult",
    "FileVerificationResult",
    "VolumeInfo",
    "FreeSpaceWipeOptions",
    "FreeSpaceWipeResult",
]


class SanitizationLevel(StrEnum):
    """The sanitization methods of NIST SP 800-88r2 Sec. 3.1: clear, purge, destroy."""

    CLEAR = "CLEAR"
    PURGE = "PURGE"
    DESTROY = "DESTROY"


class EraseMethod(StrEnum):
    """Concrete mechanism used to satisfy a :class:`SanitizationLevel`."""

    SINGLE_PASS_OVERWRITE = "SINGLE_PASS_OVERWRITE"
    DOD_5220_22_M_3PASS = "DOD_5220_22_M_3PASS"
    ATA_SECURITY_ERASE_ENHANCED = "ATA_SECURITY_ERASE_ENHANCED"
    ATA_SANITIZE_BLOCK_ERASE = "ATA_SANITIZE_BLOCK_ERASE"
    ATA_SANITIZE_OVERWRITE = "ATA_SANITIZE_OVERWRITE"
    NVME_SANITIZE_BLOCK = "NVME_SANITIZE_BLOCK"
    NVME_FORMAT_SES1 = "NVME_FORMAT_SES1"
    # Two distinct crypto-erase mechanisms on two different subsystems. They are
    # kept separate so the erase dispatcher never has to re-derive which one a
    # job means from the capability set.
    ATA_SANITIZE_CRYPTO_SCRAMBLE = "ATA_SANITIZE_CRYPTO_SCRAMBLE"
    SED_CRYPTO_ERASE = "SED_CRYPTO_ERASE"
    #: NVMe Sanitize, crypto-erase action. Issued on Windows through
    #: IOCTL_STORAGE_REINITIALIZE_MEDIA; the Linux engine does not offer it.
    NVME_SANITIZE_CRYPTO = "NVME_SANITIZE_CRYPTO"


class ErasePhase(StrEnum):
    """The phases an erase job moves through, in execution order."""

    PREFLIGHT = "PREFLIGHT"
    HIDDEN_AREA_UNLOCK = "HIDDEN_AREA_UNLOCK"
    ERASE = "ERASE"
    HIDDEN_AREA_RESTORE = "HIDDEN_AREA_RESTORE"
    VERIFY = "VERIFY"
    REPORT = "REPORT"


Transport = Literal["sata", "nvme", "usb", "mmc", "unknown"]


class Device(BaseModel):
    """A block device as enumerated from the host."""

    path: str
    model: str
    serial: str
    size_bytes: int
    rotational: bool
    transport: Transport
    is_system_disk: bool
    mounted_at: list[str]
    pt_type: str | None
    #: Stable ``/dev/disk/by-id`` path. ``path`` is not stable across replug, so
    #: anything that must survive a reconnect refers to the device by this.
    by_id_path: str | None = None


class DeviceCapabilities(BaseModel):
    """Probed sanitization capability of a specific device."""

    ata_security_erase: bool
    ata_enhanced_erase: bool
    ata_sanitize_ops: list[str]
    nvme_sanicap: dict[str, Any]
    is_sed_opal: bool
    security_frozen: bool
    #: Whole seconds the drive estimates a firmware erase will take. hdparm
    #: reports this in minutes; it is converted at the parse site so the field
    #: name states its own unit and nothing float reaches a ledger entry.
    est_erase_seconds: int
    achievable_levels: set[SanitizationLevel]
    #: Plain-language reasons a stronger level could not be established, e.g. a
    #: USB bridge that blocks ATA pass-through. Surfaced verbatim in the report.
    limitations: list[str] = []


class HiddenAreaReport(BaseModel):
    """Result of HPA/DCO probing for a device.

    ``probe_failed`` separates "there is no hidden area" from "we could not find
    out", which are different claims with different consequences. When it is
    set, the sector counts fall back to the kernel-reported size and carry no
    information about hidden sectors: nothing downstream may treat them as a
    measurement, and in particular nothing may shrink an erase to fit them.
    """

    hpa_present: bool
    dco_present: bool
    native_max_sectors: int
    accessible_sectors: int
    hidden_bytes: int
    #: True when the probe did not produce a trustworthy reading, for any
    #: reason: the tool failed, the transport cannot carry the command, or the
    #: values it returned did not survive the sanity checks.
    probe_failed: bool = False
    #: Why the probe could not be trusted, in the operator's words. Flows into
    #: the erase limitations and the report, so an unprobed drive says so.
    limitations: list[str] = Field(default_factory=list)


class ResidualKind(StrEnum):
    """What kind of thing survived. One member per detection this tool makes.

    Shared by both erase paths. The file path (:mod:`core.erase.residual`)
    reports what a filesystem left behind; the drive path reports what a
    controller left behind. A string in a list of factors cannot carry a
    measurement, and the drive-path findings are measurements.
    """

    RESIDENT_MFT_DATA = "RESIDENT_MFT_DATA"
    ALT_DATA_STREAM = "ALT_DATA_STREAM"
    FS_JOURNAL = "FS_JOURNAL"
    USN_JOURNAL = "USN_JOURNAL"
    MFT_SLACK = "MFT_SLACK"
    INDEX_SLACK = "INDEX_SLACK"
    COW_SNAPSHOT = "COW_SNAPSHOT"
    VSS_SHADOW_COPY = "VSS_SHADOW_COPY"
    FILE_SLACK = "FILE_SLACK"
    TRIM_REMAP = "TRIM_REMAP"
    COMPRESSED_REALLOC = "COMPRESSED_REALLOC"
    ENCRYPTED_EFS = "ENCRYPTED_EFS"
    HARDLINK_SURVIVES = "HARDLINK_SURVIVES"
    SPARSE_UNWRITTEN = "SPARSE_UNWRITTEN"
    BACKUP_COPY_LIKELY = "BACKUP_COPY_LIKELY"
    #: Drive path. The controller acknowledged a zero fill far faster than it
    #: can program the medium, so the cells were never written.
    CONTROLLER_WRITE_ELISION = "CONTROLLER_WRITE_ELISION"


#: Kinds the drive path produces. Everything else belongs to the file path.
#: Split explicitly so a kind cannot be added to one path and silently expected
#: of the other: the coverage tests read this rather than assuming the enum is
#: wholly owned by :mod:`core.erase.residual`.
DRIVE_PATH_KINDS: frozenset[ResidualKind] = frozenset(
    {ResidualKind.CONTROLLER_WRITE_ELISION}
)

#: Kinds the file path produces. Together with DRIVE_PATH_KINDS this partitions
#: ResidualKind; a test asserts the partition is total and disjoint.
FILE_PATH_KINDS: frozenset[ResidualKind] = frozenset(ResidualKind) - DRIVE_PATH_KINDS


class Severity(StrEnum):
    """Derived from what survives, never guessed.

    HIGH: the full content plausibly survives.
    MEDIUM: fragments or metadata survive.
    LOW: only filenames survive.
    """

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ResidualFinding(BaseModel):
    """One thing this erase could not guarantee, in words an operator can act on."""

    kind: ResidualKind
    severity: Severity
    explanation: str
    #: True when the operator can do something about it (delete the snapshots,
    #: erase the other hardlink). False when only the filesystem or firmware can.
    addressable: bool
    detail: dict[str, Any] = {}


class ResidualRiskAssessment(BaseModel):
    """Honest statement of what could not be guaranteed after an erase.

    ``factors`` are sentences for a reader. ``findings`` are the same claims in
    a form a machine can check, carrying the measurement that produced them.
    Both are populated: the strings stay for every consumer that already reads
    them, and a finding is added wherever there is evidence behind the sentence.
    """

    level: Literal["low", "medium", "high"]
    factors: list[str]
    purge_achieved: bool
    notes: str
    findings: list[ResidualFinding] = []


class EraseJob(BaseModel):
    """A single sanitization request against one device. Always executed.

    Undeclared keys are refused, not ignored: a caller passing the removed
    ``dry_run`` switch expects nothing to be written, and must not get a real
    erase on the strength of a key that was silently dropped.
    """

    model_config = ConfigDict(extra="forbid")

    job_id: str
    device: Device
    level: SanitizationLevel
    confirmed_serial: str | None
    #: An explicitly requested method, or ``None`` to select from probed
    #: capability. Only the software methods may be requested; the erase layer
    #: refuses an explicit request for a firmware method, because those are
    #: chosen from what the drive reports or not at all.
    method: EraseMethod | None = None


class VerificationResult(BaseModel):
    """Outcome of post-erase verification."""

    passed: bool
    strategy: Literal["full_read", "sampled", "hw_attested"]
    bytes_checked: int
    sample_count: int
    #: Detection **probability** in basis points: 10000 is 100.00%. Unlike
    #: :attr:`CarveCandidate.confidence_bp`, which is a weighted evidence sum,
    #: this one genuinely is a probability - 10000 for a full read, otherwise
    #: the sampling formula in :mod:`core.erase.verify` - and it is the chance
    #: of *detecting* a residual region of a given size, never a claim that
    #: none exists. An integer at the source, because this is the one number a
    #: third party reads to judge whether verification meant anything, and it
    #: must not be a lossy rewrite of something else.
    confidence_bp: int = Field(ge=0, le=10_000)
    failed_offsets: list[int]
    #: RNG seed for the sampled strategy, recorded so the sample set is
    #: reproducible by a third party checking the report.
    sample_seed: int | None = None
    #: The detection-probability formula with this run's values substituted.
    #: A bare percentage hides its own assumptions; the formula does not.
    probability_note: str = ""
    #: True only when the drive's own sanitize log reported clean completion.
    hw_attested: bool = False


class UnwritableRange(BaseModel):
    """A byte range the overwrite pass could not write, and why.

    A single bad sector must not abort a multi-terabyte wipe, so these are
    collected and surfaced as a residual-risk factor instead.
    """

    offset: int
    length: int
    errno: int

    @property
    def end(self) -> int:
        """First byte after the range."""
        return self.offset + self.length


class EraseCheckpoint(BaseModel):
    """Resume point written to the ledger during a long overwrite."""

    job_id: str
    pass_index: int
    offset: int
    bytes_written: int
    ts_utc: datetime


class ErasePlan(BaseModel):
    """What the tool intends to do, shown in full before anything is written."""

    method: EraseMethod
    level: SanitizationLevel
    justification: str
    #: Whole seconds the plan is expected to take. Named for the unit it
    #: holds, so a reader never has to guess the scale.
    est_seconds: int
    limitations: list[str] = []
    hidden_bytes: int = 0
    #: Fill byte per overwrite pass, as ``["0xA5"]``. Empty for firmware
    #: methods, which stream no host pattern. Stated in the plan because the
    #: operator is entitled to know what will be on the medium afterwards, and
    #: because a device left holding 0xA5 rather than zeros looks unwiped to
    #: anyone who was not told.
    fill_bytes: list[str] = []
    #: Why those fills and not the method's defaults. Recorded whenever the
    #: selection was driven by a measurement rather than by the method.
    fill_reason: str = ""
    #: Where est_seconds came from: the drive's own estimate, or a rate measured
    #: on this device before the run started. A reader should not have to guess
    #: whether an ETA is a manufacturer's number or an observation.
    est_basis: str = ""


class PlannedErase(BaseModel):
    """What the engine would run for one level, computed before any job exists.

    Produced by :func:`core.erase.drive.preview` from the same
    :func:`core.erase.drive.select_method` call :func:`core.erase.drive.execute`
    makes, so the screen and the certificate cannot disagree about the method
    unless the device itself changed between the two probes.
    """

    level: SanitizationLevel
    #: False when ``select_method`` refused the level for this device.
    reachable: bool
    method: EraseMethod | None = None
    #: The engine's own sentence for why this method, as the plan records it.
    justification: str = ""
    #: The probed facts the choice rests on, one sentence each.
    evidence: list[str] = []
    #: False when the method is chosen but this build cannot issue it (an Opal
    #: revert without a PSID). The job would fail rather than erase.
    executable: bool = True
    not_executable_reason: str = ""
    #: The caveats ``select_method`` attaches, capability limitations included.
    limitations: list[str] = []
    #: When unreachable: the refusal the engine raised, and its remediation.
    refusal: str = ""
    remediation: str = ""


class ErasePreview(BaseModel):
    """The engine's decision for every level a request can name, per device."""

    flash: bool
    flash_reason: str
    #: Every Purge mechanism the device offers, in the engine's preference
    #: order. The first is the one a Purge request runs.
    purge_mechanisms: list[EraseMethod] = []
    #: What this device would have to report for Purge to become reachable.
    purge_requires: str = ""
    plans: list[PlannedErase]


class EraseResult(BaseModel):
    """Outcome of one erase job. Returned by the ``execute`` generator."""

    job_id: str
    method: EraseMethod
    level: SanitizationLevel
    started_at: datetime
    finished_at: datetime
    bytes_written: int
    passes: int
    plan: ErasePlan
    residual_risk: ResidualRiskAssessment
    unwritable_ranges: list[UnwritableRange] = []
    limitations: list[str] = []
    #: True only when the drive's own sanitize status reported clean completion.
    #: Never sufficient on its own; verification always samples as well.
    hw_attested: bool = False
    #: The target as the engine read it at preflight, so a report names the
    #: device this run wrote to, not the one a caller remembered. The block
    #: sizes are the kernel's, as the engine used them.
    device: Device | None = None
    logical_block_size: int = 0
    physical_block_size: int = 0
    #: HPA/DCO as measured at preflight (None when not probed), and whether this
    #: run's erase covered the hidden region.
    hidden_areas: HiddenAreaReport | None = None
    hidden_covered: bool = False
    #: The read-back verdict. None when verification did not run: a result
    #: object would invite a "passed" for bytes nobody read back.
    verification: VerificationResult | None = None
    #: The level this run may claim (drive._achieved_level). None when the run
    #: stopped before verification.
    achieved_level: SanitizationLevel | None = None


#: Outcome of a real decode attempt. ``decoder_unavailable`` is not a verdict
#: about the bytes: it says the decoder for this format could not be run (an
#: optional dependency is missing, or the decode exceeded its deadline), so the
#: file is unjudged rather than condemned.
Validation = Literal["valid", "truncated", "corrupt", "decoder_unavailable"]

#: What an investigator filters on, one step coarser than the MIME type.
CarveCategory = Literal[
    "document",
    "image",
    "media",
    "database",
    "executable",
    "archive",
    "unknown",
]


class CarveFlags(BaseModel):
    """Content properties an investigator triages on.

    Every flag defaults to False, and False means "not observed", never
    "observed absent". A format whose decoder did not run cannot set any of
    them, which is why :attr:`inspected` exists: it separates a document with
    no macros from a document nobody opened.
    """

    has_exif_gps: bool = False
    is_password_protected: bool = False
    is_encrypted: bool = False
    contains_macros: bool = False
    has_embedded_files: bool = False
    is_signed: bool = False
    #: True once a decoder actually examined the bytes for the flags above.
    inspected: bool = False


class PiiFindings(BaseModel):
    """Personal-data triage for one recovered object: kinds and counts only.

    **No matched value is ever stored here, nor any part, mask, hash or offset
    of one.** An examiner who needs the value opens the recovered object, which
    already holds it; this record exists to say which objects to open first.
    See :mod:`core.carve.pii` for why each of those is excluded.

    A count is a signal to look, not a finding: the detectors match a shape
    and, for Aadhaar and card numbers, a checksum. ``inspected`` False means
    nobody looked, and says nothing about what the object holds.
    """

    inspected: bool = False
    #: How the bytes were read, or why they were not.
    basis: str = ""
    #: Kind -> number of matches. Kinds with no match are absent.
    counts: dict[str, int] = {}


class MacTimestamps(BaseModel):
    """Filesystem MAC timestamps carried by a surviving metadata record.

    Every field is ``None`` when the record did not carry it. ``None`` never
    means the epoch: a FAT directory entry has no access *time* at all, only an
    access date, and reporting midnight for it would invent a precision the
    filesystem never had.

    Named for what they are rather than by initial, because "C" means *created*
    on NTFS and *metadata changed* on ext - which is exactly the confusion a
    timeline built from mixed filesystems has to avoid.
    """

    modified: datetime | None = None
    accessed: datetime | None = None
    #: Metadata-change time on ext and the ``$STANDARD_INFORMATION`` MFT-change
    #: time on NTFS. Never the creation time.
    changed: datetime | None = None
    created: datetime | None = None


class CarveFragment(BaseModel):
    """One contiguous run of a carved object's content, image-absolute.

    A carved object is normally one span, and ``CarveCandidate.offset`` plus
    ``length`` says everything about where it was. A *bifragmented* object is
    not: its content is two runs with somebody else's bytes in between, and no
    single span describes it. Reporting one anyway - an offset, a length and a
    digest that do not agree - would be the tool claiming the medium held
    something it never held.
    """

    offset: int
    length: int

    @property
    def end(self) -> int:
        """First byte after the run."""
        return self.offset + self.length


class CarveCandidate(BaseModel):
    """A recovered-or-recoverable object produced by the carving pipeline."""

    offset: int
    length: int
    ext: str
    mime: str
    source: Literal["fs_metadata", "signature", "structure"]
    validation: Validation
    #: Carve **evidence score** in basis points, out of 10000. This is a sum
    #: of measured components (see :attr:`score_components`), clamped and never
    #: scaled - **not a probability that this object is correct**, and not
    #: comparable with :attr:`VerificationResult.confidence_bp`, which is one.
    #: The components come to 10500 when every one is established, so 10000 is
    #: where the clamp lands rather than a statement of certainty. What the
    #: calibration measured is per-bucket precision on a synthetic population;
    #: see ``docs/performance/calibration-pooled.md``. The field name is kept
    #: because it is part of the signed report schema.
    confidence_bp: int = Field(ge=0, le=10_000)
    bucket: Literal["HIGH", "MEDIUM", "LOW"]
    sha256: str
    original_name: str | None
    possibly_fragmented: bool
    #: The image-absolute runs the object's content was reassembled from, in
    #: file order. **Empty for the ordinary contiguous case**, where
    #: ``offset``..``offset + length`` already says where the bytes are.
    #:
    #: When it is populated the candidate is not a span: ``length`` is the sum
    #: of the runs, ``offset`` is the first run's offset, and ``sha256`` is the
    #: digest of the runs concatenated - *not* of
    #: ``offset``..``offset + length``, which covers the gap as well and hashes
    #: to something that was never a file. Anything reading the object's bytes
    #: must walk the runs; :func:`core.carve.fragmentation.read_fragments`
    #: does it through the read-only evidence handle.
    fragments: list[CarveFragment] = []
    #: What the decoder said, in the operator's words. Empty when no decoder ran.
    validation_detail: str = ""
    #: Mean Shannon entropy over the candidate, in thousandths of a bit per
    #: byte: 7500 is 7.5 bits/byte. An integer for the same reason
    #: ``confidence_bp`` is one - the report shows this number to justify a
    #: score, and it must not be a lossy rewrite of a float. ``None`` means not
    #: measured, never "measured zero".
    entropy_millibits_per_byte: int | None = Field(default=None, ge=0, le=8000)
    #: Fraction of 4 KiB windows at or above 7.5 bits/byte, in basis points.
    high_entropy_windows_bp: int | None = Field(default=None, ge=0, le=10_000)
    #: Per-component score contributions in basis points, keyed by component
    #: name. The report renders this so "0.35" can be taken apart by a reader
    #: who was not there when it was computed.
    score_components: dict[str, int] = {}
    #: True when a higher-scoring candidate covers overlapping bytes. Kept and
    #: reported, never dropped: a suppressed candidate that turns out to matter
    #: is something an examiner must be able to see.
    overlapped: bool = False
    #: Offset of the winning candidate this one was suppressed in favour of.
    overlaps_with: int | None = None
    category: CarveCategory = "unknown"
    flags: CarveFlags = CarveFlags()
    #: Identity and financial identifier counts. Never the values.
    pii: PiiFindings = PiiFindings()
    #: Every other offset the identical content was found at, ascending. The
    #: candidate itself carries the first one in ``offset``.
    duplicate_offsets: list[int] = []
    # ---- filesystem-metadata recovery (source="fs_metadata") --------------
    #: The filesystem the metadata came from: ``ntfs``, ``fat32``, ``exfat``,
    #: ``ext2``, ``ext3``, ``ext4``. Empty for every other source.
    fs_type: str = ""
    #: MAC timestamps from the surviving metadata record. ``None`` when no
    #: record was involved, which is every candidate that is not
    #: ``fs_metadata``.
    mac: MacTimestamps | None = None
    #: True when the recovery had no cluster chain and assumed the file was
    #: laid out contiguously from its start cluster. Always true on FAT32,
    #: where deletion destroys the chain. On exFAT it is true only when the
    #: stream extension's ``NoFatChain`` flag was clear; when the flag was set
    #: the file genuinely was contiguous and this stays false.
    contiguity_assumed: bool = False
    #: True when the assumption above is provably wrong - a cluster inside the
    #: assumed run is allocated to a live file, so the recovered bytes contain
    #: someone else's data. The candidate is still reported: a partial recovery
    #: that says it is partial is evidence, and silently dropping it is not.
    contiguity_contradicted: bool = False


class SubstitutedRange(BaseModel):
    """Bytes that could not be read and were filled with a known value.

    The whole point of recording these is that a caller must never mistake a
    substituted byte for one that was actually on the media. A run of zeros
    that came from a fill and a run of zeros that came from the disk are
    indistinguishable in the returned buffer; only this record separates them.
    """

    offset: int
    length: int
    #: The byte written in place of the unreadable data, 0-255.
    fill_byte: int = Field(ge=0, le=255)
    #: Why the read failed, in the operator's words. Never empty.
    reason: str


class BadSectorRange(BaseModel):
    """A run of sectors that failed to read, in logical block addresses.

    ``last_lba`` is inclusive: a single bad sector has ``first_lba ==
    last_lba``. Recorded on the acquisition, in the ledger and in the report,
    because an image containing silent substitutions and no record of them is
    not admissible.
    """

    first_lba: int
    last_lba: int
    sector_size: int
    #: The errno the final attempt returned, so a reader can tell a medium
    #: error from a device that went away mid-acquisition.
    errno: int
    #: How many times the range was retried before being written off.
    attempts: int

    @property
    def sector_count(self) -> int:
        return self.last_lba - self.first_lba + 1


class DestroyTechnique(StrEnum):
    """How media was physically destroyed, as the people who did it recorded."""

    SHRED = "SHRED"
    DISINTEGRATE = "DISINTEGRATE"
    PULVERIZE = "PULVERIZE"
    INCINERATE = "INCINERATE"
    MELT = "MELT"
    OTHER = "OTHER"


class DestructionRecord(BaseModel):
    """A physical destruction, attested by the people who performed it.

    NIST SP 800-88 Rev. 2 names Destroy as the outcome for media that cannot
    be cleared or purged, or must never be reused. No software performs it,
    and none can observe it: this is what the operator and the witness state,
    signed so it cannot change afterwards. See :mod:`core.destroy`.
    """

    serial: str = Field(min_length=1, max_length=128)
    model: str = Field(default="", max_length=128)
    capacity_bytes: int | None = Field(default=None, ge=0)
    media_type: Literal["HDD", "SSD", "USB", "SD_CARD", "OPTICAL", "TAPE", "OTHER"]
    technique: DestroyTechnique
    #: Required when the technique is OTHER.
    technique_detail: str = Field(default="", max_length=300)
    #: Largest remaining fragment, as measured or specified by the facility.
    particle_size_mm: int | None = Field(default=None, gt=0, le=1000)
    #: Why the medium was destroyed rather than cleared or purged.
    reason: str = Field(min_length=1, max_length=500)
    performed_by: str = Field(min_length=1, max_length=120)
    witnessed_by: str = Field(default="", max_length=120)
    performed_at: datetime
    location: str = Field(default="", max_length=200)
    #: A destruction vendor's certificate number, when a vendor did it.
    vendor_certificate: str = Field(default="", max_length=120)
    notes: str = Field(default="", max_length=1000)

    @model_validator(mode="after")
    def _other_is_described(self) -> DestructionRecord:
        described = self.technique_detail.strip()
        if self.technique is DestroyTechnique.OTHER and not described:
            raise ValueError("technique OTHER needs technique_detail saying what")
        for name in ("serial", "reason", "performed_by"):
            if not str(getattr(self, name)).strip():
                raise ValueError(f"{name} must not be blank")
        return self


class MediaRegion(BaseModel):
    """One region of an evidence image, classed by the statistics of its bytes.

    See :mod:`core.carve.mediamap`. Every number is an integer, so a map can
    enter a signed report and the ledger unchanged.
    """

    offset: int
    length: int
    #: The class most of the blocks read here fell into: ZERO, FILL, TEXT,
    #: STRUCTURED or HIGH_ENTROPY.
    kind: str
    #: That class's share of the blocks read, in basis points.
    share_bp: int
    #: Mean Shannon entropy of the blocks read, in millibits per byte (0-8000).
    entropy_mb: int
    #: For a FILL region, the byte it is filled with.
    fill_byte: int | None = None
    #: File headers on sector boundaries in the bytes read, by extension.
    headers: dict[str, int] = {}
    #: Bytes of this region actually read.
    bytes_read: int
    #: Some byte read here was substituted for an unreadable one.
    substituted: bool = False


class MediaMap(BaseModel):
    """What an image holds, region by region, and how the answer was reached."""

    size_bytes: int
    region_bytes: int
    block_bytes: int
    #: True when the regions were sampled rather than read in full.
    sampled: bool
    bytes_read: int
    regions: list[MediaRegion] = []
    #: Bytes of the image in each class, shared out by block count per region.
    by_kind: dict[str, int] = {}
    headers: dict[str, int] = {}
    limitations: list[str] = []


class EvidenceSource(BaseModel):
    """Identity of an evidence source and everything known about its integrity."""

    path: str
    fmt: Literal["raw", "split_raw", "ewf", "bytes"]
    size_bytes: int
    sector_size: int
    #: Present only once a full pass has hashed the source. ``None`` means not
    #: computed, never "computed and empty".
    sha256: str | None = None
    blake3: str | None = None
    #: Segment paths, in address order, for a split set. Empty otherwise.
    segments: list[str] = []
    substituted_ranges: list[SubstitutedRange] = []
    #: Guarantees that could not be made. Rendered verbatim in the report.
    limitations: list[str] = []


class AcquisitionRecord(BaseModel):
    """Chain of custody for one imaging run. Ledgered in full."""

    job_id: str
    source: EvidenceSource
    dest_path: str
    fmt: Literal["raw", "e01"]
    started_at: datetime
    finished_at: datetime
    operator: str
    tool_version: str
    #: Identifies the boot the monotonic clock belongs to. A monotonic reading
    #: is meaningless across a reboot without it.
    boot_id: str
    monotonic_ns: int
    bytes_read: int
    sha256: str
    blake3: str
    #: Size of each chunk in ``chunk_hashes``. A later integrity failure is
    #: localised to a chunk instead of condemning the whole image.
    chunk_bytes: int
    chunk_hashes: list[str] = []
    bad_sectors: list[BadSectorRange] = []
    limitations: list[str] = []
    #: True when this image was completed by resuming an interrupted run.
    resumed: bool = False
    #: True only when a software write block was applied AND read back as
    #: applied. False is honest; there is no third state that implies more.
    write_blocked: bool = False
    #: How strongly ``write_blocked`` was established. ``flag_read_back`` means
    #: the kernel reports the device read-only and nothing tried to write;
    #: ``attempted_write`` means a write was issued and refused. The acquisition
    #: path never writes to an evidence device, so it only ever produces the
    #: first - a reader is entitled to know which claim is being made.
    write_block_verified_by: str = ""


class IntegrityResult(BaseModel):
    """Outcome of re-reading an image and comparing it to its record."""

    passed: bool
    sha256_matches: bool
    blake3_matches: bool
    expected_sha256: str
    actual_sha256: str
    expected_blake3: str
    actual_blake3: str
    #: Indices into ``AcquisitionRecord.chunk_hashes`` that no longer match.
    #: Empty when the hashes agree, which is what makes a mismatch locatable.
    mismatched_chunks: list[int] = []
    bytes_verified: int


class LedgerEntry(BaseModel):
    """One hash-chained audit record. ``prev_entry_hash`` binds entry N to N-1."""

    seq: int
    ts_utc: datetime
    monotonic_ns: int
    #: Per-boot UUID. ``monotonic_ns`` is only comparable within one boot; without
    #: this a verifier cannot tell a reboot from a clock rollback.
    boot_id: str
    actor: str
    operation: str
    params_hash: str
    result_hash: str
    prev_entry_hash: str
    entry_hash: str


class Signature(BaseModel):
    """A detached signature over a report's canonical bytes."""

    alg: str
    pubkey_fingerprint: str
    pubkey_b64: str
    sig_b64: str
    signed_at: str
    #: Which canonicalisation rules produced the signed bytes. A verifier that
    #: does not implement this version cannot check the signature honestly.
    canon_version: str


class ForensicReport(BaseModel):
    """Operator-facing report, rendered and detached-signed downstream."""

    case_id: str
    operator: str
    generated_at: datetime
    tool_version: str
    pubkey_fingerprint: str
    sections: dict[str, Any]
    ledger_excerpt: list[LedgerEntry]
    signature: Signature | None = None


class Progress(BaseModel):
    """Progress record yielded by long-running generator operations.

    Every numeric field is an integer, deliberately. :mod:`core.ledger.canon`
    rejects floats, so any progress value that reaches a ledger entry would
    otherwise be rewritten at the boundary - and a boundary rewrite makes the
    recorded number a lossy transform of the measured one, in units the
    original caller never chose. Percentages are basis points and throughput is
    whole bytes per second at the source instead, so the value a verifier reads
    is the value the operation measured.
    """

    job_id: str
    phase: str
    #: Completion in basis points: 10000 is 100.00%.
    pct_bp: int = Field(ge=0, le=10_000)
    bytes_done: int
    bytes_total: int
    throughput_bytes_per_sec: int
    #: Whole seconds remaining. An ETA does not have sub-second accuracy, so
    #: recording it at finer resolution would be false precision.
    eta_seconds: int
    message: str


# ---------------------------------------------------------------------------
# M2: file and folder erasure
# ---------------------------------------------------------------------------


class Extent(BaseModel):
    """One contiguous physical run of a file, captured *before* erasure.

    The timing is the whole point. Once the file is unlinked there is no handle
    left that maps to those physical blocks, so an extent map captured
    afterwards does not exist and post-erase verification would have nothing to
    read back. This is the only record of where the bytes actually were.
    """

    #: Logical offset within the file, in bytes.
    logical_offset: int
    #: Physical offset on the volume, in bytes from the start of the volume.
    physical_offset: int
    length: int

    @property
    def end(self) -> int:
        """First byte after the extent, physically."""
        return self.physical_offset + self.length


class FileInspection(BaseModel):
    """Everything known about a file *before* anything is written to it.

    Every field a platform may be unable to determine is ``bool | None`` or
    ``list[...] | None``, and ``None`` means "could not determine". Reporting an
    unknown as ``False`` would be the tool claiming a guarantee it does not
    have - "there are no snapshots" and "nobody could ask about snapshots" lead
    an operator to opposite decisions.
    """

    path: str
    size_bytes: int
    fs_type: str = ""
    #: Cluster/allocation-unit size in bytes; 0 when it could not be read.
    cluster_bytes: int = 0
    is_resident: bool | None = None
    extents: list[Extent] = []
    is_sparse: bool | None = None
    is_compressed: bool | None = None
    is_encrypted: bool | None = None
    hardlink_count: int = 1
    #: Alternate data stream names as reported by the OS, e.g. ":hidden:$DATA".
    alt_data_streams: list[str] = []
    xattrs: list[str] = []
    is_immutable: bool | None = None
    is_reparse_point: bool = False
    #: Names of snapshots referencing this subvolume/dataset; None = unknown.
    cow_snapshots: list[str] | None = None
    #: Shadow copy IDs on this volume; None = unknown (usually: not admin).
    vss_shadow_ids: list[str] | None = None
    vss_present: bool | None = None
    trim_likely: bool | None = None
    #: True when the path lies under a known cloud-sync directory.
    in_sync_directory: bool = False
    #: Plain-language reasons a field above is unknown. Surfaced in the report.
    limitations: list[str] = []

    @property
    def slack_bytes(self) -> int:
        """Bytes between end-of-file and end-of-cluster. 0 when unknown.

        0 is returned both for "no slack" and for "cluster size unknown", which
        would be a dangerous conflation anywhere else. It is safe here because
        the residual scanner reports FILE_SLACK only on a positive value, so an
        unknown produces no finding rather than a false reassurance - and the
        unknown itself is already carried as a limitation.
        """
        if self.cluster_bytes <= 0:
            return 0
        remainder = self.size_bytes % self.cluster_bytes
        return 0 if remainder == 0 else self.cluster_bytes - remainder


class MetadataField(BaseModel):
    """One metadata field that was found, and whether it was removed."""

    container: str
    name: str
    removed: bool


class MetadataCleanseResult(BaseModel):
    """What cleansing found and removed. Never claims clean on an unparsed file."""

    path: str
    format: str
    parsed: bool
    fields: list[MetadataField] = []
    #: Why the file could not be parsed, or a caveat about what survived.
    limitations: list[str] = []

    @property
    def removed_count(self) -> int:
        return sum(1 for field in self.fields if field.removed)


class FileErasePhase(StrEnum):
    """Phases of a single-file erase, in execution order. One ledger entry each."""

    INSPECT = "INSPECT"
    CLEANSE = "CLEANSE"
    OVERWRITE = "OVERWRITE"
    STREAMS = "STREAMS"
    TRUNCATE = "TRUNCATE"
    RENAME = "RENAME"
    UNLINK = "UNLINK"
    RESIDUAL = "RESIDUAL"
    VERIFY = "VERIFY"


class FileEraseOptions(BaseModel):
    """Caller-controlled policy. The destructive gate defaults to closed.

    Undeclared keys (the removed ``dry_run`` among them) are refused.
    """

    model_config = ConfigDict(extra="forbid")

    #: The confirmation gate. Every erase is real, so nothing runs until the
    #: caller sets this explicitly.
    confirm: bool = False
    cleanse_metadata: bool = True
    #: When False (the default) a file with st_nlink > 1 is unlinked but NOT
    #: overwritten, because overwriting would destroy data reachable under a
    #: name the operator did not ask about. Either way HARDLINK_SURVIVES is
    #: reported.
    break_hardlinks: bool = False
    rename_rounds: int = 8
    recursive: bool = True
    #: None means cpu_count(). 1 forces the inline path with no pool.
    workers: int | None = None
    #: Below this many paths the pool is not started; spawn costs more than it
    #: saves. Exposed so tests can force either path.
    pool_threshold: int = 32
    #: After the erase, find what the desktop kept of these files - thumbnails,
    #: recent-files entries, Trash and Recycle Bin copies - and, on a real run,
    #: remove the ones tied to an erased path on evidence. See
    #: core.erase.traces. Off here, so a library caller opts in; the API turns
    #: it on. Only a trace tied to an erased path on evidence is removed.
    sweep_traces: bool = False


class FileVerificationResult(BaseModel):
    """Whether the erased bytes were physically confirmed gone.

    ``passed`` is tri-state on purpose. ``False`` means "read the original
    physical location and the pattern was not there". ``None`` means "could not
    read it, so nothing is claimed". Collapsing those two into one boolean is
    how a tool ends up reporting a pass it never earned, and for a file erase
    ``None`` is by far the common case.
    """

    passed: bool | None
    strategy: Literal["physical_extent_read", "not_possible"]
    reason: str = ""
    extents_checked: int = 0
    bytes_checked: int = 0
    failed_offsets: list[int] = []


class FileEraseRecord(BaseModel):
    """Outcome for one path. Batch results hold these in input order."""

    path: str
    ok: bool
    inspection: FileInspection
    #: Bytes overwritten in the unnamed data stream.
    bytes_overwritten: int = 0
    #: Streams and xattrs overwritten then removed.
    streams_removed: list[str] = []
    xattrs_removed: list[str] = []
    #: Sizes passed to ftruncate, in order.
    truncate_steps: list[int] = []
    #: The names the file was renamed through, in order. Same length as the
    #: original name by construction; a test asserts it.
    rename_chain: list[str] = []
    unlinked: bool = False
    #: True when this record describes a directory rather than a file.
    is_directory: bool = False
    cleanse: MetadataCleanseResult | None = None
    findings: list[ResidualFinding] = []
    verification: FileVerificationResult | None = None
    limitations: list[str] = []
    #: Populated instead of raising. A batch never aborts for one bad file.
    error: str | None = None
    error_kind: str | None = None
    #: True once every refusal check passed and the erase steps began. A
    #: failed record with this False was refused before anything ran; with it
    #: True the erase started and stopped partway, and the path is in an
    #: unknown state.
    attempted: bool = False

    @property
    def highest_severity(self) -> Severity | None:
        order = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2}
        return (
            max((item.severity for item in self.findings), key=lambda s: order[s])
            if self.findings
            else None
        )


class TraceRecord(BaseModel):
    """One trace the desktop kept of an erased file, and what became of it.

    See :mod:`core.erase.traces`. ``exact`` is True only when the trace was
    tied to the erased path on evidence - a thumbnail named by the MD5 of the
    file's URI, a Trash record naming its path - and only exact traces are ever
    removed.
    """

    kind: str
    #: The erased path this trace belongs to.
    target: str
    #: Where the trace is: a file, or the list that holds an entry.
    location: str
    #: Why it matches, in words.
    evidence: str
    #: A copy of the content (a thumbnail, a Trash copy), not only a mention.
    content_copy: bool
    exact: bool
    #: "erased" (put through the same steps as a target), "entry removed" (cut
    #: out of a shared list, which was overwritten in place), or empty when
    #: nothing was done: an inexact match, a report-only trace, or a failure.
    action: str = ""
    removed: bool = False
    bytes_overwritten: int = 0
    error: str = ""
    #: True for an exact trace the sweep reports and never removes, because it
    #: sits inside a file another process owns (a daemon's database, a live
    #: compound file, a Finder ``.DS_Store``). ``report_only_reason`` says why.
    report_only: bool = False
    report_only_reason: str = ""


class TraceInspection(BaseModel):
    """One place the trace sweep inspected, and what came of looking there."""

    #: What the place is: "home Trash", "Jump lists", "Quick Look cache" ...
    label: str
    location: str
    #: "searched", "absent", "unreadable" or "permission-denied".
    outcome: str
    #: Why a place was unreadable or refused, in words; empty when searched.
    detail: str = ""


class TraceSweepResult(BaseModel):
    """What the trace sweep searched, what it did not, and what it found."""

    #: Every place that was searched, including those that were not present.
    searched: list[str] = []
    #: Places on this platform that keep traces and were not searched.
    not_searched: list[str] = []
    traces: list[TraceRecord] = []
    #: Places that were present but could not be read, and why.
    notes: list[str] = []
    #: Each place inspected, with its outcome. ``searched`` is the same list as
    #: one line per place; this one keeps the outcome as a field.
    inspected: list[TraceInspection] = []


class FileEraseResult(BaseModel):
    """Outcome of one ``erase_paths`` call."""

    job_id: str
    started_at: datetime
    finished_at: datetime
    #: In the order the caller supplied the paths, regardless of completion order.
    records: list[FileEraseRecord] = []
    limitations: list[str] = []
    #: What the trace sweep found after the erase; None when it was not run.
    trace_sweep: TraceSweepResult | None = None

    @property
    def succeeded(self) -> int:
        return sum(1 for record in self.records if record.ok)

    @property
    def failed(self) -> int:
        return sum(1 for record in self.records if not record.ok)

    @property
    def highest_severity(self) -> Severity | None:
        order = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2}
        found = [
            finding.severity for record in self.records for finding in record.findings
        ]
        return max(found, key=lambda s: order[s]) if found else None


# --------------------------------------------------------------------------
# Free-space wipe (M2)
# --------------------------------------------------------------------------


class VolumeInfo(BaseModel):
    """A mounted volume a free-space wipe was asked to act on."""

    mount_point: str
    fs_type: str
    #: The mount source from /proc/mounts: a block device, or an image path.
    source: str
    #: The filesystem UUID from /dev/disk/by-uuid, when one links to the source.
    fs_uuid: str | None = None
    #: What the operator types to confirm: the UUID when known, otherwise the
    #: mount point. Shown by the read-only plan, never guessable from the
    #: request alone.
    identifier: str
    #: ``st_dev`` of the mount point, used to refuse the system volume and any
    #: volume holding this deployment's own state.
    st_dev: int
    #: Fundamental block size reported by statvfs.
    frsize: int
    #: Whether the backing device is flash that likely remaps writes. ``None``
    #: means it could not be determined, which is not the same as "no".
    trim_likely: bool | None = None


class FreeSpaceWipeOptions(BaseModel):
    """Caller policy for a free-space wipe. The gate defaults to closed.

    Undeclared keys (the removed ``dry_run`` among them) are refused.
    """

    model_config = ConfigDict(extra="forbid")

    #: The confirmation gate. Must equal the volume's identifier, as the
    #: read-only plan (:func:`core.erase.freespace.plan_volume`) reports it.
    typed_identifier: str = ""


class FreeSpaceWipeResult(BaseModel):
    """What a free-space wipe wrote, and what it did not reach.

    Every byte count is measured, and every free-space figure is the
    filesystem's own statvfs answer at that moment. Nothing here says the free
    space is clean: ``verified`` is always ``None``, because this operation
    reads nothing back.
    """

    job_id: str
    started_at: datetime
    finished_at: datetime
    volume: VolumeInfo
    fill_byte: int
    #: Bytes this job wrote into its own filler files.
    bytes_written: int = 0
    filler_files: int = 0
    #: statvfs f_bavail * f_frsize before the fill: what an unprivileged writer
    #: may allocate.
    free_bytes_before: int = 0
    #: statvfs f_bfree * f_frsize before the fill: every free block, including
    #: those reserved for root.
    free_blocks_bytes_before: int = 0
    #: The same two figures with the volume full of filler.
    free_bytes_at_full: int = 0
    free_blocks_bytes_at_full: int = 0
    #: Free blocks after the filler was deleted.
    free_bytes_after: int = 0
    #: Why the fill stopped: ``ENOSPC`` is the normal end.
    stopped_by: str = ""
    #: Whether every filler file and the filler directory were removed.
    filler_removed: bool = False
    #: Residue this operation cannot reach, named rather than implied.
    not_reached: list[str] = []
    limitations: list[str] = []
    #: Always ``None``: no read-back is performed, so no pass is claimed.
    verified: bool | None = None
