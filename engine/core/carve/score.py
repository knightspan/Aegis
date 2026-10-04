"""Assign an evidence score and HIGH/MEDIUM/LOW bucket to a candidate.

The score is a sum of named components in basis points, clamped to 0..10000,
and every component is recorded on the candidate. That matters more than the
total: an examiner asked "how did you arrive at 0.35?" can be shown the six
numbers that produced it rather than a model's opinion.

**It is not a probability that the object is correct.** The components come to
10,500 when every one is established, so a candidate carrying all of them
reads 10000 because that is where the clamp lands - not because anything
measured certainty. What the calibration measured is the *bucket's* precision
on a population: pooled over eight seeds and 173 candidates, 104 of 104 HIGH
candidates matched a planted object byte for byte, and that is a property of
those synthetic corpora rather than a rate for seized media (on the 7 GiB
image HIGH precision was 86.6% before the footer-bound fix). Anything that
renders this number must not format it as a percentage; see
``ui/src/lib/format.ts:evidenceScore``.

The components, and what each one is evidence of. The weights are the ones
in force (:data:`CALIBRATED_WEIGHTS`); :data:`ORIGINAL_WEIGHTS` keeps the
starting values:

============================  ======  ====================================
component                     weight  what it establishes
============================  ======  ====================================
``header``                      2000  the format's magic sits exactly where
                                      this candidate claims the object starts
``exact_length``                1500  the end was derived - a footer was
                                      found, or a parser walked the format's
                                      own length fields - rather than guessed
``decoder``                     4000  a real decoder read the whole object
                                      (1000 when it read a prefix and ran
                                      out, 1000 when no decoder exists for
                                      the format, 0 when it read corrupt)
``entropy``                     1000  the byte distribution matches what this
                                      format produces
``fs_metadata``                 1500  a surviving filesystem record agrees
                                      that a file lived here - which is not
                                      the same as the bytes there now being
                                      that file, and is weighted accordingly
``no_overlap``                   500  no higher-scoring candidate claims the
                                      same bytes
``reassembly``                 <= 0  holds an object rebuilt from separate
                                      runs at 7999, below HIGH, whatever the
                                      others add up to; 0 for everything else
============================  ======  ====================================

**Why a reassembled object cannot be HIGH.** Every other component of a
contiguous candidate is measured on bytes that sit on the medium as one run. A
reassembled candidate's bytes are measured just as well - the header, the exact
MCU accounting in :mod:`core.carve.fragmentation`, the decode and the entropy
all cover every byte emitted - but *where the gap was* is an inference, and on a
real case there is no manifest to check it against. The residual of that
inference is measured, not assumed: a join that loses or replaces 512 to 1,536
bytes of an object's own scan passes the accounting about one time in twenty on
noise-like JPEGs when the true tail start is not on the medium. No contiguous
candidate has that failure mode, and the population HIGH's precision was
calibrated on contained no reassembled object. The ceiling costs nothing about
the recovery - the bytes and their runs are unchanged - and changes only what
the tool claims about its own certainty. It is a component rather than a clamp
so the arithmetic still reconciles and the reason is on the record.

The weights are not invented: :mod:`testkit.calibrate` runs the pipeline over a
corpus with a known manifest and measures the precision and recall each bucket
actually achieves. See ``docs/performance/calibration.md`` for the measured
table and for every weight that moved as a result.

Entropy is the component that catches the classic false positive. A ``FFD8FF``
inside an English text file is a perfectly good JPEG header attached to bytes
carrying about 4.2 bits per byte; a real JPEG carries above 7.5 in nearly every
window. The measured value is recorded on the candidate, so the report can show
the number rather than assert the conclusion.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

import structlog

from core.carve.evidence import EvidenceHandle
from core.carve.signature import Signature, load_signatures
from core.models import CarveCandidate

__all__ = [
    "ScoreWeights",
    "ORIGINAL_WEIGHTS",
    "CALIBRATED_WEIGHTS",
    "WEIGHTS",
    "ScoreEvidence",
    "EntropyProfile",
    "ENTROPY_PROFILES",
    "HEADER_FAMILY",
    "HIGH_ENTROPY_MILLIBITS",
    "LOW_ENTROPY_MILLIBITS",
    "ENTROPY_WINDOW_BYTES",
    "HIGH_BUCKET_FLOOR_BP",
    "MEDIUM_BUCKET_FLOOR_BP",
    "REASSEMBLED_CEILING_BP",
    "measure_entropy",
    "bucket_for",
    "gather_evidence",
    "score_from_evidence",
    "score_candidate",
    "resolve_overlaps",
]

logger = structlog.get_logger(__name__)

MIB = 1024 * 1024

#: Window size for the Shannon entropy sweep. Small enough that a text region
#: inside a compressed file still shows up as its own window, large enough that
#: a 256-symbol alphabet is not undersampled.
ENTROPY_WINDOW_BYTES = 4096

#: Compressed and encrypted formats sit above this, in thousandths of a bit per
#: byte. 7.5 bits/byte is the conventional floor for "this is compressed".
HIGH_ENTROPY_MILLIBITS = 7500

#: Text and uncompressed formats sit below this.
LOW_ENTROPY_MILLIBITS = 6000

#: Share of windows that must clear :data:`HIGH_ENTROPY_MILLIBITS` before a
#: compressed format's entropy component is awarded, in basis points. Not every
#: window: a JPEG's header, EXIF block and Huffman tables are all structured.
HIGH_WINDOW_SHARE_BP = 6000

#: A format with no entropy expectation still has to look like data rather than
#: like fill. A run of zeros clears no floor at all. Lowered from 3000 after the
#: calibration run: a real SQLite database of text rows measures 2.96 bits/byte,
#: and 3000 was rejecting it for being what it is.
MIXED_ENTROPY_FLOOR_MILLIBITS = 2000

HIGH_BUCKET_FLOOR_BP = 8000
MEDIUM_BUCKET_FLOOR_BP = 5000

#: The most a candidate reassembled from separate runs can score. One basis
#: point under HIGH; see the module docstring for why.
REASSEMBLED_CEILING_BP = HIGH_BUCKET_FLOOR_BP - 1

EntropyProfile = Literal["high", "low", "mixed"]

#: What each format's bytes should look like. ``mixed`` means the format has no
#: single expectation - a PDF is a text skeleton wrapped around compressed
#: streams - so the component only rules out fill.
ENTROPY_PROFILES: dict[str, EntropyProfile] = {
    "jpg": "high",
    "png": "high",
    "gif": "high",
    "zip": "high",
    "docx": "high",
    "xlsx": "high",
    "pptx": "high",
    "mp4": "high",
    "7z": "high",
    "rar": "high",
    "webp": "high",
    "gz": "high",
    "txt": "low",
    "xml": "low",
    "html": "low",
    "csv": "low",
    "bmp": "low",
    "rtf": "low",
    "pdf": "mixed",
    "doc": "mixed",
    "elf": "mixed",
    "exe": "mixed",
    "tiff": "mixed",
    # Neither of these has a single expectation, and saying so is the honest
    # entry. Uncompressed PCM is as random as what was recorded - silence is
    # near zero bits per byte and noise is near eight - and a tar is whatever
    # its members are, text and compressed files alike.
    "wav": "mixed",
    "tar": "mixed",
    # Measured, not assumed: a database page is text rows and padding, and an
    # event log is repeated record templates. Both sit near 3 bits/byte.
    "sqlite": "low",
    "evtx": "low",
}

#: Refined extensions and the signature-table extension their magic belongs to.
#: The classifier renames a ZIP holding ``word/document.xml`` to ``docx``, and
#: the header component still has to find ``PK``: the magic did not
#: change when the name did.
HEADER_FAMILY: dict[str, str] = {
    "docx": "zip",
    "xlsx": "zip",
    "pptx": "zip",
    "docm": "zip",
    "xlsm": "zip",
    "pptm": "zip",
    "xls": "doc",
    "ppt": "doc",
}


@dataclass(frozen=True)
class ScoreWeights:
    """Basis points awarded per component. See the module docstring."""

    header: int = 2000
    exact_length: int = 1500
    decoder_valid: int = 3500
    decoder_truncated: int = 1500
    #: A decoder that could not run says nothing about the bytes. It is worth
    #: something only because the components around it were established anyway.
    decoder_unavailable: int = 0
    entropy: int = 1000
    fs_metadata: int = 1500
    no_overlap: int = 500


#: The weights this module started with, kept so the calibrated set can be read
#: as a change from something rather than as a bare assertion.
ORIGINAL_WEIGHTS = ScoreWeights()

#: The weights in force. Three moved after the run recorded in
#: ``docs/performance/calibration.md``:
#:
#: * ``decoder_valid`` 3500 -> 4000, so that header + derived length + a clean
#:   full decode reaches the HIGH floor on its own. Every candidate meeting
#:   that description in the run was a true positive, and the old weight left
#:   six of nine of them in MEDIUM.
#: * ``decoder_truncated`` 1500 -> 1000. Truncated candidates scored no true
#:   positives, and the old weight put one in MEDIUM.
#: * ``decoder_unavailable`` 0 -> 1000. An undecodable object whose header and
#:   parser-derived length agree is worth more than a corrupt one; 1000 keeps
#:   it out of HIGH by construction, since 2000 + 1500 + 1000 + 1000 + 1500 +
#:   500 is 7500 even with every other component awarded.
#:
#: ``fs_metadata`` did **not** move, and is now stated explicitly rather than
#: inherited from the default, because it has finally been measured. The
#: filesystem calibration run swept it from 0 to 5000 over real NTFS, FAT32,
#: exFAT, ext2, ext3 and ext4 images and found two hard boundaries:
#:
#: * At **2000** a candidate that recovered *no bytes at all* reaches MEDIUM -
#:   a filename read out of NTFS ``$I30`` slack whose content is gone. A report
#:   must not give an examiner a middling confidence in a file it did not
#:   recover.
#: * At **4000** the component alone carries a candidate no decoder confirmed
#:   into HIGH: 2000 header + 1500 derived length + 500 no-overlap + 4000 is
#:   exactly the 8000 floor with a decoder verdict of *corrupt*.
#:
#: Below 2000 the sweep is flat - HIGH precision stays at 100.0% and the bucket
#: contents do not change - so the measurement bounds the weight from above and
#: says nothing from below. 1500 is therefore retained as the largest value the
#: evidence permits. Raising it to 5000 makes the aggregate numbers look
#: *better* (96.0% precision, 93.8% recall) by promoting three hundred
#: correctly recovered filler files, while simultaneously scoring HIGH a FAT32
#: recovery the corpus knows is wrong. That is the trap this component exists
#: to avoid: a filesystem record agreeing that a file lived at an offset says
#: nothing about whether the bytes there now are that file.
CALIBRATED_WEIGHTS = ScoreWeights(
    decoder_valid=4000,
    decoder_truncated=1000,
    decoder_unavailable=1000,
    fs_metadata=1500,
)

WEIGHTS = CALIBRATED_WEIGHTS


@dataclass(frozen=True)
class ScoreEvidence:
    """What was established about a candidate, before any weight is applied."""

    header_match: bool = False
    exact_length: bool = False
    decoder: Literal["valid", "truncated", "corrupt", "decoder_unavailable"] = (
        "decoder_unavailable"
    )
    entropy_matches: bool = False
    fs_corroborated: bool = False
    overlapped: bool = False
    #: The object was rebuilt from separate runs across a gap the medium does
    #: not describe, so its layout is inferred.
    reassembled: bool = False
    #: Mean entropy in thousandths of a bit per byte, or None if not measured.
    entropy_millibits: int | None = None
    #: Share of windows at or above the high-entropy floor, in basis points.
    high_windows_bp: int | None = None


def measure_entropy(
    data: bytes, *, window: int = ENTROPY_WINDOW_BYTES
) -> tuple[int, int]:
    """Return ``(mean entropy in millibits/byte, share of high windows in bp)``.

    Shannon entropy over each window, averaged. Windows rather than one figure
    over the whole object, because the shape matters: a JPEG header glued to a
    text file averages out to something unremarkable, while its window profile
    is unmistakably text.
    """
    if not data:
        return 0, 0
    totals = 0.0
    windows = 0
    high = 0
    for start in range(0, len(data), window):
        chunk = data[start : start + window]
        if not chunk:
            break
        size = len(chunk)
        entropy = 0.0
        # Counter tallies a bytes object in C. The histogram this replaced was
        # a pure-Python ``for byte in chunk`` loop, and it was 236.5 s of a
        # 249.9 s profiled carve. The returned value is unchanged: the same
        # counts, the same logarithms, the same rounding - a byte that never
        # occurred contributed nothing to the sum before and is absent now.
        for count in Counter(chunk).values():
            share = count / size
            entropy -= share * math.log2(share)
        millibits = int(round(entropy * 1000))
        totals += millibits
        windows += 1
        if millibits >= HIGH_ENTROPY_MILLIBITS:
            high += 1
    if windows == 0:  # pragma: no cover - unreachable for non-empty data
        return 0, 0
    return int(round(totals / windows)), int(round(high * 10_000 / windows))


def _entropy_matches(ext: str, mean_millibits: int, high_windows_bp: int) -> bool:
    """Whether the measured profile is what this format produces."""
    profile = ENTROPY_PROFILES.get(ext.lower(), "mixed")
    if profile == "high":
        return high_windows_bp >= HIGH_WINDOW_SHARE_BP
    if profile == "low":
        return mean_millibits < LOW_ENTROPY_MILLIBITS
    return mean_millibits >= MIXED_ENTROPY_FLOOR_MILLIBITS


def _header_match(data: bytes, ext: str, signatures: Sequence[Signature]) -> bool:
    """True when a signature for ``ext`` sits exactly where the object starts."""
    wanted = {ext, HEADER_FAMILY.get(ext, ext)}
    for signature in signatures:
        if signature.ext not in wanted:
            continue
        at = signature.header_offset
        if data[at : at + len(signature.header)] == signature.header:
            return True
    return False


def _has_exact_length(candidate: CarveCandidate) -> bool:
    """Whether the end of the object was derived rather than guessed.

    A structure-carved candidate's length came from the format's own length
    fields. A signature-carved one is exact only when a footer was found, which
    the scanner records by leaving ``possibly_fragmented`` False. A candidate
    from filesystem metadata carries the recorded size.
    """
    if candidate.source == "structure":
        return candidate.validation in {"valid", "decoder_unavailable"}
    if candidate.source == "fs_metadata":
        return True
    return not candidate.possibly_fragmented


def gather_evidence(
    candidate: CarveCandidate,
    *,
    data: bytes | None = None,
    image: EvidenceHandle | None = None,
    signatures: Sequence[Signature] | None = None,
) -> ScoreEvidence:
    """Establish each component's premise from the candidate and its bytes.

    Without bytes - no ``data`` and no ``image`` - the header and entropy
    components cannot be established and are not awarded. That is deliberate:
    an unmeasured component scores zero rather than being assumed.
    """
    payload = data
    if payload is None and image is not None:
        payload = _read_candidate(candidate, image)

    entropy_millibits: int | None = candidate.entropy_millibits_per_byte
    high_windows_bp: int | None = candidate.high_entropy_windows_bp
    header_match = False
    if payload is not None:
        table = list(signatures) if signatures is not None else load_signatures()
        header_match = _header_match(payload, candidate.ext, table)
        entropy_millibits, high_windows_bp = measure_entropy(payload)

    entropy_matches = False
    if entropy_millibits is not None and high_windows_bp is not None:
        entropy_matches = _entropy_matches(
            candidate.ext, entropy_millibits, high_windows_bp
        )
    if payload is not None and not payload:
        # Zero bytes measure as zero bits per byte, which clears the floor for
        # every "low entropy" format and awarded the component to a candidate
        # that recovered nothing at all. An unmeasurable component scores zero;
        # it does not score full marks for being empty. Found by the
        # filesystem calibration run: a name recovered from NTFS $I30 slack,
        # with no content behind it, was being handed the entropy component and
        # pushed towards MEDIUM.
        entropy_matches = False
        entropy_millibits = None
        high_windows_bp = None

    return ScoreEvidence(
        header_match=header_match,
        exact_length=_has_exact_length(candidate),
        decoder=candidate.validation,
        entropy_matches=entropy_matches,
        fs_corroborated=candidate.source == "fs_metadata",
        overlapped=candidate.overlapped,
        reassembled=bool(candidate.fragments),
        entropy_millibits=entropy_millibits,
        high_windows_bp=high_windows_bp,
    )


def score_from_evidence(
    evidence: ScoreEvidence, *, weights: ScoreWeights = WEIGHTS
) -> dict[str, int]:
    """Return the per-component basis points for ``evidence``.

    Components are always present, including the ones worth zero: a report that
    lists ``entropy: 0`` says the check ran and failed, while a missing key
    would leave a reader guessing whether it ran at all.
    """
    decoder_points = {
        "valid": weights.decoder_valid,
        "truncated": weights.decoder_truncated,
        "corrupt": 0,
        # No verdict is not a verdict of "bad". It scores well below a real
        # decode, which caps the candidate below HIGH without condemning it.
        "decoder_unavailable": weights.decoder_unavailable,
    }[evidence.decoder]

    components = {
        "header": weights.header if evidence.header_match else 0,
        "exact_length": weights.exact_length if evidence.exact_length else 0,
        "decoder": decoder_points,
        "entropy": weights.entropy if evidence.entropy_matches else 0,
        "fs_metadata": weights.fs_metadata if evidence.fs_corroborated else 0,
        "no_overlap": 0 if evidence.overlapped else weights.no_overlap,
        "reassembly": 0,
    }
    if evidence.reassembled:
        components["reassembly"] = _reassembly_ceiling(components)
    return components


def _reassembly_ceiling(components: dict[str, int]) -> int:
    """What holds a reassembled object's total at :data:`REASSEMBLED_CEILING_BP`.

    Zero when the other components already come to less. Never positive.
    """
    others = sum(value for name, value in components.items() if name != "reassembly")
    return min(0, REASSEMBLED_CEILING_BP - others)


def bucket_for(confidence_bp: int) -> Literal["HIGH", "MEDIUM", "LOW"]:
    """HIGH at 8000 and above, MEDIUM from 5000, LOW below that."""
    if confidence_bp >= HIGH_BUCKET_FLOOR_BP:
        return "HIGH"
    if confidence_bp >= MEDIUM_BUCKET_FLOOR_BP:
        return "MEDIUM"
    return "LOW"


def score_candidate(
    candidate: CarveCandidate,
    *,
    data: bytes | None = None,
    image: EvidenceHandle | None = None,
    signatures: Sequence[Signature] | None = None,
    weights: ScoreWeights = WEIGHTS,
) -> CarveCandidate:
    """Return ``candidate`` with ``confidence_bp`` and ``bucket`` populated."""
    evidence = gather_evidence(
        candidate, data=data, image=image, signatures=signatures
    )
    components = score_from_evidence(evidence, weights=weights)
    total = max(0, min(10_000, sum(components.values())))

    logger.debug(
        "candidate.scored",
        offset=candidate.offset,
        ext=candidate.ext,
        confidence_bp=total,
        components=components,
    )
    return candidate.model_copy(
        update={
            "confidence_bp": total,
            "bucket": bucket_for(total),
            "score_components": components,
            "entropy_millibits_per_byte": evidence.entropy_millibits,
            "high_entropy_windows_bp": evidence.high_windows_bp,
        }
    )


def _overlaps(first: CarveCandidate, second: CarveCandidate) -> bool:
    return (
        first.offset < second.offset + second.length
        and second.offset < first.offset + first.length
    )


def resolve_overlaps(
    candidates: Sequence[CarveCandidate], *, weights: ScoreWeights = WEIGHTS
) -> list[CarveCandidate]:
    """Mark every candidate a higher-scoring one overlaps, and keep them all.

    Two candidates covering the same bytes cannot both be real objects, so the
    lower-scoring one loses its ``no_overlap`` component and is re-bucketed.
    It is *not* deleted: a suppressed candidate that later turns out to matter
    has to be visible to the examiner, together with a pointer to whichever
    candidate displaced it.

    Returned in offset order, which is the order a report reads them in.
    """
    ranked = sorted(
        candidates,
        key=lambda item: (-item.confidence_bp, -item.length, item.offset),
    )
    kept: list[CarveCandidate] = []
    resolved: list[CarveCandidate] = []
    for candidate in ranked:
        winner = next(
            (other for other in kept if _overlaps(candidate, other)),
            None,
        )
        if winner is None:
            kept.append(candidate)
            resolved.append(
                candidate.model_copy(
                    update={"overlapped": False, "overlaps_with": None}
                )
            )
            continue

        components = dict(candidate.score_components)
        if components:
            components["no_overlap"] = 0
            if candidate.fragments and "reassembly" in components:
                # The ceiling was computed with no_overlap awarded. Recompute it
                # so the component still says exactly what holds the total down.
                components["reassembly"] = _reassembly_ceiling(components)
            total = max(0, min(10_000, sum(components.values())))
        else:
            total = max(0, candidate.confidence_bp - weights.no_overlap)
        resolved.append(
            candidate.model_copy(
                update={
                    "overlapped": True,
                    "overlaps_with": winner.offset,
                    "confidence_bp": total,
                    "bucket": bucket_for(total),
                    "score_components": components,
                }
            )
        )
        logger.debug(
            "candidate.overlapped",
            offset=candidate.offset,
            winner_offset=winner.offset,
            confidence_bp=total,
        )
    return sorted(resolved, key=lambda item: (item.offset, item.length))


def _read_candidate(candidate: CarveCandidate, image: EvidenceHandle) -> bytes:
    out = bytearray()
    cursor = candidate.offset
    remaining = candidate.length
    while remaining > 0:
        piece = image.read(cursor, min(MIB, remaining))
        if not piece:
            break
        out += piece
        cursor += len(piece)
        remaining -= len(piece)
    return bytes(out)
