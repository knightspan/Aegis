"""The carve pipeline as a Progress generator, for the job registry.

:mod:`core.carve` exposes its stages as ordinary functions, which is right for
a library and wrong for a progress bar. This adapts them into one generator
that yields :class:`~core.models.Progress` at each stage boundary and returns
the finished candidate list, without any stage learning that a UI exists.

The order is the product's order and it is not arbitrary. Undelete runs first,
because it is the better evidence: a surviving filesystem record carries the
original name, the recorded size and the timestamps, and says where the bytes
were rather than inferring it from a header. Signature carving runs after it and
picks up what has no surviving metadata to be found by.

Carving goes through :func:`core.carve.structure.carve_structures`, which runs
the signature scan and then hands each hit to the parser for its format, so an
object's length is derived from the format's own length fields where a parser
exists - the ZIP central directory, the PDF xref, the JPEG segment walk, the
SQLite page count, the PNG chunk walk, the MP4 box walk - and falls back to the
footer bound where one does not. It is a replacement for
:func:`core.carve.signature.carve_signatures` and never an addition: it runs the
scan itself, so calling both would find every object twice.

This is also the call :mod:`testkit.calibrate` makes, which is what lets the
measured weights in :mod:`core.carve.score` describe the pipeline that actually
ships.

Three properties of this pipeline that are not what the module names suggest:

**The scan covers the whole image, not the unallocated regions only.** The
undelete pass produces an allocated/unallocated map and this generator reports
it, but it deliberately does not bound the scan with it. Bounding was measured
over the generated filesystem corpus and **loses recall**: on FAT32 and exFAT a
deleted file whose clusters have since been reallocated to a live file sits in
space the volume calls allocated, and its bytes are still there to be carved.
Three recoverable digests were lost and none gained. The cost of not bounding is
duplicate candidates for live files, which :func:`core.carve.classify.dedupe`
removes. See ``tests/carve/fsaware/test_unallocated_bounding.py``, which keeps
the measurement so the decision cannot be reversed by reasoning alone.

**The scan is single-process here.** :func:`carve_signatures` can split an image
across workers, but that entry point takes a path and ``carve_structures`` takes
an open handle and exposes no worker count. Parallel structure carving would
mean changing :mod:`core.carve.structure`, which is out of scope for the change
that wired it in.

**Bifragment reassembly fires, for a baseline JPEG in exactly two runs.**
``carve_structures`` does not trust ``parse_jpeg``'s verdict for a JPEG: a
segment walk cannot tell a contiguous object from head + gap + tail, because
entropy-coded data is arbitrary bytes and the walk steps over the gap to the
real EOI beyond it. The verdict is checked against
:func:`core.carve.fragmentation.is_whole_jpeg` and, for a baseline JPEG, against
:func:`~core.carve.fragmentation.scan_is_exact`, which counts the scan's MCUs
against the frame header - the check a decoder does not make, and the one that
tells a span with foreign bytes inside it from a whole file. A span that fails
goes to :func:`~core.carve.fragmentation.reassemble_bifragmented_jpeg_runs`.

A recovered object is **not a span**, so it does not pretend to be one. It
carries ``fragments`` - the image-absolute runs its content came from - and its
``sha256`` is the digest of those runs concatenated. This generator reads them
back through :func:`~core.carve.fragmentation.read_fragments` and hands the
bytes to the validator, the classifier, the scorer and the writer, exactly as it
already did for a filesystem file stored in several extents. Nothing downstream
sees ``offset``..``offset + length`` for one of these, because that span covers
the gap and hashes to something that was never a file.

The undelete pass supplies the cluster size of every volume it opened, and this
generator hands it to the carver: runs are sought only on that grid, because no
allocator produces any other layout. Outside every recognised volume, and when
``undelete`` is off, the search walks 512-byte sectors - still safe, since every
real layout lies on that grid, but slower and with less reach.

Scope, stated plainly: **one baseline JPEG in exactly two runs, both still on the
medium, with a gap of at most 2 MiB, on a volume whose cluster size is known.**
That is measured to come back byte for byte, and it is scored MEDIUM at most: the
``reassembly`` score component holds it one basis point under HIGH, because where
the gap was is inferred. Anything else - three fragments, a missing tail, a
progressive JPEG, a non-JPEG, a layout off the volume's grid, a join the bytes do
not settle - is reported as a candidate over the span the parser derived, with a
digest of bytes that really are there, and never as a recovery. Measured in
``tests/carve/signature/test_reassembly_fabrication.py``,
``tests/carve/signature/test_reassembly_cluster_size.py`` and
``tests/api/test_carve_fragment_recovery.py``; the reach figures are in
``docs/limitations.md``.

A recovery is ledgered like an erase, and for the same reason. An examiner is
asked to believe that these candidates came out of that image; without a
hash-chained record binding the two, the only evidence for it is the tool saying
so. ``carve.start`` records what was opened and ``carve.complete`` records what
came out, digest first.
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
from collections.abc import Callable, Generator
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog
from core.models import CarveCandidate, MediaMap, Progress

if TYPE_CHECKING:  # pragma: no cover - import cycle avoidance only
    from core.carve.evidence import EvidenceHandle
    from core.ledger.chain import Ledger

__all__ = [
    "carve_generator",
    "CARVE_PHASES",
    "IDENTITY_SAMPLE_BYTES",
    "SpillStore",
]

logger = structlog.get_logger(__name__)

#: Stage names, in execution order. The UI renders these as a stepper.
CARVE_PHASES = ("open", "map", "undelete", "signatures", "validate", "score", "write")

#: Bytes read from each end of the image to identify it in the ledger.
IDENTITY_SAMPLE_BYTES = 1024 * 1024


class SpillStore:
    """Candidate bytes on disk instead of in the process, for the whole run.

    Why this exists
    ---------------
    The pipeline holds bytes for every candidate whose content is **not** one
    span on the medium: a filesystem file stored in several extents, and a
    bifragmented JPEG reassembled across a gap. Those used to accumulate in a
    dictionary that lived for the length of the run, so a seven-gigabyte image
    with a few thousand fragmented objects put a few gigabytes of recovered
    content in the API process and kept it there until the carve returned. On a
    forensic image that is not a leak, it is the design being wrong at scale.

    Each payload is now written out as soon as it is produced and read back one
    at a time, so the pipeline's peak is **one object's bytes**, not the sum of
    every fragmented object's.

    What it guarantees
    ------------------
    * **Bounded memory.** :meth:`put` takes bytes and drops them; :meth:`get`
      returns exactly one payload to a caller that drops it before asking for
      the next. Nothing here holds a reference to a payload between calls.
    * **Deterministic naming.** The filename is the SHA-256 of
      ``"<source>:<offset>"``, so the same candidate lands on the same name on
      every run, and a name is never built from anything an evidence image
      supplied. A filesystem record's ``original_name`` comes off the seized
      disk and is never part of a path here.
    * **No traversal.** The name is 64 hex characters by construction. There is
      no separator to escape and no component to walk with, so confinement is a
      property of the naming rather than a check that could be forgotten.
    * **Cleanup on every exit.** :meth:`close` removes the directory, and
      :func:`carve_generator` calls it from a ``finally`` that covers the
      success path, the failure path and ``GeneratorExit`` - which is the
      cancel button. A cancelled carve leaves no spilled content behind.

    ``root`` is the API's own work directory, inside the configured state
    directory rather than the system temp directory: a deployment that confines
    everything the tool writes to one tree should not have this one exception,
    and an operator asking what the tool wrote should have one place to look.
    """

    def __init__(self, root: Path, *, job_id: str) -> None:
        root.mkdir(parents=True, exist_ok=True)
        # mkdtemp rather than a directory named after the job: two runs of the
        # same job id would otherwise share a directory, and the second one's
        # cleanup would delete the first one's spill.
        self.directory = Path(
            tempfile.mkdtemp(prefix=f"carve-{job_id}-", dir=str(root))
        )
        self._keys: set[tuple[str, int]] = set()

    @staticmethod
    def _name(key: tuple[str, int]) -> str:
        source, offset = key
        return hashlib.sha256(f"{source}:{offset}".encode()).hexdigest()

    def path_for(self, key: tuple[str, int]) -> Path:
        return self.directory / self._name(key)

    def put(self, key: tuple[str, int], payload: bytes) -> None:
        """Spill one candidate's bytes and forget them."""
        self.path_for(key).write_bytes(payload)
        self._keys.add(key)

    def has(self, key: tuple[str, int]) -> bool:
        return key in self._keys

    def get(self, key: tuple[str, int]) -> bytes | None:
        """Read one payload back, or ``None`` if it was never spilled."""
        if key not in self._keys:
            return None
        try:
            return self.path_for(key).read_bytes()
        except OSError:
            return None

    def copy_to(self, key: tuple[str, int], destination: Path) -> int:
        """Copy a spilled payload to its recovered-object path, streaming.

        ``shutil.copyfile`` rather than ``write_bytes(get(key))``: the write
        phase would otherwise reload every fragmented object into memory at the
        exact moment the run is at its largest.
        """
        shutil.copyfile(self.path_for(key), destination)
        return destination.stat().st_size

    def __len__(self) -> int:
        return len(self._keys)

    def close(self) -> None:
        """Remove the spill directory. Safe to call more than once."""
        shutil.rmtree(self.directory, ignore_errors=True)
        self._keys.clear()


def _identity_digest(handle: EvidenceHandle) -> dict[str, Any]:
    """A cheap identifier for the evidence this run read.

    **This is not a full-image hash and is not offered as one.** Hashing seven
    gigabytes before every carve would put minutes on the front of an
    interactive job, and the tool already has a place where the whole image is
    hashed: acquisition, whose manifest ``verify_integrity`` re-checks
    deliberately.

    What this does establish is that two ledger entries naming the same path
    read the same bytes at both ends of the same length, which is what catches
    an image swapped between runs. The covered ranges are recorded alongside the
    digest so nobody has to guess at what it spans.
    """
    span = min(IDENTITY_SAMPLE_BYTES, handle.size)
    digest = hashlib.sha256()
    digest.update(handle.size.to_bytes(8, "big"))
    digest.update(handle.read(0, span))
    if handle.size > span:
        digest.update(handle.read(handle.size - span, span))
    return {
        "sha256": digest.hexdigest(),
        "covers": f"first and last {span} bytes, and the length",
        "is_whole_image_hash": False,
    }


def _progress(
    job_id: str, phase: str, pct_bp: int, message: str, *, done: int = 0, total: int = 0
) -> Progress:
    return Progress(
        job_id=job_id,
        phase=phase,
        pct_bp=pct_bp,
        bytes_done=done,
        bytes_total=total,
        throughput_bytes_per_sec=0,
        eta_seconds=0,
        message=message,
    )


def _map_stage(
    handle: EvidenceHandle, *, job_id: str
) -> Generator[Progress, None, MediaMap]:
    """The media map, its progress scaled into the first 5% of the run."""
    from core.carve.mediamap import map_media

    stage = map_media(handle, job_id=job_id)
    try:
        while True:
            step = next(stage)
            yield step.model_copy(
                update={"phase": "map", "pct_bp": step.pct_bp * 500 // 10_000}
            )
    except StopIteration as stop:
        result: MediaMap = stop.value
        return result


def _cluster_lookup(
    volumes: list[tuple[int, int, int]],
) -> Callable[[int], int | None]:
    """Offset -> cluster size of the volume holding it, ``None`` outside every one.

    ``None`` is what an unrecognised region and a run with ``undelete=False``
    both get: the reassembler then walks the 512-byte sector grid, which costs
    search time and never admits a join the volume's own grid would refuse.
    """

    def cluster_bytes_at(offset: int) -> int | None:
        for start, end, size in volumes:
            if start <= offset < end:
                return size
        return None

    return cluster_bytes_at


def _triage(
    candidate: CarveCandidate, payload: bytes | None, handle: EvidenceHandle
) -> CarveCandidate:
    """Attach PII counts to ``candidate``. Counts and kinds only, never values.

    ``payload`` is the candidate's bytes when the loop already holds them. An
    object above the in-memory budget is scanned through the read-only handle
    in windows when its type is scanned as raw bytes; a container that large
    is not scanned, and says so.
    """
    from core.carve.pii import scan_content
    from core.models import PiiFindings

    def read(offset: int, size: int) -> bytes:
        return handle.read(candidate.offset + offset, size)

    scan = scan_content(
        payload,
        ext=candidate.ext,
        category=candidate.category,
        length=candidate.length,
        read=read if payload is None and not candidate.fragments else None,
    )
    return candidate.model_copy(
        update={
            "pii": PiiFindings(
                inspected=scan.inspected, basis=scan.basis, counts=scan.counts
            )
        }
    )


def carve_generator(
    image: Path,
    *,
    undelete: bool = True,
    carve_signatures: bool = True,
    out_dir: Path | None = None,
    job_id: str = "carve",
    ledger: Ledger | None = None,
    operator: str = "sanctum",
    pii_triage: bool = True,
    work_dir: Path | None = None,
    case_id: str = "",
    media_map: bool = True,
) -> Generator[Progress, None, dict[str, Any]]:
    """Run the recovery pipeline over ``image``, yielding progress per stage.

    Args:
        ledger: Where the run is recorded. ``None`` runs unledgered, which is
            for tests and for library callers; the API always passes one,
            because a recovery nobody can audit is not evidence.
        operator: Recorded as the ledger actor.
        pii_triage: Count identity and financial identifiers in each object
            of a scanned category (:mod:`core.carve.pii`). Kinds and counts
            only; no value is kept anywhere.
        work_dir: Where candidate bytes are spilled instead of being held in
            memory for the length of the run. See :class:`SpillStore`. ``None``
            falls back to the system temp directory, which is for library
            callers; the API passes its own work directory so everything the
            tool writes stays inside the configured state tree.
        case_id: Recorded in this run's chain entries so the case screen can
            find them. Empty means the run is not filed against a case, which
            is legal and is what a quick look at an image is.
        media_map: Class every region of the image by its byte statistics
            before anything else runs (:mod:`core.carve.mediamap`): where the
            zeros, fills, text and high-entropy data are, and where the file
            headers sit. Bounded by its own read budget, so a large image is
            sampled rather than read twice in full.
    """
    from core.carve.classify import _read_candidate as read_span
    from core.carve.classify import (
        classify_candidate,
        dedupe,
        output_filename,
        write_recovered,
    )
    from core.carve.evidence import open_evidence
    from core.carve.fragmentation import read_fragments
    from core.carve.score import resolve_overlaps, score_candidate
    from core.carve.structure import carve_structures
    from core.carve.validate import MAX_VALIDATE_BYTES, validate_candidate

    candidates: list[CarveCandidate] = []
    limitations: list[str] = []
    partitions: list[dict[str, Any]] = []
    unallocated_bytes = 0
    # Bytes for candidates that offset..offset+length does not describe: a
    # filesystem file stored in several extents, and a bifragmented JPEG the
    # carver reassembled across a gap. Keyed by (source, offset) because an
    # undelete record and a carved header can legitimately land on the same
    # offset and mean different objects.
    #
    # Spilled to disk rather than held: this used to be a dict of bytes that
    # lived for the whole run, which put every fragmented object's content in
    # the process at once. See SpillStore.
    payloads = SpillStore(
        Path(work_dir) if work_dir is not None else Path(tempfile.gettempdir()),
        job_id=job_id,
    )
    # (start, end, cluster bytes) for every volume whose filesystem the undelete
    # pass opened. The carver has no filesystem context of its own, and a
    # reassembled object's runs can only be on its volume's cluster grid.
    volumes: list[tuple[int, int, int]] = []
    # What a cancellation has to report, kept current as the stages run. See
    # _record_cancelled_carve.
    written: list[str] = []
    phase_reached = "open"
    bytes_scanned = 0
    mapped: MediaMap | None = None

    try:
        with open_evidence(image) as handle:
            evidence = {
                "path": str(image),
                "size_bytes": handle.size,
                "format": type(handle).__name__,
                "identity": _identity_digest(handle),
            }
            if ledger is not None:
                ledger.append(
                    actor=operator,
                    operation="carve.start",
                    params={
                        "job_id": job_id,
                        "case_id": case_id,
                        "evidence": evidence,
                        "undelete": undelete,
                        "carve_signatures": carve_signatures,
                        "pii_triage": pii_triage,
                        "out_dir": str(out_dir) if out_dir else "",
                        # Recorded because it changes what the run could have done,
                        # not merely what it did: without an output directory the
                        # pipeline lists candidates and writes nothing.
                        "writes_recovered_objects": out_dir is not None,
                    },
                    result={},
                )

            try:
                phase_reached = "open"
                yield _progress(
                    job_id, "open", 0, f"opened {image.name} ({handle.size} bytes)",
                    total=handle.size,
                )

                if media_map:
                    mapped = yield from _map_stage(handle, job_id=job_id)
                    limitations.extend(mapped.limitations)
                    if ledger is not None:
                        ledger.append(
                            actor=operator,
                            operation="carve.mediamap",
                            params={
                                "job_id": job_id,
                                "case_id": case_id,
                                "evidence_identity": evidence["identity"],
                                "regions": len(mapped.regions),
                                "region_bytes": mapped.region_bytes,
                                "sampled": mapped.sampled,
                                "bytes_read": mapped.bytes_read,
                                "by_kind": mapped.by_kind,
                                "headers": mapped.headers,
                            },
                            result={},
                        )
                    phase_reached = "map"

                if undelete:
                    from core.carve.fsaware import read_recovered, undelete_report

                    report = undelete_report(handle)
                    limitations.extend(report.limitations)
                    partitions = [
                        {
                            "index": item.index,
                            "offset": item.offset,
                            "length": item.length,
                            "description": item.description,
                            "fs_type": item.fs_type,
                            "cluster_bytes": item.cluster_bytes,
                        }
                        for item in report.partitions
                    ]
                    volumes = [
                        (item.offset, item.offset + item.length, item.cluster_bytes)
                        for item in report.partitions
                        if item.cluster_bytes
                    ]
                    unallocated_bytes = sum(item.length for item in report.unallocated)
                    for item in report.files:
                        # Written out and dropped inside the loop, so the peak is
                        # one recovered file rather than every recovered file.
                        payloads.put(
                            (item.candidate.source, item.candidate.offset),
                            read_recovered(handle, item),
                        )
                        candidates.append(item.candidate)
                    phase_reached = "undelete"
                    yield _progress(
                        job_id,
                        "undelete",
                        3000,
                        f"{len(report.files)} entries from filesystem metadata; "
                        f"{unallocated_bytes} bytes unallocated",
                        total=handle.size,
                    )

                if carve_signatures:
                    # carve_structures runs the signature scan itself and then hands
                    # each hit to the parser for its format, so this is a replacement
                    # for carve_signatures and never an addition to it: calling both
                    # would find every object twice. A hit whose format has no parser,
                    # or whose parse declines, is yielded unchanged with
                    # source="signature", so nothing the signature carver found is
                    # lost by going through here.
                    #
                    # This is the same call testkit/calibrate.py makes, which is what
                    # makes the measured weights in core/carve/score.py describe the
                    # pipeline the product actually runs.
                    carved = list(
                        carve_structures(
                            handle, cluster_bytes_at=_cluster_lookup(volumes)
                        )
                    )
                    # One uninterrupted pass with no yield inside it: by the time this
                    # line runs the scan covered the whole image, and before it, none.
                    bytes_scanned = handle.size
                    candidates.extend(carved)
                    derived = sum(1 for item in carved if item.source == "structure")
                    # A reassembled bifragmented object is two runs with a gap between
                    # them, so its bytes cannot be re-read from offset..offset+length
                    # either. read_fragments walks the runs the carver recorded, which
                    # are the same runs its sha256 was computed over.
                    reassembled_count = 0
                    for rebuilt in carved:
                        if rebuilt.fragments:
                            payloads.put(
                                (rebuilt.source, rebuilt.offset),
                                read_fragments(handle, rebuilt.fragments),
                            )
                            reassembled_count += 1
                    phase_reached = "signatures"
                    yield _progress(
                        job_id,
                        "signatures",
                        6000,
                        f"{len(carved)} candidates over {handle.size} bytes; "
                        f"{derived} had their length derived by a format parser; "
                        f"{reassembled_count} reassembled across a fragment gap",
                        done=handle.size,
                        total=handle.size,
                    )

                judged: list[CarveCandidate] = []
                for index, candidate in enumerate(candidates):
                    recovered_bytes = payloads.get((candidate.source, candidate.offset))
                    # Read back one at a time and dropped at the bottom of the
                    # loop body, which is what keeps the pipeline's peak at one
                    # object rather than the whole spill.
                    # Candidates whose content is not one span carry their bytes here:
                    # fs_metadata files stored in several extents (see
                    # core.carve.fsaware.read_recovered) and structure candidates
                    # reassembled across a fragment gap. Judging them from
                    # offset..offset+length would hand every decoder the right length
                    # of the wrong bytes.
                    shared: bytes | None
                    if recovered_bytes is not None:
                        shared = recovered_bytes
                        scored = validate_candidate(candidate, data=recovered_bytes)
                    else:
                        # Read once and shared by the classifier, the scorer and PII
                        # triage, which each used to read the span for themselves.
                        # validate_candidate still reads its own copy: passing data
                        # tells it the object is not one span, which would change
                        # what it reports about absent MPF frames.
                        shared = (
                            read_span(candidate, handle)
                            if candidate.length <= MAX_VALIDATE_BYTES
                            else None
                        )
                        scored = validate_candidate(candidate, handle)
                    if shared is not None:
                        scored = classify_candidate(scored, data=shared)
                        scored = score_candidate(scored, data=shared)
                    else:
                        scored = classify_candidate(scored, image=handle)
                        scored = score_candidate(scored, image=handle)
                    if pii_triage:
                        scored = _triage(scored, shared, handle)
                    # Dropped before the next candidate is read: the loop never
                    # holds more than one object's bytes.
                    shared = None
                    judged.append(scored)
                    if index % 25 == 0:
                        phase_reached = "validate"
                        yield _progress(
                            job_id,
                            "validate",
                            6000 + 2000 * index // max(len(candidates), 1),
                            f"validated {index}/{len(candidates)}",
                            total=handle.size,
                        )

                resolved = dedupe(resolve_overlaps(judged))
                phase_reached = "score"
                yield _progress(
                    job_id, "score", 9000, f"{len(resolved)} candidates after dedupe",
                    total=handle.size,
                )

                if out_dir is not None:
                    # Candidates whose bytes travelled with them are written here:
                    # write_recovered re-reads offset..offset+length, which is the
                    # wrong bytes for a file the filesystem stored in several extents.
                    reassembled = [
                        item
                        for item in resolved
                        if payloads.has((item.source, item.offset))
                    ]
                    contiguous = [
                        item
                        for item in resolved
                        if not payloads.has((item.source, item.offset))
                    ]

                    out_dir.mkdir(parents=True, exist_ok=True)
                    for candidate in reassembled:
                        name = output_filename(candidate)
                        try:
                            destination = out_dir / name
                            # Streamed from the spill file rather than reloaded:
                            # the write phase is where the old design peaked.
                            payloads.copy_to(
                                (candidate.source, candidate.offset), destination
                            )
                            written.append(str(destination))
                        except OSError as exc:
                            limitations.append(
                                f"Recovered object {name} could not be written: {exc}"
                            )
                    try:
                        for record in write_recovered(contiguous, handle, out_dir):
                            written.append(str(record["path"]))
                    except (OSError, ValueError) as exc:
                        limitations.append(
                            f"Recovered objects could not be written: {exc}"
                        )

                    phase_reached = "write"
                    yield _progress(
                        job_id, "write", 10_000, f"wrote {len(written)} objects",
                        total=handle.size,
                    )
            except GeneratorExit:
                # The caller closed this generator: an operator pressed Cancel, or
                # the client went away. Every stage stops at a yield, so no object
                # is half-written - but objects already in out_dir are on disk, and
                # carve.start is in the chain with nothing after it. Recorded before
                # the exception continues, for the reason acquire.cancelled is
                # (core/carve/acquire.py): output nobody can account for is worse
                # than no output.
                #
                # No progress is yielded here and none can be: a generator that
                # yields while closing raises RuntimeError.
                if ledger is not None:
                    _record_cancelled_carve(
                        ledger,
                        job_id=job_id,
                        operator=operator,
                        evidence=evidence,
                        phase_reached=phase_reached,
                        bytes_scanned=bytes_scanned,
                        raw_candidates=len(candidates),
                        out_dir=out_dir,
                        written=written,
                    )
                raise

        logger.info(
            "carve_complete",
            image=str(image),
            candidates=len(resolved),
            written=len(written),
        )
        serialised = [item.model_dump(mode="json") for item in resolved]

        if ledger is not None:
            from core.ledger.canon import canonical_bytes

            buckets: dict[str, int] = {}
            for candidate in resolved:
                buckets[candidate.bucket] = buckets.get(candidate.bucket, 0) + 1
            # The digest covers the candidate list itself, so a report quoting these
            # findings can be checked against the entry rather than trusted. Counts
            # alone would let the list be edited without breaking anything.
            findings_sha256 = hashlib.sha256(
                canonical_bytes({"candidates": serialised})
            ).hexdigest()
            ledger.append(
                actor=operator,
                operation="carve.complete",
                params={
                    "job_id": job_id,
                    "case_id": case_id,
                    "evidence": evidence,
                    "candidates": len(resolved),
                    "by_confidence": buckets,
                    "partitions": len(partitions),
                    "unallocated_bytes": unallocated_bytes,
                    "written": len(written),
                    "limitations": limitations,
                },
                result={"findings_sha256": findings_sha256},
            )

        return {
            "image": str(image),
            "evidence": evidence,
            "candidates": serialised,
            "partitions": partitions,
            "unallocated_bytes": unallocated_bytes,
            "written": written,
            "limitations": limitations,
            "media_map": mapped.model_dump(mode="json") if mapped else None,
        }
    finally:
        # Covers the success path, any exception, and GeneratorExit - which is
        # the Cancel button. A cancelled or failed carve leaves no spilled
        # recovered content behind, which matters more here than in an ordinary
        # temp-file cleanup: the spill holds content carved out of evidence.
        payloads.close()


def _record_cancelled_carve(
    ledger: Ledger,
    *,
    job_id: str,
    operator: str,
    evidence: dict[str, Any],
    phase_reached: str,
    bytes_scanned: int,
    raw_candidates: int,
    out_dir: Path | None,
    written: list[str],
) -> None:
    """Append the entry that says what a cancelled carve left on disk.

    The same discipline as ``acquire.cancelled``: name the artifacts, give the
    numbers, and publish nothing that attests to more than was done.
    ``carve.complete`` carries ``findings_sha256``, a digest over the final
    candidate list that a report's findings can be checked against. A cancelled
    run has no final list, so it gets no digest - a digest over whatever list
    existed at the moment of cancellation would be checkable, and would check
    out, and would still describe something that is not the result of a carve.
    """
    size = int(evidence.get("size_bytes") or 0)
    if written:
        output = (
            f"{len(written)} recovered object(s) had already been written to "
            f"{out_dir} and are listed in objects_written. They are genuine "
            "output of this run, but not a complete recovery. "
        )
    elif out_dir is None:
        output = "No output directory was requested, so nothing was written. "
    else:
        output = f"No recovered object had been written to {out_dir}. "
    ledger.append(
        actor=operator,
        operation="carve.cancelled",
        params={
            "job_id": job_id,
            "evidence": evidence,
            "phase_reached": phase_reached,
            "bytes_scanned": bytes_scanned,
            "bytes_total": size,
            # Before validation, scoring and dedupe: a count of what the stages
            # had found, not a count of findings.
            "raw_candidates_before_dedupe": raw_candidates,
            "out_dir": str(out_dir) if out_dir else "",
            "objects_written": list(written),
            "objects_written_count": len(written),
            "note": (
                f"CANCELLED CARVE: the run over {evidence.get('path', '')} was "
                f"cancelled after its '{phase_reached}' stage. The signature "
                f"scan covered {bytes_scanned} of {size} bytes; it is a single "
                "pass, so it either covered the whole image or had not run. "
                + output
                + "No findings_sha256 is recorded: that digest attests to a "
                "finished candidate list, and this run did not produce one. Do "
                "not report this run's output as coverage of the image."
            ),
        },
        result={},
    )
