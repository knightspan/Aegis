"""Why the signature scan is *not* bounded to the unallocated map.

Bounding the carver to the regions no live file claims is the obvious
optimisation, and both the audit and this module's own docstring history
proposed it. It was measured before being implemented, and it **loses recall**,
so it was deliberately not done. This file is the measurement, kept as a test so
the decision cannot be quietly reversed by somebody who reasoned about it
instead.

Measured over the generated filesystem corpus (seed 0), comparing digests
recovered with the whole-image scan against digests recovered when carved
candidates are restricted to headers inside an unallocated extent:

    ntfs.img                DELTA  0
    ntfs-reused.img         DELTA  0
    fat32.img               DELTA -1
    fat32-neighbours.img    DELTA -1
    exfat.img               DELTA -1
    ext2/ext3/ext4.img      DELTA  0
    fat32-plain.img         DELTA  0
    two-partitions.img      DELTA  0
    damaged-*.img           DELTA  0
    quick-formatted.img     DELTA  0

Three real recoveries lost, none gained.

The reason is that "unallocated" is the filesystem's opinion about *now*, and a
carved object is evidence about *then*. A deleted file whose clusters have since
been handed to a live file sits in space the volume calls allocated; its bytes
are still there and the carver still finds them. Bounding the scan throws that
away by definition, and on FAT32 and exFAT - where deletion destroys the cluster
chain and the carver is doing the real work - that is exactly the population
being discarded.

The cost of not bounding is duplicate candidates for live files, which
``core.carve.classify.dedupe`` already removes downstream. Paying scan time to
keep recall is the correct trade for a forensic tool.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from api.carve_job import carve_generator
from core.carve.evidence import open_evidence
from core.carve.fsaware import undelete_report
from testkit.generate_corpus import FilesystemCorpus

from tests.carve.fsaware.conftest import requires

#: The images where restricting the carver to unallocated space provably loses a
#: recoverable digest. Named individually so a change in that set is visible.
LOSES_RECALL = ("fat32.img", "fat32-neighbours.img", "exfat.img")


def _in_any_extent(offset: int, extents: Any) -> bool:
    return any(
        item.offset <= offset < item.offset + item.length for item in extents
    )


def _carve(image: Path) -> dict[str, Any]:
    generator = carve_generator(
        image, undelete=True, carve_signatures=True, job_id="bounding", ledger=None
    )
    try:
        while True:
            next(generator)
    except StopIteration as stop:
        result: dict[str, Any] = stop.value
        return result


def _recall_both_ways(image: Path, wanted: set[str]) -> tuple[int, int]:
    """Digests recovered scanning the whole image, and bounded to unallocated."""
    result = _carve(image)
    with open_evidence(image) as handle:
        unallocated = undelete_report(handle).unallocated

    whole = {item["sha256"] for item in result["candidates"]}
    bounded = {
        item["sha256"]
        for item in result["candidates"]
        # The undelete pass is unaffected by a scan bound; only carved
        # candidates would be dropped.
        if item["source"] == "fs_metadata"
        or _in_any_extent(item["offset"], unallocated)
    }
    return len(wanted & whole), len(wanted & bounded)


@requires("fat32")
@pytest.mark.parametrize("image_name", LOSES_RECALL)
def test_bounding_the_scan_to_unallocated_space_loses_recall(
    corpus: FilesystemCorpus, corpus_dir: Path, image_name: str
) -> None:
    """The measurement that decided against the optimisation.

    If this ever stops failing to lose recall - that is, if the delta reaches
    zero on every one of these images - bounding becomes viable and the module
    docstring in ``api/carve_job.py`` should be revisited.
    """
    image = corpus_dir / image_name
    if not image.exists():
        pytest.skip(f"{image_name} was not built on this host")

    whole, bounded = _recall_both_ways(image, corpus.recoverable_digests())

    assert bounded < whole, (
        f"{image_name}: bounding no longer loses recall "
        f"(whole={whole}, bounded={bounded}). Re-evaluate the decision recorded "
        "in this module's docstring and in api/carve_job.py."
    )


@requires("ntfs")
def test_bounding_costs_nothing_on_ntfs(
    corpus: FilesystemCorpus, corpus_dir: Path
) -> None:
    """Stated for contrast, so the finding is not read as universal.

    On NTFS the MFT record survives deletion with its run list intact, so the
    undelete pass recovers the file and the carver is not what is doing the
    work. The loss is specific to filesystems that destroy the mapping.
    """
    image = corpus_dir / "ntfs.img"
    if not image.exists():
        pytest.skip("ntfs.img was not built on this host")

    whole, bounded = _recall_both_ways(image, corpus.recoverable_digests())

    assert bounded == whole


def test_the_pipeline_does_not_bound_the_scan() -> None:
    """Static guard: the scan is called without a range, on purpose.

    ``core.carve.signature.scan`` accepts ``start``/``end`` and this pipeline
    deliberately passes neither. A future change that starts passing them is
    reintroducing the recall loss measured above, and should have to delete
    this test to do it.
    """
    import api.carve_job as carve_job

    source = Path(carve_job.__file__).read_text(encoding="utf-8")
    # Whitespace-normalised, so wrapping the call across lines to stay inside
    # the line-length limit does not read as changing it. What this guard is
    # about is which arguments are passed, not how they are formatted.
    flattened = " ".join(source.split())

    # Batch 7 added one keyword argument, the undelete pass's cluster sizes,
    # which chooses the reassembly grid and bounds nothing. Re-checked: no
    # range is passed, which the assertion below still enforces.
    assert "carve_structures( handle, cluster_bytes_at=" in flattened, (
        "the carve call changed shape; re-check whether a range is now passed"
    )
    assert "start=" not in source and "end=" not in source, (
        "the scan is being bounded; see this module's docstring for the recall "
        "measurement that decided against it"
    )
