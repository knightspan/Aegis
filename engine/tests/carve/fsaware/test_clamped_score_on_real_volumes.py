"""The clamp is not hypothetical: it is what the demo screen shows.

A candidate the undelete pass named, whose length a parser derived, which a
decoder read end to end and whose byte distribution matches its format, scores
2000 + 1500 + 4000 + 1000 + 1500 + 500 = **10,500**. ``score_candidate`` clamps
that to 10000, so for this candidate - and only this kind - the stored total is
*not* the sum of its components.

This matters twice over:

* ``tests/api/test_carve_pipeline_scoring.py`` reconciles components against
  the stored total. It runs on a flat image, where nothing awards
  ``fs_metadata`` and no candidate passes 9000, so an unconditional equality
  passed there while being false for every volume below.
* The runbook's 2:15 beat puts exactly this candidate on screen. The UI now
  renders the raw total and names the clamp, rather than showing 10000 alone.

Built on the project's own corpus, unprivileged, no root.
"""

from __future__ import annotations

from pathlib import Path

from core.carve.classify import classify_candidate
from core.carve.evidence import open_evidence
from core.carve.fsaware import read_recovered, undelete_report
from core.carve.score import score_candidate
from core.carve.validate import validate_candidate
from testkit.generate_corpus import FilesystemCorpus

from .conftest import requires

#: Volumes whose undelete pass returns content a decoder can read whole. ext4
#: is deliberately absent: its extent tree is zeroed on unlink, so it recovers
#: essentially nothing and cannot reach this state at all.
_VOLUMES = ("ntfs.img", "fat32.img", "exfat.img", "ext2.img")


def _fully_corroborated(corpus_dir: Path, image: str) -> list[tuple[int, int, str]]:
    """Every undelete candidate that establishes all six components."""
    found: list[tuple[int, int, str]] = []
    with open_evidence(corpus_dir / image) as handle:
        for item in undelete_report(handle).files:
            data = read_recovered(handle, item)
            if not data:
                continue
            candidate = validate_candidate(item.candidate, data=data)
            candidate = classify_candidate(candidate, data=data)
            candidate = score_candidate(candidate, data=data, image=handle)
            if all(candidate.score_components[name] > 0 for name in
                   ("header", "exact_length", "decoder", "entropy",
                    "fs_metadata", "no_overlap")):
                found.append(
                    (
                        sum(candidate.score_components.values()),
                        candidate.confidence_bp,
                        candidate.bucket,
                    )
                )
    return found


@requires("ntfs", "fat32", "exfat", "ext2")
def test_a_real_volume_produces_a_candidate_whose_components_exceed_the_clamp(
    corpus: FilesystemCorpus, corpus_dir: Path
) -> None:
    """At least one volume reaches 10,500 raw. If none does, this test is stale."""
    reached = {
        image: _fully_corroborated(corpus_dir, image)
        for image in _VOLUMES
        if (corpus_dir / image).exists()
    }
    clamped = {
        image: rows
        for image, rows in reached.items()
        if any(raw > stored for raw, stored, _ in rows)
    }
    assert clamped, (
        "no volume produced a fully corroborated undelete candidate, so the "
        "clamp path is untested; the demo runbook claims this candidate is on "
        f"screen. Scored: {reached}"
    )
    for image, rows in clamped.items():
        for raw, stored, bucket in rows:
            assert raw == 10_500, f"{image}: unexpected raw total {raw}"
            assert stored == 10_000, f"{image}: stored {stored}, expected the clamp"
            assert bucket == "HIGH"


@requires("ntfs", "fat32", "exfat", "ext2")
def test_the_stored_total_is_always_the_clamped_sum(
    corpus: FilesystemCorpus, corpus_dir: Path
) -> None:
    """The reconciliation rule that holds on every volume, clamp or not."""
    for image in _VOLUMES:
        if not (corpus_dir / image).exists():
            continue
        with open_evidence(corpus_dir / image) as handle:
            for item in undelete_report(handle).files:
                data = read_recovered(handle, item)
                candidate = validate_candidate(item.candidate, data=data)
                candidate = classify_candidate(candidate, data=data)
                candidate = score_candidate(candidate, data=data, image=handle)
                raw = sum(candidate.score_components.values())
                assert candidate.confidence_bp == max(0, min(10_000, raw)), (
                    f"{image}: {candidate.original_name} stored "
                    f"{candidate.confidence_bp} against a raw sum of {raw}"
                )
