"""Score carving output against a corpus ground truth.

Compares recovered candidates to planted files and reports recall, precision and
per-bucket accuracy. Deferred to M3 evaluation work.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from core.models import CarveCandidate

__all__ = ["evaluate"]


def evaluate(
    candidates: Sequence[CarveCandidate], ground_truth_path: Path
) -> dict[str, float]:
    """Return metrics ``{"recall", "precision", "bucket_accuracy", ...}``."""
    raise NotImplementedError
