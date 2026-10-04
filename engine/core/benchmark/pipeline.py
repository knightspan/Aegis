"""Score, evaluate, seal, write and ledger one run: the one path every caller takes.

The CLI (``python -m core.benchmark score``) and the physical harness
(``scripts/media_benchmark.py score``) both call :func:`score_and_record`, so a
physical result and a synthetic one are produced by identical code and differ
only in their manifest.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog

from core.benchmark.manifest import GroundTruthManifest
from core.benchmark.result import (
    BenchmarkResult,
    ToolIdentity,
    append_result_to_ledger,
    build_result,
    sanctum_version,
    write_result,
)
from core.benchmark.rule import Baseline, evaluate_rule, read_baseline
from core.benchmark.score import score_manifest

__all__ = [
    "DEFAULT_BASELINE_CSV",
    "read_buckets",
    "tool_identity",
    "score_and_record",
]

logger = structlog.get_logger(__name__)

#: The checked-in synthetic baseline, present in a source checkout only.
DEFAULT_BASELINE_CSV = (
    Path(__file__).resolve().parents[2] / "docs" / "performance" / "benchmark.csv"
)


def read_buckets(path: Path | None) -> dict[str, str] | None:
    """Output file name to confidence bucket, from Sanctum's run record.

    ``None`` when there is no record, which the HIGH observation reports as
    unavailable rather than as zero.
    """
    if path is None or not path.is_file():
        return None
    try:
        loaded: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    objects = loaded.get("objects") if isinstance(loaded, dict) else None
    if not isinstance(objects, list):
        return None
    return {
        str(item["file"]): str(item["bucket"])
        for item in objects
        if isinstance(item, dict) and "file" in item and "bucket" in item
    }


def tool_identity(
    name: str, *, version: str | None = None, run_meta: Mapping[str, Any] | None = None
) -> ToolIdentity:
    """Who produced the outputs. Floats from the run record become integer ms."""
    if version is None:
        version = (
            f"sanctum-forensics/{sanctum_version()}"
            if name.startswith("sanctum")
            else "not recorded"
        )
    meta = run_meta or {}
    seconds = meta.get("seconds")
    return ToolIdentity(
        name=name,
        version=version,
        returncode=int(meta["returncode"]) if "returncode" in meta else None,
        timed_out=bool(meta["timed_out"]) if "timed_out" in meta else None,
        run_ms=round(float(seconds) * 1000) if seconds is not None else None,
    )


def score_and_record(
    manifest: GroundTruthManifest,
    outputs: Path,
    *,
    out: Path,
    tool: ToolIdentity,
    payloads: Path | None = None,
    image: Path | None = None,
    buckets: Mapping[str, str] | None = None,
    baseline_csv: Path | None = DEFAULT_BASELINE_CSV,
    key: Path | None = None,
    passphrase: str | None = None,
    ledger_root: Path | None = None,
    created: datetime | None = None,
) -> BenchmarkResult:
    """Score ``outputs`` against a sealed manifest and write the sealed result.

    The baseline is read from ``baseline_csv`` before the rule is applied; a
    missing baseline makes the rule ``NOT_EVALUATED`` with the reason, never a
    silent pass.
    """
    score = score_manifest(
        manifest, outputs, payloads=payloads, image=image, buckets=buckets
    )
    baseline: Baseline | None = None
    problem = ""
    if baseline_csv is None:
        problem = "no baseline file was given"
    else:
        try:
            baseline = read_baseline(baseline_csv)
        except (OSError, LookupError, KeyError, ValueError) as failure:
            problem = f"the registered baseline could not be read: {failure}"
    rule = evaluate_rule(
        manifest.kind,
        exact=score.counts.exact,
        full=score.counts.full,
        baseline=baseline,
        image_name=manifest.image_name,
        baseline_problem=problem,
    )
    result = build_result(
        manifest,
        score,
        rule,
        tool=tool,
        created=created,
        key=key,
        passphrase=passphrase,
    )
    write_result(result, out)
    if ledger_root is not None:
        append_result_to_ledger(result, ledger_root, key=key, passphrase=passphrase)
    logger.info(
        "benchmark_result_written",
        path=str(out),
        digest=result.result_digest,
        ledgered=ledger_root is not None,
    )
    return result
