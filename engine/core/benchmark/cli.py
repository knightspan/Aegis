"""``python -m core.benchmark``: manifest, score, verify, summarize.

    manifest synthetic   seal ground truth for a built image, scored directly
    manifest physical    seal ground truth for the physical harness work dir
    score                score recovered outputs against a sealed manifest
    verify               re-check manifest and result digests and signatures
    summarize            aggregate results per kind; report physical status

Every command reads files and writes new ones. None opens a device. Output is
JSON on stdout. Exit status: 0 success, 1 a verification found a problem, 2 a
refusal (tampered or invalid input, mixed kinds, an existing file).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from core.benchmark.manifest import (
    GroundTruthManifest,
    load_manifest,
    write_manifest,
)
from core.benchmark.pipeline import (
    DEFAULT_BASELINE_CSV,
    read_buckets,
    score_and_record,
    tool_identity,
)
from core.benchmark.result import (
    LEDGER_OPERATION_MANIFEST,
    append_manifest_to_ledger,
    ledger_digests,
    load_result,
    verify_result,
)
from core.benchmark.sources import (
    TRUTH_SUFFIX,
    physical_manifest_from_work,
    read_json_record,
    synthetic_manifest,
)
from core.benchmark.stats import aggregate_by_kind, physical_validation_status
from core.errors import SanctumError

__all__ = ["main", "build_parser"]


def _emit(payload: Any) -> None:
    sys.stdout.write(json.dumps(payload, indent=1, default=str) + "\n")


def build_parser() -> argparse.ArgumentParser:
    """The argument parser, exposed for tests."""
    parser = argparse.ArgumentParser(
        prog="python -m core.benchmark", description=__doc__.splitlines()[0]
    )
    sub = parser.add_subparsers(dest="command", required=True)

    man = sub.add_parser("manifest", help="seal a ground-truth manifest")
    kinds = man.add_subparsers(dest="kind", required=True)
    syn = kinds.add_parser("synthetic", help="from a synthetic build")
    syn.add_argument("--truth", type=Path, help="the image's .truth.json")
    syn.add_argument("--image", type=Path, help="the built image")
    syn.add_argument("--work", type=Path, help="a testkit benchmark work dir")
    syn.add_argument("--stem", help="image stem inside --work/images")
    syn.add_argument("--seed", type=int, required=True)
    syn.add_argument("--id", dest="benchmark_id", required=True)
    syn.add_argument("--out", type=Path, required=True)
    phy = kinds.add_parser("physical", help="from the physical harness work dir")
    phy.add_argument("--work", type=Path, required=True)
    phy.add_argument("--seed", type=int)
    phy.add_argument("--id", dest="benchmark_id", required=True)
    phy.add_argument("--out", type=Path, required=True)
    for cmd in (syn, phy):
        cmd.add_argument("--ledger-root", type=Path)
        cmd.add_argument("--key", type=Path)

    sc = sub.add_parser("score", help="score outputs against a sealed manifest")
    sc.add_argument("--manifest", type=Path, required=True)
    sc.add_argument(
        "--outputs", type=Path, required=True, help="output dir or outputs.json"
    )
    sc.add_argument("--payloads", type=Path, help="planted-bytes store by SHA-256")
    sc.add_argument("--image", type=Path, help="image to read expected bytes from")
    sc.add_argument("--buckets", type=Path, help="sanctum-result.json of the run")
    sc.add_argument("--tool", default="sanctum-carve")
    sc.add_argument("--tool-version")
    sc.add_argument("--run-meta", type=Path, help="the run's meta.json")
    sc.add_argument("--baseline-csv", type=Path, default=DEFAULT_BASELINE_CSV)
    sc.add_argument("--key", type=Path, help="signing key file or directory")
    sc.add_argument("--ledger-root", type=Path)
    sc.add_argument("--out", type=Path, required=True)

    ver = sub.add_parser("verify", help="re-check digests and signatures")
    ver.add_argument("--manifest", type=Path, required=True)
    ver.add_argument("--result", type=Path, action="append", default=[])
    ver.add_argument("--ledger-root", type=Path)

    summ = sub.add_parser("summarize", help="aggregate results per kind")
    summ.add_argument("results", type=Path, nargs="+")
    summ.add_argument("--manifest", type=Path, action="append", default=[])
    return parser


def _seal_manifest(args: argparse.Namespace) -> GroundTruthManifest:
    if args.kind == "synthetic":
        truth, image = args.truth, args.image
        if args.work is not None and args.stem:
            truth = truth or args.work / "images" / f"{args.stem}{TRUTH_SUFFIX}"
            image = image or args.work / "images" / f"{args.stem}.img"
        if truth is None or image is None:
            raise SanctumError(
                "give --truth and --image, or --work and --stem",
                remediation="Name the ground truth and the image it describes.",
            )
        return synthetic_manifest(
            truth_path=truth,
            image_path=image,
            benchmark_id=args.benchmark_id,
            seed=args.seed,
        )
    return physical_manifest_from_work(
        args.work, benchmark_id=args.benchmark_id, seed=args.seed
    )


def _cmd_manifest(args: argparse.Namespace) -> int:
    manifest = _seal_manifest(args)
    write_manifest(manifest, args.out)
    passphrase = os.environ.get("SANCTUM_KEY_PASSPHRASE")
    entry = (
        append_manifest_to_ledger(
            manifest, args.ledger_root, key=args.key, passphrase=passphrase
        )
        if args.ledger_root is not None
        else None
    )
    _emit(
        {
            "manifest": str(args.out),
            "kind": str(manifest.kind),
            "benchmark_id": manifest.benchmark_id,
            "files": len(manifest.files),
            "manifest_digest": manifest.manifest_digest,
            "ledger_seq": entry.seq if entry is not None else None,
            "acquisition_recorded": manifest.acquisition is not None,
        }
    )
    return 0


def _cmd_score(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest)
    run_meta = read_json_record(args.run_meta) if args.run_meta else None
    result = score_and_record(
        manifest,
        args.outputs,
        out=args.out,
        tool=tool_identity(args.tool, version=args.tool_version, run_meta=run_meta),
        payloads=args.payloads,
        image=args.image,
        buckets=read_buckets(args.buckets),
        baseline_csv=args.baseline_csv,
        key=args.key,
        passphrase=os.environ.get("SANCTUM_KEY_PASSPHRASE"),
        ledger_root=args.ledger_root,
    )
    counts = result.score.counts
    _emit(
        {
            "result": str(args.out),
            "kind": str(result.kind),
            "result_digest": result.result_digest,
            "signed": result.signature is not None,
            "unsigned_reason": result.unsigned_reason,
            "counts": counts.model_dump(mode="json"),
            "rule": {
                "outcome": str(result.rule.outcome),
                "binding": result.rule.binding,
                "reason": result.rule.reason,
            },
        }
    )
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    payload: dict[str, Any] = {"manifest": str(args.manifest)}
    manifest = load_manifest(args.manifest)
    payload["manifest_digest"] = manifest.manifest_digest
    payload["manifest_digest_ok"] = True
    failed = False
    if args.ledger_root is not None:
        recorded = ledger_digests(args.ledger_root)
        in_ledger = manifest.manifest_digest in recorded[LEDGER_OPERATION_MANIFEST]
        payload["manifest_ledgered"] = in_ledger
        failed = failed or not in_ledger
    checks = []
    for path in args.result:
        verification = verify_result(
            path, manifest=manifest, ledger_root=args.ledger_root
        )
        checks.append(
            {
                "result": str(path),
                **verification.model_dump(mode="json"),
                "ok": verification.ok,
            }
        )
        failed = failed or not verification.ok
    payload["results"] = checks
    payload["ok"] = not failed
    _emit(payload)
    return 1 if failed else 0


def _cmd_summarize(args: argparse.Namespace) -> int:
    results = [load_result(path) for path in args.results]
    manifests = [load_manifest(path) for path in args.manifest]
    _emit(
        {
            "by_kind": {
                kind: summary.model_dump(mode="json")
                for kind, summary in aggregate_by_kind(results).items()
            },
            "physical_validation": physical_validation_status(
                results, manifests
            ).model_dump(mode="json"),
        }
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Run one subcommand. Returns the process exit status."""
    args = build_parser().parse_args(argv)
    handlers = {
        "manifest": _cmd_manifest,
        "score": _cmd_score,
        "verify": _cmd_verify,
        "summarize": _cmd_summarize,
    }
    try:
        return handlers[args.command](args)
    except SanctumError as refusal:
        _emit(
            {
                "refused": refusal.message,
                "kind": type(refusal).__name__,
                "remediation": refusal.remediation,
            }
        )
        return 2
