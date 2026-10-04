"""The benchmark result: counts, per-file table, the registered rule, and seals.

A result names the manifest it was scored against by digest, the tool that
produced the outputs, the build it ran on and the scorer version, and carries
its own digest: SHA-256 of its canonical JSON with the digest and signature
fields left out. When a signing key is available through
:mod:`core.report.sign`, the result is signed over the same canonical bytes
plus its digest. When none is, ``signature`` is ``null`` and
``unsigned_reason`` says why; an unsigned result is never presented as signed.

Each sealed result can be appended to the hash-chained ledger
(:mod:`core.ledger.chain`), so a later edit to the file is caught by comparing
it with the digest the chain recorded.

Nothing here opens a device or touches the network.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, Final, Literal

import structlog
from pydantic import BaseModel, ConfigDict, ValidationError

from core.benchmark.manifest import (
    BenchmarkKind,
    GroundTruthManifest,
    ManifestExists,
    ManifestInvalid,
    ManifestTampered,
    utc_stamp,
)
from core.benchmark.rule import RuleEvaluation
from core.benchmark.score import ScoreReport
from core.errors import SanctumError
from core.ledger.canon import CANON_VERSION, canonical_bytes
from core.models import LedgerEntry, Signature

__all__ = [
    "RESULT_SCHEMA",
    "RESULT_DIGEST_FIELD",
    "LEDGER_ACTOR",
    "LEDGER_OPERATION_RESULT",
    "LEDGER_OPERATION_MANIFEST",
    "ToolIdentity",
    "BuildIdentity",
    "BenchmarkResult",
    "ResultTampered",
    "ResultVerification",
    "sanctum_version",
    "build_identity",
    "result_digest_of",
    "build_result",
    "write_result",
    "load_result",
    "verify_result",
    "append_result_to_ledger",
    "append_manifest_to_ledger",
    "ledger_digests",
]

logger = structlog.get_logger(__name__)

RESULT_SCHEMA: Final = "sanctum-benchmark-result/1"
RESULT_DIGEST_FIELD = "result_digest"
_UNSEALED_FIELDS = frozenset({RESULT_DIGEST_FIELD, "signature"})
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

LEDGER_ACTOR = "benchmark"
LEDGER_OPERATION_RESULT = "benchmark.result"
LEDGER_OPERATION_MANIFEST = "benchmark.manifest"

#: Used when the installed package metadata cannot be read.
_FALLBACK_VERSION = "0.0.0"

#: What a result can and cannot say, attached to every result.
STANDING_LIMITS = (
    "Recall and precision here are measured on one corpus and one geometry; "
    "they are not a general claim about other media, filesystems or damage.",
    "A sealed manifest proves the answer key did not change after sealing. It "
    "does not prove the device identity recorded in it is true; that rests on "
    "the preflight and the operator.",
    "The registered rule covers recall only. HIGH false positives are listed as "
    "an observation because no HIGH false-positive condition is registered.",
    "A corrupt recovery's agreement ratio is positional byte equality; a "
    "shifted but otherwise intact copy scores low.",
)


class ResultTampered(ManifestTampered):
    """A result's contents no longer match its digest."""

    default_remediation = (
        "Do not quote this result. Re-score from the sealed manifest and the "
        "retained outputs, or recover the sealed result from the ledger."
    )


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ToolIdentity(_Frozen):
    """The recovery tool whose outputs were scored."""

    name: str
    version: str
    returncode: int | None = None
    timed_out: bool | None = None
    #: Wall time of the tool run, integer milliseconds (no floats are hashed).
    run_ms: int | None = None


class BuildIdentity(_Frozen):
    """The Sanctum build that scored the run."""

    sanctum_version: str
    commit: str
    #: Where ``commit`` came from, or why it is unknown.
    source: str


class BenchmarkResult(_Frozen):
    """One scored run. Frozen; verified on load."""

    schema_version: Literal["sanctum-benchmark-result/1"] = RESULT_SCHEMA
    canon_version: str = CANON_VERSION
    benchmark_id: str
    kind: BenchmarkKind
    manifest_digest: str
    image_name: str
    tool: ToolIdentity
    build: BuildIdentity
    scorer_version: str
    created_utc: str
    score: ScoreReport
    rule: RuleEvaluation
    limits: list[str]
    result_digest: str = ""
    signature: Signature | None = None
    unsigned_reason: str | None = None


class ResultVerification(_Frozen):
    """What re-checking a result found. Every check is reported separately."""

    digest_ok: bool
    signature: Literal["VALID", "INVALID", "ABSENT"]
    signature_fingerprint: str | None
    manifest_matches: bool | None
    ledger_recorded: bool | None
    problems: list[str]

    @property
    def ok(self) -> bool:
        """Digest intact, signature not invalid, and nothing else wrong."""
        return self.digest_ok and self.signature != "INVALID" and not self.problems


def sanctum_version() -> str:
    """The installed package version, or ``0.0.0`` when it cannot be read."""
    try:
        from importlib import metadata

        return metadata.version("sanctum-forensics")
    except (ImportError, ValueError, LookupError):
        return _FALLBACK_VERSION


def build_identity() -> BuildIdentity:
    """Version and commit from the build record or git. Never raises."""
    version = sanctum_version()
    try:
        from core.platform.host import build_info

        info = build_info()
    except (OSError, ValueError, ImportError, RuntimeError) as failure:
        return BuildIdentity(
            sanctum_version=version,
            commit="unknown",
            source=f"build identity unavailable: {failure}",
        )
    commit = str(info.get("commit") or "")
    if not commit:
        return BuildIdentity(
            sanctum_version=version,
            commit="unknown",
            source="no build record and no git checkout",
        )
    return BuildIdentity(
        sanctum_version=version,
        commit=commit,
        source=str(info.get("source") or "build record (build_info.json)"),
    )


def _unsealed(data: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if key not in _UNSEALED_FIELDS}


def result_digest_of(data: Mapping[str, Any]) -> str:
    """SHA-256 of a result's canonical JSON without its digest and signature."""
    return hashlib.sha256(canonical_bytes(_unsealed(data))).hexdigest()


def _signable(data: Mapping[str, Any]) -> dict[str, Any]:
    """What a signature covers: the sealed body plus its digest."""
    return {key: value for key, value in data.items() if key != "signature"}


def _load_signing_key(key: Path | None, passphrase: str | None) -> tuple[Any, str]:
    """``(private key, "")``, or ``(None, reason)``. Never creates a key."""
    if key is None:
        return None, "no signing key was given"
    from core.report.sign import key_file_for, load_or_create_key

    path = key_file_for(key)
    if not path.is_file():
        return None, f"no signing key exists at {path}; none was created"
    try:
        return load_or_create_key(path, passphrase), ""
    except (SanctumError, ValueError, OSError) as failure:
        return None, f"the signing key at {path} could not be loaded: {failure}"


def build_result(
    manifest: GroundTruthManifest,
    score: ScoreReport,
    rule: RuleEvaluation,
    *,
    tool: ToolIdentity,
    build: BuildIdentity | None = None,
    created: datetime | None = None,
    extra_limits: list[str] | None = None,
    key: Path | None = None,
    passphrase: str | None = None,
) -> BenchmarkResult:
    """Assemble, digest and (when a key is available) sign one result.

    Whether a key is available is settled first, so ``unsigned_reason`` is
    inside the digest: only the signature itself sits outside it.
    """
    private, reason = _load_signing_key(key, passphrase)
    body = BenchmarkResult(
        benchmark_id=manifest.benchmark_id,
        kind=manifest.kind,
        manifest_digest=manifest.manifest_digest,
        image_name=manifest.image_name,
        tool=tool,
        build=build or build_identity(),
        scorer_version=score.scorer_version,
        created_utc=utc_stamp(created),
        score=score,
        rule=rule,
        limits=[*STANDING_LIMITS, *(extra_limits or [])],
        unsigned_reason=None if private is not None else reason,
    )
    data = body.model_dump(mode="json")
    digest = result_digest_of(data)
    data[RESULT_DIGEST_FIELD] = digest
    sealed = body.model_copy(update={RESULT_DIGEST_FIELD: digest})
    if private is not None:
        from core.report.sign import sign_report

        sealed = sealed.model_copy(
            update={"signature": sign_report(_signable(data), private)}
        )
    logger.info(
        "benchmark_result_sealed",
        benchmark_id=sealed.benchmark_id,
        kind=str(sealed.kind),
        digest=digest,
        signed=private is not None,
        outcome=str(rule.outcome),
    )
    return sealed


def write_result(result: BenchmarkResult, path: Path) -> Path:
    """Write a sealed result to a new file. An existing file is never replaced."""
    data = result.model_dump(mode="json")
    if result_digest_of(data) != result.result_digest:
        raise ResultTampered("refusing to write a result whose digest is stale")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(path, "x", encoding="utf-8") as handle:
            handle.write(json.dumps(data, indent=1, sort_keys=True) + "\n")
    except FileExistsError as exists:
        raise ManifestExists(
            f"{path} already holds a result; results are never overwritten"
        ) from exists
    return path


def load_result(path: Path) -> BenchmarkResult:
    """Load a result and re-verify its digest.

    Raises:
        ManifestInvalid: the file is not a result.
        ResultTampered: the contents do not match the sealed digest.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as failure:
        raise ManifestInvalid(f"{path} could not be read as JSON: {failure}") from (
            failure
        )
    if not isinstance(raw, dict):
        raise ManifestInvalid(f"{path} is not a JSON object")
    recorded = raw.get(RESULT_DIGEST_FIELD)
    if not isinstance(recorded, str) or not _HEX64.match(recorded):
        raise ResultTampered(f"{path} carries no valid {RESULT_DIGEST_FIELD}")
    if result_digest_of(raw) != recorded:
        raise ResultTampered(
            f"{path}: contents do not match the sealed digest {recorded}"
        )
    try:
        result = BenchmarkResult.model_validate(raw)
    except ValidationError as failure:
        raise ManifestInvalid(f"{path} is not a valid result: {failure}") from failure
    if result_digest_of(result.model_dump(mode="json")) != recorded:
        raise ResultTampered(f"{path}: the parsed result does not reproduce its digest")
    return result


def ledger_digests(ledger_root: Path) -> dict[str, set[str]]:
    """Digests the ledger recorded, by operation. Read-only."""
    from core.ledger.chain import Ledger

    ledger = Ledger(ledger_root, tool_version="", pubkey_fingerprint="")
    found: dict[str, set[str]] = {
        LEDGER_OPERATION_MANIFEST: set(),
        LEDGER_OPERATION_RESULT: set(),
    }
    for entry in ledger.entries():
        if entry.operation not in found:
            continue
        try:
            recorded = ledger.result_of(entry)
        except (FileNotFoundError, ValueError):
            continue
        digest = recorded.get("digest")
        if isinstance(digest, str):
            found[entry.operation].add(digest)
    return found


def verify_result(
    result_path: Path,
    *,
    manifest: GroundTruthManifest | None = None,
    ledger_root: Path | None = None,
) -> ResultVerification:
    """Re-check a result file: digest, signature, manifest link, ledger record.

    A digest mismatch is reported, not raised, so every check is visible.
    """
    problems: list[str] = []
    try:
        result = load_result(result_path)
    except ResultTampered as failure:
        return ResultVerification(
            digest_ok=False,
            signature="ABSENT",
            signature_fingerprint=None,
            manifest_matches=None,
            ledger_recorded=None,
            problems=[failure.message],
        )
    signature: Literal["VALID", "INVALID", "ABSENT"] = "ABSENT"
    fingerprint: str | None = None
    if result.signature is not None:
        from core.report.sign import verify_signature

        data = result.model_dump(mode="json")
        valid = verify_signature(_signable(data), result.signature)
        signature = "VALID" if valid else "INVALID"
        fingerprint = result.signature.pubkey_fingerprint
        if not valid:
            problems.append("the signature does not verify over the result")
    manifest_matches: bool | None = None
    if manifest is not None:
        manifest_matches = manifest.manifest_digest == result.manifest_digest
        if not manifest_matches:
            problems.append(
                "the result was scored against manifest "
                f"{result.manifest_digest}, not {manifest.manifest_digest}"
            )
        if manifest.kind is not result.kind:
            problems.append(
                f"the result is {result.kind} but the manifest is {manifest.kind}"
            )
    ledger_recorded: bool | None = None
    if ledger_root is not None:
        recorded = ledger_digests(ledger_root)
        ledger_recorded = result.result_digest in recorded[LEDGER_OPERATION_RESULT]
        if not ledger_recorded:
            problems.append("the ledger holds no entry for this result's digest")
    return ResultVerification(
        digest_ok=True,
        signature=signature,
        signature_fingerprint=fingerprint,
        manifest_matches=manifest_matches,
        ledger_recorded=ledger_recorded,
        problems=problems,
    )


def _ledger(ledger_root: Path, key: Path | None, passphrase: str | None) -> Any:
    from core.ledger.chain import Ledger

    fingerprint = ""
    private, _reason = _load_signing_key(key, passphrase)
    if private is not None:
        from core.report.sign import fingerprint as fingerprint_of
        from core.report.sign import public_key_of

        fingerprint = fingerprint_of(public_key_of(private))
    return Ledger(
        ledger_root,
        tool_version=f"sanctum-forensics/{sanctum_version()}",
        pubkey_fingerprint=fingerprint,
    )


def append_manifest_to_ledger(
    manifest: GroundTruthManifest,
    ledger_root: Path,
    *,
    key: Path | None = None,
    passphrase: str | None = None,
) -> LedgerEntry:
    """Record a sealed manifest's digest in the hash-chained ledger."""
    entry: LedgerEntry = _ledger(ledger_root, key, passphrase).append(
        actor=LEDGER_ACTOR,
        operation=LEDGER_OPERATION_MANIFEST,
        params={
            "benchmark_id": manifest.benchmark_id,
            "kind": str(manifest.kind),
            "image_name": manifest.image_name,
            "files": len(manifest.files),
        },
        result={"digest": manifest.manifest_digest},
    )
    return entry


def append_result_to_ledger(
    result: BenchmarkResult,
    ledger_root: Path,
    *,
    key: Path | None = None,
    passphrase: str | None = None,
) -> LedgerEntry:
    """Record a sealed result's digest and outcome in the hash-chained ledger."""
    counts = result.score.counts
    entry: LedgerEntry = _ledger(ledger_root, key, passphrase).append(
        actor=LEDGER_ACTOR,
        operation=LEDGER_OPERATION_RESULT,
        params={
            "benchmark_id": result.benchmark_id,
            "kind": str(result.kind),
            "manifest_digest": result.manifest_digest,
            "tool": result.tool.name,
            "scorer_version": result.scorer_version,
        },
        result={
            "digest": result.result_digest,
            "signed": result.signature is not None,
            "rule_outcome": str(result.rule.outcome),
            "full": counts.full,
            "exact": counts.exact,
            "corrupt": counts.corrupt,
            "missed": counts.missed,
            "fp_total": counts.fp_total,
        },
    )
    return entry
