"""Sealed results: digest, signature when a key exists, and the ledger entry."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from core.benchmark import result as result_module
from core.benchmark.manifest import BenchmarkKind, GroundTruthManifest, ManifestExists
from core.benchmark.pipeline import score_and_record, tool_identity
from core.benchmark.result import (
    LEDGER_OPERATION_RESULT,
    ResultTampered,
    load_result,
    result_digest_of,
    verify_result,
)
from core.benchmark.rule import RuleOutcome
from core.benchmark.sources import synthetic_manifest
from core.ledger.chain import ChainStatus, Ledger

from tests.benchmark.conftest import Corpus

PASSPHRASE = "benchmark-test-passphrase"
WHEN = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)
REPO = Path(__file__).resolve().parents[2]


def _manifest(corpus: Corpus) -> GroundTruthManifest:
    return synthetic_manifest(
        truth_path=corpus.truth,
        image_path=corpus.image,
        benchmark_id="t",
        seed=0,
        created=WHEN,
    )


def _record(
    corpus: Corpus, out: Path, **kwargs: object
) -> result_module.BenchmarkResult:
    return score_and_record(
        _manifest(corpus),
        corpus.outputs,
        out=out,
        tool=tool_identity(
            "sanctum-carve",
            run_meta={"seconds": 1.25, "returncode": 0, "timed_out": False},
        ),
        payloads=corpus.payloads,
        image=corpus.image,
        baseline_csv=REPO / "docs/performance/benchmark.csv",
        created=WHEN,
        **kwargs,  # type: ignore[arg-type]
    )


@pytest.fixture
def key(tmp_path: Path) -> Path:
    from core.report.sign import load_or_create_key

    path = tmp_path / "keys" / "sanctum-signing.key.pem"
    load_or_create_key(path, PASSPHRASE)
    return path


def test_an_unsigned_result_says_why(filled: Corpus, tmp_path: Path) -> None:
    result = _record(filled, tmp_path / "result.json")
    assert result.signature is None
    assert result.unsigned_reason == "no signing key was given"
    assert result.kind is BenchmarkKind.SYNTHETIC
    assert result.manifest_digest == _manifest(filled).manifest_digest
    assert result.scorer_version.startswith("sanctum-benchmark-scorer/")
    assert result.tool.run_ms == 1250
    assert result.build.commit  # a commit, or "unknown" - never missing
    assert result.rule.outcome is RuleOutcome.NOT_APPLICABLE
    loaded = load_result(tmp_path / "result.json")
    assert loaded == result
    check = verify_result(tmp_path / "result.json")
    assert check.digest_ok and check.signature == "ABSENT" and check.ok


def test_the_result_digest_covers_everything_but_itself_and_the_signature(
    filled: Corpus, tmp_path: Path
) -> None:
    result = _record(filled, tmp_path / "result.json")
    data = json.loads((tmp_path / "result.json").read_text())
    assert result_digest_of(data) == result.result_digest
    data["unsigned_reason"] = "edited"
    assert result_digest_of(data) != result.result_digest


@pytest.mark.parametrize(
    "tamper",
    [
        lambda d: d["score"]["counts"].update(exact=d["score"]["counts"]["exact"] + 1),
        lambda d: d["rule"].update(outcome="PASS"),
        lambda d: d.update(kind="PHYSICAL"),
        lambda d: d["score"]["files"][2].update(outcome="EXACT"),
        lambda d: d.update(manifest_digest="0" * 64),
    ],
    ids=["count", "outcome", "kind", "file-row", "manifest-link"],
)
def test_an_edited_result_is_refused(
    filled: Corpus, tmp_path: Path, tamper: object
) -> None:
    path = tmp_path / "result.json"
    _record(filled, path)
    data = json.loads(path.read_text())
    tamper(data)  # type: ignore[operator]
    path.write_text(json.dumps(data))
    with pytest.raises(ResultTampered):
        load_result(path)
    check = verify_result(path)
    assert check.digest_ok is False and not check.ok


def test_a_result_is_never_overwritten(filled: Corpus, tmp_path: Path) -> None:
    path = tmp_path / "result.json"
    _record(filled, path)
    with pytest.raises(ManifestExists):
        _record(filled, path)


def test_a_result_is_signed_when_a_key_is_available(
    filled: Corpus, tmp_path: Path, key: Path
) -> None:
    path = tmp_path / "result.json"
    result = _record(filled, path, key=key, passphrase=PASSPHRASE)
    assert result.signature is not None
    assert result.unsigned_reason is None
    check = verify_result(path)
    assert check.signature == "VALID" and check.ok
    assert check.signature_fingerprint == result.signature.pubkey_fingerprint

    data = json.loads(path.read_text())
    data["signature"]["sig_b64"] = data["signature"]["sig_b64"][::-1]
    path.write_text(json.dumps(data))
    forged = verify_result(path)
    assert forged.digest_ok is True  # the signature sits outside the digest
    assert forged.signature == "INVALID" and not forged.ok


def test_a_missing_key_is_never_created(filled: Corpus, tmp_path: Path) -> None:
    absent = tmp_path / "nokeys" / "sanctum-signing.key.pem"
    result = _record(filled, tmp_path / "result.json", key=absent, passphrase="x")
    assert result.signature is None
    assert "no signing key exists" in str(result.unsigned_reason)
    assert not absent.exists()


def test_a_key_that_will_not_load_is_recorded_not_raised(
    filled: Corpus, tmp_path: Path, key: Path
) -> None:
    result = _record(filled, tmp_path / "r.json", key=key, passphrase="wrong")
    assert result.signature is None
    assert "could not be loaded" in str(result.unsigned_reason)


def test_a_ledger_entry_is_appended_and_chained(
    filled: Corpus, tmp_path: Path, key: Path
) -> None:
    ledger_root = tmp_path / "ledger"
    first = _record(filled, tmp_path / "one.json", ledger_root=ledger_root)
    second = _record(
        filled, tmp_path / "two.json", ledger_root=ledger_root, key=key,
        passphrase=PASSPHRASE,
    )
    ledger = Ledger(ledger_root, tool_version="", pubkey_fingerprint="")
    entries = ledger.entries()
    results = [entry for entry in entries if entry.operation == LEDGER_OPERATION_RESULT]
    assert len(results) == 2
    assert results[1].prev_entry_hash == results[0].entry_hash
    assert [ledger.result_of(e)["digest"] for e in results] == [
        first.result_digest,
        second.result_digest,
    ]
    assert ledger.verify().status is ChainStatus.VALID
    assert verify_result(tmp_path / "one.json", ledger_root=ledger_root).ledger_recorded


def test_a_result_absent_from_the_ledger_is_reported(
    filled: Corpus, tmp_path: Path
) -> None:
    ledger_root = tmp_path / "ledger"
    _record(filled, tmp_path / "one.json", ledger_root=ledger_root)
    filled.put("z/extra.bin", b"\x00" * 100)  # a different run, a different digest
    _record(filled, tmp_path / "unledgered.json")
    check = verify_result(tmp_path / "unledgered.json", ledger_root=ledger_root)
    assert check.ledger_recorded is False and not check.ok


def test_a_result_scored_against_another_manifest_is_reported(
    filled: Corpus, tmp_path: Path
) -> None:
    _record(filled, tmp_path / "result.json")
    other = synthetic_manifest(
        truth_path=filled.truth, image_path=filled.image, benchmark_id="other", seed=1
    )
    check = verify_result(tmp_path / "result.json", manifest=other)
    assert check.manifest_matches is False and not check.ok


def test_a_missing_build_identity_never_fails_the_result(
    filled: Corpus, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import core.platform.host as host

    def unavailable() -> dict[str, str]:
        raise OSError("no build record")

    monkeypatch.setattr(host, "build_info", unavailable)
    result = _record(filled, tmp_path / "result.json")
    assert result.build.commit == "unknown"
    assert "no build record" in result.build.source

    monkeypatch.setattr(host, "build_info", lambda: {})
    result = _record(filled, tmp_path / "result2.json")
    assert result.build.commit == "unknown"
