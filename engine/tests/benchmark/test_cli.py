"""``python -m core.benchmark``: manifest, score, verify, summarize, end to end."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from core.benchmark.cli import main

from tests.benchmark.conftest import Corpus

REPO = Path(__file__).resolve().parents[2]


def _run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, dict]:  # type: ignore[type-arg]
    code = main(list(argv))
    return code, json.loads(capsys.readouterr().out)


def _manifest(capsys: pytest.CaptureFixture[str], corpus: Corpus, out: Path) -> dict:  # type: ignore[type-arg]
    code, payload = _run(
        capsys,
        "manifest", "synthetic",
        "--work", str(corpus.root), "--stem", corpus.image.name.removesuffix(".img"),
        "--seed", "26149", "--id", "cli-test", "--out", str(out),
        "--ledger-root", str(corpus.root / "ledger"),
    )
    assert code == 0, payload
    return payload


def _score(
    capsys: pytest.CaptureFixture[str], corpus: Corpus, manifest: Path, out: Path
) -> tuple[int, dict]:  # type: ignore[type-arg]
    return _run(
        capsys,
        "score",
        "--manifest", str(manifest),
        "--outputs", str(corpus.outputs),
        "--payloads", str(corpus.payloads),
        "--image", str(corpus.image),
        "--baseline-csv", str(REPO / "docs/performance/benchmark.csv"),
        "--ledger-root", str(corpus.root / "ledger"),
        "--out", str(out),
    )


def test_the_whole_cycle(filled: Corpus, capsys: pytest.CaptureFixture[str]) -> None:
    manifest = filled.root / "manifest.json"
    sealed = _manifest(capsys, filled, manifest)
    assert sealed["kind"] == "SYNTHETIC" and sealed["files"] == 8
    assert sealed["ledger_seq"] == 1  # genesis is 0

    result = filled.root / "result.json"
    code, scored = _score(capsys, filled, manifest, result)
    assert code == 0, scored
    assert scored["counts"]["exact"] == 2 and scored["counts"]["full"] == 5
    assert scored["rule"]["outcome"] == "NOT_APPLICABLE"
    assert scored["signed"] is False and scored["unsigned_reason"]

    code, verified = _run(
        capsys,
        "verify", "--manifest", str(manifest), "--result", str(result),
        "--ledger-root", str(filled.root / "ledger"),
    )
    assert code == 0, verified
    assert verified["ok"] and verified["manifest_ledgered"]
    assert verified["results"][0]["ledger_recorded"] is True

    code, summary = _run(
        capsys, "summarize", str(result), "--manifest", str(manifest)
    )
    assert code == 0
    assert set(summary["by_kind"]) == {"SYNTHETIC"}
    assert summary["physical_validation"]["status"] == "PHYSICAL VALIDATION REQUIRED"


def test_verify_fails_on_an_edited_result(
    filled: Corpus, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = filled.root / "manifest.json"
    _manifest(capsys, filled, manifest)
    result = filled.root / "result.json"
    _score(capsys, filled, manifest, result)
    data = json.loads(result.read_text())
    data["score"]["counts"]["missed"] = 0
    result.write_text(json.dumps(data))
    code, verified = _run(
        capsys, "verify", "--manifest", str(manifest), "--result", str(result)
    )
    assert code == 1
    assert verified["results"][0]["digest_ok"] is False


def test_a_tampered_manifest_is_refused_everywhere(
    filled: Corpus, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = filled.root / "manifest.json"
    _manifest(capsys, filled, manifest)
    data = json.loads(manifest.read_text())
    data["files"][2]["status"] = "GONE"  # hide a miss
    manifest.write_text(json.dumps(data))
    code, refused = _score(capsys, filled, manifest, filled.root / "r.json")
    assert code == 2 and refused["kind"] == "ManifestTampered"
    assert not (filled.root / "r.json").exists()
    code, refused = _run(capsys, "verify", "--manifest", str(manifest))
    assert code == 2


def test_an_existing_manifest_is_not_overwritten(
    filled: Corpus, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = filled.root / "manifest.json"
    _manifest(capsys, filled, manifest)
    code, refused = _run(
        capsys,
        "manifest", "synthetic", "--truth", str(filled.truth), "--image",
        str(filled.image), "--seed", "1", "--id", "again", "--out", str(manifest),
    )
    assert code == 2 and refused["kind"] == "ManifestExists"


def test_the_module_runs_as_a_program(filled: Corpus, tmp_path: Path) -> None:
    import subprocess
    import sys

    done = subprocess.run(
        [
            sys.executable, "-m", "core.benchmark", "manifest", "synthetic",
            "--truth", str(filled.truth), "--image", str(filled.image),
            "--seed", "0", "--id", "subprocess", "--out", str(tmp_path / "m.json"),
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout)["kind"] == "SYNTHETIC"
