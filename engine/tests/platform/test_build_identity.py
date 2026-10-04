"""L3: one build identity, whatever surface reads it.

``/health`` reported the commit a stale, gitignored ``build_info.json`` recorded
while the running code was at another. The runtime, the packaged record and the
displayed identity must agree, and a record for a different commit must never
be presented as this code's.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from api.deps import AppServices
from api.jobs import JobRegistry
from api.main import create_app
from core.platform import host
from fastapi.testclient import TestClient

from tests._loopback import LOOPBACK_BASE_URL


def _git(root: Path, *argv: str) -> str:
    return subprocess.run(  # noqa: S603
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *argv],
        cwd=root, capture_output=True, text=True, check=True,
    ).stdout.strip()


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    root = tmp_path / "src"
    root.mkdir()
    _git(root, "init", "-q")
    (root / "a").write_text("a")
    _git(root, "add", "a")
    _git(root, "commit", "-q", "-m", "one")
    return root


def _record(tmp_path: Path, commit: str) -> Path:
    path = tmp_path / "build_info.json"
    path.write_text(json.dumps({"commit": commit, "version": "0.0.0"}))
    return path


def test_a_stale_record_is_ignored_and_the_live_commit_is_reported(
    checkout: Path, tmp_path: Path
) -> None:
    head = _git(checkout, "rev-parse", "HEAD")
    info = host.build_info(_record(tmp_path, "930ee2c" + "0" * 33), checkout)
    assert info["commit"] == head
    assert info["ignored_stale_build_record"].startswith("930ee2c")


def test_a_matching_record_is_kept(checkout: Path, tmp_path: Path) -> None:
    head = _git(checkout, "rev-parse", "HEAD")
    info = host.build_info(_record(tmp_path, head), checkout)
    assert info["commit"] == head and info["version"] == "0.0.0"
    assert "ignored_stale_build_record" not in info


def test_a_packaged_build_reports_its_record(
    checkout: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    info = host.build_info(_record(tmp_path, "abc123"), checkout)
    assert info["commit"] == "abc123"


def test_the_packager_and_the_runtime_name_the_same_commit() -> None:
    import importlib.util

    script = Path(__file__).resolve().parents[2] / "packaging" / "build_info.py"
    spec = importlib.util.spec_from_file_location("sanctum_packager", script)
    assert spec and spec.loader
    packager = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(packager)

    live = host.live_source_identity()
    if not live:
        pytest.skip("not a git checkout")
    assert packager.collect()["commit"] == live["commit"]


def test_health_and_platform_display_the_same_identity(tmp_path: Path) -> None:
    services = AppServices(
        registry=JobRegistry(), helper=object(),  # type: ignore[arg-type]
        state_dir=tmp_path / "state", key_dir=tmp_path / "k",
    )
    services.prepare()
    live = host.live_source_identity()
    with TestClient(
        create_app(services=services, serve_ui=False), base_url=LOOPBACK_BASE_URL
    ) as client:
        health = client.get("/health").json()["build"]
    displayed = host.platform_info().build
    assert health.get("commit") == displayed.get("commit")
    if live:
        assert health["commit"] == live["commit"]
