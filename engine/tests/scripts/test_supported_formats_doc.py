"""The supported-formats document is generated, and must match the code.

``docs/performance/benchmark.md`` once carried a hand-written table that said
seven formats had no signature for months after they gained one. The document
this test guards is produced from the signature table and the parser and
decoder registries; if a signature is added and the document is not
regenerated, this fails and names the command that fixes it.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _generator() -> object:
    spec = importlib.util.spec_from_file_location(
        "gen_supported_formats", ROOT / "scripts" / "gen_supported_formats.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_committed_document_matches_the_registries() -> None:
    generator = _generator()
    expected = generator.render()  # type: ignore[attr-defined]
    committed = (ROOT / "docs" / "supported-formats.md").read_text(encoding="utf-8")

    assert committed == expected, (
        "docs/supported-formats.md is stale; run "
        ".venv/bin/python scripts/gen_supported_formats.py"
    )


def test_bifragment_reassembly_is_claimed_for_jpeg_only() -> None:
    """The document must not overclaim what the engine does."""
    text = (ROOT / "docs" / "supported-formats.md").read_text(encoding="utf-8")
    marked = [line for line in text.splitlines() if "yes (baseline only)" in line]

    assert len(marked) == 1
    assert marked[0].startswith("| JPEG |")
