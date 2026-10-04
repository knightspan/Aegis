"""A protected directory refuses its contents too, not only itself."""

from __future__ import annotations

from pathlib import Path

import pytest
from core.erase import files as files_mod
from core.erase.files import erase_paths
from core.erase.sink import ChainLedgerSink
from core.ledger.chain import Ledger

from .conftest import drain, real_erase


def test_erasing_a_protected_root_recursively_leaves_its_contents_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Depth-first expansion emits every child before the root is refused.

    Without a check on the requested root, ``erase /usr`` erased everything the
    operator could write under ``/usr`` and only then refused ``/usr`` itself.
    """
    root = tmp_path / "protected"
    (root / "sub").mkdir(parents=True)
    keep = [root / "a.txt", root / "sub" / "b.txt"]
    for item in keep:
        item.write_text("must survive")
    monkeypatch.setattr(files_mod, "PROTECTED_PREFIXES", (str(root.resolve()),))
    sink = ChainLedgerSink(
        Ledger(
            tmp_path / "ledger", tool_version="0.0.0-test", pubkey_fingerprint="AA:BB"
        )
    )

    _, result = drain(
        erase_paths([root], real_erase(workers=1), job_id="protected-1", ledger=sink)
    )

    assert all(item.read_text() == "must survive" for item in keep)
    assert result.succeeded == 0
    assert result.records[0].ok is False
    assert result.records[0].error_kind == "SystemDiskRefused"


def test_a_non_empty_directory_keeps_its_name_when_it_cannot_be_removed(
    tmp_path: Path,
) -> None:
    """Non-recursive erase of a directory with contents must not rename it."""
    from core.erase.files import erase_one

    target = tmp_path / "keepname"
    target.mkdir()
    (target / "child.txt").write_text("still here")

    record = erase_one(target, real_erase(recursive=False))

    assert record.ok is False
    assert target.is_dir() and (target / "child.txt").read_text() == "still here"
    assert record.rename_chain == []
