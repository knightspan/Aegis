"""Batch behaviour: continue on error, deterministic order, ledgered phases."""

from __future__ import annotations

from pathlib import Path

import pytest
from core.erase.files import erase_paths, expand_targets
from core.erase.sink import ChainLedgerSink
from core.ledger.chain import ChainStatus, Ledger
from core.models import FileErasePhase

from .conftest import drain, real_erase


def _sink(root: Path) -> ChainLedgerSink:
    return ChainLedgerSink(
        Ledger(root / "ledger", tool_version="0.0.0-test", pubkey_fingerprint="AA:BB")
    )


def test_10_a_batch_continues_past_failures_and_keeps_input_order(
    real_fs_dir: Path, tmp_path: Path
) -> None:
    """One bad path must never cost the other 199.

    Order matters as much as completion: a report that listed files in whatever
    order the pool happened to finish would differ between two runs over the
    same input, and an examiner comparing them would be chasing a phantom.
    """
    paths: list[Path] = []
    for index in range(200):
        target = real_fs_dir / f"file-{index:04d}.bin"
        target.write_bytes(b"x" * 256)
        paths.append(target)

    # Three deliberate failures: two that vanish before the erase opens them,
    # and one replaced by a directory where a file is expected.
    paths[7].unlink()
    paths[123].unlink()
    paths[180].unlink()
    paths[180].mkdir()

    _, result = drain(
        erase_paths(
            paths,
            real_erase(workers=1, recursive=False),
            job_id="batch-1",
            ledger=_sink(tmp_path),
        )
    )

    assert len(result.records) == 200
    assert [record.path for record in result.records] == [str(p) for p in paths], (
        "results must come back in input order regardless of completion order"
    )
    assert result.records[7].ok is False
    assert result.records[123].ok is False
    assert result.succeeded == 198  # the directory erases fine, as a directory
    for index in (7, 123):
        assert result.records[index].error


def test_the_pool_path_produces_the_same_records_as_the_inline_path(
    real_fs_dir: Path, tmp_path: Path
) -> None:
    """Parallelism may change the speed and nothing else."""
    inline_dir = real_fs_dir / "inline"
    pooled_dir = real_fs_dir / "pooled"
    for directory in (inline_dir, pooled_dir):
        directory.mkdir()
        for index in range(40):
            (directory / f"f{index:03d}.bin").write_bytes(bytes([index]) * 512)

    inline_paths = sorted(inline_dir.iterdir())
    pooled_paths = sorted(pooled_dir.iterdir())

    _, inline = drain(
        erase_paths(
            inline_paths,
            real_erase(workers=1),
            job_id="inline",
            ledger=_sink(tmp_path / "a"),
        )
    )
    _, pooled = drain(
        erase_paths(
            pooled_paths,
            real_erase(workers=2, pool_threshold=8),
            job_id="pooled",
            ledger=_sink(tmp_path / "b"),
        )
    )

    assert [r.path for r in pooled.records] == [str(p) for p in pooled_paths]
    assert inline.succeeded == pooled.succeeded == 40
    assert [r.bytes_overwritten for r in inline.records] == [
        r.bytes_overwritten for r in pooled.records
    ]
    assert [
        sorted(f.kind.value for f in r.findings) for r in inline.records
    ] == [sorted(f.kind.value for f in r.findings) for r in pooled.records]


def test_11_a_directory_tree_is_expanded_depth_first(real_fs_dir: Path) -> None:
    """Contents before their container, so rmdir cannot meet a non-empty dir."""
    root = real_fs_dir / "case-files"
    (root / "a" / "b").mkdir(parents=True)
    (root / "top.txt").write_bytes(b"top")
    (root / "a" / "mid.txt").write_bytes(b"mid")
    (root / "a" / "b" / "deep.txt").write_bytes(b"deep")

    order = expand_targets([root], recursive=True)
    names = [path.name for path in order]

    assert names.index("deep.txt") < names.index("b")
    assert names.index("b") < names.index("a")
    assert names.index("a") < names.index("case-files")
    assert names[-1] == "case-files"


def test_11b_a_directory_tree_is_erased_and_its_names_obfuscated(
    real_fs_dir: Path, tmp_path: Path
) -> None:
    """A directory name is often as telling as a filename, so it is renamed too."""
    root = real_fs_dir / "operation-notes"
    (root / "sub-folder").mkdir(parents=True)
    (root / "top.txt").write_bytes(b"top")
    (root / "sub-folder" / "deep.txt").write_bytes(b"deep")

    _, result = drain(
        erase_paths([root], real_erase(), job_id="tree-1", ledger=_sink(tmp_path))
    )

    assert not root.exists()
    renamed_dirs = [
        record
        for record in result.records
        if record.is_directory and record.rename_chain
    ]
    assert len(renamed_dirs) == 2, (
        "directory names must be rename-obfuscated before rmdir, not just removed"
    )
    for record in renamed_dirs:
        original = Path(record.path).name
        assert all(len(name) == len(original) for name in record.rename_chain)


def test_a_symlink_inside_a_tree_is_not_followed(real_fs_dir: Path) -> None:
    """Following one would walk out of the tree the operator named."""
    root = real_fs_dir / "tree"
    root.mkdir()
    outside = real_fs_dir / "outside.bin"
    outside.write_bytes(b"UNRELATED")
    (root / "link").symlink_to(outside)

    order = expand_targets([root], recursive=True)

    assert root / "link" in order
    assert outside not in order


def test_13_every_phase_is_ledgered_and_the_chain_verifies(
    real_fs_dir: Path, tmp_path: Path
) -> None:
    """One entry per phase per record, even for a phase that did nothing.

    A phase missing from the chain would be indistinguishable from a phase that
    ran and was not recorded, so a skipped phase is ledgered as skipped.
    """
    target = real_fs_dir / "f.bin"
    target.write_bytes(b"y" * 2048)
    chain = Ledger(
        tmp_path / "ledger", tool_version="0.0.0-test", pubkey_fingerprint="AA:BB"
    )
    sink = ChainLedgerSink(chain)

    progress, result = drain(
        erase_paths([target], real_erase(), job_id="job-led", ledger=sink)
    )

    assert result.records[0].ok, result.records[0].error
    operations = [entry.operation for entry in chain.entries()]
    for phase in FileErasePhase:
        assert any(
            operation.startswith(f"erase.file.{phase.value.lower()}.")
            for operation in operations
        ), f"no ledger entry for phase {phase.value}"

    verification = chain.verify()
    assert verification.status is ChainStatus.VALID, verification.explanation

    assert progress, "erase_paths must yield Progress"
    assert progress[-1].pct_bp == 10_000
    assert all(isinstance(record.pct_bp, int) for record in progress)


def test_a_worker_never_writes_to_the_ledger() -> None:
    """One writer only. A pool worker appending would race the chain head.

    Parsed, not grepped: the first version matched the source text and failed on
    the docstring sentence explaining this very rule, while a real violation
    written as ``sink.record_file(...)`` would have slipped past it. The AST
    sees names and calls, and no prose.
    """
    import ast

    tree = ast.parse(Path("core/erase/files.py").read_text(encoding="utf-8"))
    worker = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "erase_one"
    )

    referenced = {
        node.id for node in ast.walk(worker) if isinstance(node, ast.Name)
    } | {node.attr for node in ast.walk(worker) if isinstance(node, ast.Attribute)}

    forbidden = {"ledger", "record_file", "LedgerSink", "ChainLedgerSink"}
    assert not (referenced & forbidden), (
        "erase_one runs in a pool worker under spawn; it must not touch the "
        f"chain, but references {sorted(referenced & forbidden)}"
    )


def test_an_unconfirmed_batch_is_refused_before_anything_is_touched(
    real_fs_dir: Path, tmp_path: Path
) -> None:
    from core.errors import ConfirmationMismatch
    from core.models import FileEraseOptions

    targets = []
    for index in range(3):
        target = real_fs_dir / f"keep-{index}.bin"
        target.write_bytes(b"intact")
        targets.append(target)

    sink = _sink(tmp_path)
    with pytest.raises(ConfirmationMismatch):
        drain(erase_paths(targets, FileEraseOptions(), job_id="no", ledger=sink))

    assert all(target.read_bytes() == b"intact" for target in targets)


# --------------------------------------------------------------------------
# The paths that keep one bad file from costing the batch
# --------------------------------------------------------------------------


def test_a_worker_that_raises_returns_a_failed_record_instead(
    real_fs_dir: Path, tmp_path: Path
) -> None:
    """An exception escaping a pool worker kills the result for every file.

    ``erase_one`` raises for the two gate violations by design - they are
    caller errors, not per-file failures - so a batch containing a protected
    path would otherwise lose the other 199 records to one raise inside
    ``imap_unordered``. The worker converts it to a failed record.
    """
    good = real_fs_dir / "ordinary.bin"
    good.write_bytes(b"x" * 128)
    # A directory *this platform* protects: "/usr" resolves to C:\usr on
    # Windows, which exists nowhere and fails as ENOENT rather than being
    # refused, so the gate this test is about never ran there.
    from core.platform.host import family
    from core.platform.paths import protected_prefixes

    protected = next(
        Path(item)
        for item in protected_prefixes(family())
        # Not the filesystem root (refused by a different branch, with a
        # different sentence) and not a symlink (/bin is one on Fedora, and a
        # link is refused as a link before the protected list is consulted).
        if Path(item).is_dir()
        and Path(item).parent != Path(item)
        and not Path(item).is_symlink()
    )

    _, result = drain(
        erase_paths(
            [good, protected, good.parent / "second.bin"],
            real_erase(workers=1, recursive=False),
            job_id="raising",
            ledger=_sink(tmp_path),
        )
    )

    assert len(result.records) == 3
    protected = result.records[1]
    assert protected.ok is False
    assert protected.error_kind == "SystemDiskRefused"
    assert "Refusing to erase" in (protected.error or "")
    assert result.records[0].ok, "the first file must still have been erased"


def test_a_directory_that_cannot_be_scanned_does_not_abort_the_walk(
    real_fs_dir: Path
) -> None:
    """An unreadable directory yields nothing rather than raising.

    A tree with one directory the operator cannot list is an ordinary
    situation, and losing the whole walk to it would erase nothing at all.
    """
    import os
    import stat

    root = real_fs_dir / "tree"
    (root / "readable").mkdir(parents=True)
    (root / "readable" / "f.bin").write_bytes(b"x")
    blocked = root / "blocked"
    blocked.mkdir()
    (blocked / "hidden.bin").write_bytes(b"y")

    os.chmod(blocked, 0o000)
    try:
        order = expand_targets([root], recursive=True)
    finally:
        os.chmod(blocked, stat.S_IRWXU)

    if not hasattr(os, "geteuid"):
        pytest.skip("POSIX mode bits do not block a read on Windows")
    if os.geteuid() == 0:
        pytest.skip("running as root, which reads a 0o000 directory anyway")

    names = [path.name for path in order]
    assert "f.bin" in names, "the readable half of the tree must still be walked"
    assert "blocked" in names, "the directory itself is still a target"
    assert "hidden.bin" not in names


def test_an_unconfirmed_batch_leaves_a_directory_tree_standing(
    real_fs_dir: Path, tmp_path: Path
) -> None:
    """Refused at the batch gate, so the directory branch is never reached."""
    from core.errors import ConfirmationMismatch
    from core.models import FileEraseOptions

    root = real_fs_dir / "kept-tree"
    (root / "inner").mkdir(parents=True)
    (root / "inner" / "f.bin").write_bytes(b"intact")

    with pytest.raises(ConfirmationMismatch):
        drain(
            erase_paths(
                [root], FileEraseOptions(), job_id="no-tree", ledger=_sink(tmp_path)
            )
        )

    assert root.exists()
    assert (root / "inner" / "f.bin").read_bytes() == b"intact"
