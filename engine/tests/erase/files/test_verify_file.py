"""The single worst bug this module can ship is a false pass. Prove it cannot.

A verifier that reports success it did not earn tells an operator that data is
gone when the tool never looked at the place the data used to be. For a file
erase that is the *usual* situation - the file is unlinked, the extents may be
reallocated, and reading the block device needs root - so ``passed=None`` is
the common and correct answer.

The guarantee here is structural rather than behavioural. Exactly one function
in ``core/erase/verify.py`` can construct ``passed=True``, it is only reachable
after a physical read, and the last two tests assert both facts against the
source text so a future edit cannot quietly add a second construction site.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest
from core.erase.files import erase_one
from core.erase.verify import verify_file_erase
from core.models import Extent, FileInspection

from .conftest import real_erase


def test_12_no_extent_map_means_not_possible_and_never_a_pass() -> None:
    inspection = FileInspection(path="/x/f.bin", size_bytes=4096, extents=[])
    result = verify_file_erase(inspection)
    assert result.strategy == "not_possible"
    assert result.passed is None
    assert result.passed is not True
    assert "extent" in result.reason.lower()


def test_no_raw_access_means_not_possible() -> None:
    inspection = FileInspection(
        path="/x/f.bin",
        size_bytes=4096,
        fs_type="ext4",
        extents=[Extent(logical_offset=0, physical_offset=1 << 30, length=4096)],
    )
    result = verify_file_erase(inspection, device_path="/dev/no-such-device")
    assert result.strategy == "not_possible"
    assert result.passed is None
    assert "raw read access" in result.reason.lower()


def test_a_copy_on_write_filesystem_is_not_possible_even_with_extents() -> None:
    """On CoW the overwrite went elsewhere; reading these extents proves nothing.

    Both directions: a clean read would not mean the data is gone, and a dirty
    one would not mean the erase failed. There is nothing to claim.
    """
    for fs_type in ("btrfs", "zfs", "apfs", "bcachefs"):
        inspection = FileInspection(
            path="/x/f.bin",
            size_bytes=4096,
            fs_type=fs_type,
            extents=[Extent(logical_offset=0, physical_offset=1 << 30, length=4096)],
        )
        result = verify_file_erase(inspection)
        assert result.strategy == "not_possible", fs_type
        assert result.passed is None, fs_type
        assert "copy-on-write" in result.reason.lower(), fs_type


def test_resident_data_is_not_possible_because_there_is_no_extent_to_read() -> None:
    inspection = FileInspection(
        path="/x/f.bin",
        size_bytes=200,
        fs_type="NTFS",
        is_resident=True,
        extents=[Extent(logical_offset=0, physical_offset=1 << 30, length=4096)],
    )
    result = verify_file_erase(inspection)
    assert result.strategy == "not_possible"
    assert result.passed is None
    assert "resident" in result.reason.lower()


def test_an_unprivileged_real_erase_reports_not_possible_rather_than_a_pass(
    real_fs_dir: Path,
) -> None:
    """The end-to-end case on a normal developer box.

    Everything succeeds - the file is overwritten, renamed and unlinked - and
    verification still reports nothing, because reading the block device needs
    root. That combination is exactly what must not silently become a pass.
    """
    if not hasattr(os, "geteuid"):
        pytest.skip("this case is about POSIX raw-device permissions")
    if os.geteuid() == 0:
        pytest.skip("running as root, so the raw read would succeed")

    target = real_fs_dir / "verifiable.bin"
    target.write_bytes(b"x" * 65536)

    record = erase_one(target, real_erase())

    assert record.ok, record.error
    assert record.unlinked is True
    assert record.verification is not None
    assert record.verification.passed is not True
    assert record.verification.strategy == "not_possible"


def test_exactly_one_construction_site_can_produce_a_pass() -> None:
    """Structural guard, not a behavioural one.

    A future edit that adds a second site able to produce ``passed=True`` in
    verify.py fails here before it can ship a verification the tool did not
    perform.

    Parsed rather than grepped. The first version of this test matched the
    source text and counted three hits, two of which were the comments
    explaining the rule - so it would have failed for a docstring edit and
    passed for a real second construction site written as ``passed=flag``.
    The AST sees the code and nothing else.
    """
    import ast

    tree = ast.parse(Path("core/erase/verify.py").read_text(encoding="utf-8"))

    sites: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
        if name != "FileVerificationResult":
            continue
        for keyword in node.keywords:
            if keyword.arg != "passed":
                continue
            # `passed=None` is a refusal. `passed=True` and any expression that
            # could evaluate to True are construction sites.
            if isinstance(keyword.value, ast.Constant) and keyword.value.value is None:
                continue
            enclosing = next(
                function.name
                for function in ast.walk(tree)
                if isinstance(function, ast.FunctionDef)
                and function.lineno <= node.lineno
                and (function.end_lineno or node.lineno) >= node.lineno
            )
            sites.append(enclosing)

    assert sites == ["_passed_after_physical_read"], (
        "exactly one function may construct a non-None `passed`; found "
        f"{sites}"
    )


def test_the_only_pass_factory_is_reached_only_after_a_physical_read() -> None:
    """The factory has one caller, and that caller reads the medium first."""
    source = Path("core/erase/verify.py").read_text(encoding="utf-8")
    calls = re.findall(r"_passed_after_physical_read\(", source)
    # One definition, one call.
    assert len(calls) == 2, f"expected 1 definition and 1 call, found {len(calls)}"

    body = source.split("def verify_file_erase(", 1)[1]
    read_at = body.index("_read_physical_extents(")
    construct_at = body.index("_passed_after_physical_read(")
    assert read_at < construct_at, (
        "the pass is constructed before the physical read happens"
    )


def test_the_physical_reader_never_opens_a_device_for_writing() -> None:
    """The evidence rule, applied to the erase side's own verifier."""
    source = Path("core/erase/verify.py").read_text(encoding="utf-8")
    reader = source.split("def _read_physical_extents(", 1)[1].split("\ndef ", 1)[0]
    assert "_READ_ONLY_FLAGS" in reader
    assert "O_WRONLY" not in reader
    assert "O_RDWR" not in reader
