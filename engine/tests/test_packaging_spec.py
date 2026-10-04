"""The PyInstaller spec collects what static analysis cannot see.

reportlab.graphics.barcode imports its symbologies through exec() of a string.
A build that missed them failed every certificate PDF in the packaged app
(found by scripts/package_smoke.py --isolated on 2026-09-25), while the source
tree - where the modules are simply importable - never noticed.

core.carve.signature.SIGNATURE_DB_PATH is computed from __file__, which
resolves correctly in source (repo root, testkit/signatures.yaml exists) and
in the frozen app (sys._MEIPASS, where it does not: the spec's own excludes
list names "testkit"). Every /jobs/carve request in every packaged build -
Windows, confirmed directly against an installed exe, 2026-09-27; the same
__file__ arithmetic applies identically on Linux and macOS - failed with
EvidenceIntegrityError("signature table not found: ...") before this data
file was added. package_smoke.py never exercises /jobs/carve, so no CI run
or prior packaged-checks claim ever caught it.
"""

from __future__ import annotations

import importlib
from pathlib import Path

SPEC = Path(__file__).resolve().parents[1] / "packaging" / "sanctum.spec"


def test_the_barcode_symbologies_are_collected() -> None:
    assert 'collect_submodules("reportlab.graphics.barcode")' in SPEC.read_text()


def test_the_qr_widget_the_certificate_draws_is_importable_here() -> None:
    importlib.import_module("reportlab.graphics.barcode.code128")
    qr = importlib.import_module("reportlab.graphics.barcode.qr")
    assert hasattr(qr, "QrCodeWidget")


def test_the_carve_engines_signature_table_is_collected() -> None:
    text = SPEC.read_text()
    assert '"testkit" / "signatures.yaml"' in text
    assert 'datas.append((str(SIGNATURES), "testkit"))' in text


def test_signature_db_path_is_exactly_where_the_spec_bundles_it() -> None:
    from core.carve.signature import SIGNATURE_DB_PATH

    repo_root = Path(__file__).resolve().parents[1]
    assert SIGNATURE_DB_PATH == repo_root / "testkit" / "signatures.yaml"


#: Every module of the recovery benchmark package. A new module added without
#: an entry here fails the walk test below, so the list cannot drift silently.
BENCHMARK_MODULES = {
    "core.benchmark",
    "core.benchmark.__main__",
    "core.benchmark.cli",
    "core.benchmark.manifest",
    "core.benchmark.outputs",
    "core.benchmark.pipeline",
    "core.benchmark.result",
    "core.benchmark.rule",
    "core.benchmark.score",
    "core.benchmark.sources",
    "core.benchmark.stats",
}


def test_the_benchmark_package_is_collected_with_the_rest_of_core() -> None:
    """``collect_submodules("core")`` walks packages; core.benchmark is one.

    PyInstaller's collect_submodules walks ``pkgutil`` from a package's
    ``__path__``, so a directory without ``__init__.py`` - a namespace
    package - would be skipped with everything under it. The wheel build
    (hatch, ``packages = ["core", ...]``) includes subpackages the same way.
    """
    import pkgutil
    import tomllib

    import core

    text = SPEC.read_text()
    assert 'collect_submodules("core")' in text
    excludes = text.split("excludes=")[1].split("]")[0]
    assert "core" not in excludes
    root = Path(__file__).resolve().parents[1]
    assert (root / "core" / "benchmark" / "__init__.py").is_file()
    walked = {
        info.name
        for info in pkgutil.walk_packages(core.__path__, "core.")
        if info.name == "core.benchmark" or info.name.startswith("core.benchmark.")
    }
    assert walked == BENCHMARK_MODULES
    pyproject = tomllib.loads((root / "pyproject.toml").read_text())
    assert "core" in pyproject["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]


def test_the_benchmark_package_needs_nothing_the_spec_excludes() -> None:
    """The spec excludes testkit and tests; no benchmark module may import them."""
    import ast

    excluded = ("testkit", "tests", "pytest")
    root = Path(__file__).resolve().parents[1] / "core" / "benchmark"
    for source in sorted(root.glob("*.py")):
        tree = ast.parse(source.read_text(), filename=str(source))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                assert name.split(".")[0] not in excluded, f"{source.name}: {name}"


def test_the_registered_baseline_is_bundled_where_the_benchmark_reads_it() -> None:
    from core.benchmark.pipeline import DEFAULT_BASELINE_CSV

    text = SPEC.read_text()
    assert 'ROOT / "docs" / "performance" / "benchmark.csv"' in text
    assert 'datas.append((str(BASELINE_CSV), "docs/performance"))' in text
    repo_root = Path(__file__).resolve().parents[1]
    assert DEFAULT_BASELINE_CSV == repo_root / "docs" / "performance" / "benchmark.csv"
    assert DEFAULT_BASELINE_CSV.is_file()


def test_pyinstaller_collects_the_benchmark_package() -> None:
    """Where PyInstaller is installed, ask it directly."""
    import pytest

    hooks = pytest.importorskip("PyInstaller.utils.hooks")
    collected = set(hooks.collect_submodules("core"))
    assert BENCHMARK_MODULES - {"core.benchmark.__main__"} <= collected
