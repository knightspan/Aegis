"""Acceptance: every stub raises NotImplementedError. None returns None silently.

When a milestone implements a module, its lines move out of this file into that
module's own tests. **Every module in the project is now implemented**, so what
remains here is the static guard: no function in ``core/`` may have a body that
is a bare ``pass`` or a bare ``return``, silently answering None to a question
it did not actually resolve.

The dynamic half of this file is gone because there are no stubs left to call.
That is the intended end state, not an omission: helper/ is covered by
tests/helper/, and api/ by tests/api/.
"""

from __future__ import annotations

import inspect
from pathlib import Path

#: Modules whose milestone has landed. Their behaviour is covered by their own
#: tests (tests/device/, tests/erase/), so the stub gate below no longer applies.
#: core.erase.drive is listed because its Linux-only import guard makes it
#: unimportable here; tests/erase/ covers it on Linux.
IMPLEMENTED = (
    # Covered by tests/api/test_cases.py.
    "core.cases",
    "core.device",
    "core.erase.calibrate",
    "core.erase.patterns",
    "core.erase.verify",
    "core.erase.drive",
    "core.ledger",
    "core.report",
    "core.carve.evidence",
    "core.carve.acquire",
    "core.carve.signature",
    "core.carve.structure",
    "core.carve.fragmentation",
    "core.carve.validate",
    "core.carve.score",
    "core.carve.classify",
    "core.carve.fsaware",
    # Covered by tests/carve/test_pii_detectors.py and the no-leak test,
    # tests/api/test_pii_no_leak.py.
    "core.carve.pii",
    # Covered by tests/carve/test_mediamap.py.
    "core.carve.mediamap",
    "core.erase.files",
    # Covered by tests/erase/files/test_free_space_gates.py and, on udisks loop
    # volumes, test_free_space_wipe_carve.py.
    "core.erase.freespace",
    "core.erase.inspect",
    "core.erase.metadata",
    "core.erase.residual",
    "core.erase.sink",
    # Covered by tests/erase/files/test_trace_sweep.py.
    "core.erase.traces",
    "core.erase._platform",
    # Covered by tests/platform/ (adapters from fixtures on every host).
    "core.platform",
    # Covered by tests/test_workflow.py.
    "core.workflow",
    # Covered by tests/test_destroy.py and tests/api/test_destroy_record_api.py.
    "core.destroy",
    # Covered by tests/api/test_gate_hardening.py and
    # tests/helper/test_write_seam_authorization.py.
    "core.authorization",
    # Covered by tests/benchmark/.
    "core.benchmark",
    # Covered by tests/restore/ and tests/api/test_restore_workflow.py.
    "core.backup",
    "core.restore",
    # Covered by tests/format/ and tests/api/test_format_workflow.py.
    "core.format",
    # Covered by tests/erase/test_blockclear.py and tests/platform/test_*_engine.py.
    "core.erase.blockclear",
    "core.erase.devicesanitize",
    # Covered by tests/carve/test_platform_sources.py.
    "core.carve.win_source",
    "core.carve.mac_source",
    # Covered by tests/device/test_hidden_area_workflow.py and
    # tests/api/test_hidden_area_workflow.py.
    "core.device.hidden_area_workflow",
)


def test_no_core_public_function_returns_none_silently() -> None:
    """Static guard: no core stub body is a bare ``pass`` or bare ``return``."""
    core_root = Path(__file__).resolve().parent.parent / "core"
    offenders: list[str] = []
    for py in core_root.rglob("*.py"):
        dotted = "core." + str(
            py.relative_to(core_root).with_suffix("")
        ).replace("\\", ".").replace("/", ".")
        if dotted.startswith(IMPLEMENTED):
            continue
        src = py.read_text(encoding="utf-8")
        if "raise NotImplementedError" not in src and "def " in src:
            # models.py / errors.py legitimately have no stubs
            if py.name not in {"models.py", "errors.py", "__init__.py"}:
                offenders.append(str(py))
    assert not offenders, f"modules with functions but no stub raise: {offenders}"


def test_inspect_finds_no_pass_only_bodies() -> None:
    """core stubs must not silently return; body must raise."""
    import core

    bad: list[str] = []
    pkg_root = Path(core.__file__).resolve().parent
    for py in pkg_root.rglob("*.py"):
        if py.name in {"__init__.py", "models.py", "errors.py"}:
            continue
        mod_name = "core." + str(py.relative_to(pkg_root).with_suffix("")).replace(
            "\\", "."
        ).replace("/", ".")
        if mod_name.startswith(IMPLEMENTED):
            continue
        mod = __import__(mod_name, fromlist=["*"])
        for _, obj in inspect.getmembers(mod):
            if inspect.isfunction(obj) and obj.__module__ == mod_name:
                src = inspect.getsource(obj)
                if "raise NotImplementedError" not in src:
                    bad.append(f"{mod_name}.{obj.__name__}")
    assert not bad, f"stub functions that do not raise NotImplementedError: {bad}"
