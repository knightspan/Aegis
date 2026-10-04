"""The .deb declares the two system libraries its frozen executable links."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "make_deb",
    Path(__file__).resolve().parents[1] / "packaging" / "linux" / "make_deb.py",
)
assert _SPEC is not None and _SPEC.loader is not None
make_deb = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(make_deb)


def test_the_control_file_depends_on_glibc_and_zlib() -> None:
    control = make_deb._control("0.0.0", 1024)
    assert "Depends: libc6 (>= 2.30), zlib1g\n" in control
    assert control.index("Depends:") < control.index("Description:")
