"""Every Sanctum error carries an actionable ``remediation`` string."""

from __future__ import annotations

import inspect

import core.errors as errors
import pytest
from core.errors import ConfirmationMismatch, SanctumError

CONCRETE = [
    obj
    for _, obj in inspect.getmembers(errors, inspect.isclass)
    if issubclass(obj, SanctumError) and obj is not SanctumError
]


def test_module_exports_every_concrete_error() -> None:
    assert {c.__name__ for c in CONCRETE}.issubset(set(errors.__all__))


@pytest.mark.parametrize("cls", CONCRETE, ids=lambda c: c.__name__)
def test_default_remediation_is_non_empty(cls: type[SanctumError]) -> None:
    err = cls("something failed")
    assert isinstance(err.remediation, str)
    assert err.remediation.strip()
    assert err.message == "something failed"


def test_explicit_remediation_overrides_default() -> None:
    err = ConfirmationMismatch("bad serial", remediation="type it again")
    assert err.remediation == "type it again"


def test_platform_unsupported_points_at_the_capability_screen() -> None:
    """The default names where to read the platform's own reason, not a guess."""
    from core.errors import PlatformUnsupported

    err = PlatformUnsupported("no path on this platform")
    assert "Platform screen" in err.remediation
    assert "Nothing was done" in err.remediation
