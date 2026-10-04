"""Overwrite pattern sources for software-overwrite methods.

Only the two software methods stream patterns from here. Capability-based
methods (ATA/NVMe sanitize, ATA security erase, Opal crypto erase) are executed
by the drive's own firmware and never receive a host-generated pattern; asking
this module for one is a programming error and raises.

On DOD_5220_22_M_3PASS: the historical DoD 5220.22-M sequence is a character,
its complement, then a *random* character. A random final pass cannot be
verified by reading the medium back, and unverifiable erasure is exactly what
this project refuses to ship. The third pass here is therefore a fixed zero
character, which keeps the character/complement/character shape and leaves a
result that :mod:`core.erase.verify` can actually check. That substitution is
recorded in ``docs/limitations.md``.

The method is offered only because operators are sometimes required to name it.
NIST SP 800-88r2 states that multi-pass overwrite is not needed for clear and
calls the DoD 5220.22-M pass-count language obsolete (Appendix D).
"""

from __future__ import annotations

from collections.abc import Iterator

from core.errors import UnsupportedCapability
from core.models import EraseMethod

__all__ = [
    "pattern_passes",
    "pass_count",
    "final_pattern",
    "select_fills",
    "pattern_defaults",
    "SOFTWARE_METHODS",
    "ELISION_SAFE_FILL",
]

#: The only methods this module can generate patterns for.
SOFTWARE_METHODS = frozenset(
    {EraseMethod.SINGLE_PASS_OVERWRITE, EraseMethod.DOD_5220_22_M_3PASS}
)

#: Fill byte per pass, per method. The last entry is what verification expects.
_PASS_BYTES: dict[EraseMethod, tuple[int, ...]] = {
    EraseMethod.SINGLE_PASS_OVERWRITE: (0x00,),
    EraseMethod.DOD_5220_22_M_3PASS: (0x00, 0xFF, 0x00),
}


#: The fill used in place of 0x00 when a controller does not program zeros.
#: Neither 0x00 nor 0xFF, so it is not a value a controller is likely to
#: special-case for reasons of its own, and it is the value the hardware
#: validation harness already uses as its "definitely written" marker.
ELISION_SAFE_FILL = 0xA5


def pattern_defaults(method: EraseMethod) -> tuple[int, ...]:
    """The method's own fill bytes, before any device-driven substitution."""
    return _require_software_method(method)


def select_fills(
    method: EraseMethod, *, elision_detected: bool | None, flash: bool
) -> tuple[tuple[int, ...], str]:
    """Choose the fill byte per pass, and say why.

    A zero-eliding controller acknowledges an all-zero write without programming
    a cell. The medium then reads back as zeros, the verification compares
    against zeros, and both agree about a write that never happened - the one
    pattern the flash translation layer can synthesize for free is the one being
    checked. Worse, the report names ``SINGLE_PASS_OVERWRITE`` for a write the
    device never performed: NIST SP 800-88r2 Sec. 3.1.1 describes overwrite as
    replacing target data with non-sensitive data, and an elided write replaced
    nothing. Substituting a non-zero fill is a truthfulness fix before it is a
    security one.

    Measured from the device where possible; falling back to the transport when
    calibration could not run, because a blanket rule is still better than
    verifying the fakeable pattern. Never from operator preference.

    For the three-pass method the zeros become ``0xA5`` on both ends, which
    loses the character/complement/character shape. That shape is already
    a substitution (see the module docstring) and it is worth less than passes
    that actually reach the medium.

    Returns:
        ``(fills, reason)``. ``reason`` is recorded in the ledger and the plan.
    """
    default = _require_software_method(method)
    if elision_detected:
        return (
            tuple(ELISION_SAFE_FILL if fill == 0x00 else fill for fill in default),
            f"the write calibration measured this controller acknowledging a "
            f"zero fill far faster than it programs the medium, so 0x00 passes "
            f"were replaced with 0x{ELISION_SAFE_FILL:02X} to force a real "
            f"program",
        )
    if elision_detected is None and flash:
        return (
            tuple(ELISION_SAFE_FILL if fill == 0x00 else fill for fill in default),
            f"the write calibration could not run on this flash device, so "
            f"0x00 passes were replaced with 0x{ELISION_SAFE_FILL:02X} rather "
            f"than risk verifying a pattern the controller can synthesize",
        )
    return default, "the method's own fill bytes; no write elision was measured"


def _require_software_method(method: EraseMethod) -> tuple[int, ...]:
    if method not in _PASS_BYTES:
        raise UnsupportedCapability(
            f"{method.value} is executed by device firmware and streams no "
            "host-generated pattern.",
            remediation=(
                "Dispatch this method through its firmware handler in "
                "core.erase.drive; do not route it through the overwrite path."
            ),
        )
    return _PASS_BYTES[method]


def _require_block_size(block_size: int) -> None:
    if block_size <= 0:
        raise ValueError(f"block_size must be positive, got {block_size}")


def pattern_passes(
    method: EraseMethod, *, block_size: int, fills: tuple[int, ...] | None = None
) -> Iterator[bytes]:
    """Yield one block-sized pattern buffer per overwrite pass for ``method``.

    Args:
        method: A member of :data:`SOFTWARE_METHODS`.
        block_size: Buffer length in bytes; must be positive.

    Raises:
        UnsupportedCapability: ``method`` is executed by firmware.
        ValueError: ``block_size`` is not positive.
    """
    chosen = fills if fills is not None else _require_software_method(method)
    _require_block_size(block_size)
    for fill in chosen:
        yield bytes([fill]) * block_size


def pass_count(method: EraseMethod) -> int:
    """Return how many overwrite passes ``method`` performs.

    Raises:
        UnsupportedCapability: ``method`` is executed by firmware.
    """
    return len(_require_software_method(method))


def final_pattern(
    method: EraseMethod, *, block_size: int, fills: tuple[int, ...] | None = None
) -> bytes:
    """Return the buffer the medium should hold once ``method`` completes.

    This is what :func:`core.erase.verify.verify` reads back and compares.

    Raises:
        UnsupportedCapability: ``method`` is executed by firmware.
        ValueError: ``block_size`` is not positive.
    """
    chosen = fills if fills is not None else _require_software_method(method)
    _require_block_size(block_size)
    return bytes([chosen[-1]]) * block_size
