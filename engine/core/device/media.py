"""Is this device flash, and how do we know.

``device.rotational`` is the kernel's `queue/rotational` flag, and a USB bridge
does not set it. The TransMemory stick used for hardware validation reports
``rotational: True`` — `lsblk` agrees, so it is not even a disagreement to
report — and every flash-specific caveat in the erase path was gated on
``not device.rotational``. The result was a USB flash stick whose report never
mentioned that overwrite cannot reach remapped or over-provisioned blocks.

A single negated kernel flag is not a determination. This module makes a
positive one from several signals, and returns *why*, so the report can say how
it decided rather than asserting it.

The ordering matters. Transport is checked before ``rotational`` because a
device on a USB or MMC bus is flash whatever the bridge claims about spindles:
there are no rotating USB sticks or SD cards, and the flag being wrong is the
known failure mode. ``rotational: False`` is trusted when it is set, because a
kernel that took the trouble to clear it is telling us something; ``rotational:
True`` is never trusted on its own to mean "not flash".
"""

from __future__ import annotations

import re

from core.models import Device

__all__ = ["FLASH_TRANSPORTS", "FLASH_MODEL_PATTERN", "is_flash"]

#: Buses that carry flash and nothing else. USB and MMC reach flash through a
#: bridge that may report anything; NVMe is flash by definition of the spec.
FLASH_TRANSPORTS = frozenset({"usb", "mmc", "nvme"})

#: Vendor and product strings that only appear on flash. Deliberately narrow:
#: a miss falls through to the other signals, a false hit would suppress a
#: caveat on a spinning disk, and those are not symmetric mistakes.
FLASH_MODEL_PATTERN = re.compile(
    r"""
    transmemory | cruzer | datatraveler | ultra\s*fit | sandisk | flash\s*(drive|disk)
    | \bssd\b | nvme | emmc | \bsd\s*card\b | microsd | msata | m\.2
    | samsung\s*(bar|fit|t\d) | kingston\s*dt | lexar | patriot\s*memory
    """,
    re.IGNORECASE | re.VERBOSE,
)


def is_flash(
    device: Device, *, elision_detected: bool | None = None
) -> tuple[bool, str]:
    """Whether ``device`` is flash media, and the signal that decided it.

    Args:
        device: The device to classify.
        elision_detected: Result of the write calibration, when one ran. ``True``
            means the controller acknowledged a zero fill far faster than it can
            program the medium, which only a flash translation layer does.
            ``None`` when no calibration was performed.

    Returns:
        ``(is_flash, reason)``. The reason is a sentence for the report, naming
        the signal rather than the verdict, so a reader can disagree with the
        inference and see what it rested on.
    """
    if elision_detected:
        return True, (
            "the write calibration showed the controller acknowledging a zero "
            "fill far faster than it programs the medium, which is a flash "
            "translation layer"
        )

    if device.transport in FLASH_TRANSPORTS:
        # Transport wins over the flag. A bridge that does not clear
        # queue/rotational is the documented failure mode; a rotating USB stick
        # is not a thing.
        note = ""
        if device.rotational and device.transport != "nvme":
            note = (
                f" (the kernel reports rotational=True, which a {device.transport} "
                "bridge routinely fails to clear; the transport is the stronger "
                "signal)"
            )
        return True, f"the device is on the {device.transport} bus{note}"

    if not device.rotational:
        return True, "the kernel reports queue/rotational=0"

    model = device.model or ""
    if FLASH_MODEL_PATTERN.search(model):
        return True, f"the model string {model!r} names flash media"

    return False, (
        f"no flash signal: transport {device.transport or 'unknown'!s}, "
        "queue/rotational=1, and the model string does not name flash media"
    )
