"""The two device gates demo-reset.sh runs before it destroys anything.

The --full gate was unpassable. ``guard_device`` wrote its identity banner and
its return value to the same stream; the caller captured it with ``$(...)``;
and the operator's correctly typed serial was compared against a string with
the whole banner glued to the front::

    REFUSED: typed 'B103B9C19DE1CCC1BD535ACB', device reports '   stage usb
    /dev/sda  TransMemory  serial B103B9C19DE1CCC1BD535ACB  7759462400 bytes
    B103B9C19DE1CCC1BD535ACB'. Nothing was written.

No input could match that. ``--quick`` never hit it because its call sites
redirect stdout to ``/dev/null``, discarding banner and serial together, so the
bug was invisible in the only mode that had ever been run.

These tests drive the gate the way ``--full`` drives it. They do not need a
device: ``gate_identity`` was extracted from ``guard_device`` precisely so the
print-versus-return split is testable on its own, which is what the defect was.
The device probing above it - block device, sysfs, root filesystem, mounts,
removable, size - still needs a real device and is still not covered here.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
GATE = REPO / "scripts" / "device-gate.sh"

SERIAL = "B103B9C19DE1CCC1BD535ACB"
DEVICE = "/dev/sda"


def run(script: str, stdin: str = "") -> subprocess.CompletedProcess[str]:
    """Source the gate library and run one snippet against it."""
    return subprocess.run(
        ["bash", "-c", f'set -uo pipefail\nsource "{GATE}"\n{script}'],
        input=stdin,
        capture_output=True,
        text=True,
    )


# --------------------------------------------------------------------------
# gate_identity: what goes on which stream


def test_only_the_serial_reaches_stdout() -> None:
    """The defect, stated as an assertion.

    Everything an operator reads has to be on stderr, or the caller's $(...)
    swallows it into the value it is about to compare a typed serial against.
    """
    result = run(
        f'serial="$(gate_identity "stage usb" "{DEVICE}" TransMemory'
        f' "{SERIAL}" 7759462400)"\n'
        'printf "[%s]" "$serial"'
    )

    assert result.returncode == 0
    assert result.stdout == f"[{SERIAL}]"


def test_the_banner_reaches_stderr() -> None:
    """Moving it off stdout must not mean losing it."""
    result = run(
        f'gate_identity "stage usb" "{DEVICE}" TransMemory "{SERIAL}" 7759462400'
        " >/dev/null"
    )

    assert result.returncode == 0
    assert "stage usb" in result.stderr
    assert "TransMemory" in result.stderr
    assert f"serial {SERIAL}" in result.stderr
    assert "7759462400 bytes" in result.stderr


# --------------------------------------------------------------------------
# confirm_serial: the gate itself


def test_the_correct_serial_proceeds() -> None:
    """--full, driven the way the operator drives it, past the gate."""
    result = run(
        f'confirm_serial "{SERIAL}" "stage usb" "{DEVICE}"\n'
        'echo PROCEEDED',
        stdin=f"{SERIAL}\n",
    )

    assert result.returncode == 0, result.stderr
    assert "PROCEEDED" in result.stdout
    assert "REFUSED" not in result.stderr


def test_the_captured_serial_is_what_the_gate_accepts() -> None:
    """The two halves composed, exactly as demo-reset.sh composes them.

    This is the end-to-end shape that was broken: capture the serial from the
    identity function, then hand it to the gate. It failed before the split
    because the captured value carried the banner.
    """
    result = run(
        f'USB_SERIAL="$(gate_identity "stage usb" "{DEVICE}" TransMemory'
        f' "{SERIAL}" 7759462400)"\n'
        f'confirm_serial "$USB_SERIAL" "stage usb" "{DEVICE}"\n'
        'echo PROCEEDED',
        stdin=f"{SERIAL}\n",
    )

    assert result.returncode == 0, result.stderr
    assert "PROCEEDED" in result.stdout


def test_a_wrong_serial_is_refused() -> None:
    result = run(
        f'confirm_serial "{SERIAL}" "stage usb" "{DEVICE}"\n'
        'echo PROCEEDED',
        stdin="NOTTHESERIAL\n",
    )

    assert result.returncode == 1
    assert "PROCEEDED" not in result.stdout
    assert "REFUSED" in result.stderr


def test_the_device_path_is_refused_by_name() -> None:
    """The mistake the prompt now exists to prevent.

    The banner shows the path more prominently than the serial, and the first
    operator to meet this gate typed the path. Saying "typed '/dev/sda', device
    reports 'B103...'" is true and unhelpful; the message names the mistake.
    """
    result = run(
        f'confirm_serial "{SERIAL}" "stage usb" "{DEVICE}"',
        stdin=f"{DEVICE}\n",
    )

    assert result.returncode == 1
    assert "device path, not the serial" in result.stderr


def test_a_device_with_no_serial_cannot_be_confirmed() -> None:
    """Otherwise the second gate is the Enter key.

    An empty expected serial makes an empty answer a match, and the gate the
    project promises - "the user types the device serial to confirm" - becomes
    a keystroke on any device the kernel could not identify.
    """
    result = run(
        'confirm_serial "" "stage usb" "/dev/sdz"\n'
        'echo PROCEEDED',
        stdin="\n",
    )

    assert result.returncode == 1
    assert "PROCEEDED" not in result.stdout
    assert "cannot be identified" in result.stderr


@pytest.mark.parametrize("typed", [f" {SERIAL} ", f"{SERIAL}\t", f" {SERIAL}"])
def test_surrounding_whitespace_is_forgiven(typed: str) -> None:
    """A pasted serial arrives with a trailing space often enough to matter.

    The comparison stays exact on content; only whitespace is stripped.
    """
    result = run(
        f'confirm_serial "{SERIAL}" "stage usb" "{DEVICE}"\n'
        'echo PROCEEDED',
        stdin=f"{typed}\n",
    )

    assert result.returncode == 0, result.stderr
    assert "PROCEEDED" in result.stdout


def test_the_prompt_names_the_format_not_the_value() -> None:
    """Echoing the serial in the prompt would defeat the gate.

    The operator has to read it off the device banner; the prompt's job is to
    say what shape the answer has and where to find it.
    """
    result = run(
        f'confirm_serial "{SERIAL}" "stage usb" "{DEVICE}"',
        stdin="wrong\n",
    )

    prompt = result.stderr.split("REFUSED")[0]
    assert "SERIAL - not the device path" in prompt
    assert f"{len(SERIAL)} characters" in prompt
    assert prompt.count(SERIAL) == 0


# --------------------------------------------------------------------------
# Both scripts use this gate, so both inherit the empty-serial refusal


def test_both_scripts_source_the_same_gate() -> None:
    """One implementation, and it is the one these tests drive.

    hardware-validation.sh used to compare "$TYPED" against "$SERIAL" inline.
    On a device the kernel could not identify both sides were "" and the Enter
    key passed the gate. It now calls confirm_serial, which refuses.
    """
    for script in ("demo-reset.sh", "hardware-validation.sh"):
        text = (REPO / "scripts" / script).read_text()
        assert "device-gate.sh" in text, script
        assert "confirm_serial" in text, script
        # The inline comparisons both scripts used to carry are gone.
        assert 'read -r -p "   Type the serial' not in text, script
