"""The privilege boundary: an allowlist, and two gates that live behind it."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from helper.daemon import OPERATIONS, HelperDaemon, InProcessHelper

from helper import rpc

from .authfx import make_authorization, patch_probe


def _uid() -> int:
    """This process's uid, or ``-1`` on Windows, which has no such number.

    The daemon takes an operator uid because SO_PEERCRED compares one; on a
    platform without either, the value is only an identifier it carries.
    """
    getuid = getattr(os, "getuid", None)
    return int(getuid()) if getuid is not None else -1


def test_the_operation_allowlist_is_closed() -> None:
    """A method name that is not in the table is refused.

    The daemon never accepts a shell string and never spawns a shell; a request
    names an operation, and the name is a lookup key in this table.
    """
    assert set(OPERATIONS) == {
        # Identity. Answered from the uid the daemon was started with and never
        # from the request, which is what stops a client naming its own
        # operator; see api/identity.py.
        "whoami",
        "enumerate_devices",
        # Read-only: the platform matrix, and one device re-read and assessed.
        # Both are answered by this host's platform adapter.
        "platform_status",
        "assess_device",
        "probe_capabilities",
        "detect_hidden_areas",
        "run_erase",
        # Continues an interrupted overwrite from its recorded checkpoint. It
        # writes to the medium, so it keeps every destructive gate.
        "resume_erase",
        "acquire_image",
        # Writes a recorded backup image onto a device. Gated at the write seam
        # by helper.authorization.revalidate_restore; always a real restore.
        "run_restore",
        # Writes a partition table and one filesystem onto an erased device.
        # Gated at the write seam by helper.authorization.revalidate_format (a
        # ``format``-kind authorization only); always a real format.
        "run_format",
        "prepare_device",
        # Read-only: a drive's native and accessible maxima, for the HPA/DCO
        # workflow. Never a SET MAX.
        "discover_hidden_area",
        # The only operation that changes a drive's HPA. Gated at the write
        # seam by helper.authorization.revalidate_hpa (an ``hpa``-kind
        # authorization only); always a real change. Never a DCO change.
        "run_hpa_change",
    }

    daemon = HelperDaemon(operator_uid=_uid())
    with pytest.raises(KeyError, match="not an allowed helper operation"):
        daemon._dispatch("rm -rf /", {})
    with pytest.raises(KeyError):
        daemon._dispatch("os.system", {})


def test_an_unknown_method_comes_back_as_an_error_frame_not_a_traceback() -> None:
    """A traceback from a root process describes the host to the caller."""
    daemon = HelperDaemon(operator_uid=_uid())
    reply = daemon.handle_frame(
        rpc.encode_request("not_a_real_operation", {}, req_id=1)
    )

    payload = json.loads(reply)
    assert "error" in payload
    assert "Traceback" not in reply.decode()
    assert payload["error"]["data"]["remediation"]


def test_a_malformed_frame_is_answered_rather_than_crashing_the_daemon() -> None:
    daemon = HelperDaemon(operator_uid=_uid())
    reply = json.loads(daemon.handle_frame(b"{not json"))
    assert "error" in reply


def test_the_in_process_helper_shares_the_daemon_allowlist() -> None:
    """The substitution cannot widen what the API is able to ask for."""
    helper = InProcessHelper()
    with pytest.raises(rpc.RpcError) as caught:
        helper.call("anything_else", {})
    assert "not an allowed helper operation" in caught.value.message


def _device(serial: str = "SYN-1") -> Any:
    from core.models import Device

    return Device(
        path="/dev/fake",
        model="SYNTHETIC",
        serial=serial,
        size_bytes=1024 * 1024,
        rotational=True,
        transport="sata",
        is_system_disk=False,
        mounted_at=[],
        pt_type=None,
        by_id_path=None,
    )


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason=(
        "run_erase reaches the Linux whole-drive engine; on Windows and macOS "
        "the adapter refuses it before anything is opened, which "
        "tests/platform/ pins"
    ),
)
@pytest.mark.parametrize(
    "extra",
    [{}, {"dry_run": True}, {"dry_run": False}, {"simulation": True}],
    ids=["no-authorization", "dry_run-true", "dry_run-false", "simulation"],
)
def test_run_erase_never_reaches_the_engine_without_an_authorization(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, extra: dict[str, Any]
) -> None:
    """The gate lives behind the boundary, so the API cannot forget it.

    There is no non-writing mode for a request to fall back to. A request with
    no authorization - or one still asking for the removed rehearsal - is
    refused here, in the privileged process, before the engine is entered.
    """
    import core.erase.drive as drive_mod
    from core.errors import WorkflowGateRefused

    def tripwire(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("the engine was entered without an authorization")

    monkeypatch.setattr("core.device.enumerate.get_device", lambda path: _device())
    monkeypatch.setattr("core.device.capabilities.probe", lambda device: None)
    monkeypatch.setattr(drive_mod, "execute", tripwire)

    daemon = HelperDaemon(operator_uid=_uid())
    with pytest.raises(WorkflowGateRefused):
        daemon._dispatch(
            "run_erase",
            {
                "path": "/dev/fake",
                "job_id": "j",
                "typed_serial": "SYN-1",
                "ledger_root": str(tmp_path / "ledger"),
                **extra,
            },
        )


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason=(
        "run_erase reaches the Linux whole-drive engine; on Windows and macOS "
        "the adapter refuses it before anything is opened, which "
        "tests/platform/ pins"
    ),
)
def test_run_erase_refuses_a_mismatched_serial_behind_the_boundary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Re-checked against the serial this process reads, not the one it was sent.

    A stale UI cannot authorise a wipe of a device that was swapped since the
    page loaded.

    The refusal is now raised by :func:`core.device.guard.assert_serial_confirmed`
    rather than by a second comparison inside the handler, so this asserts the
    property - a mismatch is refused, the device is named, and nothing was
    modified - instead of the deleted duplicate's exact sentence. The guard
    deliberately does not echo the device's real serial into the message; it is
    the token that authorises the operation, and ``api.jobs._redact`` exists to
    keep it from being repeated back.
    """
    from core.errors import ConfirmationMismatch

    monkeypatch.setattr(
        "core.device.enumerate.get_device", lambda path: _device("ACTUAL-SERIAL")
    )
    # A valid authorization, so the confirmation gate is what refuses: the
    # write-seam authorization check runs first and has its own tests.
    patch_probe(monkeypatch, _device("ACTUAL-SERIAL"))
    authorization = make_authorization(tmp_path, _device("ACTUAL-SERIAL"))

    daemon = HelperDaemon(operator_uid=_uid())
    with pytest.raises(ConfirmationMismatch) as caught:
        daemon._dispatch(
            "run_erase",
            {
                "path": "/dev/fake",
                "job_id": "j",
                "level": "CLEAR",
                "typed_serial": "WHAT-THE-UI-BELIEVED",
                "ledger_root": str(tmp_path / "ledger"),
                **authorization,
            },
        )

    assert "/dev/fake" in caught.value.message
    assert "does not match" in caught.value.message
    assert "Nothing has been modified" in caught.value.remediation


def _serial_less_device() -> Any:
    """A stick that reports no serial but does have a stable by-id link.

    Not a hypothetical: the USB media used for hardware validation is this
    shape whenever the bridge declines to pass the serial through.
    """
    from core.models import Device

    return Device(
        path="/dev/fake",
        model="SYNTHETIC",
        serial="",
        size_bytes=1024 * 1024,
        rotational=True,
        transport="usb",
        is_system_disk=False,
        mounted_at=[],
        pt_type=None,
        by_id_path="/dev/disk/by-id/usb-SYNTHETIC_no_serial-0:0",
    )


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason=(
        "run_erase reaches the Linux whole-drive engine; on Windows and macOS "
        "the adapter refuses it before anything is opened, which "
        "tests/platform/ pins"
    ),
)
def test_a_device_with_no_serial_is_confirmed_by_its_by_id_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The gate the helper's own copy of the rule used to make unpassable.

    ``core.device.guard.assert_serial_confirmed`` accepts the stable by-id path
    for a device that reports no serial, because there is nothing else the
    operator can read off the capability report. The helper's duplicate demanded
    an exact serial match, so it rejected that path and accepted ``""`` - which
    then failed further in, naming a gate the operator had not touched. The net
    effect was that a serial-less device could not be erased at all.

    This asserts only that the confirmation gate is passed. What follows fails
    for want of a real device, which is a different refusal and the point.
    """
    import core.erase.drive as drive_mod
    from core.errors import ConfirmationMismatch, WorkflowGateRefused

    class ReachedEngine(Exception):
        """The confirmation gate passed and the engine was about to run."""

    def engine(job: Any, *_a: Any, **_k: Any) -> Any:
        raise ReachedEngine(job.confirmed_serial)

    monkeypatch.setattr(
        "core.device.enumerate.get_device", lambda path: _serial_less_device()
    )
    # Nothing past the gate may touch the host: the probe and the engine are
    # replaced, so the suite never runs hdparm, lsblk or sedutil against a disk.
    monkeypatch.setattr("core.device.capabilities.probe", lambda device: None)
    monkeypatch.setattr(drive_mod, "execute", engine)
    patch_probe(monkeypatch, _serial_less_device())
    # A valid authorization, so the write seam passes and the confirmation
    # gate behind it is what this exercises.
    authorization = make_authorization(tmp_path / "a", _serial_less_device())

    daemon = HelperDaemon(operator_uid=_uid())
    with pytest.raises(Exception) as caught:  # noqa: B017 - the kind is the assertion
        daemon._dispatch(
            "run_erase",
            {
                "path": "/dev/fake",
                "job_id": "j",
                "level": "CLEAR",
                "typed_serial": "/dev/disk/by-id/usb-SYNTHETIC_no_serial-0:0",
                "ledger_root": str(tmp_path / "ledger"),
                **authorization,
            },
        )

    assert not isinstance(caught.value, WorkflowGateRefused), caught.value
    assert isinstance(caught.value, ReachedEngine), caught.value
    assert not isinstance(caught.value, ConfirmationMismatch), (
        "the by-id path is the only confirmation value a serial-less device has; "
        f"refusing it makes the device unerasable: {caught.value}"
    )


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason=(
        "run_erase reaches the Linux whole-drive engine; on Windows and macOS "
        "the adapter refuses it before anything is opened, which "
        "tests/platform/ pins"
    ),
)
def test_a_serial_less_device_still_refuses_a_wrong_confirmation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Delegating the check must not have widened it."""
    from core.errors import ConfirmationMismatch

    monkeypatch.setattr(
        "core.device.enumerate.get_device", lambda path: _serial_less_device()
    )
    patch_probe(monkeypatch, _serial_less_device())

    daemon = HelperDaemon(operator_uid=_uid())
    for number, typed in enumerate(("", "not-the-by-id-path", "/dev/fake")):
        # One authorization per attempt: the seam consumes it, and the property
        # under test is the confirmation gate behind it.
        authorization = make_authorization(
            tmp_path / f"a{number}",
            _serial_less_device(),
            auth_id=f"auth-00000000000000{number:02d}",
        )
        with pytest.raises(ConfirmationMismatch):
            daemon._dispatch(
                "run_erase",
                {
                    "path": "/dev/fake",
                    "job_id": "j",
                    "level": "CLEAR",
                    "typed_serial": typed,
                    "ledger_root": str(tmp_path / "ledger"),
                    **authorization,
                },
            )


def test_the_helper_does_not_reimplement_the_confirmation_rule() -> None:
    """Static guard: one implementation, called from both sides of the boundary.

    A second comparison here is a second place the rule can be fixed in one
    spot and left wrong in the other, which is exactly what happened.
    """
    import core.platform.linux as linux_adapter
    import helper.daemon as daemon_module

    helper_source = Path(daemon_module.__file__).read_text(encoding="utf-8")
    # The destructive path lives in the platform adapter now; the helper
    # delegates to it and must not grow a second comparison of its own.
    adapter_source = Path(linux_adapter.__file__).read_text(encoding="utf-8")

    assert "guard.assert_serial_confirmed(device, typed_serial)" in adapter_source
    assert "execute_drive_sanitization(params)" in helper_source
    assert "typed_serial != device.serial" not in helper_source
    assert "typed_serial != device.serial" not in adapter_source


def test_the_socket_is_created_owner_only(short_socket_dir: Path) -> None:
    """Mode 0600, set after bind because the umask applies during it.

    ``short_socket_dir`` rather than ``tmp_path``: an AF_UNIX path is capped
    near 104 bytes on macOS, where pytest's temporary directory is longer.
    """
    import stat

    socket_path = short_socket_dir / "h.sock"
    daemon = HelperDaemon(operator_uid=_uid(), socket_path=str(socket_path))
    try:
        daemon.bind()
        mode = stat.S_IMODE(socket_path.stat().st_mode)
        assert mode == 0o600, f"socket mode is {oct(mode)}, not 0600"
    finally:
        daemon.close()


def test_a_root_daemon_hands_the_socket_to_the_operator(
    short_socket_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A root-owned 0600 socket would lock out the one uid it exists to serve."""
    chowned: list[tuple[str, int, int]] = []
    monkeypatch.setattr("helper.daemon.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "helper.daemon.os.chown",
        lambda path, uid, gid: chowned.append((str(path), uid, gid)),
    )
    socket_path = short_socket_dir / "h.sock"
    daemon = HelperDaemon(operator_uid=_uid(), socket_path=str(socket_path))
    try:
        daemon.bind()
    finally:
        daemon.close()
    assert chowned == [(str(socket_path), _uid(), -1)]
