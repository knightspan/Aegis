"""The root helper writes inside one directory, chosen before it started.

``ledger_root`` and ``dest`` arrive in a request body, and the process that acts
on them is root, behind an API with no authentication. Taken at face value they
are a write-anywhere-as-root primitive; the previous batch declined to build the
obvious fix (a root ``chown -R`` aimed by a caller-supplied path) for exactly
that reason.

What makes them safe is that the directory is fixed out-of-band - by the human
who typed ``sudo python -m helper --state-dir ...`` - and every path in every
request is resolved against it before any handler runs. The fields become a
choice of filename rather than a choice of filesystem.

The second half of the policy is ownership: the daemon stamps its
``--operator-uid`` onto each request so the ledger hands the operator the files
it creates. Without it a helper-run wipe leaves ``0600`` root-owned blobs that
the unprivileged API cannot read back, and the certificate beat of the demo
fails on a permission error.
"""

from __future__ import annotations

import os
import sys
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from helper.daemon import HelperClient, HelperDaemon

from helper import rpc

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason=(
        "the helper daemon serves a Unix socket and authenticates every peer "
        "with SO_PEERCRED, which is Linux-only; helper/__main__.py refuses to "
        "start elsewhere rather than serve unauthenticated. The in-process "
        "helper is covered on every platform."
    ),
)


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    root = tmp_path / "state"
    (root / "ledger").mkdir(parents=True)
    (root / "evidence").mkdir(parents=True)
    return root


@pytest.fixture
def daemon(state_dir: Path) -> HelperDaemon:
    return HelperDaemon(operator_uid=os.getuid(), state_dir=state_dir)


# --------------------------------------------------------------------------
# Confinement
# --------------------------------------------------------------------------


def test_a_ledger_root_inside_the_state_dir_is_accepted_and_resolved(
    daemon: HelperDaemon, state_dir: Path
) -> None:
    """The ordinary case, and the path the handler sees is absolute."""
    allowed = daemon.apply_policy({"ledger_root": str(state_dir / "ledger")})

    assert allowed["ledger_root"] == str((state_dir / "ledger").resolve())


def test_a_relative_ledger_root_is_taken_against_the_state_dir(
    daemon: HelperDaemon, state_dir: Path
) -> None:
    """A relative path cannot escape, and needs no absolute path to be usable."""
    allowed = daemon.apply_policy({"ledger_root": "ledger"})

    assert allowed["ledger_root"] == str((state_dir / "ledger").resolve())


def test_an_absolute_ledger_root_outside_the_state_dir_is_refused(
    daemon: HelperDaemon, tmp_path: Path
) -> None:
    """The write-anywhere-as-root primitive, refused before a handler runs."""
    with pytest.raises(PermissionError) as raised:
        daemon.apply_policy({"ledger_root": str(tmp_path / "elsewhere")})

    assert "outside the helper's state directory" in str(raised.value)
    assert "runs as root" in str(raised.value)


def test_a_traversal_ledger_root_is_refused(daemon: HelperDaemon) -> None:
    """``..`` is resolved, not string-matched."""
    with pytest.raises(PermissionError):
        daemon.apply_policy({"ledger_root": "../../../../etc/sanctum"})


def test_a_symlink_planted_in_the_state_dir_cannot_lead_out_of_it(
    daemon: HelperDaemon, state_dir: Path, tmp_path: Path
) -> None:
    """The check that makes this a boundary rather than a prefix test.

    A comparison on the requested string would accept this: the path *starts
    with* the state directory. It resolves somewhere else entirely.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    (state_dir / "escape").symlink_to(outside)

    with pytest.raises(PermissionError):
        daemon.apply_policy({"ledger_root": "escape/ledger"})


def test_dest_is_confined_too(daemon: HelperDaemon, tmp_path: Path) -> None:
    """``acquire_image`` writes an image file, and it is root that writes it."""
    with pytest.raises(PermissionError):
        daemon.apply_policy({"dest": "/etc/planted.dd"})


def test_an_unconfined_daemon_confines_no_path(tmp_path: Path) -> None:
    """The in-process helper holds no privilege, so there is nothing to confine.

    It runs as the operator already, so a path it accepts is a path the caller
    could have written to directly. Every path parameter therefore survives
    untouched, which is the property this test exists for.
    """
    unconfined = HelperDaemon(operator_uid=os.getuid(), state_dir=None)
    params = {"ledger_root": "/tmp/anywhere", "dest": "/tmp/out.dd"}

    applied = unconfined.apply_policy(params)

    assert applied["ledger_root"] == "/tmp/anywhere"
    assert applied["dest"] == "/tmp/out.dd"


def test_identity_is_stamped_even_when_nothing_is_confined() -> None:
    """The identity fields are policy, not confinement, so they are always set.

    ``whoami`` is answered from ``owner_uid`` and ``identity_basis``, and both
    are written here on every request regardless of whether a state directory
    exists. If they were only stamped on the confined path, the in-process
    deployment would answer from whatever the caller sent - which is the exact
    spoof the trusted-identity work removed.
    """
    unconfined = HelperDaemon(operator_uid=os.getuid(), state_dir=None)

    applied = unconfined.apply_policy(
        {"owner_uid": 0, "identity_basis": "trust me"}
    )

    assert applied["owner_uid"] == os.getuid()
    assert applied["identity_basis"] != "trust me"
    assert "in-process" in applied["identity_basis"]


# --------------------------------------------------------------------------
# Ownership
# --------------------------------------------------------------------------


def test_the_owner_uid_comes_from_the_daemon_not_the_request(
    daemon: HelperDaemon, state_dir: Path
) -> None:
    """A caller must not be able to hand a root-created file to somebody else.

    ``--operator-uid`` is decided when a human types the sudo command. A request
    that names its own ``owner_uid`` has it overwritten, not honoured.
    """
    allowed = daemon.apply_policy(
        {"ledger_root": "ledger", "owner_uid": 31337}
    )

    assert allowed["owner_uid"] == os.getuid()


def test_the_request_is_not_mutated_in_place(
    daemon: HelperDaemon, state_dir: Path
) -> None:
    """The caller's dict is theirs; policy returns a new one."""
    original = {"ledger_root": "ledger"}
    daemon.apply_policy(original)

    assert original == {"ledger_root": "ledger"}


# --------------------------------------------------------------------------
# A refusal is an answer, not a dead daemon
# --------------------------------------------------------------------------


@contextmanager
def running_daemon(socket_path: Path, state_dir: Path) -> Iterator[HelperDaemon]:
    served = HelperDaemon(
        operator_uid=os.getuid(),
        socket_path=str(socket_path),
        state_dir=state_dir,
    )
    served.bind()
    thread = threading.Thread(target=served.serve_forever, daemon=True)
    thread.start()
    try:
        yield served
    finally:
        served.stop()
        served.close()
        thread.join(timeout=1.0)


def test_a_refused_path_comes_back_as_an_error_frame_and_the_daemon_survives(
    tmp_path: Path, state_dir: Path
) -> None:
    """The failure mode BATCH4 FINDING 3 was about, on the new code path.

    ``run_erase`` is streamed, and the policy check runs before the engine
    generator exists. An exception escaping there would propagate out of
    ``serve_forever`` and stop the helper for every operator on the box.
    """
    # Short path: AF_UNIX socket names are capped near 108 bytes, and pytest's
    # tmp_path is longer than that on this tree. `/tmp` was hardcoded here,
    # which on Windows resolves to C:\\tmp and does not exist.
    socket_dir = Path(tempfile.mkdtemp(prefix="snc-"))
    socket_path = socket_dir / "h.sock"

    try:
        with running_daemon(socket_path, state_dir):
            client = HelperClient(str(socket_path), idle_timeout=10.0)

            with pytest.raises(rpc.RpcError) as raised:
                list(
                    client.call_stream(
                        "run_erase",
                        {
                            "path": "/dev/null",
                            "ledger_root": "/etc/sanctum-planted",
                            "job_id": "job-1",
                        },
                    )
                )
            assert "outside the helper's state directory" in raised.value.message

            # Still serving: a second request is answered rather than timing out
            # against a process that died on the first. ``whoami`` touches no
            # device; a probe would run discovery against this machine's disks.
            assert client.call("whoami", {})["uid"] == os.getuid()
    finally:
        for leftover in socket_dir.iterdir():
            leftover.unlink()
        socket_dir.rmdir()

    assert not Path("/etc/sanctum-planted").exists()
