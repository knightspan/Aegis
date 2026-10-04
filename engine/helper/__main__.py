"""Start the privileged helper.

    sudo .venv/bin/python -m helper \
        --operator-uid "$(id -u)" \
        --state-dir /var/lib/sanctum-demo

Both arguments are required and neither is guessed.

The uid is required because a daemon that inferred its operator from the
invoking environment would accept whoever `sudo` happened to be called by, and
the whole point of ``SO_PEERCRED`` authentication is that the set of uids
allowed to ask for a raw device operation is decided once, deliberately, by the
person starting the root process. It is also the uid every file this daemon
creates in the ledger is handed to, so the unprivileged API can read back the
chain a wipe wrote.

The state directory is required for the same reason in a different key: a
request body names ``ledger_root`` and ``dest``, and a **root** process that
took either of those at face value would create files anywhere the caller
asked, in front of an API with no authentication. Fixing the directory
out-of-band, at the moment a human types sudo, is what turns those fields from
a write-anywhere primitive into a choice of filename.

This module is the entry point and nothing else: every rule it enforces lives in
:class:`helper.daemon.HelperDaemon`, so starting the daemon by hand and starting
it this way cannot diverge.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from helper.daemon import SOCKET_PATH, HelperDaemon

__all__ = ["main"]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m helper",
        description=(
            "Run the root-privileged helper. It serves five allowlisted "
            "operations over a 0600 Unix socket and spawns no shell."
        ),
    )
    parser.add_argument(
        "--operator-uid",
        type=int,
        required=True,
        help=(
            "The one uid allowed to connect. Any other peer is dropped before "
            "its request is read. Usually $(id -u) for the account running the "
            "API."
        ),
    )
    parser.add_argument(
        "--state-dir",
        required=True,
        help=(
            "The one directory tree this daemon may write into. Every path in "
            "a request is resolved and refused if it lands outside it. Use the "
            "same value as the API's SANCTUM_STATE_DIR."
        ),
    )
    parser.add_argument(
        "--socket",
        default=SOCKET_PATH,
        help=f"Socket path (default: {SOCKET_PATH}).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Serve until interrupted. Returns a process exit code."""
    args = _parser().parse_args(argv)

    if sys.platform != "linux":
        # The daemon authenticates every peer with SO_PEERCRED, which only
        # Linux has, and it exists to hold raw device access for the Linux
        # whole-drive engine. No operation implemented on Windows or macOS
        # needs a privileged process, so none is started - rather than a
        # socket that would have to serve without peer authentication.
        print(
            "The privileged helper is Linux-only. On this platform no "
            "implemented operation needs elevation: device discovery and file "
            "erasure run in the unprivileged app, and whole-drive "
            "sanitization is not offered.",
            file=sys.stderr,
        )
        return 2

    if os.geteuid() != 0:
        print(
            "The helper must run as root: it exists to be the one process that "
            "holds raw device access.\n"
            f"Try: sudo {sys.executable} -m helper "
            f"--operator-uid {os.getuid()} --state-dir <your state dir>",
            file=sys.stderr,
        )
        return 2

    if args.operator_uid == 0:
        # Not refused: root-only is more restrictive, not less. But it is almost
        # always a mistake, because the API that needs to connect is meant to be
        # the unprivileged half of this design.
        print(
            "warning: --operator-uid 0 means only root may connect. The API is "
            "meant to run unprivileged; pass that account's uid instead.",
            file=sys.stderr,
        )

    state_dir = Path(args.state_dir)
    if not state_dir.is_dir():
        print(
            f"--state-dir {state_dir} does not exist. Create it before starting "
            "the helper - this daemon confines every write to it, and a "
            "directory it had to invent would be one nobody chose.",
            file=sys.stderr,
        )
        return 2

    daemon = HelperDaemon(
        operator_uid=args.operator_uid,
        socket_path=args.socket,
        state_dir=state_dir,
    )
    try:
        daemon.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        # Removes the socket. Leaving a stale 0600 socket behind would make the
        # next start replace it anyway, but an operator inspecting /run should
        # not find a path that answers nothing.
        daemon.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
