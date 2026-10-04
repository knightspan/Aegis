"""Process-wide services the routers share.

One registry, one helper client, one ledger root, resolved once at startup and
handed to routers through FastAPI's dependency system. A module-level singleton
would work and would make the whole API untestable in a single process, because
two tests could not have two ledgers.

Everything privileged goes through :attr:`AppServices.helper`. A router never
imports :mod:`core.device` or :mod:`core.erase.drive` directly - that is the
whole point of the privilege boundary, and keeping the import out of the router
is what makes the boundary checkable by grep rather than by trust.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Generator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import structlog

from api.jobs import JobRegistry

__all__ = [
    "AppServices",
    "HelperTransport",
    "default_services",
    "default_state_dir",
    "signing_key_limitations",
]

logger = structlog.get_logger(__name__)

def default_state_dir(
    environ: dict[str, str] | None = None, platform: str | None = None
) -> Path:
    """Where the ledger, reports and recovered objects live by default.

    ``SANCTUM_STATE_DIR`` wins when it is set to something non-empty.
    Otherwise the per-user data directory each OS expects: ``~/.local/share/
    sanctum`` on Linux (``$XDG_DATA_HOME`` when set), ``%LOCALAPPDATA%\\
    Sanctum`` on Windows, ``~/Library/Application Support/Sanctum`` on macOS.

    This used to be ``Path(os.environ.get("SANCTUM_STATE_DIR", "")) or ...``,
    and ``Path("")`` is ``Path(".")``, which is truthy: with the variable
    unset the state directory was whatever directory the API was started
    from. A packaged app starts from ``/`` or ``C:\\Program Files``, where
    that is either unwritable or somewhere nobody would look for a ledger.
    """
    env = os.environ if environ is None else environ
    explicit = (env.get("SANCTUM_STATE_DIR") or "").strip()
    if explicit:
        return Path(explicit)
    host = platform or sys.platform
    if host == "win32":
        base = env.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "Sanctum"
    if host == "darwin":
        return Path.home() / "Library" / "Application Support" / "Sanctum"
    xdg = (env.get("XDG_DATA_HOME") or "").strip()
    return (Path(xdg) if xdg else Path.home() / ".local" / "share") / "sanctum"


#: Resolved once at import, for callers that read it directly.
DEFAULT_STATE_DIR = default_state_dir()


class HelperTransport(Protocol):
    """Whatever reaches the privileged helper.

    A protocol rather than a concrete class so the socket client and the
    in-process dispatcher are interchangeable, and so a test can substitute a
    recorder without a running daemon. Both real implementations run the same
    allowlist, so a substitution cannot widen what the API can ask for.

    ``call_stream`` is what the job routes use for anything long. It yields one
    progress record at a time and returns the operation's result, and closing it
    cancels the operation - which is why a wipe's progress bar moves while the
    wipe is running and why the Cancel button reaches the engine.
    """

    def call(self, method: str, params: dict[str, Any]) -> dict[str, Any]: ...

    def call_stream(
        self, method: str, params: dict[str, Any]
    ) -> Generator[dict[str, Any], None, dict[str, Any]]: ...


@dataclass
class AppServices:
    """Everything a router needs, resolved once."""

    registry: JobRegistry
    helper: HelperTransport
    state_dir: Path
    tool_version: str = "sanctum-forensics/0.0.0"
    #: Overridden in tests so a report can be signed without a real keyring.
    key_dir: Path | None = None
    limitations: list[str] = field(default_factory=list)

    @property
    def ledger_root(self) -> Path:
        return self.state_dir / "ledger"

    @property
    def reports_dir(self) -> Path:
        return self.state_dir / "reports"

    @property
    def evidence_dir(self) -> Path:
        """Acquired images. Read-only input to everything downstream."""
        return self.state_dir / "evidence"

    @property
    def recovered_dir(self) -> Path:
        """Objects carved out of evidence. Derived output, never input.

        Separate from :attr:`evidence_dir` deliberately, and not merely for
        tidiness: evidence is what the tool reads and must not modify, and
        recovered objects are what it writes. Confining a carve's ``out_dir``
        to the evidence directory would let a recovery job write files into the
        tree holding the image it is reading, which is the one place a forensic
        tool must never create anything.
        """
        return self.state_dir / "recovered"

    @property
    def cases_dir(self) -> Path:
        """Case records. See :mod:`core.cases`."""
        return self.state_dir / "cases"

    @property
    def work_dir(self) -> Path:
        """Scratch space the API owns: spilled carve payloads, demo chains.

        Inside the state directory rather than the system temp directory, so a
        deployment that confines the helper to one tree confines this too, and
        so an operator looking for what the tool wrote has one place to look.
        """
        return self.state_dir / "work"

    def prepare(self) -> None:
        """Create the directories the API writes into and wire durable jobs."""
        for directory in (
            self.state_dir,
            self.ledger_root,
            self.reports_dir,
            self.evidence_dir,
            self.recovered_dir,
            self.cases_dir,
            self.work_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        # Every finished job writes its result into the chain, so a report can
        # be rebuilt after this process is gone. Wired here rather than in
        # default_services because the test suite builds AppServices directly
        # and a durability guarantee that only held on one construction path
        # would not be one. See :mod:`api.durable`.
        self.registry.on_finish = self._record_job_outcome

    def ledger(self) -> Any:
        """A read/write handle on this deployment's chain.

        One constructor, so every caller records the same tool version and the
        same signing fingerprint in a genesis it might create. Looked up rather
        than minted: building a ledger must not have the side effect of
        creating a signing key.
        """
        from core.ledger.chain import Ledger
        from core.report.sign import fingerprint_of_existing_key

        return Ledger(
            self.ledger_root,
            tool_version=self.tool_version,
            pubkey_fingerprint=fingerprint_of_existing_key(
                self.key_dir or (self.state_dir / "keys")
            ),
        )

    def platform_snapshot(self) -> dict[str, Any]:
        """Which OS, app build and privilege a job ran under, for its report.

        Recorded in the job's parameters at submission, so it is hashed into
        the ledger with them and the certificate carries the host it was
        issued on - a Windows file erase and a Linux one are different claims
        and the report must not leave a reader to guess which.
        """
        from core.platform.host import platform_info, privilege_state

        joined = " ".join(self.limitations)
        helper = (
            "none"
            if "HELPER_NOT_REQUIRED" in joined
            else "in-process"
            if "HELPER_IN_PROCESS" in joined
            else "socket"
        )
        info = platform_info()
        privilege = privilege_state(helper=helper)
        return {
            "family": info.family,
            "os": info.os_name,
            "os_version": info.os_version,
            "os_build": info.os_build,
            "machine": info.machine,
            "app_version": info.app_version,
            "tool_version": self.tool_version,
            "packaged": info.packaged,
            "privilege": privilege.level,
            "privilege_basis": privilege.basis,
            "helper": helper,
        }

    def _record_job_outcome(self, record: Any) -> None:
        from api.durable import record_outcome

        record_outcome(self.ledger(), record)


def signing_key_limitations(services: AppServices) -> list[str]:
    """What ``/health`` says about the report check that ties a key to a chain.

    ``fingerprint_matches_genesis`` compares a report's signing key with the key
    the chain recorded at genesis. A chain started before any key existed
    records none, and the check is SKIP - not PASS - on every report that chain
    will ever carry. Nothing else surfaces that: the job routes deliberately do
    not mint a key, and the SKIP is only visible to someone reading check lines.

    Two states, because they have different remedies. Neither creates a key.
    """
    from core.ledger.chain import NO_SIGNING_KEY, genesis_fingerprint
    from core.report.sign import key_file_for

    key_dir = services.key_dir or (services.state_dir / "keys")
    recorded = genesis_fingerprint(services.ledger_root)
    if recorded == NO_SIGNING_KEY:
        return [
            "CHAIN_WITHOUT_KEY_FINGERPRINT: the ledger chain at "
            f"{services.ledger_root} was started before any signing key "
            "existed, so its genesis records no fingerprint and "
            "fingerprint_matches_genesis is SKIP, not PASS, on every report it "
            "carries. Creating a key now does not repair this chain. To tie "
            "reports to their chain, archive this ledger directory and start a "
            "new chain after the key exists."
        ]
    if recorded is None and not key_file_for(key_dir).is_file():
        return [
            f"NO_SIGNING_KEY: no report signing key exists under {key_dir} and "
            "no ledger chain has been started. The first job will start the "
            "chain with no key fingerprint in its genesis, and "
            "fingerprint_matches_genesis will then be SKIP on every report that "
            "chain carries. Create the key before the first job: "
            ".venv/bin/python scripts/hardware_validation.py keygen "
            f"--key-dir {key_dir}"
        ]
    return []


def default_services(
    *,
    state_dir: Path | None = None,
    helper: HelperTransport | None = None,
) -> AppServices:
    """Build the services for a normally-configured process.

    The helper defaults to the in-process dispatcher rather than the socket
    client, because a developer box has no root daemon running and a
    connection refused at import time would make the whole API unstartable.
    Both run the same operation allowlist. Set ``SANCTUM_HELPER_SOCKET`` to use
    the real daemon.
    """
    from helper.daemon import HelperClient, InProcessHelper

    socket_path = os.environ.get("SANCTUM_HELPER_SOCKET", "")
    if helper is None:
        helper = HelperClient(socket_path) if socket_path else InProcessHelper()

    limitations: list[str] = []
    if not socket_path and sys.platform != "linux":
        # Not a degradation here: the socket daemon exists to hold raw device
        # access for the Linux whole-drive engine, and no operation that runs
        # on Windows or macOS needs elevation. Saying "in-process" as if a
        # daemon were missing would send an operator looking for one.
        limitations.append(
            "HELPER_NOT_REQUIRED: no separate privileged helper runs on this "
            "platform. Device discovery and file erasure run unprivileged in "
            "this process. Whole-drive clear, raw acquisition and device "
            "sanitize need this process itself to be elevated (Run as "
            "administrator on Windows, sudo on macOS); until it is, the "
            "capability screen reports REQUIRES PRIVILEGE and nothing is "
            "escalated."
        )
    elif not socket_path:
        limitations.append(
            "HELPER_IN_PROCESS: no helper socket was configured, so privileged "
            "operations run with this process's own privileges rather than "
            "through the root daemon. On an unprivileged process the device "
            "operations will fail; nothing is silently escalated."
        )

    services = AppServices(
        registry=JobRegistry(),
        helper=helper,
        state_dir=Path(state_dir) if state_dir else default_state_dir(),
        limitations=limitations,
    )
    services.prepare()
    logger.info(
        "api_services_ready",
        state_dir=str(services.state_dir),
        helper=type(helper).__name__,
    )
    return services
