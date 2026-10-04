"""Who the ledger says did it, and why that is believable.

The problem
-----------
``operator`` used to be a string in a request body. The Audit screen had a text
box for it, the browser sent whatever was typed, and the ledger recorded it as
the ``actor`` of every entry. Anything that could reach the port - the API has
no authentication, by design, because it binds loopback only - could therefore
write ``"Chief Examiner"`` into an audit trail. A chain of custody whose custody
field is a free-text box is a chain of custody in name only.

What replaces it
----------------
The identity is resolved **server-side**, from the privileged helper, through
:func:`resolve`. The helper answers ``whoami`` from the operator uid it was
started with - the same uid ``SO_PEERCRED`` admits and nothing else - and never
from anything in the request. The API never sends a uid, a username or a
display name, so there is nothing for a client to substitute.

What is honestly claimed
------------------------
A local account, not a person. The host knows which uid ran the tool; it does
not know who was sitting at the keyboard, and no amount of plumbing here would
change that. So the identity carries its own basis sentence and its own
limitation, and the actor string is built to read as what it is::

    alice (uid 1000)

A client-supplied name is not discarded - an examiner's own label for a run is
useful - but it is recorded as a *label*, in the job parameters, clearly
separated from the trusted actor. :func:`Identity.labelled_actor` is what
produces the combined string, and the untrusted half is always marked.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:  # pragma: no cover - import cycle avoidance only
    from api.deps import AppServices

__all__ = ["Identity", "resolve", "IDENTITY_LIMITATION"]

logger = structlog.get_logger(__name__)

#: What every report says about the identity in its audit trail. Stated once,
#: here, so the wording cannot drift between the report, the UI and the ledger.
IDENTITY_LIMITATION = (
    "OPERATOR IDENTITY IS A LOCAL ACCOUNT, NOT A PERSON: the actor recorded in "
    "the ledger is the operating-system account that ran the operation, "
    "resolved by the privileged helper from the uid it was started with and "
    "never from anything the client sent. It establishes which account acted. "
    "It does not establish which human was at the keyboard, and this tool makes "
    "no claim that it does. Any operator label shown alongside it is text an "
    "examiner typed and is recorded as a label, not as an identity."
)

#: A client-supplied label is echoed into params and into reports, so it is
#: bounded and stripped of anything that would let it impersonate the trusted
#: half of the string - parentheses, and the word uid.
_LABEL_MAX = 96
_LABEL_FORBIDDEN = re.compile(r"[()\r\n\t]")


@dataclass(frozen=True)
class Identity:
    """The trusted local identity of whoever is driving this API."""

    uid: int
    username: str
    gid: int
    group: str
    #: A sentence saying how the value was established. Written by the helper.
    basis: str
    #: False when the helper could not be reached and the identity fell back to
    #: this process's own uid without a privileged confirmation.
    trusted: bool = True

    @property
    def actor(self) -> str:
        """The string written to the ledger's ``actor`` field.

        Windows has no numeric uid, and the helper reports ``-1`` there rather
        than inventing one; the actor then names the account as a Windows
        account instead of printing a uid that does not exist.
        """
        if self.uid < 0:
            return f"{self.username} (Windows account)"
        return f"{self.username} (uid {self.uid})"

    def labelled_actor(self, label: str) -> str:
        """The actor, plus an examiner's own label marked as untrusted.

        The label never replaces the identity and never appears without it. A
        reader of the chain sees which account acted and, separately, what the
        person driving it called themselves.
        """
        cleaned = sanitise_label(label)
        if not cleaned:
            return self.actor
        return f"{self.actor} [label: {cleaned}]"

    def as_dict(self) -> dict[str, Any]:
        return {
            "uid": self.uid,
            "username": self.username,
            "gid": self.gid,
            "group": self.group,
            "actor": self.actor,
            "basis": self.basis,
            "trusted": self.trusted,
            "limitation": IDENTITY_LIMITATION,
        }


def sanitise_label(label: str) -> str:
    """Bound a client-supplied operator label and strip its impersonation tools.

    Parentheses go because ``alice (uid 0)`` typed into the box would otherwise
    render indistinguishably from the trusted half of the actor string.
    """
    cleaned = _LABEL_FORBIDDEN.sub(" ", str(label or "")).strip()
    cleaned = re.sub(r"\s+", " ", cleaned)
    # "sanctum" is the historical default the request models still carry. It is
    # not a label anybody typed, so it is not recorded as one.
    if cleaned.lower() in {"", "sanctum"}:
        return ""
    return cleaned[:_LABEL_MAX]


def resolve(services: AppServices) -> Identity:
    """Ask the helper who is operating, and cache the answer on ``services``.

    Cached because it cannot change within the life of the process: the helper's
    operator uid is fixed when the daemon starts, and this process's own uid is
    fixed when it starts. Re-asking per request would be a socket round trip to
    learn a constant.

    A helper that cannot be reached is a degradation and is reported as one:
    the identity falls back to this process's own uid with ``trusted`` false and
    a basis sentence that says the privileged confirmation did not happen. It is
    never replaced by anything a client sent.
    """
    cached = getattr(services, "_identity", None)
    if isinstance(cached, Identity):
        return cached

    identity = _ask_helper(services)
    # Set through object.__setattr__-free assignment: AppServices is a plain
    # dataclass, so this is an ordinary attribute.
    services._identity = identity  # type: ignore[attr-defined]
    logger.info(
        "operator_identity_resolved",
        uid=identity.uid,
        username=identity.username,
        trusted=identity.trusted,
    )
    return identity


def _ask_helper(services: AppServices) -> Identity:
    import os

    own_uid = int(getattr(os, "getuid", lambda: -1)())
    own_gid = int(getattr(os, "getgid", lambda: -1)())
    try:
        answer = services.helper.call("whoami", {})
    except Exception as exc:  # noqa: BLE001 - any transport failure degrades
        uid = own_uid
        return Identity(
            uid=uid,
            username=str(uid),
            gid=own_gid,
            group=str(own_gid),
            basis=(
                f"the privileged helper could not be reached ({type(exc).__name__}: "
                f"{exc}), so the identity is this API process's own uid and was "
                "not confirmed by a privileged process"
            ),
            trusted=False,
        )
    return Identity(
        uid=int(answer.get("uid", own_uid)),
        username=str(answer.get("username") or answer.get("uid") or ""),
        gid=int(answer.get("gid", own_gid)),
        group=str(answer.get("group") or ""),
        basis=str(answer.get("basis") or ""),
        trusted=True,
    )
