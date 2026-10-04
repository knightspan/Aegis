"""Cases: the entity everything else hangs from.

Why this exists
---------------
``case_id`` used to be a free-form string on a request body. It reached the
ledger and the report and nothing else, so there was no way to ask what a case
contained, no way to group two acquisitions of the same exhibit, and nothing to
show a reader who wants one screen that accounts for an investigation. The
engines were complete and the thing that ties them together was a text field.

Storage
-------
One JSON document per case, under ``<state>/cases/<case_id>.json``, written by
replace-through-a-temporary-file so a crash leaves either the old document or
the new one and never half of either. No database, deliberately: a case is a
handful of kilobytes, is read far more often than written, and adding a schema
migration story to a tool that has to run from a USB stick on an evidence bench
would buy nothing.

**This file is an index, not the record of what happened.** Everything it
contains about an operation is also in the hash-chained ledger, which is the
authoritative account and the only one a report is built from. Deleting the
whole ``cases`` directory loses the grouping and loses no evidence. That
asymmetry is deliberate and is why the case file is allowed to be a plain
mutable JSON document while the ledger is append-only and hash-linked: if the
two ever disagree, the ledger is right.

Identifiers
-----------
A case id becomes a filename, so it is validated rather than escaped:
:data:`CASE_ID_PATTERN` admits letters, digits, dash, underscore and dot, is
bounded, and refuses a leading dot and any form of ``..``. A name that does not
match is refused with the pattern in the message. Escaping would also work and
would leave the question "what does this filename mean" open forever.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import structlog

from core.errors import SanctumError

__all__ = [
    "CASE_ID_PATTERN",
    "CaseError",
    "Case",
    "close_case",
    "create_case",
    "load_case",
    "save_case",
    "list_cases",
    "attach_evidence",
    "attach_operation",
    "attach_report",
    "update_operation",
    "case_summary",
    "valid_case_id",
]

logger = structlog.get_logger(__name__)

#: What a case id may contain. It becomes a filename, so this is a whitelist
#: and not an escaping scheme.
CASE_ID_PATTERN = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")

CaseStatus = Literal["open", "closed"]


class CaseError(SanctumError):
    """A case could not be created, found or written."""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def valid_case_id(case_id: str) -> str:
    """Return ``case_id`` if it is a legal identifier, else raise.

    Raises:
        CaseError: the id is empty, too long, contains a path separator, or
            is any spelling of ``..``.
    """
    candidate = str(case_id or "")
    if not CASE_ID_PATTERN.match(candidate) or ".." in candidate:
        raise CaseError(
            f"{case_id!r} is not a usable case id. A case id becomes a "
            "filename, so it is checked against a whitelist rather than "
            "escaped.",
            remediation=(
                "Use 1 to 64 characters from A-Z, a-z, 0-9, dot, dash and "
                "underscore, starting with a letter or digit, with no '..' "
                "anywhere. For example: CASE-2026-001."
            ),
        )
    return candidate


@dataclass
class Case:
    """One investigation, and everything recorded against it."""

    case_id: str
    title: str = ""
    description: str = ""
    created_at: str = field(default_factory=_now)
    created_by: str = ""
    updated_at: str = field(default_factory=_now)
    status: CaseStatus = "open"
    closed_at: str = ""
    closed_by: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)
    operations: list[dict[str, Any]] = field(default_factory=list)
    reports: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "description": self.description,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "updated_at": self.updated_at,
            "status": self.status,
            "closed_at": self.closed_at,
            "closed_by": self.closed_by,
            "evidence": self.evidence,
            "operations": self.operations,
            "reports": self.reports,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Case:
        status = str(raw.get("status") or "open")
        return cls(
            case_id=str(raw.get("case_id") or ""),
            title=str(raw.get("title") or ""),
            description=str(raw.get("description") or ""),
            created_at=str(raw.get("created_at") or _now()),
            created_by=str(raw.get("created_by") or ""),
            updated_at=str(raw.get("updated_at") or _now()),
            status="closed" if status == "closed" else "open",
            closed_at=str(raw.get("closed_at") or ""),
            closed_by=str(raw.get("closed_by") or ""),
            evidence=list(raw.get("evidence") or []),
            operations=list(raw.get("operations") or []),
            reports=list(raw.get("reports") or []),
        )


def _path_for(root: Path, case_id: str) -> Path:
    return Path(root) / f"{valid_case_id(case_id)}.json"


def save_case(root: Path, case: Case) -> Path:
    """Write ``case`` atomically and return its path."""
    case.updated_at = _now()
    target = _path_for(root, case.case_id)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(case.as_dict(), indent=2, sort_keys=True).encode("utf-8")
    staging = target.with_name(f".{target.name}.partial")
    descriptor = os.open(
        staging, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0),
        0o600,
    )
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(staging, target)
    return target


def load_case(root: Path, case_id: str) -> Case:
    """Read one case.

    Raises:
        CaseError: no such case, or the document does not parse.
    """
    target = _path_for(root, case_id)
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise CaseError(
            f"No case {case_id!r} exists under {root}.",
            remediation=(
                "Create it first with POST /cases, or list the cases that do "
                "exist with GET /cases."
            ),
        ) from None
    except (OSError, ValueError) as exc:
        raise CaseError(
            f"The case document for {case_id!r} could not be read: {exc}",
            remediation=(
                "The file is not valid JSON. The ledger still holds every "
                "operation recorded against this case; the case document is an "
                "index and can be rebuilt without losing evidence."
            ),
        ) from exc
    if not isinstance(raw, dict):
        raise CaseError(
            f"The case document for {case_id!r} is not a JSON object.",
            remediation="Remove or repair the file; no evidence lives in it.",
        )
    return Case.from_dict(raw)


def create_case(
    root: Path,
    *,
    case_id: str,
    title: str = "",
    description: str = "",
    created_by: str = "",
) -> Case:
    """Create a case.

    Raises:
        CaseError: the id is illegal, or a case with that id already exists.
            Existing is an error rather than an update: silently merging into
            somebody else's case is exactly the mistake a case-management layer
            exists to prevent.
    """
    target = _path_for(root, case_id)
    if target.exists():
        raise CaseError(
            f"A case {case_id!r} already exists at {target}.",
            remediation=(
                "Use a different id, or open the existing case with "
                f"GET /cases/{case_id}. Nothing was overwritten."
            ),
        )
    case = Case(
        case_id=valid_case_id(case_id),
        title=title,
        description=description,
        created_by=created_by,
    )
    save_case(root, case)
    logger.info("case_created", case_id=case.case_id, created_by=created_by)
    return case


def close_case(root: Path, *, case_id: str, closed_by: str = "") -> Case:
    """Mark a case closed. Closing is one-way through this API.

    A closed case keeps everything recorded against it and refuses new
    evidence registrations. Operations that name it still run and are still
    chained, because refusing a job over a bookkeeping field could block a
    wipe that was authorised twice over (see :func:`attach_operation`).

    Raises:
        CaseError: no such case, or it is already closed.
    """
    case = _touch(root, case_id)
    if case.status == "closed":
        raise CaseError(
            f"Case {case_id!r} is already closed"
            + (f" (closed {case.closed_at})." if case.closed_at else "."),
            remediation="Nothing was changed. Open a new case for further work.",
        )
    case.status = "closed"
    case.closed_at = _now()
    case.closed_by = closed_by
    save_case(root, case)
    logger.info("case_closed", case_id=case.case_id, closed_by=closed_by)
    return case


def list_cases(root: Path) -> list[dict[str, Any]]:
    """Summaries of every readable case, newest first.

    An unreadable document is skipped rather than raised: one corrupt file must
    not make the case list unusable, and the file is an index - the evidence is
    in the chain.
    """
    found: list[dict[str, Any]] = []
    try:
        names = sorted(Path(root).glob("*.json"))
    except OSError:
        return []
    for path in names:
        if path.name.startswith("."):
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(raw, dict):
            found.append(case_summary(Case.from_dict(raw)))
    found.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    return found


def case_summary(case: Case) -> dict[str, Any]:
    """The dashboard row: counts, not contents."""
    return {
        "case_id": case.case_id,
        "title": case.title,
        "description": case.description,
        "status": case.status,
        "closed_at": case.closed_at,
        "closed_by": case.closed_by,
        "created_at": case.created_at,
        "created_by": case.created_by,
        "updated_at": case.updated_at,
        "evidence_count": len(case.evidence),
        "operation_count": len(case.operations),
        "report_count": len(case.reports),
        "recovered_artifact_count": sum(
            int(item.get("recovered_artifacts") or 0) for item in case.operations
        ),
    }


def _touch(root: Path, case_id: str) -> Case:
    return load_case(root, case_id)


def attach_evidence(
    root: Path,
    *,
    case_id: str,
    evidence_id: str,
    source: str,
    media_type: str,
    acquired_at: str = "",
    source_hash: str = "",
    verification_hash: str = "",
    state: str = "acquired",
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Record one exhibit against a case, replacing an entry with the same id."""
    case = _touch(root, case_id)
    if case.status == "closed":
        raise CaseError(
            f"Case {case_id!r} is closed and takes no new evidence.",
            remediation="Register the exhibit against an open case.",
        )
    record = {
        "evidence_id": evidence_id,
        "case_id": case.case_id,
        "source": source,
        "media_type": media_type,
        "acquired_at": acquired_at or _now(),
        "source_hash": source_hash,
        "verification_hash": verification_hash,
        "state": state,
        "detail": dict(detail or {}),
    }
    case.evidence = [
        item for item in case.evidence if item.get("evidence_id") != evidence_id
    ]
    case.evidence.append(record)
    save_case(root, case)
    return record


def attach_operation(
    root: Path,
    *,
    case_id: str,
    operation_id: str,
    kind: str,
    actor: str,
    evidence_id: str = "",
    params: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Record that an operation was started for a case.

    Returns ``None`` when the case does not exist. A job is **not** refused
    because its case id is unknown: refusing would mean a typo in an optional
    field could block a wipe that was otherwise authorised twice over, and the
    ledger records the run regardless. The case screen shows only what it was
    told about, and the chain shows everything.
    """
    try:
        case = _touch(root, case_id)
    except CaseError:
        logger.info("case_attach_skipped", case_id=case_id, operation_id=operation_id)
        return None
    record: dict[str, Any] = {
        "operation_id": operation_id,
        "case_id": case.case_id,
        "evidence_id": evidence_id,
        "type": kind,
        "status": "running",
        "started_at": _now(),
        "completed_at": None,
        "operator": actor,
        "result_ref": "",
        "recovered_artifacts": 0,
        "params": dict(params or {}),
    }
    case.operations = [
        item for item in case.operations if item.get("operation_id") != operation_id
    ]
    case.operations.append(record)
    save_case(root, case)
    return record


def update_operation(
    root: Path,
    *,
    case_id: str,
    operation_id: str,
    status: str,
    result_ref: str = "",
    recovered_artifacts: int = 0,
    completed_at: str = "",
    error_kind: str = "",
    verification_passed: bool | None = None,
) -> None:
    """Move an operation to its terminal state. Silent when unknown.

    ``error_kind`` is the job's own structured failure kind, so the case screen
    can tell a safety refusal (``WorkflowGateRefused``: nothing written) from an
    erase that started and failed. ``verification_passed`` is the drive erase's
    read-back verdict when it reported one; ``None`` records nothing.
    """
    try:
        case = _touch(root, case_id)
    except CaseError:
        return
    changed = False
    for item in case.operations:
        if item.get("operation_id") != operation_id:
            continue
        item["status"] = status
        item["completed_at"] = completed_at or _now()
        if result_ref:
            item["result_ref"] = result_ref
        if recovered_artifacts:
            item["recovered_artifacts"] = recovered_artifacts
        if error_kind:
            item["error_kind"] = error_kind
        if verification_passed is not None:
            item["verification_passed"] = verification_passed
        changed = True
    if changed:
        save_case(root, case)


def attach_report(
    root: Path,
    *,
    case_id: str,
    report_id: str,
    operation_id: str,
    json_name: str,
    pdf_name: str,
    report_hash: str,
    signed: bool,
    fingerprint: str = "",
) -> dict[str, Any] | None:
    """Record a generated report against a case. Silent when unknown.

    ``json_name`` and ``pdf_name`` are *names inside the reports directory*,
    never absolute paths. The API serves them through ``/artifacts``, which
    resolves them against the configured directory itself; storing an absolute
    path here would put the host's filesystem layout into a document the UI
    renders and would invite a consumer to open it directly.
    """
    try:
        case = _touch(root, case_id)
    except CaseError:
        return None
    record = {
        "report_id": report_id,
        "case_id": case.case_id,
        "operation_id": operation_id,
        "json_name": json_name,
        "pdf_name": pdf_name,
        "report_hash": report_hash,
        "signed": bool(signed),
        "pubkey_fingerprint": fingerprint,
        "generated_at": _now(),
    }
    case.reports = [
        item for item in case.reports if item.get("report_id") != report_id
    ]
    case.reports.append(record)
    save_case(root, case)
    return record
