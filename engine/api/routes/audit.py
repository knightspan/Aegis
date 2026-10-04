"""``/ledger/verify`` and ``/reports/*`` - the audit surface.

The two endpoints answer different questions and must not be conflated.
``/ledger/verify`` asks whether *this host's* chain is internally consistent.
``/reports/{job_id}/verify`` asks whether *a particular report* is what it says
it is, which is a claim a third party checks on their own machine with only the
file in front of them.

The report verification runs the five checks independently and reports each
one, rather than reducing them to a single pass/fail. They fail for different
reasons and a reader needs to know which: a broken signature means the bytes
changed, while an unverifiable fingerprint means only that the key was not
published anywhere this host can reach - which is not a defect in the report at
all.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.cases import attach_report
from core.errors import SanctumError
from fastapi import APIRouter, Depends

from api.deps import AppServices
from api.routes.common import get_services, sanctum_error_response
from api.routes.models import ReportRequest, TamperDemoRequest

__all__ = ["router"]

router = APIRouter(tags=["audit"])


def _ledger(services: AppServices) -> Any:
    from core.ledger.chain import Ledger

    return Ledger(
        services.ledger_root,
        tool_version=services.tool_version,
        pubkey_fingerprint="",
    )


@router.get("/ledger/verify")
def verify_chain(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    """Walk the hash chain and report its status.

    Entry N contains the SHA-256 of entry N-1, so a modified or removed entry
    breaks every link after it. The verification names the first broken seq
    rather than only saying "invalid": an examiner needs to know how much of
    the chain is still trustworthy, which is everything before the break.
    """
    from core.errors import LedgerChainBroken

    try:
        ledger = _ledger(services)
        verification = ledger.verify(check_blobs=True)
        entries = ledger.entries()
    except LedgerChainBroken as exc:
        raise sanctum_error_response(
            "LedgerChainBroken", exc.message, exc.remediation
        ) from exc
    except (OSError, ValueError) as exc:
        return {
            "status": "EMPTY",
            "entry_count": 0,
            "explanation": f"No readable ledger at {services.ledger_root}: {exc}",
            "entries": [],
        }

    return {
        "status": verification.status.value,
        "entry_count": verification.entry_count,
        "explanation": verification.explanation,
        "first_broken_seq": getattr(verification, "first_broken_seq", None),
        "root": str(services.ledger_root),
        # Newest first: the audit screen shows the tail, which is what an
        # operator has just done and is looking for.
        "entries": [json.loads(item.model_dump_json()) for item in reversed(entries)],
    }


@router.get("/ledger/entries")
def ledger_entries(
    limit: int = 200, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    """The chain's entries, newest first, without re-verifying it."""
    try:
        entries = _ledger(services).entries()
    except (OSError, ValueError):
        return {"entries": [], "entry_count": 0}
    ordered = list(reversed(entries))[: max(limit, 0)]
    return {
        "entries": [json.loads(item.model_dump_json()) for item in ordered],
        "entry_count": len(entries),
    }


@router.post("/ledger/tamper-demo")
def tamper_demo(
    body: TamperDemoRequest,
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    """Break a **copy** of this host's chain and show the real verifier's verdict.

    Why a demonstration endpoint exists at all
    ------------------------------------------
    "Entry N contains the SHA-256 of entry N-1, so tampering is detected" is a
    sentence. What convinces somebody is watching the verifier that guards the
    real chain report BROKEN at the exact sequence number that was altered, and
    report the entries before it as still intact. This runs exactly that, on
    exactly that code path - :meth:`core.ledger.chain.Ledger.verify` - with no
    separate demo implementation anywhere.

    The production chain is not touched
    -----------------------------------
    The chain file and its blob store are **copied** into a fresh scratch
    directory under the API's work directory, and the copy is what gets
    modified. The live ledger is opened read-only for the copy and is never
    opened for writing here, so the demonstration cannot damage the evidence it
    exists to explain. The scratch directory is removed before the response is
    built, whatever happened.

    What is modified
    ----------------
    One field of one entry: the ``actor`` string, which is a change an insider
    with write access would plausibly want to make and the smallest edit that
    is unambiguously an edit. The entry's ``entry_hash`` is deliberately left
    as it was, because that is what an attacker who did not recompute the chain
    would leave, and it is what the ``HASH_MISMATCH`` verdict is *for*. The
    response reports both the before and after verdicts, so a reader can see
    that the same verifier said VALID a moment earlier.
    """
    import shutil
    import tempfile

    from core.ledger.chain import Ledger
    from core.ledger.store import CHAIN_FILENAME

    live = _ledger(services)
    try:
        before = live.verify(check_blobs=True)
        entries = live.entries()
    except (OSError, ValueError) as exc:
        raise sanctum_error_response(
            "LedgerChainBroken",
            f"The chain could not be read: {exc}",
            "There is nothing to demonstrate against. Run an operation first.",
        ) from exc

    if len(entries) < 2:
        raise sanctum_error_response(
            "LedgerChainBroken",
            f"The chain holds {len(entries)} entr"
            f"{'y' if len(entries) == 1 else 'ies'}. A tamper demonstration "
            "needs at least two, because the point of it is that entries "
            "*before* the alteration remain verifiable.",
            "Run an operation - an acquisition or a recovery - and try again. "
            "Nothing was modified.",
        )

    available = [entry.seq for entry in entries]
    # Default to the middle: it shows both halves of the verdict. Genesis is
    # excluded because breaking it leaves no verified prefix to point at.
    target_seq = body.seq if body.seq is not None else available[len(available) // 2]
    if target_seq not in available or target_seq == 0:
        raise sanctum_error_response(
            "LedgerChainBroken",
            f"Sequence {target_seq} is not an alterable entry of this chain "
            f"(it holds {available[0]}..{available[-1]}, and entry 0 is the "
            "genesis, which has no prefix to keep).",
            "Pick a sequence number the ledger listing shows, above 0. "
            "Nothing was modified.",
        )

    services.work_dir.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="tamper-demo-", dir=str(services.work_dir)))
    try:
        # Copied, not moved and not symlinked. The live tree is read here and
        # written nowhere.
        shutil.copytree(services.ledger_root, scratch / "chain")
        copied_root = scratch / "chain"
        chain_file = copied_root / "ledger" / CHAIN_FILENAME

        lines = chain_file.read_bytes().split(b"\n")
        altered_index: int | None = None
        original_actor = ""
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            record = json.loads(line)
            if int(record.get("seq", -1)) != target_seq:
                continue
            original_actor = str(record.get("actor", ""))
            record["actor"] = _flip_actor(original_actor)
            # Written back with the same separators the canonical form uses, so
            # the only difference between this line and the one it replaces is
            # the field that was edited.
            lines[index] = json.dumps(
                record, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
            altered_index = index
            break
        if altered_index is None:  # pragma: no cover - guarded by the seq check
            raise sanctum_error_response(
                "LedgerChainBroken",
                f"Entry {target_seq} vanished from the chain between reading it "
                "and copying it.",
                "Re-run the demonstration. Nothing was modified.",
            )
        chain_file.write_bytes(b"\n".join(lines))

        after = Ledger(
            copied_root,
            tool_version=services.tool_version,
            pubkey_fingerprint="",
        ).verify(check_blobs=True)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    return {
        "demonstration": True,
        "production_ledger_modified": False,
        "production_ledger_root": str(services.ledger_root),
        "tampered_seq": target_seq,
        "field": "actor",
        "original_value": original_actor,
        "modified_value": _flip_actor(original_actor),
        "before": {
            "status": before.status.value,
            "explanation": before.explanation,
            "entry_count": before.entry_count,
            "first_broken_seq": before.first_bad_seq,
        },
        "after": {
            "status": after.status.value,
            "explanation": after.explanation,
            "entry_count": after.entry_count,
            "first_broken_seq": after.first_bad_seq,
            "failure_kind": after.failure_kind.value if after.failure_kind else None,
            "verified_through": after.verified_through,
            "unverifiable_count": after.unverifiable_count,
        },
        "note": (
            "The chain above was copied to a scratch directory, one field of "
            f"entry {target_seq} was changed there, and the copy was handed to "
            "the same verifier that guards the live chain. The live chain was "
            "opened read-only and is unchanged; the scratch copy has already "
            "been deleted."
        ),
    }


def _flip_actor(value: str) -> str:
    """The altered value, chosen to be obviously an alteration.

    Not a random string: a reader comparing the before and after has to see at
    a glance that one field moved and nothing else did.
    """
    return f"{value}-TAMPERED" if value else "TAMPERED"


@router.post("/reports/{job_id}")
def generate_report(
    job_id: str,
    body: ReportRequest,
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    """Build, sign and write the JSON and PDF artifacts for one job.

    The JSON is authoritative and the PDF is not: the signature covers the
    canonical JSON bytes, and the PDF is a rendering for a human. That
    distinction is printed on the PDF itself so nobody has to be told.

    **Only for a job in a terminal state** (MANUAL_REPORT FINDING 1). A report
    generated seconds into a carve used to be signed with an empty recovery
    section and pass every check. Two refusals, because they are two
    situations with two remedies:

    * ``JobNotFinished`` (409) - the job is pending or running. Wait.
    * ``JobNotKnown`` (404) - this process holds no record of the job: it was
      never submitted here, or the API restarted since it ran. The result a
      report is built from lived in that process and is gone; the refusal says
      what the chain still holds for the job so the two cases can be told
      apart.

    A ``failed`` or ``cancelled`` job gets a report - documenting a failure is
    legitimate - with ``job_state`` in ``case_identity`` and a first limitation
    naming the state, so the artifact says what it documents.
    """
    from core.report.render import (
        build_carve_report,
        build_destroy_report,
        build_file_erase_report,
        build_report,
        drive_report_inputs,
        write_report,
    )
    from core.report.sign import (
        fingerprint,
        load_or_create_key,
        public_key_of,
        sign_report,
    )

    from api.durable import status_for

    # The registry first, the chain second. A restart no longer destroys report
    # accessibility: the job's result was written into the chain when it
    # finished, so this rebuilds the same inputs the original process had
    # rather than refusing. See :mod:`api.durable`.
    status = status_for(services, job_id)
    if status is None:
        raise _unknown_job(services, job_id)
    state = str(status.get("state") or "")
    if state not in _TERMINAL_STATES:
        raise sanctum_error_response(
            "JobNotFinished",
            f"Job {job_id!r} is {state}, not finished. A report built now would "
            "be signed over a result that does not exist yet: its sections "
            "would be empty and every verification check would still pass.",
            f"Wait until GET /jobs/{job_id} reports a state of complete, failed "
            "or cancelled, then generate the report. Nothing was written.",
        )

    ledger = _ledger(services)
    try:
        verification = ledger.verify()
        excerpt = [
            json.loads(entry.model_dump_json())
            for entry in ledger.entries()
            if ledger.params_of(entry).get("job_id") == job_id
            or entry.operation == "GENESIS"
        ]
    except (OSError, ValueError) as exc:
        raise sanctum_error_response(
            "LedgerChainBroken",
            f"The ledger at {services.ledger_root} could not be read: {exc}",
            "A report without a ledger excerpt is not independently auditable. "
            "Check that the ledger root exists and is readable.",
        ) from exc

    try:
        from core.report.sign import key_file_for

        creating = not key_file_for(
            services.key_dir or (services.state_dir / "keys")
        ).exists()
        if creating and body.key_passphrase and len(body.key_passphrase) < 12:
            raise sanctum_error_response(
                "KeyPassphraseMissing",
                "A new signing key needs a passphrase of at least 12 characters.",
                "Choose a longer passphrase. It protects the key every "
                "certificate from this deployment is signed with.",
            )
        key = load_or_create_key(
            services.key_dir or (services.state_dir / "keys"),
            body.key_passphrase or None,
        )
        pub = public_key_of(key)
        finger = fingerprint(pub)
    except SanctumError as exc:
        # KeyPassphraseMissing and KeyPermissionsUnsafe both land here, and
        # both already carry a remediation naming the exact fix. Rewriting it
        # would replace "set SANCTUM_KEY_PASSPHRASE" with a vaguer sentence
        # about permissions that happens to be wrong half the time.
        raise sanctum_error_response(
            type(exc).__name__, exc.message, exc.remediation
        ) from exc
    except ValueError as exc:
        if body.key_passphrase:
            # A typed passphrase that does not open the key. The exception
            # text is cryptography's and says nothing useful; this does.
            raise sanctum_error_response(
                "KeyPassphraseMissing",
                "That passphrase does not open this deployment's signing key.",
                "Type the passphrase the key was created with. Nothing was "
                "signed or written.",
            ) from exc
        raise sanctum_error_response(
            "SignatureInvalid",
            f"The signing key could not be loaded: {exc}",
            "Check the key file and its passphrase.",
        ) from exc
    except OSError as exc:
        raise sanctum_error_response(
            "SignatureInvalid",
            f"The signing key could not be loaded: {exc}",
            "Check the key directory's permissions; a private key must not be "
            "group- or world-readable.",
        ) from exc

    from api.identity import IDENTITY_LIMITATION
    from api.identity import resolve as resolve_identity

    identity = resolve_identity(services)
    # The operator the *job* ran under, when the chain recorded one. A report
    # for a job somebody else ran must not be stamped with whoever asked for
    # the report; the fallback is this process's identity and only applies when
    # the job carried none.
    job_actor = str(status.get("actor") or "") or identity.labelled_actor(
        body.operator
    )
    result = status.get("result") or {}
    common: dict[str, Any] = {
        "job_state": state,
        "case_id": body.case_id
        or str((status.get("params") or {}).get("case_id") or "")
        or job_id,
        "operator": job_actor,
        "generated_at": datetime.now(UTC),
        "tool_version": services.tool_version,
        "limitations": _job_state_caveat(status)
        + _reconstruction_caveat(status)
        + [IDENTITY_LIMITATION]
        + list(result.get("limitations") or [])
        + services.limitations,
        "ledger_excerpt": excerpt,
        "chain_verification": verification,
        "pubkey_fingerprint": finger,
        # The OS, app build and privilege the job ran under, as recorded at
        # submission; absent for a job recorded before snapshots existed.
        "platform": (status.get("params") or {}).get("platform") or None,
        **_anchor_fields(ledger, verification),
    }

    # One builder per job kind, chosen from the job the registry recorded rather
    # than sniffed from the result's keys. A file erasure and a recovery are
    # different documents from a drive erasure: forcing all three through the
    # drive-shaped builder produced a report whose device, method, hidden-area
    # and verification sections were all empty, which reads as a tool that
    # examined a device and found nothing to say about it.
    kind = str(status.get("kind") or "")
    builder: Callable[..., dict[str, Any]]
    if kind == "erase-files":
        builder = build_file_erase_report
        fields = common | {
            "records": list(result.get("records") or []),
            "trace_sweep": result.get("trace_sweep") or None,
        }
    elif kind == "destroy-record":
        builder = build_destroy_report
        fields = common | {
            "record": dict(result.get("record") or {}),
            "recorded_at": str(result.get("recorded_at") or ""),
        }
    elif kind == "carve":
        builder = build_carve_report
        fields = common | {
            "evidence": _section(result, "evidence"),
            "media_map": result.get("media_map") or None,
            "candidates": list(result.get("candidates") or []),
            "partitions": list(result.get("partitions") or []),
            "unallocated_bytes": int(result.get("unallocated_bytes") or 0),
            "written": list(result.get("written") or []),
        }
    else:
        builder = build_report
        fields = common | drive_report_inputs(result)

    # Built twice, deliberately. sign_report signs the canonical bytes of the
    # report *without* a signature block, so the document that is signed and
    # the document that is written must be assembled from identical inputs -
    # anything else and the signature would verify against a document nobody
    # has. Rebuilding with the same `fields` is what guarantees that; mutating
    # the first dict would work today and break the moment a builder starts
    # deriving a field from another.
    unsigned = builder(**fields)
    signature = sign_report(unsigned, key)
    signed = builder(**fields, signature=signature)
    # One directory per job. Reports are named by case id (core/report/render),
    # so writing every job's report into one directory made the second report
    # of a case overwrite the first - and GET /reports/{first job}/verify then
    # verified the second job's file and showed 5 of 5 passed. Found in the
    # 2026-09-21 black-box UI run. The job id is checked before it becomes a
    # directory name, although status_for above has already required it to be
    # a job the registry or the chain knows.
    if not _SAFE_JOB_ID.fullmatch(job_id) or ".." in job_id:
        raise sanctum_error_response(
            "JobNotKnown",
            f"{job_id!r} is not a job id this API issues.",
            "Use the job_id a POST /jobs/* call returned. Nothing was written.",
        )
    json_path, pdf_path = write_report(signed, services.reports_dir / job_id)
    json_name = json_path.relative_to(services.reports_dir).as_posix()
    pdf_name = pdf_path.relative_to(services.reports_dir).as_posix()

    digest = _digest_of(json_path)
    try:
        _record_report_generated(
            services,
            job_id=job_id,
            json_path=json_path,
            pdf_path=pdf_path,
            digest=digest,
            case_id=str(common["case_id"]),
            # The trusted actor, not the body's string. This entry used to take
            # body.operator verbatim, so the one ledger entry that binds a
            # report to its job carried whatever the browser typed.
            operator=identity.labelled_actor(body.operator),
            fingerprint_value=finger,
        )
    except SanctumError as exc:
        # LedgerBusy, in practice. The files exist and the chain does not name
        # them, which is exactly the unresolvable artifact the entry exists to
        # prevent - so the operator is told both facts, not a bare 500.
        raise sanctum_error_response(
            type(exc).__name__,
            f"{exc.message} The report files were written to {json_path} and "
            f"{pdf_path}, but no {REPORT_GENERATED} entry binds them to job "
            f"{job_id!r}, so GET /reports/{job_id}/verify cannot resolve them.",
            f"{exc.remediation} Then generate the report again with "
            f"POST /reports/{job_id}; the new entry resolves to the new files.",
        ) from exc

    case_id = str(common["case_id"])
    attach_report(
        services.cases_dir,
        case_id=case_id,
        report_id=f"{case_id}:{job_id}",
        operation_id=job_id,
        json_name=json_name,
        pdf_name=pdf_name,
        report_hash=digest,
        signed=True,
        fingerprint=finger,
    )

    return {
        "job_id": job_id,
        "case_id": case_id,
        # Paths are still returned - an operator on the console needs them, and
        # the runbook quotes them - but the UI addresses reports through the
        # artifact URLs below and never has to render a host path.
        "json_path": str(json_path),
        "pdf_path": str(pdf_path),
        "json_name": json_name,
        "pdf_name": pdf_name,
        "json_url": f"/artifacts/reports/{json_name}",
        "pdf_url": f"/artifacts/reports/{pdf_name}",
        "pubkey_fingerprint": finger,
        "sha256": digest,
        "bytes": json_path.stat().st_size,
        "generated_at": common["generated_at"].isoformat(),
    }


#: What a job id may look like before it becomes a directory name.
_SAFE_JOB_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def _served_name(services: AppServices, path: Path) -> str:
    """``path`` as the artifact endpoint names it: relative to the reports root."""
    try:
        return path.relative_to(services.reports_dir).as_posix()
    except ValueError:
        return path.name


#: The ledger operation that binds a job to the report written for it.
#:
#: A new kind rather than a reuse. The erase pipeline's REPORT phase already
#: emits ``erase.report.result`` (``core/erase/drive.py:1499``), but that entry
#: carries the ``EraseResult`` - device, method, residual risk - and says
#: nothing about the *artifact*: no path, no digest, and it is written by the
#: engine before any report file exists. It also only exists for drive erasures,
#: while reports are generated for carve and file-erase jobs too. There was
#: nothing to reuse.
REPORT_GENERATED = "report.generated"

#: Job states a report may be generated for. See :func:`generate_report`.
_TERMINAL_STATES = frozenset({"complete", "failed", "cancelled"})


def _job_state_caveat(status: dict[str, Any]) -> list[str]:
    """The limitation a report for an unfinished job opens with.

    A failed or cancelled job usually has no result, so without this the
    report's limitations collapsed to the deployment's own - the report most in
    need of a caveat carried the fewest (MANUAL_REPORT FINDING 5).
    """
    state = str(status.get("state") or "")
    if state == "complete":
        return []
    error = status.get("error")
    cause = f" ({status.get('error_kind')}: {error})" if error else ""
    return [
        f"JOB {state.upper()}: this report documents a job that ended in state "
        f"'{state}', not 'complete'{cause}. Every section holds only what the "
        "job had returned when it stopped; an empty section means the job did "
        "not get that far, not that there was nothing to find. The audit trail "
        "shows how far it got."
    ]


def _anchor_fields(ledger: Any, verification: Any) -> dict[str, Any]:
    """The chain's Merkle root, and where - if anywhere - it was published.

    Two different claims, kept apart in the report because conflating them is
    the most common overclaim a hash-chained log invites:

    * **Internal integrity.** The Merkle root over every ``entry_hash`` from
      genesis to the current head. It lets a reader holding a later copy of the
      chain check that these entries are still the ones it contains. It does
      **not** stop somebody with write access to the whole state directory from
      rebuilding the chain from scratch: the root would simply be recomputed.
    * **Externally anchored existence.** Only a root published somewhere that
      person cannot rewrite fixes the entries in time. ``SANCTUM_ANCHOR_FILE``
      names an append-only destination - intended for write-once media - and
      :class:`core.ledger.anchor.FileAnchor` appends the root there. Without it
      the :class:`~core.ledger.anchor.NullAnchor` receipt says, in the signed
      report, that nothing was published.

    A chain that does not verify gets neither: a root over a broken chain would
    be a digest of something the verifier just rejected.
    """
    import os
    from dataclasses import asdict

    from core.ledger.anchor import FileAnchor, NullAnchor
    from core.ledger.chain import ChainStatus

    if verification.status == ChainStatus.BROKEN:
        return {}
    try:
        entries = ledger.entries()
        if not entries:
            return {}
        first, last = entries[0].seq, entries[-1].seq
        root = ledger.merkle_root(first, last)
    except (OSError, ValueError):
        return {}
    target = os.environ.get("SANCTUM_ANCHOR_FILE", "")
    anchor = FileAnchor(target) if target else NullAnchor()
    try:
        receipt = anchor.publish(root, (first, last))
    except OSError:
        receipt = NullAnchor().publish(root, (first, last))
    return {"merkle_root": root, "anchor": asdict(receipt)}


def _reconstruction_caveat(status: dict[str, Any]) -> list[str]:
    """What a report says when its inputs came from the chain, not the process.

    Not a defect and not hidden. The result is the same object the running
    process held - it was written into the content-addressed blob store when
    the job finished and read back by digest - but the *progress trace* is not,
    because the chain never carried it. A reader comparing two reports of the
    same kind should know why one has no live timing figures.
    """
    if not status.get("reconstructed"):
        return []
    seq = status.get("reconstructed_from_seq")
    return [
        "REBUILT FROM THE LEDGER: this report was generated after the process "
        "that ran the job had exited, so its inputs were read back from the "
        f"hash-chained ledger (entry {seq}) rather than from that process's "
        "memory. The result object is byte-identical to the one recorded when "
        "the job finished - it is content-addressed and was fetched by digest. "
        "The per-record progress trace is not part of that record and is "
        "therefore absent."
    ]


def _unknown_job(services: AppServices, job_id: str) -> Exception:
    """The refusal for a job this process has no record of.

    Says what the chain holds, because "never submitted" and "forgotten by a
    restart" look identical from the registry and are not the same situation.
    """
    try:
        ledger = _ledger(services)
        entries = [
            entry
            for entry in ledger.entries()
            if ledger.params_of(entry).get("job_id") == job_id
        ]
    except (OSError, ValueError):
        entries = []

    if not entries:
        return sanctum_error_response(
            "JobNotKnown",
            f"No job {job_id!r} is known to this process, and the chain at "
            f"{services.ledger_root} holds no entries for it.",
            "Check the id: it is the job_id a POST /jobs/* call returned. "
            "Nothing was written.",
        )
    last = entries[-1]
    return sanctum_error_response(
        "JobNotKnown",
        f"Job {job_id!r} is not known to this process - the API was restarted "
        "since it ran, or it ran in another process - but the chain holds "
        f"{len(entries)} entr{'y' if len(entries) == 1 else 'ies'} for it, the "
        f"last being {last.operation} at seq {last.seq}. A report is built from "
        "the job's result, which lived in the process that ran it and is gone; "
        "one generated now would have signed, empty sections.",
        "The job's chain entries are intact and verify with GET /ledger/verify. "
        "To get a report, run the job again and generate the report from the "
        "process that ran it. Nothing was written.",
    )


def _digest_of(path: Path) -> str:
    """SHA-256 of a written artifact."""
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def _record_report_generated(
    services: AppServices,
    *,
    job_id: str,
    json_path: Path,
    pdf_path: Path,
    digest: str,
    case_id: str,
    operator: str,
    fingerprint_value: str,
) -> None:
    """Append the chain entry that binds this job to this report file.

    Why the ledger rather than a dictionary in this process:

    * **Reports outlive the process.** An in-memory map is gone after a restart,
      and the report on disk is not; resolution has to survive the same events
      the artifact does.
    * **The chain is already the thing an examiner is asked to trust.** Adding
      one more kind of entry costs nothing and removes a second mechanism.
    * **Generating a report is an auditable act.** A forensic tool that records
      what it did to a device and not what it published about that device has a
      gap in its own account of itself. The entry names who asked, under which
      case id, which key signed it, and the digest of the bytes - so "this is
      the report for job X" is a claim the chain carries rather than one a
      filename implies.

    A failure to record is fatal to the request, deliberately. A report that
    exists but is not in the chain is exactly the unresolvable artifact this
    endpoint stopped producing.
    """
    ledger = _ledger(services)
    ledger.append(
        actor=operator or "sanctum",
        operation=REPORT_GENERATED,
        params={
            "job_id": job_id,
            "case_id": case_id,
            "json_path": str(json_path),
            "pdf_path": str(pdf_path),
            "pubkey_fingerprint": fingerprint_value,
        },
        result={"sha256": digest, "bytes": json_path.stat().st_size},
    )


def _section(result: dict[str, Any], key: str) -> dict[str, Any]:
    """One report section from a job result, or an empty one.

    Empty rather than absent: every section is rendered, and a section that is
    simply missing from a report reads as an oversight where an explicitly
    empty one reads as "this job had nothing to say here".
    """
    value = result.get(key)
    return value if isinstance(value, dict) else {}


def _report_for_job(services: AppServices, job_id: str) -> tuple[Path, str]:
    """The report this job generated, resolved through the hash chain.

    **There is no filename fallback, and that is the point of this function.**
    It used to glob ``*{job_id}*.forensic.json`` and, failing that, return the
    alphabetically last report in the directory - so on a machine with several
    reports staged, asking to verify job A returned a green tick for job B
    (audit C8). The glob could not work in the first place: a report is named
    ``<case_id>.forensic.json`` (``core/report/render.py``), and the case id is
    the operator's, so the job id is not in the filename on the normal path.

    Resolution now reads the ``report.generated`` entry the generating request
    appended. The newest one wins, because regenerating a report for a job is
    legitimate and the latest is the one that exists.

    Raises:
        HTTPException: 404 when no report was generated for this job.
    """
    ledger = _ledger(services)
    try:
        recorded = [
            entry
            for entry in ledger.entries()
            if entry.operation == REPORT_GENERATED
            and ledger.params_of(entry).get("job_id") == job_id
        ]
    except (OSError, ValueError) as exc:
        raise sanctum_error_response(
            "LedgerChainBroken",
            f"The ledger at {services.ledger_root} could not be read: {exc}",
            "Report resolution reads the chain. Check that the ledger root "
            "exists and is readable.",
        ) from exc

    if not recorded:
        raise sanctum_error_response(
            "ReportNotFound",
            f"No report has been generated for job {job_id!r}. The chain at "
            f"{services.ledger_root} carries no {REPORT_GENERATED} entry for "
            "it, so there is nothing to verify.",
            f"Generate one first: POST /reports/{job_id}. Reports are resolved "
            "through the ledger, never by guessing at filenames - a report for "
            "a different job is not an answer to this question.",
        )

    entry = recorded[-1]
    params = ledger.params_of(entry)
    result = ledger.result_of(entry)
    target = Path(str(params.get("json_path", "")))
    if not target.is_file():
        raise sanctum_error_response(
            "ReportNotFound",
            f"The chain records a report for job {job_id!r} at {target}, but "
            "that file is not there.",
            "The report was moved or deleted after it was generated. Restore "
            f"it, or generate a new one with POST /reports/{job_id}.",
        )
    return target, str(result.get("sha256", ""))


@router.get("/reports/{job_id}/verify")
def verify_report_endpoint(
    job_id: str, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    """Run the five report checks against this host's ledger, independently.

    Each check is reported on its own. Reducing them to one boolean would hide
    the difference between "the bytes changed" and "the key was never published
    anywhere I can reach", and only the first is a reason to distrust the
    report.
    """
    from core.report.verify_report import verify_report_file

    target, recorded_digest = _report_for_job(services, job_id)
    try:
        verification = verify_report_file(target, ledger_root=services.ledger_root)
    except (OSError, ValueError) as exc:
        raise sanctum_error_response(
            "SignatureInvalid",
            f"{target.name} could not be read as a report: {exc}",
            "The file is not valid JSON, or is not a Sanctum report.",
        ) from exc

    return {
        "report": str(target),
        "report_name": _served_name(services, target),
        "json_url": f"/artifacts/reports/{_served_name(services, target)}",
        "pdf_url": "/artifacts/reports/"
        + _served_name(services, target.with_name(
            target.name.removesuffix(".json") + ".pdf"
        )),
        "passed": verification.ok,
        # The graded word and its reasons. "passed" says every check that ran
        # passed; the verdict also says whether every check could run and
        # whether the report declares limits on what it proves.
        "verdict": verification.verdict.value,
        "verdict_reasons": list(verification.verdict_reasons),
        "fingerprint": verification.fingerprint,
        # Whether the file on disk is still the bytes the chain recorded when
        # this report was generated. Reported alongside the checks rather than
        # folded into them: a mismatch and a broken signature are the same
        # event seen twice, and an examiner reading one wants to see the other.
        "ledger_digest": recorded_digest,
        "ledger_digest_matches": _digest_of(target) == recorded_digest,
        # The identity caveat travels with the result. A signature proves the
        # bytes have not changed; it does not prove who produced them, and a
        # verification screen that omitted that would invite exactly the
        # conclusion the caveat exists to prevent.
        "caveat": verification.caveat,
        "checks": [
            {
                "name": check.name.value,
                "passed": check.passed,
                # An inapplicable check is not a passing one. A report verified
                # on a host with no ledger cannot have its chain checked, and
                # rendering that as a pass would overstate what was confirmed.
                "applicable": check.applicable,
                "detail": check.detail,
            }
            for check in verification.checks
        ],
    }
