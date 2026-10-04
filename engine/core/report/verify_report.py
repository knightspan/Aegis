"""Independent verification of a signed report.

Five checks, each reported on its own line so a reader can see exactly which
property holds:

1. **Signature** - the detached signature is valid for these exact bytes under
   the public key embedded in the report.
2. **Fingerprint matches genesis** - that public key's fingerprint is the one
   recorded in the ledger's genesis entry, so the report was signed by the key
   the chain was started with. Not applicable when genesis records no
   fingerprint, with the reason named rather than guessed.
3. **Chain integrity** - the ledger excerpt carried inside the report hashes
   and links correctly *on its own terms*. An excerpt is a filtered view of one
   job's entries, so it is expected to have gaps; the result is COMPLETE,
   PARTIAL (gaps named) or BROKEN, and the gaps the report declares are
   cross-checked against the gaps it has.
4. **Chain store** - the whole chain re-verified from the store, independently
   of the excerpt and of the ``chain_status`` the report prints. Not applicable
   when the store is unreachable or unreadable.
5. **Blob availability** - the params and result blobs the excerpt references
   are present, when the store is reachable. Not applicable otherwise.

The verdict
-----------
``ok`` says every *applicable* check passed. It does not say whether every
check could run, or whether the report itself declares limits on what it proves.
:func:`grade_report` adds one word that says both, and every downgrade from
``VERIFIED`` names its reason:

* ``FAILED_VERIFICATION`` - an applicable check failed.
* ``PARTIAL`` - every check that ran passed, but at least one could not run
  (no ledger store, no genesis fingerprint), so less was confirmed than the
  five checks can confirm.
* ``VERIFIED_WITH_LIMITATIONS`` - all five ran and passed, and the report is
  authentic, but it declares limitations, residual risk above low, a
  verification it records as not passed, or an excerpt with declared gaps.
* ``VERIFIED`` - all five ran and passed and the report declares none of those.

The identity caveat below applies to every report and is not a downgrade.

What this does not prove
------------------------
An embedded public key only proves *internal consistency*: that whoever signed
this report held the private key whose public half is printed inside it. It says
nothing about who that was. Anyone can generate a key, sign a fabricated report,
and embed their own public key; every check here would pass.

A third party must compare the fingerprint against a value published
**out-of-band** - an organisation's key listing, a printed card, a prior
communication - before the signature means anything about identity. That caveat
is printed with every result rather than left for the reader to infer.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import structlog

from core.ledger.chain import (
    GENESIS_OPERATION,
    GENESIS_PREV_HASH,
    NO_SIGNING_KEY,
    ChainStatus,
    entry_hash_of,
)
from core.ledger.store import BlobStore, LedgerStore
from core.models import LedgerEntry, Signature
from core.report.render import NONE_RECORDED
from core.report.sign import verify_signature

__all__ = [
    "CheckName",
    "ChainExcerptStatus",
    "GenesisFingerprintReason",
    "ReportCheck",
    "ReportVerdict",
    "ReportVerification",
    "grade_report",
    "verify_report_file",
    "verify_report",
    "IDENTITY_CAVEAT",
]

logger = structlog.get_logger(__name__)

IDENTITY_CAVEAT = (
    "An embedded public key proves internal consistency only. It does not "
    "prove identity: a third party must compare the fingerprint above against "
    "a value published out-of-band before treating this signature as evidence "
    "of who produced the report."
)


class CheckName(StrEnum):
    """The five independently reported checks."""

    SIGNATURE = "signature"
    FINGERPRINT_MATCHES_GENESIS = "fingerprint_matches_genesis"
    CHAIN_INTEGRITY = "chain_integrity"
    CHAIN_STORE = "chain_store"
    BLOBS_AVAILABLE = "blobs_available"


class ChainExcerptStatus(StrEnum):
    """What the excerpt alone established about the chain.

    Two outcomes were not enough. A filtered excerpt cannot link end to end, so
    a pass/fail check had to call an honest omission a break - which is what it
    did, reporting "entry 7 does not link to the entry before it" for a report
    whose store verified all 42 entries. These three separate "the excerpt
    proves the whole span", "the excerpt proves what it carries and names what
    it does not", and "the excerpt contradicts itself".
    """

    #: Contiguous excerpt: every entry present from first seq to last, every
    #: link checked.
    VERIFIED_COMPLETE = "VERIFIED_COMPLETE"
    #: Gapped excerpt: every adjacent pair links, and the gaps are named. The
    #: spans inside the gaps are not evidenced by the excerpt at all.
    VERIFIED_PARTIAL = "VERIFIED_PARTIAL"
    #: An adjacent pair does not link, an entry does not hash to its recorded
    #: entry_hash, or the declared gaps do not match the observed ones.
    BROKEN = "BROKEN"


class GenesisFingerprintReason(StrEnum):
    """Why the genesis fingerprint could or could not be read.

    Five situations used to return ``None`` and print one sentence naming only
    the first of them. The hardware run hit the fifth and was told the first:
    "no genesis entry was available to compare against", about a report whose
    excerpt carried genesis at seq 0.
    """

    OK = "OK"
    GENESIS_ABSENT = "GENESIS_ABSENT"
    NO_LEDGER_ROOT = "NO_LEDGER_ROOT"
    BLOB_MISSING = "BLOB_MISSING"
    BLOB_UNPARSABLE = "BLOB_UNPARSABLE"
    FINGERPRINT_EMPTY = "FINGERPRINT_EMPTY"


_GENESIS_REASON_DETAIL = {
    GenesisFingerprintReason.GENESIS_ABSENT: (
        "the excerpt carries no genesis entry, so there is nothing to compare "
        "the signing key against"
    ),
    GenesisFingerprintReason.NO_LEDGER_ROOT: (
        "no ledger store was reachable, so the genesis entry's parameters "
        "could not be read"
    ),
    GenesisFingerprintReason.BLOB_MISSING: (
        "the genesis entry's parameter blob is not in the store"
    ),
    GenesisFingerprintReason.BLOB_UNPARSABLE: (
        "the genesis entry's parameter blob is not valid JSON"
    ),
    GenesisFingerprintReason.FINGERPRINT_EMPTY: (
        "the chain was created before any signing key existed, so genesis "
        "records no fingerprint to compare against"
    ),
}


class ReportVerdict(StrEnum):
    """One graded word for a whole verification. See the module docstring."""

    VERIFIED = "VERIFIED"
    VERIFIED_WITH_LIMITATIONS = "VERIFIED_WITH_LIMITATIONS"
    PARTIAL = "PARTIAL"
    FAILED_VERIFICATION = "FAILED_VERIFICATION"


@dataclass(frozen=True)
class ReportCheck:
    """One check, its outcome, and a one-line reason.

    ``status`` carries a check-specific verdict where pass/fail is too coarse -
    today the three :class:`ChainExcerptStatus` values and the
    :class:`GenesisFingerprintReason` that produced the outcome.
    """

    name: CheckName
    passed: bool
    detail: str
    applicable: bool = True
    status: str = ""


@dataclass
class ReportVerification:
    """Every check for one report, plus the honesty caveat."""

    checks: list[ReportCheck] = field(default_factory=list)
    caveat: str = IDENTITY_CAVEAT
    fingerprint: str = ""
    verdict: ReportVerdict = ReportVerdict.FAILED_VERIFICATION
    #: Why the verdict is not ``VERIFIED``; empty when it is.
    verdict_reasons: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True only when every applicable check passed."""
        return all(check.passed for check in self.checks if check.applicable)


def _check_signature(report: dict[str, Any]) -> ReportCheck:
    raw = report.get("signature")
    if not raw:
        return ReportCheck(
            CheckName.SIGNATURE,
            False,
            "the report carries no signature block, so nothing can be verified",
        )
    try:
        signature = Signature.model_validate(raw)
    except ValueError as exc:
        return ReportCheck(
            CheckName.SIGNATURE, False, f"signature block is malformed: {exc}"
        )
    if verify_signature(report, signature):
        return ReportCheck(
            CheckName.SIGNATURE,
            True,
            f"valid {signature.alg} signature by {signature.pubkey_fingerprint}",
        )
    return ReportCheck(
        CheckName.SIGNATURE,
        False,
        "signature does not match the report contents; the report was altered "
        "after signing, or signed by a different key",
    )


def _check_fingerprint(
    report: dict[str, Any], ledger_root: Path | None
) -> ReportCheck:
    raw = report.get("signature") or {}
    claimed = str(raw.get("pubkey_fingerprint") or "")
    if not claimed:
        return ReportCheck(
            CheckName.FINGERPRINT_MATCHES_GENESIS,
            False,
            "no fingerprint in the signature block to compare",
        )

    genesis_fingerprint, reason = _genesis_fingerprint(report, ledger_root)
    if genesis_fingerprint is None:
        return ReportCheck(
            CheckName.FINGERPRINT_MATCHES_GENESIS,
            True,
            _GENESIS_REASON_DETAIL[reason],
            applicable=False,
            status=reason.value,
        )
    if genesis_fingerprint == claimed:
        return ReportCheck(
            CheckName.FINGERPRINT_MATCHES_GENESIS,
            True,
            f"signing key {claimed} is the key recorded in the ledger genesis",
            status=GenesisFingerprintReason.OK.value,
        )
    return ReportCheck(
        CheckName.FINGERPRINT_MATCHES_GENESIS,
        False,
        f"report was signed by {claimed}, but the ledger genesis records "
        f"{genesis_fingerprint}",
        status=GenesisFingerprintReason.OK.value,
    )


def _genesis_fingerprint(
    report: dict[str, Any], ledger_root: Path | None
) -> tuple[str | None, GenesisFingerprintReason]:
    """Fingerprint from the genesis entry, with the reason when there is none.

    Every ``None`` return here used to be rendered as "no genesis entry was
    available", which named one of five possible causes and was the wrong one
    for the case that actually happened. The reason travels with the result so
    the check can say which situation it is in.
    """
    entries = _excerpt(report)
    genesis = next(
        (e for e in entries if e.get("operation") == GENESIS_OPERATION), None
    )
    if genesis is None:
        return None, GenesisFingerprintReason.GENESIS_ABSENT
    if ledger_root is None:
        return None, GenesisFingerprintReason.NO_LEDGER_ROOT
    blob = BlobStore(ledger_root).get(str(genesis.get("params_hash") or ""))
    if blob is None:
        return None, GenesisFingerprintReason.BLOB_MISSING
    try:
        params: dict[str, Any] = json.loads(blob)
    except ValueError:
        return None, GenesisFingerprintReason.BLOB_UNPARSABLE
    value = params.get("pubkey_fingerprint")
    if not value or value == NO_SIGNING_KEY:
        # A chain started before any signing key existed. Genesis records the
        # absence explicitly (see core.ledger.chain.NO_SIGNING_KEY); either way
        # there is no fingerprint to compare, and that is not a missing genesis.
        return None, GenesisFingerprintReason.FINGERPRINT_EMPTY
    return str(value), GenesisFingerprintReason.OK


def _excerpt(report: dict[str, Any]) -> list[dict[str, Any]]:
    sections = report.get("sections") or {}
    audit = sections.get("audit_trail") or {}
    entries = audit.get("entries") or []
    return [entry for entry in entries if isinstance(entry, dict)]


def _declared_gaps(report: dict[str, Any]) -> list[dict[str, int]] | None:
    """The gaps the report says its excerpt has, or ``None`` if it declares none.

    ``None`` means the field is absent - a report written before the field
    existed - which is different from a report declaring an empty list.
    """
    audit = (report.get("sections") or {}).get("audit_trail") or {}
    declared = audit.get("excerpt_gaps")
    if not isinstance(declared, list):
        return None
    return [item for item in declared if isinstance(item, dict)]


def _normalise_gaps(gaps: list[dict[str, Any]]) -> list[tuple[int, int]]:
    pairs: list[tuple[int, int]] = []
    for gap in gaps:
        try:
            pairs.append((int(gap["from_seq"]), int(gap["to_seq"])))
        except (KeyError, TypeError, ValueError):
            continue
    return sorted(pairs)


def _describe_gaps(gaps: list[tuple[int, int]]) -> str:
    return ", ".join(
        f"{low}" if low == high else f"{low}-{high}" for low, high in gaps
    )


def _check_chain(report: dict[str, Any]) -> ReportCheck:
    """Verify the excerpt on its own terms, which are not a whole chain's terms.

    The excerpt is a filtered view: one job's entries plus genesis, with other
    jobs' entries left out on purpose. Walking it as though every entry were
    adjacent to the next made an honest omission indistinguishable from a
    broken link, and reported a 42-entry chain that verified in the store as
    broken at its first excerpted entry.

    So: every entry's own hash is recomputed, links are checked only between
    entries whose ``seq`` differ by exactly one, and each gap is named rather
    than treated as a failure. The gaps the excerpt declares are cross-checked
    against the gaps it actually has, which is what makes a silently trimmed
    excerpt detectable - without the cross-check, removing an entry and leaving
    the declaration alone looks exactly like an honest filter.
    """
    raw_entries = _excerpt(report)
    if not raw_entries:
        return ReportCheck(
            CheckName.CHAIN_INTEGRITY,
            True,
            "the report embeds no ledger excerpt",
            applicable=False,
        )

    previous: LedgerEntry | None = None
    observed: list[tuple[int, int]] = []
    linked = 0
    for index, raw in enumerate(raw_entries):
        try:
            entry = LedgerEntry.model_validate(raw)
        except ValueError as exc:
            return ReportCheck(
                CheckName.CHAIN_INTEGRITY,
                False,
                f"excerpt entry {index} does not parse: {exc}",
                status=ChainExcerptStatus.BROKEN.value,
            )
        record = raw | {"ts_utc": entry.ts_utc}
        if entry_hash_of(record) != entry.entry_hash:
            return ReportCheck(
                CheckName.CHAIN_INTEGRITY,
                False,
                f"entry {entry.seq} does not hash to its recorded entry_hash; "
                "its contents were altered",
                status=ChainExcerptStatus.BROKEN.value,
            )

        if previous is None:
            if entry.seq == 0 and entry.prev_entry_hash != GENESIS_PREV_HASH:
                return ReportCheck(
                    CheckName.CHAIN_INTEGRITY,
                    False,
                    "the genesis entry does not carry the genesis prev hash",
                    status=ChainExcerptStatus.BROKEN.value,
                )
        elif entry.seq == previous.seq + 1:
            if entry.prev_entry_hash != previous.entry_hash:
                return ReportCheck(
                    CheckName.CHAIN_INTEGRITY,
                    False,
                    f"entry {entry.seq} does not link to entry {previous.seq}, "
                    "which immediately precedes it",
                    status=ChainExcerptStatus.BROKEN.value,
                )
            linked += 1
        elif entry.seq > previous.seq + 1:
            # Not a break. The excerpt never claimed to carry this span, and
            # nothing in it can speak for the entries inside the gap.
            observed.append((previous.seq + 1, entry.seq - 1))
        else:
            return ReportCheck(
                CheckName.CHAIN_INTEGRITY,
                False,
                f"entry {entry.seq} does not follow entry {previous.seq}; the "
                "excerpt is out of order or repeats a seq",
                status=ChainExcerptStatus.BROKEN.value,
            )
        previous = entry

    declared_raw = _declared_gaps(report)
    span = f"{raw_entries[0].get('seq')}..{raw_entries[-1].get('seq')}"

    if declared_raw is not None:
        declared = _normalise_gaps(declared_raw)
        if declared != observed:
            return ReportCheck(
                CheckName.CHAIN_INTEGRITY,
                False,
                "the excerpt declares gaps "
                f"[{_describe_gaps(declared) or 'none'}] but has "
                f"[{_describe_gaps(observed) or 'none'}]; entries were removed "
                "or added after the declaration was written",
                status=ChainExcerptStatus.BROKEN.value,
            )

    if not observed:
        return ReportCheck(
            CheckName.CHAIN_INTEGRITY,
            True,
            f"all {len(raw_entries)} excerpt entries link and hash correctly "
            f"({span})",
            status=ChainExcerptStatus.VERIFIED_COMPLETE.value,
        )

    missing = sum(high - low + 1 for low, high in observed)
    undeclared = " (gaps not declared by the report)" if declared_raw is None else ""
    return ReportCheck(
        CheckName.CHAIN_INTEGRITY,
        True,
        f"{len(raw_entries)} excerpt entries hash correctly and all {linked} "
        f"adjacent pair(s) link ({span}); {missing} entr(y/ies) are not carried "
        f"by this excerpt at seq {_describe_gaps(observed)} and are not "
        f"evidenced by it{undeclared}",
        status=ChainExcerptStatus.VERIFIED_PARTIAL.value,
    )


def _check_store_chain(
    report: dict[str, Any], ledger_root: Path | None
) -> ReportCheck:
    """Verify the whole chain from the store, independently of the excerpt.

    The excerpt can only ever speak for what it carries. The report also prints
    a ``chain_status`` that the *writer* computed over the whole store, and a
    reader who trusted that field would be taking the report's word for the one
    property the report exists to evidence. When the store is reachable this
    recomputes it and compares.
    """
    if ledger_root is None:
        return ReportCheck(
            CheckName.CHAIN_STORE,
            True,
            "no ledger store was given, so the full chain was not re-verified",
            applicable=False,
        )
    store = LedgerStore(ledger_root)
    if not store.path.exists():
        return ReportCheck(
            CheckName.CHAIN_STORE,
            True,
            f"no chain file at {store.path}, so the full chain was not "
            "re-verified",
            applicable=False,
        )
    if not os.access(store.path, os.R_OK):
        # LedgerStore.read() turns an unreadable file into an empty chain, and
        # an empty chain verifies. Saying "not applicable" is the honest answer;
        # saying VALID would be a verification that never happened.
        return ReportCheck(
            CheckName.CHAIN_STORE,
            True,
            f"{store.path} is not readable by this process, so the full chain "
            "was not re-verified",
            applicable=False,
        )

    from core.ledger.chain import Ledger

    ledger = Ledger(ledger_root, tool_version="", pubkey_fingerprint="")
    outcome = ledger.verify()
    declared = str(
        (report.get("sections") or {}).get("audit_trail", {}).get("chain_status") or ""
    )
    if outcome.status is not ChainStatus.VALID:
        return ReportCheck(
            CheckName.CHAIN_STORE,
            False,
            f"the ledger store does not verify: {outcome.explanation}",
            status=outcome.status.value,
        )
    if declared and declared != outcome.status.value:
        return ReportCheck(
            CheckName.CHAIN_STORE,
            False,
            f"the report records the chain as {declared}, but the store "
            f"verifies as {outcome.status.value}",
            status=outcome.status.value,
        )
    # A store that verifies on its own can still be a different history from the
    # one the signed report cites: cut short, or rebuilt. Every entry the
    # report carries must be present in the store with the same hash.
    held = {entry.seq: entry.entry_hash for entry in ledger.entries()}
    for cited in _excerpt(report):
        seq = cited.get("seq")
        if not isinstance(seq, int) or held.get(seq) != cited.get("entry_hash"):
            return ReportCheck(
                CheckName.CHAIN_STORE,
                False,
                f"the report cites entry {seq}, but the store "
                + (
                    "does not hold that entry"
                    if seq not in held
                    else "holds a different entry at that position"
                )
                + "; the store is not the history this report was signed over",
                status=outcome.status.value,
            )
    return ReportCheck(
        CheckName.CHAIN_STORE,
        True,
        f"the ledger store verifies independently: {outcome.explanation}",
        status=outcome.status.value,
    )


def _check_blobs(report: dict[str, Any], ledger_root: Path | None) -> ReportCheck:
    entries = _excerpt(report)
    if ledger_root is None or not LedgerStore(ledger_root).path.parent.exists():
        return ReportCheck(
            CheckName.BLOBS_AVAILABLE,
            True,
            "no blob store was reachable, so referenced content was not checked",
            applicable=False,
        )
    if not entries:
        return ReportCheck(
            CheckName.BLOBS_AVAILABLE,
            True,
            "the report embeds no ledger excerpt",
            applicable=False,
        )

    blobs = BlobStore(ledger_root)
    missing: list[str] = []
    for entry in entries:
        for key in ("params_hash", "result_hash"):
            digest = str(entry.get(key) or "")
            if digest and not blobs.has(digest):
                missing.append(f"{digest[:12]} ({key} of seq {entry.get('seq')})")
    if missing:
        return ReportCheck(
            CheckName.BLOBS_AVAILABLE,
            False,
            f"{len(missing)} referenced blob(s) missing: {', '.join(missing[:5])}",
        )
    return ReportCheck(
        CheckName.BLOBS_AVAILABLE,
        True,
        f"every blob referenced by {len(entries)} entries is present",
    )


def verify_report(
    report: dict[str, Any], *, ledger_root: Path | str | None = None
) -> ReportVerification:
    """Run every check over an already-loaded report."""
    root = Path(ledger_root) if ledger_root is not None else None
    signature = report.get("signature") or {}
    checks = [
        _check_signature(report),
        _check_fingerprint(report, root),
        _check_chain(report),
        _check_store_chain(report, root),
        _check_blobs(report, root),
    ]
    verdict, reasons = grade_report(report, checks)
    return ReportVerification(
        checks=checks,
        fingerprint=str(signature.get("pubkey_fingerprint") or ""),
        verdict=verdict,
        verdict_reasons=reasons,
    )


def _declared(items: Any) -> list[str]:
    """A report's list of statements, without the "none recorded" placeholder."""
    if not isinstance(items, list):
        return []
    return [str(item) for item in items if str(item) != NONE_RECORDED]


def grade_report(
    report: dict[str, Any], checks: list[ReportCheck]
) -> tuple[ReportVerdict, list[str]]:
    """The verdict word for these checks over this report, and why.

    Precedence is fixed: a failed check outranks a check that could not run,
    which outranks a limitation the report declares. The report's own content is
    read only for what it declares about itself; a malformed section is treated
    as declaring nothing, and the checks above have already said whether the
    bytes are authentic.
    """
    failed = [c for c in checks if c.applicable and not c.passed]
    if failed:
        return ReportVerdict.FAILED_VERIFICATION, [
            f"{c.name.value} failed: {c.detail}" for c in failed
        ]
    skipped = [c for c in checks if not c.applicable]
    if skipped:
        return ReportVerdict.PARTIAL, [
            f"{c.name.value} could not run: {c.detail}" for c in skipped
        ]

    reasons: list[str] = []
    for check in checks:
        if (
            check.name is CheckName.CHAIN_INTEGRITY
            and check.status == ChainExcerptStatus.VERIFIED_PARTIAL.value
        ):
            reasons.append(
                "the ledger excerpt carries only part of the chain; the gaps are "
                "declared in the report and the store verified independently"
            )
    sections = report.get("sections")
    if isinstance(sections, dict):
        limitations = sections.get("limitations")
        if isinstance(limitations, dict):
            reasons += [
                f"the report declares a limitation: {item}"
                for item in _declared(limitations.get("items"))
            ]
        residual = sections.get("residual_risk")
        if isinstance(residual, dict):
            level = str(residual.get("level") or "").strip().lower()
            if level and level != "low":
                # The factors are counted, not quoted: they are full sentences
                # and most repeat the limitations already listed above.
                count = len(_declared(residual.get("factors")))
                noun = "factor" if count == 1 else "factors"
                reasons.append(
                    f"the report records residual risk {level}"
                    + (f" ({count} {noun} in section residual_risk)" if count else "")
                )
        verification = sections.get("verification")
        if (
            isinstance(verification, dict)
            and verification.get("passed") is False
            and not _no_readback_attempted(verification)
        ):
            reasons.append("the report records that its own verification did not pass")
    if reasons:
        return ReportVerdict.VERIFIED_WITH_LIMITATIONS, reasons
    return ReportVerdict.VERIFIED, []


def _no_readback_attempted(verification: dict[str, Any]) -> bool:
    """True for the empty verification block of an operation with no read-back.

    An acquisition report carries the same section as an erase report, filled
    with its defaults: no strategy and zero bytes checked. That is the absence
    of a read-back, which the method semantics already state as "not verified",
    and not a read-back that failed.
    """
    return not verification.get("strategy") and verification.get("bytes_checked") == 0


def verify_report_file(
    path: Path | str, *, ledger_root: Path | str | None = None
) -> ReportVerification:
    """Load a ``.forensic.json`` report and verify it.

    Raises:
        FileNotFoundError: ``path`` does not exist.
        ValueError: the file is not valid JSON.
    """
    report_path = Path(path)
    raw = report_path.read_bytes()
    loaded: dict[str, Any] = json.loads(raw)
    return verify_report(loaded, ledger_root=ledger_root)
