"""Independent report verification, and the CLI a stranger runs on stage."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from core.ledger.chain import ChainStatus, Ledger
from core.report.render import build_report, write_report
from core.report.sign import (
    PASSPHRASE_ENV,
    fingerprint,
    load_or_create_key,
    public_key_of,
    sign_report,
)
from core.report.verify_report import CheckName, verify_report_file

PASSPHRASE = "test passphrase"


@pytest.fixture
def case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A signed report on disk, with the ledger that produced it."""
    monkeypatch.setenv(PASSPHRASE_ENV, PASSPHRASE)
    key = load_or_create_key(tmp_path / "sanctum.key.pem")
    print_fingerprint = fingerprint(public_key_of(key))

    ledger = Ledger(
        tmp_path / "store",
        tool_version="0.1.0",
        pubkey_fingerprint=print_fingerprint,
    )
    for index in range(4):
        ledger.append(
            actor="tester",
            operation=f"erase.phase.{index}",
            params={"index": index},
            result={"ok": True},
        )
    entries = [json.loads(e.model_dump_json()) for e in ledger.entries()]

    report = build_report(
        case_id="CASE-0001",
        operator="A. Operator",
        generated_at=datetime(2026, 3, 1, tzinfo=UTC),
        tool_version="0.1.0",
        device={"model": "M", "serial": "S", "size_bytes": 1},
        method={"method": "SINGLE_PASS_OVERWRITE"},
        hidden_areas={},
        verification={"strategy": "full_read", "passed": True},
        residual_risk={"level": "low", "factors": [], "purge_achieved": False},
        limitations=[],
        ledger_excerpt=entries,
        chain_verification=ledger.verify(),
        pubkey_fingerprint=print_fingerprint,
        merkle_root=ledger.merkle_root(0, 4),
    )
    report["signature"] = sign_report(report, key).model_dump()
    json_path, _ = write_report(report, tmp_path / "out")
    return {
        "path": json_path,
        "ledger_root": tmp_path / "store",
        "fingerprint": print_fingerprint,
    }


def tamper(path: Path, mutate: Any) -> None:
    data = json.loads(path.read_bytes())
    mutate(data)
    path.write_bytes(json.dumps(data).encode("utf-8"))


# --------------------------------------------------------------------------
# Library-level checks
# --------------------------------------------------------------------------


def test_a_report_signed_before_the_standards_fields_existed_still_verifies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Adding the standards and regulatory fields changed what new certificates
    carry, not how any certificate is verified. A report without them - the
    shape of every report signed before the change - must still pass."""
    monkeypatch.setenv(PASSPHRASE_ENV, PASSPHRASE)
    key = load_or_create_key(tmp_path / "sanctum.key.pem")
    report = build_report(
        case_id="CASE-OLD",
        operator="A. Operator",
        generated_at=datetime(2026, 3, 1, tzinfo=UTC),
        tool_version="0.1.0",
        device={"model": "M", "serial": "S", "size_bytes": 1},
        method={"method": "SINGLE_PASS_OVERWRITE"},
        hidden_areas={},
        verification={"strategy": "full_read", "passed": True},
        residual_risk={"level": "low", "factors": [], "purge_achieved": False},
        limitations=[],
        ledger_excerpt=[],
        chain_verification=Ledger(
            tmp_path / "store", tool_version="0.1.0", pubkey_fingerprint=""
        ).verify(),
        pubkey_fingerprint=fingerprint(public_key_of(key)),
    )
    del report["sections"]["method"]["standards"]
    del report["sections"]["method"]["regulatory_references"]
    report["signature"] = sign_report(report, key).model_dump()
    json_path, _ = write_report(report, tmp_path / "out")

    result = verify_report_file(json_path)
    signature = next(c for c in result.checks if c.name is CheckName.SIGNATURE)
    assert signature.passed is True
    assert result.ok is True


def test_a_good_report_passes_every_check(case: dict[str, Any]) -> None:
    result = verify_report_file(case["path"], ledger_root=case["ledger_root"])
    assert result.ok is True
    assert {c.name for c in result.checks if c.passed} >= {
        CheckName.SIGNATURE,
        CheckName.FINGERPRINT_MATCHES_GENESIS,
        CheckName.CHAIN_INTEGRITY,
        CheckName.CHAIN_STORE,
        CheckName.BLOBS_AVAILABLE,
    }


def test_each_check_is_reported_independently(case: dict[str, Any]) -> None:
    result = verify_report_file(case["path"], ledger_root=case["ledger_root"])
    assert len(result.checks) == len(CheckName)
    for check in result.checks:
        assert check.detail


def test_a_tampered_field_fails_only_the_signature_check(
    case: dict[str, Any],
) -> None:
    tamper(case["path"], lambda d: d.update({"case_id": "CASE-9999"}))
    result = verify_report_file(case["path"], ledger_root=case["ledger_root"])
    assert result.ok is False
    failed = {c.name for c in result.checks if not c.passed and c.applicable}
    assert CheckName.SIGNATURE in failed


def test_a_broken_excerpt_fails_the_chain_check(case: dict[str, Any]) -> None:
    def break_chain(data: dict[str, Any]) -> None:
        data["sections"]["audit_trail"]["entries"][2]["actor"] = "impostor"

    tamper(case["path"], break_chain)
    result = verify_report_file(case["path"], ledger_root=case["ledger_root"])
    chain_check = next(
        c for c in result.checks if c.name is CheckName.CHAIN_INTEGRITY
    )
    assert chain_check.passed is False
    assert "2" in chain_check.detail


def test_a_foreign_fingerprint_fails_the_genesis_check(
    case: dict[str, Any],
) -> None:
    tamper(
        case["path"],
        lambda d: d["signature"].update({"pubkey_fingerprint": "00:11:22"}),
    )
    result = verify_report_file(case["path"], ledger_root=case["ledger_root"])
    check = next(
        c for c in result.checks if c.name is CheckName.FINGERPRINT_MATCHES_GENESIS
    )
    assert check.passed is False


def test_blob_check_is_not_applicable_without_a_reachable_store(
    case: dict[str, Any],
) -> None:
    result = verify_report_file(case["path"], ledger_root=None)
    check = next(c for c in result.checks if c.name is CheckName.BLOBS_AVAILABLE)
    assert check.applicable is False
    assert result.ok is True


def test_a_missing_blob_is_reported(case: dict[str, Any]) -> None:
    entries = json.loads(case["path"].read_bytes())["sections"]["audit_trail"][
        "entries"
    ]
    digest = entries[1]["params_hash"]
    (case["ledger_root"] / "blobs" / digest[:2] / digest).unlink()

    result = verify_report_file(case["path"], ledger_root=case["ledger_root"])
    check = next(c for c in result.checks if c.name is CheckName.BLOBS_AVAILABLE)
    assert check.passed is False
    assert digest[:12] in check.detail


def test_an_unsigned_report_fails_rather_than_passing_vacuously(
    case: dict[str, Any],
) -> None:
    tamper(case["path"], lambda d: d.pop("signature", None))
    result = verify_report_file(case["path"], ledger_root=case["ledger_root"])
    assert result.ok is False


def test_verification_states_that_an_embedded_key_proves_only_consistency(
    case: dict[str, Any],
) -> None:
    result = verify_report_file(case["path"], ledger_root=case["ledger_root"])
    assert "out-of-band" in result.caveat
    assert "third party" in result.caveat


def test_a_report_with_a_broken_chain_verification_status_is_surfaced(
    case: dict[str, Any],
) -> None:
    def break_status(data: dict[str, Any]) -> None:
        data["sections"]["audit_trail"]["chain_status"] = ChainStatus.BROKEN.value

    tamper(case["path"], break_status)
    result = verify_report_file(case["path"], ledger_root=case["ledger_root"])
    assert result.ok is False


# --------------------------------------------------------------------------
# CLI, driven the way a person would
# --------------------------------------------------------------------------


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "core.report.cli", *args],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(Path(__file__).resolve().parents[2]),
    )


def test_cli_exits_zero_on_a_good_report(case: dict[str, Any]) -> None:
    done = run_cli(
        "verify-report", str(case["path"]), "--ledger-root", str(case["ledger_root"])
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert "PASS" in done.stdout


def test_cli_exits_non_zero_on_a_tampered_report(case: dict[str, Any]) -> None:
    tamper(case["path"], lambda d: d.update({"operator": "someone else"}))
    done = run_cli(
        "verify-report", str(case["path"]), "--ledger-root", str(case["ledger_root"])
    )
    assert done.returncode != 0
    assert "FAIL" in done.stdout
    assert "signature" in done.stdout.lower()


def test_cli_prints_one_line_per_failure(case: dict[str, Any]) -> None:
    def break_two(data: dict[str, Any]) -> None:
        data["operator"] = "someone else"
        data["sections"]["audit_trail"]["entries"][1]["actor"] = "impostor"

    tamper(case["path"], break_two)
    done = run_cli(
        "verify-report", str(case["path"]), "--ledger-root", str(case["ledger_root"])
    )
    failures = [line for line in done.stdout.splitlines() if "FAIL" in line]
    assert len(failures) >= 2


def test_cli_output_is_readable_without_knowing_the_codebase(
    case: dict[str, Any],
) -> None:
    done = run_cli(
        "verify-report", str(case["path"]), "--ledger-root", str(case["ledger_root"])
    )
    lowered = done.stdout.lower()
    assert "signature" in lowered
    assert "chain" in lowered
    assert "out-of-band" in lowered


def test_cli_reports_a_missing_file_clearly(tmp_path: Path) -> None:
    done = run_cli("verify-report", str(tmp_path / "nope.json"))
    assert done.returncode != 0
    assert "not found" in (done.stdout + done.stderr).lower()


# --------------------------------------------------------------------------
# A filtered excerpt is not a broken chain
# --------------------------------------------------------------------------


@pytest.fixture
def filtered_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A report whose excerpt carries genesis plus one job, skipping another.

    The shape the hardware run produced: an earlier job wrote seqs 1..6, the real
    job wrote 7..41, and the report for the real job embedded genesis plus
    7..41. The store verified all 42 entries; the report's own chain check
    called it broken at entry 7.
    """
    monkeypatch.setenv(PASSPHRASE_ENV, PASSPHRASE)
    key = load_or_create_key(tmp_path / "sanctum.key.pem")
    print_fingerprint = fingerprint(public_key_of(key))

    ledger = Ledger(
        tmp_path / "store", tool_version="0.1.0", pubkey_fingerprint=print_fingerprint
    )
    for job in ("first-job", "second-job"):
        for index in range(3):
            ledger.append(
                actor="tester",
                operation=f"erase.phase.{index}",
                params={"job_id": job, "index": index},
                result={"ok": True},
            )

    entries = list(ledger.entries())
    excerpt = [
        json.loads(entry.model_dump_json())
        for entry in entries
        if ledger.params_of(entry).get("job_id") == "second-job"
        or entry.operation == "GENESIS"
    ]

    report = build_report(
        case_id="CASE-FILTERED",
        operator="A. Operator",
        generated_at=datetime(2026, 3, 1, tzinfo=UTC),
        tool_version="0.1.0",
        device={"model": "M", "serial": "S", "size_bytes": 1},
        method={"method": "SINGLE_PASS_OVERWRITE"},
        hidden_areas={},
        verification={"strategy": "full_read", "passed": True},
        residual_risk={"level": "low", "factors": [], "purge_achieved": False},
        limitations=[],
        ledger_excerpt=excerpt,
        chain_verification=ledger.verify(),
        pubkey_fingerprint=print_fingerprint,
    )
    report["signature"] = sign_report(report, key).model_dump()
    json_path, _ = write_report(report, tmp_path / "out")
    return {
        "path": json_path,
        "ledger_root": tmp_path / "store",
        "fingerprint": print_fingerprint,
        "excerpt_seqs": [entry["seq"] for entry in excerpt],
    }


def chain_check(result: Any) -> Any:
    return next(c for c in result.checks if c.name == CheckName.CHAIN_INTEGRITY)


def store_check(result: Any) -> Any:
    return next(c for c in result.checks if c.name == CheckName.CHAIN_STORE)


def test_an_honestly_filtered_excerpt_verifies_partial(
    filtered_case: dict[str, Any],
) -> None:
    """The case that used to report "entry 4 does not link to the entry before it"."""
    assert filtered_case["excerpt_seqs"] == [0, 4, 5, 6]

    result = verify_report_file(
        filtered_case["path"], ledger_root=filtered_case["ledger_root"]
    )
    check = chain_check(result)

    assert check.passed is True
    assert check.status == "VERIFIED_PARTIAL"
    assert "1-3" in check.detail, check.detail
    assert result.ok is True


def test_the_declared_gaps_name_what_the_excerpt_left_out(
    filtered_case: dict[str, Any],
) -> None:
    """Declared under the signature, not left to seq arithmetic by the reader."""
    document = json.loads(Path(filtered_case["path"]).read_bytes())

    assert document["sections"]["audit_trail"]["excerpt_gaps"] == [
        {"from_seq": 1, "to_seq": 3, "count": 3}
    ]


def test_a_contiguous_excerpt_verifies_complete(case: dict[str, Any]) -> None:
    result = verify_report_file(case["path"], ledger_root=case["ledger_root"])
    check = chain_check(result)

    assert check.passed is True
    assert check.status == "VERIFIED_COMPLETE"


def test_an_entry_removed_without_updating_the_gaps_is_broken(
    filtered_case: dict[str, Any],
) -> None:
    """The trim the cross-check exists to catch.

    Silently dropping an entry produces an excerpt that looks exactly like an
    honest filter. It is the mismatch against the declaration the excerpt
    carries that gives it away.
    """
    tamper(
        Path(filtered_case["path"]),
        lambda d: d["sections"]["audit_trail"]["entries"].pop(2),
    )

    result = verify_report_file(
        filtered_case["path"], ledger_root=filtered_case["ledger_root"]
    )
    check = chain_check(result)

    assert check.passed is False
    assert check.status == "BROKEN"
    assert "declares gaps" in check.detail, check.detail


def test_an_altered_entry_is_broken_not_partial(
    filtered_case: dict[str, Any],
) -> None:
    def alter(document: dict[str, Any]) -> None:
        document["sections"]["audit_trail"]["entries"][1]["actor"] = "somebody else"

    tamper(Path(filtered_case["path"]), alter)

    check = chain_check(
        verify_report_file(
            filtered_case["path"], ledger_root=filtered_case["ledger_root"]
        )
    )

    assert check.passed is False
    assert check.status == "BROKEN"
    assert "does not hash" in check.detail


def test_a_relinked_excerpt_is_broken(filtered_case: dict[str, Any]) -> None:
    """Adjacent entries must still link; PARTIAL is not a licence to skip that."""

    def alter(document: dict[str, Any]) -> None:
        entries = document["sections"]["audit_trail"]["entries"]
        entries[2]["prev_entry_hash"] = "0" * 64
        # Re-hash so the per-entry check passes and the link check is what fails.
        from core.ledger.chain import entry_hash_of

        entries[2]["entry_hash"] = entry_hash_of(entries[2])

    tamper(Path(filtered_case["path"]), alter)

    check = chain_check(
        verify_report_file(
            filtered_case["path"], ledger_root=filtered_case["ledger_root"]
        )
    )

    assert check.passed is False
    assert check.status == "BROKEN"
    assert "does not link to entry" in check.detail


# --------------------------------------------------------------------------
# The store is re-verified independently of what the report claims
# --------------------------------------------------------------------------


def test_the_store_is_verified_independently(case: dict[str, Any]) -> None:
    check = store_check(
        verify_report_file(case["path"], ledger_root=case["ledger_root"])
    )

    assert check.applicable is True
    assert check.passed is True
    assert check.status == ChainStatus.VALID.value


def test_the_store_check_is_not_applicable_without_a_store(
    case: dict[str, Any],
) -> None:
    check = store_check(verify_report_file(case["path"]))

    assert check.applicable is False
    assert "not re-verified" in check.detail


def test_a_report_claiming_a_status_the_store_contradicts_fails(
    case: dict[str, Any], tmp_path: Path
) -> None:
    """The report's own chain_status is a claim, and claims get checked."""
    tamper(
        Path(case["path"]),
        lambda d: d["sections"]["audit_trail"].update({"chain_status": "BROKEN"}),
    )

    check = store_check(
        verify_report_file(case["path"], ledger_root=case["ledger_root"])
    )

    assert check.passed is False
    assert "records the chain as BROKEN" in check.detail


# --------------------------------------------------------------------------
# The fingerprint check must name the situation it is actually in
# --------------------------------------------------------------------------


def fingerprint_check(result: Any) -> Any:
    return next(
        c for c in result.checks if c.name == CheckName.FINGERPRINT_MATCHES_GENESIS
    )


def test_a_matching_fingerprint_reports_ok(case: dict[str, Any]) -> None:
    check = fingerprint_check(
        verify_report_file(case["path"], ledger_root=case["ledger_root"])
    )

    assert check.passed is True
    assert check.applicable is True
    assert check.status == "OK"


def test_a_chain_started_without_a_key_reports_fingerprint_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The hardware run's case, and the one it was told the wrong reason for.

    The ledger was created before the signing key existed, so genesis carried no
    fingerprint. The check reported "no genesis entry was available to compare
    against" about a report whose excerpt carried genesis at seq 0.
    """
    monkeypatch.setenv(PASSPHRASE_ENV, PASSPHRASE)
    key = load_or_create_key(tmp_path / "sanctum.key.pem")
    print_fingerprint = fingerprint(public_key_of(key))

    ledger = Ledger(tmp_path / "store", tool_version="0.1.0", pubkey_fingerprint="")
    ledger.append(actor="t", operation="erase.phase.0", params={}, result={})
    entries = [json.loads(e.model_dump_json()) for e in ledger.entries()]

    report = build_report(
        case_id="CASE-NOKEY",
        operator="A. Operator",
        generated_at=datetime(2026, 3, 1, tzinfo=UTC),
        tool_version="0.1.0",
        device={},
        method={},
        hidden_areas={},
        verification={},
        residual_risk={"level": "low", "factors": [], "purge_achieved": False},
        limitations=[],
        ledger_excerpt=entries,
        chain_verification=ledger.verify(),
        pubkey_fingerprint=print_fingerprint,
    )
    report["signature"] = sign_report(report, key).model_dump()
    json_path, _ = write_report(report, tmp_path / "out")

    check = fingerprint_check(
        verify_report_file(json_path, ledger_root=tmp_path / "store")
    )

    assert check.applicable is False
    assert check.status == "FINGERPRINT_EMPTY"
    assert "before any signing key existed" in check.detail
    assert "no genesis entry" not in check.detail


def test_genesis_records_the_absence_rather_than_an_empty_string(
    tmp_path: Path,
) -> None:
    """An empty field and "there was no key" are different claims."""
    from core.ledger.chain import NO_SIGNING_KEY

    ledger = Ledger(tmp_path / "store", tool_version="0.1.0", pubkey_fingerprint="")
    ledger.append(actor="t", operation="erase.phase.0", params={}, result={})
    genesis = next(iter(ledger.entries()))

    assert ledger.params_of(genesis)["pubkey_fingerprint"] == NO_SIGNING_KEY


def test_an_excerpt_without_genesis_reports_genesis_absent(
    case: dict[str, Any],
) -> None:
    tamper(
        Path(case["path"]),
        lambda d: d["sections"]["audit_trail"]["entries"].pop(0),
    )

    check = fingerprint_check(
        verify_report_file(case["path"], ledger_root=case["ledger_root"])
    )

    assert check.applicable is False
    assert check.status == "GENESIS_ABSENT"
    assert "carries no genesis entry" in check.detail


def test_no_ledger_root_reports_no_ledger_root(case: dict[str, Any]) -> None:
    check = fingerprint_check(verify_report_file(case["path"]))

    assert check.applicable is False
    assert check.status == "NO_LEDGER_ROOT"
    assert "no ledger store was reachable" in check.detail


def test_a_missing_genesis_blob_reports_blob_missing(
    case: dict[str, Any],
) -> None:
    document = json.loads(Path(case["path"]).read_bytes())
    genesis = document["sections"]["audit_trail"]["entries"][0]
    digest = genesis["params_hash"]
    (case["ledger_root"] / "blobs" / digest[:2] / digest).unlink()

    check = fingerprint_check(
        verify_report_file(case["path"], ledger_root=case["ledger_root"])
    )

    assert check.applicable is False
    assert check.status == "BLOB_MISSING"
    assert "not in the store" in check.detail


def test_an_unparsable_genesis_blob_reports_blob_unparsable(
    case: dict[str, Any],
) -> None:
    document = json.loads(Path(case["path"]).read_bytes())
    genesis = document["sections"]["audit_trail"]["entries"][0]
    digest = genesis["params_hash"]
    (case["ledger_root"] / "blobs" / digest[:2] / digest).write_bytes(b"{not json")

    check = fingerprint_check(
        verify_report_file(case["path"], ledger_root=case["ledger_root"])
    )

    assert check.applicable is False
    assert check.status == "BLOB_UNPARSABLE"
    assert "not valid JSON" in check.detail


def test_a_store_that_lost_entries_the_report_cites_fails(
    case: dict[str, Any],
) -> None:
    """A shorter or rewritten store must not vouch for a longer signed excerpt.

    The store's own chain still verifies after its tail is cut, so the check has
    to compare what the report cites against what the store holds.
    """
    from core.ledger.store import LedgerStore

    path = LedgerStore(case["ledger_root"]).path
    lines = path.read_bytes().splitlines(keepends=True)
    cited = len(
        json.loads(Path(case["path"]).read_text())["sections"]["audit_trail"]["entries"]
    )
    assert cited >= 2
    path.write_bytes(b"".join(lines[: cited - 1]))

    check = store_check(
        verify_report_file(case["path"], ledger_root=case["ledger_root"])
    )

    assert check.passed is False
    assert "cites" in check.detail
