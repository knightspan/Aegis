"""Sanctum-side steps of the hardware validation run. Emits JSON, prints nothing else.

Split out of ``hardware-validation.sh`` so the shell handles what shells are
good at - safety gates, process timing, driving PhotoRec - and this handles what
needs the venv: enumerating through the real probes, running the real erase
engine against real media, and computing recall against known hashes.

Every subcommand writes one JSON object to stdout and exits non-zero only on a
failure the run cannot continue past. A step that *measures a disappointing
result* still exits zero: a recall of 0.0 is a finding, not an error, and a
harness that aborted on it would hide exactly what it exists to surface.
"""

from __future__ import annotations

import argparse
import csv
import errno
import hashlib
import io
import json
import os
import random
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

MIB = 1024 * 1024


def configure_logging() -> None:
    """Send every log line to stderr, leaving stdout for JSON alone.

    structlog's default writes to stdout, which interleaves human-readable log
    lines with the JSON this script emits and makes the result unparsable.
    Found by running the harness rather than by reading it: the first carve
    step produced perfectly good output that ``json.loads`` refused.

    The log lines are kept, not silenced. On a run against real hardware the
    ledger and progress logs are half the evidence about what actually
    happened, and a harness that discarded them to keep its own output tidy
    would be optimising for the wrong reader.
    """
    import logging

    import structlog

    structlog.configure(
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        cache_logger_on_first_use=True,
    )


def emit(payload: dict[str, Any]) -> None:
    json.dump(payload, sys.stdout, indent=2, sort_keys=True, default=str)
    sys.stdout.write("\n")


# --------------------------------------------------------------------------
# Phase A.1 - enumerate, and cross-check against the system's own tools
# --------------------------------------------------------------------------


def cmd_enumerate(args: argparse.Namespace) -> int:
    """What Sanctum reports about the device, beside what lsblk and hdparm say.

    The comparison is the point. Sanctum parses ``lsblk`` and ``hdparm`` output
    itself, so a disagreement means either a parsing bug or a field that means
    something different from what was assumed - and both are the kind of thing
    that only shows up against real hardware with a real vendor string.
    """
    from core.device import capabilities, hidden_areas
    from core.device.enumerate import get_device
    from core.errors import SanctumError

    result: dict[str, Any] = {"step": "enumerate", "path": args.device}

    device = get_device(args.device)
    result["sanctum"] = {"device": device.model_dump(mode="json")}

    try:
        caps = capabilities.probe(device)
        result["sanctum"]["capabilities"] = caps.model_dump(mode="json")
        result["sanctum"]["achievable_levels"] = sorted(
            level.value for level in caps.achievable_levels
        )
    except SanctumError as exc:
        result["sanctum"]["capabilities"] = None
        result["sanctum"]["capability_error"] = exc.message

    try:
        hidden = hidden_areas.detect_hidden_areas(device)
        result["sanctum"]["hidden_areas"] = hidden.model_dump(mode="json")
    except SanctumError as exc:
        result["sanctum"]["hidden_areas"] = None
        result["sanctum"]["hidden_area_error"] = exc.message

    # -- the independent view ---------------------------------------------
    ground: dict[str, Any] = {}
    lsblk = subprocess.run(
        [
            "lsblk", "-Jbdno",
            "NAME,PATH,MODEL,SERIAL,SIZE,ROTA,TRAN,TYPE,RM,PTTYPE",
            args.device,
        ],
        capture_output=True, text=True, check=False,
    )
    if lsblk.returncode == 0:
        try:
            ground["lsblk"] = json.loads(lsblk.stdout)["blockdevices"][0]
        except (ValueError, KeyError, IndexError) as exc:
            ground["lsblk_error"] = f"unparsable: {exc}"
    else:
        ground["lsblk_error"] = lsblk.stderr.strip()

    hdparm = subprocess.run(
        ["hdparm", "-I", args.device], capture_output=True, text=True, check=False
    )
    ground["hdparm_returncode"] = hdparm.returncode
    ground["hdparm_stdout"] = hdparm.stdout
    ground["hdparm_stderr"] = hdparm.stderr.strip()

    udev = subprocess.run(
        ["udevadm", "info", "--query=property", f"--name={args.device}"],
        capture_output=True, text=True, check=False,
    )
    ground["udev"] = {
        key: value
        for key, _, value in (
            line.partition("=") for line in udev.stdout.splitlines()
        )
        if key in {
            "ID_MODEL", "ID_SERIAL_SHORT", "ID_VENDOR", "ID_BUS", "ID_FS_LABEL"
        }
    }
    result["ground_truth"] = ground

    # -- disagreements -----------------------------------------------------
    # Reported, never reconciled. A harness that quietly preferred one source
    # would destroy the only signal this step produces.
    disagreements: list[dict[str, str]] = []
    lsblk_row = ground.get("lsblk", {})
    udev_row = ground.get("udev", {})

    def compare(field: str, sanctum: Any, other: Any, source: str) -> None:
        if other in (None, "") or sanctum == other:
            return
        disagreements.append(
            {
                "field": field,
                "sanctum": str(sanctum),
                source: str(other),
            }
        )

    compare("model", device.model, lsblk_row.get("model"), "lsblk")
    compare("serial", device.serial, lsblk_row.get("serial"), "lsblk")
    compare("size_bytes", device.size_bytes, lsblk_row.get("size"), "lsblk")
    compare("rotational", device.rotational, lsblk_row.get("rota"), "lsblk")
    compare("serial", device.serial, udev_row.get("ID_SERIAL_SHORT"), "udev")
    compare("model", device.model, udev_row.get("ID_MODEL"), "udev")
    result["disagreements"] = disagreements

    emit(result)
    return 0


# --------------------------------------------------------------------------
# Phase A.2 - lay down a known pattern
# --------------------------------------------------------------------------


def cmd_pattern(args: argparse.Namespace) -> int:
    """Fill the device with one byte, at the same block size the erase path uses.

    This replaces ``tr '\\0' '\\245' < /dev/zero | dd of=$DEVICE bs=4M``. dd
    reading from a *pipe* issues one ``read()`` per block and takes whatever the
    pipe has buffered, so with no ``iflag=fullblock`` not one full 4 MiB block
    was ever assembled: measured on the validation host, 200 reads produced 200
    partial records averaging 7414 bytes. Against a 7.76 GB stick that is about
    a million short, unaligned writes, and it took 1899.76s - 4.08 MB/s against
    the 26.7 MB/s the same device sustains on a read.

    The number mattered because it went into the performance report next to the
    erase throughput. It was measuring the pipeline, not the medium. Using the
    erase path's own geometry and buffer size makes the two comparable.
    """
    import mmap
    import os

    from core.erase.drive import DEFAULT_BUFFER_BYTES, device_geometry

    geometry = device_geometry(args.device)
    size = geometry.size_bytes
    block = geometry.logical_block_size
    buf_size = max(block, (DEFAULT_BUFFER_BYTES // block) * block)
    value = int(args.byte, 0)
    if not 0 <= value <= 0xFF:
        raise ValueError(f"--byte must be a single byte value, got {args.byte}")

    # Same preference as core.erase.drive._overwrite: O_DIRECT so the timing
    # describes the medium rather than the page cache, O_DSYNC when the device
    # refuses it.
    direct_flag = getattr(os, "O_DIRECT", 0)
    direct = False
    fd = -1
    if direct_flag:
        try:
            fd = os.open(args.device, os.O_WRONLY | os.O_SYNC | direct_flag)
            direct = True
        except OSError:
            fd = -1
    if fd == -1:
        fd = os.open(args.device, os.O_WRONLY | getattr(os, "O_DSYNC", os.O_SYNC))

    buffer = mmap.mmap(-1, buf_size)  # page-aligned, which O_DIRECT requires
    buffer.write(bytes([value]) * buf_size)
    view = memoryview(buffer)

    started = time.monotonic()
    written = 0
    try:
        while written < size:
            span = min(buf_size, size - written)
            position = 0
            while position < span:
                # A fresh slice each round, released immediately: an mmap cannot
                # be closed while any memoryview over it is still exported.
                chunk = view[position:span]
                try:
                    count = os.write(fd, chunk)
                finally:
                    chunk.release()
                if count <= 0:
                    break
                position += count
                written += count
            if position < span:
                break
        os.fsync(fd)
    finally:
        view.release()
        buffer.close()
        os.close(fd)
    elapsed = time.monotonic() - started

    emit(
        {
            "step": "pattern",
            "device": args.device,
            "byte": f"0x{value:02x}",
            "size_bytes": size,
            "bytes_written": written,
            "complete": written == size,
            "buffer_bytes": buf_size,
            "block_size": block,
            "o_direct": direct,
            "elapsed_seconds": round(elapsed, 3),
            "throughput_mib_per_sec": (
                round(written / MIB / elapsed, 2) if elapsed > 0 and written else 0
            ),
        }
    )
    return 0 if written == size else 1


# --------------------------------------------------------------------------
# Phase A.4 / A.5 - erase and verify
# --------------------------------------------------------------------------


def _ledger(root: Path, key_dir: str | None = None) -> Any:
    """The run's ledger, with the signing key's fingerprint recorded at genesis.

    Genesis is written on the first append, which happens during A.4; the key
    used to be created in A.7, so genesis recorded an empty fingerprint and the
    report's fingerprint check could never do its job. Loading (or creating) the
    key here puts it in place before the first append.

    ``key_dir`` may be ``None`` for read-only uses, which never append and so
    never write genesis.
    """
    from core.ledger.chain import Ledger
    from core.report.sign import fingerprint, load_or_create_key, public_key_of

    finger = ""
    if key_dir is not None:
        finger = fingerprint(public_key_of(load_or_create_key(Path(key_dir))))

    return Ledger(
        root, tool_version="sanctum-forensics/0.0.0", pubkey_fingerprint=finger
    )


def cmd_erase(args: argparse.Namespace) -> int:
    """Run the real erase engine against real media. Always a real erase.

    ``--typed-serial`` is the confirmation the engine checks; it defaults to
    the serial just read. Step A.4 passes a wrong one first and hashes the
    device around it, to prove a refused run writes nothing.
    """
    from core.device import capabilities
    from core.device.enumerate import get_device
    from core.erase.drive import ChainLedgerSink, execute
    from core.errors import SanctumError
    from core.models import EraseJob, SanitizationLevel

    device = get_device(args.device)
    job = EraseJob(
        job_id=args.job_id,
        device=device,
        level=SanitizationLevel(args.level),
        confirmed_serial=(
            device.serial if args.typed_serial is None else args.typed_serial
        ),
        method=None,
    )

    started = time.monotonic()
    progress: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        "step": "erase",
        "job_id": args.job_id,
    }

    try:
        generator = execute(
            job,
            capabilities.probe(device),
            ledger=ChainLedgerSink(_ledger(Path(args.ledger_root), args.key_dir)),
        )
        while True:
            try:
                progress.append(next(generator).model_dump(mode="json"))
            except StopIteration as stop:
                result["result"] = stop.value.model_dump(mode="json")
                break
    except SanctumError as exc:
        result["error"] = exc.message
        result["error_kind"] = type(exc).__name__
        result["remediation"] = exc.remediation
    except OSError as exc:
        result["error"] = str(exc)
        result["error_kind"] = type(exc).__name__

    elapsed = time.monotonic() - started
    written = int((result.get("result") or {}).get("bytes_written") or 0)
    result["elapsed_seconds"] = round(elapsed, 3)
    result["throughput_mib_per_sec"] = (
        round(written / MIB / elapsed, 2) if elapsed > 0 and written else 0
    )
    # Phases in the order they were emitted, so the report can show that all
    # six ran rather than only that the job finished.
    result["phases"] = list(dict.fromkeys(item["phase"] for item in progress))
    result["progress_records"] = len(progress)
    emit(result)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Read the medium back and report what verification actually established.

    ``--expect-fill`` names the byte the medium should hold, which is the only
    way to check a device the erase left holding something other than its
    method's default. On a controller that does not program zeros the erase
    writes 0xA5, so verifying the default 0x00 would fail a good wipe - and on
    such a controller 0x00 is also the one value the flash translation layer can
    answer for free, so it is the worst thing to check against.

    It is also what makes a power-cycle check possible without re-running a
    whole phase: unplug, replug, and verify the medium still holds the pattern
    the erase wrote. A deallocate-to-zero mapping that does not survive a power
    cycle would show up here and nowhere else.
    """
    from core.device.enumerate import get_device
    from core.erase.patterns import SOFTWARE_METHODS, final_pattern
    from core.erase.verify import VerifyConfig, verify
    from core.models import EraseMethod

    fills: tuple[int, ...] | None = None
    if args.expect_fill is not None:
        value = int(args.expect_fill, 0)
        if not 0 <= value <= 0xFF:
            raise ValueError(
                f"--expect-fill must be a single byte value, got {args.expect_fill}"
            )
        fills = (value,)

    device = get_device(args.device)
    method = EraseMethod(args.method)
    started = time.monotonic()
    outcome = verify(
        device,
        method,
        config=VerifyConfig(full_read_max_bytes=args.full_read_max),
        fills=fills,
    )
    emit(
        {
            "step": "verify",
            "elapsed_seconds": round(time.monotonic() - started, 3),
            # Stated, not implied: a result that does not say what it compared
            # against cannot be read without knowing which fill the erase chose.
            "expected_fill": (
                f"0x{fills[-1]:02X}"
                if fills
                else (
                    f"0x{final_pattern(method, block_size=1)[0]:02X}"
                    if method in SOFTWARE_METHODS
                    else "firmware-attested"
                )
            ),
            "expected_fill_source": (
                "--expect-fill" if fills else "the method's default"
            ),
            "method": method.value,
            "result": outcome.model_dump(mode="json"),
        }
    )
    # Exit 0 even when verification failed. A failed verification is a
    # measurement, and this script's contract is that a disappointing result is
    # a finding rather than an error - see the module docstring. Read
    # `.result.passed` from the JSON, or let the harness reporter fail the phase.
    return 0


# --------------------------------------------------------------------------
# Phase A.7 - report, tamper, verify
# --------------------------------------------------------------------------


def cmd_report(args: argparse.Namespace) -> int:
    """Generate the signed report, tamper one byte, verify, restore, verify."""
    from datetime import UTC, datetime

    from core.report.render import build_report, drive_report_inputs, write_report
    from core.report.sign import (
        fingerprint,
        load_or_create_key,
        public_key_of,
        sign_report,
    )
    from core.report.verify_report import verify_report_file

    ledger_root = Path(args.ledger_root)
    ledger = _ledger(ledger_root, args.key_dir)
    erase = json.loads(Path(args.erase_json).read_text()) if args.erase_json else {}
    verification = (
        json.loads(Path(args.verify_json).read_text()) if args.verify_json else {}
    )
    payload = erase.get("result") or {}
    # The state this harness watched the erase end in, so the signed report
    # says it (BATCH6 FINDINGS 5). cmd_erase writes "result" only when the
    # engine's generator returned, and "error" only when it raised. With no
    # erase output at all there is nothing observed, and the builder records
    # "none recorded" rather than an implied completion.
    job_state: str | None = None
    if erase.get("result") is not None:
        job_state = "complete"
    elif erase.get("error"):
        job_state = "failed"

    key = load_or_create_key(Path(args.key_dir))
    finger = fingerprint(public_key_of(key))

    excerpt = [
        json.loads(entry.model_dump_json())
        for entry in ledger.entries()
        if ledger.params_of(entry).get("job_id") == args.job_id
        or entry.operation == "GENESIS"
    ]

    fields: dict[str, Any] = {
        "case_id": args.case_id,
        "operator": args.operator,
        "generated_at": datetime.now(UTC),
        "tool_version": "sanctum-forensics/0.0.0",
        **drive_report_inputs(payload),
        # The harness's own verify step, when it ran one, is the read-back it
        # watched; otherwise the engine's.
        "verification": verification.get("result")
        or drive_report_inputs(payload)["verification"],
        "limitations": list(payload.get("limitations") or []),
        "ledger_excerpt": excerpt,
        "chain_verification": ledger.verify(),
        "pubkey_fingerprint": finger,
        "job_state": job_state,
    }
    unsigned = build_report(**fields)
    signature = sign_report(unsigned, key)
    signed = build_report(**fields, signature=signature)
    json_path, pdf_path = write_report(signed, Path(args.out_dir))

    result: dict[str, Any] = {
        "step": "report",
        "json_path": str(json_path),
        "pdf_path": str(pdf_path),
        "json_bytes": json_path.stat().st_size,
        "pdf_bytes": pdf_path.stat().st_size,
        "pubkey_fingerprint": finger,
        "ledger_excerpt_entries": len(excerpt),
    }

    def check(label: str) -> dict[str, Any]:
        outcome = verify_report_file(json_path, ledger_root=ledger_root)
        return {
            "label": label,
            "ok": outcome.ok,
            "checks": [
                {
                    "name": item.name.value,
                    "passed": item.passed,
                    "applicable": item.applicable,
                    # COMPLETE / PARTIAL / BROKEN for the chain, and which of
                    # the five genesis situations produced the fingerprint
                    # outcome. Pass/fail alone lost both distinctions.
                    "status": item.status,
                    "detail": item.detail,
                }
                for item in outcome.checks
            ],
        }

    result["verify_as_written"] = check("as written")

    # -- tamper exactly one byte ------------------------------------------
    original = json_path.read_bytes()
    # A byte inside the payload, not in the signature block: flipping a byte of
    # the signature itself would prove only that a corrupt signature fails to
    # parse, which is a much weaker claim than "an altered report is detected".
    marker = original.find(b'"operator"')
    offset = marker + 20 if marker != -1 else len(original) // 2
    tampered = bytearray(original)
    tampered[offset] = tampered[offset] ^ 0x01
    json_path.write_bytes(bytes(tampered))
    result["tamper"] = {
        "offset": offset,
        "original_byte": original[offset],
        "tampered_byte": tampered[offset],
        "context": original[max(offset - 30, 0) : offset + 30].decode(
            "utf-8", "replace"
        ),
    }
    result["verify_tampered"] = check("one byte flipped")

    json_path.write_bytes(original)
    result["verify_restored"] = check("restored")

    emit(result)
    return 0


# --------------------------------------------------------------------------
# Phase B - acquire, verify the image, carve, score against known hashes
# --------------------------------------------------------------------------


def cmd_acquire(args: argparse.Namespace) -> int:
    """Image the device read-only and verify the result against its record."""
    from core.carve.acquire import AcquireOptions, acquire, verify_image

    started = time.monotonic()
    generator = acquire(
        Path(args.device),
        Path(args.dest),
        fmt=args.fmt,
        options=AcquireOptions(compression=args.compression, operator="validation"),
        ledger=(
            _ledger(Path(args.ledger_root), args.key_dir)
            if args.ledger_root
            else None
        ),
        job_id=args.job_id,
    )
    records = 0
    while True:
        try:
            next(generator)
            records += 1
        except StopIteration as stop:
            record = stop.value
            break
    elapsed = time.monotonic() - started

    produced = Path(args.dest)
    if not produced.exists() and args.fmt == "e01":
        produced = produced.with_suffix(".E01")

    integrity = verify_image(produced, record)
    emit(
        {
            "step": "acquire",
            "fmt": args.fmt,
            "dest": str(produced),
            "elapsed_seconds": round(elapsed, 3),
            "throughput_mib_per_sec": (
                round(record.bytes_read / MIB / elapsed, 2) if elapsed > 0 else 0
            ),
            "bytes_read": record.bytes_read,
            "on_disk_bytes": produced.stat().st_size if produced.exists() else 0,
            "sha256": record.sha256,
            "blake3": record.blake3,
            "bad_sectors": len(record.bad_sectors),
            "limitations": record.limitations,
            "write_blocked": record.write_blocked,
            "progress_records": records,
            "integrity": integrity.model_dump(mode="json"),
        }
    )
    return 0


def cmd_carve(args: argparse.Namespace) -> int:
    """Run the whole recovery pipeline and score it against known hashes.

    The manifest is ``{"path": {"sha256": ..., "name": ..., "deleted": bool}}``
    for every file that was written to the card, recorded before anything was
    deleted. Recall counts deleted files reproduced byte for byte; nothing
    softer, for the same reason ``testkit/calibrate.py`` counts nothing softer.

    Denominators are file counts, taken from the path-keyed manifest. Two
    planted files with identical content are two planted files - keying the
    manifest by digest lost one of them and shrank the denominator, which
    inflates every recall figure computed from it. Files sharing a digest
    cannot be told apart in a recovery result, so ``duplicate_content_files``
    is reported alongside: when it is non-zero, recovering one copy counts
    every copy, and the reader needs to know that.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from api.carve_job import carve_generator

    manifest = json.loads(Path(args.manifest).read_text())
    deleted_files = [item for item in manifest.values() if item.get("deleted")]
    live_files = [item for item in manifest.values() if not item.get("deleted")]
    deleted = {item["sha256"] for item in deleted_files}
    live = {item["sha256"] for item in live_files}
    duplicate_content = len(manifest) - len({
        item["sha256"] for item in manifest.values()
    })

    started = time.monotonic()
    generator = carve_generator(
        Path(args.image),
        undelete=True,
        carve_signatures=True,
        out_dir=Path(args.out_dir) if args.out_dir else None,
    )
    while True:
        try:
            next(generator)
        except StopIteration as stop:
            outcome = stop.value
            break
    elapsed = time.monotonic() - started

    candidates = outcome["candidates"]
    found = {item["sha256"] for item in candidates}

    def files_recovered(files: list[dict[str, Any]], found_digests: set[str]) -> int:
        """Planted *files* whose content came back, duplicates counted each."""
        return sum(1 for item in files if item["sha256"] in found_digests)

    def score(items: list[dict[str, Any]]) -> dict[str, Any]:
        """Recall and precision over one slice of the candidate list.

        Precision counts *candidates*, not digests, and a candidate is correct
        when its bytes are byte-identical to any file that was planted -
        deleted or live. Scoring correctness against the deleted set alone made
        a correctly recovered live file a false positive: the FAT32 delete pass
        carved five live JPEGs byte-exact out of the unallocated map and was
        docked five candidates of precision for it. That is a real recovery
        being counted as an error, so it is counted separately here and
        ``precision_bp`` includes it.

        ``exact`` stays the deleted-only figure, because recall is a question
        about deleted files and a live file is not in its denominator.
        """
        hit_deleted = [item for item in items if item["sha256"] in deleted]
        hit_live = [item for item in items if item["sha256"] in live]
        exact = {item["sha256"] for item in hit_deleted}
        return {
            "candidates": len(items),
            "named": sum(1 for item in items if item.get("original_name")),
            "exact": len(exact),
            "deleted_hit_candidates": len(hit_deleted),
            "live_hit_candidates": len(hit_live),
            "false_positive_candidates": (
                len(items) - len(hit_deleted) - len(hit_live)
            ),
            "deleted_planted": len(deleted_files),
            "deleted_planted_unique": len(deleted),
            "recall_bp": (
                int(round(
                    files_recovered(deleted_files, exact) * 10_000
                    / len(deleted_files)
                ))
                if deleted_files
                else 0
            ),
            # Correct candidates over all candidates. A live-file recovery is
            # correct.
            "precision_bp": (
                int(round(
                    (len(hit_deleted) + len(hit_live)) * 10_000 / len(items)
                ))
                if items
                else 0
            ),
            # The old definition, kept under a name that says what it is, so
            # the figures already written up stay reproducible.
            "precision_deleted_only_bp": (
                int(round(len(hit_deleted) * 10_000 / len(items)))
                if items
                else 0
            ),
        }

    # BATCH5 §4.5 rows 5 and 6. A reassembled candidate carries the runs its
    # bytes came from; one whose digest matches nothing planted is the most
    # important negative result a run can produce, so every reassembled
    # candidate is listed with what, if anything, it matched.
    planted = deleted | live
    fragment_candidates = [
        {
            "offset": item.get("offset"),
            "sha256": item["sha256"],
            "bucket": item.get("bucket"),
            "source": item.get("source"),
            "runs": item.get("fragments"),
            "matches": (
                "deleted"
                if item["sha256"] in deleted
                else "live" if item["sha256"] in live else "none"
            ),
            "planted_names": sorted(
                entry["name"]
                for entry in manifest.values()
                if entry["sha256"] == item["sha256"]
            ),
        }
        for item in candidates
        if item.get("fragments")
    ]
    high = [item for item in candidates if item.get("bucket") == "HIGH"]
    high_correct = [item for item in high if item["sha256"] in planted]
    high_true_positives = {
        "high_candidates": len(high),
        "true_positives": len(high_correct),
        "true_positives_with_fragments": sum(
            1 for item in high_correct if item.get("fragments")
        ),
        "true_positives_without_fragments": sum(
            1 for item in high_correct if not item.get("fragments")
        ),
        "false_positives_with_fragments": sum(
            1
            for item in high
            if item.get("fragments") and item["sha256"] not in planted
        ),
    }

    by_fs: dict[str, list[dict[str, Any]]] = {}
    for item in candidates:
        by_fs.setdefault(item.get("fs_type") or args.filesystem, []).append(item)

    # The undelete-only slice, so a real run can be compared against a baseline
    # measured with the signature carver switched off. ``testkit/calibrate.py``
    # calls ``undelete_report()`` and nothing else, so its precision counts no
    # signature-carve candidate and no signature-carve false positive. Under
    # one column name those are two different measurements; sliced by source
    # they are one.
    per_fs: dict[str, dict[str, Any]] = {}
    for name, items in by_fs.items():
        row = score(items)
        # Two slices, named for the pipeline halves rather than for the three
        # ``source`` values: "signature" here is source="signature" and
        # source="structure" together, because a structure candidate is a
        # signature candidate a parser then resolved, and both come from the
        # carver rather than from a directory entry.
        row["by_pipeline"] = {
            "undelete": score(
                [item for item in items if item.get("source") == "fs_metadata"]
            ),
            "signature": score(
                [item for item in items if item.get("source") != "fs_metadata"]
            ),
        }
        per_fs[name] = row

    emit(
        {
            "step": "carve",
            "image": args.image,
            "filesystem": args.filesystem,
            "damage": args.damage,
            # Which population was planted. A fragment-plant pass is not the
            # population any calibration row describes, and compare says so.
            "population": getattr(args, "population", "default"),
            # Both halves ran. The baseline this is compared against may not
            # have run both, which is why "compare" slices before it subtracts.
            "pipeline": "undelete+signature",
            "elapsed_seconds": round(elapsed, 3),
            "candidates": len(candidates),
            "planted_files": len(manifest),
            "planted_deleted": len(deleted_files),
            "planted_live": len(live_files),
            "planted_deleted_unique": len(deleted),
            "planted_live_unique": len(live),
            "duplicate_content_files": duplicate_content,
            "recovered_deleted_exact": files_recovered(deleted_files, found),
            "recovered_live_exact": files_recovered(live_files, found),
            "overall_recall_bp": (
                int(round(
                    files_recovered(deleted_files, found) * 10_000 / len(deleted_files)
                ))
                if deleted_files
                else 0
            ),
            "per_filesystem": per_fs,
            "partitions": outcome["partitions"],
            "unallocated_bytes": outcome["unallocated_bytes"],
            "limitations": outcome["limitations"],
            "buckets": {
                bucket: sum(
                    1 for item in candidates if item["bucket"] == bucket
                )
                for bucket in ("HIGH", "MEDIUM", "LOW")
            },
            "reassembled_from_fragments": len(fragment_candidates),
            "fragment_candidates": fragment_candidates,
            "high_true_positives": high_true_positives,
        }
    )
    return 0


def _boot_geometry(path: str) -> dict[str, Any]:
    """Filesystem and cluster size from a volume's boot sector. Reads 512 bytes."""
    with open(path, "rb") as handle:
        sector = handle.read(512)

    filesystem = "unknown"
    bytes_per_sector: int | None = None
    sectors_per_cluster: int | None = None
    if len(sector) == 512 and sector[3:11] == b"EXFAT   ":
        filesystem = "exfat"
        bytes_per_sector = 1 << sector[108]
        sectors_per_cluster = 1 << sector[109]
    elif len(sector) == 512 and sector[82:90] == b"FAT32   ":
        filesystem = "fat32"
        bytes_per_sector = struct.unpack_from("<H", sector, 11)[0]
        sectors_per_cluster = sector[13]
    return {
        "filesystem": filesystem,
        "bytes_per_sector": bytes_per_sector,
        "sectors_per_cluster": sectors_per_cluster,
        "cluster_bytes": (
            bytes_per_sector * sectors_per_cluster
            if bytes_per_sector and sectors_per_cluster
            else None
        ),
    }


def cmd_fs_geometry(args: argparse.Namespace) -> int:
    """The cluster size a volume was formatted with, read from its boot sector.

    Opened read-only and reads 512 bytes. mkfs chooses the cluster size from the
    volume size, so it has to be read back rather than assumed: FAT32 at the
    256 MiB Phase B default is 512-byte clusters, exFAT at the same size is
    4096. Bifragment reassembly searches the volume's own cluster grid when the
    carve can read it and the 512-byte sector grid when it cannot (Batch 7), so
    the record says which one a carve of this volume walks.
    """
    from core.carve.fragmentation import SECTOR_BYTES

    geometry = _boot_geometry(args.device)
    cluster = geometry["cluster_bytes"]
    emit(
        {
            "step": "fs_geometry",
            "device": args.device,
            **geometry,
            "reassembly_grid_bytes": cluster or SECTOR_BYTES,
            "reassembly_grid_source": "volume" if cluster else "sector",
        }
    )
    return 0


def read_runs(device: str, names: list[str]) -> dict[str, dict[str, Any]]:
    """The physical runs each named file occupies, from the volume's own structures.

    Read with pytsk3 rather than asked of the kernel. Measured on this host:
    neither ``vfat`` nor ``exfat`` answers FIEMAP (``EOPNOTSUPP``), so a
    FIEMAP-based map reports every file on exactly the filesystems Phase B
    builds as unmeasured. pytsk3 reads the FAT chain or exFAT allocation the
    carver will later read, in sector units; offsets here are bytes from the
    start of the volume, adjacent runs merged.

    ``runs`` is ``None`` for a name the volume does not hold.
    """
    import pytsk3

    filesystem = pytsk3.FS_Info(pytsk3.Img_Info(device))
    unit = int(filesystem.info.block_size)
    found: dict[str, dict[str, Any]] = {}
    for name in names:
        try:
            entry = filesystem.open("/" + name)
        except OSError:
            found[name] = {"size": None, "runs": None}
            continue
        runs: list[dict[str, int]] = []
        for attribute in entry:
            if attribute.info.type != pytsk3.TSK_FS_ATTR_TYPE_DEFAULT:
                continue
            for run in attribute:
                if run.len <= 0:
                    continue
                offset = int(run.addr) * unit
                length = int(run.len) * unit
                if runs and runs[-1]["offset"] + runs[-1]["length"] == offset:
                    runs[-1]["length"] += length
                else:
                    runs.append({"offset": offset, "length": length})
        found[name] = {"size": int(entry.info.meta.size), "runs": runs}
    return found


def cmd_extents(args: argparse.Namespace) -> int:
    """How many physical runs each named file occupies, before it is damaged.

    Reassembly has nothing to reassemble on a contiguous population, whatever
    the cluster size. Phase B's default populate writes a fresh volume in one
    pass, so its planted files are expected to be contiguous; this records
    whether they were, so a zero in ``reassembled_from_fragments`` says which
    of the two it means.

    Read from the volume with pytsk3 (see :func:`read_runs`), after ``sync``.
    The first version of this step used FIEMAP, which vfat and exfat both
    refuse, and so would have recorded every file as unmeasured.
    """
    geometry = _boot_geometry(args.device)
    runs = read_runs(args.device, list(args.names))
    files: list[dict[str, Any]] = []
    for name in args.names:
        row = runs[name]
        files.append(
            {
                "name": name,
                "size_bytes": row["size"],
                "extents": None if row["runs"] is None else len(row["runs"]),
                "runs": row["runs"],
            }
        )
    emit(
        {
            "step": "extents",
            "device": args.device,
            "method": "pytsk3: runs read from the volume's allocation structures",
            "cluster_bytes": geometry["cluster_bytes"],
            "files": len(files),
            "fragmented_files": sum(1 for f in files if (f["extents"] or 0) > 1),
            "unmeasured_files": sum(
                1
                for f in files
                if f["extents"] is None
                or (f["extents"] == 0 and (f["size_bytes"] or 0))
            ),
            "per_file": files,
        }
    )
    return 0


# --------------------------------------------------------------------------
# Phase B, opt-in - a JPEG in exactly two runs the reassembler can reach
# --------------------------------------------------------------------------

#: Size of each pad written at the end of the fill. The plant frees two
#: consecutive pads around a live one, so the head of the JPEG is one pad long
#: and the gap between its runs is one pad long.
#:
#: 64 KiB because of how far the reassembler reaches. It fixes the head at one
#: cluster and walks the gap in 4096-byte steps, and it gives up after
#: MAX_GAP_CANDIDATES (64) joins - so the second run has to start within about
#: 256 KiB of the header. A 64 KiB head plus a 64 KiB gap needs 32 of them.
#: The brief's first recipe, "delete one filler and let the tail land in the
#: remaining free space", puts the tail at the end of the volume - tens of MiB
#: past the header, and past the search.
FRAG_PAD_BYTES = 64 * 1024

#: Filler written first, to bring the volume to within a few pads of full.
FRAG_FILL_BYTES = 256 * 1024

#: Name of the planted JPEG. Created empty before the fill, so writing it later
#: needs no new directory cluster on a volume that has no free clusters left
#: except the two holes.
FRAG_JPEG_NAME = "fragjpeg.jpg"


class PlantAborted(RuntimeError):
    """The fragmented plant could not be laid down as designed."""


def fragment_jpeg_bytes() -> bytes:
    """A deterministic JPEG sized to need both holes and fit inside them.

    Larger than one pad plus two clusters, so it cannot fit in the first hole
    and its second run clears the reassembler's one-cluster floor with margin;
    smaller than two pads minus two clusters, so it cannot spill past the
    second hole on a 4096-byte volume.
    """
    from PIL import Image

    low = FRAG_PAD_BYTES + 8 * 1024
    high = 2 * FRAG_PAD_BYTES - 8 * 1024
    side = 128
    while side <= 1024:
        rng = random.Random(0x5A1C7 + side)
        image = Image.new("RGB", (side, side))
        image.putdata(
            [
                (rng.randrange(256), rng.randrange(256), rng.randrange(256))
                for _ in range(side * side)
            ]
        )
        buffer = io.BytesIO()
        image.save(buffer, "JPEG", quality=95)
        payload = buffer.getvalue()
        if low <= len(payload) <= high:
            return payload
        if len(payload) > high:
            break
        side += 4
    raise PlantAborted(
        f"no noise JPEG between {low} and {high} bytes was found; the plant "
        "cannot size its object"
    )


def plant_fragmented(
    root: Path | str, *, statvfs: Any = None, seed: int = 11
) -> dict[str, Any]:
    """Lay one JPEG down in exactly two runs, around a live pad.

    1. Create the JPEG's directory entry, empty, while space remains.
    2. Fill the volume: 256 KiB fillers until a few pads' worth is left, then
       64 KiB pads, then whatever is left, until there is no free space at all.
    3. Delete the first and third pads. The only free space on the volume is
       now two 64 KiB holes with a live 64 KiB pad between them.
    4. Write the JPEG. It does not fit the first hole, so the allocator puts
       the head there and the tail in the second.

    Every file the plant will write is created, empty, **before** the first
    byte of fill. Measured on a loopback FAT32 volume: creating pads one at a
    time made the root directory grow mid-fill, its new 512-byte cluster landed
    between two pads, and the gap came out 66,048 bytes - off the 4096-byte grid
    the search walks. An empty file takes a directory slot and no data cluster,
    so creating them all first moves every directory cluster ahead of the fill.
    Placeholders the fill did not need are removed before the holes are made;
    removing an empty file frees no data cluster.

    Step 2 filling the volume *completely* is what makes this independent of
    the allocator's search order. A next-fit allocator starts after the last
    cluster it handed out - the end of the volume - and wraps; a first-fit one
    starts at the front. With nothing free but the two holes, both reach the
    first hole first.

    This lays the plant down and records what it did. It does not decide
    whether the filesystem cooperated: ``fragment-verify`` reads the runs back
    from the volume and refuses the pass if they are not what the reassembler
    needs.

    Raises:
        PlantAborted: fewer than three pads fit, a pad came out short, or the
            volume could not be brought to zero free space.
    """
    target_root = Path(root)
    rng = random.Random(seed)
    jpeg = fragment_jpeg_bytes()
    # Resolved here rather than in the signature: `os.statvfs` as a default
    # argument is evaluated at import, and this module does not exist on
    # Windows - which made importing it there an AttributeError, and took 36
    # platform-independent carving tests down with it on the Windows runner.
    measure = statvfs if statvfs is not None else os.statvfs

    def free() -> int:
        stats = measure(target_root)
        return int(stats.f_bavail) * int(stats.f_frsize)

    created: list[str] = []
    fill_names = [
        f"fragfill{index:05d}.bin" for index in range(free() // FRAG_FILL_BYTES + 1)
    ]
    pad_names = [
        f"fragpad{index:03d}.bin"
        for index in range(FRAG_FILL_BYTES // FRAG_PAD_BYTES + 6)
    ]
    rest_names = [f"fragrest{index:02d}.bin" for index in range(16)]
    placeholders = [FRAG_JPEG_NAME, *fill_names, *pad_names, *rest_names]
    try:
        for name in placeholders:
            (target_root / name).write_bytes(b"")
    except OSError as exc:
        raise PlantAborted(
            f"creating {len(placeholders)} empty directory entries failed at "
            f"{name!r} with {free()} bytes free: {exc}"
        ) from exc
    os.sync()

    def write(name: str, size: int) -> None:
        path = target_root / name
        try:
            with path.open("r+b") as handle:
                handle.write(rng.randbytes(size))
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            if exc.errno != errno.ENOSPC:
                raise
        created.append(name)

    created.append(FRAG_JPEG_NAME)

    for name in fill_names:
        if free() < FRAG_FILL_BYTES + 4 * FRAG_PAD_BYTES:
            break
        write(name, FRAG_FILL_BYTES)

    pads: list[str] = []
    for name in pad_names:
        if free() < FRAG_PAD_BYTES:
            break
        write(name, FRAG_PAD_BYTES)
        pads.append(name)
    if len(pads) < 3:
        raise PlantAborted(
            f"only {len(pads)} pad(s) of {FRAG_PAD_BYTES} bytes fit on the volume; "
            "the plant needs three consecutive pads"
        )
    first, gap, second = pads[0], pads[1], pads[2]
    for name in (first, gap, second):
        size = (target_root / name).stat().st_size
        if size != FRAG_PAD_BYTES:
            raise PlantAborted(
                f"pad {name} holds {size} bytes, not {FRAG_PAD_BYTES}; the holes "
                "would not be the size the plant was designed around"
            )

    for name in rest_names:
        if free() <= 0:
            break
        write(name, free())
    if free() > 0:
        raise PlantAborted(
            f"{free()} bytes are still free after {len(rest_names)} top-up files; "
            "free space outside the two holes would be allocated first"
        )
    for name in placeholders:
        if name not in created:
            (target_root / name).unlink()
    os.sync()

    for name in (first, second):
        (target_root / name).unlink()
        created.remove(name)
    os.sync()
    free_before_jpeg = free()

    try:
        with (target_root / FRAG_JPEG_NAME).open("wb") as handle:
            handle.write(jpeg)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise PlantAborted(
            f"writing the {len(jpeg)}-byte JPEG failed with {free_before_jpeg} "
            f"bytes free after freeing two {FRAG_PAD_BYTES}-byte pads: {exc}"
        ) from exc
    os.sync()

    return {
        "jpeg": FRAG_JPEG_NAME,
        "jpeg_bytes": len(jpeg),
        "jpeg_sha256": hashlib.sha256(jpeg).hexdigest(),
        "pad_bytes": FRAG_PAD_BYTES,
        "fill_bytes": FRAG_FILL_BYTES,
        "pad_order": pads,
        "freed": [first, second],
        "gap_file": gap,
        "free_bytes_before_jpeg": free_before_jpeg,
        "files": created,
    }


def judge_fragment_plant(
    runs: list[dict[str, int]], *, size: int, cluster_bytes: int | None = None
) -> dict[str, Any]:
    """Whether a JPEG's on-disk runs are something the reassembler can recover.

    Mirrors the geometric constraints of
    :func:`core.carve.fragmentation.reassemble_bifragmented_jpeg_runs`: exactly
    two runs, the second after the first, head and gap whole multiples of the
    volume's cluster size (the 512-byte sector when it is unknown), a tail
    holding more than its EOI marker, and the whole object within the search
    window of its header.

    ``reachable`` is necessary, not sufficient. The search also refuses when
    the gap bytes next to the runs carry no byte pair a scan cannot contain and
    too many joins would have to be tried to rule them out, and when other JPEG
    ends between the runs use up its budget. Those depend on bytes this verdict
    does not read.

    Two verdicts, because they mean different things and lead to different
    actions:

    * ``plant_ok`` - the object really is one JPEG in exactly two runs. When it
      is not, the pass has nothing to say about bifragment reassembly and the
      harness stops it.
    * ``reachable`` - the layout is one the search enumerates. When a good
      plant is *not* reachable the pass still runs, labelled: at ``hwval-run4``
      a two-run JPEG the search could not enumerate made the reassembler join
      the real head to a partial tail and score it HIGH, matching nothing
      planted. Refusing that pass would hide whether it still can.
    """
    from core.carve.fragmentation import MAX_SEARCH_WINDOW, SECTOR_BYTES

    step = cluster_bytes or SECTOR_BYTES
    reasons: list[str] = []
    reach: list[str] = []
    verdict: dict[str, Any] = {
        "runs": len(runs),
        "head_bytes": None,
        "gap_bytes": None,
        "tail_bytes": None,
        "grid_bytes": step,
        "max_search_window": MAX_SEARCH_WINDOW,
    }
    if len(runs) != 2:
        plural = "" if len(runs) == 1 else "s"
        reasons.append(
            f"the JPEG occupies {len(runs)} run{plural} on the medium; the "
            "reassembler recovers exactly 2"
        )
    else:
        head, tail = runs
        head_bytes = int(head["length"])
        gap = int(tail["offset"]) - (int(head["offset"]) + head_bytes)
        tail_bytes = size - head_bytes
        verdict.update(head_bytes=head_bytes, gap_bytes=gap, tail_bytes=tail_bytes)
        if int(tail["offset"]) <= int(head["offset"]):
            reach.append(
                "the second run lies before the first on the medium; the gap "
                "search only looks forward from the header"
            )
        else:
            if head_bytes % step:
                reach.append(
                    f"the head is {head_bytes} bytes, not a multiple of {step}; "
                    "the search only tries heads on the volume's cluster grid"
                )
            if gap % step:
                reach.append(
                    f"the gap is {gap} bytes, not a multiple of {step}; the "
                    "search only tries gaps on the volume's cluster grid"
                )
            if tail_bytes <= 2:
                reach.append(
                    f"the tail holds {tail_bytes} bytes, no more than the EOI "
                    "marker; there is nothing to join"
                )
            if head_bytes + gap + max(tail_bytes, 0) > MAX_SEARCH_WINDOW:
                reach.append(
                    f"the object ends {head_bytes + gap + tail_bytes} bytes after "
                    f"its header, past the {MAX_SEARCH_WINDOW}-byte search window"
                )
    verdict["reasons"] = reasons
    verdict["reach_reasons"] = reach
    verdict["plant_ok"] = not reasons
    verdict["reachable"] = not reasons and not reach
    return verdict


def cmd_plant_fragmented(args: argparse.Namespace) -> int:
    """Lay the fragmented plant down on a mounted volume. See plant_fragmented."""
    try:
        plant = plant_fragmented(Path(args.root))
    except PlantAborted as exc:
        emit({"step": "fragment_plant", "ok": False, "error": str(exc)})
        return 1
    emit({"step": "fragment_plant", "ok": True, **plant})
    return 0


def cmd_fragment_verify(args: argparse.Namespace) -> int:
    """Read the plant back from the unmounted volume and refuse it unless usable.

    Annotates every manifest entry with its runs, extent count and the volume's
    cluster size, so the recall figures can be read against the population that
    was actually on the medium. Exits 1 when the JPEG is not in exactly two
    runs, or when the bytes at those runs are not the JPEG that was written:
    the harness stops the pass there, loudly, because a zero from a failed plant
    would read as a result about reassembly. A good plant the search cannot
    recover exits 0 with ``reachable: false`` - see judge_fragment_plant.
    """
    plant = json.loads(Path(args.plant_json).read_text())
    geometry = _boot_geometry(args.device)
    manifest_path = Path(args.manifest)
    manifest = json.loads(manifest_path.read_text())

    runs = read_runs(
        args.device, sorted({entry["name"] for entry in manifest.values()})
    )
    roles = {plant["jpeg"]: "fragmented_jpeg", plant["gap_file"]: "gap_pad"}
    for entry in manifest.values():
        row = runs.get(entry["name"]) or {"runs": None}
        entry["runs"] = row["runs"]
        entry["extent_count"] = None if row["runs"] is None else len(row["runs"])
        entry["cluster_bytes"] = geometry["cluster_bytes"]
        if entry["name"] in roles:
            entry["fragment_plant_role"] = roles[entry["name"]]
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))

    jpeg = runs.get(plant["jpeg"]) or {"size": None, "runs": None}
    jpeg_runs = jpeg["runs"] or []
    verdict = judge_fragment_plant(
        jpeg_runs,
        size=int(jpeg["size"] or 0),
        cluster_bytes=geometry["cluster_bytes"],
    )

    on_disk = bytearray()
    with open(args.device, "rb") as handle:
        for run in jpeg_runs:
            handle.seek(run["offset"])
            on_disk += handle.read(run["length"])
    on_disk_sha = hashlib.sha256(bytes(on_disk[: int(jpeg["size"] or 0)])).hexdigest()
    verdict["on_disk_sha256_matches"] = on_disk_sha == plant["jpeg_sha256"]
    if not verdict["on_disk_sha256_matches"]:
        verdict["reasons"].append(
            "the bytes at the recorded runs are not the JPEG that was written"
        )
        verdict["plant_ok"] = False
        verdict["reachable"] = False

    emit(
        {
            "step": "fragment_verify",
            "device": args.device,
            "cluster_bytes": geometry["cluster_bytes"],
            "filesystem": geometry["filesystem"],
            "jpeg": plant["jpeg"],
            "jpeg_size": jpeg["size"],
            "jpeg_runs": jpeg["runs"],
            "gap_file_runs": (runs.get(plant["gap_file"]) or {}).get("runs"),
            "verdict": verdict,
            "plant_ok": verdict["plant_ok"],
            "reachable": verdict["reachable"],
            "manifest_files_with_more_than_one_run": sum(
                1 for entry in manifest.values() if (entry["extent_count"] or 0) > 1
            ),
        }
    )
    return 0 if verdict["plant_ok"] else 1


#: Below this many deleted files a baseline row is a demonstration that a
#: mechanism applies, not a rate. The exFAT row is n=2 - one file with
#: ``NoFatChain`` set that came back and one that used a chain the deletion
#: destroyed - and real media returning 460 of 460 against its "50%" was
#: flagged as a divergence. It is not one. Nothing about 460 measurements
#: disagrees with two.
MIN_BASELINE_N = 30

#: A recall gap wider than this is not noise on a corpus of the size Phase B
#: plants, and means the calibration is describing synthetic media rather than
#: real media.
DIVERGENCE_BP = 1000


def cmd_compare(args: argparse.Namespace) -> int:
    """Real-media recall beside what the synthetic corpus predicted.

    This is the point of Phase B. Every confidence number the report prints is
    derived from weights calibrated on synthetic images; if real media recalls
    differently, the calibration is describing something other than reality and
    the numbers inherit the error.

    Three things have to line up before a difference between the two sides is
    a finding rather than an artefact of how they were measured, and the first
    real run got all three wrong:

    * **The damage model.** The baseline was looked up by filesystem name
      alone, so a quick-format run - where every directory entry is gone and
      undelete has nothing to work from - was scored against a delete baseline
      and came out 94 points low. Those are two experiments, not one
      measurement and its prediction.
    * **The sample size.** A row of two files was flagged as diverging from a
      row of 460. See :data:`MIN_BASELINE_N`.
    * **The pipeline.** ``testkit/calibrate.py`` measures undelete only; a real
      run carves signatures as well, and every signature-carve false positive
      exists on one side of that subtraction and not the other. The comparison
      now slices the real run by candidate source and compares the slice the
      baseline actually measured.
    """
    synthetic: dict[tuple[str, str], dict[str, Any]] = {}
    csv_path = Path(args.calibration_csv)
    if csv_path.exists():
        with csv_path.open(encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                # Rows written before the columns existed are delete-damage,
                # undelete-pipeline rows; that is what the corpus did.
                damage = row.get("damage") or "delete"
                synthetic[(row["filesystem"], damage)] = {
                    "deleted": int(row["deleted"]),
                    "recall_bp": int(row["recall_bp"]),
                    "precision_bp": int(row["precision_bp"]),
                    "pipeline": row.get("pipeline") or "undelete",
                }

    rows: list[dict[str, Any]] = []
    for path in args.carve_json:
        measured = json.loads(Path(path).read_text())
        damage = measured.get("damage", "delete")
        population = measured.get("population", "default")
        for name, row in measured["per_filesystem"].items():
            # A pass that planted a different population has no baseline, even
            # when a row for its filesystem and damage exists.
            predicted = (
                synthetic.get((name, damage)) if population == "default" else None
            )
            entry: dict[str, Any] = {
                "filesystem": name,
                "damage": damage,
                "real_deleted": row["deleted_planted"],
                "real_exact": row["exact"],
                "real_recall_bp": row["recall_bp"],
                "real_precision_bp": row["precision_bp"],
                "real_pipeline": measured.get("pipeline", "undelete+signature"),
            }

            if predicted is None:
                # Not a divergence and not a match: nothing in the corpus did
                # this to a volume, so there is nothing to compare against.
                entry.update(
                    synthetic_deleted=None,
                    synthetic_recall_bp=None,
                    synthetic_precision_bp=None,
                    synthetic_pipeline=None,
                    compared_pipeline=None,
                    recall_delta_bp=None,
                    precision_delta_bp=None,
                    status="no_baseline",
                    note=(
                        f"no calibration row for {name}/{damage}: this is a new"
                        " measurement, not a comparison"
                        if population == "default"
                        else f"this pass planted the {population!r} population,"
                        " which no calibration row describes: a new measurement,"
                        " not a comparison"
                    ),
                    diverges=None,
                )
                rows.append(entry)
                continue

            # Compare the half of the real run the baseline measured. When the
            # baseline ran both halves this is the whole run and the slice is a
            # no-op.
            pipeline = predicted["pipeline"]
            slice_ = row.get("by_pipeline", {}).get(pipeline, row)
            recall_delta = slice_["recall_bp"] - predicted["recall_bp"]
            precision_delta = slice_["precision_bp"] - predicted["precision_bp"]
            underpowered = predicted["deleted"] < MIN_BASELINE_N

            entry.update(
                synthetic_deleted=predicted["deleted"],
                synthetic_recall_bp=predicted["recall_bp"],
                synthetic_precision_bp=predicted["precision_bp"],
                synthetic_pipeline=pipeline,
                compared_pipeline=pipeline,
                compared_recall_bp=slice_["recall_bp"],
                compared_precision_bp=slice_["precision_bp"],
                compared_candidates=slice_["candidates"],
                recall_delta_bp=recall_delta,
                precision_delta_bp=precision_delta,
            )

            if underpowered:
                entry.update(
                    status="baseline_underpowered",
                    note=(
                        f"baseline is n={predicted['deleted']}, below the"
                        f" minimum of {MIN_BASELINE_N}: it shows which"
                        " mechanism applies, not a rate, and a gap against it"
                        " is not a divergence"
                    ),
                    diverges=False,
                )
            elif abs(recall_delta) > DIVERGENCE_BP:
                entry.update(
                    status="diverges",
                    note=(
                        f"real {pipeline} recall differs from the calibration"
                        f" by {recall_delta / 100:+.2f} points"
                    ),
                    diverges=True,
                )
            else:
                entry.update(status="agrees", note="", diverges=False)

            rows.append(entry)

    emit({"step": "compare", "min_baseline_n": MIN_BASELINE_N, "rows": rows})
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    """Create the signing key, and report its fingerprint.

    A subcommand rather than a heredoc in the caller, because a bare
    ``python - <<EOF`` snippet never calls :func:`configure_logging` and
    structlog's default writes to **stdout**. demo-reset.sh captured that
    stdout into ``key.json``::

        2026-09-05 15:12:08 [info  ] signing_key_created  path=.../key.pem
        {"fingerprint": "27:9F:14:..."}

    ``json.loads`` refuses that, ``harness_json_field`` returned "", and the
    console printed an empty fingerprint over a key that had been created
    perfectly well. Routing it through this file puts the log line on stderr
    where it belongs and leaves stdout to the JSON alone.

    Genesis is unaffected either way: the ledger reads the fingerprint from the
    key file with ``fingerprint_of_existing_key``, never from this JSON. What
    was broken was the report of the value, not the value.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from core.report.sign import fingerprint, load_or_create_key, public_key_of

    key = load_or_create_key(Path(args.key_dir))
    emit({"step": "keygen", "fingerprint": fingerprint(public_key_of(key))})
    return 0


def cmd_hash_tree(args: argparse.Namespace) -> int:
    """Record the SHA-256 of every file under a directory, before deletion.

    Keyed by path, not by digest. Keyed by digest, files with identical content
    collapsed into one entry: the 14 files planted in Phase A.2 - three
    byte-identical PDFs and two byte-identical docx among them - were recorded
    as 11, and 11 is what the console reported as "planted". A recall
    denominator taken from that count is wrong by a quarter.
    """
    manifest: dict[str, dict[str, Any]] = {}
    root = Path(args.root)
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        name = str(path.relative_to(root))
        manifest[name] = {
            "name": name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size": path.stat().st_size,
            "deleted": False,
        }
    Path(args.out).write_text(json.dumps(manifest, indent=2, sort_keys=True))
    digests = {item["sha256"] for item in manifest.values()}
    emit(
        {
            "step": "hash_tree",
            "root": str(root),
            "files": len(manifest),
            # Reported beside the file count rather than instead of it: carving
            # recovers content, so files sharing a digest cannot be told apart
            # in a recovery result, and a reader needs both numbers to read a
            # recall figure correctly.
            "unique_digests": len(digests),
            "duplicate_content_files": len(manifest) - len(digests),
        }
    )
    return 0


def cmd_mark_deleted(args: argparse.Namespace) -> int:
    """Mark manifest entries as deleted, by name."""
    path = Path(args.manifest)
    manifest = json.loads(path.read_text())
    names = set(args.names)
    marked = 0
    for item in manifest.values():
        if item["name"] in names:
            item["deleted"] = True
            marked += 1
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    missing = sorted(names - {item["name"] for item in manifest.values()})
    emit(
        {
            "step": "mark_deleted",
            "marked": marked,
            "requested": len(names),
            "not_in_manifest": missing,
        }
    )
    return 0 if not missing else 1


# --------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    enumerate_parser = sub.add_parser("enumerate")
    enumerate_parser.add_argument("--device", required=True)
    enumerate_parser.set_defaults(handler=cmd_enumerate)

    erase_parser = sub.add_parser("erase")
    erase_parser.add_argument(
        "--key-dir",
        required=True,
        help=(
            "Directory holding the signing key. Loaded or created before the "
            "first ledger append so genesis records its fingerprint."
        ),
    )
    erase_parser.add_argument("--device", required=True)
    erase_parser.add_argument("--job-id", required=True)
    erase_parser.add_argument("--ledger-root", required=True)
    erase_parser.add_argument("--level", default="CLEAR")
    erase_parser.add_argument(
        "--typed-serial",
        default=None,
        help="The confirmation value. Defaults to the serial read from the device.",
    )
    erase_parser.set_defaults(handler=cmd_erase)

    pattern_parser = sub.add_parser("pattern")
    pattern_parser.add_argument("--device", required=True)
    pattern_parser.add_argument(
        "--byte", default="0xA5", help="Fill byte, e.g. 0xA5. Default: 0xA5."
    )
    pattern_parser.set_defaults(handler=cmd_pattern)

    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--device", required=True)
    verify_parser.add_argument("--method", default="SINGLE_PASS_OVERWRITE")
    verify_parser.add_argument(
        "--full-read-max", type=int, default=64 * 1024 * MIB
    )
    verify_parser.add_argument(
        "--expect-fill",
        default=None,
        help=(
            "Byte the medium should hold, e.g. 0xA5. Overrides the method's "
            "default pattern. Use it when the erase chose a non-zero fill, and "
            "to re-check a device after a power cycle."
        ),
    )
    verify_parser.set_defaults(handler=cmd_verify)

    report_parser = sub.add_parser("report")
    report_parser.add_argument("--job-id", required=True)
    report_parser.add_argument("--ledger-root", required=True)
    report_parser.add_argument("--key-dir", required=True)
    report_parser.add_argument("--out-dir", required=True)
    report_parser.add_argument("--case-id", default="HW-VALIDATION")
    report_parser.add_argument("--operator", default="validation")
    report_parser.add_argument("--erase-json")
    report_parser.add_argument("--verify-json")
    report_parser.set_defaults(handler=cmd_report)

    acquire_parser = sub.add_parser("acquire")
    acquire_parser.add_argument("--device", required=True)
    acquire_parser.add_argument("--dest", required=True)
    acquire_parser.add_argument("--fmt", default="raw", choices=["raw", "e01"])
    acquire_parser.add_argument("--compression", default="fast")
    acquire_parser.add_argument("--ledger-root")
    acquire_parser.add_argument("--key-dir")
    acquire_parser.add_argument("--job-id", default="acquire")
    acquire_parser.set_defaults(handler=cmd_acquire)

    carve_parser = sub.add_parser("carve")
    carve_parser.add_argument("--image", required=True)
    carve_parser.add_argument("--manifest", required=True)
    carve_parser.add_argument("--filesystem", required=True)
    carve_parser.add_argument(
        "--damage",
        default="delete",
        help=(
            "Damage model that made the files unreachable. Recorded in the "
            "output and used to pick the calibration baseline: a quick-format "
            "run scored against a delete baseline compares two experiments."
        ),
    )
    carve_parser.add_argument("--out-dir")
    carve_parser.add_argument(
        "--population",
        default="default",
        help="What Phase B planted: 'default', or 'fragment-plant'.",
    )
    carve_parser.set_defaults(handler=cmd_carve)

    compare_parser = sub.add_parser("compare")
    compare_parser.add_argument("--carve-json", nargs="+", required=True)
    compare_parser.add_argument(
        "--calibration-csv",
        default="docs/performance/calibration-filesystems.csv",
    )
    compare_parser.set_defaults(handler=cmd_compare)

    geometry_parser = sub.add_parser("fs-geometry")
    geometry_parser.add_argument("--device", required=True)
    geometry_parser.set_defaults(handler=cmd_fs_geometry)

    extents_parser = sub.add_parser("extents")
    extents_parser.add_argument("--device", required=True)
    extents_parser.add_argument("--names", nargs="+", required=True)
    extents_parser.set_defaults(handler=cmd_extents)

    plant_parser = sub.add_parser("plant-fragmented")
    plant_parser.add_argument("--root", required=True)
    plant_parser.set_defaults(handler=cmd_plant_fragmented)

    frag_verify_parser = sub.add_parser("fragment-verify")
    frag_verify_parser.add_argument("--device", required=True)
    frag_verify_parser.add_argument("--plant-json", required=True)
    frag_verify_parser.add_argument("--manifest", required=True)
    frag_verify_parser.set_defaults(handler=cmd_fragment_verify)

    keygen_parser = sub.add_parser("keygen")
    keygen_parser.add_argument("--key-dir", required=True)
    keygen_parser.set_defaults(handler=cmd_keygen)

    hash_parser = sub.add_parser("hash-tree")
    hash_parser.add_argument("--root", required=True)
    hash_parser.add_argument("--out", required=True)
    hash_parser.set_defaults(handler=cmd_hash_tree)

    mark_parser = sub.add_parser("mark-deleted")
    mark_parser.add_argument("--manifest", required=True)
    mark_parser.add_argument("--names", nargs="+", required=True)
    mark_parser.set_defaults(handler=cmd_mark_deleted)

    args = parser.parse_args()
    configure_logging()
    handler: Any = args.handler
    return int(handler(args))


if __name__ == "__main__":
    sys.exit(main())
