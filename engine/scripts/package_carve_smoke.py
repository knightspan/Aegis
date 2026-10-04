"""Prove /jobs/carve works through an *installed* package, against the same
deterministic ground-truth image scripts/demo_fragmented.py uses.

Every prior "M3 carving" claim in this project ran the carve engine
in-process, directly against the source tree, where
``core/carve/signature.py:SIGNATURE_DB_PATH`` (computed from ``__file__``)
happens to resolve correctly. ``scripts/package_smoke.py`` has never called
``/jobs/carve`` on any platform, so no prior packaged-checks claim actually
proves carving works in the *shipped* package - and on 2026-09-27 it did not:
the signature table lived under ``testkit/``, which ``packaging/sanctum.spec``
excludes, and every packaged build raised
``EvidenceIntegrityError: signature table not found`` the moment carving was
asked to run. Fixed by bundling that one data file (see
``packaging/sanctum.spec`` and ``tests/test_packaging_spec.py``); this script
is the runtime proof, not a static check of the archive's contents.

No device is opened. The image is a synthetic file this script builds via
``scripts/demo_fragmented.py:build()`` - the exact PNG/JPEG bifragment split,
intact/duplicate, corrupted-tail and decoy scenarios that script checks
in-process, now checked again through the real API, on the real installed
executable.

    python scripts/package_carve_smoke.py dist/Sanctum/Sanctum.exe \\
        --out carve-smoke-Windows.json
"""

from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import demo_fragmented  # noqa: E402
import package_smoke  # noqa: E402

SEED = demo_fragmented.SEED


def _finish(client: package_smoke.Client, job_id: str, timeout_s: float = 90.0) -> dict:
    deadline = time.monotonic() + timeout_s
    status: dict = {}
    while time.monotonic() < deadline:
        code, status = client.request(f"/jobs/{job_id}")
        finished = isinstance(status, dict) and status.get("state") != "running"
        if code == 200 and finished:
            return status
        time.sleep(0.3)
    raise TimeoutError(f"job {job_id} did not finish: {status}")


def _row_for(item: dict[str, Any], candidates: list[dict[str, Any]]) -> dict[str, Any]:
    found = [c for c in candidates if int(c.get("offset", -1)) == item["offset"]]
    best = max(found, key=lambda c: int(c.get("confidence_bp") or 0), default=None)
    folded_into = next(
        (
            int(c["offset"])
            for c in candidates
            if item["offset"] in (c.get("duplicate_offsets") or [])
        ),
        None,
    )
    return {
        **item,
        "found": best is not None,
        "duplicate_of": folded_into,
        "bucket": (best or {}).get("bucket"),
        "evidence_score": (best or {}).get("confidence_bp"),
        "digest_matches_ground_truth": bool(
            best and item.get("sha256") and best.get("sha256") == item["sha256"]
        ),
    }


def _grade(row: dict[str, Any]) -> tuple[bool, str]:
    """Same expectations scripts/demo_fragmented.py's ground truth carries."""
    expect = row["expect"]
    if "same digest as" in expect:
        ok = not row["found"] and row["duplicate_of"] is not None
        return ok, "deduplicated as expected" if ok else "not deduplicated"
    if expect.startswith("recovered whole, HIGH") or "reassembled" in expect:
        below_high = "below HIGH" in expect
        ok = (
            row["found"]
            and row["digest_matches_ground_truth"]
            and (row["bucket"] != "HIGH" if below_high else row["bucket"] == "HIGH")
        )
        digest_ok = row["digest_matches_ground_truth"]
        return ok, f"bucket={row['bucket']} digest_ok={digest_ok}"
    if "not rebuilt" in expect or "not valid" in expect:
        ok = row["bucket"] != "HIGH" and not row.get("digest_matches_ground_truth")
        return ok, f"bucket={row['bucket']}"
    if "never HIGH" in expect:
        ok = row["bucket"] != "HIGH"
        return ok, f"bucket={row['bucket']}"
    return False, f"no grading rule for: {expect!r}"


def run(executable: Path, argv_extra: list[str] | None = None) -> dict[str, Any]:
    scratch = Path(tempfile.mkdtemp(prefix="sanctum-carvesmoke-"))
    state = scratch / "state"
    url_file = scratch / "session-url.txt"
    image_bytes, truth = demo_fragmented.build(random.Random(SEED))
    source = scratch / "carve-smoke-source.img"
    source.write_bytes(image_bytes)

    environment = dict(os.environ)
    environment.update(
        {"SANCTUM_STATE_DIR": str(state), "SANCTUM_URL_FILE": str(url_file)}
    )
    log_path = scratch / "app.log"
    log = log_path.open("w", encoding="utf-8")
    process = subprocess.Popen(  # noqa: S603 - argv list, no shell
        [str(executable), *(argv_extra or [])],
        env=environment,
        stdout=log,
        stderr=subprocess.STDOUT,
        text=True,
    )

    checks: list[dict[str, Any]] = []

    def record(name: str, ok: bool, detail: Any = "") -> None:
        checks.append(
            {"check": name, "result": "PASS" if ok else "FAIL", "detail": detail}
        )

    rows: list[dict[str, Any]] = []
    try:
        url = package_smoke.wait_for_url(url_file, timeout_s=60)
        base = url.split("/session/")[0]
        client = package_smoke.Client(base)
        client.request(url[len(base) :])

        code, acc = client.request(
            "/jobs/acquire",
            method="POST",
            body={"source": str(source), "dest": "carve-smoke/image.raw"},
        )
        record("acquire accepted", code == 200, acc)
        if code == 200:
            acq_status = _finish(client, acc["job_id"])
            acq_ok = acq_status.get("state") == "complete"
            record("acquire completed", acq_ok, acq_status)

        image_path = state / "evidence" / "carve-smoke" / "image.raw"
        code, carve_acc = client.request(
            "/jobs/carve",
            method="POST",
            body={
                "image": str(image_path),
                "undelete": False,
                "carve_signatures": True,
                "pii_triage": False,
                "media_map": True,
            },
        )
        record(
            "carve accepted - the signature table loaded from the packaged "
            "location without EvidenceIntegrityError",
            code == 200,
            carve_acc,
        )
        if code == 200:
            carve_status = _finish(client, carve_acc["job_id"])
            record(
                "carve completed",
                carve_status.get("state") == "complete",
                carve_status.get("error"),
            )
            result = carve_status.get("result") or {}
            record("media map present", result.get("media_map") is not None)
            candidates = result.get("candidates") or []
            rows = [_row_for(item, candidates) for item in truth]
            for row in rows:
                ok, detail = _grade(row)
                record(f"{row['label']} (offset {row['offset']})", ok, detail)

        code, _ = client.request("/app/quit", method="POST")
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            pass
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:  # pragma: no cover
                process.kill()
        log.close()

    return {
        "executable": str(executable),
        "seed": SEED,
        "image_sha256": __import__("hashlib").sha256(image_bytes).hexdigest(),
        "rows": rows,
        "checks": checks,
        "result": "FAIL" if any(c["result"] == "FAIL" for c in checks) else "PASS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("executable", type=Path)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument(
        "--arg", action="append", default=[], help="extra argument for the executable"
    )
    args = parser.parse_args(argv)

    if not args.executable.exists():
        print(f"no such executable: {args.executable}", file=sys.stderr)
        return 2

    evidence = run(args.executable, args.arg)
    if args.out:
        args.out.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    for check in evidence["checks"]:
        print(f"  {check['result']:<5} {check['check']} {check['detail']}")
    print(evidence["result"])
    return 0 if evidence["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
