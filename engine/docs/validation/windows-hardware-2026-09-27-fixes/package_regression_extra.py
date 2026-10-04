"""Non-destructive package-regression extension for ba66fbe.

Covers what scripts/package_smoke.py does not exercise: an explicit
trace-sweep confirmation, a real acquire+carve+media-map round trip through
the installed exe (a synthetic image, never a device), and a Destroy
attestation record. Reuses package_smoke.py's own Client and launch pattern.
Nothing here touches a device or SANCTUMREC.
"""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[0]
REPO = Path(r"C:\Projects\sanctum-forensics")
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO))

import package_smoke  # noqa: E402
import scripts.demo_fragmented as demo_fragmented  # noqa: E402

EXE = Path(os.environ["LOCALAPPDATA"]) / "Programs" / "Sanctum" / "Sanctum.exe"


def finish(client: package_smoke.Client, job_id: str, timeout_s: float = 60.0) -> dict:
    deadline = time.monotonic() + timeout_s
    status: dict = {}
    while time.monotonic() < deadline:
        code, status = client.request(f"/jobs/{job_id}")
        finished = isinstance(status, dict) and status.get("state") != "running"
        if code == 200 and finished:
            return status
        time.sleep(0.2)
    raise TimeoutError(f"job {job_id} did not finish: {status}")


def main() -> int:
    scratch = Path(tempfile.mkdtemp(prefix="sanctum-pkgreg-"))
    state = scratch / "state"
    victim = scratch / "victim"
    victim.mkdir(parents=True)
    (victim / "a.txt").write_text("trace sweep regression target")
    url_file = scratch / "session-url.txt"

    env = dict(os.environ)
    env.update(
        {
            "SANCTUM_URL_FILE": str(url_file),
            "SANCTUM_STATE_DIR": str(state),
        }
    )
    log_path = scratch / "app.log"
    log = log_path.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        [str(EXE)], env=env, stdout=log, stderr=subprocess.STDOUT, text=True
    )

    results: dict[str, object] = {}
    try:
        url = package_smoke.wait_for_url(url_file, timeout_s=60)
        base = url.split("/session/")[0]
        client = package_smoke.Client(base)
        code, health = client.request(url[len(base):])
        assert code in (200, 303), health
        code, health = client.request("/health")
        results["commit"] = health["build"]["commit"]
        assert health["build"]["commit"] == "437081ed8d740771bc77fd535fea97938ccd0d2e"

        # 1) Trace sweep, explicit
        code, accepted = client.request(
            "/jobs/erase-files",
            method="POST",
            body={
                "paths": [str(victim)],
                "dry_run": False,
                "confirm": True,
                "recursive": True,
                "sweep_traces": True,
            },
        )
        assert code == 200, accepted
        status = finish(client, accepted["job_id"])
        assert status["state"] == "complete", status
        erase_result = status.get("result") or {}
        records = erase_result.get("records") or []
        results["trace_sweep_present"] = "trace_sweep" in erase_result
        results["trace_sweep"] = erase_result.get("trace_sweep")
        results["erase_record_keys"] = sorted(records[0].keys()) if records else []

        # 2) Acquire + carve + media map, synthetic image (never a device)
        rng = random.Random(26149)
        image_bytes, manifest = demo_fragmented.build(rng)
        src = scratch / "pkgreg-source.img"
        src.write_bytes(image_bytes)
        code, acc = client.request(
            "/jobs/acquire",
            method="POST",
            body={"source": str(src), "dest": "pkgreg/image.raw"},
        )
        assert code == 200, acc
        acq_status = finish(client, acc["job_id"])
        results["acquire_state"] = acq_status["state"]
        assert acq_status["state"] == "complete", acq_status

        evidence_dir = state / "evidence"
        image_path = evidence_dir / "pkgreg" / "image.raw"
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
        assert code == 200, carve_acc
        carve_status = finish(client, carve_acc["job_id"])
        results["carve_state"] = carve_status["state"]
        results["carve_error"] = carve_status.get("error")
        carve_result = carve_status.get("result") or {}
        results["carve_result_keys"] = sorted(carve_result.keys())
        results["candidates"] = len(carve_result.get("candidates") or [])
        results["planted"] = len(manifest)
        results["media_map_present"] = carve_result.get("media_map") is not None

        # 3) Destroy attestation, metadata only, no device
        code, destroy_acc = client.request(
            "/jobs/record-destroy",
            method="POST",
            body={
                "serial": "PKGREG-TEST-0001",
                "model": "Test Media",
                "media_type": "USB",
                "technique": "SHRED",
                "reason": "package regression, ba66fbe",
                "performed_by": "package-regression-script",
                "performed_at": "2026-09-27T00:00:00Z",
            },
        )
        assert code == 200, destroy_acc
        destroy_status = finish(client, destroy_acc["job_id"])
        results["destroy_state"] = destroy_status["state"]
        code, report = client.request(
            f"/reports/{destroy_acc['job_id']}",
            method="POST",
            body={"case_id": "", "operator": "", "key_passphrase": "pkgreg passphrase"},
        )
        results["destroy_certificate_issued"] = code == 200
        code, verify = client.request(f"/reports/{destroy_acc['job_id']}/verify")
        results["destroy_certificate_verifies"] = (
            code == 200 and isinstance(verify, dict) and verify.get("passed") is True
        )

        code, _ = client.request("/app/quit", method="POST")
        results["quit_code"] = code
        try:
            proc.wait(timeout=20)
            results["exited_clean"] = True
        except subprocess.TimeoutExpired:
            results["exited_clean"] = False
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
        log.close()

    print(json.dumps(results, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
