"""The real API app over a *synthetic* helper, for the Sanitize browser run.

Usage (from the repo root, project venv): python server.py STATE_DIR PORT

Everything the browser drives is the real server: the real routes, the real
workflow state machine, the real authorization store and the real erase
engine's request path. Only the privileged helper is replaced, by the same
recording double the API test suite uses, so ``run_erase`` answers from a
fixture and no device is opened. No physical device is touched, enumerated or
probed: the device list is the double's three synthetic rows.

Two flag files under STATE_DIR let the browser driver change the "hardware"
between steps, which is how a refusal is provoked through the real UI:

    mounted.flag   /dev/sdz reports a mounted filesystem
    serial.flag    /dev/sdz reports a different serial

    boom.flag      the helper probe raises an unexpected RuntimeError (HTTP 500)
    seam.flag      a real run_erase is refused the way the helper's write-seam
                   check refuses one (WorkflowGateRefused), before any write
    readback.flag  a real run_erase completes but its read-back verification
                   FAILED (added for the 2026-09-25 remediation run)

A ``calls.log`` records every helper call, so the driver can prove that a
refusal never reached ``run_erase`` with ``dry_run=false``.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

import uvicorn
from api.deps import AppServices
from api.jobs import JobRegistry
from api.main import create_app
from helper.rpc import RpcError
from tests.api import conftest
from tests.api.conftest import RecordingHelper

state = Path(sys.argv[1])
port = int(sys.argv[2])
state.mkdir(parents=True, exist_ok=True)


def _synthetic_platform() -> Any:
    """A Linux adapter that reads the double's devices, never the host's.

    The same patching tests/helper/test_enumerate_preview.py uses, so the rows
    carry the real ``erase_preview``, ``normalized`` and ``assessment`` the
    screens render, computed by the real core over synthetic ``Device`` records.
    """
    from core.device import capabilities as caps_mod
    from core.device import enumerate as enum_mod
    from core.device import hidden_areas as hidden_mod
    from core.models import (
        Device,
        DeviceCapabilities,
        HiddenAreaReport,
        SanitizationLevel,
    )
    from core.platform import linux as linux_mod

    def devices() -> list[Device]:
        out = []
        for row in conftest.FAKE_DEVICES[:2]:
            fields = {**row["device"]}
            if fields["path"] == "/dev/sdz":
                if (state / "mounted.flag").exists():
                    fields["mounted_at"] = ["/run/media/browser/SANCTUMREC-FIXTURE"]
                if (state / "serial.flag").exists():
                    fields["serial"] = "SWAPPED-DISK-9"
            out.append(Device.model_validate(fields))
        return out

    def probe(device: Device) -> DeviceCapabilities:
        raw = next(
            r for r in conftest.FAKE_DEVICES if r["device"]["path"] == device.path
        )
        data = {**raw["capabilities"]}
        data["achievable_levels"] = {
            SanitizationLevel(x) for x in data["achievable_levels"]
        }
        return DeviceCapabilities.model_validate(data)

    enum_mod.enumerate_devices = lambda *a, **k: devices()  # type: ignore[assignment]
    caps_mod.probe = probe  # type: ignore[assignment]
    hidden_mod.detect_hidden_areas = lambda device: HiddenAreaReport(  # type: ignore[assignment]
        hpa_present=False,
        dco_present=False,
        native_max_sectors=1,
        accessible_sectors=1,
        hidden_bytes=0,
    )
    adapter = linux_mod.LinuxAdapter(
        helper="socket",
        helper_basis="synthetic double standing in for the helper socket",
    )
    adapter._partitions = lambda probe: {}  # type: ignore[method-assign]
    adapter._removable = lambda probe, device: None  # type: ignore[method-assign]
    return adapter


ADAPTER = _synthetic_platform()


class FlagHelper(RecordingHelper):
    def _row(self, path: str) -> dict[str, Any]:
        row = copy.deepcopy(super()._row(path))
        if path == "/dev/sdz":
            if (state / "mounted.flag").exists():
                row["device"]["mounted_at"] = ["/run/media/browser/SANCTUMREC-FIXTURE"]
            if (state / "serial.flag").exists():
                row["device"]["serial"] = "SWAPPED-DISK-9"
        return row

    def call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "probe_capabilities" and (state / "boom.flag").exists():
            raise RuntimeError("synthetic unexpected failure at /var/lib/secret/path")
        seam = (
            method == "run_erase"
            and params.get("dry_run") is False
            and (state / "seam.flag").exists()
        )
        with (state / "calls.log").open("a", encoding="utf-8") as log:
            entry = {"method": method, "dry_run": params.get("dry_run")}
            log.write(json.dumps({**entry, "refused_at_seam": seam}) + "\n")
        if seam:
            raise RpcError(
                "REFUSED at the write seam: model changed since the backup and "
                "approval. Nothing was erased.",
                remediation="Open a new workflow.",
                kind="WorkflowGateRefused",
            )
        if method == "enumerate_devices":
            return {"devices": ADAPTER.device_rows()}
        if (
            method == "run_erase"
            and params.get("dry_run") is False
            and (state / "readback.flag").exists()
        ):
            answer = super().call(method, params)
            answer["result"]["verification"].update(
                passed=False, failed_offsets=[4096, 1_048_576]
            )
            return answer
        if method == "platform_status":
            from core.platform import platform_status

            return platform_status(ADAPTER).model_dump(mode="json")
        if method == "assess_device":
            for row in ADAPTER.device_rows():
                if row["normalized"]["id"] == params.get("path"):
                    return {
                        "normalized": row["normalized"],
                        "assessment": row["assessment"],
                    }
            raise RpcError(
                "No such device.", remediation="Rescan.", kind="DeviceVanished"
            )
        return super().call(method, params)


services = AppServices(
    registry=JobRegistry(),
    helper=FlagHelper(),
    state_dir=state / "app",
    key_dir=state / "keys",
)
services.prepare()
with (services.evidence_dir / "backup.img").open("wb") as handle:
    handle.truncate(64 * 1024 * 1024)
app = create_app(
    services=services, serve_ui=True, session_token="browsercheck-token-0002"
)
uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
