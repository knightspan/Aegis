"""``GET /devices`` - enumerate, probe capability, probe hidden areas.

One endpoint and one helper round trip for all three, because the device screen
needs all three and a per-device probe would mean N+1 socket calls for a list
that refreshes.

A probe that fails does **not** fail the request. A USB bridge that blocks ATA
pass-through is the common case, not an error, and a device list that returned
500 because one disk could not be interrogated would be useless on exactly the
hardware an operator most needs to look at. The per-device error travels in the
row instead, and the UI renders it as a limitation on that device.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import Field

from api.deps import AppServices
from api.identity import resolve as resolve_identity
from api.routes.common import get_services, sanctum_error_response
from api.routes.models import DestructiveRequest

__all__ = ["router"]

router = APIRouter(tags=["devices"])


@router.get("/devices")
def list_devices(
    include_virtual: bool = False,
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    """Every block device, with its capability and hidden-area reports.

    ``include_virtual`` adds loop and ram devices, which the carving testkit
    uses and which are never erase targets.
    """
    from helper.rpc import RpcError

    try:
        answer = services.helper.call(
            "enumerate_devices", {"include_virtual": include_virtual}
        )
    except RpcError as exc:
        # Reported as an empty list plus the reason rather than a 500: the UI
        # shows "no devices, because <reason>", which is actionable, where a
        # 500 is not.
        return {
            "devices": [],
            "limitations": [
                *services.limitations,
                f"Device enumeration failed: {exc.message} {exc.remediation}".strip(),
            ],
        }
    except OSError as exc:
        return {
            "devices": [],
            "limitations": [
                *services.limitations,
                f"The privileged helper could not be reached ({exc}). Start the "
                "helper daemon, or set SANCTUM_HELPER_SOCKET to its socket path.",
            ],
        }

    return {"devices": answer.get("devices", []), "limitations": services.limitations}


class PrepareDeviceRequest(DestructiveRequest):
    """Body for ``POST /devices/prepare``."""

    path: str = Field(max_length=256)
    #: The device serial, typed by hand. Checked against the helper's own read.
    typed_serial: str = Field(default="", max_length=128)


@router.post("/devices/prepare")
def prepare_device(
    body: PrepareDeviceRequest,
    services: AppServices = Depends(get_services),
) -> dict[str, Any]:
    """Unmount (macOS) or take offline (Windows) a disk, as an explicit step.

    Separate from every erase on purpose: an erase refuses a mounted device and
    never unmounts one itself. System and internal disks are refused by the
    adapter. Always a real unmount or offline; it needs the typed serial.
    """
    from helper.rpc import RpcError

    try:
        return services.helper.call(
            "prepare_device",
            {
                "path": body.path,
                "typed_serial": body.typed_serial,
                "ledger_root": str(services.ledger_root),
                "tool_version": services.tool_version,
                "actor": resolve_identity(services).actor,
            },
        )
    except RpcError as exc:
        raise sanctum_error_response(
            exc.kind or "PlatformUnsupported", exc.message, exc.remediation
        ) from exc
