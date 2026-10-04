"""``GET /platform`` - which OS, which privileges, and what can be done here.

The matrix is computed by the helper, on the privileged side, from this host's
platform adapter; see :mod:`core.platform`. Nothing on the page it feeds is a
hardcoded checkmark: every row carries the probe or code path that set it.

``/platform/devices/{device_id}/assessment`` re-reads one device and assesses
it now. The Sanitize screen calls it before showing the confirmation, so the
target an operator confirms is the one the OS reports at that moment rather
than the row the device list loaded minutes earlier.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from api.deps import AppServices
from api.routes.common import get_services, sanctum_error_response

__all__ = ["router"]

router = APIRouter(tags=["platform"])


@router.get("/platform")
def platform(services: AppServices = Depends(get_services)) -> dict[str, Any]:
    """Platform, privilege, operation matrix, media classes, filesystems."""
    from helper.rpc import RpcError

    try:
        answer = services.helper.call("platform_status", {})
    except RpcError as exc:
        raise sanctum_error_response(
            exc.kind or "PlatformUnsupported", exc.message, exc.remediation
        ) from exc
    except OSError as exc:
        raise sanctum_error_response(
            "PlatformUnsupported",
            f"The privileged helper could not be reached: {exc}",
            "Start the helper daemon, or unset SANCTUM_HELPER_SOCKET to run "
            "in-process.",
        ) from exc
    return {**answer, "limitations": list(services.limitations)}


@router.get("/platform/devices/{device_id:path}/assessment")
def assessment(
    device_id: str, services: AppServices = Depends(get_services)
) -> dict[str, Any]:
    """Re-read ``device_id`` from the OS and return its current assessment."""
    from helper.rpc import RpcError

    try:
        return services.helper.call("assess_device", {"path": device_id})
    except RpcError as exc:
        raise sanctum_error_response(
            exc.kind or "DeviceVanished", exc.message, exc.remediation
        ) from exc
    except OSError as exc:
        raise sanctum_error_response(
            "PlatformUnsupported",
            f"The privileged helper could not be reached: {exc}",
            "Start the helper daemon and rescan.",
        ) from exc
