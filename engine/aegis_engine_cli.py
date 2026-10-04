"""AEGIS Engine Bridge: the desktop's process interface to the AEGIS Variant engine.

AEGIS integration module (2026-10-03). Replaces the earlier fail-closed facade.
Part of the AEGIS Variant tree; same license and notices as the rest of it.
See docs/INTEGRATION_PROVENANCE.md in the AEGIS bundle.

Every subcommand calls the engine's own functions - ``core.carve.acquire``,
``api.carve_job.carve_generator``, ``core.platform.windows.WindowsAdapter``,
``core.erase.traces``, ``core.ledger.chain``, ``core.report`` - and reports what
they returned. Nothing here re-implements an algorithm, and nothing here
reports a result an engine call did not produce.

Protocol (version 1)
--------------------
stdout carries one JSON object per line and nothing else. Every object has
``AEGIS_EVENT``:

* ``HELLO``    first line: protocol, bridge version, command, operation id.
* ``PROGRESS`` phase, pct (0-100), bytes_done, bytes_total, throughput, eta, message.
* ``LOG``      level, message.
* ``RESULT``   last line: status, command, operation_id, result, warnings, error.

``status`` is one of SUCCESS, SUCCESS_WITH_WARNINGS, FAILED, BLOCKED,
UNSUPPORTED, UNAVAILABLE, CANCELLED. A result too large for one line is written
to ``<state>/jobs/<job>.json`` and named by ``result_file``.

``--cancel-file PATH``: when that file appears, the running engine generator is
closed at its next yield, which is the engine's own cancellation path: it
ledgers what was done before the cancel.

Exit codes: 0 success, 1 failed, 2 blocked, 3 unsupported/unavailable,
4 cancelled, 5 usage.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import threading
import time
import traceback
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

PROTOCOL = 1
BRIDGE_VERSION = "1.0.0"
TOOL_VERSION = "aegis-engine/1.0.0 (sanctum-forensics 0.1.2)"

# The protocol channel. Anything else that writes to "stdout" (a library print,
# a log handler) is redirected to stderr so it can never corrupt a JSON line.
_PROTOCOL_OUT = sys.stdout
sys.stdout = sys.stderr

ENGINE_ROOT = Path(__file__).resolve().parent
if str(ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(ENGINE_ROOT))


def _configure_logging() -> None:
    import structlog

    level = logging.DEBUG if os.environ.get("AEGIS_ENGINE_DEBUG") else logging.INFO
    structlog.configure(
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        wrapper_class=structlog.make_filtering_bound_logger(level),
    )


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

_OUT_LOCK = threading.Lock()
CANCEL = threading.Event()


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if isinstance(value, bytes):
        return value.hex()
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        return dump(mode="json")
    return str(value)


def emit(event: str, **fields: Any) -> None:
    payload = {"AEGIS_EVENT": event, **fields}
    line = json.dumps(payload, default=_json_default, ensure_ascii=True)
    with _OUT_LOCK:
        _PROTOCOL_OUT.write(line + "\n")
        _PROTOCOL_OUT.flush()


class Cancelled(Exception):
    """The operator cancelled; the engine generator has been closed."""


class Refused(Exception):
    """An AEGIS-level gate refused the operation before the engine was called."""

    def __init__(self, status: str, kind: str, message: str, remediation: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.kind = kind
        self.message = message
        self.remediation = remediation


_CANCEL_FILE: str = ""
_CANCEL_CHECKED = [0.0]


def cancel_requested() -> bool:
    """True once the desktop created the cancel flag file (or CANCEL was set).

    A flag file rather than a stdin reader: on Windows a thread blocked in a
    synchronous read of the stdin pipe deadlocks any DLL that queries the
    standard handles while loading (numpy, OpenCV), so stdin is never read.
    """
    if CANCEL.is_set():
        return True
    now = time.monotonic()
    if _CANCEL_FILE and now - _CANCEL_CHECKED[0] > 0.2:
        _CANCEL_CHECKED[0] = now
        if os.path.exists(_CANCEL_FILE):
            CANCEL.set()
            emit("LOG", level="WARNING", message="Cancellation requested by the operator.")
    return CANCEL.is_set()


def progress_of(item: Any) -> dict[str, Any] | None:
    data = item.model_dump(mode="json") if hasattr(item, "model_dump") else item
    if not isinstance(data, dict) or "pct_bp" not in data:
        return None
    return {
        "phase": str(data.get("phase") or ""),
        "pct": round(int(data.get("pct_bp") or 0) / 100.0, 2),
        "bytes_done": int(data.get("bytes_done") or 0),
        "bytes_total": int(data.get("bytes_total") or 0),
        "throughput": int(data.get("throughput_bytes_per_sec") or 0),
        "eta": int(data.get("eta_seconds") or 0),
        "message": str(data.get("message") or ""),
    }


def drive(generator: Any, on_record: Callable[[Any], None] | None = None) -> Any:
    """Run an engine generator to completion, streaming progress, honouring CANCEL."""
    last = 0.0
    try:
        while True:
            if cancel_requested():
                generator.close()
                raise Cancelled("Cancelled by the operator. The engine recorded what it had done.")
            try:
                item = next(generator)
            except StopIteration as stop:
                return stop.value
            except GeneratorExit as exc:
                # A cancel raised from inside a long single pass (see _scan_progress):
                # the engine has already recorded what it did before it stopped.
                raise Cancelled("Cancelled by the operator during the scan. The engine recorded what it had done.") from exc
            if on_record is not None:
                on_record(item)
            prog = progress_of(item)
            now = time.monotonic()
            if prog is not None and (now - last > 0.2 or prog["pct"] >= 100):
                emit("PROGRESS", **prog)
                last = now
    except GeneratorExit:  # pragma: no cover - defensive
        raise


# ---------------------------------------------------------------------------
# State: per-case directory, jobs, ledger, keys
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(UTC)


def _job_id(kind: str) -> str:
    return f"{kind}-{_now().strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:8]}"


class Context:
    def __init__(self, args: argparse.Namespace) -> None:
        local = os.environ.get("LOCALAPPDATA") or str(Path.home())
        roaming = os.environ.get("APPDATA") or str(Path.home())
        self.state = Path(args.state) if getattr(args, "state", None) else Path(local) / "AEGIS" / "engine-state"
        self.keys = Path(args.keys) if getattr(args, "keys", None) else Path(roaming) / "AEGIS" / "keys"
        self.operator = getattr(args, "operator", None) or os.environ.get("USERNAME") or "aegis"
        self.case_id = getattr(args, "case_id", None) or ""
        self.state.mkdir(parents=True, exist_ok=True)
        (self.state / "jobs").mkdir(exist_ok=True)
        self._ledger: Any = None
        self.current_job = ""

    # -- jobs ------------------------------------------------------------

    def job_path(self, job_id: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", job_id):
            raise Refused("BLOCKED", "InvalidJobId", f"{job_id!r} is not an AEGIS job id.")
        return self.state / "jobs" / f"{job_id}.json"

    def save_job(self, job: dict[str, Any]) -> Path:
        self.current_job = str(job["job_id"])
        path = self.job_path(job["job_id"])
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(job, default=_json_default, indent=1), encoding="utf-8")
        os.replace(tmp, path)
        return path

    def load_job(self, job_id: str) -> dict[str, Any]:
        path = self.job_path(job_id)
        if not path.is_file():
            raise Refused("FAILED", "JobNotKnown", f"No AEGIS job {job_id} is recorded in {self.state}.")
        return json.loads(path.read_text(encoding="utf-8"))

    # -- keys and ledger ---------------------------------------------------

    def passphrase(self) -> str:
        env = os.environ.get("SANCTUM_KEY_PASSPHRASE")
        if env:
            return env
        blob = self.keys / "aegis-key-passphrase.dpapi"
        if blob.is_file():
            return _dpapi_unprotect(blob.read_bytes()).decode("utf-8")
        self.keys.mkdir(parents=True, exist_ok=True)
        secret = uuid.uuid4().hex + uuid.uuid4().hex
        blob.write_bytes(_dpapi_protect(secret.encode("utf-8")))
        return secret

    def signing_key(self) -> Any:
        from core.report.sign import load_or_create_key

        return load_or_create_key(self.keys, self.passphrase())

    def fingerprint(self) -> str:
        from core.report.sign import fingerprint, public_key_of

        return fingerprint(public_key_of(self.signing_key()))

    def ledger(self) -> Any:
        if self._ledger is None:
            from core.ledger.chain import Ledger

            self._ledger = Ledger(
                self.state / "ledger",
                tool_version=TOOL_VERSION,
                pubkey_fingerprint=self.fingerprint(),
            )
        return self._ledger

    def ledger_params(self) -> dict[str, Any]:
        return {
            "ledger_root": str(self.state / "ledger"),
            "tool_version": TOOL_VERSION,
            "pubkey_fingerprint": self.fingerprint(),
        }


# Windows DPAPI: the signing-key passphrase is bound to this Windows account.
class _Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data: bytes, protect: bool) -> bytes:
    if sys.platform != "win32":
        raise Refused("UNSUPPORTED", "PlatformUnsupported",
                      "DPAPI key protection is Windows-only; set SANCTUM_KEY_PASSPHRASE.")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    buffer = ctypes.create_string_buffer(data, len(data))
    blob_in = _Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    blob_out = _Blob()
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    ok = fn(ctypes.byref(blob_in), "AEGIS signing key" if protect else None, None, None, None,
            0x1, ctypes.byref(blob_out))
    if not ok:
        raise OSError(ctypes.GetLastError(), "DPAPI call failed")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def _dpapi_protect(data: bytes) -> bytes:
    return _dpapi(data, True)


def _dpapi_unprotect(data: bytes) -> bytes:
    return _dpapi(data, False)


# ---------------------------------------------------------------------------
# Host facts
# ---------------------------------------------------------------------------


def _elevated() -> bool:
    if sys.platform != "win32":
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def _powershell(script: str, timeout: float = 60.0) -> str:
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True, text=True, timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return proc.stdout


def _disk_geometry() -> dict[int, dict[str, Any]]:
    """Logical/physical sector size and bus per disk number, from the Storage module."""
    try:
        out = _powershell(
            "Get-Disk | Select-Object Number,LogicalSectorSize,PhysicalSectorSize,BusType,"
            "IsBoot,IsSystem,IsOffline,PartitionStyle | ConvertTo-Json -Compress"
        )
        rows = json.loads(out) if out.strip() else []
        if isinstance(rows, dict):
            rows = [rows]
        return {int(r["Number"]): r for r in rows if r.get("Number") is not None}
    except (OSError, ValueError, subprocess.SubprocessError):
        return {}


def _disk_of_path(path: Path) -> int | None:
    """The physical disk number holding ``path``'s volume (drive letter only)."""
    drive = os.path.splitdrive(str(path.resolve()))[0]
    if len(drive) != 2 or drive[1] != ":":
        return None
    try:
        out = _powershell(f"(Get-Partition -DriveLetter {drive[0]} -ErrorAction Stop).DiskNumber")
        return int(out.strip()) if out.strip().isdigit() else None
    except (OSError, subprocess.SubprocessError):
        return None


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_health(args: argparse.Namespace, ctx: Context) -> dict[str, Any]:
    modules: dict[str, str] = {}
    for name in ("pytsk3", "pyewf", "blake3", "ahocorasick", "cryptography", "reportlab", "pikepdf",
                 "PIL", "construct", "pydantic", "cv2"):
        try:
            mod = __import__(name)
            version = getattr(mod, "__version__", "") or getattr(mod, "TSK_VERSION_STR", "")
            if name == "pyewf":
                version = mod.get_version()
            modules[name] = str(version or "available")
        except Exception as exc:  # noqa: BLE001 - an import failure of any kind is the answer
            modules[name] = f"UNAVAILABLE: {exc}"
    from core.carve import acquire as acq
    from core.carve import ewf_ctypes

    e01 = acq.e01_write_supported()
    sr = {}
    try:
        import cv2

        sr["dnn_superres"] = hasattr(cv2, "dnn_superres")
    except ImportError:
        sr["dnn_superres"] = False
    models = ENGINE_ROOT / "models"
    sr["models"] = sorted(p.name for p in models.glob("*.pb")) if models.is_dir() else []
    return {
        "protocol": PROTOCOL,
        "bridge_version": BRIDGE_VERSION,
        "tool_version": TOOL_VERSION,
        "python": sys.version.split()[0],
        "executable": sys.executable,
        "engine_root": str(ENGINE_ROOT),
        "platform": platform.platform(),
        "elevated": _elevated(),
        "modules": modules,
        "e01_write": {"supported": e01, "backend": acq._e01_backend() if e01 else "",
                      "writer_library": ewf_ctypes.library_version(),
                      "reason": "" if e01 else ewf_ctypes.unavailable_reason()},
        "hashes": ["SHA-256", "BLAKE3"],
        "enhancement": sr,
        "state_dir": str(ctx.state),
        "key_dir": str(ctx.keys),
        "capabilities": ["devices", "acquire", "verify-image", "recover", "prepare-device",
                         "sanitize-device", "traces", "thumbcache", "ledger-verify", "ledger-list",
                         "record", "report", "verify-report", "enhance"],
    }


#: AEGIS policy (operator directive, 2026-10-03): device sanitization is allowed
#: only on removable media attached over USB or an SD/MMC reader. Every internal
#: drive - SSD, NVMe, SATA, SAS, RAID, HDD - is refused, system disk or not, and
#: an unknown bus is refused (fail closed).
REMOVABLE_BUSES = frozenset({"usb", "sd", "mmc"})


def sanitize_policy_refusal(device: Any, bus_type: str) -> str:
    """Why AEGIS refuses to sanitize ``device``, or "" if the policy allows it."""
    bus = (bus_type or "").strip().lower()
    iface = str(getattr(device, "interface", "") or "").strip().lower()
    if getattr(device, "system_device", False):
        return "System or boot disk: " + " ".join(getattr(device, "system_reasons", []) or [])
    if getattr(device, "internal", None) is True:
        return "Internal drive: AEGIS never sanitizes an internal drive."
    if iface not in REMOVABLE_BUSES and bus not in REMOVABLE_BUSES:
        return (f"Internal or unidentified drive (bus {bus_type or 'unknown'}, interface {iface or 'unknown'}): "
                "AEGIS sanitizes only removable USB or SD/MMC media and never an internal SSD or disk.")
    if bus and iface and (bus in REMOVABLE_BUSES) != (iface in REMOVABLE_BUSES):
        return f"Bus type {bus_type!r} and interface {iface!r} disagree, so the drive cannot be confirmed removable."
    return ""


def _bus_of(device_id: str) -> str:
    match = re.search(r"(\d+)$", device_id or "")
    if not match:
        return ""
    return str(_disk_geometry().get(int(match.group(1)), {}).get("BusType") or "")


def _device_rows(include_virtual: bool = False) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    from core.platform.windows import WindowsAdapter

    adapter = WindowsAdapter()
    devices = adapter.enumerate_devices(include_virtual=include_virtual)
    geometry = _disk_geometry()
    elevated = _elevated()
    rows: list[dict[str, Any]] = []
    for device in devices:
        row = device.model_dump(mode="json")
        number = None
        match = re.search(r"(\d+)$", device.id)
        if match:
            number = int(match.group(1))
        geo = geometry.get(number, {}) if number is not None else {}
        row["number"] = number
        row["logical_sector_size"] = int(geo.get("LogicalSectorSize") or 0)
        row["physical_sector_size"] = int(geo.get("PhysicalSectorSize") or 0)
        row["bus_type"] = str(geo.get("BusType") or "")
        row["is_boot"] = bool(geo.get("IsBoot")) if geo else None
        row["is_system"] = bool(geo.get("IsSystem")) if geo else None
        row["is_offline"] = bool(geo.get("IsOffline")) if geo else None
        row["partition_style"] = str(geo.get("PartitionStyle") or "")
        try:
            row["assessment"] = adapter.assess_device(device).model_dump(mode="json")
        except Exception as exc:  # noqa: BLE001 - reported per device, never hidden
            row["assessment"] = {"status": "UNAVAILABLE", "headline": "ASSESSMENT FAILED", "reason": str(exc)}
        # AEGIS acquisition policy: read-only imaging of any non-system disk with
        # a bound identity; the live OS disk is refused (an image of a running
        # system disk is internally inconsistent).
        if device.system_device:
            acq = {"eligible": False, "status": "BLOCKED",
                   "reason": "Live system/boot disk: " + " ".join(device.system_reasons)}
        elif not device.serial.strip():
            acq = {"eligible": False, "status": "BLOCKED",
                   "reason": "The disk reports no serial number, so its identity cannot be bound."}
        elif not elevated:
            acq = {"eligible": False, "status": "REQUIRES PRIVILEGE",
                   "reason": "Raw physical-disk reads need an elevated process. Start AEGIS with Run as administrator."}
        else:
            acq = {"eligible": True, "status": "READY", "reason": "Identity bound; read-only open available."}
        row["acquisition"] = acq
        refusal = sanitize_policy_refusal(device, row["bus_type"])
        row["sanitization"] = {"eligible": not refusal,
                               "status": "ALLOWED" if not refusal else ("SYSTEM DISK" if device.system_device else "INTERNAL DRIVE"),
                               "reason": refusal or "Removable USB/SD media: device sanitization permitted by AEGIS policy."}
        rows.append(row)
    discovery = {
        "tool": "Windows Storage module (Get-Disk, Get-PhysicalDisk, Get-Partition, Get-Volume) via the AEGIS Variant WindowsAdapter",
        "elevated": elevated,
        "privilege": adapter.privilege_state().model_dump(mode="json"),
    }
    return rows, discovery


def cmd_devices(args: argparse.Namespace, ctx: Context) -> dict[str, Any]:
    rows, discovery = _device_rows(include_virtual=args.include_virtual)
    return {"devices": rows, "discovery": discovery, "count": len(rows)}


def _verify_progress(message: str) -> Callable[[int, int], None]:
    """PROGRESS for the read-back verification (otherwise a silent pass over the whole image)."""
    started = time.monotonic()
    last_emit = [0.0]

    def report(done: int, total: int) -> None:
        if cancel_requested():
            raise Cancelled("Verification cancelled by the operator. The image was written but is NOT verified.")
        now = time.monotonic()
        if total <= 0 or (now - last_emit[0] < 0.5 and done < total):
            return
        last_emit[0] = now
        rate = int(done / max(now - started, 1e-6))
        emit("PROGRESS", phase="verify", pct=round(100.0 * done / total, 1), bytes_done=done, bytes_total=total,
             throughput=rate, eta=int((total - done) / rate) if rate > 0 else 0, message=message)

    return report


def cmd_acquire(args: argparse.Namespace, ctx: Context) -> dict[str, Any]:
    from core.carve.acquire import AcquireOptions, acquire, is_win32_device_path, verify_image

    source = args.source
    dest = Path(args.dest)
    fmt = args.format.lower()
    if fmt not in ("raw", "e01"):
        raise Refused("BLOCKED", "InvalidFormat", f"Unsupported image format {args.format}.")
    if fmt == "e01" and dest.suffix.lower() != ".e01":
        dest = dest.with_suffix(".E01")
    if not dest.parent.is_dir():
        raise Refused("BLOCKED", "DestinationUnavailable", f"Destination folder {dest.parent} does not exist.")
    device = is_win32_device_path(source)
    size_hint = int(args.expected_size or 0)
    if device:
        if not _elevated():
            raise Refused("BLOCKED", "RequiresPrivilege",
                          "Reading a physical disk needs an elevated process. Nothing was read.",
                          "Close AEGIS and start it with Run as administrator.")
        if not args.expected_serial:
            raise Refused("BLOCKED", "IdentityUnbound",
                          "A physical-disk acquisition needs the selected disk's serial so the open handle can be bound to it.")
        source_disk = int(re.search(r"(\d+)$", source).group(1))  # type: ignore[union-attr]
        dest_disk = _disk_of_path(dest.parent)
        if dest_disk is not None and dest_disk == source_disk:
            raise Refused("BLOCKED", "DestinationOnSource",
                          f"The destination {dest.parent} is on the source disk {source}. "
                          "Writing an image onto the disk being imaged would alter the evidence.")
        rows, _ = _device_rows()
        match = next((r for r in rows if r.get("number") == source_disk), None)
        if match is None:
            raise Refused("BLOCKED", "DeviceVanished", f"{source} is no longer present.")
        if match.get("system_device"):
            raise Refused("BLOCKED", "SystemDiskRefused",
                          f"{source} is the live system/boot disk; AEGIS does not image it from the running OS.")
        if (match.get("serial") or "").strip() != args.expected_serial.strip():
            raise Refused("BLOCKED", "IdentityMismatch",
                          f"{source} now reports serial {match.get('serial')!r}, not the selected {args.expected_serial!r}. Nothing was read.")
        size_hint = int(match.get("capacity_bytes") or size_hint)
    else:
        if not Path(source).is_file():
            raise Refused("BLOCKED", "SourceUnavailable", f"Source {source} does not exist.")
        size_hint = Path(source).stat().st_size
    try:
        free = shutil.disk_usage(dest.parent).free
        if size_hint and free < size_hint:
            raise Refused("BLOCKED", "InsufficientSpace",
                          f"{dest.parent} has {free} bytes free; the source is {size_hint} bytes.")
    except OSError as exc:
        raise Refused("BLOCKED", "DestinationUnavailable", f"Destination capacity unreadable: {exc}") from exc

    job_id = args.job_id or _job_id("acquire")
    sector = int(args.sector_size or 512)
    if fmt == "e01" and size_hint % sector:
        raise Refused("BLOCKED", "E01NeedsWholeSectors",
                      f"The source is {size_hint} bytes, not a whole number of {sector}-byte sectors. An E01 stores whole "
                      "sectors, so the last partial sector would be lost and the image would not verify. Nothing was written.",
                      "Acquire this source to RAW, which preserves every byte.")
    options = AcquireOptions(
        sector_size=sector,
        block_bytes=max(sector, (1 << 20) // sector * sector),
        operator=ctx.operator,
        case_number=ctx.case_id,
        evidence_number=args.evidence_number or "",
        examiner=args.examiner or ctx.operator,
        description=args.description or "",
        notes=args.notes or "",
        expected_serial=args.expected_serial or "",
        expected_size=int(args.expected_size or 0),
        compression="fast",
    )
    ledger = ctx.ledger()
    job = {"job_id": job_id, "kind": "acquire", "case_id": ctx.case_id, "operator": ctx.operator,
           "started_at": _now(), "status": "RUNNING",
           "params": {"source": source, "dest": str(dest), "format": fmt, "expected_serial": args.expected_serial,
                      "expected_size": args.expected_size, "evidence_number": args.evidence_number,
                      "device_model": args.device_model, "sector_size": sector}}
    ctx.save_job(job)
    record = drive(acquire(source, dest, fmt=fmt, options=options, ledger=ledger, job_id=job_id))
    message = "re-reading the image to verify SHA-256 and BLAKE3"
    emit("PROGRESS", phase="verify", pct=0.0, bytes_done=0, bytes_total=record.bytes_read,
         throughput=0, eta=0, message=message)
    integrity = verify_image(dest, record, progress=_verify_progress(message))
    ledger.append(actor=ctx.operator, operation="aegis.acquire.verify",
                  params={"job_id": job_id, "case_id": ctx.case_id, "image": str(dest)},
                  result=integrity.model_dump(mode="json"))
    result = {
        "record": record.model_dump(mode="json"),
        "verification": integrity.model_dump(mode="json"),
        "image_path": str(dest),
        "segments": record.source.segments or [str(dest)],
        "bad_sector_count": sum(int(getattr(b, "count", 0) or 0) for b in record.bad_sectors),
    }
    job.update(status="SUCCESS" if integrity.passed else "FAILED", finished_at=_now(), result=result)
    ctx.save_job(job)
    if not integrity.passed:
        raise Refused("FAILED", "VerificationMismatch",
                      "The image does not match its acquisition hashes on read-back.")
    warnings = list(record.limitations)
    if record.bad_sectors:
        warnings.insert(0, f"{len(record.bad_sectors)} unreadable range(s) were filled and recorded.")
    return {"job_id": job_id, **result, "_warnings": warnings}


def cmd_verify_image(args: argparse.Namespace, ctx: Context) -> dict[str, Any]:
    from core.carve.acquire import verify_image
    from core.models import AcquisitionRecord

    job = ctx.load_job(args.job_id)
    record = AcquisitionRecord.model_validate(job["result"]["record"])
    image = Path(job["result"]["image_path"])
    if not image.exists():
        raise Refused("FAILED", "ImageMissing", f"{image} no longer exists.")
    integrity = verify_image(image, record, progress=_verify_progress("re-reading the image to verify SHA-256 and BLAKE3"))
    ctx.ledger().append(actor=ctx.operator, operation="aegis.acquire.reverify",
                        params={"job_id": args.job_id, "case_id": job.get("case_id", ""), "image": str(image)},
                        result=integrity.model_dump(mode="json"))
    if not integrity.passed:
        raise Refused("FAILED", "VerificationMismatch",
                      f"{image} no longer matches its acquisition record (chunks {integrity.mismatched_chunks[:10]}).")
    return {"job_id": args.job_id, "verification": integrity.model_dump(mode="json")}


def cmd_recover(args: argparse.Namespace, ctx: Context) -> dict[str, Any]:
    from api.carve_job import carve_generator
    from core.carve.acquire import is_win32_device_path
    from core.carve.classify import output_filename
    from core.models import CarveCandidate

    image = args.image
    # Recovery reads acquired evidence only. A physical device is acquired first
    # (Disk Imager), and the engine reads the image, never the device.
    if is_win32_device_path(image) or image.startswith("\\\\?\\") or image.startswith("//./"):
        raise Refused("BLOCKED", "EvidenceOnly",
                      "Advanced Recovery reads acquired evidence images (RAW, split RAW, E01), never a live device.",
                      "Acquire the device with Disk Imager, then recover from the verified image.")
    path = Path(image)
    if not path.is_file():
        raise Refused("BLOCKED", "SourceUnavailable", f"Evidence image {image} does not exist.")
    job_id = args.job_id or _job_id("carve")
    out_dir: Path | None = None if args.no_write else (Path(args.out) if args.out else ctx.state / "recovered" / job_id)
    if out_dir is not None and out_dir.resolve() == path.resolve().parent:
        raise Refused("BLOCKED", "OutputBesideEvidence", "Recovered files must not be written into the evidence folder.")
    work = ctx.state / "work"
    from core.carve import signature as signature_module

    last_emit = [0.0]

    def _scan_progress(done: int, total: int) -> None:
        # The signature/structure scan is one pass with no yield; report it as the
        # 30-60% band of the run and honour Cancel inside it.
        if cancel_requested():
            raise GeneratorExit
        now = time.monotonic()
        if now - last_emit[0] >= 0.5 and total > 0:
            last_emit[0] = now
            emit("PROGRESS", phase="signatures", pct=round(30 + 12 * done / total, 1), bytes_done=done,
                 bytes_total=total, throughput=0, eta=0, message=f"scanning {done * 100 // total}% of the image")

    # After the byte scan come two more silent loops: one candidate per signature hit
    # (42-48%), then a structure parse per candidate (48-60%). Without these the
    # display sat at "scanning 99%" for the whole of both on a large image.
    bands = {"candidates": (42, 6, "building candidates"), "parse": (48, 12, "parsing structures")}

    def _stage_progress(stage: str, done: int, total: int) -> None:
        if cancel_requested():
            raise GeneratorExit
        now = time.monotonic()
        if now - last_emit[0] >= 0.5 and total > 0 and stage in bands:
            last_emit[0] = now
            base, width, label = bands[stage]
            emit("PROGRESS", phase="signatures", pct=round(base + width * done / total, 1), bytes_done=0,
                 bytes_total=0, throughput=0, eta=0, message=f"{label} {done:,} / {total:,}")

    signature_module.SCAN_PROGRESS_HOOK = _scan_progress
    signature_module.STAGE_PROGRESS_HOOK = _stage_progress
    job = {"job_id": job_id, "kind": "carve", "case_id": ctx.case_id, "operator": ctx.operator,
           "started_at": _now(), "status": "RUNNING",
           "params": {"image": str(path), "out_dir": str(out_dir or ""), "undelete": not args.no_undelete,
                      "carve_signatures": not args.no_carve, "media_map": not args.no_media_map,
                      "source_job": args.source_job or ""}}
    ctx.save_job(job)
    result = drive(carve_generator(
        path, undelete=not args.no_undelete, carve_signatures=not args.no_carve, out_dir=out_dir,
        job_id=job_id, ledger=ctx.ledger(), operator=ctx.operator, pii_triage=True, work_dir=work,
        case_id=ctx.case_id, media_map=not args.no_media_map,
    ))
    written = {Path(p).name: p for p in result.get("written", [])}
    for item in result.get("candidates", []):
        try:
            name = output_filename(CarveCandidate.model_validate(item))
        except Exception:  # noqa: BLE001 - a name we cannot rebuild just has no file link
            name = ""
        item["output_path"] = written.get(name, "")
        if item["output_path"]:
            try:
                item["output_sha256"] = hashlib.sha256(Path(item["output_path"]).read_bytes()).hexdigest()
            except OSError:
                item["output_sha256"] = ""
    result["out_dir"] = str(out_dir or "")
    job.update(status="SUCCESS", finished_at=_now(), result=result)
    path_out = ctx.save_job(job)
    by_bucket: dict[str, int] = {}
    for item in result.get("candidates", []):
        by_bucket[str(item.get("bucket", ""))] = by_bucket.get(str(item.get("bucket", "")), 0) + 1
    return {"job_id": job_id, "result_file": str(path_out), "candidates": len(result.get("candidates", [])),
            "written": len(result.get("written", [])), "by_bucket": by_bucket, "out_dir": str(out_dir or ""),
            "_warnings": list(result.get("limitations", []))[:50]}


def _backup_gate(ctx: Context, serial: str, args: argparse.Namespace) -> dict[str, Any]:
    """A destructive device operation needs a verified image of that device, or a typed waiver."""
    if args.backup_job:
        job = ctx.load_job(args.backup_job)
        if job.get("kind") != "acquire" or job.get("status") != "SUCCESS":
            raise Refused("BLOCKED", "BackupNotVerified", f"{args.backup_job} is not a verified acquisition.")
        bound = str((job.get("params") or {}).get("expected_serial") or "").strip()
        if bound != serial.strip():
            raise Refused("BLOCKED", "BackupMismatch",
                          f"{args.backup_job} imaged serial {bound!r}, not this device's {serial!r}.")
        return {"backup_job": args.backup_job, "image": job["result"]["image_path"],
                "sha256": job["result"]["record"]["sha256"]}
    if args.waive_backup and args.waive_backup.strip().upper() == "NO BACKUP":
        return {"backup_job": "", "waived": True, "waiver_text": "NO BACKUP"}
    raise Refused("BLOCKED", "BackupRequired",
                  "A device sanitization needs a verified Disk Imager acquisition of the same serial, "
                  "or the operator must type the waiver NO BACKUP.",
                  "Acquire the device first, or record the waiver explicitly.")


def cmd_prepare_device(args: argparse.Namespace, ctx: Context) -> dict[str, Any]:
    from core.platform.windows import WindowsAdapter

    adapter = WindowsAdapter()
    adapter.enumerate_devices(include_virtual=True)
    device = adapter.inspect_device(args.device)
    if device.system_device:
        from core.errors import SystemDiskRefused

        raise SystemDiskRefused(f"Refusing to take {device.path} offline: it is the system or boot disk.")
    refusal = sanitize_policy_refusal(device, _bus_of(device.id))
    if refusal:
        raise Refused("BLOCKED", "InternalDriveRefused", f"Refusing to take {device.path} offline: {refusal}",
                      "Only removable USB or SD/MMC media are prepared for sanitization.")
    if not _elevated():
        raise Refused("BLOCKED", "RequiresPrivilege", "Taking a disk offline needs an elevated process.",
                      "Start AEGIS with Run as administrator.")
    outcome = adapter.prepare_device({"path": args.device, "typed_serial": args.typed_serial})
    ctx.ledger().append(actor=ctx.operator, operation="aegis.device.prepare",
                        params={"case_id": ctx.case_id, "device": args.device}, result=outcome)
    return outcome


def cmd_sanitize_device(args: argparse.Namespace, ctx: Context) -> dict[str, Any]:
    from core.platform.windows import WindowsAdapter

    if not args.confirm_destructive:
        raise Refused("BLOCKED", "ConfirmationMissing", "Destructive confirmation was not given. Nothing was written.")
    # Identity and policy first: a protected disk is refused whatever the privilege.
    adapter = WindowsAdapter()
    adapter.enumerate_devices(include_virtual=True)
    device = adapter.inspect_device(args.device)
    refusal = sanitize_policy_refusal(device, _bus_of(device.id))
    if refusal and not device.system_device:
        ctx.ledger().append(actor=ctx.operator, operation="aegis.sanitize.refused",
                            params={"case_id": ctx.case_id, "device": device.path, "serial": device.serial,
                                    "model": device.model, "reason": "internal_drive"},
                            result={"reason": refusal})
        raise Refused("BLOCKED", "InternalDriveRefused", f"Refusing {device.path}: {refusal} Nothing was written.",
                      "Only removable USB or SD/MMC media can be sanitized with AEGIS.")
    if device.system_device:
        from core.errors import SystemDiskRefused

        ctx.ledger().append(actor=ctx.operator, operation="aegis.sanitize.refused",
                            params={"case_id": ctx.case_id, "device": device.path, "serial": device.serial,
                                    "model": device.model, "reason": "system_device"},
                            result={"reasons": device.system_reasons})
        raise SystemDiskRefused(f"Refusing {device.path}: it is the system or boot disk. " + " ".join(device.system_reasons))
    if not _elevated():
        raise Refused("BLOCKED", "RequiresPrivilege",
                      "Writing to a physical disk needs an elevated process. Nothing was written.",
                      "Start AEGIS with Run as administrator.")
    if args.expected_serial and device.serial.strip() != args.expected_serial.strip():
        raise Refused("BLOCKED", "IdentityMismatch",
                      f"{device.path} now reports serial {device.serial!r}, not the selected {args.expected_serial!r}.")
    if args.expected_size and int(args.expected_size) != int(device.capacity_bytes):
        raise Refused("BLOCKED", "IdentityMismatch",
                      f"{device.path} now reports {device.capacity_bytes} bytes, not the selected {args.expected_size}.")
    backup = _backup_gate(ctx, device.serial, args)
    job_id = args.job_id or _job_id("erase")
    params = {"path": args.device, "typed_serial": args.typed_serial, "level": args.level.upper(),
              "job_id": job_id, "overwrite_method": args.overwrite_method or "", **ctx.ledger_params()}
    ctx.ledger().append(actor=ctx.operator, operation="aegis.sanitize.authorized",
                        params={"job_id": job_id, "case_id": ctx.case_id, "device": device.path,
                                "serial": device.serial, "model": device.model,
                                "size_bytes": device.capacity_bytes, "level": args.level.upper(),
                                "overwrite_method": args.overwrite_method or "SINGLE_PASS_OVERWRITE",
                                "backup": backup, "operator_confirmed": True},
                        result={})
    job = {"job_id": job_id, "kind": "erase-drive", "case_id": ctx.case_id, "operator": ctx.operator,
           "started_at": _now(), "status": "RUNNING",
           "params": {"device": device.model_dump(mode="json"), "level": args.level.upper(), "backup": backup,
                      "overwrite_method": args.overwrite_method or "SINGLE_PASS_OVERWRITE",
                      "mount_points": device.mount_points}}
    ctx.save_job(job)
    outcome = drive(adapter.execute_drive_sanitization(params))
    result = (outcome or {}).get("result") or {}
    job.update(status="SUCCESS", finished_at=_now(), result=result)
    path_out = ctx.save_job(job)
    verification = result.get("verification") or {}
    return {"job_id": job_id, "result_file": str(path_out), "achieved_level": result.get("achieved_level"),
            "verification": verification, "_warnings": list(result.get("limitations") or [])}


def cmd_traces(args: argparse.Namespace, ctx: Context) -> dict[str, Any]:
    from core.erase.sink import ChainLedgerSink
    from core.erase.traces import find_traces, sweep
    from core.models import FileEraseOptions, FileEraseRecord, FileInspection

    records = []
    for raw in args.erased:
        path = Path(raw)
        if path.exists():
            raise Refused("BLOCKED", "NotErased",
                          f"{raw} still exists. Traces are swept only for paths whose erase completed.")
        records.append(FileEraseRecord(path=str(path), ok=True, unlinked=True, attempted=True,
                                       is_directory=bool(args.directory),
                                       inspection=FileInspection(path=str(path), size_bytes=0)))
    job_id = args.job_id or _job_id("traces")
    if args.find_only:
        found = find_traces(records)
        return {"job_id": job_id, "sweep": found.model_dump(mode="json"), "removed": False}
    sink = ChainLedgerSink(ctx.ledger())
    result = drive(sweep(records, FileEraseOptions(), job_id=job_id, ledger=sink))
    data = result.model_dump(mode="json")
    job = {"job_id": job_id, "kind": "traces", "case_id": ctx.case_id, "operator": ctx.operator,
           "started_at": _now(), "finished_at": _now(), "status": "SUCCESS",
           "params": {"erased": args.erased, "source_job": args.source_job or ""}, "result": {"trace_sweep": data}}
    ctx.save_job(job)
    return {"job_id": job_id, "sweep": data, "removed": True}


# -- Windows thumbnail cache, coordinated through the Restart Manager ---------


class _RmProcessInfo(ctypes.Structure):
    class _Unique(ctypes.Structure):
        _fields_ = [("dwProcessId", ctypes.c_uint32), ("ProcessStartTime", ctypes.c_uint64)]

    _fields_ = [("Process", _Unique), ("strAppName", ctypes.c_wchar * 256),
                ("strServiceShortName", ctypes.c_wchar * 64), ("ApplicationType", ctypes.c_int),
                ("AppStatus", ctypes.c_uint32), ("TSSessionId", ctypes.c_uint32), ("bRestartable", ctypes.c_int)]


def cmd_thumbcache(args: argparse.Namespace, ctx: Context) -> dict[str, Any]:
    """Overwrite and remove the user's thumbcache_*.db, coordinating holders via Restart Manager.

    The thumbnail databases cannot be tied to an erased path (entries are keyed
    by a cache hash), so this clears the whole cache and says so. Holders are
    asked to shut down gracefully (RmShutdown without RmForceShutdown); nothing
    is force-killed. A holder that refuses leaves its file untouched and
    reported. The shell is restarted through RmRestart.
    """
    if sys.platform != "win32":
        raise Refused("UNSUPPORTED", "PlatformUnsupported", "The Windows thumbnail cache exists only on Windows.")
    local = os.environ.get("LOCALAPPDATA", "")
    folder = Path(local) / "Microsoft" / "Windows" / "Explorer"
    files = sorted(folder.glob("thumbcache_*.db")) if folder.is_dir() else []
    job_id = args.job_id or _job_id("thumbcache")
    actions: list[dict[str, Any]] = []
    holders: list[dict[str, Any]] = []
    if not files:
        return {"job_id": job_id, "files": [], "actions": [], "holders": [],
                "_warnings": [f"No thumbcache_*.db files under {folder}; nothing was cleared."]}
    if args.find_only:
        return {"job_id": job_id, "files": [{"path": str(f), "size": f.stat().st_size} for f in files],
                "actions": [], "holders": []}
    rm = ctypes.WinDLL("rstrtmgr.dll")
    session = ctypes.c_uint32()
    key = ctypes.create_unicode_buffer(uuid.uuid4().hex[:31])
    rc = rm.RmStartSession(ctypes.byref(session), 0, key)
    if rc != 0:
        raise Refused("FAILED", "RestartManager", f"RmStartSession failed ({rc}). Nothing was cleared.")
    shut_down = False
    try:
        arr = (ctypes.c_wchar_p * len(files))(*[str(f) for f in files])
        rc = rm.RmRegisterResources(session, len(files), arr, 0, None, 0, None)
        needed = ctypes.c_uint32(0)
        count = ctypes.c_uint32(16)
        infos = (_RmProcessInfo * 16)()
        reasons = ctypes.c_uint32(0)
        rc = rm.RmGetList(session, ctypes.byref(needed), ctypes.byref(count), infos, ctypes.byref(reasons))
        for i in range(min(count.value, 16)):
            holders.append({"pid": infos[i].Process.dwProcessId, "app": infos[i].strAppName,
                            "restartable": bool(infos[i].bRestartable)})
        if holders:
            rc = rm.RmShutdown(session, 0, None)  # 0: graceful only, never RmForceShutdown
            shut_down = rc == 0
            actions.append({"action": "RmShutdown(graceful)", "rc": rc,
                            "holders": [h["app"] for h in holders]})
        for f in files:
            entry = {"path": str(f)}
            try:
                size = f.stat().st_size
                with open(f, "r+b", buffering=0) as handle:
                    block = b"\x00" * (1 << 20)
                    done = 0
                    while done < size:
                        n = handle.write(block[: min(len(block), size - done)])
                        done += n
                    handle.flush()
                    os.fsync(handle.fileno())
                f.unlink()
                entry.update(cleared=True, bytes_overwritten=size)
            except OSError as exc:
                entry.update(cleared=False, error=str(exc))
            actions.append(entry)
    finally:
        if shut_down:
            rc = rm.RmRestart(session, 0, None)
            actions.append({"action": "RmRestart", "rc": rc})
        rm.RmEndSession(session)
    cleared = [a for a in actions if a.get("cleared")]
    failed = [a for a in actions if a.get("cleared") is False]
    ctx.ledger().append(actor=ctx.operator, operation="aegis.thumbcache.clear",
                        params={"job_id": job_id, "case_id": ctx.case_id, "folder": str(folder),
                                "holders": holders},
                        result={"cleared": len(cleared), "failed": len(failed), "actions": actions})
    job = {"job_id": job_id, "kind": "thumbcache", "case_id": ctx.case_id, "operator": ctx.operator,
           "started_at": _now(), "finished_at": _now(), "status": "SUCCESS" if not failed else "SUCCESS_WITH_WARNINGS",
           "params": {"folder": str(folder)}, "result": {"actions": actions, "holders": holders}}
    ctx.save_job(job)
    warnings = [f"{a['path']}: {a.get('error')}" for a in failed]
    warnings.append("The thumbnail cache cannot be tied to one file; the whole per-user cache was cleared and "
                    "Windows rebuilds it on demand.")
    return {"job_id": job_id, "actions": actions, "holders": holders, "cleared": len(cleared),
            "failed": len(failed), "_warnings": warnings}


def cmd_ledger_verify(args: argparse.Namespace, ctx: Context) -> dict[str, Any]:
    chain = ctx.state / "ledger" / "ledger" / "chain.jsonl"
    if not chain.is_file() or chain.stat().st_size == 0:
        return {"status": "EMPTY", "entry_count": 0, "explanation": "No ledger entries have been recorded for this case yet."}
    verification = ctx.ledger().verify(check_blobs=True)
    data = {
        "status": verification.status.value,
        "explanation": verification.explanation,
        "entry_count": verification.entry_count,
        "verified_through": verification.verified_through,
        "first_bad_seq": verification.first_bad_seq,
        "failure_kind": verification.failure_kind.value if verification.failure_kind else None,
    }
    if verification.status.value != "VALID":
        raise _ResultError("FAILED", "LedgerChainBroken", verification.explanation, data)
    return data


class _ResultError(Exception):
    def __init__(self, status: str, kind: str, message: str, result: dict[str, Any]) -> None:
        super().__init__(message)
        self.status, self.kind, self.message, self.result = status, kind, message, result


def _arg_text(value: str | None) -> str:
    """Arguments may arrive as ``b64:<base64 utf-8>`` so JSON survives Windows command-line quoting."""
    if value and value.startswith("b64:"):
        import base64

        return base64.b64decode(value[4:]).decode("utf-8")
    return value or ""


def cmd_record(args: argparse.Namespace, ctx: Context) -> dict[str, Any]:
    """Append a desktop-side event (evidence registration, file sanitization) to the case ledger.

    Only ``aegis.desktop.*`` operations are accepted, so the desktop can never
    write an entry that impersonates an engine operation (acquire.*, carve.*,
    erase.*, report.*).
    """
    operation = args.operation.strip()
    if not re.fullmatch(r"aegis\.desktop\.[a-z0-9_.-]+", operation):
        raise Refused("BLOCKED", "OperationNotAllowed",
                      f"{operation!r} is not an aegis.desktop.* operation; engine operations are recorded by the engine.")
    try:
        params = json.loads(_arg_text(args.params_json) or "{}")
        result = json.loads(_arg_text(args.result_json) or "{}")
    except json.JSONDecodeError as exc:
        raise Refused("BLOCKED", "InvalidJson", f"Parameters are not valid JSON: {exc}") from exc
    if not isinstance(params, dict) or not isinstance(result, dict):
        raise Refused("BLOCKED", "InvalidJson", "Parameters and result must be JSON objects.")
    params.setdefault("case_id", ctx.case_id)
    entry = ctx.ledger().append(actor=ctx.operator, operation=operation, params=params, result=result)
    return {"seq": entry.seq, "entry_hash": entry.entry_hash, "operation": operation}


def cmd_ledger_list(args: argparse.Namespace, ctx: Context) -> dict[str, Any]:
    ledger = ctx.ledger()
    rows = []
    for entry in ledger.entries():
        row = json.loads(entry.model_dump_json())
        try:
            row["params"] = ledger.params_of(entry)
            row["result"] = ledger.result_of(entry)
        except (OSError, ValueError, FileNotFoundError) as exc:
            row["blob_error"] = str(exc)
        if args.job and row.get("params", {}).get("job_id") not in (args.job, None):
            continue
        rows.append(row)
    out = ctx.state / "jobs" / "_ledger_export.json"
    out.write_text(json.dumps({"entries": rows}, default=_json_default), encoding="utf-8")
    return {"count": len(rows), "result_file": str(out)}


def _acquisition_report(job: dict[str, Any], common: dict[str, Any], signature: Any = None) -> dict[str, Any]:
    from core.report.render import CANON_VERSION, _audit_trail, _envelope

    result = job.get("result") or {}
    record = result.get("record") or {}
    params = job.get("params") or {}
    sections = {
        "case_identity": {
            "case_id": common["case_id"], "operator": common["operator"],
            "generated_at": common["generated_at"], "tool_version": common["tool_version"],
            "canon_version": CANON_VERSION, "job_state": job.get("status", ""), "report_kind": "ACQUISITION",
        },
        "evidence_source": {
            "source": params.get("source", ""), "device_model": params.get("device_model") or "",
            "device_serial": params.get("expected_serial") or "", "size_bytes": (record.get("source") or {}).get("size_bytes"),
            "sector_size": (record.get("source") or {}).get("sector_size"),
            "evidence_number": params.get("evidence_number") or "",
        },
        "acquisition": {
            "format": record.get("fmt"), "image": result.get("image_path"), "segments": result.get("segments"),
            "started_at": record.get("started_at"), "finished_at": record.get("finished_at"),
            "bytes_read": record.get("bytes_read"), "sha256": record.get("sha256"), "blake3": record.get("blake3"),
            "chunk_bytes": record.get("chunk_bytes"), "chunk_count": len(record.get("chunk_hashes") or []),
            "write_blocked": record.get("write_blocked"), "write_block_verified_by": record.get("write_block_verified_by"),
        },
        "unreadable_sectors": {"ranges": record.get("bad_sectors") or [],
                               "substituted": (record.get("source") or {}).get("substituted_ranges") or []},
        "verification": result.get("verification") or {},
        "limitations": {"items": common["limitations"] + list(record.get("limitations") or [])},
        "audit_trail": _audit_trail(ledger_excerpt=common["ledger_excerpt"],
                                    chain_verification=common["chain_verification"],
                                    merkle_root=None, anchor=None),
    }
    return _envelope(case_id=common["case_id"], generated_at=common["generated_at"],
                     tool_version=common["tool_version"], pubkey_fingerprint=common["pubkey_fingerprint"],
                     sections=sections, signature=signature)


def cmd_report(args: argparse.Namespace, ctx: Context) -> dict[str, Any]:
    from core.report.render import (build_carve_report, build_file_erase_report, build_report,
                                    drive_report_inputs, write_report)
    from core.report.sign import sign_report

    job = ctx.load_job(args.job_id)
    if job.get("status") == "RUNNING":
        raise Refused("BLOCKED", "JobNotFinished", f"{args.job_id} has not finished; a report now would be empty.")
    ledger = ctx.ledger()
    key = ctx.signing_key()
    verification = ledger.verify()
    # The ledger is per case, so a report carries the whole case chain up to now
    # (every entry hash-linked, no excerpt gaps) unless it is very large, in
    # which case it carries this job's entries plus genesis and declares the gaps.
    entries = ledger.entries()
    excerpt = []
    whole = len(entries) <= 5000
    for entry in entries:
        if whole or entry.operation == "GENESIS":
            excerpt.append(json.loads(entry.model_dump_json()))
            continue
        try:
            params = ledger.params_of(entry)
        except (OSError, FileNotFoundError, ValueError):
            params = {}
        if params.get("job_id") == args.job_id:
            excerpt.append(json.loads(entry.model_dump_json()))
    result = job.get("result") or {}
    common: dict[str, Any] = {
        "job_state": str(job.get("status") or ""),
        "case_id": ctx.case_id or job.get("case_id") or args.job_id,
        "operator": job.get("operator") or ctx.operator,
        "generated_at": _now(),
        "tool_version": TOOL_VERSION,
        "limitations": list(result.get("limitations") or []),
        "ledger_excerpt": excerpt,
        "chain_verification": verification,
        "pubkey_fingerprint": ctx.fingerprint(),
    }
    kind = job.get("kind")
    if kind == "acquire":
        unsigned = _acquisition_report(job, common)
        signed = _acquisition_report(job, common, signature=sign_report(unsigned, key))
    else:
        if kind == "carve":
            builder = build_carve_report
            fields = common | {"evidence": result.get("evidence") or {}, "media_map": result.get("media_map"),
                               "candidates": [{k: v for k, v in c.items() if k not in ("output_path", "output_sha256")}
                                              for c in result.get("candidates") or []],
                               "partitions": result.get("partitions") or [],
                               "unallocated_bytes": int(result.get("unallocated_bytes") or 0),
                               "written": result.get("written") or []}
        elif kind in ("traces",):
            builder = build_file_erase_report
            fields = common | {"records": [], "trace_sweep": result.get("trace_sweep")}
        elif kind == "erase-drive":
            builder = build_report
            fields = common | drive_report_inputs(result)
        else:
            raise Refused("UNSUPPORTED", "ReportKind", f"No signed report shape exists for a {kind} job.")
        unsigned = builder(**fields)
        signed = builder(**fields, signature=sign_report(unsigned, key))
    out_dir = ctx.state / "reports" / args.job_id
    json_path, pdf_path = write_report(signed, out_dir)
    digest = hashlib.sha256(json_path.read_bytes()).hexdigest()
    ledger.append(actor=ctx.operator, operation="report.generated",
                  params={"job_id": args.job_id, "case_id": common["case_id"], "kind": kind,
                          "json": str(json_path), "pdf": str(pdf_path)},
                  result={"sha256": digest, "pubkey_fingerprint": common["pubkey_fingerprint"]})
    meta = {"job_id": args.job_id, "kind": kind, "json": str(json_path), "pdf": str(pdf_path),
            "sha256": digest, "generated_at": common["generated_at"], "fingerprint": common["pubkey_fingerprint"]}
    (out_dir / "aegis-report.meta.json").write_text(json.dumps(meta, default=_json_default, indent=1), encoding="utf-8")
    return meta


def cmd_verify_report(args: argparse.Namespace, ctx: Context) -> dict[str, Any]:
    from core.report.verify_report import verify_report_file

    path = Path(args.report)
    if not path.is_file():
        raise Refused("FAILED", "ReportMissing", f"{path} does not exist.")
    try:
        verification = verify_report_file(path, ledger_root=ctx.state / "ledger")
    except ValueError as exc:
        raise _ResultError("FAILED", "ReportUnreadable", f"{path} is not a valid report: {exc}",
                           {"verdict": "INVALID", "checks": []}) from exc
    data = {
        "verdict": verification.verdict.value,
        "fingerprint": verification.fingerprint,
        "reasons": list(verification.verdict_reasons),
        "checks": [c.model_dump(mode="json") if hasattr(c, "model_dump") else c.__dict__ for c in verification.checks],
        "report_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
    verdict = verification.verdict.value
    if verdict == "FAILED_VERIFICATION":
        raise _ResultError("FAILED", "ReportInvalid", "; ".join(data["reasons"]) or "Report verification failed.", data)
    if verdict != "VERIFIED":
        data["_warnings"] = data["reasons"] or [f"Verdict {verdict}."]
    return data


def cmd_enhance(args: argparse.Namespace, ctx: Context) -> dict[str, Any]:
    try:
        import cv2
        import numpy as np
    except ImportError as exc:
        raise Refused("UNAVAILABLE", "EnhancementUnavailable", f"OpenCV is not installed in the engine runtime: {exc}")
    if not hasattr(cv2, "dnn_superres"):
        raise Refused("UNAVAILABLE", "EnhancementUnavailable", "OpenCV in this runtime has no dnn_superres module.")
    model_name = args.model.upper()
    scale = int(args.scale)
    model_file = ENGINE_ROOT / "models" / f"{model_name}_x{scale}.pb"
    if not model_file.is_file():
        raise Refused("UNAVAILABLE", "ModelMissing", f"Model file {model_file.name} is not packaged.")
    source = Path(args.input)
    if not source.is_file():
        raise Refused("FAILED", "SourceUnavailable", f"{source} does not exist.")
    original_bytes = source.read_bytes()
    source_sha = hashlib.sha256(original_bytes).hexdigest()
    image = cv2.imdecode(np.frombuffer(original_bytes, dtype=np.uint8), cv2.IMREAD_COLOR)
    if image is None:
        raise Refused("FAILED", "UndecodableImage", f"{source.name} could not be decoded as an image.")
    job_id = args.job_id or _job_id("enhance")
    out_dir = ctx.state / "enhanced" / job_id
    out_dir.mkdir(parents=True, exist_ok=True)
    # The derivative copy: the enhancement reads this copy, never the original.
    derivative = out_dir / f"original_{source.name}"
    derivative.write_bytes(original_bytes)
    sr = cv2.dnn_superres.DnnSuperResImpl_create()
    sr.readModel(str(model_file))
    sr.setModel(model_name.lower(), scale)
    h, w = image.shape[:2]
    tile = int(args.tile)
    pad = 8
    output = np.zeros((h * scale, w * scale, 3), dtype=np.uint8)
    tiles = [(y, x) for y in range(0, h, tile) for x in range(0, w, tile)]
    started = time.monotonic()
    for index, (y, x) in enumerate(tiles):
        if cancel_requested():
            shutil.rmtree(out_dir, ignore_errors=True)
            raise Cancelled("Enhancement cancelled; the partial derivative was removed.")
        y0, x0 = max(0, y - pad), max(0, x - pad)
        y1, x1 = min(h, y + tile + pad), min(w, x + tile + pad)
        up = sr.upsample(image[y0:y1, x0:x1])
        oy, ox = (y - y0) * scale, (x - x0) * scale
        th, tw = min(tile, h - y) * scale, min(tile, w - x) * scale
        output[y * scale:y * scale + th, x * scale:x * scale + tw] = up[oy:oy + th, ox:ox + tw]
        emit("PROGRESS", phase="enhance", pct=round(100.0 * (index + 1) / len(tiles), 1), bytes_done=index + 1,
             bytes_total=len(tiles), throughput=0, eta=0, message=f"tile {index + 1}/{len(tiles)}")
    enhanced = out_dir / f"enhanced_{model_name}x{scale}_{source.stem}.png"
    ok, encoded = cv2.imencode(".png", output)
    if not ok:
        raise Refused("FAILED", "EncodeFailed", "The enhanced derivative could not be encoded.")
    enhanced.write_bytes(encoded.tobytes())
    after_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    record = {
        "job_id": job_id, "case_id": ctx.case_id, "operator": ctx.operator,
        "source": str(source), "source_sha256": source_sha, "source_unchanged": after_sha == source_sha,
        "derivative_copy": str(derivative), "derivative_copy_sha256": hashlib.sha256(derivative.read_bytes()).hexdigest(),
        "enhanced": str(enhanced), "enhanced_sha256": hashlib.sha256(enhanced.read_bytes()).hexdigest(),
        "model": model_name, "model_file": model_file.name,
        "model_sha256": hashlib.sha256(model_file.read_bytes()).hexdigest(),
        "framework": f"OpenCV {cv2.__version__} dnn_superres", "scale": scale, "tile": tile,
        "input_size": [w, h], "output_size": [w * scale, h * scale],
        "seconds": round(time.monotonic() - started, 2), "timestamp": _now(),
        "note": "AI-enhanced derivative for viewing only. It is not evidence; the original is unchanged.",
    }
    ctx.ledger().append(actor=ctx.operator, operation="aegis.enhance", params={k: v for k, v in record.items()
                        if k not in ("seconds",)}, result={"enhanced_sha256": record["enhanced_sha256"]})
    ctx.save_job({"job_id": job_id, "kind": "enhance", "case_id": ctx.case_id, "operator": ctx.operator,
                  "started_at": record["timestamp"], "finished_at": _now(), "status": "SUCCESS",
                  "params": {"input": str(source), "model": model_name, "scale": scale}, "result": record})
    (out_dir / "derivative.json").write_text(json.dumps(record, default=_json_default, indent=1), encoding="utf-8")
    if not record["source_unchanged"]:
        raise Refused("FAILED", "OriginalChanged", "The original changed during enhancement.")
    return record


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

COMMANDS: dict[str, Callable[[argparse.Namespace, Context], dict[str, Any]]] = {
    "health": cmd_health,
    "devices": cmd_devices,
    "acquire": cmd_acquire,
    "verify-image": cmd_verify_image,
    "recover": cmd_recover,
    "prepare-device": cmd_prepare_device,
    "sanitize-device": cmd_sanitize_device,
    "traces": cmd_traces,
    "thumbcache": cmd_thumbcache,
    "ledger-verify": cmd_ledger_verify,
    "ledger-list": cmd_ledger_list,
    "record": cmd_record,
    "report": cmd_report,
    "verify-report": cmd_verify_report,
    "enhance": cmd_enhance,
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis_engine_cli", description="AEGIS Engine Bridge")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--state", help="per-case AEGIS state directory (ledger, jobs, reports)")
    common.add_argument("--keys", help="signing key directory")
    common.add_argument("--case-id", default="")
    common.add_argument("--operator", default="")
    common.add_argument("--job-id", default="")
    common.add_argument("--cancel-file", default="", help="cancel when this file appears")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("health", parents=[common])
    p = sub.add_parser("devices", parents=[common])
    p.add_argument("--include-virtual", action="store_true")
    p = sub.add_parser("acquire", parents=[common])
    p.add_argument("--source", required=True)
    p.add_argument("--dest", required=True)
    p.add_argument("--format", default="raw")
    p.add_argument("--expected-serial", default="")
    p.add_argument("--expected-size", default="0")
    p.add_argument("--sector-size", default="512")
    p.add_argument("--evidence-number", default="")
    p.add_argument("--examiner", default="")
    p.add_argument("--description", default="")
    p.add_argument("--notes", default="")
    p.add_argument("--device-model", default="")
    p = sub.add_parser("verify-image", parents=[common])
    p = sub.add_parser("recover", parents=[common])
    p.add_argument("--image", required=True)
    p.add_argument("--out", default="")
    p.add_argument("--source-job", default="")
    p.add_argument("--no-undelete", action="store_true")
    p.add_argument("--no-carve", action="store_true")
    p.add_argument("--no-media-map", action="store_true")
    p.add_argument("--no-write", action="store_true", help="list and score candidates without writing recovered copies")
    p = sub.add_parser("prepare-device", parents=[common])
    p.add_argument("--device", required=True)
    p.add_argument("--typed-serial", required=True)
    p = sub.add_parser("sanitize-device", parents=[common])
    p.add_argument("--device", required=True)
    p.add_argument("--typed-serial", required=True)
    p.add_argument("--expected-serial", default="")
    p.add_argument("--expected-size", default="0")
    p.add_argument("--level", default="CLEAR")
    p.add_argument("--overwrite-method", default="")
    p.add_argument("--backup-job", default="")
    p.add_argument("--waive-backup", default="")
    p.add_argument("--confirm-destructive", action="store_true")
    p = sub.add_parser("traces", parents=[common])
    p.add_argument("--erased", action="append", default=[], required=True)
    p.add_argument("--directory", action="store_true")
    p.add_argument("--find-only", action="store_true")
    p.add_argument("--source-job", default="")
    p = sub.add_parser("thumbcache", parents=[common])
    p.add_argument("--find-only", action="store_true")
    sub.add_parser("ledger-verify", parents=[common])
    p = sub.add_parser("ledger-list", parents=[common])
    p.add_argument("--job", default="")
    p = sub.add_parser("record", parents=[common])
    p.add_argument("--operation", required=True)
    p.add_argument("--params-json", default="{}")
    p.add_argument("--result-json", default="{}")
    sub.add_parser("report", parents=[common])
    p = sub.add_parser("verify-report", parents=[common])
    p.add_argument("--report", required=True)
    p = sub.add_parser("enhance", parents=[common])
    p.add_argument("--input", required=True)
    p.add_argument("--model", default="EDSR")
    p.add_argument("--scale", default="2")
    p.add_argument("--tile", default="192")
    return parser


_STATUS_BY_ERROR = {
    "SystemDiskRefused": "BLOCKED", "MountedRefused": "BLOCKED", "ConfirmationMismatch": "BLOCKED",
    "DeviceVanished": "BLOCKED", "DeviceFrozen": "BLOCKED", "WorkflowGateRefused": "BLOCKED",
    "GeometryRefused": "BLOCKED", "UnsupportedCapability": "UNSUPPORTED", "PlatformUnsupported": "UNSUPPORTED",
    "LedgerBusy": "FAILED", "LedgerChainBroken": "FAILED", "EvidenceIntegrityError": "FAILED",
    "OverwriteIncomplete": "FAILED", "SignatureInvalid": "FAILED",
}
_EXIT = {"SUCCESS": 0, "SUCCESS_WITH_WARNINGS": 0, "FAILED": 1, "BLOCKED": 2, "UNSUPPORTED": 3,
         "UNAVAILABLE": 3, "CANCELLED": 4}


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        emit("RESULT", status="FAILED", command="", error={"type": "Usage", "message": "Invalid arguments."})
        return 5
    for key, value in vars(args).items():
        if isinstance(value, str) and value.startswith("b64:"):
            setattr(args, key, _arg_text(value))
        elif isinstance(value, list):
            setattr(args, key, [_arg_text(v) if isinstance(v, str) else v for v in value])
    operation_id = args.job_id or uuid.uuid4().hex
    emit("HELLO", protocol=PROTOCOL, bridge_version=BRIDGE_VERSION, command=args.command, operation_id=operation_id)
    _configure_logging()
    global _CANCEL_FILE
    _CANCEL_FILE = getattr(args, "cancel_file", "") or ""
    status, result, error, warnings = "FAILED", {}, None, []
    ctx_ref: list[Context] = []
    try:
        ctx = Context(args)
        ctx_ref.append(ctx)
        result = COMMANDS[args.command](args, ctx) or {}
        warnings = list(result.pop("_warnings", []) or [])
        status = "SUCCESS_WITH_WARNINGS" if warnings else "SUCCESS"
    except Cancelled as exc:
        status, error = "CANCELLED", {"type": "Cancelled", "message": str(exc)}
    except Refused as exc:
        status, error = exc.status, {"type": exc.kind, "message": exc.message, "remediation": exc.remediation}
    except _ResultError as exc:
        status, error, result = exc.status, {"type": exc.kind, "message": exc.message}, exc.result
    except PermissionError as exc:
        status = "BLOCKED"
        error = {"type": "RequiresPrivilege" if getattr(exc, "winerror", 0) == 5 else "PermissionDenied",
                 "message": str(exc), "remediation": "Start AEGIS with Run as administrator, or check access to the path."}
    except Exception as exc:  # noqa: BLE001 - every failure is reported, never swallowed
        name = type(exc).__name__
        status = _STATUS_BY_ERROR.get(name, "FAILED")
        error = {"type": name, "message": getattr(exc, "message", None) or str(exc),
                 "remediation": getattr(exc, "remediation", "") or "",
                 "traceback": traceback.format_exc(limit=6)}
    if ctx_ref and ctx_ref[0].current_job and isinstance(result, dict) and not result.get("job_id"):
        result["job_id"] = ctx_ref[0].current_job
    if isinstance(result, dict) and result.get("job_id"):
        operation_id = str(result["job_id"])
    emit("RESULT", status=status, command=args.command, operation_id=operation_id, result=result,
         warnings=warnings, error=error)
    return _EXIT.get(status, 1)


if __name__ == "__main__":
    _code = main()
    try:
        _PROTOCOL_OUT.flush()
        sys.stderr.flush()
    finally:
        # A daemon thread blocked reading stdin (the CANCEL watcher) can hang
        # interpreter finalisation on Windows; the RESULT line is already out.
        os._exit(_code)
