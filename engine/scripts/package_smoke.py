"""Drive an *installed* Sanctum the way a user would, and check what it does.

Run against the packaged executable - the AppImage, the installed
``Sanctum.exe``, the ``.app`` binary - never against a source checkout. The
point is to prove that the thing a user double-clicks works with no developer
environment behind it:

1. it starts, on a private loopback port, and answers ``/health``;
2. it refuses every request that does not carry this launch's session cookie,
   and refuses a request addressed to a non-loopback ``Host``;
3. it discovers devices through the platform adapter and assesses each one;
4. it erases a folder of scratch files **inside a temporary directory this
   script created**, and never anything else;
5. it issues a signed certificate for that erase and verifies it;
6. it stops when asked.

No device is opened and no whole-drive operation is requested. The scratch
directory is this script's own; if the app erased anything outside it, step 4
fails loudly.

    python scripts/package_smoke.py dist/Sanctum-0.0.0-x86_64.AppImage \\
        --out package-smoke-Linux.json

Step 3 is real device discovery: on a CI runner that is the runner's disks, on
a workstation it is whatever is plugged in. ``--isolated`` (Linux, needs
bubblewrap) is for a machine where that is not acceptable. The unpacked
executable runs in a sandbox with no ``/sys``, a ``/dev`` with no block device,
and no udev database or removable-media mount; the sandbox is inspected from
inside before the app starts, and the run refuses to continue if any of those
is visible. Discovery still runs - it is not skipped - and the check becomes
"it found nothing, because nothing is there". The two checks that need a real
device are reported as NOT RUN with the reason, never as passed.

    python scripts/package_smoke.py --isolated \\
        squashfs-root/usr/lib/sanctum/Sanctum --out package-smoke-isolated.json
"""

from __future__ import annotations

import argparse
import http.client
import http.cookiejar
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

PASSPHRASE = "package smoke test passphrase"


#: Every capability the resolver answers for (core.platform.model.Capability).
#: Written out here because this script is stdlib-only and must not import the
#: application it is checking.
RESOLVER_CAPABILITIES = (
    "device_discovery",
    "file_erase",
    "free_space_wipe",
    "whole_drive_clear",
    "ata_sanitize",
    "ata_security_erase",
    "nvme_sanitize",
    "nvme_format",
    "crypto_erase",
    "raw_acquisition",
    "volume_acquisition",
    "hpa_dco_discovery",
    "hpa_dco_modify",
    "backup_restore",
    "trace_sweep",
)

#: Capabilities whose implementation is a platform backend module. If the
#: package lost the module, the resolver still answers from its table, so the
#: check is on the table's own mechanism text being present.
PLATFORM_BACKENDS: dict[str, tuple[str, ...]] = {
    "linux": ("whole_drive_clear", "raw_acquisition", "backup_restore"),
    "windows": (
        "whole_drive_clear",
        "raw_acquisition",
        "volume_acquisition",
        "ata_sanitize",
        "nvme_sanitize",
        "crypto_erase",
        "backup_restore",
    ),
    "macos": ("whole_drive_clear", "raw_acquisition", "backup_restore"),
}


class Client:
    """Tiny HTTP client that keeps the session cookie, with no dependencies."""

    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPRedirectHandler(),
        )

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        body: dict[str, Any] | None = None,
        host: str | None = None,
        cookies: bool = True,
    ) -> tuple[int, Any]:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            self.base + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"} if data else {},
        )
        if host:
            request.add_header("Host", host)
        opener = self.opener if cookies else urllib.request.build_opener()
        try:
            with opener.open(request, timeout=30) as response:  # noqa: S310
                raw = response.read().decode("utf-8", "replace")
                return response.status, (
                    json.loads(raw) if raw.startswith(("{", "[")) else raw
                )
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            return exc.code, (json.loads(raw) if raw.startswith(("{", "[")) else raw)
        except (
            urllib.error.URLError,
            http.client.HTTPException,
            OSError,
        ) as exc:
            # A server that is shutting down closes the connection instead of
            # answering - cleanly on POSIX, with a reset on Windows
            # (WinError 10054). Either way the caller decides whether a
            # missing reply is a failure; quit expects one.
            return 0, str(exc)


#: Physical block-device nodes, as a listing of a sandbox's /dev would name them.
_BLOCK_NODE = re.compile(
    r"^(?:sd[a-z]+\d*|hd[a-z]+\d*|vd[a-z]+\d*|xvd[a-z]+\d*|nvme\S*|mmcblk\S*"
    r"|sr\d+|sg\d+|dm-\d+|md\d+\S*|loop\S*|disk|mapper|block|bsg)$"
)
#: Paths that must not exist inside the sandbox.
_HIDDEN = ("/sys", "/run/media", "/media", "/run/udev", "/dev/disk")


def sandbox_prefix(scratch: Path, executable: Path) -> list[str]:
    """bubblewrap arguments: host userland read-only, no device of any kind.

    The package sees ``/usr`` and ``/etc`` read-only, its own directory
    read-only and the scratch directory. It gets a fresh ``/proc``, a minimal
    ``/dev`` (null, zero, random, tty - no block device), empty ``/tmp`` and
    ``/run``, and no ``/sys``. The network namespace is shared, so this script
    can reach the loopback port the app opens.
    """
    bwrap = shutil.which("bwrap")
    if bwrap is None:
        raise SystemExit(
            "--isolated needs bubblewrap (bwrap). Refusing to run the package "
            "outside the sandbox."
        )
    return [
        bwrap, "--unshare-all", "--share-net", "--die-with-parent", "--new-session",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/lib64", "/lib64", "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/bin", "/bin", "--symlink", "usr/sbin", "/sbin",
        "--ro-bind", "/etc", "/etc",
        "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/run",
        "--bind", str(scratch), str(scratch),
        "--ro-bind", str(executable.parent), str(executable.parent),
        "--setenv", "HOME", str(scratch / "home"), "--setenv", "TMPDIR", "/tmp",
        "--unsetenv", "DISPLAY", "--unsetenv", "WAYLAND_DISPLAY",
        "--unsetenv", "XDG_RUNTIME_DIR", "--unsetenv", "DBUS_SESSION_BUS_ADDRESS",
        "--chdir", str(scratch),
    ]  # fmt: skip


def sandbox_view(prefix: list[str]) -> dict[str, Any]:
    """What the sandbox exposes, read from inside it with the same arguments."""
    script = (
        "ls -1A /dev; echo --; "
        + "; ".join(f"[ -e {path} ] && echo {path}" for path in _HIDDEN)
        + "; echo --; cat /proc/self/mountinfo"
    )
    probe = subprocess.run(  # noqa: S603 - argv list, no shell on the host side
        [*prefix, "/usr/bin/sh", "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    parts = probe.stdout.split("--\n")
    if len(parts) != 3:
        return {"ok": False, "error": probe.stderr.strip()[:500] or probe.stdout[:500]}
    dev_entries = parts[0].split()
    present_paths = parts[1].split()
    mount_lines = [line for line in parts[2].splitlines() if line.strip()]
    block_nodes = [name for name in dev_entries if _BLOCK_NODE.match(name)]
    media_mounts = [line for line in mount_lines if "/media" in line]
    return {
        "ok": not block_nodes and not present_paths and not media_mounts,
        "dev": dev_entries,
        "block_nodes": block_nodes,
        "present_but_should_not_be": present_paths,
        "removable_media_mounts": media_mounts,
        "mount_count": len(mount_lines),
    }


def wait_for_url(url_file: Path, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if url_file.is_file() and url_file.read_text(encoding="utf-8").strip():
            return url_file.read_text(encoding="utf-8").strip()
        time.sleep(0.5)
    raise TimeoutError(f"the app never wrote its session URL to {url_file}")


def _finish(client: Client, job_id: str, timeout_s: float = 120.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    status: dict[str, Any] = {}
    while time.monotonic() < deadline:
        code, status = client.request(f"/jobs/{job_id}")
        if (
            code == 200
            and isinstance(status, dict)
            and status.get("state") != "running"
        ):
            return status
        time.sleep(0.3)
    raise TimeoutError(f"job {job_id} did not finish")


def run(
    executable: Path, argv_extra: list[str], *, isolated: bool = False
) -> dict[str, Any]:
    scratch = Path(tempfile.mkdtemp(prefix="sanctum-smoke-"))
    state = scratch / "state"
    victim = scratch / "victim"
    keep = scratch / "keep"
    (victim / "nested").mkdir(parents=True)
    keep.mkdir()
    (keep / "untouched.txt").write_text("this file is outside the erase target")
    for index in range(3):
        (victim / f"file{index}.bin").write_bytes(os.urandom(4096))
    (victim / "nested" / "deep.bin").write_bytes(os.urandom(2048))
    url_file = scratch / "session-url.txt"
    (scratch / "home").mkdir()
    prefix = sandbox_prefix(scratch, executable) if isolated else []
    checks: list[dict[str, Any]] = []

    def record(name: str, ok: bool, detail: Any = "") -> None:
        checks.append(
            {"check": name, "result": "PASS" if ok else "FAIL", "detail": detail}
        )

    def not_run(name: str, reason: str) -> None:
        checks.append({"check": name, "result": "NOT RUN", "detail": reason})

    view: dict[str, Any] = {}
    if isolated:
        view = sandbox_view(prefix)
        record(
            "the sandbox exposes no block device, sysfs or removable media",
            view["ok"],
            view,
        )
        if not view["ok"]:
            shutil.rmtree(scratch, ignore_errors=True)
            return _evidence(executable, checks, "", prefix, view)

    environment = dict(os.environ)
    environment.update(
        {
            "SANCTUM_URL_FILE": str(url_file),
            "SANCTUM_STATE_DIR": str(state),
        }
    )
    # To a file, not a pipe: the app logs steadily, and a pipe nobody reads
    # fills its buffer and blocks the very process being tested.
    log_path = scratch / "app.log"
    log = log_path.open("w", encoding="utf-8")
    process = subprocess.Popen(  # noqa: S603 - argv list, no shell
        [*prefix, str(executable), *argv_extra],
        env=environment,
        stdout=log,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        url = wait_for_url(url_file, timeout_s=120)
        base = url.split("/session/")[0]
        client = Client(base)

        code, _ = client.request("/health", cookies=False)
        record("health refused without the session cookie", code == 401, code)

        code, _ = client.request(url[len(base) :])
        record("session link accepted", code in (200, 303), code)

        code, health = client.request("/health")
        record("health answers with the cookie", code == 200, health)
        record(
            "session protection is on",
            isinstance(health, dict) and health.get("session_protected") is True,
        )
        record(
            "launcher mode",
            isinstance(health, dict) and health.get("launcher") is True,
        )
        record(
            "UI bundle served from the package",
            isinstance(health, dict) and health.get("ui_bundled") is True,
        )

        code, _ = client.request("/health", host="evil.example")
        record("non-loopback Host refused", code == 400, code)

        code, status = client.request("/platform")
        ok = code == 200 and isinstance(status, dict) and status.get("operations")
        record("platform matrix served", bool(ok), code)
        operations = (
            {row["operation"]: row for row in (status.get("operations") or [])}
            if isinstance(status, dict)
            else {}
        )
        record(
            "every capability row has a source",
            bool(operations) and all(row["source"] for row in operations.values()),
        )
        family = (
            (status.get("platform") or {}).get("family")
            if isinstance(status, dict)
            else ""
        )
        # The capability resolver ships and answers for every capability on
        # this platform, with a state, a reason and (where code exists) the
        # exact mechanism. This is what catches a platform backend that did
        # not make it into the package: its row would say NOT IMPLEMENTED.
        resolved = (
            {
                row.get("capability"): row
                for row in (status.get("capabilities") or [])
                if isinstance(row, dict)
            }
            if isinstance(status, dict)
            else {}
        )
        record(
            "capability resolver answers for every capability",
            set(RESOLVER_CAPABILITIES) <= set(resolved)
            and all(
                row.get("state") and row.get("reason") for row in resolved.values()
            ),
            sorted(set(RESOLVER_CAPABILITIES) - set(resolved)),
        )
        expected_backends = PLATFORM_BACKENDS.get(str(family), ())
        record(
            "platform backends shipped (not NOT_IMPLEMENTED)",
            all(
                resolved.get(name, {}).get("state") not in (None, "NOT_IMPLEMENTED")
                and resolved.get(name, {}).get("mechanism")
                for name in expected_backends
            ),
            {name: resolved.get(name, {}).get("state") for name in expected_backends},
        )
        record(
            "whole-drive clear is never a blanket UNSUPPORTED",
            operations.get("whole_drive_clear", {}).get("state")
            not in (None, "NOT_IMPLEMENTED"),
            operations.get("whole_drive_clear", {}).get("state"),
        )

        code, devices = client.request("/devices")
        rows = devices.get("devices", []) if isinstance(devices, dict) else []
        if isolated:
            # Discovery ran; the boundary is that it had nothing to find.
            record(
                "device discovery in the sandbox finds no device",
                rows == [],
                {"status": code, "devices": len(rows)},
            )
            for name in (
                "every device assessed",
                "protected devices are NOT AVAILABLE",
            ):
                not_run(name, "isolated: the sandbox exposes no device to assess")
        else:
            record(
                "device discovery through the package",
                code == 200 and bool(rows),
                len(rows),
            )
            record(
                "every device assessed",
                all("assessment" in row and "normalized" in row for row in rows),
            )
            record(
                "protected devices are NOT AVAILABLE",
                all(
                    row["assessment"]["headline"] == "NOT AVAILABLE"
                    for row in rows
                    if row["normalized"]["system_device"]
                    or row["normalized"]["mounted"]
                ),
            )

        code, accepted = client.request(
            "/jobs/erase-files",
            method="POST",
            body={
                "paths": [str(victim)],
                "confirm": True,
                "recursive": True,
            },
        )
        record("erase accepted", code == 200 and isinstance(accepted, dict), accepted)
        job_id = accepted["job_id"] if isinstance(accepted, dict) else ""
        status = _finish(client, job_id)
        record(
            "erase completed", status.get("state") == "complete", status.get("error")
        )
        record("target folder is gone", not victim.exists())
        record(
            "nothing outside the target was touched",
            (keep / "untouched.txt").is_file()
            and (keep / "untouched.txt").read_text().startswith("this file is outside"),
        )
        records = (status.get("result") or {}).get("records") or []
        record("one record per path", len(records) >= 5, len(records))
        verification = [
            (item.get("verification") or {}).get("passed") for item in records
        ]
        record(
            "verification is never invented",
            all(value in (True, False, None) for value in verification),
            verification,
        )

        code, report = client.request(
            f"/reports/{job_id}",
            method="POST",
            body={"case_id": "", "operator": "", "key_passphrase": PASSPHRASE},
        )
        record("certificate issued", code == 200 and isinstance(report, dict), code)
        code, check = client.request(f"/reports/{job_id}/verify")
        record(
            "certificate verifies",
            code == 200 and isinstance(check, dict) and check.get("passed") is True,
            check if code != 200 else check.get("passed"),
        )

        code, _ = client.request("/app/quit", method="POST", cookies=False)
        record("quit refused without the session", code == 401, code)
        # A quit that drops the connection is a quit; the app is stopping.
        quit_code, _ = client.request("/app/quit", method="POST")
        record("quit accepted", quit_code in (200, 0), quit_code)
        try:
            process.wait(timeout=30)
            record("app exited on quit", True, process.returncode)
        except subprocess.TimeoutExpired:
            record("app exited on quit", False, "still running")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:  # pragma: no cover
                process.kill()
        log.close()
        output = log_path.read_text(encoding="utf-8", errors="replace")
        shutil.rmtree(scratch, ignore_errors=True)

    return _evidence(executable, checks, output, prefix, view)


def _evidence(
    executable: Path,
    checks: list[dict[str, Any]],
    output: str,
    prefix: list[str],
    view: dict[str, Any],
) -> dict[str, Any]:
    return {
        "executable": str(executable),
        "size_bytes": executable.stat().st_size if executable.is_file() else 0,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "isolated": bool(prefix),
        "sandbox": prefix[1:],
        "sandbox_view": view,
        "checks": checks,
        # NOT RUN is reported, never counted as a pass or hidden.
        "result": "FAIL" if any(c["result"] == "FAIL" for c in checks) else "PASS",
        "not_run": [c["check"] for c in checks if c["result"] == "NOT RUN"],
        "app_output_tail": output[-4000:],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("executable", type=Path)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument(
        "--arg", action="append", default=[], help="extra argument for the executable"
    )
    parser.add_argument(
        "--isolated",
        action="store_true",
        help="run the unpacked executable in a bubblewrap sandbox with no device",
    )
    args = parser.parse_args(argv)

    if not args.executable.exists():
        print(f"no such executable: {args.executable}", file=sys.stderr)
        return 2
    if args.isolated and not (args.executable.parent / "_internal").is_dir():
        print(
            "--isolated needs the unpacked executable (with _internal/ beside it): "
            "extract the AppImage with --appimage-extract or unpack the .deb",
            file=sys.stderr,
        )
        return 2
    evidence = run(args.executable, args.arg, isolated=args.isolated)
    if args.out:
        args.out.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    for check in evidence["checks"]:
        print(f"  {check['result']:<5} {check['check']} {check['detail']}")
    print(evidence["result"])
    return 0 if evidence["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
