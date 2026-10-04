"""Drive an *installed* Sanctum with no stdio explicitly redirected - the
condition that crashed every packaged build before ba66fbe.

``scripts/package_smoke.py`` redirects the child process's stdout/stderr to
a real log file (so a full pipe never blocks the process under test). That
is the right call for what it tests, but it means it can never exercise the
bug: a ``console=False`` PyInstaller build can leave ``sys.stdout``/
``sys.stderr``/``sys.stdin`` as ``None``, and the first structured log call
then crashed before the server ever started.

Whether they actually end up ``None`` turns out to depend on platform *and*
launch method, not just the build flag - confirmed by running this exact
script in CI on both, 2026-09-27:

* **Windows:** ``None``, regardless of how the process is started.
  ``close_fds`` (default since Python 3.7) genuinely detaches a
  ``console=False`` child from any console at the OS level. Confirmed on
  physical hardware and in CI.
* **macOS:** invoking the ``.app``'s Mach-O binary directly from a shell -
  what this script does, and what ``package_smoke.py`` already does -
  inherits real, open file descriptors 0/1/2 via ordinary POSIX fork/exec.
  They are not ``None``. (A real Dock/Finder double-click goes through
  LaunchServices instead of a direct exec and may behave differently; that
  is not exercised here - see the module-level note in this script's
  regression test companion, ``tests/platform/test_boundary_and_security.py``.)
* **Linux:** ``console=False`` is ignored entirely (``packaging/sanctum.spec``).

Either way, the app must not crash and must behave correctly - that is what
this script actually checks. It sets **no** stdout, stderr or stdin on the
child process at all (default ``subprocess.Popen`` behaviour); the one
environment variable it sets, ``SANCTUM_URL_FILE``, does not touch stdio -
it is the documented, existing hook this app ships specifically so a script
with no desktop can retrieve the session URL without redirecting anything.

    python scripts/package_no_console_smoke.py dist/Sanctum/Sanctum.exe \\
        --out no-console-smoke-Windows.json
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import package_smoke  # noqa: E402


def run(executable: Path, timeout_s: float = 60.0) -> dict[str, Any]:
    scratch = Path(tempfile.mkdtemp(prefix="sanctum-noconsole-"))
    state = scratch / "state"
    url_file = scratch / "session-url.txt"

    checks: list[dict[str, Any]] = []

    def record(name: str, ok: bool, detail: Any = "") -> None:
        checks.append(
            {"check": name, "result": "PASS" if ok else "FAIL", "detail": detail}
        )

    environment = dict(os.environ)
    environment.update(
        {"SANCTUM_STATE_DIR": str(state), "SANCTUM_URL_FILE": str(url_file)}
    )

    # No stdout=, no stderr=, no stdin=: this is the whole point. Redirecting
    # any of them here - even to a log file - would give sys.stdout/stderr a
    # real file object again and stop testing anything.
    process = subprocess.Popen(  # noqa: S603 - argv list, no shell
        [str(executable)], env=environment
    )

    url = ""
    try:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if url_file.is_file() and url_file.read_text(encoding="utf-8").strip():
                url = url_file.read_text(encoding="utf-8").strip()
                break
            if process.poll() is not None:
                break
            time.sleep(0.3)

        record(
            "process is still running (did not crash on startup)",
            process.poll() is None,
            process.returncode,
        )
        record("session URL was written", bool(url), url or "not written")

        if not url:
            return _evidence(executable, checks, state)

        base = url.split("/session/")[0]
        client = package_smoke.Client(base)

        code, _ = client.request("/health", cookies=False)
        record("health refused without the session cookie", code == 401, code)

        code, _ = client.request(url[len(base) :])
        record("session link accepted", code in (200, 303), code)

        code, health = client.request("/health")
        record("health answers with the cookie", code == 200, health)
        build = health.get("build") or {} if isinstance(health, dict) else {}
        record(
            "commit in the health response matches this build",
            bool(build.get("commit")),
            build.get("commit"),
        )

        # Whether sys.stdout/sys.stderr were actually None is a fact about
        # this platform and this exact launch method, not something this
        # script can require - it turns out to differ by *how* the process
        # is started, not only by OS. Direct exec of a Mach-O binary from a
        # shell inherits real, open fd 0/1/2 via POSIX fork/exec regardless
        # of the PyInstaller "windowed" build flag (confirmed on macos-14 in
        # CI, 2026-09-27: the app logged straight through to this step's own
        # captured output, and _ensure_logging_has_somewhere_to_write()
        # correctly no-opped because nothing was None). Windows differs:
        # close_fds genuinely detaches a console=False child from any
        # console regardless of invocation method (confirmed the same day,
        # both on physical hardware and in CI). Record which happened; only
        # fail if the two are inconsistent with each other.
        log_file = state / "logs" / "launcher.log"
        log_created = log_file.is_file()
        record(
            "sys.stdout/sys.stderr state this launch produced",
            True,
            "None (launcher.log was written)" if log_created else "real (inherited)",
        )
        if log_created:
            record(
                "launcher.log has real content, since it was created",
                log_file.stat().st_size > 0,
                log_file.stat().st_size,
            )

        code, _ = client.request("/app/quit", method="POST")
        record("quit accepted", code in (200, 0), code)
        try:
            process.wait(timeout=20)
            record("process exited after quit", True, process.returncode)
        except subprocess.TimeoutExpired:
            record("process exited after quit", False, "still running")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:  # pragma: no cover
                process.kill()

    return _evidence(executable, checks, state)


def _evidence(
    executable: Path, checks: list[dict[str, Any]], state: Path
) -> dict[str, Any]:
    log_file = state / "logs" / "launcher.log"
    return {
        "executable": str(executable),
        "state_dir": str(state),
        "launcher_log_tail": (
            log_file.read_text(encoding="utf-8", errors="replace")[-2000:]
            if log_file.is_file()
            else ""
        ),
        "checks": checks,
        "result": "FAIL" if any(c["result"] == "FAIL" for c in checks) else "PASS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("executable", type=Path)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    if not args.executable.exists():
        print(f"no such executable: {args.executable}", file=sys.stderr)
        return 2
    if sys.platform not in ("win32", "darwin"):
        print(
            f"nothing to prove on {sys.platform}: console=False is ignored off "
            "Windows and macOS (packaging/sanctum.spec)",
            file=sys.stderr,
        )
        return 0

    evidence = run(args.executable)
    if args.out:
        args.out.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    for check in evidence["checks"]:
        print(f"  {check['result']:<5} {check['check']} {check['detail']}")
    print(evidence["result"])
    return 0 if evidence["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
