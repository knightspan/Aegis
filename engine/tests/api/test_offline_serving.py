"""The bundle actually loads with networking disabled. Tested, not assumed.

The static-analysis tests next door prove nothing points off-host. This proves
the stronger and more useful thing: the server starts, serves the bundle, and
answers the API inside a network namespace with **no route off the machine**.

``unshare --net`` gives a namespace whose only interface is loopback. A process
inside it cannot reach a CDN even if something tried, so a bundle that secretly
depended on one fails here in the way it would fail at the venue. It needs no
root - Linux has allowed unprivileged network namespaces via a user namespace
for years - and the test skips with a stated reason where it does not work.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from tests._loopback import LOOPBACK_BASE_URL

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="unshare --net is Linux-only"
)

REPO = Path(__file__).resolve().parents[2]

#: Run inside the namespace. It starts the app in-process against a TestClient
#: rather than binding a port: binding proves nothing extra here and would make
#: the test racy on a busy machine.
PROBE = textwrap.dedent(
    """
    import json, os, socket, sys, tempfile
    sys.path.insert(0, {repo!r})

    # Prove the namespace really is cut off before trusting anything else.
    reachable = True
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(2)
        probe.connect(("1.1.1.1", 80))
        probe.close()
    except OSError:
        reachable = False

    os.environ["SANCTUM_KEY_PASSPHRASE"] = "offline-probe"
    from fastapi.testclient import TestClient
    from api.main import create_app

    state = tempfile.mkdtemp()
    app = create_app(state_dir=__import__("pathlib").Path(state), serve_ui=True)
    with TestClient(app, base_url={loopback!r}) as client:
        index = client.get("/")
        health = client.get("/health")
        assets = []
        import re
        for match in re.finditer(r'(?:src|href)="([^"]+)"', index.text):
            target = match.group(1).lstrip(".")
            answer = client.get(target)
            assets.append((target, answer.status_code, len(answer.content)))
        ledger = client.get("/ledger/verify")

    print(json.dumps({{
        "outbound_reachable": reachable,
        "index_status": index.status_code,
        "index_bytes": len(index.content),
        "health_status": health.status_code,
        "ledger_status": ledger.status_code,
        "assets": assets,
    }}))
    """
)


def _run_isolated(script: str) -> dict[str, object]:
    # Two questions, kept apart: can this host make the namespace at all (a skip
    # if not), and did the probe inside it work (a failure if not). One check
    # for both skipped this test from 2026-09-21 on a NameError in the probe.
    namespace = ["unshare", "--net", "--map-root-user"]
    available = subprocess.run(
        [*namespace, "true"], capture_output=True, text=True, timeout=30
    )
    if available.returncode != 0:
        pytest.skip(
            "unprivileged network namespaces are unavailable on this host: "
            f"{available.stderr.strip()[:300]}"
        )
    completed = subprocess.run(
        [*namespace, sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=REPO,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    return json.loads(completed.stdout.strip().splitlines()[-1])


def test_the_ui_and_api_work_with_no_route_off_the_machine(ui_dist: Path) -> None:
    """The acceptance criterion, run rather than asserted."""
    if shutil.which("unshare") is None:
        pytest.skip("util-linux `unshare` is not installed")
    assert ui_dist.is_dir()

    result = _run_isolated(PROBE.format(repo=str(REPO), loopback=LOOPBACK_BASE_URL))

    # The namespace has to actually be isolated, or the rest proves nothing.
    assert result["outbound_reachable"] is False, (
        "the probe could still reach the internet, so this run does not "
        "demonstrate anything about offline operation"
    )

    assert result["index_status"] == 200
    assert int(result["index_bytes"]) > 0
    assert result["health_status"] == 200
    assert result["ledger_status"] == 200

    assets = result["assets"]
    assert assets, "index.html referenced no assets, which cannot be right"
    for target, status, size in assets:  # type: ignore[misc]
        assert status == 200, f"{target} did not load offline ({status})"
        assert size > 0, f"{target} loaded empty offline"
