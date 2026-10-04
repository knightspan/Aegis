"""Free-space wipe, judged by the tool's own recovery pipeline.

Each case: format a volume image, attach it as a loop device through udisks and
let the kernel's own filesystem driver mount it, plant JPEGs and delete them,
detach, and run the recovery pipeline (``api.carve_job.carve_generator``, the
job the Recovery screen runs) over the image. The planted files must come back.
Then attach again, wipe the free space, detach, and carve again. They must not.

Recall is by SHA-256 of the planted file against every candidate the pipeline
returns. A second, independent measure reads the raw image for a 512-byte slice
from inside each planted file, so a survivor the carver failed to recognise is
still counted.

Unprivileged: udisks mounts loop devices for the active desktop user through
polkit. Where that is not permitted - CI, a container, an SSH session - the
tests skip with the reason. No real device is touched: every volume is an image
file under tmp_path.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from core.models import FreeSpaceWipeOptions, FreeSpaceWipeResult

from tests.carve.signature.conftest import make_noisy_jpeg

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="udisks loop mounts are Linux"
)

MIB = 1024 * 1024
PLANTED = 6
SLICE_AT = 2048
SLICE_BYTES = 512

#: The layouts this batch measures: FAT32 and exFAT at the cluster sizes the
#: fragment matrix ran on, and ext4 at its default block size.
LAYOUTS = [
    ("fat32", 512),
    ("fat32", 4096),
    ("exfat", 4096),
    ("exfat", 32768),
    ("ext4", 4096),
]


# --------------------------------------------------------------------------
# udisks loop volumes
# --------------------------------------------------------------------------


def _run(*argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, timeout=120)


def _mounted_at(dev: str) -> str | None:
    for line in Path("/proc/mounts").read_text().splitlines():
        fields = line.split()
        if fields and fields[0] == dev:
            return fields[1].replace("\\040", " ")
    return None


def make_image(path: Path, kind: str, cluster: int) -> None:
    tools = {"fat32": "mkfs.vfat", "exfat": "mkfs.exfat", "ext4": "mkfs.ext4"}
    if shutil.which(tools[kind]) is None:
        pytest.skip(f"{tools[kind]} is not installed")
    # FAT32 needs at least 65,525 clusters or it is not FAT32.
    size = max(64 * MIB, 80_000 * cluster) if kind == "fat32" else 64 * MIB
    with path.open("wb") as handle:
        handle.truncate(size)
    if kind == "fat32":
        argv = ["mkfs.vfat", "-F", "32", "-S", "512", "-s", str(cluster // 512)]
    elif kind == "exfat":
        argv = ["mkfs.exfat", "-c", str(cluster)]
    else:
        argv = [
            "mkfs.ext4",
            "-q",
            "-F",
            "-b",
            str(cluster),
            "-E",
            f"root_owner={os.getuid()}:{os.getgid()}",
        ]
    done = _run(*argv, str(path))
    assert done.returncode == 0, done.stderr


def attach(image: Path) -> tuple[str, Path]:
    """Loop-attach ``image`` through udisks and return (device, mount point)."""
    if shutil.which("udisksctl") is None:
        pytest.skip("udisksctl is not installed")
    done = _run("udisksctl", "loop-setup", "--no-user-interaction", "-f", str(image))
    match = re.search(r"/dev/loop\d+", done.stdout)
    if done.returncode != 0 or match is None:
        pytest.skip(f"udisks would not attach a loop device: {done.stderr.strip()}")
    dev = match.group(0)
    for _ in range(100):
        point = _mounted_at(dev)
        if point:
            return dev, Path(point)
        time.sleep(0.05)
    mounted = _run("udisksctl", "mount", "--no-user-interaction", "-b", dev)
    if mounted.returncode != 0:
        detach(dev)
        pytest.skip(f"udisks would not mount {dev}: {mounted.stderr.strip()}")
    return dev, Path(mounted.stdout.strip().split(" at ", 1)[1].rstrip("."))


def detach(dev: str) -> None:
    """Unmount and release. udisks sets autoclear, so the unmount usually detaches."""
    if _mounted_at(dev):
        _run("udisksctl", "unmount", "--no-user-interaction", "-b", dev)
    size = Path(f"/sys/block/{Path(dev).name}/size")
    for _ in range(100):
        if not size.exists() or size.read_text().strip() == "0":
            return
        time.sleep(0.05)
    _run("udisksctl", "loop-delete", "--no-user-interaction", "-b", dev)


@pytest.fixture
def attached() -> Iterator[list[str]]:
    """Every device a test attaches, released even if the test fails."""
    devices: list[str] = []
    yield devices
    for dev in devices:
        detach(dev)


# --------------------------------------------------------------------------
# Plant, carve, wipe
# --------------------------------------------------------------------------


@dataclass
class Planted:
    name: str
    data: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


def planted_files() -> list[Planted]:
    return [
        Planted(f"planted{index}.jpg", make_noisy_jpeg(size=256, seed=500 + index))
        for index in range(PLANTED)
    ]


def plant_and_delete(point: Path, files: list[Planted]) -> None:
    for item in files:
        with (point / item.name).open("wb") as handle:
            handle.write(item.data)
            handle.flush()
            os.fsync(handle.fileno())
    os.sync()
    for item in files:
        (point / item.name).unlink()
    os.sync()


def carve(image: Path) -> dict[str, Any]:
    from api.carve_job import carve_generator

    pipeline = carve_generator(image)
    try:
        while True:
            next(pipeline)
    except StopIteration as finished:
        result: dict[str, Any] = finished.value
    return result


def recall(result: dict[str, Any], files: list[Planted]) -> list[str]:
    """Names of planted files whose exact bytes the pipeline recovered."""
    digests = {candidate["sha256"] for candidate in result["candidates"]}
    return [item.name for item in files if item.sha256 in digests]


def raw_survivors(image: Path, files: list[Planted]) -> list[str]:
    """Names of planted files a 512-byte slice of which is still in the image."""
    data = image.read_bytes()
    return [
        item.name
        for item in files
        if data.find(item.data[SLICE_AT : SLICE_AT + SLICE_BYTES]) >= 0
    ]


def wipe(point: Path, ledger_root: Path, job_id: str) -> FreeSpaceWipeResult:
    from core.erase.freespace import resolve_volume, wipe_free_space
    from core.ledger.chain import Ledger

    ledger = Ledger(ledger_root, tool_version="test", pubkey_fingerprint="")
    volume = resolve_volume(point)
    generator = wipe_free_space(
        point,
        FreeSpaceWipeOptions(typed_identifier=volume.identifier),
        job_id=job_id,
        ledger=ledger,
        protected=[ledger_root],
    )
    try:
        while True:
            next(generator)
    except StopIteration as finished:
        return finished.value  # type: ignore[no-any-return]


@dataclass
class Measurement:
    kind: str
    cluster: int
    recall_before: list[str]
    raw_before: list[str]
    recall_after: list[str]
    raw_after: list[str]
    result: FreeSpaceWipeResult
    operator_file_intact: bool


def measure(
    tmp_path: Path, kind: str, cluster: int, attached: list[str]
) -> Measurement:
    """The whole before-and-after, shared with the report script."""
    image = tmp_path / f"{kind}-{cluster}.img"
    make_image(image, kind, cluster)
    files = planted_files()

    dev, point = attach(image)
    attached.append(dev)
    keep = point / "operator-evidence.bin"
    keep_bytes = os.urandom(3 * cluster + 17)
    keep.write_bytes(keep_bytes)
    os.sync()
    plant_and_delete(point, files)
    detach(dev)

    before = carve(image)
    recall_before = recall(before, files)
    raw_before = raw_survivors(image, files)

    dev, point = attach(image)
    attached.append(dev)
    keep_stat = (point / keep.name).stat()
    result = wipe(point, tmp_path / "ledger", f"wipe-{kind}-{cluster}")
    after_stat = (point / keep.name).stat()
    intact = (
        (point / keep.name).read_bytes() == keep_bytes
        and after_stat.st_mtime_ns == keep_stat.st_mtime_ns
        and not any(p.name.startswith(".sanctum-freespace") for p in point.iterdir())
    )
    detach(dev)

    after = carve(image)
    return Measurement(
        kind=kind,
        cluster=cluster,
        recall_before=recall_before,
        raw_before=raw_before,
        recall_after=recall(after, files),
        raw_after=raw_survivors(image, files),
        result=result,
        operator_file_intact=intact,
    )


@pytest.mark.parametrize(("kind", "cluster"), LAYOUTS)
def test_deleted_files_the_carver_recovers_are_gone_after_the_wipe(
    tmp_path: Path, kind: str, cluster: int, attached: list[str]
) -> None:
    found = measure(tmp_path, kind, cluster, attached)

    # Before: the demonstration is only worth anything if they were recoverable.
    assert found.raw_before, "the planted files never reached the medium"
    assert found.recall_before, (
        f"the pipeline recovered none of {PLANTED} deleted files before the wipe; "
        "there is nothing for the wipe to demonstrate"
    )

    assert found.result.stopped_by == "ENOSPC"
    assert found.result.bytes_written > 0
    assert found.result.free_bytes_at_full == 0
    assert found.result.filler_removed is True
    assert found.result.verified is None
    assert found.operator_file_intact, "a file the operator did not name changed"

    assert found.raw_after == [], (
        f"planted content survived the wipe on {kind} {cluster}: {found.raw_after}; "
        f"{found.result.free_blocks_bytes_at_full} bytes of blocks were still free "
        "at ENOSPC"
    )
    assert found.recall_after == []


def test_a_cancelled_fill_removes_its_filler_and_is_ledgered(
    tmp_path: Path, attached: list[str]
) -> None:
    from core.erase.freespace import resolve_volume, wipe_free_space
    from core.ledger.chain import Ledger

    image = tmp_path / "cancel.img"
    make_image(image, "fat32", 4096)
    dev, point = attach(image)
    attached.append(dev)
    keep = point / "operator-evidence.bin"
    keep.write_bytes(b"evidence" * 1000)

    ledger = Ledger(tmp_path / "ledger", tool_version="test", pubkey_fingerprint="")
    volume = resolve_volume(point)
    generator = wipe_free_space(
        point,
        FreeSpaceWipeOptions(typed_identifier=volume.identifier),
        job_id="wipe-cancel",
        ledger=ledger,
        protected=[tmp_path / "ledger"],
    )
    for progress in generator:
        if progress.phase == "fill":
            break
    generator.close()

    assert not any(p.name.startswith(".sanctum-freespace") for p in point.iterdir())
    assert keep.read_bytes() == b"evidence" * 1000
    cancelled = [
        ledger.params_of(entry)
        for entry in ledger.entries()
        if entry.operation == "erase.freespace.cancelled"
    ]
    assert len(cancelled) == 1
    assert cancelled[0]["filler_removed"] is True
    assert cancelled[0]["bytes_written"] > 0
