"""The opt-in fragmented plant for Phase B, and the verdict that guards it.

PREFLIGHT_REPORT §4.3 and §5.2: Phase B writes a fresh volume in one pass, so no
planted object is ever fragmented and ``reassembled_from_fragments`` is zero on
every pass by construction. ``--fragment-plant`` puts one JPEG on the medium in
exactly two runs that the reassembler in ``core/carve/fragmentation.py`` can
reach, and refuses the pass loudly when the filesystem did not cooperate - a
plant that silently came out contiguous would turn a failed plant into an
apparent feature failure, which is the confound this exists to remove.

Nothing here mounts anything. The planner is driven against a simulated volume;
the kernel allocator itself is measured on loopback images and written up in
PREFLIGHT2_REPORT.md.
"""

from __future__ import annotations

import importlib.util
import math
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
K = 4096
PAD = 64 * 1024


@pytest.fixture(scope="module")
def harness() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "hardware_validation_frag", REPO / "scripts" / "hardware_validation.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["hardware_validation_frag"] = module
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------
# the object
# --------------------------------------------------------------------------


def test_the_planted_jpeg_needs_both_holes_and_is_a_whole_jpeg(
    harness: ModuleType,
) -> None:
    from core.carve.fragmentation import is_whole_jpeg

    payload = harness.fragment_jpeg_bytes()
    # Larger than one pad plus a cluster, so it cannot fit in the first hole and
    # its second run holds at least the reassembler's one-cluster floor; no
    # larger than two pads, so it cannot spill past the second hole.
    assert harness.FRAG_PAD_BYTES + K < len(payload) <= 2 * harness.FRAG_PAD_BYTES
    assert is_whole_jpeg(payload)
    assert payload == harness.fragment_jpeg_bytes(), "must be deterministic"


# --------------------------------------------------------------------------
# the verdict
# --------------------------------------------------------------------------


def _runs(*pairs: tuple[int, int]) -> list[dict[str, int]]:
    return [{"offset": offset, "length": length} for offset, length in pairs]


def test_two_forward_runs_within_reach_are_a_good_plant_and_reachable(
    harness: ModuleType,
) -> None:
    from core.carve.fragmentation import MAX_SEARCH_WINDOW

    size = 100_000
    verdict = harness.judge_fragment_plant(
        _runs((10 * K, PAD), (10 * K + 2 * PAD, 12 * K)), size=size, cluster_bytes=K
    )
    assert verdict["plant_ok"] is True, verdict["reasons"]
    assert verdict["reachable"] is True, verdict["reach_reasons"]
    assert verdict["runs"] == 2
    assert verdict["head_bytes"] == PAD
    assert verdict["gap_bytes"] == PAD
    assert verdict["tail_bytes"] == size - PAD
    assert verdict["grid_bytes"] == K
    assert verdict["max_search_window"] == MAX_SEARCH_WINDOW
    assert "gap_candidates_needed" not in verdict, (
        "reach is a byte window now; a step count would describe the old search"
    )
    assert verdict["reasons"] == [] and verdict["reach_reasons"] == []


def test_the_finding_1_split_is_reachable_on_its_own_512_byte_grid(
    harness: ModuleType,
) -> None:
    """PREFLIGHT2 FINDING 1's runs: off the 4096 grid, on the volume's own.

    The old verdict called this unreachable because the search walked 4096-byte
    steps whatever the volume was. The search now walks the volume's cluster
    size, so this plant is one it can recover - and one where a fabricated
    object would be a defect rather than a documented limit.
    """
    runs = _runs((266_937_856, 65_536), (267_069_440, 8_704))

    verdict = harness.judge_fragment_plant(runs, size=73_870, cluster_bytes=512)

    assert verdict["gap_bytes"] == 66_048
    assert verdict["grid_bytes"] == 512
    assert verdict["reachable"] is True, verdict["reach_reasons"]


def test_an_unknown_cluster_size_judges_on_the_sector_grid(harness: ModuleType) -> None:
    verdict = harness.judge_fragment_plant(
        _runs((0, PAD), (2 * PAD + 512, 12 * K)), size=100_000, cluster_bytes=None
    )
    assert verdict["grid_bytes"] == 512
    assert verdict["reachable"] is True, verdict["reach_reasons"]


@pytest.mark.parametrize(
    ("runs", "reason"),
    [
        pytest.param(_runs((0, 32 * K)), "1 run", id="contiguous"),
        pytest.param(
            _runs((0, 4 * K), (8 * K, 4 * K), (16 * K, 32 * K)), "3 runs", id="three"
        ),
    ],
)
def test_anything_but_two_runs_is_a_failed_plant(
    harness: ModuleType, runs: list[dict[str, int]], reason: str
) -> None:
    """The brief's step 4: one run, or more than two, and the pass stops."""
    verdict = harness.judge_fragment_plant(runs, size=100_000, cluster_bytes=K)
    assert verdict["plant_ok"] is False
    assert verdict["reachable"] is False
    assert reason in " ".join(verdict["reasons"]), verdict["reasons"]


@pytest.mark.parametrize(
    ("runs", "size", "reason"),
    [
        pytest.param(
            _runs((40 * K, PAD), (0, 12 * K)), 100_000, "before", id="tail-first"
        ),
        pytest.param(
            _runs((0, PAD), (PAD + PAD + 512, 12 * K)),
            100_000,
            "4096",
            id="gap-off-grid",
        ),
        pytest.param(
            _runs((0, PAD + 512), (PAD + 512 + PAD, 12 * K)),
            100_000,
            "4096",
            id="head-off-grid",
        ),
        pytest.param(
            _runs((0, PAD), (PAD + 9 * 1024 * K, 12 * K)),
            100_000,
            "window",
            id="too-far",
        ),
        pytest.param(
            _runs((0, PAD), (2 * PAD, K)), PAD + 2, "tail", id="tail-is-only-the-eoi"
        ),
    ],
)
def test_a_two_run_plant_the_search_cannot_recover_is_kept_and_labelled(
    harness: ModuleType, runs: list[dict[str, int]], size: int, reason: str
) -> None:
    """Not a failed plant: a genuine bifragmented object the reassembler cannot recover.

    Measured on a loopback FAT32 volume: a plant whose gap the search could not
    enumerate made the reassembler of ``hwval-run4`` join the real head to a
    partial tail and score it HIGH, matching nothing planted. Refusing such a
    pass would hide whether that still happens. It proceeds, labelled.
    """
    verdict = harness.judge_fragment_plant(runs, size=size, cluster_bytes=K)
    assert verdict["plant_ok"] is True, verdict["reasons"]
    assert verdict["reachable"] is False
    assert reason in " ".join(verdict["reach_reasons"]), verdict["reach_reasons"]


# --------------------------------------------------------------------------
# the planner, against a simulated volume
# --------------------------------------------------------------------------


class FakeVolume:
    """Free space is capacity minus what the files in ``root`` occupy."""

    def __init__(self, root: Path, capacity: int, cluster: int = K) -> None:
        self.root = root
        self.capacity = capacity
        self.cluster = cluster

    def statvfs(self, _path: Any) -> SimpleNamespace:
        used = sum(
            math.ceil(item.stat().st_size / self.cluster) * self.cluster
            for item in self.root.iterdir()
            if item.is_file()
        )
        free = max(self.capacity - used, 0)
        return SimpleNamespace(f_bavail=free // self.cluster, f_frsize=self.cluster)


def test_the_planner_fills_the_volume_and_frees_two_pads_around_a_live_one(
    harness: ModuleType, tmp_path: Path
) -> None:
    (tmp_path / "fill00000.bin").write_bytes(bytes(8 * 1024 * 1024))
    volume = FakeVolume(tmp_path, capacity=12 * 1024 * 1024)
    names_at_each_measurement: list[set[str]] = []

    def statvfs(path: Any) -> SimpleNamespace:
        names_at_each_measurement.append({item.name for item in tmp_path.iterdir()})
        return volume.statvfs(path)

    plant = harness.plant_fragmented(tmp_path, statvfs=statvfs)

    jpeg = tmp_path / plant["jpeg"]
    assert jpeg.read_bytes() == harness.fragment_jpeg_bytes()
    first, gap, second = plant["freed"][0], plant["gap_file"], plant["freed"][1]
    assert not (tmp_path / first).exists() and not (tmp_path / second).exists()
    assert (tmp_path / gap).stat().st_size == harness.FRAG_PAD_BYTES
    assert plant["pad_order"].index(gap) == plant["pad_order"].index(first) + 1
    assert plant["pad_order"].index(second) == plant["pad_order"].index(gap) + 1
    # Every file the plant left on the volume is named, so a quick format can
    # count it and a manifest can find it.
    live = sorted(
        item.name for item in tmp_path.iterdir() if item.name != "fill00000.bin"
    )
    assert sorted(plant["files"]) == live
    # Before the JPEG was written the only free space was the two holes.
    assert plant["free_bytes_before_jpeg"] == 2 * harness.FRAG_PAD_BYTES
    assert plant["jpeg_sha256"]
    # Every name the plant writes data into existed before the first byte of
    # fill: a directory that grows mid-fill puts its new cluster between the
    # pads, which is what knocked the first loopback plant off the grid.
    # The first measurement sizes the placeholders; the second is the first
    # fill decision, taken before any data has been written.
    existed = names_at_each_measurement[1]
    assert set(plant["files"]) | set(plant["freed"]) <= existed
    assert not [p for p in tmp_path.iterdir() if p.stat().st_size == 0]


def test_the_planner_refuses_a_volume_too_full_to_leave_three_pads(
    harness: ModuleType, tmp_path: Path
) -> None:
    (tmp_path / "fill00000.bin").write_bytes(bytes(1024 * 1024))
    volume = FakeVolume(tmp_path, capacity=1024 * 1024 + 2 * PAD)

    with pytest.raises(harness.PlantAborted, match="pad"):
        harness.plant_fragmented(tmp_path, statvfs=volume.statvfs)


# --------------------------------------------------------------------------
# verification against a real volume image, and the compare row
# --------------------------------------------------------------------------


@pytest.mark.skipif(
    __import__("shutil").which("mcopy") is None,
    reason="mtools builds the FAT32 image; not installed",
)
def test_verify_refuses_a_plant_that_is_not_two_runs_and_annotates_the_manifest(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    """testkit fragments into several holes, which is exactly what must be refused."""
    import hashlib
    import json

    from testkit.fsimage import PlantedFile, build_fat32

    payload = harness.fragment_jpeg_bytes()
    image = tmp_path / "fat32.img"
    # 32 KiB holes, so the builder has to spread the JPEG across three or more
    # of them: the multi-run layout verification must refuse.
    build_fat32(
        image,
        [PlantedFile(harness.FRAG_JPEG_NAME, payload, fragmented=True)],
        filler_bytes=32 * 1024,
        scratch=tmp_path / "scratch",
    )
    plant = tmp_path / "plant.json"
    plant.write_text(
        json.dumps(
            {
                "jpeg": harness.FRAG_JPEG_NAME,
                "jpeg_sha256": hashlib.sha256(payload).hexdigest(),
                "gap_file": "none.bin",
            }
        )
    )
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                harness.FRAG_JPEG_NAME: {
                    "name": harness.FRAG_JPEG_NAME,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "deleted": False,
                }
            }
        )
    )

    args = SimpleNamespace(
        device=str(image), plant_json=str(plant), manifest=str(manifest)
    )
    capsys.readouterr()
    code = harness.cmd_fragment_verify(args)
    out = json.loads(capsys.readouterr().out)

    runs = out["jpeg_runs"]
    assert len(runs) > 1
    assert out["verdict"]["on_disk_sha256_matches"] is True
    if len(runs) != 2:
        assert code == 1
        assert out["verdict"]["plant_ok"] is False
        assert f"{len(runs)} runs" in " ".join(out["verdict"]["reasons"])
    entry = json.loads(manifest.read_text())[harness.FRAG_JPEG_NAME]
    assert entry["extent_count"] == len(runs)
    assert entry["runs"] == runs
    assert entry["cluster_bytes"] == 512
    assert entry["fragment_plant_role"] == "fragmented_jpeg"


def test_a_fragment_plant_pass_has_no_calibration_baseline(
    harness: ModuleType, tmp_path: Path, capsys: Any
) -> None:
    import json

    carve = tmp_path / "carve.json"
    carve.write_text(
        json.dumps(
            {
                "damage": "delete",
                "population": "fragment-plant",
                "pipeline": "undelete+signature",
                "per_filesystem": {
                    "fat32": {
                        "deleted_planted": 460,
                        "exact": 460,
                        "recall_bp": 10000,
                        "precision_bp": 10000,
                    }
                },
            }
        )
    )
    args = SimpleNamespace(
        carve_json=[str(carve)],
        calibration_csv=str(
            REPO / "docs" / "performance" / "calibration-filesystems.csv"
        ),
    )
    capsys.readouterr()
    assert harness.cmd_compare(args) == 0
    row = json.loads(capsys.readouterr().out)["rows"][0]
    assert row["status"] == "no_baseline"
    assert "fragment-plant" in row["note"]


def test_a_jpeg_that_cannot_be_written_is_a_refused_plant_not_a_traceback(
    harness: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Measured on a loopback exFAT volume with 32 KiB clusters: ENOSPC on the
    JPEG write escaped as a raw traceback and the harness had nothing to print.
    """
    import errno

    (tmp_path / "fill00000.bin").write_bytes(bytes(8 * 1024 * 1024))
    volume = FakeVolume(tmp_path, capacity=12 * 1024 * 1024)
    real_open = Path.open

    class FullVolumeHandle:
        """Accepts the empty placeholder; refuses the JPEG's bytes, as exFAT did."""

        def __init__(self, handle: Any) -> None:
            self.handle = handle

        def __enter__(self) -> FullVolumeHandle:
            return self

        def __exit__(self, *exc: object) -> None:
            self.handle.close()

        def write(self, data: bytes) -> int:
            if data:
                raise OSError(errno.ENOSPC, "No space left on device")
            return 0

        def flush(self) -> None:
            self.handle.flush()

        def fileno(self) -> int:
            return int(self.handle.fileno())

    def refusing_open(self: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        handle = real_open(self, mode, *args, **kwargs)
        if self.name == harness.FRAG_JPEG_NAME and "w" in mode:
            return FullVolumeHandle(handle)
        return handle

    monkeypatch.setattr(Path, "open", refusing_open)
    with pytest.raises(harness.PlantAborted, match="bytes free"):
        harness.plant_fragmented(tmp_path, statvfs=volume.statvfs)
