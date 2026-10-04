"""The work directory guard: refuse memory-backed and undersized volumes.

A demo reset writes its PhotoRec recup tree under a temporary directory. On a
host where ``/tmp`` is tmpfs that tree is written into RAM, and PhotoRec's
dovecot signature emits one 81,920-byte file per all-zero 80 KiB block, so a
device holding ``0x00`` produces a tree roughly the size of the device. Nothing
fails: the host swaps, and a swapping host presents as 1% CPU, no progress and a
clean dmesg. Forty minutes of a rehearsal window went into looking for a hang
that was a full memory disk.

The first version of this guard printed a warning. These tests exist because a
warning read at 2am is not a guard, so both checks now refuse:

* a memory-backed ``TMPDIR`` relocates to a disk-backed fallback, and refuses
  outright when the fallback is memory too;
* a volume with less free space than the scanned device is a refusal before the
  first destructive step, not an ENOSPC in a log nobody is reading.

No real ``df``, no device. A stub on PATH stands in for the filesystem.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

STEPS = Path(__file__).resolve().parents[2] / "scripts" / "harness-steps.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None, reason="bash is not available"
)

#: A `df` that answers from the environment instead of from the kernel, so a
#: tmpfs and a full volume can both be staged without either one existing.
DF_STUB = """#!/usr/bin/env bash
mode="$1"; shift
[[ "${1:-}" == "-B1" ]] && shift
target="${1:-}"
if [[ "$mode" == "--output=fstype" ]]; then
    printf 'Type\\n'
    for prefix in ${FAKE_TMPFS:-}; do
        if [[ "$target" == "$prefix" || "$target" == "$prefix"/* ]]; then
            printf 'tmpfs\\n'; exit 0
        fi
    done
    printf 'ext4\\n'
    exit 0
fi
printf 'Avail\\n%s\\n' "${FAKE_AVAIL:-999999999999}"
"""


def stub_bin(tmp_path: Path, name: str, body: str) -> Path:
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir(exist_ok=True)
    script = binary_dir / name
    shebang = "" if body.startswith("#!") else "#!/usr/bin/env bash\n"
    script.write_text(f"{shebang}{body}\n")
    script.chmod(0o755)
    return binary_dir


def run_bash(
    script: str,
    tmp_path: Path,
    *,
    path_prefix: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    prefix = f'export PATH="{path_prefix}:$PATH"\n' if path_prefix else ""
    body = (
        f'set -uo pipefail\nPY="{shutil.which("python3")}"\n'
        f'{prefix}. "{STEPS}"\n{script}\n'
    )
    return subprocess.run(
        ["bash", "-c", body],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        check=False,
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), **(env or {})},
    )


def staged(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A memory-backed TMPDIR, a disk-backed fallback, and the `df` stub."""
    memory = tmp_path / "mem"
    disk = tmp_path / "disk"
    memory.mkdir()
    disk.mkdir()
    return memory, disk, stub_bin(tmp_path, "df", DF_STUB)


# --------------------------------------------------------------------------
# The filesystem check
# --------------------------------------------------------------------------


def test_a_memory_backed_tmpdir_is_relocated_to_the_disk_fallback(
    tmp_path: Path,
) -> None:
    memory, disk, binary_dir = staged(tmp_path)
    result = run_bash(
        'harness_workdir 0; printf "rc=%s dir=%s" "$?" "$HARNESS_WORKDIR"',
        tmp_path,
        path_prefix=binary_dir,
        env={
            "TMPDIR": str(memory),
            "HARNESS_WORKDIR_FALLBACK": str(disk),
            "FAKE_TMPFS": str(memory),
        },
    )
    assert "rc=0" in result.stdout
    assert f"dir={disk}/" in result.stdout
    assert "relocated" in result.stdout
    # The reason is printed, not just the destination. An operator who reads
    # "relocated" and nothing else learns nothing about why /tmp was wrong.
    assert "memory, not disk" in result.stdout


def test_a_memory_backed_fallback_is_refused_rather_than_used(tmp_path: Path) -> None:
    """Relocation is not a fix when there is nowhere disk-backed to relocate to."""
    memory, disk, binary_dir = staged(tmp_path)
    result = run_bash(
        'harness_workdir 0; printf "rc=%s dir=[%s]" "$?" "$HARNESS_WORKDIR"',
        tmp_path,
        path_prefix=binary_dir,
        env={
            "TMPDIR": str(memory),
            "HARNESS_WORKDIR_FALLBACK": str(disk),
            "FAKE_TMPFS": f"{memory} {disk}",
        },
    )
    assert "rc=1" in result.stdout
    assert "dir=[]" in result.stdout
    assert "Set TMPDIR to a real" in result.stdout


def test_a_disk_backed_tmpdir_is_used_as_it_is(tmp_path: Path) -> None:
    memory, disk, binary_dir = staged(tmp_path)
    result = run_bash(
        'harness_workdir 0; printf "rc=%s dir=%s" "$?" "$HARNESS_WORKDIR"',
        tmp_path,
        path_prefix=binary_dir,
        env={
            "TMPDIR": str(memory),
            "HARNESS_WORKDIR_FALLBACK": str(disk),
            "FAKE_TMPFS": "",
        },
    )
    assert "rc=0" in result.stdout
    assert f"dir={memory}/" in result.stdout
    assert "relocated" not in result.stdout


# --------------------------------------------------------------------------
# The size check
# --------------------------------------------------------------------------


def test_a_volume_smaller_than_the_device_is_refused_before_anything_runs(
    tmp_path: Path,
) -> None:
    """The recup tree can reach the size of the device it was carved from."""
    memory, disk, binary_dir = staged(tmp_path)
    result = run_bash(
        'harness_workdir 7758413824; printf "rc=%s dir=[%s]" "$?" "$HARNESS_WORKDIR"',
        tmp_path,
        path_prefix=binary_dir,
        env={
            "TMPDIR": str(memory),
            "HARNESS_WORKDIR_FALLBACK": str(disk),
            "FAKE_TMPFS": "",
            "FAKE_AVAIL": "1000000000",
        },
    )
    assert "rc=1" in result.stdout
    assert "dir=[]" in result.stdout
    assert "1.00 GB free" in result.stdout
    assert "7.76 GB" in result.stdout


def test_a_volume_larger_than_the_device_is_accepted(tmp_path: Path) -> None:
    memory, disk, binary_dir = staged(tmp_path)
    result = run_bash(
        'harness_workdir 7758413824; printf "rc=%s" "$?"',
        tmp_path,
        path_prefix=binary_dir,
        env={
            "TMPDIR": str(memory),
            "HARNESS_WORKDIR_FALLBACK": str(disk),
            "FAKE_TMPFS": "",
            "FAKE_AVAIL": "20000000000",
        },
    )
    assert "rc=0" in result.stdout


def test_an_unreadable_df_fails_the_size_check_rather_than_passing_it(
    tmp_path: Path,
) -> None:
    """0 bytes free is the safe reading of "df said nothing I could parse"."""
    memory, disk, _ = staged(tmp_path)
    binary_dir = stub_bin(tmp_path, "df", "printf 'Type\\next4\\n'")
    result = run_bash(
        'harness_workdir 4096; printf "rc=%s" "$?"',
        tmp_path,
        path_prefix=binary_dir,
        env={"TMPDIR": str(memory), "HARNESS_WORKDIR_FALLBACK": str(disk)},
    )
    assert "rc=1" in result.stdout


# --------------------------------------------------------------------------
# The same two checks, at the PhotoRec call
# --------------------------------------------------------------------------


def read_json(path: Path) -> dict:
    return json.loads(path.read_text())


def test_photorec_refuses_a_memory_backed_output_directory(tmp_path: Path) -> None:
    """Defence in depth: harness_photorec is called with directories the work
    directory guard never chose, including hardware-validation.sh's run dir."""
    stub_bin(tmp_path, "df", DF_STUB)
    binary_dir = stub_bin(tmp_path, "photorec", 'touch "$PWD/photorec-ran"; exit 0')
    result = run_bash(
        "harness_photorec before /dev/null out scan.json\n"
        'printf "rc=%s failures=%s" "$?" "$(harness_failure_count)"',
        tmp_path,
        path_prefix=binary_dir,
        env={"FAKE_TMPFS": "out"},
    )
    assert "rc=1" in result.stdout
    assert "failures=1" in result.stdout
    assert not (tmp_path / "photorec-ran").exists()
    # A skip and a clean device must not produce the same number.
    assert "memory-backed" in read_json(tmp_path / "scan.json")["skipped"]


def test_photorec_refuses_an_output_volume_smaller_than_the_device(
    tmp_path: Path,
) -> None:
    stub_bin(tmp_path, "df", DF_STUB)
    binary_dir = stub_bin(tmp_path, "photorec", 'touch "$PWD/photorec-ran"; exit 0')
    device = tmp_path / "device.img"
    device.write_bytes(b"\0" * 4096)
    result = run_bash(
        f"harness_photorec before {device} out scan.json\n"
        'printf "rc=%s failures=%s" "$?" "$(harness_failure_count)"',
        tmp_path,
        path_prefix=binary_dir,
        env={"FAKE_TMPFS": "", "FAKE_AVAIL": "512"},
    )
    assert "rc=1" in result.stdout
    assert "failures=1" in result.stdout
    assert not (tmp_path / "photorec-ran").exists()
    assert read_json(tmp_path / "scan.json")["skipped"] == (
        "insufficient free space at output directory"
    )
