"""The suite's host-device guard refuses what it says it refuses, on each host.

Three kinds of test, and what each one proves:

* **Decision tests** call the guard's decision functions with a rule set named
  explicitly. They run on every host, for the Linux, macOS and Windows rule
  sets alike, and open and launch nothing: they validate the guard's
  *decision*, not the execution of any command.
* **Event tests** raise, with :func:`sys.audit`, the audit events CPython
  raises on each host - the same event names and argument shapes, such as the
  ``cmd.exe /c "..."`` line :mod:`subprocess` builds on Windows for
  ``shell=True`` - with that host's rule set selected for the length of the
  call. They prove the hook refuses before anything runs; ``sys.audit`` itself
  runs nothing.
* **Live tests** go through the real APIs - ``open``, ``os.open``,
  ``subprocess.run`` with a list and with ``shell=True``, ``os.system``,
  ``glob`` - under the rules of the host running the suite, inside
  :func:`launch_barrier`. The barrier stops anything the guard lets through
  before it happens, so a broken guard fails the test with ``BarrierReached``;
  it cannot run a disk command or open a device. Linux and macOS raise the
  same POSIX events, so the Linux and macOS live tests both run on either of
  those hosts, the matching rules borrowed for the call; the Windows ones run
  on Windows.

No test here touches a physical device. Refused targets are synthetic
(``/dev/sdzz9``, ``disk99``), or real-looking where that is the point
(``/dev/disk0``, ``PhysicalDrive0``) and then stopped by the guard with the
barrier behind it. Destructive command forms appear only in decision tests.
Each refusal is taken off ``BLOCKED`` by the test that caused it, so the
session-end verdict counts only unexpected ones.
"""

from __future__ import annotations

import base64
import glob
import json
import os
import plistlib
import subprocess
import sys
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

import pytest
from core.device._sysio import CommandResult
from core.errors import PlatformUnsupported
from core.platform.macos import DISKUTIL, MacOSAdapter
from core.platform.windows import WindowsAdapter, encoded_script

from tests import _host_device_guard as guard
from tests._host_device_guard import (
    ALLOWED_DISKS,
    LINUX,
    MACOS,
    RULE_SETS,
    WINDOWS,
    BarrierReached,
    HostDeviceAccessBlocked,
    command_reason,
    expect_refusal,
    launch_barrier,
    media_reason,
    path_reason,
    rules_for_platform,
    shell_reason,
    summary_lines,
)

HOST = rules_for_platform(sys.platform)


def _encoded(script: str) -> str:
    """``script`` as PowerShell's ``-EncodedCommand`` wants it."""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def _ids(value: Any) -> str:
    text = value if isinstance(value, str) else repr(value)
    return text[:60]


@contextmanager
def rules(host: str | None) -> Iterator[None]:
    """The hook applies ``host``'s rules for the length of the block.

    Kept to one ``sys.audit`` call: anything else the process does meanwhile
    is judged by the borrowed rules too.
    """
    previous = guard.ACTIVE
    guard.ACTIVE = host
    try:
        yield
    finally:
        guard.ACTIVE = previous


@contextmanager
def refused_once() -> Iterator[None]:
    with expect_refusal() as taken, pytest.raises(HostDeviceAccessBlocked):
        yield
    assert len(taken) == 1, taken


@contextmanager
def refused_live() -> Iterator[None]:
    """Refused by the guard, with the barrier behind it."""
    with refused_once(), launch_barrier():
        yield


def live_on(*hosts: str) -> pytest.MarkDecorator:
    names = " or ".join(RULE_SETS[host] for host in hosts)
    return pytest.mark.skipif(
        HOST not in hosts,
        reason=(
            f"drives the real APIs, which raise the audit events of a {names} "
            "host only on one; the decision and event tests check the same rules "
            "on every host"
        ),
    )


# --------------------------------------------------------------------------
# Rule sets and the summary
# --------------------------------------------------------------------------


def test_each_host_gets_its_own_rule_set() -> None:
    assert rules_for_platform("linux") == LINUX
    assert rules_for_platform("darwin") == MACOS
    assert rules_for_platform("win32") == WINDOWS
    assert rules_for_platform("freebsd14") is None
    assert rules_for_platform("cygwin") is None
    assert guard.ACTIVE == HOST


@pytest.mark.parametrize(
    "host, name", [(LINUX, "Linux"), (MACOS, "macOS"), (WINDOWS, "Windows")]
)
def test_the_summary_names_the_rule_set_that_was_active(host: str, name: str) -> None:
    with rules(host):
        lines = summary_lines()
    assert lines[0] == f"Host-device guard: {name} rules active"
    assert "refusal(s)" in lines[1]
    assert not any("pass" in line.casefold() for line in lines)


def test_a_host_with_no_rule_set_is_reported_as_unprotected() -> None:
    with rules(None):
        lines = summary_lines()
    assert lines == [
        "Host-device guard: no rules active - there is no rule set for "
        f"sys.platform {sys.platform!r}, so no host device is refused here"
    ]


def test_the_terminal_summary_prints_this_hosts_rule_set() -> None:
    from tests import conftest

    class Reporter:
        def __init__(self) -> None:
            self.lines: list[str] = []

        def write_line(self, line: str) -> None:
            self.lines.append(line)

        def section(self, title: str, **_: Any) -> None:
            self.lines.append(title)

        def line(self, text: str) -> None:
            self.lines.append(text)

    reporter = Reporter()
    conftest.pytest_terminal_summary(reporter)  # type: ignore[arg-type]

    assert reporter.lines[: len(summary_lines())] == summary_lines()
    if HOST is not None:
        assert reporter.lines[0] == f"Host-device guard: {RULE_SETS[HOST]} rules active"


def test_the_rule_sets_are_separate() -> None:
    """Each set names its own host's devices; none claims another's."""
    assert path_reason("/dev/disk0", LINUX) is None
    assert path_reason(r"\\.\PhysicalDrive0", LINUX) is None
    assert path_reason("/dev/sda", MACOS) is None
    assert path_reason("/dev/sda", WINDOWS) is None
    assert command_reason(["diskutil", "list"], LINUX) is None
    assert command_reason(["diskpart"], MACOS) is None
    assert path_reason("/dev/sda", None) == path_reason("/dev/sda", HOST)


def test_expect_refusal_fails_when_nothing_is_refused() -> None:
    with pytest.raises(AssertionError, match="refused nothing"), expect_refusal():
        pass


# --------------------------------------------------------------------------
# Decisions: paths
# --------------------------------------------------------------------------

_CLIMB = "/".join([".."] * 64)

LINUX_REFUSED_PATHS: list[Any] = [
    "/dev/sda", "/dev/sdb1", "/dev/sdzz9", "/dev/hda", "/dev/vda2", "/dev/xvda1",
    "/dev/nvme0", "/dev/nvme0n1", "/dev/nvme0n1p2", "/dev/ng0n1", "/dev/mmcblk0",
    "/dev/mmcblk0p1", "/dev/mmcblk0boot0", "/dev/mmcblk0rpmb", "/dev/sr0",
    "/dev/sg0", "/dev/dm-0", "/dev/md0", "/dev/md127p1",
    "/dev/disk/by-id/usb-SANCTUM_SELFTEST", "/dev/disk/by-uuid/0000",
    "/dev/mapper/root", "/dev/block/8:0", "/dev/bsg/0:0:0:0", "/proc/partitions",
    "/proc/diskstats", "/proc/scsi/scsi", "/sys/block", "/sys/block/sdzz9/size",
    "/sys/class/block/nvme9n9/removable", "/sys/dev/block/0:0",
    "/run/udev/data/b8:0", "/sys/bus/usb/devices", "/sys/class/nvme/nvme0",
    # The same nodes spelled differently.
    "//dev/sdzz9", "///dev/sdzz9", "/dev//sdzz9", "/dev/./sdzz9",
    "/dev/../dev/sdzz9", "/tmp/../dev/sdzz9", "/sys/block/../block/sdzz9/size",
    f"{_CLIMB}/dev/sdzz9", b"/dev/sdzz9", PurePosixPath("/dev/nvme9n9"),
]  # fmt: skip
LINUX_ALLOWED_PATHS: list[Any] = [
    "/dev/null", "/dev/zero", "/dev/urandom", "/dev/random", "/dev/loop7",
    "/dev/loop-control", "/dev/shm/sanctum", "/dev/pts/0",
    "/proc/self/mountinfo", "/sys/block/loop7/queue/rotational",
    "/home/examiner/dev/sda", "/tmp/dev/sda", "sda", "/dev/diskette", 3,
]  # fmt: skip

MACOS_REFUSED_PATHS: list[Any] = [
    "/dev/disk0", "/dev/disk1", "/dev/rdisk0", "/dev/rdisk1", "/dev/disk2s1",
    "/dev/rdisk2s1", "/dev/disk3s1s1", "/dev/disk10", "/dev/rdisk99s2",
    # Case: the root volume is case-insensitive.
    "/DEV/DISK0", "/dev/Disk0", "/Dev/rdisk3", "/dev/RDISK4S2",
    # The same nodes spelled differently.
    "//dev/disk0", "/dev//rdisk0", "/dev/./disk0", "/private/../dev/disk0",
    f"{_CLIMB}/dev/disk0", b"/dev/rdisk0", PurePosixPath("/dev/disk2s1"),
    # Mounted volumes other than the suite's.
    "/Volumes", "/Volumes/SANCTUM_SELFTEST", "/Volumes/SANCTUM_SELFTEST/DCIM/1.jpg",
    "/volumes/sanctum_selftest/x",
]  # fmt: skip
MACOS_ALLOWED_PATHS: list[Any] = [
    "/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/disk",
    "/dev/diskette", "/Users/examiner/disk0", "/tmp/rdisk2",
    "/private/var/folders/xy/T/disk2s1.img", "/Library/Caches/x", 3,
]  # fmt: skip

_VOLUME_GUID = "Volume{0f9b8c1a-5b6c-11ef-a1b2-806e6f6e6963}"
WINDOWS_REFUSED_PATHS: list[Any] = [
    r"\\.\PhysicalDrive0", r"\\.\PhysicalDrive1", r"\\.\PhysicalDrive17",
    r"\\.\PhysicalDrive", r"\\.\PHYSICALDRIVE0", r"\\.\physicaldrive2",
    "//./PhysicalDrive0", "//./physicaldrive1", r"\\?\PhysicalDrive0",
    r"\??\PhysicalDrive0", r"\\.\\PhysicalDrive0", "\\\\.\\PhysicalDrive0\\",
    r"\\.\PhysicalDrive0.", "\\\\.\\PhysicalDrive0 ", r"\\.\C:\..\PhysicalDrive0",
    r"\\?\GLOBALROOT\Device\Harddisk0\DR0",
    r"\\.\GLOBALROOT\Device\Harddisk0\Partition1", r"\\.\Harddisk0Partition1",
    r"\\.\HarddiskVolume3", r"\\.\HarddiskVolumeShadowCopy1",
    # Raw volumes: a drive or volume with no path after it.
    r"\\.\C:", r"\\.\c:", r"\\?\D:", "//./E:", "\\\\.\\C: ",
    f"\\\\.\\{_VOLUME_GUID}", f"\\\\?\\{_VOLUME_GUID}",
    r"\\?\scsi#disk&ven_sanctum&prod_selftest#4&1a2b3c&0&000000"
    r"#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}",
    r"\\.\CdRom0", r"\\.\Tape0", r"\\.\Scsi0:", r"\\.\MountPointManager",
    r"\Device\Harddisk0\DR0", r"\Device\HarddiskVolume1",
    b"\\\\.\\PhysicalDrive0", PureWindowsPath(r"\\.\PhysicalDrive0"),
]  # fmt: skip
WINDOWS_ALLOWED_PATHS: list[Any] = [
    r"C:\Users\runner\AppData\Local\Temp\pytest-1\disk.img",
    r"\\?\C:\Users\runner\long\path.txt", r"\\?\UNC\server\share\f.bin",
    r"\\server\share\f.bin", r"\\.\pipe\sanctum-helper", r"\\.\NUL", "NUL",
    "CON", r"\\.\C:\Windows\Temp\x", "\\\\?\\C:\\", f"\\\\?\\{_VOLUME_GUID}\\f.txt",
    r"C:\data\PhysicalDrive0.img", "PhysicalDrive2", "/dev/sda", 3,
]  # fmt: skip


@pytest.mark.parametrize(
    "host, path",
    [(LINUX, path) for path in LINUX_REFUSED_PATHS]
    + [(MACOS, path) for path in MACOS_REFUSED_PATHS]
    + [(WINDOWS, path) for path in WINDOWS_REFUSED_PATHS],
    ids=_ids,
)
def test_device_paths_are_refused(host: str, path: Any) -> None:
    assert path_reason(path, host), path


@pytest.mark.parametrize(
    "host, path",
    [(LINUX, path) for path in LINUX_ALLOWED_PATHS]
    + [(MACOS, path) for path in MACOS_ALLOWED_PATHS]
    + [(WINDOWS, path) for path in WINDOWS_ALLOWED_PATHS],
    ids=_ids,
)
def test_ordinary_paths_stay_allowed(host: str, path: Any) -> None:
    assert path_reason(path, host) is None, path


def test_only_the_disk_holding_the_suite_is_readable_in_sysfs() -> None:
    for name in ALLOWED_DISKS:
        assert path_reason(f"/sys/block/{name}/queue/rotational", LINUX) is None
        assert path_reason(f"/dev/{name}", LINUX) is not None, "its node is refused"
    assert "sdzz9" not in ALLOWED_DISKS
    assert path_reason("/sys/block/sdzz9/queue/rotational", LINUX) is not None
    assert path_reason("/sys/block", LINUX) is not None, "listing the tree is discovery"


def test_only_the_volume_holding_the_suite_is_readable_on_macos(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(guard, "ALLOWED_VOLUMES", frozenset({"work"}))
    assert path_reason("/Volumes/Work/sanctum/tests/conftest.py", MACOS) is None
    assert path_reason("/Volumes/Other/DCIM/1.jpg", MACOS) is not None
    assert path_reason("/Volumes", MACOS) is not None, "the listing"


def test_removable_media_is_refused_unless_it_is_a_loop_volume() -> None:
    mounts = [
        ("/run/media/someone/LOOPVOL", "/dev/loop7"),
        ("/run/media/someone/STICK", "/dev/sdzz9"),
        ("/run", "tmpfs"),
        ("/", "/dev/nvme9n9p1"),
    ]
    assert media_reason("/run/media/someone/LOOPVOL/file.bin", mounts) is None
    assert media_reason("/run/media/someone/STICK/img01.jpg", mounts) is not None
    assert media_reason("/run/media/someone", mounts) is not None, "the listing"


@pytest.mark.skipif(
    os.name != "posix",
    reason="symlinks are followed on POSIX hosts only: on Windows resolving a "
    "reparse point opens its target, so the guard does not (a stated limitation)",
)
@pytest.mark.parametrize(
    "host, target", [(LINUX, "/dev/sdzz9"), (MACOS, "/dev/rdisk99")]
)
def test_a_symlink_is_judged_by_where_it_leads(
    tmp_path: Path, host: str, target: str
) -> None:
    link = tmp_path / "innocent.img"
    link.symlink_to(target)
    assert path_reason(str(link), host)
    assert command_reason(["dd", f"if={link}", "of=/dev/null"], host)
    assert shell_reason(f"head -c 512 < {link}", host)


# --------------------------------------------------------------------------
# Decisions: commands
# --------------------------------------------------------------------------

#: The Windows adapter's own discovery command, as core/platform/windows.py
#: builds it: PowerShell 5.1 by absolute path, the inventory script encoded.
WINDOWS_ADAPTER_ARGV = [
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
    "-EncodedCommand", encoded_script(),
]  # fmt: skip

LINUX_REFUSED_COMMANDS: list[Sequence[str] | str] = [
    # Discovery with no loop or image operand, or a tool naming a device.
    ["lsblk"], ["lsblk", "--version"], ["/usr/bin/lsblk", "-J", "-O"], ["blkid"],
    ["smartctl", "--scan"], ["udisksctl", "status"], ["mount"],
    ["lshw", "-class", "disk"],
    ["hdparm", "-I", "/dev/sdzz9"], ["wipefs", "-a", "/dev/sdzz9"],
    ["blkdiscard", "/dev/sdzz9"], ["sg_inq", "/dev/sg9"], ["fstrim", "-a"],
    ["dd", "if=/dev/sdzz9", "of=/dev/null"], ["dd", "of=/dev/nvme9n9"],
    ["cat", "/dev/sdzz9"], ["tee", "/dev/sdzz9"], ["file", "-s", "/dev/sdzz9"],
    ["cp", "/dev/sdzz9", "disk.img"], ["mkfs.ext4", "/dev/sdzz9"],
    ["e2fsck", "-n", "/dev/sdzz9"], ["ntfsclone", "/dev/sdzz9"],
    ["ewfacquire", "/dev/sdzz9"], ["photorec", "/dev/sdzz9"], ["mmls", "/dev/sdzz9"],
    ["losetup", "/dev/loop0", "/dev/sdzz9"], ["ls", "/dev/disk/by-id"], ["ls", "/dev"],
    ["find", "/dev", "-name", "sd*"], ["find", "/tmp", "-exec", "lsblk", ";"],
    # Wrappers, and the node spelled differently.
    ["sudo", "lsblk"], ["sudo", "-u", "root", "hdparm", "-I", "/dev/sdzz9"],
    ["env", "LC_ALL=C", "lsblk"], ["timeout", "5", "dd", "if=/dev/sdzz9"],
    ["nice", "-n", "5", "blkid"], ["xargs", "lsblk"], ["busybox", "fdisk", "-l"],
    ["nohup", "lsblk"], ["dd", "if=//dev/sdzz9"], ["cat", "/dev/./sdzz9"],
    # Shells: -c in every spelling, nesting, substitution, quoting, keywords.
    ["sh", "-c", "lsblk"], ["bash", "-lc", "lsblk"], ["bash", "-e", "-c", "lsblk -J"],
    ["bash", "-o", "pipefail", "-c", "lsblk"], ["/bin/bash", "--norc", "-c", "lsblk"],
    ["dash", "-c", "true; lsblk"], ["zsh", "-c", "true && lsblk"],
    ["sh", "-c", "echo x | lsblk"], ["sh", "-c", "(lsblk)"], ["sh", "-c", "{ lsblk; }"],
    ["sh", "-c", "if lsblk; then :; fi"], ["sh", "-c", "! lsblk"],
    ["sh", "-c", "for d in a; do lsblk; done"], ["sh", "-c", "echo $(lsblk)"],
    ["sh", "-c", 'echo "$(lsblk -J)"'], ["sh", "-c", "echo `lsblk`"],
    ["sh", "-c", "cat <(lsblk)"], ["sh", "-c", "l's'blk"], ["sh", "-c", 'l"s"blk'],
    ["sh", "-c", "\\lsblk"], ["sh", "-c", '"/usr/bin/lsblk"'],
    ["sh", "-c", "LC_ALL=C lsblk"],
    ["sh", "-c", "eval lsblk"], ["sh", "-c", "eval 'lsblk -J'"],
    ["sh", "-c", "exec lsblk"],
    ["sh", "-c", "time lsblk"], ["sh", "-c", "sh -c 'lsblk'"],
    ["sh", "-c", "bash -c \"sh -c 'hdparm -I /dev/sdzz9'\""],
    ["sudo", "sh", "-c", "lsblk"],
    ["env", "bash", "-c", "lsblk"], ["su", "-c", "lsblk", "root"],
    ["sh", "-c", "lsblk\necho '"],  # line one runs even though line two cannot parse
    # Redirections: the shell opens the device, whatever the program.
    ["sh", "-c", "head -c 512 < /dev/sdzz9"], ["sh", "-c", "cat</dev/sdzz9"],
    ["sh", "-c", "echo x > /dev/sdzz9"], ["sh", "-c", "exec 3</dev/nvme9n9"],
    ["sh", "-c", ": > //dev/sdzz9"],
    ["sh", "-c", "wc -c < /dev/disk/by-id/usb-SELFTEST"],
    # A string is a simple command, split as the shell would.
    "lsblk -J", "dd if=/dev/sdzz9 of=/dev/null",
]  # fmt: skip
LINUX_ALLOWED_COMMANDS: list[Sequence[str] | str] = [
    ["git", "status"], ["python3", "-c", "print('/dev/sda')"],
    ["lsblk", "-no", "SERIAL", "/dev/loop7"], ["dd", "if=/dev/zero", "of=/dev/null"],
    ["cat", "/dev/null"], ["mkfs.vfat", "-C", "/tmp/sanctum-new.img", "1440"],
    # The file eraser's own snapshot listings (core/erase/_platform/posix.py).
    ["btrfs", "subvolume", "list", "-s", "/tmp"],
    ["zfs", "list", "-t", "snapshot", "-H", "-o", "name"],
    # A device path handed to a function or printed is data.
    ["bash", "-c", 'source gate.sh\ngate_identity "stage usb" "/dev/sda" Model S 1'],
    ["sh", "-c", "command -v lsblk"], ["sh", "-c", "echo lsblk"],
    ["sh", "-c", "printf '%s\\n' /dev/sda"], ["sh", "-c", "echo hi > /dev/null"],
    ["sh", "-c", "grep -q mount /etc/fstab"], ["sh", "-c", "ls /tmp"],
    ["timeout", "5", "git", "status"], "git status",
]  # fmt: skip

MACOS_REFUSED_COMMANDS: list[Sequence[str] | str] = [
    # The macOS adapter's own discovery commands (core/platform/macos.py).
    [DISKUTIL, "list", "-plist"], [DISKUTIL, "apfs", "list", "-plist"],
    [DISKUTIL, "info", "-plist", "/"], [DISKUTIL, "info", "-plist", "disk4"],
    ["diskutil"], ["diskutil", "list"], ["DiskUtil", "list"],
    ["/USR/SBIN/DISKUTIL", "list"],
    ["diskutil", "eraseDisk", "JHFS+", "SANCTUM", "disk99"],
    ["diskutil", "secureErase", "0", "/dev/disk99"], ["diskutil", "zeroDisk", "disk99"],
    ["diskutil", "unmountDisk", "/dev/disk99"],
    ["asr", "restore", "--source", "x.dmg", "--target", "/Volumes/SELFTEST", "--erase"],
    ["gpt", "show", "disk99"], ["bless", "--device", "/dev/disk99s2", "--setBoot"],
    ["dd", "if=/dev/rdisk0", "of=out.img", "bs=1m"], ["dd", "of=/dev/rdisk99"],
    ["cat", "/dev/disk0"], ["cat", "/DEV/DISK0"], ["newfs_apfs", "/dev/disk99s1"],
    ["fsck_apfs", "-n", "/dev/rdisk99s1"], ["mount_apfs", "/dev/disk99s1", "/tmp/x"],
    ["fdisk", "/dev/rdisk0"], ["smartctl", "-a", "disk0"], ["mount"],
    ["umount", "/Volumes/SELFTEST"], ["hdiutil", "info"],
    ["hdiutil", "detach", "/dev/disk99"],
    ["hdiutil", "attach", "-nomount", "ram://2048"], ["ioreg", "-l"],
    ["ioreg", "-r", "-c", "IOMedia"], ["ioreg", "-c", "IONVMeController"],
    ["system_profiler"], ["system_profiler", "SPStorageDataType"],
    ["system_profiler", "SPUSBDataType", "-json"],
    ["system_profiler", "-detailLevel", "mini"],
    ["ls", "/Volumes"], ["ls", "/dev"],
    ["sudo", "diskutil", "list"], ["arch", "-x86_64", "diskutil", "list"],
    ["caffeinate", "-i", "dd", "if=/dev/rdisk0"],
    ["sh", "-c", "diskutil list"], ["zsh", "-c", "diskutil list | grep external"],
    ["bash", "-lc", "d'isk'util list"], ["sh", "-c", "head -c 512 < /dev/rdisk0"],
    ["sh", "-c", 'n="$(diskutil info -plist /)"'],
    ["sh", "-c", "dd if=/dev/rdisk0 bs=1m count=1 > out.bin"],
    "diskutil list",
]  # fmt: skip
MACOS_ALLOWED_COMMANDS: list[Sequence[str] | str] = [
    # The file eraser's own snapshot listing (core/erase/_platform/posix.py).
    ["tmutil", "listlocalsnapshots", "/private/var/folders/xy/T/pytest-1"],
    ["sw_vers"], ["git", "status"],
    ["ioreg", "-c", "IOPlatformExpertDevice", "-d", "2"],
    ["system_profiler", "SPHardwareDataType"], ["system_profiler", "-listDataTypes"],
    ["hdiutil", "create", "-size", "1m", "/tmp/sanctum-selftest.dmg"],
    ["dd", "if=/dev/zero", "of=/dev/null", "count=1"], ["sh", "-c", "echo /dev/disk0"],
]  # fmt: skip

WINDOWS_REFUSED_COMMANDS: list[Sequence[str] | str] = [
    # The Windows adapter's own discovery command, as a list and as the
    # command line CreateProcess receives.
    WINDOWS_ADAPTER_ARGV, subprocess.list2cmdline(WINDOWS_ADAPTER_ARGV),
    # PowerShell: every spelling of -Command, positional, and case.
    ["powershell", "-Command", "Get-Disk"],
    ["powershell.exe", "-c", "Get-PhysicalDisk | fl"],
    ["pwsh", "-NoProfile", "-Command", "Get-Partition"],
    ["pwsh", "-Command", "Get-Volume"],
    ["powershell", "Get-Disk"], ["PowerShell.EXE", "-COMMAND", "GET-DISK"],
    [r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "-c", "Get-Disk"],
    ["powershell", "/Command", "Get-Disk"], ["powershell", "-Command:Get-Disk"],
    ["powershell", "-ExecutionPolicy", "Bypass", "-Command", "Get-Disk"],
    ["powershell", "-w", "hidden", "-c", "Get-Disk"],
    # -EncodedCommand, decoded.
    ["powershell", "-EncodedCommand", _encoded("Get-Disk")],
    ["powershell", "-e", _encoded("Get-Disk")],
    ["powershell", "-ec", _encoded("Get-PhysicalDisk")],
    ["powershell", "-enc", _encoded("Get-D`isk")],
    # Destructive cmdlets.
    ["powershell", "-Command", "Clear-Disk -Number 99 -RemoveData -Confirm:$false"],
    ["powershell", "-Command", "Initialize-Disk -Number 99"],
    ["powershell", "-Command", "Format-Volume -DriveLetter Z"],
    ["powershell", "-Command", "Set-Disk -Number 99 -IsOffline $true"],
    ["powershell", "-Command", "New-Partition -DiskNumber 99 -UseMaximumSize"],
    ["powershell", "-Command", "Remove-Partition -DiskNumber 99 -PartitionNumber 1"],
    ["powershell", "-Command", "Get-BitLockerVolume"],
    # WMI/CIM and .NET.
    ["powershell", "-Command", "Get-CimInstance Win32_DiskDrive"],
    ["powershell", "-Command", "gwmi -Class Win32_LogicalDisk"],
    ["pwsh", "-c", "gcim -Namespace root/Microsoft/Windows/Storage MSFT_Disk"],
    ["powershell", "-Command", "Get-PnpDevice -Class DiskDrive"],
    ["powershell", "-Command", "[System.IO.DriveInfo]::GetDrives()"],
    # Escapes, quoting and indirection.
    ["powershell", "-Command", "Get-D`isk"], ["powershell", "-Command", "& 'Get-Disk'"],
    ["powershell", "-Command", 'Invoke-Expression "Get-Disk"'],
    ["powershell", "-Command", "Storage\\Get-Disk"],
    ["powershell", "-Command", "$d = Get-Disk"],
    # Device paths inside a script.
    ["powershell", "-Command", "[IO.File]::OpenRead('\\\\.\\PhysicalDrive0')"],
    ["powershell", "-Command", "Get-Content -Path \\\\.\\PhysicalDrive1 -TotalCount 1"],
    ["powershell", "-Command", "$p = '\\\\.\\PhysicalDrive' + 0"],
    ["powershell", "-Command", "[IO.File]::OpenRead('\\\\.\\C:')"],
    # External commands from PowerShell.
    ["powershell", "-Command", "Start-Process diskpart"],
    ["powershell", "-Command", "cmd /c diskpart"],
    ["powershell", "-Command", "& diskpart.exe /s x.txt"],
    ["powershell", "-Command", "wmic diskdrive get model"],
    # Disk tools.
    ["diskpart"], ["diskpart.exe", "/s", "script.txt"],
    [r"C:\Windows\System32\diskpart.exe"],
    ["DISKPART"], ["diskpart."], ["format", "Z:", "/FS:NTFS", "/Q"],
    ["format.com", "Z:"],
    ["chkdsk", "C:"], ["defrag", "C:", "/O"], ["mountvol"], ["manage-bde", "-status"],
    ["diskshadow"], ["mbr2gpt", "/validate"], ["sdelete", "-z", "Z:"],
    ["wmic", "diskdrive", "get", "serialnumber"], ["wmic", "logicaldisk", "list"],
    ["WMIC", "path", "Win32_DiskDrive", "get"], ["fsutil", "fsinfo", "drives"],
    ["fsutil", "volume", "dismount", "Z:"], ["vssadmin", "delete", "shadows", "/all"],
    ["cipher", "/w:C:\\"], ["wsl", "--mount", "\\\\.\\PhysicalDrive1"],
    ["dd", "if=\\\\.\\PhysicalDrive0", "of=disk.img"],
    ["certutil", "-hashfile", "\\\\.\\PhysicalDrive0"],
    ["robocopy", "\\\\.\\C:", "out"],
    # cmd.exe: separators, escapes, wrappers, redirections, switches.
    ["cmd", "/c", "diskpart"], ["cmd.exe", "/C", "wmic diskdrive get model"],
    ["cmd", "/c", "d^iskpart"], ["cmd", "/c", "echo x & diskpart"],
    ["cmd", "/c", "echo x && diskpart"], ["cmd", "/c", "echo x | diskpart"],
    ["cmd", "/c", '(echo x) & ("diskpart")'], ["cmd", "/c", 'start "" /b diskpart'],
    ["cmd", "/c", "call diskpart"], ["cmd", "/c", "@diskpart"],
    ["cmd", "/c", "powershell -Command Get-Disk"],
    ["cmd", "/c", "type \\\\.\\PhysicalDrive0 > out.bin"],
    ["cmd", "/c", "echo x > \\\\.\\PhysicalDrive1"],
    ["cmd", "/c", "more < \\\\.\\PhysicalDrive0"], ["cmd", "/cdiskpart"],
    ["cmd", "/q", "/d", "/c", "diskpart"], ["cmd", "/c", "cmd /c diskpart"],
    ["cmd", "/c", "if exist C:\\ diskpart"],
    ["runas", "/user:administrator", "diskpart"],
    ["env", "diskpart"], ["bash", "-c", "dd if=//./PhysicalDrive0 of=x.img"],
    # Command lines, as CreateProcess receives them.
    r'C:\Windows\system32\cmd.exe /c "powershell Get-Disk"',
    r'"C:\Program Files\PowerShell\7\pwsh.exe" -Command Get-Disk',
    "diskpart /s x.txt", r'C:\Windows\system32\cmd.exe /c "d^iskpart"',
    'cmd /s /c ""diskpart""', 'cmd /c "echo x & diskpart"',
    'powershell -Command "Get-Disk | Select-Object Number"',
]  # fmt: skip
WINDOWS_ALLOWED_COMMANDS: list[Sequence[str] | str] = [
    # The file eraser's own queries (core/erase/_platform/win.py).
    ["fsutil", "behavior", "query", "DisableDeleteNotify"],
    ["vssadmin", "list", "shadows", "/for=C:"],
    ["git", "status"], ["python", "-c", "print('\\\\.\\PhysicalDrive0')"],
    ["powershell", "-Command", "Get-Date"],
    ["powershell", "-Command", "Get-ChildItem C:\\Users | Format-Table"],
    ["powershell", "-Command", "Get-DiskImage -ImagePath C:\\images\\x.vhdx"],
    ["powershell", "-Command", "Write-Output 'Format-Table'"],
    ["cmd", "/c", "ver"], ["cmd", "/c", "echo ok & exit 0"],
    ["cmd", "/c", "echo PhysicalDrive2"],
    ["cmd", "/c", "type C:\\x.txt > NUL"], ["cipher", "/e", "file.txt"],
    ["wmic", "os", "get", "caption"], ["type", "C:\\x.txt"],
    ["dd", "if=C:\\x.img", "of=NUL"],
    ["certutil", "-hashfile", "C:\\x.img", "SHA256"],
    ["fsutil", "hardlink", "list", "C:\\x"],
    ["wsl", "--list"], r'C:\Windows\system32\cmd.exe /c "ver"', "git status",
]  # fmt: skip


@pytest.mark.parametrize(
    "host, command",
    [(LINUX, command) for command in LINUX_REFUSED_COMMANDS]
    + [(MACOS, command) for command in MACOS_REFUSED_COMMANDS]
    + [(WINDOWS, command) for command in WINDOWS_REFUSED_COMMANDS],
    ids=_ids,
)
def test_disk_commands_are_refused(host: str, command: Sequence[str] | str) -> None:
    assert command_reason(command, host), command


@pytest.mark.parametrize(
    "host, command",
    [(LINUX, command) for command in LINUX_ALLOWED_COMMANDS]
    + [(MACOS, command) for command in MACOS_ALLOWED_COMMANDS]
    + [(WINDOWS, command) for command in WINDOWS_ALLOWED_COMMANDS],
    ids=_ids,
)
def test_ordinary_commands_stay_allowed(
    host: str, command: Sequence[str] | str
) -> None:
    assert command_reason(command, host) is None, command


def test_images_and_loop_devices_stay_allowed_and_redirections_do_not_count(
    tmp_path: Path,
) -> None:
    image = tmp_path / "disk.img"
    image.write_bytes(b"\0" * 512)
    assert command_reason(["losetup", "--find", "--show", str(image)], LINUX) is None
    assert command_reason(["blkid", str(image)], LINUX) is None
    assert command_reason(["mkfs.ext4", "-q", "-F", str(image)], LINUX) is None
    assert command_reason(["sh", "-c", f"cat < {image}"], LINUX) is None
    assert command_reason(["hdiutil", "attach", str(image)], MACOS) is None
    assert command_reason(["hdiutil", "imageinfo", str(image)], MACOS) is None
    # A regular file the output is redirected to is not an operand of lsblk.
    assert command_reason(["sh", "-c", f"lsblk > {image}"], LINUX) is not None


@pytest.mark.parametrize(
    "host, script",
    [
        (LINUX, "lsblk"), (LINUX, "true; lsblk --version"), (LINUX, "lsblk | head"),
        (LINUX, "cat /dev/sdzz9"), (LINUX, "echo x > /dev/sdzz9"), (LINUX, b"lsblk"),
        (MACOS, "diskutil list"), (MACOS, "dd if=/dev/rdisk0 bs=1m count=1"),
        (WINDOWS, "diskpart"), (WINDOWS, "powershell -NoProfile -Command Get-Disk"),
        (WINDOWS, "wmic diskdrive get model"), (WINDOWS, '"diskpart"'),
        (WINDOWS, "echo x & diskpart"), (WINDOWS, "d^iskpart"),
        (WINDOWS, '"powershell" -Command "Get-Disk"'),
    ],
    ids=_ids,
)  # fmt: skip
def test_shell_true_is_judged_as_the_hosts_own_shell(host: str, script: Any) -> None:
    """``sh -c`` on Linux and macOS; ``cmd.exe /c``, never ``sh``, on Windows."""
    assert shell_reason(script, host)


@pytest.mark.parametrize(
    "host, script",
    [(LINUX, "echo ok"), (MACOS, "sw_vers"), (WINDOWS, "echo ok"), (WINDOWS, "ver"),
     (WINDOWS, "dir C:\\")],
    ids=_ids,
)  # fmt: skip
def test_ordinary_shell_scripts_stay_allowed(host: str, script: str) -> None:
    assert shell_reason(script, host) is None


def test_nesting_deeper_than_the_guard_unpicks_is_refused() -> None:
    script = "true"
    for _ in range(12):
        script = f"sh -c {subprocess.list2cmdline([script])}"
    assert "nested" in (command_reason(["sh", "-c", script], LINUX) or "")


@pytest.mark.parametrize(
    "argv",
    [
        ["prog", "a b", 'q"uote', "back\\slash", "trail\\", 'tr"ail\\', "", 'x\\\\"y'],
        [r"C:\Program Files\x\app.exe", "-Command", "Get-Disk | Select-Object Number"],
        ["cmd", "/c", 'echo "a & b"'],
    ],
    ids=_ids,
)
def test_the_windows_command_line_split_inverts_list2cmdline(argv: list[str]) -> None:
    """The guard reads a command line the way ``CreateProcess`` programs do."""
    assert guard._windows_split(subprocess.list2cmdline(argv)) == argv


# --------------------------------------------------------------------------
# The project's own commands
# --------------------------------------------------------------------------


class RecordingRunner:
    """Records each argv and runs nothing."""

    def __init__(self, answer: Callable[[list[str]], str]) -> None:
        self.answer = answer
        self.argvs: list[list[str]] = []

    def run(self, argv: Sequence[str]) -> CommandResult:
        self.argvs.append(list(argv))
        return CommandResult(list(argv), 0, self.answer(list(argv)), "")


def test_the_macos_adapters_discovery_commands_are_refused_under_macos_rules() -> None:
    def answer(argv: list[str]) -> str:
        if argv[1:] == ["list", "-plist"]:
            return plistlib.dumps({"WholeDisks": ["disk4"]}).decode()
        return plistlib.dumps({}).decode()

    runner = RecordingRunner(answer)
    MacOSAdapter(runner=runner).enumerate_devices()

    assert [argv[1:] for argv in runner.argvs] == [
        ["list", "-plist"],
        ["apfs", "list", "-plist"],
        ["info", "-plist", "/"],
        ["info", "-plist", "disk4"],
        [
            "-json",
            "SPUSBDataType",
            "SPUSBHostDataType",
            "SPNVMeDataType",
            "SPSerialATADataType",
            "SPThunderboltDataType",
        ],
    ]
    for argv in runner.argvs:
        assert command_reason(argv, MACOS), argv
        assert shell_reason(subprocess.list2cmdline(argv), MACOS), argv


def test_the_windows_adapters_discovery_command_is_refused_under_windows_rules() -> (
    None
):
    runner = RecordingRunner(lambda argv: json.dumps({}))
    WindowsAdapter(runner=runner).enumerate_devices()

    (argv,) = runner.argvs
    assert "-EncodedCommand" in argv
    for form in (argv, subprocess.list2cmdline(argv)):
        reason = command_reason(form, WINDOWS)
        assert reason and "get-disk" in reason.casefold(), form


# --------------------------------------------------------------------------
# The hook: each host's own audit events, replayed
# --------------------------------------------------------------------------

_CMD = r"C:\Windows\system32\cmd.exe"

REFUSED_EVENTS: list[tuple[str, str, tuple[Any, ...]]] = [
    (
        LINUX,
        "subprocess.Popen",
        ("/bin/sh", ["/bin/sh", "-c", "lsblk --version"], None, None),
    ),
    (LINUX, "subprocess.Popen", ("lsblk", ["lsblk", "--version"], None, None)),
    (LINUX, "subprocess.Popen", ("/usr/bin/lsblk", ["sanctum-harmless"], None, None)),
    (LINUX, "os.system", ("true; lsblk --version",)),
    (LINUX, "os.system", (b"lsblk",)),
    (LINUX, "os.exec", ("/usr/bin/lsblk", ["lsblk"], {})),
    (LINUX, "os.posix_spawn", ("/usr/bin/dd", ["dd", "if=/dev/sdzz9"], {})),
    (LINUX, "os.spawn", (0, "/bin/dd", ["dd", "if=/dev/sdzz9"], {})),
    (LINUX, "open", ("/dev/sdzz9", "rb", 0)),
    (LINUX, "open", (b"//dev/sdzz9", "rb", 0)),
    (LINUX, "os.listdir", ("/dev",)),
    (LINUX, "os.scandir", ("/dev/disk/by-id",)),
    (LINUX, "glob.glob", ("/dev/sd*", False)),
    (LINUX, "glob.glob/2", ("/dev/nvme*", False, None, None)),
    (
        MACOS,
        "subprocess.Popen",
        ("/bin/sh", ["/bin/sh", "-c", "diskutil list"], None, None),
    ),
    (MACOS, "subprocess.Popen", (None, [DISKUTIL, "list", "-plist"], None, None)),
    (MACOS, "os.system", ("diskutil list",)),
    (MACOS, "os.posix_spawn", (DISKUTIL, ["diskutil", "info", "-plist", "/"], {})),
    (MACOS, "open", ("/dev/rdisk0", "rb", 0)),
    (MACOS, "open", ("/dev/disk2s1", "rb", 0)),
    (MACOS, "os.listdir", ("/Volumes",)),
    (MACOS, "glob.glob", ("/dev/disk*", False)),
    # shell=True on Windows: subprocess raises the event with cmd.exe's line.
    (
        WINDOWS,
        "subprocess.Popen",
        (_CMD, f'{_CMD} /c "powershell -NoProfile -Command Get-Disk"', None, None),
    ),
    (WINDOWS, "subprocess.Popen", (_CMD, f'{_CMD} /c "d^iskpart"', None, None)),
    (
        WINDOWS,
        "subprocess.Popen",
        (
            None,
            subprocess.list2cmdline(["powershell.exe", "-Command", "Get-Disk"]),
            None,
            None,
        ),
    ),
    (
        WINDOWS,
        "subprocess.Popen",
        (r"C:\Windows\System32\diskpart.exe", "sanctum-harmless", None, None),
    ),
    (WINDOWS, "_winapi.CreateProcess", (None, "diskpart", None)),
    (
        WINDOWS,
        "_winapi.CreateProcess",
        (r"C:\Windows\System32\wbem\WMIC.exe", "wmic diskdrive get model", None),
    ),
    (WINDOWS, "os.system", ("diskpart",)),
    (WINDOWS, "os.system", ("echo x & d^iskpart",)),
    (WINDOWS, "open", (r"\\.\PhysicalDrive0", "rb", 0)),
    (WINDOWS, "open", ("//./PHYSICALDRIVE1", "rb", 0)),
    (WINDOWS, "_winapi.CreateFile", (r"\\.\PhysicalDrive0", 0x80000000, 3, 3, 0)),
    (WINDOWS, "os.startfile", (r"\\.\PhysicalDrive0", "open")),
]
ALLOWED_EVENTS: list[tuple[str, str, tuple[Any, ...]]] = [
    (LINUX, "subprocess.Popen", ("git", ["git", "status"], None, None)),
    (LINUX, "os.system", ("echo ok",)),
    (LINUX, "open", ("/dev/null", "rb", 0)),
    (
        MACOS,
        "subprocess.Popen",
        ("tmutil", ["tmutil", "listlocalsnapshots", "/tmp"], None, None),
    ),
    (MACOS, "open", ("/dev/null", "rb", 0)),
    (WINDOWS, "subprocess.Popen", (_CMD, f'{_CMD} /c "ver"', None, None)),
    (
        WINDOWS,
        "subprocess.Popen",
        (None, "fsutil behavior query DisableDeleteNotify", None, None),
    ),
    (WINDOWS, "_winapi.CreateProcess", (None, "vssadmin list shadows /for=C:", None)),
    (WINDOWS, "open", (r"C:\Users\runner\x.txt", "rb", 0)),
]


@pytest.mark.parametrize("host, event, args", REFUSED_EVENTS, ids=_ids)
def test_the_hook_refuses_each_hosts_own_events(
    host: str, event: str, args: tuple[Any, ...]
) -> None:
    with refused_once(), rules(host):
        sys.audit(event, *args)


@pytest.mark.parametrize("host, event, args", ALLOWED_EVENTS, ids=_ids)
def test_the_hook_allows_each_hosts_ordinary_events(
    host: str, event: str, args: tuple[Any, ...]
) -> None:
    before = list(guard.BLOCKED)
    with rules(host):
        sys.audit(event, *args)
    assert guard.BLOCKED == before


def test_with_no_rule_set_nothing_is_refused() -> None:
    with rules(None):
        sys.audit("open", "/dev/sdzz9", "rb", 0)
        sys.audit("subprocess.Popen", None, "diskpart", None, None)


# --------------------------------------------------------------------------
# Live: the real APIs, this host's rules, the barrier behind them
# --------------------------------------------------------------------------


def test_what_the_guard_allows_reaches_the_barrier_and_goes_no_further(
    tmp_path: Path,
) -> None:
    target = tmp_path / "ordinary.bin"
    for attempt in (
        lambda: open(target, "wb"),  # noqa: SIM115
        lambda: os.listdir(tmp_path),
        lambda: subprocess.run([sys.executable, "-c", "pass"], check=False),
    ):
        before = list(guard.BLOCKED)
        with pytest.raises(BarrierReached), launch_barrier():
            attempt()
        assert guard.BLOCKED == before
    assert not target.exists(), "the barrier stopped the open before it happened"


def test_the_barrier_lets_a_launch_wrap_its_own_pipes(tmp_path: Path) -> None:
    """``capture_output=True`` wraps the pipe descriptors with ``io.open(fd)``
    before ``subprocess.Popen`` is raised. Wrapping a descriptor that is
    already open reaches nothing new, so the barrier waits for the launch.
    Found on the macOS runner: the barrier stopped the pipe, not the launch."""
    before = list(guard.BLOCKED)
    with pytest.raises(BarrierReached, match="subprocess.Popen"), launch_barrier():
        subprocess.run([sys.executable, "-c", "pass"], capture_output=True)
    assert guard.BLOCKED == before


@live_on(LINUX, MACOS)
@pytest.mark.parametrize(
    "host, adapter, tool",
    [(MACOS, MacOSAdapter, "diskutil"), (WINDOWS, WindowsAdapter, "get-disk")],
)
def test_live_the_real_adapter_and_runner_are_stopped_before_discovery(
    host: str, adapter: Any, tool: str
) -> None:
    """The product's own adapter and ``SubprocessRunner`` (``capture_output``
    pipes and all), launch refused under that host's rules. On a Windows host
    tests/platform/test_windows_filesystem.py runs the same check natively."""
    with (
        expect_refusal() as refusals,
        launch_barrier(),
        rules(host),
        pytest.raises(PlatformUnsupported),
    ):
        adapter().enumerate_devices()
    assert refusals and all(tool in refusal.casefold() for refusal in refusals)


def test_the_barrier_is_inert_until_armed(tmp_path: Path) -> None:
    target = tmp_path / "ordinary.bin"
    target.write_bytes(b"x")
    assert target.read_bytes() == b"x"


# os.system is called on purpose, with literal strings: it is one of the
# routes the guard has to close, and the guard refuses it before any shell runs.
LINUX_LIVE: dict[str, Callable[[], Any]] = {
    "argv": lambda: subprocess.run(["lsblk", "--version"], check=False),
    "shell-true": lambda: subprocess.run("lsblk --version", shell=True, check=False),
    "shell-true-sequence": lambda: subprocess.run(
        "true; lsblk --version", shell=True, check=False
    ),
    "sh-c": lambda: subprocess.run(
        ["sh", "-c", "true && lsblk --version"], check=False
    ),
    "executable": lambda: subprocess.run(
        ["sanctum-harmless"], executable="/usr/bin/lsblk", check=False
    ),
    "os-system": lambda: os.system("lsblk --version"),
    "cat-node": lambda: subprocess.run(["cat", "/dev/sdzz9"], check=False),
    "dd-operand": lambda: subprocess.run(["dd", "if=/dev/sdzz9", "of=/dev/null"]),
    "open-node": lambda: open("/dev/sdzz9", "rb"),  # noqa: SIM115
    "open-double-slash": lambda: open("//dev/sdzz9", "rb"),  # noqa: SIM115
    "os-open-dot": lambda: os.open("/dev/./sdzz9", os.O_RDONLY),
    "sysfs-physical-name": lambda: os.open("/sys/block/sdzz9/size", os.O_RDONLY),
    "sysfs-class-block": lambda: os.open(
        "/sys/class/block/nvme9n9/removable", os.O_RDONLY
    ),
    "list-removable-media": lambda: os.listdir("/run/media/sanctum-guard-selftest"),
    "list-dev-disk": lambda: os.scandir("/dev/disk/by-id-sanctum-guard-selftest"),
    "open-by-id": lambda: open("/dev/disk/by-id/usb-SANCTUM_GUARD_SELFTEST", "rb"),  # noqa: SIM115
    "list-dev": lambda: os.listdir("/dev"),
    "glob-nodes": lambda: glob.glob("/dev/sd*"),
}
MACOS_LIVE: dict[str, Callable[[], Any]] = {
    "argv": lambda: subprocess.run([DISKUTIL, "list"], check=False),
    "shell-true": lambda: subprocess.run("diskutil list", shell=True, check=False),
    "sh-c-pipe": lambda: subprocess.run(
        ["sh", "-c", "diskutil list | head -1"], check=False
    ),
    "os-system": lambda: os.system("diskutil list"),
    "ioreg-media": lambda: subprocess.run(
        ["ioreg", "-r", "-c", "IOMedia"], check=False
    ),
    "system-profiler": lambda: subprocess.run(
        ["system_profiler", "SPStorageDataType"], check=False
    ),
    "dd-raw": lambda: subprocess.run(["dd", "if=/dev/rdisk0", "of=/dev/null"]),
    "open-disk0": lambda: open("/dev/disk0", "rb"),  # noqa: SIM115
    "open-rdisk0": lambda: open("/dev/rdisk0", "rb"),  # noqa: SIM115
    "open-partition": lambda: open("/dev/disk2s1", "rb"),  # noqa: SIM115
    "os-open-case": lambda: os.open("/DEV/DISK1", os.O_RDONLY),
    "list-volumes": lambda: os.listdir("/Volumes"),
    "list-dev": lambda: os.listdir("/dev"),
    "glob-nodes": lambda: glob.glob("/dev/disk*"),
}
_GET_DISK = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Get-Disk"]
WINDOWS_LIVE: dict[str, Callable[[], Any]] = {
    "powershell-argv": lambda: subprocess.run(_GET_DISK, check=False),
    "powershell-shell-true": lambda: subprocess.run(
        subprocess.list2cmdline(_GET_DISK), shell=True, check=False
    ),
    "os-system": lambda: os.system(subprocess.list2cmdline(_GET_DISK)),
    "wmic-argv": lambda: subprocess.run(["wmic", "diskdrive", "get", "model"]),
    "wmic-shell-true": lambda: subprocess.run(
        "wmic diskdrive get model", shell=True, check=False
    ),
    "cmd-c": lambda: subprocess.run(["cmd", "/c", "wmic diskdrive get model"]),
    "open-physicaldrive": lambda: open(r"\\.\PhysicalDrive0", "rb"),  # noqa: SIM115
    "open-forward-slashes": lambda: open("//./PhysicalDrive0", "rb"),  # noqa: SIM115
    "os-open-case": lambda: os.open(r"\\.\PHYSICALDRIVE0", os.O_RDONLY),
    "open-raw-volume": lambda: open(r"\\.\C:", "rb"),  # noqa: SIM115
}


@live_on(LINUX, MACOS)
@pytest.mark.parametrize("attempt", LINUX_LIVE.values(), ids=LINUX_LIVE.keys())
def test_live_linux_routes_to_a_device_are_refused(attempt: Callable[[], Any]) -> None:
    with refused_live(), rules(LINUX):
        attempt()


@live_on(LINUX, MACOS)
@pytest.mark.parametrize("attempt", MACOS_LIVE.values(), ids=MACOS_LIVE.keys())
def test_live_macos_routes_to_a_device_are_refused(attempt: Callable[[], Any]) -> None:
    with refused_live(), rules(MACOS):
        attempt()


@live_on(WINDOWS)
@pytest.mark.parametrize("attempt", WINDOWS_LIVE.values(), ids=WINDOWS_LIVE.keys())
def test_live_windows_routes_to_a_device_are_refused(
    attempt: Callable[[], Any],
) -> None:
    with refused_live():
        attempt()


@live_on(LINUX, MACOS)
@pytest.mark.parametrize(
    "host, target", [(LINUX, "/dev/sdzz9"), (MACOS, "/dev/rdisk99")]
)
def test_live_a_symlink_to_a_device_is_refused(
    tmp_path: Path, host: str, target: str
) -> None:
    link = tmp_path / "innocent.img"
    link.symlink_to(target)
    with refused_live(), rules(host):
        open(link, "rb")  # noqa: SIM115
