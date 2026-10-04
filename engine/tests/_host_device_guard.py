"""No test reaches a host storage device. Enforced here, not left to convention.

``tests/conftest.py`` has always said "no real device access anywhere in the
suite". Until 2026-09-25 that was a convention, and five tests broke it: they
built the real Linux adapter, whose capability matrix runs device discovery
(``lsblk`` over sysfs) against whatever happens to be plugged into the machine
running the suite. Read-only, but it enumerated real disks, including removable
media a person had attached for a different purpose. Until 2026-09-27 the rules
below were Linux's only; on macOS and Windows the hook was installed but matched
nothing native to those hosts.

How it works
============

:func:`install` adds a :func:`sys.addaudithook` hook. CPython raises an audit
event *before* the operation it describes: before ``open`` reaches the kernel,
before :mod:`subprocess` forks or calls ``CreateProcess``, and before
:func:`os.system` hands its string to a shell. A refused call therefore never
reaches the operating system. The events judged are :data:`GUARDED_EVENTS`.

A refusal raises :class:`HostDeviceAccessBlocked`, a ``PermissionError``: the
code under test sees what an unprivileged process would, so a refusal inside a
worker thread fails that job instead of hanging the suite. It is also recorded
in :data:`BLOCKED`, and ``tests/conftest.py`` fails any session with a refusal
in it - including one the code under test caught and handled.

One rule set per host
=====================

The hook applies the rule set of the host it runs on (:data:`ACTIVE`), and the
end-of-run summary names it: ``Host-device guard: Linux rules active``, ``...
macOS rules active`` or ``... Windows rules active``. A host with no rule set
(any other ``sys.platform``) gets ``no rules active`` and nothing is refused
there. The decision functions (:func:`path_reason`, :func:`command_reason`,
:func:`shell_reason`, :func:`launch_reason`, :func:`event_reason`) take the rule
set as an argument, so the self-test checks all three on every host.

Linux
-----

Device paths refused: ``/dev/sd*``, ``/dev/hd*``, ``/dev/vd*``, ``/dev/xvd*``,
``/dev/nvme*`` and ``/dev/ng*``, ``/dev/mmcblk*`` (partitions, ``boot0/1``,
``rpmb``), ``/dev/sr*``, ``/dev/sg*``, ``/dev/dm-*``, ``/dev/md*``, and
everything under ``/dev/disk``, ``/dev/mapper``, ``/dev/block`` and
``/dev/bsg``; the kernel's tables ``/proc/partitions``, ``/proc/diskstats`` and
``/proc/scsi/scsi``; the block-device trees in ``/sys`` and their SCSI, NVMe and
USB buses; udev's database; anything under ``/run/media`` or ``/media`` that is
not a loop volume; and a listing of ``/dev`` or a glob over device nodes.

Commands refused:

* a discovery or management tool (``lsblk``, ``blkid``, ``hdparm``,
  ``smartctl``, ``nvme``, ``wipefs``, ``parted``, ``fdisk``, ``mount``,
  ``udisksctl``, ``blkdiscard``, ``fstrim``, ``lshw``, ``mdadm``, the LVM
  scanners, ``sg_*``, ...) unless it names a loop device or a regular file -
  with no such operand these tools mean "every device", which is discovery;
* any of those, or a raw read/write, filesystem or forensic tool (``dd``,
  ``cat``, ``tee``, ``file``, ``losetup``, ``mkfs.*``, ``fsck.*``, ``e2*``,
  ``ntfs*``, ``ewfacquire``, ``photorec``, the Sleuth Kit, ...), naming a device
  path; a listing tool (``ls``, ``find``, ``stat``, ...) naming a device
  directory;
* a shell redirection to or from a device path (``< /dev/sda``,
  ``> /dev/sda``): the shell itself opens it, whatever the program is.

Allowed, deliberately:

* the sysfs attributes of the disk that holds the suite's own files (the
  repository and the temporary directory). The file-eraser tests erase files on
  a real block-backed filesystem beside the repository on purpose - tmpfs cannot
  answer their questions - and the eraser reads that disk's queue attributes to
  judge whether TRIM may have remapped a page. The disk is worked out once, from
  the mount table and sysfs, *before* the hook exists, and the terminal summary
  names it on every run;
* loop devices and files on loop volumes (the udisks loop tests), and the mount
  table itself, which names mounts but touches no device;
* a device path handed to any other program as data: the harness tests pass
  ``/dev/sda`` to a banner function.

macOS
-----

Device paths refused: ``/dev/diskN`` and ``/dev/rdiskN`` with any partition or
snapshot suffix (``/dev/disk2s1``, ``/dev/rdisk3s1s1``), in any letter case -
the root volume is case-insensitive, so ``/DEV/DISK0`` reaches the same node;
``/Volumes`` itself and every volume under it except the one holding the suite's
files; a listing of ``/dev`` or a glob over device nodes.

Commands refused: ``diskutil``, ``asr``, ``gpt``, ``pdisk``, ``bless`` and
``apfs_hfs_convert`` always; ``hdiutil`` unless it works on a disk-image file
(``create`` and ``makehybrid`` name a file that does not exist yet); ``ioreg``
unless it is narrowed to a class, name or key that is not storage;
``system_profiler`` with no data type or a storage one (``SPStorageDataType``,
``SPNVMeDataType``, ``SPUSBDataType``, ...); ``newfs_*``, ``fsck_*`` and
``mount_*`` naming a device path; and the shared POSIX tools as on Linux
(``dd``, ``cat``, ``mount``, ``smartctl``, redirections, ...) judged against the
macOS device paths. Program names are compared case-insensitively, for the same
reason as paths. ``tmutil listlocalsnapshots <path>``, which the file eraser
runs on APFS, is allowed.

Windows
-------

Device paths refused, in any letter case, with ``/`` or ``\\``, repeated
separators, trailing dots and spaces, and ``.``/``..`` components resolved:
anything in the device namespaces ``\\\\.\\``, ``\\\\?\\`` and ``\\??\\`` that names
``PhysicalDriveN``, ``HarddiskNPartitionM``, ``HarddiskVolumeN``, ``CdRomN``,
``TapeN``, ``ScsiN:``, ``GLOBALROOT``, the mount-point manager or a
device-interface path (``...#{53f56307-...}``); a raw volume (``\\\\.\\C:``,
``\\\\?\\Volume{GUID}`` with no path after it); and NT object paths such as
``\\Device\\Harddisk0\\DR0``. ``\\\\?\\C:\\long\\path`` and
``\\\\?\\UNC\\server\\share`` are ordinary files and stay allowed, as do
``\\\\.\\pipe\\...`` and ``NUL``.

Commands refused: ``diskpart``, ``format``, ``chkdsk``, ``defrag``,
``mountvol``, ``manage-bde``, ``diskshadow``, ``wbadmin``, ``bootsect``,
``bcdboot``, ``mbr2gpt``, ``sdelete`` and their kin always; ``wmic`` with a disk
alias or storage class; ``fsutil fsinfo|volume|repair|usn``; ``vssadmin
delete|resize|create|add|revert``; ``cipher /w``; ``wsl --mount``; raw
read/write tools (``type``, ``copy``, ``certutil``, ``robocopy``, ``dd``, ...)
naming a device path; a ``cmd`` redirection to or from one; and any PowerShell
command whose script - from ``-Command``, positional text or a decoded
``-EncodedCommand`` - uses a storage cmdlet (``Get-Disk``,
``Get-PhysicalDisk``, ``Get-Partition``, ``Get-Volume``, ``Clear-Disk``,
``Initialize-Disk``, ``Format-Volume``, ``Set-Disk``, the ``*-BitLocker``
family, ...), a storage WMI/CIM class (``Win32_DiskDrive``, ``MSFT_Disk``,
...), a ``PhysicalDrive`` name, a device path, or one of the commands above.
``fsutil behavior query`` and ``vssadmin list shadows``, which the file eraser
runs, are allowed.

What the rules see: normalisation
=================================

Every rule is applied to a normalised form, never to the raw string:

* paths are made absolute with ``.``, ``..`` and repeated ``/`` collapsed -
  including a leading ``//``, which Linux and macOS treat as ``/`` - and on a
  POSIX host every symlink is followed too; a path is refused if either form
  matches. Windows paths are normalised as text (above);
* a command's program is its base name (on Windows without ``.exe``, ``.com``,
  ``.bat``, ``.cmd``); an ``executable=`` that differs from ``argv[0]`` is
  judged as well;
* shell ``-c`` scripts (including combined flags such as ``-lc``), ``su -c``,
  ``eval``, nested shells, ``$(...)``, backticks and ``<(...)`` (also inside
  double quotes), leading ``VAR=value`` assignments, keywords (``if``, ``!``,
  ``do``, ...) and wrappers (``sudo``, ``env``, ``exec``, ``timeout``,
  ``xargs``, ``nice``, ...) are unpicked down to simple commands, and each is
  judged. POSIX quoting is undone by :mod:`shlex`, so ``l's'blk`` is ``lsblk``;
* on Windows a command line is split by ``CreateProcess``'s rules;
  ``cmd /c`` scripts have ``^`` escapes and outer quotes removed and are split
  on ``&``, ``|``, ``&&``, ``||`` and parentheses; ``start``, ``call``,
  ``runas`` and PowerShell's ``Start-Process``, ``Invoke-Expression`` and ``&``
  are unwrapped; PowerShell backtick escapes and quotes are removed before the
  script is searched. ``shell=True`` on Windows runs ``cmd.exe /c`` - never
  ``sh -c`` - and is judged as such.

Limitations, stated plainly
===========================

* Scope: this process. A child process is outside the hook. The guard judges a
  command's text, so what the child reads for itself - a script file
  (``bash script.sh``, ``powershell -File x.ps1``), standard input, a Python
  ``-c`` program - and names built at run time (variables, string
  concatenation, ``%VAR%``) are outside its view. The suite's children are bash
  snippets of the harness gate library (which never call its device probes) and
  Python scripts on synthetic inputs.
* ``os.stat`` raises no audit event, so a stat of a device path is not refused.
* A foreign function called through :mod:`ctypes` raises no audit event
  (CPython raises ``ctypes.call_function`` only from ``ctypes``' private call
  helpers), so ``CreateFileW`` on ``\\\\.\\PhysicalDrive0`` or libc's ``open``
  through ``ctypes`` is not refused. Nor is device access from inside a native
  library: Disk Arbitration or IOKit through PyObjC, WMI through COM.
* Windows: reparse points are not followed, because resolving one opens its
  target; files on other drive letters, removable ones included, are not
  refused (there is no ``/run/media`` to recognise them by).
* Conservative, not exact: ``$(...)`` inside single quotes is refused although
  the shell would not run it, and a script ``shlex`` cannot parse is judged line
  by line, a line that still cannot be parsed word by word.

The self-test (``tests/test_host_device_guard.py``) checks the decisions of all
three rule sets on every host, replays each host's own audit events through the
hook, and drives the real APIs - Linux and macOS rules on either of those hosts,
Windows rules on Windows - behind :func:`launch_barrier`, which stops anything
the guard allows before it runs. Those tests validate the guard's decisions
through intercepted launches; no test touches a physical device, and the guard
was never tested against one.
"""

from __future__ import annotations

import base64
import binascii
import os
import posixpath
import re
import shlex
import subprocess
import sys
import threading
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

__all__ = [
    "ACTIVE",
    "ALLOWED_DISKS",
    "ALLOWED_VOLUMES",
    "BLOCKED",
    "GUARDED_EVENTS",
    "LINUX",
    "MACOS",
    "RULE_SETS",
    "WINDOWS",
    "BarrierReached",
    "HostDeviceAccessBlocked",
    "command_reason",
    "event_reason",
    "expect_refusal",
    "install",
    "launch_barrier",
    "launch_reason",
    "media_reason",
    "path_reason",
    "rules_for_platform",
    "shell_reason",
    "summary_lines",
]


class HostDeviceAccessBlocked(PermissionError):
    """A test tried to reach a host storage device. See the module docstring."""


class BarrierReached(RuntimeError):
    """The guard allowed an operation and :func:`launch_barrier` stopped it."""


LINUX = "linux"
MACOS = "macos"
WINDOWS = "windows"
#: Rule set -> the name the terminal summary gives it.
RULE_SETS: dict[str, str] = {LINUX: "Linux", MACOS: "macOS", WINDOWS: "Windows"}


def rules_for_platform(platform: str) -> str | None:
    """The rule set for a ``sys.platform`` value, or ``None`` if there is none."""
    if platform.startswith("linux"):
        return LINUX
    if platform == "darwin":
        return MACOS
    if platform == "win32":
        return WINDOWS
    return None


#: The rule set the hook applies: the host's own. The self-test swaps it for
#: the length of one call, to replay another host's audit events or to drive
#: the real APIs of a Linux or macOS host under the other one's rules.
ACTIVE: str | None = rules_for_platform(sys.platform)

#: Every refusal made in this process, ``"<test id>: <reason>"``.
BLOCKED: list[str] = []
#: Linux: kernel names of the disk holding the suite's files, whose sysfs may
#: be read.
ALLOWED_DISKS: frozenset[str] = frozenset()
_ALLOWED_DEVNUMS: frozenset[str] = frozenset()
#: macOS: names under ``/Volumes`` (case-folded) that hold the suite's files.
ALLOWED_VOLUMES: frozenset[str] = frozenset()

#: The audit events the guard judges, and the only ones the barrier stops.
GUARDED_EVENTS = frozenset(
    {
        "open", "os.listdir", "os.scandir", "glob.glob", "glob.glob/2",
        "subprocess.Popen", "os.exec", "os.posix_spawn", "os.spawn",
        "os.system", "os.startfile", "os.startfile/2", "_winapi.CreateProcess",
        "_winapi.CreateFile",
    }
)  # fmt: skip

_MAX_DEPTH = 8

# --------------------------------------------------------------------------
# Linux paths
# --------------------------------------------------------------------------

_NAME = (
    r"(?:sd[a-z]+\d*|hd[a-z]+\d*|vd[a-z]+\d*|xvd[a-z]+\d*"
    r"|nvme\d+(?:n\d+(?:p\d+)?)?|ng\d+n\d+|mmcblk\d+(?:p\d+|boot\d+|rpmb)?"
    r"|sr\d+|sg\d+|dm-\d+|md\d+(?:p\d+)?)"
)
_NODE = re.compile(rf"^/dev/(?:{_NAME}|(?:disk|mapper|block|bsg)(?:/.*)?)$")
_KERNEL_NAME = re.compile(rf"^{_NAME}$")
_MEDIA = ("/run/media", "/media")
_ROOTS = (
    "/run/udev/data",
    "/dev/disk",
    "/sys/class/scsi_disk",
    "/sys/class/nvme",
    "/sys/bus/scsi",
    "/sys/bus/usb",
)
_TREES = ("/sys/block", "/sys/class/block")
_DEVNUMS = "/sys/dev/block"
_TABLES = frozenset({"/proc/partitions", "/proc/diskstats", "/proc/scsi/scsi"})

# --------------------------------------------------------------------------
# macOS paths
# --------------------------------------------------------------------------

#: ``disk2``, ``rdisk2``, ``disk2s1``, ``disk3s1s1`` (an APFS snapshot).
_MAC_NODE = re.compile(r"^/dev/r?disk\d+(?:s\d+)*$")

# --------------------------------------------------------------------------
# Windows paths
# --------------------------------------------------------------------------

#: ``\\.\``, ``\\?\`` and the NT ``\??\``, once ``/`` has become ``\``.
_WIN_NAMESPACE = re.compile(r"^(?:\\\\[.?]|\\\?\?)\\+")
_WIN_NT_DEVICE = re.compile(
    r"^\\+device\\+(?:harddisk|cdrom|tape|changer|floppy|scsi|raw|volume"
    r"|mountpointmanager)"
)

# --------------------------------------------------------------------------
# Command families
# --------------------------------------------------------------------------

#: Discovery and management tools. With no loop-device or regular-file
#: operand they address every device, which is discovery; with a device path
#: they reach that device.
_DISCOVERY = frozenset(
    {
        "lsblk", "blkid", "findfs", "hdparm", "smartctl", "nvme", "sdparm",
        "sedutil-cli", "blockdev", "wipefs", "parted", "sfdisk", "fdisk",
        "sgdisk", "gdisk", "partprobe", "udevadm", "udisksctl", "mount",
        "umount", "eject", "cryptsetup", "dmsetup", "badblocks", "lsscsi",
        "lsusb", "blkdiscard", "blkzone", "fstrim", "lshw", "hwinfo", "inxi",
        "mdadm", "pvs", "vgs", "lvs", "pvscan", "vgscan", "lvscan", "pvdisplay",
        "vgdisplay", "lvdisplay", "kpartx", "multipath", "zpool", "swapon",
        "swapoff", "cfdisk",
    }
)  # fmt: skip
#: Tools that read or write whatever path they are given. Naming a device
#: path to one of these is refused; to any other program a path is data (the
#: harness tests pass "/dev/sda" as a label to a banner function).
_RAW_IO = frozenset(
    {
        "dd", "cat", "head", "tail", "od", "xxd", "hexdump", "shred", "cmp",
        "cp", "pv", "sha256sum", "sha1sum", "md5sum", "b2sum", "sha224sum",
        "sha384sum", "sha512sum", "cksum", "sum", "tee", "file", "strings",
        "less", "more", "base64", "gzip", "zcat", "xz", "tar", "rsync",
        "ddrescue", "dcfldd", "dc3dd", "losetup", "btrfs", "zfs", "nwipe",
        "scrub", "openssl", "ewfacquire", "ewfverify", "ewfinfo", "ewfexport",
        "mmls", "mmstat", "fls", "icat", "fsstat", "img_stat", "img_cat",
        "blkls", "blkcat", "istat", "ils", "tsk_recover", "tsk_loaddb",
        "photorec", "testdisk", "foremost", "scalpel", "bulk_extractor",
        "mkswap", "mkdosfs", "mkntfs", "fatlabel", "mlabel", "mcopy",
    }
)  # fmt: skip
#: Filesystem builders and checkers, by prefix: ``mkfs.ext4``, ``e2fsck``,
#: ``ntfsclone``, ``xfs_repair``, ``newfs_apfs``, ``fsck_hfs``, ...
_RAW_PREFIXES = (
    "mkfs", "fsck", "mke2fs", "e2", "tune2fs", "dumpe2fs", "debugfs",
    "resize2fs", "xfs_", "ntfs", "exfat", "partclone", "newfs_", "mount_",
)  # fmt: skip
#: Tools that list what they are given: refused on a device directory.
_LISTERS = frozenset({"ls", "tree", "du", "stat", "find"})
_SHELLS = frozenset(
    {"sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "fish", "csh", "tcsh"}
)
#: Words after which the next word is the command.
_KEYWORDS = frozenset(
    {
        "if", "then", "else", "elif", "do", "while", "until", "!", "{",
        "command", "builtin", "busybox", "toybox", "coproc",
    }
)  # fmt: skip
#: Programs that run another program named somewhere in their arguments.
_WRAPPERS = frozenset(
    {
        "sudo", "doas", "env", "nice", "ionice", "timeout", "stdbuf", "xargs",
        "setsid", "unshare", "nsenter", "flock", "chroot", "taskset", "chrt",
        "watch", "strace", "ltrace", "caffeinate", "arch", "exec", "nohup",
        "time",
    }
)  # fmt: skip
_POSIX_SPECIAL = frozenset({"su", "runuser", "eval"})

_MAC_ALWAYS = frozenset(
    {"diskutil", "asr", "gpt", "pdisk", "bless", "apfs_hfs_convert"}
)
_MAC_SPECIAL = frozenset({"hdiutil", "ioreg", "system_profiler"})
_HDIUTIL_MAKERS = frozenset({"create", "makehybrid", "help"})
_STORAGE_WORDS = (
    "media", "storage", "disk", "nvme", "ahci", "sata", "scsi", "usbmass",
    "apfs", "block", "partition",
)  # fmt: skip
_PROFILER_STORAGE = frozenset(
    name.casefold()
    for name in (
        "SPStorageDataType", "SPNVMeDataType", "SPSerialATADataType",
        "SPUSBDataType", "SPUSBHostDataType", "SPParallelSCSIDataType",
        "SPSASDataType", "SPCardReaderDataType", "SPDiscBurningDataType",
        "SPThunderboltDataType", "SPFireWireDataType", "SPParallelATADataType",
        "SPFibreChannelDataType", "SPHardwareRAIDDataType",
    )
)  # fmt: skip

_WIN_ALWAYS = frozenset(
    {
        "diskpart", "format", "chkdsk", "chkntfs", "defrag", "convert",
        "label", "recover", "mountvol", "manage-bde", "diskshadow", "wbadmin",
        "bootsect", "bcdboot", "mbr2gpt", "sdelete", "sdelete64", "diskperf",
    }
)  # fmt: skip
_WIN_RAW_IO = frozenset(
    {
        "type", "copy", "xcopy", "robocopy", "certutil", "fc", "comp",
        "findstr", "ftkimager", "7z", "expand", "esentutl",
    }
)  # fmt: skip
_WIN_CONDITIONAL = frozenset({"wmic", "fsutil", "vssadmin", "cipher", "wsl"})
_POWERSHELLS = frozenset({"powershell", "pwsh", "powershell_ise"})
_WIN_WRAPPERS = frozenset(
    {
        "start", "call", "runas", "start-process", "saps", "invoke-expression",
        "iex", "invoke-command", "icm", "start-job", "if", "for", "do", "else",
        "psexec", "psexec64",
    }
)  # fmt: skip
_WMIC_DISK = frozenset(
    {"diskdrive", "partition", "logicaldisk", "volume", "cdrom", "diskquota"}
)
_EXECUTABLE_SUFFIXES = (".exe", ".com", ".bat", ".cmd")

#: A storage cmdlet: ``Get-Disk``, ``Clear-Disk``, ``Format-Volume``, ...
#: ``Get-DiskImage`` (a VHD or ISO file) is not one.
_PS_CMDLET = re.compile(
    r"(?<![\w-])(?:get|clear|initialize|set|update|format|new|remove|resize"
    r"|repair|optimize|reset|add|connect|disconnect|enable|disable|suspend"
    r"|resume|lock|unlock|backup|mount|dismount)-(?:disk|physicaldisk|partition"
    r"|volume|virtualdisk|storagepool|storagesubsystem|storagenode"
    r"|storagereliabilitycounter|storageenclosure|storagejob"
    r"|partitionsupportedsize|partitionaccesspath|bitlocker\w*)(?![\w-])"
)
_WMI_CLASS = re.compile(
    r"(?<!\w)(?:win32_(?:diskdrive|diskpartition|logicaldisk|volume"
    r"|physicalmedia|mountpoint|cdromdrive|tapedrive|encryptablevolume"
    r"|diskquota|shadowcopy)\w*|msft_(?:disk|physicaldisk|partition|volume"
    r"|virtualdisk|storage)\w*|msstoragedriver_\w+)"
)
#: ``PhysicalDrive`` in any form, ``Get-PnpDevice -Class DiskDrive``, and
#: ``[System.IO.DriveInfo]::GetDrives()``.
_DISK_WORD = re.compile(r"(?<!\w)(?:physicaldrive|diskdrive|driveinfo)")
_WIN_PATH_IN_TEXT = re.compile(
    r"(?:\\\\|//)[.?][\\/][^\s'\"`;|&(){}<>,]+|\\\?\?\\[^\s'\"`;|&(){}<>,]+"
)
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_PS_ASSIGNMENT = re.compile(r"^\s*\$[\w:]+\s*=\s*")
_SUBSTITUTION = re.compile(r"(?:\$|[<>])\(([^()]*)\)|`([^`]*)`")
_PUNCTUATION = frozenset("();<>|&")
_NOT_DEVICES = ("/dev/shm", "/dev/fd")


# --------------------------------------------------------------------------
# The mount table
# --------------------------------------------------------------------------


def _unescape(field: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), field)


def _mounts() -> list[tuple[str, str]]:
    """``(mount point, source)`` for every mount, longest mount point first."""
    rows: list[tuple[str, str]] = []
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as handle:
            for line in handle:
                fields = line.split()
                rows.append((_unescape(fields[4]), fields[fields.index("-") + 2]))
    except (OSError, ValueError, IndexError):
        return []
    return sorted(rows, key=lambda row: len(row[0]), reverse=True)


def _mount_of(path: str, mounts: list[tuple[str, str]]) -> tuple[str, str] | None:
    for point, source in mounts:
        if path == point or path.startswith(point.rstrip("/") + "/"):
            return point, source
    return None


def media_reason(path: str, mounts: list[tuple[str, str]]) -> str | None:
    """Refuse a removable-media path unless it lies on a loop volume."""
    hit = _mount_of(path, mounts)
    if hit and hit[1].startswith("/dev/loop") and hit[0] != "/":
        return None
    return f"{path} (removable media, not a loop volume)"


# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------


def _rules(host: str | None) -> str | None:
    return ACTIVE if host is None else host


def _text(raw: Any) -> str | None:
    """``raw`` as a path string, or ``None`` if it is not one (a descriptor)."""
    if isinstance(raw, int):
        return None  # an already-open descriptor
    try:
        text = os.fsdecode(raw)
    except (TypeError, ValueError):
        return None
    return text if text and "\0" not in text else None


def _cwd() -> str:
    try:
        return os.getcwd()
    except OSError:
        return "/"


def _posix_forms(text: str) -> list[str]:
    """``text`` as the kernel would resolve it.

    Absolute, with ``.``, ``..`` and repeated ``/`` collapsed - a leading
    ``//`` too, which POSIX leaves implementation-defined and Linux and macOS
    treat as ``/``. On a POSIX host the symlink-resolved form follows it.
    """
    joined = text if text.startswith("/") else posixpath.join(_cwd(), text)
    absolute = posixpath.normpath("/" + joined.lstrip("/"))
    forms = [absolute]
    if os.name == "posix":
        try:
            real = os.path.realpath(text)
        except (OSError, ValueError):
            real = absolute
        if real != absolute:
            forms.append(real)
    return forms


def _linux_rule(path: str) -> str | None:
    if _NODE.match(path):
        return f"block-device node {path}"
    if path in _TABLES:
        return f"kernel block-device table {path}"
    for root in _MEDIA:
        if path == root or path.startswith(root + "/"):
            return media_reason(path, _mounts())
    for root in _ROOTS:
        if path == root or path.startswith(root + "/"):
            return f"{path} (under {root})"
    for tree in (*_TREES, _DEVNUMS):
        if path == tree:
            return f"block-device tree {tree} (discovery)"
        if path.startswith(tree + "/"):
            name = path[len(tree) + 1 :].split("/", 1)[0]
            if tree == _DEVNUMS:
                allowed = name in _ALLOWED_DEVNUMS
            else:
                allowed = name in ALLOWED_DISKS or not _KERNEL_NAME.match(name)
            if not allowed:
                return f"sysfs entry of a block device other than the suite's {path}"
    return None


def _macos_rule(path: str) -> str | None:
    folded = path.casefold()
    if _MAC_NODE.match(folded):
        return f"block-device node {path}"
    if folded == "/volumes":
        return "the mounted-volume directory /Volumes (discovery)"
    if folded.startswith("/volumes/"):
        if folded.split("/", 3)[2] not in ALLOWED_VOLUMES:
            return f"{path} (a mounted volume other than the suite's)"
    return None


def _windows_parts(rest: str) -> list[str]:
    """Components, with the trailing dots and spaces Win32 would strip."""
    return [part.rstrip(" .") or part for part in re.split(r"\\+", rest)]


def _windows_resolved(parts: list[str]) -> list[str]:
    """``.`` and ``..`` resolved, ``..`` allowed to climb past the first part."""
    stack: list[str] = []
    for part in parts:
        if part == ".":
            continue
        if part == "..":
            if stack:
                stack.pop()
            continue
        stack.append(part)
    return stack


def _windows_head_reason(head: str, has_tail: bool) -> str | None:
    if head.startswith("physicaldrive"):
        return "physical disk"
    if head.startswith("harddisk"):
        return "disk partition or volume device"
    if re.fullmatch(r"(?:cdrom|tape|changer|floppy)\d*", head):
        return "removable-media device"
    if re.fullmatch(r"scsi\d+:?", head):
        return "SCSI port device"
    if head in ("globalroot", "mountpointmanager"):
        return "NT device namespace"
    if "#" in head:
        return "device-interface path"
    if not has_tail and (
        re.fullmatch(r"[a-z]:", head) or re.fullmatch(r"volume\{[0-9a-f-]+\}", head)
    ):
        return "raw volume"
    return None


def _windows_rule(text: str) -> str | None:
    folded = text.replace("/", "\\").casefold()
    if _WIN_NT_DEVICE.match(folded):
        return f"NT device object {text}"
    match = _WIN_NAMESPACE.match(folded)
    if not match:
        return None
    parts = _windows_parts(folded[match.end() :])
    for form in (parts, _windows_resolved(parts)):
        if form:
            reason = _windows_head_reason(form[0], len(form) > 1)
            if reason:
                return f"{reason} {text}"
    return None


def path_reason(raw: Any, host: str | None = None) -> str | None:
    """Why opening ``raw`` is refused under ``host``'s rules, or ``None``.

    ``host`` is :data:`LINUX`, :data:`MACOS` or :data:`WINDOWS`; ``None`` means
    the rules the hook applies (:data:`ACTIVE`).
    """
    rules = _rules(host)
    text = _text(raw)
    if text is None or rules is None:
        return None
    if rules == WINDOWS:
        return _windows_rule(text)
    rule = _linux_rule if rules == LINUX else _macos_rule
    for path in _posix_forms(text):
        reason = rule(path)
        if reason:
            return reason
    return None


def _listing_reason(raw: Any, host: str | None = None) -> str | None:
    rules = _rules(host)
    reason = path_reason(raw, rules)
    text = _text(raw)
    if reason or text is None or rules not in (LINUX, MACOS):
        return reason
    for path in _posix_forms(text):
        if (path.casefold() if rules == MACOS else path) == "/dev":
            return "a listing of /dev (discovery)"
    return None


def _glob_reason(pattern: Any, host: str | None = None) -> str | None:
    rules = _rules(host)
    text = _text(pattern)
    if text is None or rules not in (LINUX, MACOS):
        return None
    head = text.split("*", 1)[0].split("?", 1)[0].split("[", 1)[0]
    squeezed = re.sub(r"/(?:\./)+", "/", re.sub(r"/+", "/", head))
    for candidate in {head, squeezed}:
        folded = candidate.casefold() if rules == MACOS else candidate
        if folded.startswith("/dev/") and not folded.startswith(_NOT_DEVICES):
            return f"a glob over device nodes {text}"
    return _listing_reason(posixpath.dirname(head) or head, rules) if head else None


# --------------------------------------------------------------------------
# Commands: shared pieces
# --------------------------------------------------------------------------


def _operands(argv: list[str]) -> list[str]:
    """Each argument, its value after ``=``, and an option's value after ``:``."""
    parts: list[str] = []
    for token in argv[1:]:
        parts.append(token)
        if "=" in token:
            parts.append(token.split("=", 1)[1])
        if token[:1] in "-/" and ":" in token:
            parts.append(token.split(":", 1)[1])
    return parts


def _device_operand(argv: list[str], host: str) -> str | None:
    for part in _operands(argv):
        if "/" in part or "\\" in part:
            reason = path_reason(part, host)
            if reason:
                return reason
    return None


def _is_virtual(token: str) -> bool:
    return token.startswith("/dev/loop") or os.path.isfile(token)


def _argv(value: Any) -> list[str]:
    if isinstance(value, (str, bytes)):
        text = os.fsdecode(value)
        try:
            return shlex.split(text)
        except ValueError:
            return [text]
    try:
        return [os.fsdecode(item) for item in value]
    except TypeError:
        return []


def _nested(argv: Sequence[str]) -> str:
    return (
        f"a command nested more than {_MAX_DEPTH} levels deep, which the guard "
        f"does not unpick: {' '.join(argv)[:200]}"
    )


def _argv_reason(argv: list[str], host: str, depth: int) -> str | None:
    if host == WINDOWS:
        return _windows_argv_reason(argv, depth)
    return _posix_argv_reason(argv, host, depth)


# --------------------------------------------------------------------------
# Commands: POSIX shells and tools (Linux, macOS)
# --------------------------------------------------------------------------


def _posix_name(token: str, host: str) -> str:
    name = PurePosixPath(token).name
    # macOS's root volume is case-insensitive: /usr/sbin/DiskUtil runs diskutil.
    return name.casefold() if host == MACOS else name


def _is_posix_known(name: str, host: str) -> bool:
    if name.startswith(("sg_", *_RAW_PREFIXES)):
        return True
    families = (
        _DISCOVERY, _RAW_IO, _LISTERS, _SHELLS, _KEYWORDS, _WRAPPERS,
        _POSIX_SPECIAL,
    )  # fmt: skip
    if any(name in family for family in families):
        return True
    return host == MACOS and (name in _MAC_ALWAYS or name in _MAC_SPECIAL)


def _shell_script(argv: list[str]) -> str | None:
    """The script a POSIX shell's ``-c`` runs, ``-lc`` and ``-e -c`` included."""
    has_c = False
    index = 1
    while index < len(argv):
        token = argv[index]
        if token == "--":
            index += 1
            break
        if token in ("-o", "+o", "-O", "+O", "--rcfile", "--init-file"):
            index += 2
            continue
        if token.startswith("--command="):
            return token.split("=", 1)[1]
        if token.startswith("--"):
            has_c = has_c or token == "--command"
            index += 1
            continue
        if len(token) > 1 and token[0] in "-+":
            has_c = has_c or (token[0] == "-" and "c" in token[1:])
            index += 1
            continue
        break
    return argv[index] if has_c and index < len(argv) else None


def _option_value(argv: list[str], names: tuple[str, ...]) -> str | None:
    for index, token in enumerate(argv[1:], start=1):
        if token in names and index + 1 < len(argv):
            return argv[index + 1]
        for name in names:
            if name.startswith("--") and token.startswith(name + "="):
                return token.split("=", 1)[1]
    return None


def _ioreg_reports_storage(args: list[str]) -> bool:
    """``ioreg`` narrowed to a non-storage class, name or key is allowed."""
    narrowed = False
    for index, token in enumerate(args):
        if token in ("-c", "-n", "-k") and index + 1 < len(args):
            narrowed = True
            value = args[index + 1].casefold()
            if any(word in value for word in _STORAGE_WORDS):
                return True
    return not narrowed


def _profiler_reports_storage(args: list[str]) -> bool:
    folded = [token.casefold() for token in args]
    if "-listdatatypes" in folded:
        return False
    types = [token for token in folded if token.startswith("sp")]
    return not types or any(token in _PROFILER_STORAGE for token in types)


def _posix_tool_reason(argv: list[str], name: str, host: str) -> str | None:
    shown = shlex.join(argv)
    if host == MACOS and name in _MAC_ALWAYS:
        return (
            f"{name}, which reaches the host's disks through Disk Arbitration "
            f"or IOKit: {shown}"
        )
    discovery = (
        name in _DISCOVERY
        or name.startswith("sg_")
        or (host == MACOS and name == "hdiutil")
    )
    raw = name in _RAW_IO or name.startswith(_RAW_PREFIXES)
    if discovery or raw:
        device = _device_operand(argv, host)
        if device:
            return f"{name} naming {device}: {shown}"
    if name in _LISTERS:
        for part in _operands(argv):
            listing = _listing_reason(part, host) if "/" in part else None
            if listing:
                return f"{name} naming {listing}: {shown}"
    if host == MACOS and name == "ioreg" and _ioreg_reports_storage(argv[1:]):
        return f"ioreg reporting the I/O Kit storage registry: {shown}"
    if host == MACOS and name == "system_profiler":
        if _profiler_reports_storage(argv[1:]):
            return f"system_profiler reporting storage devices: {shown}"
    if host == MACOS and name == "hdiutil" and len(argv) > 1:
        if argv[1].casefold() in _HDIUTIL_MAKERS:
            return None
    if discovery and not any(_is_virtual(part) for part in _operands(argv)):
        return (
            f"{name} with no loop-device or regular-file operand, which "
            f"addresses every device: {shown}"
        )
    return None


def _posix_argv_reason(argv: list[str], host: str, depth: int) -> str | None:
    if depth > _MAX_DEPTH:
        return _nested(argv)
    while argv and _ASSIGNMENT.match(argv[0]):
        argv = argv[1:]
    if not argv:
        return None
    name = _posix_name(argv[0], host)
    if name in _KEYWORDS:
        rest = argv[1:]
        if name == "command" and any(token in ("-v", "-V") for token in rest[:2]):
            return None  # prints where the program is; runs nothing
        if name != "!":
            while rest and rest[0].startswith("-"):
                rest = rest[1:]
        return _posix_argv_reason(rest, host, depth + 1)
    if name in _WRAPPERS:
        for index in range(1, len(argv)):
            if _is_posix_known(_posix_name(argv[index], host), host):
                return _posix_argv_reason(argv[index:], host, depth + 1)
        return None
    script: str | None = None
    if name in _SHELLS:
        script = _shell_script(argv)
    elif name in ("su", "runuser"):
        script = _option_value(argv, ("-c", "--command"))
    elif name == "eval":
        script = " ".join(argv[1:])
    else:
        reason = _posix_tool_reason(argv, name, host)
        if reason or name != "find":
            return reason
        for index, token in enumerate(argv):
            if token in ("-exec", "-execdir", "-ok", "-okdir"):
                stop = next(
                    (j for j in range(index + 1, len(argv)) if argv[j] in (";", "+")),
                    len(argv),
                )
                reason = _posix_argv_reason(argv[index + 1 : stop], host, depth + 1)
                if reason:
                    return reason
        return None
    return None if script is None else _posix_script_reason(script, host, depth + 1)


def _lex(text: str) -> list[str]:
    lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    return list(lexer)


def _script_tokens(script: str) -> list[str]:
    """Tokens, a newline read as ``;``. A script ``shlex`` cannot parse whole
    is lexed line by line, and a line it still cannot parse word by word."""
    try:
        return _lex(script.replace("\n", "\n ; "))
    except ValueError:
        pass
    tokens: list[str] = []
    for line in script.splitlines():
        try:
            tokens += _lex(line)
        except ValueError:
            words = re.split(r"([;&|()<>]+)|\s+", line)
            tokens += [word.strip("'\"") for word in words if word]
        tokens.append(";")
    return tokens


def _script_commands(script: str) -> list[tuple[list[str], list[str]]]:
    """``(argv, redirection targets)`` for each simple command in ``script``."""
    commands: list[tuple[list[str], list[str]]] = [([], [])]
    tokens = iter(_script_tokens(script))
    for token in tokens:
        if not token or not set(token) <= _PUNCTUATION:
            commands[-1][0].append(token)
        elif not any(char in token for char in ";()") and any(
            char in token for char in "<>"
        ):
            target = next(tokens, "")
            if not token.startswith("<<"):  # a here-document's word is no path
                commands[-1][1].append(target)
        else:
            commands.append(([], []))
    return [command for command in commands if command[0] or command[1]]


def _substitutions(script: str) -> tuple[str, list[str]]:
    """``script`` with ``$(...)``, backticks and ``<(...)`` taken out, and
    their bodies - innermost first, quoted or not."""
    bodies: list[str] = []

    def take(match: re.Match[str]) -> str:
        bodies.append(match[1] if match[1] is not None else match[2])
        return " _ "

    while True:
        script, count = _SUBSTITUTION.subn(take, script)
        if not count:
            return script, bodies


def _posix_script_reason(script: str, host: str, depth: int) -> str | None:
    if depth > _MAX_DEPTH:
        return _nested([script])
    remaining, bodies = _substitutions(script)
    for body in bodies:
        reason = _posix_script_reason(body, host, depth + 1)
        if reason:
            return reason
    for argv, targets in _script_commands(remaining):
        for target in targets:
            pathlike = "/" in target or "\\" in target
            reason = path_reason(target, host) if pathlike else None
            if reason:
                return f"a shell redirection to {reason}"
        reason = _argv_reason(argv, host, depth + 1) if argv else None
        if reason:
            return reason
    return None


# --------------------------------------------------------------------------
# Commands: Windows (CreateProcess, cmd.exe, PowerShell)
# --------------------------------------------------------------------------


def _win_name(token: str) -> str:
    name = PureWindowsPath(token.replace('"', "").strip()).name
    name = name.casefold().rstrip(" .")
    for suffix in _EXECUTABLE_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _is_windows_known(name: str) -> bool:
    families = (
        _WIN_ALWAYS, _WIN_RAW_IO, _WIN_CONDITIONAL, _POWERSHELLS, _WIN_WRAPPERS,
        _RAW_IO, _SHELLS, _WRAPPERS,
    )  # fmt: skip
    return name == "cmd" or any(name in family for family in families)


def _windows_program(line: str) -> tuple[str, int]:
    """``argv[0]`` of a command line and the index after it, as CreateProcess
    reads it: to the closing quote if it starts with one, else to whitespace."""
    index = 0
    while index < len(line) and line[index] in " \t":
        index += 1
    if index < len(line) and line[index] == '"':
        end = line.find('"', index + 1)
        if end < 0:
            return line[index + 1 :], len(line)
        return line[index + 1 : end], end + 1
    end = index
    while end < len(line) and line[end] not in " \t":
        end += 1
    return line[index:end], end


def _windows_split(line: str) -> list[str]:
    """A command line split as ``CommandLineToArgvW`` and the C runtime do."""
    program, index = _windows_program(line)
    if not program and index >= len(line.rstrip()):
        return []
    args = [program]
    size = len(line)
    while True:
        while index < size and line[index] in " \t":
            index += 1
        if index >= size:
            return args
        chars: list[str] = []
        quoted = False
        while index < size:
            char = line[index]
            if char == "\\":
                end = index
                while end < size and line[end] == "\\":
                    end += 1
                count = end - index
                if end < size and line[end] == '"':
                    chars.append("\\" * (count // 2))
                    if count % 2:
                        chars.append('"')
                        end += 1
                    index = end
                else:
                    chars.append("\\" * count)
                    index = end
                continue
            if char == '"':
                if quoted and index + 1 < size and line[index + 1] == '"':
                    chars.append('"')
                    index += 2
                    continue
                quoted = not quoted
                index += 1
                continue
            if not quoted and char in " \t":
                break
            chars.append(char)
            index += 1
        args.append("".join(chars))


def _cmd_script(tail: str) -> str | None:
    """What ``cmd.exe`` runs, from the text after its own name: whatever
    follows ``/c``, ``/k`` or ``/r``, past any other switches."""
    index = 0
    while index < len(tail):
        while index < len(tail) and tail[index] in " \t":
            index += 1
        if index >= len(tail) or tail[index] != "/":
            return None
        if index + 1 < len(tail) and tail[index + 1].casefold() in "ckr":
            return tail[index + 2 :]
        index += 1
        while index < len(tail) and tail[index] not in " \t/":
            index += 1
    return None


def _cmd_redirects(segment: str) -> tuple[str, list[str]]:
    """``segment`` without its redirections, and their targets."""
    kept: list[str] = []
    targets: list[str] = []
    quoted = False
    index = 0
    size = len(segment)
    while index < size:
        char = segment[index]
        if char == '"':
            quoted = not quoted
        if quoted or char not in "<>":
            kept.append(char)
            index += 1
            continue
        while index < size and segment[index] in "<>":
            index += 1
        if index < size and segment[index] == "&":  # 2>&1: a handle, no path
            index += 1
            while index < size and segment[index].isdigit():
                index += 1
            continue
        while index < size and segment[index] in " \t":
            index += 1
        if index < size and segment[index] == '"':
            end = segment.find('"', index + 1)
            end = size if end < 0 else end
            targets.append(segment[index + 1 : end])
            index = end + 1
        else:
            start = index
            while index < size and segment[index] not in " \t<>":
                index += 1
            targets.append(segment[start:index])
    return "".join(kept), targets


def _cmd_commands(script: str) -> list[tuple[str, list[str]]]:
    """``(command text, redirection targets)`` for each command of a ``cmd``
    script: ``^`` escapes undone outside quotes, split on ``&``, ``|``,
    parentheses and line breaks outside quotes."""
    segments: list[str] = []
    chars: list[str] = []
    quoted = False
    index = 0
    while index < len(script):
        char = script[index]
        if char == '"':
            quoted = not quoted
            chars.append(char)
        elif quoted:
            chars.append(char)
        elif char == "^" and index + 1 < len(script):
            index += 1
            chars.append(script[index])
        elif char in "&|()\r\n":
            segments.append("".join(chars))
            chars = []
        else:
            chars.append(char)
        index += 1
    segments.append("".join(chars))
    commands: list[tuple[str, list[str]]] = []
    for segment in segments:
        text, targets = _cmd_redirects(segment)
        text = text.strip().lstrip("@").strip()
        if text or targets:
            commands.append((text, targets))
    return commands


def _cmd_script_reason(script: str, depth: int) -> str | None:
    """Judge a ``cmd /c`` script, with and without its outer quotes: which
    ``cmd`` strips depends on switches and quote counts, so both are read."""
    if depth > _MAX_DEPTH:
        return _nested([script])
    variants = [script]
    stripped = script.strip()
    if stripped.startswith('"'):
        body = stripped[1:]
        last = body.rfind('"')
        variants.append(body[:last] + body[last + 1 :] if last >= 0 else body)
    for variant in variants:
        for text, targets in _cmd_commands(variant):
            for target in targets:
                reason = path_reason(target, WINDOWS)
                if reason:
                    return f"a cmd redirection to {reason}"
            argv = _windows_split(text) if text else []
            reason = _windows_argv_reason(argv, depth + 1) if argv else None
            if reason:
                return reason
    return None


def _windows_line_reason(line: str, depth: int) -> str | None:
    program, end = _windows_program(line)
    if _win_name(program) == "cmd":
        script = _cmd_script(line[end:])
        return None if script is None else _cmd_script_reason(script, depth + 1)
    return _windows_argv_reason(_windows_split(line), depth)


def _decode_encoded(value: str) -> str:
    """An ``-EncodedCommand`` value: base64 of UTF-16LE, or itself if not."""
    try:
        return base64.b64decode(value.strip("'\" "), validate=True).decode("utf-16-le")
    except (binascii.Error, ValueError):
        return value


_PS_VALUE_OPTIONS = (
    "executionpolicy", "windowstyle", "workingdirectory", "version",
    "psconsolefile", "outputformat", "inputformat", "configurationname",
    "settingsfile", "custompipename", "encodedarguments",
)  # fmt: skip
_PS_VALUE_ALIASES = frozenset({"ep", "w", "wd", "of", "if", "ea"})


def _powershell_scripts(argv: list[str]) -> list[str]:
    """The script text a ``powershell``/``pwsh`` command line runs.

    ``-Command`` (any unambiguous prefix, ``-c``) takes the rest of the line;
    ``-EncodedCommand`` (``-e``, ``-ec``, ``-enc``, ...) is decoded; with
    neither, the first positional argument starts the script (Windows
    PowerShell reads it as ``-Command``; PowerShell 7 as ``-File``, whose
    script is out of view, so reading it as a command is the stricter choice).
    ``-File`` names a script file, which is out of view.
    """
    scripts: list[str] = []
    index = 1
    while index < len(argv):
        token = argv[index]
        if token[:1] not in "-/" or token in ("-", "/"):
            scripts.append(" ".join(argv[index:]))
            break
        name, _, inline = token.lstrip("-/").casefold().partition(":")
        if name in ("e", "ec") or (
            name.startswith("en") and "encodedcommand".startswith(name)
        ):
            value = inline or (argv[index + 1] if index + 1 < len(argv) else "")
            scripts.append(_decode_encoded(value))
            index += 1 if inline else 2
            continue
        if name == "cwa" or (
            name.startswith("c")
            and ("command".startswith(name) or "commandwithargs".startswith(name))
        ):
            scripts.append(" ".join(([inline] if inline else []) + argv[index + 1 :]))
            break
        if name == "f" or (name.startswith("fi") and "file".startswith(name)):
            break
        takes_value = name in _PS_VALUE_ALIASES or (
            len(name) >= 2 and any(full.startswith(name) for full in _PS_VALUE_OPTIONS)
        )
        index += 2 if takes_value and not inline else 1
    return scripts


def _powershell_script_reason(script: str, depth: int) -> str | None:
    if depth > _MAX_DEPTH:
        return _nested([script])
    text = script.replace("`", "")
    bare = re.sub(r"['\"]", " ", text)
    folded = bare.casefold()
    for pattern, what in (
        (_PS_CMDLET, "storage cmdlet"),
        (_WMI_CLASS, "storage WMI/CIM class"),
        (_DISK_WORD, "disk device name"),
    ):
        found = pattern.search(folded)
        if found:
            return f"{what} {found[0]}"
    for found in _WIN_PATH_IN_TEXT.finditer(text):
        reason = _windows_rule(found[0])
        if reason:
            return reason
    for statement in re.split(r"[;|\n\r{}()&]+", text):
        statement = _PS_ASSIGNMENT.sub("", statement)
        tokens = [
            token.strip("'\"")
            for token in re.findall(r"\"[^\"]*\"|'[^']*'|\S+", statement)
        ]
        while tokens and tokens[0] == ".":  # dot-sourcing
            tokens = tokens[1:]
        reason = _windows_argv_reason(tokens, depth + 1) if tokens else None
        if reason:
            return reason
    return None


def _windows_argv_reason(argv: list[str], depth: int) -> str | None:
    if depth > _MAX_DEPTH:
        return _nested(argv)
    argv = [token for token in argv if token]  # start "" /b x: an empty title
    if not argv:
        return None
    name = _win_name(argv[0])
    shown = subprocess.list2cmdline(argv)
    if name in _WIN_WRAPPERS or name in _WRAPPERS:
        for index in range(1, len(argv)):
            if _is_windows_known(_win_name(argv[index])):
                return _windows_argv_reason(argv[index:], depth + 1)
        return None
    if name == "cmd":
        script = _cmd_script(" " + subprocess.list2cmdline(argv[1:]))
        return None if script is None else _cmd_script_reason(script, depth + 1)
    if name in _POWERSHELLS:
        for script in _powershell_scripts(argv):
            reason = _powershell_script_reason(script, depth + 1)
            if reason:
                return f"PowerShell running a {reason}: {shown}"
        return None
    if name in _SHELLS:  # Git Bash, MSYS2, Cygwin: POSIX text, Windows devices
        script = _shell_script(argv)
        if script is None:
            return None
        return _posix_script_reason(script, WINDOWS, depth + 1)
    args = [token.casefold() for token in argv[1:]]
    verb = next((token for token in args if token[:1] not in "-/"), "")
    if name in _WIN_ALWAYS:
        return f"{name}, a Windows disk-management tool: {shown}"
    if name == "wmic" and (
        any(token in _WMIC_DISK for token in args) or _WMI_CLASS.search(" ".join(args))
    ):
        return f"wmic querying disks or volumes: {shown}"
    if name == "fsutil" and verb in ("fsinfo", "volume", "repair", "usn"):
        return f"fsutil {verb}, which reads or changes a volume: {shown}"
    if name == "vssadmin" and verb in ("delete", "resize", "create", "add", "revert"):
        return f"vssadmin {verb}, which changes the host's shadow storage: {shown}"
    if name == "cipher" and any(token.startswith("/w") for token in args):
        return f"cipher /w, which overwrites a volume's free space: {shown}"
    if name == "wsl" and any(token in ("--mount", "--unmount") for token in args):
        return f"wsl attaching a physical disk: {shown}"
    if name in _WIN_RAW_IO or name in _RAW_IO or name.startswith(_RAW_PREFIXES):
        device = _device_operand(argv, WINDOWS)
        if device:
            return f"{name} naming {device}: {shown}"
    return None


# --------------------------------------------------------------------------
# Public decisions
# --------------------------------------------------------------------------


def command_reason(command: Sequence[str] | str, host: str | None = None) -> str | None:
    """Why launching ``command`` is refused under ``host``'s rules, or ``None``.

    ``command`` is an argument list, or a command line as the host's launcher
    receives it: on Windows the string ``CreateProcess`` parses (``cmd /c ...``
    included); elsewhere a simple command, split as a POSIX shell would. A
    shell's ``-c`` script is split into its simple commands and each is judged;
    a script ``source``-d from a file is outside this view.
    """
    rules = _rules(host)
    if rules is None:
        return None
    if isinstance(command, str):
        if rules == WINDOWS:
            return _windows_line_reason(command, 0)
        return _argv_reason(_argv(command), rules, 0)
    return _argv_reason(list(command), rules, 0)


def shell_reason(script: Any, host: str | None = None) -> str | None:
    """Why running ``script`` through the host's shell is refused, or ``None``.

    That is ``sh -c`` on Linux and macOS and ``cmd.exe /c`` on Windows: what
    :func:`os.system` and ``subprocess(..., shell=True)`` run.
    """
    rules = _rules(host)
    text = _text(script)
    if rules is None or text is None:
        return None
    if rules == WINDOWS:
        return _cmd_script_reason(text, 0)
    return _posix_script_reason(text, rules, 0)


def launch_reason(executable: Any, args: Any, host: str | None = None) -> str | None:
    """Why starting a process is refused, from what its audit event carries.

    ``args`` is the argument list, or on Windows the command line; an
    ``executable`` that differs from ``argv[0]`` is judged in its place too.
    """
    rules = _rules(host)
    if rules is None:
        return None
    program = _text(executable) if executable is not None else None
    if isinstance(args, (str, bytes)):
        line = os.fsdecode(args)
        reason = command_reason(line, rules)
        if reason is None and program:
            if rules == WINDOWS:
                _, end = _windows_program(line)
                swapped = subprocess.list2cmdline([program]) + line[end:]
                reason = _windows_line_reason(swapped, 0)
            else:
                reason = _argv_reason([program, *_argv(line)[1:]], rules, 0)
        return reason
    argv = _argv(args)
    reason = _argv_reason(argv, rules, 0)
    if reason is None and program:
        reason = _argv_reason([program, *argv[1:]], rules, 0)
    return reason


def event_reason(
    event: str, args: tuple[Any, ...], host: str | None = None
) -> str | None:
    """Why the operation an audit event announces is refused, or ``None``."""
    rules = _rules(host)
    if rules is None or event not in GUARDED_EVENTS:
        return None
    if event in ("open", "_winapi.CreateFile", "os.startfile", "os.startfile/2"):
        return path_reason(args[0], rules)
    if event in ("os.listdir", "os.scandir"):
        return _listing_reason(args[0] if args[0] is not None else ".", rules)
    if event in ("glob.glob", "glob.glob/2"):
        return _glob_reason(args[0], rules)
    if event == "os.system":
        return shell_reason(args[0], rules)
    if event == "os.spawn":  # (mode, path, args, env)
        return launch_reason(args[1], args[2], rules)
    # subprocess.Popen (executable, args, cwd, env), os.exec and
    # os.posix_spawn (path, args, env), _winapi.CreateProcess (application
    # name, command line, current directory).
    return launch_reason(args[0], args[1], rules)


# --------------------------------------------------------------------------
# The hooks
# --------------------------------------------------------------------------


#: Per thread: ``judging`` while the guard's own hook runs (so the barrier
#: ignores what the guard itself opens, the mount table), ``armed`` inside
#: :func:`launch_barrier`.
_state = threading.local()


def _hook(event: str, args: tuple[Any, ...]) -> None:
    if event not in GUARDED_EVENTS:
        return
    depth = getattr(_state, "judging", 0)
    _state.judging = depth + 1
    try:
        reason = event_reason(event, args)
    finally:
        _state.judging = depth
    if reason:
        test = os.environ.get("PYTEST_CURRENT_TEST", "outside a test").split(" ")[0]
        BLOCKED.append(f"{test}: {reason}")
        raise HostDeviceAccessBlocked(
            f"refused {reason}. The suite never reaches a host storage device; "
            "give this test a fake probe or fixture instead."
        )


def _reads_no_device(event: str, args: tuple[Any, ...]) -> bool:
    """An ``open`` of a descriptor already open, or of an existing regular file.

    Neither can reach a device, and the barrier has to let both through:
    ``subprocess`` wraps its pipes with ``io.open(fd)`` before it raises
    ``subprocess.Popen``, and a module imported lazily reads its ``.pyc``.
    Found on the macOS CI runner, where the barrier stopped the pipe instead
    of the launch. A Windows device-namespace path is never stat-ed: a stat
    opens a handle to the device.
    """
    if event != "open":
        return False
    if isinstance(args[0], int):
        return True
    text = _text(args[0])
    if text is None or text.replace("/", "\\").startswith("\\\\"):
        return False
    return os.path.isfile(text)


def _barrier_hook(event: str, args: tuple[Any, ...]) -> None:
    if (
        event in GUARDED_EVENTS
        and getattr(_state, "armed", False)
        and not getattr(_state, "judging", 0)
        and not _reads_no_device(event, args)
    ):
        raise BarrierReached(
            f"{event} passed the host-device guard and was stopped by the "
            f"launch barrier: {args!r:.300}"
        )


@contextmanager
def launch_barrier() -> Iterator[None]:
    """Stop, in this thread, every guarded operation the guard lets through.

    The self-test's safety net. Its hook is added straight after the guard's,
    so it sees only what the guard allowed, and it raises :class:`BarrierReached`
    before that open or launch happens. Not stopped: what the guard reads while
    judging (the mount table), and an ``open`` of an already-open descriptor or
    an existing regular file, which cannot reach a device. Inside the block a broken
    guard fails the test; it cannot run a disk command or open a device.
    """
    if not _installed:
        raise RuntimeError("install() adds the barrier's hook; it has not run")
    _state.armed = True
    try:
        yield
    finally:
        _state.armed = False


@contextmanager
def expect_refusal() -> Iterator[list[str]]:
    """Require at least one refusal in the block, and take it off the record.

    Yields the list the block's refusals are moved to, so the session-end
    verdict counts only unexpected ones.
    """
    before = len(BLOCKED)
    taken: list[str] = []
    try:
        yield taken
    finally:
        taken.extend(BLOCKED[before:])
        del BLOCKED[before:]
    if not taken:
        raise AssertionError("the host-device guard refused nothing")


# --------------------------------------------------------------------------
# Installation and the summary
# --------------------------------------------------------------------------


def _lineage(name: str, depth: int = 0) -> set[str]:
    """``name``, the disk it is a partition of, and the devices it is built on."""
    found = {name}
    real = os.path.realpath(f"/sys/class/block/{name}")
    if os.path.exists(os.path.join(real, "partition")):
        found.add(os.path.basename(os.path.dirname(real)))
    slaves = os.path.join(real, "slaves")
    if depth < 8 and os.path.isdir(slaves):
        for slave in os.listdir(slaves):
            found |= _lineage(slave, depth + 1)
    return found


def _disks_holding(roots: Iterable[str]) -> set[str]:
    """Kernel names of the block devices that hold ``roots``, and their disks."""
    if not sys.platform.startswith("linux"):
        return set()  # os.major and sysfs are Linux's
    mounts = _mounts()
    names: set[str] = set()
    for root in roots:
        real = os.path.realpath(root)
        hit = _mount_of(real, mounts)
        if hit and hit[1].startswith("/dev/") and os.path.exists(hit[1]):
            names |= _lineage(os.path.basename(os.path.realpath(hit[1])))
        try:
            dev = os.stat(real).st_dev
        except OSError:
            continue
        if os.major(dev):  # 0 is tmpfs, btrfs subvolumes, overlays
            link = f"{_DEVNUMS}/{os.major(dev)}:{os.minor(dev)}"
            names |= _lineage(os.path.basename(os.path.realpath(link)))
    return {name for name in names if _KERNEL_NAME.match(name)}


def _volumes_holding(roots: Iterable[str]) -> set[str]:
    """Names under ``/Volumes`` (case-folded) that hold ``roots``."""
    names: set[str] = set()
    for root in roots:
        real = os.path.realpath(root).casefold()
        if real.startswith("/volumes/"):
            names.add(real.split("/", 3)[2])
    return names


_installed = False


def install(roots: Iterable[str]) -> None:
    """Work out what the suite's own files sit on, then add the hooks, once.

    That is computed before the hooks exist, so working it out is not itself
    refused. The guard's hook goes first and the barrier's second. Neither can
    be removed afterwards.
    """
    global _installed, ALLOWED_DISKS, _ALLOWED_DEVNUMS, ALLOWED_VOLUMES
    if _installed:
        return
    roots = list(roots)
    if ACTIVE == LINUX:
        ALLOWED_DISKS = frozenset(_disks_holding(roots))
        numbers = set()
        for name in ALLOWED_DISKS:
            try:
                with open(f"/sys/class/block/{name}/dev", encoding="ascii") as handle:
                    numbers.add(handle.read().strip())
            except OSError:
                continue
        _ALLOWED_DEVNUMS = frozenset(numbers)
    elif ACTIVE == MACOS:
        ALLOWED_VOLUMES = frozenset(_volumes_holding(roots))
    sys.addaudithook(_hook)
    sys.addaudithook(_barrier_hook)
    _installed = True


def summary_lines() -> list[str]:
    """The end-of-run summary: the rule set applied, refusals, the allowance."""
    if not _installed:
        return ["Host-device guard: not installed; nothing is refused"]
    if ACTIVE is None:
        return [
            "Host-device guard: no rules active - there is no rule set for "
            f"sys.platform {sys.platform!r}, so no host device is refused here"
        ]
    detail = f"Host-device guard: {len(BLOCKED)} refusal(s)"
    if ACTIVE == LINUX:
        disks = ", ".join(sorted(ALLOWED_DISKS)) or "none"
        detail += (
            f"; sysfs attributes readable only for {disks} (the disk holding "
            "the suite's files)"
        )
    elif ACTIVE == MACOS:
        volumes = ", ".join(sorted(ALLOWED_VOLUMES)) or "none"
        detail += (
            f"; readable under /Volumes: {volumes} (only the volume holding the "
            "suite's files)"
        )
    return [f"Host-device guard: {RULE_SETS[ACTIVE]} rules active", detail]
