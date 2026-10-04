"""Fakes and captured tool output for core.device tests.

No real device access: every probe is driven by a FakeRunner returning captured
command output and by a synthetic sysfs tree under tmp_path.
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from core.device._sysio import CommandResult

# --------------------------------------------------------------------------
# Fake runner
# --------------------------------------------------------------------------


class FakeRunner:
    """Maps an argv prefix to a canned :class:`CommandResult`."""

    def __init__(self, responses: dict[tuple[str, ...], CommandResult]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str]) -> CommandResult:
        key = tuple(argv)
        self.calls.append(key)
        if key in self.responses:
            return self.responses[key]
        # Longest matching prefix wins, so tests can key on the tool + subcommand.
        for prefix in sorted(self.responses, key=len, reverse=True):
            if key[: len(prefix)] == prefix:
                return self.responses[prefix]
        return CommandResult(
            argv=list(argv), returncode=127, stdout="", stderr="command not found"
        )


def ok(stdout: str) -> CommandResult:
    return CommandResult(argv=[], returncode=0, stdout=stdout, stderr="")


def fail(returncode: int = 1, stderr: str = "") -> CommandResult:
    return CommandResult(argv=[], returncode=returncode, stdout="", stderr=stderr)


MISSING = CommandResult(argv=[], returncode=127, stdout="", stderr="not found")


# --------------------------------------------------------------------------
# Captured lsblk output
# --------------------------------------------------------------------------

LSBLK_JSON = json.dumps(
    {
        "blockdevices": [
            {
                "name": "nvme0n1",
                "kname": "nvme0n1",
                "path": "/dev/nvme0n1",
                "type": "disk",
                "model": "Samsung SSD 980 PRO 1TB",
                "serial": "S5GXNX0R123456",
                "size": 1000204886016,
                "rota": False,
                "tran": "nvme",
                "pttype": "gpt",
                "mountpoints": [None],
                "children": [
                    {
                        "name": "nvme0n1p1",
                        "kname": "nvme0n1p1",
                        "type": "part",
                        "size": 536870912,
                        "mountpoints": ["/boot/efi"],
                        "pkname": "nvme0n1",
                    },
                    {
                        "name": "nvme0n1p2",
                        "kname": "nvme0n1p2",
                        "type": "part",
                        "size": 999667990528,
                        "mountpoints": ["/"],
                        "pkname": "nvme0n1",
                    },
                ],
            },
            {
                "name": "sda",
                "kname": "sda",
                "path": "/dev/sda",
                "type": "disk",
                "model": "Cruzer Blade",
                "serial": "4C530001120523107104",
                "size": 15597568000,
                "rota": True,
                "tran": "usb",
                "pttype": "dos",
                "mountpoints": [None],
                "children": [
                    {
                        "name": "sda1",
                        "kname": "sda1",
                        "type": "part",
                        "size": 15596519424,
                        "mountpoints": ["/media/usb"],
                        "pkname": "sda",
                    }
                ],
            },
            {
                "name": "sdb",
                "kname": "sdb",
                "path": "/dev/sdb",
                "type": "disk",
                "model": "ST2000DM008-2FR102",
                "serial": "ZFL2ABCD",
                "size": 2000398934016,
                "rota": True,
                "tran": "ata",
                "pttype": None,
                "mountpoints": [None],
            },
            {
                "name": "sr0",
                "kname": "sr0",
                "path": "/dev/sr0",
                "type": "rom",
                "model": "DVD-RW",
                "serial": None,
                "size": 1073741312,
                "rota": True,
                "tran": "sata",
                "pttype": None,
                "mountpoints": [None],
            },
            {
                "name": "loop0",
                "kname": "loop0",
                "path": "/dev/loop0",
                "type": "loop",
                "model": None,
                "serial": None,
                "size": 67108864,
                "rota": False,
                "tran": None,
                "pttype": None,
                "mountpoints": ["/mnt/corpus"],
            },
        ]
    }
)

# Older util-linux emits a scalar "mountpoint" instead of the "mountpoints" list.
LSBLK_JSON_LEGACY_MOUNTPOINT = json.dumps(
    {
        "blockdevices": [
            {
                "name": "sdb",
                "type": "disk",
                "model": "ST2000DM008",
                "serial": "ZFL2ABCD",
                "size": 2000398934016,
                "rota": True,
                "tran": "ata",
                "pttype": "gpt",
                "mountpoint": None,
                "children": [
                    {
                        "name": "sdb1",
                        "type": "part",
                        "size": 2000397885440,
                        "mountpoint": "/data",
                    }
                ],
            }
        ]
    }
)


FINDMNT_ROOT = "/dev/nvme0n1p2\n"
SWAPS_NONE = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
SWAPS_ON_SDB = (
    "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
    "/dev/sdb2                               partition\t8388604\t\t0\t\t-2\n"
)


#: link name under /dev/disk/by-id -> kernel device name it resolves to.
#: Injected directly rather than built from symlinks so the suite runs on hosts
#: where creating symlinks is not permitted.
BY_ID_MAP = {
    "nvme-Samsung_SSD_980_PRO_1TB_S5GXNX0R123456": "nvme0n1",
    "nvme-eui.0025385991b1c2d3": "nvme0n1",
    "usb-SanDisk_Cruzer_Blade_4C530001120523107104-0:0": "sda",
    "ata-ST2000DM008-2FR102_ZFL2ABCD": "sdb",
    "wwn-0x5000c500a1b2c3d4": "sdb",
}
