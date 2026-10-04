"""Qualify an interface's software write block by trying to defeat it.

**Scratch media only. This writes to the device if the write block fails**, which
is exactly the case you are testing for. Never point it at evidence: a write
test is safe only when the block works, and it is precisely when the block does
not work that the test writes to the thing it was protecting.

That asymmetry is why ``core.carve.acquire.apply_write_block`` does not do this
itself. The acquisition path sets BLKROSET, reads it back, and says on the
record that the refusal was not verified. Verification lives here, run once
against scratch media to qualify a bridge, which is how write blockers are
qualified in practice.

A flag that reads back set but does not refuse a write is worse than no write
block at all: the acquisition record would claim a protection that does not
exist, and every downstream statement about the evidence path inherits that.

Measured on a Toshiba TransMemory behind a USB bridge, 2026-09-05:
``WRITE_BLOCK_WORKS``, with the refusal arriving at ``write()`` with ``EPERM``
while ``open(O_WRONLY)`` **succeeded**. A check that stopped at the open would
have reported a working block on a cosmetic flag. Test the write, not the open.

Sequence, against a region of the device that is deliberately overwritten and
then restored:

  1. read and hash the probe region, so any change is detectable
  2. record the device's current read-only flag, so it can be put back
  3. BLKROSET 1, then BLKROGET to read it back
  4. attempt to open O_WRONLY, and if that succeeds attempt an actual write
  5. re-read the region and compare - the only evidence that matters
  6. clear the flag, restore the region if it changed, verify the restore
  7. also run core.carve.acquire.apply_write_block so the tool's own verdict
     is recorded beside the raw one

Destructive only within the probe region, and only if the write block fails -
which is the finding. Run as root:

  cd /path/to/sanctum-forensics
  sudo .venv/bin/python scripts/probe-write-block.py /dev/sdX \\
      --i-understand-this-may-write-to-the-device
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import struct
import sys
from pathlib import Path
from typing import Any

BLKROSET = 0x125D
BLKROGET = 0x125E
BLKGETSIZE64 = 0x80081272

#: Far enough in to be nowhere near a partition table or a filesystem
#: superblock, so a failed restore damages nothing structural.
PROBE_OFFSET = 4 * 1024**3
PROBE_BYTES = 1024 * 1024
#: Written only if the write block fails to stop it. Neither 0x00 nor 0xA5, so
#: it cannot be confused with a wipe pattern or with this device's fill.
POISON = 0x5A


def get_flag(path: str) -> int | None:
    """The read-only flag, or ``None`` when the ioctl does not apply."""
    fd = os.open(path, os.O_RDONLY)
    try:
        raw = fcntl.ioctl(fd, BLKROGET, struct.pack("i", 0))
        return int(struct.unpack("i", raw)[0])
    except OSError:
        return None
    finally:
        os.close(fd)


def set_flag(path: str, value: int | None) -> str:
    """Set the read-only flag. A ``None`` value means there was nothing to put back."""
    if value is None:
        return "not applicable"
    fd = os.open(path, os.O_RDONLY)
    try:
        fcntl.ioctl(fd, BLKROSET, struct.pack("i", value))
        return ""
    except OSError as exc:
        return errno.errorcode.get(exc.errno or 0, str(exc.errno))
    finally:
        os.close(fd)


def read_region(path: str, offset: int, span: int) -> bytes:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.lseek(fd, offset, os.SEEK_SET)
        chunks, got = [], 0
        while got < span:
            part = os.read(fd, span - got)
            if not part:
                break
            chunks.append(part)
            got += len(part)
        return b"".join(chunks)
    finally:
        os.close(fd)


def try_write(path: str, offset: int, payload: bytes) -> dict[str, Any]:
    """Attempt a real write. Reports where it was refused, if it was."""
    try:
        fd = os.open(path, os.O_WRONLY)
    except OSError as exc:
        return {
            "open_refused": True,
            "open_errno": errno.errorcode.get(exc.errno or 0, str(exc.errno)),
            "write_refused": None,
            "write_errno": None,
            "bytes_written": 0,
        }
    try:
        os.lseek(fd, offset, os.SEEK_SET)
        written = os.write(fd, payload)
        os.fsync(fd)
        return {
            "open_refused": False,
            "open_errno": None,
            "write_refused": False,
            "write_errno": None,
            "bytes_written": written,
        }
    except OSError as exc:
        return {
            "open_refused": False,
            "open_errno": None,
            "write_refused": True,
            "write_errno": errno.errorcode.get(exc.errno or 0, str(exc.errno)),
            "bytes_written": 0,
        }
    finally:
        os.close(fd)


CONFIRM_FLAG = "--i-understand-this-may-write-to-the-device"

#: Above this a "USB stick" is a disk somebody plugged in. The same figure
#: ``scripts/device-gate.sh`` uses, so the two destructive paths refuse the
#: same devices for the same reason.
MAX_SANE_BYTES = 137438953472  # 128 GiB

USAGE = (
    "usage: probe-write-block.py <device> "
    f"{CONFIRM_FLAG}\n"
    "\n"
    "The device is required and is never defaulted. This probe writes to its\n"
    "target when the write block does not hold, which is the case it exists to\n"
    "detect, so a forgotten argument must not become a write to whatever\n"
    "happens to be first on the bus.\n"
)


def _refuse(reason: str) -> int:
    sys.stderr.write(f"REFUSED: {reason}\n")
    return 2


def _assert_scratch_media(path: str) -> str | None:
    """Refuse anything that is not scratch media. Returns a reason, or ``None``.

    The gates are the ones every other destructive path in this repository
    applies, and two of them are not reimplemented here:
    :func:`core.device.guard.assert_erasable` is the same function the erase
    engine calls, so the system-disk and mounted-filesystem refusals cannot
    drift between this script and the tool. Removable and size are checked
    against the figures ``scripts/device-gate.sh`` uses.

    A regular file is allowed through with no device gates, because none of
    them mean anything for an image and running the probe against one is what
    makes it exercisable without hardware. A regular file cannot be a raw
    device, so nothing is weakened by allowing it.
    """
    # Run from anywhere: the repository root has to be importable for `core`.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

    from core.device.enumerate import get_device
    from core.device.guard import assert_erasable
    from core.errors import SanctumError

    try:
        mode = os.stat(path).st_mode
    except OSError as exc:
        return f"{path} cannot be read: {exc}"

    import stat as stat_mod

    if stat_mod.S_ISREG(mode):
        return None
    if not stat_mod.S_ISBLK(mode):
        return (
            f"{path} is neither a block device nor a regular file. This probe "
            "runs against scratch media or an image, and nothing else."
        )

    try:
        device = get_device(path)
    except SanctumError as exc:
        return f"{path} could not be identified: {exc.message}"

    # The system disk and any mounted filesystem, refused by the same function
    # the erase engine uses rather than by a second copy of the rule.
    try:
        assert_erasable(device)
    except SanctumError as exc:
        return exc.message

    kernel_name = os.path.basename(os.path.realpath(path))
    removable = ""
    try:
        removable = (
            Path(f"/sys/block/{kernel_name}/removable")
            .read_text(encoding="utf-8")
            .strip()
        )
    except OSError:
        removable = ""
    if removable != "1":
        return (
            f"{path} is not removable (/sys/block/{kernel_name}/removable = "
            f"{removable or 'unreadable'}). This probe writes to its target "
            "when the block fails; point it at scratch media."
        )

    if device.size_bytes > MAX_SANE_BYTES:
        return (
            f"{path} is {device.size_bytes} bytes, over the "
            f"{MAX_SANE_BYTES} byte sanity limit. That is not a scratch stick."
        )

    return None


def main() -> int:
    argv = [item for item in sys.argv[1:] if item != CONFIRM_FLAG]
    confirmed = CONFIRM_FLAG in sys.argv[1:]

    # No default. The confirmation flag is filtered out of argv above, so a run
    # carrying only the flag used to fall through to a hardcoded device path -
    # which on most hosts is the system disk.
    if not argv:
        sys.stderr.write(USAGE)
        return 2
    path = argv[0]

    if not confirmed:
        # The same two-gate shape the erase path uses. This probe writes to the
        # target when the write block fails, and that is not something to
        # discover afterwards.
        sys.stderr.write(
            f"REFUSED: this probe writes to {path} if the write block does not "
            f"hold, which is the case it exists to detect. Point it at scratch "
            f"media, never at evidence, and pass {CONFIRM_FLAG}.\n"
        )
        return 2

    # The flag says "I meant to run a destructive probe". The gates say "against
    # this device". The flag does not replace them, and both run before a single
    # byte is read or written.
    refusal = _assert_scratch_media(path)
    if refusal is not None:
        return _refuse(refusal)

    result: dict[str, Any] = {"step": "write_block_probe", "device": path}

    fd = os.open(path, os.O_RDONLY)
    try:
        try:
            raw = fcntl.ioctl(fd, BLKGETSIZE64, struct.pack("Q", 0))
            size = int(struct.unpack("Q", raw)[0])
        except OSError:
            # Not a block device. The flag ioctls below will report that
            # honestly; letting the probe run against an image is what makes it
            # testable without a device attached.
            size = os.lseek(fd, 0, os.SEEK_END)
    finally:
        os.close(fd)
    result["size_bytes"] = size

    offset = PROBE_OFFSET if size > PROBE_OFFSET + PROBE_BYTES else max(size // 2, 0)
    offset -= offset % 4096
    result["probe_offset"] = offset
    result["probe_bytes"] = PROBE_BYTES

    before = read_region(path, offset, PROBE_BYTES)
    result["region_sha256_before"] = hashlib.sha256(before).hexdigest()
    result["region_distinct_bytes_before"] = sorted(set(before))[:4]

    result["flag_at_start"] = get_flag(path)

    set_error = set_flag(path, 1)
    result["blkroset_error"] = set_error or None
    result["flag_after_set"] = get_flag(path)

    result["write_attempt"] = try_write(path, offset, bytes([POISON]) * 4096)

    after = read_region(path, offset, PROBE_BYTES)
    result["region_sha256_after"] = hashlib.sha256(after).hexdigest()
    result["region_changed"] = after != before

    # -- the verdict -------------------------------------------------------
    attempt = result["write_attempt"]
    blocked = bool(attempt["open_refused"] or attempt["write_refused"])
    if set_error or not result["flag_after_set"]:
        result["verdict"] = "FLAG_REFUSED"
        result["verdict_detail"] = (
            "BLKROSET did not take. The tool already reports this as "
            "WRITE_BLOCK_NOT_APPLIED; confirm that limitation appears on the "
            "acquisition record."
        )
    elif blocked and not result["region_changed"]:
        result["verdict"] = "WRITE_BLOCK_WORKS"
        result["verdict_detail"] = (
            "The flag read back set and the write was refused. Software write "
            "block is real on this bridge."
        )
    elif result["region_changed"]:
        result["verdict"] = "FLAG_COSMETIC"
        result["verdict_detail"] = (
            "The flag read back set and the device was written anyway. The "
            "acquisition record must NOT claim a software write block on this "
            "transport."
        )
    else:
        result["verdict"] = "INCONCLUSIVE"
        result["verdict_detail"] = (
            "The write was refused but the region also did not change, and one "
            "of those should have been decisive. Read the raw fields."
        )

    # -- restore -----------------------------------------------------------
    restore: dict[str, Any] = {"flag_restored_to": result["flag_at_start"]}
    set_flag(path, 0)
    if result["region_changed"]:
        fd = os.open(path, os.O_WRONLY)
        try:
            os.lseek(fd, offset, os.SEEK_SET)
            os.write(fd, before)
            os.fsync(fd)
        finally:
            os.close(fd)
        recheck = read_region(path, offset, PROBE_BYTES)
        restore["region_restored"] = recheck == before
        restore["region_sha256_restored"] = hashlib.sha256(recheck).hexdigest()
    else:
        restore["region_restored"] = True
    if result["flag_at_start"]:
        set_flag(path, 1)  # put it back exactly as it was found
    restore["flag_now"] = get_flag(path)
    result["restore"] = restore

    # -- what the tool itself concludes ------------------------------------
    # Run this from the repository root so ``core`` is importable.
    sys.path.insert(0, os.getcwd())
    try:
        from core.carve.acquire import apply_write_block

        outcome = apply_write_block(path)
        result["apply_write_block"] = {
            "applied": outcome.applied,
            "limitations": outcome.limitations,
        }
        # apply_write_block sets the flag and never clears it.
        set_flag(path, result["flag_at_start"])
        result["flag_final"] = get_flag(path)
    except Exception as exc:  # noqa: BLE001 - a probe reports, it does not raise
        result["apply_write_block_error"] = f"{type(exc).__name__}: {exc}"

    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
