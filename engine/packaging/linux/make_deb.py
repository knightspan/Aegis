"""Build a .deb from the PyInstaller onedir, with no dpkg-deb dependency.

A .deb is an ``ar`` archive of three members - ``debian-binary``,
``control.tar.gz``, ``data.tar.gz`` - and nothing else, so it is written
directly. The tars are GNU format: Python's default is PAX, and dpkg refuses
PAX extended headers ("unsupported PAX tar header type 'x'"). That keeps
the Linux build to one prerequisite (Python) on any distribution, including
Fedora, where dpkg is not installed.

    python packaging/linux/make_deb.py dist/Sanctum 0.0.0 dist/sanctum_0.0.0_amd64.deb

Installs to /opt/sanctum with a launcher at /usr/bin/sanctum and a desktop
entry. Uninstall with ``apt remove sanctum``; the per-user state directory
(~/.local/share/sanctum: ledger, reports) is deliberately left in place,
because deleting an audit trail is not something a package manager should do.
"""

from __future__ import annotations

import io
import sys
import tarfile
import time
from pathlib import Path

DESKTOP = """[Desktop Entry]
Type=Application
Name=Sanctum
Comment=Secure sanitization and forensic recovery
Exec=/opt/sanctum/Sanctum
Icon=sanctum
Terminal=false
Categories=System;Security;
"""

LAUNCHER = """#!/bin/sh
exec /opt/sanctum/Sanctum "$@"
"""


def _control(version: str, size_kib: int) -> str:
    return (
        "Package: sanctum\n"
        f"Version: {version}\n"
        "Section: utils\n"
        "Priority: optional\n"
        "Architecture: amd64\n"
        "Maintainer: Sanctum Forensics maintainers <noreply@localhost>\n"
        f"Installed-Size: {size_kib}\n"
        # The frozen executable links libc (symbols up to GLIBC_2.30, from the
        # glibc 2.31 build image) and libz from the system; every other library
        # is bundled. Measured by docs/validation/package-2026-09-25/identity.py.
        "Depends: libc6 (>= 2.30), zlib1g\n"
        "Recommends: hdparm, nvme-cli\n"
        "Description: Secure data sanitization and forensic recovery\n"
        " NIST SP 800-88 Clear/Purge with capability-driven method selection,\n"
        " file and folder erasure with residual reporting, and read-only\n"
        " forensic carving. Runs on loopback only; no network access.\n"
    )


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes, mode: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.mtime = int(time.time())
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    tar.addfile(info, io.BytesIO(data))


def _add_dirs(tar: tarfile.TarFile, *paths: str) -> None:
    """Every parent directory as its own entry: dpkg creates nothing implicitly."""
    seen: set[str] = set()
    for path in paths:
        parts = path.strip("./").split("/")[:-1]
        for depth in range(1, len(parts) + 1):
            name = "./" + "/".join(parts[:depth])
            if name in seen:
                continue
            seen.add(name)
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.mtime = int(time.time())
            info.uname = info.gname = "root"
            tar.addfile(info)


def _root_owned(info: tarfile.TarInfo) -> tarfile.TarInfo:
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    return info


def _ar_member(name: str, data: bytes) -> bytes:
    header = (
        f"{name:<16}{int(time.time()):<12}{0:<6}{0:<6}{0o100644:<8o}{len(data):<10}`\n"
    ).encode("ascii")
    return header + data + (b"\n" if len(data) % 2 else b"")


def build(onedir: Path, version: str, out: Path, icon: Path | None) -> None:
    data_buf = io.BytesIO()
    size = 0
    with tarfile.open(fileobj=data_buf, mode="w:gz", format=tarfile.GNU_FORMAT) as tar:
        _add_dirs(
            tar,
            "./opt/sanctum",
            "./usr/bin/sanctum",
            "./usr/share/applications/sanctum.desktop",
            "./usr/share/icons/hicolor/512x512/apps/sanctum.png",
        )
        tar.add(onedir, arcname="./opt/sanctum", filter=_root_owned)
        _add_bytes(tar, "./usr/bin/sanctum", LAUNCHER.encode(), 0o755)
        _add_bytes(
            tar, "./usr/share/applications/sanctum.desktop", DESKTOP.encode(), 0o644
        )
        if icon and icon.is_file():
            _add_bytes(
                tar,
                "./usr/share/icons/hicolor/512x512/apps/sanctum.png",
                icon.read_bytes(),
                0o644,
            )
    size = sum(p.stat().st_size for p in onedir.rglob("*") if p.is_file()) // 1024

    control_buf = io.BytesIO()
    with tarfile.open(
        fileobj=control_buf, mode="w:gz", format=tarfile.GNU_FORMAT
    ) as tar:
        _add_bytes(tar, "./control", _control(version, size).encode(), 0o644)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(
        b"!<arch>\n"
        + _ar_member("debian-binary", b"2.0\n")
        + _ar_member("control.tar.gz", control_buf.getvalue())
        + _ar_member("data.tar.gz", data_buf.getvalue())
    )


if __name__ == "__main__":
    if len(sys.argv) < 4:
        raise SystemExit(__doc__)
    icon_path = Path(sys.argv[4]) if len(sys.argv) > 4 else None
    build(Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]), icon_path)
