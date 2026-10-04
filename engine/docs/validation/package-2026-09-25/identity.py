"""Does an unpacked Sanctum package hold exactly the code of one git commit?

    PYTHONPATH=<site-packages with PyInstaller> python3.11 identity.py \\
        UNPACKED_APP_DIR COMMIT [--ui-dist ui/dist] [--deb PKG.deb] [--out FILE]

``UNPACKED_APP_DIR`` holds the frozen ``Sanctum`` executable and ``_internal/``
(``--appimage-extract``, or the ``opt/sanctum`` of an unpacked ``.deb``). Every
check reads; nothing from the package is executed.

1. ``build_info.json`` names ``COMMIT`` exactly, with no ``+dirty``.
2. Every Python module under ``core/``, ``api/`` and ``helper/`` at ``COMMIT``
   is in the frozen archive, and each archived code object equals the one this
   Python compiles from that commit's source (``code == code`` compares the
   bytecode, constants, names and line table recursively; the file name is not
   part of it). No other project module is archived.
3. With ``--ui-dist``: the bundled UI equals that directory, file for file.
4. With ``--deb``: control fields, maintainer scripts, and no set-uid, set-gid
   or world-writable file in the payload.

The bytecode comparison needs the same Python minor version as the build.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import stat
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any

from PyInstaller.archive.readers import CArchiveReader

ROOTS = ("core", "api", "helper")


def git(*args: str) -> bytes:
    return subprocess.run(["git", *args], check=True, capture_output=True).stdout


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def module_name(path: str) -> str:
    parts = path[: -len(".py")].split("/")
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def check_modules(executable: Path, commit: str) -> dict[str, Any]:
    pkg = CArchiveReader(str(executable))
    pyz_name = next(name for name, entry in pkg.toc.items() if entry[4] == "z")
    pyz = pkg.open_embedded_archive(pyz_name)
    paths = [
        line
        for line in git("ls-tree", "-r", "--name-only", commit, *ROOTS).decode().split()
        if line.endswith(".py")
    ]
    wanted = {module_name(path): path for path in paths}
    identical, differing, missing = [], [], []
    for name, path in sorted(wanted.items()):
        if name not in pyz.toc:
            missing.append(name)
            continue
        archived = pyz.extract(name)
        source = git("show", f"{commit}:{path}")
        compiled = compile(source, archived.co_filename, "exec", dont_inherit=True)
        (identical if compiled == archived else differing).append(name)
    extra = sorted(
        name
        for name in pyz.toc
        if name.split(".", 1)[0] in ROOTS and name not in wanted
    )
    return {
        "archive": pyz_name,
        "modules_at_commit": len(wanted),
        "identical": len(identical),
        "differing": differing,
        "missing": missing,
        "extra": extra,
        "security_modules": {
            name: name in identical
            for name in (
                "helper.authorization",
                "api.authorization",
                "core.authorization",
            )
        },
    }


def tree(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): sha256(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def check_ui(bundled: Path, expected: Path) -> dict[str, Any]:
    have, want = tree(bundled), tree(expected)
    return {
        "files": len(want),
        "identical": sum(1 for name in want if have.get(name) == want[name]),
        "differing": sorted(n for n in want if n in have and have[n] != want[n]),
        "missing": sorted(set(want) - set(have)),
        "extra": sorted(set(have) - set(want)),
    }


def ar_members(data: bytes) -> dict[str, bytes]:
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("not an ar archive")
    members, offset = {}, 8
    while offset + 60 <= len(data):
        header = data[offset : offset + 60]
        name = header[:16].decode().strip().rstrip("/")
        size = int(header[48:58].decode().strip())
        members[name] = data[offset + 60 : offset + 60 + size]
        offset += 60 + size + (size % 2)
    return members


def check_deb(deb: Path) -> dict[str, Any]:
    members = ar_members(deb.read_bytes())
    control_name = next(n for n in members if n.startswith("control.tar"))
    data_name = next(n for n in members if n.startswith("data.tar"))
    with tarfile.open(fileobj=io.BytesIO(members[control_name])) as control:
        names = control.getnames()
        fields: dict[str, str] = {}
        member = control.extractfile("./control") or control.extractfile("control")
        for line in (member.read().decode() if member else "").splitlines():
            if ":" in line and not line.startswith(" "):
                key, _, value = line.partition(":")
                fields[key.strip()] = value.strip()
    scripts = sorted(
        n.lstrip("./")
        for n in names
        if n.lstrip("./") in {"preinst", "postinst", "prerm", "postrm"}
    )
    risky, owners, files = [], set(), 0
    with tarfile.open(fileobj=io.BytesIO(members[data_name])) as payload:
        for info in payload.getmembers():
            files += info.isfile()
            owners.add(f"{info.uname or info.uid}:{info.gname or info.gid}")
            if info.mode & (stat.S_ISUID | stat.S_ISGID) or (
                info.mode & stat.S_IWOTH and not info.issym()
            ):
                risky.append(f"{info.name} {oct(info.mode)}")
    return {
        "control": {
            k: fields.get(k, "")
            for k in (
                "Package",
                "Version",
                "Architecture",
                "Depends",
                "Maintainer",
                "Installed-Size",
            )
        },
        "maintainer_scripts": scripts,
        "payload_files": files,
        "owners": sorted(owners),
        "setuid_setgid_or_world_writable": risky,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("app_dir", type=Path)
    parser.add_argument("commit")
    parser.add_argument("--ui-dist", type=Path)
    parser.add_argument("--deb", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    commit = git("rev-parse", args.commit).decode().strip()
    internal = args.app_dir / "_internal"
    info = json.loads((internal / "core/platform/build_info.json").read_text())
    result: dict[str, Any] = {
        "commit": commit,
        "python": sys.version.split()[0],
        "build_info": info,
        "build_info_matches": info.get("commit") == commit,
        "modules": check_modules(args.app_dir / "Sanctum", commit),
        "executable_sha256": sha256(args.app_dir / "Sanctum"),
    }
    if args.ui_dist:
        result["ui"] = check_ui(internal / "ui/dist", args.ui_dist)
    if args.deb:
        result["deb"] = check_deb(args.deb)
    modules = result["modules"]
    ok = (
        result["build_info_matches"]
        and not modules["differing"]
        and not modules["missing"]
        and not modules["extra"]
        and all(modules["security_modules"].values())
    )
    if "ui" in result:
        ui = result["ui"]
        ok = ok and ui["identical"] == ui["files"] and not ui["extra"]
    if "deb" in result:
        ok = ok and not result["deb"]["setuid_setgid_or_world_writable"]
    result["result"] = "PASS" if ok else "FAIL"
    text = json.dumps(result, indent=2)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
