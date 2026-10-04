"""Builds the AEGIS branding jars for the NetBeans/Autopsy platform.

    python tools/build-aegis-branding.py [--cluster working/autopsy/build/cluster] [--out working/autopsy/build/aegis-branding]

NetBeans resolves Bundle_<token>.properties from <cluster>/{core,modules}/locale/<jar>_<token>.jar
ahead of the module's own Bundle.properties, key by key. With the branding token "autopsy"
(etc/autopsy.conf: --branding autopsy) this rebrands user-visible text without changing any
Autopsy class or jar:

1. working/autopsy/branding/core/core.jar/...          -> core/locale/core_autopsy.jar (splash, frame icons, version)
2. working/autopsy/branding/modules/<jar>/...          -> modules/locale/<jar>_autopsy.jar (window title)
3. every Bundle.properties value in the built module jars that names "Autopsy" as a word
   -> an override with "AEGIS", merged into modules/locale/<jar>_autopsy.jar.

Only whole-word "Autopsy" in values is replaced: keys, URLs, file names and identifiers such as
"AutopsyIngest" or "org_sleuthkit_autopsy" are never touched. The upstream licences and notices
are unaffected and ship in THIRD_PARTY_NOTICES.md.
"""
from __future__ import annotations

import argparse
import re
import zipfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOKEN = "autopsy"
WORD = re.compile(r"\bAutopsy\b")
URLISH = re.compile(r"https?://|www\.|\.(?:html?|xml|exe|jar|log|aut)\b", re.IGNORECASE)
BUNDLE = re.compile(r"(^|/)Bundle\.properties$")
MANIFEST = "Manifest-Version: 1.0\r\nCreated-By: AEGIS branding (tools/build-aegis-branding.py)\r\n\r\n"


def logical_entries(text: str) -> list[str]:
    """Properties entries with backslash-continued lines joined back together."""
    entries: list[str] = []
    buffer = ""
    for line in text.splitlines():
        buffer += line + "\n" if buffer else line + "\n"
        stripped = line.rstrip()
        trailing = len(stripped) - len(stripped.rstrip("\\"))
        if trailing % 2 == 1:
            continue
        entries.append(buffer.rstrip("\n"))
        buffer = ""
    if buffer:
        entries.append(buffer.rstrip("\n"))
    return entries


def split_entry(entry: str) -> tuple[str, str] | None:
    body = entry.lstrip()
    if not body or body[0] in "#!":
        return None
    match = re.search(r"(?<!\\)[=:]|(?<!\\)\s", body)
    if not match:
        return None
    return body[: match.start()].strip(), body[match.end():]


def rebrand_value(value: str) -> str | None:
    if not WORD.search(value) or URLISH.search(value):
        return None
    return WORD.sub("AEGIS", value)


def bundle_overrides(cluster: Path) -> dict[str, dict[str, list[str]]]:
    """{jar file name: {path of Bundle_autopsy.properties: [override lines]}}"""
    found: dict[str, dict[str, list[str]]] = defaultdict(dict)
    for jar in sorted((cluster / "modules").glob("*.jar")):
        with zipfile.ZipFile(jar) as z:
            for name in z.namelist():
                if not BUNDLE.search(name):
                    continue
                lines = []
                for entry in logical_entries(z.read(name).decode("latin-1")):
                    kv = split_entry(entry)
                    if kv is None:
                        continue
                    new = rebrand_value(kv[1])
                    if new is not None:
                        lines.append(f"{kv[0]}={new}")
                if lines:
                    found[jar.name][name[: -len("Bundle.properties")] + f"Bundle_{TOKEN}.properties"] = lines
    return found


def source_branding(branding: Path) -> dict[tuple[str, str], dict[str, bytes]]:
    """{(cluster subdir, locale jar name): {entry path: bytes}} from working/autopsy/branding."""
    out: dict[tuple[str, str], dict[str, bytes]] = defaultdict(dict)
    for kind in ("core", "modules"):
        base = branding / kind
        if not base.is_dir():
            continue
        for jar_dir in base.iterdir():
            jar_stem = jar_dir.name[: -len(".jar")]
            for f in jar_dir.rglob("*"):
                if not f.is_file():
                    continue
                rel = f.relative_to(jar_dir).as_posix()
                stem, dot, ext = rel.rpartition(".")
                out[(kind, f"{jar_stem}_{TOKEN}.jar")][f"{stem}_{TOKEN}.{ext}"] = f.read_bytes()
    return out


def write_jar(path: Path, entries: dict[str, bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("META-INF/MANIFEST.MF", MANIFEST)
        for name in sorted(entries):
            z.writestr(name, entries[name])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cluster", default=str(ROOT / "working/autopsy/build/cluster"))
    ap.add_argument("--branding", default=str(ROOT / "working/autopsy/branding"))
    ap.add_argument("--out", default=str(ROOT / "working/autopsy/build/aegis-branding"))
    args = ap.parse_args()
    out = Path(args.out)

    jars = source_branding(Path(args.branding))
    total = 0
    for jar_name, bundles in bundle_overrides(Path(args.cluster)).items():
        target = jars[("modules", jar_name[: -len(".jar")] + f"_{TOKEN}.jar")]
        for path, lines in bundles.items():
            existing = target.get(path, b"").decode("latin-1")
            target[path] = (existing + ("\n" if existing else "") + "\n".join(lines) + "\n").encode("latin-1")
            total += len(lines)
    for (kind, name), entries in sorted(jars.items()):
        write_jar(out / kind / "locale" / name, entries)
        print(f"{kind}/locale/{name}: {len(entries)} file(s)")
    print(f"{total} Autopsy-named value(s) rebranded")


if __name__ == "__main__":
    main()
