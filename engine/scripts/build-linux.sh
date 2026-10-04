#!/usr/bin/env bash
# Build the Linux desktop packages: Sanctum-<version>-x86_64.AppImage and
# sanctum_<version>_amd64.deb, into dist/.
#
# Prerequisites: python3.11, node >= 20 with npm, network access for the first
# run (pip wheels, npm packages, appimagetool). Nothing else: the .deb is
# written by packaging/linux/make_deb.py, not dpkg-deb. appimagetool also
# needs desktop-file-validate (desktop-file-utils).
#
# Reproducibility: Python dependencies are installed with constraints.txt,
# the UI with `npm ci` against the lockfile, and appimagetool is pinned by
# release tag and verified against APPIMAGETOOL_SHA256 when that is set.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-python3.11}"
BUILD="${BUILD_DIR:-$ROOT/build/linux}"
VENV="$BUILD/venv"
APPIMAGETOOL_URL="${APPIMAGETOOL_URL:-https://github.com/AppImage/appimagetool/releases/download/1.9.0/appimagetool-x86_64.AppImage}"

mkdir -p "$BUILD" dist

if [ "${SKIP_UI:-0}" = "1" ] && [ -f ui/dist/index.html ]; then
  echo "==> UI bundle: using the existing ui/dist (SKIP_UI=1)"
else
  echo "==> UI bundle"
  (cd ui && npm ci --no-audit --no-fund && npm run build)
fi

echo "==> Build environment (isolated venv; the end user needs no Python)"
"$PY" -m venv "$VENV"
"$VENV/bin/python" -m pip install --quiet --upgrade pip
"$VENV/bin/python" -m pip install --quiet --constraint constraints.txt ".[build]"
VERSION="$("$VENV/bin/python" -c 'import importlib.metadata as m; print(m.version("sanctum-forensics"))')"

echo "==> Build metadata"
"$VENV/bin/python" packaging/build_info.py

echo "==> Icons"
"$VENV/bin/python" packaging/make_icons.py build/icons

echo "==> Freeze (PyInstaller onedir)"
"$VENV/bin/python" -m PyInstaller --noconfirm --clean \
  --distpath "$BUILD/dist" --workpath "$BUILD/work" packaging/sanctum.spec

echo "==> .deb"
"$VENV/bin/python" packaging/linux/make_deb.py "$BUILD/dist/Sanctum" "$VERSION" \
  "dist/sanctum_${VERSION}_amd64.deb" build/icons/sanctum.png

echo "==> AppImage"
APPDIR="$BUILD/Sanctum.AppDir"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/lib"
cp -a "$BUILD/dist/Sanctum" "$APPDIR/usr/lib/sanctum"
cp build/icons/sanctum.png "$APPDIR/sanctum.png"
cat > "$APPDIR/sanctum.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=Sanctum
Comment=Secure sanitization and forensic recovery
Exec=Sanctum
Icon=sanctum
Terminal=false
Categories=System;Security;
DESKTOP
cat > "$APPDIR/AppRun" <<'APPRUN'
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/lib/sanctum/Sanctum" "$@"
APPRUN
chmod +x "$APPDIR/AppRun"

TOOL="$BUILD/appimagetool"
if [ ! -x "$TOOL" ]; then
  curl -fsSL -o "$TOOL" "$APPIMAGETOOL_URL"
  if [ -n "${APPIMAGETOOL_SHA256:-}" ]; then
    echo "$APPIMAGETOOL_SHA256  $TOOL" | sha256sum -c -
  fi
  chmod +x "$TOOL"
fi
# --appimage-extract-and-run: works on hosts and CI runners without FUSE.
ARCH=x86_64 "$TOOL" --appimage-extract-and-run --no-appstream "$APPDIR" \
  "dist/Sanctum-${VERSION}-x86_64.AppImage"

echo "==> Checksums"
(cd dist && sha256sum "Sanctum-${VERSION}-x86_64.AppImage" "sanctum_${VERSION}_amd64.deb" > SHA256SUMS-linux.txt)
ls -la dist
