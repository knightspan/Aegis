#!/usr/bin/env bash
# Build Sanctum.app and Sanctum.dmg (macOS 12+, the architecture of the build
# machine) into dist/.
#
# Prerequisites on the build Mac: Python 3.11 (python.org or Homebrew), Node
# 20+ with npm, Xcode command line tools (libewf-python has no macOS wheel and
# is compiled from source). The target Mac needs none of these.
#
# Signing: PyInstaller ad-hoc signs the bundle, which is enough to run it on
# the machine that built it. Distributing it needs a Developer ID certificate
# and notarization, which this script does not have. Set CODESIGN_IDENTITY to
# sign with a real identity; notarization (`xcrun notarytool submit`) is a
# separate, documented step (docs/packaging.md) and is NOT performed here.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-python3.11}"
BUILD="$ROOT/build/macos"
VENV="$BUILD/venv"
mkdir -p "$BUILD" dist

echo "==> UI bundle"
(cd ui && npm ci --no-audit --no-fund && npm run build)

echo "==> Build environment"
"$PY" -m venv "$VENV"
"$VENV/bin/python" -m pip install --quiet --upgrade pip
"$VENV/bin/python" -m pip install --quiet --constraint constraints.txt ".[build,desktop]"
VERSION="$("$VENV/bin/python" -c 'import importlib.metadata as m; print(m.version("sanctum-forensics"))')"

echo "==> Build metadata"
"$VENV/bin/python" packaging/build_info.py

echo "==> Icons"
"$VENV/bin/python" packaging/make_icons.py build/icons

echo "==> Freeze (PyInstaller .app)"
"$VENV/bin/python" -m PyInstaller --noconfirm --clean \
  --distpath "$BUILD/dist" --workpath "$BUILD/work" packaging/sanctum.spec

APP="$BUILD/dist/Sanctum.app"
if [ -n "${CODESIGN_IDENTITY:-}" ]; then
  echo "==> Sign with $CODESIGN_IDENTITY"
  codesign --force --deep --options runtime --timestamp -s "$CODESIGN_IDENTITY" "$APP"
fi
codesign --verify --deep --strict "$APP" || echo "warning: codesign verification failed"

echo "==> DMG"
STAGE="$BUILD/dmg"
rm -rf "$STAGE" && mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
DMG="dist/Sanctum-${VERSION}.dmg"
rm -f "$DMG"
hdiutil create -volname "Sanctum" -srcfolder "$STAGE" -ov -format UDZO "$DMG"
cp "$DMG" dist/Sanctum.dmg
shasum -a 256 "$DMG" dist/Sanctum.dmg > dist/SHA256SUMS-macos.txt
ls -la dist
