#!/usr/bin/env bash
# Build the Linux packages inside a glibc 2.31 container, so they run on
# Debian 11+, Ubuntu 20.04+, Fedora, RHEL 9 - not only on hosts as new as the
# build machine.
#
# A PyInstaller build links against the build host's glibc and needs at least
# that version at run time: the same AppImage built on Fedora 44 fails on
# Debian 12 with "GLIBC_2.38 not found". This is the build to distribute.
#
# Prerequisites: podman (or docker via CONTAINER=docker), and a UI bundle in
# ui/dist (npm run build) - the container has no Node.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENGINE="${CONTAINER:-podman}"
IMAGE="${IMAGE:-docker.io/library/python:3.11-bullseye}"
[ -f "$ROOT/ui/dist/index.html" ] || { echo "run 'npm ci && npm run build' in ui/ first"; exit 1; }
# label=disable rather than :Z: relabelling would rewrite the SELinux label
# of every file in the checkout, including root-owned validation output.
"$ENGINE" run --rm --security-opt label=disable -v "$ROOT:/src" -w /src "$IMAGE" bash -c '
  set -e
  apt-get update -qq && apt-get install -y -qq file desktop-file-utils >/dev/null
  git config --global --add safe.directory /src || true
  SKIP_UI=1 PYTHON=python3.11 BUILD_DIR=/src/build/linux-portable bash scripts/build-linux.sh
'
