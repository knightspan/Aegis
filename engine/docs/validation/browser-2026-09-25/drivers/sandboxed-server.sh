#!/usr/bin/env bash
# Run server.py inside a bubblewrap sandbox that has no block device to find.
#
#   bash sandboxed-server.sh STATE_DIR PORT
#
# The server sees /usr and /etc read-only, the repository read-only and the
# state directory. It gets a fresh /proc, a minimal /dev (no block device), empty
# /tmp and /run, and no /sys, so even a code path this driver forgot to replace
# could not enumerate or open a disk. The network namespace is shared so the
# browser outside can reach the loopback port. Nothing here needs privilege.
set -euo pipefail
STATE="$(realpath "$1")"
PORT="$2"
REPO="$(cd "$(dirname "$0")/../../../.." && pwd)"
mkdir -p "$STATE/home"
exec bwrap --unshare-all --share-net --die-with-parent --new-session \
  --ro-bind /usr /usr \
  --symlink usr/lib64 /lib64 --symlink usr/lib /lib \
  --symlink usr/bin /bin --symlink usr/sbin /sbin \
  --ro-bind /etc /etc --proc /proc --dev /dev --tmpfs /tmp --tmpfs /run \
  --ro-bind "$REPO" "$REPO" --bind "$STATE" "$STATE" \
  --setenv HOME "$STATE/home" --setenv TMPDIR /tmp \
  --setenv PYTHONDONTWRITEBYTECODE 1 --setenv PYTHONPATH "$REPO" \
  --chdir "$REPO" \
  "$REPO/.venv/bin/python" docs/validation/browser-2026-09-25/drivers/server.py \
  "$STATE" "$PORT"
