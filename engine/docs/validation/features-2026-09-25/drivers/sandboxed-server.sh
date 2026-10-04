#!/usr/bin/env bash
# Run the browser-check server for the 2026-09-25 feature run in a bubblewrap
# sandbox with no block device, no /sys and no removable-media mount - the same
# sandbox as ../../browser-2026-09-25/drivers/sandboxed-server.sh - and with the
# state directory mounted at /cases and a synthetic home at /home/examiner, so
# the paths on screen are short and nothing outside the state directory exists.
#
#   SANCTUM_KEY_PASSPHRASE=... bash sandboxed-server.sh STATE_DIR PORT
set -euo pipefail
STATE="$(realpath "$1")"
PORT="$2"
REPO="$(cd "$(dirname "$0")/../../../.." && pwd)"
mkdir -p "$STATE/home"
exec bwrap --unshare-all --share-net --new-session \
  --ro-bind /usr /usr \
  --symlink usr/lib64 /lib64 --symlink usr/lib /lib \
  --symlink usr/bin /bin --symlink usr/sbin /sbin \
  --ro-bind /etc /etc --proc /proc --dev /dev --tmpfs /tmp --tmpfs /run \
  --ro-bind "$REPO" "$REPO" \
  --dir /home --bind "$STATE/home" /home/examiner --bind "$STATE" /cases \
  --setenv HOME /home/examiner --setenv TMPDIR /tmp \
  --setenv PYTHONDONTWRITEBYTECODE 1 --setenv PYTHONPATH "$REPO" \
  --chdir "$REPO" \
  "$REPO/.venv/bin/python" docs/validation/browser-2026-09-25/drivers/server.py \
  /cases "$PORT"
