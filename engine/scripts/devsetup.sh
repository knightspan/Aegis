#!/usr/bin/env bash
# One-time developer setup on a Debian/Ubuntu host.
# Python 3.11 specifically: pytsk3 wheels are least painful there.
set -euo pipefail

sudo apt update
sudo apt install -y build-essential libtsk-dev libewf-dev pkg-config python3.11-dev \
    ntfs-3g exfatprogs dosfstools hdparm nvme-cli sleuthkit

python3.11 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip
pip install --constraint constraints.txt -e ".[dev]"

python -c "import pytsk3, pyewf; print('native bindings OK')"
echo "devsetup complete. Activate with: source .venv/bin/activate"
