#!/usr/bin/env bash
# Acceptance checks that need a Linux + Docker host (criteria 1 and 2 of Prompt 0).
# The scaffold was generated on Windows, where docker/make are unavailable; run
# this on the Linux target to close those out.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== 1. make gate =="
make install
make lint
make typecheck
make test

echo "== 2. docker build + native import =="
docker build -t sanctum-forensics .
docker run --rm sanctum-forensics \
    python -c "import pytsk3, pyewf; print('pytsk3', pytsk3.get_version(), '| pyewf', pyewf.get_version())"

echo "all Linux-only acceptance checks passed"
