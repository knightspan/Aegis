#!/usr/bin/env bash
# Full local gate: lint, strict type-check of core/, and the test suite.
set -euo pipefail
cd "$(dirname "$0")/.."

ruff check .
mypy --strict core/ helper/ api/
# The Windows platform backend, checked as Windows. See the Makefile.
mypy --strict --platform win32 core/erase/_platform/win.py
pytest -q
