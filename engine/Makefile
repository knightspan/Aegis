# Sanctum Forensics task runner.
#
# The deployment target is Linux, but development happens on Windows too, and a
# virtualenv puts its executables in different directories on each: Scripts/ on
# Windows, bin/ everywhere else. Probe for the interpreter rather than assuming
# a layout, so `make lint typecheck test` is one command on both. Probing the
# file beats branching on $(OS) because a POSIX-layout venv on a Windows host
# (WSL, Git Bash) still resolves correctly.
#
# Every target runs its tool as `$(PY) -m <tool>`. Invoking the console scripts
# directly would reintroduce the same bin/ vs Scripts/ split this file exists to
# remove, and `-m` guarantees the tool comes from the same interpreter that
# resolves the project's imports.

VENV ?= .venv
PY := $(if $(wildcard $(VENV)/Scripts/python.exe),$(VENV)/Scripts/python.exe,$(VENV)/bin/python)

# Interpreter used only to create the venv, before $(PY) exists. The Windows
# launcher takes `py -3.11`; POSIX installs expose `python3.11` on PATH.
ifeq ($(OS),Windows_NT)
BOOTSTRAP_PY ?= py -3.11
else
BOOTSTRAP_PY ?= python3.11
endif

# Cache removal runs on whatever interpreter is on PATH, not $(PY): `clean`
# deletes the venv, and on Windows a running python.exe cannot delete itself.
HOST_PY ?= python

.PHONY: install test lint typecheck check run docker clean package-linux package-linux-portable validation-record

install:
	$(BOOTSTRAP_PY) -m venv $(VENV)
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install --constraint constraints.txt -e ".[dev]"

lint:
	$(PY) -m ruff check .

# Two passes, because no single one can check both platform backends. The
# first analyses as Linux (pyproject sets platform = "linux") and excludes
# core/erase/_platform/win.py, whose ctypes-over-Win32 body cannot resolve
# there. The second checks exactly that file as Windows. Without it the Windows
# backend would never be type-checked at all: under platform = "linux" mypy
# treats the `if sys.platform == "win32"` import as unreachable and skips it.
typecheck:
	$(PY) -m mypy --strict core/ helper/ api/
	$(PY) -m mypy --strict --platform win32 core/erase/_platform/win.py
	$(PY) -m mypy --strict --platform win32 core/platform api/security.py api/deps.py core/erase/files.py
	$(PY) -m mypy --strict --platform darwin core/platform

# No -q here: pyproject's addopts already sets it, and a second -q suppresses
# the summary line, hiding the pass and skip counts.
test:
	$(PY) -m pytest

# The full gate, in the order a failure is cheapest to read.
check: lint typecheck test

# The same port and loopback address as `python -m api.main`, which is what every
# document names. Without these uvicorn serves its own default, 8000.
SANCTUM_PORT ?= 8787

# `python -m api.main`, not `uvicorn --reload`: the entry point is what prints
# the session URL this run is reachable at, and what refuses every request
# that does not carry its cookie. For an auto-reloading server without that
# protection, run uvicorn yourself with SANCTUM_DEV_INSECURE=1 and read the
# warning it prints.
run:
	$(PY) -m api.main

docker:
	docker build -t sanctum-forensics .

clean:
	$(HOST_PY) -c "import pathlib, shutil; \
	[shutil.rmtree(p, ignore_errors=True) for p in ('$(VENV)', '.pytest_cache', '.mypy_cache', '.ruff_cache', 'build', 'dist')]; \
	[shutil.rmtree(p, ignore_errors=True) for p in pathlib.Path('.').rglob('__pycache__')]; \
	[shutil.rmtree(p, ignore_errors=True) for p in pathlib.Path('.').glob('*.egg-info')]"

# Desktop packages. Windows and macOS: scripts/build-windows.ps1 and
# scripts/build-macos.sh on those machines; see docs/packaging.md.
package-linux:
	bash scripts/build-linux.sh

package-linux-portable:
	bash scripts/build-linux-portable.sh

# Run this platform's suites and record the result for the capability matrix.
validation-record:
	$(PY) scripts/record_platform_validation.py
