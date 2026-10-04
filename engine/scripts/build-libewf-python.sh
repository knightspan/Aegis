#!/usr/bin/env bash
# Build libewf-python with E01 *write* support and install it into the venv.
#
# Why this script exists at all
# ----------------------------
# `pip install libewf-python==20240506` produces a module that can read E01 and
# cannot write one. The failure is silent until the first write, which reports:
#
#     libewf_handle_open: write access currently not supported - compiled
#     without zlib
#
# The cause is in the upstream sdist's own setup.py, which hardcodes:
#
#     command = "sh configure --disable-nls --disable-shared-libs"
#
# `--disable-shared-libs` is meant to keep the bundled libyal dependencies
# (libcerror, libbfio, libuna, ...) internal so the wheel needs nothing from the
# host. But m4/zlib.m4 shares that switch:
#
#     [test "x$ac_cv_enable_shared_libs" = xno || test "x$ac_cv_with_zlib" = xno],
#     [ac_cv_zlib=no]
#
# so it also forces libewf's *local* deflate implementation, and libewf refuses
# write access without real zlib. `--with-zlib=/usr` does not override it: the
# `||` short-circuits first. The only fix is to stop passing the flag.
#
# Dropping it alone is not enough either. setup.py declares the extension with
# `libraries=[]`, so nothing external is linked, and the module then fails to
# import with an undefined symbol. This script therefore makes two edits:
#
#   1. drop `--disable-shared-libs` so zlib and bzlib are found;
#   2. add `-lz -lbz2` to the extension.
#
# `--without-openssl --without-libuuid --without-pthread` keep the external
# surface to exactly those two libraries. libewf's own MD5/SHA implementations
# are used instead of OpenSSL's, which removes a whole class of "built against
# a different OpenSSL" breakage and costs nothing: the hashes Sanctum reports
# come from hashlib and blake3 in core/carve/acquire.py, never from libewf.
#
# Build requirements: gcc, make, python3.11-devel, zlib headers, bzip2 headers.
# On Fedora: dnf install gcc make python3.11-devel zlib-devel bzip2-devel
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${LIBEWF_VERSION:-20240506}"
VENV="${VENV:-.venv}"
PY="$VENV/bin/python"

if [[ ! -x "$PY" ]]; then
    echo "no interpreter at $PY; run 'make install' first" >&2
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== downloading libewf-python==$VERSION sdist =="
"$PY" -m pip download --no-binary :all: --no-deps --no-build-isolation \
    "libewf-python==$VERSION" -d "$WORK/sdist" >/dev/null

tar xzf "$WORK/sdist/libewf-python-$VERSION.tar.gz" -C "$WORK"
SRC="$WORK/libewf-$VERSION"

echo "== patching setup.py =="
# 1. Let configure find the system zlib and bzlib.
sed -i \
    's|sh configure --disable-nls --disable-shared-libs|sh configure --disable-nls --without-openssl --without-libuuid --without-pthread|' \
    "$SRC/setup.py"
# 2. Link what configure just decided to use.
sed -i 's|^            libraries=\[\],$|            libraries=["z", "bz2"],|' \
    "$SRC/setup.py"

grep -q -- '--without-openssl' "$SRC/setup.py" \
    || { echo "configure-flag patch did not apply" >&2; exit 1; }
grep -q 'libraries=\["z", "bz2"\]' "$SRC/setup.py" \
    || { echo "link-libraries patch did not apply" >&2; exit 1; }

echo "== building wheel (a few minutes) =="
"$PY" -m pip wheel --no-build-isolation --no-deps -w "$WORK/wheel" "$SRC" \
    >"$WORK/build.log" 2>&1 \
    || { tail -40 "$WORK/build.log" >&2; exit 1; }

echo "== installing =="
"$PY" -m pip install --force-reinstall --no-deps "$WORK"/wheel/libewf_python-*.whl \
    >/dev/null

echo "== verifying write support =="
"$PY" - <<'PYEOF'
import os
import sys
import tempfile

import pyewf

print("pyewf", pyewf.get_version())

with tempfile.TemporaryDirectory() as directory:
    # libewf treats the name given for write as a *base* and appends the
    # segment extension itself: passing "probe" produces "probe.E01".
    # Passing "probe.E01" would produce "probe.E01.E01".
    base = os.path.join(directory, "probe")
    payload = os.urandom(1 << 20)
    handle = pyewf.handle()
    handle.open([base], "w")
    handle.write(payload)
    handle.close()

    reader = pyewf.handle()
    reader.open(pyewf.glob(base + ".E01"), "r")
    read_back = reader.read_buffer_at_offset(len(payload), 0)
    reader.close()

if read_back != payload:
    print("E01 write produced a container that does not read back", file=sys.stderr)
    raise SystemExit(1)

print("E01 write support: OK (1 MiB round-tripped byte-identical)")
PYEOF
