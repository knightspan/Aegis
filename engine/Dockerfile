# Sanctum Forensics runtime + dev image.
#
# Built to be offline-repeatable once built: pinned base tags and pinned Python
# deps via constraints.txt, an `npm ci` against the committed lockfile, and no
# network access needed at run time.
#
# Two things this image used to get wrong, both of which made the shipped
# container not the product:
#
#   1. It did not build the UI. `ui/dist/` is gitignored, so a clean clone has
#      no bundle, no stage produced one, and `api/main.py` mounted nothing -
#      the "container deliverable" in README.md was a headless API. Stage 1
#      below builds it and stage 2 copies it to the path `UI_DIST` names.
#   2. It installed the stock `libewf-python`, which reads E01 and **cannot
#      write one** - the failure constraints.txt warns about in writing, silent
#      until the first acquisition to E01. `scripts/build-libewf-python.sh`
#      exists to fix exactly that and was never run here; it is run below, and
#      its own verification step round-trips a 1 MiB E01 during the build, so
#      an image that cannot write E01 fails to build rather than shipping.

# --------------------------------------------------------------------------
# Stage 1 - the UI bundle
# --------------------------------------------------------------------------
FROM node:22-slim AS ui

WORKDIR /ui

# The lockfile alone first, so a source-only change does not reinstall
# node_modules. `npm ci` and not `npm install`: it installs the lockfile
# exactly, and a build that resolved versions afresh at image-build time is not
# the bundle anybody tested.
COPY ui/package.json ui/package-lock.json ./
RUN npm ci

COPY ui/ ./
RUN npm run build

# The bundle must carry no external origin: the tool is used on an evidence
# network, and a font or script fetched from a CDN at load time is both an
# offline failure and a disclosure. Checked here so the *image* cannot ship one
# even if a source change introduces it.
#
# `-P` alone. This line used to pass `-E` and `-P` together, which grep rejects
# with "conflicting matchers specified" and exit status 2 - and `!` turned that
# into success, so the check could never fail. The lookahead excludes loopback
# and the identifier-only origins tests/api/test_bundle_offline.py justifies:
# XML namespace URIs and React's error-decoder link, which nothing fetches.
# grep exits 0 on a match, 1 on none and 2 on an error; only 1 passes.
RUN set +e; \
    grep -rIlP 'https?://(?!127\.0\.0\.1|localhost|\[::1\]|www\.w3\.org|react\.dev|reactjs\.org)' \
        dist/ --include='*.js' --include='*.css' --include='*.html'; \
    status=$?; \
    if [ "$status" -eq 0 ]; then echo "the UI bundle references an external origin" >&2; exit 1; fi; \
    if [ "$status" -ne 1 ]; then echo "the external-origin check itself failed (grep exit $status)" >&2; exit 1; fi

# --------------------------------------------------------------------------
# Stage 2 - the application
# --------------------------------------------------------------------------
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Apt gives us the forensic userland (sleuthkit, libewf, hdparm, nvme-cli) and
# the filesystem tools the erase/carve layers shell out to. zlib1g-dev and
# libbz2-dev are for the libewf-python rebuild below: without real zlib headers
# libewf compiles its local deflate and refuses write access.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libtsk-dev \
        libewf-dev \
        zlib1g-dev \
        libbz2-dev \
        sleuthkit \
        hdparm \
        nvme-cli \
        ntfs-3g \
        exfatprogs \
        dosfstools \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependency layer first, and it must not depend on the source. It used to copy
# core/, helper/, api/ and testkit/ before `pip install`, so every source change
# invalidated this layer and the next build re-resolved every dependency from
# the package index - which fails with no network at a venue, and once failed
# transiently with the network up (STANDARDS_REPORT F20).
#
# Only the two files that decide the dependency set are copied. The install
# needs the package directories and the readme pyproject names to exist, so
# empty ones stand in. Over empty directories hatchling's editable install adds
# no path entry at all - measured: the `sanctum` console script then failed with
# "No module named 'core'" from any directory but /app - so PYTHONPATH below,
# after the source copy, is what makes the real source importable.
COPY pyproject.toml constraints.txt ./
RUN mkdir -p core helper api testkit && touch README.md \
 && pip install --constraint constraints.txt -e ".[dev]"

# Replace the pip-installed libewf-python with one that can write E01. The
# script takes the interpreter prefix from $VENV, so pointing it at
# /usr/local uses this image's own python rather than a virtualenv.
COPY scripts/build-libewf-python.sh ./scripts/
RUN VENV=/usr/local ./scripts/build-libewf-python.sh

COPY . .

# After the source copy, so setting it does not invalidate the dependency layers.
ENV PYTHONPATH=/app

# Prove the two hard-to-build native deps actually import, and that E01 write
# survived into this layer rather than only into the build script's. After the
# source copy, because the second check imports core; it needs no network. The
# last check runs the console script from outside /app, which is the case the
# stub-directory install broke and a check run from WORKDIR would not see.
RUN python -c "import pytsk3, pyewf; print('pytsk3', pytsk3.get_version()); print('pyewf', pyewf.get_version())" \
 && python -c "from core.carve.acquire import e01_write_supported; assert e01_write_supported(), 'E01 write not available'; print('e01_write_supported True')" \
 && cd / && sanctum verify-report --help > /dev/null && echo "sanctum console script imports from /"

# The bundle from stage 1, at the path api/main.py:49 looks for. Copied after
# `COPY . .` so a stale host-built ui/dist cannot win.
COPY --from=ui /ui/dist ./ui/dist

# The API serves on 127.0.0.1 only, by design (api/main.py:45). Reach it with
# `podman run --network host` / `docker run --network host`, or exercise it from
# inside the container; publishing a port would require binding 0.0.0.0, which
# is the one thing this application refuses to do.
EXPOSE 8787
CMD ["python", "-m", "api.main"]
