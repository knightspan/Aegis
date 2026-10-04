# Package verification, 2026-09-25

**Rebuilt at `76dde42`** (2026-09-26, the release-hold remediation), after five
commits that change packaged code: `e9253a3` (a device's firmware Purge option and
the Devices badge read Unverified without a hardware record), `c71c6b7` (a
write-seam refusal is BLOCKED in Cases and on the Overview, a failed read-back
never advances past Verify, a file erase that failed partway is not "not
attempted"), `338f955` (the overview's physical runs are dated to their builds),
`644a2e3` (a finished job's status is re-read until its outcome is settled) and
`76dde42` (the Cases note names BLOCKED and VERIFY FAILED). The previous build, at
`d95603d`, is this README's previous version in git history; `dist/` held it until
this rebuild and now holds the `76dde42` build.

`e81f491` is where the reportlab fix landed: reportlab imports its barcode symbologies
through `exec()`, which PyInstaller cannot see, and the certificate draws its QR code
through that package, so a build without it answers every certificate request with a
500 (`ModuleNotFoundError: reportlab.graphics.barcode.code128`). The fix is still in
`packaging/sanctum.spec`, guarded by `tests/test_packaging_spec.py`; the `76dde42`
archive holds `reportlab.graphics.barcode.code128` and `.qr`, and the isolated
smoke below issues and verifies a certificate from each package.

Packages built with `scripts/build-linux-portable.sh` (podman, `python:3.11-bullseye`,
glibc 2.31 image) from a clean clone checked out at **`76dde42`**, with `ui/dist`
built in that clone. Later commits change documentation and evidence only, none of
which is packaged (`packaging/sanctum.spec` collects `core`, `api`, `helper`,
`ui/dist` and build metadata). Check that for any later HEAD with:

```sh
git diff --stat 76dde42 HEAD -- api core helper ui/src packaging pyproject.toml constraints.txt
```

An empty result means the packages still hold that HEAD's code. The packages report
**the build commit**, not the repository HEAD; `/health` from a source checkout reports
the live HEAD instead. `build_info.json` records the branch as `HEAD`, because the
clone was a detached checkout of the commit.

| Artifact | SHA-256 |
|---|---|
| `Sanctum-0.0.0-x86_64.AppImage` | `3997f9c5d62133293a8377f5a864cb595e57d364c554b54f5be22dcfc266f983` |
| `sanctum_0.0.0_amd64.deb` | `1642bfa308a6948098c487dbc8bdcb541e19c08cc9820605e4672135b38fcbd2` |

## Identity: `identity.py`

Reads the unpacked payloads; nothing from a package is executed.
`identity-appimage.json` and `identity-deb.json`, both **PASS**:

- `build_info.json` names `76dde4246338f4cc5ca261d3b8fa1a275d0dbeaa` exactly, with no `+dirty`.
- All **92 of 92** Python modules under `core/`, `api/` and `helper/` at that commit are
  in the frozen archive, and every archived code object equals the one Python 3.11
  compiles from the commit's source. None missing, none extra. This includes
  `helper.authorization`, `api.authorization` and `core.authorization`, and the
  2026-09-25 additions `core.erase.traces`, `core.carve.mediamap` and `core.destroy`.
- The bundled UI equals `ui/dist` built from the same sources, **8 of 8** files
  (the bundle now carries its own fonts). That `ui/dist` is also byte-identical to
  the one the four browser runs of 2026-09-26 were served.
- The bundle holds the remediation's words: *BLOCKED by a safety refusal before
  any write*, *REQUEST FAILED - the case record could not be read*, *VERIFY
  FAILED*, *read-back verification FAILED*, *PURGE · UNVERIFIED*, *failed
  partway*, *This release: no physical validation*; and still *Record a physical
  destruction*, the media map and the trace sweep. The archive holds
  `core.erase.traces`, `core.carve.mediamap`, `core.destroy`,
  `helper.authorization` and `api.authorization`, and the packaged
  `core/platform/validation_record.json` has an empty `hardware` section, which is
  what makes firmware Purge read Unverified.
- The two packages carry the same executable and byte-identical payload trees.
- `.deb`: package `sanctum` 0.0.0 amd64, no maintainer scripts, 202 payload files all
  owned `root:root`, no set-uid, set-gid or world-writable file. It now declares
  `Depends: libc6 (>= 2.30), zlib1g`; the executable needs `libc.so.6` (symbols up to `GLIBC_2.30`), `libz.so.1`,
  `libdl.so.2` and `libpthread.so.0` from the system, all of which are required packages
  on Debian and Ubuntu.

## Behaviour: `scripts/package_smoke.py --isolated`

The unpacked executable of each package ran inside a bubblewrap sandbox with no `/sys`,
no block device in `/dev`, no udev database and no removable-media mount; the view was
read from inside the sandbox before the app started (`sandbox_view` in the JSON).
`smoke-isolated-appimage.json` and `smoke-isolated-deb.json`: **22 PASS, 2 NOT RUN, 0
FAIL** each. Session protection, host check, `/platform`, device discovery (it ran and
found nothing, because nothing was there), a real folder erase inside the script's own
scratch directory, a signed certificate that verifies, and quit.

**NOT RUN, and why:** "every device assessed" and "protected devices are NOT AVAILABLE"
need a real device. No physical device was enumerated, opened or written by either run.

Reproduce: `bash scripts/build-linux-portable.sh` from a clean checkout, unpack
(`--appimage-extract`; `ar x` then `tar -xzf data.tar.gz`), then
`PYTHONPATH=<build venv site-packages> python3.11 identity.py <app dir> <commit>
--ui-dist ui/dist [--deb …]` and `python scripts/package_smoke.py --isolated <app
dir>/Sanctum`.
