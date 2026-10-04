# Technical environment notes

Things that cost somebody an evening to work out, written down so they cost the
next person nothing. Everything here was established on the target platform by
running it, not read off a changelog.

Verified on Fedora Linux 44, kernel 6.19.10, CPython 3.11.16, on 2026-09-04.

## Python 3.11 is required, and the host interpreter is not it

`pyproject.toml` pins `requires-python = "==3.11.*"`. Fedora 44 ships CPython
3.14 as `python3`, which cannot be used: it fails the pin, and
`libewf-python` has no wheel for it either.

```bash
sudo dnf install -y python3.11 python3.11-devel
make install          # the Makefile bootstraps the venv with python3.11
```

## pytsk3 needs no Sleuth Kit build

`pytsk3==20260715` publishes a `cp311` `manylinux_2_24_x86_64.manylinux_2_28_x86_64`
wheel. It installs in seconds and needs **no** `libtsk-dev`, no compiler and no
`sleuthkit` package. The wheel bundles its own libtsk.

Installing `sleuthkit` is still worth it for the CLI tools — `fls`, `istat`,
`icat`, `mmls` — which are the fastest way to check what
`core/carve/fsaware.py` is seeing when a recovery looks wrong. They are a
debugging aid, not a dependency; nothing in the codebase shells out to them.

## libewf-python must be built, and the stock build cannot write E01

Two separate facts, and the second one is the expensive one.

**There is no `cp311` Linux wheel.** `libewf-python==20240506` publishes
`cp310` for `manylinux_2_34` and nothing newer for Linux, so 3.11 builds from
the sdist. That needs `gcc`, `make` and `python3.11-devel`. The sdist bundles
libewf's full C source, so no `libewf-devel` is required — which is just as
well, because:

**Fedora's packaged `libewf` is 20140608.** A 2014 release, ten years behind
the bundled source. Do not link against it. `dnf install libewf` is only useful
if you want `ewfinfo` for cross-checking, and even then its output describes a
decade-old implementation.

**The stock build silently cannot write E01.** `pip install libewf-python`
produces a module that reads E01 perfectly and fails on the first write with:

```
libewf_handle_open: write access currently not supported - compiled without zlib
```

The cause is in the upstream sdist's own `setup.py`:

```python
command = "sh configure --disable-nls --disable-shared-libs"
```

`--disable-shared-libs` is meant to keep the bundled libyal dependencies
internal. But `m4/zlib.m4` reads the same switch:

```
[test "x$ac_cv_enable_shared_libs" = xno || test "x$ac_cv_with_zlib" = xno],
[ac_cv_zlib=no]
```

so it also forces libewf's *local* deflate implementation, and libewf refuses
write access without real zlib. `--with-zlib=/usr` does **not** override it —
the `||` short-circuits first. The only fix is to stop passing the flag.

Dropping it alone is not enough: `setup.py` declares the extension with
`libraries=[]`, so nothing external is linked and the module then fails to
import with `undefined symbol: OSSL_PARAM_construct_end`.

`scripts/build-libewf-python.sh` does both edits and verifies the result by
writing and reading back a container:

```bash
./scripts/build-libewf-python.sh
```

It configures with `--without-openssl --without-libuuid --without-pthread` so
the only external libraries are `zlib` and `bzlib`. libewf's own MD5/SHA
implementations are used instead of OpenSSL's, which removes a class of "built
against a different OpenSSL" breakage and costs nothing: every hash Sanctum
reports comes from `hashlib` and `blake3` in `core/carve/acquire.py`, never
from libewf.

## pyewf binds no write-configuration setters at all

Even in a write-capable build, `pyewf.handle` exposes exactly one setter,
`set_header_codepage`. libewf's C API has `libewf_handle_set_compression_values`,
`set_media_size`, `set_format`, `set_sectors_per_chunk` and a dozen more; none
of them are bound.

Two consequences, both recorded on every acquisition record:

- **Compression is not selectable**, and libewf's default is *no compression*.
  An E01 written through `pyewf` comes out marginally **larger** than the
  source. Confirmed with `ewfinfo`: `Compression level: no compression`, and
  8 MiB of a single repeated byte produced an 8,394,899-byte container.
- **An E01 acquisition cannot be resumed**, because libewf has no append mode
  for an existing segment set.

`e01_write_supported()` therefore **probes by writing a throwaway container**
rather than testing for an attribute. An earlier version checked
`hasattr(pyewf.handle, "set_media_size")` and was wrong in both directions: the
attribute is absent on every build, including ones that write E01 correctly.

## Filesystem tooling, and why none of the corpus needs root

Mounting a filesystem needs `CAP_SYS_ADMIN` in the initial user namespace.
`ntfs-3g` is not setuid on Fedora and refuses to mount as a normal user, and
there is no `fuse-exfat` package at all. So `testkit/fsimage.py` mounts
nothing:

| filesystem | written with | deleted with |
|---|---|---|
| NTFS | `mkfs.ntfs` + `ntfscp` | this codebase, on the structures |
| FAT32 | `mkfs.vfat` + `mtools` | `mdel` |
| exFAT | `mkfs.exfat` + this codebase | this codebase |
| ext2/3/4 | `mkfs.ext*` + `debugfs` | `debugfs` + explicit extent zeroing |

```bash
sudo dnf install -y gcc make zlib-devel bzip2-devel \
    ntfsprogs ntfs-3g dosfstools mtools exfatprogs e2fsprogs sleuthkit
```

Two details worth knowing before editing the builders:

- **`ntfscp` reports success on a full volume and writes nothing.** Read the
  directory back with `ntfsls` rather than trusting the exit status.
- **`debugfs rm` only unlinks.** It does not free blocks and does not touch the
  inode's extent tree, so an ext4 corpus built with `rm` alone leaves the
  extent tree intact and makes ext4 undelete look like NTFS. The kernel's
  `ext4_ext_remove_space` zeroes `i_block`, and the builder does the same with
  `sif <inode> block[0..14] 0`.

## Container builds

`Dockerfile` uses `python:3.11-slim` and Debian package names
(`libtsk-dev`, `libewf-dev`). Those are correct for that image and wrong for a
Fedora host; the notes above are for building on the host directly.

## The Windows and macOS device layers are tested through doubles

Whole-drive clear, raw acquisition, device sanitize, restore and the HPA/DCO
workflow on Windows and macOS go through two narrow seams, and the suite never
crosses either of them against a real device:

- **Windows:** `core/device/win/native.py` is the only module that calls
  `kernel32` (through `ctypes`). Everything above it talks to the `NativeApi`
  protocol, and every IOCTL structure is packed and parsed by pure functions in
  `core/device/win/ioctl.py`, `ata.py` and `nvme.py`. The tests drive it with
  `testkit/fake_windows.py`, which answers the same calls from a byte buffer and
  parses the same packed structures.
- **macOS:** `core/device/mac/rawdisk.py` opens `/dev/rdiskN` through the
  `MacIo` protocol; `testkit/fake_macos.py` stands in for it.

Unbuffered I/O on Windows (`FILE_FLAG_NO_BUFFERING`) needs the buffer address,
offset and length to be sector multiples; the raw macOS device needs offset and
length to be block multiples. Both layers widen reads to the sector or block and
slice back, which is what the acquisition's 512-byte salvage path needs on a 4Kn
disk.

The only run against a real OS is `scripts/native_smoke.py` in `platform-ci`
(Windows runner, and the macOS runner under `sudo`): one read-only handle, the
identity ioctls and one sector. It opens nothing for writing and issues no
destructive command, so it proves the bindings work, not any destructive
operation. None of this is physical validation; what is and is not physically
validated, by device class, is in the generated
[capability matrix](validation/capability-completion-2026-09-28/capability-matrix.md)
(`python scripts/capability_matrix.py` regenerates it; a test fails when the
committed copy is stale).
