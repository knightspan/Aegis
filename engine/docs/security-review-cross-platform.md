# Security review: cross-platform support

Scope: every file added or changed to make the product cross-platform — the
platform adapters (`core/platform/`), the helper's new operations, the API's
front door (`api/security.py`), the desktop launcher (`api/desktop.py`), the
file-erase walk and protected paths, the report signing path, and the
installers. Reviewed 2026-09-21 against the checklist below. Findings are
listed with what was done; residual risks are listed as such.

**Updated 2026-09-28.** Windows and macOS now have a native device layer:
whole-drive clear, raw acquisition, restore, and on Windows device sanitize and
the HPA/DCO workflow. Two statements of the 2026-09-21 review stopped being true
and are corrected in place below ("Privilege escalation" and "Target identity");
the new layer is reviewed in
[The native device layer](#the-native-device-layer-windows-and-macos). None of it
has run against a physical device; its state per capability and device class is in
the generated
[capability matrix](validation/capability-completion-2026-09-28/capability-matrix.md).

## Found and fixed

| # | Finding | Severity | Fix | Test |
|---|---|---|---|---|
| 1 | **Folder erase descended through Windows directory junctions.** `DirEntry.is_dir(follow_symlinks=False)` is True for a junction and `is_symlink()` is False, so a recursive erase of `C:\case` containing a junction to `D:\` would have queued everything on `D:\` for erasure. | Critical (Windows) | `core/erase/files.py`: the walk and the top-level expansion check `FILE_ATTRIBUTE_REPARSE_POINT` from `lstat`; any reparse point is emitted as itself and refused by `erase_one`. | `test_a_folder_erase_does_not_descend_through_a_junction`, `test_a_reparse_attribute_alone_marks_a_directory_as_a_link` |
| 2 | **DNS rebinding.** The loopback API had no `Host` check, so a web page whose domain rebinds to 127.0.0.1 could drive it as same-origin — including `POST /jobs/erase-files`. | High | `api/security.py`: any request whose `Host` is not `127.0.0.1`, `localhost` or `[::1]` gets 400 before routing. | `test_host_check`, `test_a_rebinding_host_is_refused_before_any_route` |
| 3 | **Any local account could drive the API.** Loopback is shared by every user on the machine. | High (multi-user hosts) | Launcher mode: per-launch 32-byte token, `HttpOnly` `SameSite=Strict` cookie set by one `/session/<token>` request, constant-time compare, 401 otherwise. | `test_with_a_token_only_the_launched_window_gets_in` |
| 4 | **State directory defaulted to the current directory.** `Path(os.environ.get("SANCTUM_STATE_DIR", "")) or ...` — `Path("")` is `Path(".")`, which is truthy. A packaged app started from `/` or `C:\Program Files` would write its ledger there or fail. | Medium | `api/deps.default_state_dir`: per-user data directory per OS. | `test_an_empty_state_dir_variable_is_not_the_current_directory` |
| 5 | **Windows protected paths were case-sensitive and assumed `C:`.** `c:\windows\system32\...` and a `D:\Windows` install were not refused; only the directories themselves, not their contents, were covered. | Medium (Windows) | `core/platform/paths.py`: `%SystemRoot%`, Program Files, System Volume Information etc. from the environment, compared case-insensitively, as whole subtrees; macOS `/System`, swap directory. The Linux list is unchanged. | `test_windows_system_locations_are_refused_case_insensitively` and siblings |
| 6 | **Alternate data streams opened in text mode.** `os.open(stream, O_WRONLY)` without `O_BINARY` on Windows. Harmless for a zero fill, wrong for any other pattern. | Low | `O_BINARY` added. | type-checked as win32 |
| 7 | **The packaged app could not sign a certificate** (no environment variable, no terminal to prompt), which would push an operator towards weakening the key protection. | Medium (usability → security) | The operator types the passphrase in the UI for that one request; never logged, stored or echoed; a new key needs ≥12 characters; a wrong one is reported as such. | `test_the_desktop_app_can_sign_with_a_typed_passphrase` |
| 8 | **The helper entry point crashed on Windows** (`os.geteuid`) and the in-process helper could not construct (`os.getuid`). | Low | Helper daemon refuses to start off Linux with a reason; in-process helper uses `-1` for "no uid"; `whoami` on Windows reads the account from the process token (`GetUserNameW`), not `%USERNAME%`. | typecheck as win32; `test_platform_status_is_served_through_the_allowlist` |
| 9 | **Inside a container, the host's system disks were assessed READY.** `/sys` lists every host disk while the container's mount table shows none of the host's root, mounts or swap, so system-disk detection found nothing. Found by running the packaged AppImage in Debian 12 and Ubuntu 22.04 containers. The same gap exists in the engine's own guard when a container is given host device nodes. | High (containers) | `core/platform/linux.py`: in a container (`/run/.containerenv`, `/.dockerenv`) whole-drive work is NOT AVAILABLE, the probe is refused, and an erase is refused in the privileged process before the device is opened. Override only with `SANCTUM_ALLOW_CONTAINER_DEVICES=1` when exactly the target device was passed in. | `test_inside_a_container_whole_drive_is_refused_not_guessed` |
| 10 | **`.deb` built with PAX headers and without directory entries** — dpkg rejected it. | Build defect | GNU tar format, explicit root-owned directory entries. | installed and removed in a Debian 12 container |

## Checked, and correct by construction

- **Shell injection / command construction.** Every new external command is an
  argv list with `shell=False` (`core/device/_sysio.SubprocessRunner`).
  Windows discovery is one constant PowerShell script passed as
  `-EncodedCommand` (UTF-16LE base64), so no character is subject to
  command-line quoting; it takes no parameters (`param()`, `$args`, `$input`
  are absent, pinned by a test). `powershell.exe` is resolved from
  `GetSystemDirectoryW`, not `PATH`. `diskutil` is `/usr/sbin/diskutil`; a
  disk name reaches its argv only after `re.fullmatch(r"disk\d+")`.
- **Privilege escalation / admin overreach.** No component requests
  elevation. The PyInstaller spec sets `uac_admin=False`; the Inno Setup
  installer is `PrivilegesRequired=lowest`. On Linux the helper is unchanged:
  root, 0600 Unix socket, `SO_PEERCRED`, static allowlist, state-directory
  confinement. *(2026-09-28)* On Windows and macOS there is still no separate
  privileged process, but whole-drive and raw work now exists there and needs
  one: a human starts Sanctum with *Run as administrator* (Windows) or as root
  (macOS). Nothing elevates itself; unelevated, the resolver reports REQUIRES
  PRIVILEGE and nothing is opened.
- **Insecure IPC / unauthenticated privileged endpoints.** The two new helper
  operations (`platform_status`, `assess_device`) are read-only and go
  through the same allowlist and `apply_policy`. `helper_mode`, which decides
  the privilege a capability row reports, is stamped by the daemon and
  overwrites anything in the request (pinned by a test).
- **Target identity / TOCTOU on devices.** *(2026-09-21; superseded for
  Windows and macOS on 2026-09-28 — see
  [The native device layer](#the-native-device-layer-windows-and-macos).)*
  At the time no destructive device operation existed on Windows or macOS.
  On Linux the helper re-reads the device from the host and applies
  `guard.assert_serial_confirmed` in the adapter, and `drive.execute`
  re-reads the serial again before writing. The UI's confirmation is preceded
  by a fresh `assess_device` re-read and refuses if the serial changed or the
  device is no longer READY — a convenience; the helper's check is the gate.
- **Device identity spoofing.** Serials come from the OS; a device with no
  serial is confirmed by its stable id on Linux as before. Windows and macOS
  report missing serials as a limitation rather than inventing one.
- **Environment-variable injection.** The Windows protected-path list reads
  `%SystemRoot%` and friends; a user who changes them can only weaken the
  protection of their own erase requests, which they could already issue.
  Nothing privileged reads the environment for a path.
- **Path traversal in the UI server.** Unchanged: static files are served
  only from inside `ui/dist` after `resolve()`.
- **Installers.** No maintainer scripts in the `.deb` (nothing runs as root
  at install time). Uninstallers never delete the ledger or reports.
- **Offline.** No new network access: no CDN, fonts, telemetry or update
  check. The launcher binds 127.0.0.1 only; the only outbound-looking call is
  to its own `/health`.

## The native device layer (Windows and macOS)

Reviewed 2026-09-28 against the code in `core/device/win/`, `core/device/mac/`,
`core/platform/windows.py`, `core/platform/macos.py`, `core/erase/blockclear.py`,
`core/carve/win_source.py`, `core/carve/mac_source.py` and
`helper/authorization.py`. Every path is exercised through adapter doubles
(`testkit/fake_windows.py`, `testkit/fake_macos.py`); none has run against a
physical disk.

### Trust boundary

- **Windows: the elevated process itself holds raw access.** There is no
  separate helper and no socket; the helper allowlist runs in-process
  (`InProcessHelper`). Raw disk access is granted by Windows only to an elevated
  process, so whole-drive, raw and firmware work needs Sanctum started with *Run
  as administrator*, and everything that process serves - including the loopback
  API and its session token - runs elevated for that session. That is a wider
  elevated surface than the Linux design, where only the helper holds root. The
  mitigation is that a human chooses it for one session, and the installer and
  executable never request it.
- **One module calls the OS.** `core/device/win/native.py` is the only code that
  calls `kernel32`, through `ctypes`, behind the `NativeApi` protocol. Every IOCTL
  input and output structure is packed and parsed by pure functions
  (`core/device/win/ioctl.py`, `ata.py`, `nvme.py`), so the byte layouts are
  tested without Windows. Unbuffered transfers use a page-aligned `mmap` buffer.
  Win32 failures surface as `NativeError` with the error code, so a medium error
  (salvaged) is never confused with a vanished device (stop).
- **macOS: root, one raw node.** The socket helper daemon is Linux-only because it
  authenticates peers with `SO_PEERCRED`, so on macOS the same allowlist also runs
  in-process and the process must run as root (the adapter's advice reads "start
  the Sanctum helper with sudo"). The only device path opened is `/dev/rdiskN` or
  `/dev/rdiskNsM`, matched by `re` before use; a synthesized APFS container disk
  and internal Apple storage are refused before this layer is reached (BLOCKED FOR
  SAFETY: the Secure Enclave encrypts it, and Erase All Content and Settings is
  named instead).
- **Firmware commands on Windows** go through `IOCTL_ATA_PASS_THROUGH` (ATA
  SANITIZE, HPA SET MAX) and `IOCTL_STORAGE_REINITIALIZE_MEDIA` (NVMe Sanitize),
  and are offered only when the controller's own IDENTIFY answer reports them. ATA
  SECURITY ERASE is not implemented on Windows (it would leave a password-locked
  drive with no tested recovery path), and DCO RESTORE/SET are never issued on
  any platform.
- **CI never writes.** `scripts/native_smoke.py` runs the real bindings on the
  Windows and macOS runners with one read-only handle, the identity ioctls and one
  sector; it contains no write handle and no destructive command.

### Identity binding

- **Windows: identity is read from the open handle, never trusted from the
  path.** After `CreateFileW` on `\\.\PhysicalDriveN`,
  `core/device/win/disk.py:WindowsDisk.bind` asks the handle itself which disk it
  is (`IOCTL_STORAGE_GET_DEVICE_NUMBER`), what serial it reports
  (`IOCTL_STORAGE_QUERY_PROPERTY`) and how long it is
  (`IOCTL_DISK_GET_LENGTH_INFO`), and refuses on any difference from the plan.
  Every later read or write uses that same handle, so a USB disk unplugged and
  replaced by another that takes its number is refused rather than written. A
  drive letter or volume path is never accepted as a disk (`parse_disk_number`).
- **Windows: no write while any volume is exposed.** At the write seam the volume
  manager is asked again, through the same API, whether any volume on the disk is
  exposed; a volume without a drive letter can still have a filesystem mounted on
  demand, so any exposed volume refuses the write (and the restore). The disk must
  be taken offline first.
- **macOS: bound by size, serial re-read just before open.** macOS has no ioctl
  that returns a drive serial. `core/platform/macos.py:_open_bound` re-reads the
  device through `diskutil` / `system_profiler`, refuses a changed serial or a
  mounted volume, then opens `/dev/rdiskN` and `MacRawDisk.bind` checks its size
  (`DKIOCGETBLOCKCOUNT` × `DKIOCGETBLOCKSIZE`, read from the open descriptor)
  against the plan.
- **Both: no serial, no write.** A device that reports no serial, or two devices
  that report the same serial, are refused before anything opens
  (`core/platform/base.py:_revalidated`).
- **The write seam re-checks the authorization.** `helper/authorization.py`
  re-reads the device through the platform adapter immediately before the engine
  starts and refuses on any drift from the approved identity, plan or backup, as on
  Linux. Erase, restore and HPA authorizations each have a kind and cannot be spent
  as another.

### TOCTOU windows that remain

- **macOS serial re-read to `open()`.** Between the `system_profiler` re-read and
  the `open()` of `/dev/rdiskN`, a different disk of exactly the same size could be
  attached as the same `diskN`, and the size check would pass. The window is
  milliseconds and needs a physical swap at that moment, but it is not closed. The
  clear's limitations record how the binding was made (serial re-read immediately
  before the open, the open device bound by its kernel size); they do not claim the
  window is closed.
- **Authorization check to first write** (all platforms): between the write
  seam's check and the first write only the engine's own guards stand. On Windows
  the handle binding narrows this to the disk the handle already proved it is.

### The preparation step

`POST /devices/prepare` is the only code that takes a disk offline (Windows,
`IOCTL_DISK_SET_DISK_ATTRIBUTES`, **not persistent**: the disk returns online at
the next reboot or re-attach) or unmounts it (macOS, `diskutil unmountDisk`). It
is never part of an erase, needs the serial typed (there is no dry-run mode),
refuses the system disk and internal Apple storage, and is ledgered.
Taking a disk offline writes nothing to it.

## Residual risks (not fixed, stated)

- **`SANCTUM_DEV_INSECURE=1` turns the development session off.** It is
  explicit, it prints a warning naming what it allows, and it is the only way
  to run without a token. (Fixed since the first version of this review: the
  development server used to have no session protection at all, and
  `python -m api.main` now mints a token per start and prints the one URL
  that opens it.)
- **The session cookie is not `Secure`.** It is sent over plain HTTP on
  loopback and never leaves the machine; there is no TLS to require.
- **File-erase TOCTOU.** Between the `lstat` that decides a path is not a link
  and the `open` that overwrites it, a process with write access to the parent
  directory could swap in a link. Pre-existing on every platform; exploiting
  it needs write access to the directory being erased.
- **Browser fallback.** Without `pywebview` (always in the Linux packages;
  a Linux source install gets it from the `desktop` extra) the session URL
  is passed to the default browser's command line, where another process of
  the same user could read it. Such a process can already act as that user.
- **Unsigned packages.** See `docs/packaging.md`.
- **An elevated Windows session elevates the API too** (above, *Trust
  boundary*). Run elevated only for the session that needs raw access.
- **macOS size-only binding window** (above, *TOCTOU windows that remain*).
