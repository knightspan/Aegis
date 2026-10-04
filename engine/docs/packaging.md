# Packaging and running the desktop app

One product, three native packages. Each is the same Python application
(API + UI bundle + platform adapters) frozen by PyInstaller into a
self-contained runtime, so **the target machine needs no Python, no Node and
no developer tools**. The app serves its UI on a private loopback port and
opens it in a window; nothing is fetched from the network, ever.

| Platform | Artifact | Built by | Built and driven |
|---|---|---|---|
| Linux | `Sanctum-<ver>-x86_64.AppImage`, `sanctum_<ver>_amd64.deb` | `scripts/build-linux-portable.sh` (glibc 2.31 container) or `scripts/build-linux.sh` (host) | **Yes** — locally and on `ubuntu-22.04` in CI; installed and run on Debian 12 and Ubuntu 22.04; 23 of 23 packaged checks in CI on 2026-09-22 at `ba13a9a`, an earlier build (the 24th, then *whole-drive unsupported off Linux*, did not apply to Linux; that check has since been replaced by the resolver-state checks below). The build for this release ran the isolated smoke only: 22 PASS, 2 NOT RUN, because two checks need a real device ([`validation/package-2026-09-25/`](validation/package-2026-09-25/README.md)) |
| Windows 10 1809+ / 11, x64 | `SanctumSetup.exe` | `scripts/build-windows.ps1` (PyInstaller + Inno Setup 6) | **Yes, in CI** — built on `windows-latest`, installed silently, the installed app driven, then uninstalled. **Also yes, physically** — built, installed and driven by a human on a Windows 11 Home machine (build 10.0.26200), 23 of 23 packaged checks, 2026-09-27 ([`validation/windows-hardware-2026-09-27-fixes/`](validation/windows-hardware-2026-09-27-fixes/README.md)). Unsigned. |
| macOS 12+ (arm64) | `Sanctum.dmg` containing `Sanctum.app` | `scripts/build-macos.sh` (PyInstaller + `hdiutil`) | **Yes, in CI** — built on `macos-14`, DMG mounted, `Sanctum.app` driven through a folder erase and a signed certificate; 24 of 24 checks. Unsigned, **not notarized**. |

**Windows:** installed by a human on a physical Windows 11 machine and driven
against a real removable USB stick, 2026-09-27 — device discovery (`usb-flash`),
the mounted-device refusal, and file/folder erase → verify → certificate on the
host system disk (device class not recorded) all real. See
[`validation/windows-hardware-2026-09-27-fixes/`](validation/windows-hardware-2026-09-27-fixes/README.md).
That build predates the Windows whole-drive clear, device sanitize and raw
acquisition backends; the packages now ship them (below), and they are
**IMPLEMENTED / UNVALIDATED** or **DEVICE-DEPENDENT**: tested against adapter
doubles only, never run on a physical disk.
**macOS:** not yet installed by a human on physical hardware, and has not
touched removable media. Its whole-drive clear and raw acquisition backends for
external disks ship and are **IMPLEMENTED / UNVALIDATED**. Per-platform states:
[`validation/capability-completion-2026-09-28/capability-matrix.md`](validation/capability-completion-2026-09-28/capability-matrix.md).

## Build commands

### Linux (distributable)

```bash
cd ui && npm ci && npm run build && cd ..
bash scripts/build-linux-portable.sh        # needs podman (or CONTAINER=docker)
ls dist/   # Sanctum-0.0.0-x86_64.AppImage  sanctum_0.0.0_amd64.deb  SHA256SUMS-linux.txt
```

`scripts/build-linux.sh` builds the same packages on the host directly. That
build only runs on systems whose glibc is at least the build host's (a
Fedora 44 build needs glibc 2.38 and fails on Debian 12); use it for local
testing, and the portable build for anything handed to someone else.

### Windows

From a Developer PowerShell with Python 3.11 (`py -3.11`), Node 20+ and
Inno Setup 6 installed:

```powershell
pwsh scripts\build-windows.ps1
# dist\SanctumSetup.exe
```

### macOS

With Python 3.11, Node 20+ and the Xcode command line tools:

```bash
bash scripts/build-macos.sh
# dist/Sanctum.dmg (and dist/Sanctum-<ver>.dmg)
```

### CI

`.github/workflows/release.yml` builds all three on `ubuntu-22.04`,
`windows-latest` and `macos-14`, after running that platform's validation
suite and bundling the result (see *Validation record* below).

## Running

| Platform | Installed | From source (developer) |
|---|---|---|
| Linux | `./Sanctum-<ver>-x86_64.AppImage` (or `--appimage-extract-and-run` without FUSE); `.deb`: `sudo apt install ./sanctum_<ver>_amd64.deb`, then *Sanctum* in the app menu or `sanctum` | `pip install -c constraints.txt -e .[dev,desktop]`, then `python -m api.desktop` (native Qt window); or `make run` and open the `/session/<token>` URL it prints |
| Windows | Run `SanctumSetup.exe`, then *Sanctum* in the Start menu | `py -3.11 -m venv .venv; .venv\Scripts\python -m pip install -c constraints.txt -e .[dev,desktop]; .venv\Scripts\python -m api.desktop` |
| macOS | Open `Sanctum.dmg`, drag *Sanctum* to Applications, open it (right-click > Open the first time: the build is unsigned) | `python3.11 -m venv .venv && .venv/bin/pip install -c constraints.txt -e .[dev,desktop] && .venv/bin/python -m api.desktop` |

### Whole-drive and raw device work

Each platform reaches raw devices differently. What each needs, and what has
been proven there, is in [`INSTALL.md`](../INSTALL.md):

- **Windows:** no separate helper. Start Sanctum with *Run as administrator*,
  and take the target disk offline first (Devices > Prepare, or Disk
  Management). Without elevation the capabilities read REQUIRES PRIVILEGE.
- **macOS:** `/dev/rdiskN` is root-only, and the Linux socket helper does not
  start on macOS, so the Sanctum process that does the raw work must run as
  root; unmount the external disk first (Devices > Prepare, or `diskutil
  unmountDisk`). Internal Apple storage is never raw-written or imaged.
- **Linux:** the privileged helper, below.

#### Linux

Whole-drive sanitization needs the privileged helper. The UI never runs as
root:

```bash
sudo mkdir -p /var/lib/sanctum
sudo ./Sanctum-<ver>-x86_64.AppImage --appimage-extract-and-run helper \
     --operator-uid "$(id -u)" --state-dir /var/lib/sanctum
# then, as yourself:
SANCTUM_HELPER_SOCKET=/run/sanctum/helper.sock SANCTUM_STATE_DIR=/var/lib/sanctum \
     ./Sanctum-<ver>-x86_64.AppImage
```

(With the `.deb`: `sudo /opt/sanctum/Sanctum helper ...` and `sanctum`.)

## What the launcher does

`api/desktop.py`, the entry point of every package:

1. Picks a free port on 127.0.0.1.
2. Generates a 32-byte session token and passes it to the API in the
   environment. Every request without the matching `HttpOnly`,
   `SameSite=Strict` cookie gets 401 (`api/security.py`).
3. Starts the API and waits for `/health`.
4. Opens `http://127.0.0.1:<port>/session/<token>` - in a native window
   (WebView2 on Windows, WKWebView on macOS, Qt WebEngine on Linux) and
   nowhere else. If `pywebview` is missing or the window fails, the launcher
   prints why and exits 1; it never opens a browser.
5. Stops when the window closes, or when *Quit Sanctum* is pressed in the
   sidebar.

State lives in the per-user data directory: `~/.local/share/sanctum`,
`%LOCALAPPDATA%\Sanctum`, `~/Library/Application Support/Sanctum`, or
`SANCTUM_STATE_DIR`.

## Upgrades and uninstall

- **Windows:** the installer has a fixed `AppId`, so a newer
  `SanctumSetup.exe` upgrades in place and replaces the runtime wholesale.
  Uninstall (Settings > Apps) removes the program; the ledger and reports in
  `%LOCALAPPDATA%\Sanctum` are **kept**, because deleting an audit trail is
  not an uninstaller's decision. The installer is per-user by default and
  never requests elevation; an administrator can choose an all-users install.
- **Linux:** `apt install` a newer `.deb` upgrades; `apt remove sanctum`
  removes `/opt/sanctum`, `/usr/bin/sanctum` and the desktop entry, and keeps
  `~/.local/share/sanctum`. The AppImage is a single file: replace it.
- **macOS:** replace `Sanctum.app` in Applications; delete it to uninstall.
  `~/Library/Application Support/Sanctum` is kept.

## Signing - not performed

| | Status | Remaining step |
|---|---|---|
| Windows Authenticode | **Unsigned.** SmartScreen will warn. | Obtain a code-signing certificate; run `scripts/build-windows.ps1 -SignCommand "signtool sign /fd sha256 /tr <tsa> /td sha256 /f cert.pfx /p ..."`. |
| macOS Developer ID | **Ad-hoc signed only** (PyInstaller). Gatekeeper blocks a double-click on other Macs. | `CODESIGN_IDENTITY="Developer ID Application: ..." bash scripts/build-macos.sh` |
| macOS notarization | **Not performed.** | `xcrun notarytool submit dist/Sanctum.dmg --keychain-profile <profile> --wait && xcrun stapler staple dist/Sanctum.dmg` |
| Linux | AppImage and `.deb` are unsigned; `SHA256SUMS-linux.txt` is produced. | Sign the checksum file with the release key. |

## Validation record

`scripts/record_platform_validation.py` runs the platform suites with pytest
and writes `core/platform/validation_record.json`; the spec bundles it. The
app's capability screen reads it: a suite not recorded as `PASS` on the
platform the app is running on leaves the capabilities it backs at
**Unverified**. A build nobody tested therefore says so on its own screen.
The same file's `physical_validations` list holds the physical runs, each keyed
by platform, capability and device class and added only through
`scripts/record_physical_validation.py`; the resolver reads it to decide
whether a capability is SUPPORTED for a device class
([`validation/physical-validation-procedure.md`](validation/physical-validation-procedure.md)).

The record carries two shapes. `suites` is what the capability model gates
on. `features` is one row per platform feature - platform, OS, architecture,
commit, the tests behind it, the result, the date, the evidence file and the
limitations that still apply - so the record never says "Windows verified",
only which feature was validated, by what, and when. The CI jobs produce one
record per runner and `--merge` folds them together, preferring a row that
says something over one that says NOT RUN.

## Which platform backends ship

Every package carries every platform's backend modules, because the adapters
import them lazily and a missing one would only surface when the screen that
needs it is opened. Three checks pin this:

- `tests/test_package_completeness.py` — every module the capability
  resolver's `IMPLEMENTATIONS` table names (the Windows `core.device.win.*`
  kernel32 layer, `core.device.mac.rawdisk`, `core.carve.win_source`,
  `core.carve.mac_source`, `core.erase.blockclear`,
  `core.erase.devicesanitize`, `core.report.semantics`, `core.backup`,
  `core.restore`, `core.benchmark`) is importable, is collected by the
  PyInstaller spec's `collect_submodules("core")`, and imports nothing the
  spec excludes.
- `scripts/package_smoke.py` — against the installed package, asserts the
  resolver answers for every capability and that the platform's backends are
  present (not NOT IMPLEMENTED): on Linux whole-drive clear, raw acquisition
  and restore; on Windows those plus volume acquisition, ATA SANITIZE, NVMe
  Sanitize and crypto erase; on macOS whole-drive clear, raw acquisition and
  restore. It opens no device.
- `scripts/native_smoke.py`, in `platform-ci` on the real Windows and macOS
  runners — opens the runner's own disk 0 **read-only** through the real
  kernel32 or `/dev/rdisk0` binding, asks the handle for its identity and
  size, and reads one sector. It opens no write handle and issues no
  destructive, sanitize, HPA or offline command. It proves the bindings load
  and answer on the real OS; **it is not physical validation** of any
  destructive or acquisition capability, and its evidence file says so.

The resolver itself reports NOT IMPLEMENTED, naming the missing module, if a
package lost a backend it names. A shipped backend is not a validated one: the
generated matrix,
[`validation/capability-completion-2026-09-28/capability-matrix.md`](validation/capability-completion-2026-09-28/capability-matrix.md),
separates the two.

## Known packaging limits

- **E01 writing** needs the patched libewf build (`scripts/build-libewf-python.sh`,
  used by the Docker image). The desktop packages use the stock
  `libewf-python`, which reads E01 but cannot write it; acquisition to raw
  works. On macOS `libewf-python` compiles from source, and CI installs
  without it if that fails (E01 then unavailable in that environment).
- **AppImage and FUSE:** hosts without FUSE 2 need
  `--appimage-extract-and-run`.
- **Linux desktop window:** the launcher needs `pywebview[qt]`. The Linux
  package build scripts do not yet install the `desktop` extra, so a Linux
  package built from them has no window to open and exits with an error.
- **Architectures:** x86_64 Linux and Windows; macOS builds for the build
  machine's architecture (arm64 on `macos-14`). No universal2 build.
