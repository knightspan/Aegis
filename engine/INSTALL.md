# Installing Sanctum Forensics

This guide covers Linux, Windows and macOS. There are two ways to get a working
copy:

- **A desktop package** (AppImage / `.deb`, `SanctumSetup.exe`, `Sanctum.dmg`).
  The target machine needs no Python and no Node. Packages are built from this
  repository; no pre-built release is published on GitHub yet, so either build
  one yourself (see [Building a desktop package](#building-a-desktop-package))
  or download the artifacts of a `release` workflow run from the repository's
  **Actions** tab.
- **From source** — for development, running the test suite, or when you want
  the exact code in this checkout.

Before you start, know what each platform can do. Two questions are kept
apart everywhere in this repository: **is it implemented** on that platform,
and **has it been run on a physical device** of that class. File and folder
erasure (M2), recovery from an image (M3), and signed reports are implemented
on all three. Whole-drive clear and raw device acquisition are now implemented
on all three too, but outside Linux they have only been tested against
synthetic media and adapter doubles.

| | Linux | Windows | macOS |
|---|---|---|---|
| Supported OS | x86_64; packages run on Debian 12 and Ubuntu 22.04, source verified on Fedora 44 | Windows 10 1809+ / 11, x64 | macOS 12+ (arm64 package; source install on Intel too) |
| Whole-drive clear (M1, addressable overwrite) | SUPPORTED on `usb-flash` (one TOSHIBA TransMemory stick, 2026-09-05); IMPLEMENTED / UNVALIDATED on every other class; needs the root helper | IMPLEMENTED / UNVALIDATED; needs **Run as administrator** and the disk taken offline | IMPLEMENTED / UNVALIDATED for external disks; needs root; internal Apple storage is never raw-written |
| Device sanitize (M1 Purge: ATA / NVMe) | DEVICE-DEPENDENT, never run on a physical drive | ATA SANITIZE and NVMe Sanitize DEVICE-DEPENDENT, never run on a physical drive; ATA SECURITY ERASE NOT IMPLEMENTED; NVMe Format PLATFORM-LIMITED | PLATFORM-LIMITED (no public ATA/NVMe pass-through) |
| Raw device acquisition (M3) | SUPPORTED on `usb-flash` (same stick, 2026-09-05) | IMPLEMENTED / UNVALIDATED; read-only handle, no software write block | IMPLEMENTED / UNVALIDATED for external disks; no software write block |
| File / folder erase (M2) | IMPLEMENTED / UNVALIDATED | SUPPORTED on the host system disk (class not recorded, 2026-09-27) | IMPLEMENTED / UNVALIDATED (APFS: the overwrite cannot be verified; reported, not claimed) |
| Recovery from image (M3) | yes | yes | yes |

These states come from the capability resolver, not from this page. The
generated per-platform matrix, with the reason and limit for every row, is
[`capability-matrix.md`](docs/validation/capability-completion-2026-09-28/capability-matrix.md);
what changed and what is physically validated is in
[`capability-completion-2026-09-28/`](docs/validation/capability-completion-2026-09-28/README.md).
The app shows the same states, with their reasons, on its **Platform** screen.

---

## Requirements for a source install

| Tool | Version | Why |
|---|---|---|
| Python | **3.11 exactly** | `pyproject.toml` pins `==3.11.*`. 3.12+ and 3.10 are refused by pip. |
| Node.js + npm | 20 or newer (CI uses 22) | Builds the UI bundle in `ui/dist/`. Without it the API runs headless. |
| Git | any | To clone. |
| C compiler | Linux and macOS only | `libewf-python` has no cp311 wheel for Linux or for Apple Silicon and compiles from source. Windows gets a wheel. |

The host's default `python3` is often **not** 3.11 (Fedora 44 ships 3.14,
Ubuntu 24.04 ships 3.12). Install 3.11 alongside it; do not replace the
system interpreter.

---

## Linux

### Option A: desktop package

AppImage (any x86_64 distribution with glibc 2.31 or newer, when built with
the portable script):

```bash
chmod +x Sanctum-<ver>-x86_64.AppImage
./Sanctum-<ver>-x86_64.AppImage
# Without FUSE 2 on the host:
./Sanctum-<ver>-x86_64.AppImage --appimage-extract-and-run
```

`.deb` (Debian, Ubuntu):

```bash
sudo apt install ./sanctum_<ver>_amd64.deb
sanctum          # or "Sanctum" in the application menu
```

The packaged app opens in its own native window on a private loopback URL.
It never opens a browser. If the window cannot start, it prints why and exits.

### Option B: from source

**1. System packages**

Debian 12 / Ubuntu 22.04:

```bash
sudo apt update
sudo apt install -y git build-essential pkg-config python3.11 python3.11-venv python3.11-dev \
    nodejs npm ntfs-3g exfatprogs dosfstools hdparm nvme-cli sleuthkit
```

Ubuntu 24.04 does not ship Python 3.11; add the deadsnakes PPA first:

```bash
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt update
# then run the apt install line above
```

If your distribution's `nodejs` is older than 20, install Node 20+ from
[nodejs.org](https://nodejs.org/) or NodeSource instead.

Fedora:

```bash
sudo dnf install -y git gcc gcc-c++ make python3.11 python3.11-devel nodejs npm \
    ntfs-3g exfatprogs dosfstools hdparm nvme-cli sleuthkit
```

`hdparm` and `nvme-cli` are what the capability probe reads to choose an
erase method; `sedutil-cli` (not packaged by most distributions) adds Opal
crypto erase. Without them the probe cannot see firmware Purge support, and
the app will not offer it. `sleuthkit` is a debugging aid only.

**2. Clone and install**

```bash
git clone https://github.com/Invinciblx777/sanctum-forensics.git
cd sanctum-forensics
make install                     # creates .venv with python3.11, installs .[dev]
source .venv/bin/activate
python -c "import pytsk3, pyewf; print('native bindings OK')"
```

On Debian/Ubuntu, `./scripts/devsetup.sh` does steps 1 and 2 in one go.

To run Sanctum as its own desktop window rather than a browser tab, also
install the `desktop` extra:

```bash
python -m pip install --constraint constraints.txt -e ".[desktop]"
```

On Linux it installs pywebview with its Qt backend (PyQt6 and Qt WebEngine,
about 530 MB once installed). No system packages and no `sudo` are needed. Run on
Fedora 44 under Wayland (2026-09-28); X11 has not been tried.

**3. Build the UI**

```bash
(cd ui && npm ci && npm run build)
```

**4. Check and run**

```bash
make check       # ruff, mypy --strict, pytest; optional but recommended
```

As a desktop app, in its own window (needs the `desktop` extra from step 2):

```bash
python -m api.desktop
```

It picks a free loopback port, mints a session token and opens the UI in a
native window. Closing the window stops Sanctum. Without the `desktop` extra
the command prints an error and exits; it does not fall back to a browser.

As a plain server, in a browser:

```bash
make run         # prints http://127.0.0.1:8787/session/<token>
```

Open the `/session/<token>` URL it prints. Any other URL, including the bare
`http://127.0.0.1:8787`, is refused with 401.

**5. Optional: an application menu entry**

To start the source checkout from the application menu like any other app,
create `~/.local/share/applications/sanctum-dev.desktop`, replacing
`/path/to/sanctum-forensics` with the absolute path of your checkout:

```ini
[Desktop Entry]
Type=Application
Name=Sanctum (dev)
Comment=Sanctum Forensics desktop window, run from the source checkout
Exec=/path/to/sanctum-forensics/.venv/bin/python -m api.desktop
Path=/path/to/sanctum-forensics
Icon=/path/to/sanctum-forensics/packaging/icon/sanctum-logo.png
Terminal=false
Categories=Utility;
```

Then run `update-desktop-database ~/.local/share/applications`. This entry
runs as your own user, so it uses the in-process helper; whole-drive work still
needs the root helper below.

### Linux: whole-drive work

Whole-drive sanitization needs the privileged helper. The UI and API never run
as root; a human starts the helper with `sudo`, in its own terminal:

```bash
sudo mkdir -p /var/lib/sanctum
sudo .venv/bin/python -m helper --operator-uid "$(id -u)" --state-dir /var/lib/sanctum
```

Then, as yourself, in a second terminal:

```bash
SANCTUM_HELPER_SOCKET=/run/sanctum/helper.sock \
SANCTUM_STATE_DIR=/var/lib/sanctum \
.venv/bin/python -m api.main
```

With the `desktop` extra installed, replace `api.main` with `api.desktop` to
get the same session in its own window.

With a package, replace `.venv/bin/python -m helper` with
`./Sanctum-<ver>-x86_64.AppImage --appimage-extract-and-run helper` or
`/opt/sanctum/Sanctum helper`.

Check `/health` before any real job: its `limitations` list must **not**
contain `HELPER_IN_PROCESS`. The full procedure, including creating the signing
key before the first ledger entry, is in
[user manual §3](docs/user-manual.md#3-starting-it).

---

## Windows

### Option A: installer

1. Run `SanctumSetup.exe`. The installer is **unsigned**, so SmartScreen shows
   *Windows protected your PC*; choose **More info → Run anyway**.
2. It installs per-user by default and does not ask for Administrator.
   Installing needs no elevation; whole-drive and raw device work later does
   (see [Windows: what to expect](#windows-what-to-expect)).
3. Start **Sanctum** from the Start menu. It opens in its own window (WebView2).

Uninstall from **Settings → Apps**. The ledger and reports in
`%LOCALAPPDATA%\Sanctum` are kept on purpose; delete that folder yourself if
you want them gone.

### Option B: from source

**1. Install the tools** (PowerShell):

```powershell
winget install -e --id Python.Python.3.11
winget install -e --id OpenJS.NodeJS.LTS
winget install -e --id Git.Git
```

Close and reopen PowerShell so the new `PATH` is picked up. No compiler is
needed: `pytsk3` and `libewf-python` both ship Windows wheels for Python 3.11.

**2. Clone and install**

```powershell
git clone https://github.com/Invinciblx777/sanctum-forensics.git
cd sanctum-forensics
py -3.11 -m venv .venv
.venv\Scripts\python -m pip install --upgrade pip
.venv\Scripts\python -m pip install --constraint constraints.txt -e ".[dev,desktop]"
```

If PowerShell refuses to run `.venv\Scripts\Activate.ps1`, you do not need
it; every command here calls `.venv\Scripts\python` directly.

**3. Build the UI**

```powershell
cd ui; npm ci; npm run build; cd ..
```

**4. Run**

```powershell
.venv\Scripts\python -m api.desktop     # opens a native window
# or the plain server, then open the /session/<token> URL it prints:
.venv\Scripts\python -m api.main
```

Tests: `.venv\Scripts\python -m pytest`. The `Makefile` also works from Git
Bash or any shell with GNU make; it detects the Windows venv layout.

### Windows: what to expect

- **Device work needs Run as administrator.** Whole-drive clear, device
  sanitize (ATA SANITIZE, NVMe Sanitize), raw physical-device and volume
  acquisition, and the HPA/DCO workflow open `\\.\PhysicalDriveN` or send
  a pass-through command, which Windows grants to an elevated process only.
  The Windows build has **no separate helper**: close Sanctum and start it
  again with *Run as administrator* (right-click the Start menu entry, or an
  elevated PowerShell for a source install). Without elevation those
  capabilities read **REQUIRES PRIVILEGE**; discovery and file erasure still
  work unelevated.
- **Take the disk offline first.** A disk that still exposes any volume is
  refused, and no erase takes a disk offline by itself. Use **Devices →
  Prepare** (the volumes it affects are shown, then the serial is typed by
  hand; the offline state is not persistent and the disk returns online at the
  next reboot or when you bring it online), or *Disk Management → Offline*.
  The system disk is always refused.
- **What has been run on physical hardware.** Device discovery on a USB stick
  and file/folder erase on the host system disk (2026-09-27). Whole-drive
  clear, device sanitize and raw acquisition on Windows are implemented and
  tested against adapter doubles only; the app shows them as
  **IMPLEMENTED / UNVALIDATED** or **DEVICE-DEPENDENT**, never as validated.
- ATA SECURITY ERASE is **NOT IMPLEMENTED** on Windows, NVMe Format is
  **PLATFORM-LIMITED**, and free-space wipe is **NOT IMPLEMENTED**; the app
  says why for each.
- File-erase verification reads the disk back; without elevation it is
  reported as *not verified*, never as a pass.

---

## macOS

### Option A: disk image

1. Open `Sanctum.dmg` and drag **Sanctum** to **Applications**.
2. The build is ad-hoc signed and **not notarized**, so Gatekeeper blocks a
   double-click the first time. Right-click **Sanctum** → **Open** → **Open**.
   On macOS 15 and later, if there is no *Open* button, go to
   **System Settings → Privacy & Security** and choose **Open Anyway**.
3. Sanctum opens in its own window.

The published package is arm64 (Apple Silicon). On an Intel Mac, install from
source.

### Option B: from source

**1. Install the tools**

```bash
xcode-select --install                 # C compiler for libewf-python
brew install python@3.11 node git     # Homebrew: https://brew.sh
```

**2. Clone and install**

```bash
git clone https://github.com/Invinciblx777/sanctum-forensics.git
cd sanctum-forensics
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python scripts/ci_install.py dev,desktop
```

`libewf-python` has no Apple Silicon wheel and compiles from source. If that
compile fails, `scripts/ci_install.py` retries without it and prints a note:
everything works except reading and writing E01 images.

**3. Build the UI**

```bash
(cd ui && npm ci && npm run build)
```

**4. Run**

```bash
python -m api.desktop       # opens a native window
# or: make run, then open the /session/<token> URL it prints
```

### macOS: what to expect

- **Internal Apple storage is never raw-written or imaged.** On Apple silicon
  and T2 Macs the Secure Enclave encrypts it; the purge path is macOS's own
  **System Settings → General → Transfer or Reset → Erase All Content and
  Settings**, which destroys the storage encryption keys. The app names it as
  the recommended action and cannot perform or verify it.
- **External disks: whole-drive clear and raw acquisition need root.** They
  go through `/dev/rdiskN`, which macOS opens for root only; without it the
  capabilities read **REQUIRES PRIVILEGE**. The in-app advice says to start
  Sanctum itself with `sudo`. Note that the Linux socket daemon
  (`python -m helper`) does not start on macOS — it exits with *"The
  privileged helper is Linux-only"* — so in this build the raw work runs in
  the Sanctum server process itself, and that process must be the one started
  with `sudo`. Unmount every volume on the disk first: **Devices → Prepare**
  (the volumes it unmounts are shown, then the serial is typed) or
  `diskutil unmountDisk /dev/diskN`. A mounted disk is refused and no erase
  unmounts one itself.
- **Nothing on macOS has been run on a physical device.** Discovery, file
  erase, whole-drive clear of an external disk and raw acquisition are
  **IMPLEMENTED / UNVALIDATED**. Device sanitize, crypto erase and HPA/DCO are
  **PLATFORM-LIMITED** (macOS exposes no public ATA or NVMe pass-through), and
  free-space wipe is **NOT IMPLEMENTED**.
- File erasure runs on APFS, but APFS is copy-on-write, so the erase cannot be
  verified. The report says *not verifiable* and gives the reason.

---

## Docker (API, UI and recovery only)

```bash
docker build -t sanctum-forensics .          # or: podman build -t sanctum-forensics .
docker run --rm --network host -e SANCTUM_STATE_DIR=/var/lib/sanctum sanctum-forensics
```

`--network host` is required because the API binds `127.0.0.1` only. The image
has no privileged helper, so device operations inside it fail rather than
escalate. It is the one build that can **write** E01 images; see
[`docs/technical.md`](docs/technical.md).

---

## Building a desktop package

| Platform | Prerequisites | Command | Output |
|---|---|---|---|
| Linux (portable) | podman or Docker, Node 20+ | `(cd ui && npm ci && npm run build) && bash scripts/build-linux-portable.sh` | `dist/Sanctum-<ver>-x86_64.AppImage`, `dist/sanctum_<ver>_amd64.deb` |
| Linux (host only) | Python 3.11, Node 20+ | `make package-linux` | same, but only runs on glibc at least the build host's |
| Windows | Python 3.11, Node 20+, [Inno Setup 6](https://jrsoftware.org/isinfo.php) | `pwsh scripts\build-windows.ps1` | `dist\SanctumSetup.exe` |
| macOS | Python 3.11, Node 20+, Xcode command line tools | `bash scripts/build-macos.sh` | `dist/Sanctum.dmg` |

Signing, notarization, upgrades and the packaging limits are in
[`docs/packaging.md`](docs/packaging.md).

---

## Where your data goes

Ledger, reports, signing keys and recovered files live in the per-user state
directory. Uninstalling the app never deletes it.

| Platform | Default location |
|---|---|
| Linux | `~/.local/share/sanctum` |
| Windows | `%LOCALAPPDATA%\Sanctum` |
| macOS | `~/Library/Application Support/Sanctum` |

Set `SANCTUM_STATE_DIR` to use another directory.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `ERROR: Package 'sanctum-forensics' requires a different Python` | The venv is not Python 3.11. Delete `.venv` and recreate it with `python3.11 -m venv .venv` (or `py -3.11` on Windows). |
| `error: command 'gcc' failed` while installing `libewf-python` | No C compiler or Python headers. Linux: install `build-essential python3.11-dev` (Debian/Ubuntu) or `gcc python3.11-devel` (Fedora). macOS: `xcode-select --install`. |
| `libewf_handle_open: write access currently not supported - compiled without zlib` | The stock `libewf-python` reads E01 but cannot write it. Acquire to raw, or use the Docker image or `scripts/build-libewf-python.sh`. |
| The page is blank, or `/health` shows `"ui_bundled": false` | The UI was not built. Run `npm ci && npm run build` in `ui/`. |
| Every request returns 401 | Open the `/session/<token>` URL the server printed, not the bare address. A new token is minted each start. |
| `/health` lists `HELPER_IN_PROCESS` (Linux) | The API did not find the helper socket. Check the helper terminal is still running and `SANCTUM_HELPER_SOCKET` matches the path it printed. |
| `hdparm could not read /dev/sdX: permission denied.` | Same cause as above: a privilege failure, not a statement about the drive. |
| AppImage: `dlopen(): error loading libfuse.so.2` | Run it with `--appimage-extract-and-run`, or install FUSE 2 (`libfuse2` / `fuse-libs`). |
| Windows: SmartScreen blocks the installer | The installer is unsigned. **More info → Run anyway**. |
| macOS: *"Sanctum" cannot be opened* | Not notarized. Right-click → Open, or System Settings → Privacy & Security → Open Anyway. |

Next: the [user manual](docs/user-manual.md) walks through sanitizing a drive,
erasing files, recovering evidence and verifying a report.
