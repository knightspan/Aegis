# Building AEGIS

AEGIS 1.0.0 is built and tested on Windows 10/11 x64. The build has four parts: the desktop (an Autopsy
4.23.1 suite with the AEGIS overlay and module), the engine runtime, the native sanitizer and launcher,
and the package that brings them together.

## Prerequisites

| Tool | Version used | Notes |
|---|---|---|
| JDK | Microsoft Build of OpenJDK **17**.0.20.1 x64 | Do not build with a newer default `java`; set `JAVA_HOME`/`JDK_HOME` explicitly |
| Apache Ant | 1.10.15 | |
| Node.js + npm | LTS | Required by the Autopsy build (MCP server component) |
| Git | any | |
| uv | any | Installs CPython 3.11 for the engine runtime |
| GCC (MinGW-w64) | WinLibs GCC 16 (UCRT, x86_64) | Sanitizer (C++20) and launcher. Install it in a path **without spaces**; the linker fails otherwise |
| Autopsy 4.23.1 64-bit MSI | official release | Source of the x64 Sleuth Kit JNI and its sibling DLLs (no Visual Studio needed) |
| Sleuth Kit | 4.15.0 source | Java bindings |

## 1. Desktop suite

```powershell
git clone https://github.com/knightspan/Aegis.git
git clone --branch autopsy-4.23.1 --depth 1 https://github.com/sleuthkit/autopsy.git autopsy
powershell -ExecutionPolicy Bypass -File Aegis\tools\apply-autopsy-overlay.ps1 -Autopsy autopsy
```

`apply-autopsy-overlay.ps1` copies `desktop/autopsy-overlay` over the checkout (the 47 files listed in
`OVERLAY_FILES.txt`), and adds the AEGIS module as `autopsy\AegisSanitization`, the branding as
`autopsy\branding` and the launcher source as `autopsy\launcher`.

### Sleuth Kit Java bindings (64-bit)

The official Sleuth Kit Windows zip is 32-bit and cannot load in a 64-bit JVM. Instead of compiling
`libtsk_jni.dll`, take the x64 JNI and its siblings (`libtsk_jni.dll`, `libewf.dll`, `zlib.dll`,
`libvmdk.dll`, `libvhdi.dll`, `libcrypto-1_1-x64.dll`, `libssl-1_1-x64.dll` and the VC runtime DLLs)
from the official Autopsy 4.23.1 64-bit MSI and place them in `%TSK_HOME%\win32\x64\Release`. Then:

```bat
set JAVA_HOME=C:\tools\jdk-17.0.20.1+1
set JDK_HOME=%JAVA_HOME%
set TSK_HOME=C:\src\sleuthkit-4.15.0
set PATH=%JAVA_HOME%\bin;C:\tools\apache-ant-1.10.15\bin;C:\mingw64\bin;%PATH%
cd /d %TSK_HOME%\bindings\java
ant dist
```

Check that `sleuthkit-4.15.0.jar` contains class version 61 and `NATIVELIBS/amd64/win/libtsk_jni.dll`
(PE machine `0x8664`), and copy it to `autopsy\Core\release\modules\ext\`.

### Build and run

Use `cmd.exe` so Ant's dotted properties are not split by PowerShell:

```bat
cd /d C:\src\autopsy
ant
ant run
```

For module-only iterations (much faster):

```bat
cd /d C:\src\autopsy\AegisSanitization
ant -q clean netbeans
```

Always **clean**-build the module: an incremental build once kept stale anonymous inner classes and
failed at run time with `NoSuchMethodError`.

### Portable suite archive

```bat
ant -Ddist.dir=C:\aegis-dist -Dnbdist.dir=C:\aegis-dist build-zip
```

This produces `autopsy.zip` and the folder `autopsy-4.23.1` (the NetBeans branding token is `autopsy`).
The staging step below renames it to `AEGIS` and installs the AEGIS launcher.

## 2. Engine runtime

The engine runs on a private CPython 3.11 with the engine's locked dependencies:

```powershell
uv python install 3.11
# copy the uv-managed CPython 3.11 folder to <work>\engine-runtime\python311, then:
uv pip install --python <work>\engine-runtime\python311\python.exe --break-system-packages `
    -r Aegis\engine\constraints.txt opencv-contrib-python-headless==4.12.0.88
powershell -ExecutionPolicy Bypass -File Aegis\tools\fetch-models.ps1
```

`fetch-models.ps1` downloads the EDSR models into `engine\models` and verifies their pinned SHA-256.

**E01 writing.** The PyPI `libewf-python` wheel for Windows reads E01 but cannot write it. AEGIS writes
E01 through the write-capable libewf that Autopsy ships (`ewfexport_exec\64-bit`: `libewf.dll`,
`zlib.dll`, `vcruntime140.dll`), loaded with ctypes (`engine/core/carve/ewf_ctypes.py`). Copy those three
DLLs to `<work>\engine-runtime\libewf`.

## 3. Native sanitizer and launcher

```powershell
cd Aegis\sanitizer
$env:AEGIS_CXX = "C:\mingw64\bin\g++.exe"
powershell -ExecutionPolicy Bypass -File build.ps1      # aegis_cli.exe + engine_tests.exe
.\engine_tests.exe                                       # "all engine tests passed"

cd ..\desktop\launcher
windres aegis_launcher.rc -O coff -o aegis_launcher.res.o
g++ -O2 -mwindows -static -s aegis_launcher.cpp aegis_launcher.res.o -o AEGIS.exe -lshell32
```

## 4. Stage the package

`tools/stage-aegis-package.ps1` assembles the distributable folder from the build outputs and refuses
to finish if any staged file differs from its build output:

```powershell
powershell -ExecutionPolicy Bypass -File tools\stage-aegis-package.ps1 -Dist C:\aegis-dist [-Zip]
```

It:

1. renames `autopsy-4.23.1` to `AEGIS` (first run) and refuses to run while AEGIS is running;
2. installs the clean module jar, the sanitizer and its MinGW runtime DLLs;
3. mirrors the engine source, runtime and libewf into `AEGIS\aegis-engine`;
4. mirrors the JDK into `AEGIS\jre`; creates `bin\aegis64.exe` (the platform launcher with the AEGIS
   icon, via `tools/set-exe-icon.py`) with `etc\aegis.conf` / `etc\aegis.clusters`, and installs `AEGIS.exe`;
5. builds and installs the branding jars (`tools/build-aegis-branding.py`): splash, window title, and
   every UI string that named the upstream product;
6. moves upstream top-level readme files under `third-party\autopsy` (licence files are kept);
7. touches `autopsy\.lastModified` so existing profiles drop NetBeans' class cache;
8. hashes every staged file against its build output and writes `AEGIS_BUILD_MANIFEST.txt`;
9. with `-Zip`, writes `AEGIS-final.zip`.

The scripts in `tools/` assume the build workspace layout used for AEGIS 1.0.0 (`working\autopsy`,
`working\engine-runtime`, `external\aegis variant`); adjust the paths at the top of each script for a
different layout.

## 5. Build the installer

The Windows installer is built with [Inno Setup 6](https://jrsoftware.org/isinfo.php) from the staged,
hash-verified folder:

```powershell
& "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe" /DSourceDir=C:\aegis-dist\AEGIS /DOutputDir=C:\aegis-installer installer\aegis.iss
```

`installer/aegis.iss` produces `AEGIS-1.0.0-Setup.exe`, which:

- installs machine-wide to `Program Files\AEGIS` (administrator) or, if chosen in the first dialog or with
  `/CURRENTUSER`, for the current user only — no administrator rights needed;
- shows the AEGIS licence, creates Start-menu shortcuts **AEGIS** and **AEGIS (Administrator)** (the
  latter marked *Run as administrator* for raw device access) and an optional desktop shortcut;
- precompiles the engine's Python bytecode at install time, because `Program Files` is read-only for
  standard users;
- registers a standard uninstaller that removes the program but **keeps** `%APPDATA%\AEGIS` (profile and
  report-signing key) and every case folder.

Silent install: `AEGIS-1.0.0-Setup.exe /VERYSILENT /SUPPRESSMSGBOXES [/CURRENTUSER] [/DIR="D:\Apps\AEGIS"]`.

## Package layout

```
AEGIS\
  AEGIS.exe                       launcher (bundled jre, %APPDATA%\AEGIS profile)
  bin\aegis64.exe                 NetBeans platform launcher (etc\aegis.conf)
  jre\                            Java 17
  autopsy\modules\org-sleuthkit-autopsy-aegis.jar
  autopsy\bin\aegis_cli.exe       native file/folder sanitizer
  autopsy\{core,modules}\locale\  AEGIS branding jars
  aegis-engine\
    engine\aegis_engine_cli.py    process bridge (JSON lines)
    engine\core, api, ...         engine source
    engine\models\EDSR_x*.pb
    runtime\python311\            CPython 3.11 + dependencies
    runtime\libewf\               E01 writer DLLs
  AEGIS_BUILD_MANIFEST.txt
  THIRD_PARTY_NOTICES.md
  third-party\autopsy\            upstream readme and licence
```

## Rebuilding the GitHub export

The repository is exported from the build workspace with `tools/export-github-repo.py <repo dir>`. It
copies sources only (no binaries, caches, test results, evidence images or models) and regenerates
`desktop/autopsy-overlay` by comparing the workspace's Autopsy tree with pristine Autopsy 4.23.1.
