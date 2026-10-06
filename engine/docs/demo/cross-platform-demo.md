# Cross-platform demo

The point to land: **one sanitization platform, not three applications.** The
same screens, the same capability model and the same certificate on every OS;
what differs is what each OS can honestly do, and the app says so itself.

Use only designated disposable media. Never demonstrate on a disk that holds
data, and never on the laptop's own disk except to show the refusal.

Every state named below is the resolver's word, as the app shows it. The
authoritative per-platform table is the generated
[`capability-matrix.md`](../validation/capability-completion-2026-09-28/capability-matrix.md);
what changed on 2026-09-28 is in
[`capability-completion-2026-09-28/README.md`](../validation/capability-completion-2026-09-28/README.md).
**SUPPORTED** means a physical run of that capability on that device class is
recorded; **IMPLEMENTED / UNVALIDATED** means the code runs and has only been
tested synthetically or against adapter doubles. Say which one is on screen.
Only the Linux section below writes to a device, and only to the disposable
test stick; the Windows and macOS sections stop at refusals and the approval
gate. There is no dry-run mode to show instead.

## Linux (the full engine) — about 3 minutes

1. Launch `Sanctum-<ver>-x86_64.AppImage` (helper running as in
   `docs/packaging.md` for whole-drive work).
2. **Platform** screen: Linux, privilege *Privileged helper*, the build's commit,
   whole-drive clear **SUPPORTED** for `usb-flash` only (the 2026-09-05 run on
   one USB stick) with the flash limit, device sanitize **DEVICE-DEPENDENT**
   (the tools and the per-device probe exist; no firmware sanitize has been
   recorded on a physical drive), each row with its source. Point at *How to
   read a state* and *Not proven on hardware, or not available*, then at a filesystem row:
   detect ≠ support.
3. **Devices**: the laptop's own disk is locked — *holds the running root
   filesystem*. Select the designated USB stick.
4. **Sanitization**: the step tracker; *Ready to sanitize*; the three answers
   (device, what will happen, can it be verified); the flash limitation; Purge
   listed under *Unavailable, and why* (the USB bridge blocks pass-through) -
   no silent downgrade.
5. *Review plan* → the **REAL DEVICE** card → *Erase this device* → backup image
   → acknowledge and type the serial → *Approve* → type the serial again →
   *Erase*.
6. Watch progress; verification result; *Get certificate*; verify it on the
   **Audit** screen.

## Windows — about 2 minutes

(What CI already proves, so nothing here is a rehearsal of an untried path:
the installer builds, installs silently, the installed app discovers both of
the runner's disks and refuses both — boot disk, page file — erases a scratch
folder and issues a certificate that verifies.)

1. Run `SanctumSetup.exe` (no administrator prompt), open Sanctum from Start.
2. **Platform**: Windows 11, *Standard user*. Discovery **SUPPORTED** for
   `usb-flash` and file erase **SUPPORTED** for the host disk (both physical
   runs of 2026-09-27); whole-drive clear, raw acquisition and restore
   **IMPLEMENTED / UNVALIDATED** (never run on a physical disk); ATA SANITIZE
   and NVMe Sanitize **DEVICE-DEPENDENT**; ATA SECURITY ERASE UNIT **NOT
   IMPLEMENTED** and NVMe Format **PLATFORM-LIMITED**, each with its reason;
   free-space wipe **NOT IMPLEMENTED**. Say that the implemented rows are not
   physically validated; that is the design working.
3. **Devices**: the USB stick with size, bus and device class; the internal
   disk locked as the boot/system disk with the Windows reasons (IsBoot,
   system volume, page file).
4. Select the stick → whole-drive clear reads **REQUIRES PRIVILEGE** (*Run as
   administrator*) as a standard user, and a mounted stick is **BLOCKED FOR
   SAFETY** until it is taken offline. Show the *Prepare* panel: it lists the
   volumes it would take offline and waits for the typed serial. Do not type
   it, and do not run an erase on stage.
5. **File eraser**: erase a scratch folder on the stick → per-file results,
   the NTFS residual findings → *Get certificate*.

## macOS — about 2 minutes

(Also proven in CI on macOS 14 arm64: the DMG mounts, the app runs, the
internal disk is refused because the running system boots from an APFS
container on it, a folder erase completes and its certificate verifies.)

1. Open `Sanctum.dmg`, drag to Applications, open (right-click > Open: the
   build is unsigned and not notarized - say so).
2. **Platform**: macOS, APFS rows showing erase *Runs, not verifiable*
   (copy-on-write). Whole-drive clear and raw acquisition of external disks
   **IMPLEMENTED / UNVALIDATED** (no macOS physical run is recorded);
   ATA/NVMe sanitize, crypto erase and HPA/DCO **PLATFORM-LIMITED** (macOS
   exposes no pass-through); free-space wipe **NOT IMPLEMENTED**.
3. **Devices**: the internal SSD locked - *the running macOS boots from an
   APFS container on this disk*; internal Apple storage is never raw-written
   or imaged, and Apple's own path is named (*Erase All Content and
   Settings*). The stick listed.
4. Stick → whole-drive clear reads **REQUIRES PRIVILEGE** until Sanctum itself
   is started with `sudo`, and **BLOCKED FOR SAFETY** while a volume is mounted.
   Show the *Prepare* panel and its volume list only; do not type the serial.
   No write on stage.
5. **File eraser** on the stick; certificate.

## The close

Put the three **Platform** screens side by side: same layout, same statuses,
different answers - every one of them traced to a probe or to a recorded
physical run. "A platform that honestly says *implemented, not validated on
this kind of device* is a stronger forensic product than one that shows a
green check and performs an unverified wipe."
