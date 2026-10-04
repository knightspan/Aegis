# Feature run, 2026-09-25: media map, trace sweep, Record of Destruction

> **Current state (2026-09-28).** Current product execution no longer exposes
> a user-facing simulation/dry-run mode: every operation runs against the
> selected real device once its gates pass, and a request that asks for a
> rehearsal is refused. References below to a dry run or a simulation record
> what the build of that date did; they are historical evidence and are kept as
> run.

**Repeated 2026-09-26 at `76dde42`** (the release-hold remediation), on a fresh
sandboxed server and the UI bundle packaged at that commit: 19 of 19, no assertion changed.
The pinned screenshots here were not regenerated. See
[`../remediation-2026-09-25/`](../remediation-2026-09-25/README.md).

The three features added on 2026-09-25, driven through the real UI and the real API
in Chromium (headless shell, revision 1243, Playwright 1.63.0 from a separate venv)
at commit **`e21f88d`** (the sidebar in each screenshot shows the build).
`results.json` holds **19 checks: 19 pass**, with no console error and no page error.

**Population: SYNTHETIC.** Everything was created by `drivers/seed.py` inside the
state directory. The server ran in a bubblewrap sandbox with no `/sys`, no block
device in `/dev`, no udev database and no removable-media mount, with the state
directory mounted at `/cases` and a synthetic home at `/home/examiner`
(`drivers/sandboxed-server.sh`). No physical device was enumerated, opened or
written, and no real home directory was read.

| Screenshot | What it shows |
|---|---|
| `01-recovery-media-map.png` | A 32 MiB image mapped before carving: zeroed, text, high-entropy, 0xFF and 0xA5 fill regions where the seed put them, and ticks for the four sector-aligned JPEG headers |
| `02-file-eraser-traces-dry-run.png` | A dry run of a folder erase finds seven traces - two thumbnails named by the MD5 of each file's URI, three recent-files entries, a Trash copy and its `.trashinfo` - each with its evidence, and removes none |
| `03-file-eraser-traces-removed.png` | The real erase: all seven removed. The checks read the synthetic home afterwards: thumbnails gone, the recent list keeps only its unrelated entry, the Trash is empty |
| `04-file-erase-certificate.png` | The file-erasure certificate, with the *Desktop traces* line: 7 found, 7 removed |
| `05-destroy-record-form.png` | The Record a physical destruction form, prefilled from a detected (synthetic) device |
| `06-destroy-record-signed.png` | Recorded in the chain as *attested, not observed*, and signed |
| `07-record-of-destruction.png` | The Record of Destruction: attested and recorded dates kept apart, *Observed by this tool: no* |

What this does **not** show: a trace sweep of a real desktop session (the GTK, KDE,
Windows and macOS formats are built from their specifications in the tests, not
captured from a live system), and any physical destruction - the record is what
people attest, which is exactly what it says.

Reproduce, from the repository root:

```sh
python docs/validation/features-2026-09-25/drivers/seed.py STATE          # project venv
SANCTUM_KEY_PASSPHRASE=… bash docs/validation/features-2026-09-25/drivers/sandboxed-server.sh STATE 8812
SANCTUM_BROWSER_EXE=… python docs/validation/features-2026-09-25/drivers/features.py STATE OUT   # Playwright venv
```

`seed.py` needs `PYTHONPATH=.`; `features.py` also needs `pdftoppm` to render the
certificates.
