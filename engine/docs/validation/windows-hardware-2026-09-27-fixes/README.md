# Windows physical-hardware validation, post-fix — 2026-09-27

Supersedes [`../windows-hardware-2026-09-27/`](../windows-hardware-2026-09-27/README.md)
for everything it covers, and extends it. That earlier record is **preserved
unchanged as history**: it documents commit `2d00526`, which turned out to
crash on a genuine no-console launch. This record documents the same machine,
the same physical stick (`SANCTUMREC`, untouched, still not opened for
writing or raw reading), after two fixes landed:

- `ba66fbe` — the desktop-launcher crash (see below)
- `437081e` — the carve engine's signature table was never bundled into any
  packaged build (found *while validating* `ba66fbe`; see below)

**Final commit validated here: `437081ed8d740771bc77fd535fea97938ccd0d2e`**
(clean; `core/platform/build_info.json` in the build carries this exact
string, no `+dirty` suffix). `SanctumSetup.exe` SHA-256
`8e3ed9e6c6299cd30c23b496393ac2f438463e201cdb5a004a58791017936f4a`; installed
`Sanctum.exe` SHA-256
`3d4bc66327800a2b3afd2078be719a33522cfde01905e6c7980f8ccffc55cdea`.

## 1. The bug this run exists to catch: a genuine no-console launch

`scripts/package_smoke.py` redirects the child process's `stdout`/`stderr` to
a real log file (`subprocess.Popen(..., stdout=log, stderr=STDOUT)`). Every
packaged-checks claim in this repository before today — "22/22", "23/23",
"24/24" — was produced that way. None of them can catch a bug that only
exists when `sys.stdout`/`sys.stderr` are `None`, because in that harness
they never are.

This run launched the installed exe the way `Start-Process` does — no
console, no redirected stdio, an isolated `SANCTUM_STATE_DIR`, and (only to
retrieve the session token without touching stdio) `SANCTUM_URL_FILE`, an
existing, sanctioned launch mode documented in `api/desktop.py` for exactly
this purpose:

| Check | Result |
|---|---|
| Process starts, does not crash | PASS — no `TypeError`, no traceback |
| Loopback server binds | PASS — real socket, port discovered independently |
| `/health` without the session cookie | 401 |
| Session link accepted | 200 |
| `/health` with the cookie | 200, `build.commit` = `437081ed8d740771bc77fd535fea97938ccd0d2e` |
| `launcher.log` created in the isolated state directory | PASS — real structlog lines, e.g. `api_services_ready`, `api_ready` |
| `POST /app/quit` (with cookie) | accepted; connection reset on shutdown (documented as the expected shutdown signature) |
| Process exits after quit | PASS — confirmed gone from the process list |

This is a **mechanism-level distinction from a literal double-click**: no
human clicked an icon. It is not a distinction that matters to the bug —
`sys.stdout`/`sys.stderr` are `None` for exactly the same reason
(`console=False`, no console attached) regardless of whether a human or
`Start-Process` triggered the launch. An untouched `Start-Process` run (no
env vars, no way to retrieve the token) was also done as a first pass and
showed the same result: alive after 4 s, a real listening socket, no crash.

## 2. macOS genuine no-console launch: NOT VALIDATED — no Mac hardware available

This session runs on a single physical Windows 11 machine. There is no macOS
hardware here, and none was used at any point in this project's history
(`docs/validation/hardware-platform-matrix.md` has always said so). This gap
is **not closed by this record** and must not be represented as closed.

What *is* true, and is not the same thing: the crash mechanism
(`sys.stdout`/`sys.stderr` are `None` under a windowed frozen build) is
Python-level and platform-independent once a stream is `None` — the *cause*
differs by OS (`console=False` applies identically to macOS in
`packaging/sanctum.spec`), but the code path that crashed and the fix that
repairs it (`api/desktop.py:_ensure_logging_has_somewhere_to_write`,
`api/desktop.py:main`) are shared, unconditional, cross-platform code, not
behind a `sys.platform` branch. `tests/platform/test_boundary_and_security.py`
now carries an explicit, parametrized regression test forcing `sys.stdout`,
`sys.stderr`, and both together to `None` directly (three cases), proving the
fix holds for every combination a frozen Windows *or* macOS process can
actually present — but it is a unit test, not a macOS GUI launch, and its
docstring says so.

## 3. Windows package regression — non-destructive, no device opened

`scripts/package_smoke.py` against the reinstalled `437081e` build:
[`package-smoke-windows.json`](package-smoke-windows.json), **23 of 23 PASS**,
`build.commit` = `437081ed8d740771bc77fd535fea97938ccd0d2e`. Unchanged from
the pre-fix run in shape (`package_smoke.py` does not exercise `/jobs/carve`,
`/jobs/record-destroy`, or media map — see §4).

## 4. What package_smoke.py does not cover, checked separately

[`package_regression_extra.py`](package_regression_extra.py) (reuses
`package_smoke.py`'s own `Client` and launch pattern; full output:
[`package-regression-extra.json`](package-regression-extra.json)), against
the same installed `437081e` exe, in its own scratch directory, no device
opened:

| Item | Result |
|---|---|
| Build identity | `commit` = `437081ed8d740771bc77fd535fea97938ccd0d2e` |
| Trace Sweep (explicit `sweep_traces: true`) | ran for real: searched this machine's actual `C:\$Recycle.Bin` and `Recent shortcuts` path, found nothing (correct — the erased file was never in either), and reported both what was searched and what was not, matching `core/erase/traces.py`'s "the enumeration is the deliverable" design |
| Acquire (read-only, synthetic image, never a device) | `complete` |
| Carve, `media_map: true` | `complete`, 0 errors — **this failed before `437081e`** with `EvidenceIntegrityError: signature table not found: ...\_internal\testkit\signatures.yaml`; see §5 |
| Candidates recovered | 5 of 6 planted objects (the 6th is a duplicate that correctly deduplicates to the first — the same ground-truth image `scripts/demo_fragmented.py` uses) |
| Media map present in the carve result | yes |
| Destroy attestation (`POST /jobs/record-destroy`, metadata only, no device) | `complete` |
| Destroy certificate issued and verified | both true (also re-confirms the reportlab/QR-symbology fix: a build missing it answers every certificate request with a 500, per `docs/validation/package-2026-09-25/README.md`) |
| `helper`/`api` identity and authorization | exercised implicitly by every job above — `resolve_identity` runs on every submission; no authorization error on any of them |
| Clean quit | `POST /app/quit` accepted, process exited |

**Not covered here, and not claimed:** a rendered-UI/browser pass (Playwright
was not run this session — no dev-tooling regression to report, just not
attempted); whole-drive Clear/Purge on Windows (UNSUPPORTED by design,
unchanged); raw physical-device acquisition on Windows (NOT IMPLEMENTED,
unchanged, see `docs/validation/windows-hardware-2026-09-27/README.md` §4).

## 5. The defect this validation pass found: M3 carving was broken in every packaged build

While validating `ba66fbe` end to end (not while writing tests — while
actually running `/jobs/carve` through the installed exe for the first time
ever), carving failed:

```
EvidenceIntegrityError: signature table not found:
C:\Users\...\Programs\Sanctum\_internal\testkit\signatures.yaml
```

`core/carve/signature.py:SIGNATURE_DB_PATH` is computed from `__file__`:
correct in source (repo root) and in every dev/CI run, and in every prior
"M3 carving: SYNTHETIC VALIDATION" claim, all of which ran
`scripts/demo_fragmented.py` directly against the source tree — never wrong,
because `testkit/signatures.yaml` really is there in source. Wrong only in
the frozen app, where `testkit` is (correctly, in general) excluded from the
PyInstaller bundle, and the carve engine's own data file happened to live
inside it. `package_smoke.py` has never called `/jobs/carve`, on any
platform, in this project's history, so no prior "22/22"/"23/23"/"24/24"
packaged-checks claim — Windows, Linux, or macOS — actually proves carving
works in the shipped package. Fixed in `437081e` by bundling the one data
file; see that commit and `tests/test_packaging_spec.py` for the regression
guard. §4 above is the first time `/jobs/carve` has been run through any
installed package and shown to work.

**This changes the honest scope of every prior "M3 carving" claim across this
project's docs**, including today's own earlier `windows-hardware-2026-09-27`
record (§1 of that file ran `demo_fragmented.py` directly, in-process, from
the dev venv — never through the packaged exe, so it never could have caught
this). The claim was never "the packaged app carves"; it was "the carving
engine carves", which remains true and unaffected. Nothing about the earlier
record was wrong — its scope was simply narrower than this one.

## 6. What is still not validated

- macOS: no physical launch, no physical package validation, of any kind, on
  any commit. See §2.
- Windows raw physical-device acquisition: not implemented (unchanged).
- Windows whole-drive Clear/Purge: UNSUPPORTED by design (unchanged).
- A rendered-UI/browser regression pass on this build (not attempted this
  session; `ui_bundled: true` was confirmed, rendering was not).
- ~~CI (`platform-ci`) has not been run against `ba66fbe` or `437081e`~~ —
  now run, on branch `fix/no-console-and-carve-packaging`, commit `1ed3dca`:
  all 7 jobs green on Linux, Windows and macOS, including packaged carving
  (11/11, all three platforms) and a genuine no-console launch (Windows and
  macOS). See
  [`../platform-ci-2026-09-27/`](../platform-ci-2026-09-27/README.md). That
  branch was not merged to `main`.
