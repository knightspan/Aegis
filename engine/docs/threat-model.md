# Threat model

What Sanctum defends against, how, where the defence lives in the code, and —
as prominently as the rest — what it does **not** defend against. Each row
names the test that holds the property, so a claim here can be checked by
running one file rather than by trusting this page.

## Assets

| Asset | Why it matters |
|---|---|
| Evidence images and source devices | Modifying them destroys their evidential value. |
| The hash-chained ledger and its blob store | The record of what was done; the audit trail a report is checked against. |
| The report signing key | Anyone holding it can sign a report that verifies. |
| Recovered artifacts | Derived from evidence; may contain personal data. |
| Target media for sanitization | A wrong-device wipe is irreversible. |
| The host itself | The API runs on a forensic workstation that holds all of the above. |

## Trust boundaries

```
browser ──HTTP, 127.0.0.1 only──► API (unprivileged) ──Unix socket, SO_PEERCRED──► helper (root)
                                     │                                               │
                                     ├─ reads evidence O_RDONLY                      ├─ raw device I/O
                                     ├─ writes: state dir only                       └─ writes: --state-dir only
                                     └─ ledger (append-only, hash-chained)
```

- **Browser → API.** No authentication, by design: the API binds `127.0.0.1`
  only (`api/main.py:LOOPBACK_HOST`). Anything that can open a loopback socket
  on this host can drive it. See *Local multi-user* below.
- **API → helper.** The helper authenticates each connection with
  `SO_PEERCRED` before reading a byte and admits only root and the operator uid
  fixed at start (`helper/daemon.py:_authenticate_peer`). Operations come from a
  static allowlist; no shell is spawned and no shell string is accepted.
- **Evidence → parsers.** Every byte read from an image is attacker-controlled.

## Threats and controls

### Untrusted forensic image parsing and malformed evidence

A seized disk is filled by an adversary. Every parser and decoder reads it.

- Structure parsers take an explicit `max_size` and return `None` rather than
  a fabricated length when a length field does not hold up
  (`core/carve/structure.py`). Tested in `tests/carve/signature/`.
- Validators convert every decoder failure into a verdict, never an exception
  into the carve job. The fuzz pass found one that did not — CPython's `wave`
  raises a bare `RuntimeError` on a lying chunk size — and it is fixed and held
  by `tests/carve/test_validate_malformed.py`.
- Validation has a wall-clock deadline and an in-memory byte budget
  (`core/carve/validate.py:DEADLINE_S`, `MAX_VALIDATE_BYTES`).
- A bounded fuzz pass is recorded in [`validation/fuzz.md`](validation/fuzz.md).
  **It is not a proof of absence of parser bugs.**

### Decompression bombs

- PDF streams are inflated under a byte bound and object-stream bombs are
  refused before open (commit `b5a439a`; `core/carve/pii.py`).
- GZIP/ZIP validation reads under the validation budget and deadline.
- Recovered images are **never decoded server-side** to make thumbnails; the
  browser renders them (`api/artifacts.py` docstring). Inline rendering is
  capped at `MAX_INLINE_BYTES`.

### Path traversal and symlink attacks

- Every client-supplied output path is resolved — following symlinks — and then
  tested for containment in a configured directory
  (`api/routes/common.py:resolve_output_path`). Tests:
  `tests/api/test_output_path_confinement.py`.
- The artifact endpoint accepts a root **name** from a closed set, refuses
  absolute names and `..` components, resolves symlinks before the containment
  test, and serves only regular files (`api/artifacts.py:resolve_artifact`).
  Tests: `tests/api/test_artifacts.py` (traversal, encoded traversal, absolute,
  escaping symlink, directory, unlisted root).
- Case ids become filenames and are whitelisted, not escaped
  (`core/cases.py:valid_case_id`); tested in `tests/api/test_cases.py`.
- The helper confines `ledger_root` and `dest` to its `--state-dir`, resolving
  symlinks first (`helper/daemon.py:_confine`).
- Spilled carve payloads are named by SHA-256 of `(source, offset)`, never by a
  name read from evidence (`api/carve_job.py:SpillStore`).

### Serving recovered content to a browser

- Content type comes from a closed extension table, never from sniffing;
  `X-Content-Type-Options: nosniff` is sent on every response.
- `text/html`, `image/svg+xml` and every other script-bearing type is served as
  `application/octet-stream` with `Content-Disposition: attachment`.
- Recovered PDFs always download; only reports this tool generated may render
  inline. CSP is `default-src 'self'` with `object-src 'none'`.
- Download filenames are reduced to a conservative character set, so a
  recovered name cannot inject a header.

### Privilege boundary

- Only the helper holds raw device access. The API never imports device or
  drive-erase modules directly (`docs/privilege-boundary.md`).
- Destructive gates — the one-use authorization and the typed serial — are
  re-checked inside the helper against the serial it re-reads, and a request
  that still carries a removed `dry_run`/`simulation` switch is refused there, so a stale or hostile client
  cannot authorise a wipe (`helper/daemon.py:_stream_run_erase`). Resume keeps
  both gates (`tests/api/test_resume.py`). A real erase also has its authorization
  re-checked by the helper against fresh reads at the write seam
  (`helper/authorization.py`, `tests/helper/test_write_seam_authorization.py`,
  `tests/api/test_write_seam_integration.py`; synthetic devices only).
- Devices with a mounted filesystem or holding the root filesystem are refused
  (`core/device/guard.py`).

### Operator identity spoofing

- The ledger `actor` is resolved server-side by the helper's `whoami`, from the
  uid it was started with. The request body cannot set it; a typed label is
  sanitised and recorded beside the identity, marked as a label
  (`api/identity.py`). Tests: `tests/api/test_operator_identity.py`.
- **Limit:** the identity is a local account, not a person. Every report says so.

### Report tampering

- Reports are Ed25519-signed over canonical JSON; the independent verifier runs
  five checks separately (`core/report/verify_report.py`).
- The chain records a `report.generated` entry with the report's SHA-256, and
  verification reports whether the file still matches it.
- **Limit:** an embedded public key proves integrity, not identity. The
  fingerprint must be compared against a value published out of band.

### Audit manipulation

- Entry N carries SHA-256 of entry N−1; the verifier names the first broken
  sequence, separates a crash (`INCOMPLETE_TAIL`) from tampering (`BROKEN`),
  and checks blobs. Tests: `tests/ledger/`.
- The UI has no endpoint that modifies the ledger. The tamper demonstration
  copies the chain to a scratch directory and alters only the copy; a test
  hashes the live tree before and after (`tests/api/test_tamper_demo.py`).
- **Limit — privileged insider:** someone with write access to the whole state
  directory can rebuild the chain from genesis and it will verify. Internal
  hashing cannot prevent this. Only an external anchor on media that person
  cannot rewrite does (`core/ledger/anchor.py`; no network anchor ships).

### Temporary artifact security

- Carve spill lives under the state directory's `work/`, in a per-run
  `mkdtemp` directory, removed in a `finally` that covers success, failure and
  cancellation (`tests/api/test_carve_spill.py`).
- Tamper-demo scratch copies are removed before the response is built.
- **Limit:** removal is `unlink`, not sanitization. On flash media the spilled
  bytes may persist physically. Put the state directory on an encrypted volume
  if recovered content is sensitive.

### Information disclosure through errors

- Anticipated errors return the remediation their author wrote. Unanticipated
  exceptions return an incident id only; the message and traceback are logged
  server-side (`api/main.py:_unhandled`). Test:
  `tests/api/test_endpoints.py::test_an_unanticipated_failure_returns_an_incident_id_and_not_the_message`.
- **Known residual:** several *anticipated* refusals still name host paths
  (e.g. the ledger root in a `LedgerChainBroken` message, the configured output
  directory in `OutputPathRefused`). These go to the local operator on
  loopback and are deliberate — the remediation needs the path — but a
  screen-shared demo will show them.

### Denial of service

- The API binds loopback only; there is no remote DoS surface.
- Progress buffers are bounded (`api/jobs.py:MAX_BUFFERED_PROGRESS`); artifact
  listings are bounded; request bodies are validated with field length limits.
- Carve memory is bounded to one object's bytes at a time (`SpillStore`).
- **Limit:** a local process can start many jobs; there is no per-client job
  quota.

### Local multi-user threat

- The helper admits only the configured operator uid and root.
- **Limit:** the API has no authentication. Any local account that can reach
  `127.0.0.1:8787` can drive it with the privileges of the account running the
  API, and through the helper with the operator's device authority. Run it on a
  single-user examination workstation, or restrict loopback access with host
  firewall rules. This is a deployment requirement, not something the code
  enforces.

## Out of scope

Network attackers (nothing listens beyond loopback), supply-chain compromise of
dependencies (pinned in `constraints.txt`, not audited), firmware that lies
about sanitization (the report says what the drive attested, and that the host
cannot measure a firmware erase of remapped blocks), and physical attacks on the
workstation.
