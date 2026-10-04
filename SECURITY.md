# Security policy

AEGIS handles evidence and performs destructive operations, so safety defects are treated as
security defects.

## Reporting a vulnerability

Please report privately through GitHub's **Security → Report a vulnerability** on this repository.
Do not open a public issue for:

- any path by which AEGIS could write to, or sanitize, an internal drive, the system disk or a device
  other than the one the operator authorized;
- any way to modify evidence, a ledger entry or a signed report without verification detecting it;
- disclosure of the report-signing key or its passphrase;
- a false `SUCCESS` (an operation reported as completed or verified when it was not).

Include the AEGIS version, Windows version, steps to reproduce and, where relevant, the engine log from
`<case>\AEGIS\logs`. Never attach real evidence or personal data.

## Scope

| In scope | Out of scope |
|---|---|
| The AEGIS module, engine, sanitizer and launcher in this repository | Vulnerabilities in upstream Autopsy, The Sleuth Kit, NetBeans, Java or Python themselves (report them upstream) |
| The packaged release built from this repository | Results on modified builds |

## Design references

- [Safety model](docs/safety-model.md): what AEGIS will and will not do to a device, and where each rule is enforced.
- [Architecture](docs/architecture.md): process boundary between the desktop and the engine.
