"""``sanctum`` command line interface.

Output here is read aloud in front of people who did not write this code, so it
is plain text, one line per check, PASS or FAIL first, and no jargon that needs
the source to decode.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer

from core.report.verify_report import ReportVerification, verify_report_file

__all__ = ["app", "main"]

app = typer.Typer(
    add_completion=False,
    help="Sanctum Forensics command line tools.",
    no_args_is_help=True,
)


@app.callback()
def _root() -> None:
    """Sanctum Forensics.

    Present so Typer keeps sub-command dispatch even while only one command is
    registered; without it ``verify-report`` would be parsed as an argument.
    """


def _render(result: ReportVerification, path: Path) -> None:
    typer.echo(f"Report: {path}")
    if result.fingerprint:
        typer.echo(f"Signed by fingerprint: {result.fingerprint}")
    typer.echo("")
    for check in result.checks:
        if not check.applicable:
            status = "SKIP"
        elif check.passed:
            status = "PASS"
        else:
            status = "FAIL"
        typer.echo(f"[{status}] {check.name.value}: {check.detail}")
    typer.echo("")
    typer.echo(f"Result: {'PASS' if result.ok else 'FAIL'}")
    typer.echo(f"Verdict: {result.verdict.value}")
    for reason in result.verdict_reasons:
        typer.echo(f"  - {reason}")
    typer.echo("")
    typer.echo(f"Note: {result.caveat}")


@app.command("verify-report")
def verify_report_command(
    # B008 is suppressed here: calling typer.Argument/typer.Option in the
    # default is how Typer declares CLI metadata, not an accidental shared
    # mutable default.
    path: Path = typer.Argument(  # noqa: B008
        ..., help="Path to a .forensic.json report."
    ),
    ledger_root: Path = typer.Option(  # noqa: B008
        None,
        "--ledger-root",
        help="Ledger store directory, to check the genesis key and blobs.",
    ),
) -> None:
    """Verify a signed forensic report. Exits 0 only if every check passes."""
    if not path.exists():
        typer.echo(f"[FAIL] report not found: {path}")
        raise typer.Exit(code=2)
    try:
        result = verify_report_file(path, ledger_root=ledger_root)
    except json.JSONDecodeError as exc:
        typer.echo(f"[FAIL] {path} is not valid JSON: {exc}")
        raise typer.Exit(code=2) from exc

    _render(result, path)
    raise typer.Exit(code=0 if result.ok else 1)


def main() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":
    sys.exit(app())
