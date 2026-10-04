"""Entry point for ``python -m core.benchmark``."""

from __future__ import annotations

import sys

import structlog

from core.benchmark.cli import main

if __name__ == "__main__":
    # stdout carries the JSON the commands print; log lines go to stderr.
    structlog.configure(logger_factory=structlog.PrintLoggerFactory(file=sys.stderr))
    raise SystemExit(main())
