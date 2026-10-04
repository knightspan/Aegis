"""Deterministic serialisation for everything that gets hashed.

A hash chain is only as trustworthy as the bytes it hashes. If the same logical
payload can serialise two ways - a different key order, a float that prints
differently on another CPU, a timestamp with a variable number of fractional
digits - then a chain written today fails to verify tomorrow and the tool has
accused an innocent operator of tampering.

This module implements the subset of RFC 8785 (JSON Canonicalization Scheme)
that Sanctum needs, plus two deliberate restrictions RFC 8785 does not impose:

* **No floats, anywhere.** RFC 8785 specifies ECMAScript number formatting for
  doubles, which is well-defined but still means a value like ``0.1`` depends on
  binary64 rounding to round-trip. Ledgered payloads carry durations as integer
  nanoseconds and percentages as integer basis points instead. A float raises,
  naming the key path that holds it.
* **Timestamps are RFC3339 UTC with exactly six fractional digits and a literal
  ``Z``.** ``datetime.isoformat`` drops the fractional part when microseconds
  are zero and emits ``+00:00`` rather than ``Z``, so two timestamps one
  microsecond apart would serialise with different shapes.

Pydantic's ``model_dump_json`` is deliberately not used: its output is tied to a
pydantic version, and a patch release changing whitespace or float formatting
would silently invalidate every ledger ever written. Dump to a dict, then
canonicalise here.

The regression anchor for this format lives in
``tests/ledger/test_canon.py::ANCHOR``. It is a hand-derived literal. If a
change makes that test fail, the change altered what a hash means.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

__all__ = ["CANON_VERSION", "canonical_bytes", "canonical_json", "to_canonical"]

#: Bumped only for a breaking change to the byte format. Recorded in the ledger
#: genesis entry and in every signature, so a verifier knows which rules applied.
CANON_VERSION = "sanctum-jcs-1"

_JSON_SEPARATORS = (",", ":")


def _path_str(path: tuple[str, ...]) -> str:
    return "".join(path).lstrip(".") or "<root>"


def _reject(path: tuple[str, ...], reason: str) -> TypeError:
    return TypeError(f"{_path_str(path)}: {reason}")


def _canonical_datetime(value: datetime, path: tuple[str, ...]) -> str:
    if value.tzinfo is None:
        raise _reject(
            path,
            "naive datetime is not ledgerable; it must be timezone-aware UTC",
        )
    offset = value.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise _reject(
            path,
            f"datetime must be UTC, got offset {offset}. Convert with "
            "astimezone(timezone.utc) before ledgering",
        )
    utc = value.astimezone(UTC)
    return (
        f"{utc.year:04d}-{utc.month:02d}-{utc.day:02d}"
        f"T{utc.hour:02d}:{utc.minute:02d}:{utc.second:02d}"
        f".{utc.microsecond:06d}Z"
    )


def _utf16_sort_key(key: str) -> bytes:
    """Sort key giving UTF-16 code-unit order, as RFC 8785 requires.

    Python sorts strings by code point. For astral characters the two differ:
    as UTF-16 they are surrogate pairs beginning ``0xD800``, which order below
    ``U+E000..U+FFFF``. Encoding to UTF-16 big-endian and comparing bytes gives
    the specified order for every input.
    """
    return key.encode("utf-16-be")


def to_canonical(value: Any, path: tuple[str, ...] = ()) -> Any:
    """Validate ``value`` and return a JSON-ready structure in canonical order.

    Raises:
        TypeError: The value contains a float, a NaN, a non-UTC or naive
            datetime, a non-string mapping key, or any non-JSON type. The
            message names the key path.
    """
    # bool first: isinstance(True, int) is True, and true/false must not become 1/0.
    if value is None or isinstance(value, bool):
        return value

    if isinstance(value, int):
        return value

    if isinstance(value, float):
        if math.isnan(value):
            raise _reject(path, "NaN is not representable in canonical JSON")
        if math.isinf(value):
            raise _reject(path, "Infinity is not representable in canonical JSON")
        raise _reject(
            path,
            f"float values are not ledgerable (got {value!r}). Use integer "
            "nanoseconds for durations and integer basis points for percentages",
        )

    if isinstance(value, str):
        return value

    if isinstance(value, datetime):
        return _canonical_datetime(value, path)

    if isinstance(value, Mapping):
        items: list[tuple[str, Any]] = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise _reject(
                    path,
                    f"mapping key {key!r} is a {type(key).__name__}; canonical "
                    "JSON requires string keys",
                )
            items.append((key, item))
        items.sort(key=lambda pair: _utf16_sort_key(pair[0]))
        return {
            key: to_canonical(item, (*path, f".{key}")) for key, item in items
        }

    if isinstance(value, list):
        return [
            to_canonical(item, (*path, f"[{index}]"))
            for index, item in enumerate(value)
        ]

    if isinstance(value, (bytes, bytearray, memoryview)):
        raise _reject(
            path,
            f"{type(value).__name__} is not JSON; encode it as a hex or base64 "
            "string before ledgering",
        )

    if isinstance(value, (set, frozenset)):
        raise _reject(
            path,
            f"{type(value).__name__} has no defined order; convert it to a "
            "sorted list before ledgering",
        )

    if isinstance(value, tuple):
        raise _reject(
            path,
            "tuple is not JSON; convert it to a list before ledgering",
        )

    if isinstance(value, Sequence):
        raise _reject(path, f"{type(value).__name__} is not a JSON array")

    raise _reject(path, f"{type(value).__name__} is not a JSON type")


def canonical_json(value: Any) -> str:
    """Canonical JSON text for ``value``."""
    return json.dumps(
        to_canonical(value),
        ensure_ascii=False,
        separators=_JSON_SEPARATORS,
        allow_nan=False,
        sort_keys=False,
        check_circular=True,
    )


def canonical_bytes(value: Any) -> bytes:
    """Canonical UTF-8 bytes for ``value``. This is what gets hashed and signed."""
    return canonical_json(value).encode("utf-8")
