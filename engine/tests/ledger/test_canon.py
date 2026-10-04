"""Deterministic serialisation. The regression anchor for the whole chain."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from core.ledger.canon import CANON_VERSION, canonical_bytes, canonical_json

# A fixed nested structure exercising every rule: empty key, key sorting by
# UTF-16 code unit, non-BMP-free unicode, nested objects inside arrays, null,
# bool, int, and an aware UTC datetime.
SAMPLE: dict[str, object] = {
    "zebra": 1,
    "alpha": {"nested": [1, 2, {"b": True, "a": None}]},
    "Ωmega": "unicode ✓",
    "digits": 10,
    "ts": datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC),
    "": "empty key",
    "aé": "e-acute",
}

# THE REGRESSION ANCHOR. Derived by hand from the JCS subset rules, not captured
# from a run. If a refactor changes this, the hash chain has changed meaning and
# every previously written ledger becomes unverifiable. Do not update it to make
# a test pass.
ANCHOR = (
    '{"":"empty key",'
    '"alpha":{"nested":[1,2,{"a":null,"b":true}]},'
    '"aé":"e-acute",'
    '"digits":10,'
    '"ts":"2026-01-02T03:04:05.123456Z",'
    '"zebra":1,'
    '"Ωmega":"unicode ✓"}'
).encode()


def test_canonical_bytes_match_the_hardcoded_anchor() -> None:
    assert canonical_bytes(SAMPLE) == ANCHOR


def test_canonical_bytes_are_stable_across_input_key_order() -> None:
    shuffled = dict(reversed(list(SAMPLE.items())))
    assert canonical_bytes(shuffled) == ANCHOR


def test_canonical_json_is_the_decoded_form() -> None:
    assert canonical_json(SAMPLE) == ANCHOR.decode("utf-8")


def test_no_insignificant_whitespace() -> None:
    out = canonical_bytes({"a": 1, "b": [1, 2]})
    assert out == b'{"a":1,"b":[1,2]}'


def test_keys_sort_by_utf16_code_unit_not_by_byte() -> None:
    out = canonical_json({"é": 1, "z": 2})
    assert out.index('"z"') < out.index('"é"')


def test_unicode_is_emitted_raw_not_escaped() -> None:
    assert "✓".encode() in canonical_bytes({"k": "✓"})


def test_control_characters_use_shortest_form_escapes() -> None:
    assert canonical_bytes({"k": "\n\t"}) == b'{"k":"\\n\\t\\u0001"}'


# --------------------------------------------------------------------------
# Rejections. Each names the offending key path.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("payload", "path"),
    [
        ({"a": 1.5}, "a"),
        ({"a": {"b": 0.1}}, "a.b"),
        ({"a": [0, {"b": [1, 2.0]}]}, "a[1].b[1]"),
        ({"pct": 99.9}, "pct"),
    ],
)
def test_float_is_rejected_with_its_key_path(
    payload: dict[str, object], path: str
) -> None:
    with pytest.raises(TypeError) as excinfo:
        canonical_bytes(payload)
    assert path in str(excinfo.value)
    assert "float" in str(excinfo.value).lower()


def test_nan_is_rejected() -> None:
    with pytest.raises(TypeError, match="rate"):
        canonical_bytes({"rate": float("nan")})


def test_infinity_is_rejected() -> None:
    with pytest.raises(TypeError, match="rate"):
        canonical_bytes({"rate": float("inf")})


def test_bool_is_not_treated_as_int() -> None:
    assert canonical_bytes({"a": True}) == b'{"a":true}'


@pytest.mark.parametrize(
    ("value", "label"),
    [
        (b"raw", "bytes"),
        ({1, 2}, "set"),
        ((1, 2), "tuple"),
        (object(), "object"),
    ],
)
def test_non_json_types_are_rejected_by_name(value: object, label: str) -> None:
    with pytest.raises(TypeError) as excinfo:
        canonical_bytes({"field": value})
    message = str(excinfo.value)
    assert "field" in message
    assert label in message.lower()


def test_non_string_keys_are_rejected() -> None:
    with pytest.raises(TypeError, match="key"):
        canonical_bytes({1: "x"})


# --------------------------------------------------------------------------
# datetime rules
# --------------------------------------------------------------------------


def test_naive_datetime_is_rejected_with_its_path() -> None:
    with pytest.raises(TypeError) as excinfo:
        canonical_bytes({"when": datetime(2026, 1, 1)})  # noqa: DTZ001
    assert "when" in str(excinfo.value)
    assert "timezone-aware" in str(excinfo.value)


def test_non_utc_datetime_is_rejected() -> None:
    ist = timezone(timedelta(hours=5, minutes=30))
    with pytest.raises(TypeError) as excinfo:
        canonical_bytes({"when": datetime(2026, 1, 1, tzinfo=ist)})
    assert "UTC" in str(excinfo.value)


def test_datetime_always_has_exactly_six_fractional_digits() -> None:
    out = canonical_json({"when": datetime(2026, 1, 1, tzinfo=UTC)})
    assert out == '{"when":"2026-01-01T00:00:00.000000Z"}'


def test_datetime_uses_a_literal_z_not_an_offset() -> None:
    out = canonical_json({"when": datetime(2026, 6, 1, 12, 0, 0, 1, tzinfo=UTC)})
    assert out.endswith('Z"}')
    assert "+00:00" not in out


# --------------------------------------------------------------------------
# Integer discipline
# --------------------------------------------------------------------------


def test_large_integers_survive_exactly() -> None:
    big = 2**63 + 12345
    assert canonical_bytes({"n": big}) == f'{{"n":{big}}}'.encode()


def test_negative_and_zero_integers() -> None:
    assert canonical_bytes({"a": -1, "b": 0}) == b'{"a":-1,"b":0}'


def test_canon_version_is_declared() -> None:
    assert isinstance(CANON_VERSION, str)
    assert CANON_VERSION
