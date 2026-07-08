import pytest

from capsule.canonical import (
    bytes_to_hex,
    concat_bytes,
    hex_to_bytes,
    jcs,
    sha256,
    sha256_hex,
)


def test_jcs_basic_object_sorts_keys():
    assert jcs({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_jcs_nested_sorts_at_every_level():
    obj = {"z": 1, "a": {"y": 2, "b": 3}}
    assert jcs(obj) == b'{"a":{"b":3,"y":2},"z":1}'


def test_jcs_empty_object_and_array():
    assert jcs({}) == b"{}"
    assert jcs([]) == b"[]"


def test_jcs_null_and_booleans():
    assert jcs(None) == b"null"
    assert jcs(True) == b"true"
    assert jcs(False) == b"false"


def test_jcs_integers():
    assert jcs(0) == b"0"
    assert jcs(-1) == b"-1"
    assert jcs(123) == b"123"


def test_jcs_string_escapes():
    assert jcs("hello") == b'"hello"'
    assert jcs('he said "hi"') == b'"he said \\"hi\\""'
    assert jcs("a\nb") == b'"a\\nb"'
    assert jcs("\x01") == b'"\\u0001"'


def test_jcs_unicode_passthrough():
    # Non-ASCII passes through verbatim per JCS (no \u escaping required).
    assert jcs("héllo") == '"héllo"'.encode()


def test_jcs_rejects_non_finite_numbers():
    with pytest.raises(ValueError):
        jcs(float("nan"))
    with pytest.raises(ValueError):
        jcs(float("inf"))


def test_jcs_array_preserves_order():
    assert jcs([3, 1, 2]) == b"[3,1,2]"


def test_sha256_known_vector():
    # SHA-256 of empty bytes: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    h = sha256_hex(b"")
    assert h == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_sha256_returns_32_bytes():
    h = sha256(b"hello")
    assert isinstance(h, bytes)
    assert len(h) == 32


def test_hex_roundtrip():
    raw = bytes(range(256))
    assert hex_to_bytes(bytes_to_hex(raw)) == raw


def test_hex_to_bytes_rejects_odd_length():
    with pytest.raises(ValueError):
        hex_to_bytes("abc")


def test_hex_to_bytes_rejects_non_hex():
    with pytest.raises(ValueError):
        hex_to_bytes("zzzz")


def test_hex_to_bytes_lowercase_only():
    # Spec is lowercase-hex consistently; reader-side leniency happens
    # at parse time, not here.
    assert hex_to_bytes("00ff") == b"\x00\xff"


def test_concat_bytes_two_pieces():
    assert concat_bytes(b"ab", b"cd") == b"abcd"


def test_concat_bytes_no_pieces():
    assert concat_bytes() == b""


def test_concat_bytes_three_pieces():
    assert concat_bytes(b"ab", b"cd", b"ef") == b"abcdef"


def test_concat_bytes_rejects_non_bytes_like():
    with pytest.raises(TypeError):
        concat_bytes(b"ab", "cd")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        concat_bytes(b"ab", 123)  # type: ignore[arg-type]


def test_bytes_to_hex_rejects_non_bytes_like():
    with pytest.raises(TypeError):
        bytes_to_hex("hello")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        bytes_to_hex([0, 1, 2])  # type: ignore[arg-type]


def test_bytes_to_hex_accepts_bytearray_and_memoryview():
    assert bytes_to_hex(bytearray(b"\x00\xff")) == "00ff"
    assert bytes_to_hex(memoryview(b"\x00\xff")) == "00ff"


def test_jcs_rejects_integers_beyond_ieee_exact_range():
    assert jcs(2**53 - 1) == b"9007199254740991"
    with pytest.raises(ValueError):
        jcs(2**53 + 1)
    with pytest.raises(ValueError):
        jcs(-(2**53) - 1)


def test_jcs_number_layout_matches_ecmascript():
    # Exponent-notation thresholds and layout, per ECMA-262 7.1.12.1.
    assert jcs(0.000015) == b"0.000015"
    assert jcs(-0.0) == b"0"
    assert jcs(1e21) == b"1e+21"
    assert jcs(1e-7) == b"1e-7"
    assert jcs(1e-6) == b"0.000001"
    assert jcs(5e-324) == b"5e-324"
    assert jcs(100.0) == b"100"


def test_jcs_numbers_match_spec_vectors():
    import json
    import struct
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "spec" / "vectors" / "jcs-numbers.json"
    doc = json.loads(path.read_text())
    vectors = doc["vectors"]
    assert vectors, "vector file is empty"
    for entry in vectors:
        value = struct.unpack(">d", bytes.fromhex(entry["ieee_hex"]))[0]
        got = jcs(value).decode("utf-8")
        assert got == entry["expected"], f"bits {entry['ieee_hex']}"
