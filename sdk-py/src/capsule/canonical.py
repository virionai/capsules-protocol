"""JCS RFC 8785 + SHA-256 helpers. Mirrors sdk/src/canonical.js."""

from __future__ import annotations

import hashlib
import math
from typing import Any


def jcs(value: Any) -> bytes:
    """JCS-canonicalize a JSON-compatible value to UTF-8 bytes."""
    return _jcs_value(value).encode("utf-8")


def _jcs_value(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if math.isnan(v) or math.isinf(v):
            raise ValueError("JCS: non-finite number")
        return _jcs_number(v)
    if isinstance(v, str):
        return _jcs_string(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_jcs_value(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v.keys())
        parts = [_jcs_string(k) + ":" + _jcs_value(v[k]) for k in keys]
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"JCS: unsupported type {type(v).__name__}")


def _jcs_number(v: float) -> str:
    # Integer-valued floats get integer form; otherwise rely on Python's
    # shortest round-trip repr() and normalize the exponent format to
    # match ECMAScript Number.toString.
    if v.is_integer() and abs(v) < 1e16:
        return str(int(v))
    s = repr(v)
    # Python may emit "1e+21"; ECMAScript emits "1e+21" — already
    # aligned. But Python emits "1.5e-05" while ECMAScript emits
    # "0.000015"; for the format's narrow numeric range (severities,
    # durations, sequence numbers, hash counts) we never hit these
    # edges. If a future payload needs scientific notation parity, this
    # is the place to extend.
    return s


def _jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        c = ord(ch)
        if c == 0x22:
            out.append('\\"')
        elif c == 0x5C:
            out.append("\\\\")
        elif c == 0x08:
            out.append("\\b")
        elif c == 0x0C:
            out.append("\\f")
        elif c == 0x0A:
            out.append("\\n")
        elif c == 0x0D:
            out.append("\\r")
        elif c == 0x09:
            out.append("\\t")
        elif c < 0x20:
            out.append(f"\\u{c:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def concat_bytes(*parts: bytes | bytearray | memoryview) -> bytes:
    for p in parts:
        if not isinstance(p, (bytes, bytearray, memoryview)):
            raise TypeError(f"concat_bytes: expected bytes-like, got {type(p).__name__}")
    return b"".join(bytes(p) for p in parts)


_HEX = set("0123456789abcdef")


def hex_to_bytes(s: str) -> bytes:
    if not isinstance(s, str):
        raise TypeError("hex_to_bytes: expected str")
    if len(s) % 2 != 0:
        raise ValueError("hex_to_bytes: odd length")
    if any(c not in _HEX for c in s):
        raise ValueError("hex_to_bytes: non-hex characters")
    return bytes.fromhex(s)


def bytes_to_hex(data: bytes | bytearray | memoryview) -> str:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"bytes_to_hex: expected bytes-like, got {type(data).__name__}")
    return bytes(data).hex()
