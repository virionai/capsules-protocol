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
        if abs(v) > _MAX_SAFE_INTEGER:
            raise ValueError(
                "JCS: integer outside IEEE-754 exact range (|n| > 2^53 - 1); "
                "not representable identically across implementations"
            )
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


_MAX_SAFE_INTEGER = 2**53 - 1


def _jcs_number(v: float) -> str:
    # RFC 8785 §3.2.2.3: serialize per ECMAScript Number::toString
    # (ECMA-262 §7.1.12.1). Python's repr() already yields the shortest
    # digit string that round-trips (same digits ECMAScript uses); the
    # work here is re-laying those digits out with ECMAScript's rules
    # for where plain decimal ends and scientific notation begins.
    if v == 0.0:
        return "0"  # covers -0.0: JCS serializes negative zero as "0"

    s = repr(v)
    negative = s.startswith("-")
    if negative:
        s = s[1:]

    if "e" in s:
        mantissa, _, exp_str = s.partition("e")
        exponent = int(exp_str)
    else:
        mantissa, exponent = s, 0
    int_part, _, frac_part = mantissa.partition(".")

    # digits = shortest significant digits; n such that value = 0.digits * 10^n
    stripped_int = int_part.lstrip("0")
    if stripped_int:
        n = len(stripped_int)
    else:
        n = -(len(frac_part) - len(frac_part.lstrip("0")))
    n += exponent
    digits = (int_part + frac_part).strip("0")
    k = len(digits)

    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        head = digits[0] + ("." + digits[1:] if k > 1 else "")
        out = f"{head}e{'+' if e >= 0 else '-'}{abs(e)}"

    return ("-" + out) if negative else out


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
