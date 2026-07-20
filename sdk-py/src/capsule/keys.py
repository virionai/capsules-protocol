"""Key-input normalization for the public API surface. Mirrors sdk-js/src/keys.js.

Protocol wire format is strict: lowercase 64-hex everywhere. The API
boundary is forgiving: every place that takes a key accepts either 32
raw bytes or a hex string (any case), including the keypair objects
returned by ``generate_ed25519()`` / ``generate_x25519()``, so callers
never have to know which representation an internal layer wants.
Normalization happens here, once, at the boundary.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from .canonical import bytes_to_hex

KeyLike = str | bytes | bytearray | memoryview

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def to_raw_key(value: Any, name: str, length: int = 32) -> bytes:
    """Normalize a key to raw bytes. Accepts bytes-like or a hex string."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if len(raw) != length:
            raise ValueError(f"{name} must be {length} bytes, got {len(raw)}")
        return raw
    if isinstance(value, str):
        if len(value) != length * 2 or not _HEX_RE.match(value):
            raise ValueError(f"{name} must be a {length * 2}-char hex string or {length} raw bytes")
        return bytes.fromhex(value.lower())
    raise ValueError(f"{name} must be a hex string or bytes, got {type(value).__name__}")


def to_key_hex(value: Any, name: str, length: int = 32) -> str:
    """Normalize a key to lowercase hex. Accepts bytes-like or a hex string."""
    return bytes_to_hex(to_raw_key(value, name, length))


def _field(obj: Any, *names: str) -> Any:
    """Read the first present field from a dict or attribute-style object."""
    for n in names:
        if isinstance(obj, dict):
            if obj.get(n) is not None:
                return obj[n]
        else:
            value = getattr(obj, n, None)
            if value is not None:
                return value
    return None


def to_signer(signer: Any, index: int = 0) -> dict:
    """Normalize one signer.

    Accepts the ``Ed25519KeyPair`` returned by ``generate_ed25519()``
    (role defaults to "originator") or a dict of
    ``{"role"?, "public_key", "private_key"}`` with keys as hex strings
    or bytes. Returns ``{"role", "public_key": bytes, "private_key": bytes}``.
    """
    if signer is None or isinstance(signer, (str, bytes, bytearray, memoryview)):
        raise ValueError(
            f"signers[{index}] must be a keypair or dict with public_key and private_key"
        )
    role = _field(signer, "role") or "originator"
    if not isinstance(role, str) or not role:
        raise ValueError(f"signers[{index}].role must be a non-empty string")
    pub = _field(signer, "public_key", "public_key_hex")
    priv = _field(signer, "private_key", "private_key_hex")
    if pub is None or priv is None:
        raise ValueError(f"signers[{index}] requires public_key and private_key (hex or 32 bytes)")
    return {
        "role": role,
        "public_key": to_raw_key(pub, f"signers[{index}].public_key"),
        "private_key": to_raw_key(priv, f"signers[{index}].private_key"),
    }


def to_recipient(recipient: Any, index: int = 0) -> bytes:
    """Normalize one encryption recipient to its raw 32-byte X25519 public key.

    Accepts a hex string, raw bytes, a dict with ``public_key``, or the
    ``X25519KeyPair`` returned by ``generate_x25519()``.
    """
    value = (
        recipient
        if isinstance(recipient, (str, bytes, bytearray, memoryview))
        else _field(recipient, "public_key", "public_key_hex")
    )
    if value is None:
        raise ValueError(f"recipients[{index}] requires a public_key (hex or 32 bytes)")
    return to_raw_key(value, f"recipients[{index}].public_key")


def now_iso() -> str:
    """Current UTC time as an ISO 8601 string with second precision."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
