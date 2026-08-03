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


# Curve tags (finding A04). Ed25519 (signing) and X25519 (key agreement)
# keypair objects are structurally identical, and the two key types are
# indistinguishable from their bytes (any X25519 public key also parses
# as an Ed25519 point). X25519 clamps and accepts any 32-byte
# u-coordinate, so encrypting to an Ed25519 public key "succeeds" and
# produces content the Ed25519 holder can never decrypt — a data-loss
# bug that surfaces only at decryption time, potentially years later.
# Seal-time round-trip verification cannot catch it (the sealer has no
# recipient private key). The generators therefore tag every keypair
# object with its curve, and the normalizers below enforce the tag on
# the object path. Raw hex and raw bytes stay untagged and accepted:
# a caller who extracts bytes is asserting the curve themselves.


def _assert_curve_tag(obj: Any, expected: str, name: str) -> None:
    """Raise when an object carries a curve tag other than ``expected``."""
    curve = _field(obj, "curve")
    if curve is not None and curve != expected:
        raise ValueError(
            f"{name} is tagged curve '{curve}' but must be an {expected} key: "
            "Ed25519 signs, X25519 encrypts — the two are not interchangeable"
        )


def to_signer(signer: Any, index: int = 0) -> dict:
    """Normalize one signer.

    Accepts the ``Ed25519KeyPair`` returned by ``generate_ed25519()``
    (role defaults to "originator") or a dict of
    ``{"role"?, "public_key", "private_key"}`` with keys as hex strings
    or bytes. Returns ``{"role", "public_key": bytes, "private_key": bytes}``.

    An object tagged with a non-Ed25519 curve (e.g. an ``X25519KeyPair``)
    is rejected. Untagged dicts stay accepted: a cross-curve mistake on
    the signing side fails loudly at first verification (the stored
    public key does not match the signature), unlike the silent
    recipient-side hazard.
    """
    if signer is None or isinstance(signer, (str, bytes, bytearray, memoryview)):
        raise ValueError(
            f"signers[{index}] must be a keypair or dict with public_key and private_key"
        )
    _assert_curve_tag(signer, "ed25519", f"signers[{index}]")
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

    The keypair-object path is the branded path, and it is the ONLY
    object path for keypair-shaped input: an object carrying private key
    material must be tagged ``curve="x25519"`` (an Ed25519 tag, or no
    tag at all, is rejected — the untagged shape is indistinguishable
    from the Ed25519 hazard). Public-key-only objects, hex, and raw
    bytes stay accepted untagged; those forms carry no evidence of curve
    either way and are the caller's assertion.
    """
    if not isinstance(recipient, (str, bytes, bytearray, memoryview)) and recipient is not None:
        _assert_curve_tag(recipient, "x25519", f"recipients[{index}]")
        has_private = _field(recipient, "private_key", "private_key_hex") is not None
        if has_private and _field(recipient, "curve") is None:
            raise ValueError(
                f"recipients[{index}] is a keypair object without a curve tag: cannot tell "
                "X25519 from Ed25519 key material by shape. Pass a generate_x25519() keypair "
                '(curve="x25519"), or just its public_key (hex or 32 bytes)'
            )
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
