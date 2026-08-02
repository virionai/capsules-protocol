"""Ed25519 and X25519/HKDF/ChaCha20-Poly1305 wrappers around `cryptography`."""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .canonical import bytes_to_hex


@dataclass(frozen=True)
class Ed25519KeyPair:
    public_key: bytes  # 32 raw bytes
    private_key: bytes  # 32 raw bytes
    public_key_hex: str
    private_key_hex: str


def generate_ed25519() -> Ed25519KeyPair:
    sk = Ed25519PrivateKey.generate()
    priv_raw = sk.private_bytes_raw()
    pub_raw = sk.public_key().public_bytes_raw()
    return Ed25519KeyPair(
        public_key=pub_raw,
        private_key=priv_raw,
        public_key_hex=bytes_to_hex(pub_raw),
        private_key_hex=bytes_to_hex(priv_raw),
    )


def ed25519_sign(private_key_raw: bytes, message: bytes) -> bytes:
    if len(private_key_raw) != 32:
        raise ValueError("Ed25519 private key must be 32 bytes")
    sk = Ed25519PrivateKey.from_private_bytes(private_key_raw)
    return sk.sign(message)


# Ed25519 group/field constants used for pre-verification key and
# signature validation.
_ED25519_P = 2**255 - 19
_ED25519_L = 2**252 + 27742317777372353535851937790883648493

# The 8 points whose order divides 8, as canonical y encodings with the
# x-sign bit already cleared: the identity (y=1), the two order-4 points
# (y=0), the order-2 point (y=p-1), and the four order-8 points (two y
# values, two x signs each). Masking the sign bit means each entry covers
# both x signs.
_ED25519_SMALL_ORDER_Y = frozenset(
    {
        bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),
        bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000"),
        bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
        bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
        bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    }
)


def ed25519_public_key_is_acceptable(public_key_raw: bytes) -> bool:
    """True when a 32-byte Ed25519 public key is canonical and not small-order.

    OpenSSL (and therefore `cryptography`) accepts both non-canonical
    encodings (masked y >= p) and small-order keys. A small-order key is a
    no-private-key forgery: pick `edff…ff7f`, send a 64-byte all-zero
    signature, and vary any signed field until the cofactored verification
    equation happens to hold (~1 message in 4). We reject both classes
    before delegating.
    """
    if len(public_key_raw) != 32:
        return False
    masked = public_key_raw[:31] + bytes([public_key_raw[31] & 0x7F])
    if int.from_bytes(masked, "little") >= _ED25519_P:
        return False
    return masked not in _ED25519_SMALL_ORDER_Y


def ed25519_signature_s_is_reduced(signature: bytes) -> bool:
    """True when a 64-byte signature's S component is canonical (S < L).

    RFC 8032 §5.1.7 requires it; enforcing it here removes one source of
    signature malleability regardless of what the backend does.
    """
    if len(signature) != 64:
        return False
    return int.from_bytes(signature[32:], "little") < _ED25519_L


def ed25519_verify(public_key_raw: bytes, message: bytes, signature: bytes) -> bool:
    try:
        if len(signature) != 64:
            return False
        if not ed25519_public_key_is_acceptable(public_key_raw):
            return False
        if not ed25519_signature_s_is_reduced(signature):
            return False
        pk = Ed25519PublicKey.from_public_bytes(public_key_raw)
        pk.verify(signature, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# X25519 key agreement
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class X25519KeyPair:
    public_key: bytes  # 32 raw bytes
    private_key: bytes  # 32 raw bytes
    public_key_hex: str
    private_key_hex: str


def generate_x25519() -> X25519KeyPair:
    sk = X25519PrivateKey.generate()
    priv_raw = sk.private_bytes_raw()
    pub_raw = sk.public_key().public_bytes_raw()
    return X25519KeyPair(
        public_key=pub_raw,
        private_key=priv_raw,
        public_key_hex=bytes_to_hex(pub_raw),
        private_key_hex=bytes_to_hex(priv_raw),
    )


def x25519_dh(private_key_raw: bytes, peer_public_key_raw: bytes) -> bytes:
    if len(private_key_raw) != 32:
        raise ValueError("X25519 private key must be 32 bytes")
    if len(peer_public_key_raw) != 32:
        raise ValueError("X25519 peer public key must be 32 bytes")
    sk = X25519PrivateKey.from_private_bytes(private_key_raw)
    pk = X25519PublicKey.from_public_bytes(peer_public_key_raw)
    return sk.exchange(pk)


# ---------------------------------------------------------------------------
# HKDF-SHA256
# ---------------------------------------------------------------------------


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(ikm)


# ---------------------------------------------------------------------------
# ChaCha20-Poly1305
# ---------------------------------------------------------------------------


def chacha20_poly1305_encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("ChaCha20-Poly1305 key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("ChaCha20-Poly1305 nonce must be 12 bytes")
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad if aad else None)


def chacha20_poly1305_decrypt(
    key: bytes, nonce: bytes, aad: bytes, ciphertext_with_tag: bytes
) -> bytes:
    if len(key) != 32:
        raise ValueError("ChaCha20-Poly1305 key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("ChaCha20-Poly1305 nonce must be 12 bytes")
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext_with_tag, aad if aad else None)


# ---------------------------------------------------------------------------
# Random helpers
# ---------------------------------------------------------------------------


def random_key32() -> bytes:
    return os.urandom(32)


def random_nonce12() -> bytes:
    return os.urandom(12)
