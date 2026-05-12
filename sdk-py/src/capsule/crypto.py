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


def ed25519_verify(public_key_raw: bytes, message: bytes, signature: bytes) -> bool:
    try:
        if len(public_key_raw) != 32:
            return False
        if len(signature) != 64:
            return False
        # Reject the all-zeros public key. Python's `cryptography` library
        # spuriously verifies all-zero pubkey + all-zero signature — an
        # Ed25519 low-order-point quirk that RFC 8032 strict mode catches
        # but the lib does not. This guard closes that path and matches
        # the JS reference's behavior. Full low-order-point hardening
        # (rejecting all 8 known small-subgroup points) is v0.2 work.
        if public_key_raw == b"\x00" * 32:
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
