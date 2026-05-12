"""Provenance envelope (plain only). Mirrors sdk/src/envelope.js minus encrypted paths."""

from __future__ import annotations

from .canonical import bytes_to_hex, concat_bytes, hex_to_bytes, jcs
from .crypto import ed25519_sign, ed25519_verify

ENVELOPE_VERSION: str = "0.6"
_SUPPORTED_CIPHERS = {"none", "ChaCha20-Poly1305"}


class EncryptedCapsulesNotSupportedError(NotImplementedError):
    """Encryption is v0.2 in the Python SDK; raised when a caller asks for it."""


def build_envelope(
    *,
    capsule_id: str,
    first_event_hash: str,
    entry_hash: str,
    manifest_hash: str,
    content_index_hash: str,
    encrypted_blob_hash: str | None,
    cipher: str = "none",
    signed_at: str,
) -> dict:
    if cipher not in _SUPPORTED_CIPHERS:
        raise ValueError(f"unsupported cipher: {cipher}")
    if cipher == "none" and encrypted_blob_hash is not None:
        raise ValueError("plain capsule must have encrypted_blob_hash=None")
    if cipher != "none":
        if not isinstance(encrypted_blob_hash, str) or len(encrypted_blob_hash) != 64:
            raise ValueError("encrypted capsule requires encrypted_blob_hash (64-hex)")
    return {
        "version": ENVELOPE_VERSION,
        "capsule_id": capsule_id,
        "first_event_hash": first_event_hash,
        "entry_hash": entry_hash,
        "manifest_hash": manifest_hash,
        "content_index_hash": content_index_hash,
        "encrypted_blob_hash": encrypted_blob_hash,
        "cipher": cipher,
        "signed_at": signed_at,
        "signers": [],
    }


def envelope_canonical_payload(envelope: dict) -> bytes:
    """JCS-canonical bytes of envelope minus the signers field."""
    rest = {k: v for k, v in envelope.items() if k != "signers"}
    return jcs(rest)


def envelope_signing_input(envelope: dict, role: str) -> bytes:
    """domain_sep_bytes || canonical_payload_bytes — the raw signing input."""
    if not isinstance(role, str) or len(role) == 0:
        raise ValueError("role must be a non-empty string")
    domain = f"capsule-provenance-v{ENVELOPE_VERSION}:{role}\x00".encode()
    return concat_bytes(domain, envelope_canonical_payload(envelope))


def sign_envelope(envelope: dict, signers: list[dict]) -> dict:
    """Sign and append signers in-place.

    signers: [{"role": str, "public_key": bytes32, "private_key": bytes32}]
    """
    if envelope["signers"]:
        raise ValueError("envelope already has signers")
    for s in signers:
        role = s.get("role")
        priv = s.get("private_key")
        pub = s.get("public_key")
        if not role:
            raise ValueError("signer requires role")
        if not isinstance(priv, (bytes, bytearray)) or len(priv) != 32:
            raise ValueError("signer requires 32-byte private_key")
        if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
            raise ValueError("signer requires 32-byte public_key")
        message = envelope_signing_input(envelope, role)
        sig = ed25519_sign(bytes(priv), message)
        envelope["signers"].append(
            {
                "role": role,
                "public_key": bytes_to_hex(pub),
                "signature": bytes_to_hex(sig),
            }
        )
    return envelope


def verify_envelope_signatures(envelope: dict) -> dict:
    """Verify envelope signatures only (no manifest/chain cross-check).

    Returns {"ok": bool, "signers": [{"role", "public_key", "valid"}], ...}.
    """
    if envelope.get("version") != ENVELOPE_VERSION:
        return {
            "ok": False,
            "signers": [],
            "note": f"unsupported envelope version: {envelope.get('version')}",
        }
    cipher = envelope.get("cipher")
    if cipher not in _SUPPORTED_CIPHERS:
        return {
            "ok": False,
            "signers": [],
            "note": f"unsupported cipher: {cipher}",
        }
    signers = envelope.get("signers")
    if not isinstance(signers, list) or len(signers) == 0:
        return {"ok": False, "signers": [], "note": "envelope has no signers"}

    out = []
    all_valid = True
    for s in signers:
        valid = False
        try:
            message = envelope_signing_input(envelope, s["role"])
            pub = hex_to_bytes(s["public_key"])
            sig = hex_to_bytes(s["signature"])
            valid = ed25519_verify(pub, message, sig)
        except (KeyError, ValueError, TypeError):
            valid = False
        if not valid:
            all_valid = False
        out.append(
            {
                "role": s.get("role"),
                "public_key": s.get("public_key"),
                "valid": valid,
            }
        )
    return {"ok": all_valid, "signers": out}
