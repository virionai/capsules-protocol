"""Provenance envelope (plain only). Mirrors sdk/src/envelope.js minus encrypted paths."""

from __future__ import annotations

from .canonical import bytes_to_hex, concat_bytes, hex_to_bytes, jcs
from .crypto import ed25519_sign, ed25519_verify
from .versions import (
    CURRENT_VERSION,
    classify_version,
    provenance_domain,
    unsupported_version_message,
)

ENVELOPE_VERSION: str = CURRENT_VERSION
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
    """domain_sep_bytes || canonical_payload_bytes — the raw signing input.

    The domain embeds the envelope's DECLARED version
    (``capsule-provenance-v<version>:<role>\0``) — keyed selection per
    spec/versioning.md, so an older era's signatures stay verifiable
    under that era's domain forever. (Whether the declared version is
    one this verifier knows is gated earlier.)
    """
    if not isinstance(role, str) or len(role) == 0:
        raise ValueError("role must be a non-empty string")
    version = envelope.get("version")
    if not isinstance(version, str):
        version = CURRENT_VERSION
    return concat_bytes(provenance_domain(version, role), envelope_canonical_payload(envelope))


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
    # Any KNOWN version verifies under its own era's domain strings; an
    # unknown one fails closed with the standard distinguishable
    # diagnosis (spec/versioning.md), never a tamper-flavored failure.
    version_class = classify_version(envelope.get("version"))
    if version_class["status"] == "invalid":
        return {
            "ok": False,
            "signers": [],
            "note": f"unsupported envelope version: {envelope.get('version')}",
        }
    if version_class["status"] != "known":
        return {
            "ok": False,
            "signers": [],
            "note": unsupported_version_message(
                "envelope.version", envelope.get("version"), version_class["status"]
            ),
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

    # Duplicate (role, public_key) entries are malformed: counting rows
    # instead of distinct members lets one key satisfy an M-of-N policy.
    # Same key under different roles is permitted (distinct members).
    seen: set[tuple] = set()
    for s in signers:
        role = s.get("role") if isinstance(s, dict) else None
        key = s.get("public_key") if isinstance(s, dict) else None
        member = (role, key.lower() if isinstance(key, str) else key)
        if member in seen:
            return {
                "ok": False,
                "signers": [],
                "note": f"duplicate signer entry (role={role}, public_key={key})",
            }
        seen.add(member)

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
                # A signer row may not be an object at all (mirrors the
                # isinstance guard in the duplicate check above); report it
                # as an invalid row rather than raising out of verification.
                "role": s.get("role") if isinstance(s, dict) else None,
                "public_key": s.get("public_key") if isinstance(s, dict) else None,
                "valid": valid,
            }
        )
    return {"ok": all_valid, "signers": out}
