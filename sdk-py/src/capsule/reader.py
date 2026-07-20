"""CapsuleReader — plain capsule. Mirrors sdk/src/reader.js (plain branch)."""

from __future__ import annotations

import json

from .canonical import bytes_to_hex, hex_to_bytes, jcs
from .chain import events_from_jsonl
from .crypto import chacha20_poly1305_decrypt, hkdf_sha256, x25519_dh
from .envelope import EncryptedCapsulesNotSupportedError
from .keys import _field, to_raw_key
from .zip_io import unpack_zip


class MalformedCapsuleError(ValueError):
    pass


class CapsuleReader:
    def __init__(self, files: dict[str, bytes], manifest: dict, envelope: dict) -> None:
        self._files = files
        self._manifest = manifest
        self._envelope = envelope

    @classmethod
    def from_bytes(cls, data: bytes) -> CapsuleReader:
        files = unpack_zip(data)
        if "manifest.json" not in files:
            raise MalformedCapsuleError("missing manifest.json")
        if "provenance/envelope.json" not in files:
            raise MalformedCapsuleError("missing provenance/envelope.json")
        try:
            manifest = json.loads(files["manifest.json"].decode("utf-8"))
            envelope = json.loads(files["provenance/envelope.json"].decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise MalformedCapsuleError(f"manifest/envelope parse: {e}") from e
        return cls(files, manifest, envelope)

    def manifest(self) -> dict:
        return self._manifest

    def envelope(self) -> dict:
        return self._envelope

    def files(self) -> dict[str, bytes]:
        return self._files

    def is_encrypted(self) -> bool:
        if isinstance(self._manifest.get("encryption"), dict):
            return True
        if self._envelope.get("cipher") not in (None, "none"):
            return True
        return "content.enc" in self._files

    def encrypted_blob_bytes(self) -> bytes:
        blob = self._files.get("content.enc")
        if blob is None:
            raise MalformedCapsuleError("missing content.enc")
        return blob

    def decryption_metadata(self) -> dict | None:
        if not self.is_encrypted():
            return None
        path = (
            self._manifest.get("encryption", {}).get("metadata_path")
            if isinstance(self._manifest.get("encryption"), dict)
            else None
        ) or "skills/decryption/decryption.json"
        raw = self._files.get(path)
        if raw is None:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise MalformedCapsuleError(f"decryption metadata parse: {e}") from e

    def decrypt(
        self,
        keypair=None,
        *,
        recipient_public_key=None,
        recipient_private_key=None,
    ) -> CapsuleReader:
        """Decrypt the inner capsule.

        Accepts the ``X25519KeyPair`` returned by ``generate_x25519()``
        as a single positional argument, or explicit
        ``recipient_public_key`` / ``recipient_private_key`` keywords.
        Keys may be hex strings or 32 raw bytes. The public key selects
        the matching recipient bundle.
        """
        if not self.is_encrypted():
            raise ValueError("capsule is not encrypted")
        if keypair is not None:
            recipient_public_key = recipient_public_key or _field(
                keypair, "public_key", "public_key_hex"
            )
            recipient_private_key = recipient_private_key or _field(
                keypair, "private_key", "private_key_hex"
            )
        if recipient_public_key is None or recipient_private_key is None:
            raise ValueError(
                "decrypt requires the recipient keypair: pass generate_x25519()'s keypair or "
                "recipient_public_key + recipient_private_key (hex or 32 bytes)"
            )
        recipient_public_key = to_raw_key(recipient_public_key, "recipient_public_key")
        recipient_private_key = to_raw_key(recipient_private_key, "recipient_private_key")

        meta = self.decryption_metadata()
        if meta is None:
            raise MalformedCapsuleError("missing decryption metadata")
        if meta.get("cipher") != "ChaCha20-Poly1305":
            raise ValueError(f"unsupported cipher: {meta.get('cipher')}")

        recipient_pub_hex = bytes_to_hex(recipient_public_key)
        bundle = next(
            (
                b
                for b in (meta.get("key_bundles") or [])
                if b.get("recipient_public_key") == recipient_pub_hex
            ),
            None,
        )
        if bundle is None:
            raise ValueError("no matching recipient bundle")

        eph_pub = hex_to_bytes(bundle["ephemeral_public_key"])
        wrap_nonce = hex_to_bytes(bundle["wrap_nonce"])
        wrapped_key = hex_to_bytes(bundle["wrapped_key"])

        shared = x25519_dh(bytes(recipient_private_key), eph_pub)
        wrap_key = hkdf_sha256(
            ikm=shared,
            salt=bytes(recipient_public_key),
            info=b"capsule-key-wrap-v0.6",
            length=32,
        )
        content_key = chacha20_poly1305_decrypt(wrap_key, wrap_nonce, b"", wrapped_key)

        aad = jcs(
            {
                "version": "0.6",
                "capsule_id": self._envelope["capsule_id"],
                "first_event_hash": self._envelope["first_event_hash"],
                "originator_public_key": self._manifest["originator"]["public_key"],
                "cipher": "ChaCha20-Poly1305",
            }
        )
        content_nonce = hex_to_bytes(meta["content_nonce"])
        content_enc = self.encrypted_blob_bytes()
        inner_zip_bytes = chacha20_poly1305_decrypt(content_key, content_nonce, aad, content_enc)

        inner_files = unpack_zip(inner_zip_bytes)
        if "manifest.json" not in inner_files or "provenance/envelope.json" not in inner_files:
            raise MalformedCapsuleError("decrypted inner capsule missing manifest or envelope")
        inner_manifest = json.loads(inner_files["manifest.json"].decode("utf-8"))
        inner_envelope = json.loads(inner_files["provenance/envelope.json"].decode("utf-8"))
        return CapsuleReader(inner_files, inner_manifest, inner_envelope)

    def _require_plain(self) -> None:
        if self.is_encrypted():
            raise EncryptedCapsulesNotSupportedError(
                "this Python SDK reads plain capsules only (encrypted: v0.2)"
            )

    def events(self) -> list[dict]:
        self._require_plain()
        raw = self._files.get("chain/events.jsonl")
        if raw is None:
            raise MalformedCapsuleError("missing chain/events.jsonl")
        return events_from_jsonl(raw)

    def program(self) -> str:
        self._require_plain()
        raw = self._files.get("program.md")
        if raw is None:
            raise MalformedCapsuleError("missing program.md")
        return raw.decode("utf-8")

    def agents_md(self) -> str | None:
        if self.is_encrypted():
            return None
        raw = self._files.get("agents.md")
        return raw.decode("utf-8") if raw is not None else None
