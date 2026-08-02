"""CapsuleReader — plain capsule. Mirrors sdk/src/reader.js (plain branch)."""

from __future__ import annotations

import json
import re

from .canonical import bytes_to_hex, hex_to_bytes, jcs
from .chain import events_from_jsonl
from .crypto import chacha20_poly1305_decrypt, hkdf_sha256, x25519_dh
from .envelope import EncryptedCapsulesNotSupportedError
from .keys import _field, to_raw_key
from .zip_io import unpack_zip


class MalformedCapsuleError(ValueError):
    pass


_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _is_hex64(value) -> bool:
    return isinstance(value, str) and _HEX64.match(value) is not None


def _validate_manifest_shape(manifest) -> None:
    """Shape check on manifest.json. Mirrors sdk-js reader.js.

    Full integrity is the verifier's job; this catches obvious
    malformation at the parse boundary so a caller that reads
    ``reader.manifest()["id"]`` without verifying can rely on the field
    being 64-char lowercase hex per spec, and so ``verify_capsule``
    stays a total function over whatever the reader hands back.
    """
    if not isinstance(manifest, dict):
        raise MalformedCapsuleError("manifest.json is not a JSON object")
    fmt = manifest.get("format")
    version = fmt.get("version") if isinstance(fmt, dict) else None
    if version != "0.6":
        raise MalformedCapsuleError(f"manifest.format.version: expected '0.6', got {version!r}")
    if not _is_hex64(manifest.get("id")):
        raise MalformedCapsuleError(
            f"manifest.id is not a 64-char lowercase hex string: {manifest.get('id')!r}"
        )
    originator = manifest.get("originator")
    if not isinstance(originator, dict) or not _is_hex64(originator.get("public_key")):
        raise MalformedCapsuleError(
            "manifest.originator.public_key must be a 64-char lowercase hex string"
        )
    if not _is_hex64(manifest.get("first_event_hash")):
        raise MalformedCapsuleError(
            "manifest.first_event_hash must be a 64-char lowercase hex string"
        )
    _validate_content_index_shape(manifest.get("content_index"))


def _validate_content_index_shape(index) -> None:
    if not isinstance(index, dict):
        raise MalformedCapsuleError("manifest.content_index must be a JSON object")
    if not _is_hex64(index.get("index_hash")):
        raise MalformedCapsuleError(
            "manifest.content_index.index_hash must be a 64-char lowercase hex string"
        )
    files = index.get("files")
    if not isinstance(files, list):
        raise MalformedCapsuleError("manifest.content_index.files must be an array")
    for i, f in enumerate(files):
        if not isinstance(f, dict):
            raise MalformedCapsuleError(f"manifest.content_index.files[{i}] must be a JSON object")
        path = f.get("path")
        if not isinstance(path, str) or not path:
            raise MalformedCapsuleError(
                f"manifest.content_index.files[{i}].path must be a non-empty string"
            )
        if not _is_hex64(f.get("sha256")):
            raise MalformedCapsuleError(
                f"manifest.content_index.files[{i}].sha256 must be a 64-char lowercase hex string"
            )


def _validate_envelope_shape(envelope) -> None:
    """Shape check on provenance/envelope.json. Mirrors sdk-js reader.js."""
    if not isinstance(envelope, dict):
        raise MalformedCapsuleError("envelope.json is not a JSON object")
    if envelope.get("version") != "0.6":
        raise MalformedCapsuleError(
            f"envelope.version: expected '0.6', got {envelope.get('version')!r}"
        )
    if not _is_hex64(envelope.get("capsule_id")):
        raise MalformedCapsuleError("envelope.capsule_id must be a 64-char lowercase hex string")
    signers = envelope.get("signers")
    if not isinstance(signers, list) or not signers:
        raise MalformedCapsuleError("envelope.signers must be a non-empty array")


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
        _validate_manifest_shape(manifest)
        _validate_envelope_shape(envelope)
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
        try:
            inner_manifest = json.loads(inner_files["manifest.json"].decode("utf-8"))
            inner_envelope = json.loads(inner_files["provenance/envelope.json"].decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise MalformedCapsuleError(f"decrypted manifest/envelope parse: {e}") from e
        _validate_manifest_shape(inner_manifest)
        _validate_envelope_shape(inner_envelope)
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
