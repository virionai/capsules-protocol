"""Capsule v0.6 reference Python SDK.

Mirrors the JS reference at sdk/src/. v0.1 supports plain capsules end
to end; encrypted capsules raise EncryptedCapsulesNotSupportedError.
"""

from .builder import CapsuleBuilder
from .canonical import (
    bytes_to_hex,
    concat_bytes,
    hex_to_bytes,
    jcs,
    sha256,
    sha256_hex,
)
from .chain import (
    build_chain_events,
    events_from_jsonl,
    events_to_jsonl,
    first_and_entry_hash,
    hash_event,
    verify_chain,
)
from .crypto import (
    Ed25519KeyPair,
    X25519KeyPair,
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
    ed25519_sign,
    ed25519_verify,
    generate_ed25519,
    generate_x25519,
    hkdf_sha256,
    random_key32,
    random_nonce12,
    x25519_dh,
)
from .envelope import (
    EncryptedCapsulesNotSupportedError,
    build_envelope,
    envelope_canonical_payload,
    envelope_signing_input,
    sign_envelope,
    verify_envelope_signatures,
)
from .manifest import (
    CONTENT_INDEX_EXCLUDED,
    STRUCTURAL_EXCLUDED,
    build_content_index,
    build_manifest,
    compute_capsule_id,
    content_index_exclusions,
    manifest_bytes,
    manifest_hash,
)
from .pith import PITH_VERSION, compress_event_payload, compress_text
from .reader import CapsuleReader, MalformedCapsuleError
from .verifier import verify_capsule
from .zip_io import UnsafeZipPathError, pack_zip, unpack_zip

__version__ = "0.6.0"
SPEC_VERSION = "0.6"

__all__ = [
    "CONTENT_INDEX_EXCLUDED",
    "STRUCTURAL_EXCLUDED",
    "PITH_VERSION",
    "SPEC_VERSION",
    "CapsuleBuilder",
    "CapsuleReader",
    "Ed25519KeyPair",
    "EncryptedCapsulesNotSupportedError",
    "MalformedCapsuleError",
    "UnsafeZipPathError",
    "X25519KeyPair",
    "__version__",
    "build_chain_events",
    "build_content_index",
    "content_index_exclusions",
    "build_envelope",
    "build_manifest",
    "bytes_to_hex",
    "chacha20_poly1305_decrypt",
    "chacha20_poly1305_encrypt",
    "compress_event_payload",
    "compress_text",
    "compute_capsule_id",
    "concat_bytes",
    "ed25519_sign",
    "ed25519_verify",
    "envelope_canonical_payload",
    "envelope_signing_input",
    "events_from_jsonl",
    "events_to_jsonl",
    "first_and_entry_hash",
    "generate_ed25519",
    "generate_x25519",
    "hash_event",
    "hex_to_bytes",
    "hkdf_sha256",
    "jcs",
    "manifest_bytes",
    "manifest_hash",
    "pack_zip",
    "random_key32",
    "random_nonce12",
    "sha256",
    "sha256_hex",
    "sign_envelope",
    "unpack_zip",
    "verify_capsule",
    "verify_chain",
    "verify_envelope_signatures",
    "x25519_dh",
]
