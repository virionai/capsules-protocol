"""Capsule v0.7 reference Python SDK.

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
    ACTOR_NAMESPACES,
    EVENT_KINDS,
    HOST_ACTOR,
    build_chain_events,
    events_from_jsonl,
    events_to_jsonl,
    first_and_entry_hash,
    hash_event,
    is_valid_actor_id,
    is_valid_event_kind,
    participant_actor_id_problems,
    participant_actor_ids,
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
from .pith import (
    PITH_VERSION,
    compress_event_payload,
    compress_text,
    normalize_event_payload,
)
from .profiles import (
    DEFAULT_PROFILE,
    SUPPORTED_PROFILES,
    InvalidProfileError,
    ProfileError,
    ProfileMismatchError,
    UnsupportedProfileError,
    classify_profile,
    is_valid_profile_id,
    profile_declaration_problems,
)
from .reader import CapsuleReader, MalformedCapsuleError
from .verifier import verify_capsule
from .versions import (
    CURRENT_VERSION,
    KNOWN_VERSIONS,
    SUITES,
    UnsupportedCapsuleVersionError,
    classify_version,
    id_domain,
    key_wrap_info,
    provenance_domain,
)
from .zip_io import UnsafeZipPathError, pack_zip, unpack_zip

__version__ = "0.7.0"
# The spec version this SDK seals at — always the versions module's
# CURRENT_VERSION, never a separate literal (a second copy is exactly
# how a bump leaves a stale era behind).
SPEC_VERSION = CURRENT_VERSION

__all__ = [
    "ACTOR_NAMESPACES",
    "CONTENT_INDEX_EXCLUDED",
    "CURRENT_VERSION",
    "DEFAULT_PROFILE",
    "KNOWN_VERSIONS",
    "SUITES",
    "SUPPORTED_PROFILES",
    "EVENT_KINDS",
    "HOST_ACTOR",
    "PITH_VERSION",
    "SPEC_VERSION",
    "STRUCTURAL_EXCLUDED",
    "CapsuleBuilder",
    "CapsuleReader",
    "Ed25519KeyPair",
    "EncryptedCapsulesNotSupportedError",
    "InvalidProfileError",
    "MalformedCapsuleError",
    "ProfileError",
    "ProfileMismatchError",
    "UnsafeZipPathError",
    "UnsupportedCapsuleVersionError",
    "UnsupportedProfileError",
    "X25519KeyPair",
    "__version__",
    "build_chain_events",
    "build_content_index",
    "build_envelope",
    "build_manifest",
    "bytes_to_hex",
    "chacha20_poly1305_decrypt",
    "classify_profile",
    "classify_version",
    "chacha20_poly1305_encrypt",
    "compress_event_payload",
    "normalize_event_payload",
    "compress_text",
    "compute_capsule_id",
    "concat_bytes",
    "content_index_exclusions",
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
    "id_domain",
    "is_valid_actor_id",
    "is_valid_event_kind",
    "is_valid_profile_id",
    "jcs",
    "key_wrap_info",
    "manifest_bytes",
    "manifest_hash",
    "pack_zip",
    "participant_actor_id_problems",
    "participant_actor_ids",
    "profile_declaration_problems",
    "provenance_domain",
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
