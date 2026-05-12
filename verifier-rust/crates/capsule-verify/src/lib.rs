//! `capsule-verify` is the Rust reference verifier for Capsule artifacts. It
//! mirrors the JavaScript SDK's verification pipeline: SHA-256 hashing, strict
//! lowercase hex encoding/decoding, Ed25519 signature verification over raw
//! 32-byte public keys and 64-byte signatures, JCS (RFC 8785) canonical JSON,
//! and a deterministic STORED-only ZIP reader. The higher-level chain,
//! envelope, manifest, and orchestrator pieces are wired through the
//! [`verify_capsule`] entry point.

pub mod chain;
pub mod crypto;
pub mod decrypt;
pub mod envelope;
pub mod jcs;
mod l3;
pub mod manifest;
pub mod schemas;
pub mod verifier;
pub mod zip_reader;

#[cfg(test)]
mod test_support;

pub use crypto::{
    bytes_to_hex, ed25519_verify, hex_to_bytes, sha256, sha256_hex, CryptoError,
};
pub use decrypt::{decrypt_inner_zip, DecryptError, DecryptionMetadata, KeyBundle};
pub use jcs::jcs;
pub use schemas::{
    parse_chain_jsonl, ChainEvent, ChainParseError, ContentIndex, ContentIndexEntry, Encryption,
    Envelope, FormatBlock, Manifest, Originator, Participant, Signer,
};
pub use verifier::{
    verify_capsule, ChainCheck, ContentIndexCheck, EnvelopeCheck, SignerOutcome, TopError,
    TopErrorCategory, TopErrorScope, VerifyOptions, VerifyResult,
};
pub use zip_reader::{unpack_zip, PathReason, ZipError, MAX_ENTRIES, MAX_TOTAL_BYTES};
