//! L3 decryption of an encrypted Capsule v0.6.
//!
//! Given an outer envelope, outer manifest, the file map already extracted
//! from the outer ZIP, and a recipient's X25519 32-byte private key, this
//! module:
//!
//! 1. Locates the matching key bundle in
//!    `skills/decryption/decryption.json`.
//! 2. Performs an X25519 ECDH between the recipient's secret and the
//!    bundle's ephemeral public key.
//! 3. HKDF-SHA256-derives a 32-byte wrap key (salt = recipient's *own*
//!    public key, info = `b"capsule-key-wrap-v0.6"`).
//! 4. AEAD-decrypts the bundle's `wrapped_key` to recover the 32-byte
//!    content key.
//! 5. AEAD-decrypts `content.enc` with the content key, the
//!    `content_nonce` from the metadata, and AAD = JCS over the 5-field
//!    `aad_obj` constructed from the outer envelope+manifest.
//! 6. Returns the inner ZIP bytes ready for further unpacking by the
//!    caller.
//!
//! **AAD construction is authoritative against the JS reference SDK
//! (`sdk/src/builder.js`), not the spec text.** The 5 fields are:
//!
//! ```text
//! { "version": "0.6",
//!   "capsule_id":            envelope.capsule_id,
//!   "first_event_hash":      envelope.first_event_hash,
//!   "originator_public_key": manifest.originator.public_key,
//!   "cipher":                "ChaCha20-Poly1305" }
//! ```
//!
//! The HKDF *salt* is the recipient's public key (32 raw bytes), NOT the
//! ephemeral. That mirrors the `hkdfSha256(shared, r.publicKey, info, 32)`
//! call in the JS builder.
//!
//! This module performs decryption only. Inner-envelope signature
//! verification is the caller's responsibility (Task 2 wires it into the
//! verifier proper).

use std::collections::BTreeMap;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use serde::Deserialize;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::{bytes_to_hex, hex_to_bytes};
use crate::jcs::jcs;
use crate::schemas::{Envelope, Manifest};

/// Errors returned by [`decrypt_inner_zip`].
#[derive(Debug, Error)]
pub enum DecryptError {
    /// The capsule is not encrypted: cipher == "none" or `content.enc`
    /// is absent. Caller can fall through to plain-capsule handling.
    #[error("capsule is not encrypted (no content.enc)")]
    NotEncrypted,
    /// Outer envelope has `cipher` set to a value we do not implement.
    /// Currently only `"ChaCha20-Poly1305"` and `"none"` are recognized.
    #[error("unsupported cipher: {0}")]
    UnsupportedCipher(String),
    /// `skills/decryption/decryption.json` was not present in the outer
    /// ZIP. Required for any encrypted capsule.
    #[error("decryption metadata missing: skills/decryption/decryption.json")]
    DecryptionMetadataMissing,
    /// `skills/decryption/decryption.json` was present but failed to
    /// parse. The wrapped error string is the deserializer's message.
    #[error("decryption metadata invalid: {0}")]
    DecryptionMetadataInvalid(String),
    /// No bundle in `key_bundles` had a `recipient_public_key` matching
    /// the public key derived from the supplied private key.
    #[error("no key bundle matches the supplied recipient private key")]
    NoMatchingRecipient,
    /// AEAD authentication failed during the wrapped-key step. Either
    /// the supplied private key is wrong, the bundle was corrupted, or
    /// the salt/info inputs to HKDF disagree with the JS reference.
    #[error("key unwrap failed (ChaCha20-Poly1305 auth tag invalid for wrapped_key)")]
    KeyUnwrapFailed,
    /// AEAD authentication failed on `content.enc`. The blob was
    /// modified, the AAD diverges from the JS reference, or the content
    /// key recovered upstream is wrong.
    #[error("content decrypt failed (ChaCha20-Poly1305 auth tag invalid for content.enc)")]
    ContentDecryptFailed,
    /// A hex string in the metadata did not decode as strict lowercase
    /// hex, or had the wrong length for its declared field.
    #[error("malformed hex in decryption metadata: {0}")]
    Hex(String),
    /// Catch-all for unexpected crypto-layer errors. Should not fire on
    /// valid inputs; surfaced for diagnostic purposes.
    #[error("crypto operation failed: {0}")]
    Crypto(String),
}

/// On-disk shape of `skills/decryption/decryption.json`. Mirrors the JS
/// builder's `decryptionMeta` object byte-for-byte.
#[derive(Debug, Deserialize)]
pub struct DecryptionMetadata {
    pub cipher: String,
    /// 24 lowercase hex chars (12 raw bytes) — the AEAD nonce used to
    /// encrypt `content.enc`.
    pub content_nonce: String,
    pub key_bundles: Vec<KeyBundle>,
}

/// One per-recipient bundle. The recipient identifies itself by its X25519
/// public key (`recipient_public_key`); the producer encrypted the content
/// key under a wrap key derived from ECDH(eph_secret, recipient_public_key).
#[derive(Debug, Deserialize)]
pub struct KeyBundle {
    /// 64 lowercase hex chars (32 raw bytes) — recipient's X25519 public
    /// key. The decryptor matches this against
    /// `x25519_pubkey_from_secret(private_key)` to find its bundle.
    pub recipient_public_key: String,
    /// 64 lowercase hex chars (32 raw bytes) — ephemeral X25519 public
    /// key used as the producer side of the ECDH.
    pub ephemeral_public_key: String,
    /// 24 lowercase hex chars (12 raw bytes) — AEAD nonce used for the
    /// wrapped-key step.
    pub wrap_nonce: String,
    /// AEAD ciphertext over the 32-byte content key under the
    /// HKDF-derived wrap key with empty AAD. Typically 96 hex chars
    /// (32 bytes plaintext + 16-byte tag = 48 raw, 96 hex).
    pub wrapped_key: String,
}

/// Decrypt an encrypted Capsule v0.6 inner ZIP.
///
/// `envelope` and `manifest` are the *outer* envelope and manifest (already
/// parsed by the caller). `files` is the file map produced by
/// [`crate::unpack_zip`] for the outer container. `recipient_private_key`
/// is the X25519 32-byte secret whose corresponding public key appears in
/// one of the `key_bundles`.
///
/// On success, returns the raw inner ZIP bytes. The caller is responsible
/// for unpacking those bytes and verifying the inner envelope's signature.
///
/// On failure, returns a [`DecryptError`] that names the specific failure
/// mode. AEAD authentication failures are split into
/// [`DecryptError::KeyUnwrapFailed`] (wrong recipient secret or corrupt
/// bundle) vs. [`DecryptError::ContentDecryptFailed`] (wrong AAD or
/// corrupt blob), so callers can attribute the failure precisely.
pub fn decrypt_inner_zip(
    envelope: &Envelope,
    manifest: &Manifest,
    files: &BTreeMap<String, Vec<u8>>,
    recipient_private_key: &[u8; 32],
) -> Result<Vec<u8>, DecryptError> {
    // Step 1: cipher gate. "none" → not encrypted; anything other than
    // ChaCha20-Poly1305 we do not implement.
    match envelope.cipher.as_str() {
        "ChaCha20-Poly1305" => {}
        "none" => return Err(DecryptError::NotEncrypted),
        other => return Err(DecryptError::UnsupportedCipher(other.to_string())),
    }

    // Step 2: locate content.enc. Absent → treat as not-encrypted: this
    // should not happen with a well-formed encrypted capsule, but we want
    // a stable error rather than a confusing decryption failure.
    let content_enc = files
        .get("content.enc")
        .ok_or(DecryptError::NotEncrypted)?;

    // Step 3: locate decryption metadata.
    let meta_bytes = files
        .get("skills/decryption/decryption.json")
        .ok_or(DecryptError::DecryptionMetadataMissing)?;

    // Step 4: parse decryption metadata.
    let meta: DecryptionMetadata = serde_json::from_slice(meta_bytes)
        .map_err(|e| DecryptError::DecryptionMetadataInvalid(e.to_string()))?;

    // Sanity: the metadata's own cipher field must match the outer
    // envelope's. The JS builder always writes the same string into both
    // places; a divergence is a sign the outer manifest/metadata pair is
    // inconsistent and we refuse to guess which one to trust.
    if meta.cipher != "ChaCha20-Poly1305" {
        return Err(DecryptError::DecryptionMetadataInvalid(format!(
            "metadata cipher = {:?}, expected \"ChaCha20-Poly1305\"",
            meta.cipher
        )));
    }

    // Step 5+6: derive my pubkey, find my bundle.
    let my_pubkey = x25519_pubkey_from_secret(recipient_private_key);
    let my_pubkey_hex = bytes_to_hex(&my_pubkey);
    let bundle = meta
        .key_bundles
        .iter()
        .find(|b| b.recipient_public_key == my_pubkey_hex)
        .ok_or(DecryptError::NoMatchingRecipient)?;

    // Step 7: decode the bundle hex fields with length checks.
    let ephemeral_pub = decode_hex_fixed::<32>(&bundle.ephemeral_public_key, "ephemeral_public_key")?;
    let wrap_nonce = decode_hex_fixed::<12>(&bundle.wrap_nonce, "wrap_nonce")?;
    let wrapped_key = hex_to_bytes(&bundle.wrapped_key)
        .map_err(|e| DecryptError::Hex(format!("wrapped_key: {e}")))?;

    // ECDH.
    let shared = x25519_dh(recipient_private_key, &ephemeral_pub);

    // Step 8: HKDF. Salt is the recipient's own pubkey raw 32 bytes; info
    // is the v0.6 wrap-step domain string; output 32 bytes.
    let wrap_key = hkdf_sha256(&shared, &my_pubkey, b"capsule-key-wrap-v0.6", 32);
    let wrap_key_arr: [u8; 32] = wrap_key
        .as_slice()
        .try_into()
        .expect("hkdf_sha256 returned exactly 32 bytes");

    // Step 9: unwrap the content key. AAD is empty, matching the JS
    // builder's `Buffer.alloc(0)`.
    let content_key = chacha20_poly1305_decrypt(&wrap_key_arr, &wrap_nonce, &[], &wrapped_key)
        .map_err(|_| DecryptError::KeyUnwrapFailed)?;
    let content_key_arr: [u8; 32] = content_key
        .as_slice()
        .try_into()
        .map_err(|_| DecryptError::Crypto(format!(
            "wrapped_key plaintext was {} bytes, expected 32",
            content_key.len()
        )))?;

    // Step 10: AAD = JCS(aad_obj). build_aad encapsulates the canonical
    // 5-field shape.
    let aad = build_aad(envelope, manifest);

    // Step 11: decrypt the content blob.
    let content_nonce = decode_hex_fixed::<12>(&meta.content_nonce, "content_nonce")?;
    let inner_zip = chacha20_poly1305_decrypt(&content_key_arr, &content_nonce, &aad, content_enc)
        .map_err(|_| DecryptError::ContentDecryptFailed)?;

    Ok(inner_zip)
}

/// Decode a strict-lowercase hex string into a fixed-size byte array.
/// The `field` argument names the metadata key being decoded so failures
/// have actionable context.
fn decode_hex_fixed<const N: usize>(s: &str, field: &str) -> Result<[u8; N], DecryptError> {
    let raw = hex_to_bytes(s).map_err(|e| DecryptError::Hex(format!("{field}: {e}")))?;
    raw.as_slice()
        .try_into()
        .map_err(|_| DecryptError::Hex(format!(
            "{field}: expected {} bytes, got {}",
            N,
            raw.len()
        )))
}

/// Derive the X25519 public key for a 32-byte secret. Mirrors the JS
/// reference's `generateX25519`/`x25519DH` produce-side public-key
/// derivation: the Montgomery base point times the clamped scalar.
///
/// `x25519_dalek::StaticSecret::from(bytes)` clamps internally before use,
/// so we don't pre-clamp; passing raw bytes through is correct.
fn x25519_pubkey_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    let s = StaticSecret::from(*secret);
    PublicKey::from(&s).to_bytes()
}

/// Compute the X25519 ECDH shared secret between `secret` and `peer_pub`.
/// The result is the canonical Montgomery u-coordinate, raw 32 bytes —
/// suitable as an HKDF IKM. Mirrors the JS reference's `x25519DH`.
fn x25519_dh(secret: &[u8; 32], peer_pub: &[u8; 32]) -> [u8; 32] {
    let s = StaticSecret::from(*secret);
    let p = PublicKey::from(*peer_pub);
    s.diffie_hellman(&p).to_bytes()
}

/// HKDF-SHA256 extract+expand. `salt` is *required* by the JS reference
/// (mirrors Node's `hkdfSync(...)` signature with an explicit salt
/// argument); pass `&[]` only if a caller deliberately wants RFC 5869's
/// "salt = HashLen zero bytes" fallback. The JS builder always passes a
/// non-empty salt.
fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .expect("HKDF-SHA256 expand never fails for length <= 255*32");
    okm
}

/// ChaCha20-Poly1305 decrypt: returns plaintext on success, `Err(())` on
/// any AEAD-layer failure (auth tag mismatch, malformed inputs, etc.).
/// Callers map `Err(())` to the specific [`DecryptError`] variant that
/// applies in their context (wrap step vs content step) — the AEAD layer
/// itself can't tell why authentication failed.
fn chacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ()> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| ())
}

/// Build the AAD bytes = JCS(aad_obj) where `aad_obj` is the 5-field
/// object captured at the top of this module.
///
/// Order independence: JCS sorts object keys alphabetically, so the
/// `serde_json::json!` literal below could list the keys in any order —
/// the canonical bytes are determined by the alphabetic sort, not by the
/// source ordering.
fn build_aad(envelope: &Envelope, manifest: &Manifest) -> Vec<u8> {
    let aad_obj = serde_json::json!({
        "version": "0.6",
        "capsule_id": envelope.capsule_id,
        "first_event_hash": envelope.first_event_hash,
        "originator_public_key": manifest.originator.public_key,
        "cipher": "ChaCha20-Poly1305",
    });
    jcs(&aad_obj)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{recipient_x25519_private_key, tampered_capsule_bytes};
    use crate::unpack_zip;

    /// RFC 5869 §A.1 "Test Case 1" — basic SHA-256 HKDF vector.
    /// IKM = 22 bytes 0x0b, salt = 13 bytes (0x00..=0x0c), info = 10
    /// bytes (0xf0..=0xf9), L = 42. Expected OKM is captured directly
    /// from the RFC.
    #[test]
    fn hkdf_known_vector() {
        let ikm = [0x0b; 22];
        let salt: Vec<u8> = (0u8..=0x0c).collect();
        let info: Vec<u8> = (0xf0u8..=0xf9).collect();
        let got = hkdf_sha256(&ikm, &salt, &info, 42);
        let expected = hex_to_bytes(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();
        assert_eq!(got, expected, "RFC 5869 §A.1 OKM");
    }

    /// RFC 7748 §6.1 — Alice's keypair. Private scalar -> public key
    /// derivation must match the published value byte-for-byte.
    #[test]
    fn x25519_known_vector() {
        let alice_secret_hex =
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        let alice_public_hex =
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
        let alice_secret: [u8; 32] = hex_to_bytes(alice_secret_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let alice_public_expected: [u8; 32] = hex_to_bytes(alice_public_hex)
            .unwrap()
            .try_into()
            .unwrap();

        let got = x25519_pubkey_from_secret(&alice_secret);
        assert_eq!(got, alice_public_expected, "RFC 7748 Alice pubkey");
    }

    /// Round-trip a known plaintext through ChaCha20-Poly1305 with both
    /// empty and non-empty AAD; confirm a one-bit ciphertext mutation is
    /// rejected by the auth tag.
    #[test]
    fn chacha20poly1305_round_trip() {
        // A fixed key+nonce keeps the test deterministic; we don't need
        // randomness to exercise the AEAD path.
        let key: [u8; 32] = *b"0123456789abcdef0123456789abcdef";
        let nonce: [u8; 12] = *b"0123456789ab";
        let plaintext = b"hello world: capsule v0.6 inner zip placeholder";

        // Encrypt for both AAD shapes. We need a local encrypt helper
        // since the production code only exposes `decrypt`. Inline the
        // call to ChaCha20Poly1305 to avoid leaking an encrypt function
        // into the public surface.
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

        for aad in [b"" as &[u8], b"some aad bytes"] {
            let ct = cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload { msg: plaintext, aad },
                )
                .expect("encrypt succeeds");

            // Round-trip succeeds.
            let pt = chacha20_poly1305_decrypt(&key, &nonce, aad, &ct)
                .expect("round-trip decrypt succeeds");
            assert_eq!(pt, plaintext);

            // Mutate the last byte (the auth tag's last byte): decrypt
            // must fail.
            let mut bad = ct.clone();
            *bad.last_mut().unwrap() ^= 0x01;
            assert!(
                chacha20_poly1305_decrypt(&key, &nonce, aad, &bad).is_err(),
                "mutated ciphertext must fail auth"
            );
        }
    }

    /// Pin the AAD construction to a captured oracle: load
    /// `clean-encrypted.capsule`, parse outer envelope+manifest, call
    /// [`build_aad`], and assert the canonical bytes match exactly. Any
    /// future drift in field order, key naming, or value sourcing will
    /// be caught here before it can desync from the JS reference.
    #[test]
    fn build_aad_matches_jcs_oracle() {
        let bytes = tampered_capsule_bytes("clean-encrypted.capsule");
        let files = unpack_zip(&bytes).expect("clean-encrypted unzips");
        let manifest: Manifest =
            serde_json::from_slice(files.get("manifest.json").expect("manifest"))
                .expect("manifest parses");
        let envelope: Envelope =
            serde_json::from_slice(files.get("provenance/envelope.json").expect("envelope"))
                .expect("envelope parses");

        let got = build_aad(&envelope, &manifest);
        let expected = br#"{"capsule_id":"d6d73f94c78e68442b7a3f19fcfbd93a035155732efb2dc5ee2bf44f4322ab95","cipher":"ChaCha20-Poly1305","first_event_hash":"577a1933292463b7ecf8f3a5b32dbc970804fef418aab805b8a94fccf819d076","originator_public_key":"c172289fcacf417de58632909bc0353d11c87d5a6b0b79288c70723c5cf3749e","version":"0.6"}"#;
        assert_eq!(
            got,
            expected,
            "AAD bytes mismatch:\n got:      {}\n expected: {}",
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(expected)
        );
    }

    /// Full integration: decrypt `clean-encrypted.capsule` end-to-end and
    /// confirm the resulting bytes are a valid inner ZIP containing the
    /// expected file set.
    #[test]
    fn decrypts_clean_encrypted_capsule() {
        let outer_bytes = tampered_capsule_bytes("clean-encrypted.capsule");
        let outer_files = unpack_zip(&outer_bytes).expect("outer unzips");
        let manifest: Manifest =
            serde_json::from_slice(outer_files.get("manifest.json").expect("manifest"))
                .expect("manifest parses");
        let envelope: Envelope =
            serde_json::from_slice(outer_files.get("provenance/envelope.json").expect("envelope"))
                .expect("envelope parses");
        let secret = recipient_x25519_private_key();

        let inner = decrypt_inner_zip(&envelope, &manifest, &outer_files, &secret)
            .expect("decryption succeeds");

        // ZIP magic: PK\x03\x04 marks the start of the first local file
        // header. Anything else means we got plaintext-of-something-else
        // back.
        assert!(
            inner.starts_with(&[0x50, 0x4b, 0x03, 0x04]),
            "decrypted inner does not start with ZIP magic; first 8 = {:?}",
            &inner.get(..inner.len().min(8))
        );

        let inner_files = unpack_zip(&inner).expect("inner zip is well-formed");
        for required in [
            "manifest.json",
            "chain/events.jsonl",
            "provenance/envelope.json",
        ] {
            assert!(
                inner_files.contains_key(required),
                "inner zip must contain {required}; got keys = {:?}",
                inner_files.keys().collect::<Vec<_>>()
            );
        }
    }

    /// `tampered-blob.capsule` mutates `content.enc`: AEAD auth must
    /// reject the blob in the content step (the wrap step succeeds because
    /// the bundle is intact).
    #[test]
    fn tampered_blob_fails_decryption() {
        let outer_bytes = tampered_capsule_bytes("tampered-blob.capsule");
        let outer_files = unpack_zip(&outer_bytes).expect("outer unzips");
        let manifest: Manifest =
            serde_json::from_slice(outer_files.get("manifest.json").expect("manifest"))
                .expect("manifest parses");
        let envelope: Envelope =
            serde_json::from_slice(outer_files.get("provenance/envelope.json").expect("envelope"))
                .expect("envelope parses");
        let secret = recipient_x25519_private_key();

        let err = decrypt_inner_zip(&envelope, &manifest, &outer_files, &secret)
            .expect_err("tampered blob must not decrypt");
        assert!(
            matches!(err, DecryptError::ContentDecryptFailed),
            "expected ContentDecryptFailed, got {err:?}"
        );
    }

    /// A wrong (but well-formed) X25519 secret derives a public key that
    /// is not present in any bundle. The lookup must fail before any
    /// AEAD call is attempted.
    #[test]
    fn wrong_key_returns_no_matching_recipient() {
        let outer_bytes = tampered_capsule_bytes("clean-encrypted.capsule");
        let outer_files = unpack_zip(&outer_bytes).expect("outer unzips");
        let manifest: Manifest =
            serde_json::from_slice(outer_files.get("manifest.json").expect("manifest"))
                .expect("manifest parses");
        let envelope: Envelope =
            serde_json::from_slice(outer_files.get("provenance/envelope.json").expect("envelope"))
                .expect("envelope parses");
        let bogus_secret: [u8; 32] = [0x42; 32];

        let err = decrypt_inner_zip(&envelope, &manifest, &outer_files, &bogus_secret)
            .expect_err("bogus secret must not decrypt");
        assert!(
            matches!(err, DecryptError::NoMatchingRecipient),
            "expected NoMatchingRecipient, got {err:?}"
        );
    }
}
