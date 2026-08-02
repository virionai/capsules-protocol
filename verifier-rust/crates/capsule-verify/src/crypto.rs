//! Crypto and hex helpers, mirroring `sdk-js/src/canonical.js` and the Ed25519
//! verify path in `sdk-js/src/crypto.js`.
//!
//! Hex handling is intentionally strict: lowercase only, even length, no
//! `0x` prefix, no whitespace. This matches the JS reference's lowercase
//! output and keeps both implementations interchangeable.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors returned by the strict hex decoder.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    /// Input length is not a multiple of two.
    #[error("hex input has odd length")]
    OddHexLength,
    /// Input contains a character outside `[0-9a-f]`.
    #[error("hex input contains non-hex character")]
    NonHexCharacter,
}

/// SHA-256 of `bytes`, returning the 32-byte digest by value.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// SHA-256 of `bytes`, lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    bytes_to_hex(&sha256(bytes))
}

/// Lowercase hex encoding of `bytes`.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Strict lowercase hex decoder. Rejects odd length, uppercase, and any
/// non-hex character. Returns a typed [`CryptoError`] on bad input.
pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>, CryptoError> {
    if !s.len().is_multiple_of(2) {
        return Err(CryptoError::OddHexLength);
    }
    if !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(CryptoError::NonHexCharacter);
    }
    // At this point the input is even-length and pure lowercase hex, so
    // `hex::decode` cannot fail. Map any unexpected error to NonHexCharacter
    // to keep the public API total.
    hex::decode(s).map_err(|_| CryptoError::NonHexCharacter)
}

/// Field prime p = 2^255 - 19, little-endian.
const ED25519_P_LE: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// The 8 points whose order divides 8, as canonical y encodings with the
/// x-sign bit cleared: the identity (y = 1), the two order-4 points (y = 0),
/// the order-2 point (y = p - 1), and the four order-8 points (two y values,
/// two x signs each). Masking the sign bit means each entry covers both signs.
const ED25519_SMALL_ORDER_Y_HEX: [&str; 5] = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];

/// True when a 32-byte Ed25519 public key is canonically encoded and is not
/// one of the 8 small-subgroup points.
///
/// `VerifyingKey::from_bytes` decompresses without a canonicity check, and
/// the non-strict `Verifier::verify` accepts small-order keys — which is a
/// no-private-key forgery: take `edff…ff7f`, send a 64-byte all-zero
/// signature, and vary any signed field until the cofactored equation holds.
fn ed25519_public_key_is_acceptable(public_key: &[u8; 32]) -> bool {
    let mut masked = *public_key;
    masked[31] &= 0x7f;
    // Little-endian comparison against p, most significant byte first.
    // Equality with p is itself non-canonical, so the loop falling through
    // means "not acceptable".
    let mut canonical = false;
    for i in (0..32).rev() {
        if masked[i] != ED25519_P_LE[i] {
            canonical = masked[i] < ED25519_P_LE[i];
            break;
        }
    }
    if !canonical {
        return false;
    }
    let masked_hex = bytes_to_hex(&masked);
    !ED25519_SMALL_ORDER_Y_HEX.contains(&masked_hex.as_str())
}

/// Verify an Ed25519 signature using a raw 32-byte public key and 64-byte
/// signature. Returns `false` on any error (wrong length, malformed key,
/// non-canonical or small-order key, invalid signature). Never panics.
pub fn ed25519_verify(public_key_raw: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let pk_bytes: &[u8; 32] = match public_key_raw.try_into() {
        Ok(arr) => arr,
        Err(_) => return false,
    };
    let sig_bytes: &[u8; 64] = match signature.try_into() {
        Ok(arr) => arr,
        Err(_) => return false,
    };
    if !ed25519_public_key_is_acceptable(pk_bytes) {
        return false;
    }
    let key = match VerifyingKey::from_bytes(pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(sig_bytes);
    // `verify_strict` also rejects a small-order R; ed25519-dalek already
    // rejects a non-reduced S (`Scalar::from_canonical_bytes`) for both
    // verify paths.
    key.verify_strict(message, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        let got = sha256_hex(b"abc");
        assert_eq!(
            got,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_empty() {
        let got = sha256_hex(b"");
        assert_eq!(
            got,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hex_round_trip() {
        let original: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
        let encoded = bytes_to_hex(&original);
        assert_eq!(encoded, "deadbeef");
        let decoded = hex_to_bytes(&encoded).expect("round-trip should succeed");
        assert_eq!(decoded, original);
    }

    #[test]
    fn hex_rejects_bad_input() {
        // non-hex character
        assert_eq!(hex_to_bytes("0g"), Err(CryptoError::NonHexCharacter));
        // odd length
        assert_eq!(hex_to_bytes("abc"), Err(CryptoError::OddHexLength));
        // uppercase rejected (we only accept lowercase, matching the JS reference)
        assert_eq!(hex_to_bytes("AB"), Err(CryptoError::NonHexCharacter));
    }

    /// Witness triples an unguarded verifier accepts: the 8 small-subgroup
    /// encodings plus the non-canonical encodings that decode into it.
    #[rustfmt::skip]
    const SMALL_ORDER_WITNESSES: [(&str, &str, u32); 12] = [
        ("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", 5),
        ("0000000000000000000000000000000000000000000000000000000000000080", "0000000000000000000000000000000000000000000000000000000000000000", 0),
        ("0100000000000000000000000000000000000000000000000000000000000000", "0100000000000000000000000000000000000000000000000000000000000000", 0),
        ("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "0000000000000000000000000000000000000000000000000000000000000000", 8),
        ("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", "0000000000000000000000000000000000000000000000000000000000000000", 3),
        ("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "0000000000000000000000000000000000000000000000000000000000000000", 3),
        ("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", "0000000000000000000000000000000000000000000000000000000000000000", 15),
        ("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0100000000000000000000000000000000000000000000000000000000000000", 0),
        ("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "0100000000000000000000000000000000000000000000000000000000000000", 0),
        ("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0000000000000000000000000000000000000000000000000000000000000000", 1),
        ("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0100000000000000000000000000000000000000000000000000000000000000", 0),
        ("0100000000000000000000000000000000000000000000000000000000000080", "0100000000000000000000000000000000000000000000000000000000000000", 0),
    ];

    #[test]
    fn ed25519_rejects_small_order_and_non_canonical_keys() {
        for (pk_hex, r_hex, probe) in SMALL_ORDER_WITNESSES {
            let pk = hex_to_bytes(pk_hex).unwrap();
            let mut sig = hex_to_bytes(r_hex).unwrap();
            sig.extend_from_slice(&[0u8; 32]);
            let message = format!("capsule-low-order-probe-{probe}");
            assert!(
                !ed25519_verify(&pk, message.as_bytes(), &sig),
                "{pk_hex}: small-order / non-canonical key must be rejected"
            );
        }
    }

    #[test]
    fn ed25519_rejects_non_reduced_signature_s() {
        // RFC 8032 section 7.1 TEST 2, then the same signature with S + L.
        let pk = hex_to_bytes(
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        )
        .unwrap();
        let msg = hex_to_bytes("72").unwrap();
        let good = hex_to_bytes(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        )
        .unwrap();
        let non_reduced = hex_to_bytes(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             f52db7415978abc61b2c2eb6aeebfca0387b2eaeb4302aeeb00d291612bb0c10",
        )
        .unwrap();
        assert!(ed25519_verify(&pk, &msg, &good));
        assert!(!ed25519_verify(&pk, &msg, &non_reduced));
    }

    #[test]
    fn ed25519_verify_known_vector() {
        // RFC 8032 test vector, empty message.
        let pk = hex_to_bytes(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )
        .unwrap();
        let sig = hex_to_bytes(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )
        .unwrap();
        let msg: &[u8] = b"";

        // Good signature verifies.
        assert!(ed25519_verify(&pk, msg, &sig));

        // Mutate one byte of the signature: should fail.
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0x01;
        assert!(!ed25519_verify(&pk, msg, &bad_sig));

        // Wrong-length pubkey (31 bytes): should fail without panicking.
        let short_pk = &pk[..31];
        assert!(!ed25519_verify(short_pk, msg, &sig));
    }
}
