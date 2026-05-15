//! Crypto and hex helpers, mirroring `sdk-js/src/canonical.js` and the Ed25519
//! verify path in `sdk-js/src/crypto.js`.
//!
//! Hex handling is intentionally strict: lowercase only, even length, no
//! `0x` prefix, no whitespace. This matches the JS reference's lowercase
//! output and keeps both implementations interchangeable.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
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

/// Verify an Ed25519 signature using a raw 32-byte public key and 64-byte
/// signature. Returns `false` on any error (wrong length, malformed key,
/// invalid signature). Never panics.
pub fn ed25519_verify(public_key_raw: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let pk_bytes: &[u8; 32] = match public_key_raw.try_into() {
        Ok(arr) => arr,
        Err(_) => return false,
    };
    let sig_bytes: &[u8; 64] = match signature.try_into() {
        Ok(arr) => arr,
        Err(_) => return false,
    };
    let key = match VerifyingKey::from_bytes(pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(sig_bytes);
    key.verify(message, &sig).is_ok()
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
