//! Envelope canonical payload, signing input, and per-signer Ed25519
//! verification. Mirrors `envelopeCanonicalPayload`, `envelopeSigningInput`,
//! and `verifyEnvelopeSignatures` in `sdk-js/src/envelope.js`.
//!
//! The signed payload is `JCS(envelope minus signers)`. The actual signing
//! input is then `domain_sep_bytes || canonical_envelope_bytes`, where
//! `domain_sep_bytes = utf8("capsule-provenance-v0.6:" + role + "\x00")`.
//! Concatenation is over RAW BYTES; the verifier never feeds hex strings to
//! the cryptographic hash.

use crate::crypto::{ed25519_verify, hex_to_bytes};
use crate::jcs::jcs;
use crate::schemas::Envelope;

/// Domain separator prefix per the v0.6 envelope spec. The full domain
/// includes the per-signer role and a NUL terminator; see [`signing_input`].
const ENVELOPE_DOMAIN_PREFIX: &str = "capsule-provenance-v0.6:";

/// Result of verifying a single signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSigner {
    pub role: String,
    pub public_key: String,
    pub valid: bool,
}

/// JCS-canonical bytes of `envelope` with the `signers` field removed.
///
/// Matches `envelopeCanonicalPayload` in `sdk-js/src/envelope.js`. We go through
/// `serde_json::to_value` (rather than constructing a parallel
/// "EnvelopeMinusSigners" struct) so that any future field added to
/// `Envelope` is automatically picked up — and so the JCS canonicalization
/// runs over the same shape as the JS reference.
pub fn canonical_payload(envelope: &Envelope) -> Vec<u8> {
    // serde_json::to_value cannot fail on a struct that derives Serialize and
    // contains only JSON-representable types, but we still match on the
    // result rather than unwrapping to keep the verifier panic-free even if
    // schema evolution introduces a non-finite-number field by accident.
    let mut value = match serde_json::to_value(envelope) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    if let Some(map) = value.as_object_mut() {
        map.remove("signers");
    }
    jcs(&value)
}

/// Build the per-role signing input: `utf8("capsule-provenance-v0.6:" + role
/// + "\x00") || JCS(envelope minus signers)`. Mirrors `envelopeSigningInput`.
pub fn signing_input(envelope: &Envelope, role: &str) -> Vec<u8> {
    let mut domain = Vec::with_capacity(ENVELOPE_DOMAIN_PREFIX.len() + role.len() + 1);
    domain.extend_from_slice(ENVELOPE_DOMAIN_PREFIX.as_bytes());
    domain.extend_from_slice(role.as_bytes());
    domain.push(0u8); // NUL terminator
    let canonical = canonical_payload(envelope);
    let mut out = Vec::with_capacity(domain.len() + canonical.len());
    out.extend_from_slice(&domain);
    out.extend_from_slice(&canonical);
    out
}

/// Verify each signer's Ed25519 signature against the per-role signing
/// input. Returns one [`VerifiedSigner`] per element of `envelope.signers`,
/// preserving order. Mirrors `verifyEnvelopeSignatures` minus the version /
/// cipher pre-checks (those live at the top-level verifier).
///
/// On any per-signer error (bad hex, wrong length, signature failure), the
/// signer's `valid` is `false`. The function never panics.
pub fn verify_signatures(envelope: &Envelope) -> Vec<VerifiedSigner> {
    let mut out = Vec::with_capacity(envelope.signers.len());
    for s in &envelope.signers {
        let valid = verify_one(envelope, &s.role, &s.public_key, &s.signature);
        out.push(VerifiedSigner {
            role: s.role.clone(),
            public_key: s.public_key.clone(),
            valid,
        });
    }
    out
}

/// Verify a single signer. Hex/length errors degrade gracefully to `false`.
fn verify_one(envelope: &Envelope, role: &str, public_key_hex: &str, signature_hex: &str) -> bool {
    let pk = match hex_to_bytes(public_key_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return false,
    };
    let sig = match hex_to_bytes(signature_hex) {
        Ok(b) if b.len() == 64 => b,
        _ => return false,
    };
    let input = signing_input(envelope, role);
    ed25519_verify(&pk, &input, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::clean_capsule_bytes;
    use crate::unpack_zip;

    fn parse_clean_envelope() -> Envelope {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).unwrap();
        let env_bytes = map.get("provenance/envelope.json").unwrap();
        serde_json::from_slice(env_bytes).unwrap()
    }

    #[test]
    fn canonical_payload_excludes_signers() {
        let env = parse_clean_envelope();
        let bytes = canonical_payload(&env);
        let s = std::str::from_utf8(&bytes).unwrap();
        // The JCS string starts with `{"capsule_id":...}` (object keys
        // sorted, no `signers` field present).
        assert!(s.starts_with('{'));
        assert!(!s.contains("\"signers\""));
        // And it does contain other top-level keys like "capsule_id".
        assert!(s.contains("\"capsule_id\":"));
        assert!(s.contains("\"manifest_hash\":"));
    }

    #[test]
    fn signing_input_starts_with_domain_separator() {
        let env = parse_clean_envelope();
        let role = "originator";
        let input = signing_input(&env, role);
        let prefix = format!("{ENVELOPE_DOMAIN_PREFIX}{role}\0");
        assert!(input.starts_with(prefix.as_bytes()));
        // After the NUL the rest must equal the canonical payload bytes.
        let canon = canonical_payload(&env);
        assert_eq!(&input[prefix.len()..], canon.as_slice());
    }

    #[test]
    fn clean_envelope_signatures_verify() {
        let env = parse_clean_envelope();
        let outcomes = verify_signatures(&env);
        assert_eq!(outcomes.len(), env.signers.len());
        assert!(outcomes.iter().all(|s| s.valid),
                "all clean signers must verify, got {outcomes:?}");
    }

    #[test]
    fn tampered_signature_does_not_verify() {
        let mut env = parse_clean_envelope();
        // Flip one hex nibble of the first signer's signature. The function
        // must yield `valid = false` rather than panicking.
        let sig = &mut env.signers[0].signature;
        let mut chars: Vec<char> = sig.chars().collect();
        chars[0] = if chars[0] == '0' { '1' } else { '0' };
        *sig = chars.into_iter().collect();
        let outcomes = verify_signatures(&env);
        assert!(!outcomes[0].valid);
    }

    #[test]
    fn non_hex_signature_yields_invalid_not_panic() {
        let mut env = parse_clean_envelope();
        env.signers[0].signature = "not-hex-not-hex-not-hex-not-hex-not-hex-not-hex-not-hex-not-hex".to_string();
        let outcomes = verify_signatures(&env);
        assert!(!outcomes[0].valid);
    }
}
