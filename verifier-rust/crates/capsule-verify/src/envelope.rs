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
use crate::versions::{provenance_domain, CURRENT_VERSION};

/// Result of verifying a single signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSigner {
    pub role: String,
    pub public_key: String,
    pub valid: bool,
}

/// JCS-canonical bytes of `envelope` with the `signers` field removed.
///
/// Matches `envelopeCanonicalPayload` in `sdk-js/src/envelope.js`. Takes the
/// PRESERVED `serde_json::Value` tree parsed from the on-disk
/// `provenance/envelope.json` bytes — never the typed `Envelope` struct. A
/// struct projection silently drops members it does not know, so signing
/// over a struct round-trip would diverge from what the signer actually
/// signed whenever the envelope carries extension members
/// (spec/envelope.md "Unknown members"). The preserved tree keeps them.
pub fn canonical_payload(envelope_value: &serde_json::Value) -> Vec<u8> {
    let mut value = envelope_value.clone();
    if let Some(map) = value.as_object_mut() {
        map.remove("signers");
    }
    jcs(&value)
}

/// Build the per-role signing input:
/// `utf8("capsule-provenance-v<version>:" + role + "\x00") ||
/// JCS(envelope minus signers)`. Mirrors `envelopeSigningInput`.
/// `envelope_value` is the preserved envelope tree (see [`canonical_payload`]).
///
/// The domain embeds the envelope's DECLARED `version` member — keyed
/// selection per spec/versioning.md, so an older era's signatures stay
/// verifiable under that era's domain forever. (Whether the declared
/// version is one this verifier knows is gated earlier, in the
/// verifier's version gate.)
pub fn signing_input(envelope_value: &serde_json::Value, role: &str) -> Vec<u8> {
    let version = envelope_value
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or(CURRENT_VERSION);
    let domain = provenance_domain(version, role);
    let canonical = canonical_payload(envelope_value);
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
/// `envelope` is the typed view (source of the signer list);
/// `envelope_value` is the preserved tree the signed payload is
/// canonicalised from. Both must come from the same on-disk bytes — the
/// top-level verifier parses the tree once and projects the view from it.
///
/// On any per-signer error (bad hex, wrong length, signature failure), the
/// signer's `valid` is `false`. The function never panics.
pub fn verify_signatures(
    envelope: &Envelope,
    envelope_value: &serde_json::Value,
) -> Vec<VerifiedSigner> {
    let mut out = Vec::with_capacity(envelope.signers.len());
    for s in &envelope.signers {
        let valid = verify_one(envelope_value, &s.role, &s.public_key, &s.signature);
        out.push(VerifiedSigner {
            role: s.role.clone(),
            public_key: s.public_key.clone(),
            valid,
        });
    }
    out
}

/// Verify a single signer. Hex/length errors degrade gracefully to `false`.
fn verify_one(
    envelope_value: &serde_json::Value,
    role: &str,
    public_key_hex: &str,
    signature_hex: &str,
) -> bool {
    let pk = match hex_to_bytes(public_key_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return false,
    };
    let sig = match hex_to_bytes(signature_hex) {
        Ok(b) if b.len() == 64 => b,
        _ => return false,
    };
    let input = signing_input(envelope_value, role);
    ed25519_verify(&pk, &input, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::clean_capsule_bytes;
    use crate::unpack_zip;

    /// Parse the clean fixture's envelope as (typed view, preserved tree) —
    /// the same pairing the top-level verifier produces from one parse.
    fn parse_clean_envelope() -> (Envelope, serde_json::Value) {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).unwrap();
        let env_bytes = map.get("provenance/envelope.json").unwrap();
        let value: serde_json::Value = serde_json::from_slice(env_bytes).unwrap();
        let envelope: Envelope = serde_json::from_value(value.clone()).unwrap();
        (envelope, value)
    }

    #[test]
    fn canonical_payload_excludes_signers() {
        let (_, env_value) = parse_clean_envelope();
        let bytes = canonical_payload(&env_value);
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
        let (_, env_value) = parse_clean_envelope();
        let role = "originator";
        let input = signing_input(&env_value, role);
        // The domain embeds the envelope's DECLARED version.
        let declared = env_value["version"].as_str().expect("clean envelope declares a version");
        let prefix = format!("capsule-provenance-v{declared}:{role}\0");
        assert!(input.starts_with(prefix.as_bytes()));
        // After the NUL the rest must equal the canonical payload bytes.
        let canon = canonical_payload(&env_value);
        assert_eq!(&input[prefix.len()..], canon.as_slice());
    }

    #[test]
    fn clean_envelope_signatures_verify() {
        let (env, env_value) = parse_clean_envelope();
        let outcomes = verify_signatures(&env, &env_value);
        assert_eq!(outcomes.len(), env.signers.len());
        assert!(outcomes.iter().all(|s| s.valid),
                "all clean signers must verify, got {outcomes:?}");
    }

    #[test]
    fn tampered_signature_does_not_verify() {
        let (mut env, env_value) = parse_clean_envelope();
        // Flip one hex nibble of the first signer's signature. The function
        // must yield `valid = false` rather than panicking.
        let sig = &mut env.signers[0].signature;
        let mut chars: Vec<char> = sig.chars().collect();
        chars[0] = if chars[0] == '0' { '1' } else { '0' };
        *sig = chars.into_iter().collect();
        let outcomes = verify_signatures(&env, &env_value);
        assert!(!outcomes[0].valid);
    }

    #[test]
    fn non_hex_signature_yields_invalid_not_panic() {
        let (mut env, env_value) = parse_clean_envelope();
        env.signers[0].signature = "not-hex-not-hex-not-hex-not-hex-not-hex-not-hex-not-hex-not-hex".to_string();
        let outcomes = verify_signatures(&env, &env_value);
        assert!(!outcomes[0].valid);
    }

    /// A post-seal mutation of an UNKNOWN envelope member must invalidate
    /// the signature: the canonical payload is built from the preserved
    /// tree, so the member sits inside the signed bytes. (A struct
    /// round-trip would drop it and the signature would keep verifying —
    /// the exact bug class the preserved-Value contract prevents.)
    #[test]
    fn unknown_member_mutation_invalidates_signature() {
        let (env, mut env_value) = parse_clean_envelope();
        env_value["x-acme-attestation"] = serde_json::json!("urn:acme:attest:43");
        let outcomes = verify_signatures(&env, &env_value);
        assert!(
            !outcomes[0].valid,
            "injected unknown member must change the signed payload; got {outcomes:?}"
        );
    }
}
