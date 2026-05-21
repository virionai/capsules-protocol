//! Parity tests against the JavaScript SDK's shared vector fixtures.
//!
//! The fixtures live in `spec/vectors/tamper-detection/output/`. They are
//! the source of truth for the Rust verifier's behavior: every assertion
//! in this file is a byte-for-byte cross-check between the Rust port and
//! the JS reference.
//!
//! The whole suite reads the originator pubkey out of `keys.json` so a
//! regenerated fixture (with a fresh keypair) does not silently drift
//! from the hardcoded constant.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use capsule_verify::{verify_capsule, VerifyOptions};
use serde::Deserialize;

/// One half of the keypair JSON written by `build.mjs`. We only need the
/// public key.
#[derive(Debug, Deserialize)]
struct KeyPair {
    #[serde(rename = "publicKey")]
    public_key: String,
}

/// Top-level shape of `keys.json`.
#[derive(Debug, Deserialize)]
struct Keys {
    originator: KeyPair,
}

/// Resolve a fixture by name under
/// `<workspace>/../spec/vectors/tamper-detection/output/<name>`.
fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("spec/vectors/tamper-detection/output")
        .join(name)
        .canonicalize()
        .unwrap_or_else(|_| {
            panic!(
                "fixture {name:?} missing; populate spec/vectors before running parity tests"
            )
        })
}

fn read_fixture(name: &str) -> Vec<u8> {
    let path = fixture_path(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {path:?} failed: {e}"))
}

/// Read the originator pubkey out of `keys.json` once. A static
/// `OnceLock` makes this safe to call from multiple `#[test]` fns in
/// parallel without re-reading the file.
fn originator_pubkey() -> &'static str {
    static PK: OnceLock<String> = OnceLock::new();
    PK.get_or_init(|| {
        let path = fixture_path("keys.json");
        let bytes = std::fs::read(&path).expect("read keys.json");
        let keys: Keys = serde_json::from_slice(&bytes).expect("parse keys.json");
        keys.originator.public_key
    })
    .as_str()
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

/// The clean fixture must verify cleanly with the JS-produced
/// originator key on the allowlist. We additionally assert exactly one
/// signer and exactly one trusted signer — anything else would mean the
/// fixture or verifier drifted.
#[test]
fn clean_capsule_passes() {
    let bytes = read_fixture("clean.capsule");
    let allowlist = vec![originator_pubkey().to_string()];
    let result = verify_capsule(
        &bytes,
        &VerifyOptions {
            allowlist,
            recipient_private_key: None,
        },
    );

    assert!(
        result.ok,
        "clean.capsule must verify; errors: {:?}; chain.errors: {:?}; ci.errors: {:?}",
        result.errors, result.chain.errors, result.content_index.errors
    );
    assert_eq!(
        result.envelope.signers.len(),
        1,
        "clean.capsule must have exactly one signer; got: {:?}",
        result.envelope.signers
    );
    assert_eq!(
        result.trusted_signer_count, 1,
        "with originator on allowlist, trusted_signer_count must be 1; got: {}",
        result.trusted_signer_count
    );
}

/// `tampered-payload.capsule` flips one byte in `program.md`. The
/// content_index must surface a per-file hash mismatch naming
/// `program.md` AND including both the stored and recomputed hashes
/// (the forensics format added in Task 5).
#[test]
fn tampered_payload_fails_at_content_index() {
    let bytes = read_fixture("tampered-payload.capsule");
    let allowlist = vec![originator_pubkey().to_string()];
    let result = verify_capsule(
        &bytes,
        &VerifyOptions {
            allowlist,
            recipient_private_key: None,
        },
    );

    assert!(!result.ok, "tampered payload must not verify");
    assert!(
        !result.content_index.errors.is_empty(),
        "expected at least one content_index error; got result: {result:?}"
    );
    assert!(
        result
            .content_index
            .errors
            .iter()
            .any(|e| e.contains("program.md")),
        "at least one content_index error must mention program.md; got: {:?}",
        result.content_index.errors
    );
    assert!(
        result
            .content_index
            .errors
            .iter()
            .any(|e| e.contains("stored") && e.contains("recomputed")),
        "at least one content_index error must include both 'stored' and 'recomputed'; got: {:?}",
        result.content_index.errors
    );
}

/// `tampered-chain.capsule` modifies one event in `chain/events.jsonl`.
/// The fixture either fails the chain walk (because the prev/hash
/// linkage breaks) OR fails the content_index (since the chain file is
/// itself indexed). Either signal is acceptable parity with the JS
/// verifier.
#[test]
fn tampered_chain_fails_at_chain_or_content_index() {
    let bytes = read_fixture("tampered-chain.capsule");
    let allowlist = vec![originator_pubkey().to_string()];
    let result = verify_capsule(
        &bytes,
        &VerifyOptions {
            allowlist,
            recipient_private_key: None,
        },
    );

    assert!(!result.ok, "tampered chain must not verify");
    assert!(
        !result.chain.errors.is_empty() || !result.content_index.errors.is_empty(),
        "expected at least one chain or content_index error; got result: {result:?}"
    );
}

/// `tampered-envelope.capsule` flips one byte in the originator's
/// signature. Ed25519 verification must reject that signer; the
/// envelope.ok aggregate must be false.
#[test]
fn tampered_envelope_fails_at_signature() {
    let bytes = read_fixture("tampered-envelope.capsule");
    let allowlist = vec![originator_pubkey().to_string()];
    let result = verify_capsule(
        &bytes,
        &VerifyOptions {
            allowlist,
            recipient_private_key: None,
        },
    );

    assert!(!result.ok, "tampered envelope must not verify");
    assert!(
        result.envelope.signers.iter().any(|s| !s.valid),
        "at least one signer must be marked invalid; got: {:?}",
        result.envelope.signers
    );
    assert!(
        !result.envelope.ok,
        "envelope.ok must be false on signature tamper; got envelope: {:?}",
        result.envelope
    );
}

/// `tampered-blob.capsule` is encrypted with a mutated `content.enc`; L2
/// must reject it with a precise `encrypted_blob_hash mismatch` error.
/// The chain check is deferred to L3 (the failure is at encryption, not
/// at chain).
#[test]
fn encrypted_capsule_rejected_with_clear_message() {
    let bytes = read_fixture("tampered-blob.capsule");
    let allowlist = vec![originator_pubkey().to_string()];
    let result = verify_capsule(
        &bytes,
        &VerifyOptions {
            allowlist,
            recipient_private_key: None,
        },
    );

    assert!(!result.ok, "tampered-blob must be rejected at L2");
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.message.contains("encrypted_blob_hash mismatch")),
        "expected an 'encrypted_blob_hash mismatch' error in result.errors; got: {:?}",
        result.errors
    );
    assert!(
        result.chain.ok && result.chain.note.is_some(),
        "chain check must be deferred (ok=true, note set); got chain: {:?}",
        result.chain
    );
}

/// `clean-encrypted.capsule` with the recipient's X25519 private key
/// must promote to L3: the inner ZIP is decrypted, the inner chain is
/// walked, and the deferred-chain note is cleared because a real walk
/// happened. This is the v0.3 happy path — fixture parity for the L3
/// promotion the JS SDK also performs when given the recipient key.
#[test]
fn encrypted_clean_capsule_passes_l3() {
    let bytes = read_fixture("clean-encrypted.capsule");
    let keys: serde_json::Value = serde_json::from_slice(&read_fixture("keys.json"))
        .expect("keys.json parses");
    let recipient_secret_hex = keys
        .pointer("/recipient/privateKey")
        .and_then(|v| v.as_str())
        .expect("recipient.privateKey present");
    let recipient_secret_bytes = hex::decode(recipient_secret_hex).expect("hex decode");
    let recipient_secret: [u8; 32] = recipient_secret_bytes
        .try_into()
        .expect("32 bytes");

    let result = verify_capsule(
        &bytes,
        &VerifyOptions {
            allowlist: vec![],
            recipient_private_key: Some(recipient_secret),
        },
    );
    assert!(
        result.ok,
        "expected L3 PASS, got errors: {:?}",
        result.errors
    );
    assert_eq!(result.level, "L3");
    assert!(result.chain.ok);
    assert!(
        result.chain.note.is_none(),
        "chain note should be cleared at L3"
    );
    assert!(result.chain.event_count >= 1);

    // v0.4: inner envelope signature verification. On a successful L3
    // promotion the inner envelope must be parsed, every inner signer's
    // Ed25519 signature must verify, and `inner_envelope.ok` must be
    // true. Allowlist-based trust is asserted separately under unit
    // tests; the parity test only pins parity with the JS SDK on the
    // clean-encrypted fixture.
    assert!(
        result.inner_envelope.is_some(),
        "L3 should populate inner_envelope on a successfully decrypted capsule",
    );
    let inner = result.inner_envelope.as_ref().unwrap();
    assert!(
        inner.ok,
        "inner envelope signature should verify; got: {:?}",
        inner.signers,
    );
    assert!(
        !inner.signers.is_empty(),
        "clean-encrypted has at least one inner signer (originator)",
    );
    assert!(
        inner.signers.iter().all(|s| s.valid),
        "all inner signers should be valid; got: {:?}",
        inner.signers,
    );

    // v0.5: full inner plain-capsule verification at L3. On a successful L3
    // promotion the inner content_index must be recomputed and verified, and
    // the four inner checks (format/version, capsule_id, manifest_hash,
    // content_index) must all pass — no `"L3 inner:"`-prefixed errors should
    // appear in `result.errors`.
    assert!(
        result.inner_content_index.is_some(),
        "L3 should populate inner_content_index on a successfully decrypted capsule",
    );
    let inner_ci = result.inner_content_index.as_ref().unwrap();
    assert!(
        inner_ci.ok,
        "inner content_index should verify; got errors: {:?}",
        inner_ci.errors,
    );
    // All four inner checks pass:
    assert!(
        !result.errors.iter().any(|e| e.message.starts_with("L3 inner:")),
        "no L3 inner errors expected; got: {:?}",
        result.errors,
    );
}

/// `clean-encrypted.capsule` is the encrypted variant of the clean
/// fixture: same payload, encrypted outer. As of v0.2 L2 must accept it,
/// rendering the chain check as deferred to L3 rather than failed.
#[test]
fn encrypted_clean_capsule_passes_l2() {
    let bytes = read_fixture("clean-encrypted.capsule");
    let allowlist = vec![originator_pubkey().to_string()];
    let result = verify_capsule(
        &bytes,
        &VerifyOptions {
            allowlist,
            recipient_private_key: None,
        },
    );

    assert!(
        result.ok,
        "clean-encrypted must pass at L2; errors: {:?}",
        result.errors
    );
    assert!(result.errors.is_empty(), "no top-level errors: {:?}", result.errors);
    assert!(
        result.envelope.signers.iter().all(|s| s.valid),
        "all signers must be valid; got: {:?}",
        result.envelope.signers
    );
    assert!(result.chain.ok, "chain.ok must be true (deferred, not failed)");
    let note = result
        .chain
        .note
        .as_deref()
        .expect("chain.note must be set on encrypted outer");
    assert!(
        note.contains("deferred") || note.contains("encrypted"),
        "chain.note must mention deferral or encryption; got: {note:?}"
    );
    assert_eq!(result.trusted_signer_count, 1, "originator on allowlist → 1 trusted");
}
