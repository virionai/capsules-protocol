//! Registry-driven conformance against `spec/vectors/`.
//!
//! Unlike `parity_against_js_sdk.rs` (which pins Rust-specific forensics
//! detail per fixture), these tests read the language-neutral outcome
//! registries directly, so the Rust lane tracks the same normative
//! expectations as the JS reference lane without hand-copied assertions:
//!
//!   - tamper-detection/vectors.json   (verify-stage outcomes)
//!   - malformed-layout/vectors.json   (open-stage reasons + verify-stage)
//!   - signing-input.json              (byte-level signing/hashing pins)
//!
//! The registry's `reason` categories are normative; the substring tables
//! below map each category onto this lane's error messages.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use capsule_verify::{
    ed25519_verify, jcs, sha256_hex, unpack_zip, verify_capsule, VerifyOptions, VerifyResult,
};
use serde_json::Value;

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("spec/vectors")
        .canonicalize()
        .expect("spec/vectors must exist")
}

fn load_json(path: &Path) -> Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {path:?}: {e}"))
}

/// Resolve the collection's allowlist: inline hex key or keys_file.
fn registry_allowlist(doc: &Value, base: &Path) -> Vec<String> {
    if let Some(k) = doc["originator_public_key_hex"].as_str() {
        return vec![k.to_string()];
    }
    if let Some(kf) = doc["keys_file"].as_str() {
        let keys = load_json(&base.join(kf));
        if let Some(pk) = keys.pointer("/originator/publicKey").and_then(|v| v.as_str()) {
            return vec![pk.to_string()];
        }
    }
    Vec::new()
}

fn all_error_messages(result: &VerifyResult) -> Vec<String> {
    let mut out: Vec<String> = result.errors.iter().map(|e| e.message.clone()).collect();
    out.extend(result.content_index.errors.iter().cloned());
    out.extend(result.chain.errors.iter().cloned());
    out
}

fn assert_verify_outcome(name: &str, expected: &Value, result: &VerifyResult) {
    let expected_ok = expected["ok"].as_bool().expect("expected.ok");
    assert_eq!(
        result.ok, expected_ok,
        "{name}: expected ok={expected_ok}; errors: {:?}; chain: {:?}; content_index: {:?}",
        result.errors, result.chain.errors, result.content_index.errors
    );
    if let Some(failing) = expected["failing"].as_array() {
        for area in failing {
            match area.as_str().expect("failing area") {
                "content_index" => assert!(
                    !result.content_index.ok,
                    "{name}: content_index must fail; got {:?}",
                    result.content_index
                ),
                "chain" => assert!(
                    !result.chain.ok,
                    "{name}: chain must fail; got {:?}",
                    result.chain
                ),
                "envelope" => assert!(
                    !result.envelope.ok,
                    "{name}: envelope must fail; got {:?}",
                    result.envelope
                ),
                "encrypted_blob" => assert!(
                    result
                        .errors
                        .iter()
                        .any(|e| e.message.contains("encrypted_blob_hash")),
                    "{name}: expected an encrypted_blob_hash error; got {:?}",
                    result.errors
                ),
                other => panic!("{name}: unknown failing area {other:?}"),
            }
        }
    }
    if let Some(needle) = expected["error_includes"].as_str() {
        let haystack = all_error_messages(result).join(" ");
        assert!(
            haystack.contains(needle),
            "{name}: expected an error containing {needle:?}; got {haystack:?}"
        );
    }
}

fn verify_fixture(base: &Path, allowlist: &[String], vector: &Value) -> VerifyResult {
    let file = vector["capsule_file"].as_str().expect("capsule_file");
    let bytes =
        std::fs::read(base.join(file)).unwrap_or_else(|e| panic!("read fixture {file:?}: {e}"));
    verify_capsule(
        &bytes,
        &VerifyOptions {
            allowlist: allowlist.to_vec(),
            recipient_private_key: None,
        },
    )
}

#[test]
fn tamper_registry_outcomes() {
    let path = vectors_dir().join("tamper-detection/vectors.json");
    let doc = load_json(&path);
    let base = path.parent().unwrap().to_path_buf();
    let allowlist = registry_allowlist(&doc, &base);
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty());
    for v in vectors {
        let name = v["name"].as_str().expect("name");
        let result = verify_fixture(&base, &allowlist, v);
        assert_verify_outcome(name, &v["expected"], &result);
    }
}

/// Per-lane mapping of the registry's normative open-stage reason
/// categories onto this verifier's error messages. The Rust verifier
/// never panics: open failures surface as `Malformed` errors in the
/// result, which is this lane's idiom for "the reader rejects the
/// container".
fn open_reason_needles(reason: &str) -> &'static [&'static str] {
    match reason {
        "missing_required_file" => &["missing manifest.json", "missing provenance/envelope.json"],
        "invalid_json" => &["failed to parse manifest.json"],
        "duplicate_entry" => &["duplicate entry"],
        "unsafe_path" => &["parent-traversal", "path is absolute"],
        "unsupported_compression" => &["unsupported compression"],
        "symlink_entry" => &["symlink"],
        other => panic!("unknown open-stage reason {other:?}"),
    }
}

#[test]
fn malformed_registry_outcomes() {
    let path = vectors_dir().join("malformed-layout/vectors.json");
    let doc = load_json(&path);
    let base = path.parent().unwrap().to_path_buf();
    let allowlist = registry_allowlist(&doc, &base);
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty());
    for v in vectors {
        let name = v["name"].as_str().expect("name");
        let expected = &v["expected"];
        let result = verify_fixture(&base, &allowlist, v);
        if expected["stage"].as_str() == Some("open") {
            let reason = expected["reason"].as_str().expect("reason");
            let needles = open_reason_needles(reason);
            assert!(!result.ok, "{name}: open-stage fixture must not verify");
            let haystack = all_error_messages(&result).join(" ");
            assert!(
                needles.iter().any(|n| haystack.contains(n)),
                "{name}: expected an error matching reason {reason:?} (any of {needles:?}); got {haystack:?}"
            );
        } else {
            assert_verify_outcome(name, expected, &result);
        }
    }
}

#[test]
fn signing_input_pins() {
    let path = vectors_dir().join("signing-input.json");
    let doc = load_json(&path);
    let capsule_ref = doc
        .pointer("/meta/capsule_ref")
        .and_then(|v| v.as_str())
        .expect("meta.capsule_ref");
    let ref_doc = load_json(&vectors_dir().join(capsule_ref));
    let capsule_bytes = BASE64
        .decode(ref_doc["capsule_bytes_b64"].as_str().expect("capsule_bytes_b64"))
        .expect("base64 decode");
    let files = unpack_zip(&capsule_bytes).expect("capsule must unpack");

    let manifest: Value =
        serde_json::from_slice(files.get("manifest.json").expect("manifest.json")).unwrap();
    let envelope: Value = serde_json::from_slice(
        files
            .get("provenance/envelope.json")
            .expect("provenance/envelope.json"),
    )
    .unwrap();

    // capsule_id = SHA-256(domain || originator_pub_raw || first_event_hash_raw)
    let cid = &doc["capsule_id"];
    let domain = hex::decode(cid["domain_hex"].as_str().unwrap()).unwrap();
    assert_eq!(
        cid["domain_utf8"].as_str().unwrap().as_bytes(),
        domain.as_slice(),
        "capsule_id domain_utf8 / domain_hex disagree"
    );
    let preimage = [
        domain.as_slice(),
        &hex::decode(cid["originator_public_key_hex"].as_str().unwrap()).unwrap(),
        &hex::decode(cid["first_event_hash_hex"].as_str().unwrap()).unwrap(),
    ]
    .concat();
    let derived = sha256_hex(&preimage);
    assert_eq!(derived, cid["capsule_id_hex"].as_str().unwrap());
    assert_eq!(derived, manifest["id"].as_str().unwrap());

    // events: hash = SHA-256(prev_hash_raw || JCS(event minus hash))
    let jsonl = files.get("chain/events.jsonl").expect("chain/events.jsonl");
    let lines: Vec<&[u8]> = jsonl
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .collect();
    let pins = doc["events"].as_array().expect("events array");
    assert_eq!(lines.len(), pins.len(), "event count mismatch");
    for (pin, line) in pins.iter().zip(lines.iter()) {
        let mut event: Value = serde_json::from_slice(line).expect("event line parses");
        let stored_hash = event["hash"].as_str().expect("stored hash").to_string();
        event.as_object_mut().unwrap().remove("hash");
        let canon = jcs(&event);
        assert_eq!(
            hex::encode(&canon),
            pin["canonical_bytes_hex"].as_str().unwrap(),
            "event {} canonical bytes mismatch",
            pin["seq"]
        );
        let prev = hex::decode(pin["prev_hash_hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            event["prev_hash"].as_str().unwrap(),
            pin["prev_hash_hex"].as_str().unwrap()
        );
        let recomputed = sha256_hex(&[prev.as_slice(), canon.as_slice()].concat());
        assert_eq!(recomputed, pin["hash_hex"].as_str().unwrap());
        assert_eq!(recomputed, stored_hash);
    }

    // manifest_hash = SHA-256(JCS(manifest))
    let manifest_canon = jcs(&manifest);
    assert_eq!(
        hex::encode(&manifest_canon),
        doc.pointer("/manifest/canonical_bytes_hex").unwrap().as_str().unwrap()
    );
    let manifest_sha = sha256_hex(&manifest_canon);
    assert_eq!(
        manifest_sha,
        doc.pointer("/manifest/sha256_hex").unwrap().as_str().unwrap()
    );
    assert_eq!(manifest_sha, envelope["manifest_hash"].as_str().unwrap());

    // content_index_hash = SHA-256(JCS(content_index.files))
    let index_canon = jcs(manifest.pointer("/content_index/files").unwrap());
    assert_eq!(
        hex::encode(&index_canon),
        doc.pointer("/content_index/canonical_bytes_hex").unwrap().as_str().unwrap()
    );
    let index_sha = sha256_hex(&index_canon);
    assert_eq!(
        index_sha,
        doc.pointer("/content_index/sha256_hex").unwrap().as_str().unwrap()
    );
    assert_eq!(index_sha, envelope["content_index_hash"].as_str().unwrap());

    // envelope canonical payload = JCS(envelope minus signers); signing
    // input per role = domain_sep_bytes || canonical_payload_bytes.
    let mut env_minus = envelope.clone();
    env_minus.as_object_mut().unwrap().remove("signers");
    let env_canon = jcs(&env_minus);
    let canonical_payload_hex = doc
        .pointer("/envelope/canonical_payload_hex")
        .unwrap()
        .as_str()
        .unwrap();
    assert_eq!(hex::encode(&env_canon), canonical_payload_hex);
    assert_eq!(
        sha256_hex(&env_canon),
        doc.pointer("/envelope/canonical_payload_sha256").unwrap().as_str().unwrap()
    );

    let signer_pins = doc.pointer("/envelope/signers").unwrap().as_array().unwrap();
    let stored_signers = envelope["signers"].as_array().unwrap();
    assert_eq!(signer_pins.len(), stored_signers.len());
    for (pin, stored) in signer_pins.iter().zip(stored_signers.iter()) {
        assert_eq!(pin["role"], stored["role"]);
        assert_eq!(pin["public_key_hex"], stored["public_key"]);
        assert_eq!(pin["signature_hex"], stored["signature"]);
        let domain = hex::decode(pin["domain_hex"].as_str().unwrap()).unwrap();
        assert_eq!(pin["domain_utf8"].as_str().unwrap().as_bytes(), domain.as_slice());
        let input = [domain.as_slice(), env_canon.as_slice()].concat();
        assert_eq!(
            sha256_hex(&input),
            pin["signing_input_sha256"].as_str().unwrap()
        );
        let pk = hex::decode(pin["public_key_hex"].as_str().unwrap()).unwrap();
        let sig = hex::decode(pin["signature_hex"].as_str().unwrap()).unwrap();
        assert!(
            ed25519_verify(&pk, &input, &sig),
            "pinned signature must verify over reconstructed signing input"
        );
    }
}
