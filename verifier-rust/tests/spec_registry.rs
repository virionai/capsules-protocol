//! Registry-driven conformance against `spec/vectors/`.
//!
//! Unlike `parity_against_js_sdk.rs` (which pins Rust-specific forensics
//! detail per fixture), these tests read the language-neutral outcome
//! registries directly, so the Rust lane tracks the same normative
//! expectations as the JS reference lane without hand-copied assertions:
//!
//!   - tamper-detection/vectors.json   (verify-stage outcomes)
//!   - malformed-layout/vectors.json   (open-stage reasons + verify-stage)
//!   - unknown-fields/vectors.json     (unknown-member preservation outcomes)
//!   - signer-set/vectors.json         (signer-set binding outcomes)
//!   - chain-binding/vectors.json      (empty-chain anchors + stored-line hashing)
//!   - chain-rules/vectors.json        (per-event actor + kind field rules)
//!   - signing-input.json              (byte-level signing/hashing pins)
//!   - jcs-key-order.json              (RFC 8785 §3.2.3 member ordering)
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
                "signer_set" => assert!(
                    !result.signer_set.ok,
                    "{name}: signer_set must fail; got {:?}",
                    result.signer_set
                ),
                "originator_binding" => assert!(
                    result
                        .errors
                        .iter()
                        .any(|e| e.message.contains("originator binding")),
                    "{name}: expected an originator binding error; got {:?}",
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
    if let Some(bound) = expected["signer_set_bound"].as_bool() {
        assert_eq!(
            result.signer_set.bound, bound,
            "{name}: expected signer_set.bound={bound}; got {:?}",
            result.signer_set
        );
    }
    // Actor-set binding (chain.md step 6) follows the signer-set
    // contract: a non-empty manifest.participants[] binds the chain's
    // actors; an empty one must be REPORTED as unbound, never rejected.
    if let Some(bound) = expected["actor_set_bound"].as_bool() {
        assert_eq!(
            result.actor_set.bound, bound,
            "{name}: expected actor_set.bound={bound}; got {:?}",
            result.actor_set
        );
    }
    // Honest-reporting pin: some rules require the verifier to REPORT a
    // weaker claim machine-readably (e.g. a zero-event chain that was not
    // walked), not just to pass/fail.
    if let Some(needle) = expected["notes_includes"].as_str() {
        assert!(
            result.notes.iter().any(|n| n.contains(needle)),
            "{name}: expected a note containing {needle:?}; got {:?}",
            result.notes
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

/// Unknown members in the hashed documents MUST be preserved and hashed
/// (spec/manifest.md "Unknown members", spec/envelope.md, spec/chain.md).
/// The positive vector carries `x-` extension members in manifest.json,
/// provenance/envelope.json, and a chain event, all covered by the seal;
/// it must verify ok=true. The tampered variants mutate an unknown member
/// post-seal and must fail in the pinned area — proving the members are
/// inside the integrity envelope, not decoration. A verifier that projects
/// the documents onto a fixed schema and re-serializes the projection for
/// hashing drops the members and fails the positive vector.
#[test]
fn unknown_fields_registry_outcomes() {
    let path = vectors_dir().join("unknown-fields/vectors.json");
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

/// Signer-set binding: PRESENCE BINDS, ABSENCE REPORTS
/// (spec/manifest.md "signer_commitment", spec/envelope.md "Signer set
/// binding"). A present manifest.signer_commitment must equal the
/// normalized envelope signer set exactly — strip / add / role-swap /
/// unsorted all fail closed; an absent one verifies with
/// signer_set.bound=false. Duplicate (role, public_key) signers are
/// malformed, and the manifest originator must have a valid
/// role-"originator" signature.
#[test]
fn signer_set_registry_outcomes() {
    let path = vectors_dir().join("signer-set/vectors.json");
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

/// Empty-chain anchor rule + stored-line hashing (spec/chain.md "Empty
/// chains"). A chain with zero events is legal — the weakest honest
/// shape — and then manifest.first_event_hash, envelope.first_event_hash
/// and envelope.entry_hash MUST all be null (claiming an anchor over
/// zero events fails closed; those anchors are the only envelope-to-
/// chain binding in a plain capsule). The verifier must REPORT that no
/// events were walked (notes pin). And an event whose stored bytes omit
/// the optional untrusted_payload_fields member must verify: the hash
/// preimage is the stored line, never a typed-struct round-trip.
#[test]
fn chain_binding_registry_outcomes() {
    let path = vectors_dir().join("chain-binding/vectors.json");
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

/// chain.md per-event field rules (verification steps 6 and 7). The
/// actor rule is conditional on the manifest's own claim: a non-empty
/// participants[] binds every event actor to the declared set or
/// `system:host` (fail-closed); an empty one verifies with
/// `actor_set.bound=false` plus a note — absence is a weaker claim made
/// honestly. The kind enum is closed in every tier. All three fixtures
/// are cryptographically well-formed, so only these rules decide them.
#[test]
fn chain_rule_registry_outcomes() {
    let path = vectors_dir().join("chain-rules/vectors.json");
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
        "directory_marker_shape" => &["directory marker shape"],
        "local_central_name_mismatch" => &["local/central name mismatch"],
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

/// JCS object-member ordering registry (RFC 8785 §3.2.3): members sort on
/// their UTF-16 code-unit sequences.
///
/// That is NOT Rust's `str` ordering. `str: Ord` compares UTF-8 bytes,
/// which is Unicode code-point order, and the two disagree whenever a
/// supplementary-plane key (>= U+10000, UTF-16 lead surrogate
/// 0xD800..0xDBFF) meets a key in U+E000..U+FFFF. This lane is correct by
/// construction because `serde_jcs` wraps keys in a `Utf16Key` whose `Ord`
/// compares `Vec<u16>` from `encode_utf16()`; the vectors pin that against
/// a future dependency bump or a hand-rolled replacement.
#[test]
fn jcs_key_order_registry() {
    let path = vectors_dir().join("jcs-key-order.json");
    let doc = load_json(&path);
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty(), "vector file is empty");
    for v in vectors {
        let name = v["name"].as_str().expect("name");
        let keys = v["keys"].as_array().expect("keys");
        // serde_json::Map is a BTreeMap here, so insertion order is
        // irrelevant: serde_jcs re-sorts on UTF-16 regardless.
        let mut map = serde_json::Map::new();
        for (i, k) in keys.iter().enumerate() {
            map.insert(
                k.as_str().expect("key is a string").to_string(),
                Value::from(i),
            );
        }
        let canon = jcs(&Value::Object(map));
        assert_eq!(
            hex::encode(&canon),
            v["canonical_utf8_hex"].as_str().expect("canonical_utf8_hex"),
            "{name}: canonical bytes"
        );
        assert_eq!(
            sha256_hex(&canon),
            v["sha256_hex"].as_str().expect("sha256_hex"),
            "{name}: sha256"
        );
    }
}

/// Ed25519 key/signature validation registry: small-order and
/// non-canonically encoded public keys, and non-reduced S, must be refused;
/// the positive control must still verify.
#[test]
fn ed25519_key_validation_registry() {
    let path = vectors_dir().join("ed25519-key-validation.json");
    let doc = load_json(&path);
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty());
    for v in vectors {
        let name = v["name"].as_str().expect("name");
        let pk = hex::decode(v["public_key_hex"].as_str().expect("public_key_hex")).unwrap();
        let msg = hex::decode(v["message_hex"].as_str().expect("message_hex")).unwrap();
        let sig = hex::decode(v["signature_hex"].as_str().expect("signature_hex")).unwrap();
        let expected = v["expected"]["valid"].as_bool().expect("expected.valid");
        assert_eq!(
            ed25519_verify(&pk, &msg, &sig),
            expected,
            "{name}: expected valid={expected} ({})",
            v["reason"]
        );
    }
}
