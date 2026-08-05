//! Registry-driven conformance against `spec/vectors/`.
//!
//! Unlike `parity_against_js_sdk.rs` (which pins Rust-specific forensics
//! detail per fixture), these tests read the language-neutral outcome
//! registries directly, so the Rust lane tracks the same normative
//! expectations as the JS reference lane without hand-copied assertions:
//!
//!   - tamper-detection/vectors.json   (verify-stage outcomes)
//!   - malformed-layout/vectors.json   (open-stage reasons + verify-stage)
//!   - malformed-shape/vectors.json    (manifest/chain document shape rules)
//!   - unknown-fields/vectors.json     (unknown-member preservation outcomes)
//!   - signer-set/vectors.json         (signer-set binding outcomes)
//!   - chain-binding/vectors.json      (empty-chain anchors + stored-line hashing)
//!   - chain-rules/vectors.json        (per-event actor + kind field rules)
//!   - profile-declaration/vectors.json (the profile gate + its refusals)
//!   - result-vocabulary/vectors.json  (verdict / reason / qualifiers)
//!   - signing-input.json              (byte-level signing/hashing pins)
//!   - jcs-key-order.json              (RFC 8785 §3.2.3 member ordering)
//!   - ijson-acceptance.json           (the I-JSON canonicalization input domain)
//!   - lineage/vectors.json            (manifest.predecessors: fail-closed
//!     standalone checks + report-only supplied-bytes linkage)
//!   - unicode-boundary/vectors.json   (Pith-truncated astral text verifies)
//!   - pith-authoring/vectors.json     (verbatim technical prose + the
//!                                      pith_normalized_fields marker verify)
//!
//! The registry's `reason` categories are normative; the substring tables
//! below map each category onto this lane's error messages.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use capsule_verify::{
    check_ijson, ed25519_verify, jcs, sha256_hex, unpack_zip, verify_capsule, VerifyOptions,
    VerifyResult,
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
    // Lineage entry errors are REPORT-ONLY (they never join
    // result.errors), but their diagnoses are pinned wording.
    out.extend(
        result
            .lineage
            .entries
            .iter()
            .flat_map(|e| e.errors.iter().cloned()),
    );
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
                "lineage" => assert!(
                    !result.lineage.ok,
                    "{name}: lineage must fail; got {:?}",
                    result.lineage
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
    // walked), not just to pass/fail. A string pins one substring; an
    // array pins several (e.g. the lineage phrases "declared, not
    // verified" AND "not countersigned").
    let note_needles: Vec<&str> = match &expected["notes_includes"] {
        Value::String(s) => vec![s.as_str()],
        Value::Array(items) => items
            .iter()
            .map(|n| n.as_str().expect("notes_includes entry"))
            .collect(),
        _ => Vec::new(),
    };
    for needle in note_needles {
        assert!(
            result.notes.iter().any(|n| n.contains(needle)),
            "{name}: expected a note containing {needle:?}; got {:?}",
            result.notes
        );
    }
    // The capsule's identity is a reported fact some vectors pin (e.g.
    // the same-id-zero-event-rewrap and unendorsed-successor ids).
    if let Some(want) = expected["capsule_id"].as_str() {
        assert_eq!(
            result.capsule_id, want,
            "{name}: expected capsule_id {want}"
        );
    }
    assert_lineage_outcome(name, expected, result);
    assert_result_vocabulary(name, expected, result);
    // Skill-trust derivation (spec/trust.md "Skill trust"): the tier MUST
    // come from the verify result — capsule_signed plus the exact per-id
    // map — never from any skill_trust member in the capsule itself.
    if let Some(want) = expected.get("skill_trust") {
        let want_signed = want["capsule_signed"].as_bool().expect("capsule_signed");
        assert_eq!(
            result.skill_trust.capsule_signed, want_signed,
            "{name}: expected skill_trust.capsule_signed={want_signed}; got {:?}",
            result.skill_trust
        );
        let want_skills: std::collections::BTreeMap<String, String> = want["skills"]
            .as_object()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().expect("tier").to_string()))
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(
            result.skill_trust.skills, want_skills,
            "{name}: skill_trust.skills mismatch"
        );
    }
}

/// The lineage area (spec/lineage.md "Reporting"), ignore-if-absent per
/// the shared outcome-schema contract so every collection parses.
/// `expected.lineage` pins declared / ok / verified_depth and, when
/// present, per-entry status / hop / reason / identity_checked /
/// capsule_id plus the supplied artifact's observed version. The three
/// lineage QUALIFIERS ride `expected.qualifiers`, asserted once by
/// [`assert_result_vocabulary`] alongside the seven base names.
fn assert_lineage_outcome(name: &str, expected: &Value, result: &VerifyResult) {
    if let Some(want) = expected.get("lineage") {
        let got = &result.lineage;
        if let Some(declared) = want["declared"].as_bool() {
            assert_eq!(got.declared, declared, "{name}: lineage.declared");
        }
        if let Some(ok) = want["ok"].as_bool() {
            assert_eq!(got.ok, ok, "{name}: lineage.ok; got {got:?}");
        }
        if let Some(depth) = want["verified_depth"].as_u64() {
            assert_eq!(
                got.verified_depth as u64, depth,
                "{name}: lineage.verified_depth; got {got:?}"
            );
        }
        if let Some(entries) = want["entries"].as_array() {
            assert_eq!(
                got.entries.len(),
                entries.len(),
                "{name}: lineage entry count; got {:?}",
                got.entries
            );
            for (i, want_entry) in entries.iter().enumerate() {
                let got_entry = &got.entries[i];
                if let Some(status) = want_entry["status"].as_str() {
                    assert_eq!(
                        got_entry.status, status,
                        "{name}: lineage.entries[{i}].status; got {got_entry:?}"
                    );
                }
                if let Some(hop) = want_entry["hop"].as_u64() {
                    assert_eq!(
                        got_entry.hop as u64, hop,
                        "{name}: lineage.entries[{i}].hop"
                    );
                }
                if let Some(reason) = want_entry["reason"].as_str() {
                    assert_eq!(
                        got_entry.reason.as_deref(),
                        Some(reason),
                        "{name}: lineage.entries[{i}].reason"
                    );
                }
                if let Some(capsule_id) = want_entry["capsule_id"].as_str() {
                    assert_eq!(
                        got_entry.capsule_id.as_deref(),
                        Some(capsule_id),
                        "{name}: lineage.entries[{i}].capsule_id"
                    );
                }
                if let Some(checked) = want_entry["identity_checked"].as_bool() {
                    assert_eq!(
                        got_entry.identity_checked, checked,
                        "{name}: lineage.entries[{i}].identity_checked"
                    );
                }
                if let Some(version) = want_entry["artifact_observed_version"].as_str() {
                    assert_eq!(
                        got_entry
                            .artifact
                            .as_ref()
                            .and_then(|a| a.observed_version.as_deref()),
                        Some(version),
                        "{name}: lineage.entries[{i}].artifact.observed_version"
                    );
                }
                // A FLOOR, not an equality: the count is lane-local, so
                // only the honesty invariant is pinned — an artifact
                // reported as failing never also reports zero errors.
                if let Some(floor) = want_entry["artifact_error_count_min"].as_u64() {
                    let got_count = got_entry
                        .artifact
                        .as_ref()
                        .map_or(0, |a| a.error_count as u64);
                    assert!(
                        got_count >= floor,
                        "{name}: lineage.entries[{i}].artifact.error_count >= {floor}; got {got_count}"
                    );
                }
            }
        }
    }
}

/// The lineage linkage pool (spec/lineage.md): per-vector `predecessors`
/// names checked-in artifacts relative to the collection file, supplied
/// to the verify call. REPORT-ONLY by design — the vectors pin that the
/// pool never flips the capsule's own `ok`.
fn vector_predecessors(base: &Path, vector: &Value) -> Vec<Vec<u8>> {
    vector["predecessors"]
        .as_array()
        .map(|pool| {
            pool.iter()
                .map(|rel| {
                    let rel = rel.as_str().expect("predecessors entry");
                    std::fs::read(base.join(rel))
                        .unwrap_or_else(|e| panic!("read predecessor {rel:?}: {e}"))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The normalized verdict surface (spec/results.md) and the profile
/// channel (spec/profiles.md), asserted on BOTH the verify-stage results
/// and the fail-closed results of open-stage vectors — the observed facts
/// are what keep "this verifier is too old / lacks this profile" apart
/// from "this capsule is corrupt".
///
/// `expected.qualifiers` is an EXACT array in the spec-defined order,
/// compared after stripping `x-` vendor entries from the result: emission
/// cannot drift by omission or by invention.
fn assert_result_vocabulary(name: &str, expected: &Value, result: &VerifyResult) {
    if let Some(want) = expected["verdict"].as_str() {
        assert_eq!(
            result.verdict.as_str(),
            want,
            "{name}: expected verdict={want:?}; errors: {:?}",
            result.errors
        );
        assert_eq!(
            result.ok,
            want == "valid",
            "{name}: ok == (verdict == 'valid') is an invariant"
        );
    }
    if expected.get("verdict_reason").is_some() {
        let want = expected["verdict_reason"].as_str();
        assert_eq!(
            result.verdict_reason.as_deref(),
            want,
            "{name}: expected verdict_reason={want:?}"
        );
    }
    if let Some(want) = expected["qualifiers"].as_array() {
        let want: Vec<&str> = want
            .iter()
            .map(|q| q.as_str().expect("qualifier name"))
            .collect();
        // ONE exact-array comparison for the whole TEN-name vocabulary —
        // the seven base names and the three lineage names ride the same
        // member, so a lineage vector pins the base qualifiers its fixture
        // genuinely produces and vice versa.
        let got: Vec<&str> = result
            .qualifiers
            .iter()
            .map(String::as_str)
            .filter(|q| !q.starts_with("x-"))
            .collect();
        assert_eq!(got, want, "{name}: qualifiers must match exactly");
    }
    // The observed declaration, reported even on refusal.
    if expected.get("observed_profile").is_some() {
        assert_eq!(
            result.profile.observed.as_deref(),
            expected["observed_profile"].as_str(),
            "{name}: expected profile.observed"
        );
    }
    if expected.get("observed_profile_version").is_some() {
        assert_eq!(
            result.profile.observed_version.as_deref(),
            expected["observed_profile_version"].as_str(),
            "{name}: expected profile.observed_version"
        );
    }
    if let Some(want) = expected["profile"].as_object() {
        for (key, value) in want {
            let got = match key.as_str() {
                "observed" => Value::from(result.profile.observed.clone()),
                "observed_version" => Value::from(result.profile.observed_version.clone()),
                "declared" => Value::from(result.profile.declared),
                "effective" => Value::from(result.profile.effective.clone()),
                "effective_version" => Value::from(result.profile.effective_version.clone()),
                "supported" => Value::from(result.profile.supported),
                "status" => Value::from(result.profile.status.clone()),
                other => panic!("{name}: unknown expected.profile key {other:?}"),
            };
            assert_eq!(&got, value, "{name}: expected profile.{key}={value}");
        }
    }
    // Suite honesty: the suite fact nulls whenever the effective profile
    // is not the era default, including on every profile-gate refusal.
    if expected.get("suite").is_some() {
        assert_eq!(
            result.format_version.suite.as_deref(),
            expected["suite"].as_str(),
            "{name}: expected format_version.suite"
        );
    }
}

/// Resolve a per-vector `allowlist` of keypair NAMES against the
/// collection's keys_file (`[]` = verify with no allowlist).
fn named_allowlist(name: &str, keys: &Value, entries: &Value) -> Vec<String> {
    entries
        .as_array()
        .expect("per-vector allowlist")
        .iter()
        .map(|entry| {
            let key_name = entry.as_str().expect("allowlist name");
            keys.pointer(&format!("/{key_name}/publicKey"))
                .and_then(|k| k.as_str())
                .unwrap_or_else(|| panic!("{name}: allowlist entry {key_name:?} not in keys_file"))
                .to_string()
        })
        .collect()
}

fn verify_fixture(base: &Path, allowlist: &[String], vector: &Value) -> VerifyResult {
    let file = vector["capsule_file"].as_str().expect("capsule_file");
    let bytes =
        std::fs::read(base.join(file)).unwrap_or_else(|e| panic!("read fixture {file:?}: {e}"));
    // Host version policy (spec/versioning.md "Host policy"): reported,
    // never decided — but only reachable when a vector declares it.
    let accept_versions = vector["accept_versions"].as_array().map(|versions| {
        versions
            .iter()
            .map(|v| v.as_str().expect("accept_versions entry").to_string())
            .collect()
    });
    verify_capsule(
        &bytes,
        &VerifyOptions {
            allowlist: allowlist.to_vec(),
            recipient_private_key: None,
            accept_versions,
            predecessors: vector_predecessors(base, vector),
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

/// Skill trust is DERIVED from the verify result, never read from the
/// capsule (spec/trust.md "Skill trust"). The same capsule bytes classify
/// differently at hosts with different allowlists, so each vector pins its
/// own trust configuration: the per-vector `allowlist` names keypairs in
/// keys_file ([] = verify with no allowlist). A lane that surfaces the
/// fixture's own `skill_trust` manifest member as trust hands
/// prompt-injection text to a host LLM as trusted instructions — the
/// defect (A01) this collection exists to keep closed.
#[test]
fn skill_trust_registry_outcomes() {
    let path = vectors_dir().join("skill-trust/vectors.json");
    let doc = load_json(&path);
    let base = path.parent().unwrap().to_path_buf();
    let keys = load_json(&base.join(doc["keys_file"].as_str().expect("keys_file")));
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty());
    for v in vectors {
        let name = v["name"].as_str().expect("name");
        let allowlist = named_allowlist(name, &keys, &v["allowlist"]);
        let result = verify_fixture(&base, &allowlist, v);
        assert_verify_outcome(name, &v["expected"], &result);
    }
}

/// spec/profiles.md: a capsule may DECLARE the verification profile that
/// governs it, and this verifier fails closed on any declaration it cannot
/// apply — with three distinguishable diagnoses, because they carry three
/// different remediations. `unsupported_profile` is a limitation of the
/// verifier (route the capsule to an implementation of that profile);
/// `profile_mismatch` is a capsule self-contradiction, diagnosed BEFORE
/// any table lookup (verdict `invalid`, never a verdict_reason); a shape
/// or grammar violation is a malformed document, never "unsupported".
/// Absence means the default profile `v0.6-suite`/`1.0` permanently, and
/// explicit declaration of the default is exactly equivalent to absence.
///
/// Every negative fixture is internally coherent under default rules
/// except the declaration under test — the declaration sits inside
/// `manifest_hash` and the signed envelope payload — so a lane that skips
/// the gate verifies it `ok: true` and fails here: each negative vector
/// doubles as the anti-silent-downgrade pin.
#[test]
fn profile_declaration_registry_outcomes() {
    let path = vectors_dir().join("profile-declaration/vectors.json");
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
            let needles: &[&str] = match reason {
                // This lane's profile shape problems are field-path
                // prefixed (the invalid_manifest_shape idiom) and can name
                // either document — the profile object is closed in both.
                "invalid_manifest_shape" => &["manifest.format.profile", "envelope.profile"],
                other => open_reason_needles(other),
            };
            assert!(!result.ok, "{name}: open-stage fixture must not verify");
            let haystack = all_error_messages(&result).join(" ");
            assert!(
                needles.iter().any(|n| haystack.contains(n)),
                "{name}: expected an error matching reason {reason:?} (any of {needles:?}); got {haystack:?}"
            );
            if reason == "invalid_manifest_shape" {
                assert!(
                    !haystack.contains("is not supported by this verifier"),
                    "{name}: a malformed declaration is a defect of the capsule, never a support gap"
                );
            }
            if let Some(observed) = expected["observed_version"].as_str() {
                assert_eq!(
                    result.format_version.observed.as_deref(),
                    Some(observed),
                    "{name}: the observed format version is reported even on refusal"
                );
            }
            // The refused capsule still REPORTS: the declaration it
            // carried, the verdict class, and the nulled suite fact.
            assert_result_vocabulary(name, expected, &result);
        } else {
            assert_verify_outcome(name, expected, &result);
        }
    }
}

/// spec/results.md: every verify result derives `verdict`,
/// `verdict_reason`, and `qualifiers` from facts it already carries. The
/// qualifiers are the weaker-claim facts a renderer must not hide beside a
/// valid verdict — an unbound signer set, an unwalked empty chain, an
/// unread encrypted payload, a version outside the host's accepted set, an
/// allowlist that was never supplied or matched nothing.
///
/// Several vectors verify the SAME capsule bytes under different host
/// configurations (per-vector `allowlist`, `accept_versions`): the
/// host-relative qualifiers are facts about THIS verification, which is
/// exactly why they can never be capsule members.
#[test]
fn result_vocabulary_registry_outcomes() {
    let path = vectors_dir().join("result-vocabulary/vectors.json");
    let doc = load_json(&path);
    let base = path.parent().unwrap().to_path_buf();
    let keys = load_json(&base.join(doc["keys_file"].as_str().expect("keys_file")));
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty());
    for v in vectors {
        let name = v["name"].as_str().expect("name");
        let expected = &v["expected"];
        if let Some(requires) = v["requires"].as_array() {
            for req in requires {
                // This lane implements every capability defined today;
                // fail loudly on one it does not know rather than skipping.
                assert_eq!(
                    req.as_str(),
                    Some("encryption"),
                    "{name}: unknown requirement {req:?}"
                );
            }
        }
        let mut allowlist = match v.get("allowlist") {
            Some(entries) => named_allowlist(name, &keys, entries),
            None => Vec::new(),
        };
        // `allowlist_literal` entries reach the verifier VERBATIM — never
        // resolved against keys_file, because a MALFORMED entry is by
        // construction one no keypair can produce. Allowlist hygiene
        // (spec/results.md: `trust_not_evaluated` is about the EFFECTIVE,
        // well-formed set) is otherwise inexpressible at the registry
        // surface, and it is exactly the rule that drifted apart across
        // lanes once. The vector drives the LIBRARY here: this lane's CLI
        // rejects a malformed --allowlist up front as a usage error, so
        // only the library surface can show the qualifier.
        if let Some(entries) = v["allowlist_literal"].as_array() {
            allowlist.extend(
                entries
                    .iter()
                    .map(|e| e.as_str().expect("allowlist_literal entry").to_string()),
            );
        }
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
            if let Some(observed) = expected["observed_version"].as_str() {
                assert_eq!(
                    result.format_version.observed.as_deref(),
                    Some(observed),
                    "{name}: the observed version is reported even on refusal"
                );
            }
            assert_result_vocabulary(name, expected, &result);
            continue;
        }
        assert_verify_outcome(name, expected, &result);

        // encrypted_outer_only is PER-RESULT: the outer L2 result of an
        // encrypted capsule carries it; the L3 result of the decrypted
        // inner — an ordinary plain-capsule verification — never does.
        if let Some(key_name) = expected["decryptable_with"].as_str() {
            let priv_hex = keys
                .pointer(&format!("/{key_name}/privateKey"))
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("{name}: keys_file has no {key_name}/privateKey"));
            let priv_bytes: [u8; 32] = hex::decode(priv_hex)
                .expect("private key hex")
                .try_into()
                .expect("private key must be 32 bytes");
            let file = v["capsule_file"].as_str().expect("capsule_file");
            let bytes = std::fs::read(base.join(file)).expect("read fixture");
            let l3 = verify_capsule(
                &bytes,
                &VerifyOptions {
                    allowlist: allowlist.clone(),
                    recipient_private_key: Some(priv_bytes),
                    accept_versions: None,
                    predecessors: Vec::new(),
                },
            );
            assert!(l3.ok, "{name}: L3 must verify; errors: {:?}", l3.errors);
            assert_eq!(l3.level, "L3", "{name}: level must upgrade to L3");
            assert!(
                !l3.qualifiers.iter().any(|q| q == "encrypted_outer_only"),
                "{name}: the L3 result read the content — it must not carry encrypted_outer_only; got {:?}",
                l3.qualifiers
            );
        }
    }
}

/// A JS-built capsule carrying Pith-truncated astral text must verify here.
/// A failure means this lane's canonicalization disagrees on well-formed
/// astral text — not that the capsule was tampered with.
#[test]
fn unicode_boundary_registry_outcomes() {
    let path = vectors_dir().join("unicode-boundary/vectors.json");
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

/// Pith is opt-in authoring (spec/pith.md); its marker is an ordinary member.
///
/// `technical-prose-verbatim`: a default-built capsule whose summary holds
/// dots inside an identifier and decimals, stored byte-identical, no marker.
/// `pith-normalized-marker`: a pith-enabled capsule whose event carries
/// `pith_normalized_fields` (spec/chain.md), covered by the event hash like
/// any other member. Both MUST verify ok:true; a failure means this lane
/// rejects or re-projects an optional event member, not tampering.
#[test]
fn pith_authoring_registry_outcomes() {
    let path = vectors_dir().join("pith-authoring/vectors.json");
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

/// Lineage (spec/lineage.md, `manifest.predecessors`). PRESENCE BINDS,
/// ABSENCE REPORTS: an absent member is "no claim" (declared=false,
/// reported); a PRESENT malformed declaration fails closed with the
/// shared `predecessors[i].<member>` diagnoses — never a lane-specific
/// parse crash, which is why this lane keeps the member raw in the typed
/// manifest view and diagnoses at check time.
///
/// Linkage against the supplied `predecessors` pool is REPORT-ONLY: it
/// can falsify the lineage AREA but never the capsule's overall `ok`.
/// The mismatch and predecessor_invalid vectors pin exactly that — a
/// host's file handling must not forge a forgery verdict against an
/// honest successor, and a lane that "helpfully" hardens this into an
/// overall failure is non-conforming.
#[test]
fn lineage_registry_outcomes() {
    let path = vectors_dir().join("lineage/vectors.json");
    let doc = load_json(&path);
    let base = path.parent().unwrap().to_path_buf();
    let allowlist = registry_allowlist(&doc, &base);
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty());
    for v in vectors {
        let name = v["name"].as_str().expect("name");
        if let Some(requires) = v["requires"].as_array() {
            for req in requires {
                // This lane implements every capability defined today;
                // fail loudly on one it does not know rather than skipping.
                assert_eq!(
                    req.as_str(),
                    Some("encryption"),
                    "{name}: unknown requirement {req:?}"
                );
            }
        }
        let expected = &v["expected"];
        let result = verify_fixture(&base, &allowlist, v);
        assert_verify_outcome(name, expected, &result);

        // Encrypted successors (spec/lineage.md): L2 evaluates the outer
        // declaration, L3 the inner plus the both-present JCS equality.
        // This lane runs L3 inside the same verification, so the inner
        // outcome is the same result verified WITH the recipient key.
        if let Some(key_name) = expected["decryptable_with"].as_str() {
            let keys = load_json(&base.join(doc["keys_file"].as_str().expect("keys_file")));
            let priv_hex = keys
                .pointer(&format!("/{key_name}/privateKey"))
                .and_then(|k| k.as_str())
                .unwrap_or_else(|| panic!("{name}: keys_file has no {key_name}/privateKey"));
            let priv_bytes: [u8; 32] = hex::decode(priv_hex)
                .expect("private key hex")
                .try_into()
                .expect("private key must be 32 bytes");
            let file = v["capsule_file"].as_str().expect("capsule_file");
            let bytes = std::fs::read(base.join(file)).expect("read fixture");
            let l3 = verify_capsule(
                &bytes,
                &VerifyOptions {
                    allowlist: allowlist.clone(),
                    recipient_private_key: Some(priv_bytes),
                    accept_versions: None,
                    predecessors: vector_predecessors(&base, v),
                },
            );
            let want_inner_ok = expected["inner_ok"].as_bool().unwrap_or(true);
            assert_eq!(
                l3.ok, want_inner_ok,
                "{name}: expected inner_ok={want_inner_ok}; errors: {:?}",
                l3.errors
            );
            if let Some(needle) = expected["inner_error_includes"].as_str() {
                let haystack = all_error_messages(&l3).join(" ");
                assert!(
                    haystack.contains(needle),
                    "{name}: expected an inner error containing {needle:?}; got {haystack:?}"
                );
            }
        }
    }
}

/// Normative reject-reason vocabulary from `ijson-acceptance.json`.
const IJSON_REASONS: &[&str] = &["integer_out_of_range", "unpaired_surrogate", "duplicate_member"];

/// `spec/canonicalization.md`: the acceptance boundary is identical in every
/// lane. A reject vector is satisfied by refusal at parse time OR at the
/// canonicalization gate — whichever this lane reaches first. In Rust
/// `serde_json` refuses lone-surrogate escapes at parse; `check_ijson`
/// refuses out-of-range integer literals.
#[test]
fn ijson_acceptance_boundary() {
    let path = vectors_dir().join("ijson-acceptance.json");
    let doc = load_json(&path);
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty());
    for v in vectors {
        let name = v["name"].as_str().expect("name");
        let text = v["input_json"].as_str().expect("input_json");
        let expect = v["expect"].as_str().expect("expect");
        // The lane's strict document parse: serde_json plus the
        // duplicate-member gate. Rejection here IS the parse-time refusal
        // the vector contract allows.
        let parsed: Value = match capsule_verify::parse_json_strict(text.as_bytes()) {
            Ok(value) => value,
            Err(e) => {
                assert_eq!(expect, "reject", "{name}: an accept vector must parse ({e})");
                continue;
            }
        };
        if expect == "accept" {
            check_ijson(&parsed).unwrap_or_else(|e| panic!("{name}: must be accepted: {e}"));
            let canonical = v["canonical"].as_str().expect("canonical");
            assert_eq!(
                String::from_utf8(jcs(&parsed)).expect("utf8"),
                canonical,
                "{name}"
            );
            continue;
        }
        assert_eq!(expect, "reject", "{name}: expect must be accept or reject");
        let reason = v["reason"].as_str().expect("reason");
        assert!(
            IJSON_REASONS.contains(&reason),
            "{name}: unknown reason {reason:?}"
        );
        assert!(
            check_ijson(&parsed).is_err(),
            "{name}: parsed, so the canonicalization gate must refuse it"
        );
    }
}

/// Per-lane mapping of the registry's normative verify-stage reason
/// categories (semantic-binding/vectors.json) onto this verifier's error
/// messages. Panics on an unknown category so a new reason cannot be
/// silently skipped.
fn verify_reason_needle(reason: &str) -> &'static str {
    match reason {
        "first_event_hash_binding" => "manifest.first_event_hash mismatch",
        "encryption_shape" => "manifest.encryption must be",
        "encryption_metadata_path" => "manifest.encryption.metadata_path",
        "cipher_without_blob" => "plain capsule must have cipher='none'",
        "blob_without_cipher" => "encrypted blob present but envelope.",
        other => panic!("unknown verify-stage reason {other:?}"),
    }
}

/// Manifest claims must agree with the signed envelope, the chain, and the
/// files (spec/manifest.md, spec/envelope.md). Every fixture is
/// well-formed and correctly signed; only its semantics are wrong.
/// `requires: ["encryption"]` vectors run here — this lane implements L3
/// decryption — and `decryptable_with` pins that the decryption metadata
/// is resolved through `manifest.encryption.metadata_path`, never a
/// hardcoded path.
#[test]
fn semantic_binding_registry_outcomes() {
    let path = vectors_dir().join("semantic-binding/vectors.json");
    let doc = load_json(&path);
    let base = path.parent().unwrap().to_path_buf();
    let allowlist = registry_allowlist(&doc, &base);
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty());
    for v in vectors {
        let name = v["name"].as_str().expect("name");
        if let Some(requires) = v["requires"].as_array() {
            for req in requires {
                // This lane implements every capability defined today;
                // fail loudly on one it does not know rather than skipping.
                assert_eq!(
                    req.as_str(),
                    Some("encryption"),
                    "{name}: unknown requirement {req:?}"
                );
            }
        }
        let expected = &v["expected"];
        let result = verify_fixture(&base, &allowlist, v);
        assert_verify_outcome(name, expected, &result);

        if let Some(reason) = expected["reason"].as_str() {
            let needle = verify_reason_needle(reason);
            let haystack = all_error_messages(&result).join(" ");
            assert!(
                haystack.contains(needle),
                "{name}: expected an error for reason {reason:?} ({needle:?}); got {haystack:?}"
            );
        }

        if let Some(key_name) = expected["decryptable_with"].as_str() {
            let keys = load_json(&base.join(doc["keys_file"].as_str().expect("keys_file")));
            let priv_hex = keys
                .pointer(&format!("/{key_name}/privateKey"))
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("{name}: keys_file has no {key_name}/privateKey"));
            let priv_bytes: [u8; 32] = hex::decode(priv_hex)
                .expect("private key hex")
                .try_into()
                .expect("private key must be 32 bytes");
            let file = v["capsule_file"].as_str().expect("capsule_file");
            let bytes = std::fs::read(base.join(file)).expect("read fixture");
            let l3 = verify_capsule(
                &bytes,
                &VerifyOptions {
                    allowlist: allowlist.clone(),
                    recipient_private_key: Some(priv_bytes),
                    accept_versions: None,
                    predecessors: Vec::new(),
                },
            );
            assert!(
                l3.ok,
                "{name}: L3 decrypt must follow manifest.encryption.metadata_path; errors: {:?}",
                l3.errors
            );
            assert_eq!(l3.level, "L3", "{name}: level must upgrade to L3");
        }
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
        // spec/versioning.md: unknown versions fail closed with a
        // diagnosis DISTINCT from malformation or tampering.
        "unsupported_version_newer" => &["newer than this verifier supports"],
        "unsupported_version_older" => &["older than any version this verifier supports"],
        // spec/profiles.md: a declared profile outside this verifier's
        // table is a LIMITATION OF THE VERIFIER (never corruption);
        // disagreeing declarations are a capsule defect, diagnosed before
        // any table lookup.
        "unsupported_profile" => &["is not supported by this verifier"],
        "profile_mismatch" => &["envelope.profile does not match manifest.format.profile"],
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

/// spec/versioning.md: known versions open and report; unknown fail closed
/// with a NON-TAMPER diagnosis. This lane has no separate "open" stage —
/// refusals surface as `FormatVersion` errors in the total verify result —
/// so the open-stage vectors map to: !ok, the pinned needle, the observed
/// version REPORTED on `result.format_version`, and (for the unknown-
/// version fixtures) no tamper-flavored errors from applying the wrong
/// era's rules.
#[test]
fn version_compat_registry_outcomes() {
    let path = vectors_dir().join("version-compat/vectors.json");
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
            let needles: &[&str] = match reason {
                // The typed manifest view parses "banana" fine (it is a
                // string); the version gate's grammar check names the
                // field path, this lane's invalid_manifest_shape idiom.
                "invalid_manifest_shape" => &["manifest.format.version"],
                other => open_reason_needles(other),
            };
            assert!(!result.ok, "{name}: open-stage fixture must not verify");
            let haystack = all_error_messages(&result).join(" ");
            assert!(
                needles.iter().any(|n| haystack.contains(n)),
                "{name}: expected an error matching reason {reason:?} (any of {needles:?}); got {haystack:?}"
            );
            // The same refusal at the NORMALIZED surface: verdict
            // "unsupported" with a machine-readable reason, so a host
            // never has to substring-match this lane's errors to tell an
            // unknown era from tampering. The envelope-side vector pins
            // that the refusal derives even when the MANIFEST's observed
            // version is known.
            assert_result_vocabulary(name, expected, &result);
        } else {
            assert_verify_outcome(name, expected, &result);
        }
        if let Some(observed) = expected["observed_version"].as_str() {
            // The observed version is a REPORTED fact even when the
            // capsule is refused — what lets an auditor tell "this
            // verifier is too old" apart from "this capsule is corrupt".
            assert_eq!(
                result.format_version.observed.as_deref(),
                Some(observed),
                "{name}: expected format_version.observed={observed:?}, got {:?}",
                result.format_version
            );
        }
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
fn malformed_shape_registry_outcomes() {
    let path = vectors_dir().join("malformed-shape/vectors.json");
    let doc = load_json(&path);
    let base = path.parent().unwrap().to_path_buf();
    let allowlist = registry_allowlist(&doc, &base);
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty());
    for v in vectors {
        let name = v["name"].as_str().expect("name");
        let expected = &v["expected"];
        let result = verify_fixture(&base, &allowlist, v);
        // Verify-stage vectors THIS lane legitimately refuses at parse:
        // serde_json rejects the hostile number literal (1e999) before a
        // manifest hash can be recomputed, which spec/canonicalization.md
        // blesses explicitly ("rejection may happen at JSON parse time or
        // at the canonicalization gate; both are conforming"). The pinned
        // error_includes ("manifest hash recompute failed") is the
        // canonicalization-gate wording, so assert the parse-time refusal
        // instead. Pinned by name so a lane that starts ACCEPTING the
        // value fails here.
        if name == "manifest-hostile-number" {
            assert!(!result.ok, "{name}: hostile number must not verify");
            let haystack = all_error_messages(&result).join(" ");
            assert!(
                haystack.contains("failed to parse manifest.json"),
                "{name}: expected a manifest parse refusal; got {haystack:?}"
            );
            continue;
        }
        if expected["stage"].as_str() == Some("open") {
            let reason = expected["reason"].as_str().expect("reason");
            let needles: &[&str] = match reason {
                // This lane's typed manifest view refuses the shapes the
                // registry names, so the reader-level refusal surfaces as
                // a manifest parse failure rather than a per-field path.
                "invalid_manifest_shape" => &["failed to parse manifest.json"],
                other => open_reason_needles(other),
            };
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
