//! Profile declaration policy (spec/profiles.md). Mirrors
//! `sdk-js/src/profiles.js`.
//!
//! A capsule may DECLARE the verification profile that governs it —
//! `manifest.format.profile` and `envelope.profile`, mirroring the
//! `format.version` / `envelope.version` dyad. A verifier keeps a table of
//! the profiles it implements (keyed selection, exactly like the
//! known-version table) and:
//!
//! - treats ABSENCE of a declaration in a 0.6/0.7 capsule as the default
//!   profile `v0.6-suite` version `1.0`, permanently — the mirror of the
//!   algorithm-suite pin in spec/versioning.md;
//! - requires the two documents' NORMALIZED declarations (absence = default)
//!   to agree; a capsule whose pairs differ is ambiguous about which rules
//!   bind it and fails closed BEFORE any table lookup (`profile_mismatch` —
//!   a defect of the capsule);
//! - FAILS CLOSED on a declared `(id, version)` pair outside the table, with
//!   a diagnosis distinct from both tampering and malformation:
//!   `unsupported_profile` is a limitation of the verifier, never a defect
//!   of the capsule;
//! - treats a present declaration that violates the closed object shape or
//!   the identifier grammar as a MALFORMED document, not a support gap.
//!
//! The gate runs after the version gate and before anything else: applying
//! the wrong profile's rules — or silently downgrading to the defaults —
//! would manufacture mismatch errors indistinguishable from tampering,
//! versioning.md's confusion reproduced on the profile axis.

use serde_json::Value;

use crate::versions::parse_version;

/// The default profile: the envelope.md verification/encryption procedure
/// of the capsule's declared era with the v0.6 algorithm suite of
/// versioning.md. The id deliberately matches the suite fact (`v0.6`)
/// verifiers already report. Frozen forever — the absence rule makes this
/// spelling permanent.
pub const DEFAULT_PROFILE: (&str, &str) = ("v0.6-suite", "1.0");

/// Every `(id, version)` profile row this implementation applies.
/// Exact-match on the pair — no ranges, no compatibility semantics. A
/// profile once supported is supported forever (the archival rule applied
/// to profiles), and the default row of every known era is always present.
pub const SUPPORTED_PROFILES: &[(&str, &str)] = &[DEFAULT_PROFILE];

/// `profile-id = lowletter *63( lowletter / DIGIT / "-" / "." )`, with the
/// vendor fence: an id beginning `x-` MUST be vendor-scoped
/// `x-<vendor>-<name>`; ids not beginning `x-` are reserved to the spec,
/// exactly like non-`x-` member keys.
pub fn is_valid_profile_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-' || *b == b'.')
    {
        return false;
    }
    if id.ends_with('-') || id.ends_with('.') {
        return false;
    }
    if let Some(rest) = id.strip_prefix("x-") {
        // x-<vendor>-<name>: a non-empty vendor segment carrying no "-",
        // then a non-empty name.
        let Some((vendor, name)) = rest.split_once('-') else {
            return false;
        };
        if vendor.is_empty() || name.is_empty() {
            return false;
        }
    }
    true
}

/// `profile-ver`: the SAME grammar and parser as format versions
/// (spec/versioning.md) — `<major>.<minor>`, decimal, no leading zeros.
pub fn is_valid_profile_version(version: &str) -> bool {
    parse_version(version).is_some()
}

/// Shape problems for ONE document's PRESENT profile declaration. Returns
/// an empty vector for a well-formed declaration; every message is
/// prefixed with the offending field path (the `invalid_manifest_shape`
/// idiom). `envelope` applies the envelope-copy rules (no `params`: params
/// are single-sourced in the manifest so no second copy can diverge).
pub fn profile_declaration_problems(value: &Value, path: &str, envelope: bool) -> Vec<String> {
    let members = if envelope {
        "{ id, version }"
    } else {
        "{ id, version, params? }"
    };
    let mut problems = Vec::new();
    if value.is_null() {
        // null is NOT a declaration: the honest way to not declare is to
        // omit, and a second spelling of absence is a known typed-decoder
        // divergence across lanes.
        problems.push(format!(
            "{path} must be an object {members}; null is not a declaration — \
             omit the member to not declare"
        ));
        return problems;
    }
    let Some(object) = value.as_object() else {
        problems.push(format!(
            "{path} must be an object {members}, got {}",
            compact(value)
        ));
        return problems;
    };
    // The object is CLOSED: an uninterpretable member in the rule SELECTOR
    // is the capsule asserting something meaningless about what governs
    // it. Vendor freight rides in manifest params or x- members.
    let allowed: &[&str] = if envelope {
        &["id", "version"]
    } else {
        &["id", "version", "params"]
    };
    for key in object.keys() {
        if allowed.contains(&key.as_str()) {
            continue;
        }
        if envelope && key == "params" {
            problems.push(format!(
                "{path}.params is not allowed: params are single-sourced in manifest.format.profile"
            ));
        } else {
            problems.push(format!(
                "{path}.{key} is not a member of the closed profile object (exactly: {})",
                allowed.join(", ")
            ));
        }
    }
    let id = object.get("id");
    if !id.and_then(Value::as_str).is_some_and(is_valid_profile_id) {
        problems.push(format!(
            "{path}.id must be a profile identifier (1-64 bytes, lowercase letter first, \
             then lowercase letters, digits, '-' or '.'; 'x-' ids vendor-scoped as \
             x-<vendor>-<name>), got {}",
            compact_opt(id)
        ));
    }
    let version = object.get("version");
    if !version
        .and_then(Value::as_str)
        .is_some_and(is_valid_profile_version)
    {
        problems.push(format!(
            "{path}.version must be a '<major>.<minor>' version string, got {}",
            compact_opt(version)
        ));
    }
    if !envelope {
        if let Some(params) = object.get("params") {
            if !params.is_object() {
                problems.push(format!(
                    "{path}.params must be a JSON object, got {}",
                    compact(params)
                ));
            }
        }
    }
    problems
}

/// Closed status vocabulary for a classified declaration dyad
/// (spec/profiles.md "Reporting: the profile channel").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileStatus {
    /// No declaration, or the explicit era default: default rules apply
    /// (explicit default is exactly equivalent to absence — a redundant
    /// claim made honestly).
    Default,
    /// Declared alternate profile this reader implements, applied
    /// exclusively (unreachable in-era: the reference table holds one row).
    Supported,
    /// Declared alternate the reader does not implement: a limitation of
    /// the verifier, not a defect of the capsule.
    Unsupported,
    /// Normalized declarations disagree: the capsule is ambiguous about
    /// which rules bind it (a defect).
    Mismatched,
    /// A present member violates the closed shape or the grammar: a
    /// malformed document.
    Invalid,
    /// Read but not classified — the version gate refused first (profile
    /// semantics are era-scoped).
    Unevaluated,
    /// Could not be read at all: the fail-closed default.
    Unread,
}

impl ProfileStatus {
    /// The machine-readable status token reported on the verify result.
    pub fn as_str(&self) -> &'static str {
        match self {
            ProfileStatus::Default => "default",
            ProfileStatus::Supported => "supported",
            ProfileStatus::Unsupported => "unsupported",
            ProfileStatus::Mismatched => "mismatched",
            ProfileStatus::Invalid => "invalid",
            ProfileStatus::Unevaluated => "unevaluated",
            ProfileStatus::Unread => "unread",
        }
    }
}

/// A normalized `(id, version)` declaration pair — absence normalized to
/// the era default.
pub type ProfilePair = (String, String);

/// The classification of one capsule's declaration dyad. Total and never
/// failing: refusal is a `status`, not an error.
#[derive(Debug, Clone)]
pub struct ProfileClassification {
    /// The declared id as read — reported even on refusal and even when
    /// invalid (the observed fact). On a dyad mismatch these are the
    /// manifest values; when the manifest is silent, the envelope's.
    pub observed: Option<String>,
    pub observed_version: Option<String>,
    /// Whether a declaration was present in either document.
    pub declared: bool,
    /// The profile actually applied; `None` whenever no profile's rules
    /// were applied.
    pub effective: Option<String>,
    pub effective_version: Option<String>,
    pub supported: bool,
    pub status: ProfileStatus,
    /// Field-path-prefixed shape problems (status `Invalid` only).
    pub problems: Vec<String>,
    /// Both NORMALIZED pairs (status `Mismatched` only), manifest first.
    pub normalized: Option<(ProfilePair, ProfilePair)>,
}

/// Classify the (manifest, envelope) declaration dyad against this
/// implementation's table. Pass the raw member values (`None` when the
/// member is absent; `Some(Value::Null)` for a present `null`, which is
/// malformed). Pure and total.
///
/// The caller is responsible for gate ORDER: classify only after both
/// documents pass the version gate (the absence rule is era-keyed).
pub fn classify_profile(
    manifest_decl: Option<&Value>,
    envelope_decl: Option<&Value>,
) -> ProfileClassification {
    let declared = manifest_decl.is_some() || envelope_decl.is_some();
    let (observed, observed_version) = best_effort_observed(manifest_decl, envelope_decl);
    let base = ProfileClassification {
        observed,
        observed_version,
        declared,
        effective: None,
        effective_version: None,
        supported: false,
        status: ProfileStatus::Unread,
        problems: Vec::new(),
        normalized: None,
    };

    let mut problems = Vec::new();
    if let Some(decl) = manifest_decl {
        problems.extend(profile_declaration_problems(
            decl,
            "manifest.format.profile",
            false,
        ));
    }
    if let Some(decl) = envelope_decl {
        problems.extend(profile_declaration_problems(decl, "envelope.profile", true));
    }
    if !problems.is_empty() {
        return ProfileClassification {
            status: ProfileStatus::Invalid,
            problems,
            ..base
        };
    }

    // Normalized dyad equality: absence means the era default, so the
    // default declared in exactly one document is coherent (both readings
    // mean the default) — refusing it would punish a truthful statement.
    let manifest_pair = normalize(manifest_decl);
    let envelope_pair = normalize(envelope_decl);
    if manifest_pair != envelope_pair {
        // Mismatch BEFORE table lookup: the effective declaration does not
        // exist until the documents agree, and reporting a mismatched
        // capsule as "unsupported" would hand the auditor a false
        // remediation ("find a better verifier" for a defective capsule).
        return ProfileClassification {
            status: ProfileStatus::Mismatched,
            normalized: Some((manifest_pair, envelope_pair)),
            ..base
        };
    }

    let (id, version) = manifest_pair;
    if !SUPPORTED_PROFILES
        .iter()
        .any(|(pid, pver)| *pid == id && *pver == version)
    {
        return ProfileClassification {
            observed: Some(id),
            observed_version: Some(version),
            status: ProfileStatus::Unsupported,
            ..base
        };
    }
    let is_default = (id.as_str(), version.as_str()) == DEFAULT_PROFILE;
    ProfileClassification {
        status: if is_default {
            ProfileStatus::Default
        } else {
            ProfileStatus::Supported
        },
        effective: Some(id),
        effective_version: Some(version),
        supported: true,
        ..base
    }
}

/// Cross-lane refusal wording (spec/profiles.md, spec/results.md). The
/// needles "is not supported by this verifier" and "this is a limitation
/// of the verifier, not corruption of the capsule" are the conformance
/// contract (spec/vectors/profile-declaration/).
pub fn unsupported_profile_message(id: &str, version: &str) -> String {
    let supported = SUPPORTED_PROFILES
        .iter()
        .map(|(pid, pver)| format!("{pid}/{pver}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "profile '{id}' version '{version}' is not supported by this verifier \
         (supported: {supported}); this is a limitation of the verifier, not corruption \
         of the capsule — verify it with an implementation of that profile"
    )
}

/// Cross-lane mismatch wording: both NORMALIZED pairs quoted.
pub fn profile_mismatch_message(manifest: &ProfilePair, envelope: &ProfilePair) -> String {
    format!(
        "envelope.profile does not match manifest.format.profile: manifest normalizes to \
         '{}' version '{}', envelope normalizes to '{}' version '{}' (absence means the era \
         default {}/{}); the capsule is ambiguous about which rules bind it",
        manifest.0, manifest.1, envelope.0, envelope.1, DEFAULT_PROFILE.0, DEFAULT_PROFILE.1
    )
}

/// The declared id/version as read, without judging either: the observed
/// fact a refusing reader is still allowed to report.
fn best_effort_observed(
    manifest_decl: Option<&Value>,
    envelope_decl: Option<&Value>,
) -> (Option<String>, Option<String>) {
    let source = manifest_decl
        .filter(|v| v.is_object())
        .or(envelope_decl.filter(|v| v.is_object()));
    let member = |key: &str| {
        source
            .and_then(|v| v.get(key))
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    (member("id"), member("version"))
}

/// Normalize one document's declaration to `(id, version)`, treating
/// ABSENCE as the era default. Only called on well-formed declarations.
fn normalize(decl: Option<&Value>) -> ProfilePair {
    match decl {
        None => (DEFAULT_PROFILE.0.to_string(), DEFAULT_PROFILE.1.to_string()),
        Some(v) => (
            v.get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            v.get("version")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        ),
    }
}

/// Compact JSON rendering for a diagnosis, matching the JS reference's
/// `JSON.stringify(value)`.
fn compact(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
}

/// The same, for an absent member (rendered `null` — the member is not
/// there to quote).
fn compact_opt(value: Option<&Value>) -> String {
    value.map(compact).unwrap_or_else(|| "null".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn identifier_grammar() {
        assert!(is_valid_profile_id("v0.6-suite"));
        assert!(is_valid_profile_id("x-acme-kms-es256"));
        assert!(is_valid_profile_id("a"));
        assert!(is_valid_profile_id(&"a".repeat(64)));
        // Uppercase, spaces, punctuation: a rule selector no reader can
        // parse is a meaningless self-assertion.
        assert!(!is_valid_profile_id("Acme KMS!"));
        assert!(!is_valid_profile_id(""));
        assert!(!is_valid_profile_id(&"a".repeat(65)));
        assert!(!is_valid_profile_id("0abc"), "must start with a letter");
        assert!(!is_valid_profile_id("abc-"), "no trailing '-'");
        assert!(!is_valid_profile_id("abc."), "no trailing '.'");
        // The vendor fence: `x-` ids must be vendor-scoped.
        assert!(!is_valid_profile_id("x-acme"));
        assert!(!is_valid_profile_id("x--acme"));
    }

    #[test]
    fn version_grammar_is_the_format_version_grammar() {
        assert!(is_valid_profile_version("1.0"));
        assert!(is_valid_profile_version("9.9"));
        assert!(!is_valid_profile_version("1"));
        assert!(!is_valid_profile_version("1.0.0"));
        assert!(!is_valid_profile_version("01.0"));
    }

    #[test]
    fn absence_means_the_default_profile() {
        let cls = classify_profile(None, None);
        assert_eq!(cls.status, ProfileStatus::Default);
        assert!(!cls.declared);
        assert_eq!(cls.observed, None);
        assert_eq!(cls.effective.as_deref(), Some("v0.6-suite"));
        assert_eq!(cls.effective_version.as_deref(), Some("1.0"));
        assert!(cls.supported);
    }

    #[test]
    fn explicit_default_is_equivalent_to_absence() {
        let decl = json!({ "id": "v0.6-suite", "version": "1.0" });
        let both = classify_profile(Some(&decl), Some(&decl));
        assert_eq!(both.status, ProfileStatus::Default);
        assert!(both.declared);
        assert_eq!(both.effective.as_deref(), Some("v0.6-suite"));
        // Declared in exactly one document: both readings mean the
        // default, so the capsule is coherent and verifies.
        let one = classify_profile(Some(&decl), None);
        assert_eq!(one.status, ProfileStatus::Default);
        assert!(one.declared);
    }

    #[test]
    fn unknown_pair_is_a_verifier_limitation() {
        let decl = json!({ "id": "x-test-kms-1", "version": "1.0" });
        let cls = classify_profile(Some(&decl), Some(&decl));
        assert_eq!(cls.status, ProfileStatus::Unsupported);
        assert_eq!(cls.observed.as_deref(), Some("x-test-kms-1"));
        assert_eq!(cls.observed_version.as_deref(), Some("1.0"));
        assert_eq!(cls.effective, None, "no profile's rules were applied");
        // Exact-match on the PAIR: a known id with an unknown version is
        // not understood, period.
        let bad_version = json!({ "id": "v0.6-suite", "version": "9.9" });
        assert_eq!(
            classify_profile(Some(&bad_version), Some(&bad_version)).status,
            ProfileStatus::Unsupported
        );
    }

    #[test]
    fn disagreeing_documents_are_a_capsule_defect() {
        let vendor = json!({ "id": "x-test-kms-1", "version": "1.0" });
        let default = json!({ "id": "v0.6-suite", "version": "1.0" });
        let value = classify_profile(Some(&vendor), Some(&default));
        assert_eq!(value.status, ProfileStatus::Mismatched);
        let (m, e) = value.normalized.expect("normalized pairs");
        assert_eq!(m.0, "x-test-kms-1");
        assert_eq!(e.0, "v0.6-suite");
        // A silent envelope normalizes to the default, so presence
        // mismatch is exactly as ambiguous as value mismatch.
        assert_eq!(
            classify_profile(Some(&vendor), None).status,
            ProfileStatus::Mismatched
        );
    }

    #[test]
    fn malformed_declarations_are_never_unsupported() {
        let cases = [
            json!(null),
            json!("v0.6-suite"),
            json!({ "id": "Acme KMS!", "version": "1.0" }),
            json!({ "id": "v0.6-suite", "version": "1.0", "critical": ["id"] }),
            json!({ "id": "v0.6-suite" }),
            json!({ "id": "v0.6-suite", "version": "1.0", "params": "nope" }),
        ];
        for case in cases {
            let cls = classify_profile(Some(&case), None);
            assert_eq!(
                cls.status,
                ProfileStatus::Invalid,
                "{case} must be malformed, not a support gap"
            );
            assert!(
                cls.problems
                    .iter()
                    .all(|p| p.starts_with("manifest.format.profile")),
                "shape problems are field-path prefixed; got {:?}",
                cls.problems
            );
            assert!(
                !cls.problems.iter().any(|p| p.contains("unsupported")),
                "malformed is a defect of the capsule, never a support gap: {:?}",
                cls.problems
            );
        }
    }

    #[test]
    fn envelope_copy_carries_no_params() {
        let decl = json!({ "id": "v0.6-suite", "version": "1.0", "params": { "a": 1 } });
        // Legal in the manifest, malformed in the envelope: params are
        // single-sourced so no second copy can diverge.
        assert_eq!(
            classify_profile(Some(&decl), None).status,
            ProfileStatus::Default
        );
        let cls = classify_profile(None, Some(&decl));
        assert_eq!(cls.status, ProfileStatus::Invalid);
        assert!(
            cls.problems.iter().any(|p| p.contains("single-sourced")),
            "got {:?}",
            cls.problems
        );
    }

    #[test]
    fn refusal_wording_carries_the_cross_lane_needles() {
        let unsupported = unsupported_profile_message("x-test-kms-1", "1.0");
        assert!(unsupported.contains("profile 'x-test-kms-1' version '1.0' is not supported by this verifier"));
        assert!(unsupported.contains(
            "this is a limitation of the verifier, not corruption of the capsule — \
             verify it with an implementation of that profile"
        ));
        let mismatch = profile_mismatch_message(
            &("x-test-kms-1".to_string(), "1.0".to_string()),
            &("v0.6-suite".to_string(), "1.0".to_string()),
        );
        assert!(mismatch.contains("envelope.profile does not match manifest.format.profile"));
        assert!(mismatch.contains("'x-test-kms-1' version '1.0'"));
        assert!(mismatch.contains("'v0.6-suite' version '1.0'"));
    }
}
