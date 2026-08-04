//! Version-compatibility policy (spec/versioning.md). Mirrors
//! `sdk-js/src/versions.js`.
//!
//! A capsule DECLARES its format era (`manifest.format.version` and
//! `envelope.version`), and every domain-separation string embeds that
//! version. This module is the known-version table and the version-keyed
//! selectors:
//!
//! - any KNOWN version verifies under that era's rules and constants,
//!   forever (the archival profile), with the observed version reported
//!   as a fact on the verify result;
//! - an UNKNOWN version fails closed with a diagnosis distinct from
//!   tamper detection ("this verifier is too old" is not "this capsule
//!   is corrupt");
//! - a version string violating the `<major>.<minor>` grammar is a
//!   malformed document, not a support gap.

/// Every format version this implementation knows, oldest → newest. A
/// version is never removed (spec/versioning.md: dropping a version a
/// verifier once knew is a conformance violation).
pub const KNOWN_VERSIONS: &[&str] = &["0.6", "0.7"];

/// The version this implementation targets when writing (none today —
/// this crate is a verifier — but the constant anchors the table).
pub const CURRENT_VERSION: &str = "0.7";

/// Per-era algorithm-suite identifier (spec/versioning.md "Algorithm
/// suites"): a v0.6 capsule names no algorithm anywhere in its bytes;
/// absence means the v0.6 suite (Ed25519 / SHA-256 / JCS RFC 8785 /
/// X25519 + HKDF-SHA-256 + ChaCha20-Poly1305), permanently. v0.7
/// introduces no algorithm changes and no agility: absence in a 0.7
/// capsule means the SAME v0.6 suite — the identifier names the
/// algorithm set by the era that introduced it, not the sealing era.
pub fn suite_for(version: &str) -> Option<&'static str> {
    match version {
        "0.6" | "0.7" => Some("v0.6"),
        _ => None,
    }
}

/// Closed classification vocabulary for a declared version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionStatus {
    /// In the known table; verification proceeds under that era's rules.
    Known,
    /// Orders after the newest known version: this verifier is too old
    /// for the capsule — a verifier limitation, not capsule corruption.
    UnknownNewer,
    /// Any other unknown version.
    UnknownOlder,
    /// Violates the `<major>.<minor>` grammar: a malformed document.
    Invalid,
}

impl VersionStatus {
    /// The machine-readable status token reported on the verify result.
    pub fn as_str(&self) -> &'static str {
        match self {
            VersionStatus::Known => "known",
            VersionStatus::UnknownNewer => "unknown_newer",
            VersionStatus::UnknownOlder => "unknown_older",
            VersionStatus::Invalid => "invalid",
        }
    }
}

/// Parse `<major>.<minor>` (decimal, no leading zeros).
fn parse_version(v: &str) -> Option<(u64, u64)> {
    let (major, minor) = v.split_once('.')?;
    fn component(s: &str) -> Option<u64> {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if s.len() > 1 && s.starts_with('0') {
            return None; // no leading zeros
        }
        s.parse().ok()
    }
    Some((component(major)?, component(minor)?))
}

/// Classify a declared version against the known-version table.
pub fn classify_version(v: &str) -> VersionStatus {
    let Some(parsed) = parse_version(v) else {
        return VersionStatus::Invalid;
    };
    if KNOWN_VERSIONS.contains(&v) {
        return VersionStatus::Known;
    }
    let newest = parse_version(KNOWN_VERSIONS[KNOWN_VERSIONS.len() - 1])
        .expect("KNOWN_VERSIONS entries are well-formed");
    if parsed > newest {
        VersionStatus::UnknownNewer
    } else {
        VersionStatus::UnknownOlder
    }
}

/// Standard diagnosis wording. The needles
/// "newer than this verifier supports" and
/// "older than any version this verifier supports" are the cross-lane
/// conformance contract (spec/vectors/version-compat/).
pub fn unsupported_version_message(field: &str, observed: &str, status: VersionStatus) -> String {
    match status {
        VersionStatus::UnknownNewer => format!(
            "{field} '{observed}' is newer than this verifier supports (newest known: {newest}); \
             this is a limitation of the verifier, not corruption of the capsule — verify it \
             with a newer implementation",
            newest = KNOWN_VERSIONS[KNOWN_VERSIONS.len() - 1],
        ),
        _ => format!(
            "{field} '{observed}' is older than any version this verifier supports \
             (oldest known: {oldest}); this is not evidence of tampering — verify it with an \
             implementation that retains the {observed} rules",
            oldest = KNOWN_VERSIONS[0],
        ),
    }
}

// ---------------------------------------------------------------------------
// Version-keyed domain-separation strings. A verifier that accepts a
// v0.6 capsule must retain the v0.6 strings forever, selected by the
// capsule's DECLARED version — never a single current constant.
// ---------------------------------------------------------------------------

/// `capsule-id-v<version>\0` — the capsule_id hash domain.
pub fn id_domain(version: &str) -> Vec<u8> {
    let mut out = format!("capsule-id-v{version}").into_bytes();
    out.push(0);
    out
}

/// `capsule-provenance-v<version>:<role>\0` — the signing-input domain.
pub fn provenance_domain(version: &str, role: &str) -> Vec<u8> {
    let mut out = format!("capsule-provenance-v{version}:{role}").into_bytes();
    out.push(0);
    out
}

/// `capsule-key-wrap-v<version>` — the HKDF info for recipient key wrap.
pub fn key_wrap_info(version: &str) -> Vec<u8> {
    format!("capsule-key-wrap-v{version}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_vocabulary() {
        assert_eq!(classify_version("0.6"), VersionStatus::Known);
        assert_eq!(classify_version("9.9"), VersionStatus::UnknownNewer);
        assert_eq!(classify_version("1.0"), VersionStatus::UnknownNewer);
        // Numeric ordering, not lexicographic: 0.10 > 0.6.
        assert_eq!(classify_version("0.10"), VersionStatus::UnknownNewer);
        assert_eq!(classify_version("0.1"), VersionStatus::UnknownOlder);
        assert_eq!(classify_version("banana"), VersionStatus::Invalid);
        assert_eq!(classify_version("0.6.1"), VersionStatus::Invalid);
        assert_eq!(classify_version("06.1"), VersionStatus::Invalid);
        assert_eq!(classify_version(""), VersionStatus::Invalid);
    }

    #[test]
    fn domain_strings_are_keyed_by_declared_version() {
        assert_eq!(id_domain("0.6"), b"capsule-id-v0.6\x00".to_vec());
        assert_eq!(id_domain("0.7"), b"capsule-id-v0.7\x00".to_vec());
        assert_eq!(
            provenance_domain("0.7", "notary"),
            b"capsule-provenance-v0.7:notary\x00".to_vec()
        );
        assert_eq!(key_wrap_info("0.7"), b"capsule-key-wrap-v0.7".to_vec());
    }
}
