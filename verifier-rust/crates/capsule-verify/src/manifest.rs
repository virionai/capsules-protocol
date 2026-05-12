//! Manifest-level helpers: capsule_id derivation, content_index recompute,
//! manifest_hash. Mirrors `computeCapsuleId`, `buildContentIndex`,
//! `manifestHash`, and the `CONTENT_INDEX_EXCLUDED` set from
//! `sdk/src/manifest.js`.
//!
//! The functions here are pure: they take parsed schemas and per-file
//! byte maps, and return the strings or vectors the top-level verifier
//! needs to compare against the on-disk values.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::crypto::{bytes_to_hex, hex_to_bytes, sha256, sha256_hex, CryptoError};
use crate::jcs::jcs;
use crate::schemas::{ContentIndex, ContentIndexEntry, Manifest};

/// Domain separator for capsule_id derivation. Mirrors the JS SDK's
/// `Buffer.from("capsule-id-v0.6\x00", "utf8")` constant.
const CAPSULE_ID_DOMAIN: &[u8] = b"capsule-id-v0.6\x00";

/// Three paths excluded from the content index, by spec:
///   * `manifest.json` — the index lives inside it
///   * `provenance/envelope.json` — commits to the index hash already
///   * `content.enc` — bound separately by `envelope.encrypted_blob_hash`
///
/// Surfaced as both a constant (for callers that want a slice they can pass
/// to a helper) and a predicate (for callers that want a `match`-style
/// boolean check). Both are kept in sync — adding/removing an entry must be
/// done in one place. Tests in this module assert the two stay aligned.
pub const CONTENT_INDEX_EXCLUDED: &[&str] = &[
    "manifest.json",
    "provenance/envelope.json",
    "content.enc",
];

/// Predicate form of [`CONTENT_INDEX_EXCLUDED`] — returns `true` if `path`
/// is in the excluded set.
pub fn is_content_index_excluded(path: &str) -> bool {
    CONTENT_INDEX_EXCLUDED.contains(&path)
}

/// Errors returned by [`compute_capsule_id`].
#[derive(Debug, thiserror::Error)]
pub enum CapsuleIdError {
    #[error("originator pubkey must be 32 bytes")]
    BadOriginatorLength,
    #[error("first_event_hash must be 64-hex")]
    BadFirstEventHashShape,
    #[error("first_event_hash hex decode failed: {0}")]
    Hex(#[from] CryptoError),
}

/// Compute capsule_id as `sha256_hex(domain || originator_pubkey_raw ||
/// first_event_hash_raw)`, where `domain = b"capsule-id-v0.6\0"`.
///
/// Mirrors `computeCapsuleId` in `sdk/src/manifest.js`.
pub fn compute_capsule_id(
    originator_pubkey_raw: &[u8],
    first_event_hash_hex: &str,
) -> Result<String, CapsuleIdError> {
    if originator_pubkey_raw.len() != 32 {
        return Err(CapsuleIdError::BadOriginatorLength);
    }
    if first_event_hash_hex.len() != 64 {
        return Err(CapsuleIdError::BadFirstEventHashShape);
    }
    let feh_raw = hex_to_bytes(first_event_hash_hex)?;
    let mut input =
        Vec::with_capacity(CAPSULE_ID_DOMAIN.len() + originator_pubkey_raw.len() + feh_raw.len());
    input.extend_from_slice(CAPSULE_ID_DOMAIN);
    input.extend_from_slice(originator_pubkey_raw);
    input.extend_from_slice(&feh_raw);
    Ok(bytes_to_hex(&sha256(&input)))
}

/// Recompute the content index from per-file bytes.
///
/// Files in [`is_content_index_excluded`] are skipped. The output `files`
/// array is sorted by path (matching the JS reference's `sort` step), and
/// `index_hash = sha256_hex(jcs(files_as_value))`.
///
/// Mirrors `buildContentIndex` in `sdk/src/manifest.js`.
pub fn build_content_index(files: &BTreeMap<String, Vec<u8>>) -> ContentIndex {
    let mut entries: Vec<ContentIndexEntry> = Vec::new();
    for (path, bytes) in files {
        if is_content_index_excluded(path) {
            continue;
        }
        entries.push(ContentIndexEntry {
            path: path.clone(),
            sha256: sha256_hex(bytes),
        });
    }
    // BTreeMap iteration is already lexicographically sorted by path, so
    // the entries vector is sorted by construction. The explicit sort below
    // is a defensive belt-and-suspenders move that mirrors the JS step
    // exactly — useful if a future refactor swaps in a different map type
    // upstream.
    entries.sort_by(|a, b| a.path.cmp(&b.path));

    // Build a JSON Value of the array for canonicalization. Each entry is
    // an object with two string keys; serde_json::to_value cannot fail.
    let arr = Value::Array(
        entries
            .iter()
            .map(|e| json!({"path": e.path, "sha256": e.sha256}))
            .collect(),
    );
    let index_hash = sha256_hex(&jcs(&arr));
    ContentIndex {
        files: entries,
        index_hash,
    }
}

/// JCS-canonical bytes of a manifest, then SHA-256, lowercase hex.
///
/// Mirrors `manifestHash` in `sdk/src/manifest.js`. Goes through
/// `serde_json::to_value` so the canonicalization runs over the same shape
/// the JS reference's `JSON.stringify` would produce.
pub fn manifest_hash(manifest: &Manifest) -> String {
    let value = match serde_json::to_value(manifest) {
        Ok(v) => v,
        // Manifest contains only JSON-representable types; this branch is
        // unreachable in practice. We surface a clearly-wrong sentinel hash
        // rather than panicking so that the verifier stays panic-free for
        // any conceivable input.
        Err(_) => return "0".repeat(64),
    };
    sha256_hex(&jcs(&value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::clean_capsule_bytes;
    use crate::unpack_zip;

    fn load_clean() -> (Manifest, BTreeMap<String, Vec<u8>>) {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).unwrap();
        let manifest_bytes = map.get("manifest.json").unwrap();
        let manifest: Manifest = serde_json::from_slice(manifest_bytes).unwrap();
        (manifest, map)
    }

    #[test]
    fn capsule_id_matches_stored() {
        let (manifest, _) = load_clean();
        let pk = hex_to_bytes(&manifest.originator.public_key).unwrap();
        let id = compute_capsule_id(&pk, &manifest.first_event_hash).unwrap();
        assert_eq!(id, manifest.id);
    }

    #[test]
    fn capsule_id_rejects_short_pubkey() {
        let err = compute_capsule_id(&[0u8; 31], &"00".repeat(32)).unwrap_err();
        assert!(matches!(err, CapsuleIdError::BadOriginatorLength));
    }

    #[test]
    fn capsule_id_rejects_short_first_event_hash() {
        let err = compute_capsule_id(&[0u8; 32], "deadbeef").unwrap_err();
        assert!(matches!(err, CapsuleIdError::BadFirstEventHashShape));
    }

    #[test]
    fn content_index_matches_stored() {
        let (manifest, files) = load_clean();
        let recomputed = build_content_index(&files);
        assert_eq!(recomputed.index_hash, manifest.content_index.index_hash);
        assert_eq!(recomputed.files, manifest.content_index.files);
    }

    #[test]
    fn manifest_hash_is_deterministic() {
        let (manifest, _) = load_clean();
        let h1 = manifest_hash(&manifest);
        let h2 = manifest_hash(&manifest);
        assert_eq!(h1, h2);
        // 64 lowercase hex chars.
        assert_eq!(h1.len(), 64);
        assert!(h1.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    }

    #[test]
    fn excluded_set_is_correct() {
        assert!(is_content_index_excluded("manifest.json"));
        assert!(is_content_index_excluded("provenance/envelope.json"));
        assert!(is_content_index_excluded("content.enc"));
        assert!(!is_content_index_excluded("program.md"));
        assert!(!is_content_index_excluded("chain/events.jsonl"));
    }
}
