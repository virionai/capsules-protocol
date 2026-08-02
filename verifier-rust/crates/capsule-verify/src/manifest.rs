//! Manifest-level helpers: capsule_id derivation, content_index recompute,
//! manifest_hash. Mirrors `computeCapsuleId`, `buildContentIndex`,
//! `manifestHash`, and the `CONTENT_INDEX_EXCLUDED` set from
//! `sdk-js/src/manifest.js`.
//!
//! The functions here are pure: they take parsed schemas and per-file
//! byte maps, and return the strings or vectors the top-level verifier
//! needs to compare against the on-disk values.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::crypto::{bytes_to_hex, hex_to_bytes, sha256, sha256_hex, CryptoError};
use crate::jcs::jcs;
use crate::schemas::{ContentIndex, ContentIndexEntry};

/// Domain separator for capsule_id derivation. Mirrors the JS SDK's
/// `Buffer.from("capsule-id-v0.6\x00", "utf8")` constant — now selected
/// BY the capsule's declared version via [`crate::versions::id_domain`]
/// (spec/versioning.md "Version-keyed domain separation").

/// Paths excluded from the content index by structural necessity, for every
/// capsule regardless of profile:
///   * `manifest.json` — the index lives inside it
///   * `provenance/envelope.json` — commits to the index hash already
pub const STRUCTURAL_EXCLUDED: &[&str] = &["manifest.json", "provenance/envelope.json"];

/// The exclusion set for an encrypted capsule: the structural files plus
/// `content.enc`, which is bound separately by `envelope.encrypted_blob_hash`.
///
/// `content.enc` is excluded ONLY for encrypted capsules. In a plain capsule
/// a stray `content.enc` must be indexed (and will therefore fail
/// verification), so a signed plain capsule cannot smuggle an unaccounted-for
/// blob past the verifier. Choose the set with [`content_index_exclusions`].
pub const CONTENT_INDEX_EXCLUDED: &[&str] =
    &["manifest.json", "provenance/envelope.json", "content.enc"];

/// Choose the content-index exclusion set for the capsule's profile, keyed on
/// whether the (signed) envelope declares a cipher.
pub fn content_index_exclusions(encrypted: bool) -> &'static [&'static str] {
    if encrypted {
        CONTENT_INDEX_EXCLUDED
    } else {
        STRUCTURAL_EXCLUDED
    }
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
/// `first_event_hash_hex: None` is the zero-event capsule shape
/// (spec/chain.md "Empty chains"): there is no first event, and the
/// derivation uses 32 zero bytes — the genesis prev-hash value — in
/// place of `first_event_hash_raw` (spec/manifest.md "Capsule identity").
///
/// Mirrors `computeCapsuleId` in `sdk-js/src/manifest.js`.
pub fn compute_capsule_id(
    originator_pubkey_raw: &[u8],
    first_event_hash_hex: Option<&str>,
    version: &str,
) -> Result<String, CapsuleIdError> {
    if originator_pubkey_raw.len() != 32 {
        return Err(CapsuleIdError::BadOriginatorLength);
    }
    let feh_raw: Vec<u8> = match first_event_hash_hex {
        None => vec![0u8; 32], // genesis stand-in for an empty chain
        Some(hex) => {
            if hex.len() != 64 {
                return Err(CapsuleIdError::BadFirstEventHashShape);
            }
            hex_to_bytes(hex)?
        }
    };
    let domain = crate::versions::id_domain(version);
    let mut input =
        Vec::with_capacity(domain.len() + originator_pubkey_raw.len() + feh_raw.len());
    input.extend_from_slice(&domain);
    input.extend_from_slice(originator_pubkey_raw);
    input.extend_from_slice(&feh_raw);
    Ok(bytes_to_hex(&sha256(&input)))
}

/// Recompute the content index from per-file bytes.
///
/// Files in `excluded` are skipped (pass [`STRUCTURAL_EXCLUDED`] for a plain
/// capsule, [`CONTENT_INDEX_EXCLUDED`] for an encrypted one — see
/// [`content_index_exclusions`]). The output `files` array is sorted by path
/// (matching the JS reference's `sort` step), and
/// `index_hash = sha256_hex(jcs(files_as_value))`.
///
/// Mirrors `buildContentIndex` in `sdk-js/src/manifest.js`.
pub fn build_content_index(
    files: &BTreeMap<String, Vec<u8>>,
    excluded: &[&str],
) -> ContentIndex {
    let mut entries: Vec<ContentIndexEntry> = Vec::new();
    for (path, bytes) in files {
        if excluded.contains(&path.as_str()) {
            continue;
        }
        entries.push(ContentIndexEntry {
            path: path.clone(),
            sha256: sha256_hex(bytes),
        });
    }
    // content_index.files is a JSON *array*, so this order is inside the
    // bytes index_hash covers — and this function runs on the verify path,
    // so the order has to match every other lane's, not merely be stable.
    //
    // BTreeMap iteration sorts by `str: Ord`, which is UTF-8 byte order ==
    // Unicode code-point order. That is NOT the RFC 8785 §3.2.3 order the
    // rest of the format uses: a supplementary-plane path (>= U+10000,
    // UTF-16 lead surrogate 0xD800..0xDBFF) sorts BELOW U+E000..U+FFFF in
    // UTF-16 and above it by code point. So this sort is load-bearing, not
    // defensive: it re-orders the map's iteration into the normative order.
    entries.sort_by(|a, b| a.path.encode_utf16().cmp(b.path.encode_utf16()));

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
/// Mirrors `manifestHash` in `sdk-js/src/manifest.js`. Takes the PRESERVED
/// `serde_json::Value` tree parsed from the on-disk `manifest.json` bytes —
/// never the typed `Manifest` struct. A struct projection silently drops
/// members it does not know, so hashing a struct round-trip would diverge
/// from what the signer signed whenever the manifest carries extension
/// members (spec/manifest.md "Unknown members"). The preserved tree keeps
/// them, so a legitimate signer's extensions verify and a post-seal
/// mutation of any member — known or unknown — breaks the hash.
pub fn manifest_hash(manifest: &Value) -> String {
    sha256_hex(&jcs(manifest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schemas::Manifest;
    use crate::test_support::clean_capsule_bytes;
    use crate::unpack_zip;

    fn load_clean() -> (Manifest, BTreeMap<String, Vec<u8>>) {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).unwrap();
        let manifest_bytes = map.get("manifest.json").unwrap();
        let manifest: Manifest = serde_json::from_slice(manifest_bytes).unwrap();
        (manifest, map)
    }

    fn load_clean_manifest_value() -> Value {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).unwrap();
        serde_json::from_slice(map.get("manifest.json").unwrap()).unwrap()
    }

    #[test]
    fn capsule_id_matches_stored() {
        let (manifest, _) = load_clean();
        let pk = hex_to_bytes(&manifest.originator.public_key).unwrap();
        let id = compute_capsule_id(&pk, manifest.first_event_hash.as_deref(), "0.6").unwrap();
        assert_eq!(id, manifest.id);
    }

    #[test]
    fn capsule_id_rejects_short_pubkey() {
        let err = compute_capsule_id(&[0u8; 31], Some(&"00".repeat(32)), "0.6").unwrap_err();
        assert!(matches!(err, CapsuleIdError::BadOriginatorLength));
    }

    #[test]
    fn capsule_id_rejects_short_first_event_hash() {
        let err = compute_capsule_id(&[0u8; 32], Some("deadbeef"), "0.6").unwrap_err();
        assert!(matches!(err, CapsuleIdError::BadFirstEventHashShape));
    }

    /// `None` (a zero-event capsule) derives exactly like the genesis
    /// zero hash — 32 zero bytes stand in for `first_event_hash_raw`
    /// (spec/manifest.md "Capsule identity").
    #[test]
    fn capsule_id_none_uses_genesis_zero_bytes() {
        let via_none = compute_capsule_id(&[7u8; 32], None, "0.6").unwrap();
        let via_zero_hex = compute_capsule_id(&[7u8; 32], Some(&"0".repeat(64)), "0.6").unwrap();
        assert_eq!(via_none, via_zero_hex);
    }

    #[test]
    fn content_index_matches_stored() {
        let (manifest, files) = load_clean();
        // clean.capsule is plain; structural exclusions reproduce its index.
        let recomputed = build_content_index(&files, STRUCTURAL_EXCLUDED);
        assert_eq!(recomputed.index_hash, manifest.content_index.index_hash);
        assert_eq!(recomputed.files, manifest.content_index.files);
    }

    /// `content_index.files` is a JSON array, so its order is inside the
    /// bytes `index_hash` covers — and this function runs on the VERIFY
    /// path (`verify_content_index`), not just at build time. The order
    /// must therefore be the same UTF-16 code-unit order RFC 8785 §3.2.3
    /// gives object members, which is NOT Rust's `str: Ord` (UTF-8 byte
    /// order == code-point order). A code-point sort puts the U+1F600 path
    /// last and yields a different index_hash, so an honest capsule built
    /// in any other lane fails content-index verification here.
    #[test]
    fn content_index_orders_paths_by_utf16_code_units() {
        let emoji = "\u{1F600}.txt";
        let pua = "\u{E000}.txt";
        let nonchar = "\u{FFFF}.txt";
        let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        files.insert(nonchar.into(), b"a".to_vec());
        files.insert(emoji.into(), b"b".to_vec());
        files.insert(pua.into(), b"c".to_vec());
        files.insert("z.txt".into(), b"d".to_vec());
        let index = build_content_index(&files, STRUCTURAL_EXCLUDED);
        let order: Vec<&str> = index.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(order, vec!["z.txt", emoji, pua, nonchar]);
        // Pinned from the JS reference lane over the same file map:
        //   buildContentIndex(new Map([...])).index_hash
        assert_eq!(
            index.index_hash,
            "49e4bccd112720dad9125d366459e2d4893cb1ffd58d99dc75ea40cc6aa04976"
        );
    }

    #[test]
    fn plain_profile_indexes_stray_content_enc() {
        // A content.enc present in a plain capsule must be indexed (structural
        // exclusions only), so it cannot be smuggled past the verifier.
        let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        files.insert("a.txt".into(), b"a".to_vec());
        files.insert("content.enc".into(), b"smuggled".to_vec());
        let plain = build_content_index(&files, STRUCTURAL_EXCLUDED);
        assert!(plain.files.iter().any(|f| f.path == "content.enc"));
        let encrypted = build_content_index(&files, CONTENT_INDEX_EXCLUDED);
        assert!(!encrypted.files.iter().any(|f| f.path == "content.enc"));
    }

    #[test]
    fn manifest_hash_is_deterministic() {
        let manifest = load_clean_manifest_value();
        let h1 = manifest_hash(&manifest);
        let h2 = manifest_hash(&manifest);
        assert_eq!(h1, h2);
        // 64 lowercase hex chars.
        assert_eq!(h1.len(), 64);
        assert!(h1.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    }

    /// Unknown members are part of the hashed document: adding one to the
    /// preserved tree MUST change the manifest hash. (A struct round-trip
    /// would drop it and leave the hash unchanged — the exact bug class
    /// the preserved-Value contract exists to prevent.)
    #[test]
    fn manifest_hash_covers_unknown_members() {
        let clean = load_clean_manifest_value();
        let h_clean = manifest_hash(&clean);

        let mut extended = clean.clone();
        extended["x-acme-policy"] = serde_json::json!({ "tier": "gold" });
        let h_extended = manifest_hash(&extended);

        assert_ne!(
            h_clean, h_extended,
            "an unknown member must be canonicalised into the manifest hash"
        );
        // And the hash over the extended tree is stable — the member is
        // preserved, not re-projected away.
        assert_eq!(h_extended, manifest_hash(&extended));
    }

    #[test]
    fn excluded_sets_are_correct() {
        assert_eq!(
            STRUCTURAL_EXCLUDED,
            &["manifest.json", "provenance/envelope.json"]
        );
        assert_eq!(
            CONTENT_INDEX_EXCLUDED,
            &["manifest.json", "provenance/envelope.json", "content.enc"]
        );
        assert_eq!(content_index_exclusions(false), STRUCTURAL_EXCLUDED);
        assert_eq!(content_index_exclusions(true), CONTENT_INDEX_EXCLUDED);
    }
}
