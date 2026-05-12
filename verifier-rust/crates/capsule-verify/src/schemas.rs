//! Strongly-typed serde schemas for the three JSON artifacts produced by the
//! JS reference SDK: `manifest.json`, `provenance/envelope.json`, and the
//! per-line records inside `chain/events.jsonl`.
//!
//! The point of these structs is *parse fidelity*: the verifier needs to walk
//! these blobs by name, not as untyped `serde_json::Value`, so a stale field
//! name or type mismatch fails fast at deserialization rather than silently
//! later in the pipeline.
//!
//! Notes that are easy to get wrong:
//!
//! - **Field names are snake_case across the board.** The JS SDK writes
//!   keys like `first_event_hash`, `content_index`, `actor_id`,
//!   `untrusted_payload_fields`, etc. We do not apply
//!   `#[serde(rename_all = "camelCase")]`; the Rust field names mirror the
//!   on-disk keys exactly.
//!
//! - **`Manifest::skill_trust` uses `BTreeMap`, not `HashMap`.** JCS sorts
//!   object keys, and the JS SDK relies on that — the data is logically
//!   sorted-keyed, and we preserve that semantic at the type level so any
//!   later canonicalization through `serde_jcs` produces matching bytes.
//!
//! - **`Envelope::encrypted_blob_hash` is `Option<String>`.** Plain (cipher
//!   == "none") capsules write `null` here; encrypted ones write a 64-hex
//!   string. The struct must accept either form without choking.
//!
//! - **`ChainEvent::untrusted_payload_fields` defaults to empty.** Older
//!   capsules (pre-feature) might omit the field entirely; `#[serde(default)]`
//!   yields an empty `Vec` rather than failing the parse.
//!
//! - **`ChainEvent::payload` is `serde_json::Value`.** Payloads are arbitrary
//!   JSON; the chain hash commits to the canonical bytes of the whole event,
//!   so we must preserve everything inside `payload` losslessly. Round-
//!   tripping through `Value` is fine for that — the JCS canonicalizer
//!   re-sorts keys at hash time anyway.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The `format` block at the top of every manifest. All four fields are
/// fixed-vocabulary strings in v0.6 (`"0.6"`, `"zip"`, `"JCS-RFC8785"`,
/// `"SHA-256"`); we keep them as `String` rather than enums so an unknown
/// future value fails at the *verifier* level (with a clear "unsupported
/// format" message) rather than at deserialization with a serde-internal
/// error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormatBlock {
    pub version: String,
    pub container: String,
    pub canonicalization: String,
    pub hash_algorithm: String,
}

/// Originator block: the entity that *created* the capsule.
///
/// `public_key` is 64 lowercase hex chars (32 raw bytes); `label` is a free-
/// form display name. Both are required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Originator {
    pub public_key: String,
    pub label: String,
}

/// Participant entry: a non-originator party whose role is recorded in the
/// manifest for trust and audit purposes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Participant {
    pub actor_id: String,
    pub role: String,
    pub label: String,
}

/// One row of the content index: a path inside the capsule and the SHA-256
/// of its raw bytes (lowercase hex).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentIndexEntry {
    pub path: String,
    pub sha256: String,
}

/// The full content index: a sorted list of per-file entries plus the
/// SHA-256 of the JCS-canonical form of that list (lowercase hex).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentIndex {
    pub files: Vec<ContentIndexEntry>,
    pub index_hash: String,
}

/// Encryption metadata: present on encrypted capsules, absent (`null`) on
/// plain ones. `metadata_path` points at the in-zip JSON describing per-key
/// envelope-encrypted blob keys; `cipher` names the AEAD scheme (e.g.
/// `"ChaCha20-Poly1305"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Encryption {
    pub metadata_path: String,
    pub cipher: String,
}

/// The full v0.6 manifest. Field names match the on-disk keys exactly.
///
/// `skill_trust` is keyed by skill id (e.g. `"intake-checklist"`) and valued
/// by trust state (e.g. `"signed"`). `BTreeMap` is intentional: the on-disk
/// representation comes through JCS, which sorts object keys, and any
/// re-canonicalization on our side has to honor the same ordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub format: FormatBlock,
    pub id: String,
    pub originator: Originator,
    pub participants: Vec<Participant>,
    pub first_event_hash: String,
    pub content_index: ContentIndex,
    pub skill_trust: BTreeMap<String, String>,
    pub encryption: Option<Encryption>,
    pub created_at: String,
}

/// One signature in the envelope's `signers` array. `role` namespaces the
/// signing input (see `envelope.md` for the domain-separation rule); the
/// public key is 32 raw bytes (64 hex) and the signature 64 raw bytes
/// (128 hex).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signer {
    pub role: String,
    pub public_key: String,
    pub signature: String,
}

/// Provenance envelope: the signed root of trust over a capsule.
///
/// The signed payload is `JCS(envelope minus signers)` per role. We model
/// `signers` as a plain `Vec` so re-serialization preserves the exact set of
/// fields and order from the original document. `encrypted_blob_hash` is an
/// `Option<String>` because the JS SDK writes literal `null` on plain
/// capsules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub version: String,
    pub capsule_id: String,
    pub first_event_hash: String,
    pub entry_hash: String,
    pub manifest_hash: String,
    pub content_index_hash: String,
    pub encrypted_blob_hash: Option<String>,
    pub cipher: String,
    pub signed_at: String,
    pub signers: Vec<Signer>,
}

/// One event from `chain/events.jsonl`.
///
/// `payload` is `serde_json::Value` because event payloads are application-
/// defined and may carry arbitrary nested structure. The chain hash commits
/// to the JCS-canonical bytes of the entire event (excluding `hash`), so the
/// payload's exact contents must round-trip losslessly; `Value` does that by
/// construction.
///
/// `untrusted_payload_fields` carries the convention from `chain.md`: each
/// entry is a JSON-pointer-like path identifying a payload field whose
/// content is LLM-generated narrative and must not be treated as ground
/// truth by downstream consumers. `#[serde(default)]` allows older events
/// that pre-date this field; on round-trip we re-emit the field as `[]`,
/// which is harmless because verification ignores absent vs empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainEvent {
    pub seq: u64,
    pub event_id: String,
    pub actor: String,
    pub kind: String,
    pub action: String,
    pub target: String,
    pub timestamp: String,
    pub payload: serde_json::Value,
    #[serde(default)]
    pub untrusted_payload_fields: Vec<String>,
    pub prev_hash: String,
    pub hash: String,
}

/// Errors returned by [`parse_chain_jsonl`].
#[derive(Debug, Error)]
pub enum ChainParseError {
    /// A non-empty line failed JSON deserialization. `line` is 1-based and
    /// counts every line in the input — including blank ones — so it
    /// corresponds directly to what a text editor would show.
    #[error("chain line {line}: invalid JSON: {source}")]
    LineParse {
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    /// The bytes were not valid UTF-8.
    #[error("chain bytes are not valid UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
}

/// Parse `chain/events.jsonl` bytes into an event vector.
///
/// Splits on `\n`, skips empty lines (so a trailing newline — or two — is
/// fine), and deserializes each non-empty line as a [`ChainEvent`]. The line
/// number reported on parse failure is the 1-based index in the original
/// input, which matches `nl`/editor numbering for the underlying file.
///
/// Mirrors `eventsFromJsonl` in `sdk/src/chain.js`.
pub fn parse_chain_jsonl(bytes: &[u8]) -> Result<Vec<ChainEvent>, ChainParseError> {
    let text = std::str::from_utf8(bytes)?;
    let mut events = Vec::new();
    for (i, raw) in text.split('\n').enumerate() {
        if raw.is_empty() {
            // Skip blank lines — including the trailing one produced by
            // `eventsToJsonl`'s `lines.join("\n") + "\n"`. Note we keep
            // `enumerate` over the *unfiltered* iterator so the 1-based
            // `line` number reported in errors matches the file's actual
            // line numbering.
            continue;
        }
        let event: ChainEvent = serde_json::from_str(raw)
            .map_err(|source| ChainParseError::LineParse { line: i + 1, source })?;
        events.push(event);
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::clean_capsule_bytes;
    use crate::unpack_zip;

    /// Predicate: lowercase hex of exactly `expected` characters.
    fn is_hex_of_len(s: &str, expected: usize) -> bool {
        s.len() == expected
            && s.bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }

    #[test]
    fn parses_clean_manifest() {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).expect("unzip");
        let manifest_bytes = map
            .get("manifest.json")
            .expect("manifest.json present in clean.capsule");

        let manifest: Manifest =
            serde_json::from_slice(manifest_bytes).expect("manifest deserializes");

        assert_eq!(manifest.format.version, "0.6");
        assert_eq!(manifest.format.canonicalization, "JCS-RFC8785");
        assert_eq!(manifest.format.container, "zip");
        assert_eq!(manifest.format.hash_algorithm, "SHA-256");
        assert!(
            is_hex_of_len(&manifest.id, 64),
            "manifest.id must be 64 lowercase hex chars, got {:?}",
            manifest.id
        );
        assert!(
            manifest.encryption.is_none(),
            "clean.capsule is plain; encryption must be null"
        );
        assert!(
            !manifest.participants.is_empty(),
            "manifest must have at least one participant"
        );

        // The fixture must contain at least the three baseline files.
        let paths: Vec<&str> = manifest
            .content_index
            .files
            .iter()
            .map(|f| f.path.as_str())
            .collect();
        for required in ["program.md", "agents.md", "chain/events.jsonl"] {
            assert!(
                paths.contains(&required),
                "content_index must list {required}; got {paths:?}"
            );
        }
        assert!(
            manifest.content_index.files.len() >= 3,
            "expected at least 3 content_index entries, got {}",
            manifest.content_index.files.len()
        );

        // Sanity on originator pubkey shape.
        assert!(
            is_hex_of_len(&manifest.originator.public_key, 64),
            "originator.public_key must be 64 hex"
        );
    }

    #[test]
    fn parses_clean_envelope() {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).expect("unzip");
        let envelope_bytes = map
            .get("provenance/envelope.json")
            .expect("envelope present in clean.capsule");

        let envelope: Envelope =
            serde_json::from_slice(envelope_bytes).expect("envelope deserializes");

        assert_eq!(envelope.version, "0.6");
        assert_eq!(envelope.cipher, "none");
        assert!(
            envelope.encrypted_blob_hash.is_none(),
            "plain capsule must have encrypted_blob_hash=null"
        );
        assert!(
            !envelope.signers.is_empty(),
            "envelope must have at least one signer"
        );
        for s in &envelope.signers {
            assert!(
                is_hex_of_len(&s.signature, 128),
                "signer.signature must be 128 hex, got {:?}",
                s.signature
            );
            assert!(
                is_hex_of_len(&s.public_key, 64),
                "signer.public_key must be 64 hex, got {:?}",
                s.public_key
            );
            assert!(!s.role.is_empty(), "signer.role must not be empty");
        }
    }

    #[test]
    fn parses_clean_chain() {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).expect("unzip");
        let jsonl = map
            .get("chain/events.jsonl")
            .expect("chain present in clean.capsule");

        let events = parse_chain_jsonl(jsonl).expect("chain parses");

        assert!(!events.is_empty(), "chain must have at least one event");
        assert_eq!(events[0].seq, 1, "first event seq must be 1");
        assert_eq!(
            events[0].prev_hash,
            "0".repeat(64),
            "first event prev_hash must be the genesis (32 zero bytes hex)"
        );
        assert!(
            is_hex_of_len(&events[0].hash, 64),
            "events[0].hash must be 64 hex"
        );

        // For each subsequent event, prev_hash chains correctly and seq is 1-based.
        for (i, e) in events.iter().enumerate().skip(1) {
            assert_eq!(
                e.prev_hash,
                events[i - 1].hash,
                "events[{i}].prev_hash must equal events[{}].hash",
                i - 1
            );
            assert_eq!(
                e.seq,
                (i as u64) + 1,
                "events[{i}].seq must be {} (1-based)",
                i + 1
            );
            assert!(
                is_hex_of_len(&e.hash, 64),
                "events[{i}].hash must be 64 hex"
            );
        }
    }

    #[test]
    fn manifest_round_trip() {
        // parse → serialize → parse → struct equality. This proves no field
        // is silently dropped on round-trip; we do NOT require byte-equal
        // JSON output, since serde_json's writer ordering does not match
        // JCS's, and the JS reference itself outputs JCS bytes (which the
        // verifier will recompute via the JCS module, not via this writer).
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).expect("unzip");
        let manifest_bytes = map.get("manifest.json").expect("present");

        let parsed: Manifest = serde_json::from_slice(manifest_bytes).expect("first parse");
        let serialized = serde_json::to_string(&parsed).expect("serialize");
        let reparsed: Manifest = serde_json::from_str(&serialized).expect("second parse");
        assert_eq!(parsed, reparsed, "manifest round-trip must be lossless");
    }

    #[test]
    fn envelope_round_trip() {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).expect("unzip");
        let envelope_bytes = map.get("provenance/envelope.json").expect("present");

        let parsed: Envelope = serde_json::from_slice(envelope_bytes).expect("first parse");
        let serialized = serde_json::to_string(&parsed).expect("serialize");
        let reparsed: Envelope = serde_json::from_str(&serialized).expect("second parse");
        assert_eq!(parsed, reparsed, "envelope round-trip must be lossless");
    }

    #[test]
    fn chain_event_round_trip() {
        let bytes = clean_capsule_bytes();
        let map = unpack_zip(&bytes).expect("unzip");
        let jsonl = map.get("chain/events.jsonl").expect("present");
        let events = parse_chain_jsonl(jsonl).expect("parse");
        let event = events.first().cloned().expect("at least one event");

        let serialized = serde_json::to_string(&event).expect("serialize");
        let reparsed: ChainEvent = serde_json::from_str(&serialized).expect("second parse");
        assert_eq!(event, reparsed, "chain event round-trip must be lossless");
    }

    #[test]
    fn untrusted_payload_fields_default_when_absent() {
        // Older capsules might predate the untrusted_payload_fields convention;
        // the field must default to empty rather than failing the parse. JSONL
        // is one event per line, so the test record is constructed on a single
        // line — `parse_chain_jsonl` splits on '\n'.
        let line = concat!(
            r#"{"seq":1,"event_id":"evt_001","actor":"human:alice","kind":"decision","#,
            r#""action":"submitted","target":"program.md","timestamp":"2026-01-01T00:00:00Z","#,
            r#""payload":{},"#,
            r#""prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","#,
            r#""hash":"0000000000000000000000000000000000000000000000000000000000000001"}"#,
            "\n",
        );
        let events = parse_chain_jsonl(line.as_bytes())
            .expect("parse must succeed without untrusted_payload_fields");
        assert_eq!(events.len(), 1);
        assert!(
            events[0].untrusted_payload_fields.is_empty(),
            "default for missing field must be empty Vec, got {:?}",
            events[0].untrusted_payload_fields
        );
    }

    #[test]
    fn chain_jsonl_skips_blank_trailing_lines() {
        // Two events with a `\n\n` tail — second blank line must be skipped,
        // not parsed as an empty event.
        let mk = |seq: u64, hash: &str, prev: &str| -> String {
            format!(
                r#"{{"seq":{seq},"event_id":"evt_{seq:03}","actor":"a","kind":"k","action":"x","target":"t","timestamp":"2026-01-01T00:00:00Z","payload":{{}},"prev_hash":"{prev}","untrusted_payload_fields":[],"hash":"{hash}"}}"#
            )
        };
        let h1 = "1111111111111111111111111111111111111111111111111111111111111111";
        let h2 = "2222222222222222222222222222222222222222222222222222222222222222";
        let zero = "0".repeat(64);
        let mut s = String::new();
        s.push_str(&mk(1, h1, &zero));
        s.push('\n');
        s.push_str(&mk(2, h2, h1));
        s.push('\n');
        s.push('\n'); // extra blank trailing line

        let events = parse_chain_jsonl(s.as_bytes()).expect("parse");
        assert_eq!(
            events.len(),
            2,
            "blank trailing line must not produce an extra event"
        );
        assert_eq!(events[0].seq, 1);
        assert_eq!(events[1].seq, 2);
        assert_eq!(events[1].prev_hash, h1);
    }
}
